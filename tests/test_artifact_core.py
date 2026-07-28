from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from router_dump_analyzer.artifact_core import (
    ArtifactBoundaryError,
    ArtifactLimits,
    CoreArtifactReader,
    normalize_artifact_path,
)


def _tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


class CoreArtifactReaderTests(unittest.TestCase):
    def test_raw_file_is_inventoried_and_read_without_exposing_source_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "status.jsonl"
            source.write_bytes(b'{"status":"up"}\n')
            with CoreArtifactReader(
                source,
                node_hint="router-a",
                metadata={"platform": "sample"},
            ) as reader:
                self.assertEqual(reader.inventory.node_hint, "router-a")
                self.assertEqual(
                    reader.inventory.metadata["container_kind"],
                    "file",
                )
                self.assertFalse(hasattr(reader, "input_path"))
                self.assertNotIn(
                    os.fspath(source),
                    repr(reader.inventory),
                )
                artifact = reader.inventory.artifacts[0]
                self.assertEqual(
                    artifact.logical_path,
                    PurePosixPath("status.jsonl"),
                )
                with reader.open_binary(artifact.artifact_id) as stream:
                    self.assertEqual(stream.read(), b'{"status":"up"}\n')
                private = Path(
                    reader.materialize_private_path(artifact.artifact_id)
                )
                self.assertNotEqual(private, source)
                self.assertTrue(private.is_file())
            with self.assertRaisesRegex(ArtifactBoundaryError, "closed"):
                reader.open_binary(artifact.artifact_id)

    def test_scoped_reader_exposes_only_selected_artifact_capabilities(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "dump"
            source.mkdir()
            (source / "one.txt").write_bytes(b"one")
            (source / "two.txt").write_bytes(b"two")
            reader = CoreArtifactReader(source, node_hint="router-a")
            one, two = reader.inventory.artifacts

            scoped = reader.scoped((one.artifact_id,))
            self.assertEqual(scoped.inventory.node_hint, "router-a")
            self.assertEqual(scoped.inventory.artifacts, (one,))
            self.assertFalse(hasattr(scoped, "close"))
            with scoped.open_binary(one.artifact_id) as stream:
                self.assertEqual(stream.read(), b"one")
            for access in (
                lambda: scoped.open_binary(two.artifact_id),
                lambda: scoped.materialize_private_path(two.artifact_id),
                lambda: scoped.materialize_private_tree(
                    (one.artifact_id, two.artifact_id)
                ),
                lambda: scoped.scoped((two.artifact_id,)),
            ):
                with self.subTest(access=access), self.assertRaisesRegex(
                    ArtifactBoundaryError,
                    "outside this reader scope",
                ):
                    access()

            reader.close()
            with self.assertRaisesRegex(ArtifactBoundaryError, "closed"):
                scoped.open_binary(one.artifact_id)

    def test_directory_inventory_is_sorted_and_private_tree_preserves_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "dump"
            (source / "logs").mkdir(parents=True)
            (source / "status").mkdir()
            (source / "logs" / "events.jsonl").write_text(
                "{}\n",
                encoding="utf-8",
            )
            (source / "status" / "final.json").write_text(
                "{}",
                encoding="utf-8",
            )
            with CoreArtifactReader(source) as reader:
                self.assertEqual(
                    [
                        item.logical_path.as_posix()
                        for item in reader.inventory.artifacts
                    ],
                    ["logs/events.jsonl", "status/final.json"],
                )
                artifact_ids = tuple(
                    item.artifact_id for item in reader.inventory.artifacts
                )
                tree = Path(reader.materialize_private_tree(artifact_ids))
                self.assertEqual(
                    (tree / "logs" / "events.jsonl").read_text(
                        encoding="utf-8"
                    ),
                    "{}\n",
                )
                status_only = Path(
                    reader.materialize_private_tree(
                        (artifact_ids[1],),
                        PurePosixPath("status"),
                    )
                )
                self.assertEqual(
                    (status_only / "final.json").read_text(encoding="utf-8"),
                    "{}",
                )

    def test_logical_artifact_ids_are_portable_across_input_locations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = root / "left" / "status.jsonl"
            right = root / "right" / "status.jsonl"
            left.parent.mkdir()
            right.parent.mkdir()
            left.write_bytes(b"same\n")
            right.write_bytes(b"same\n")
            with (
                CoreArtifactReader(left) as left_reader,
                CoreArtifactReader(right) as right_reader,
            ):
                self.assertEqual(
                    left_reader.inventory.artifacts[0].artifact_id,
                    right_reader.inventory.artifacts[0].artifact_id,
                )

    def test_tar_and_zip_reject_unsafe_or_non_regular_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe_tar = root / "unsafe.tgz"
            _tar(unsafe_tar, {"../escape": b"bad"})
            with self.assertRaisesRegex(ArtifactBoundaryError, "unsafe"):
                CoreArtifactReader(unsafe_tar)

            link_tar = root / "link.tgz"
            with tarfile.open(link_tar, mode="w:gz") as archive:
                info = tarfile.TarInfo("status-link")
                info.type = tarfile.SYMTYPE
                info.linkname = "status.json"
                archive.addfile(info)
            with self.assertRaisesRegex(
                ArtifactBoundaryError,
                "non-regular",
            ):
                CoreArtifactReader(link_tar)

            unsafe_zip = root / "unsafe.zip"
            with zipfile.ZipFile(unsafe_zip, mode="w") as archive:
                archive.writestr("/absolute", b"bad")
            with self.assertRaisesRegex(ArtifactBoundaryError, "unsafe"):
                CoreArtifactReader(unsafe_zip)

            directories = root / "directories.tgz"
            with tarfile.open(directories, mode="w:gz") as archive:
                directory_info = tarfile.TarInfo("status/")
                directory_info.type = tarfile.DIRTYPE
                archive.addfile(directory_info)
                file_info = tarfile.TarInfo("status/final.json")
                file_info.size = 2
                archive.addfile(file_info, io.BytesIO(b"{}"))
            with CoreArtifactReader(directories) as reader:
                self.assertEqual(
                    reader.inventory.artifacts[0].logical_path,
                    PurePosixPath("status/final.json"),
                )

    def test_archives_are_bounded_and_case_collisions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "case.tgz"
            _tar(
                archive_path,
                {
                    "status/A.json": b"one",
                    "status/a.json": b"two",
                },
            )
            with self.assertRaisesRegex(
                ArtifactBoundaryError,
                "colliding",
            ):
                CoreArtifactReader(archive_path)

            count_path = root / "count.zip"
            with zipfile.ZipFile(count_path, mode="w") as archive:
                archive.writestr("one", b"1")
                archive.writestr("two", b"2")
            with self.assertRaisesRegex(
                ArtifactBoundaryError,
                "count",
            ):
                CoreArtifactReader(
                    count_path,
                    limits=ArtifactLimits(max_artifacts=1),
                )

            size_path = root / "size.tgz"
            _tar(size_path, {"large": b"x" * 32})
            with self.assertRaisesRegex(
                ArtifactBoundaryError,
                "per-file",
            ):
                CoreArtifactReader(
                    size_path,
                    limits=ArtifactLimits(max_artifact_bytes=16),
                )

    def test_tar_members_are_read_from_one_forward_indexed_session(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "ordered.tgz"
            _tar(
                archive_path,
                {
                    "z-last-logical.txt": b"physical-first",
                    "a-first-logical.txt": b"physical-second",
                    "m-middle-logical.txt": b"physical-third",
                },
            )
            with CoreArtifactReader(archive_path) as reader:
                expected = {
                    "a-first-logical.txt": b"physical-second",
                    "m-middle-logical.txt": b"physical-third",
                    "z-last-logical.txt": b"physical-first",
                }
                original_tar_open = tarfile.open
                with (
                    patch.object(
                        tarfile.TarFile,
                        "getmember",
                        side_effect=AssertionError(
                            "indexed reads must not linearly search members"
                        ),
                    ),
                    patch(
                        "router_dump_analyzer.artifact_core.tarfile.open",
                        wraps=original_tar_open,
                    ) as open_tar,
                ):
                    for artifact in reader.inventory.artifacts:
                        with reader.open_binary(
                            artifact.artifact_id
                        ) as stream:
                            self.assertEqual(
                                stream.read(),
                                expected[artifact.logical_path.as_posix()],
                            )
                self.assertEqual(open_tar.call_count, 1)

    def test_enumeration_is_bounded_for_every_container_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            directory_input = root / "directory"
            directory_input.mkdir()
            for index in range(3):
                (directory_input / f"empty-{index}").mkdir()

            tar_input = root / "directories.tgz"
            with tarfile.open(tar_input, mode="w:gz") as archive:
                for index in range(3):
                    info = tarfile.TarInfo(f"empty-{index}/")
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)

            zip_input = root / "directories.zip"
            with zipfile.ZipFile(zip_input, mode="w") as archive:
                for index in range(3):
                    archive.writestr(f"empty-{index}/", b"")

            limits = ArtifactLimits(max_inventory_entries=2)
            for candidate, container_kind in (
                (directory_input, "directory"),
                (tar_input, "tar"),
            ):
                with (
                    self.subTest(container_kind=container_kind),
                    self.assertRaisesRegex(
                        ArtifactBoundaryError,
                        "inventory limit",
                    ),
                ):
                    CoreArtifactReader(candidate, limits=limits)
            with (
                patch(
                    "router_dump_analyzer.artifact_core.zipfile.ZipFile",
                    side_effect=AssertionError(
                        "ZipFile must not build an oversized member list"
                    ),
                ),
                self.assertRaisesRegex(
                    ArtifactBoundaryError,
                    "inventory limit",
                ),
            ):
                CoreArtifactReader(zip_input, limits=limits)

    def test_portable_namespace_rejects_unicode_and_prefix_collisions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collisions = {
                "nfc.tgz": {
                    "status/caf\u00e9.json": b"one",
                    "status/cafe\u0301.json": b"two",
                },
                "parent-case.tgz": {
                    "Status/one.json": b"one",
                    "status/two.json": b"two",
                },
                "prefix.tgz": {
                    "status": b"file",
                    "status/final.json": b"child",
                },
            }
            for filename, members in collisions.items():
                candidate = root / filename
                _tar(candidate, members)
                with (
                    self.subTest(filename=filename),
                    self.assertRaises(ArtifactBoundaryError),
                ):
                    CoreArtifactReader(candidate)

    def test_unsafe_archive_directory_names_fail_before_being_skipped(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe_tar = root / "unsafe-directory.tgz"
            with tarfile.open(unsafe_tar, mode="w:gz") as archive:
                info = tarfile.TarInfo("../")
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            with self.assertRaisesRegex(ArtifactBoundaryError, "unsafe"):
                CoreArtifactReader(unsafe_tar)

            unsafe_zip = root / "unsafe-directory.zip"
            with zipfile.ZipFile(unsafe_zip, mode="w") as archive:
                archive.writestr("CON/", b"")
            with self.assertRaisesRegex(ArtifactBoundaryError, "unsafe"):
                CoreArtifactReader(unsafe_zip)

    def test_source_replacement_after_inventory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "status.json"
            source.write_bytes(b"old")
            replacement = source.with_suffix(".replacement")
            reader = CoreArtifactReader(source)
            artifact_id = reader.inventory.artifacts[0].artifact_id
            replacement.write_bytes(b"new")
            replacement.replace(source)
            try:
                with self.assertRaisesRegex(
                    ArtifactBoundaryError,
                    "changed",
                ):
                    reader.open_binary(artifact_id)
            finally:
                reader.close()

    def test_portable_path_policy_matches_normative_vectors(self) -> None:
        vectors = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "state-dump-generator"
                / "tests"
                / "fixtures"
                / "archive-member-name-conformance.json"
            ).read_text(encoding="utf-8")
        )
        for accepted in vectors["accepted"]:
            with self.subTest(accepted=accepted):
                self.assertEqual(
                    normalize_artifact_path(accepted),
                    PurePosixPath(accepted),
                )
        for rejected in vectors["rejected"]:
            with self.subTest(rejected=rejected), self.assertRaises(
                ArtifactBoundaryError
            ):
                normalize_artifact_path(rejected)

    def test_portable_path_rejects_windows_characters_controls_and_bytes(
        self,
    ) -> None:
        rejected = (
            "bad<name",
            "bad>name",
            'bad"name',
            "bad|name",
            "bad?name",
            "bad*name",
            "bad\x1fname",
            "x" * 256,
            "/".join("x" * 255 for _ in range(17)),
        )
        for value in rejected:
            with (
                self.subTest(value=value[:40]),
                self.assertRaisesRegex(ArtifactBoundaryError, "unsafe"),
            ):
                normalize_artifact_path(value)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from rsl_demo_generator import (
    ASSEMBLY_FORMAT_VERSION,
    ASSEMBLY_ROOT,
    COVERAGE_CASES,
    DEFAULT_ASSEMBLY_ID,
    DEFAULT_PLUGIN_ID,
    DEFAULT_PLUGIN_VERSION,
    DEMO_LINKS,
    DEMO_NODES,
    GENERATED_TOPOLOGY_PROFILE,
    PACKET_PROFILES,
    AssemblyConfig,
    build_coverage,
    build_demo_fixture,
    build_ingestion_conformance_corpus,
    ensure_demo_fixture_for_launch,
    ingestion_temporal_semantic_vector,
    probe_demo_fixture_for_launch,
    validate_demo_fixture,
)
from rsl_demo_generator import _scale as scale_generator
from rsl_demo_generator import catalog as generator_catalog
from rsl_demo_generator._archive import (
    validate_archive_name,
    write_deterministic_tgz,
)
from rsl_demo_generator.assembly import (
    _GENERATED_JSONL_REWRITE_PLANS,
    _case_candidate_paths,
    _compact_json_line,
    _loaded_source_scenario_descriptor,
    _projection_rows,
    _source_event_rows,
    _source_resource_id,
    _topology_projection,
    _transform_generated_json_line,
    _transform_value,
    _validate_projection_member,
)
from rsl_demo_generator.conformance import (
    EXPECTATIONS_MEMBER as INGESTION_EXPECTATIONS_MEMBER,
)
from rsl_demo_generator.conformance import (
    MANIFEST_MEMBER as INGESTION_MANIFEST_MEMBER,
)
from rsl_demo_plugin import (
    GENERATED_COVERAGE_FORMAT_VERSION,
    GENERATED_COVERAGE_REGISTRY_ID,
    GENERATED_PROJECTION_POLICY,
    PLUGIN_ID,
    PLUGIN_VERSION,
    plugin,
    render_conformance_status_fixture,
)
from rsl_demo_plugin.advanced_trace import ADVANCED_TRACE_SCENARIOS
from rsl_demo_plugin.route_policy import DEMO_ROUTE_POLICY
from rsl_demo_plugin.scale_data import load_scale_dataset
from rsl_demo_plugin.scenario_registry import (
    PACKET_TRACE_SCENARIOS,
    ROUTE_PROTOCOL_BY_TYPE,
    SCENARIO_BY_ID,
)

from router_dump_analyzer import AnalysisLoadStage, multi_node_route

NODE_PACK_ROOT = "router-state-lab-100k"


def _member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    source = archive.extractfile(name)
    if source is None:
        raise AssertionError(f"missing archive member: {name}")
    return source.read()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def _outer_members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, mode="r:gz") as archive:
        return {
            member.name: _member_bytes(archive, member.name)
            for member in archive.getmembers()
            if member.isfile()
        }


def _write_outer_members(path: Path, members: dict[str, bytes]) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(
            fileobj=raw,
            mode="wb",
            mtime=0,
            filename="",
        ) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                for name, content in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = 0
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(content))


def _write_header_only_tgz(
    path: Path,
    *,
    member_name: str,
    declared_size: int,
) -> None:
    info = tarfile.TarInfo(member_name)
    info.size = declared_size
    info.mtime = 0
    info.mode = 0o644
    raw_tar = info.tobuf(format=tarfile.USTAR_FORMAT) + (b"\0" * 1024)
    with path.open("wb") as output:
        with gzip.GzipFile(
            fileobj=output,
            mode="wb",
            mtime=0,
            filename="",
        ) as zipped:
            zipped.write(raw_tar)


def _launch_ready_outer_members() -> dict[str, bytes]:
    config = AssemblyConfig()
    state_change_records = scale_generator._scenario_metadata(
        config.events_per_node,
        scale_generator._layout(config.resources_per_node),
    )["expected_changes"]["state_change_events"]
    coverage = build_coverage(config)
    coverage_content = _json_bytes(coverage)
    members: dict[str, bytes] = {
        f"{ASSEMBLY_ROOT}/coverage.json": coverage_content,
    }
    nodes: list[dict[str, object]] = []
    for node in DEMO_NODES:
        content = f"opaque generated node pack: {node.node_id}\n".encode()
        logical_archive = f"nodes/{node.node_id}.tgz"
        members[f"{ASSEMBLY_ROOT}/{logical_archive}"] = content
        nodes.append(
            {
                "node_id": node.node_id,
                "revision_id": node.revision_id,
                "label": node.label,
                "archive": logical_archive,
                "sha256": hashlib.sha256(content).hexdigest(),
                "compressed_size": len(content),
                "event_records": config.events_per_node,
                "state_change_event_records": state_change_records,
                "resource_records": config.resources_per_node,
                "identity_namespace": node.identity_namespace,
            }
        )
    manifest = {
        "generator": "router-dump-analyzer-demo-assembly-v1",
        "format_version": ASSEMBLY_FORMAT_VERSION,
        "assembly_id": DEFAULT_ASSEMBLY_ID,
        "source_scenario": _loaded_source_scenario_descriptor(),
        "plugin": GENERATED_PROJECTION_POLICY.archive_plugin_descriptor(),
        "default_node_id": DEMO_NODES[0].node_id,
        "scale_policy": {"full_scale": True},
        "nodes": nodes,
        "node_count": len(nodes),
        "coverage": {
            "path": "coverage.json",
            "sha256": hashlib.sha256(coverage_content).hexdigest(),
            "cases": len(coverage["cases"]),
            "complete": True,
        },
    }
    members[f"{ASSEMBLY_ROOT}/manifest.json"] = _json_bytes(manifest)
    return members


def _rewrite_launch_manifest(
    members: dict[str, bytes],
    mutate: object,
) -> None:
    manifest_name = f"{ASSEMBLY_ROOT}/manifest.json"
    manifest = json.loads(members[manifest_name])
    assert callable(mutate)
    mutate(manifest)
    members[manifest_name] = _json_bytes(manifest)


def _install_launch_ready_fixture(
    output: Path,
    **_: object,
) -> tuple[Path, object]:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    _write_outer_members(output, _launch_ready_outer_members())
    return output, mock.sentinel.validation_report


class DemoFixtureGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.config = AssemblyConfig(
            nodes=DEMO_NODES[:2],
            events_per_node=120,
            resources_per_node=120,
            seed=12345,
            allow_small=True,
        )
        cls.first = build_demo_fixture(
            cls.root / "first.tgz",
            config=cls.config,
        )
        cls.second = build_demo_fixture(
            cls.root / "second.tgz",
            config=cls.config,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_small_assembly_is_byte_deterministic_and_deep_valid(self) -> None:
        self.assertEqual(
            hashlib.sha256(self.first.read_bytes()).hexdigest(),
            hashlib.sha256(self.second.read_bytes()).hexdigest(),
        )
        report = validate_demo_fixture(
            self.first,
            require_full_scale=False,
            deep=True,
        )
        self.assertEqual(report.node_ids, ("node-a", "node-b"))
        self.assertEqual(report.coverage_case_count, len(COVERAGE_CASES))
        self.assertFalse(report.full_scale)

    def test_launch_preflight_accepts_only_complete_multi_node_outer_shape(
        self,
    ) -> None:
        archive = self.root / "launch-ready.tgz"
        _write_outer_members(archive, _launch_ready_outer_members())

        report = probe_demo_fixture_for_launch(archive)

        self.assertEqual(report.assembly_id, DEFAULT_ASSEMBLY_ID)
        self.assertEqual(
            report.node_ids,
            tuple(node.node_id for node in DEMO_NODES),
        )
        self.assertTrue(report.full_scale)
        self.assertEqual(
            report.coverage_case_count,
            len(COVERAGE_CASES),
        )

    def test_launch_preflight_does_not_decode_nested_node_packs(self) -> None:
        archive = self.root / "launch-ready-opaque-packs.tgz"
        _write_outer_members(archive, _launch_ready_outer_members())
        from rsl_demo_generator import __main__ as generator_main

        with mock.patch.object(
            generator_main,
            "validate_demo_fixture",
        ) as validate:
            result = generator_main.main(
                ["--check-launchable", str(archive)]
            )

        self.assertEqual(result, 0)
        validate.assert_not_called()

    def test_launch_preflight_cli_rejects_conflicting_operations(self) -> None:
        from rsl_demo_generator import __main__ as generator_main

        archive = self.root / "launch-ready-cli-conflict.tgz"
        operations = (
            ["--deep-validate"],
            ["--node", DEMO_NODES[0].node_id],
            ["--write-conformance-fixture", str(self.root / "status.jsonl")],
            [
                "--write-ingestion-conformance-corpus",
                str(self.root / "ingestion.tgz"),
            ],
            ["--output", str(self.root / "replacement.tgz")],
            ["--path-only"],
        )
        for extra in operations:
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    generator_main.main(
                        ["--check-launchable", str(archive), *extra]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_ensure_cli_path_only_returns_selected_archive(self) -> None:
        from rsl_demo_generator import __main__ as generator_main

        preferred = self.root / "ensure-cli-unowned.tgz"
        preferred.write_bytes(b"preserve me")
        recovery = self.root / "ensure-cli-unowned.generated.tgz"
        _write_outer_members(recovery, _launch_ready_outer_members())
        output = io.StringIO()
        with redirect_stdout(output):
            result = generator_main.main(
                [
                    "--ensure-launchable",
                    str(preferred),
                    "--path-only",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().strip(), str(recovery))
        self.assertEqual(preferred.read_bytes(), b"preserve me")

    def test_launch_preflight_rejects_noncanonical_or_incomplete_archives(
        self,
    ) -> None:
        scenarios: dict[str, tuple[object, str]] = {
            "partial node catalog": (
                lambda members: _rewrite_launch_manifest(
                    members,
                    lambda manifest: (
                        manifest["nodes"].pop(),
                        manifest.__setitem__(
                            "node_count",
                            len(manifest["nodes"]),
                        ),
                    ),
                ),
                "every canonical generated node dump",
            ),
            "missing node pack": (
                lambda members: members.pop(
                    f"{ASSEMBLY_ROOT}/nodes/{DEMO_NODES[-1].node_id}.tgz"
                ),
                "missing or has the wrong size",
            ),
            "wrong node pack size": (
                lambda members: members.__setitem__(
                    f"{ASSEMBLY_ROOT}/nodes/{DEMO_NODES[-1].node_id}.tgz",
                    b"wrong-size",
                ),
                "missing or has the wrong size",
            ),
            "developer scale": (
                lambda members: _rewrite_launch_manifest(
                    members,
                    lambda manifest: manifest["scale_policy"].__setitem__(
                        "full_scale",
                        False,
                    ),
                ),
                "full-scale",
            ),
            "stale authoring source": (
                lambda members: _rewrite_launch_manifest(
                    members,
                    lambda manifest: manifest["source_scenario"].__setitem__(
                        "sha256",
                        "0" * 64,
                    ),
                ),
                "current canonical authoring scenario",
            ),
            "extra outer member": (
                lambda members: members.__setitem__(
                    f"{ASSEMBLY_ROOT}/unexpected.bin",
                    b"unexpected",
                ),
                "unexpected assembly member",
            ),
        }
        for index, (name, (mutate, message)) in enumerate(
            scenarios.items()
        ):
            with self.subTest(name=name):
                members = _launch_ready_outer_members()
                assert callable(mutate)
                mutate(members)
                archive = self.root / f"not-launch-ready-{index}.tgz"
                _write_outer_members(archive, members)
                with self.assertRaisesRegex(RuntimeError, message):
                    probe_demo_fixture_for_launch(archive)

    def test_launch_preflight_rejects_stale_materializer_fingerprint(
        self,
    ) -> None:
        members = _launch_ready_outer_members()
        _rewrite_launch_manifest(
            members,
            lambda manifest: manifest["source_scenario"][
                "materializer"
            ].__setitem__("fingerprint", "0" * 64),
        )
        archive = self.root / "stale-materializer-fingerprint.tgz"
        _write_outer_members(archive, members)

        with self.assertRaisesRegex(
            RuntimeError,
            "current canonical authoring scenario",
        ):
            probe_demo_fixture_for_launch(archive)

    def test_launch_preflight_uses_a_fresh_source_descriptor(self) -> None:
        from rsl_demo_generator import assembly

        archive = self.root / "fresh-source-preflight.tgz"
        _write_outer_members(archive, _launch_ready_outer_members())
        changed = _loaded_source_scenario_descriptor()
        changed["sha256"] = "0" * 64

        with mock.patch.object(
            assembly,
            "_fresh_source_scenario_descriptor",
            return_value=changed,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "current canonical authoring scenario",
            ):
                probe_demo_fixture_for_launch(archive)

    def test_launch_preflight_rejects_selected_node_developer_fixture(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "every canonical generated node dump",
        ):
            probe_demo_fixture_for_launch(self.first)

    def test_launch_preflight_hashes_opaque_node_packs(self) -> None:
        members = _launch_ready_outer_members()
        node_member = (
            f"{ASSEMBLY_ROOT}/nodes/{DEMO_NODES[-1].node_id}.tgz"
        )
        original = members[node_member]
        members[node_member] = bytes(
            [original[0] ^ 0x01]
        ) + original[1:]
        archive = self.root / "same-size-node-corruption.tgz"
        _write_outer_members(archive, members)

        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            probe_demo_fixture_for_launch(archive)

    def test_launch_preflight_rejects_names_and_sizes_before_payloads(
        self,
    ) -> None:
        from rsl_demo_generator import assembly

        cases = (
            (
                "unexpected",
                "customer-data.bin",
                assembly._MAX_LAUNCH_NODE_ARCHIVE_BYTES + 1,
                "unexpected assembly member",
            ),
            (
                "oversize manifest",
                f"{ASSEMBLY_ROOT}/manifest.json",
                assembly._MAX_LAUNCH_METADATA_BYTES + 1,
                "member size is invalid",
            ),
        )
        for index, (name, member_name, size, message) in enumerate(cases):
            with self.subTest(name=name):
                archive = self.root / f"early-bound-{index}.tgz"
                _write_header_only_tgz(
                    archive,
                    member_name=member_name,
                    declared_size=size,
                )
                with self.assertRaisesRegex(RuntimeError, message):
                    probe_demo_fixture_for_launch(archive)

    def test_launch_preflight_enforces_cumulative_uncompressed_limit(
        self,
    ) -> None:
        from rsl_demo_generator import assembly

        archive = self.root / "cumulative-bound.tgz"
        _write_outer_members(archive, _launch_ready_outer_members())
        with mock.patch.object(
            assembly,
            "_MAX_LAUNCH_UNCOMPRESSED_BYTES",
            1,
        ):
            with self.assertRaisesRegex(RuntimeError, "uncompressed limit"):
                probe_demo_fixture_for_launch(archive)

    def test_ensure_reuses_a_valid_preferred_archive(self) -> None:
        from rsl_demo_generator import assembly

        preferred = self.root / "ensure-reuse.tgz"
        _write_outer_members(preferred, _launch_ready_outer_members())
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
        ) as build:
            report = ensure_demo_fixture_for_launch(preferred)

        self.assertFalse(report.generated)
        self.assertEqual(report.output_path, preferred)
        self.assertFalse(report.used_recovery_path)
        build.assert_not_called()

    def test_ensure_generates_a_missing_preferred_archive(self) -> None:
        from rsl_demo_generator import assembly

        preferred = self.root / "ensure-missing.tgz"
        self.assertFalse(preferred.exists())
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
            side_effect=_install_launch_ready_fixture,
        ) as build:
            report = ensure_demo_fixture_for_launch(preferred)

        self.assertTrue(report.generated)
        self.assertEqual(report.output_path, preferred)
        self.assertFalse(report.used_recovery_path)
        build.assert_called_once()
        probe_demo_fixture_for_launch(preferred)

    def test_ensure_rebuilds_owned_same_size_corruption_in_place(self) -> None:
        from rsl_demo_generator import assembly

        preferred = self.root / "ensure-owned-corrupt.tgz"
        members = _launch_ready_outer_members()
        node_member = (
            f"{ASSEMBLY_ROOT}/nodes/{DEMO_NODES[0].node_id}.tgz"
        )
        original = members[node_member]
        members[node_member] = original[:-1] + bytes(
            [original[-1] ^ 0x01]
        )
        _write_outer_members(preferred, members)
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
            side_effect=_install_launch_ready_fixture,
        ) as build:
            report = ensure_demo_fixture_for_launch(preferred)

        self.assertTrue(report.generated)
        self.assertEqual(report.output_path, preferred)
        self.assertFalse(report.used_recovery_path)
        build.assert_called_once()
        probe_demo_fixture_for_launch(preferred)

    def test_build_refuses_publication_when_source_changes_during_build(
        self,
    ) -> None:
        from rsl_demo_generator import assembly

        output = self.root / "source-changed-during-build.tgz"
        current = _loaded_source_scenario_descriptor()
        changed = json.loads(json.dumps(current))
        changed["sha256"] = "0" * 64
        state = {"guard_calls": 0, "changed": False}
        original_guard = assembly._assert_replaceable_output

        def fresh_descriptor() -> dict[str, object]:
            return changed if state["changed"] else current

        def publication_guard(path: Path) -> None:
            original_guard(path)
            state["guard_calls"] += 1
            if state["guard_calls"] == 2:
                state["changed"] = True

        with (
            mock.patch.object(
                assembly,
                "_fresh_source_scenario_descriptor",
                side_effect=fresh_descriptor,
            ),
            mock.patch.object(
                assembly,
                "_assert_replaceable_output",
                side_effect=publication_guard,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "changed during demo generation",
            ),
        ):
            build_demo_fixture(
                output,
                config=AssemblyConfig(
                    nodes=DEMO_NODES[:1],
                    events_per_node=120,
                    resources_per_node=120,
                    seed=12345,
                    allow_small=True,
                ),
            )

        self.assertTrue(state["changed"])
        self.assertFalse(output.exists())

    def test_ensure_preserves_unowned_preferred_and_uses_recovery(
        self,
    ) -> None:
        from rsl_demo_generator import assembly

        preferred = self.root / "ensure-unowned.tgz"
        original = b"customer-owned bytes must remain unchanged"
        preferred.write_bytes(original)
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
            side_effect=_install_launch_ready_fixture,
        ):
            report = ensure_demo_fixture_for_launch(preferred)

        expected_recovery = self.root / "ensure-unowned.generated.tgz"
        self.assertEqual(preferred.read_bytes(), original)
        self.assertEqual(report.output_path, expected_recovery)
        self.assertTrue(report.used_recovery_path)
        self.assertTrue(report.preserved_preferred)
        probe_demo_fixture_for_launch(expected_recovery)

    def test_ensure_preserves_preferred_symlink_and_uses_recovery(
        self,
    ) -> None:
        from rsl_demo_generator import assembly

        target = self.root / "ensure-symlink-target.tgz"
        target.write_bytes(b"customer target")
        preferred = self.root / "ensure-symlink.tgz"
        try:
            preferred.symlink_to(target)
        except OSError:
            self.skipTest("filesystem does not permit symlink creation")
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
            side_effect=_install_launch_ready_fixture,
        ):
            report = ensure_demo_fixture_for_launch(preferred)

        self.assertTrue(preferred.is_symlink())
        self.assertEqual(target.read_bytes(), b"customer target")
        self.assertEqual(
            report.output_path,
            self.root / "ensure-symlink.generated.tgz",
        )
        self.assertTrue(report.preserved_preferred)

    def test_ensure_fails_closed_for_an_unsafe_recovery_path(self) -> None:
        from rsl_demo_generator import assembly

        preferred = self.root / "ensure-both-unowned.tgz"
        recovery = self.root / "ensure-both-unowned.generated.tgz"
        preferred.write_bytes(b"preferred customer data")
        recovery.write_bytes(b"recovery customer data")
        with mock.patch.object(
            assembly,
            "_build_demo_fixture_with_report",
        ) as build:
            with self.assertRaisesRegex(
                RuntimeError,
                "unsafe recovery fixture path",
            ):
                ensure_demo_fixture_for_launch(preferred)

        self.assertEqual(preferred.read_bytes(), b"preferred customer data")
        self.assertEqual(recovery.read_bytes(), b"recovery customer data")
        build.assert_not_called()

    def test_build_checks_final_output_symlink_before_resolving(self) -> None:
        target = self.root / "symlink-target.tgz"
        target.write_bytes(b"customer target")
        output = self.root / "symlink-output.tgz"
        try:
            output.symlink_to(target)
        except OSError:
            self.skipTest("filesystem does not permit symlink creation")

        with self.assertRaisesRegex(RuntimeError, "symbolic-link output"):
            build_demo_fixture(output, config=self.config)
        self.assertEqual(target.read_bytes(), b"customer target")
        self.assertTrue(output.is_symlink())

    def test_build_runs_lexical_symlink_guard_before_resolution(self) -> None:
        from rsl_demo_generator import assembly

        lexical_output = mock.MagicMock(spec=Path)
        lexical_output.is_symlink.return_value = True
        lexical_output.__str__.return_value = "lexical-output.tgz"
        with mock.patch.object(
            assembly,
            "_lexical_absolute_path",
            return_value=lexical_output,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "symbolic-link output",
            ):
                assembly._build_demo_fixture_with_report(
                    self.root / "not-followed.tgz",
                    config=self.config,
                )

        lexical_output.resolve.assert_not_called()
        lexical_output.parent.mkdir.assert_called_once_with(
            parents=True,
            exist_ok=True,
        )

    def test_fast_jsonl_namespacing_matches_reference_transform(self) -> None:
        scale_root = self.root / "transform-reference"
        scale_generator.generate_scale_tree(scale_root, 500, 250)
        jsonl_names = (
            "events.jsonl",
            "relationships.jsonl",
            "high-fanout-relationships.jsonl",
            "relationship-mutations.jsonl",
        )
        for node in (DEMO_NODES[0], DEMO_NODES[1], DEMO_NODES[4]):
            for name in jsonl_names:
                with self.subTest(node=node.node_id, member=name):
                    with (scale_root / name).open("rb") as source:
                        for raw_line in source:
                            expected = _compact_json_line(
                                _transform_value(
                                    json.loads(raw_line),
                                    node=node,
                                )
                            )
                            self.assertEqual(
                                _transform_generated_json_line(
                                    raw_line,
                                    node,
                                    plan=(
                                        _GENERATED_JSONL_REWRITE_PLANS[name]
                                    ),
                                ),
                                expected,
                            )

    def test_multi_node_build_generates_one_shared_scale_template(self) -> None:
        from rsl_demo_generator import assembly

        output = self.root / "one-template.tgz"
        config = AssemblyConfig(
            nodes=DEMO_NODES[:3],
            events_per_node=120,
            resources_per_node=120,
            seed=45678,
            allow_small=True,
        )
        with mock.patch.object(
            assembly.scale_generator,
            "generate_scale_tree",
            wraps=assembly.scale_generator.generate_scale_tree,
        ) as generate, mock.patch.object(
            assembly,
            "_topology_projection",
            wraps=assembly._topology_projection,
        ) as topology_projection:
            build_demo_fixture(output, config=config)
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(topology_projection.call_count, len(config.nodes))

    def test_archive_writer_reports_emitted_digest_and_size(self) -> None:
        source_a = self.root / "archive-source-a.txt"
        source_b = self.root / "archive-source-b.txt"
        source_a.write_bytes(b"a" * 10_000)
        source_b.write_bytes(b"b" * 25_000)
        first = self.root / "archive-result-first.tgz"
        second = self.root / "archive-result-second.tgz"
        members = {
            "nested/a.txt": source_a,
            "nested/b.txt": source_b,
        }
        first_result = write_deterministic_tgz(first, members)
        second_result = write_deterministic_tgz(second, members)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result, second_result)
        self.assertEqual(first_result.size, first.stat().st_size)
        self.assertEqual(
            first_result.sha256,
            hashlib.sha256(first.read_bytes()).hexdigest(),
        )

    def test_shallow_validation_rejects_stale_assembly_schema(self) -> None:
        stale = self.root / "stale-assembly-schema.tgz"
        members = _outer_members(self.first)
        manifest_name = f"{ASSEMBLY_ROOT}/manifest.json"
        manifest = json.loads(members[manifest_name])
        self.assertEqual(
            manifest["format_version"],
            ASSEMBLY_FORMAT_VERSION,
        )
        manifest["format_version"] = ASSEMBLY_FORMAT_VERSION - 1
        members[manifest_name] = _json_bytes(manifest)
        _write_outer_members(stale, members)

        with self.assertRaisesRegex(
            RuntimeError,
            "assembly format version",
        ):
            validate_demo_fixture(
                stale,
                require_full_scale=False,
                deep=False,
            )

    def test_shallow_validation_rejects_stale_candidate_path_shape(
        self,
    ) -> None:
        stale = self.root / "stale-coverage-shape.tgz"
        members = _outer_members(self.first)
        manifest_name = f"{ASSEMBLY_ROOT}/manifest.json"
        coverage_name = f"{ASSEMBLY_ROOT}/coverage.json"
        coverage = json.loads(members[coverage_name])
        route_case = next(
            case
            for case in coverage["cases"]
            if "route_resolution" in case["required_capabilities"]
        )
        route_case.pop("candidate_paths")
        members[coverage_name] = _json_bytes(coverage)
        manifest = json.loads(members[manifest_name])
        manifest["coverage"]["sha256"] = hashlib.sha256(
            members[coverage_name]
        ).hexdigest()
        members[manifest_name] = _json_bytes(manifest)
        _write_outer_members(stale, members)

        with self.assertRaisesRegex(RuntimeError, "lacks candidate_paths"):
            validate_demo_fixture(
                stale,
                require_full_scale=False,
                deep=False,
            )

    def test_shallow_validation_rejects_incomplete_exact_coverage_evidence(
        self,
    ) -> None:
        stale = self.root / "incomplete-coverage-evidence.tgz"
        members = _outer_members(self.first)
        manifest_name = f"{ASSEMBLY_ROOT}/manifest.json"
        coverage_name = f"{ASSEMBLY_ROOT}/coverage.json"
        coverage = json.loads(members[coverage_name])
        topology_case = next(
            case
            for case in coverage["cases"]
            if case["case_id"] == "topology-shared-subnet-multiaccess"
        )
        topology_case["evidence_refs"][0].pop("classification")
        members[coverage_name] = _json_bytes(coverage)
        manifest = json.loads(members[manifest_name])
        manifest["coverage"]["sha256"] = hashlib.sha256(
            members[coverage_name]
        ).hexdigest()
        members[manifest_name] = _json_bytes(manifest)
        _write_outer_members(stale, members)

        with self.assertRaisesRegex(
            RuntimeError,
            "topology_claim evidence lacks classification",
        ):
            validate_demo_fixture(
                stale,
                require_full_scale=False,
                deep=False,
            )

    def test_shallow_projection_validation_rejects_tampered_topology_reference(
        self,
    ) -> None:
        node = DEMO_NODES[0]
        forwarding = _projection_rows(node, config=self.config)[1]
        tampered = json.loads(json.dumps(forwarding))
        decision = next(
            decision
            for row in tampered
            if row.get("scenario_id")
            for decisions in row["directional_decisions"].values()
            for decision in decisions
            if decision["next_hop"] is not None
        )
        decision["next_hop"]["topology_references"] = []
        content = b"".join(_json_bytes(row) for row in tampered)
        descriptor = {
            "records": len(tampered),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        with self.assertRaisesRegex(
            RuntimeError,
            "exactly one topology reference",
        ):
            _validate_projection_member(
                io.BytesIO(content),
                node_id=node.node_id,
                revision_id=node.revision_id,
                descriptor=descriptor,
                projection_name="forwarding",
            )

    def test_outer_manifest_indexes_one_pack_per_selected_node(self) -> None:
        with tarfile.open(self.first, mode="r:gz") as archive:
            manifest = json.loads(
                _member_bytes(
                    archive,
                    f"{ASSEMBLY_ROOT}/manifest.json",
                )
            )
            coverage = json.loads(
                _member_bytes(
                    archive,
                    f"{ASSEMBLY_ROOT}/coverage.json",
                )
            )
            names = set(archive.getnames())
        self.assertEqual(manifest["node_count"], 2)
        self.assertFalse(manifest["scale_policy"]["full_scale"])
        self.assertEqual(
            manifest["source_scenario"],
            _loaded_source_scenario_descriptor(),
        )
        self.assertEqual(
            manifest["plugin"],
            GENERATED_PROJECTION_POLICY.archive_plugin_descriptor(),
        )
        self.assertEqual(DEFAULT_PLUGIN_ID, PLUGIN_ID)
        self.assertEqual(DEFAULT_PLUGIN_VERSION, PLUGIN_VERSION)
        self.assertEqual(plugin.manifest.plugin_id, PLUGIN_ID)
        self.assertEqual(plugin.manifest.plugin_version, PLUGIN_VERSION)
        self.assertEqual(
            {item["archive"] for item in manifest["nodes"]},
            {"nodes/node-a.tgz", "nodes/node-b.tgz"},
        )
        self.assertIn(
            f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            names,
        )
        self.assertIn(
            f"{ASSEMBLY_ROOT}/nodes/node-b.tgz",
            names,
        )
        self.assertEqual(
            {item["case_id"] for item in coverage["cases"]},
            {item.case_id for item in COVERAGE_CASES},
        )
        self.assertEqual(
            coverage["format_version"],
            GENERATED_COVERAGE_FORMAT_VERSION,
        )
        self.assertEqual(
            coverage["registry_id"],
            GENERATED_COVERAGE_REGISTRY_ID,
        )
        self.assertEqual(
            {
                intent
                for item in coverage["cases"]
                for intent in item["private_analysis_intents"]
            },
            {
                "route_trace",
                "trace_correlation",
                "evidence_correlation",
                "evidence_interpretation",
            },
        )
        self.assertTrue(
            all(
                item["private_analysis_intents"]
                == list(spec.private_analysis_intents)
                for item, spec in zip(
                    coverage["cases"],
                    COVERAGE_CASES,
                    strict=True,
                )
            )
        )
        self.assertTrue(
            all(
                "evidence_analysis" in item["required_capabilities"]
                for item in coverage["cases"]
            )
        )
        # A selected-node developer fixture still enumerates every public case,
        # but truthfully identifies cases whose other evidence packs are absent.
        self.assertFalse(coverage["complete"])
        self.assertTrue(any(item["missing_nodes"] for item in coverage["cases"]))

    def test_node_pack_contains_raw_inputs_and_plugin_projection_once(self) -> None:
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        with tarfile.open(fileobj=io.BytesIO(node_bytes), mode="r:gz") as node:
            node_names = set(node.getnames())
            intent_bearing_node_members = []
            for member in node.getmembers():
                if not member.isfile() or not member.name.endswith(
                    (".json", ".jsonl")
                ):
                    continue
                source = node.extractfile(member)
                assert source is not None
                if b'"private_analysis_intents"' in source.read():
                    intent_bearing_node_members.append(member.name)
            pack_manifest = json.loads(
                _member_bytes(node, f"{NODE_PACK_ROOT}/manifest.json")
            )
            projection_manifest = json.loads(
                _member_bytes(
                    node,
                    (
                        f"{NODE_PACK_ROOT}/plugin-projection/"
                        "manifest.json"
                    ),
                )
            )
            container_bytes = _member_bytes(
                node,
                f"{NODE_PACK_ROOT}/containers/evpn-control.tgz",
            )
        self.assertEqual(pack_manifest["node_id"], "node-a")
        self.assertEqual(intent_bearing_node_members, [])
        self.assertEqual(
            pack_manifest["source"]["authoring_scenario"]["sha256"],
            generator_catalog.DEFAULT_SCENARIO_SOURCE.sha256,
        )
        self.assertEqual(
            pack_manifest["revision_id"],
            "demo/node-a/revision-0001",
        )
        self.assertEqual(
            pack_manifest["plugin_projection_root"],
            "plugin-projection",
        )
        self.assertEqual(
            pack_manifest["plugin"],
            GENERATED_PROJECTION_POLICY.archive_plugin_descriptor(),
        )
        self.assertEqual(projection_manifest["plugin_id"], PLUGIN_ID)
        self.assertEqual(
            projection_manifest["plugin_version"],
            PLUGIN_VERSION,
        )
        self.assertEqual(
            projection_manifest["projection_policy_id"],
            GENERATED_PROJECTION_POLICY.policy_id,
        )
        self.assertEqual(
            projection_manifest["projection_materialization"],
            "precomputed_during_generation",
        )
        self.assertFalse(projection_manifest["parser_replayed"])
        self.assertEqual(
            set(projection_manifest["files"]),
            {"topology", "routes", "forwarding", "packet_cases"},
        )
        self.assertIn(
            f"{NODE_PACK_ROOT}/normalized-scale/events.jsonl",
            node_names,
        )
        self.assertFalse(
            any(
                name.startswith(f"{NODE_PACK_ROOT}/review-projection/")
                for name in node_names
            ),
        )
        self.assertNotIn("review_projection_root", pack_manifest)
        self.assertNotIn("review_projection", pack_manifest)
        with tarfile.open(
            fileobj=io.BytesIO(container_bytes),
            mode="r:gz",
        ) as container:
            container_names = set(container.getnames())
            container_manifest = json.loads(
                _member_bytes(container, "manifest.json")
            )
        self.assertIn("trace/ctf/metadata", container_names)
        self.assertIn("trace/ctf/dummystream", container_names)
        self.assertIn("trace/system.log", container_names)
        self.assertIn("status/resource-status.txt", container_names)
        self.assertNotIn("trace/normalized-events.jsonl", container_names)
        self.assertNotIn(
            "normalized_export",
            container_manifest["trace"],
        )

    def test_saved_scenario_history_is_materialized_without_private_truth(
        self,
    ) -> None:
        source = generator_catalog.DEFAULT_SCENARIO_SOURCE
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        with tarfile.open(
            fileobj=io.BytesIO(node_bytes),
            mode="r:gz",
        ) as node:
            events = [
                json.loads(line)
                for line in _member_bytes(
                    node,
                    f"{NODE_PACK_ROOT}/normalized-scale/events.jsonl",
                ).splitlines()
                if line.strip()
            ]
            resources = _member_bytes(
                node,
                f"{NODE_PACK_ROOT}/normalized-scale/resources.table.txt",
            ).decode("utf-8")
            scenario = json.loads(
                _member_bytes(
                    node,
                    f"{NODE_PACK_ROOT}/normalized-scale/scenario.json",
                )
            )
            unpacked_content = b"\n".join(
                _member_bytes(node, member.name)
                for member in node.getmembers()
                if member.isfile()
            )

        authored = [
            event
            for event in events
            if event.get("phase") == "authored_history"
        ]
        self.assertEqual(
            {
                event["event_uid"].rsplit("/", 1)[-1]
                for event in authored
            },
            {
                item.event_id
                for item in source.observations_by_node["node-a"]
            },
        )
        self.assertEqual(
            scenario["source_scenario"]["sha256"],
            source.sha256,
        )
        self.assertEqual(
            int(scenario["scale"]["events"]),
            self.config.events_per_node + len(authored),
        )
        for resource in source.resources_at("node-a"):
            self.assertIn(
                _source_resource_id(
                    "node-a",
                    resource.resource_type,
                    resource.resource_id,
                ),
                resources,
            )
        for change in source.physical_changes:
            self.assertNotIn(
                change.medium_id.encode("utf-8"),
                unpacked_content,
            )

    def test_topology_projection_replays_only_node_local_observations(
        self,
    ) -> None:
        source = generator_catalog.DEFAULT_SCENARIO_SOURCE
        p1 = next(
            node for node in DEMO_NODES if node.node_id == "transit-p-1"
        )
        projection = _topology_projection(p1, config=AssemblyConfig())
        interface = next(
            item
            for item in projection["resources"]
            if item["resource_id"].endswith(
                "/VIRTUAL_INTERFACE/interface:Ethernet3/1"
            )
        )
        self.assertEqual(
            [
                (
                    int(item["time_ns"]) - source.base_time_ns,
                    item["status"],
                    item["state_changed"],
                )
                for item in interface["changes"]
            ],
            [
                (90_050_000_000, "down", True),
                (240_100_000_000, "up", True),
            ],
        )
        for claim in projection["claims"]:
            self.assertNotIn("participants", claim.get("subnet", {}))
            self.assertNotIn("participant_count", claim.get("subnet", {}))
        encoded = json.dumps(projection, sort_keys=True)
        for change in source.physical_changes:
            self.assertNotIn(change.medium_id, encoded)

    def test_saved_failed_update_uses_normalized_demo_outcome(self) -> None:
        node_b = next(node for node in DEMO_NODES if node.node_id == "node-b")
        events = [json.loads(line) for line in _source_event_rows(node_b)]
        failed = next(
            item
            for item in events
            if item["event_uid"].endswith(
                "/node-b-failed-next-hop-update"
            )
        )
        self.assertEqual(failed["outcome"], "failure")
        self.assertFalse(failed["state_changed"])
        self.assertEqual(failed["properties"]["source_outcome"], "failed")
        self.assertNotEqual(failed["result"]["updateStatus"], "Ok")

    def test_resource_event_and_projection_evidence_share_node_namespace(
        self,
    ) -> None:
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        with tarfile.open(fileobj=io.BytesIO(node_bytes), mode="r:gz") as node:
            event = json.loads(
                _member_bytes(
                    node,
                    f"{NODE_PACK_ROOT}/normalized-scale/events.jsonl",
                ).splitlines()[0]
            )
            table_lines = _member_bytes(
                node,
                f"{NODE_PACK_ROOT}/normalized-scale/resources.table.txt",
            ).decode("utf-8").splitlines()
            routes = [
                json.loads(line)
                for line in _member_bytes(
                    node,
                    (
                        f"{NODE_PACK_ROOT}/plugin-projection/"
                        "routes.jsonl"
                    ),
                ).splitlines()
                if line.strip()
            ]
        header = table_lines[0].split("|")
        resource_index = header.index("RESOURCE_ID")
        resources = {
            line.split("|")[resource_index] for line in table_lines[1:]
        }
        self.assertTrue(event["event_uid"].startswith("node-a/"))
        self.assertTrue(event["resource_id"].startswith("node-a/"))
        self.assertTrue(all(item.startswith("node-a/") for item in resources))
        self.assertTrue(routes)
        for route in routes:
            self.assertTrue(route["route_id"].startswith("node-a/"))
            self.assertTrue(
                set(route["evidence_resource_ids"]).issubset(resources)
            )

    def test_node_pack_remains_compatible_with_scale_dataset_loader(self) -> None:
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        node_path = self.root / "node-a-loader.tgz"
        node_path.write_bytes(node_bytes)
        cache = self.root / "search-cache"
        with mock.patch.dict(
            os.environ,
            {"ROUTER_DUMP_SEARCH_CACHE_DIR": str(cache)},
        ):
            dataset = load_scale_dataset(
                node_path,
                revision_id="demo/node-a/revision-0001",
                gaps=[],
                review_prompts=[],
            )
        source = generator_catalog.DEFAULT_SCENARIO_SOURCE
        self.assertEqual(
            dataset["demo"]["event_count"],
            120 + len(source.observations_by_node["node-a"]),
        )
        self.assertEqual(
            dataset["demo"]["resource_count"],
            120 + len(source.resources_at("node-a")),
        )
        self.assertTrue(
            all(
                identifier.startswith("node-a/")
                for identifier in dataset["_scale_runtime"].resource_by_id
            )
        )

    def test_scale_loader_reports_real_parse_and_index_stages(self) -> None:
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        node_path = self.root / "node-a-progress.tgz"
        node_path.write_bytes(node_bytes)
        with (
            mock.patch.dict(
                os.environ,
                {"ROUTER_DUMP_SEARCH_CACHE_DIR": str(self.root / "progress-cache")},
            ),
            mock.patch("rsl_demo_plugin.scale_data.report_analysis_load") as report,
        ):
            dataset = load_scale_dataset(
                node_path,
                revision_id="demo/node-a/revision-0001",
                gaps=[],
                review_prompts=[],
            )

        stages = [call.args[0] for call in report.call_args_list]
        self.assertIn(AnalysisLoadStage.PARSING, stages)
        self.assertIn(AnalysisLoadStage.NORMALIZING, stages)
        self.assertIn(AnalysisLoadStage.INDEXING, stages)
        determinate = [
            call
            for call in report.call_args_list
            if call.args == (AnalysisLoadStage.PARSING,)
            and call.kwargs.get("total") is not None
        ]
        self.assertTrue(determinate)
        expected_total = (
            dataset["demo"]["packed_event_count"]
            + dataset["demo"]["packed_resource_count"]
            + dataset["demo"]["relationship_count"]
            + dataset["demo"]["relationship_mutation_count"]
        )
        self.assertEqual(determinate[-1].kwargs["completed"], expected_total)
        self.assertEqual(determinate[-1].kwargs["total"], expected_total)

    def test_scale_loader_rejects_manifest_record_count_mismatch(self) -> None:
        with tarfile.open(self.first, mode="r:gz") as outer:
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        source_path = self.root / "node-a-count-source.tgz"
        source_path.write_bytes(node_bytes)
        members = _outer_members(source_path)
        manifest_name = f"{NODE_PACK_ROOT}/normalized-scale/manifest.json"
        manifest = json.loads(members[manifest_name])
        manifest["resources"]["records"] += 1
        members[manifest_name] = _json_bytes(manifest)
        mismatched = self.root / "node-a-count-mismatch.tgz"
        _write_outer_members(mismatched, members)

        with (
            mock.patch.dict(
                os.environ,
                {"ROUTER_DUMP_SEARCH_CACHE_DIR": str(self.root / "count-cache")},
            ),
            self.assertRaisesRegex(RuntimeError, "record counts do not match"),
        ):
            load_scale_dataset(
                mismatched,
                revision_id="demo/node-a/revision-0001",
                gaps=[],
                review_prompts=[],
            )

    def test_full_scale_policy_rejects_developer_counts(self) -> None:
        with self.assertRaisesRegex(ValueError, "state-changing events"):
            AssemblyConfig(
                events_per_node=1_000,
                resources_per_node=7_500,
            )
        with self.assertRaisesRegex(ValueError, "between"):
            AssemblyConfig(
                events_per_node=1_250_000,
                resources_per_node=4_999,
            )

    def test_default_catalog_advertises_complete_full_scale_coverage(self) -> None:
        config = AssemblyConfig()
        coverage = build_coverage(config)
        self.assertTrue(config.full_scale)
        self.assertTrue(coverage["complete"])
        self.assertTrue(all(item["generated"] for item in coverage["cases"]))
        self.assertEqual(
            {item["case_id"] for item in coverage["cases"]},
            {item.case_id for item in COVERAGE_CASES},
        )

    def test_typed_next_hop_endpoint_pair_survives_plugin_validation(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            seed=12345,
            allow_small=True,
        )
        node = next(
            item for item in DEMO_NODES if item.node_id == "transit-p-1"
        )
        forwarding_rows = _projection_rows(node, config=config)[1]
        row, next_hop = next(
            (row, next_hop)
            for row in forwarding_rows
            if isinstance(row.get("continuation"), dict)
            if (next_hop := row["continuation"].get("next_hop"))
            is not None
            and next_hop.get("node_id") == "transit-p-2"
            and any(
                reference.get("reference_kind")
                == "typed_inter_node_link"
                for reference in next_hop["topology_references"]
            )
        )

        GENERATED_PROJECTION_POLICY.validate_forwarding_row(
            row,
            node_id=node.node_id,
            revision_id=node.revision_id,
        )

        self.assertEqual(
            [
                reference["reference_kind"]
                for reference in next_hop["topology_references"]
            ],
            ["connectivity_domain", "typed_inter_node_link"],
        )
        typed_reference = next_hop["topology_references"][1]
        self.assertNotIn("link_id", typed_reference)
        self.assertEqual(
            typed_reference["source_endpoint"]["resource_id"],
            next_hop["interface_resource_id"],
        )
        self.assertEqual(
            typed_reference["target_endpoint"]["resource_id"],
            next_hop["remote_interface_resource_id"],
        )
        self.assertEqual(
            typed_reference["source_endpoint"]["typed_resource_key"][
                "node"
            ],
            "transit-p-1",
        )
        self.assertEqual(
            typed_reference["target_endpoint"]["typed_resource_key"][
                "node"
            ],
            "transit-p-2",
        )

    def test_every_route_case_has_complete_directional_candidate_evidence(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            seed=12345,
            allow_small=True,
        )
        coverage_by_id = {
            item["case_id"]: item
            for item in build_coverage(config)["cases"]
        }
        forwarding_by_node = {
            node.node_id: {
                row["scenario_id"]: row
                for row in _projection_rows(node, config=config)[1]
                if row["scenario_id"] is not None
            }
            for node in DEMO_NODES
        }
        adjacent_pairs = {
            frozenset((source, target))
            for link in DEMO_LINKS
            for source in link.participants
            for target in link.participants
            if source != target
        }
        known_node_ids = {node.node_id for node in DEMO_NODES}

        for case in COVERAGE_CASES:
            if "route_resolution" not in case.required_capabilities:
                continue
            with self.subTest(case_id=case.case_id):
                candidates = _case_candidate_paths(case)
                self.assertTrue(candidates)
                self.assertEqual(
                    {item["direction"] for item in candidates},
                    {"forward", "reverse"},
                )
                candidate_by_id = {
                    item["candidate_id"]: item for item in candidates
                }
                self.assertEqual(len(candidate_by_id), len(candidates))
                path_node_ids = list(
                    dict.fromkeys(
                        node_id
                        for candidate in candidates
                        for node_id in candidate["node_sequence"]
                    )
                )
                path_node_set = set(path_node_ids)
                self.assertEqual(
                    [
                        item["node_id"]
                        for item in coverage_by_id[case.case_id][
                            "evidence_refs"
                        ]
                    ],
                    [
                        *(
                            node_id
                            for node_id in coverage_by_id[case.case_id][
                                "involved_nodes"
                            ]
                            if node_id in path_node_set
                        ),
                        *(
                            node_id
                            for node_id in path_node_ids
                            if node_id
                            not in coverage_by_id[case.case_id][
                                "involved_nodes"
                            ]
                        ),
                    ],
                )
                self.assertTrue(
                    set(path_node_ids).issubset(
                        coverage_by_id[case.case_id]["involved_nodes"]
                    )
                )
                for candidate in candidates:
                    sequence = candidate["node_sequence"]
                    self.assertTrue(sequence)
                    self.assertEqual(
                        sequence[0],
                        (
                            (
                                coverage_by_id[case.case_id].get(
                                    "trace_start_node"
                                )
                                or case.source_node
                            )
                            if candidate["direction"] == "forward"
                            else case.destination_node
                        ),
                    )
                    self.assertTrue(set(sequence).issubset(known_node_ids))
                    for source, target in zip(sequence, sequence[1:]):
                        if source != target:
                            self.assertIn(
                                frozenset((source, target)),
                                adjacent_pairs,
                            )

                for node_id in path_node_ids:
                    row = forwarding_by_node[node_id][case.case_id]
                    expected_occurrences = {
                        (
                            candidate["candidate_id"],
                            visit_index,
                            (
                                candidate["node_sequence"][visit_index + 1]
                                if visit_index + 1
                                < len(candidate["node_sequence"])
                                else None
                            ),
                        )
                        for candidate in candidates
                        for visit_index, candidate_node_id in enumerate(
                            candidate["node_sequence"]
                        )
                        if candidate_node_id == node_id
                    }
                    actual_occurrences = set()
                    for direction, decisions in row[
                        "directional_decisions"
                    ].items():
                        for decision in decisions:
                            candidate = candidate_by_id[
                                decision["candidate_id"]
                            ]
                            self.assertEqual(
                                candidate["direction"],
                                direction,
                            )
                            self.assertEqual(
                                decision["selected_active"],
                                candidate["selected_active"],
                            )
                            self.assertEqual(
                                decision["primary"],
                                candidate["primary"],
                            )
                            self.assertEqual(
                                decision["alternative_state"],
                                candidate["alternative_state"],
                            )
                            self.assertTrue(decision["state"])
                            self.assertTrue(decision["disposition"])
                            self.assertTrue(decision["resolution_text"])
                            next_node_id = decision["next_node_id"]
                            next_hop = decision["next_hop"]
                            if (
                                next_node_id is not None
                                and next_node_id != node_id
                            ):
                                self.assertEqual(
                                    next_hop["node_id"],
                                    next_node_id,
                                )
                                reference_kinds = [
                                    item["reference_kind"]
                                    for item in next_hop[
                                        "topology_references"
                                    ]
                                ]
                                self.assertEqual(
                                    reference_kinds.count(
                                        "connectivity_domain"
                                    ),
                                    1,
                                )
                                self.assertLessEqual(
                                    reference_kinds.count(
                                        "typed_inter_node_link"
                                    ),
                                    1,
                                )
                                self.assertEqual(
                                    len(reference_kinds),
                                    1
                                    + reference_kinds.count(
                                        "typed_inter_node_link"
                                    ),
                                )
                            else:
                                self.assertIsNone(next_hop)
                            actual_occurrences.add(
                                (
                                    decision["candidate_id"],
                                    decision["visit_index"],
                                    next_node_id,
                                )
                            )
                    self.assertEqual(
                        actual_occurrences,
                        expected_occurrences,
                    )

    def test_every_non_route_case_has_exact_generated_evidence(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            seed=12345,
            allow_small=True,
        )
        cases_by_id = {
            item["case_id"]: item
            for item in build_coverage(config)["cases"]
        }
        nodes_by_id = {node.node_id: node for node in DEMO_NODES}
        topology_claims = {
            claim["claim_id"]: claim
            for node in DEMO_NODES
            for claim in _topology_projection(
                node,
                config=config,
            )["claims"]
        }
        layout = scale_generator._layout(config.resources_per_node)
        raw_events = {
            event["event_uid"]: event
            for event in (
                json.loads(line)
                for line in scale_generator._event_lines(
                    config.events_per_node,
                    layout,
                )
            )
        }
        expected_topology_references = {
            "topology-shared-subnet-multiaccess": {
                "core-west-multi-access",
            },
            "topology-point-to-point-collapse": {"p1-p2-sr"},
            "topology-vlan-lag-subinterface": {
                "core-west-multi-access",
                "core-east-multi-access",
                "pe-c-transit",
            },
            "topology-external-management-loopback-vpn": {
                "ottawa-external",
                "management",
                "loopback",
                "blue-l3vpn",
                "red-l3vpn",
                "blue-evpn",
            },
        }
        expected_temporal_events = {
            "temporal-single-home-to-multihome": {
                (
                    "single_home_create",
                    "evpn_single_home_service_create",
                ),
                (
                    "multihome_add",
                    "evpn_multihome_attachment_add",
                ),
            },
            "temporal-mass-es-withdraw": {
                ("mass_es_withdraw", "evpn_es_mass_withdraw"),
            },
            "temporal-mass-es-restore": {
                ("mass_es_restore", "evpn_es_mass_restore"),
            },
            "temporal-next-hop-churn": {
                ("next_hop_churn", "dte_next_hop_dependency_change"),
            },
            "temporal-cross-layer-lag": {
                ("next_hop_churn", "dte_next_hop_dependency_change"),
            },
        }

        non_route_cases = [
            case
            for case in COVERAGE_CASES
            if "route_resolution" not in case.required_capabilities
        ]
        self.assertTrue(non_route_cases)
        self.assertEqual(
            {case.category for case in non_route_cases},
            {"topology", "temporal"},
        )
        for spec in non_route_cases:
            with self.subTest(case_id=spec.case_id):
                materialized = cases_by_id[spec.case_id]
                self.assertTrue(materialized["generated"])
                self.assertEqual(materialized["missing_evidence"], [])
                self.assertTrue(materialized["evidence_refs"])
                self.assertTrue(
                    all(
                        "route_id" not in item
                        and "forwarding_id" not in item
                        for item in materialized["evidence_refs"]
                    )
                )
                if spec.category == "topology":
                    self.assertTrue(spec.topology_evidence)
                    self.assertFalse(spec.temporal_evidence)
                    self.assertEqual(
                        {
                            item["reference_id"]
                            for item in materialized["evidence_refs"]
                        },
                        expected_topology_references[spec.case_id],
                    )
                    for item in materialized["evidence_refs"]:
                        self.assertEqual(
                            item["evidence_kind"],
                            "topology_claim",
                        )
                        self.assertNotIn("event_uid", item)
                        claim = topology_claims[
                            item["topology_claim_id"]
                        ]
                        self.assertEqual(
                            item["resource_id"],
                            claim["interface_resource_id"],
                        )
                        self.assertEqual(
                            item["segment_key"],
                            claim["segment_key"],
                        )
                        self.assertEqual(
                            item["matcher_id"],
                            claim["matcher_id"],
                        )
                        self.assertEqual(
                            item["classification"],
                            claim["subnet"]["classification"],
                        )
                        self.assertEqual(
                            item["attachment_kind"],
                            claim["attachment_kind"],
                        )
                        self.assertEqual(
                            item["calculation"],
                            claim["calculation"],
                        )
                else:
                    self.assertTrue(spec.temporal_evidence)
                    self.assertFalse(spec.topology_evidence)
                    self.assertEqual(
                        {
                            (item["phase"], item["event_name"])
                            for item in materialized["evidence_refs"]
                        },
                        expected_temporal_events[spec.case_id],
                    )
                    for item in materialized["evidence_refs"]:
                        self.assertEqual(
                            item["evidence_kind"],
                            "temporal_event",
                        )
                        raw_uid = item["event_uid"].split("/", 1)[1]
                        actual = _transform_value(
                            raw_events[raw_uid],
                            node=nodes_by_id[item["node_id"]],
                        )
                        for field in (
                            "resource_id",
                            "event_uid",
                            "event_name",
                            "phase",
                            "timestamp_ns",
                            "resource_kind",
                            "action",
                            "outcome",
                            "state_changed",
                        ):
                            self.assertEqual(item[field], actual[field])

        failed_update = cases_by_id[
            "temporal-cross-layer-lag"
        ]["evidence_refs"]
        self.assertTrue(
            all(
                item["outcome"] == "failure"
                and item["state_changed"] is False
                for item in failed_update
            )
        )

    def test_special_reverse_and_counterfactual_candidates_are_declared(
        self,
    ) -> None:
        candidates_by_id = {
            case.case_id: _case_candidate_paths(case)
            for case in COVERAGE_CASES
            if "route_resolution" in case.required_capabilities
        }
        expected_reverse_sequences = {
            "cross-layer-inconsistent": {
                ("node-b", "transit-p-1", "node-a"),
                ("node-b", "transit-p-2", "node-a"),
            },
            "evpn-mh-all-active": {
                ("node-e", "transit-p-1", "node-a"),
                ("node-e", "transit-p-2", "node-a"),
            },
            "evpn-stale-fib-after-withdraw": {
                ("node-e", "transit-p-1", "node-a"),
                ("node-e", "transit-p-2", "node-a"),
            },
            "srv6-all-active": {
                ("node-e", "transit-p-1", "node-a"),
                ("node-e", "transit-p-2", "node-a"),
            },
            "recursive-resolution-cycle": {
                ("node-b", "node-b", "node-b"),
            },
            "cross-node-forwarding-loop": {
                ("node-b", "transit-p-2", "node-a", "transit-p-2"),
            },
        }
        for case_id, expected in expected_reverse_sequences.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    {
                        tuple(item["node_sequence"])
                        for item in candidates_by_id[case_id]
                        if item["direction"] == "reverse"
                    },
                    expected,
                )

        one_way_reverse = [
            item
            for item in candidates_by_id["site-b-site-c-one-way"]
            if item["direction"] == "reverse"
        ]
        self.assertEqual(
            {
                (
                    tuple(item["node_sequence"]),
                    tuple(item["resolution_modes"]),
                    item.get("inferred", False),
                )
                for item in one_way_reverse
            },
            {
                (
                    ("node-c", "transit-p-2"),
                    ("strict", "best_effort"),
                    False,
                ),
                (
                    ("node-c", "transit-p-2", "transit-p-1", "node-b"),
                    ("best_effort",),
                    True,
                ),
            },
        )

        forced = candidates_by_id["packet-forced-steering"]
        self.assertEqual(
            {
                (
                    item["direction"],
                    item["steering_profile_id"],
                    tuple(item["node_sequence"]),
                    item["selected_active"],
                    item["counterfactual"],
                )
                for item in forced
            },
            {
                (
                    "forward",
                    "observed",
                    ("node-a", "transit-p-1", "transit-p-2", "node-b"),
                    True,
                    False,
                ),
                (
                    "forward",
                    "force-alternate-p2",
                    ("node-a", "transit-p-2", "node-b"),
                    False,
                    True,
                ),
                (
                    "reverse",
                    "observed",
                    ("node-b", "transit-p-2", "transit-p-1", "node-a"),
                    True,
                    False,
                ),
                (
                    "reverse",
                    "force-alternate-p2",
                    ("node-b", "transit-p-2", "node-a"),
                    False,
                    True,
                ),
            },
        )

    def test_directional_dispositions_do_not_leak_between_paths(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        rows = {
            (node.node_id, row["scenario_id"]): row
            for node in DEMO_NODES
            for row in _projection_rows(node, config=config)[1]
            if row["scenario_id"] is not None
        }
        p2_one_way = rows[
            ("transit-p-2", "site-b-site-c-one-way")
        ]["directional_decisions"]
        self.assertEqual(
            {
                item["disposition"]
                for item in p2_one_way["forward"]
            },
            {"forward"},
        )
        self.assertEqual(
            {
                (
                    item["alternative_state"],
                    item["disposition"],
                )
                for item in p2_one_way["reverse"]
            },
            {
                ("selected_primary", "drop"),
                ("best_effort_possible", "best_effort_inferred"),
            },
        )
        self.assertEqual(
            rows[("node-a", "packet-mtu-drop")]["disposition"],
            "forward",
        )
        self.assertEqual(
            rows[
                ("transit-p-2", "incomplete-intermediate-resolution")
            ]["directional_decisions"]["forward"][0]["disposition"],
            "unresolved",
        )

    def test_route_and_packet_semantics_have_one_plugin_owned_registry(
        self,
    ) -> None:
        self.assertIs(DEMO_ROUTE_POLICY.scenarios, SCENARIO_BY_ID)
        self.assertIs(
            ADVANCED_TRACE_SCENARIOS,
            PACKET_TRACE_SCENARIOS,
        )
        self.assertEqual(
            {
                case.case_id
                for case in COVERAGE_CASES
                if case.category in {"route", "packet"}
            },
            set(SCENARIO_BY_ID),
        )
        for case in COVERAGE_CASES:
            if case.category not in {"route", "packet"}:
                continue
            with self.subTest(case_id=case.case_id):
                scenario = SCENARIO_BY_ID[case.case_id]
                forward = scenario.get(
                    "directional_routing_contexts",
                    {},
                ).get("forward", scenario)
                self.assertEqual(case.route_type, forward["route_type"])
                self.assertEqual(case.route_family, forward["route_family"])
                self.assertEqual(
                    case.address_family,
                    forward["address_family"],
                )
                self.assertEqual(case.vrf, forward["vrf_id"])
        with self.assertRaisesRegex(
            ValueError,
            "routing context must come from scenario_registry",
        ):
            generator_catalog._case(
                "single-active-primary",
                "Duplicate semantic declaration",
                route_type="mpls_transport",
            )

    def test_generated_route_inventory_preserves_all_declared_contexts(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        rows = [
            row
            for node in DEMO_NODES
            for row in _projection_rows(node, config=config)[0]
        ]
        inventory = [
            row for row in rows if row.get("inventory_context_id")
        ]
        resolved_contexts = {
            str(context["context_id"]): context
            for node in DEMO_NODES
            for context in generator_catalog.route_inventory_contexts_for_node(
                node.node_id
            )
        }
        expected_pairs = {
            (
                context_id,
                source_node_id,
                destination_node_id,
            )
            for context_id, context in resolved_contexts.items()
            for source_node_id in context["eligible_node_ids"]
            for destination_node_id in context["eligible_node_ids"]
            if source_node_id != destination_node_id
        }
        actual_pairs = {
            (
                str(row["inventory_context_id"]),
                str(row["node_id"]),
                str(row["destination_node_id"]),
            )
            for row in inventory
            if not str(row["inventory_context_id"]).startswith("retained:")
        }
        self.assertEqual(actual_pairs, expected_pairs)
        self.assertGreaterEqual(len(rows), 180)
        self.assertEqual(
            {row["route_type"] for row in rows},
            set(ROUTE_PROTOCOL_BY_TYPE),
        )
        self.assertEqual(
            {row["vrf"] for row in rows},
            {"default", "blue", "red", "management"},
        )
        self.assertTrue(
            {
                "isis_underlay",
                "evpn_ip_prefix",
            }
            <= {row["route_type"] for row in inventory}
        )
        self.assertTrue(
            any(
                row["route_type"] == "evpn_ip_prefix"
                and row["node_id"].startswith("transit-")
                and row["install_state"] == "control_plane_only"
                and not row["forwarding_capable"]
                for row in inventory
            )
        )
        self.assertTrue(
            any(
                row["backup"]
                and row["install_state"] == "eligible_not_installed"
                and row["trace_scenario_id"] == "single-active-primary"
                for row in inventory
            )
        )
        for row in inventory:
            self.assertIn("trace_query", row)
            self.assertIn("counterpart_trace_query", row)
            self.assertIn("node_sequence", row)
            self.assertNotIn("continuation_evidence", row)
            self.assertNotIn("counterpart_evidence", row)

    def test_generated_route_actions_bind_to_exact_topology_resources(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        topology_resources = {
            node.node_id: {
                item["resource_id"]
                for item in _topology_projection(
                    node,
                    config=config,
                )["resources"]
            }
            for node in DEMO_NODES
        }
        routes = [
            row
            for node in DEMO_NODES
            for row in _projection_rows(node, config=config)[0]
        ]
        actions_by_type = {}
        for row in routes:
            for next_hop in row.get("candidate_next_hops", []):
                self.assertIn(
                    next_hop["interface_resource_id"],
                    topology_resources[row["node_id"]],
                )
                self.assertIn(
                    next_hop["adjacency_resource_id"],
                    topology_resources[row["node_id"]],
                )
                self.assertIn(
                    next_hop["remote_interface_resource_id"],
                    topology_resources[next_hop["node_id"]],
                )
                self.assertIn(
                    next_hop["remote_adjacency_resource_id"],
                    topology_resources[next_hop["node_id"]],
                )
                self.assertEqual(
                    next_hop["interface_endpoint"]["resource_id"],
                    next_hop["interface_resource_id"],
                )
                self.assertEqual(
                    next_hop["adjacency_endpoint"]["resource_id"],
                    next_hop["adjacency_resource_id"],
                )
            if row.get("forwarding_actions"):
                actions_by_type.setdefault(
                    row["route_type"],
                    row["forwarding_actions"][0],
                )
                next_hop_ids = {
                    item["next_hop_id"]
                    for item in row["candidate_next_hops"]
                }
                self.assertIn(
                    row["forwarding_actions"][0][
                        "applies_to_next_hop_id"
                    ],
                    next_hop_ids,
                )
        self.assertEqual(
            [
                item["kind"]
                for item in actions_by_type["mpls_l3vpn"]["values"]
            ],
            ["sr_mpls_sid", "mpls_label"],
        )
        self.assertEqual(
            actions_by_type["mpls_transport"]["kind"],
            "mpls_label_stack",
        )
        self.assertEqual(
            actions_by_type["srv6_policy"]["kind"],
            "srv6_sid_list",
        )

    def test_generated_forwarding_evidence_keeps_semantic_reason_codes(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        forwarding = [
            row
            for node in DEMO_NODES
            for row in _projection_rows(node, config=config)[1]
            if row.get("scenario_id")
        ]
        reasons = {
            decision["reason_code"]
            for row in forwarding
            for decisions in row["directional_decisions"].values()
            for decision in decisions
        }
        self.assertTrue(
            {
                "forwarding_loop",
                "recursive_resolution_cycle",
                "split_horizon_same_scope",
                "evpn_es_withdrawn",
                "stale_fib_to_withdrawn_es",
            }
            <= reasons
        )
        for row in forwarding:
            self.assertIn("reason_code", row)
            self.assertEqual(
                set(row["directional_route_contexts"]),
                {"forward", "reverse"},
            )
            self.assertNotIn("counterpart_evidence", row)
        self.assertTrue(
            any(
                row["directional_decisions"]["reverse"]
                for row in forwarding
            )
        )

    def test_every_traceable_generated_row_owns_an_exact_executable_path(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        projected = {
            node.node_id: _projection_rows(node, config=config)
            for node in DEMO_NODES
        }
        rows = [
            row
            for routes, _ in projected.values()
            for row in routes
        ]
        coverage = {
            item["case_id"]: item
            for item in build_coverage(config)["cases"]
        }
        declared_paths = {
            path["path_id"]
            for case in coverage.values()
            for path in case["candidate_paths"]
        }
        cases_by_id = {
            item.case_id: item for item in COVERAGE_CASES
        }
        for row in rows:
            with self.subTest(route_id=row["route_id"]):
                if row["traceable"]:
                    self.assertTrue(row["table_visible"])
                    self.assertTrue(row["trace_query"])
                    self.assertEqual(
                        row["trace_query"]["focus_path_id"],
                        row["path_id"],
                    )
                    scenario_id = (
                        row.get("scenario_id")
                        or row.get("trace_scenario_id")
                    )
                    if row["path_id"] in declared_paths:
                        case = cases_by_id[scenario_id]
                        self.assertEqual(
                            row["trace_query"]["source"]["node_id"],
                            case.source_node,
                        )
                        self.assertEqual(
                            row["trace_query"]["destination"]["node_id"],
                            case.destination_node,
                        )
                    elif not row["trace_query"].get("starting_point"):
                        self.assertEqual(
                            row["trace_query"]["source"]["node_id"],
                            row["node_sequence"][0],
                        )
                    candidate = next(
                        (
                            path
                            for case in coverage.values()
                            for path in case["candidate_paths"]
                            if path["path_id"] == row["path_id"]
                        ),
                        None,
                    )
                    if (
                        candidate is not None
                        and candidate.get("steering_profile_id")
                        not in {None, "observed"}
                    ):
                        self.assertEqual(
                            row["trace_query"].get(
                                "steering_profile_id"
                            ),
                            candidate["steering_profile_id"],
                        )
                    if row.get("trace_scenario_id") not in {
                        None,
                        "router-to-router",
                    } or row.get("scenario_id"):
                        self.assertIn(row["path_id"], declared_paths)
                else:
                    self.assertFalse(row["table_visible"])
                    self.assertEqual(row["trace_query"], {})

    def test_inventory_routes_have_one_exact_non_table_continuation_per_visit(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        projected = {
            node.node_id: _projection_rows(node, config=config)
            for node in DEMO_NODES
        }
        inventory = [
            row
            for routes, _ in projected.values()
            for row in routes
            if row.get("inventory_context_id")
            and not str(row["inventory_context_id"]).startswith(
                "retained:"
            )
        ]
        continuations_by_route: dict[str, list[dict[str, object]]] = {}
        for _, forwarding in projected.values():
            for row in forwarding:
                if (
                    row.get("coverage_category")
                    != "inventory_continuation"
                ):
                    continue
                continuations_by_route.setdefault(
                    row["route_id"],
                    [],
                ).append(row)
                self.assertFalse(row["traceable"])
                self.assertFalse(row["table_visible"])
        for route in inventory:
            with self.subTest(route_id=route["route_id"]):
                continuations = sorted(
                    continuations_by_route[route["route_id"]],
                    key=lambda item: item["continuation"][
                        "visit_index"
                    ],
                )
                self.assertEqual(
                    len(continuations),
                    len(route["node_sequence"]),
                )
                self.assertEqual(
                    [
                        item["continuation"]["node_id"]
                        for item in continuations
                    ],
                    route["node_sequence"],
                )
                for index, item in enumerate(continuations):
                    continuation = item["continuation"]
                    self.assertEqual(
                        continuation["path_id"],
                        route["path_id"],
                    )
                    if index + 1 < len(continuations):
                        self.assertEqual(
                            continuation["next_node_id"],
                            route["node_sequence"][index + 1],
                        )
                        self.assertIsNotNone(
                            continuation["next_hop"]
                        )
                    else:
                        self.assertIsNone(
                            continuation["next_node_id"]
                        )
                        self.assertIsNone(
                            continuation["next_hop"]
                        )

    def test_generated_inventory_keeps_local_connected_and_policy_paths_exact(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        rows = [
            row
            for node in DEMO_NODES
            for row in _projection_rows(node, config=config)[0]
        ]
        connected = [
            row for row in rows if row["route_type"] == "connected"
        ]
        self.assertEqual(len(connected), 1)
        self.assertEqual(connected[0]["node_id"], "node-e")
        self.assertEqual(connected[0]["node_sequence"], ["node-e"])
        self.assertEqual(connected[0]["candidate_next_hops"], [])
        self.assertEqual(
            connected[0]["connected_attachment"]["classification"],
            "external",
        )
        selected = next(
            row
            for row in rows
            if row["node_id"] == "node-c"
            and row.get("scenario_id")
            == "site-a-site-c-asymmetric"
        )
        standby = next(
            row
            for row in rows
            if row["node_id"] == "node-c"
            and row.get("backup")
            and row.get("trace_scenario_id")
            == "site-a-site-c-asymmetric"
        )
        self.assertEqual(selected["route_type"], "mpls_transport")
        self.assertEqual(selected["vrf"], "default")
        self.assertEqual(
            selected["node_sequence"],
            ["node-c", "transit-p-2", "transit-p-1", "node-a"],
        )
        self.assertEqual(
            standby["node_sequence"],
            ["node-c", "transit-p-2", "node-a"],
        )
        contexts = {
            (row["vrf"], row["route_family"], row["route_type"])
            for row in rows
            if row.get("inventory_context_id")
        }
        self.assertIn(
            ("default", "ipv6_unicast", "srv6_policy"),
            contexts,
        )
        self.assertIn(
            ("blue", "mpls_labeled_unicast", "mpls_transport"),
            contexts,
        )
        evpn_vteps = {
            row["destination_node_id"]: row["remote_vtep"]
            for row in rows
            if row["route_type"] == "evpn_ip_prefix"
            and row.get("remote_vtep")
        }
        self.assertEqual(
            len(set(evpn_vteps.values())),
            len(evpn_vteps),
        )
        self.assertTrue(
            all(
                row["segment_list"]
                for row in rows
                if row["route_type"] == "srv6_policy"
            )
        )

    def test_coverage_candidates_own_presentation_cycles_and_findings(
        self,
    ) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        coverage = {
            item["case_id"]: item
            for item in build_coverage(config)["cases"]
        }
        all_path_ids = []
        for case in coverage.values():
            for candidate in case["candidate_paths"]:
                all_path_ids.append(candidate["path_id"])
                for field in (
                    "label",
                    "perspective",
                    "forwarding_capable",
                    "encapsulation",
                    "route_context",
                    "protocol",
                    "traversal_states",
                    "terminal_semantics",
                ):
                    self.assertIn(field, candidate)
                self.assertEqual(
                    len(candidate["traversal_states"]),
                    len(candidate["node_sequence"]),
                )
        self.assertEqual(len(all_path_ids), len(set(all_path_ids)))
        repeated = coverage["cross-node-forwarding-loop"][
            "candidate_paths"
        ][0]["traversal_states"]
        self.assertTrue(any(item["repeated"] for item in repeated))
        for case_id in (
            "cross-layer-inconsistent",
            "evpn-stale-fib-after-withdraw",
        ):
            findings = coverage[case_id]["consistency_findings"]
            self.assertTrue(findings)
            self.assertTrue(findings[0]["candidate_ids"])
            self.assertTrue(findings[0]["path_ids"])

    def test_generator_node_catalog_is_not_duplicated_at_runtime(
        self,
    ) -> None:
        for duplicate_catalog in (
            "_ROUTERS",
            "_BOUNDARIES",
            "_ROUTE_PLUGIN_BY_NODE",
            "_ROUTE_TABLE_CONTEXTS",
            "_ROUTE_TABLE_REPRESENTATIVE_CONTEXTS",
        ):
            with self.subTest(duplicate_catalog=duplicate_catalog):
                self.assertFalse(
                    hasattr(multi_node_route, duplicate_catalog)
                )
        self.assertEqual(
            len({item.node_id for item in DEMO_NODES}),
            len(DEMO_NODES),
        )

    def test_generator_refuses_to_replace_an_unowned_file(self) -> None:
        output = self.root / "unowned.tgz"
        output.write_bytes(b"user data")
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            build_demo_fixture(output, config=self.config)
        self.assertEqual(output.read_bytes(), b"user data")

    def test_generator_requires_exact_bounded_owner_identity(self) -> None:
        mutations = (
            lambda manifest: manifest.__setitem__(
                "generator",
                "lookalike-generator",
            ),
            lambda manifest: manifest.__setitem__(
                "format_version",
                ASSEMBLY_FORMAT_VERSION + 1,
            ),
            lambda manifest: manifest.__setitem__(
                "assembly_id",
                "customer-assembly",
            ),
            lambda manifest: manifest["plugin"].__setitem__(
                "plugin_id",
                "customer.plugin",
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                output = self.root / f"weak-owner-{index}.tgz"
                members = _launch_ready_outer_members()
                _rewrite_launch_manifest(members, mutate)
                _write_outer_members(output, members)
                original = output.read_bytes()

                with self.assertRaisesRegex(RuntimeError, "unowned"):
                    build_demo_fixture(output, config=self.config)

                self.assertEqual(output.read_bytes(), original)

    def test_generate_cli_reuses_its_internal_validation_report(self) -> None:
        from rsl_demo_generator import __main__ as generator_cli
        from rsl_demo_generator import assembly

        output = self.root / "cli-single-validation.tgz"
        with mock.patch.object(
            assembly,
            "validate_demo_fixture",
            wraps=assembly.validate_demo_fixture,
        ) as validate:
            result = generator_cli.main(
                [
                    "--output",
                    str(output),
                    "--node",
                    "node-a",
                    "--events-per-node",
                    "120",
                    "--resources-per-node",
                    "120",
                    "--seed",
                    "54321",
                    "--allow-small",
                    "--deep-validate",
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(validate.call_count, 1)
        self.assertTrue(validate.call_args.kwargs["deep"])
        self.assertEqual(
            validate.call_args.kwargs["require_full_scale"],
            False,
        )

    def test_generator_cli_owns_the_small_parser_conformance_vector(
        self,
    ) -> None:
        from rsl_demo_generator import __main__ as generator_cli

        fixture = self.root / "generated-minimal-status.jsonl"
        self.assertEqual(
            generator_cli.main(
                ["--write-conformance-fixture", str(fixture)]
            ),
            0,
        )
        self.assertEqual(
            fixture.read_bytes(),
            render_conformance_status_fixture(),
        )
        self.assertEqual(
            generator_cli.main(
                ["--verify-conformance-fixture", str(fixture)]
            ),
            0,
        )

    def test_generator_owns_compact_ingestion_corpus_and_cli_round_trip(
        self,
    ) -> None:
        from rsl_demo_generator import __main__ as generator_cli

        expected = build_ingestion_conformance_corpus()
        self.assertEqual(expected, build_ingestion_conformance_corpus())
        with tarfile.open(fileobj=io.BytesIO(expected), mode="r:gz") as archive:
            members = {
                member.name: _member_bytes(archive, member.name)
                for member in archive.getmembers()
                if member.isfile()
            }
        manifest = json.loads(members[INGESTION_MANIFEST_MEMBER])
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["large_demo_runtime"], "v1-unchanged")
        self.assertEqual(
            json.loads(members[INGESTION_EXPECTATIONS_MEMBER]),
            ingestion_temporal_semantic_vector(),
        )

        output = self.root / "runtime-v2-ingestion-conformance.tgz"
        self.assertEqual(
            generator_cli.main(
                ["--write-ingestion-conformance-corpus", str(output)]
            ),
            0,
        )
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(
            generator_cli.main(
                ["--verify-ingestion-conformance-corpus", str(output)]
            ),
            0,
        )
        output.write_bytes(expected + b"tampered")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                generator_cli.main(
                    [
                        "--verify-ingestion-conformance-corpus",
                        str(output),
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_generator_uses_the_installed_example_policy_facade(
        self,
    ) -> None:
        self.assertIs(
            plugin.generated_projection_policy,
            GENERATED_PROJECTION_POLICY,
        )
        self.assertEqual(
            DEFAULT_PLUGIN_ID,
            GENERATED_PROJECTION_POLICY.plugin_id,
        )
        self.assertEqual(
            DEFAULT_PLUGIN_VERSION,
            GENERATED_PROJECTION_POLICY.plugin_version,
        )
        self.assertIs(
            PACKET_PROFILES,
            GENERATED_PROJECTION_POLICY.packet_profiles,
        )
        self.assertIs(
            GENERATED_TOPOLOGY_PROFILE,
            GENERATED_PROJECTION_POLICY.topology_profile,
        )

    def test_bulk_stages_use_system_temp_and_publication_is_clean(self) -> None:
        from rsl_demo_generator import assembly

        output = self.root / "system-temp-stage.tgz"
        real_mkdtemp = tempfile.mkdtemp
        stage_paths: list[Path] = []

        def record_mkdtemp(*args: object, **kwargs: object) -> str:
            path = real_mkdtemp(*args, **kwargs)
            stage_paths.append(Path(path).resolve())
            return path

        with mock.patch.object(
            assembly.tempfile,
            "mkdtemp",
            side_effect=record_mkdtemp,
        ):
            build_demo_fixture(output, config=self.config)

        self.assertGreaterEqual(len(stage_paths), 2)
        system_temp = Path(tempfile.gettempdir()).resolve()
        self.assertTrue(
            all(stage.parent == system_temp for stage in stage_paths)
        )
        self.assertTrue(
            all(stage.parent != output.parent.resolve() for stage in stage_paths)
        )
        self.assertFalse(
            list(output.parent.glob(f".{output.name}.publish-*.tmp"))
        )

    def test_deep_validation_reads_every_tar_stream_forward_only(self) -> None:
        from rsl_demo_generator import assembly

        real_open = tarfile.open
        modes: list[str] = []

        def record_open(
            name: object = None,
            mode: str = "r",
            fileobj: object = None,
            **kwargs: object,
        ) -> tarfile.TarFile:
            modes.append(mode)
            return real_open(
                name=name,
                mode=mode,
                fileobj=fileobj,
                **kwargs,
            )

        with mock.patch.object(
            assembly.tarfile,
            "open",
            side_effect=record_open,
        ):
            report = validate_demo_fixture(
                self.first,
                require_full_scale=False,
                deep=True,
            )
        self.assertTrue(report.deep)
        self.assertEqual(modes, ["r|gz", "r|gz", "r|gz"])

    def test_archive_member_validation_rejects_cross_platform_escapes(
        self,
    ) -> None:
        invalid = (
            "",
            ".",
            "./member",
            "member//child",
            "member/../child",
            "../member",
            "/member",
            "C:/member",
            r"C:\member",
            r"member\child",
            "member/",
            "member\x00child",
            "member:stream",
            "NUL",
            "name.",
            "dir/COM1.txt",
        )
        for name in invalid:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_archive_name(name)
        self.assertEqual(
            validate_archive_name(
                "node-a/layer/status.txt"
            ).as_posix(),
            "node-a/layer/status.txt",
        )

    def test_package_module_is_the_only_documented_generator_cli(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "rsl_demo_generator",
                "--validate",
                str(self.first),
                "--deep-validate",
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertIn("Validated router-state-lab-generated-demo-v1", completed.stdout)

        powershell = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "launch_demo.ps1"
        ).read_text(encoding="utf-8")
        shell = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "launch_demo.sh"
        ).read_text(encoding="utf-8")
        command_wrapper = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "launch_demo.cmd"
        ).read_text(encoding="utf-8")
        for launcher in (powershell, shell):
            self.assertIn(
                "rsl_demo_generator",
                launcher,
            )
            self.assertNotIn("-m generator", launcher)
            self.assertIn("demo_router", launcher)
            self.assertNotIn("--plugin-module", launcher)
            self.assertNotIn("router_dump_analyzer_demo.plugin", launcher)
            self.assertNotIn("router_dump_analyzer_demo.generator", launcher)
            self.assertNotIn("router-dump-demo", launcher)
            self.assertNotIn("generate_demo_fixture.py", launcher)
            self.assertNotIn("generate_packed_scale_bundle.py", launcher)
            self.assertNotIn("validate_scale_archive.py", launcher)
            self.assertIn(
                "The server intentionally stays attached to this terminal.",
                launcher,
            )
            self.assertIn("--ensure-launchable", launcher)
            self.assertIn("--path-only", launcher)
            self.assertIn("--force-rebuild", launcher)
            self.assertLess(
                launcher.index("--ensure-launchable"),
                launcher.index("Starting Router State Lab"),
            )
        self.assertIn('"router_dump_analyzer"', powershell)
        self.assertIn("-m router_dump_analyzer", shell)
        self.assertIn("[switch]$ValidateFixture", powershell)
        self.assertIn(
            "if ($ValidateFixture)",
            powershell,
        )
        self.assertIn("--validate-fixture", shell)
        self.assertIn(
            'if [[ "${validate_fixture}" == true ]]',
            shell,
        )
        self.assertIn(
            "canonical full-scale",
            powershell,
        )
        self.assertIn(
            "canonical full-scale multi-node assembly",
            shell,
        )
        self.assertIn("[Console]::OutputEncoding", powershell)
        self.assertIn("System.Text.UTF8Encoding", powershell)
        self.assertIn(
            "$PreviousConsoleOutputEncoding",
            powershell,
        )
        self.assertIn("$PreviousOutputEncoding", powershell)
        self.assertLess(
            powershell.index("[Console]::OutputEncoding = $Utf8NoBom"),
            powershell.index("$SelectedFixtureOutput = & $AnalyzerPython"),
        )
        self.assertGreater(
            powershell.rindex(
                "[Console]::OutputEncoding = "
                "$PreviousConsoleOutputEncoding"
            ),
            powershell.index("$SelectedFixtureOutput = & $AnalyzerPython"),
        )
        self.assertIn(
            "exit /b %ERRORLEVEL%",
            command_wrapper,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import gc
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

from rsl_demo_plugin import (
    GENERATED_ASSEMBLY_FORMAT_VERSION,
    GENERATED_COVERAGE_FORMAT_VERSION,
    GENERATED_COVERAGE_REGISTRY_ID,
    GENERATED_PROJECTION_POLICY,
)
from rsl_demo_plugin.assembly_store import (
    DemoAssemblyError,
    DemoAssemblyStore,
)
from rsl_demo_plugin.scale_data import ScaleRuntime

from router_dump_analyzer import AnalysisLoadStage


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def _node_archive_bytes(
    node_id: str,
    *,
    forwarding_rows: list[dict[str, object]] | None = None,
    projection_format_version: int | None = None,
) -> bytes:
    revision_id = f"revision:{node_id}"
    topology = {
        "format_version": 1,
        "projection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
        "node_id": node_id,
        "revision_id": revision_id,
        "resources": [],
        "claims": [],
    }
    packet_cases = {
        "format_version": 1,
        "projection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
        "node_id": node_id,
        "revision_id": revision_id,
        "cases": [],
    }
    routes = b""
    forwarding = b"".join(
        _json_bytes(row) for row in (forwarding_rows or [])
    )
    projection_payloads = {
        "topology": _json_bytes(topology),
        "routes": routes,
        "forwarding": forwarding,
        "packet_cases": _json_bytes(packet_cases),
    }
    projection_manifest = {
        **GENERATED_PROJECTION_POLICY.projection_manifest_identity(
            node_id=node_id,
            revision_id=revision_id,
        ),
        "files": {
            key: GENERATED_PROJECTION_POLICY.projection_file_descriptor(
                key,
                records=(
                    len(forwarding_rows or [])
                    if key == "forwarding"
                    else 0
                ),
                sha256_hex=hashlib.sha256(content).hexdigest(),
            )
            for key, content in projection_payloads.items()
        },
    }
    if projection_format_version is not None:
        projection_manifest["format_version"] = projection_format_version
    members = {
        "router-state-lab-100k/plugin-projection/manifest.json": _json_bytes(
            projection_manifest
        ),
        "router-state-lab-100k/plugin-projection/topology.json": (
            projection_payloads["topology"]
        ),
        "router-state-lab-100k/plugin-projection/routes.jsonl": routes,
        "router-state-lab-100k/plugin-projection/forwarding.jsonl": forwarding,
        "router-state-lab-100k/plugin-projection/packet-cases.json": (
            projection_payloads["packet_cases"]
        ),
    }
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as zipped:
        with tarfile.open(fileobj=zipped, mode="w|") as archive:
            for name, content in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mtime = 0
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _valid_coverage_case() -> dict[str, object]:
    return {
        "case_id": "basic.ip",
        "required_capabilities": ["evidence_analysis"],
        "private_analysis_intents": ["evidence_interpretation"],
        "involved_nodes": ["node-a"],
        "candidate_paths": [],
        "evidence_refs": [
            {
                "evidence_kind": "temporal_event",
                "node_id": "node-a",
                "revision_id": "revision:node-a",
                "resource_id": "node-a/resource/1",
                "event_uid": "node-a/event/1",
                "event_name": "test_state_change",
                "phase": "test",
                "timestamp_ns": "1",
                "resource_kind": "TEST_RESOURCE",
                "action": "modify",
                "outcome": "success",
                "state_changed": True,
            }
        ],
    }


def _write_assembly(
    path: Path,
    *,
    plugin_descriptor: dict[str, object] | None = None,
    assembly_format_version: int = GENERATED_ASSEMBLY_FORMAT_VERSION,
    coverage_format_version: int = GENERATED_COVERAGE_FORMAT_VERSION,
    coverage_case: dict[str, object] | None = None,
    forwarding_rows_by_node: dict[
        str, list[dict[str, object]]
    ] | None = None,
    projection_format_version: int | None = None,
) -> None:
    node_archives = {
        node_id: _node_archive_bytes(
            node_id,
            forwarding_rows=(
                (forwarding_rows_by_node or {}).get(node_id)
            ),
            projection_format_version=projection_format_version,
        )
        for node_id in ("node-a", "node-b")
    }
    nodes = []
    for node_id, content in node_archives.items():
        nodes.append(
            {
                "node_id": node_id,
                "revision_id": f"revision:{node_id}",
                "label": node_id.upper(),
                "role": "test",
                "site": "test",
                "archive": f"nodes/{node_id}.tgz",
                "sha256": hashlib.sha256(content).hexdigest(),
                "compressed_size": len(content),
                "event_records": 3,
                "resource_records": 2,
                "identity_namespace": f"demo/{node_id}",
            }
        )
    manifest = {
        "generator": "router-dump-analyzer-demo-assembly-v1",
        "format_version": assembly_format_version,
        "assembly_id": "test-assembly",
        "seed": 1,
        "plugin": (
            plugin_descriptor
            or GENERATED_PROJECTION_POLICY.archive_plugin_descriptor()
        ),
        "default_node_id": "node-a",
        "scale_policy": {"full_scale": False},
        "nodes": nodes,
        "coverage": {"path": "coverage.json", "cases": 1},
    }
    coverage = {
        "format_version": coverage_format_version,
        "registry_id": GENERATED_COVERAGE_REGISTRY_ID,
        "cases": [
            coverage_case or _valid_coverage_case()
        ],
    }
    members = {
        "router-state-lab-demo/manifest.json": _json_bytes(manifest),
        "router-state-lab-demo/coverage.json": _json_bytes(coverage),
        **{
            f"router-state-lab-demo/nodes/{node_id}.tgz": content
            for node_id, content in node_archives.items()
        },
    }
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                for name, content in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = 0
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(content))


def _forwarding_row_with_topology_reference(
    *,
    include_topology_reference: bool = True,
) -> dict[str, object]:
    next_hop: dict[str, object] = {
        "node_id": "node-b",
        "interface_resource_id": "node-a/interface/1",
        "remote_interface_resource_id": "node-b/interface/1",
        "selection_owner": "plugin",
        "selection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
        "topology_references": (
            [
                {
                    "reference_kind": "connectivity_domain",
                    "match": {
                        "matcher_id": (
                            GENERATED_PROJECTION_POLICY
                            .topology_segment_matcher_id
                        ),
                        "matcher_contract_version": "1.0",
                        "arguments": {
                            "segment_key": {
                                "type": "string",
                                "value": "subnet:test-a-b",
                            }
                        },
                    },
                }
            ]
            if include_topology_reference
            else []
        ),
    }
    return {
        "forwarding_id": "node-a/forwarding/basic.route",
        "node_id": "node-a",
        "revision_id": "revision:node-a",
        "scenario_id": "basic.route",
        "directional_decisions": {
            "forward": [
                {
                    "candidate_id": "basic.route:forward:primary",
                    "visit_index": 0,
                    "next_node_id": "node-b",
                    "next_hop": next_hop,
                    "selected_active": True,
                    "primary": True,
                    "alternative_state": "selected_primary",
                    "state": "active",
                    "disposition": "forward",
                    "resolution_text": "Forward through the declared subnet.",
                }
            ],
            "reverse": [],
        },
    }


class _CloseCountingSearch:
    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


def _scale_runtime(search: _CloseCountingSearch) -> ScaleRuntime:
    return ScaleRuntime(
        resources=[],
        resource_by_id={},
        resources_by_kind={},
        resource_counts={},
        events=[],
        event_by_uid={},
        event_times=[],
        events_by_resource={},
        lifecycle_by_resource={},
        state_by_resource={},
        relationships=[],
        relationships_by_endpoint={},
        mutations=[],
        mutation_times=[],
        mutations_by_endpoint={},
        initial_resource_ids=[],
        event_search=search,
    )


class DemoAssemblyStoreTests(unittest.TestCase):
    @staticmethod
    def _rewrite_outer(path: Path, mutate: Callable[[list[tuple[tarfile.TarInfo, bytes | None]]], None]) -> None:
        with tarfile.open(path, "r:gz") as archive:
            rows = [
                (member, archive.extractfile(member).read() if member.isfile() else None)
                for member in archive
            ]
        mutate(rows)
        with tarfile.open(path, "w:gz") as archive:
            for member, content in rows:
                archive.addfile(member, io.BytesIO(content) if content is not None else None)

    def test_outer_streams_twice_with_metadata_after_reordered_packs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assembly.tgz"
            _write_assembly(path)
            self._rewrite_outer(path, lambda rows: rows.reverse())
            with patch(
                "rsl_demo_plugin.assembly_store.tarfile.open", wraps=tarfile.open
            ) as opened, DemoAssemblyStore(path) as store:
                self.assertEqual(
                    [item.node_id for item in store.assembly.revisions],
                    ["node-a", "node-b"],
                )
                self.assertEqual(store.projection_for_node("node-a")["routes"], [])
            outer_calls = [call for call in opened.call_args_list if "fileobj" in call.kwargs]
            self.assertEqual(len(outer_calls), 2)
            self.assertTrue(all(call.kwargs["mode"] == "r|gz" for call in outer_calls))
            self.assertIs(outer_calls[0].kwargs["fileobj"], outer_calls[1].kwargs["fileobj"])

    def test_outer_rejects_headers_and_metadata_changed_between_passes(self) -> None:
        for mutation in ("header", "metadata", "missing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "assembly.tgz"
                _write_assembly(path)
                real_open = tarfile.open
                calls = 0

                def mutate(rows, mutation=mutation):
                    if mutation == "header":
                        rows[-1][0].mode ^= 1
                    elif mutation == "missing":
                        rows.pop()
                    else:
                        for index, (member, content) in enumerate(rows):
                            if member.name.endswith("/manifest.json"):
                                changed = json.loads(content)
                                changed["assembly_id"] = "evil-assembly"
                                content = _json_bytes(changed)
                                member.size = len(content)
                                rows[index] = (member, content)
                                break

                def open_pass(*args, path=path, mutate=mutate, real_open=real_open, **kwargs):
                    nonlocal calls
                    if "fileobj" in kwargs:
                        calls += 1
                        if calls == 2:
                            with patch("rsl_demo_plugin.assembly_store.tarfile.open", real_open):
                                self._rewrite_outer(path, mutate)
                    return real_open(*args, **kwargs)

                with (
                    patch("rsl_demo_plugin.assembly_store.tarfile.open", side_effect=open_pass),
                    self.assertRaisesRegex(DemoAssemblyError, "changed between passes"),
                ):
                    DemoAssemblyStore(path)

    def test_outer_rejects_trailing_unsafe_and_duplicate_members(self) -> None:
        for mutation in ("unsafe", "duplicate", "symlink", "checksum", "size", "missing-pack"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "assembly.tgz"
                _write_assembly(path)

                def mutate(rows, mutation=mutation):
                    if mutation == "duplicate":
                        rows.append(rows[0])
                    elif mutation == "missing-pack":
                        rows[:] = [row for row in rows if not row[0].name.endswith("node-a.tgz")]
                    elif mutation == "size":
                        for index, (member, content) in enumerate(rows):
                            if member.name.endswith("/manifest.json"):
                                changed = json.loads(content)
                                changed["nodes"][0]["compressed_size"] += 1
                                content = _json_bytes(changed)
                                member.size = len(content)
                                rows[index] = (member, content)
                                break
                    elif mutation == "checksum":
                        for index, (member, content) in enumerate(rows):
                            if member.name.endswith(".tgz"):
                                rows[index] = (member, bytes([content[0] ^ 1]) + content[1:])
                                break
                    else:
                        member = tarfile.TarInfo("../unsafe" if mutation == "unsafe" else "safe-link")
                        if mutation == "symlink":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "other"
                        rows.append((member, b""))

                self._rewrite_outer(path, mutate)
                with self.assertRaises(DemoAssemblyError):
                    DemoAssemblyStore(path)

    def test_outer_archive_reports_bounded_node_inventory_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "assembly.tgz"
            _write_assembly(archive)
            with patch(
                "rsl_demo_plugin.assembly_store.report_analysis_load"
            ) as report, DemoAssemblyStore(archive):
                pass

            inventory_updates = [
                call
                for call in report.call_args_list
                if call.args == (AnalysisLoadStage.INVENTORYING,)
            ]
            self.assertTrue(inventory_updates)
            self.assertEqual(
                [
                    (call.kwargs.get("completed"), call.kwargs.get("total"))
                    for call in inventory_updates
                    if "total" in call.kwargs
                ],
                [(0, 2), (1, 2), (2, 2)],
            )

    def test_projection_reader_uses_one_streaming_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            node_archive = Path(directory) / "node-a.tgz"
            node_archive.write_bytes(_node_archive_bytes("node-a"))
            with patch(
                "rsl_demo_plugin.assembly_store.tarfile.open",
                wraps=tarfile.open,
            ) as opened:
                projection = DemoAssemblyStore._read_plugin_projection(
                    node_archive,
                    "node-a",
                    "revision:node-a",
                )

            self.assertEqual(projection["routes"], [])
            self.assertEqual(projection["forwarding"], [])
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(opened.call_args.kwargs["mode"], "r|gz")

    def test_runtime_rejects_stale_outer_assembly_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "stale-assembly.tgz"
            _write_assembly(archive, assembly_format_version=1)
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "assembly format version",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_stale_projection_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "stale-projection.tgz"
            _write_assembly(archive, projection_format_version=1)
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "installed example policy at format_version",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_stale_coverage_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "stale-coverage-version.tgz"
            _write_assembly(
                archive,
                coverage_format_version=(GENERATED_COVERAGE_FORMAT_VERSION - 1),
            )
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "coverage format version",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_missing_unknown_or_duplicate_analysis_intents(
        self,
    ) -> None:
        malformed = {
            "missing": None,
            "unknown": ["vendor_private_intent"],
            "duplicate": ["route_trace", "route_trace"],
        }
        for label, intents in malformed.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                case = _valid_coverage_case()
                if intents is None:
                    case.pop("private_analysis_intents")
                else:
                    case["private_analysis_intents"] = intents
                archive = Path(directory) / f"{label}-analysis-intents.tgz"
                _write_assembly(archive, coverage_case=case)
                with self.assertRaisesRegex(
                    DemoAssemblyError,
                    "private_analysis_intents",
                ):
                    DemoAssemblyStore(archive)

    def test_runtime_requires_analysis_capability_for_declared_intents(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            case = _valid_coverage_case()
            case["required_capabilities"] = []
            archive = Path(directory) / "missing-analysis-capability.tgz"
            _write_assembly(archive, coverage_case=case)
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "lacks evidence_analysis capability",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_coverage_without_candidate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "stale-coverage.tgz"
            _write_assembly(
                archive,
                coverage_case={
                    "case_id": "basic.ip",
                    "required_capabilities": ["evidence_analysis"],
                    "private_analysis_intents": ["evidence_interpretation"],
                    "involved_nodes": ["node-a"],
                    "evidence_refs": [
                        {
                            "evidence_kind": "temporal_event",
                            "node_id": "node-a",
                            "revision_id": "revision:node-a",
                            "resource_id": "node-a/resource/1",
                            "event_uid": "node-a/event/1",
                            "event_name": "test_state_change",
                            "phase": "test",
                            "timestamp_ns": "1",
                            "resource_kind": "TEST_RESOURCE",
                            "action": "modify",
                            "outcome": "success",
                            "state_changed": True,
                        }
                    ],
                },
            )
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "lacks candidate_paths",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_incomplete_exact_coverage_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "incomplete-evidence.tgz"
            _write_assembly(
                archive,
                coverage_case={
                    "case_id": "topology.shared",
                    "required_capabilities": [
                        "topology_projection",
                        "evidence_analysis",
                    ],
                    "private_analysis_intents": ["evidence_correlation"],
                    "involved_nodes": ["node-a"],
                    "candidate_paths": [],
                    "evidence_refs": [
                        {
                            "evidence_kind": "topology_claim",
                            "node_id": "node-a",
                            "revision_id": "revision:node-a",
                            "resource_id": "node-a/interface/1",
                            "topology_claim_id": "node-a/topology/shared",
                        }
                    ],
                },
            )
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "topology_claim evidence lacks selector_kind",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_tampered_forwarding_topology_reference(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "tampered-forwarding.tgz"
            _write_assembly(
                archive,
                forwarding_rows_by_node={
                    "node-a": [
                        _forwarding_row_with_topology_reference(
                            include_topology_reference=False,
                        )
                    ]
                },
            )
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "exactly one topology reference",
            ):
                DemoAssemblyStore(archive)

    def test_runtime_rejects_a_different_generated_policy_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "wrong-policy.tgz"
            descriptor = (
                GENERATED_PROJECTION_POLICY.archive_plugin_descriptor()
            )
            descriptor["projection_policy_id"] = "other.policy.v1"
            _write_assembly(
                archive,
                plugin_descriptor=descriptor,
            )
            with self.assertRaisesRegex(
                DemoAssemblyError,
                "installed example policy",
            ):
                DemoAssemblyStore(archive)

    def test_node_and_revision_views_share_one_lazy_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            calls: list[tuple[str, bytes]] = []

            def load(path: Path, revision_id: str) -> dict[str, object]:
                calls.append((revision_id, path.read_bytes()))
                node_id = revision_id.removeprefix("revision:")
                return {
                    "demo": {
                        "node": node_id,
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    }
                }

            with DemoAssemblyStore(
                archive,
                cache_size=1,
                dataset_loader=load,
            ) as store:
                self.assertEqual(store.default_revision_id, "revision:node-a")
                by_node = store.dataset_for_node("node-a")
                by_revision = store.dataset_for_revision("revision:node-a")
                self.assertIs(by_node["demo"], by_revision["demo"])
                self.assertEqual(len(calls), 1)
                by_node.release()
                by_revision.release()
                node_b = store.dataset_for_node("node-b")
                self.assertEqual(
                    store.loaded_revision_ids(),
                    ("revision:node-b",),
                )
                node_b.release()
                reopened = store.dataset_for_node("node-a")
                self.assertEqual(len(calls), 3)
                reopened.release()

    def test_live_leases_survive_eviction_and_revisits_close_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            searches: dict[str, list[_CloseCountingSearch]] = {}

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                node_id = revision_id.removeprefix("revision:")
                search = _CloseCountingSearch()
                searches.setdefault(revision_id, []).append(search)
                return {
                    "demo": {
                        "node": node_id,
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    },
                    "_scale_runtime": _scale_runtime(search),
                }

            store = DemoAssemblyStore(
                archive,
                cache_size=1,
                dataset_loader=load,
            )
            node_a = store.dataset_for_node("node-a")
            node_b = store.dataset_for_node("node-b")

            self.assertEqual(
                store.loaded_revision_ids(),
                ("revision:node-a", "revision:node-b"),
            )
            self.assertEqual(searches["revision:node-a"][0].close_count, 0)
            self.assertEqual(searches["revision:node-b"][0].close_count, 0)

            del node_b
            gc.collect()
            self.assertEqual(
                store.loaded_revision_ids(),
                ("revision:node-a",),
            )
            self.assertEqual(searches["revision:node-b"][0].close_count, 1)
            self.assertEqual(searches["revision:node-a"][0].close_count, 0)

            revisited_b = store.dataset_for_node("node-b")
            self.assertEqual(len(searches["revision:node-b"]), 2)
            self.assertEqual(searches["revision:node-a"][0].close_count, 0)
            node_a.release()
            self.assertEqual(searches["revision:node-a"][0].close_count, 1)

            store.close()
            store.close()
            self.assertEqual(searches["revision:node-b"][1].close_count, 0)
            revisited_b.release()
            self.assertEqual(searches["revision:node-b"][1].close_count, 1)

    def test_cache_hits_and_releases_continue_during_a_cold_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            cold_started = Event()
            allow_cold = Event()
            hit_finished = Event()
            release_finished = Event()
            errors: list[BaseException] = []

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                if revision_id == "revision:node-b":
                    cold_started.set()
                    if not allow_cold.wait(10):
                        raise TimeoutError("test did not release cold load")
                return {
                    "demo": {
                        "node": revision_id.removeprefix("revision:"),
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    }
                }

            store = DemoAssemblyStore(
                archive,
                cache_size=2,
                dataset_loader=load,
            )
            original = store.dataset_for_node("node-a")
            leases: list[Mapping[str, object]] = []

            def load_cold() -> None:
                try:
                    leases.append(store.dataset_for_node("node-b"))
                except Exception as error:
                    errors.append(error)

            def load_cached() -> None:
                try:
                    leases.append(store.dataset_for_node("node-a"))
                except Exception as error:
                    errors.append(error)
                finally:
                    hit_finished.set()

            def release_original() -> None:
                original.release()
                release_finished.set()

            cold_thread = Thread(target=load_cold)
            hit_thread = Thread(target=load_cached)
            release_thread = Thread(target=release_original)
            cold_thread.start()
            self.assertTrue(cold_started.wait(10))
            hit_thread.start()
            release_thread.start()
            try:
                self.assertTrue(
                    hit_finished.wait(10),
                    "a cache hit was blocked by cold materialization",
                )
                self.assertTrue(
                    release_finished.wait(10),
                    "a lease release was blocked by cold materialization",
                )
            finally:
                allow_cold.set()
                for thread in (cold_thread, hit_thread, release_thread):
                    thread.join(10)

            self.assertFalse(
                any(
                    thread.is_alive()
                    for thread in (cold_thread, hit_thread, release_thread)
                )
            )
            self.assertEqual(errors, [])
            for lease in leases:
                lease.release()
            store.close()

    def test_duplicate_cold_misses_materialize_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            begin = Event()
            ready = [Event(), Event()]
            load_started = Event()
            allow_load = Event()
            calls: list[str] = []
            leases: list[Mapping[str, object]] = []
            errors: list[BaseException] = []

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                calls.append(revision_id)
                load_started.set()
                if not allow_load.wait(10):
                    raise TimeoutError("test did not release cold load")
                return {
                    "demo": {
                        "node": "node-a",
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    }
                }

            store = DemoAssemblyStore(archive, dataset_loader=load)

            def request(index: int) -> None:
                ready[index].set()
                begin.wait()
                try:
                    leases.append(store.dataset_for_node("node-a"))
                except Exception as error:
                    errors.append(error)

            threads = [
                Thread(target=request, args=(index,)) for index in range(2)
            ]
            for thread in threads:
                thread.start()
            self.assertTrue(all(event.wait(10) for event in ready))
            begin.set()
            self.assertTrue(load_started.wait(10))
            allow_load.set()
            for thread in threads:
                thread.join(10)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(calls, ["revision:node-a"])
            self.assertEqual(len(leases), 2)
            for lease in leases:
                lease.release()
            store.close()

    def test_close_during_load_rejects_publish_and_closes_runtime_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            load_started = Event()
            allow_load = Event()
            search = _CloseCountingSearch()
            errors: list[BaseException] = []

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                load_started.set()
                if not allow_load.wait(10):
                    raise TimeoutError("test did not release cold load")
                return {
                    "demo": {
                        "node": "node-a",
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    },
                    "_scale_runtime": _scale_runtime(search),
                }

            store = DemoAssemblyStore(archive, dataset_loader=load)
            temporary_path = Path(store._temporary_directory.name)

            def request() -> None:
                try:
                    store.dataset_for_node("node-a")
                except Exception as error:
                    errors.append(error)

            thread = Thread(target=request)
            thread.start()
            self.assertTrue(load_started.wait(10))
            store.close()
            self.assertTrue(temporary_path.exists())
            allow_load.set()
            thread.join(10)

            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], RuntimeError)
            self.assertEqual(str(errors[0]), "demo assembly store is closed")
            self.assertEqual(store.loaded_revision_ids(), ())
            self.assertEqual(search.close_count, 1)
            self.assertFalse(temporary_path.exists())
            store.close()
            self.assertEqual(search.close_count, 1)

    def test_close_during_failed_load_cleans_up_and_closes_runtime_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            load_started = Event()
            allow_load = Event()
            search = _CloseCountingSearch()
            errors: list[BaseException] = []

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                load_started.set()
                if not allow_load.wait(10):
                    raise TimeoutError("test did not release cold load")
                return {
                    "demo": {
                        "node": "wrong-node",
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    },
                    "_scale_runtime": _scale_runtime(search),
                }

            store = DemoAssemblyStore(archive, dataset_loader=load)
            temporary_path = Path(store._temporary_directory.name)

            def request() -> None:
                try:
                    store.dataset_for_node("node-a")
                except Exception as error:
                    errors.append(error)

            thread = Thread(target=request)
            thread.start()
            self.assertTrue(load_started.wait(10))
            store.close()
            allow_load.set()
            thread.join(10)

            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], DemoAssemblyError)
            self.assertEqual(search.close_count, 1)
            self.assertFalse(temporary_path.exists())

    def test_failed_load_leaves_open_store_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            calls = 0

            def load(path: Path, revision_id: str) -> dict[str, object]:
                nonlocal calls
                path.read_bytes()
                calls += 1
                if calls == 1:
                    raise ValueError("synthetic load failure")
                return {
                    "demo": {
                        "node": "node-a",
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    }
                }

            store = DemoAssemblyStore(archive, dataset_loader=load)
            temporary_path = Path(store._temporary_directory.name)
            with self.assertRaisesRegex(ValueError, "synthetic load failure"):
                store.dataset_for_node("node-a")

            self.assertTrue(temporary_path.exists())
            self.assertEqual(store.loaded_revision_ids(), ())
            lease = store.dataset_for_node("node-a")
            self.assertEqual(calls, 2)
            lease.release()
            store.close()
            self.assertFalse(temporary_path.exists())

    def test_lease_copy_preserves_view_and_survives_store_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            search = _CloseCountingSearch()

            def load(path: Path, revision_id: str) -> dict[str, object]:
                path.read_bytes()
                return {
                    "demo": {
                        "node": "node-a",
                        "revision_id": revision_id,
                        "event_count": 3,
                        "resource_count": 2,
                    },
                    "shared": [],
                    "_scale_runtime": _scale_runtime(search),
                }

            store = DemoAssemblyStore(archive, dataset_loader=load)
            source = store.dataset_for_node("node-a")
            source["added"] = {"value": 1}
            del source["shared"]
            copied = source.copy()

            self.assertIn("added", copied)
            self.assertNotIn("shared", copied)
            self.assertIs(copied["added"], source["added"])
            source["added"] = {"value": 2}
            copied["copy-only"] = True
            self.assertEqual(copied["added"], {"value": 1})
            self.assertNotIn("copy-only", source)

            store.close()
            copied_after_close = copied.copy()
            source.release()
            with self.assertRaisesRegex(RuntimeError, "lease is released"):
                source.copy()
            copied.release()
            self.assertEqual(search.close_count, 0)
            copied_after_close.release()
            self.assertEqual(search.close_count, 1)
            copied_after_close.release()
            self.assertEqual(search.close_count, 1)

    def test_manifest_inventory_is_available_without_loading_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "demo.tgz"
            _write_assembly(archive)
            with DemoAssemblyStore(
                archive,
                dataset_loader=lambda _path, _revision: self.fail(
                    "dataset should remain lazy"
                ),
            ) as store:
                self.assertEqual(len(store.assembly.revisions), 2)
                self.assertEqual(store.loaded_revision_ids(), ())
                self.assertEqual(
                    store.assembly.coverage_case_ids,
                    ("basic.ip",),
                )
                projection = store.projection_for_node("node-a")
                self.assertEqual(
                    projection["runtime_load"],
                    GENERATED_PROJECTION_POLICY.runtime_load_descriptor(),
                )
                self.assertFalse(
                    projection["runtime_load"]["parser_replayed"]
                )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.generate_sample_bundle as sample_generator
from scripts.generate_sample_bundle import (
    _ctf_archive,
    _validate_archive_name,
    build_bundle,
)
from scripts.generate_packed_scale_bundle import PACK_ROOT, build_packed_bundle
from scripts.generate_scale_fixtures import generate as generate_scale_fixtures
from scripts.fetch_babeltrace_sample import FILES as CTF_FILES, fetch
from router_dump_analyzer.demo_data import (
    configure_demo_archive,
    load_demo_dataset,
)


ROOT = Path(__file__).resolve().parents[1]
CTF_SOURCE = ROOT / "samples" / "external" / "ctf2-smalltrace"


def _safe_names(archive: tarfile.TarFile) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for member in archive.getmembers():
        name = member.name
        canonical = _validate_archive_name(name).as_posix()
        if not member.isfile():
            raise ValueError(f"non-file generated archive member: {name!r}")
        if canonical in seen:
            raise ValueError(f"duplicate generated archive member: {name!r}")
        seen.add(canonical)
        names.append(name)
    return names


class SampleBundleTests(unittest.TestCase):
    def test_pinned_ctf_files_match_size_and_sha256(self) -> None:
        for name, (expected_size, expected_sha256) in CTF_FILES.items():
            content = (CTF_SOURCE / name).read_bytes()
            self.assertEqual(len(content), expected_size)
            self.assertEqual(hashlib.sha256(content).hexdigest(), expected_sha256)

    def test_ctf_is_revalidated_before_it_is_embedded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for name in CTF_FILES:
                shutil.copyfile(CTF_SOURCE / name, source / name)
            (source / "dummystream").write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "size mismatch"):
                _ctf_archive(source)

            content = bytearray((CTF_SOURCE / "dummystream").read_bytes())
            content[0] ^= 0x01
            (source / "dummystream").write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                _ctf_archive(source)

    def test_fetch_rolls_back_if_publication_fails(self) -> None:
        class Response:
            def __init__(self, content: bytes) -> None:
                self.content = content

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                return self.content[:size]

        payloads = {
            name: (CTF_SOURCE / name).read_bytes() for name in CTF_FILES
        }

        def fake_urlopen(url: str, timeout: int) -> Response:
            self.assertEqual(timeout, 30)
            return Response(payloads[url.rsplit("/", 1)[-1]])

        original_replace = Path.replace

        def fail_second_publish(source: Path, target: Path) -> Path:
            target = Path(target)
            if source.suffix == ".tmp" and target.name == "dummystream":
                raise OSError("simulated second publication failure")
            return original_replace(source, target)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            old = {"metadata": b"old metadata", "dummystream": b"old stream"}
            for name, content in old.items():
                (destination / name).write_bytes(content)
            with (
                mock.patch(
                    "scripts.fetch_babeltrace_sample.urllib.request.urlopen",
                    side_effect=fake_urlopen,
                ),
                mock.patch.object(Path, "replace", new=fail_second_publish),
                self.assertRaisesRegex(OSError, "second publication"),
            ):
                fetch(destination)
            for name, content in old.items():
                self.assertEqual((destination / name).read_bytes(), content)
            self.assertFalse((destination / ".ctf-fixture-fetch.lock").exists())

    def test_fetch_refuses_non_file_target_without_displacing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            target = destination / "metadata"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("user data", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "non-file"):
                fetch(destination)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")
            self.assertFalse((destination / ".ctf-fixture-fetch.lock").exists())

    def test_archive_member_validation_rejects_windows_and_posix_escapes(self) -> None:
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
            r"\\server\share",
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
                    _validate_archive_name(name)
        self.assertEqual(
            _validate_archive_name("node-a/layer/status.txt").as_posix(),
            "node-a/layer/status.txt",
        )

    def test_generator_refuses_to_replace_unowned_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unowned"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("user data", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                build_bundle(output, CTF_SOURCE)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")

    def test_generator_preserves_content_added_during_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            build_bundle(output, CTF_SOURCE)
            original_bundle = (output / "node-a.tgz").read_bytes()
            original_build = sample_generator._build_bundle_in_empty_output

            def build_then_mutate(stage: Path, source: Path) -> Path:
                result = original_build(stage, source)
                (output / "added-during-build.txt").write_text(
                    "preserve me", encoding="utf-8"
                )
                return result

            with (
                mock.patch.object(
                    sample_generator,
                    "_build_bundle_in_empty_output",
                    side_effect=build_then_mutate,
                ),
                self.assertRaisesRegex(RuntimeError, "output changed"),
            ):
                build_bundle(output, CTF_SOURCE)
            self.assertEqual(
                (output / "added-during-build.txt").read_text(encoding="utf-8"),
                "preserve me",
            )
            self.assertEqual((output / "node-a.tgz").read_bytes(), original_bundle)

    def test_checked_in_fixture_matches_current_generator(self) -> None:
        checked_in = ROOT / "samples" / "generated"
        with tempfile.TemporaryDirectory() as directory:
            fresh = Path(directory)
            build_bundle(fresh, CTF_SOURCE)
            checked_files = {
                path.relative_to(checked_in): path.read_bytes()
                for path in checked_in.rglob("*")
                if path.is_file()
            }
            fresh_files = {
                path.relative_to(fresh): path.read_bytes()
                for path in fresh.rglob("*")
                if path.is_file()
            }
            self.assertEqual(fresh_files, checked_files)

    def test_generated_bundle_has_nested_layers_and_real_ctf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = build_bundle(Path(directory), CTF_SOURCE)
            with tarfile.open(bundle, "r:gz") as outer:
                names = _safe_names(outer)
                self.assertIn("node-a/manifest.json", names)
                self.assertIn("node-a/data-bridge-layer.tgz", names)
                bridge_member = outer.extractfile("node-a/data-bridge-layer.tgz")
                self.assertIsNotNone(bridge_member)
                assert bridge_member is not None
                bridge_bytes = bridge_member.read()

            with tarfile.open(fileobj=io.BytesIO(bridge_bytes), mode="r:gz") as bridge:
                names = _safe_names(bridge)
                ctf_name = "var/lib/bridge-dump/mnt/trace/ctf2-smalltrace.tgz"
                router_ctf_name = (
                    "var/lib/bridge-dump/mnt/trace/ctf2-router-domain.tgz"
                )
                codec_name = (
                    "var/lib/bridge-dump/mnt/trace/codec-chain-marker.zst.gz"
                )
                self.assertIn(ctf_name, names)
                self.assertIn(router_ctf_name, names)
                self.assertIn(codec_name, names)
                ctf_member = bridge.extractfile(ctf_name)
                router_ctf_member = bridge.extractfile(router_ctf_name)
                codec_member = bridge.extractfile(codec_name)
                self.assertIsNotNone(ctf_member)
                self.assertIsNotNone(router_ctf_member)
                self.assertIsNotNone(codec_member)
                assert ctf_member is not None
                assert router_ctf_member is not None
                assert codec_member is not None
                ctf_bytes = ctf_member.read()
                router_ctf_bytes = router_ctf_member.read()
                codec_bytes = codec_member.read()

            with tarfile.open(fileobj=io.BytesIO(ctf_bytes), mode="r:gz") as ctf:
                self.assertEqual(
                    _safe_names(ctf),
                    ["smalltrace/dummystream", "smalltrace/metadata"],
                )

            with tarfile.open(
                fileobj=io.BytesIO(router_ctf_bytes), mode="r:gz"
            ) as router_ctf:
                self.assertEqual(
                    _safe_names(router_ctf),
                    ["routertrace/dummystream", "routertrace/metadata"],
                )
                metadata_member = router_ctf.extractfile("routertrace/metadata")
                stream_member = router_ctf.extractfile("routertrace/dummystream")
                assert metadata_member is not None and stream_member is not None
                self.assertIn(b"router-resource-update", metadata_member.read())
                stream = stream_member.read()
                self.assertIn(b"route:blue:203.0.113.0/24\x00", stream)
                self.assertIn(b"bridgeStatus\x00DependencyError\x00", stream)

            zstd_frame = gzip.decompress(codec_bytes)
            expected_codec_payload = b"synthetic gzip-then-zstd codec-chain fixture\n"
            self.assertEqual(zstd_frame[:5], b"\x28\xb5\x2f\xfd\x20")
            self.assertEqual(zstd_frame[5], len(expected_codec_payload))
            block_header = int.from_bytes(zstd_frame[6:9], "little")
            self.assertEqual(block_header & 0b111, 1)
            block_size = block_header >> 3
            self.assertEqual(
                zstd_frame[9 : 9 + block_size],
                expected_codec_payload,
            )

    def test_illustrative_route_and_tri_state_consistency_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build_bundle(output, CTF_SOURCE)
            route = json.loads(
                (output / "illustrative" / "route-resolution.json").read_text()
            )
            self.assertEqual(route["matched_prefix"], "203.0.113.0/24")
            self.assertEqual(route["provenance"], "reconstructed")
            self.assertEqual(route["quality"], "best_effort")
            self.assertEqual(route["explanation"]["kind"], "correlation_chain")
            observed_route = json.loads(
                (output / "illustrative" / "route-resolution-observed.json").read_text()
            )
            self.assertEqual(
                observed_route["basis"]["kind"], "observed_capture_vector"
            )
            self.assertEqual(observed_route["quality"], "exact")

            findings = [
                json.loads(line)
                for line in (
                    output / "illustrative" / "consistency-findings.jsonl"
                )
                .read_text()
                .splitlines()
            ]
            self.assertEqual(
                {finding["result"] for finding in findings},
                {"pass", "fail", "unknown"},
            )
            retry_failure = next(
                finding
                for finding in findings
                if finding["rule_id"] == "failed-update-retry"
            )
            self.assertEqual(retry_failure["result"], "fail")

            relationships = [
                json.loads(line)
                for line in (
                    output / "illustrative" / "relationships.jsonl"
                )
                .read_text()
                .splitlines()
            ]
            edge_pairs = {
                (relationship["source"], relationship["target"])
                for relationship in relationships
            }
            self.assertIn(
                (
                    "control-plane/EVPN_ROUTE/blue/203.0.113.0/24",
                    "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
                ),
                edge_pairs,
            )
            self.assertIn(
                (
                    "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
                    "data-bridge-layer/DTE/dte-mpls-16011",
                ),
                edge_pairs,
            )
            self.assertIn(
                (
                    "data-bridge-layer/ETG/blue/etg-evpn-east",
                    "data-bridge-layer/ETG/blue/etg-core-srv6",
                ),
                edge_pairs,
            )
            self.assertIn(
                (
                    "data-bridge-layer/DTE/dte-mpls-16011",
                    "control-plane/IP_ROUTING/blue",
                ),
                edge_pairs,
            )

            events = [
                json.loads(line)
                for line in (output / "illustrative" / "domain-events.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertEqual(
                {event["clock_domain"] for event in events},
                {"node-a-realtime"},
            )
            self.assertEqual(len(events), 25)
            self.assertTrue(
                all(
                    {
                        "event_uid",
                        "timestamp_uncertainty_ns",
                        "source_sequence",
                        "outcome",
                        "subjects",
                        "source",
                        "evidence",
                        "provenance",
                        "quality",
                    }
                    <= event.keys()
                    for event in events
                )
            )
            self.assertTrue(
                all(
                    subject.get("resource_id")
                    for event in events
                    for subject in event["subjects"]
                )
            )
            failed = [event for event in events if event["outcome"] == "failure"]
            self.assertEqual(len(failed), 1)
            self.assertFalse(failed[0]["state_changed"])
            self.assertEqual(failed[0]["effects"], [])
            add_existing = next(
                event for event in events if event["event_type"] == "ete_existing_add"
            )
            self.assertEqual(add_existing["action"], "add")
            self.assertEqual(add_existing["effects"][0]["effect_type"], "modify")

            state_intervals = [
                json.loads(line)
                for line in (output / "illustrative" / "state-intervals.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertGreaterEqual(len(state_intervals), 30)
            self.assertTrue(
                all(
                    {
                        "resource",
                        "valid_from_ns",
                        "valid_to_ns",
                        "status",
                        "status_class",
                        "start_event_uid",
                    }
                    <= interval.keys()
                    for interval in state_intervals
                )
            )
            mutations = [
                json.loads(line)
                for line in (
                    output / "illustrative" / "relationship-mutations.jsonl"
                )
                .read_text()
                .splitlines()
            ]
            self.assertEqual({mutation["operation"] for mutation in mutations}, {"add", "remove"})
            self.assertGreater(len({mutation["effective_time_ns"] for mutation in mutations}), 5)
            self.assertTrue(all(mutation.get("relationship_id") for mutation in mutations))
            causal_links = (
                output / "illustrative" / "causal-links.jsonl"
            ).read_text().splitlines()
            self.assertEqual(len(causal_links), 3)

    def test_plugin_owned_forwarding_model_and_etg_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build_bundle(output, CTF_SOURCE)
            illustrative = output / "illustrative"

            def read_jsonl(name: str) -> list[dict[str, object]]:
                return [
                    json.loads(line)
                    for line in (illustrative / name).read_text().splitlines()
                ]

            resources = read_jsonl("resources.jsonl")
            lifecycle = read_jsonl("lifecycle-intervals.jsonl")
            relationships = read_jsonl("relationship-intervals.jsonl")
            causal_links = read_jsonl("causal-links.jsonl")
            descriptors = json.loads(
                (illustrative / "kind-descriptors.json").read_text()
            )
            relationship_descriptors = json.loads(
                (illustrative / "relationship-descriptors.json").read_text()
            )
            causal_link_descriptors = json.loads(
                (illustrative / "causal-link-descriptors.json").read_text()
            )
            dashboards = json.loads(
                (illustrative / "dashboard-descriptors.json").read_text()
            )
            topology = json.loads((illustrative / "topology.json").read_text())

            by_id = {item["resource_id"]: item for item in resources}
            kinds = {item["kind"] for item in resources}
            self.assertNotIn("DTG", kinds)
            self.assertTrue(
                {
                    "FORWARDING_GROUP",
                    "ETG",
                    "ETE",
                    "DTE",
                    "VIRTUAL_INTERFACE",
                    "GLUE",
                    "IP_ROUTING",
                }
                <= kinds
            )
            self.assertEqual(
                set(topology["protocols"]),
                {"IS-IS Level 2", "SR-MPLS", "SRv6", "BGP EVPN"},
            )
            glue_descriptor = next(
                item for item in descriptors if item["kind"] == "GLUE"
            )
            self.assertEqual(
                set(glue_descriptor["presentation_tags"]),
                {"connector", "compact"},
            )
            self.assertEqual(kinds, {item["kind"] for item in descriptors})
            self.assertTrue(all(item["icon"]["path"] for item in descriptors))
            self.assertEqual(
                len({item["icon"]["path"] for item in descriptors}),
                len(descriptors),
            )
            self.assertTrue(all(item["plugin_defined"] for item in resources))
            self.assertTrue(all(item["evidence"] for item in resources))
            self.assertEqual(len(dashboards), 4)
            self.assertEqual(
                {item["dashboard_id"] for item in dashboards if item["default_open"]},
                {"forwarding-health", "protocol-state"},
            )
            self.assertTrue(all(item["plugin_defined"] for item in dashboards))
            self.assertTrue(all(item["movable"] for item in dashboards))
            self.assertEqual(
                {item["relation_type"] for item in relationships},
                {item["relation_type"] for item in relationship_descriptors},
            )
            self.assertTrue(all(item["plugin_defined"] for item in relationships))
            self.assertTrue(all(item["evidence"] for item in relationships))
            self.assertEqual(
                {item["link_type"] for item in causal_links},
                {item["link_type"] for item in causal_link_descriptors},
            )
            self.assertTrue(all(item["plugin_defined"] for item in causal_links))
            self.assertTrue(all(item["evidence"] for item in causal_links))

            forwarding_group = "data-bridge-layer/FORWARDING_GROUP/fg-blue-east"
            fg_edges = [
                item for item in relationships if item["source"] == forwarding_group
            ]
            self.assertIn("contains_ingress", {item["relation_type"] for item in fg_edges})
            self.assertIn("contains_egress", {item["relation_type"] for item in fg_edges})

            for item in relationships:
                if item["relation_type"] != "next_hop":
                    continue
                source_kind = by_id[item["source"]]["kind"]
                if source_kind not in {"ETG", "DTE"}:
                    continue
                self.assertIn(by_id[item["target"]]["kind"], {"ETG", "IP_ROUTING"})

            def active(item: dict[str, object], timestamp: int) -> bool:
                start = item.get("valid_from_ns")
                end = item.get("valid_to_ns")
                return (start is None or timestamp >= int(str(start))) and (
                    end is None or timestamp < int(str(end))
                )

            boundaries = sorted(
                {
                    int(str(value))
                    for item in lifecycle + relationships
                    for value in (item.get("valid_from_ns"), item.get("valid_to_ns"))
                    if value is not None
                }
            )
            etg_ids = {
                item["resource_id"] for item in resources if item["kind"] == "ETG"
            }
            for timestamp in boundaries:
                active_resources = {
                    item["resource"] for item in lifecycle if active(item, timestamp)
                }
                for etg_id in etg_ids & active_resources:
                    entries = {
                        item["target"]
                        for item in relationships
                        if item["source"] == etg_id
                        and item["relation_type"] == "owns"
                        and active(item, timestamp)
                        and item["target"] in active_resources
                    }
                    self.assertGreaterEqual(
                        len(entries),
                        1,
                        f"{etg_id} has no active ETE at {timestamp}",
                    )

    def test_control_fixture_has_typed_protobuf_json_and_layer_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = build_bundle(Path(directory), CTF_SOURCE)
            with tarfile.open(bundle, "r:gz") as outer:
                control_member = outer.extractfile("node-a/control-plane.tgz")
                self.assertIsNotNone(control_member)
                assert control_member is not None
                control_bytes = control_member.read()

            with tarfile.open(fileobj=io.BytesIO(control_bytes), mode="r:gz") as control:
                updates_member = control.extractfile(
                    "var/lib/control-dump/proto/resource_updates.jsonl"
                )
                events_member = control.extractfile(
                    "var/lib/control-dump/trace/lltng_domain_export.jsonl"
                )
                self.assertIsNotNone(updates_member)
                self.assertIsNotNone(events_member)
                assert updates_member is not None and events_member is not None
                updates = [
                    json.loads(line) for line in updates_member.read().splitlines()
                ]
                events = [json.loads(line) for line in events_member.read().splitlines()]

            properties = updates[0]["properties"]
            self.assertEqual(
                properties["member_uuids"]["uint64List"]["values"],
                ["1001", "1002"],
            )
            self.assertEqual(properties["opaque_id"]["bytesValue"], "AQIDBA==")
            self.assertEqual({event["layer"] for event in events}, {"control-plane"})

    def test_scale_fixture_counts_and_hashes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            manifest_path = generate_scale_fixtures(output, 250, 125)
            first_manifest = manifest_path.read_bytes()
            first_events = (output / "events.jsonl").read_bytes()
            generate_scale_fixtures(output, 250, 125)
            self.assertEqual(manifest_path.read_bytes(), first_manifest)
            self.assertEqual((output / "events.jsonl").read_bytes(), first_events)

            manifest = json.loads(first_manifest)
            self.assertEqual(manifest["events"]["records"], 250)
            self.assertEqual(manifest["resources"]["records"], 125)
            self.assertGreater(manifest["relationships"]["records"], 125)
            self.assertEqual(manifest["high_fanout_relationships"]["records"], 125)
            self.assertEqual(
                manifest["scenario_id"],
                "evpn-multihome-mass-failover-v2",
            )
            self.assertEqual(manifest["generator_version"], 2)

            scenario = json.loads((output / "scenario.json").read_text())
            walkthrough = json.loads((output / "walkthrough.json").read_text())
            plugin_schema = json.loads((output / "plugin-schema.json").read_text())
            events = [json.loads(line) for line in first_events.splitlines()]
            relationships = [
                json.loads(line)
                for line in (output / "relationships.jsonl").read_bytes().splitlines()
            ]
            mutations = [
                json.loads(line)
                for line in (
                    output / "relationship-mutations.jsonl"
                ).read_bytes().splitlines()
            ]

            phase_order = [
                "single_home_create",
                "multihome_add",
                "mass_es_withdraw",
                "mass_es_restore",
                "next_hop_churn",
            ]
            self.assertEqual(scenario["phase_order"], phase_order)
            self.assertEqual(
                list(dict.fromkeys(event["phase"] for event in events)),
                phase_order,
            )
            self.assertEqual(
                sum(phase["events"] for phase in scenario["phases"]),
                250,
            )
            self.assertEqual(sum(scenario["resource_counts"].values()), 125)
            self.assertEqual(
                set(scenario["resource_counts"]),
                {
                    "DTE",
                    "ETE_BACKUP",
                    "ETE_PRIMARY",
                    "ETG",
                    "EVPN_ES",
                    "IP_ROUTING",
                    "VIRTUAL_INTERFACE",
                },
            )
            self.assertEqual(
                manifest["relationship_mutations"]["records"],
                scenario["expected_changes"]["relationship_mutations"],
            )
            self.assertEqual(plugin_schema["semantic_owner"], "plugin")
            self.assertFalse(plugin_schema["core_interprets_domain_types"])

            create_event = next(
                event
                for event in events
                if event["event_name"] == "evpn_single_home_service_create"
            )
            self.assertEqual(
                {effect["kind"] for effect in create_event["effects"]},
                {"ETG", "ETE", "DTE"},
            )
            multihome_event = next(
                event
                for event in events
                if event["event_name"] == "evpn_multihome_attachment_add"
            )
            self.assertEqual(
                multihome_event["properties"]["prior_home_mode"],
                "single-home",
            )
            self.assertEqual(
                multihome_event["properties"]["home_mode"],
                "all-active",
            )
            event_names = {event["event_name"] for event in events}
            self.assertTrue(
                {
                    "evpn_es_mass_withdraw",
                    "evpn_mass_service_failover",
                    "evpn_es_mass_restore",
                    "evpn_mass_service_restore",
                    "dte_next_hop_dependency_change",
                }.issubset(event_names)
            )

            failover = next(
                event
                for event in events
                if event["event_name"] == "evpn_mass_service_failover"
            )
            restore = next(
                event
                for event in events
                if event["event_name"] == "evpn_mass_service_restore"
            )
            expected_dependency_changes = {
                ("selected_egress", "remove"),
                ("selected_egress", "add"),
                ("next_hop", "remove"),
                ("next_hop", "add"),
                ("active_path", "remove"),
                ("active_path", "add"),
            }
            self.assertEqual(
                {
                    (effect["type"], effect["operation"])
                    for effect in failover["relationship_effects"]
                },
                expected_dependency_changes,
            )
            self.assertEqual(
                {
                    (effect["type"], effect["operation"])
                    for effect in restore["relationship_effects"]
                },
                expected_dependency_changes,
            )
            self.assertEqual(
                failover["properties"]["selected_egress_before"],
                restore["properties"]["selected_egress_after"],
            )
            self.assertEqual(
                failover["properties"]["selected_egress_after"],
                restore["properties"]["selected_egress_before"],
            )

            churn = next(
                event
                for event in events
                if event["event_name"] == "dte_next_hop_dependency_change"
            )
            self.assertNotEqual(
                churn["properties"]["next_hop_before"],
                churn["properties"]["next_hop_after"],
            )
            failed_churn = next(
                event
                for event in events
                if event["event_name"] == "dte_next_hop_dependency_change"
                and event["outcome"] == "failure"
            )
            self.assertNotEqual(
                failed_churn["result"]["updateStatus"],
                "Ok",
            )
            self.assertFalse(failed_churn["state_changed"])
            self.assertEqual(failed_churn["effects"], [])
            self.assertEqual(failed_churn["relationship_effects"], [])
            self.assertEqual(
                {mutation["relation_type"] for mutation in mutations},
                {"active_path", "next_hop", "selected_egress", "uses_interface"},
            )
            self.assertEqual(
                {mutation["phase"] for mutation in mutations},
                {"mass_es_withdraw", "mass_es_restore", "next_hop_churn"},
            )

            service = walkthrough["services"][0]
            states = service["states"]
            self.assertEqual([state["phase"] for state in states], phase_order)
            primary = service["resource_ids"]["primary_ete"]
            backup = service["resource_ids"]["backup_ete"]
            self.assertEqual(
                [state["selected_egress"] for state in states],
                [primary, primary, backup, primary, primary],
            )
            self.assertEqual(states[0]["dte_next_hop"], states[3]["dte_next_hop"])
            self.assertNotEqual(states[2]["dte_next_hop"], states[3]["dte_next_hop"])
            self.assertNotEqual(states[4]["dte_next_hop"], states[3]["dte_next_hop"])

            selected_egress = [
                relationship
                for relationship in relationships
                if relationship["source"] == service["resource_ids"]["etg"]
                and relationship["type"] == "selected_egress"
            ]
            primary_before = next(
                relationship
                for relationship in selected_egress
                if relationship["target"] == primary
                and relationship["valid_to_ns"] is not None
            )
            backup_during = next(
                relationship
                for relationship in selected_egress
                if relationship["target"] == backup
            )
            self.assertEqual(primary_before["valid_to_ns"], failover["timestamp_ns"])
            self.assertEqual(backup_during["valid_from_ns"], failover["timestamp_ns"])
            self.assertEqual(backup_during["valid_to_ns"], restore["timestamp_ns"])

            first_event = events[0]
            first_relationship = relationships[0]
            self.assertIsInstance(first_event["timestamp_ns"], str)
            self.assertIsInstance(first_relationship["valid_from_ns"], str)

    def test_packed_scale_bundle_has_ctf_status_variants_and_demo_projection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scale = root / "scale"
            review = root / "review"
            packed = root / "router-state-lab-100k.tgz"
            generate_scale_fixtures(scale, 250, 125)
            build_bundle(review, CTF_SOURCE)
            build_packed_bundle(
                packed,
                scale,
                review / "illustrative",
                review / "unpacked" / "node-a" / "manifest.json",
            )
            first_bytes = packed.read_bytes()
            build_packed_bundle(
                packed,
                scale,
                review / "illustrative",
                review / "unpacked" / "node-a" / "manifest.json",
            )
            self.assertEqual(packed.read_bytes(), first_bytes)

            resource_total = 0
            event_total = 0
            table_counts: set[int] = set()
            expected_containers = {
                "evpn-control",
                "forwarding-multihome",
                "forwarding-single-home",
                "underlay-agent",
            }
            with tarfile.open(packed, mode="r:gz") as outer:
                names = set(_safe_names(outer))
                manifest_member = outer.extractfile(f"{PACK_ROOT}/manifest.json")
                self.assertIsNotNone(manifest_member)
                assert manifest_member is not None
                manifest = json.loads(manifest_member.read())
                self.assertEqual(manifest["scale"], {"events": 250, "resources": 125})
                self.assertEqual(
                    {item["container_id"] for item in manifest["containers"]},
                    expected_containers,
                )
                self.assertIn(
                    f"{PACK_ROOT}/normalized-scale/events.jsonl",
                    names,
                )
                self.assertIn(
                    f"{PACK_ROOT}/review-projection/resources.jsonl",
                    names,
                )

                for container_id in expected_containers:
                    nested_name = (
                        f"{PACK_ROOT}/containers/{container_id}.tgz"
                    )
                    nested_member = outer.extractfile(nested_name)
                    self.assertIsNotNone(nested_member)
                    assert nested_member is not None
                    with tarfile.open(
                        fileobj=io.BytesIO(nested_member.read()),
                        mode="r:gz",
                    ) as nested:
                        nested_names = set(_safe_names(nested))
                        self.assertTrue(
                            {
                                "manifest.json",
                                "status/resource-status.txt",
                                "status/table-index.json",
                                "trace/ctf/metadata",
                                "trace/ctf/dummystream",
                                "trace/normalized-events.jsonl",
                            }
                            <= nested_names
                        )
                        container_manifest_member = nested.extractfile(
                            "manifest.json"
                        )
                        status_member = nested.extractfile(
                            "status/resource-status.txt"
                        )
                        metadata_member = nested.extractfile(
                            "trace/ctf/metadata"
                        )
                        stream_member = nested.extractfile(
                            "trace/ctf/dummystream"
                        )
                        self.assertIsNotNone(container_manifest_member)
                        self.assertIsNotNone(status_member)
                        self.assertIsNotNone(metadata_member)
                        self.assertIsNotNone(stream_member)
                        assert (
                            container_manifest_member is not None
                            and status_member is not None
                            and metadata_member is not None
                            and stream_member is not None
                        )
                        container_manifest = json.loads(
                            container_manifest_member.read()
                        )
                        status_text = status_member.read().decode("utf-8")
                        table_count = container_manifest[
                            "resource_status"
                        ]["table_count"]
                        self.assertEqual(
                            status_text.count("=== TABLE:"),
                            table_count,
                        )
                        self.assertGreater(
                            container_manifest["trace"]["event_records"],
                            0,
                        )
                        self.assertIn(
                            b"router-resource-update",
                            metadata_member.read(),
                        )
                        self.assertTrue(
                            stream_member.read().startswith(b"\xc1\x1f\xfc\xc1")
                        )
                        table_counts.add(table_count)
                        resource_total += container_manifest[
                            "resource_status"
                        ]["resource_rows"]
                        event_total += container_manifest["trace"][
                            "event_records"
                        ]

            self.assertEqual(resource_total, 125)
            self.assertEqual(event_total, 250)
            self.assertIn(1, table_counts)
            self.assertTrue(any(count > 1 for count in table_counts))

            configure_demo_archive(packed)
            try:
                dataset = load_demo_dataset()
                self.assertEqual(dataset["demo"]["mode"], "packed-fixture")
                self.assertEqual(
                    dataset["demo"]["fixture"],
                    "synthetic-packed-tgz",
                )
                self.assertEqual(dataset["demo"]["packed_event_count"], 250)
                self.assertEqual(dataset["demo"]["packed_resource_count"], 125)
                self.assertEqual(dataset["demo"]["packed_container_count"], 4)
                self.assertEqual(dataset["inventory"]["archive"], packed.name)
                self.assertEqual(len(dataset["events"]), 25)
                self.assertEqual(len(dataset["resources"]), 24)
            finally:
                configure_demo_archive(None)

            launch_script = (ROOT / "scripts" / "launch_demo.ps1").read_text(
                encoding="utf-8"
            )
            self.assertIn("router-state-lab-100k.tgz", launch_script)
            self.assertIn("--fixture-archive", launch_script)
            self.assertIn("generate_packed_scale_bundle.py", launch_script)

    def test_scale_generator_refuses_unowned_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scale"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("user data", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                generate_scale_fixtures(output, 10, 10)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")

    def test_scale_generator_refuses_symbolic_link_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "scale-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaisesRegex(RuntimeError, "symbolic-link"):
                generate_scale_fixtures(link, 10, 10)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

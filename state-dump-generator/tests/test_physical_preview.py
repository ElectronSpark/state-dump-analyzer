from __future__ import annotations

import json
import shutil
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import test_semantics as browser_tests
from state_dump_generator.model import scenario_from_dict, validate_scenario
from state_dump_generator.server import create_server
from state_dump_generator.simulation import (
    _preview_physical_truth,
    compile_scenario,
    reconstruct_scenario,
)


@unittest.skipUnless(
    shutil.which("node"), "Node.js is required for browser conformance"
)
class PhysicalPreviewTests(unittest.TestCase):
    run_web = browser_tests.BrowserSemanticsTests.run_web

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server("127.0.0.1", 0)
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def preview(self, value: dict, at_time_ns: int = 1_000_000) -> dict:
        self.assertTrue(validate_scenario(value)["ok"])
        output = self.run_web(
            """
const nativeFetch = fetch;
globalThis.fetch = (path, options) => nativeFetch(input.base_url + path, options);
scenario = normalizeScenario(input.scenario);
selectedTimeMs = () => input.at_time_ns / 1_000_000;
renderCanvas = () => {};
const before = scenario.physical_links.map(link => linkStateAt(link.id, selectedTimeMs()));
await refreshPhysicalPreview();
return {before, status: physicalPreview.status, error: physicalPreview.error,
  project: toCanonicalProject(),
  states: Object.fromEntries(scenario.physical_links.map(link => [
    canonicalMediumIdForTarget(link.id), linkStateAt(link.id, selectedTimeMs()),
  ]))};
""",
            {"scenario": value, "base_url": self.base_url, "at_time_ns": at_time_ns},
        )
        self.assertEqual(output["status"], "ready", output.get("error"))
        expected = {
            medium["medium_id"]: medium["state"]
            for medium in reconstruct_scenario(value, at_time_ns=at_time_ns)[
                "private_truth"
            ]["media"]
        }
        self.assertEqual(output["states"], expected)
        self.assertTrue(all(state == "unknown" for state in output["before"]))
        return output

    def test_physical_status_precedence_and_json_values_match_reconstruction(
        self,
    ) -> None:
        cases = [
            {"status": "down", "state": "up", "properties": {"state": "degraded"}},
            {"state": "down", "properties": {"state": "up"}},
            {"properties": {"state": "down"}, "state_patch": {"state": "up"}},
            {"payload": {"state": "down"}, "state_patch": {"state": "up"}},
            {"properties": {"oper_status": "down"}},
            {"properties": None},
            {"state_patch": None},
            {},
        ]
        cases += [
            {"status": value, "properties": {"state": "down"}}
            for value in (
                None,
                False,
                True,
                0,
                1.25,
                "",
                "🙂",
                [],
                {"state": False},
            )
        ]
        for fields in cases:
            with self.subTest(fields=fields):
                value = browser_tests.scenario()
                del value["events"][0]["status"]
                value["events"][0].update(fields)
                output = self.preview(value)
                self.assertEqual(
                    compile_scenario(output["project"]), compile_scenario(value)
                )

    def test_initial_medium_state_is_not_replaced_by_a_truthy_default(self) -> None:
        for field in ("state", "initial_state"):
            for initial in (None, False, 0, "", ["down"], {"state": "down"}):
                with self.subTest(field=field, initial=initial):
                    value = browser_tests.scenario()
                    value["events"] = []
                    value["media"][0].pop("state", None)
                    value["media"][0][field] = initial
                    self.preview(value)

    def test_physical_target_aliases_keep_the_compiler_precedence(self) -> None:
        for fields in (
            {"target_id": "another-wire", "link_id": "another-wire"},
            {"kind": "custom", "scope": "physical"},
            {"kind": "custom", "target_type": "physical_link"},
        ):
            with self.subTest(fields=fields):
                value = browser_tests.scenario()
                value["media"].append(
                    {**value["media"][0], "medium_id": "another-wire"}
                )
                value["events"][0].update(fields)
                self.preview(value)

    def test_new_event_order_after_a_large_imported_order_remains_exact(self) -> None:
        value = browser_tests.scenario()
        value["events"][0]["order"] = "9007199254740993"
        output = self.run_web(
            """
scenario = normalizeScenario(input);
selectedTimeMs = () => 1;
scenario.events.push(makeEvent({id:'later', scope:'physical',
  target_id:'private-wire', status:'up'}));
return toCanonicalProject();
""",
            value,
        )
        self.assertEqual(output["events"][1]["order"], "9007199254740994")
        self.assertTrue(validate_scenario(output)["ok"])

    def test_physical_classification_and_failed_events_use_python_rules(self) -> None:
        for kind in (
            *browser_tests.EVENT_SEMANTICS["physical_kinds"],
            "physical-ſtate",
        ):
            with self.subTest(kind=kind):
                value = browser_tests.scenario()
                value["events"][0]["kind"] = f" {kind.replace('-', '_')} "
                self.preview(value)
        for apply in (
            False,
            True,
            0,
            1,
            "",
            "false",
            [],
            [False],
            {},
            {"apply": False},
        ):
            with self.subTest(apply=apply):
                value = browser_tests.scenario()
                value["events"][0].update(outcome="FaIlEd", apply_on_failure=apply)
                self.preview(value)

    def test_exact_order_and_timestamp_ties_are_locale_independent(self) -> None:
        cases = [
            [("a", "1", "1"), ("Z", "1", "1")],
            [("a", "1", "9007199254740992"), ("Z", "1", "9007199254740993")],
            [("a", "9007199254740992", "1"), ("Z", "9007199254740993", "1")],
        ]
        for events in cases:
            with self.subTest(events=events):
                value = browser_tests.scenario()
                value["capture_time_ns"] = "9007199255000000"
                value["events"] = [
                    {
                        **value["events"][0],
                        "event_id": event_id,
                        "timestamp_ns": timestamp,
                        "order": order,
                        "status": event_id,
                    }
                    for event_id, timestamp, order in events
                ]
                output = self.preview(value, 9_007_199_255_000_000)
                expected = sorted(
                    events, key=lambda item: (int(item[1]), int(item[2]), item[0])
                )
                self.assertEqual(
                    [event["event_id"] for event in output["project"]["events"]],
                    [event[0] for event in expected],
                )
                self.assertEqual(
                    compile_scenario(output["project"]), compile_scenario(value)
                )

    def test_codepoint_comparator_handles_non_bmp_without_locale_or_utf16_order(
        self,
    ) -> None:
        values = [
            "a",
            "Z",
            "a~",
            "a+",
            "A",
            "é",
            "e",
            "\uffff",
            "🙂",
            "𐀀",
            "a🙂",
            "a\uffff",
        ]
        output = self.run_web(
            "return input.values.sort(compareCodePoints);", {"values": values}
        )
        self.assertEqual(output, sorted(values))
        # Identifiers themselves remain restricted by the existing ASCII schema.
        value = browser_tests.scenario()
        value["events"][0]["event_id"] = "🙂"
        self.assertFalse(validate_scenario(value)["ok"])

    def test_time_aliases_and_ties_to_even_rounding_survive_preview_and_save(
        self,
    ) -> None:
        for fields in (
            {"time_ns": "101", "time_ms": 1},
            {"at_ns": "103"},
            {"time_seconds": 0.0000000005},
            {"at_seconds": 0.0000000015},
            {"time_s": 0.0000000025},
            {"time_ms": 0.0000005},
            {"timestamp_ms": 0.0000015},
            {"at_ms": 0.0000025},
        ):
            with self.subTest(fields=fields):
                value = browser_tests.scenario()
                del value["events"][0]["timestamp_ns"]
                value["events"][0].update(fields)
                output = self.preview(value)
                self.assertEqual(
                    int(output["project"]["events"][0]["timestamp_ns"]),
                    scenario_from_dict(value).events[0]["timestamp_ns"],
                )

    def test_physical_view_is_bounded_and_does_not_compile_node_histories(self) -> None:
        value = browser_tests.scenario()
        value["media"][0]["properties"] = {"large": "x" * 100_000}
        payload = {"scenario": value, "view": "physical", "at_time_ns": "1000000"}
        request = Request(
            self.base_url + "/api/scenario/preview",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with (
            patch(
                "state_dump_generator.simulation._physical_observations",
                side_effect=AssertionError("node histories must not be built"),
            ),
            urlopen(request, timeout=3) as response,
        ):
            content = response.read()
        self.assertLess(len(content), 300)
        self.assertEqual(
            json.loads(content), _preview_physical_truth(value, at_time_ns="1000000")
        )
        payload["at_time_ns"] = "1000000001"
        request.data = json.dumps(payload).encode()
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 400)

    def test_coalesced_preview_drops_stale_successes_and_errors(self) -> None:
        for rejected in (False, True):
            with self.subTest(rejected=rejected):
                output = self.run_web(
                    """
scenario = normalizeScenario(input);
let time = 1;
selectedTimeMs = () => time;
renderCanvas = () => {};
const calls = [];
globalThis.fetch = (path, options) => new Promise((resolve, reject) => {
  calls.push({path, payload:JSON.parse(options.body), resolve, reject});
});
const link = scenario.physical_links[0].id;
const pending = refreshPhysicalPreview();
const states = [linkStateAt(link, time)];
time = 2; refreshPhysicalPreview();
time = 3; refreshPhysicalPreview();
scenario.events[0].status = 'up'; projectEditVersion += 1; refreshPhysicalPreview();
const callCountBeforeResolution = calls.length;
if (input.rejected) calls[0].reject(new Error('obsolete failure'));
else calls[0].resolve({ok:true, json:async () => ({at_time_ns:'1000000',
  media:[{medium_id:'private-wire',state:'down'}]})});
for (let count=0; count<8 && calls.length<2; count++) await Promise.resolve();
states.push(linkStateAt(link, time));
calls[1].resolve({ok:true, json:async () => ({at_time_ns:'3000000',
  media:[{medium_id:'private-wire',state:'up'}]})});
await pending;
states.push(linkStateAt(link, time));
return {states, callCountBeforeResolution, calls:calls.map(call => call.payload),
  description:physicalPreviewDescription('up')};
""",
                    {**browser_tests.scenario(), "rejected": rejected},
                )
                self.assertEqual(output["states"], ["unknown", "unknown", "up"])
                self.assertEqual(output["callCountBeforeResolution"], 1)
                self.assertEqual(len(output["calls"]), 2)
                self.assertEqual(output["calls"][1]["at_time_ns"], "3000000")
                self.assertEqual(
                    output["calls"][1]["scenario"]["events"][0]["status"], "up"
                )
                self.assertEqual(output["description"], "Physical state: up")

    def test_failure_and_project_replacement_never_restore_old_truth(self) -> None:
        output = self.run_web("""
scenario = normalizeScenario(input);
selectedTimeMs = () => 1;
renderCanvas = () => {};
const link = scenario.physical_links[0].id;
globalThis.fetch = async () => ({ok:true,json:async () => ({at_time_ns:'1000000',
  media:[{medium_id:'private-wire',state:'down'}]})});
await refreshPhysicalPreview();
const states = [linkStateAt(link, 1)];
let rejectRequest;
globalThis.fetch = () => new Promise((resolve, reject) => {rejectRequest = reject;});
projectEditVersion += 1;
const pending = refreshPhysicalPreview();
states.push(linkStateAt(link, 1));
rejectRequest(new Error('preview offline'));
await pending;
states.push(linkStateAt(link, 1));
const description = physicalPreviewDescription('unknown');
scenario = normalizeScenario(input);
states.push(linkStateAt(scenario.physical_links[0].id, 1));
return {states, description};
""")
        self.assertEqual(output["states"], ["down", "unknown", "unknown", "unknown"])
        self.assertIn("preview offline", output["description"])


if __name__ == "__main__":
    unittest.main()

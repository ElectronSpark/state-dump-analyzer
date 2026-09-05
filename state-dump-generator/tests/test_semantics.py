from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from state_dump_generator._semantics import (
    EVENT_SEMANTICS,
    delay_ns,
    propagation_horizon_ns,
    propagation_target_ids,
)
from state_dump_generator.model import scenario_from_dict, validate_scenario
from state_dump_generator.simulation import _preview_propagation, compile_scenario, reconstruct_scenario

WEB_ROOT = Path(__file__).resolve().parents[1] / "src/state_dump_generator/web"


def scenario() -> dict:
    return {
        "name": "Scheduling conformance",
        "seed": 7,
        "capture_time_ns": 1_000_000_000,
        "nodes": [{"node_id": value} for value in ("a", "b", "c")],
        "media": [
            {
                "medium_id": "private-wire",
                "kind": "broadcast",
                "attachments": [
                    {"node_id": value, "port_id": "p"} for value in ("a", "b", "c")
                ],
            }
        ],
        "events": [
            {
                "event_id": "change",
                "timestamp_ns": 0,
                "order": 1,
                "kind": "medium-state",
                "medium_id": "private-wire",
                "status": "down",
                "propagation": {"mode": "best-effort", "delay_ms": 100},
            }
        ],
    }


class SchedulingTests(unittest.TestCase):
    def test_reconstruction_time_reuses_integer_rules_and_boundary_messages(self) -> None:
        value = scenario()
        value["capture_time_ns"] = "9007199254740993"
        for coordinate in (0, 2.0, "9007199254740993"):
            with self.subTest(coordinate=coordinate):
                self.assertEqual(reconstruct_scenario(value, at_time_ns=coordinate)["at_time_ns"], int(coordinate))
        for coordinate, message in (
            (True, "must be an integer"),
            (1.5, "must be an integer"),
            (float("nan"), "must be an integer"),
            (float("inf"), "must be an integer"),
            ("1.5", "must be an integer"),
            (-1, "cannot be negative"),
            ("9007199254740994", "cannot be after the final snapshot capture"),
        ):
            with self.subTest(coordinate=coordinate):
                with self.assertRaisesRegex(ValueError, f"^at_time_ns {message}$"):
                    reconstruct_scenario(value, at_time_ns=coordinate)

    def test_physical_observation_overrides_static_oper_status(self) -> None:
        for outcome in ("success", "stale", "failed"):
            with self.subTest(outcome=outcome):
                value = scenario()
                attachment = value["media"][0]["attachments"][0]
                attachment["node_local_observation"] = {
                    "resource_id": "local:a-p",
                    "properties": {"oper_status": "up", "admin_status": "down", "description": "Uplink"},
                }
                value["events"][0]["propagation"]["outcomes"] = {"a": outcome}
                local = compile_scenario(value)["a"]
                expected = "down" if outcome == "success" else "up"
                self.assertEqual(local["final_state"][0]["status"], expected)
                self.assertEqual(local["final_state"][0]["properties"]["oper_status"], expected)
                self.assertEqual(local["final_state"][0]["properties"]["admin_status"], "down")
                self.assertEqual(local["final_state"][0]["properties"]["description"], "Uplink")
                preview = _preview_propagation(scenario_from_dict(value), "change")
                generated = next(row for row in preview["events"] if row["node_id"] == "a")
                if outcome == "success":
                    self.assertEqual(generated["properties"]["oper_status"], generated["status"])
                    self.assertEqual(local["logs"][0]["properties"]["oper_status"], local["logs"][0]["status"])
                else:
                    self.assertEqual(generated["properties"], {})
                    self.assertFalse(local["logs"][0]["state_changed"])

    def test_preview_budget_counts_attachments_before_building_observations(self) -> None:
        value = scenario()
        value["media"][0]["attachments"] = [
            {"node_id": "a", "port_id": f"p{index}"} for index in range(513)
        ]
        with patch("state_dump_generator.simulation._physical_observations") as schedule:
            with self.assertRaisesRegex(ValueError, "512-observation"):
                _preview_propagation(scenario_from_dict(value), "change")
        schedule.assert_not_called()

    def test_validation_rejects_resolved_private_event_identities(self) -> None:
        for key in ("resource_id", "subject", "target_id"):
            for kind in ("status", "log"):
                with self.subTest(key=key, kind=kind):
                    value = scenario()
                    value["events"] = [{
                        "event_id": "local", "timestamp_ns": 0, "node_id": "a",
                        "kind": kind, key: "private-wire",
                    }]
                    report = validate_scenario(value)
                    self.assertFalse(report["ok"])
                    self.assertIn("private physical medium identifier", str(report["errors"]))
                    with self.assertRaisesRegex(ValueError, "private physical medium identifier"):
                        compile_scenario(value)

    def test_physical_propagation_preserves_every_local_attachment(self) -> None:
        for outcome in ("success", "stale", "failed"):
            with self.subTest(outcome=outcome):
                value = scenario()
                value["media"][0]["attachments"].append({
                    "node_id": "a", "port_id": "p.100",
                    "node_local_observation": {
                        "resource_id": "interface:p.100",
                        "resource_type": "virtual-interface",
                        "properties": {"parent_resource_id": "interface:p", "vlan_id": 100},
                    },
                })
                value["events"][0]["propagation"].update(
                    cadence="serial", outcomes={"a": outcome},
                )
                self.assertTrue(validate_scenario(value)["ok"])
                expected = compile_scenario(value)
                local = expected["a"]
                self.assertEqual(len(local["logs"]), 2)
                self.assertEqual(len({row["event_id"] for row in local["logs"]}), 2)
                self.assertEqual({row["timestamp_ns"] for row in local["logs"]}, {100_000_000})
                self.assertEqual(
                    {row["resource_id"]: row["status"] for row in local["final_state"]},
                    {"interface:p": "down" if outcome == "success" else "up",
                     "interface:p.100": "down" if outcome == "success" else "up"},
                )
                self.assertEqual(expected["b"]["logs"][0]["timestamp_ns"], 200_000_000)
                preview = _preview_propagation(scenario_from_dict(value), "change")
                self.assertEqual(len(preview["events"]), 4)
                value["events"][0]["propagation"]["materialized"] = True
                value["events"].extend(preview["events"])
                actual = compile_scenario(value)
                for node_id in expected:
                    self.assertEqual(actual[node_id]["final_state"], expected[node_id]["final_state"])
                    self.assertEqual(
                        [(row["resource_id"], row["timestamp_ns"], row["state_changed"]) for row in actual[node_id]["logs"]],
                        [(row["resource_id"], row["timestamp_ns"], row["state_changed"]) for row in expected[node_id]["logs"]],
                    )

    def test_preview_rejects_payload_amplification_before_materializing(self) -> None:
        value = scenario()
        value["events"][0]["properties"] = {"note": "x" * 1_500_000}
        with self.assertRaisesRegex(ValueError, "response budget"):
            _preview_propagation(scenario_from_dict(value), "change")

    def test_preview_budget_includes_attachment_observation_payloads(self) -> None:
        value = scenario()
        value["media"][0]["attachments"][0]["node_local_observation"] = {
            "resource_id": "interface:p",
            "properties": {"note": "x" * 4_300_000},
        }
        with self.assertRaisesRegex(ValueError, "response budget"):
            _preview_propagation(scenario_from_dict(value), "change")

    def test_preview_checks_actual_encoded_response_size(self) -> None:
        value = scenario()
        value["events"][0]["status"] = "x" * 2_000_000
        value["events"][0]["propagation"]["targets"] = ["a"]
        with self.assertRaisesRegex(ValueError, "response budget"):
            _preview_propagation(scenario_from_dict(value), "change")

    def test_preview_materialization_has_the_same_effect_as_compilation(self) -> None:
        for cadence in ("parallel", "serial", "waves"):
            for mode in ("best-effort", "failed", "manual", "suppressed"):
                for physical in (True, False):
                    with self.subTest(cadence=cadence, mode=mode, physical=physical):
                        value = scenario()
                        event = value["events"][0]
                        if not physical:
                            event.update(
                                kind="status",
                                node_id="a",
                                resource_id="resource:test",
                                resource_type="resource",
                            )
                            del event["medium_id"]
                        event["propagation"].update(
                            cadence=cadence,
                            mode=mode,
                            jitter_ns=100_001,
                            delay_ns=50_000_001,
                            outcomes={"a": "ok", "b": "stale", "c": "success"},
                        )
                        expected = compile_scenario(value)
                        preview = _preview_propagation(
                            scenario_from_dict(value), "change"
                        )
                        event["propagation"]["materialized"] = True
                        value["events"].extend(preview["events"])
                        actual = compile_scenario(value)
                        for node_id in expected:
                            self.assertEqual(
                                actual[node_id]["final_state"],
                                expected[node_id]["final_state"],
                            )
                            self.assertEqual(
                                [
                                    (
                                        row["timestamp_ns"],
                                        row["outcome"],
                                        row["state_changed"],
                                    )
                                    for row in actual[node_id]["logs"]
                                ],
                                [
                                    (
                                        row["timestamp_ns"],
                                        row["outcome"],
                                        row["state_changed"],
                                    )
                                    for row in expected[node_id]["logs"]
                                ],
                            )

    def test_horizon_and_schedule_share_cadence_slots(self) -> None:
        for cadence, delay, expected in (
            ("waves", 100, [100_000_000, 100_000_000, 150_000_000]),
            ("serial", 0, [0, 1_000_000, 2_000_000]),
        ):
            event = scenario()["events"][0]
            event["propagation"].update(cadence=cadence, delay_ms=delay)
            actual = [
                delay_ns(1, event, node_id, index)
                for index, node_id in enumerate(("a", "b", "c"))
            ]
            self.assertEqual(actual, expected)
            self.assertEqual(
                propagation_horizon_ns(event["propagation"], target_count=3),
                max(actual),
            )

    def test_omitted_and_empty_targets_remain_distinct(self) -> None:
        value = scenario()
        event = value["events"][0]
        event["propagation"]["target_mode"] = "all-nodes"
        self.assertEqual(
            propagation_target_ids(value["media"], event, ["a", "b", "c"]),
            ("a", "b", "c"),
        )
        event["propagation"]["targets"] = []
        self.assertEqual(
            propagation_target_ids(value["media"], event, ["a", "b", "c"]), ()
        )

    def test_simultaneous_physical_and_local_events_preserve_authored_order(
        self,
    ) -> None:
        value = scenario()
        value["events"][0]["propagation"]["delay_ms"] = 0
        value["events"].append(
            {
                "event_id": "later",
                "timestamp_ns": 0,
                "order": 2,
                "node_id": "a",
                "kind": "status",
                "resource_id": "interface:p",
                "resource_type": "interface",
                "status": "up",
            }
        )
        plan = compile_scenario(value)["a"]
        self.assertEqual(plan["final_state"][0]["status"], "up")
        self.assertEqual([item["source_sequence"] for item in plan["logs"]], [1, 2])
        self.assertEqual([item["status"] for item in plan["logs"]], ["down", "up"])

    def test_materialization_preserves_capture_cutoff(self) -> None:
        value = scenario()
        value["capture_time_ns"] = 50_000_000
        expected = compile_scenario(value)
        preview = _preview_propagation(scenario_from_dict(value), "change")
        value["events"][0]["propagation"]["materialized"] = True
        value["events"].extend(preview["events"])
        report = validate_scenario(value)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["warnings"]), 3)
        self.assertEqual(compile_scenario(value), expected)

    def test_fractional_integer_coordinates_are_rejected(self) -> None:
        for field in ("timestamp_ns", "order"):
            value = scenario()
            value["events"][0][field] = 1.5
            self.assertFalse(validate_scenario(value)["ok"], field)
        for field in ("capture_time_ns", "seed"):
            value = scenario()
            value[field] = 1.5
            self.assertFalse(validate_scenario(value)["ok"], field)
        value = scenario()
        value["nodes"][0]["clock"] = {"offset_ns": 1.5}
        self.assertFalse(validate_scenario(value)["ok"])


@unittest.skipUnless(
    shutil.which("node"), "Node.js is required for executable editor conformance"
)
class BrowserSemanticsTests(unittest.TestCase):
    def run_web(self, code: str, value: dict | None = None) -> object:
        runner = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = vm.createContext({
  document: {addEventListener(){}}, structuredClone, console,
  crypto: require('node:crypto').webcrypto, input: request.input,
  semantics: JSON.parse(fs.readFileSync(request.root + '/semantics.json', 'utf8')),
});
vm.runInContext(fs.readFileSync(request.root + '/app.js', 'utf8'), context);
vm.runInContext('eventSemantics = semantics;', context);
Promise.resolve(vm.runInContext('(async () => {' + request.code + '})()', context))
  .then(result => process.stdout.write(JSON.stringify(result)))
  .catch(error => {console.error(error);process.exitCode = 1;});
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", runner],
            input=json.dumps(
                {
                    "root": WEB_ROOT.as_posix(),
                    "input": value or scenario(),
                    "code": code,
                }
            ),
            text=True,
            check=False,
            capture_output=True,
            encoding="utf-8",
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_attachment_identity_defaults_survive_browser_round_trip(self) -> None:
        for port, declared in (("p", None), ("interface:p", None), ("local:a/xe0", None), ("interface:p", "local:a-p")):
            with self.subTest(port=port, declared=declared):
                value = scenario()
                attachment = value["media"][0]["attachments"][0]
                attachment["port_id"] = port
                if declared is not None:
                    attachment["node_local_observation"] = {"resource_id": declared}
                output = self.run_web(
                    "scenario = normalizeScenario(input); return toCanonicalProject();", value,
                )
                self.assertTrue(validate_scenario(output)["ok"])
                self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_partial_multiaccess_pattern_uses_all_local_attachments(self) -> None:
        value = scenario()
        value["events"] = []
        value["media"][0]["attachments"].append({
            "node_id": "a", "port_id": "p2",
            "node_local_observation": {
                "resource_id": "local:a-p2", "resource_type": "virtual-interface",
            },
        })
        output = self.run_web("""
scenario = normalizeScenario(input);
const medium = scenario.nodes.find(node => node.kind === 'shared-medium');
scenario.events = buildPatternEvents('partial-multi-access', {
  time:0, delay:1, duration:100, targetId:medium.id, nodeId:'a',
});
return toCanonicalProject();
""", value)
        self.assertTrue(validate_scenario(output)["ok"])
        compiled = compile_scenario(output)
        self.assertEqual(len(output["events"]), 4)
        self.assertEqual({row["resource_id"] for row in compiled["a"]["logs"]}, {"interface:p", "local:a-p2"})
        self.assertEqual({row["resource_type"] for row in compiled["a"]["logs"]}, {"interface", "virtual-interface"})
        self.assertTrue(all(row["state_changed"] for row in compiled["a"]["logs"]))
        self.assertFalse(compiled["c"]["logs"][0]["state_changed"])
        self.assertNotIn("private-wire", json.dumps(compiled))

    def test_log_only_defaults_and_explicit_flags_survive_round_trip(self) -> None:
        for kind in ("log", "log-only", "log_only", "clock", "status"):
            for flags in (
                {},
                {"update_final_state": False},
                {"update_final_state": True},
                {"update_snapshot": False},
                {"update_snapshot": True},
                {"update_snapshot": True, "update_final_state": False},
            ):
                with self.subTest(kind=kind, flags=flags):
                    value = scenario()
                    value["media"] = []
                    value["events"] = [{
                        "event_id": "local", "timestamp_ns": 1, "node_id": "a",
                        "kind": kind, "resource_id": "thing:x",
                        "resource_type": "resource", "message": "Local event",
                        **flags,
                    }]
                    output = self.run_web(
                        "scenario = normalizeScenario(input); return toCanonicalProject();",
                        value,
                    )
                    expected = compile_scenario(value)
                    self.assertEqual(compile_scenario(output), expected)
                    self.assertEqual(
                        expected["a"]["logs"][0]["state_changed"],
                        flags.get("update_snapshot", flags.get("update_final_state", kind == "status")),
                    )

    def test_resource_type_defaults_and_aliases_survive_round_trip(self) -> None:
        for fields, resource_type in (
            ({}, "resource"),
            ({"target_type": "status"}, "resource"),
            ({"resource_kind": "route"}, "route"),
            ({"properties": {"resource_type": "neighbor"}}, "neighbor"),
            ({"payload": {"resource_type": "interface"}}, "interface"),
            ({"resource_type": "route", "resource_kind": "neighbor"}, "route"),
        ):
            with self.subTest(fields=fields):
                value = scenario()
                value["media"] = []
                value["events"] = [{
                    "event_id": "local", "timestamp_ns": 1, "node_id": "a",
                    "kind": "status", "resource_id": "thing:x", "status": "up",
                    **fields,
                }]
                output = self.run_web(
                    "scenario = normalizeScenario(input); return toCanonicalProject();", value,
                )
                self.assertEqual(output["events"][0]["resource_type"], resource_type)
                self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_exact_clock_coordinates_survive_round_trip(self) -> None:
        for coordinate in (0, 1, "9007199254740991", "9007199254740992", "9007199254740993", "-9007199254740993"):
            for aliases in (False, True):
                with self.subTest(coordinate=coordinate, aliases=aliases):
                    value = scenario()
                    value["capture_time_ns"] = "9007199254741999"
                    uncertainty = str(abs(int(coordinate)))
                    if aliases:
                        value["nodes"][0].update(clock_offset_ns=coordinate, clock_uncertainty_ns=uncertainty)
                    else:
                        value["nodes"][0]["clock"] = {"offset_ns": coordinate, "uncertainty_ns": uncertainty}
                    output = self.run_web(
                        "scenario = normalizeScenario(input); return toCanonicalProject();", value,
                    )
                    self.assertEqual(int(output["nodes"][0]["clock"]["offset_ns"]), int(coordinate))
                    self.assertEqual(int(output["nodes"][0]["clock"]["uncertainty_ns"]), int(uncertainty))
                    self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_browser_rejects_inexact_clock_numbers_without_rounding(self) -> None:
        for coordinate in (9007199254740992, 1.5, "1.5", True):
            with self.subTest(coordinate=coordinate):
                value = scenario()
                value["nodes"][0]["clock"] = {"offset_ns": coordinate}
                output = self.run_web("""
try { normalizeScenario(input); return null; } catch (error) { return error.message; }
""", value)
                self.assertIn("exact integer", output)

    def test_log_and_clock_form_save_preserves_nonmutating_default(self) -> None:
        for kind in ("log", "clock"):
            with self.subTest(kind=kind):
                value = scenario()
                value["media"] = []
                value["events"] = [{
                    "event_id": "local", "timestamp_ns": 1, "node_id": "a",
                    "kind": kind, "resource_id": "thing:x", "message": "Local event",
                }]
                output = self.run_web("""
scenario = normalizeScenario(input);
for (const id of ['event-heading','event-time','event-node','event-kind','event-outcome',
  'event-subject','event-action','event-payload','event-log','event-update-snapshot',
  'event-auto-propagate','save-event','delete-event']) dom[id] = {value:'',options:[]};
dom['event-kind'].options = [{value:input.events[0].kind}];
dom['event-outcome'].options = [{value:'ok'}];
validatePayloadField = () => {}; loadPropagationControls = () => {};
transact = mutate => mutate(); toast = () => {};
loadEventForm(scenario.events[0]);
dom['event-auto-propagate'].checked = false;
parsePayload = () => ({ok:true,value:JSON.parse(dom['event-payload'].value)});
saveEventFromForm({preventDefault(){}});
return toCanonicalProject();
""", value)
                self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_canonical_round_trip_preserves_schedule_and_capture(self) -> None:
        value = scenario()
        value["events"][0]["propagation"].update(
            target_mode="all-nodes",
            delay_ns=100_000_001,
            jitter_ns=1001,
            outcomes={"a": "failed", "b": "stale"},
        )
        output = self.run_web(
            "scenario = normalizeScenario(input); return toCanonicalProject();", value
        )
        self.assertEqual(
            output["events"][0]["propagation"], value["events"][0]["propagation"]
        )
        self.assertEqual(output["capture_time_ns"], value["capture_time_ns"])
        self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_exact_timestamps_and_explicit_orders_survive_round_trip(self) -> None:
        value = scenario()
        value["capture_time_ns"] = "9007199254740993"
        value["events"][0].update(timestamp_ns="9007199254740001", order=17)
        output = self.run_web(
            "scenario = normalizeScenario(input); return toCanonicalProject();", value
        )
        self.assertEqual(output["capture_time_ns"], value["capture_time_ns"])
        self.assertEqual(
            output["events"][0]["timestamp_ns"], value["events"][0]["timestamp_ns"]
        )
        self.assertEqual(output["events"][0]["order"], 17)

    def test_default_capture_is_chosen_only_by_the_server(self) -> None:
        output = self.run_web(
            "delete input.capture_time_ns; scenario = normalizeScenario(input); return toCanonicalProject();"
        )
        self.assertNotIn("capture_time_ns", output)
        self.assertTrue(validate_scenario(output)["ok"])

    def test_supported_physical_kinds_and_failed_truth_preview(self) -> None:
        for kind in EVENT_SEMANTICS["physical_kinds"]:
            value = scenario()
            value["events"][0]["kind"] = kind.replace("-", "_")
            output = self.run_web(
                "scenario = normalizeScenario(input); return linkStateAt(scenario.physical_links[0].id, 1);",
                value,
            )
            self.assertEqual(output, "down", kind)
        value["events"][0]["outcome"] = "failed"
        output = self.run_web(
            "scenario = normalizeScenario(input); return linkStateAt(scenario.physical_links[0].id, 1);",
            value,
        )
        self.assertEqual(output, "up")

    def test_deleting_imported_medium_removes_canonical_target_events(self) -> None:
        output = self.run_web("""
scenario = normalizeScenario(input);
selection = {type: 'node', id: scenario.nodes.find(n => n.kind === 'shared-medium').id};
renderAll = () => {}; globalThis.confirm = () => true;
deleteSelection();
return toCanonicalProject();
""")
        self.assertEqual(output["media"], [])
        self.assertEqual(output["events"], [])

    def test_editing_imported_status_and_time_replaces_canonical_values(self) -> None:
        output = self.run_web("""
scenario = normalizeScenario(input); selectedEventId = scenario.events[0].id;
const fields = {'event-time':'0.001','event-node':'','event-kind':'medium-state',
  'event-subject':'','event-action':'','event-outcome':'ok','event-log':''};
for (const [id, value] of Object.entries(fields)) dom[id] = {value};
dom['event-update-snapshot'] = {checked: true};
dom['event-auto-propagate'] = {checked: false};
dom['save-event'] = {}; dom['delete-event'] = {};
parsePayload = () => ({ok:true, value:{state:'up'}});
transact = mutate => mutate(); toast = () => {};
saveEventFromForm({preventDefault(){}});
return toCanonicalProject().events[0];
""")
        self.assertEqual(output["status"], "up")
        self.assertEqual(int(output["timestamp_ns"]), 1_000_000)

    def test_noop_event_form_save_preserves_exact_nanoseconds(self) -> None:
        for timestamp in ("1000001", "9007199254740993"):
            with self.subTest(timestamp=timestamp):
                value = scenario()
                value["capture_time_ns"] = "9007199254741999"
                value["events"][0]["timestamp_ns"] = timestamp
                output = self.run_web(
                    """
scenario = normalizeScenario(input);
for (const id of ['event-heading','event-time','event-node','event-kind','event-outcome',
  'event-subject','event-action','event-payload','event-log','event-update-snapshot',
  'event-auto-propagate','save-event','delete-event']) dom[id] = {value:'',options:[]};
dom['event-kind'].options = [{value:'medium-state'}];
dom['event-outcome'].options = [{value:'ok'}];
validatePayloadField = () => {}; loadPropagationControls = () => {};
transact = mutate => mutate(); toast = () => {};
loadEventForm(scenario.events[0]);
const displayed = dom['event-time'].value;
dom['event-auto-propagate'].checked = false;
parsePayload = () => ({ok:true,value:JSON.parse(dom['event-payload'].value)});
saveEventFromForm({preventDefault(){}});
return {displayed, timestamp:toCanonicalProject().events[0].timestamp_ns};
""",
                    value,
                )
                self.assertEqual(output["timestamp"], timestamp)
                self.assertEqual(
                    int(output["displayed"].replace(".", "")), int(timestamp)
                )

    def test_late_preview_cannot_render_for_different_selection_or_settings(
        self,
    ) -> None:
        for change in ("selection", "settings"):
            for rejected in (False, True):
                with self.subTest(change=change, rejected=rejected):
                    value = scenario()
                    value["change"] = change
                    value["rejected"] = rejected
                    output = self.run_web(
                        """
scenario = normalizeScenario(input); selectedEventId = scenario.events[0].id;
let delay = 100;
propagationSettings = () => ({mode:'best-effort',delay_ms:delay});
let complete, reject;
computePropagationPreview = () => new Promise((resolve, fail) => {complete=resolve;reject=fail;});
let renders = 0;
dom['propagation-preview'] = {textContent:'',replaceChildren(){renders++;},append(){renders++;}};
const pending = previewPropagation();
if (input.change === 'selection') selectedEventId = 'another-event'; else delay = 200;
if (input.rejected) reject(Error('stale error')); else complete({events:[],summary:'stale result'});
await pending;
return {renders,text:dom['propagation-preview'].textContent};
""",
                        value,
                    )
                    self.assertEqual(output["renders"], 0)
                    self.assertNotIn("stale", output["text"])

    def test_browser_uses_server_schedule_without_reinterpreting_it(self) -> None:
        value = scenario()
        value["schedule"] = _preview_propagation(scenario_from_dict(value), "change")
        output = self.run_web(
            """
scenario = normalizeScenario(input);
apiJson = async (url, payload) => {
  if (url !== '/api/scenario/propagation' || payload.event_id !== 'change') throw Error('wrong endpoint');
  return input.schedule;
};
return await computePropagationPreview(scenario.events[0], scenario.events[0].propagation);
""",
            value,
        )
        self.assertEqual(output["events"], value["schedule"]["events"])

    def test_semantics_asset_uses_get(self) -> None:
        output = self.run_web("""
globalThis.fetch = async (url, options) => ({ok:true, json:async()=>({url,method:options.method})});
return await apiJson('/assets/semantics.json');
""")
        self.assertEqual(output, {"url": "/assets/semantics.json", "method": "GET"})


if __name__ == "__main__":
    unittest.main()

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

    def run_project_load(self, code: str, value: dict | None = None) -> object:
        return self.run_web("""
scenario = normalizeScenario(input.scenario || input);
const actions = {};
const requests = [];
const ui = {renders:0, pickers:0, downloads:0, messages:[]};
for (const id of ['new-project','open-project','project-file','save-project','undo','redo',
  'validate-project','generate-dumps','project-name']) {
  dom[id] = {value:scenario.name,
    addEventListener(type, handler) { actions[`${id}:${type}`] = handler; },
    click() { ui.pickers += 1; },
  };
}
globalThis.addEventListener = () => {};
globalThis.confirm = () => true;
globalThis.requestAnimationFrame = callback => callback();
globalThis.Blob = class Blob {};
globalThis.fetch = () => new Promise((resolve, reject) => requests.push({resolve, reject}));
loadPropagationControls = () => {};
renderAll = () => { ui.renders += 1; dom['project-name'].value = scenario.name; };
renderCanvas = () => {};
fitCanvas = () => {};
downloadBlob = () => { ui.downloads += 1; };
toast = (message, kind) => ui.messages.push({message, kind});
bindProjectActions();
function startLoad(kind, name) {
  if (kind === 'new') {
    const index = requests.length;
    const pending = actions['new-project:click']();
    return {pending,
      resolve:project => requests[index].resolve({ok:true, json:async () => project}),
      reject:error => requests[index].reject(error),
    };
  }
  let resolveText, rejectText;
  const text = new Promise((resolve, reject) => { resolveText=resolve; rejectText=reject; });
  const pending = actions['project-file:change']({target:{value:'selected',files:[{
    name, text:() => text,
  }]}});
  return {pending, resolve:project => resolveText(JSON.stringify(project)), reject:rejectText};
}
function currentState() {
  return {scenario, dirty, history, future, selection, selectedEventId};
}
""" + code, value)

    def test_latest_new_or_open_handler_owns_project_replacement(self) -> None:
        for first in ("new", "open"):
            for second in ("new", "open"):
                for first_fails in (False, True):
                    with self.subTest(first=first, second=second, first_fails=first_fails):
                        result = self.run_project_load("""
transact(() => { scenario.name = 'Unsaved original'; }, {render:false});
const older = startLoad(input.first, 'older.json');
const newer = startLoad(input.second, 'newer.json');
const winner = {...input.scenario, name:'Winning project'};
newer.resolve(winner);
await newer.pending;
const before = JSON.stringify(currentState());
if (input.first_fails) older.reject(new Error('stale load failure'));
else older.resolve({...input.scenario, name:'Stale project'});
await older.pending;
return {unchanged:JSON.stringify(currentState()) === before,
  name:scenario.name, dirty, historyLength:history.length, futureLength:future.length, ui};
""", {"scenario": scenario(), "first": first, "second": second, "first_fails": first_fails})
                        self.assertTrue(result["unchanged"])
                        self.assertEqual(result["name"], "Winning project")
                        self.assertFalse(result["dirty"])
                        self.assertEqual(result["historyLength"], 0)
                        self.assertEqual(result["futureLength"], 0)
                        self.assertEqual(result["ui"]["renders"], 1)
                        self.assertEqual(len(result["ui"]["messages"]), 1)
                        self.assertNotIn("stale", json.dumps(result["ui"]).lower())

    def test_startup_or_file_load_cannot_replace_intervening_edits(self) -> None:
        for kind in ("startup", "open"):
            for failed in (False, True):
                with self.subTest(kind=kind, failed=failed):
                    result = self.run_project_load("""
const loading = input.kind === 'startup' ? {
  pending:loadBlankProject(),
  resolve:project => requests[0].resolve({ok:true, json:async () => project}),
  reject:error => requests[0].reject(error),
} : startLoad('open', 'pending.json');
transact(() => { scenario.description = 'Keep my edit'; }, {render:false});
selection = {type:'node', id:scenario.nodes[0].id};
selectedEventId = scenario.events[0].id;
const before = JSON.stringify(currentState());
if (input.failed) loading.reject(new Error('stale read failure'));
else loading.resolve({...input.scenario, name:'Stale replacement'});
await loading.pending;
return {unchanged:JSON.stringify(currentState()) === before, dirty,
  historyLength:history.length, ui};
""", {"scenario": scenario(), "kind": kind, "failed": failed})
                    self.assertTrue(result["unchanged"])
                    self.assertTrue(result["dirty"])
                    self.assertEqual(result["historyLength"], 1)
                    self.assertEqual(result["ui"]["renders"], 0)
                    self.assertEqual(result["ui"]["messages"], [])

    def test_undo_redo_save_and_active_drag_invalidate_pending_load(self) -> None:
        for edit in ("undo", "redo", "save", "drag"):
            with self.subTest(edit=edit):
                result = self.run_project_load("""
transact(() => { scenario.name = 'Current project'; }, {render:false});
if (input.edit === 'redo') undo();
const loading = startLoad('new', 'pending');
if (input.edit === 'undo') undo();
else if (input.edit === 'redo') redo();
else if (input.edit === 'save') {
  dom['project-name'].value = scenario.name;
  actions['save-project:click']();
} else {
  const node = scenario.nodes[0];
  pointers.set(1, {x:0,y:0});
  dragState = {kind:'node', pointerId:1, id:node.id,
    start:{x:0,y:0}, origin:{...node.position}, changed:false};
  clientToWorld = (x,y) => ({x,y});
  canvasPointerMove({pointerId:1,clientX:20,clientY:30});
}
const before = JSON.stringify(currentState());
const rendersBefore = ui.renders;
loading.resolve({...input.scenario, name:'Stale project'});
await loading.pending;
return {unchanged:JSON.stringify(currentState()) === before,
  extraRenders:ui.renders-rendersBefore, dirty,
  historyLength:history.length, futureLength:future.length, ui};
""", {"scenario": scenario(), "edit": edit})
                self.assertTrue(result["unchanged"])
                self.assertEqual(result["extraRenders"], 0)
                self.assertEqual(result["dirty"], edit != "save")
                if edit == "undo":
                    self.assertEqual(result["futureLength"], 1)
                self.assertFalse(any("Started" in item["message"] for item in result["ui"]["messages"]))

    def test_open_picker_cancels_an_older_blank_load_before_file_selection(self) -> None:
        result = self.run_project_load("""
const loading = startLoad('new', 'pending');
const before = JSON.stringify(currentState());
actions['open-project:click']();
loading.resolve({...input, name:'Stale project'});
await loading.pending;
return {unchanged:JSON.stringify(currentState()) === before, ui};
""")
        self.assertTrue(result["unchanged"])
        self.assertEqual(result["ui"]["pickers"], 1)
        self.assertEqual(result["ui"]["messages"], [])

    def test_current_load_failure_has_explicit_new_and_open_behavior(self) -> None:
        for kind in ("new", "open"):
            with self.subTest(kind=kind):
                result = self.run_project_load("""
transact(() => { scenario.name = 'Unsaved original'; }, {render:false});
const before = JSON.stringify(currentState());
const loading = startLoad(input.kind, 'broken.json');
loading.reject(new Error('current failure'));
await loading.pending;
return {unchanged:JSON.stringify(currentState()) === before, dirty,
  nodes:scenario.nodes.length, historyLength:history.length, ui};
""", {"scenario": scenario(), "kind": kind})
                if kind == "open":
                    self.assertTrue(result["unchanged"])
                    self.assertTrue(result["dirty"])
                    self.assertEqual(result["ui"]["messages"][0]["kind"], "error")
                else:
                    self.assertFalse(result["dirty"])
                    self.assertEqual(result["nodes"], 0)
                    self.assertEqual(result["historyLength"], 0)
                    self.assertIn("Started", result["ui"]["messages"][0]["message"])

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

    def test_schema_identifier_alphabet_and_length_survive_browser_round_trip(self) -> None:
        identifiers = [
            "A", "0", "aZ09_.:@/+~-", "n" + "x" * 255,
            *(f"node{character}1" for character in "_.:@/+~-"),
        ]
        value = {
            "scenario_id": "scenario_.:@/+~-",
            "seed": 7,
            "capture_time_ns": 1_000_000_000,
            "nodes": [{"node_id": identifier} for identifier in identifiers],
            "media": [],
            "events": [],
        }
        self.assertTrue(validate_scenario(value)["ok"])
        output = self.run_web(
            "scenario = normalizeScenario(input); return toCanonicalProject();", value,
        )
        self.assertTrue(validate_scenario(output)["ok"])
        self.assertEqual(output["scenario_id"], value["scenario_id"])
        self.assertEqual([node["node_id"] for node in output["nodes"]], identifiers)
        self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_distinct_identifiers_keep_all_cross_references_and_generated_history(self) -> None:
        node_ids = ["node+1", "node-1", "node@1", "node~1"]
        value = {
            "scenario_id": "scenario+@~1",
            "seed": 7,
            "capture_time_ns": 1_000_000_000,
            "nodes": [{"node_id": node_id} for node_id in node_ids],
            "media": [],
            "events": [],
        }
        for index, punctuation in enumerate("+-@~"):
            medium_id = f"wire{punctuation}1"
            attached_nodes = node_ids[:3] if punctuation == "~" else node_ids[:2]
            attachments = [{
                "node_id": node_id,
                "port_id": f"port{punctuation}{index}/0",
                "resource_id": f"attachment{punctuation}{index}:{node_id}",
                "node_local_observation": {
                    "resource_id": f"observed{punctuation}{index}:{node_id}",
                    "properties": {"oper_status": "up"},
                },
            } for node_id in attached_nodes]
            value["media"].append({
                "medium_id": medium_id,
                "kind": "broadcast" if punctuation == "~" else "point-to-point",
                "attachments": attachments,
            })
            value["events"].append({
                "event_id": f"physical{punctuation}1",
                "timestamp_ns": index * 100_000_000,
                "kind": "medium-state",
                "medium_id": medium_id,
                "status": "down",
                "propagation": {
                    "targets": attached_nodes,
                    "outcomes": {node_id: "success" for node_id in attached_nodes},
                },
            })
            value["events"].append({
                "event_id": f"local{punctuation}1",
                "timestamp_ns": index * 100_000_000 + 1,
                "node_id": node_ids[index],
                "resource_id": f"resource{punctuation}1",
                "status": "up",
            })
        self.assertTrue(validate_scenario(value)["ok"])
        output = self.run_web(
            "scenario = normalizeScenario(input); return toCanonicalProject();", value,
        )
        self.assertTrue(validate_scenario(output)["ok"])
        self.assertEqual([node["node_id"] for node in output["nodes"]], node_ids)
        expected_media = {medium["medium_id"]: medium for medium in value["media"]}
        actual_media = {medium["medium_id"]: medium for medium in output["media"]}
        self.assertEqual(set(actual_media), set(expected_media))
        for medium_id, medium in expected_media.items():
            for actual, expected in zip(
                actual_media[medium_id]["attachments"], medium["attachments"], strict=True,
            ):
                for field in ("node_id", "port_id", "resource_id", "node_local_observation"):
                    if field == "node_local_observation":
                        self.assertEqual(actual[field]["resource_id"], expected[field]["resource_id"])
                    else:
                        self.assertEqual(actual[field], expected[field])
        expected_events = {event["event_id"]: event for event in value["events"]}
        self.assertEqual({event["event_id"] for event in output["events"]}, set(expected_events))
        for event in output["events"]:
            expected = expected_events[event["event_id"]]
            for field in ("node_id", "resource_id", "medium_id", "propagation"):
                if field in expected:
                    self.assertEqual(event[field], expected[field])
        self.assertEqual(compile_scenario(output), compile_scenario(value))

    def test_invalid_identifiers_are_rejected_without_lossy_rewriting(self) -> None:
        identifiers = ["+node", "@node", "_node", "a b", "a?b", "a\\b", "a" * 257]
        results = self.run_web("""
return input.identifiers.map(value => {
  try { return {value: safeIdentifier(value, 'fallback')}; }
  catch (error) { return {error: error.message}; }
});
""", {"identifiers": identifiers})
        for identifier, result in zip(identifiers, results, strict=True):
            with self.subTest(identifier=identifier):
                value = scenario()
                value["scenario_id"] = identifier
                with self.assertRaisesRegex(ValueError, "safe identifier characters"):
                    scenario_from_dict(value)
                self.assertIn("safe identifier characters", result["error"])
        self.assertEqual(
            self.run_web("return [safeIdentifier(null, 'fallback'), safeIdentifier('', 'fallback')];"),
            ["fallback", "fallback"],
        )

    def test_invalid_identifier_save_keeps_unsaved_project_and_reports_error(self) -> None:
        result = self.run_web("""
scenario = normalizeScenario(input);
scenario.nodes[0].id = 'node?1';
dirty = true;
dom['project-name'] = {value:scenario.name};
globalThis.Blob = class Blob {};
let downloads = 0;
const messages = [];
downloadBlob = () => { downloads += 1; };
toast = (message, kind) => messages.push({message, kind});
saveProject();
return {downloads, dirty, messages};
""")
        self.assertEqual(result["downloads"], 0)
        self.assertTrue(result["dirty"])
        self.assertEqual(result["messages"][0]["kind"], "error")
        self.assertIn("Could not save project", result["messages"][0]["message"])
        self.assertIn("safe identifier characters", result["messages"][0]["message"])

    def test_generating_dump_keeps_project_unsaved_until_source_save(self) -> None:
        result = self.run_web("""
scenario = normalizeScenario(input);
dirty = true;
dom['generation-dialog'] = {open:true};
dom['retry-generation'] = {};
dom['project-name'] = {value:scenario.name};
const states = [];
const downloads = [];
setGenerationState = kind => states.push(kind);
toast = () => {};
downloadBlob = (blob, filename) => downloads.push({blob, filename});
globalThis.Blob = class Blob { constructor(parts) { this.parts = parts; } };
globalThis.fetch = async () => ({
  ok:true, headers:{get:() => 'attachment; filename="generated.tgz"'},
  blob:async () => ({generated:true}),
});
await generateDumps();
const dirtyAfterGeneration = dirty;
saveProject();
return {dirtyAfterGeneration, dirtyAfterSave:dirty, states,
  filenames:downloads.map(item => item.filename),
  saved:JSON.parse(downloads[1].blob.parts.join(''))};
""")
        self.assertTrue(result["dirtyAfterGeneration"])
        self.assertFalse(result["dirtyAfterSave"])
        self.assertEqual(result["states"], ["working", "success"])
        self.assertEqual(result["filenames"][0], "generated.tgz")
        self.assertTrue(result["filenames"][1].endswith(".scenario.json"))
        self.assertEqual(compile_scenario(result["saved"]), compile_scenario(scenario()))

    def test_generation_success_and_failures_preserve_existing_dirty_state(self) -> None:
        for initially_dirty in (False, True):
            for result_kind in ("success", "http-error", "network-error"):
                with self.subTest(initially_dirty=initially_dirty, result_kind=result_kind):
                    result = self.run_web("""
scenario = normalizeScenario(input.scenario);
dirty = input.initially_dirty;
dom['generation-dialog'] = {open:true};
dom['retry-generation'] = {};
const states = [];
let downloads = 0;
setGenerationState = kind => states.push(kind);
downloadBlob = () => { downloads += 1; };
globalThis.fetch = async () => {
  if (input.result_kind === 'network-error') throw new Error('network unavailable');
  if (input.result_kind === 'http-error') return {
    ok:false, status:422, json:async () => ({error:'invalid scenario'}),
  };
  return {ok:true, headers:{get:() => null}, blob:async () => ({generated:true})};
};
await generateDumps();
return {dirty, downloads, states, retryHidden:dom['retry-generation'].hidden};
""", {"scenario": scenario(), "initially_dirty": initially_dirty, "result_kind": result_kind})
                    succeeded = result_kind == "success"
                    self.assertEqual(result["dirty"], initially_dirty)
                    self.assertEqual(result["downloads"], int(succeeded))
                    self.assertEqual(result["states"], ["working", "success" if succeeded else "error"])
                    self.assertEqual(result["retryHidden"], succeeded)

    def test_edits_during_outstanding_generation_remain_unsaved(self) -> None:
        result = self.run_web("""
scenario = normalizeScenario(input);
dirty = false;
dom['generation-dialog'] = {open:true};
dom['retry-generation'] = {};
setGenerationState = () => {};
downloadBlob = () => {};
let resolveResponse;
let submitted;
globalThis.fetch = (_url, options) => {
  submitted = JSON.parse(options.body).scenario;
  return new Promise(resolve => { resolveResponse = resolve; });
};
const running = generateDumps();
transact(() => { scenario.description = 'Edited during generation'; }, {render:false});
resolveResponse({ok:true, headers:{get:() => null}, blob:async () => ({generated:true})});
await running;
return {dirty, description:scenario.description,
  submittedDescription:submitted.metadata.description, historyLength:history.length};
""")
        self.assertTrue(result["dirty"])
        self.assertEqual(result["description"], "Edited during generation")
        self.assertEqual(result["submittedDescription"], "")
        self.assertEqual(result["historyLength"], 1)

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

    def test_file_open_and_save_preserve_exact_seed_and_python_jitter_history(self) -> None:
        histories = {}
        for seed in (
            0, 7, 9_007_199_254_740_991,
            "9007199254740992", "9007199254740993", "18446744073709551615",
            "+009007199254740993", "1" + "0" * 100,
        ):
            with self.subTest(seed=seed):
                value = scenario()
                value["seed"] = seed
                value["events"][0]["propagation"].update(
                    delay_ns=100_000_001, jitter_ns=49_000_001,
                )
                output = self.run_web("""
const messages = [];
loadPropagationControls = () => {};
renderAll = () => {};
globalThis.requestAnimationFrame = () => {};
toast = (message, kind) => messages.push({message, kind});
await handleProjectFile({target:{value:'selected',files:[{
  name:'exact-seed.scenario.json', text:async () => JSON.stringify(input),
}]}});
const normalizedSeed = scenario.seed;
dom['project-name'] = {value:scenario.name};
globalThis.Blob = class Blob { constructor(parts) { this.parts = parts; } };
let saved;
downloadBlob = blob => { saved = JSON.parse(blob.parts.join('')); };
saveProject();
return {normalizedSeed, saved, messages};
""", value)
                expected_seed = str(int(seed)) if isinstance(seed, str) else seed
                self.assertEqual(output["normalizedSeed"], expected_seed)
                self.assertEqual(output["saved"]["seed"], expected_seed)
                self.assertTrue(all(message["kind"] == "success" for message in output["messages"]))
                expected = compile_scenario(value)
                self.assertEqual(compile_scenario(output["saved"]), expected)
                histories[str(int(seed))] = [
                    log["timestamp_ns"] for node in expected.values() for log in node["logs"]
                ]
        self.assertNotEqual(histories["9007199254740992"], histories["9007199254740993"])

    def test_invalid_or_unsafe_seed_is_rejected_at_import_and_serialization(self) -> None:
        for seed in (9_007_199_254_740_992, 9_007_199_254_740_993, 1.5, True, None, "", "1.5", -1, "-1"):
            with self.subTest(seed=seed):
                value = scenario()
                value["seed"] = seed
                output = self.run_web("""
const messages = [];
try { normalizeScenario(input); messages.push(null); }
catch (error) { messages.push(error.message); }
scenario.seed = input.seed;
try { toCanonicalProject(); messages.push(null); }
catch (error) { messages.push(error.message); }
return messages;
""", value)
                for message in output:
                    self.assertIsInstance(message, str)
                    self.assertIn("Seed", message)
                    self.assertIn("cannot be negative" if seed in (-1, "-1") else "exact integer", message)

    def test_missing_seed_retains_default(self) -> None:
        output = self.run_web("""
delete input.seed;
scenario = normalizeScenario(input);
return {normalizedSeed:scenario.seed, savedSeed:toCanonicalProject().seed};
""")
        self.assertEqual(output, {"normalizedSeed": 1, "savedSeed": 1})

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

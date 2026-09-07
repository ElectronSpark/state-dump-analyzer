import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const SOURCE = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `topology.js must define ${name}()`);
  const ending = /\r?\n\}/.exec(SOURCE.slice(start));
  assert.ok(ending, `${name}() must have a closing brace`);
  return SOURCE.slice(start, start + ending.index + ending[0].length);
}

function harness(forward, reverse, symmetry = {}) {
  // Run the actual outcome helpers and their real classification dependencies;
  // loading the whole page entry would also start the unrelated topology UI.
  const functions = [
    "firstArray", "firstDeclaredString", "normalizedRouteEnum", "firstRouteEnum", "routeStateEnum", "explicitRouteBoolean",
    "explicitRouteConsistency", "explicitRouteDisposition", "legacyRouteDisposition", "routeCompletenessIsInferred",
    "routeCompletenessIsUnresolved", "routeCompletenessIsUnknown", "routeConsistencyIsInconsistent", "routeForwardingSegments",
    "routeValueIsTerminal", "routeValueIsCycle", "routeValueIsPolicyBlocked", "routePolicyPresentation", "pathIsDead",
    "pathIsControlPlaneOnly", "pathIsInferred", "pathIsUnresolved", "pathIsInconsistent", "pathIsUsableActive",
    "traceIsControlPlaneOnly", "controlPlaneOnlyFinding", "controlPlaneOnlyReason", "traceIsInconsistent", "traceIsIncomplete",
    "traceDirectionState", "bidirectionalSummary", "routeTraceOutcome",
  ];
  const constants = SOURCE.match(/const ROUTE_[A-Z_]+ = new Set\([\s\S]*?\);/g);
  assert.ok(constants?.length);
  return new Function("state", `${constants.join("\n")}\n${functions.map(functionSource).join("\n")}
    return { traceDirectionState, bidirectionalSummary, routeTraceOutcome, pathIsDead, routeValueIsCycle, routeValueIsPolicyBlocked, pathIsUsableActive };`
  )({ routeTraces: { forward, reverse }, routeBundle: { symmetry } });
}

function trace(overrides = {}, pathOverrides = {}) {
  return {
    reachable: true, complete: true, completeness: "complete", consistency: "consistent",
    paths: [{ activity: "active", selection: "selected", completeness: "complete", consistency: "consistent", disposition: "forward", segments: [], ...pathOverrides }],
    ...overrides,
  };
}

const unresolvedTrace = () => trace(
  { reachable: false, complete: false, completeness: "incomplete" },
  { disposition: "unresolved", unresolved: true, completeness: "incomplete", terminal_reason: "hop_budget_exhausted" },
);

test("budget-limited unresolved directions remain incomplete, not a proven bidirectional failure", () => {
  for (const symmetry of [{}, { endpoint_state: "both_unreachable" }, { one_way: true }]) {
    const forward = unresolvedTrace(); const reverse = unresolvedTrace();
    const api = harness(forward, reverse, symmetry);
    assert.equal(api.traceDirectionState(forward).code, "unresolved");
    const comparison = api.bidirectionalSummary();
    assert.equal(comparison.code, "incomplete");
    assert.equal(comparison.label, "Endpoint validation incomplete");
    assert.match(comparison.detail, /unresolved forward · unresolved return/);
    const outcome = api.routeTraceOutcome(forward, comparison);
    assert.equal(outcome.code, "incomplete"); assert.equal(outcome.label, "Trace is incomplete");
  }
});

test("unresolved or unknown directions do not imply one-way failure or established reachability", () => {
  const unknown = trace({ reachable: null }, { activity: "unknown", selection: "unknown", disposition: "unknown" });
  for (const uncertain of [unresolvedTrace(), unknown, trace({ completeness: "best_effort" })]) {
    for (const pair of [[uncertain, trace()], [trace(), uncertain]]) {
      const api = harness(...pair);
      const comparison = api.bidirectionalSummary();
      assert.equal(comparison.code, "incomplete");
      assert.doesNotMatch(comparison.label, /fail|reachable/);
      assert.equal(api.routeTraceOutcome(uncertain, comparison).code, "incomplete");
    }
  }
  const api = harness(trace(), trace(), { endpoint_state: "unresolved" });
  assert.equal(api.bidirectionalSummary().code, "incomplete");
});

test("single-direction unresolved and unknown outcomes never become proven failures", () => {
  for (const unresolved of [unresolvedTrace(), trace({ reachable: null, paths: [] })]) {
    const api = harness(unresolved);
    assert.equal(api.bidirectionalSummary().code, "single_direction");
    assert.equal(api.routeTraceOutcome(unresolved, api.bidirectionalSummary()).code, "incomplete");
  }
  const unknown = trace({ reachable: null }, { activity: "unknown", selection: "unknown", disposition: "unknown" });
  const api = harness(unknown);
  assert.equal(api.routeTraceOutcome(unknown, api.bidirectionalSummary()).code, "unknown");
});

test("explicit drops, loops, and policy blocks retain their proven direction failures", () => {
  for (const [disposition, directionCode, outcomeCode] of [
    ["drop", "dropped", "unreachable"], ["forwarding_loop", "cycle", "cycle"], ["policy_blocked", "policy_blocked", "policy_blocked"],
  ]) {
    // Terminal evidence stays authoritative even when later traversal is incomplete.
    const failed = trace({ reachable: false, complete: false, completeness: "incomplete" }, { disposition, completeness: "incomplete" });
    const single = harness(failed);
    assert.equal(single.traceDirectionState(failed).code, directionCode);
    assert.equal(single.routeTraceOutcome(failed, single.bidirectionalSummary()).code, outcomeCode);
    const oneWay = harness(failed, trace());
    assert.equal(oneWay.bidirectionalSummary().code, "one_way");
    const both = harness(failed, failed);
    assert.equal(both.bidirectionalSummary().code, "both_unreachable");
    assert.equal(both.bidirectionalSummary().label, "Both directions fail");
    const mixed = harness(failed, unresolvedTrace());
    assert.equal(mixed.bidirectionalSummary().code, "incomplete");
    assert.equal(mixed.routeTraceOutcome(failed, mixed.bidirectionalSummary()).code, outcomeCode);
  }
});

test("fully resolved endpoints retain reachable and informational asymmetric outcomes", () => {
  const forward = trace(); const reverse = trace();
  for (const pathRelation of ["symmetric", "not_comparable", "asymmetric"]) {
    const api = harness(forward, reverse, { endpoint_state: "bidirectionally_reachable", path_relation: { state: pathRelation } });
    const comparison = api.bidirectionalSummary();
    assert.equal(comparison.code, pathRelation === "asymmetric" ? "asymmetric" : "compared");
    assert.equal(comparison.className, "is-good");
    assert.equal(api.routeTraceOutcome(forward, comparison).code, pathRelation === "asymmetric" ? "asymmetric" : "reachable");
  }
});

for (const [disposition, directionCode, classifier] of [
  ["drop", "dropped", "pathIsDead"], ["forwarding_loop", "cycle", "routeValueIsCycle"], ["policy_blocked", "policy_blocked", "routeValueIsPolicyBlocked"],
]) {
  test(`a ${disposition} branch cannot establish direction failure while another eligible candidate is uncertain`, () => {
    const failed = trace({}, { disposition }).paths[0];
    const candidates = [
      unresolvedTrace().paths[0],
      { ...unresolvedTrace().paths[0], activity: "unknown" },
      { ...unresolvedTrace().paths[0], selection: "unknown" },
      trace({}, { activity: "unknown", selection: "unknown", disposition: "unknown" }).paths[0],
      trace({}, { completeness: "unknown", disposition: "unknown" }).paths[0],
    ];
    for (const candidate of candidates) {
      for (const paths of [[failed, candidate], [candidate, failed]]) {
        const mixed = trace({ reachable: false, complete: false, completeness: "incomplete", paths });
        const snapshot = structuredClone(mixed);
        for (const pair of [[mixed, trace()], [trace(), mixed]]) {
          const api = harness(...pair);
          assert.equal(api.pathIsUsableActive(candidate), false);
          assert.equal(api.traceDirectionState(mixed).code, "unresolved");
          assert.equal(api.bidirectionalSummary().code, "incomplete");
          assert.equal(api.routeTraceOutcome(mixed, api.bidirectionalSummary()).code, "incomplete");
          assert.equal(api[classifier](failed), true, "the explicit branch failure remains available");
          assert.deepEqual(mixed, snapshot, "direction aggregation never rewrites branch evidence");
        }
      }
    }
    const allFailed = trace({ reachable: false, complete: false, completeness: "incomplete", paths: [failed, { ...failed }] });
    const api = harness(allFailed, trace());
    assert.equal(api.traceDirectionState(allFailed).code, directionCode);
    assert.equal(api.bidirectionalSummary().code, "one_way");
    assert.equal(harness(allFailed, allFailed).bidirectionalSummary().code, "both_unreachable");
  });
}

test("known inactive or excluded alternatives are not promoted into forwarding candidates", () => {
  const failed = trace({}, { disposition: "drop" }).paths[0];
  const exclusions = [
    ...["inactive", "standby", "backup", "withdrawn", "disabled"].map((activity) => ({ activity })),
    ...["eligible_standby", "inactive_candidate", "best_effort_candidate", "comparison_only", "control_expected_not_observed", "ineligible_dead"].map((selection) => ({ selection })),
  ];
  for (const exclusion of exclusions) {
    const alternative = { ...unresolvedTrace().paths[0], ...exclusion };
    const mixed = trace({ reachable: false, paths: [failed, alternative] });
    const api = harness(mixed, trace());
    assert.equal(api.pathIsUsableActive(alternative), false);
    assert.equal(api.traceDirectionState(mixed).code, "dropped");
    assert.equal(api.bidirectionalSummary().code, "one_way");
  }
});

test("a usable active path keeps inactive terminal alternatives branch-local", () => {
  for (const disposition of ["drop", "forwarding_loop", "policy_blocked"]) {
    const healthy = trace().paths[0];
    const failed = trace({}, { disposition, activity: "inactive", selection: "inactive_candidate" }).paths[0];
    const mixed = trace({ paths: [failed, healthy] });
    const api = harness(mixed, trace());
    assert.equal(api.pathIsUsableActive(healthy), true);
    assert.equal(api.traceDirectionState(mixed).code, "resolved");
    assert.equal(api.bidirectionalSummary().code, "compared");
    assert.equal(api.routeTraceOutcome(mixed, api.bidirectionalSummary()).code, "reachable");
  }
});

test("backend partial active reachability remains partial despite reachable:false", () => {
  const delivered = trace({}, {
    disposition: "delivered", selected_active_by_plugin: true,
    plugin_terminal: { classification: "delivered", classification_complete: true },
    terminal_reachability: { state: "reached", reached: true, exact_match: true },
  }).paths[0];
  const dropped = trace({}, {
    disposition: "drop", selected_active_by_plugin: true,
    plugin_terminal: { classification: "not_delivered", classification_complete: true },
    terminal_reachability: { state: "not_reached", reached: false, exact_match: false },
  }).paths[0];
  // multi_node_route aggregates [True, False] into reaches_target=None and then
  // publishes reachable=(reaches_target is True), not an all-branches-failed flag.
  for (const complete of [true, false]) {
    const partial = trace({
      reachable: false, complete, completeness: complete ? "complete" : "incomplete",
      paths: [delivered, dropped],
      endpoint_reachability: {
        state: "partial_active_reachability", reaches_target: null, active_branch_count: 2,
        reached_active_branch_count: 1, failed_active_branch_count: 1, unresolved_active_branch_count: 0,
        all_active_branches_reach: false, selection_complete: true, no_selected_active_path: false,
      },
    });
    for (const symmetry of [{}, { endpoint_state: "partial_active_reachability" }]) {
      for (const pair of [[partial, trace()], [trace(), partial]]) {
        const api = harness(...pair, symmetry);
        assert.equal(api.pathIsUsableActive(delivered), true);
        assert.equal(api.pathIsDead(dropped), true);
        assert.equal(api.traceDirectionState(partial).code, "partial");
        assert.equal(api.traceDirectionState(partial).label, "partial reachability");
        const comparison = api.bidirectionalSummary();
        assert.equal(comparison.code, "incomplete");
        const outcome = api.routeTraceOutcome(partial, comparison);
        assert.equal(outcome.code, "partial"); assert.equal(outcome.label, "Partial active reachability");
        assert.match(outcome.detail, /Some selected active branches reach/);
        assert.doesNotMatch(outcome.detail, /No complete forwarding path/);
      }
    }
  }
});

test("reachable:false alone cannot turn an active resolved path into a proven drop", () => {
  for (const includeTerminalAlternative of [false, true]) {
    const paths = [trace().paths[0]];
    if (includeTerminalAlternative) paths.push(trace({}, { disposition: "drop" }).paths[0]);
    const uncertain = trace({ reachable: false, paths });
    const api = harness(uncertain, trace());
    assert.equal(api.traceDirectionState(uncertain).code, "unknown");
    assert.equal(api.bidirectionalSummary().code, "incomplete");
    assert.equal(api.routeTraceOutcome(uncertain, api.bidirectionalSummary()).code, "incomplete");
  }
});

test("counterfactual delivered alternatives without selected active branches remain unverified, not dropped", () => {
  const alternate = trace({
    reachable: false, counterfactual: true, steering_profile_id: "force-alternate",
    endpoint_reachability: {
      state: "unknown_no_selected_active_path", reaches_target: null,
      active_branch_count: 0, no_selected_active_path: true, selection_complete: false,
    },
  }, {
    activity: "inactive", selection: "eligible_standby", disposition: "delivered", selected_active_by_plugin: false,
    plugin_terminal: { classification: "delivered", classification_complete: true },
    terminal_reachability: { state: "reached", reached: true },
  });
  for (const reverse of [undefined, trace()]) {
    const api = harness(alternate, reverse);
    assert.equal(api.traceDirectionState(alternate).code, "unknown");
    assert.equal(api.traceDirectionState(alternate).label, "no selected active path");
    const comparison = api.bidirectionalSummary();
    assert.equal(comparison.code, reverse ? "incomplete" : "single_direction");
    assert.ok(["unknown", "incomplete"].includes(api.routeTraceOutcome(alternate, comparison).code));
    assert.equal(api.pathIsDead(alternate.paths[0]), false);
    const withoutEndpointMetadata = { ...alternate }; delete withoutEndpointMetadata.endpoint_reachability;
    assert.equal(api.traceDirectionState(withoutEndpointMetadata).code, "unknown");
  }
});

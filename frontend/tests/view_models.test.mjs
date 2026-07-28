import assert from "node:assert/strict";
import test from "node:test";

import {
  dashboardDescriptorErrorMessage,
  dashboardFieldLookup,
  dashboardFilterMatches,
  dashboardRowIncluded,
  dashboardStatisticEvaluation,
  declaredHealthPresentation,
  graphStatusClass,
  rangeSummaryFacts,
  replaceAbortController,
  routeEndpointSeedValue,
  routePayloadForwardingPresentation,
} from "../assets/view_models.js";

test("normalized topology health uses the declared core vocabulary", () => {
  assert.equal(declaredHealthPresentation({ status_class: "usable" }), "good");
  assert.equal(declaredHealthPresentation({ condition_class: "error" }), "error");
  assert.equal(
    declaredHealthPresentation(
      { status_class: "degraded", status: "usable" },
      { includeStatus: true },
    ),
    "warning",
  );
  assert.equal(declaredHealthPresentation({ status: "usable" }), null);
  assert.equal(
    declaredHealthPresentation({ status: "unusable" }, { includeStatus: true }),
    "error",
  );
});

test("route-table seeding prefers canonical identifiers over labels", () => {
  assert.equal(
    routeEndpointSeedValue(
      { source_id: "node-a", label: "PE-A / Alpha NOS" },
      "source",
    ),
    "node-a",
  );
  assert.equal(
    routeEndpointSeedValue(
      { resource_id: "node-b/loopback", value: "10.0.0.2" },
      "destination",
    ),
    "node-b/loopback",
  );
  assert.equal(routeEndpointSeedValue("203.0.113.0/24", "destination"), "203.0.113.0/24");
});

test("correlation graph status honors normalized status transport fields", () => {
  assert.equal(graphStatusClass({ status_class: "error", status: "usable" }), "error");
  assert.equal(graphStatusClass({ status: "error" }), "error");
  assert.equal(graphStatusClass({ status_value: "down" }), "unknown");
});

test("an empty forwarding result is not fabricated as local delivery", () => {
  const empty = routePayloadForwardingPresentation({});
  assert.deepEqual(empty.branches, []);
  assert.equal(empty.nextHopText, "Not returned");
  assert.equal(empty.egressText, "Not returned");
  assert.equal(empty.scope, "no active branch");
  assert.match(empty.emptyMessage, /does not infer local delivery/);

  const selected = routePayloadForwardingPresentation({
    branches: [
      { next_hop: "primary", egress_interface: "xe-0/0/0", active: true },
      { next_hop: "backup", egress_interface: "xe-0/0/1", active: false },
    ],
  });
  assert.equal(selected.nextHopText, "primary");
  assert.equal(selected.egressText, "xe-0/0/0");
  assert.equal(selected.scope, "1 active");
});

test("bounded range facts preserve affected and evaluated populations", () => {
  const facts = rangeSummaryFacts({
    event_count: 125_005,
    failure_count: 2_425,
    affected_resource_count: 7_502,
    relationship_change_count: 54_898,
    endpoint_diff_evaluated_count: 500,
    truncated: {
      endpoint_diff: true,
      relationship_changes: true,
    },
  });
  assert.equal(facts.eventCount, 125_005);
  assert.equal(facts.affectedResourceCount, 7_502);
  assert.equal(facts.evaluatedEndpointCount, 500);
  assert.equal(facts.omittedEndpointCount, 7_002);
  assert.deepEqual(facts.truncatedKinds, ["endpoint_diff", "relationship_changes"]);
});

test("latest-request replacement aborts only the superseded controller", () => {
  const previous = {
    aborted: false,
    abort() {
      this.aborted = true;
    },
  };
  const next = { aborted: false, abort() { this.aborted = true; } };
  assert.equal(replaceAbortController(previous, () => next), next);
  assert.equal(previous.aborted, true);
  assert.equal(next.aborted, false);
});

test("dashboard lookup preserves explicit null and envelope precedence", () => {
  const row = { status: null, state: { status: "up", metric: 7 } };
  assert.deepEqual(dashboardFieldLookup(row, "status"), { found: true, value: null });
  assert.deepEqual(dashboardFieldLookup(row, "metric"), { found: true, value: 7 });
  assert.deepEqual(dashboardFieldLookup(row, "missing"), { found: false, value: undefined });
  assert.equal(
    dashboardFilterMatches(row, { field: "status", operator: "exists", value: true }),
    true,
  );
  assert.equal(
    dashboardFilterMatches({}, { field: "status", operator: "eq", value: null }),
    false,
  );
  assert.equal(
    dashboardFilterMatches(row, { field: "status", operator: "eq", value: null }),
    true,
  );
});

test("local dashboard statistics match backend null and numeric semantics", () => {
  const rows = [
    { state: { value: null } },
    { state: { value: 0 } },
    { state: { value: "3" } },
    { state: { value: true } },
    { state: {} },
  ];
  const distinct = dashboardStatisticEvaluation(rows, {
    aggregation: "count_distinct",
    field: "state.value",
  });
  assert.equal(distinct.value, 4);
  assert.equal(distinct.sampleCount, 4);

  const sum = dashboardStatisticEvaluation(rows, {
    aggregation: "sum",
    field: "state.value",
  });
  assert.equal(sum.value, 0);
  assert.equal(sum.sampleCount, 1);

  const empty = dashboardStatisticEvaluation([{ state: {} }], {
    aggregation: "sum",
    field: "state.value",
  });
  assert.equal(empty.value, 0);
  assert.equal(empty.sampleCount, 0);
});

test("serialized dashboard descriptor failures remain visible to the operator", () => {
  assert.equal(
    dashboardDescriptorErrorMessage({
      descriptor_errors: [{
        path: "dashboards[0].tables[0].max_rows",
        message: "must be an integer between 1 and 500",
      }],
    }),
    "dashboards[0].tables[0].max_rows: must be an integer between 1 and 500",
  );
  assert.equal(dashboardDescriptorErrorMessage({ descriptor_errors: [] }), "");
});

test("dashboard row inclusion preserves tri-state existence semantics", () => {
  assert.equal(dashboardRowIncluded({ kind: "ETG", exists: true }, ["ETG"]), true);
  assert.equal(dashboardRowIncluded({ kind: "ETG", exists: false }, ["ETG"]), false);
  assert.equal(dashboardRowIncluded({ kind: "ETG", exists: null }, ["ETG"]), false);
  assert.equal(dashboardRowIncluded({ kind: "ETG" }, ["ETG"]), false);
  assert.equal(dashboardRowIncluded({ kind: "ETG", exists: null }, ["ETG"], true), true);
  assert.equal(dashboardRowIncluded({ kind: "ETE", exists: true }, ["ETG"], true), false);
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  authoritativeTopologyLink,
  controlPlaneCollectionPageDecision,
  dashboardComparable,
  dashboardDescriptorErrorMessage,
  dashboardFieldLookup,
  dashboardFilterMatches,
  dashboardRowIncluded,
  dashboardStatisticEvaluation,
  declaredHealthPresentation,
  durableMutationDisposition,
  durableReportMemberValidation,
  durableReportRequestBody,
  durableReviewControlAvailability,
  graphStatusClass,
  rangeSummaryFacts,
  reconstructionTimelineModel,
  reconstructionTimelineValueAtPosition,
  replaceAbortController,
  routeEndpointSeedValue,
  routePayloadForwardingPresentation,
  stateChipClassName,
  statusClassPresentation,
  statusSegmentClassName,
  topologyResolutionLabel,
  virtualScrollTopForIndex,
  virtualScrollWindow,
} from "../assets/view_models.js";

test("million-row virtual scrolling stays inside a bounded physical surface", () => {
  const rowCount = 1_250_001;
  const rowHeight = 44;
  const maximumHeight = 8_000_000;
  const viewportHeight = 600;
  const targetIndex = rowCount - 1;
  const scrollTop = virtualScrollTopForIndex({
    index: targetIndex,
    rowCount,
    rowHeight,
    maximumHeight,
    viewportHeight,
  });
  const model = virtualScrollWindow({
    rowCount,
    rowHeight,
    maximumHeight,
    viewportHeight,
    scrollTop,
    overscan: 10,
  });

  assert.ok(model.totalHeight <= maximumHeight);
  assert.ok(model.scale < rowHeight);
  assert.equal(model.end, rowCount);
  assert.ok(model.start <= targetIndex);
  assert.ok(targetIndex < model.end);
  assert.ok(model.end - model.start < 100);
  assert.ok(scrollTop <= maximumHeight - viewportHeight);
});

test("small virtual logs preserve one physical row per logical row", () => {
  const model = virtualScrollWindow({
    rowCount: 1_001,
    rowHeight: 44,
    maximumHeight: 8_000_000,
    viewportHeight: 440,
    scrollTop: 22_000,
    overscan: 10,
  });
  assert.equal(model.scale, 44);
  assert.equal(model.totalHeight, 44_044);
  assert.equal(model.start, 490);
  assert.equal(model.end, 520);
});

test("typed topology links require authoritative federation evidence", () => {
  assert.equal(authoritativeTopologyLink({ link_id: "legacy" }), true);
  assert.equal(authoritativeTopologyLink({
    typed_federation: true,
    resolution: "matched",
    federation_complete: true,
    federation_truncated: false,
  }), true);
  for (const candidate of [
    { resolution: "ambiguous", federation_complete: true, federation_truncated: false },
    { resolution: "conflict", federation_complete: true, federation_truncated: false },
    { resolution: "matched", federation_complete: false, federation_truncated: false },
    { resolution: "matched", federation_complete: true, federation_truncated: true },
  ]) {
    assert.equal(authoritativeTopologyLink({ typed_federation: true, ...candidate }), false);
  }
  assert.equal(authoritativeTopologyLink(null), false);
});

test("topology resolution audits have outcome-specific labels", () => {
  assert.equal(topologyResolutionLabel("ambiguous"), "Multiple candidate remote endpoints");
  assert.equal(topologyResolutionLabel("conflict"), "Conflicting remote endpoints");
  assert.equal(topologyResolutionLabel("incomplete"), "Incomplete federation evidence");
  assert.equal(topologyResolutionLabel("mixed"), "Mixed federation outcomes");
  assert.equal(topologyResolutionLabel("unresolved"), "No compatible remote endpoint");
  assert.equal(topologyResolutionLabel("future-value"), "Unresolved federation outcome");
});

const DASHBOARD_PARITY_FIXTURE = JSON.parse(readFileSync(
  new URL("../../tests/fixtures/dashboard-evaluator-parity.json", import.meta.url),
  "utf8",
));

function parityRecipeAmount(recipe, bounds) {
  return Number(bounds[recipe.bound]) + Number(recipe.offset || 0);
}

function buildParityValue(recipe, bounds) {
  switch (recipe.kind) {
    case "literal":
      return recipe.value;
    case "signed_zero":
      return recipe.negative === true ? -0 : 0;
    case "nonfinite":
      return {
        nan: Number.NaN,
        positive_infinity: Number.POSITIVE_INFINITY,
        negative_infinity: Number.NEGATIVE_INFINITY,
      }[recipe.value];
    case "bigint_bits": {
      const bits = parityRecipeAmount(recipe, bounds);
      return 1n << BigInt(bits - 1);
    }
    case "nested_sequence": {
      let value = null;
      for (let depth = 0; depth < parityRecipeAmount(recipe, bounds); depth += 1) {
        value = [value];
      }
      return value;
    }
    case "sequence_items":
      return Array.from(
        { length: parityRecipeAmount(recipe, bounds) },
        (_, index) => index,
      );
    case "mapping_items":
      return Object.fromEntries(Array.from(
        { length: parityRecipeAmount(recipe, bounds) },
        (_, index) => [`key-${index}`, index],
      ));
    case "comparison_unit_tree": {
      const targetUnits = parityRecipeAmount(recipe, bounds);
      const groupCount = Number(bounds.max_container_items);
      let leafCount = targetUnits - 1 - groupCount;
      if (leafCount < 0 || leafCount > groupCount * 3) {
        throw new Error("comparison_unit_tree recipe is not representable");
      }
      const groups = Array.from({ length: groupCount }, () => {
        const groupSize = Math.min(3, leafCount);
        leafCount -= groupSize;
        return Array.from({ length: groupSize }, () => 0);
      });
      if (leafCount !== 0) {
        throw new Error("comparison_unit_tree recipe left unused units");
      }
      return groups;
    }
    case "repeated_string":
      return "x".repeat(parityRecipeAmount(recipe, bounds));
    case "unsupported":
      return Symbol("unsupported dashboard parity value");
    case "cycle_sequence": {
      const cycle = [];
      cycle.push(cycle);
      return cycle;
    }
    default:
      throw new Error(`unknown dashboard parity recipe: ${recipe.kind}`);
  }
}

test("normalized topology status uses one closed server vocabulary", () => {
  const expected = new Map([
    ["absent", ["warning", "is-absent"]],
    ["degraded", ["warning", "is-degraded"]],
    ["error", ["error", "is-error"]],
    ["healthy", ["good", "is-healthy"]],
    ["unknown", ["warning", "is-unknown"]],
  ]);
  for (const [statusClass, [health, className]] of expected) {
    const value = { status_class: statusClass };
    assert.equal(declaredHealthPresentation(value), health);
    assert.equal(statusClassPresentation(value), className);
  }
  assert.equal(declaredHealthPresentation({ status: "healthy" }), null);
  assert.equal(
    declaredHealthPresentation({ status: "healthy" }, { includeStatus: true }),
    "good",
  );
  for (const deadAlias of ["failed", "failure", "good", "warning", "usable", "unusable"]) {
    assert.equal(statusClassPresentation({ status_class: deadAlias }), "is-unknown");
  }
});

test("every normalized topology status class has explicit component CSS", () => {
  const css = readFileSync(new URL("../assets/styles.css", import.meta.url), "utf8");
  for (const statusClass of ["absent", "degraded", "error", "healthy", "unknown"]) {
    const className = statusClassPresentation({ status_class: statusClass });
    assert.match(css, new RegExp(`\\.topology-node-time\\.${className}::before`));
    assert.match(css, new RegExp(`\\.topology-status\\.${className}(?:\\s|\\{|,)`));
  }
});

test("state chips use the shared closed status presentation vocabulary", () => {
  const expected = new Map([
    ["absent", "state-chip is-absent"],
    ["degraded", "state-chip is-degraded"],
    ["error", "state-chip is-error"],
    ["healthy", "state-chip is-healthy"],
    ["unknown", "state-chip is-unknown"],
  ]);
  for (const [statusClass, className] of expected) {
    assert.equal(stateChipClassName({ status_class: statusClass }), className);
  }
  for (const deadAlias of ["failed", "failure", "good", "warning", "usable", "unusable"]) {
    assert.equal(stateChipClassName({ status_class: deadAlias }), "state-chip is-unknown");
  }
});

test("every normalized status chip class has explicit component CSS", () => {
  const css = readFileSync(new URL("../assets/styles.css", import.meta.url), "utf8");
  for (const statusClass of ["absent", "degraded", "error", "healthy", "unknown"]) {
    const className = statusClassPresentation({ status_class: statusClass });
    assert.match(css, new RegExp(`\\.state-chip\\.${className}(?:\\s|\\{|,)`));
  }
});

test("timeline status segments use the shared closed status presentation vocabulary", () => {
  const expected = new Map([
    ["absent", "status-segment is-absent"],
    ["degraded", "status-segment is-degraded"],
    ["error", "status-segment is-error"],
    ["healthy", "status-segment is-healthy"],
    ["unknown", "status-segment is-unknown"],
  ]);
  for (const [statusClass, className] of expected) {
    assert.equal(statusSegmentClassName({ status_class: statusClass }), className);
  }
  for (const deadAlias of ["failed", "failure", "ambiguous", "good", "warning", "usable", "unusable"]) {
    assert.equal(
      statusSegmentClassName({ status_class: deadAlias }),
      "status-segment is-unknown",
    );
  }
});

test("every normalized timeline status segment has explicit component CSS", () => {
  const css = readFileSync(new URL("../assets/styles.css", import.meta.url), "utf8");
  for (const statusClass of ["absent", "degraded", "error", "healthy", "unknown"]) {
    const className = statusClassPresentation({ status_class: statusClass });
    assert.match(css, new RegExp(`\\.status-segment\\.${className}(?:\\s|\\{|,)`));
  }
});

test("reconstruction timeline places and clamps an exact absolute instant", () => {
  const startNs = "1759680000000000000";
  const endNs = "1759680000000001000";
  const midpoint = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "1759680000000000500",
    startNs,
    endNs,
    captureNs: endNs,
  });
  assert.deepEqual(midpoint, {
    available: true,
    basisKind: "absolute_time",
    coordinateKind: "absolute_time",
    axisStartNs: startNs,
    axisEndNs: endNs,
    valueNs: "1759680000000000500",
    clampedValueNs: "1759680000000000500",
    positionPercent: 50,
    clamped: false,
  });

  const before = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "1759679999999999999",
    startNs,
    endNs,
  });
  assert.equal(before.positionPercent, 0);
  assert.equal(before.clampedValueNs, startNs);
  assert.equal(before.clamped, true);

  const after = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "1759680000000001001",
    startNs,
    endNs,
  });
  assert.equal(after.positionPercent, 100);
  assert.equal(after.clampedValueNs, endNs);
  assert.equal(after.clamped, true);
});

test("reconstruction timeline keeps watermark-relative coordinates relative", () => {
  const model = reconstructionTimelineModel({
    basisKind: "relative_to_watermark",
    valueNs: "-2000",
    startNs: "1759680000000001000",
    endNs: "1759680000000005000",
    captureNs: "1759680000000005000",
  });
  assert.deepEqual(model, {
    available: true,
    basisKind: "relative_to_watermark",
    coordinateKind: "relative_offset",
    axisStartNs: "-4000",
    axisEndNs: "0",
    valueNs: "-2000",
    clampedValueNs: "-2000",
    positionPercent: 50,
    clamped: false,
  });

  const endFallback = reconstructionTimelineModel({
    basisKind: "relative_to_watermark",
    valueNs: "0",
    startNs: "1759680000000001000",
    endNs: "1759680000000005000",
  });
  assert.equal(endFallback.coordinateKind, "relative_offset");
  assert.equal(endFallback.axisStartNs, "-4000");
  assert.equal(endFallback.axisEndNs, "0");
  assert.equal(endFallback.valueNs, "0");
  assert.equal(endFallback.positionPercent, 100);
});

test("reconstruction timeline handles degenerate and unavailable ranges safely", () => {
  const degenerate = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "1759680000000005000",
    startNs: "1759680000000005000",
    endNs: "1759680000000005000",
  });
  assert.equal(degenerate.available, true);
  assert.equal(degenerate.axisStartNs, degenerate.axisEndNs);
  assert.equal(degenerate.clampedValueNs, degenerate.valueNs);
  assert.equal(degenerate.positionPercent, 50);
  assert.equal(degenerate.clamped, false);

  for (const input of [
    {},
    { basisKind: "absolute_time", valueNs: "not-an-integer", startNs: "1", endNs: "2" },
    { basisKind: "absolute_time", valueNs: "1", startNs: "2", endNs: "1" },
    { basisKind: "relative_to_watermark", valueNs: "-1", startNs: "1" },
    { basisKind: "unsupported", valueNs: "1", startNs: "0", endNs: "2" },
  ]) {
    const unavailable = reconstructionTimelineModel(input);
    assert.equal(unavailable.available, false);
    assert.equal(unavailable.coordinateKind, "unknown");
    assert.equal(unavailable.axisStartNs, null);
    assert.equal(unavailable.axisEndNs, null);
    assert.equal(unavailable.valueNs, null);
    assert.equal(unavailable.clampedValueNs, null);
    assert.equal(unavailable.positionPercent, null);
    assert.equal(unavailable.clamped, false);
  }
});

test("reconstruction timeline inverse mapping preserves exact BigInt coordinates", () => {
  const absolute = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "9007199254740993501",
    startNs: "9007199254740993001",
    endNs: "9007199254740994001",
  });
  assert.equal(
    reconstructionTimelineValueAtPosition(absolute, 0),
    "9007199254740993001",
  );
  assert.equal(
    reconstructionTimelineValueAtPosition(absolute, 500_000),
    "9007199254740993501",
  );
  assert.equal(
    reconstructionTimelineValueAtPosition(absolute, 1_000_000),
    "9007199254740994001",
  );

  const indivisible = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "9007199254740993001",
    startNs: "9007199254740993001",
    endNs: "9007199254740993008",
  });
  assert.equal(
    reconstructionTimelineValueAtPosition(indivisible, 333_333),
    "9007199254740993003",
  );
});

test("reconstruction timeline inverse mapping clamps and fails closed", () => {
  const model = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "150",
    startNs: "100",
    endNs: "200",
  });
  assert.equal(reconstructionTimelineValueAtPosition(model, -1), "100");
  assert.equal(reconstructionTimelineValueAtPosition(model, 1_000_001), "200");
  assert.equal(reconstructionTimelineValueAtPosition(model, "500000"), "150");

  for (const invalidPosition of [
    null,
    undefined,
    "",
    "1.5",
    Number.NaN,
    Number.POSITIVE_INFINITY,
    {},
  ]) {
    assert.equal(
      reconstructionTimelineValueAtPosition(model, invalidPosition),
      null,
    );
  }
  assert.equal(
    reconstructionTimelineValueAtPosition(
      reconstructionTimelineModel(),
      500_000,
    ),
    null,
  );
});

test("reconstruction timeline inverse mapping handles relative and degenerate axes", () => {
  const relative = reconstructionTimelineModel({
    basisKind: "relative_to_watermark",
    valueNs: "-2000",
    startNs: "1759680000000001000",
    endNs: "1759680000000005000",
    captureNs: "1759680000000005000",
  });
  assert.equal(
    reconstructionTimelineValueAtPosition(relative, 0),
    "-4000",
  );
  assert.equal(
    reconstructionTimelineValueAtPosition(relative, 500_000),
    "-2000",
  );
  assert.equal(
    reconstructionTimelineValueAtPosition(relative, 1_000_000),
    "0",
  );
  assert.ok(
    BigInt(reconstructionTimelineValueAtPosition(relative, 1_000_001)) <= 0n,
  );

  const degenerate = reconstructionTimelineModel({
    basisKind: "absolute_time",
    valueNs: "1759680000000005000",
    startNs: "1759680000000005000",
    endNs: "1759680000000005000",
  });
  for (const position of [-1, 0, 500_000, 1_000_000, 1_000_001]) {
    assert.equal(
      reconstructionTimelineValueAtPosition(degenerate, position),
      "1759680000000005000",
    );
  }
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

test("request replacement aborts the prior signal and preserves explicit cancellation", () => {
  const previous = new AbortController();
  const next = replaceAbortController(previous);
  assert.equal(previous.signal.aborted, true);
  assert.equal(next.signal.aborted, false);
  next.abort();
  assert.equal(next.signal.aborted, true);
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

test("local dashboard comparison is bounded, cycle-safe, and fail-closed", () => {
  let allowedDepth = null;
  for (let depth = 0; depth < 16; depth += 1) allowedDepth = [allowedDepth];
  assert.notEqual(dashboardComparable(allowedDepth), null);

  let excessiveDepth = null;
  for (let depth = 0; depth < 17; depth += 1) excessiveDepth = [excessiveDepth];
  const excessiveItems = Array.from({ length: 1_025 }, (_, index) => index);
  const excessiveUnits = Array.from({ length: 1_024 }, () => [1, 2, 3]);
  const cyclic = [];
  cyclic.push(cyclic);

  for (const invalid of [
    excessiveDepth,
    excessiveItems,
    excessiveUnits,
    "x".repeat(65_537),
    cyclic,
  ]) {
    assert.equal(dashboardComparable(invalid), null);
    assert.equal(
      dashboardFilterMatches(
        { state: { value: invalid } },
        { field: "state.value", operator: "eq", value: invalid },
      ),
      false,
    );
    assert.equal(
      dashboardFilterMatches(
        { state: { value: invalid } },
        { field: "state.value", operator: "not_eq", value: "other" },
      ),
      false,
    );
  }
});

test("invalid local dashboard samples are excluded and signed zero compares equal", () => {
  const cyclic = {};
  cyclic.self = cyclic;
  const oversized = Array.from({ length: 1_025 }, (_, index) => index);
  const distinct = dashboardStatisticEvaluation([
    { state: { value: 0 } },
    { state: { value: -0 } },
    { state: { value: cyclic } },
    { state: { value: oversized } },
  ], {
    aggregation: "count_distinct",
    field: "state.value",
  });

  assert.equal(dashboardComparable(-0), dashboardComparable(0));
  assert.equal(distinct.value, 1);
  assert.equal(distinct.matchingCount, 4);
  assert.equal(distinct.sampleCount, 2);
  assert.equal(
    dashboardFilterMatches(
      { state: { value: -0 } },
      { field: "state.value", operator: "eq", value: 0 },
    ),
    true,
  );
});

test("dashboard evaluator follows the shared cross-language parity fixture", () => {
  const fixture = DASHBOARD_PARITY_FIXTURE;
  assert.equal(fixture.schema_version, 1);
  const values = new Map(fixture.values.map((item) => [
    item.id,
    buildParityValue(item.recipe, fixture.bounds),
  ]));

  for (const item of fixture.values) {
    assert.equal(
      dashboardComparable(values.get(item.id)) !== null,
      item.comparable,
      `comparable case ${item.id}`,
    );
  }

  for (const fixtureCase of fixture.equality_cases) {
    assert.equal(
      dashboardFilterMatches(
        { state: { value: values.get(fixtureCase.left) } },
        {
          field: "state.value",
          operator: "eq",
          value: values.get(fixtureCase.right),
        },
      ),
      fixtureCase.equal,
      `equality case ${fixtureCase.id}`,
    );
  }

  for (const fixtureCase of fixture.filter_cases) {
    const state = Object.hasOwn(fixtureCase, "actual")
      ? { value: values.get(fixtureCase.actual) }
      : {};
    const expected = Object.hasOwn(fixtureCase, "candidates")
      ? fixtureCase.candidates.map((item) => values.get(item))
      : values.get(fixtureCase.expected);
    assert.equal(
      dashboardFilterMatches(
        { state },
        {
          field: "state.value",
          operator: fixtureCase.operator,
          value: expected,
        },
      ),
      fixtureCase.matches,
      `filter case ${fixtureCase.id}`,
    );
  }
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

test("control-plane pagination follows declared offsets and fails closed", () => {
  assert.deepEqual(
    controlPlaneCollectionPageDecision({
      payload: { items: [{ id: 1 }], next_offset: null },
      offset: 0,
      requestedLimit: 5,
      accumulatedCount: 0,
      maximumCount: 10,
    }),
    {
      complete: true,
      capExceeded: false,
      nextOffset: null,
      totalCount: 1,
    },
  );
  assert.deepEqual(
    controlPlaneCollectionPageDecision({
      payload: { items: [{ id: 1 }, { id: 2 }], next_offset: 7 },
      offset: 5,
      requestedLimit: 2,
      accumulatedCount: 5,
      maximumCount: 10,
    }),
    {
      complete: false,
      capExceeded: false,
      nextOffset: 7,
      totalCount: 7,
    },
  );
  assert.equal(
    controlPlaneCollectionPageDecision({
      payload: { items: [{ id: 1 }], next_offset: 10 },
      offset: 9,
      requestedLimit: 1,
      accumulatedCount: 9,
      maximumCount: 10,
    }).capExceeded,
    true,
  );
  assert.throws(
    () => controlPlaneCollectionPageDecision({
      payload: { items: [{ id: 1 }], next_offset: 5 },
      offset: 5,
      requestedLimit: 1,
      accumulatedCount: 0,
      maximumCount: 10,
    }),
    /does not advance/,
  );
  assert.throws(
    () => controlPlaneCollectionPageDecision({
      payload: { next_offset: null },
      offset: 0,
      requestedLimit: 1,
      accumulatedCount: 0,
      maximumCount: 10,
    }),
    /items array/,
  );
});

test("durable report scopes cover revisions, live sessions, and snapshots", () => {
  assert.deepEqual(
    durableReportRequestBody({ kind: "revision", id: "rev-a" }),
    { revision_ids: ["rev-a"] },
  );
  assert.deepEqual(
    durableReportRequestBody({ kind: "session", id: "session-a" }),
    { session_id: "session-a" },
  );
  assert.deepEqual(
    durableReportRequestBody({ kind: "snapshot", id: "snapshot-a" }),
    { snapshot_id: "snapshot-a" },
  );
  assert.throws(
    () => durableReportRequestBody({ kind: "unknown", id: "value" }),
    /unsupported report scope kind/,
  );
});

test("durable report member validation rejects unsafe revision vectors", () => {
  const member = (revisionId) => ({ revision_id: revisionId });
  assert.deepEqual(
    durableReportMemberValidation([member("r1"), member("r2")], 2),
    { valid: true, memberCount: 2, reason: null },
  );
  assert.equal(durableReportMemberValidation([], 2).reason, "empty");
  assert.equal(
    durableReportMemberValidation([member("r1"), member("r1")], 2).reason,
    "duplicate",
  );
  assert.equal(
    durableReportMemberValidation([member("r1"), member("r2"), member("r3")], 2).reason,
    "oversized",
  );
  assert.equal(durableReportMemberValidation([member("")], 2).reason, "invalid");
});

test("durable mutation disposition retains only ambiguous outcomes", () => {
  assert.equal(durableMutationDisposition({ ambiguous: true }), "retain");
  assert.equal(durableMutationDisposition({ ambiguous: false }), "discard");
  assert.equal(durableMutationDisposition(new Error("known failure")), "discard");
});

test("durable review controls enforce read-only and report-write exclusion", () => {
  const base = {
    ready: true,
    writable: true,
    connecting: false,
    markerBusy: false,
    correlationBusy: false,
    reportBusy: false,
    selectionReady: true,
  };
  const readOnly = durableReviewControlAvailability({
    ...base,
    writable: false,
  });
  assert.equal(readOnly.reportDisabled, false);
  assert.equal(readOnly.markerDisabled, true);
  assert.equal(readOnly.correlationDisabled, true);

  const reportBusy = durableReviewControlAvailability({
    ...base,
    reportBusy: true,
  });
  assert.equal(reportBusy.markerDisabled, true);
  assert.equal(reportBusy.correlationDisabled, true);

  const markerBusy = durableReviewControlAvailability({
    ...base,
    markerBusy: true,
  });
  assert.equal(markerBusy.reportDisabled, true);
  assert.equal(markerBusy.reportScopeDisabled, true);

  const journalBlocked = durableReviewControlAvailability({
    ...base,
    journalBlocked: true,
  });
  assert.equal(journalBlocked.reportDisabled, false);
  assert.equal(journalBlocked.markerDisabled, true);
  assert.equal(journalBlocked.correlationDisabled, true);
});

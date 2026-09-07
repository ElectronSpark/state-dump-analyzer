import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `missing production function ${name}`);
  const end = /\r?\n\}/.exec(source.slice(start));
  assert.ok(end);
  return source.slice(start, start + end.index + end[0].length);
}

function harness() {
  const state = {
    cursorNs: 50n,
    viewStartNs: 0n,
    viewEndNs: 100n,
    resourceById: new Map(),
    laneByResource: new Map(),
    eventByUid: new Map(),
    dataset: {
      kind_descriptors: [{ kind: "thing", condition_field: "mode" }],
      resources: [],
      events: [],
    },
  };
  const functions = [
    "canonicalResourceId", "resourceIdOf", "resourceKindDescriptor",
    "resourceKind", "resourceLayer", "resourceLabel", "presentationTags",
    "registerResource", "ensureLane", "normalizeInterval", "deriveLaneIntervals",
    "normalizeTimeline", "normalizeRecordLane", "normalizeSourceMark", "statusAtLane",
    "fallbackResourceItems",
  ];
  const factory = new Function("state", `
    const toNs = (value, fallback = 0n) => value == null ? fallback : BigInt(value);
    const formatValue = String;
    const dashboardFieldValue = (value, field) => value[field];
    const isScaleMode = () => false;
    const MAX_RESOURCE_ROWS = 100;
    ${functions.map(functionSource).join("\n")}
    return { normalizeTimeline, deriveLaneIntervals, statusAtLane, fallbackResourceItems };
  `);
  return { state, ...factory(state) };
}

function serverLane(overrides = {}) {
  return {
    lane_id: "r1",
    resource_id: "r1",
    resource: {
      resource_id: "r1", kind: "thing", layer: "device",
      state: { mode: "future-final" },
    },
    has_lifecycle_history: true,
    lifecycle_intervals: [],
    status_intervals: [],
    event_marks: [],
    ...overrides,
  };
}

function normalize(h, raw, start = "0", end = "60") {
  h.normalizeTimeline({ start_ns: start, end_ns: end, lanes: [raw] });
  return h.state.laneByResource.get("r1");
}

test("successful empty server history preserves absence and never borrows a future snapshot", () => {
  const h = harness();
  h.state.dataset.lifecycle_intervals = [{ resource: "r1", valid_from_ns: "80", valid_to_ns: null }];
  h.state.dataset.state_intervals = [{ resource: "r1", valid_from_ns: "80", valid_to_ns: null, properties: { mode: "future-final" } }];
  const lane = normalize(h, serverLane());
  assert.deepEqual(lane.lifecycle, []);
  assert.deepEqual(lane.statuses, []);
  assert.deepEqual(h.statusAtLane(lane, 50n), {
    exists: false, status: "absent", statusClass: "absent", properties: {},
  });
  const [tableRow] = h.fallbackResourceItems();
  assert.equal(tableRow.exists, false);
  assert.deepEqual(tableRow.state, {});
});

test("missing lifecycle evidence remains unknown for current and older timeline responses", () => {
  for (const hasHistory of [false, undefined]) {
    const h = harness();
    const lane = normalize(h, serverLane({ has_lifecycle_history: hasHistory }));
    assert.deepEqual(h.statusAtLane(lane, 50n), {
      exists: null, status: "unknown", statusClass: "unknown", properties: {},
    });
    assert.deepEqual(lane.lifecycle, []);
    assert.deepEqual(lane.statuses, []);
  }
});

test("known history cannot establish absence outside the returned half-open window", () => {
  const h = harness();
  const lane = normalize(h, serverLane(), "20", "60");
  assert.equal(h.statusAtLane(lane, 20n).exists, false);
  assert.equal(h.statusAtLane(lane, 59n).exists, false);
  assert.equal(h.statusAtLane(lane, 19n).exists, null);
  assert.equal(h.statusAtLane(lane, 60n).exists, null);
  assert.equal(h.statusAtLane(lane, 80n).exists, null);
});

test("an authoritative live interval with a status gap stays live with unknown properties", () => {
  const h = harness();
  const lane = normalize(h, serverLane({
    has_lifecycle_history: undefined,
    lifecycle_intervals: [{ start_ns: "0", end_ns: "60" }],
  }));
  assert.deepEqual(h.statusAtLane(lane, 50n), {
    exists: true, status: "unknown", statusClass: "unknown", properties: {},
  });
  assert.deepEqual(lane.statuses, []);
});

test("authoritative empty properties and declared status survive normalization", () => {
  const h = harness();
  const lane = normalize(h, serverLane({
    lifecycle_intervals: [{ start_ns: "0", end_ns: null }],
    status_intervals: [{ start_ns: "0", end_ns: null, status: "ready", status_class: "healthy", properties: {} }],
  }));
  assert.deepEqual(h.statusAtLane(lane, 50n), {
    exists: true, status: "ready", statusClass: "healthy", properties: {},
  });
});

test("server event previews retain display durations without becoming another reducer", () => {
  const h = harness();
  const lane = normalize(h, serverLane());
  lane.marks.push({
    timeNs: 10n, stateChanged: true, effectType: "created",
    durationToNextChangeNs: null,
  });
  h.deriveLaneIntervals(lane);
  assert.equal(lane.marks[0].durationToNextChangeNs, 90n);
  assert.deepEqual(lane.lifecycle, []);
  assert.deepEqual(lane.statuses, []);
  assert.equal(h.statusAtLane(lane, 50n).exists, false);
});

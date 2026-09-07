import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { replaceAbortController } from "../assets/view_models.js";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const signature = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert.ok(signature, `missing production function ${name}`);
  const tail = source.slice(signature.index);
  const ending = /\r?\n\}/.exec(tail);
  assert.ok(ending);
  return tail.slice(0, ending.index + ending[0].length);
}

function fixture() {
  const basis = { kind: "absolute_time", clock_domain: "utc", time_ns: "50" };
  const projection = {
    projection_id: "links", status_perspective_id: "observed",
    resolved_time: {
      node_id: "n1", member_id: "m1", revision_id: "rev1",
      projection_id: "links", status_perspective_id: "observed",
      resolution: "bounded", local_time_ns: "500", query_time_ns: "50",
      absolute_min_ns: "45", absolute_max_ns: "55", uncertainty_ns: "5",
      mapping_method: "recorded transform", watermark_ns: "40",
    },
    resources: [
      { resource_id: "absent", exists: false, status: "absent", state: {} },
      { resource_id: "unknown", exists: null, status: "unknown", state: {} },
    ],
    local_links: [{ relationship_id: "relation", source_resource_id: "absent", target_resource_id: "unknown", present: null, status: "unknown" }],
    counts: { resources: { total_count: 2, returned_count: 2, truncated: false } },
    complete: true,
  };
  const snapshot = {
    revision_id: "rev1",
    resolved_basis: { kind: "absolute_time", requested: basis, clock_policy: "strict", simultaneity: "same_absolute_instant" },
    node: {
      node_id: "n1", member_id: "m1", revision_id: "rev1", label: "Recorded node",
      resources_available: true, plugin_results: [projection],
    },
    completeness: { complete: true },
  };
  const request = {
    projection_id: "links", status_perspective_id: "observed", clock_policy: "strict",
    member_id: "m1", node_ids: ["n1"], basis: { ...basis },
  };
  return { snapshot, projection, request };
}

function harness({ snapshotMode = true, api = async () => { throw new Error("Unexpected API call"); } } = {}) {
  const data = fixture();
  const state = {
    dataset: { workspace: { revision_id: "rev1" }, node_snapshot: data.snapshot },
    topologyRequestId: 0, topologyQueryPending: false, topologyAbortController: null,
    cursorNs: 999n, viewStartNs: 0n, viewEndNs: 1000n,
    resourceById: new Map([["cached", { resource_id: "cached", exists: true }]]),
    layerMeta: new Map([["undeclared-layer", { label: "Not a perspective" }]]),
  };
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, { value: "", innerHTML: "", textContent: "", checked: true });
    return elements.get(id);
  };
  const effects = { renders: 0 };
  const navigationContext = {};
  const dependencies = {
    state, byId, replaceAbortController, navigationContext,
    isTopologyNodeSnapshot: () => snapshotMode,
    analysisRuntimeApi: api,
    topologyRequestBody: () => structuredClone(data.request),
    revisionPath: (path) => `/v1/revisions/rev1/${path}`,
    renderTopologyQueryState() {},
    renderTopologyResults() { effects.renders += 1; },
    firstArray: (...values) => values.find(Array.isArray) || [],
    toNs: (value, fallback = 0n) => value == null ? fallback : BigInt(value),
    escapeHtml: String,
    titleCase: String,
    topologyTimeLabel: (value) => `${value} ns`,
    formatDuration: (value) => `${value} ns`,
    statusClassPresentation: () => "is-unknown",
    MAX_TOPOLOGY_RESOURCE_ROWS: 80,
    MAX_TOPOLOGY_CONNECTIVITY_ROWS: 80,
    MAX_TOPOLOGY_CHANGE_ROWS: 100,
    MAX_TOPOLOGY_NODE_ROWS: 48,
    TOPOLOGY_HISTORY_WINDOW_NS: 120_000_000_000n,
  };
  const names = [
    "workspaceMetadata", "topologyBasisIdentity", "initializeTopologySnapshotControls",
    "renderTopologyPerspectiveOptions",
    "unavailableTopologyQuery", "nodeSnapshotTopologyQuery", "normalizeTopologyCapabilities",
    "topologyProjectionId", "topologyPerspectiveId", "topologyNodeId",
    "topologyResultNodeTimes", "topologyBasisSummary", "renderTopologyNodeTimes",
    "beginLatestRequest", "finishLatestRequest", "requestWasAborted", "abortLatestRequests",
    "requestTopology", "parseSignedSecondsNs",
  ];
  const requestBuilder = functionSource("topologyRequestBody")
    .replace("function topologyRequestBody(", "function buildTopologyRequestBody(");
  const methods = new Function(...Object.keys(dependencies),
    `${names.map(functionSource).join("\n")}\n${requestBuilder}\nreturn {${names.join(",")},buildTopologyRequestBody};`)(...Object.values(dependencies));
  return { ...data, state, byId, effects, navigationContext, ...methods };
}

test("an exact recorded node projection preserves absence, ambiguity, relationships, and clock facts", () => {
  const h = harness();
  const result = h.nodeSnapshotTopologyQuery(h.request);
  assert.equal(result.source, "validated_node_snapshot");
  assert.deepEqual(result.resources, h.projection.resources);
  assert.deepEqual(result.relationships, h.projection.local_links);
  assert.deepEqual(result.inferred_connectivity, []);
  assert.deepEqual(result.changes, []);
  assert.deepEqual(result.resolved_basis, h.snapshot.resolved_basis);
  for (const [field, value] of Object.entries(h.projection.resolved_time)) {
    assert.deepEqual(result.node_times[0][field], value);
  }
  result.resources[0].exists = true;
  result.node_times[0].uncertainty_ns = "0";
  assert.equal(h.projection.resources[0].exists, false);
  assert.equal(h.projection.resolved_time.uncertainty_ns, "5");
});

test("snapshot selectors cannot reinterpret another member, perspective, projection, time, or clock", () => {
  const mutations = [
    (r) => { r.member_id = "other"; },
    (r) => { r.plugin_set_id = "other"; },
    (r) => { r.plugin_id = "other"; },
    (r) => { r.node_ids = ["other"]; },
    (r) => { r.node_ids.push("other"); },
    (r) => { r.projection_id = "other"; },
    (r) => { r.status_perspective_id = "other"; },
    (r) => { r.basis.time_ns = "51"; },
    (r) => { r.basis.clock_domain = "unmapped-clock"; },
    (r) => { r.clock_policy = "best_effort"; },
    (r) => { r.basis.clock_policy = "best_effort"; },
    (r) => { r.basis = { kind: "relative_to_watermark", offset_ns: "0" }; },
    (r) => { r.basis.scopes = [{ node_id: "other" }]; },
  ];
  for (const mutate of mutations) {
    const h = harness();
    mutate(h.request);
    const result = h.nodeSnapshotTopologyQuery(h.request);
    assert.equal(result.source, "unavailable");
    assert.deepEqual(result.resources, []);
    assert.deepEqual(result.node_times, []);
    assert.deepEqual(result.relationships, []);
    assert.equal(result.resolved_basis.kind, "unresolved");
    assert.ok(result.unavailable_reason);
  }
});

test("missing and ambiguous snapshot authority never select a convenient recorded result", () => {
  const mutations = [
    (h) => { h.state.dataset.workspace.revision_id = "different-revision"; },
    (h) => { h.snapshot.revision_id = "different-revision"; },
    (h) => { h.snapshot.node.plugin_results.push(structuredClone(h.projection)); },
    (h) => { h.snapshot.node.plugin_results = null; },
    (h) => { delete h.snapshot.node.member_id; },
    (h) => { h.projection.resolved_time.member_id = "different-member"; },
    (h) => { h.projection.resolved_time = null; },
    (h) => { delete h.projection.local_links; },
    (h) => { delete h.snapshot.resolved_basis; },
  ];
  for (const mutate of mutations) {
    const h = harness();
    mutate(h);
    assert.equal(h.nodeSnapshotTopologyQuery(h.request).source, "unavailable");
  }
});

test("local-only snapshot clocks retain null absolute evidence and render unknown uncertainty", () => {
  const h = harness();
  h.request.basis = { kind: "relative_to_watermark", offset_ns: "-250000001" };
  h.snapshot.resolved_basis = {
    requested: { ...h.request.basis }, kind: "relative_capture_vector",
    clock_policy: "strict", simultaneity: "not_implied",
  };
  Object.assign(h.projection.resolved_time, {
    resolution: "local_exact", local_time_ns: "500", query_time_ns: null,
    absolute_min_ns: null, absolute_max_ns: null, uncertainty_ns: null, watermark_ns: null,
  });
  h.request.basis.scopes = [{ node_id: "n1", status_perspective_id: "observed", topology_projection_id: "links" }];
  const result = h.nodeSnapshotTopologyQuery(h.request);
  assert.equal(result.source, "validated_node_snapshot");
  assert.equal(result.node_times[0].absolute_min_ns, null);
  assert.equal(result.node_times[0].uncertainty_ns, null);
  h.state.topologyQuery = result;
  h.renderTopologyNodeTimes();
  const card = h.byId("topology-node-times").innerHTML;
  assert.match(card, /Absolute mapping not supplied/);
  assert.match(card, /uncertainty unknown/);
  assert.doesNotMatch(card, /uncertainty 0 ns|layer watermark/);
});

test("recorded snapshot controls start at the original basis instead of the current cursor", () => {
  const h = harness();
  h.initializeTopologySnapshotControls();
  assert.equal(h.byId("topology-absolute-time").value, "50");
  assert.equal(h.byId("topology-absolute-clock-domain").value, "utc");
  assert.equal(h.byId("topology-follow-cursor").checked, false);
  assert.equal(h.byId("topology-clock-policy").value, "strict");
  h.snapshot.resolved_basis.requested = { kind: "relative_to_watermark", offset_ns: "-250000001" };
  h.initializeTopologySnapshotControls();
  assert.equal(h.byId("topology-basis-kind").value, "relative_to_watermark");
  assert.equal(h.parseSignedSecondsNs(h.byId("topology-relative-seconds").value), -250000001n);
});

test("snapshot initialization selects its unique declared projection instead of general capability defaults", () => {
  const h = harness();
  h.state.topologyCapabilities = {
    projections: [
      { projection_id: "default", supported_status_perspective_ids: ["default-status"] },
      { projection_id: "links", supported_status_perspective_ids: ["observed"] },
    ],
    status_perspectives: [{ status_perspective_id: "default-status" }, { status_perspective_id: "observed" }],
    defaults: { projection_id: "default", status_perspective_id: "default-status" },
  };
  h.byId("topology-projection").value = "default";
  h.byId("topology-perspective").value = "default-status";
  h.initializeTopologySnapshotControls();
  assert.equal(h.byId("topology-projection").value, "links");
  assert.equal(h.byId("topology-perspective").value, "observed");
  h.byId("topology-projection").value = "default";
  h.byId("topology-perspective").value = "default-status";
  h.navigationContext.projectionId = "default";
  h.initializeTopologySnapshotControls();
  assert.equal(h.byId("topology-projection").value, "default", "an explicit navigation request is not replaced");
  delete h.navigationContext.projectionId;
  h.snapshot.node.plugin_results.push(structuredClone(h.projection));
  h.initializeTopologySnapshotControls();
  assert.equal(h.byId("topology-projection").value, "default", "ambiguous results never choose a first projection");
});

test("production controls and request serialization round-trip the recorded absolute and scoped relative basis", () => {
  for (const basis of [
    { kind: "absolute_time", clock_domain: "utc", time_ns: "1759680005000000000" },
    { kind: "relative_to_watermark", offset_ns: "-250000001" },
  ]) {
    const h = harness();
    h.snapshot.resolved_basis.requested = { ...basis };
    h.state.topologyCapabilities = {
      projections: [{ projection_id: "links", supported_status_perspective_ids: ["observed"] }],
      status_perspectives: [{ status_perspective_id: "observed" }],
      nodes: [{ node_id: "n1" }],
      defaults: {},
    };
    h.initializeTopologySnapshotControls();
    const request = h.buildTopologyRequestBody();
    assert.equal(h.topologyBasisIdentity(request.basis), h.topologyBasisIdentity(basis));
    if (basis.kind === "relative_to_watermark") {
      assert.deepEqual(request.basis.scopes, [{ node_id: "n1", status_perspective_id: "observed", topology_projection_id: "links" }]);
    }
    assert.equal(h.nodeSnapshotTopologyQuery(request).source, "validated_node_snapshot");
  }
});

test("singular and plural snapshot watermark scopes cannot override the recorded offset or anchor", () => {
  for (const field of ["scope", "scopes"]) {
    for (const change of [
      { node_id: "other-node" },
      { offset_ns: "-999" },
      { anchor: { status_perspective_id: "other-perspective" } },
    ]) {
      const h = harness();
      h.request.basis = { kind: "relative_to_watermark", offset_ns: "0" };
      h.snapshot.resolved_basis.requested = { ...h.request.basis };
      const scope = { node_id: "n1", status_perspective_id: "observed", topology_projection_id: "links", ...change };
      h.request.basis[field] = field === "scopes" ? [scope] : scope;
      assert.equal(h.nodeSnapshotTopologyQuery(h.request).source, "unavailable");
    }
    const h = harness();
    h.request.basis = { kind: "relative_to_watermark", offset_ns: "0" };
    h.snapshot.resolved_basis.requested = { ...h.request.basis };
    const scope = { node_id: "n1", status_perspective_id: "observed", topology_projection_id: "links", offset_ns: "0" };
    h.request.basis[field] = field === "scopes" ? [scope] : scope;
    assert.equal(h.nodeSnapshotTopologyQuery(h.request).source, "validated_node_snapshot");
  }
});

test("capability normalization cannot invent projections or perspectives from cached resource layers", () => {
  const h = harness();
  const result = h.normalizeTopologyCapabilities({});
  assert.deepEqual(result.projections, []);
  assert.deepEqual(result.status_perspectives, []);
  assert.deepEqual(result.nodes, []);
  assert.deepEqual(result.defaults, {});
});

test("snapshot display bounds preserve total counts and disclose truncation", () => {
  const h = harness();
  h.projection.resources = Array.from({ length: 81 }, (_, index) => ({ resource_id: `r${index}`, exists: null }));
  h.projection.counts.resources = { total_count: 81, returned_count: 81, truncated: false };
  const result = h.nodeSnapshotTopologyQuery(h.request);
  assert.equal(result.resources.length, 80);
  assert.equal(result.counts.resources.total_count, 81);
  assert.equal(result.counts.resources.returned_count, 80);
  assert.equal(result.completeness.resources.returned_count, 80);
  assert.equal(result.completeness.resources.truncated, true);
  assert.equal(result.completeness.complete, false);
});

test("HTTP validation and network errors remain unavailable even when cached data and a snapshot exist", async () => {
  for (const message of ["HTTP 422: unsupported clock", "Network unavailable"]) {
    const h = harness({ snapshotMode: false, api: async () => { throw new Error(message); } });
    h.state.topologyQuery = { resources: [{ resource_id: "stale" }], node_times: [{ uncertainty_ns: "0" }] };
    await h.requestTopology();
    assert.equal(h.state.topologyQuery.source, "unavailable");
    assert.deepEqual(h.state.topologyQuery.resources, []);
    assert.deepEqual(h.state.topologyQuery.node_times, []);
    assert.equal(h.state.topologyQueryPending, false);
    assert.equal(h.state.topologyAbortController, null);
    assert.match(h.byId("topology-query-error").textContent, /Topology query unavailable/);
    assert.match(h.topologyBasisSummary(h.state.topologyQuery), /No topology or clock resolution/);
  }
});

test("the request controller renders exact snapshots without an API call and rejects changed selectors", async () => {
  const h = harness();
  await h.requestTopology();
  assert.equal(h.state.topologyQuery.source, "validated_node_snapshot");
  assert.equal(h.state.topologyQuery.resources[0].exists, false);
  h.request.status_perspective_id = "not-recorded";
  await h.requestTopology();
  assert.equal(h.state.topologyQuery.source, "unavailable");
  assert.deepEqual(h.state.topologyQuery.resources, []);
  assert.match(h.byId("topology-query-error").textContent, /No unique recorded projection/);
});

test("late successes and failures cannot replace a newer topology response", async () => {
  for (const lateFailure of [false, true]) {
    let resolveFirst;
    let rejectFirst;
    const firstResponse = new Promise((resolve, reject) => { resolveFirst = resolve; rejectFirst = reject; });
    let calls = 0;
    const latest = { source: "versioned API", resources: [{ resource_id: "current" }] };
    const h = harness({ snapshotMode: false, api: () => ++calls === 1 ? firstResponse : Promise.resolve(latest) });
    const first = h.requestTopology();
    const firstController = h.state.topologyAbortController;
    await h.requestTopology();
    assert.equal(firstController.signal.aborted, true);
    if (lateFailure) rejectFirst(new Error("stale failure"));
    else resolveFirst({ resources: [{ resource_id: "stale" }] });
    await first;
    assert.deepEqual(h.state.topologyQuery, latest);
    assert.equal(h.byId("topology-query-error").textContent, "");
    assert.equal(h.state.topologyQueryPending, false);
    assert.equal(h.state.topologyAbortController, null);
    assert.equal(h.effects.renders, 1);
  }
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { api, replaceAbortController } from "../assets/browser_transport.js";
import { escapeHtml, titleCase, toBigInt } from "../assets/shared.js";
import { eventFailed } from "../assets/timeline_models.js";
import { rangeSummaryFacts } from "../assets/view_models.js";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const signature = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert.ok(signature, `missing production function ${name}`);
  const tail = source.slice(signature.index);
  const ending = /\r?\n\}/.exec(tail);
  assert.ok(ending);
  return tail.slice(0, ending.index + ending[0].length);
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness({ snapshotMode = false, request = async () => { throw new Error("Unexpected API call"); } } = {}) {
  const state = {
    dataset: { workspace: snapshotMode ? { history_mode: "point-in-time" } : { history_mode: "server-windowed" } },
    rangeStartNs: 10n, rangeEndNs: 90n, viewStartNs: 0n, viewEndNs: 100n,
    rangeSummary: null, rangeRequestId: 0, rangeAbortController: null,
    eventByUid: new Map([["cached", { event_uid: "cached", timestamp_ns: "50", resource_ids: ["r1"] }]]),
    lanes: [],
  };
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: "", innerHTML: "", hidden: false, value: "",
      querySelectorAll: () => [],
    });
    return elements.get(id);
  };
  const calls = [];
  const effects = { activeLoads: 0 };
  const dependencies = {
    state, byId, escapeHtml, titleCase, eventFailed, rangeSummaryFacts, replaceAbortController,
    toNs: toBigInt,
    api: async (path, options) => { calls.push({ path, options }); return request(path, options); },
    analysisLoadProgress: {
      begin() { effects.activeLoads += 1; return Symbol(); },
      end() { effects.activeLoads -= 1; },
    },
    revisionPath: (path) => `/v1/revisions/rev1/${path}`,
    formatOffset: (value) => `${value} ns`,
    formatDuration: (value) => `${value} ns`,
    formatValue: String,
    clampNs: (value) => value,
    relationshipDisplayLabel: String,
    selectResource() {},
    updateRangeBands() {},
    updateTimelineCommandAvailability() {},
  };
  const names = [
    "workspaceMetadata", "isTopologyNodeSnapshot", "analysisRuntimeApi",
    "beginLatestRequest", "finishLatestRequest", "requestWasAborted", "abortLatestRequests",
    "canonicalResourceId", "resourceIdOf", "canonicalResourceForSubject", "eventSubject",
    "eventTime", "eventResourceRefs", "rangeBounds", "statusAtLane", "localRangeSummary",
    "formatRangeInput", "syncRangeInputs", "conciseEndpointState", "endpointDiffItems",
    "renderRangeSummary", "requestRangeSummary", "clearRangeSelection",
  ];
  const methods = new Function(...Object.keys(dependencies),
    `${names.map(functionSource).join("\n")}\nreturn {${names.join(",")}};`)(...Object.values(dependencies));
  return { state, byId, calls, effects, ...methods };
}

function assertNoComparison(h) {
  const text = h.byId("range-facts").innerHTML + h.byId("range-diff").innerHTML;
  assert.doesNotMatch(text, /\d+ events|\d+ failed|endpoint states evaluated|No endpoint state difference/);
}

test("unrequested and loading server ranges do not present partial browser caches as summaries", async () => {
  const pending = deferred();
  const h = harness({ request: () => pending.promise });
  h.renderRangeSummary();
  assert.match(h.byId("range-facts").innerHTML, /has not been loaded/);
  assertNoComparison(h);
  const run = h.requestRangeSummary();
  assert.match(h.byId("range-facts").innerHTML, /Loading range summary/);
  assertNoComparison(h);
  pending.resolve({ event_count: 19, affected_resource_count: 4, endpoint_diff: [] });
  await run;
  assert.match(h.byId("range-facts").innerHTML, /19 events/);
  assert.equal(h.state.rangeAbortController, null);
  assert.equal(h.effects.activeLoads, 0);
});

test("HTTP 503 with a partial event cache renders unavailable and escapes the server error", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(
    JSON.stringify({ detail: "503 <service unavailable>" }),
    { status: 503, headers: { "Content-Type": "application/json" } },
  ));
  const h = harness({ request: api });
  await h.requestRangeSummary();
  assert.equal(h.calls[0].path, "/v1/revisions/rev1/range/summary");
  assert.equal(h.calls[0].options.method, "POST");
  assert.deepEqual(JSON.parse(h.calls[0].options.body), { start_ns: "10", end_ns: "90" });
  assert.equal(h.state.rangeSummary.source, "unavailable");
  assert.equal(h.state.rangeSummary.event_count, undefined);
  assert.match(h.byId("range-facts").innerHTML, /Range summary unavailable/);
  assert.match(h.byId("range-diff").innerHTML, /503 &lt;service unavailable&gt;/);
  assert.match(h.byId("range-diff").innerHTML, /Select the range again to retry/);
  assertNoComparison(h);
  assert.equal(h.state.rangeAbortController, null);
  assert.equal(h.effects.activeLoads, 0);
  h.renderRangeSummary();
  assertNoComparison(h);
});

test("network errors remain unavailable until a successful retry supplies authoritative facts", async () => {
  let fail = true;
  const h = harness({ request: async () => {
    if (fail) throw new TypeError("Failed to fetch");
    return {
      event_count: 125, failure_count: 7, affected_resource_count: 10,
      endpoint_diff_evaluated_count: 3, endpoint_diff: [],
      truncated: { endpoint_diff: true }, relationship_change_count: 9,
    };
  } });
  await h.requestRangeSummary();
  assert.match(h.byId("range-diff").innerHTML, /Failed to fetch/);
  assertNoComparison(h);
  fail = false;
  await h.requestRangeSummary();
  assert.match(h.byId("range-facts").innerHTML, /125 events/);
  assert.match(h.byId("range-facts").innerHTML, /7 failed/);
  assert.match(h.byId("range-facts").innerHTML, /3 of 10 endpoint states evaluated \/ bounded/);
  assert.match(h.byId("range-diff").innerHTML, /evaluated subset/);
  assert.match(h.byId("range-diff").innerHTML, /7 affected resources were not evaluated/);
  assert.equal(h.state.rangeAbortController, null);
});

test("explicit node snapshot mode retains a labeled local summary without requesting another scope", async () => {
  const h = harness({ snapshotMode: true });
  await h.requestRangeSummary();
  assert.equal(h.calls.length, 0);
  assert.equal(h.state.rangeSummary.source, "local_node_snapshot");
  assert.equal(h.state.rangeSummary.event_count, 1);
  assert.deepEqual(h.state.rangeSummary.affected_resources, ["r1"]);
  assert.match(h.byId("range-facts").innerHTML, /Local snapshot summary \/ loaded evidence only/);
  assert.match(h.byId("range-facts").innerHTML, /1 events/);
  assert.equal(h.state.rangeAbortController, null);
});

test("clearing a pending range aborts it and its late failure cannot recreate summary content", async () => {
  const pending = deferred();
  const h = harness({ request: () => pending.promise });
  const run = h.requestRangeSummary();
  const signal = h.calls[0].options.signal;
  assert.equal(h.clearRangeSelection(), true);
  assert.equal(signal.aborted, true);
  pending.reject(new DOMException("Cancelled", "AbortError"));
  await run;
  assert.equal(h.state.rangeSummary, null);
  assert.equal(h.state.rangeAbortController, null);
  assert.equal(h.byId("range-facts").innerHTML, "");
  assert.equal(h.byId("range-diff").innerHTML, "");
  assert.match(h.byId("range-title").textContent, /Drag horizontally/);
  assert.equal(h.effects.activeLoads, 0);
});

test("an abort without a replacement request ends loading without reporting an empty comparison", async () => {
  const h = harness({ request: async () => { throw new DOMException("Cancelled", "AbortError"); } });
  await h.requestRangeSummary();
  assert.equal(h.state.rangeSummary.source, "unavailable");
  assert.match(h.byId("range-diff").innerHTML, /request was cancelled/);
  assertNoComparison(h);
  assert.equal(h.state.rangeAbortController, null);
  assert.equal(h.effects.activeLoads, 0);
});

test("a transport that resolves after its current request was aborted cannot publish its answer", async () => {
  const pending = deferred();
  const h = harness({ request: () => pending.promise });
  const run = h.requestRangeSummary();
  h.abortLatestRequests("rangeAbortController");
  pending.resolve({ event_count: 999, endpoint_diff: [] });
  await run;
  assert.equal(h.state.rangeSummary.source, "unavailable");
  assertNoComparison(h);
  assert.equal(h.state.rangeAbortController, null);
});

for (const staleOutcome of ["success", "failure"]) {
  test(`a stale ${staleOutcome} cannot release the newer controller or replace its server result`, async () => {
    const pending = [deferred(), deferred()];
    let next = 0;
    const h = harness({ request: () => pending[next++].promise });
    const oldRun = h.requestRangeSummary();
    const oldSignal = h.calls[0].options.signal;
    h.state.rangeStartNs = 20n;
    const newRun = h.requestRangeSummary();
    const newController = h.state.rangeAbortController;
    assert.equal(oldSignal.aborted, true);
    if (staleOutcome === "success") pending[0].resolve({ event_count: 999, endpoint_diff: [] });
    else pending[0].reject(new Error("Old service failure"));
    await oldRun;
    assert.equal(h.state.rangeAbortController, newController);
    assert.equal(h.state.rangeSummary.source, "loading");
    assertNoComparison(h);
    pending[1].resolve({ event_count: 8, endpoint_diff: [] });
    await newRun;
    assert.equal(h.state.rangeSummary.event_count, 8);
    assert.match(h.byId("range-facts").innerHTML, /8 events/);
    assert.doesNotMatch(h.byId("range-facts").innerHTML, /999/);
    assert.equal(h.state.rangeAbortController, null);
    assert.equal(h.effects.activeLoads, 0);
  });
}

test("an older success cannot overwrite an unavailable result for a newer range", async () => {
  const pending = [deferred(), deferred()];
  let next = 0;
  const h = harness({ request: () => pending[next++].promise });
  const oldRun = h.requestRangeSummary();
  h.state.rangeEndNs = 95n;
  const newRun = h.requestRangeSummary();
  pending[1].reject(new Error("Latest service failure"));
  await newRun;
  pending[0].resolve({ event_count: 999, endpoint_diff: [] });
  await oldRun;
  assert.equal(h.state.rangeSummary.source, "unavailable");
  assert.match(h.byId("range-diff").innerHTML, /Latest service failure/);
  assertNoComparison(h);
  assert.equal(h.state.rangeAbortController, null);
  assert.equal(h.effects.activeLoads, 0);
});

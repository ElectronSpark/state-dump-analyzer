import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { createDensityViewportController, densityPageQuery, densityResolution, normalizeDensityPage } from "../assets/density_viewport.js";
import { timelineDensityBinBounds, timelineDensityBinIndex } from "../assets/timeline_viewport.js";

function query(overrides = {}) {
  return densityPageQuery({ context: "node/a", url: "/v1/revisions/a/events/density/query", startNs: -100n, endNs: 10000n,
    binCount: 720, windowStartNs: 0n, windowEndNs: 2000n, globalStart: 100, globalEnd: 180, ...overrides });
}
function harness() {
  const jobs = new Map();
  const requests = [];
  let id = 0;
  let changes = 0;
  const controller = createDensityViewportController({
    schedule: (callback) => { jobs.set(++id, callback); return id; },
    cancel: (key) => jobs.delete(key),
    onChange: () => { changes += 1; },
    fetchPage: (q, signal) => new Promise((resolve, reject) => requests.push({ q, signal, resolve, reject })),
  });
  const flush = async () => { const entries = [...jobs.values()]; jobs.clear(); for (const callback of entries) callback(); await Promise.resolve(); };
  const complete = async (request, bins = [{ index: request.q.globalStart, count: 3, failure_count: 1 }]) => {
    request.resolve({ bins, total_count: 30 }); await Promise.resolve(); await Promise.resolve();
  };
  return { controller, requests, jobs, flush, complete, get changes() { return changes; } };
}

test("nearby zooms share levels and nearby pans share aligned pages", () => {
  assert.equal(densityResolution(2.1, 0n, 1000000n), densityResolution(2.3, 0n, 1000000n));
  assert.equal(query().key, query({ globalStart: 110, globalEnd: 190 }).key);
  assert.notEqual(query().key, query({ binCount: 1440 }).key);
  assert.equal(densityResolution(Number.MAX_VALUE, 0n, 5n), 6);
});

test("identity includes revision, context, capture bounds and resolution", () => {
  const base = query();
  for (const change of [{ url: "/v1/revisions/b/events/density/query" }, { context: "node/b" }, { startNs: -101n }, { endNs: 10001n }, { binCount: 1440 }]) {
    assert.notEqual(query(change).key, base.key);
  }
});

test("normalization preserves exact nondivisible partitions at large and negative times", () => {
  for (const startNs of [-100n, 9007199254740992000n]) {
    const q = query({ startNs, endNs: startNs + 10n, binCount: 3, globalStart: 0, globalEnd: 3 });
    const page = normalizeDensityPage({ bins: [0, 1, 2].map((index) => ({ index, count: index + 1 })) }, q);
    assert.equal(page.bins[0].startNs, startNs);
    assert.equal(page.bins.at(-1).endNs, startNs + 10n);
    for (let i = 0; i < page.bins.length; i += 1) {
      const bin = page.bins[i];
      assert.deepEqual({ startNs: bin.startNs, endNs: bin.endNs }, timelineDensityBinBounds({ index: i, startNs, endNs: q.endNs, binCount: 3 }));
      if (i) assert.equal(page.bins[i - 1].endNs + 1n, bin.startNs);
      assert.equal(timelineDensityBinIndex({ timeNs: bin.endNs, startNs, endNs: q.endNs, binCount: 3 }), i);
    }
  }
});

test("new pan aborts the previous request and rejects its late response", async () => {
  const h = harness();
  h.controller.view(query()); await h.flush();
  h.controller.view(query({ globalStart: 300, globalEnd: 400 }));
  assert.equal(h.requests[0].signal.aborted, true);
  await h.complete(h.requests[0]);
  assert.equal(h.changes, 0);
  await h.flush(); await h.complete(h.requests[1]);
  assert.equal(h.changes, 1);
  assert.equal(h.controller.view(query({ globalStart: 300, globalEnd: 400 })).exact, true);
});

test("superseded debounce and abort rejection do not display errors", async () => {
  const h = harness();
  h.controller.view(query());
  h.controller.view(query({ globalStart: 300, globalEnd: 400 }));
  assert.equal(h.jobs.size, 1);
  await h.flush();
  h.controller.view(query());
  h.requests[0].reject(Object.assign(new Error("cancelled"), { name: "AbortError" }));
  await Promise.resolve(); await Promise.resolve();
  assert.equal(h.controller.view(query()).failed, false);
  assert.equal(h.changes, 0);
});

test("gesture reuses original cached geometry and refines only after settling", async () => {
  const h = harness();
  const coarse = query({ binCount: 180, globalStart: 0, globalEnd: 180 });
  h.controller.view(coarse); await h.flush(); await h.complete(h.requests[0], [{ index: 10, count: 20 }]);
  const original = h.controller.view(coarse).page.bins[0];
  h.controller.setGesture(true);
  const fine = query({ binCount: 720 });
  const view = h.controller.view(fine);
  assert.equal(view.exact, false);
  assert.equal(view.gesture, true);
  assert.equal(view.page.binCount, 180);
  assert.deepEqual(view.page.bins[0], original);
  assert.equal(h.jobs.size, 0);
  h.controller.setGesture(false); await h.flush();
  assert.equal(h.requests.length, 2);
  await h.complete(h.requests[1]);
  assert.equal(h.controller.view(fine).exact, true);
  assert.equal(h.controller.view(coarse).exact, true);
});

test("revision switch during a gesture clears cached geometry and stale responses", async () => {
  const h = harness();
  h.controller.view(query()); await h.flush();
  h.controller.setGesture(true);
  const next = query({ context: "node/b", url: "/v1/revisions/b/events/density/query" });
  const view = h.controller.view(next);
  assert.equal(view.page, null);
  assert.equal(view.gesture, true);
  await h.complete(h.requests[0]);
  assert.equal(h.changes, 0);
  h.controller.setGesture(false); await h.flush(); await h.complete(h.requests[1]);
  assert.equal(h.controller.view(next).exact, true);
});

test("partial cache coverage is exposed and failures retain an honest preview", async () => {
  const h = harness();
  h.controller.view(query()); await h.flush(); await h.complete(h.requests[0]);
  const moved = query({ globalStart: 200, globalEnd: 300, windowStartNs: 0n, windowEndNs: 9000n });
  const preview = h.controller.view(moved);
  assert.ok(preview.page);
  assert.equal(preview.exact, false);
  assert.equal(preview.coverageComplete, false);
  await h.flush(); h.requests[1].reject(new Error("failed"));
  await Promise.resolve(); await Promise.resolve();
  const failed = h.controller.view(moved);
  assert.equal(failed.failed, true);
  assert.ok(failed.page);
  assert.equal(h.jobs.size, 0);
});

test("reset aborts requests even when server ignores the abort signal", async () => {
  const h = harness(); h.controller.view(query()); await h.flush();
  h.controller.reset(); assert.equal(h.requests[0].signal.aborted, true);
  await h.complete(h.requests[0]); assert.equal(h.changes, 0);
  assert.equal(h.controller.view(query()).page, null);
});


const APP_SOURCE = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const start = APP_SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = /\r?\n\}/.exec(APP_SOURCE.slice(start));
  return APP_SOURCE.slice(start, start + end.index + end[0].length);
}

test("app renders a finer cached partition honestly during zoom out without rebucketing", () => {
  const original = { index: 500, startNs: 50n, endNs: 60n, count: 19, failures: 2, topTypes: new Map() };
  const state = { viewStartNs: 0n, viewEndNs: 1000n, zoom: 1, timelineWheelBurstActive: true, hoverModels: new Map(), selectedEventUid: "selected", cursorNs: 55n };
  const dependencies = {
    state, densityResolution, timelineDensityBinBounds,
    densityRenderWindow: () => ({ start: 0, end: 180 }),
    densityServerQuery: () => ({}),
    densityViewport: { setGesture() {}, view: () => ({ page: { binCount: 720, bins: [original] }, exact: false, gesture: true, coverageComplete: true }) },
    usesServerWindowedHistory: () => true, escapeHtml: String,
    timelinePointIntervalVisible: () => true,
    inclusiveIntervalIntersectsRange: () => false,
    offsetPrecisionForSpan: () => 1, formatOffset: String,
    barStyle: () => "", densityBinHeight: () => 10,
    timelineLaneWidth: () => 200, displayedHistoryEventCount: () => 1000000,
  };
  const render = new Function(...Object.keys(dependencies), `${functionSource("eventDensityLane")}; return eventDensityLane;`)(...Object.values(dependencies));
  const html = render(900);
  assert.match(html, /cached 720-bin view/);
  assert.match(html, /refinement after gesture/);
  assert.match(html, /data-range-start-ns="50" data-range-end-ns="60"/);
  assert.match(html, /19 events/);
  assert.equal(state.selectedEventUid, "selected");
  assert.equal(state.cursorNs, 55n);
});

test("truncated lifecycle details cannot establish absence at an omitted instant", () => {
  const state = { cursorNs: 50n };
  const status = new Function("state", `${functionSource("statusAtLane")}; return statusAtLane;`)(state);
  const lane = { lifecycle: [], statuses: [], authoritativeHistory: true,
    historyWindowStartNs: 0n, historyWindowEndNs: 100n, hasLifecycleHistory: true,
    lifecycleDetailsTruncated: true };
  assert.equal(status(lane, 50n).exists, null);
  assert.equal(status(lane, 50n).status, "unknown");
  lane.lifecycleDetailsTruncated = false;
  assert.equal(status(lane, 50n).exists, false);
});

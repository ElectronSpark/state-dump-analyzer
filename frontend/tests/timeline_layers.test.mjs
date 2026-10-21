import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { timelineTimeAtRatio, timelineWindowForZoom } from "../assets/timeline_viewport.js";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");

function functionSource(name) {
  const match = new RegExp(`^(?:async )?function ${name}\\(`, "m").exec(source);
  assert.ok(match, `missing production function ${name}`);
  const end = /\r?\n\}(?=\r?\n|$)/.exec(source.slice(match.index));
  assert.ok(end);
  return source.slice(match.index, match.index + end.index + end[0].length);
}

function harness() {
  const lanes = [
    { resourceId: "r1", layer: "routing" },
    { resourceId: "r2", layer: "interfaces" },
  ];
  const state = {
    dataset: {}, lanes, layerMeta: new Map(), activeLayers: new Set(),
    viewStartNs: 0n, viewEndNs: 1000n,
    timelineWindowStartNs: 0n, timelineWindowEndNs: 1000n,
    zoom: 1, cursorNs: 500n, recordLaneRules: [], sourceRecords: [], timelineRequestId: 0,
    timelineWheelBurstActive: false, timelineWindowRequestTimer: null,
    selectedResourceId: null,
  };
  const timers = new Map();
  const requests = [];
  const renders = [];
  const elements = new Map();
  let nextTimer = 1;
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", style: {}, scrollLeft: 0, scrollWidth: 1000, clientWidth: 1000,
      setAttribute() {}, getBoundingClientRect: () => ({ left: 0 }),
    });
    return elements.get(id);
  };
  let buttons = [];
  const toggles = {
    set innerHTML(html) {
      buttons = [...html.matchAll(/data-layer="([^"]+)" aria-pressed="([^"]+)"/g)]
        .map(([, layer, pressed]) => ({
          dataset: { layer }, pressed,
          addEventListener(type, callback) { assert.equal(type, "click"); this.click = callback; },
        }));
    },
    querySelectorAll: () => buttons,
  };
  elements.set("layer-toggles", toggles);
  const functions = [
    "layerConfig", "discoverPresentation", "renderLayerToggles", "laneIsVisible",
    "requestTimeline", "refreshScaleTimeline", "scheduleTimelineWindowRefresh",
    "invalidatePendingTimelineWindowRequest", "applyTimelineZoom",
    "visibleTimelineCenterNs", "panTimelineViewportByPixels", "panTimelineViewport",
  ];
  const dependencies = {
    state, byId,
    window: {
      setTimeout(callback) { const id = nextTimer++; timers.set(id, callback); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    titleCase: String, stableColor: () => "#123456", safePresentationColor: () => "#123456",
    escapeHtml: String, layerColor: () => "#123456", humanLayer: String,
    isScaleMode: () => true, isTopologyNodeSnapshot: () => false,
    laneSelectedByMode: () => true,
    densityViewport: { setGesture() {} }, refreshDensityLaneForScroll() {},
    timelineWindowBounds: () => [state.timelineWindowStartNs, state.timelineWindowEndNs],
    rangeBounds: () => null, scaleTimelineResourceIds: () => lanes.map((lane) => lane.resourceId),
    canonicalResourceId: (id) => id, timelinePhysicalTrackWidth: () => 1000,
    abortLatestRequests() {}, beginLatestRequest: () => ({ signal: {} }),
    finishLatestRequest() {}, requestWasAborted: () => false, revisionPath: (path) => path,
    analysisRuntimeApi(path, options) {
      return new Promise((resolve) => requests.push({ path, body: JSON.parse(options.body), resolve }));
    },
    normalizeTimeline(payload) { state.lanes = payload.lanes; },
    renderTimeline() { renders.push(state.lanes.filter((lane) => state.activeLayers.has(lane.layer))); },
    renderResourceTables() {}, showToast() {},
    cancelScheduledTimelineZoom() {}, finishTimelinePointer() {}, rememberTimelineView() {},
    timelineZoomControlValue: String, timelineLaneWidth: () => 0,
    clampNs: (value) => value, updateTimelineCommandAvailability() {},
    timelineTimeAtRatio, timelineWindowForZoom,
  };
  const api = new Function(...Object.keys(dependencies), `
    "use strict";
    ${functions.map(functionSource).join("\n")}
    return { discoverPresentation, renderLayerToggles, refreshScaleTimeline,
      applyTimelineZoom, panTimelineViewport, laneIsVisible };
  `)(...Object.values(dependencies));
  api.discoverPresentation();
  api.renderLayerToggles();
  return {
    state, api, requests, renders,
    click(layer) { buttons.find((button) => button.dataset.layer === layer).click(); },
    pressed(layer) { return buttons.find((button) => button.dataset.layer === layer)?.pressed; },
    runRefreshTimer() {
      assert.equal(timers.size, 1);
      const [id, callback] = [...timers][0];
      timers.delete(id);
      return callback();
    },
  };
}

test("hidden layers stay hidden after settled zoom and pan queries", async () => {
  const h = harness();
  h.click("routing");
  assert.equal(h.pressed("routing"), "false");
  assert.equal(h.api.applyTimelineZoom(2), true);
  const zoomRefresh = h.runRefreshTimer();
  assert.equal(h.requests[0].body.start_ns, "250");
  assert.equal(h.requests[0].body.end_ns, "750");
  h.requests[0].resolve({ lanes: [...h.state.lanes] });
  await zoomRefresh;
  assert.equal(h.pressed("routing"), "false");
  assert.deepEqual(h.renders.at(-1).map((lane) => lane.layer), ["interfaces"]);
  assert.equal(h.api.laneIsVisible(h.state.lanes[0]), false);

  assert.equal(h.api.panTimelineViewport(1), true);
  const panRefresh = h.runRefreshTimer();
  assert.ok(BigInt(h.requests[1].body.start_ns) > 250n);
  assert.equal(h.requests[1].body.start_ns, String(h.state.timelineWindowStartNs));
  assert.equal(h.requests[1].body.end_ns, String(h.state.timelineWindowEndNs));
  h.requests[1].resolve({ lanes: [...h.state.lanes] });
  await panRefresh;
  assert.equal(h.pressed("routing"), "false");
  assert.deepEqual(h.renders.at(-1).map((lane) => lane.layer), ["interfaces"]);

  h.click("routing");
  assert.equal(h.pressed("routing"), "true");
  assert.equal(h.api.laneIsVisible(h.state.lanes[0]), true);
});

test("a toggle changed during a pending query wins over rediscovered layers", async () => {
  const h = harness();
  const refresh = h.api.refreshScaleTimeline();
  h.click("routing");
  h.requests[0].resolve({ lanes: [...h.state.lanes] });
  await refresh;
  assert.equal(h.pressed("routing"), "false");
  assert.equal(h.state.activeLayers.has("routing"), false);
});

test("new layers default visible while absent and returning layers retain user choices", async () => {
  const h = harness();
  h.click("routing");
  const routing = h.state.lanes[0];
  const interfaces = h.state.lanes[1];
  const discovery = h.api.refreshScaleTimeline();
  h.requests[0].resolve({ lanes: [interfaces, { resourceId: "r3", layer: "forwarding" }] });
  await discovery;
  assert.equal(h.pressed("forwarding"), "true");
  assert.equal(h.pressed("routing"), "false");

  const returning = h.api.refreshScaleTimeline();
  h.requests[1].resolve({ lanes: [routing, interfaces] });
  await returning;
  assert.equal(h.pressed("routing"), "false");
  assert.equal(h.api.laneIsVisible(routing), false);
});

test("a superseded scale query does not republish obsolete presentation", async () => {
  const h = harness();
  const stale = h.api.refreshScaleTimeline();
  const latest = h.api.refreshScaleTimeline();
  h.click("routing");
  h.requests[1].resolve({ lanes: [...h.state.lanes] });
  await latest;
  const renders = h.renders.length;
  h.requests[0].resolve({ lanes: [{ resourceId: "old", layer: "obsolete" }] });
  await stale;
  assert.equal(h.renders.length, renders);
  assert.equal(h.state.layerMeta.has("obsolete"), false);
  assert.equal(h.pressed("routing"), "false");
});

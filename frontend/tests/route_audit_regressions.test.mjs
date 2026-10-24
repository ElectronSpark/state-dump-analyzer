import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { escapeHtml, safeClass, titleCase } from "../assets/shared.js";
import { routeEndpointSeedValue } from "../assets/view_models.js";

const source = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");
const definitions = [...source.matchAll(/^(?:async )?function (\w+)\(/gm)].map((match) => {
  const tail = source.slice(match.index);
  const end = /\r?\n\}(?=\r?\n|$)/.exec(tail);
  return [match[1], tail.slice(0, end.index + end[0].length)];
});
const constants = [
  ...source.matchAll(/^const [A-Z_]+ = \d+;/gm),
  ...source.matchAll(/const ROUTE_[A-Z_]+ = new Set\([\s\S]*?\);/g),
].map((match) => match[0]).join("\n");

// Load declarations without the page bootstrap. Overrides isolate unrelated
// painting only; normalizers, request builders and installed handlers stay real.
function load(names, overrides = {}) {
  const deps = { escapeHtml, safeClass, titleCase, routeEndpointSeedValue, ...overrides };
  return new Function(...Object.keys(deps), `${constants}
    ${definitions.filter(([name]) => !(name in deps)).map(([, text]) => text).join("\n")}
    return {${names.join(",")}};`)(...Object.values(deps));
}

function dom() {
  const elements = new Map();
  const document = { activeElement: null, querySelectorAll: () => [] };
  const byId = (id) => {
    if (!elements.has(id)) {
      const listeners = new Map();
      const classes = new Set();
      elements.set(id, {
        value: "", textContent: "", innerHTML: "", dataset: {}, options: [], isConnected: true,
        classList: { add: (name) => classes.add(name), remove: (name) => classes.delete(name),
          toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }, contains: (name) => classes.has(name) },
        setAttribute(name, value) { this[name] = value; },
        removeAttribute(name) { delete this[name]; },
        insertAdjacentHTML() {}, scrollIntoView() {},
        addEventListener(name, handler) { listeners.set(name, [...listeners.get(name) || [], handler]); },
        fire(type, event = {}) { for (const listener of listeners.get(type) || []) listener({ type, ...event }); },
        focus() { document.activeElement = this; this.fire("focus"); },
      });
    }
    return elements.get(id);
  };
  return { byId, document };
}

const cleanPath = (extra = {}) => ({ path_id: "active", activity: "active", selection: "selected",
  completeness: "complete", consistency: "consistent", disposition: "forward", segments: [], ...extra });

function servicePopupHarness() {
  const { byId, document } = dom();
  const rect = (left, top, width, height) => ({ left, top, width, height, right: left + width, bottom: top + height });
  let anchorRect = rect(300, 200, 210, 40), toolbarRect = null, serial = 0;
  document.body = byId("body");
  document.activeElement = document.body;
  document.body.append = (element) => { element.parentElement = document.body; };
  document.querySelector = (selector) => selector === ".topbar"
    ? { getBoundingClientRect: () => rect(0, 0, 1265, 76) }
    : selector === ".mn-route-view-toolbar" && toolbarRect ? { getBoundingClientRect: () => toolbarRect } : null;
  const container = byId("mn-route-presentations"), card = byId("mn-route-hover-card");
  // Model the browser's replacement semantics: removed buttons disconnect and
  // focused descendants fall back to BODY, rather than remaining usable mocks.
  for (const element of [container, card]) {
    let markup = "", children = [];
    element.writes = 0;
    element.style = {};
    element.scrollTop = 0;
    element.scrollHeight = 700;
    element.parentElement = document.body;
    element.contains = (target) => target === element || children.includes(target);
    element.querySelectorAll = () => children;
    element.querySelector = () => children[0] || null;
    Object.defineProperty(element, "innerHTML", {
      get: () => markup,
      set(value) {
        if (children.includes(document.activeElement)) document.activeElement = document.body;
        children.forEach((child) => { child.isConnected = false; });
        markup = value;
        element.writes++;
        children = [...value.matchAll(/<button\b[^>]*>/g)].map(([tag]) => {
          const button = byId(`service-button-${++serial}`);
          const groupId = /data-route-presentation-trigger="([^"]+)"/.exec(tag)?.[1];
          if (groupId) button.dataset.routePresentationTrigger = groupId;
          button.getBoundingClientRect = () => anchorRect;
          button.closest = () => null;
          return button;
        });
      },
    });
  }
  card.hidden = true;
  const layer = { presentation_id: "service", group_id: "service:blue", role: "overlay", scope: "path", style: "band",
    label: "Blue service", facts: [{ label: "Remote VTEP", value: "10.254.0.2" }] };
  const paths = [cleanPath({ path_id: "primary", presentations: [layer] }),
    cleanPath({ path_id: "alternate", presentations: [{ ...layer, facts: [{ label: "Remote VTEP", value: "10.254.0.5" }] }] })];
  const state = { routeTrace: { paths }, activeRouteDirection: "forward", routeGraphMode: "all", selectedRoutePathId: "",
    previewRoutePathId: "", previewRoutePresentationId: "", routePresentationPinned: false,
    routePresentationTrigger: null, resizeTargets: new Set(), resizeFrame: null };
  const frames = [];
  const noop = () => {};
  const deps = { byId, document, state, window: { innerWidth: 1265, innerHeight: 720, PointerEvent: class {} },
    clearTimeout: noop, setTimeout: noop, cancelAnimationFrame: noop,
    requestAnimationFrame: (fn) => { frames.push(fn); return frames.length; },
    selectedRoutePath: () => state.routeGraphMode === "focused" ? state.routeTrace?.paths[0] || null : null,
    renderDirectionTabs: noop, renderRouteSeed: noop, updateRouteViewChrome: noop, renderRouteOutcome: noop,
    renderRoutePacketEvolution: noop, renderUnselectedRoutePathTabs: noop,
    allPathGraphNodes: () => [], selectedResultNodes: () => [], applyRouteHighlights: noop, applyOverviewPathEmphasis: noop,
    routePathPreviewMarkup: () => "Path details",
    renderRouteDirectionalDifference: () => null, routePathMatchesDirectionalDifference: () => false,
    routeNodeSequence: () => [], routePathNodeRefs: () => [], routeFlowEndpointLabel: () => "Router",
    routeTraceStartLabel: () => "Router", renderNodeGraph: noop,
  };
  const api = load(["renderRoutePresentations", "showRoutePresentationPreview", "positionRoutePathPreview",
    "renderFocusedRouteMap", "renderRouteTrace", "clearRoutePresentationPreview", "showRoutePathPreview"], deps);
  api.renderRoutePresentations(paths);
  const activate = () => {
    const trigger = container.querySelector();
    trigger.focus();
    trigger.fire("keydown", { key: " ", preventDefault() {} });
    return trigger;
  };
  return { api, deps, state, document, byId, container, card, paths, frames, activate, rect,
    move: (value) => { anchorRect = value; }, toolbar: (value) => { toolbarRect = value; } };
}

test("LV01: page scroll dismisses a clipped service pin, while detail scrolling retains the anchor and reading position", () => {
  const h = servicePopupHarness();
  h.card.scrollHeight = 330;
  const start = source.indexOf('  document.addEventListener("scroll",');
  const end = source.indexOf("\n}", start);
  h.document.addEventListener = (type, handler, options) => {
    assert.equal(type, "scroll");
    assert.deepEqual(options, { capture: true, passive: true });
    h.document.scroll = handler;
  };
  const deps = { ...h.deps, ...h.api, scheduleTopologyInspectorPosition() {} };
  new Function(...Object.keys(deps), source.slice(start, end))(...Object.values(deps));
  h.activate();
  h.card.scrollTop = 51;
  const close = h.document.activeElement;
  h.document.scroll({ target: h.card });
  assert.equal(h.card.hidden, false);
  assert.equal(h.card.scrollTop, 51);
  assert.equal(h.document.activeElement, close);
  h.move(h.rect(300, 130, 210, 40));
  h.document.scroll({ target: h.document });
  while (h.frames.length) h.frames.shift()();
  assert.equal(h.card.style.top, "112px", "the card follows its visible document anchor");
  h.move(h.rect(300, 10, 210, 40));
  h.document.scroll({ target: h.document });
  while (h.frames.length) h.frames.shift()();
  assert.equal(h.card.hidden, true, "the sticky page header fully occludes the trigger");
  assert.equal(h.state.routePresentationPinned, false);
  h.move(h.rect(300, 200, 210, 40));
  h.document.scroll({ target: h.document });
  assert.equal(h.card.hidden, true, "scrolling back does not resurrect a dismissed context");
});

test("LV01: service popup rejects disconnected and fully off-screen anchors, while partial anchors remain usable", () => {
  for (const rectangle of [null, [-250, 200, 210, 40], [1300, 200, 210, 40], [300, -50, 210, 40], [300, 730, 210, 40]]) {
    const h = servicePopupHarness();
    const trigger = h.activate();
    if (rectangle) h.move(h.rect(...rectangle)); else trigger.isConnected = false;
    h.api.positionRoutePathPreview(trigger);
    assert.equal(h.card.hidden, true, `invalid anchor ${rectangle}`);
    assert.equal(h.state.routePresentationTrigger, null);
  }
  const h = servicePopupHarness();
  h.move(h.rect(300, 65, 210, 40));
  h.activate();
  assert.equal(h.card.hidden, false);
  assert.ok(parseFloat(h.card.style.top) >= 88, "service details do not cover the sticky header");
});

test("LV01: short viewports bound service details below the header and shared path previews reclaim available height", () => {
  const h = servicePopupHarness();
  h.deps.window.innerHeight = 300;
  const trigger = h.activate();
  const top = parseFloat(h.card.style.top), maxHeight = parseFloat(h.card.style.maxHeight);
  assert.ok(top >= 88);
  assert.ok(top + maxHeight <= 288, "the whole scrollable dialog fits below the header and inside the viewport");
  h.api.showRoutePathPreview("primary", trigger);
  assert.equal(h.state.previewRoutePresentationId, "");
  assert.equal(h.state.previewRoutePathId, "primary");
  assert.ok(parseFloat(h.card.style.maxHeight) > maxHeight, "a path preview does not inherit the service header offset");
  assert.ok(parseFloat(h.card.style.top) + parseFloat(h.card.style.maxHeight) <= 288);
});

test("HCR2-03: narrow service previews leave the trigger and route-mode toolbar pointer-accessible", () => {
  for (const [height, triggerTop, toolbarTop, expectedSide] of [
    [536, 310, 260, "below"], [536, 450, 395, "above"], [300, 180, 145, "below"],
    [536, 65, 20, "below"], [536, 528, 470, "above"],
  ]) {
    const h = servicePopupHarness();
    h.deps.window.innerWidth = 459;
    h.deps.window.innerHeight = height;
    const triggerRect = h.rect(56, triggerTop, 300, 40), toolbarRect = h.rect(42, toolbarTop, 372, 26);
    h.move(triggerRect);
    h.toolbar(toolbarRect);
    const trigger = h.container.querySelector();
    trigger.fire("pointerenter", { clientX: 250, clientY: triggerTop + 20 });
    assert.equal(h.card.role, "tooltip", "the unpinned preview also leaves adjacent controls usable");
    const bounds = () => h.rect(parseFloat(h.card.style.left), parseFloat(h.card.style.top),
      parseFloat(h.card.style.width), Math.min(h.card.scrollHeight, parseFloat(h.card.style.maxHeight)));
    const checkBounds = () => {
      const cardRect = bounds();
      assert.ok(cardRect.left >= 12 && cardRect.right <= 447);
      assert.ok(cardRect.top >= 88 && cardRect.bottom <= height - 12);
      for (const target of [triggerRect, toolbarRect]) {
        assert.ok(cardRect.bottom <= target.top || cardRect.top >= target.bottom,
          "the popup cannot intercept a pointer on the trigger or mode toolbar");
      }
      assert.equal(cardRect.top >= triggerRect.bottom, expectedSide === "below");
    };
    checkBounds();
    trigger.fire("click", { preventDefault() {}, stopPropagation() {} });
    const close = h.document.activeElement;
    h.card.scrollTop = 51;
    const writes = h.card.writes;
    for (let index = 0; index < 3; index++) {
      trigger.fire("pointerenter", { clientX: 250, clientY: triggerTop + 20 });
      h.api.positionRoutePathPreview(trigger);
      checkBounds();
    }
    assert.equal(h.card.role, "dialog");
    assert.equal(h.card.writes, writes);
    assert.equal(h.card.scrollTop, 51);
    assert.equal(h.document.activeElement, close);
    h.deps.window.innerWidth = 1265;
    h.api.positionRoutePathPreview(trigger);
    assert.equal(parseFloat(h.card.style.maxHeight), Math.min(330, height - 100),
      "a wider viewport restores the available scrollable height without replacing details");
  }
});

test("HCR2-03: wide service previews fit beside the complete trigger on either side", () => {
  for (const left of [300, 800]) {
    const h = servicePopupHarness();
    const triggerRect = h.rect(left, 200, 210, 40);
    h.move(triggerRect);
    const trigger = h.container.querySelector();
    trigger.fire("pointerenter", { clientX: left + 20, clientY: 220 });
    const cardLeft = parseFloat(h.card.style.left), cardRight = cardLeft + parseFloat(h.card.style.width);
    assert.ok(cardRight < triggerRect.left || cardLeft > triggerRect.right,
      "pointer entry inside a wide trigger does not place the card over its remaining width");
    assert.equal(h.card.style.maxHeight, "330px");
  }
});

test("HCR2-03: a viewport without a vertical gap dismisses service details instead of covering controls", () => {
  const h = servicePopupHarness();
  h.deps.window.innerWidth = 459;
  h.deps.window.innerHeight = 144;
  h.move(h.rect(56, 100, 300, 40));
  h.toolbar(h.rect(42, 80, 372, 20));
  h.activate();
  assert.equal(h.card.hidden, true);
  assert.equal(h.state.previewRoutePresentationId, "");
  assert.equal(h.state.routePresentationTrigger, null);
});

test("LV02: passive service re-entry preserves pinned DOM, scroll and keyboard ownership; explicit activation enters it", () => {
  const h = servicePopupHarness();
  const trigger = h.activate();
  const close = h.document.activeElement;
  h.card.scrollTop = 51;
  trigger.fire("pointerenter", { clientX: 320, clientY: 220 });
  assert.equal(h.card.scrollTop, 51);
  assert.equal(h.document.activeElement, close);
  assert.equal(close.isConnected, true);
  const zoom = h.byId("zoom-in");
  zoom.focus();
  const writes = h.card.writes;
  for (let index = 0; index < 3; index++) {
    trigger.fire("pointerenter", { clientX: 320, clientY: 220 });
    trigger.fire("pointerleave");
  }
  assert.equal(h.card.writes, writes, "passive re-entry does not rebuild pinned contents");
  assert.equal(h.card.scrollTop, 51);
  assert.equal(h.document.activeElement, zoom, "pointer preview cannot steal keyboard focus from graph controls");
  trigger.fire("keydown", { key: "Enter", preventDefault() {} });
  assert.equal(h.document.activeElement, close, "explicit activation moves focus into the existing dialog");
  assert.equal(h.card.scrollTop, 51);
});

test("LV03: delayed graph resize after service activation preserves the pin and trigger; semantic changes retire it", () => {
  const h = servicePopupHarness();
  let resize;
  class ResizeObserver {
    constructor(callback) { resize = callback; }
    observe() {}
  }
  const start = source.indexOf('  if ("ResizeObserver" in window) {');
  const end = source.indexOf('  document.addEventListener("scroll",', start);
  const deps = { ...h.deps, ...h.api, window: { ...h.deps.window, ResizeObserver }, ResizeObserver, renderLinkStatusMap() {} };
  new Function(...Object.keys(deps), source.slice(start, end))(...Object.values(deps));
  // An All-path render starts its height transition. The service is activated
  // before the ResizeObserver's next frame, matching rapid mode-switch input.
  h.api.renderRouteTrace();
  h.api.renderFocusedRouteMap();
  resize([{ target: { id: "mn-route-map-stage" } }]);
  const trigger = h.activate();
  const close = h.document.activeElement;
  h.card.scrollTop = 51;
  const writes = [h.container.writes, h.card.writes];
  for (let index = 0; index < 3; index++) {
    while (h.frames.length) h.frames.shift()();
    resize([{ target: { id: "mn-route-map-stage" } }]);
  }
  while (h.frames.length) h.frames.shift()();
  assert.equal(h.card.hidden, false);
  assert.equal(h.state.routePresentationPinned, true);
  assert.equal(h.state.routePresentationTrigger, trigger);
  assert.equal(trigger.isConnected, true);
  assert.equal(h.document.activeElement, close);
  assert.equal(h.card.scrollTop, 51);
  assert.deepEqual([h.container.writes, h.card.writes], writes, "layout-only frames do not replace service UI");
  h.state.activeRouteDirection = "reverse";
  h.state.routeTrace = { paths: [{ ...h.paths[0], path_id: "return", presentations: [{ ...h.paths[0].presentations[0],
    facts: [{ label: "Remote VTEP", value: "10.254.0.1" }] }] }] };
  h.api.renderRouteTrace();
  assert.equal(h.card.hidden, true, "a changed direction cannot retain the former context even with the same group ID");
  assert.equal(trigger.isConnected, false);
  h.activate();
  assert.match(h.card.innerHTML, /10\.254\.0\.1/);
  assert.doesNotMatch(h.card.innerHTML, /10\.254\.0\.[25]/);
  h.state.routeTrace = null;
  h.state.routeCapabilities = {};
  h.api.renderRouteTrace();
  assert.equal(h.card.hidden, true);
  assert.equal(h.container.hidden, true);
});

test("path service context stays outside forwarding geometry and retains its details and path selection", () => {
  const { byId, document } = dom();
  const container = byId("mn-route-presentations");
  const state = { selectedRoutePathId: "alternate", routeGraphMode: "all", previewRoutePathId: "" };
  const strip = byId("blue-strip"), otherStrip = byId("red-strip"), trigger = byId("blue-trigger");
  strip.dataset.routePathIds = '["primary","alternate"]';
  otherStrip.dataset.routePathIds = '["other"]';
  trigger.dataset.routePresentationTrigger = "service:blue";
  container.querySelectorAll = () => container.hidden ? [] : [trigger];
  byId("mn-route-map-stage").querySelectorAll = () => [];
  document.querySelectorAll = () => [strip, otherStrip];
  const previews = [];
  const api = load(["renderRoutePresentations", "routePresentationGroups", "routePresentationPreviewMarkup", "applyOverviewPathEmphasis"], {
    state, document, byId, window: {},
    showRoutePresentationPreview: (...args) => previews.push(args),
    routeNodeSequence: () => { throw new Error("path context must not infer participating devices"); },
  });
  const layer = { presentation_id: "service", group_id: "service:blue", role: "overlay", scope: "path", style: "band",
    label: "Blue service", facts: [{ label: "Routing context", value: "blue" }] };
  const paths = ["primary", "alternate"].map((path_id) => ({ path_id, presentations: [layer],
    node_sequence: ["pe-a", "transit-without-service", "pe-b"] }));
  const original = JSON.stringify(paths);
  api.renderRoutePresentations(paths);
  assert.equal(container.hidden, false);
  assert.equal((container.innerHTML.match(/data-route-presentation-trigger=/g) || []).length, 1);
  assert.doesNotMatch(container.innerHTML, /<(svg|rect|path)\b|transit-without-service|data-route-focus-targets/);
  assert.match(container.innerHTML, /Path context does not imply device participation/);
  const group = api.routePresentationGroups(paths)[0];
  assert.match(api.routePresentationPreviewMarkup(group), /Routing context/);
  trigger.fire("keydown", { key: "Enter", preventDefault() {} });
  assert.deepEqual(previews[0], ["service:blue", trigger, true]);
  api.applyOverviewPathEmphasis();
  assert.equal(strip.classList.contains("is-route-pinned"), true);
  assert.equal(otherStrip.classList.contains("is-route-suppressed"), true);
  state.selectedRoutePathId = "";
  api.applyOverviewPathEmphasis();
  assert.equal(otherStrip.classList.contains("is-route-suppressed"), false);
  assert.equal(JSON.stringify(paths), original, "context rendering preserves the physical path and descriptors");
  api.renderRoutePresentations([{ path_id: "non-service", presentations: [{ ...layer, scope: "step" }] }]);
  assert.equal(container.hidden, true);
  assert.equal(container.innerHTML, "", "a subsequent path without service context removes the strip");
});

test("route boundary labels follow their own link and resolution-step highlights", () => {
  const { byId, document } = dom();
  const state = { routeHoverTokens: new Set(), routeHoverExact: false,
    routeTokenElements: new Set(), routeFocusElements: new Set(),
    routeTokenIndex: new Map(), routeFocusIndex: new Map(),
    routeCorrelatedElements: new Set(), routeDimmedElements: new Set() };
  const api = load(["routeBoundaryTagMarkup", "bindRouteCorrelationElements", "clearRouteHover"],
    { state, document, quadraticEdgePoint: () => ({ x: 10, y: 20 }) });
  const labels = ["west", "east"].map((id) => {
    const markup = api.routeBoundaryTagMarkup({ graph_presentation: { label: id, role: "outer-boundary" },
      component_tokens: [`segment:${id}`], highlight_target_ids: [`target:${id}`] }, {}, "path");
    const element = byId(`label-${id}`);
    for (const [attribute, key] of [["data-route-tokens", "routeTokens"], ["data-route-focus-targets", "routeFocusTargets"]]) {
      const encoded = markup.match(new RegExp(`${attribute}="([^"]*)"`))?.[1];
      assert.ok(encoded, `rendered label carries ${attribute}`);
      element.dataset[key] = encoded.replaceAll("&quot;", '"');
    }
    return element;
  });
  const controls = ["link-west", "step-east"].map((id, index) => {
    const element = byId(id);
    element.dataset = { ...labels[index].dataset, routeKind: index ? "resolution-step" : "route-segment", routeId: id };
    return element;
  });
  const elements = [...labels, ...controls];
  elements.forEach((element) => {
    element.closest = () => scope;
    element.hasAttribute = (name) => name === "data-route-focus-targets";
  });
  const scope = { querySelectorAll: () => elements, contains: (element) => elements.includes(element) };
  api.bindRouteCorrelationElements(scope);
  for (const [index, control] of controls.entries()) {
    control.focus();
    assert.equal(labels[index].classList.contains("is-route-correlated"), true);
    assert.equal(labels[1 - index].classList.contains("is-route-dimmed"), true);
  }
  api.clearRouteHover();
  assert.ok(elements.every((element) => !element.classList.contains("is-route-correlated")
    && !element.classList.contains("is-route-dimmed")));
});

test("MN001/MN002: normalize gaps and unknown proof flags without inventing disagreement", () => {
  const api = load(["normalizeRouteTrace", "normalizeRouteSegment", "pathStatusSummary", "routeTraceOutcome"], { state: { query: { nodes: [] } } });
  for (const consistency of [{ state: "incomplete", consistent: false }, { state: "best_effort_with_gap", consistent: false },
    { state: "unknown", consistent: false }, undefined]) {
    const raw = { consistency, consistent: false, complete: false, completeness: "incomplete", reachable: false,
      paths: [cleanPath({ consistency, consistent: false, completeness: "incomplete", disposition: "unresolved" })] };
    const trace = api.normalizeRouteTrace(raw, {});
    assert.equal(trace.inconsistent, null);
    assert.equal(trace.paths[0].inconsistent, null);
    assert.equal(api.normalizeRouteSegment({ consistency, consistent: false }, 0, []).inconsistent, null);
    assert.equal(api.routeTraceOutcome(trace, { code: "single_direction" }).code, "incomplete");
  }
  for (const conflict of [{ consistency: "cross_layer_mismatch" }, { inconsistent: true },
    { consistency: "mismatch", consistent: false }]) {
    const trace = api.normalizeRouteTrace({ ...conflict, paths: [cleanPath(conflict)] }, {});
    assert.equal(trace.inconsistent, true);
    assert.equal(trace.paths[0].inconsistent, true);
    assert.equal(api.pathStatusSummary(trace.paths[0]), "Inconsistent evidence");
  }
  const finding = api.normalizeRouteTrace({ consistency: { state: "incomplete", consistent: false }, paths: [cleanPath({ issue_refs: ["fault"] })],
    issues: [{ issue_id: "fault", affects_consistency: true, path_ids: ["active"] }] }, {});
  assert.equal(finding.inconsistent, true, "positive findings remain authoritative independently of incomplete coverage");
  assert.equal(finding.paths[0].inconsistent, true);
});

test("MN004: withdrawn history remains visible without downgrading proven active delivery", () => {
  const state = { query: { nodes: [] }, routeTraces: {} };
  const api = load(["normalizeRouteTrace", "routeTraceOutcome", "traceDirectionState", "pathStatusSummary"], { state });
  const raw = { reachable: true, complete: false, completeness: { state: "partial" }, consistency: "consistent_after_failover",
    endpoint_reachability: { reaches_target: true, state: "all_active_reachable" },
    paths: [cleanPath(), cleanPath({ path_id: "history", activity: "withdrawn", selection: "inactive_candidate", completeness: "incomplete", disposition: "unresolved" })] };
  const trace = api.normalizeRouteTrace(raw, {});
  assert.equal(api.traceDirectionState(trace).code, "resolved");
  assert.equal(api.routeTraceOutcome(trace, { code: "single_direction" }).code, "reachable");
  assert.equal(trace.paths.length, 2);
  assert.equal(trace.paths[1].completeness, "incomplete");
  const unknown = api.normalizeRouteTrace({ ...raw, paths: [raw.paths[0], { ...raw.paths[1], activity: "unknown", selection: "unknown" }] }, {});
  assert.equal(api.routeTraceOutcome(unknown, { code: "single_direction" }).code, "incomplete");
});

test("MN008: hop and recursion stops expose budget metadata alongside retained steps", () => {
  const api = load(["normalizeRouteTrace", "routeTraceOutcome", "pathStatusSummary", "routeDiagnosticItems"], { state: { query: { nodes: [] } } });
  for (const [kind, reason, label, limit, observed] of [["max_hops", "hop_limit_exceeded", "Hop limit reached", 1, 2],
    ["max_recursion", "recursion_limit_exceeded", "Recursion limit reached", 0, 1]]) {
    const trace = api.normalizeRouteTrace({ reachable: false, complete: false, completeness: "incomplete",
      paths: [cleanPath({ completeness: "incomplete", disposition: "unresolved", terminal_reason: reason,
        resolution_budget: { kind, limit, observed }, route_resolution_sequence: [{ text: "Retained local deliver" }] })] }, {});
    const result = api.routeTraceOutcome(trace, { code: "single_direction" });
    assert.equal(result.label, "Traversal limit reached");
    assert.match(result.detail, new RegExp(`configured limit ${limit}; observed ${observed}`));
    assert.equal(api.pathStatusSummary(trace.paths[0]), label);
    const diagnostics = api.routeDiagnosticItems(trace.paths[0]);
    assert.equal(diagnostics[0].text, label);
    assert.match(diagnostics[0].detail, /retained node-local steps do not establish delivery/);
    assert.equal(trace.paths[0].steps[0].text, "Retained local deliver");
  }
});

function controls() {
  const { byId, document } = dom();
  const nodes = ["a", "b", "p"].map((node_id) => ({ node_id, member_id: `member:${node_id}` }));
  const state = { query: { context_id: "context", nodes, request: { basis: {}, node_queries: [] } },
    routeCapabilities: {
      scenarios: [{ scenario_id: "example", default_source: "source:a", default_destination: "destination:b", default_start: "start:a",
        route_type: "ipv4", route_family: "ipv4", vrf_id: "blue", directional_routing_contexts: {
          forward: { route_type: "ipv4", route_family: "ipv4", vrf_id: "blue" },
          reverse: { route_type: "mpls", route_family: "labeled", vrf_id: "default" },
        } }], directional_pairs: [],
      sources: [{ source_id: "source:a", endpoint_id: "endpoint:a", node_id: "a", label: "Router A" }],
      destinations: [{ destination_id: "destination:b", endpoint_id: "endpoint:b", node_id: "b", label: "Router B", value: "node-b" }],
      start_points: nodes.map((node) => ({ ...node, start_id: `start:${node.node_id}`, label: node.node_id })),
      route_types: [{ type_id: "ipv4" }, { type_id: "mpls" }],
      route_families: [{ route_family: "ipv4", address_family: "ipv4", supported_route_types: ["ipv4"] },
        { route_family: "labeled", address_family: "ipv4", supported_route_types: ["mpls"] }],
      vrfs: [{ vrf_id: "blue", vrf: "blue", route_families: ["ipv4"] }, { vrf_id: "default", vrf: "default", route_families: ["labeled"] }],
      policies: ["strict"], limits: {}, steering_profiles: [],
    }, routeTableSnapshot: { items: [], route_table_context_id: "table-context" } };
  byId("mn-route-scenario").value = "example";
  byId("mn-route-policy").value = "strict";
  byId("mn-route-validation").value = "forward";
  const noop = () => {};
  const overrides = { state, byId, document, location: { search: "" }, matchMedia: () => ({ matches: true }),
    renderRouteTrace: noop, renderMap: noop, renderRouteTables: noop, renderRouteSeed: noop,
    clearRoutePacketSelection: noop, clearRoutePathPreview: noop, clearRouteHover: noop, syncUrl: noop, showToast: noop };
  const api = load(["useRouteTableEntry", "buildRouteTraceRequest", "routeFlowEndpointLabel", "selectedRouteEndpoint", "setRouteEndpointInput",
    "routeScenarioContext", "applyCompatibleRouteContext", "syncRouteStartControlState", "invalidateRouteTraceResult"], overrides);
  return { state, byId, document, api, overrides };
}

test("MN005/MN009/MN010/MN011: row seeding keeps logical endpoint identity and synchronizes dependent state", () => {
  const h = controls();
  const endpoint = { destination_id: "destination:service", endpoint_id: "endpoint:service", node_id: "b", value: "203.0.113.0/24", label: "Service subnet" };
  const row = { route_entry_id: "row", route_entry_ref: { route_entry_id: "row" }, node_id: "p", traceable: true,
    trace_query: { scenario_id: "example", source: { node_id: "a", source_id: "source:a" }, destination: endpoint,
      starting_point: { node_id: "p" }, direction: "forward", route_type: "ipv4", route_family: "ipv4", vrf_id: "blue" } };
  h.state.routeTableSnapshot.items = [row];
  h.byId("mn-route-error").textContent = "old request failed";
  h.api.useRouteTableEntry("row");
  assert.equal(h.byId("mn-route-destination").value, endpoint.value);
  assert.equal(h.byId("mn-route-error").textContent, "");
  let request = h.api.buildRouteTraceRequest();
  assert.deepEqual(request.flow.destination, endpoint);
  assert.deepEqual(request.destination, endpoint);
  assert.equal(request.trace_starts.forward.node_id, "p");
  assert.equal(h.api.routeFlowEndpointLabel({ flow: { destination: endpoint } }, "destination"), "Service subnet");
  assert.equal(h.api.routeFlowEndpointLabel({ flow: { destination: { ...endpoint, label: "" } } }, "destination"), endpoint.value);
  assert.equal(h.byId("mn-route-start").disabled, false);
  row.trace_query.direction = "reverse";
  h.api.useRouteTableEntry("row");
  assert.equal(h.byId("mn-route-start").disabled, true);
  assert.equal(h.byId("mn-route-start-field")["data-route-start-usage"], "unused");
  assert.match(h.byId("mn-route-start-help").textContent, /Not used for return-only/);
  request = h.api.buildRouteTraceRequest();
  assert.equal(request.ingress, undefined);
  row.trace_query.direction = "forward";
  h.api.useRouteTableEntry("row");
  assert.equal(h.byId("mn-route-start").disabled, false);
  assert.equal(h.byId("mn-route-start-field")["data-route-start-usage"], "used");
  h.byId("mn-route-destination").dataset.endpointDescriptor = "malformed";
  assert.equal(h.api.selectedRouteEndpoint("destination"), null);
  assert.equal(h.byId("mn-route-destination").dataset.endpointDescriptor, undefined);
});

function installControlBlock(marker, endMarker, deps) {
  const start = source.indexOf(marker, source.indexOf("function bindControls()"));
  const end = source.indexOf(endMarker, start + marker.length);
  assert.ok(start >= 0 && end > start);
  new Function(...Object.keys(deps), source.slice(start, end))(...Object.values(deps));
}

test("HC3-2: explicit context edits reconcile dependent controls regardless of edit order", () => {
  const start = '["mn-route-vrf", "mn-route-family", "mn-route-type"].forEach';
  for (const order of [["vrf", "family"], ["family", "vrf"], ["type", "vrf"]]) {
    const h = controls();
    h.state.routeCapabilities.route_families = [
      { route_family: "ipv4/unicast", supported_route_types: ["ipv4"] },
      { route_family: "vpnv4", supported_route_types: ["mpls_l3vpn"] },
    ];
    h.state.routeCapabilities.route_types = [{ type_id: "ipv4" }, { type_id: "mpls_l3vpn" }];
    h.state.routeCapabilities.vrfs = [
      { vrf_id: "default", vrf: "default", route_families: ["ipv4/unicast"], supported_route_types: ["ipv4"] },
      { vrf_id: "blue", vrf: "blue", route_families: ["vpnv4"], supported_route_types: ["mpls_l3vpn"] },
    ];
    h.byId("mn-route-type").value = "mpls_l3vpn";
    h.byId("mn-route-family").value = "vpnv4";
    h.byId("mn-route-vrf").value = "blue";
    installControlBlock(start, 'byId("mn-route-policy").addEventListener', {
      ...h.overrides, ...h.api, clearFocusedRouteEntry() {},
    });
    for (const field of order) {
      h.byId(`mn-route-${field}`).value = { type: "ipv4", family: "ipv4/unicast", vrf: "default" }[field];
      h.byId(`mn-route-${field}`).fire("change");
      assert.equal(h.byId("mn-route-type").value, "ipv4", `${field} edit must reconcile type`);
      assert.equal(h.byId("mn-route-family").value, "ipv4/unicast");
      assert.equal(h.byId("mn-route-vrf").value, "default");
    }
    // The same handler must also recover the VPN context in the other direction.
    h.byId("mn-route-family").value = "vpnv4";
    h.byId("mn-route-family").fire("change");
    assert.equal(h.byId("mn-route-type").value, "mpls_l3vpn");
    assert.equal(h.byId("mn-route-vrf").value, "blue");
    h.api.setRouteEndpointInput("source", "source:a");
    h.api.setRouteEndpointInput("destination", "destination:b");
    h.byId("mn-route-start").value = "start:a";
    const request = h.api.buildRouteTraceRequest();
    assert.equal(request.route_type, "mpls_l3vpn");
    assert.equal(request.route_family, "vpnv4");
    assert.equal(request.vrf, "blue");
  }
});

test('history-restored route controls reconcile with applied filters after pageshow and ordinary renders', () => {
  const { byId, document } = dom();
  const row = (prefix) => ({ node_id: 'a', prefix, next_hops: [], forwarding_actions: [], protocol: 'static' });
  const state = { routeTableFilters: { search: '', node: '', vrf: '', family: '', type: '', protocol: '', destination: '' },
    routeTableSnapshot: { groups: [{ node_id: 'a', label: 'A' }], items: [row('packet-mtu'), row('10.255.0.0/24')] }, routeTableOpenNodes: new Set() };
  let visible = [], pageshow;
  const frames = [];
  const api = load(['routeTableFilterOptions', 'routeTableEntryMatchesFilters'], { state, byId });
  const renderRouteTables = () => {
    api.routeTableFilterOptions();
    visible = state.routeTableSnapshot.items.filter(api.routeTableEntryMatchesFilters);
  };
  byId('mn-route-table-search').tagName = byId('mn-route-table-destination-filter').tagName = 'INPUT';
  installControlBlock('byId("mn-route-table-filters").addEventListener', '  byId("mn-route-direction-tabs")', {
    state, byId, document, renderRouteTables,
    window: { addEventListener(type, callback) { assert.equal(type, 'pageshow'); pageshow = callback; } },
    requestAnimationFrame: (callback) => frames.push(callback),
  });
  renderRouteTables();
  pageshow({ persisted: false });
  // Browser form restoration follows pageshow, without emitting input/change.
  byId('mn-route-table-search').value = 'packet-mtu';
  byId('mn-route-table-destination-filter').value = 'packet-mtu';
  frames.shift()();
  assert.equal(byId('mn-route-table-search').value, '');
  assert.equal(byId('mn-route-table-destination-filter').value, '');
  assert.equal(visible.length, 2);
  byId('mn-route-table-search').value = 'packet-mtu';
  byId('mn-route-table-search').fire('input');
  assert.equal(visible.length, 1);
  pageshow({ persisted: true });
  frames.shift()();
  assert.equal(byId('mn-route-table-search').value, 'packet-mtu', 'BFCache retains the existing applied state');
  assert.equal(visible.length, 1);
  byId('mn-route-table-destination-filter').value = 'absent';
  byId('mn-route-table-destination-filter').fire('input');
  assert.equal(visible.length, 0);
  byId('mn-route-table-clear').fire('click');
  assert.equal(visible.length, 2);
  assert.equal(byId('mn-route-table-destination-filter').value, '');
});

test('focused policy-blocked edges reference their SVG marker without colliding with form controls', () => {
  const svg = { setAttribute() {}, innerHTML: '' };
  const nodes = [{ key: 'a', node_id: 'a' }, { key: 'b', node_id: 'b' }];
  const path = { path_id: 'blocked', label: 'Blocked', segments: [{ source: nodes[0], target: nodes[1], segment_id: 'stop', status: 'blocked' }] };
  const api = load(['renderEdges'], { state: {}, byId: () => svg,
    routeForwardingSegments: (value) => value.segments,
    findRouteOccurrence: (ref) => nodes.find((node) => ref.node_id === node.node_id),
    findNodeForRef: (ref) => nodes.find((node) => ref.node_id === node.node_id), selectedResultNodes: () => nodes,
    routeSegmentIsTerminal: () => false, routeSegmentIsCycleClosing: () => false, routeSegmentIsPolicyBlocked: () => true,
    curvedEdgeGeometry: () => ({ d: 'M0,0 L100,0' }),
    routeQualityClasses: () => [], routeSegmentQualityState: () => ({}), routePolicyPresentation: () => ({ label: 'Policy blocked' }),
    nodeLabelForRef: (ref) => ref.node_id, pathStatusSummary: () => 'Blocked', routeTokensAttribute: () => '', routeFocusTargetsAttribute: () => '',
    packetRefsAttribute: () => '', routeBoundaryTagMarkup: () => '',
    bindRouteCorrelationElements() {}, bindRoutePacketGraphElements() {},
  });
  api.renderEdges(nodes, new Map(nodes.map((node, index) => [node.key, { x: index * 100, y: 0 }])),
    { width: 400, height: 300 }, new Map(), { showTopology: false, showRoute: true, routePath: path });
  const marker = /class="mn-route-edge [^"]*is-policy-blocked" marker-end="url\(#([^)]*)\)"/.exec(svg.innerHTML)?.[1];
  assert.ok(marker);
  assert.ok(svg.innerHTML.includes(`<marker id="${marker}"`));
  const page = readFileSync(new URL('../pages/topology.html', import.meta.url), 'utf8');
  assert.ok(page.includes('id="mn-route-policy"'), 'resolution select remains available');
  for (const [, markerId] of svg.innerHTML.matchAll(/<marker id="([^"]+)"/g)) {
    assert.ok(!page.includes(`id="${markerId}"`), `marker ${markerId} must not resolve to an HTML control`);
  }
});

test("MN003: actual direction handler applies declared Return and Forward contexts without changing flow", () => {
  const h = controls();
  h.api.setRouteEndpointInput("source", "source:a");
  h.api.setRouteEndpointInput("destination", "destination:b");
  const selectedRouteScenario = () => h.state.routeCapabilities.scenarios[0];
  installControlBlock('byId("mn-route-validation").addEventListener', '  byId("mn-route-table-filters")', {
    ...h.overrides, ...h.api, selectedRouteScenario, clearFocusedRouteEntry() {},
  });
  for (const [direction, type, family, vrf, disabled] of [["reverse", "mpls", "labeled", "default", true], ["forward", "ipv4", "ipv4", "blue", false]]) {
    h.byId("mn-route-validation").value = direction;
    h.byId("mn-route-validation").fire("change");
    assert.equal(h.byId("mn-route-type").value, type);
    assert.equal(h.byId("mn-route-family").value, family);
    assert.equal(h.byId("mn-route-vrf").value, vrf);
    assert.equal(h.byId("mn-route-start").disabled, disabled);
    assert.equal(h.api.selectedRouteEndpoint("destination").node_id, "b");
  }
});

test("MN011: endpoint input clears an obsolete error and seed identity even after a settled failure", () => {
  const h = controls();
  h.api.setRouteEndpointInput("destination", { destination_id: "service", value: "203.0.113.0/24" });
  installControlBlock('["mn-route-source", "mn-route-destination"].forEach', '  byId("mn-route-start").addEventListener', {
    ...h.overrides, ...h.api, clearFocusedRouteEntry() {}, refreshRouteEndpointIdentity() {},
  });
  h.byId("mn-route-error").textContent = "unknown destination from previous request";
  h.byId("mn-route-destination").value = "node-b";
  h.byId("mn-route-destination").fire("input");
  assert.equal(h.byId("mn-route-error").textContent, "");
  assert.equal(h.byId("mn-route-destination").dataset.endpointDescriptor, undefined);
  assert.equal(h.api.selectedRouteEndpoint("destination").node_id, "b");
});

test("MN006: existing node and resource links return to the latest synchronized route state", () => {
  const h = controls();
  const location = new URL("http://localhost:8883/?route_scenario=old#routes");
  const links = ["/node?member_id=member%3Ab&node_id=b&return_to=old", "/node?member_id=member%3Ab&node_id=b&resource_id=if0&return_to=old",
    "https://elsewhere.example/node?return_to=old"].map((href) => ({ href }));
  h.document.querySelectorAll = () => links;
  Object.assign(h.state, { capabilities: { nodes: [] }, selectedNodeKeys: new Set(), topologyNetworkView: "physical", activeRouteDirection: "reverse", routeGraphMode: "focused" });
  h.byId("mn-route-validation").value = "reverse";
  h.byId("mn-basis-kind").value = "absolute_time";
  h.byId("mn-absolute-time").value = "42";
  const { syncUrl: unused, ...overrides } = h.overrides;
  const api = load(["syncUrl"], { ...overrides, location, history: { replaceState(_state, _unused, href) { location.href = new URL(href, location).href; } },
    topologyElementVisible: () => true, TOPOLOGY_ELEMENT_KEYS: ["subnets"] });
  api.syncUrl();
  for (const [index, anchor] of links.slice(0, 2).entries()) {
    const outer = new URL(anchor.href, location);
    const back = new URL(outer.searchParams.get("return_to"), location);
    assert.equal(back.searchParams.get("route_scenario"), "example");
    assert.equal(back.searchParams.get("route_direction"), "reverse");
    assert.equal(back.searchParams.get("time_ns"), "42");
    assert.equal(back.searchParams.get("focus_node"), "b");
    assert.equal(back.searchParams.get("focus_resource"), index ? "if0" : null);
  }
  assert.equal(links[2].href, "https://elsewhere.example/node?return_to=old");
});

test("MN007: End focus owns packet preview across stationary hover; deliberate pointer movement takes over", () => {
  const { byId, document } = dom();
  const state = { routePacketKeyboardAnchor: null, routeGraphMode: "focused" };
  const buttons = ["first", "middle", "last"].map((id) => Object.assign(byId(id), { dataset: { routePacketRef: id, routeKind: "packet", routeId: id } }));
  const scope = { contains: (element) => buttons.includes(element), querySelectorAll: () => buttons };
  const observed = { preview: "", hover: "", clears: 0, pin: "" };
  const noop = () => {};
  const api = load(["bindRoutePacketElements", "bindRouteCorrelationElements"], { state, document,
    showRoutePacketPreview: (ref) => { observed.preview = ref; }, scheduleClearRoutePacketPreview: () => observed.clears++,
    selectRoutePacketTransition: (ref) => { observed.pin = ref; }, pruneRouteInteractionIndex: noop, indexRouteInteractionElement: noop,
    applyRouteHighlights: noop, readRouteFocusTargets: () => [], readRouteTokens: (element) => [element.dataset.routePacketRef],
    setRouteHover: (tokens) => { observed.hover = tokens[0]; }, clearRouteHover: () => { observed.hover = ""; } });
  api.bindRouteCorrelationElements(scope);
  api.bindRoutePacketElements(scope);
  buttons[0].focus();
  buttons[0].fire("keydown", { key: "End", preventDefault() {} });
  assert.equal(document.activeElement, buttons[2]);
  buttons[1].fire("pointerenter");
  buttons[1].fire("pointerleave");
  assert.equal(observed.preview, "last");
  assert.equal(observed.hover, "last");
  assert.equal(observed.clears, 0);
  buttons[1].fire("pointermove", { movementX: 1, movementY: 0 });
  assert.equal(observed.preview, "middle");
  assert.equal(observed.hover, "middle");
  assert.equal(observed.pin, "");
  buttons[2].fire("click");
  assert.equal(observed.pin, "last");
});

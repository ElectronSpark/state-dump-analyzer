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

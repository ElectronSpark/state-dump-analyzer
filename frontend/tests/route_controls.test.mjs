import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const SOURCE = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");
const PAGE = readFileSync(new URL("../pages/topology.html", import.meta.url), "utf8");

function functionSource(name) {
  const start = SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `topology.js must define ${name}()`);
  const ending = /\r?\n\}/.exec(SOURCE.slice(start));
  assert.ok(ending, `${name}() must have a closing brace`);
  return SOURCE.slice(start, start + ending.index + ending[0].length);
}

function harness(search = "", limits = {
  default_max_hops: 64,
  maximum_max_hops: 128,
  default_max_recursion: 16,
  maximum_max_recursion: 64,
}) {
  const elements = new Map();
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "",
      textContent: "",
      innerHTML: "",
      disabled: false,
      min: "",
      max: "",
      classList: { add() {}, toggle() {} },
      removeAttribute(name) { delete this[name]; },
    });
    return elements.get(id);
  };
  const state = {
    routeCapabilities: {
      limits,
      scenarios: [
        {
          scenario_id: "ordinary",
          label: "Ordinary trace",
          description: "Follow the declared ordinary path.",
          default_source: "source:a",
          default_destination: "destination:b",
          route_type: "ipv4",
          route_family: "ipv4",
          vrf_id: "blue",
        },
        {
          scenario_id: "external",
          label: "External termination",
          description: "Deliver at the declared external attachment; do not invent another router.",
          default_source: { endpoint_id: "source:e" },
          default_destination: { endpoint_id: "destination:external" },
          route_type: "connected",
          route_family: "ipv4",
          vrf_id: "default",
        },
        {
          scenario_id: "transit",
          label: "Transit observation",
          description: "Return reaches the source without revisiting the observation point.",
          default_source: "source:e",
          default_destination: "destination:b",
          default_start: { start_id: "start:p" },
          route_type: "ipv4",
          route_family: "ipv4",
          vrf_id: "blue",
        },
      ],
      directional_pairs: [],
      sources: [{ source_id: "source:a", node_id: "a" }, { source_id: "source:e", node_id: "e" }],
      destinations: [{ destination_id: "destination:b", node_id: "b" }, { destination_id: "destination:external", node_id: "e" }],
      start_points: [{ start_id: "start:a", node_id: "a" }, { start_id: "start:e", node_id: "e" }, { start_id: "start:p", node_id: "p" }],
      vrfs: [{ vrf_id: "blue", vrf: "blue" }, { vrf_id: "default", vrf: "default" }],
      route_families: [{ route_family: "ipv4", address_family: "ipv4", label: "IPv4" }],
      route_types: [{ type_id: "ipv4", label: "IPv4" }, { type_id: "connected", label: "Connected" }],
      policies: ["strict", "best_effort"],
      default_scenario_id: "ordinary",
      default_source: "source:a",
      default_destination: "destination:b",
      default_start: "start:a",
      default_vrf: "blue",
      default_route_family: "ipv4",
      default_route_type: "ipv4",
      default_policy: "strict",
      default_steering_profile: "",
    },
    query: { context_id: "context", request: { basis: { kind: "absolute_time", time_ns: "1" }, node_queries: [] } },
  };
  const functions = [
    "firstDeclaredString", "routeStartSelectorValue", "selectedRouteScenario", "directionalPairForScenario",
    "routeBudgetDefinition", "routeBudgetValue", "renderRouteBudgetControls", "routeTraceBudgets", "syncRouteBudgetParams",
    "routeScenarioEndpointDefaults", "routeScenarioStartDefault", "renderRouteScenarioGuide", "renderRouteControls", "buildRouteTraceRequest",
  ];
  const factory = new Function("state", "byId", "location", `
    const escapeHtml = (value) => String(value ?? "");
    const titleCase = (value) => String(value ?? "");
    const routeStartDisplayValue = (point) => point.start_id;
    const routeEndpointInputValue = (_, value) => value;
    const setRouteEndpointInput = (kind, value) => { byId("mn-route-" + kind).value = value; };
    const setRouteStartInput = (value) => { byId("mn-route-start").value = value; };
    const selectedRouteEndpoint = (kind) => state.routeCapabilities[kind === "source" ? "sources" : "destinations"]
      .find((item) => item[kind + "_id"] === byId("mn-route-" + kind).value);
    const selectedRouteStart = () => state.routeCapabilities.start_points.find((item) => item.start_id === byId("mn-route-start").value);
    const resolveCompatibleRouteContext = ({routeType, routeFamily, vrf}) => ({routeType,
      family: state.routeCapabilities.route_families.find((item) => item.route_family === routeFamily),
      vrf: state.routeCapabilities.vrfs.find((item) => item.vrf === vrf)});
    const applyCompatibleRouteContext = ({routeType, routeFamily, vrf}) => {
      byId("mn-route-type").value = routeType;
      byId("mn-route-family").value = routeFamily;
      byId("mn-route-vrf").value = vrf;
    };
    const renderRouteSteeringProfiles = (_, value) => { byId("mn-route-steering").value = value; };
    const syncRouteStartControlState = () => {};
    const steeringProfilesForScenario = () => [];
    const routeEndpointScopeIssue = () => "";
    const routeStartScopeIssue = () => "";
    const sameCanonicalRouteEndpoint = () => false;
    const MAX_ROUTE_PATHS = 64;
    ${functions.map(functionSource).join("\n")}
    return {${functions.join(",")}};
  `);
  return { state, byId, api: factory(state, byId, { search }) };
}

test("scenario selector and live description are visible outside advanced controls", () => {
  const scenario = PAGE.indexOf('id="mn-route-scenario"');
  const advanced = PAGE.indexOf('<details class="mn-route-advanced">');
  assert.ok(scenario >= 0 && scenario < advanced);
  assert.equal(PAGE.match(/id="mn-route-scenario"/g).length, 1);
  assert.match(PAGE, /id="mn-route-scenario-description" aria-live="polite"/);
  assert.match(functionSource("bindControls"), /renderRouteScenarioGuide\(scenario\)/);
});

test("scenario-only deep links load the selected endpoints and source start together", () => {
  const { api, byId } = harness("?route_scenario=external");
  api.renderRouteControls();
  assert.equal(byId("mn-route-source").value, "source:e");
  assert.equal(byId("mn-route-destination").value, "destination:external");
  assert.equal(byId("mn-route-start").value, "start:e");
  assert.equal(byId("mn-route-vrf").value, "default");
  assert.equal(byId("mn-route-type").value, "connected");
  assert.match(byId("mn-route-scenario-description").textContent, /external attachment/);
  const request = api.buildRouteTraceRequest();
  assert.equal(request.source_id, "source:e");
  assert.equal(request.destination_id, "destination:external");
  assert.equal(request.trace_starts.forward.start_id, "start:e");
});

test("explicit URL endpoints and start override scenario defaults; transit starts remain explicit", () => {
  const transit = harness("?route_scenario=transit");
  transit.api.renderRouteControls();
  assert.equal(transit.byId("mn-route-start").value, "start:p");
  const override = harness("?route_scenario=transit&route_source=source%3Aa&route_destination=destination%3Aexternal&route_start=start%3Ae");
  override.api.renderRouteControls();
  assert.equal(override.byId("mn-route-source").value, "source:a");
  assert.equal(override.byId("mn-route-destination").value, "destination:external");
  assert.equal(override.byId("mn-route-start").value, "start:e");
});

test("scenario changes and deep links share endpoint defaults, including directional pairs", () => {
  const { api, state } = harness();
  const scenario = state.routeCapabilities.scenarios[1];
  assert.deepEqual(api.routeScenarioEndpointDefaults(scenario), { source: "source:e", destination: "destination:external" });
  assert.deepEqual(api.routeScenarioEndpointDefaults(scenario, { forward: { source_id: "source:a", destination_id: "destination:b" } }),
    { source: "source:a", destination: "destination:b" });
  assert.match(functionSource("bindControls"), /routeScenarioEndpointDefaults\(scenario, pair\)/);
  assert.match(functionSource("bindControls"), /routeScenarioStartDefault\(scenario\)/);
});

test("scenario descriptions are rendered as text, including untrusted markup", () => {
  const { api, byId } = harness();
  api.renderRouteScenarioGuide({ description: "<img src=x onerror=bad()>" });
  assert.equal(byId("mn-route-scenario-description").textContent, "<img src=x onerror=bad()>");
  assert.equal(byId("mn-route-scenario-description").innerHTML, "");
});

test("unavailable tracing disables budgets and explains the missing scenario", () => {
  const { api, state, byId } = harness();
  state.routeCapabilities = null;
  api.renderRouteControls();
  assert.equal(byId("mn-route-run").disabled, true);
  assert.equal(byId("mn-route-max-hops").disabled, true);
  assert.equal(byId("mn-route-max-recursion").disabled, true);
  assert.equal(byId("mn-route-scenario-description").textContent, "No route scenario is advertised for this assembly.");
});

test("budget controls use advertised defaults and maxima and send numeric request values", () => {
  const { api, byId } = harness("?route_max_hops=5&route_max_recursion=0", {
    default_max_hops: 9, maximum_max_hops: 12, default_max_recursion: 3, maximum_max_recursion: 6,
  });
  api.renderRouteControls();
  assert.equal(byId("mn-route-max-hops").min, "1");
  assert.equal(byId("mn-route-max-hops").max, "12");
  assert.equal(byId("mn-route-max-recursion").min, "0");
  assert.equal(byId("mn-route-max-recursion").max, "6");
  assert.match(byId("mn-route-max-hops-help").textContent, /default 9/);
  assert.deepEqual(api.routeTraceBudgets(), { max_hops: 5, max_recursion: 0 });
  const request = api.buildRouteTraceRequest();
  assert.equal(request.max_hops, 5);
  assert.equal(request.max_recursion, 0);
  const params = new URLSearchParams();
  api.syncRouteBudgetParams(params);
  assert.equal(params.get("route_max_hops"), "5");
  assert.equal(params.get("route_max_recursion"), "0");
  assert.match(functionSource("syncUrl"), /syncRouteBudgetParams\(url.searchParams\)/);
});

test("invalid deep-link budgets use declared defaults, while invalid edits block tracing", () => {
  const { api, byId } = harness("?route_max_hops=129&route_max_recursion=-1");
  api.renderRouteControls();
  assert.deepEqual(api.routeTraceBudgets(), { max_hops: 64, max_recursion: 16 });
  for (const value of ["", "0", "-1", "1.5", "1e2", "NaN", "129", "9007199254740993"]) {
    byId("mn-route-max-hops").value = value;
    assert.throws(() => api.buildRouteTraceRequest(), /Maximum hops must be a whole number from 1 to 128/);
  }
  byId("mn-route-max-hops").value = "128";
  byId("mn-route-max-recursion").value = "64";
  assert.deepEqual(api.routeTraceBudgets(), { max_hops: 128, max_recursion: 64 });
  byId("mn-route-max-recursion").value = "65";
  assert.throws(() => api.routeTraceBudgets(), /Maximum recursion/);
  const params = new URLSearchParams("route_max_recursion=65");
  api.syncRouteBudgetParams(params);
  assert.equal(params.has("route_max_recursion"), false);
});

test("missing or malformed capability limits are not invented or sent", () => {
  for (const limits of [undefined, {}, { default_max_hops: "64", maximum_max_hops: 128 },
    { default_max_hops: 64, maximum_max_hops: 20 }, { default_max_recursion: -1, maximum_max_recursion: 64 }]) {
    const { api, state, byId } = harness();
    state.routeCapabilities.limits = limits;
    api.renderRouteControls();
    assert.equal(byId("mn-route-max-hops").disabled, true);
    assert.equal(byId("mn-route-max-recursion").disabled, true);
    assert.deepEqual(api.routeTraceBudgets(), {});
    const request = api.buildRouteTraceRequest();
    assert.equal(Object.hasOwn(request, "max_hops"), false);
    assert.equal(Object.hasOwn(request, "max_recursion"), false);
  }
});

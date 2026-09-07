import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");
const page = readFileSync(new URL("../pages/topology.html", import.meta.url), "utf8");
const css = readFileSync(new URL("../assets/topology.css", import.meta.url), "utf8");
function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = /\r?\n\}/.exec(source.slice(start));
  assert.ok(end);
  return source.slice(start, start + end.index + end[0].length);
}

const escapeHtml = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;");
function elements() {
  const map = new Map();
  return (id) => {
    if (!map.has(id)) map.set(id, { hidden: false, value: "", textContent: "", innerHTML: "",
      classList: { add() {}, remove() {} }, removeAttribute(key) { delete this[key]; } });
    return map.get(id);
  };
}

test("restore limits uses advertised defaults, preserves unrelated inputs and invalidates stale results", () => {
  const state = { routeCapabilities: { limits: {
    default_max_hops: 32, maximum_max_hops: 96, default_max_recursion: 7, maximum_max_recursion: 20,
  } } };
  const byId = elements();
  byId("mn-route-max-hops").value = "bad";
  byId("mn-route-max-recursion").value = "0";
  byId("mn-route-source").value = "tenant-source";
  byId("mn-route-steering").value = "declared-override";
  let invalidations = 0;
  let synchronized = 0;
  const run = new Function("state", "byId", "invalidateRouteTraceResult", "syncUrl",
    ["routeBudgetDefinition", "routeBudgetValue", "renderRouteBudgetControls", "restoreRouteBudgets"]
      .map(functionSource).join("\n") + ";return restoreRouteBudgets;")(
    state, byId, () => invalidations++, () => synchronized++,
  );
  run();
  assert.equal(byId("mn-route-max-hops").value, "32");
  assert.equal(byId("mn-route-max-recursion").value, "7");
  assert.equal(byId("mn-route-source").value, "tenant-source");
  assert.equal(byId("mn-route-steering").value, "declared-override");
  assert.equal(invalidations, 1);
  assert.equal(synchronized, 1);
  assert.match(byId("mn-route-limits-status").textContent, /Trace the route to apply/);
  state.routeCapabilities.limits = {};
  run();
  assert.equal(byId("mn-route-restore-limits").disabled, true);
  assert.equal(byId("mn-route-max-hops").value, "");
});

function outcomeHarness() {
  const state = { routePending: false, routeTraces: {}, routeBundle: null };
  const byId = elements();
  const verdict = { code: "incomplete", className: "is-unresolved", label: "Unknown <state>", detail: "No complete evidence" };
  const dependencies = { state, byId, escapeHtml,
    bidirectionalSummary: () => ({ label: "Incomplete", detail: "Partial" }),
    routeTraceOutcome: () => verdict, routeFlowEndpointLabel: (_trace, side) => side,
  };
  const render = new Function(...Object.keys(dependencies), `${functionSource("renderRouteOutcome")};return renderRouteOutcome;`)(...Object.values(dependencies));
  return { state, byId, verdict, render };
}

test("accepted trace clears the restore reminder before starting work, invalid input does not", async () => {
  const byId = elements();
  const reminder = "Advertised limits restored. Trace the route to apply them.";
  const started = new Error("test stops at work boundary");
  let invalid = false;
  const run = new Function("byId", "immutableSnapshot", "buildRouteTraceRequest", "analysisLoadProgress",
    `async ${functionSource("runRouteTrace")}; return runRouteTrace;`)(
    byId, (value) => value,
    () => { if (invalid) throw new Error("Invalid limits"); return {}; },
    { begin() { throw started; } },
  );
  byId("mn-route-limits-status").textContent = reminder;
  invalid = true;
  await run();
  assert.equal(byId("mn-route-limits-status").textContent, reminder);
  assert.equal(byId("mn-route-error").textContent, "Invalid limits");
  invalid = false;
  await assert.rejects(run(), (error) => error === started);
  assert.equal(byId("mn-route-limits-status").textContent, "");
});

test("trace-wide outcome is independent of path selection and hides stale pending/empty results", () => {
  const h = outcomeHarness();
  const trace = { paths: [{ path_id: "a" }] };
  h.render(trace);
  assert.equal(h.byId("mn-direction-comparison").hidden, false);
  assert.match(h.byId("mn-direction-comparison").innerHTML, /Unknown &lt;state>/);
  assert.match(h.byId("mn-direction-comparison").innerHTML, /Resolution quality/);
  h.state.routePending = true;
  h.render(trace);
  assert.equal(h.byId("mn-direction-comparison").hidden, true);
  h.state.routePending = false;
  h.render(null);
  assert.equal(h.byId("mn-direction-comparison").hidden, true);
  h.verdict.code = "unreachable";
  h.render({ paths: [] });
  assert.equal(h.byId("mn-direction-comparison").hidden, false);
  assert.match(h.byId("mn-direction-comparison").innerHTML, /Forwarding result/);
});

test("overview render computes verdict before the no-pinned-path early return", () => {
  const h = outcomeHarness();
  h.state.routeTrace = { paths: [{ path_id: "p" }] };
  const noop = () => {};
  const dependencies = { state: h.state, byId: h.byId, document: { querySelector: () => ({}) },
    renderDirectionTabs: noop, renderRouteSeed: noop, updateRouteViewChrome: noop,
    renderRoutePacketEvolution: noop, renderRouteOutcome: h.render,
    selectedRoutePath: () => null, renderUnselectedRoutePathTabs: noop,
  };
  new Function(...Object.keys(dependencies), `${functionSource("renderRouteTrace")};renderRouteTrace();`)(...Object.values(dependencies));
  assert.equal(h.byId("mn-route-content").hidden, true, "path-local details still stay hidden");
  assert.equal(h.byId("mn-direction-comparison").hidden, false, "trace verdict stays visible");
  assert.equal((page.match(/id="mn-direction-comparison"/g) || []).length, 1);
  assert.ok(page.indexOf('id="mn-direction-comparison"') < page.indexOf('class="mn-route-workbench"'), "verdict is outside selection-dependent containers");
  assert.match(css, /\.mn-direction-comparison\[hidden\]\s*\{\s*display:\s*none;/, "component display must not override hidden state");
});

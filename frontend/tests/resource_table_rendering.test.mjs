import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";

import { relationshipPresencePresentation, resourceExistenceLabel, stateChipClassName } from "../assets/view_models.js";

const productionSource = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function productionFunction(name) {
  const start = productionSource.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `production function ${name} exists`);
  const next = productionSource.slice(start + 1).search(/\n(?:async )?function /);
  return productionSource.slice(start, next < 0 ? undefined : start + 1 + next);
}

test("timeline visibility checkboxes keep a positive accessible name in both states", () => {
  for (const visible of [true, false]) {
    const context = vm.createContext({
      laneSelectedByMode: () => visible,
      escapeHtml: (value) => String(value).replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;"),
    });
    vm.runInContext(productionFunction("laneVisibilityCheckbox"), context, { timeout: 1_000 });
    const markup = context.laneVisibilityCheckbox("resource-1", 'uplink <A> "one"');
    assert.equal(markup.includes(" checked"), visible);
    assert.ok(markup.includes('aria-label="Show uplink &lt;A> &quot;one&quot; in Resource timeline"'));
    assert.ok(!markup.includes("Hide "));
    assert.ok(context.laneVisibilityCheckbox("resource-1", "").includes('aria-label="Show resource-1 in Resource timeline"'));
  }
});

test("the production resource-table renderer does not turn unknown existence into yes", () => {
  const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
  const start = source.indexOf("function renderResourceTables() {");
  const end = source.indexOf("\nfunction dashboardDescriptors()", start);
  assert.ok(start >= 0 && end > start, "production renderer must be present");
  const elements = new Map();
  for (const id of ["resource-table-wrap", "resource-search", "resource-type-tabs", "resource-table-summary"]) {
    elements.set(id, { innerHTML: "", value: "", querySelectorAll: () => [] });
  }
  const items = [true, false, null].map((exists, index) => ({
    resource_id: `r${index}`, label: `r${index}`, kind: "interface", layer: "hardware",
    exists, status: "unknown", status_class: "unknown",
  }));
  const context = vm.createContext({
    byId: (id) => elements.get(id),
    state: { resourceQuery: { items }, selectedResourceKind: "interface" },
    MAX_RESOURCE_ROWS: 100,
    initializeResourceTableView() {},
    resourceTableViewDescriptors: () => [],
    canonicalResourceId: (id) => id,
    escapeHtml: (value) => String(value),
    humanResourceType: (value) => value,
    humanLayer: (value) => value,
    presentationColumns: () => [],
    presentationTags: () => new Set(),
    resourcePageDetails: () => ({ returned: 3, first: 1, last: 3 }),
    resourceTimeSummary: () => "selected time",
    resourcePaginationMarkup: () => "",
    laneVisibilityCheckbox: () => "",
    bindResourcePagination() {},
    bindLaneVisibilityCheckboxes() {},
    resourceExistenceLabel,
    stateChipClassName,
  });
  vm.runInContext(`${source.slice(start, end)}\nrenderResourceTables();`, context, { timeout: 1_000 });
  const markup = elements.get("resource-table-wrap").innerHTML;
  for (const [id, label] of [["r0", "yes"], ["r1", "no"], ["r2", "unknown"]]) {
    const row = markup.match(new RegExp(`<tr data-resource-id="${id}"[\\s\\S]*?</tr>`))?.[0];
    assert.ok(row, `rendered row ${id} is missing`);
    assert.ok(row.includes(`<td>${label}</td>`), `${id} must display ${label}`);
  }
});

test("cross-kind selection refreshes the generic query and resets paging, not bundle scope", () => {
  for (const [kind, view, requests] of [["route", null, 1], ["interface", null, 0], ["route", "bundled", 0]]) {
    const state = {
      selectedResourceId: "a", selectedResourceKind: "interface", selectedResourceViewId: view,
      resourceOffset: 500, resourceQuery: { items: [] },
      resourceById: new Map([["b", { resource_id: "b", kind }]]), correlatedResourceIds: new Set(),
      graph: null, cursorNs: 0n,
    };
    const queried = [];
    const context = vm.createContext({
      state, canonicalResourceId: (id) => id, resourceKind: (item) => item.kind,
      requestResources: () => queried.push({ kind: state.selectedResourceKind, offset: state.resourceOffset }),
      isScaleMode: () => false, markCorrelationPending() {}, rerenderTimelinePreservingScroll() {},
      renderResourceTables() {}, refreshDashboardSelectionPresentation() {}, requestGraph() {}, updateFabricNavigationLink() {},
    });
    vm.runInContext(`${productionFunction("selectResource")}\nselectResource('b');`, context, { timeout: 1_000 });
    assert.equal(queried.length, requests);
    assert.equal(state.selectedResourceId, "b");
    assert.equal(state.selectedResourceViewId, view);
    if (requests) assert.deepEqual(queried[0], { kind: "route", offset: 0 });
    else assert.equal(state.resourceOffset, 500);
  }
});

test("production local, transport, and timeline graphs retain relationship presence", () => {
  for (const flag of ["omitted", true, false, null]) {
    const edge = { source: "a", target: "b", type: "link", quality: "exact", valid_from_ns: "0", valid_to_ns: "20" };
    if (flag !== "omitted") edge.present = flag;
    const state = {
      dataset: { relationships: [], relationship_intervals: [edge] }, viewStartNs: 0n, viewEndNs: 20n,
      resourceById: new Map([["a", {}], ["b", {}]]), laneByResource: new Map([["a", {}], ["b", {}]]),
      graph: { nodes: [], edges: [edge] },
    };
    const context = vm.createContext({
      state, relationshipPresencePresentation, canonicalResourceId: (id) => id,
      toNs: (value) => BigInt(value), statusAtLane: () => ({ exists: true, properties: {} }),
      relationshipPresentation: () => ({}), resourceLabel: (_, id) => id,
      resourceKind: () => "item", resourceLayer: () => "layer", presentationTags: () => new Set(),
    });
    vm.runInContext(["relationshipTransportKey", "localGraphAt", "normalizedGraph", "normalizedRelationshipSpan"].map(productionFunction).join("\n"), context, { timeout: 1_000 });
    const local = vm.runInContext("localGraphAt(10n)", context, { timeout: 1_000 });
    const normalized = vm.runInContext("normalizedGraph()", context, { timeout: 1_000 });
    const span = vm.runInContext("normalizedRelationshipSpan(state.graph.edges[0])", context, { timeout: 1_000 });
    for (const graph of [local, normalized]) {
      assert.equal(graph.edges.length, flag === false ? 0 : 1);
      if (graph.edges.length) {
        assert.equal(graph.edges[0].present, flag === null ? null : true);
        assert.equal(graph.edges[0].quality, flag === null ? "ambiguous" : "exact");
        assert.deepEqual(Array.from(graph.edges[0].possible_presence), flag === null ? [false, true] : [true]);
      }
    }
    assert.equal(span === null, flag === false);
    if (span) assert.equal(span.quality, flag === null ? "ambiguous" : "exact");
  }
});

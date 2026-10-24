import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = /\r?\n\}/.exec(source.slice(start));
  return source.slice(start, start + end.index + end[0].length);
}
const api = new Function(`${functionSource("focusedGraphCanvasWidth")}
  ${functionSource("graphEdgeGeometry")}
  return { focusedGraphCanvasWidth, graphEdgeGeometry };`)();

test("focused relationship labels clear both cards at narrow and wide widths", () => {
  // Include the audit viewport, compact and desktop cards, and a long plug-in label.
  for (const availableWidth of [320, 426, 474, 900, 1400]) {
    for (const nodeWidth of [146, 184, 220]) {
      for (const labelWidth of [67, 140, 260]) {
        const width = Math.max(availableWidth, api.focusedGraphCanvasWidth(nodeWidth, labelWidth));
        const positions = new Map([
          ["incoming", { x: 15, y: 50 }],
          ["selected", { x: 50, y: 50 }],
          ["outgoing", { x: 85, y: 50 }],
        ]);
        for (const [source, target] of [["incoming", "selected"], ["selected", "outgoing"], ["outgoing", "selected"]]) {
          const geometry = api.graphEdgeGeometry({ source, target }, positions, 540, width, 0);
          const centers = [positions.get(source).x, positions.get(target).x].sort((a, b) => a - b);
          const leftCardRight = centers[0] / 100 * width + nodeWidth * 1.025 / 2;
          const rightCardLeft = centers[1] / 100 * width - nodeWidth * 1.025 / 2;
          assert.ok(geometry.labelX - labelWidth / 2 >= leftCardRight + 15);
          assert.ok(geometry.labelX + labelWidth / 2 <= rightCardLeft - 15);
        }
      }
    }
  }
});

for (const mode of ["focus", "full"]) {
  test(`rendered ${mode} graph preserves relationship pointer and keyboard identity`, () => {
    const element = (dataset = {}) => ({
      dataset, attrs: {}, handlers: {}, style: {}, offsetWidth: 146,
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute(name, value) { this.attrs[name] = value; },
      addEventListener(name, handler) { this.handlers[name] = handler; },
    });
    const svg = element();
    const path = element();
    const label = element();
    let measurements = 0;
    label.getComputedTextLength = () => {
      assert.equal(svg.attrs.viewBox, "0 0 426 540", "measurement starts at one CSS pixel per SVG unit");
      measurements += 1;
      return 67;
    };
    const buttons = [element({ resourceId: "selected" }), element({ resourceId: "peer374" })];
    const query = selector => ({
      ".graph-node": buttons, ".graph-edge-label": [label], ".graph-edge": [path],
      "[data-graph-edge-id]": [path, label],
    })[selector] || [];
    const canvas = { style: {}, querySelectorAll: query,
      get clientWidth() { return Math.max(426, parseFloat(this.style.minWidth) || 0); } };
    const stage = { ...element(), clientWidth: 426, querySelectorAll: query,
      querySelector: selector => selector === ".graph-canvas" ? canvas : svg };
    const graph = {
      nodes: ["selected", "peer374"].map(id => ({ id, label: id, kind: "interface", layer: "control" })),
      edges: [{ id: "edge374", source: "selected", target: "peer374", type: "has_neighbor" }],
    };
    const positions = new Map([["selected", { x: 50, y: 50 }], ["peer374", { x: 85, y: 50 }]]);
    const pinned = [];
    const noop = () => {};
    const deps = {
      state: { selectedResourceId: mode === "focus" ? "selected" : null },
      byId: id => id === "graph-stage" ? stage : element(),
      closeCorrelationHover: noop, normalizedGraph: () => graph, graphDisplayTimeNs: () => 0,
      renderCorrelationTimeState: noop, syncGraphScopeButton: noop, updateCorrelationState: noop,
      scopedGraph: value => value, boundedCorrelationGraph: value => value,
      graphLayout: () => ({ positions, height: 540, mode, columns: [] }),
      layerColor: () => "cyan", escapeHtml: String, humanLayer: String,
      relationshipPresentation: () => ({ displayLabel: "has_neighbor", directed: true }),
      isCompact: () => false, resourceIconMarkup: () => "", graphColumnHeadingsHtml: () => "",
      ...api, validGraphInspection: () => null, bindCorrelationHover: noop,
      setGraphInspection: noop, graphNodeHoverHtml: () => "resource", graphEdgeHoverHtml: () => "edge",
      pinGraphInspection: (_stage, _graph, inspection) => pinned.push(inspection),
      formatOffset: String, renderCorrelationList: noop,
    };
    new Function(...Object.keys(deps), `${functionSource("renderGraph")}; renderGraph();`)(...Object.values(deps));
    assert.equal(measurements, mode === "focus" ? 1 : 0);
    assert.equal(svg.attrs.viewBox, `0 0 ${canvas.clientWidth} 540`);
    assert.ok(Math.abs(Number(label.attrs.x) - canvas.clientWidth * 0.675) < 1e-9);
    if (mode === "full") assert.equal(canvas.clientWidth, 426, "full/no-selection graph retains the viewport width");
    const event = key => ({ key, preventDefault() {}, stopPropagation() {} });
    label.handlers.click(event());
    label.handlers.keydown(event("Enter"));
    path.handlers.click(event());
    assert.deepEqual(pinned, Array.from({ length: 3 }, () => ({ kind: "edge", id: "edge374" })));
  });
}

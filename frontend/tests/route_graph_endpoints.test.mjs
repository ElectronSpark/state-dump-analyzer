import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { escapeHtml } from "../assets/shared.js";

const SOURCE = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const ending = /\r?\n\}/.exec(SOURCE.slice(start));
  assert.ok(ending);
  return SOURCE.slice(start, start + ending.index + ending[0].length);
}

function harness(direction = "forward") {
  const dependencies = {
    state: { activeRouteDirection: direction }, escapeHtml,
    nodeHealth: () => "good", basisForNode: () => ({}), nodePlan: () => ({}),
    interactionTokensForNode: () => [], interactionFocusTargetsForNode: () => [],
    routeForwardingSegments: (path) => path?.segments || [], routeNodeQualityClasses: () => [],
    routeQualitySignature: () => "", routeQualityClasses: () => [], pathStatusSummary: () => "declared",
    pathIsControlPlaneOnly: () => false, packetRefsForRouteNode: () => [],
    routeTokensAttribute: () => "", routeFocusTargetsAttribute: () => "", packetRefsAttribute: () => "",
    formatDurationNs: () => "", refRouteTokens: () => [],
    findNodeForRef: (ref, nodes) => nodes.find((node) => node.node_id === ref.node_id),
    refIdentity: (ref) => ref,
  };
  const names = ["firstArray", "sameRouteRef", "normalizedRouteOccurrences", "routePathNodeRefs", "routeNodeSequence", "allPathGraphNodes", "routePathMemberships", "mapNodeMarkup", "allPathNodeMarkup"];
  return new Function(...Object.keys(dependencies), `${names.map(functionSource).join("\n")}
    return { normalizedRouteOccurrences, routeNodeSequence, allPathGraphNodes, mapNodeMarkup, allPathNodeMarkup };
  `)(...Object.values(dependencies));
}

const nodes = ["a", "p", "b"].map((id) => ({ key: id, member_id: `member:${id}`, node_id: id, label: id.toUpperCase(), plan: {} }));
const position = { x: 0, y: 0 };

function path(api, ids, reached, occurrenceIndexes = ids.map(() => 0)) {
  const value = {
    path_id: "path:test", label: "Declared candidate", segments: [],
    terminal_reachability: reached === undefined ? undefined : { reached },
  };
  value.node_occurrences = api.normalizedRouteOccurrences({ node_occurrences: ids.map((id, index) => ({
    occurrence_id: `visit:${index}`, occurrence_index: occurrenceIndexes[index], ref: nodes.find((node) => node.node_id === id),
  })) }, value.path_id, [], nodes);
  return value;
}

function hasEndBadge(html) {
  return /class="[^"]*\bis-route-destination\b/.test(html);
}

test("zero-based repeated occurrence indexes are preserved; one-based ordinals remain compatible", () => {
  const api = harness();
  const declared = api.normalizedRouteOccurrences({ node_occurrences: [
    { node_id: "p", occurrence_index: 0 }, { node_id: "p", occurrence_index: 1 },
    { node_id: "p", ordinal: 3 }, { node_id: "p" },
  ] }, "path:test", [], nodes);
  assert.deepEqual(declared.map((item) => item.occurrence_index), [0, 1, 2, 3]);
});

test("a loop-ending repeat does not make the shared first visit a destination", () => {
  const api = harness();
  const loop = path(api, ["a", "p", "p"], false, [0, 0, 1]);
  const graphNodes = api.allPathGraphNodes([loop], nodes);
  const visits = graphNodes.filter((node) => node.node_id === "p");
  assert.equal(visits.length, 2);
  const first = api.allPathNodeMarkup(visits[0], position, [loop]);
  const repeated = api.allPathNodeMarkup(visits[1], position, [loop]);
  assert.equal(hasEndBadge(first), false);
  assert.equal(hasEndBadge(repeated), true);
  assert.match(first, /node details, visit 1/);
  assert.match(repeated, /node details, visit 2/);
  assert.match(repeated, /data-route-end-label="TRACE END"/);
  assert.doesNotMatch(first + repeated, /data-route-end-label="DESTINATION"/);
});

test("focused and all-path graphs label reached endpoints only from the declared reachability", () => {
  for (const direction of ["forward", "reverse"]) {
    const api = harness(direction);
    for (const reached of [true, false, null, undefined]) {
      const candidate = path(api, ["a", "b"], reached);
      const focusedNodes = api.routeNodeSequence(candidate, nodes);
      const overviewNodes = api.allPathGraphNodes([candidate], nodes);
      const expected = reached === true ? direction === "reverse" ? "SOURCE TARGET" : "DESTINATION" : "TRACE END";
      const focused = api.mapNodeMarkup(focusedNodes.at(-1), position, candidate, focusedNodes);
      const overview = api.allPathNodeMarkup(overviewNodes.at(-1), position, [candidate]);
      for (const html of [focused, overview]) {
        assert.equal(hasEndBadge(html), true);
        assert.ok(html.includes(`data-route-end-label="${expected}"`));
      }
    }
  }
});

test("focused repeated visits retain distinct numbering and only the final visit is a trace end", () => {
  const api = harness();
  const loop = path(api, ["a", "p", "p"], false, [0, 0, 1]);
  const routeNodes = api.routeNodeSequence(loop, nodes);
  const first = api.mapNodeMarkup(routeNodes[1], position, loop, routeNodes);
  const final = api.mapNodeMarkup(routeNodes[2], position, loop, routeNodes);
  assert.equal(hasEndBadge(first), false);
  assert.equal(hasEndBadge(final), true);
  assert.equal(routeNodes[1].route_occurrence_index, 0);
  assert.equal(routeNodes[2].route_occurrence_index, 1);
  assert.match(final, /data-route-end-label="TRACE END"/);
});

test("a shared terminal with mixed reached and unknown candidates retains the neutral trace-end label", () => {
  const api = harness();
  const reached = path(api, ["a", "b"], true);
  const unknown = { ...path(api, ["a", "b"], null), path_id: "path:unknown" };
  const graphNodes = api.allPathGraphNodes([reached, unknown], nodes);
  const html = api.allPathNodeMarkup(graphNodes.at(-1), position, [reached, unknown]);
  assert.equal(hasEndBadge(html), true);
  assert.match(html, /data-route-end-label="TRACE END"/);
});

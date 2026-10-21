import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/app.js", import.meta.url), "utf8");
function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  const end = /\r?\n\}/.exec(source.slice(start));
  return source.slice(start, start + end.index + end[0].length);
}

test("invalid topology form supersedes a pending valid response", async () => {
  const state = { topologyRequestId: 0 };
  const error = { textContent: "" };
  let resolve;
  let invalid = false;
  let abortCount = 0;
  let renders = 0;
  const api = new Promise((done) => { resolve = done; });
  const request = new Function("state", "error", "api", "invalid", "abort", "render", `
    const byId = () => error;
    const topologyRequestBody = () => { if (invalid()) throw new Error("Invalid time"); return {}; };
    const abortLatestRequests = abort;
    const renderTopologyQueryState = () => {};
    const isTopologyNodeSnapshot = () => false;
    const beginLatestRequest = () => ({signal: {}});
    const analysisRuntimeApi = () => api;
    const revisionPath = () => "query";
    const finishLatestRequest = () => {};
    const renderTopologyResults = render;
    async ${functionSource("requestTopology")}
    return requestTopology;
  `)(state, error, api, () => invalid, () => abortCount++, () => renders++);
  const old = request();
  invalid = true;
  await request();
  resolve({ unavailable_reason: "old error" });
  await old;
  assert.equal(error.textContent, "Invalid time");
  assert.equal(state.topologyQueryPending, false);
  assert.equal(renders, 0);
  assert.equal(abortCount, 2);
});

test("route explanation recognizes the core candidate next hop relationship", () => {
  const explain = new Function(`
    const humanResourceType = (value) => value;
    const formatValue = String;
    const relationshipDisplayLabel = (value) => "Unknown relationship (" + value + ")";
    ${functionSource("explanationSteps")}
    return explanationSteps;
  `)();
  assert.match(explain({kind: "NEXT_HOP", resource: "n", relation_type: "candidate_next_hop"})[0].text, /Candidate next hop/);
  assert.match(explain({kind: "NEXT_HOP", resource: "n", relation_type: "custom"})[0].text, /Unknown relationship \(custom\)/);
});

test("inferred connectivity preserves its label and explicit direction", () => {
  const elements = new Map([['topology-connectivity-count', {}], ['topology-connectivity-body', {}]]);
  const state = { topologyQuery: {} };
  const render = new Function('state', 'elements', `
    const byId = (id) => elements.get(id);
    const MAX_TOPOLOGY_CONNECTIVITY_ROWS = 200;
    const topologyResultRelationships = () => [];
    const topologyResultInferred = () => [{source: 'a', target: 'b', label: 'Declared adjacency', directed: true, inferred: true}];
    const topologyReferenceLabel = String;
    const relationshipPresentation = () => ({displayLabel: 'Unknown relationship', directed: null});
    const escapeHtml = String;
    const topologyObjectPreview = String;
    const topologyValidityLabel = () => 'current';
    const statusClassPresentation = () => 'unknown';
    const firstArray = (...values) => values.find(Array.isArray) || [];
    ${functionSource('renderTopologyConnectivity')}
    return renderTopologyConnectivity;
  `)(state, elements);
  render();
  assert.match(elements.get('topology-connectivity-body').innerHTML, /Declared adjacency/);
  assert.match(elements.get('topology-connectivity-body').innerHTML, /→/);
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const SOURCE = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `topology.js must define ${name}()`);
  const ending = /\r?\n\}/.exec(SOURCE.slice(start));
  assert.ok(ending, `${name}() must have a closing brace`);
  return SOURCE.slice(start, start + ending.index + ending[0].length);
}

function startLabel(startPoints) {
  return new Function("state", `${functionSource("routeTraceStartLabel")}; return routeTraceStartLabel;`)(
    { routeCapabilities: startPoints === undefined ? null : { start_points: startPoints } },
  );
}

test("missing optional start identity fields cannot match the first advertised point", () => {
  const label = startLabel([
    { start_id: "start:a", node_id: "a", label: "Node A" },
    { start_id: "start:b", node_id: "b", label: "Node B" },
  ]);
  assert.equal(label({ trace_start: { start_id: "start:b", node_id: "b" } }), "Node B");
  assert.equal(label({ trace_start: { node_id: "b" } }), "Node B");
  assert.equal(label({ trace_start: { node_id: "custom", label: "Custom start" } }), "Custom start");
  assert.equal(label({ trace_start: {} }), "trace start");
});

test("exact start identity outranks an earlier matching member or node", () => {
  const label = startLabel([
    { start_id: "start:other", member_id: "member:a", node_id: "a", label: "Other ingress" },
    { start_id: "start:exact", member_id: "member:a", node_id: "a", label: "Exact ingress" },
  ]);
  assert.equal(label({ trace_start: { start_id: "start:exact", member_id: "member:a", node_id: "a" } }), "Exact ingress");
});

test("member-qualified starts outrank an earlier node-only match", () => {
  const label = startLabel([
    { start_id: "start:old", member_id: "member:old", node_id: "a", label: "Old member" },
    { start_id: "start:new", member_id: "member:new", node_id: "a", label: "New member" },
  ]);
  assert.equal(label({ trace_start: { member_id: "member:new", node_id: "a" } }), "New member");
});

test("start labels retain request and explicit-label fallbacks when capabilities are absent", () => {
  const label = startLabel(undefined);
  assert.equal(label({ direction: "reverse", request: { trace_starts: { reverse: { label: "Return observation" } } } }), "Return observation");
  assert.equal(label({ starting_point: { node_id: "custom" } }), "custom");
  assert.equal(label({}), "trace start");
});

function packetHarness() {
  const functions = [
    "firstArray", "normalizedRouteEnum", "firstRouteEnum", "explicitRouteBoolean",
    "normalizedPacketNumber", "normalizePacketFields", "normalizePacketLayer", "normalizePacketSize",
    "normalizePacketState", "normalizePacketContribution", "packetTransitionRef",
    "normalizePacketTransitionEvaluation", "normalizePacketTrace",
  ];
  // Exercise real normalization and packet-reference propagation. Unrelated
  // resource token generation is isolated; these fixtures have no contributions.
  return new Function("routeTokensFor", "packetResourceReferenceTokens", "packetTopologyReferenceTokens", `
    const MAX_PACKET_LAYERS = 64;
    ${functions.map(functionSource).join("\n")}
    return { normalizePacketTransitionEvaluation, normalizePacketTrace };
  `)(() => [], () => [], () => []);
}

function resolutionStep(stepId, segmentId, target = stepId) {
  return { step_id: stepId, segment_id: segmentId, component_tokens: [`step:${stepId}`], highlight_target_ids: [`target:${target}`] };
}

function transition(stepId, segmentId) {
  return { segment_id: segmentId, transition: { step_id: stepId, transition_id: "packet:transition" } };
}

test("exact packet step wins over the first step on a shared segment", () => {
  const api = packetHarness();
  const steps = [resolutionStep("step:first", "segment:shared"), resolutionStep("step:second", "segment:shared")];
  const segments = [{ segment_id: "segment:shared" }];
  const packet = api.normalizePacketTrace({ transitions: [transition("step:second", "segment:shared")] }, "path:p", steps, segments);
  const evaluation = packet.transitions[0];
  assert.equal(evaluation.step_id, "step:second");
  assert.equal(evaluation.source_step_id, "step:second");
  assert.equal(evaluation.transition.step_id, "step:second");
  assert.deepEqual(evaluation.highlight_target_ids, ["target:step:second"]);
  assert.equal(steps[0].packet_refs, undefined);
  assert.deepEqual(steps[1].packet_refs, [evaluation.packet_ref]);
  assert.deepEqual(segments[0].packet_refs, [evaluation.packet_ref]);
});

test("exact packet step outranks an earlier legacy segment alias", () => {
  const api = packetHarness();
  const steps = [resolutionStep("step:other", "step:exact"), resolutionStep("step:exact", "segment:exact")];
  const result = api.normalizePacketTransitionEvaluation(transition("step:exact"), 0, "path:p", steps, [
    { segment_id: "step:exact" }, { segment_id: "segment:exact" },
  ]);
  assert.equal(result.step_id, "step:exact");
  assert.equal(result.segment_id, "segment:exact");
  assert.deepEqual(result.highlight_target_ids, ["target:step:exact"]);
});

test("a unique legacy segment-valued packet step remains correlated", () => {
  const api = packetHarness();
  const result = api.normalizePacketTransitionEvaluation(transition("segment:a", "segment:a"), 0, "path:p", [
    resolutionStep("step:a", "segment:a"),
  ], [{ segment_id: "segment:a" }]);
  assert.equal(result.step_id, "step:a");
  assert.equal(result.source_step_id, "segment:a");
  assert.deepEqual(result.highlight_target_ids, ["target:step:a"]);
});

test("ambiguous segment-only packet identity does not select an arbitrary resolution step", () => {
  const api = packetHarness();
  for (const stepId of [undefined, "segment:shared"]) {
    const steps = [resolutionStep("step:first", "segment:shared"), resolutionStep("step:second", "segment:shared")];
    const result = api.normalizePacketTransitionEvaluation(transition(stepId, "segment:shared"), 0, "path:p", steps, [{ segment_id: "segment:shared" }]);
    assert.equal(result.step_id, stepId || "packet-step-1");
    assert.equal(result.segment_id, "segment:shared");
    assert.deepEqual(result.highlight_target_ids, []);
  }
});

test("an undeclared packet step may correlate through a unique explicit segment", () => {
  const api = packetHarness();
  const result = api.normalizePacketTransitionEvaluation(transition(undefined, "segment:a"), 0, "path:p", [
    resolutionStep("step:a", "segment:a"),
  ], [{ segment_id: "segment:a" }]);
  assert.equal(result.step_id, "step:a");
  assert.deepEqual(result.highlight_target_ids, ["target:step:a"]);
});

test("a generated packet step fallback cannot impersonate a declared resolution step", () => {
  const api = packetHarness();
  const result = api.normalizePacketTransitionEvaluation(transition(undefined, "segment:a"), 0, "path:p", [
    resolutionStep("packet-step-1", "segment:other"), resolutionStep("step:a", "segment:a"),
  ], [{ segment_id: "segment:other" }, { segment_id: "segment:a" }]);
  assert.equal(result.step_id, "step:a");
  assert.equal(result.segment_id, "segment:a");
  assert.deepEqual(result.highlight_target_ids, ["target:step:a"]);
});

test("generated packet identities remain unbound through trace reference propagation", () => {
  const api = packetHarness();
  for (const segmentId of [undefined, "segment:shared"]) {
    const steps = [
      resolutionStep("packet-step-1", "segment:unrelated"),
      resolutionStep("step:first", "segment:shared"), resolutionStep("step:second", "segment:shared"),
    ];
    const segments = [{ segment_id: "packet-step-1" }, { segment_id: "segment:shared" }];
    const packet = api.normalizePacketTrace({ transitions: [transition(undefined, segmentId)] }, "path:p", steps, segments);
    const result = packet.transitions[0];
    assert.equal(result.step_id, "packet-step-1", "a display fallback remains available");
    assert.equal(result.resolution_step_id, null, "a display fallback is not a resolved step reference");
    assert.equal(result.segment_id, segmentId || null);
    assert.ok(steps.every((step) => step.packet_refs === undefined));
    assert.equal(segments[0].packet_refs, undefined, "a generated display ID cannot match a real segment ID");
    assert.deepEqual(segments[1].packet_refs, segmentId ? [result.packet_ref] : undefined);
  }
});

test("packet detail context uses resolved step identity instead of a display fallback", () => {
  const steps = [resolutionStep("packet-step-1", "segment:unrelated")];
  const context = new Function("routePacketPathForEvaluation", "nodeLabelForRef",
    `${functionSource("routePacketContext")}; return routePacketContext;`)(
    () => ({ steps, segments: [] }), () => "",
  );
  assert.equal(context({ step_id: "packet-step-1", resolution_step_id: null }).step, null);
  assert.equal(context({ step_id: "packet-step-1", resolution_step_id: "packet-step-1" }).step, steps[0]);
});

test("an unknown explicit packet step is preserved instead of rewritten from its segment", () => {
  const api = packetHarness();
  const steps = [resolutionStep("step:a", "segment:a")];
  const segments = [{ segment_id: "segment:a" }];
  const packet = api.normalizePacketTrace({ transitions: [transition("step:missing", "segment:a")] }, "path:p", steps, segments);
  const result = packet.transitions[0];
  assert.equal(result.step_id, "step:missing");
  assert.equal(result.transition.step_id, "step:missing");
  assert.equal(result.segment_id, "segment:a");
  assert.deepEqual(result.highlight_target_ids, []);
  assert.equal(steps[0].packet_refs, undefined);
  assert.deepEqual(segments[0].packet_refs, [result.packet_ref]);
});

test("explicit packet segment identity outranks earlier step-derived segments", () => {
  const api = packetHarness();
  const steps = [resolutionStep("step:a", "segment:from-step")];
  const segments = [{ segment_id: "segment:from-step" }, { segment_id: "segment:explicit" }];
  for (const segmentId of ["segment:explicit", "segment:missing"]) {
    const result = api.normalizePacketTransitionEvaluation(transition("step:a", segmentId), 0, "path:p", steps, segments);
    assert.equal(result.step_id, "step:a");
    assert.equal(result.segment_id, segmentId);
  }
});

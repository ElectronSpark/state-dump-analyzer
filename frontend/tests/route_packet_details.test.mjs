import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { escapeHtml, safeClass, titleCase } from "../assets/shared.js";

const SOURCE = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = SOURCE.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `topology.js must define ${name}()`);
  const ending = /\r?\n\}/.exec(SOURCE.slice(start));
  assert.ok(ending, `${name}() must have a closing brace`);
  return SOURCE.slice(start, start + ending.index + ending[0].length);
}

function harness() {
  const functions = [
    "firstArray", "formatInteger", "normalizedRouteEnum", "firstRouteEnum", "explicitRouteBoolean",
    "normalizedPacketNumber", "normalizePacketFields", "normalizePacketLayer", "normalizePacketSize",
    "normalizePacketState", "normalizePacketContribution", "packetTransitionRef", "normalizePacketTransitionEvaluation",
    "packetValueText", "packetResourceReferenceText", "packetTopologyReferenceText", "packetEvidenceText",
    "packetStateSummary", "packetSizeLabel", "packetDiffCount", "packetMtuLabel", "packetLayerClasses",
    "packetStateMarkup", "packetDiffMarkup", "packetContributionsMarkup", "packetTransitionDetailMarkup",
  ];
  const constants = SOURCE.match(/const (?:MAX_PACKET_LAYERS|PACKET_[A-Z_]+) = \d+;/g);
  assert.ok(constants?.length);
  // Execute the actual normalizers and detail renderer. Only unrelated route
  // context/token lookup is isolated; resource text and escaping remain real.
  return new Function("escapeHtml", "safeClass", "titleCase", `
    const routeTokensFor = () => [];
    const packetResourceReferenceTokens = () => [];
    const packetTopologyReferenceTokens = () => [];
    const routePacketContext = () => ({ location: "Step declared-step" });
    ${constants.join("\n")}
    ${functions.map(functionSource).join("\n")}
    return { normalizePacketTransitionEvaluation, packetTransitionDetailMarkup, packetStateMarkup };
  `)(escapeHtml, safeClass, titleCase);
}

const api = harness();

function packet(basis, size = 64, complete = true) {
  return {
    complete: true,
    layers: [{ layer_id: "payload", contract_id: "opaque.payload.v1", complete: true, fields: [] }],
    size: basis === undefined ? null : { basis_contract_id: basis, size_bytes: size, complete },
  };
}

function evaluation({ before = packet("opaque.before-size.v1"), after = packet("opaque.wire-size.v1"), constraint = null, mtu = {} } = {}) {
  return api.normalizePacketTransitionEvaluation({
    transition: {
      transition_id: "declared-transition", step_id: "declared-step",
      before, after, mtu_constraint: constraint,
      action_contract_id: "opaque.action.v1", action_label: "Declared action",
      disposition: "drop", actor_id: "declared-node", contributions: [],
    },
    mtu, diff: { complete: true }, continuity_valid: true,
  }, 0, "declared-path", [], []);
}

test("incomparable packet and MTU bases stay visible without converting or inferring a failure", () => {
  const value = evaluation({
    constraint: { basis_contract_id: "opaque.interface-size.v1", limit_bytes: 32, complete: true },
    mtu: { outcome: "unknown_basis_mismatch", size_bytes: 64, limit_bytes: 32 },
  });
  const html = api.packetTransitionDetailMarkup(value);
  assert.match(html, /Packet size basis: opaque\.before-size\.v1/);
  assert.match(html, /Packet size basis: opaque\.wire-size\.v1/);
  assert.match(html, /MTU basis: opaque\.interface-size\.v1/);
  assert.match(html, /MTU limit: 32 B/);
  assert.match(html, /MTU basis differs/);
  assert.match(html, /Disposition: Drop/);
  assert.doesNotMatch(html, /exceeds|MTU exceeded|fits .*MTU/);
});

test("equal bases retain the declared comparison and show the interface constraint resource", () => {
  const value = evaluation({
    before: packet("opaque.wire-size.v1"),
    constraint: {
      basis_contract_id: "opaque.wire-size.v1", limit_bytes: 64, complete: true,
      resource: { namespace: "opaque", node: "declared-node", layer: "network", kind: "interface", parts: [["name", "port-1"]] },
    },
    mtu: { outcome: "fits", size_bytes: 64, limit_bytes: 64, excess_bytes: 0 },
  });
  const snapshot = structuredClone(value);
  const html = api.packetTransitionDetailMarkup(value);
  assert.equal((html.match(/Packet size basis: opaque\.wire-size\.v1/g) || []).length, 2);
  assert.match(html, /MTU basis: opaque\.wire-size\.v1 · declared-node · opaque\/network\/interface · name=port-1/);
  assert.match(html, /MTU limit: 64 B/);
  assert.match(html, /64 B fits 64 B MTU/);
  assert.deepEqual(value, snapshot, "rendering must not modify plug-in declarations or comparison results");
});

test("missing packet observations and constraint fields remain explicitly unknown", () => {
  const html = api.packetTransitionDetailMarkup(evaluation({
    before: packet(undefined), after: packet(undefined), constraint: {}, mtu: { outcome: "unknown" },
  }));
  assert.equal((html.match(/Packet size basis: unknown/g) || []).length, 2);
  assert.equal((html.match(/>size unknown</g) || []).length, 2);
  assert.match(html, /MTU basis: unknown/);
  assert.match(html, /MTU limit: unknown · constraint incomplete/);
  assert.match(html, /MTU comparison unknown/);
  assert.doesNotMatch(html, /undefined|null|MTU limit: 0 B|fits .*MTU|exceeds/);
});

test("absent MTU constraint is not manufactured from packet layers or evaluation values", () => {
  const html = api.packetTransitionDetailMarkup(evaluation({
    after: { ...packet(undefined), layers: [{ contract_id: "ethernet.ipv4.tcp", size_bytes: 64 }] },
    mtu: { outcome: "not_declared", basis_contract_id: "not-a-constraint", limit_bytes: 128 },
  }));
  assert.match(html, /MTU not declared/);
  assert.match(html, /Packet size basis: unknown/);
  assert.doesNotMatch(html, /MTU basis:|MTU limit:|not-a-constraint/);
});

test("incomplete equal-basis evidence does not promote an unknown result; zero limit stays zero", () => {
  const html = api.packetTransitionDetailMarkup(evaluation({
    after: packet("opaque.wire-size.v1", 0, false),
    constraint: { basis_contract_id: "opaque.wire-size.v1", limit_bytes: 0, complete: false },
    mtu: { outcome: "unknown", size_bytes: 0, limit_bytes: 0 },
  }));
  assert.match(html, /Packet size basis: opaque\.wire-size\.v1 · size observation incomplete/);
  assert.match(html, /MTU limit: 0 B · constraint incomplete/);
  assert.match(html, /MTU comparison unknown/);
  assert.doesNotMatch(html, /fits .*MTU|exceeds/);
});

test("declared basis IDs and constraint resources are escaped in text and tooltip attributes", () => {
  const basis = 'opaque.<img src=x onerror="alert(1)">&\'size';
  const resource = '<svg onload="alert(2)">&\'interface';
  const html = api.packetTransitionDetailMarkup(evaluation({
    before: packet(basis), after: packet(basis),
    constraint: { basis_contract_id: basis, limit_bytes: 128, complete: true, resource: { label: resource } },
    mtu: { outcome: "unknown" },
  }));
  assert.ok(html.includes(`Packet size basis: ${escapeHtml(basis)}`));
  assert.ok(html.includes(`MTU basis: ${escapeHtml(basis)} · ${escapeHtml(resource)}`));
  assert.ok(html.includes(`title="${escapeHtml(`MTU basis: ${basis} · ${resource}`)}"`));
  assert.doesNotMatch(html, /<img|<svg|onerror="|onload="/);
});

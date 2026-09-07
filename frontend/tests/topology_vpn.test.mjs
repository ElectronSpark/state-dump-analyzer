import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../assets/topology.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `missing production function ${name}`);
  const end = /\r?\n\}/.exec(source.slice(start));
  assert.ok(end);
  return source.slice(start, start + end.index + end[0].length);
}

function harness() {
  const state = { topologyNetworkView: "vpn", query: { links: [], connectivity_domains: [] } };
  const functions = ["firstDeclaredString", "normalizeConnectivityDomain", "normalizeSegmentAttachmentModel",
    "isSuppressedConnectivityDomain", "isVpnConnectivityDomain", "topologyConnectivityDomains"];
  const factory = new Function("state", `
    const firstArray = (...values) => values.find(Array.isArray) || [];
    const refIdentity = (value, fallback) => ({ ...fallback, ...value });
    const selectedResultNodes = () => [{ node_id: "pe-a" }];
    const findNodeForRef = (ref, nodes) => nodes.find(node => node.node_id === ref.node_id);
    ${functions.map(functionSource).join("\n")}
    return { normalizeConnectivityDomain, isVpnConnectivityDomain, topologyConnectivityDomains };
  `);
  return { state, ...factory(state) };
}

function domain(overrides = {}) {
  return {
    segment_id: "service:example", presentation_plane: "vpn", connectivity_enabled: false,
    _attachments: [{ attachment_id: "attachment:a", node_id: "pe-a", exists: true }],
    ...overrides,
  };
}

test("VPN normalization and graph filtering preserve absent, true and false display declarations", () => {
  for (const [flag, expected] of [[undefined, 1], [true, 1], [false, 0]]) {
    const h = harness();
    const normalized = h.normalizeConnectivityDomain(domain({ separate_view: flag }), 0, [{ node_id: "pe-a" }]);
    assert.equal(normalized.separate_view, flag);
    h.state.query.connectivity_domains = [normalized];
    assert.equal(h.topologyConnectivityDomains().length, expected);
    h.state.topologyNetworkView = "underlay";
    assert.equal(h.topologyConnectivityDomains().length, 0, "VPN cannot become physical connectivity");
  }
});

test("plug-in display declaration takes precedence over legacy fields", () => {
  const h = harness();
  h.state.query.connectivity_domains = [h.normalizeConnectivityDomain(domain({
    separate_view: true, plugin_semantics: { separate_view: false, presentation_group: "vpn" },
  }), 0, [{ node_id: "pe-a" }])];
  assert.equal(h.topologyConnectivityDomains().length, 0);
});

test("explicit presentation plane is authoritative and legacy VPN flag is fallback only", () => {
  const h = harness();
  assert.equal(h.isVpnConnectivityDomain({ presentation_plane: "underlay", is_vpn: true }), false);
  assert.equal(h.isVpnConnectivityDomain({ presentation_plane: "vpn", is_vpn: false }), true);
  assert.equal(h.isVpnConnectivityDomain({ network_plane: "overlay" }), true);
  assert.equal(h.isVpnConnectivityDomain({ is_vpn: true }), true);
  assert.equal(h.isVpnConnectivityDomain({}), false);
});

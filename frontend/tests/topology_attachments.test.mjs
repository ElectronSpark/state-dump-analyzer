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

const KEYS = ["subnets", "vlans", "interfaces", "subinterfaces", "lags", "external"];
const helpers = new Function("state", "TOPOLOGY_ELEMENT_KEYS", [
  "firstArray", "middleEllipsis", "compactResourceLabel", "normalizeSegmentAttachmentModel",
  "networkAttachmentLabel", "topologyAttachmentComponents", "fullTopologyAttachmentLabel",
].map(functionSource).join("\n") + `
  return { normalizeSegmentAttachmentModel, topologyAttachmentComponents, fullTopologyAttachmentLabel };`
)({ topologyElementVisibility: new Set(KEYS) }, KEYS);

const normalize = (model, fallback = "node/resource") => helpers.normalizeSegmentAttachmentModel(
  { attachment_model: model }, { resource_id: fallback },
);

test("declared nested logical attachments retain logical labels without physical inference", () => {
  const attachment = normalize({ kind: "logical", components: { logical_interface: "tenant-interface" } });
  assert.equal(attachment.interface_kind, "logical");
  assert.equal(attachment.subinterface, "tenant-interface");
  assert.deepEqual(attachment.physical_interfaces, []);
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment), [{
    kind: "interface", label: "tenant-interface", full: "Logical interface: tenant-interface",
  }]);
  assert.equal(helpers.fullTopologyAttachmentLabel(attachment), "Logical interface: tenant-interface");
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment, new Set()), []);
});

test("logical attachment kind alone never turns its resource identity into a physical interface", () => {
  for (const kind of ["logical", "logical_interface", "virtual", "virtual_interface"]) {
    const attachment = normalize({ kind }, "node/opaque-resource");
    assert.equal(helpers.fullTopologyAttachmentLabel(attachment), "Logical interface: node/opaque-resource");
    assert.equal(helpers.topologyAttachmentComponents(attachment)[0].label, "opaque-resource");
  }
});

test("existing flat physical attachment fields and fallback labels remain unchanged", () => {
  const attachment = normalize({ interface_kind: "physical", physical_interfaces: ["Ethernet1/1"] });
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment), [{
    kind: "interface", label: "1", full: "Physical interface: Ethernet1/1",
  }]);
  assert.equal(helpers.fullTopologyAttachmentLabel(normalize({})), "Physical interface: node/resource");
});

test("existing flat LAG and subinterface stacks preserve declared physical components and VLANs", () => {
  const attachment = normalize({
    interface_kind: "subinterface", kind: "logical",
    physical_interface_resource_ids: ["Ethernet1/1", "Ethernet1/2"],
    logical_interface_resource_id: "ae1.310", parent_interface_resource_id: "ae1",
    lag_resource_id: "ae1", vlan_id: 310,
  });
  assert.equal(attachment.interface_kind, "subinterface");
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment).map((item) => item.full), [
    "Physical interface: Ethernet1/1", "Physical interface: Ethernet1/2",
    "Link aggregation: ae1", "Subinterface: ae1.310", "VLAN: 310",
  ]);
});

test("flat logical interface IDs retain subinterface rendering without a declared kind", () => {
  const attachment = normalize({ logical_interface_resource_id: "Ethernet1.310" });
  assert.equal(attachment.interface_kind, "interface");
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment, new Set(["subinterfaces"])), [{
    kind: "subinterface", label: "Subif Ethernet1.310", full: "Subinterface: Ethernet1.310",
  }]);
});

test("flat subinterface IDs on LAG attachments retain both stack components", () => {
  const attachment = normalize({ interface_kind: "lag", lag_resource_id: "ae1", subinterface_resource_id: "ae1.310" });
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment).map((item) => item.full), [
    "Link aggregation: ae1", "Subinterface: ae1.310",
  ]);
});

test("explicit logical and virtual kinds never duplicate their logical interface as a subinterface", () => {
  for (const kind of ["logical", "logical_interface", "virtual", "virtual_interface"]) {
    const attachment = normalize({ kind, logical_interface_resource_id: "tenant-interface" });
    assert.deepEqual(helpers.topologyAttachmentComponents(attachment).map((item) => item.full), [
      "Logical interface: tenant-interface",
    ]);
    assert.deepEqual(helpers.topologyAttachmentComponents(attachment, new Set(["subinterfaces"])), []);
  }
});

test("generic nested physical and aggregate components use the same labels as flat models", () => {
  const nested = normalize({ kind: "lag", components: {
    physical_interfaces: ["Ethernet1/1"], lag_id: "ae1", vlan_id: 310,
  } });
  const flat = normalize({ interface_kind: "lag", physical_interfaces: ["Ethernet1/1"], lag_resource_id: "ae1", vlan_id: 310 });
  assert.deepEqual(helpers.topologyAttachmentComponents(nested), helpers.topologyAttachmentComponents(flat));
});

test("unknown declared kinds are not promoted to physical or logical interfaces", () => {
  const attachment = normalize({ kind: "plugin-specific-kind" });
  assert.deepEqual(helpers.topologyAttachmentComponents(attachment), []);
  assert.equal(helpers.fullTopologyAttachmentLabel(attachment), "node/resource");
});

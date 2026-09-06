import test from "node:test";
import assert from "node:assert/strict";
import { candidateSelection, sessionMemberBody } from "../assets/management_workflows.js";

test("parser choice pins probe and full available execution identity", () => {
  const record = { probe_set_hash: "sha256:probe" }; const candidate = { plugin_id: "p", plugin_version: "1", package_hash: "sha256:package", instance_id: "i", registered_execution_identity: "sha256:execution", ignored: "not authority" };
  assert.deepEqual(candidateSelection(record, candidate), { probe_set_hash: "sha256:probe", plugin_id: "p", plugin_version: "1", package_hash: "sha256:package", instance_id: "i", registered_execution_identity: "sha256:execution" });
  assert.throws(() => candidateSelection({}, candidate));
  assert.throws(() => candidateSelection(record, { ...candidate, registered_execution_identity: "" }));
});
test("legacy candidates omit both unavailable identity fields", () => {
  assert.deepEqual(candidateSelection({ probe_set_hash: "probe" }, { plugin_id: "p", plugin_version: "1", package_hash: "hash", instance_id: "", registered_execution_identity: "" }), { probe_set_hash: "probe", plugin_id: "p", plugin_version: "1", package_hash: "hash" });
});
test("session membership copies exact published fixture/revision without guessing node identities", () => {
  assert.deepEqual(sessionMemberBody({ fixture_id: "fixture", revision_id: "r/1", node_id: "device" }, "comparison", true), { fixture_id: "fixture", revision_id: "r/1", role: "comparison", make_default: true });
  assert.throws(() => sessionMemberBody({ revision_id: "r" }));
});

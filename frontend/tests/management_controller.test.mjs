import test from "node:test";
import assert from "node:assert/strict";
import { createManagementClient, managementPath, managementVersion, managementHealth } from "../assets/management_controller.js";

const response = (body = {}, status = 200) => ({ ok: status < 400, status, statusText: "test", headers: { get: () => "application/json" }, json: async () => body });
test("management identifiers are encoded and required", () => {
  assert.equal(managementPath("projects", "a/b"), "/v1/control-plane/projects/a%2Fb");
  for (const bad of ["", "\r", "a".repeat(513), null]) assert.throws(() => managementPath(bad));
});
test("versions preserve exact decimal coordinates and reject rounded numbers", () => {
  assert.equal(managementVersion("9223372036854775807"), '"9223372036854775807"');
  for (const bad of [-1, 1.2, 2 ** 63, "01", "1e2", "9223372036854775808"]) assert.throws(() => managementVersion(bad));
});
test("health classifies degraded HTTP-200 responses as attention", () => {
  assert.equal(managementHealth({ status: "ok" }), "healthy");
  assert.equal(managementHealth({ status: "degraded" }), "attention");
  assert.equal(managementHealth(null), "unavailable");
});
test("public reads cannot escape aggregate health and scope requests require connection", async () => {
  let calls = 0; const client = createManagementClient({ fetchImpl: async () => { calls++; return response(); } });
  for (const path of ["https://external.invalid/health", "//evil/health", "/health-bad", "/v1/control-plane/projects#secret"]) await assert.rejects(client.request(path, { publicRead: true }));
  await assert.rejects(client.request(managementPath("projects")));
  await assert.rejects(client.request(managementPath("context"), { publicRead: true }));
  await client.request("/health", { publicRead: true }); assert.equal(calls, 1);
});
test("requests bind explicit identity, avoid cache and put no scope in URL", async () => {
  let observed; const client = createManagementClient({ fetchImpl: async (path, options) => { observed = { path, ...options }; return response(); }, uuid: () => "once" });
  client.connect("tenant", "reviewer"); await client.request(managementPath("projects"), { method: "POST", body: { label: "Example" } });
  assert.equal(observed.headers["X-Tenant-ID"], "tenant"); assert.equal(observed.headers["X-Principal-ID"], "reviewer"); assert.equal(observed.headers["Idempotency-Key"], "once"); assert.equal(observed.cache, "no-store"); assert.equal(observed.path, managementPath("projects"));
});
test("stale identity responses are discarded", async () => {
  let resolve; const client = createManagementClient({ fetchImpl: () => new Promise((done) => { resolve = done; }) });
  client.connect("a", "reader"); const pending = client.request(managementPath("projects")); client.connect("b", "reader"); resolve(response({ items: ["old"] })); await assert.rejects(pending, /stale/);
});
test("writes are single-flight, require versions and uncertain writes cannot replay", async () => {
  let calls = 0; const client = createManagementClient({ fetchImpl: async () => { calls++; throw new Error("connection lost"); } });
  client.connect("a", "writer"); await assert.rejects(client.request(managementPath("projects"), { method: "DELETE" }), /version/); assert.equal(calls, 0);
  await assert.rejects(client.request(managementPath("projects"), { method: "POST", body: {} })); assert.equal(client.uncertain, true);
  await assert.rejects(client.request(managementPath("projects"), { method: "POST", body: {} }), /uncertain/); assert.equal(calls, 1);
});
test("concurrent writes and identity changes during write are refused", async () => {
  let resolve; const client = createManagementClient({ fetchImpl: () => new Promise((done) => { resolve = done; }) });
  client.connect("a", "writer"); const write = client.request(managementPath("projects"), { method: "POST", body: {} });
  assert.throws(() => client.disconnect(), /current write/); assert.throws(() => client.connect("b", "writer"), /current write/);
  await assert.rejects(client.request(managementPath("projects"), { method: "POST", body: {} }), /in progress/);
  resolve(response()); await write; assert.equal(client.writing, false);
});
test("raw uploads reuse bounded transport without serializing the file", async () => {
  let observed; const file = new Blob(["test dump"]); const client = createManagementClient({ fetchImpl: async (_path, options) => { observed = options; return response(); } });
  client.connect("a", "writer"); await client.request(managementPath("projects", "p", "workspaces", "w", "imports"), { method: "POST", file });
  assert.equal(observed.body, file); assert.equal(observed.headers["Content-Type"], "application/octet-stream");
  assert.equal(observed.headers["X-Node-Hint"], undefined);
});

test("optional node hints use only the raw import header without changing file or identity", async () => {
  let observed; const file = new Blob(["dump"]);
  const client = createManagementClient({ fetchImpl: async (path, options) => { observed = { path, ...options }; return response(); } });
  client.connect("tenant", "writer");
  await client.request(managementPath("projects", "p", "workspaces", "w", "imports") + "?original_name=sample", { method: "POST", file, nodeHint: "router-1" });
  assert.equal(observed.headers["X-Node-Hint"], "router-1");
  assert.equal(observed.headers["X-Tenant-ID"], "tenant"); assert.equal(observed.body, file);
  assert.doesNotMatch(observed.path, /router-1/);
});

test("invalid or non-upload node hints fail before transport and do not create uncertain writes", async () => {
  let calls = 0; const file = new Blob(["dump"]);
  const client = createManagementClient({ fetchImpl: async () => { calls++; return response(); } }); client.connect("tenant", "writer");
  const path = managementPath("projects", "p", "workspaces", "w", "imports");
  for (const nodeHint of [null, "", "a".repeat(257), "router 1", "router\r\nX-Tenant-ID: other", "路由器", "\u007f"]) await assert.rejects(client.request(path, { method: "POST", file, nodeHint }), /node hint/);
  for (const options of [{ nodeHint: "router-1" }, { method: "POST", nodeHint: "router-1" }, { method: "POST", file, nodeHint: "router-1", mutation: false }]) await assert.rejects(client.request(path, options), /node hint/);
  await assert.rejects(client.request(managementPath("projects"), { method: "POST", file, nodeHint: "router-1" }), /node hint/);
  assert.equal(calls, 0); assert.equal(client.writing, false); assert.equal(client.uncertain, false);
});

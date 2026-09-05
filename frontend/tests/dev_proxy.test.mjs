import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, request } from "node:http";
import test from "node:test";

import { createDevProxy, frontendOrigin } from "../scripts/dev-proxy.mjs";

async function listen(server, t) {
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

function send(port, headers, method = "POST", body = "{\"name\":\"example\"}") {
  return new Promise((resolve, reject) => {
    const outgoing = request({
      host: "127.0.0.1", port, method,
      path: "/v1/control-plane/projects?example=1",
      headers,
      agent: false,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    outgoing.setTimeout(1500, () => outgoing.destroy(new Error("request timeout")));
    outgoing.on("error", reject);
    outgoing.end(body);
  });
}

test("development entry point uses the source-validating proxy", () => {
  const source = readFileSync(new URL("../scripts/dev-server.mjs", import.meta.url), "utf8");
  assert.match(source, /import \{ createDevProxy, frontendOrigin \} from "\.\/dev-proxy\.mjs"/);
  assert.match(source, /origin: frontendOrigin\(options\.host, options\.port\)/);
});

test("wildcard listeners do not establish a trusted browser origin", () => {
  for (const host of ["", "0.0.0.0", "::", "[::]"]) {
    assert.equal(frontendOrigin(host, 4173), null);
  }
  assert.equal(frontendOrigin("127.0.0.1", 4173), "http://127.0.0.1:4173");
  assert.equal(frontendOrigin("::1", 4173), "http://[::1]:4173");
});

test("real HTTP proxy admits only its exact browser source for mutations", { timeout: 10000 }, async (t) => {
  const received = [];
  const backend = createServer((incoming, response) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      const record = {
        method: incoming.method, url: incoming.url, headers: incoming.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      received.push(record);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(record));
    });
  });
  const backendPort = await listen(backend, t);
  let proxy;
  const frontend = createServer((incoming, response) => proxy(incoming, response));
  const frontendPort = await listen(frontend, t);
  const origin = frontendOrigin("127.0.0.1", frontendPort);
  const authority = new URL(origin).host;
  const backendOrigin = frontendOrigin("127.0.0.1", backendPort);
  proxy = createDevProxy({ backend: backendOrigin, origin });
  const baseHeaders = [
    "Host", authority,
    "Content-Type", "application/json",
    "Authorization", "Bearer synthetic-test-token",
    "X-Tenant-ID", "tenant-a",
    "X-Principal-ID", "principal-a",
    "If-Match", "\"3\"",
    "Idempotency-Key", "test-operation",
  ];

  await t.test("accepted browser origin is rewritten and payload/authority preserved", async () => {
    const response = await send(frontendPort, [...baseHeaders, "Origin", origin], "PATCH");
    assert.equal(response.status, 200);
    const record = JSON.parse(response.body);
    assert.equal(record.headers.origin, backendOrigin);
    assert.equal(record.headers.host, new URL(backendOrigin).host);
    assert.equal(record.method, "PATCH");
    assert.equal(record.url, "/v1/control-plane/projects?example=1");
    assert.equal(record.body, "{\"name\":\"example\"}");
    for (let index = 2; index < baseHeaders.length; index += 2) {
      assert.equal(record.headers[baseHeaders[index].toLowerCase()], baseHeaders[index + 1]);
    }
  });

  for (const [name, headers] of [
    ["foreign origin", [...baseHeaders, "Origin", "http://foreign.invalid"]],
    ["opaque null origin", [...baseHeaders, "Origin", "null"]],
    ["duplicate matching origins", [...baseHeaders, "Origin", origin, "origin", origin]],
    ["mismatched host", ["Host", "foreign.invalid", "Origin", origin]],
    ["duplicate matching hosts", [...baseHeaders, "Host", authority, "Origin", origin]],
  ]) {
    await t.test(`rejects ${name} without forwarding`, async () => {
      const count = received.length;
      const response = await send(frontendPort, headers);
      assert.equal(response.status, 403);
      assert.equal(received.length, count);
    });
  }

  await t.test("no-Origin CLI mutations preserve absent Origin and auth headers", async () => {
    const response = await send(frontendPort, baseHeaders);
    assert.equal(response.status, 200);
    const record = JSON.parse(response.body);
    assert.equal(record.headers.origin, undefined);
    assert.equal(record.headers.authorization, "Bearer synthetic-test-token");
    assert.equal(record.headers["x-tenant-id"], "tenant-a");
    assert.equal(record.body, "{\"name\":\"example\"}");
  });

  await t.test("read requests preserve Origin for the backend's existing policy", async () => {
    const response = await send(frontendPort, [...baseHeaders, "Origin", "http://foreign.invalid"], "GET", "");
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(response.body).headers.origin, "http://foreign.invalid");
  });

  await t.test("Host rewriting cannot admit foreign-host reads or no-Origin writes", async () => {
    for (const method of ["GET", "POST"]) {
      const count = received.length;
      const response = await send(frontendPort, ["Host", "foreign.invalid"], method, "");
      assert.equal(response.status, 403);
      assert.equal(received.length, count);
    }
  });

  await t.test("wildcard listener refuses browser mutation but permits no-Origin CLI", async () => {
    proxy = createDevProxy({ backend: backendOrigin, origin: null });
    const count = received.length;
    assert.equal((await send(frontendPort, [...baseHeaders, "Origin", origin])).status, 403);
    assert.equal(received.length, count);
    assert.equal((await send(frontendPort, baseHeaders)).status, 200);
  });
});

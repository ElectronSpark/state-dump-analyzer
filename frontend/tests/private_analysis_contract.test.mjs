import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../pages/private-analysis.html", import.meta.url), "utf8");
const adapter = readFileSync(new URL("../assets/private_analysis.js", import.meta.url), "utf8");
const controller = readFileSync(new URL("../assets/private_analysis_controller.js", import.meta.url), "utf8");
const manifest = JSON.parse(readFileSync(new URL("../frontend-manifest.json", import.meta.url), "utf8"));
const topology = readFileSync(new URL("../pages/topology.html", import.meta.url), "utf8");
const node = readFileSync(new URL("../pages/node.html", import.meta.url), "utf8");
const frontendReadme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const stylesheet = readFileSync(new URL("../assets/private_analysis.css", import.meta.url), "utf8");

test("private-analysis grid layouts respect hidden state and conditional clock fields", () => {
  assert.match(stylesheet, /\.pa-body\s+\[hidden\]\s*\{\s*display:\s*none\s*!important\s*;/);
  for (const id of ["pa-compose", "pa-time-field", "pa-results"]) {
    assert.match(page, new RegExp(`id="${id}"[^>]*hidden`));
  }
});

test("manifest and core navigation expose the private-analysis route without query state", () => {
  assert.equal(manifest.pages["/analysis"], "pages/private-analysis.html");
  assert.match(topology, /href="\/analysis"/);
  assert.match(node, /href="\/analysis"/);
  assert.doesNotMatch(topology, /href="\/analysis\?/);
  assert.doesNotMatch(node, /href="\/analysis\?/);
});

test("static pages do not advertise API documentation that is disabled by default", () => {
  for (const source of [topology, node, page]) {
    assert.doesNotMatch(source, /href=["']\/docs(?:[?"'])/);
  }
  assert.match(frontendReadme, /\/docs.*--expose-api-docs/);
  assert.match(frontendReadme, /API documentation is closed\s+by default/);
});

test("private-analysis identity, unsent query, and opaque run ID stay ephemeral", () => {
  for (const forbidden of [
    "localStorage", "sessionStorage", "indexedDB", "caches.open",
    "serviceWorker", "history.pushState", "history.replaceState",
    "URLSearchParams", "document.title", "console.log",
  ]) {
    assert.doesNotMatch(`${page}\n${adapter}\n${controller}`, new RegExp(forbidden.replace(".", "\\.")));
  }
  assert.match(page, /scope, principal, and an unsent query stay only in this page's memory/i);
  assert.match(page, /submitted run, its query, and its outcome are durable server-side records/i);
  assert.match(page, /Run IDs are not added to the URL or browser storage/i);
});

test("the public form has no caller-controlled execution authority fields", () => {
  for (const forbiddenId of ["provider", "model", "api-key", "endpoint", "command", "transport", "configuration-digest"]) {
    assert.doesNotMatch(page, new RegExp(`id=["'][^"']*${forbiddenId}`, "i"));
    assert.doesNotMatch(page, new RegExp(`name=["'][^"']*${forbiddenId}`, "i"));
  }
  assert.match(controller, /revision_ids/);
  assert.match(controller, /runner_id/);
  assert.match(controller, /runner_version/);
  assert.doesNotMatch(controller, /body\.transport|body\.configuration_digest/);
  assert.match(page, /id="pa-submit"[^>]*disabled/);
  assert.match(adapter, /privateAnalysisSubmissionAvailable/);
});

test("hostile report text crosses a textContent-only rendering boundary", () => {
  assert.match(adapter, /\.textContent\s*=/);
  assert.doesNotMatch(adapter, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  assert.match(adapter, /evidence_reference_digest/);
  assert.match(adapter, /not applied/);
  assert.match(adapter, /unsupported_hypothesis/);
});

test("controller owns one-shot mutation and lifecycle safeguards", () => {
  assert.match(controller, /"Idempotency-Key"/);
  assert.match(controller, /"If-Match"/);
  assert.match(controller, /executeIssuedForRun/);
  assert.match(controller, /cancelAttempt/);
  assert.match(controller, /cancelAttempt\.generation === expected/);
  assert.match(controller, /cancelAttempt\.runId === runId/);
  assert.match(adapter, /cancelLocked/);
  assert.match(controller, /pollPromise/);
  assert.match(controller, /cleanup_pending/);
  assert.match(controller, /BigInt/);
  assert.match(controller, /AbortController/);
  assert.match(controller, /StalePrivateAnalysisResponseError/);
});

test("proposal review stays explicit, human-authored, and recoverable", () => {
  assert.match(page, /separately authored review target/i);
  assert.match(page, /Review is final and durable/i);
  assert.match(adapter, /I reviewed the cited evidence/i);
  assert.match(adapter, /model proposal payload is never copied/i);
  assert.match(controller, /decisionAttempts/);
  assert.match(controller, /recoveryAttempts/);
  assert.match(controller, /proposal_digest/);
  assert.match(controller, /result_digest/);
  assert.match(controller, /privateAnalysisDecisionBody/);
  assert.doesNotMatch(controller, /target\s*:\s*matches\[0\]\.payload/);
});

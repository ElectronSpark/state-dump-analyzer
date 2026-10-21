import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../pages/private-analysis.html", import.meta.url), "utf8");
const descendants = (node) => node.children.flatMap((child) => [child, ...descendants(child)]);

class Element {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.dataset = {};
    this.value = this.defaultValue = "";
    this.disabled = this.required = this.checked = this.hidden = false;
  }
  append(...nodes) {
    this.children.push(...nodes);
    if (this.tagName === "SELECT" && this.children.length === nodes.length) {
      this.value = nodes[0]?.value || "";
    }
  }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  get childElementCount() { return this.children.length; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map((child) => child.textContent).join(""); }
  setAttribute(name, value) { this[name] = String(value); }
  removeAttribute(name) { delete this[name]; }
  focus() {}
  addEventListener(name, callback) {
    this.listeners.set(name, [...(this.listeners.get(name) || []), callback]);
  }
  async emit(name) {
    for (const callback of this.listeners.get(name) || []) {
      await callback({ preventDefault() {} });
    }
  }
  querySelectorAll(selector) {
    return descendants(this).filter((node) => node.tagName === "INPUT"
      && node.type === "checkbox" && (!selector.endsWith(":checked") || node.checked));
  }
  querySelector() { return descendants(this).find((node) => node.tagName === "INPUT") || null; }
  reset() {
    // Native reset restores values, but leaves dynamic required constraints intact.
    for (const node of descendants(this)) {
      node.value = node.defaultValue;
      node.checked = false;
    }
  }
  async requestSubmit() {
    // Hidden ancestors do not exempt a required input from constraint validation.
    if (descendants(this).some((node) => !node.disabled && node.required
      && (node.type === "checkbox" ? !node.checked : !node.value))) return false;
    await this.emit("submit");
    return true;
  }
}

function jsonResponse(payload, { status = 200, version } = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...(version ? { ETag: `"${version}"` } : {}) },
  });
}

async function application(t) {
  const elements = new Map();
  for (const [, tag, attributes, id] of page.matchAll(/<([a-z0-9]+)([^>]*\sid="([^"]+)"[^>]*)>/g)) {
    const node = new Element(tag);
    node.hidden = /\shidden(?:\s|$)/.test(attributes);
    node.required = /\srequired(?:\s|$)/.test(attributes);
    node.disabled = /\sdisabled(?:\s|$)/.test(attributes);
    elements.set(id, node);
  }
  for (const [, id, contents] of page.matchAll(/<form\s+id="([^"]+)"[^>]*>([\s\S]*?)<\/form>/g)) {
    elements.get(id).append(...[...contents.matchAll(/\sid="([^"]+)"/g)]
      .map((match) => elements.get(match[1])));
  }
  const byId = (id) => elements.get(id);
  const clockDefault = /<select id="pa-clock">\s*<option value="([^"]+)"/.exec(page)[1];
  byId("pa-clock").value = byId("pa-clock").defaultValue = clockDefault;
  const calls = [];
  const run = (version = "2") => ({
    run_id: "run-a", version, state: "completed", terminal: true,
    cleanup_pending: false, revision_ids: ["revision-a"],
  });
  const report = { run: run(), outcome: { kind: "error", error: { stage: "runner", code: "cancelled" } } };
  const fetch = async (path, options) => {
    calls.push({ path, ...options });
    if (path.endsWith("/private-analysis-capabilities")) {
      return jsonResponse({ enabled: true, capabilities: [{ id: "route_trace_analysis", label: "Route trace" }] });
    }
    if (path.endsWith("/private-analysis-runners")) {
      return jsonResponse({ items: [{ runner_id: "local", runner_version: "1", transport: "in_process" }] });
    }
    if (path.includes("/revisions?")) {
      return jsonResponse({ items: [{ revision_id: "revision-a", node_id: "router-a", execution_plan: {} }], next_offset: null });
    }
    if (path.endsWith("/missing")) return jsonResponse({ detail: "Run does not exist." }, { status: 404 });
    if (path.endsWith("/private-analysis-runs")) return jsonResponse(run("1"), { version: "1" });
    if (path.endsWith("/run-a/execute") || path.endsWith("/run-a")) return jsonResponse(run(), { version: "2" });
    if (path.endsWith("/run-a/report")) return jsonResponse(report, { version: "2" });
    throw new Error(`Unexpected request ${path}`);
  };
  const pageWindow = new Element("window");
  const replacements = {
    document: { getElementById: byId, createElement: (tag) => new Element(tag) },
    window: pageWindow, fetch, crypto: webcrypto,
  };
  const originals = Object.fromEntries(Object.keys(replacements)
    .map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  for (const [key, value] of Object.entries(replacements)) {
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  t.after(async () => {
    await pageWindow.emit("pagehide");
    for (const [key, descriptor] of Object.entries(originals)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  });
  await import(`../assets/private_analysis.js?regression=${webcrypto.randomUUID()}`);
  const connect = async () => {
    for (const field of ["tenant", "project", "workspace", "principal"]) byId(`pa-${field}`).value = `${field}-a`;
    assert.equal(await byId("pa-scope-form").requestSubmit(), true);
  };
  const selectRevision = () => { byId("pa-revisions").querySelector("input").checked = true; };
  const reload = async (runId) => {
    byId("pa-run-id").value = runId;
    assert.equal(await byId("pa-reload-form").requestSubmit(), true);
  };
  return { byId, calls, connect, selectRevision, reload };
}

test("reconnect and clear synchronize conditional time validity before the actual submit handler", async (t) => {
  for (const [transition, mode] of [["reconnect", "absolute_unix_ns"], ["clear", "revision_end_relative_ns"]]) {
    await t.test(transition, async (t) => {
      const app = await application(t);
      const { byId } = app;
      assert.equal(byId("pa-time").required, false);
      await app.connect();
      app.selectRevision();
      byId("pa-query").value = "Review selected evidence.";
      byId("pa-clock").value = mode;
      await byId("pa-clock").emit("change");
      assert.equal(byId("pa-time-field").hidden, false);
      assert.equal(byId("pa-time").required, true);
      assert.equal(await byId("pa-run-form").requestSubmit(), false);
      assert.equal(app.calls.filter((call) => call.method === "POST").length, 0);
      if (transition === "clear") {
        await byId("pa-disconnect").emit("click");
        assert.equal(byId("pa-time-field").hidden, true);
        assert.equal(byId("pa-time").required, false);
      }
      await app.connect();
      assert.equal(byId("pa-clock").value, "latest_per_revision");
      assert.equal(byId("pa-time-field").hidden, true);
      assert.equal(byId("pa-time").required, false);
      app.selectRevision();
      byId("pa-query").value = "Review after reconnect.";
      assert.equal(await byId("pa-run-form").requestSubmit(), true);
      const mutations = app.calls.filter((call) => call.method === "POST");
      assert.equal(mutations.length, 2);
      assert.deepEqual(JSON.parse(mutations[0].body).clock, { mode: "latest_per_revision" });
      assert.equal(byId("pa-results").hidden, false);
    });
  }
});

test("failed lookup clears old results and permits lookup retry or creation with the retained form", async (t) => {
  const app = await application(t);
  const { byId } = app;
  await app.connect();
  app.selectRevision();
  byId("pa-query").value = "Retain this unsent question.";
  await app.reload("run-a");
  assert.equal(byId("pa-results").hidden, false);
  await app.reload("missing");
  assert.equal(byId("pa-status").dataset.error, "true");
  assert.match(byId("pa-status").textContent, /Run does not exist/);
  assert.equal(byId("pa-results").hidden, true);
  assert.equal(byId("pa-run-summary").hidden, true);
  assert.equal(byId("pa-submit").disabled, false);
  assert.equal(byId("pa-submit").title, undefined);
  assert.equal(byId("pa-revisions").querySelector("input").checked, true);
  assert.equal(byId("pa-query").value, "Retain this unsent question.");
  assert.equal(app.calls.filter((call) => call.method === "POST").length, 0);
  await app.reload("run-a");
  assert.equal(byId("pa-status").dataset.error, "false");
  assert.equal(byId("pa-results").hidden, false);
  await app.reload("missing");
  assert.equal(await byId("pa-run-form").requestSubmit(), true);
  assert.equal(app.calls.filter((call) => call.method === "POST").length, 2);
  assert.equal(byId("pa-status").dataset.error, "false");
  assert.equal(byId("pa-results").hidden, false);
});

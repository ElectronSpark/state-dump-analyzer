import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

class Element {
  constructor(tag = "div", text = "") {
    this.tagName = tag.toUpperCase(); this.text = text; this.children = []; this.listeners = new Map();
    this.attributes = new Map(); this.dataset = {}; this.style = {}; this.value = ""; this.disabled = false;
  }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); if (this.tagName === "SELECT" && this.children.length === 1) this.value = node.value; } }
  prepend(...nodes) { for (const node of nodes) node.parent = this; this.children.unshift(...nodes); }
  replaceChildren(...nodes) { for (const node of this.children) node.parent = null; this.children = []; this.append(...nodes); }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter((node) => node !== this); this.parent = null; } }
  add(node) { this.append(node); }
  get isConnected() { return this.connected === true || this.parent?.isConnected === true; }
  get textContent() { return String(this.text) + this.children.map((node) => node.textContent).join(" "); }
  set textContent(value) { this.text = String(value); this.replaceChildren(); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  addEventListener(type, callback) { const callbacks = this.listeners.get(type) || []; callbacks.push(callback); this.listeners.set(type, callbacks); }
  emit(type, properties = {}) {
    const event = { target: this, currentTarget: this, preventDefault() {}, ...properties };
    for (const callback of this.listeners.get(type) || []) callback(event);
  }
  closest(selector) { if (selector === "[data-view]" && this.dataset.view) return this; return this.parent?.closest(selector) ?? null; }
}

const descendants = (node) => [node, ...node.children.flatMap(descendants)];
const settle = async () => { for (let index = 0; index < 4; index++) await new Promise(setImmediate); };
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const jsonResponse = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const analysisResponse = (query, digest) => {
  const member = { member_id: "member", node_id: "node", revision_id: "revision", fixture_id: "fixture" };
  return jsonResponse({ selection: { revision_vector_digest: digest }, revision_vector: [member], selected_member: member, section: query.section, time_ns: query.time_ns || "200", timeline: { start_ns: "100", end_ns: "200" }, count: 0, total_count: 0, items: [], offset: 0, next_offset: null, capabilities: { route: { reason: "Not supported" }, topology: { reason: "Not supported" } } });
};

async function application(t, intercept = () => undefined) {
  const elements = new Map();
  for (const id of ["management-content", "management-message", "management-breadcrumb", "management-project", "management-workspace", "management-identity", "management-connect", "management-disconnect", "management-refresh", "management-tabs"]) {
    const node = new Element(id.endsWith("connect") ? "form" : "div"); node.connected = true; elements.set(id, node);
  }
  const tabs = ["projects", "catalog", "imports", "sessions", "administration", "server"].map((view) => { const tab = new Element("button", view); tab.dataset.view = view; return tab; });
  elements.get("management-tabs").append(...tabs);
  const document = { hidden: false, getElementById: (id) => elements.get(id), createElement: (tag) => new Element(tag), querySelectorAll: (selector) => selector === "[data-view]" ? tabs : [], addEventListener() {} };
  const pageWindow = new Element("window");
  class Option extends Element { constructor(label, value) { super("option", label); this.value = value; } }
  class FormData {
    constructor(form) { this.values = form.formValues || Object.fromEntries(descendants(form).filter((node) => node.name).map((node) => [node.name, node.value])); }
    get(key) { return this.values[key] ?? null; }
    *[Symbol.iterator]() { yield* Object.entries(this.values); }
  }
  const calls = [];
  const fetch = async (path, options) => {
    calls.push({ path, ...options });
    const overridden = intercept(path, options, calls);
    if (overridden !== undefined) return await overridden;
    const url = new URL(path, "http://test.invalid");
    const endpoint = url.pathname;
    if (endpoint.endsWith("/context")) return jsonResponse({ enabled: true, tenant_id: "tenant", principal_id: "principal", can_admin: true, can_write: true, can_instance_operator: false, identity_mode: "deployment" });
    if (endpoint === "/v1/control-plane/projects") return jsonResponse({ items: [{ project_id: "project", label: "Project" }], next_offset: null });
    if (endpoint.endsWith("/workspaces")) return jsonResponse({ items: ["workspace-a", "workspace-b"].map((workspace_id) => ({ workspace_id, label: workspace_id })), next_offset: null });
    const workspace = endpoint.includes("/workspace-b/") ? "workspace-b" : "workspace-a";
    const member = { member_id: "member", node_id: "node", fixture_id: "fixture", revision_id: `revision-${workspace}` };
    const session = { session_id: "shared-session", label: `Session ${workspace}`, version: 1, default_member_id: "member", members: [member] };
    const snapshot = { snapshot_id: "snapshot", session_id: "shared-session", session_version: 1, members: [member] };
    const importRecord = { import_id: "shared-import", original_name: `Dump ${workspace}`, state: "completed", terminal: true, byte_count: 12, attempt_count: 1, max_attempts: 1, revision_id: member.revision_id, error: null };
    if (endpoint.endsWith("/sessions")) return jsonResponse({ items: [session], next_offset: null });
    if (endpoint.endsWith("/sessions/shared-session")) return jsonResponse(session);
    if (endpoint.endsWith("/snapshots")) return jsonResponse({ items: [snapshot], next_offset: null });
    if (endpoint.endsWith("/snapshots/snapshot")) return jsonResponse(snapshot);
    if (endpoint.endsWith("/revisions")) return jsonResponse({ items: [member], next_offset: null });
    if (endpoint.endsWith("/fixtures")) return jsonResponse({ items: [], next_offset: null });
    if (endpoint.endsWith("/imports")) return jsonResponse({ items: [importRecord], next_cursor: null });
    if (endpoint.endsWith("/imports/shared-import")) return jsonResponse(importRecord);
    if (endpoint.endsWith("/candidates") || endpoint.endsWith("/events")) return jsonResponse({ items: [] });
    if (endpoint.endsWith("/private-analysis-policy")) return jsonResponse({ version: 0, explicit: false, policy: { policy_version: "router_dump_analyzer.workspace_disclosure_policy.v1", mode: "disabled", transports: [] } });
    throw new Error(`Unexpected test request: ${options.method} ${endpoint}`);
  };
  const replacements = { document, window: pageWindow, Option, FormData, fetch, crypto: webcrypto };
  const originals = Object.fromEntries(Object.keys(replacements).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  for (const [key, value] of Object.entries(replacements)) Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  t.after(() => {
    pageWindow.emit("pagehide");
    for (const [key, descriptor] of Object.entries(originals)) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; }
  });
  await import(`../assets/management.js?regression=${webcrypto.randomUUID()}`);
  await settle();
  const content = elements.get("management-content");
  const findButton = (label, root = content) => descendants(root).find((node) => node.tagName === "BUTTON" && node.textContent === label);
  const click = async (node) => { assert.ok(node, "button must exist"); assert.equal(node.disabled, false, "button must be available"); node.emit("click"); await settle(); };
  const tab = async (name) => { elements.get("management-tabs").emit("click", { target: tabs.find((node) => node.dataset.view === name) }); await settle(); };
  const workspaceCard = (name) => descendants(content).find((node) => node.className === "management-row" && node.textContent.includes(name));
  const connect = async () => {
    const form = elements.get("management-connect"); form.formValues = { tenant: "tenant", principal: "principal" }; form.emit("submit"); await settle();
    const project = elements.get("management-project"); project.value = "project"; project.emit("change"); await settle();
    await click(findButton("Select workspace", workspaceCard("workspace-a")));
  };
  return { elements, content, calls, findButton, click, tab, workspaceCard, connect };
}

test("actual card and dropdown workspace changes clear prior import/session selection", async (t) => {
  const app = await application(t); await app.connect();
  await app.tab("sessions"); await app.click(app.findButton("Manage session"));
  assert.match(app.content.textContent, /Session members/);
  await app.tab("imports"); await app.click(app.findButton("Inspect import"));
  assert.match(app.content.textContent, /Import details/);
  await app.tab("projects");
  await app.click(app.findButton("Select workspace", app.workspaceCard("workspace-b")));
  assert.equal(app.elements.get("management-workspace").value, "workspace-b");
  assert.match(app.elements.get("management-breadcrumb").textContent, /workspace-b/);
  await app.tab("sessions");
  assert.match(app.content.textContent, /Create session/); assert.doesNotMatch(app.content.textContent, /Session members/);
  await app.click(app.findButton("Manage session"));
  const dropdown = app.elements.get("management-workspace"); dropdown.value = "workspace-a"; dropdown.emit("change"); await settle();
  assert.match(app.content.textContent, /Create session/); assert.doesNotMatch(app.content.textContent, /Session members/);
  await app.tab("imports");
  assert.match(app.content.textContent, /Upload a state dump/); assert.doesNotMatch(app.content.textContent, /Import details/);
});

test("card and dropdown refuse workspace changes while a real client mutation is pending", async (t) => {
  const write = deferred();
  const app = await application(t, (path, options) => options.method === "POST" && path.endsWith("/sessions/shared-session/snapshots") ? write.promise : undefined);
  await app.connect(); await app.tab("sessions"); await app.click(app.findButton("Manage session"));
  await app.click(app.findButton("Create immutable snapshot"));
  await app.tab("projects");
  await app.click(app.findButton("Select workspace", app.workspaceCard("workspace-b")));
  assert.match(app.elements.get("management-message").textContent, /Wait for the current write/);
  assert.equal(app.elements.get("management-workspace").value, "workspace-a");
  const dropdown = app.elements.get("management-workspace"); dropdown.value = "workspace-b"; dropdown.emit("change"); await settle();
  assert.equal(dropdown.value, "workspace-a");
  assert.match(app.elements.get("management-breadcrumb").textContent, /workspace-a/);
  write.resolve(jsonResponse({ snapshot_id: "saved" })); await settle();
  await app.click(app.findButton("Select workspace", app.workspaceCard("workspace-b")));
  assert.match(app.elements.get("management-breadcrumb").textContent, /workspace-b/);
});

test("late findings and snapshot reads cannot append into a newly selected view", async (t) => {
  const findings = deferred(); const snapshot = deferred();
  const app = await application(t, (path) => path.includes("/consistency-findings?") ? findings.promise : path.endsWith("/snapshots/snapshot") ? snapshot.promise : undefined);
  await app.connect(); await app.click(app.findButton("Consistency findings"));
  await app.tab("imports"); findings.resolve(jsonResponse({ marker: "STALE-FINDINGS" })); await settle();
  assert.doesNotMatch(app.content.textContent, /STALE-FINDINGS|Consistency findings/);
  await app.tab("sessions"); await app.click(app.findButton("Snapshot details"));
  await app.tab("catalog"); snapshot.resolve(jsonResponse({ marker: "STALE-SNAPSHOT" })); await settle();
  assert.doesNotMatch(app.content.textContent, /STALE-SNAPSHOT|Immutable snapshot/);
});

test("workspace selection invalidates a pending read before the new scope renders", async (t) => {
  const findings = deferred();
  const app = await application(t, (path) => path.includes("/consistency-findings?") ? findings.promise : undefined);
  await app.connect(); await app.click(app.findButton("Consistency findings"));
  await app.tab("projects"); await app.click(app.findButton("Select workspace", app.workspaceCard("workspace-b")));
  findings.resolve(jsonResponse({ marker: "OLD-WORKSPACE-FINDINGS" })); await settle();
  assert.doesNotMatch(app.content.textContent, /OLD-WORKSPACE-FINDINGS/);
  assert.match(app.elements.get("management-message").textContent, /stale response was discarded/);
});

test("project selection removes prior controls immediately while the workspace list loads", async (t) => {
  const workspaces = deferred();
  const app = await application(t, (path) => path.includes("/projects/other-project/workspaces?") ? workspaces.promise : undefined);
  await app.connect();
  const project = app.elements.get("management-project"); project.value = "other-project"; project.emit("change"); await settle();
  assert.match(app.content.textContent, /Loading selected project/);
  assert.doesNotMatch(app.content.textContent, /Published revisions|Consistency findings/);
  workspaces.resolve(jsonResponse({ items: [], next_offset: null })); await settle();
});

test("a cancel preflight cannot issue a mutation after its workspace changes", async (t) => {
  const preflight = deferred(); let reads = 0;
  const importRecord = { import_id: "shared-import", original_name: "Awaiting parser", state: "awaiting_selection", terminal: false, byte_count: 12, attempt_count: 1, max_attempts: 1, revision_id: null, version: 1 };
  const app = await application(t, (path, options) => {
    if (path.endsWith("/imports/shared-import") && options.method === "GET") return ++reads === 1 ? jsonResponse(importRecord) : preflight.promise;
    return undefined;
  });
  await app.connect(); await app.tab("imports"); await app.click(app.findButton("Inspect import"));
  await app.click(app.findButton("Cancel import"));
  const dropdown = app.elements.get("management-workspace"); dropdown.value = "workspace-b"; dropdown.emit("change"); await settle();
  preflight.resolve(jsonResponse(importRecord)); await settle();
  assert.equal(app.calls.some((call) => call.path.endsWith("/cancel")), false);
  assert.match(app.elements.get("management-breadcrumb").textContent, /workspace-b/);
  assert.match(app.elements.get("management-message").textContent, /stale response was discarded/);
});

test("actual shared buttons preserve dynamically enabled audit continuation and block double clicks", async (t) => {
  const page = deferred(); let auditCalls = 0;
  const app = await application(t, (path) => {
    if (!path.includes("/retention/audit?")) return undefined;
    auditCalls++;
    const after = Number(new URL(path, "http://test.invalid").searchParams.get("catalog_after_sequence"));
    if (after === 100) return page.promise;
    return jsonResponse({ catalog: [], review: [], ingestion: [], catalog_next_after_sequence: after === 0 ? 100 : after === 200 ? 300 : null, review_next_after_sequence: null });
  });
  await app.connect(); await app.tab("administration"); await app.click(app.findButton("Load / refresh retention audit"));
  const next = app.findButton("Next catalog audit page");
  await app.click(next); assert.equal(next.getAttribute("aria-busy"), "true");
  next.emit("click"); await settle(); assert.equal(auditCalls, 2);
  page.resolve(jsonResponse({ catalog: [], review: [], ingestion: [], catalog_next_after_sequence: 200, review_next_after_sequence: null })); await settle();
  assert.equal(next.getAttribute("aria-busy"), null); assert.equal(next.disabled, false);
  await app.click(next); assert.equal(next.disabled, false);
  await app.click(next); assert.equal(next.disabled, true);
  assert.equal(auditCalls, 4);
});

test("a project change rejected during a write restores the displayed project", async (t) => {
  const write = deferred();
  const app = await application(t, (path, options) => options.method === "POST" && path.endsWith("/sessions/shared-session/snapshots") ? write.promise : undefined);
  await app.connect(); await app.tab("sessions"); await app.click(app.findButton("Manage session"));
  await app.click(app.findButton("Create immutable snapshot"));
  const project = app.elements.get("management-project"); project.value = "different-project"; project.emit("change"); await settle();
  const displayed = project.value;
  write.resolve(jsonResponse({ snapshot_id: "saved" })); await settle();
  assert.equal(displayed, "project");
  assert.match(app.elements.get("management-breadcrumb").textContent, /^project \/ workspace-a$/);
});

test("failed health reads cannot add an abandoned server view to another tab", async (t) => {
  const health = deferred();
  const app = await application(t, (path) => path === "/health" ? health.promise : path === "/v1/control-plane/health" ? jsonResponse({ detail: "Unavailable" }, 503) : undefined);
  await app.connect(); await app.tab("server"); await app.tab("imports");
  health.resolve(jsonResponse({ detail: "Unavailable" }, 503)); await settle();
  assert.match(app.content.textContent, /Upload a state dump/);
  assert.doesNotMatch(app.content.textContent, /Instance operational diagnostics|Status reflects response contents/);
});

test("digest conflict recovery remains visible and unpins only on explicit membership reload", async (t) => {
  const queries = []; const firstDigest = "sha256:" + "a".repeat(64); const nextDigest = "sha256:" + "b".repeat(64);
  const app = await application(t, (path, options) => {
    if (!path.endsWith("/analysis/query")) return undefined;
    const query = JSON.parse(options.body); queries.push(query);
    if (query.expected_revision_vector_digest === firstDigest) return jsonResponse({ detail: "analysis revision vector changed; refresh the selection" }, 409);
    return analysisResponse(query, queries.length === 1 ? firstDigest : nextDigest);
  });
  await app.connect(); await app.tab("sessions"); await app.click(app.findButton("Inspect member analysis"));
  await app.click(app.findButton("Resources"));
  assert.match(app.content.textContent, /No replacement was accepted automatically/);
  assert.ok(app.findButton("Reload current session membership"));
  assert.equal(queries.length, 2); assert.equal(queries[1].expected_revision_vector_digest, firstDigest);
  await app.click(app.findButton("Reset analysis filters"));
  assert.equal(queries.at(-1).expected_revision_vector_digest, firstDigest);
  const recovery = app.findButton("Reload current session membership"); await app.click(recovery);
  assert.equal(queries.at(-1).expected_revision_vector_digest, undefined);
  assert.deepEqual(queries.at(-1).selector, { session_id: "shared-session" });
  assert.match(app.content.textContent, new RegExp(nextDigest));
  await app.click(app.findButton("Resources"));
  assert.equal(queries.at(-1).expected_revision_vector_digest, nextDigest);
  const count = queries.length;
  recovery.emit("click"); await settle();
  assert.equal(queries.length, count, "detached recovery controls cannot mutate the new analysis view");
});

test("invalid analysis moments retain the visible selection without sending an invalid query", async (t) => {
  let calls = 0;
  const app = await application(t, (path, options) => {
    if (!path.endsWith("/analysis/query")) return undefined;
    calls++; return analysisResponse(JSON.parse(options.body), "sha256:" + "a".repeat(64));
  });
  await app.connect(); await app.click(app.findButton("Inspect analysis"));
  const moment = descendants(app.content).find((node) => node.name === "time");
  moment.value = "-0"; moment.parent.parent.emit("submit"); await settle();
  assert.equal(calls, 1); assert.match(app.elements.get("management-message").textContent, /canonical signed 64-bit/);
  assert.match(app.content.textContent, /Reconstructed moment/);
  assert.equal(app.findButton("Reload current session membership"), undefined);
});

test("actual relationship analysis labels unknown presence separately from confirmed edges", async (t) => {
  const app = await application(t, (path, options) => {
    if (!path.endsWith("/analysis/query")) return undefined;
    const query = JSON.parse(options.body);
    return analysisResponse(query, "sha256:" + "a".repeat(64)).json().then((result) => jsonResponse({
      ...result,
      count: 2, total_count: 2,
      items: [
        { relation_type: "unknown-peer", present: null, quality: "exact" },
        { relation_type: "confirmed-peer", present: true, quality: "exact" },
      ],
    }));
  });
  await app.connect(); await app.click(app.findButton("Inspect analysis"));
  await app.click(app.findButton("Relationships"));
  const summaries = descendants(app.content).filter((node) => node.tagName === "SUMMARY").map((node) => node.textContent);
  assert.ok(summaries.includes("unknown-peer · presence unknown"));
  assert.ok(summaries.includes("confirmed-peer · confirmed present"));
  assert.equal(summaries.includes("unknown-peer · exact"), false);
});

test("the upload form forwards its optional node hint through the actual client header", async (t) => {
  let upload;
  const app = await application(t, (path, options) => {
    if (options.method === "POST" && path.includes("/imports?")) { upload = { path, ...options }; return jsonResponse({ import_id: "shared-import" }); }
    return undefined;
  });
  await app.connect(); await app.tab("imports");
  const file = Object.assign(new Blob(["dump"]), { name: "sample.dump" });
  const fileInput = descendants(app.content).find((node) => node.type === "file"); fileInput.files = [file];
  const label = descendants(app.content).find((node) => node.tagName === "LABEL" && node.text === "Node identity hint (optional)"); label.children[0].value = "router-7";
  fileInput.parent.parent.emit("submit"); await settle();
  assert.ok(upload); assert.equal(upload.headers["X-Node-Hint"], "router-7"); assert.equal(upload.body, file);
  assert.doesNotMatch(upload.path, /router-7/); assert.match(app.content.textContent, /Import details/);
});

test("actual import cancellation refreshes the version and sends one scoped conditional mutation", async (t) => {
  let reads = 0; let cancelled = false; let cancellation;
  const app = await application(t, (path, options) => {
    if (path.endsWith("/imports/shared-import") && options.method === "GET") {
      reads++;
      return jsonResponse({ import_id: "shared-import", original_name: "Pending dump", byte_count: 12, attempt_count: 1, max_attempts: 2, revision_id: null, state: cancelled ? "cancelled" : "awaiting_selection", terminal: cancelled, version: reads === 1 ? 3 : cancelled ? 10 : 9 });
    }
    if (path.endsWith("/imports/shared-import/cancel")) { cancellation = { path, ...options }; cancelled = true; return jsonResponse({ state: "cancelled", version: 10 }); }
    return undefined;
  });
  await app.connect(); await app.tab("imports"); await app.click(app.findButton("Inspect import"));
  await app.click(app.findButton("Cancel import"));
  assert.equal(cancellation.path, "/v1/control-plane/projects/project/workspaces/workspace-a/imports/shared-import/cancel");
  assert.equal(cancellation.method, "POST"); assert.equal(cancellation.headers["If-Match"], '"9"');
  assert.equal(cancellation.headers["X-Tenant-ID"], "tenant"); assert.equal(cancellation.headers["X-Principal-ID"], "principal");
  assert.equal(cancellation.body, undefined); assert.equal(app.calls.filter((call) => call.path.endsWith("/cancel")).length, 1);
  assert.equal(app.findButton("Cancel import"), undefined); assert.match(app.content.textContent, /cancelled/);
});

test("a retryable import resumes only after the user clicks and without a stale version precondition", async (t) => {
  let resumed = false; let mutation;
  const app = await application(t, (path, options) => {
    if (path.endsWith("/imports/shared-import") && options.method === "GET") return jsonResponse({ import_id: "shared-import", original_name: "Retryable dump", byte_count: 12, attempt_count: resumed ? 2 : 1, max_attempts: 2, revision_id: null, state: resumed ? "completed" : "failed", terminal: true, version: 4, error: resumed ? null : { code: "retryable", message: "Worker unavailable", retryable: true } });
    if (path.endsWith("/imports/shared-import/resume")) { resumed = true; mutation = { path, ...options }; return jsonResponse({ state: "queued" }); }
    return undefined;
  });
  await app.connect(); await app.tab("imports"); await app.click(app.findButton("Inspect import"));
  assert.equal(resumed, false); await app.click(app.findButton("Resume import"));
  assert.equal(mutation.path, "/v1/control-plane/projects/project/workspaces/workspace-a/imports/shared-import/resume");
  assert.equal(mutation.method, "POST"); assert.equal(mutation.headers["If-Match"], undefined); assert.equal(mutation.body, undefined);
  assert.equal(app.calls.filter((call) => call.path.endsWith("/resume")).length, 1);
  assert.equal(app.findButton("Resume import"), undefined); assert.match(app.content.textContent, /completed/);
});

test("session member save and remove use exact revision binding and the newly refreshed version", async (t) => {
  let session = { session_id: "shared-session", label: "Editable session", version: 4, default_member_id: null, members: [] };
  let saved; let removed;
  const app = await application(t, (path, options) => {
    if (path.endsWith("/sessions/shared-session") && options.method === "GET") return jsonResponse(session);
    if (path.endsWith("/sessions/shared-session/members/member-added") && options.method === "PUT") {
      saved = { path, ...options }; const body = JSON.parse(options.body);
      session = { ...session, version: 5, default_member_id: "member-added", members: [{ member_id: "member-added", node_id: "node", ...body }] };
      return jsonResponse(session);
    }
    if (path.endsWith("/sessions/shared-session/members/member-added") && options.method === "DELETE") {
      removed = { path, ...options }; session = { ...session, version: 6, default_member_id: null, members: [] }; return jsonResponse(session);
    }
    return undefined;
  });
  await app.connect(); await app.tab("sessions"); await app.click(app.findButton("Manage session"));
  const label = (name) => descendants(app.content).find((node) => node.tagName === "LABEL" && node.text === name);
  label("Member ID").children[0].value = "member-added";
  label("Published revision").children[0].value = "revision-workspace-a";
  label("Default member").children[0].checked = true;
  app.findButton("Save member").parent.emit("submit"); await settle();
  assert.equal(saved.headers["If-Match"], '"4"');
  assert.deepEqual(JSON.parse(saved.body), { fixture_id: "fixture", revision_id: "revision-workspace-a", role: "member", make_default: true });
  assert.match(app.content.textContent, /member-added/); assert.match(app.content.textContent, /version 5/);
  await app.click(app.findButton("Remove member"));
  assert.equal(removed.method, "DELETE"); assert.equal(removed.headers["If-Match"], '"5"'); assert.equal(removed.body, undefined);
  assert.equal(app.findButton("Remove member"), undefined); assert.match(app.content.textContent, /No revisions selected yet/);
  assert.match(app.content.textContent, /version 6/);
});

test("protected session deletion requires exact confirmation and preserves the selected session on conflict", async (t) => {
  const deletes = [];
  const app = await application(t, (path, options) => {
    if (path.endsWith("/sessions/shared-session") && options.method === "DELETE") { deletes.push({ path, ...options }); return jsonResponse({ detail: "Session is protected by immutable snapshots" }, 409); }
    return undefined;
  });
  await app.connect(); await app.tab("sessions"); await app.click(app.findButton("Manage session"));
  const form = app.findButton("Delete session").parent;
  const confirmation = descendants(form).find((node) => node.name === "confirm");
  confirmation.value = "wrong-session"; form.emit("submit"); await settle();
  assert.equal(deletes.length, 0); assert.match(app.elements.get("management-message").textContent, /match this session ID exactly/);
  confirmation.value = "shared-session"; form.emit("submit"); await settle();
  assert.equal(deletes.length, 1); assert.equal(deletes[0].headers["If-Match"], '"1"'); assert.equal(deletes[0].body, undefined);
  assert.match(app.elements.get("management-message").textContent, /protected by immutable snapshots/);
  assert.match(app.content.textContent, /Session members/); assert.equal(app.findButton("Delete session").disabled, false);
  app.elements.get("management-refresh").emit("click"); await settle();
  assert.equal(deletes.length, 1); assert.match(app.content.textContent, /Session members/);
});

test("read-only identities receive disabled mutation controls even with instance-operator access", async (t) => {
  let retryable = false;
  const app = await application(t, (path, options) => {
    if (path.includes("/context?")) return jsonResponse({ enabled: true, tenant_id: "tenant", principal_id: "principal", can_write: false, can_admin: false, can_instance_operator: true, identity_mode: "deployment" });
    if (path.endsWith("/imports/shared-import") && options.method === "GET") return jsonResponse({ import_id: "shared-import", original_name: "Read-only dump", state: retryable ? "failed" : "awaiting_selection", terminal: retryable, version: 1, byte_count: 12, attempt_count: 1, max_attempts: 2, probe_set_hash: "sha256:probe", error: retryable ? { code: "temporary", message: "Retryable failure", retryable: true } : null });
    if (path.endsWith("/candidates")) return jsonResponse({ items: [{ plugin_id: "parser", plugin_version: "1", package_hash: "sha256:package", confidence: 1, match_kind: "exact" }] });
    return undefined;
  });
  await app.connect(); await app.tab("imports");
  assert.equal(app.findButton("Upload & queue").disabled, true);
  assert.equal(descendants(app.content).find((node) => node.type === "file").disabled, true);
  await app.click(app.findButton("Inspect import"));
  assert.equal(app.findButton("Cancel import").disabled, true); assert.equal(app.findButton("Select parser").disabled, true);
  retryable = true; await app.click(app.findButton("Refresh import")); assert.equal(app.findButton("Resume import").disabled, true);
  await app.tab("sessions"); assert.equal(app.findButton("Create").disabled, true);
  await app.click(app.findButton("Manage session"));
  for (const label of ["Remove member", "Save member", "Create immutable snapshot", "Save name", "Delete session"]) assert.equal(app.findButton(label).disabled, true, label);
  await app.tab("administration"); assert.equal(app.findButton("Save confirmed policy").disabled, true); assert.equal(app.findButton("Execute confirmed retention"), undefined);
  assert.equal(app.calls.every((call) => call.method === "GET"), true);
});

test("related tool links are exact same-origin entry links without identity or selection parameters", async (t) => {
  const app = await application(t); await app.connect();
  const links = descendants(app.content).filter((node) => node.tagName === "A");
  assert.deepEqual(links.map((link) => link.href), ["/analysis", "/node#durable-review-setup"]);
  for (const link of links) {
    const url = new URL(link.href, "https://same-origin.example");
    assert.equal(url.origin, "https://same-origin.example"); assert.equal(url.search, "");
    assert.doesNotMatch(link.href, /tenant|principal|workspace-a|revision-workspace-a/);
    assert.equal(link.target, "_blank"); assert.equal(link.rel, "noopener");
  }
  assert.match(app.content.textContent, /Neither link submits data or starts a model run/);
  assert.equal(app.calls.every((call) => call.method === "GET"), true);
});

test("catalog selections outside quick-picker windows remain represented by selected options", async (t) => {
  const app = await application(t, (path) => {
    const url = new URL(path, "http://test.invalid");
    if (url.pathname === "/v1/control-plane/projects" && url.searchParams.get("limit") === "50") return jsonResponse({ items: [{ project_id: "outside-project", label: "Outside project" }], next_offset: null });
    if (url.pathname === "/v1/control-plane/projects/outside-project/workspaces") return jsonResponse({ items: url.searchParams.get("limit") === "5000" ? [] : [{ workspace_id: "outside-workspace", label: "Outside workspace" }], next_offset: null });
    return undefined;
  });
  await app.connect(); await app.tab("projects"); await app.click(app.findButton("Select project"));
  const project = app.elements.get("management-project");
  assert.equal(project.value, "outside-project"); assert.equal(project.children.some((option) => option.value === "outside-project"), true);
  await app.click(app.findButton("Select workspace", app.workspaceCard("outside-workspace")));
  const workspace = app.elements.get("management-workspace");
  assert.equal(workspace.value, "outside-workspace"); assert.equal(workspace.children.some((option) => option.value === "outside-workspace"), true);
  assert.equal(app.elements.get("management-breadcrumb").textContent, "outside-project / outside-workspace");
});

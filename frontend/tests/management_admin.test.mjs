import test from "node:test";
import assert from "node:assert/strict";
import {
  canManageAdministration,
  validateDisclosurePolicy,
  validateRetentionPayload,
  retentionPreviewSummary,
  renderAdministration,
} from "../assets/management_admin.js";

const policy = (mode = "disabled", transports = []) => ({ policy_version: "router_dump_analyzer.workspace_disclosure_policy.v1", mode, transports });
const record = { version: 0, policy: policy(), explicit: false };
const inventory = (enabled = false) => ({ policy: { enabled }, total_candidate_count: 0, candidates: [], truncated: false });
const preview = (enabled = true) => ({ executed: false, observation_mode: "best_effort_preview", catalog: inventory(enabled), review: inventory(), ingestion: { policy_enabled: false, truncated: false, host_storage_orphan_inventory: "not_observed" } });

test("administration requires the exact independent admin flag", () => {
  assert.equal(canManageAdministration({ can_admin: true }), true);
  for (const context of [null, {}, { can_admin: "true" }, { can_admin: 1 }, { can_write: true }, { can_instance_operator: true }]) assert.equal(canManageAdministration(context), false);
});

test("disclosure policy validates closed fields, explicit transports, and lexical order", () => {
  assert.deepEqual(validateDisclosurePolicy(policy()), policy());
  assert.deepEqual(validateDisclosurePolicy(policy("full_fidelity", ["in_process", "local_subprocess"])), policy("full_fidelity", ["in_process", "local_subprocess"]));
  for (const value of [null, [], {}, { ...policy(), unknown: true }, { ...policy(), policy_version: "other" }, policy("full_fidelity"), policy("disabled", ["in_process"]), policy("client_safe", ["remote"]), policy("client_safe", ["in_process", "in_process"]), policy("client_safe", ["local_subprocess", "in_process"])]) assert.throws(() => validateDisclosurePolicy(value));
});

test("retention defaults stay disabled and preserve exact large timestamp strings", () => {
  const result = validateRetentionPayload({ catalog: { revision_before_ns: "9223372036854775807" } });
  assert.equal(result.catalog.enabled, false); assert.equal(result.review.enabled, false);
  assert.equal(result.catalog.preserve_latest_snapshot_per_session, true);
  assert.equal(result.catalog.revision_before_ns, "9223372036854775807");
  assert.equal(result.review.audit_mode, "preserve");
  assert.equal(result.review.audit_before_sequence, null);
  assert.deepEqual(validateRetentionPayload(JSON.stringify(result)), result);
});

test("retention rejects unsafe coordinates, server-owned fields, and malformed protections", () => {
  for (const value of [0, 100, 9223372036854775807, "01", " 1", "-1", "1e9", "9223372036854775808", true, ""]) assert.throws(() => validateRetentionPayload({ catalog: { revision_before_ns: value } }));
  for (const value of [null, [], { ingestion: {} }, { catalog: null }, { catalog: { external_references_checked: true } }, { catalog: { enabled: "true" } }, { review: { maximum_candidates: 0 } }, { review: { maximum_candidates: "2" } }, { catalog: { maximum_candidates: 5001 } }, { catalog: { protected_fixture_ids: ["a", "a"] } }, { catalog: { protected_revision_ids: ["bad\n"] } }, { review: { audit_mode: "prune_explicit" } }, { review: { audit_before_sequence: "1" } }, { review: { audit_mode: "prune_explicit", audit_before_sequence: "9007199254740992" } }]) assert.throws(() => validateRetentionPayload(value));
  assert.throws(() => validateRetentionPayload(" ".repeat(1_048_577)), /large/);
  const result = validateRetentionPayload({ review: { enabled: true, audit_mode: "prune_explicit", audit_before_sequence: "9007199254740991" } });
  assert.equal(result.review.audit_before_sequence, "9007199254740991");
});

test("preview summaries expose incompleteness and do not call disabled inventory a cleanup proof", () => {
  const value = preview(); value.catalog.candidates = [{ blockers: [] }, { blockers: ["protected"] }]; value.catalog.total_candidate_count = 2;
  assert.deepEqual(retentionPreviewSummary(value), { valid: true, complete: true, enabled: true, candidateCount: 2, eligibleShown: 1, hostInventory: "not observed" });
  assert.equal(retentionPreviewSummary(preview(false)).enabled, false);
  assert.equal(retentionPreviewSummary({ ...value, executed: true }).valid, false);
  assert.equal(retentionPreviewSummary({ ...value, catalog: { ...value.catalog, truncated: true } }).complete, false);
  assert.equal(retentionPreviewSummary({ ...value, ingestion: {} }).complete, false);
  assert.equal(retentionPreviewSummary({ ...value, catalog: { policy: { enabled: true }, truncated: false } }).complete, false);
});

class Element {
  constructor(tag, text = "", className = "") { this.tag = tag; this.text = text ?? ""; this.className = className; this.children = []; this.listeners = new Map(); this.style = {}; this.disabled = false; this.value = ""; this.checked = false; }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
  replaceChildren(...nodes) { for (const node of this.children) node.parent = null; this.children = []; this.append(...nodes); }
  get isConnected() { return this.connected === true || this.parent?.isConnected === true; }
  set textContent(value) { this.text = String(value); this.replaceChildren(); }
  get textContent() { return String(this.text) + this.children.map((child) => child.textContent).join(" "); }
  addEventListener(type, action) { const callbacks = this.listeners.get(type) || []; callbacks.push(action); this.listeners.set(type, callbacks); }
  dispatch(type) { for (const action of this.listeners.get(type) || []) action({ target: this }); this.parent?.dispatch(type); }
}

function harness({ context = { enabled: true, can_admin: true, can_write: false, can_instance_operator: false }, request } = {}) {
  const content = new Element("main"); content.connected = true;
  const state = { context, project: "project-a", workspace: "workspace-a", serial: 1 };
  const calls = []; const messages = [];
  const client = { generation: 1, uncertain: false, request: async (path, options = {}) => { calls.push({ path, ...options }); return request ? request(path, options, calls) : structuredClone(record); } };
  const el = (tag, text, className) => new Element(tag, text, className);
  const ui = { content, state, client, path: (...parts) => "/v1/control-plane/projects/project-a/workspaces/workspace-a/" + parts.join("/"), el, card: (title) => el("article", title), json: (value) => el("pre", JSON.stringify(value)), button: (label, action, disabled = false) => { const element = el("button", label); element.action = action; element.disabled = disabled; return element; }, message: (text) => messages.push(text) };
  const all = (node = content) => [node, ...node.children.flatMap((child) => all(child))];
  const button = (label) => all().find((node) => node.tag === "button" && node.text === label);
  const field = (label) => all().find((node) => node.tag === "label" && node.text === label)?.children[0];
  const containingField = (label) => all().find((node) => node.tag === "label" && node.text.includes(label))?.children[0];
  return { ui, content, state, client, calls, messages, all, button, field, containingField };
}

test("non-admin readers can read policy but receive no retention controls or raw configuration", async () => {
  const view = harness({ context: { enabled: true, can_instance_operator: true, configuration: { secret: "SECRET" }, state_root: "PRIVATE-PATH" } });
  await renderAdministration(view.ui);
  assert.equal(view.calls.length, 1); assert.match(view.calls[0].path, /private-analysis-policy$/);
  assert.equal(view.button("Save confirmed policy").disabled, true);
  assert.equal(view.button("Preview retention (no deletion)"), undefined);
  assert.doesNotMatch(view.content.textContent, /SECRET|PRIVATE-PATH/);
  await assert.rejects(view.button("Save confirmed policy").action(), /administrator/);
});

test("policy saves use the loaded version and direct body only after explicit confirmation", async () => {
  const view = harness({ request: async (_path, options) => options.method === "PUT" ? { ...record, version: 1, explicit: true, policy: options.body } : structuredClone(record) });
  await renderAdministration(view.ui);
  const mode = view.field("Disclosure mode"); mode.value = "client_safe"; mode.dispatch("change");
  view.field("Allow in-process runners").checked = true;
  await assert.rejects(view.button("Save confirmed policy").action(), /confirm/);
  const confirm = view.containingField("I confirm this disclosure-policy change"); confirm.checked = true; confirm.dispatch("change");
  await view.button("Save confirmed policy").action();
  const write = view.calls.find((item) => item.method === "PUT");
  assert.equal(write.version, 0); assert.deepEqual(write.body, policy("client_safe", ["in_process"]));
  assert.equal(confirm.checked, false); assert.equal(view.button("Save confirmed policy").disabled, true);
  assert.match(view.content.textContent, /Version 1/);
});

test("policy conflicts preserve displayed data, disable retry, and require explicit refresh", async () => {
  const error = Object.assign(new Error("stale version"), { status: 409 });
  const view = harness({ request: async (_path, options) => { if (options.method === "PUT") throw error; return structuredClone(record); } });
  await renderAdministration(view.ui);
  const confirm = view.containingField("I confirm this disclosure-policy change"); confirm.checked = true;
  await assert.rejects(view.button("Save confirmed policy").action(), /stale version/);
  assert.equal(view.button("Save confirmed policy").disabled, true);
  confirm.checked = true; await assert.rejects(view.button("Save confirmed policy").action(), /Refresh/);
  assert.equal(view.calls.filter((item) => item.method === "PUT").length, 1);
  await view.button("Refresh policy").action();
  assert.equal(confirm.checked, false);
});

test("retention preview is explicitly non-mutating and execution requires matching preview plus typed workspace", async () => {
  const view = harness({ request: async (path) => path.endsWith("/preview") ? preview() : path.endsWith("/execute") ? { executed: true } : structuredClone(record) });
  await renderAdministration(view.ui);
  view.field("Enable catalog retention").checked = true;
  await assert.rejects(view.button("Execute confirmed retention").action(), /Preview/);
  await view.button("Preview retention (no deletion)").action();
  const request = view.calls.find((item) => item.path.endsWith("/preview"));
  assert.equal(request.method, "POST"); assert.equal(request.mutation, false);
  assert.equal(view.calls.some((item) => item.path.endsWith("/execute")), false);
  view.containingField("I reviewed the preview").checked = true;
  const typed = view.containingField("Type the exact workspace ID"); typed.value = "wrong";
  await assert.rejects(view.button("Execute confirmed retention").action(), /workspace ID/);
  typed.value = "workspace-a"; typed.dispatch("input");
  assert.equal(view.button("Execute confirmed retention").disabled, false);
  await view.button("Execute confirmed retention").action();
  const execution = view.calls.find((item) => item.path.endsWith("/execute"));
  assert.deepEqual(execution.body, request.body); assert.equal(execution.version, undefined);
  assert.equal(view.button("Execute confirmed retention").disabled, true);
  await assert.rejects(view.button("Execute confirmed retention").action(), /Preview/);
});

test("edited inputs and incomplete previews cannot authorize retention execution", async () => {
  const view = harness({ request: async (path) => path.endsWith("/preview") ? preview() : structuredClone(record) });
  await renderAdministration(view.ui);
  await view.button("Preview retention (no deletion)").action();
  view.containingField("I reviewed the preview").checked = true; view.containingField("Type the exact workspace ID").value = "workspace-a";
  const cutoff = view.field("revision before ns"); cutoff.value = "9223372036854775807"; cutoff.dispatch("input");
  await assert.rejects(view.button("Execute confirmed retention").action(), /Preview/);
  assert.equal(view.containingField("I reviewed the preview").checked, false);
  const truncated = harness({ request: async (path) => path.endsWith("/preview") ? { ...preview(), catalog: { ...inventory(true), truncated: true } } : structuredClone(record) });
  await renderAdministration(truncated.ui); await truncated.button("Preview retention (no deletion)").action();
  assert.match(truncated.content.textContent, /Inventory is truncated/);
  assert.equal(truncated.button("Execute confirmed retention").disabled, true);
});

test("late previews and actions from stale views never repaint or execute", async () => {
  let resolve;
  const view = harness({ request: async (path) => path.endsWith("/preview") ? new Promise((done) => { resolve = done; }) : structuredClone(record) });
  await renderAdministration(view.ui);
  const pending = view.button("Preview retention (no deletion)").action();
  view.state.serial++; resolve(preview()); await pending;
  assert.doesNotMatch(view.content.textContent, /Advisory preview and completeness/);
  await assert.rejects(view.button("Execute confirmed retention").action(), /Scope changed/);
  assert.equal(view.calls.some((item) => item.path.endsWith("/execute")), false);
});

test("retention audit keeps independent bounded cursors and ingestion coverage explicit", async () => {
  const view = harness({ request: async (path) => path.includes("/audit?") ? { catalog: [], review: [], ingestion: [], catalog_next_after_sequence: 100, review_next_after_sequence: 200 } : structuredClone(record) });
  await renderAdministration(view.ui); await view.button("Load / refresh retention audit").action();
  await view.button("Next catalog audit page").action();
  assert.match(view.calls.at(-1).path, /catalog_after_sequence=100&review_after_sequence=0$/);
  await view.button("Next review audit page").action();
  assert.match(view.calls.at(-1).path, /catalog_after_sequence=100&review_after_sequence=200$/);
  assert.match(view.content.textContent, /Ingestion shows only its latest bounded entries/);
});

test("failed retention execution is never automatically retried", async () => {
  const view = harness({ request: async (path) => { if (path.endsWith("/preview")) return preview(); if (path.endsWith("/execute")) throw Object.assign(new Error("uncertain write"), { ambiguous: true }); return structuredClone(record); } });
  await renderAdministration(view.ui); await view.button("Preview retention (no deletion)").action();
  view.containingField("I reviewed the preview").checked = true; view.containingField("Type the exact workspace ID").value = "workspace-a";
  await assert.rejects(view.button("Execute confirmed retention").action(), /uncertain/);
  assert.match(view.content.textContent, /No retry was made/);
  assert.equal(view.calls.filter((item) => item.path.endsWith("/execute")).length, 1);
  await assert.rejects(view.button("Execute confirmed retention").action(), /Preview/);
});

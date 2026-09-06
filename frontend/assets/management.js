import { createManagementClient, managementPath, MANAGEMENT_PAGE_SIZE, managementHealth } from "./management_controller.js";
import { renderCatalog, renderImports, renderSessions } from "./management_workflows.js";
import { renderAdministration } from "./management_admin.js";
import { renderDurableAnalysis } from "./management_analysis.js";

const $ = (id) => document.getElementById(id);
const client = createManagementClient();
const state = { context: null, project: "", workspace: "", view: "projects", offsets: {}, serial: 0 };
const content = $("management-content");
let refreshTimer = null;
function scheduleRefresh(milliseconds) { clearTimeout(refreshTimer); const serial = state.serial; refreshTimer = setTimeout(() => { if (serial === state.serial && !document.hidden && !client.writing && !client.uncertain) run(show); }, milliseconds); }
function resetScopeDetails() { for (const key of Object.keys(state)) if (key.startsWith("analysis") || ["importId", "importCursors", "importEventsAfter", "sessionId", "memberRevisionOffset"].includes(key)) delete state[key]; state.offsets = {}; }
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = String(text); if (className) node.className = className; return node; }
function message(text, error = false) { $("management-message").textContent = text; $("management-message").dataset.error = String(error); }
function json(value) { return el("pre", JSON.stringify(value, null, 2)); }
function button(label, action, disabled = false, danger = false) { const node = el("button", label, danger ? "danger" : ""); node.type = "button"; node.disabled = disabled; let busy = false; node.addEventListener("click", () => { if (busy) return; run(async () => { busy = true; node.setAttribute("aria-busy", "true"); try { await action(); } finally { busy = false; node.removeAttribute("aria-busy"); } }); }); return node; }
async function run(action) { try { await action(); } catch (error) { message(error.message, true); } }
function path(...parts) { if (!state.project || !state.workspace) throw new Error("Select a project and workspace first."); return managementPath("projects", state.project, "workspaces", state.workspace, ...parts); }
function card(title) { const node = el("article", undefined, "management-card"); node.append(el("h3", title)); return node; }
function clear(title) { content.replaceChildren(el("h2", title)); }
function inputForm(title, fields, submit, { disabled = false, submitText = "Create" } = {}) {
  const wrap = card(title); const form = el("form", undefined, "management-form");
  for (const [name, label, value = ""] of fields) { const holder = el("label", label); const field = el("input"); field.name = name; field.value = value; field.required = true; field.maxLength = 256; field.disabled = disabled; holder.append(field); form.append(holder); }
  const send = el("button", submitText); send.type = "submit"; send.disabled = disabled; form.append(send);
  form.addEventListener("submit", (event) => { event.preventDefault(); run(async () => { send.disabled = true; try { await submit(Object.fromEntries(new FormData(form))); } finally { if (send.isConnected) send.disabled = disabled || client.uncertain; } }); });
  wrap.append(form); return wrap;
}
function pager(root, next, offset, callback) {
  const row = el("div", undefined, "management-pager"); row.append(button("Previous", () => callback(Math.max(0, offset - MANAGEMENT_PAGE_SIZE)), offset === 0), el("span", `Page ${Math.floor(offset / MANAGEMENT_PAGE_SIZE) + 1}`), button("Next", () => callback(next), next === null || next === undefined)); root.append(row);
}
async function collection(target, key, root, render) {
  const serial = state.serial; const offset = state.offsets[key] || 0;
  const page = await client.request(`${target}?limit=${MANAGEMENT_PAGE_SIZE}&offset=${offset}`);
  if (serial !== state.serial || !root.isConnected) return;
  const items = page.items || [];
  if (!items.length) root.append(el("p", "No items in this scope yet.", "management-empty"));
  const list = el("div", undefined, "management-list"); for (const item of items) list.append(render(item)); root.append(list);
  pager(root, page.next_offset, offset, async (value) => { state.offsets[key] = value; await show(); });
}
function recordRow(label, detail, actions = []) { const row = el("div", undefined, "management-row"); const text = el("div"); text.append(el("strong", label), el("small", detail)); const controls = el("div", undefined, "management-actions"); controls.append(...actions); row.append(text, controls); return row; }
function selectOptions(id, items, field, placeholder) { const node = $(id); node.replaceChildren(new Option(placeholder, "")); for (const item of items) node.add(new Option(item.label || item[field], item[field])); node.disabled = false; }
function selectScopeValue(id, value) {
  const node = $(id);
  // The paginated catalog can select an item outside the bounded quick picker.
  if (value && !Array.from(node.children).some((option) => option.value === value)) node.add(new Option(value, value));
  node.value = value;
}
async function refreshProjects() { const token = state.serial; const page = await client.request(managementPath("projects") + "?limit=5000&offset=0"); if (token !== state.serial) return; selectOptions("management-project", page.items, "project_id", "Choose a project"); selectScopeValue("management-project", state.project); }
async function chooseProject(value) {
  if (client.writing) {
    $("management-project").value = state.project;
    throw new Error("Wait for the current write.");
  }
  client.invalidate();
  state.serial++;
  state.project = value;
  state.workspace = "";
  resetScopeDetails();
  content.replaceChildren(el("p", "Loading selected project…"));
  selectScopeValue("management-project", value);
  selectOptions("management-workspace", [], "workspace_id", "Choose a workspace");
  if (value) {
    const token = state.serial;
    const page = await client.request(managementPath("projects", value, "workspaces") + "?limit=5000&offset=0");
    if (token !== state.serial) return;
    selectOptions("management-workspace", page.items, "workspace_id", "Choose a workspace");
  }
  await show();
}
async function chooseWorkspace(value, view = state.view) { if (client.writing) { $("management-workspace").value = state.workspace; throw new Error("Wait for the current write."); } client.invalidate(); state.workspace = value; resetScopeDetails(); selectScopeValue("management-workspace", value); state.view = view; await show(); }
async function projects() {
  clear("Projects & workspaces");
  if (!state.context) { content.append(el("p", "Connect above to discover your authorized projects. Server status is available without a connection.")); return; }
  const grid = el("div", undefined, "management-grid"); const projectList = card("Projects"); const workspaceList = card("Workspaces"); grid.append(projectList, workspaceList); content.append(grid);
  content.append(el("p", "The quick pickers show up to 5,000 entries. Use the paginated lists below to reach and select any remaining project or workspace."));
  const canWrite = state.context.can_write === true;
  content.append(inputForm("Create project", [["label", "Project name"], ["project_id", "Stable project ID", crypto.randomUUID()]], async (body) => { const item = await client.request(managementPath("projects"), { method: "POST", body }); await refreshProjects(); await chooseProject(item.project_id); message("Project created. Create a workspace to begin importing data."); }, { disabled: !canWrite }));
  if (state.project) content.append(inputForm("Create workspace", [["label", "Workspace name"], ["workspace_id", "Stable workspace ID", crypto.randomUUID()]], async (body) => { const item = await client.request(managementPath("projects", state.project, "workspaces"), { method: "POST", body }); await chooseProject(state.project); state.workspace = item.workspace_id; $("management-workspace").value = state.workspace; await show(); message("Workspace created."); }, { disabled: !canWrite }));
  await collection(managementPath("projects"), "projects", projectList, (item) => recordRow(item.label, item.project_id, [button("Select project", () => chooseProject(item.project_id))]));
  if (state.project && workspaceList.isConnected) await collection(managementPath("projects", state.project, "workspaces"), "workspaces", workspaceList, (item) => recordRow(item.label, item.workspace_id, [button("Select workspace", () => chooseWorkspace(item.workspace_id, "catalog"))]));
  else workspaceList.append(el("p", "Select a project first."));
}
async function server() {
  clear("Server status"); const grid = el("div", undefined, "management-grid"); content.append(grid);
  const followLabel = el("label", "Refresh every 10 seconds while this page is visible "); const follow = el("input"); follow.type = "checkbox"; follow.checked = state.followHealth === true; follow.addEventListener("change", () => { state.followHealth = follow.checked; if (follow.checked) scheduleRefresh(10000); else clearTimeout(refreshTimer); }); followLabel.append(follow); content.prepend(followLabel);
  for (const [label, target] of [["Analysis runtime", "/health"], ["Durable queue & workers", managementPath("health")]]) {
    const box = card(label); grid.append(box);
    try {
      const health = await client.request(target, { publicRead: true }); if (!box.isConnected) return;
      box.append(el("p", managementHealth(health), "metric"));
      const workers = health.ingestion_workers || health.control_plane?.ingestion_workers;
      const table = el("table"); const facts = label === "Analysis runtime"
        ? [["Mode", health.mode], ["Analysis", health.mode === "control-plane" ? "API-only server · no startup dump" : health.analysis_ready ? "Ready" : "Loading / unavailable"], ["Events", health.event_count], ["Resources", health.resource_count], ["Search index", health.history_search_ready ? "Ready" : "Not ready"]]
        : [["Workers", workers ? `${workers.live_workers}/${workers.configured_workers} alive` : "Unavailable"], ["Pending imports", workers?.pending_imports], ["Awaiting selection", workers?.awaiting_selection_imports], ["Stalled imports", workers?.stalled_imports], ["Unexpected worker exits", workers?.unexpected_worker_exits], ["Last worker error", workers?.last_claim_error || workers?.last_iteration_error || "None"]];
      for (const [name, value] of facts) { const row = el("tr"); row.append(el("th", name), el("td", value === undefined ? "Unavailable" : value)); table.append(row); }
      const raw = el("details"); raw.append(el("summary", "Diagnostic payload"), json(health)); box.append(table, raw);
    } catch (error) { if (box.isConnected) box.append(el("p", error.message)); }
  }
  if (!grid.isConnected) return;
  const diagnostics = card("Instance operational diagnostics"); content.append(diagnostics);
  if (state.context?.can_instance_operator === true) {
    const data = await client.request(managementPath("diagnostics", "operational-events"));
    if (!diagnostics.isConnected) return;
    diagnostics.append(json(data));
  } else diagnostics.append(el("p", "Requires the separate instance-operator role. Tenant administration does not grant access to these process-wide counters."));
  content.append(el("p", "Status reflects response contents, not merely HTTP 200. Automatic refresh is opt-in and stops when this view is hidden."));
  if (state.view === "server" && state.followHealth) scheduleRefresh(10000);
}
async function show() {
  clearTimeout(refreshTimer);
  state.serial++; $("management-breadcrumb").textContent = state.workspace ? `${state.project} / ${state.workspace}` : state.project || "No workspace selected";
  document.querySelectorAll("[data-view]").forEach((node) => node.setAttribute("aria-pressed", String(node.dataset.view === state.view)));
  if (state.view === "projects") return projects();
  if (state.view === "server") return server();
  clear(state.view === "catalog" ? "Data & revisions" : state.view === "durable-analysis" ? "Durable revision analysis" : state.view[0].toUpperCase() + state.view.slice(1));
  if (!state.context || !state.workspace) { content.append(el("p", "Select a project and workspace to use this section.")); return; }
  const related = el("details");
  related.append(el("summary", "Related review and private-analysis tools"));
  related.append(el("p", `Project: ${state.project} · Workspace: ${state.workspace}. Connect the other page using this scope and your authorized identity; identities are not passed in links or stored in the browser.`));
  const links = el("div", undefined, "management-actions");
  for (const [label, href] of [["Open private evidence analysis", "/analysis"], ["Open node review and AI correlation reports", "/node#durable-review-setup"]]) {
    const link = el("a", label); link.href = href; link.target = "_blank"; link.rel = "noopener"; links.append(link);
  }
  related.append(links, el("p", "Node review annotates the startup analysis input; it does not switch that input to a catalog revision. Private evidence analysis selects published revisions after connecting. Neither link submits data or starts a model run."));
  content.append(related);
  const scopePrefix = path(); const scopedPath = (...parts) => scopePrefix + parts.map((part) => `/${encodeURIComponent(part)}`).join("");
  const ui = { content, client, state, path: scopedPath, el, card, json, button, message, run, show, collection, pager, recordRow, inputForm, openAnalysis, scheduleRefresh };
  if (state.view === "durable-analysis") return renderDurableAnalysis(ui);
  if (state.view === "catalog") return renderCatalog(ui);
  if (state.view === "imports") return renderImports(ui);
  if (state.view === "sessions") return renderSessions(ui);
  if (state.view === "administration") return renderAdministration(ui);
  content.append(el("p", "This management section is being connected to the existing core APIs."));
}
async function openAnalysis(selector) { for (const key of Object.keys(state)) if (key.startsWith("analysis")) delete state[key]; state.analysisSelector = selector; state.view = "durable-analysis"; await show(); }
$("management-connect").addEventListener("submit", (event) => { event.preventDefault(); run(async () => {
  const values = new FormData(event.currentTarget); client.connect(String(values.get("tenant")), String(values.get("principal"))); state.serial++; state.context = null; state.project = ""; state.workspace = ""; resetScopeDetails(); content.replaceChildren();
  $("management-identity").textContent = "Connecting — identity has not been verified yet.";
  for (const id of ["management-project", "management-workspace"]) { $(id).replaceChildren(new Option("Connect first", "")); $(id).disabled = true; }
  $("management-breadcrumb").textContent = "No workspace selected";
  const connectingGeneration = client.generation;
  const context = await client.request(managementPath("context") + "?limit=50&offset=0").catch((error) => {
    if (client.generation === connectingGeneration) $("management-identity").textContent = "Not connected. Check the identity and the server's access configuration, then connect again.";
    throw error;
  }); state.context = context;
  $("management-identity").textContent = `${context.principal_id} · ${context.tenant_id} · ${context.can_write ? "Read/write" : "Read only"}${context.can_admin ? " · Tenant admin" : ""}${context.can_instance_operator ? " · Instance operator" : ""}. ${context.identity_mode === "trusted_headers" ? "Local trusted-header mode is not authentication." : "Identity is verified by the deployment."}`;
  await refreshProjects(); await show(); message("Connected. Select a project and workspace.");
}); });
$("management-disconnect").addEventListener("click", () => run(async () => { client.disconnect(); state.context = null; state.project = ""; state.workspace = ""; resetScopeDetails(); $("management-identity").textContent = "Disconnected. No identity is stored."; document.querySelectorAll("#management-connect input").forEach((input) => { input.value = ""; }); for (const id of ["management-project", "management-workspace"]) { $(id).replaceChildren(new Option("Connect first", "")); $(id).disabled = true; } await show(); }));
$("management-project").addEventListener("change", (event) => run(() => chooseProject(event.target.value)));
$("management-workspace").addEventListener("change", (event) => run(() => chooseWorkspace(event.target.value)));
$("management-refresh").addEventListener("click", () => run(show));
$("management-tabs").addEventListener("click", (event) => { const target = event.target.closest("[data-view]"); if (target) run(async () => { state.view = target.dataset.view; await show(); }); });
run(show);
window.addEventListener("pagehide", () => clearTimeout(refreshTimer));
document.addEventListener("visibilitychange", () => { if (document.hidden) clearTimeout(refreshTimer); else if ((state.view === "server" && state.followHealth) || (state.view === "imports" && state.importId && state.followImport !== false)) run(show); });

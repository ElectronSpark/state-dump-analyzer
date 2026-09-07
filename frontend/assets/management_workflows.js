import { MANAGEMENT_PAGE_SIZE } from "./management_controller.js";

export function candidateSelection(record, candidate) {
  if (!record.probe_set_hash) throw new Error("Refresh the import before choosing a parser.");
  const body = { probe_set_hash: record.probe_set_hash };
  for (const key of ["plugin_id", "plugin_version", "package_hash"]) {
    if (typeof candidate[key] !== "string" || !candidate[key]) throw new Error("The candidate identity is incomplete.");
    body[key] = candidate[key];
  }
  if (candidate.instance_id || candidate.registered_execution_identity) {
    if (!candidate.instance_id || !candidate.registered_execution_identity) throw new Error("The candidate execution identity is incomplete.");
    body.instance_id = candidate.instance_id; body.registered_execution_identity = candidate.registered_execution_identity;
  }
  return body;
}

export function sessionMemberBody(revision, role = "member", makeDefault = false) {
  if (!revision?.revision_id || !revision?.fixture_id) throw new Error("Choose a published revision.");
  return { fixture_id: revision.fixture_id, revision_id: revision.revision_id, role, make_default: makeDefault };
}

function disclosure(ui, label, data) { const box = ui.el("details"); box.append(ui.el("summary", label), ui.json(data)); return box; }

export async function renderCatalog(ui) {
  const { content, state, path, client, card, el, collection, recordRow, button, openAnalysis } = ui;
  const grid = el("div", undefined, "management-grid"); const revisions = card("Published revisions"); const fixtures = card("Admitted fixtures"); grid.append(revisions, fixtures); content.append(grid);
  await collection(path("revisions"), "revisions", revisions, (item) => {
    const row = el("div"); row.append(recordRow(item.node_id, item.revision_id, [button("Inspect analysis", () => openAnalysis({ revision_ids: [item.revision_id] })), button("Consistency findings", async () => {
      const result = await client.request(path("revisions", item.revision_id, "consistency-findings") + "?limit=50&offset=0"); if (!row.isConnected) return; const detail = card("Consistency findings · first 50"); detail.append(ui.json(result)); content.append(detail);
    })]), disclosure(ui, "Provenance & execution plan", item)); return row;
  });
  if (!fixtures.isConnected) return;
  await collection(path("fixtures"), "fixtures", fixtures, (item) => { const row = el("div"); row.append(recordRow(item.label, item.fixture_id), disclosure(ui, "Fixture provenance", item)); return row; });
  if (!fixtures.isConnected) return;
  content.append(el("p", "Catalog data is immutable and scoped to this workspace. Session membership chooses revisions without replacing the startup demo. Import a dump in Imports to add data."));
}

export async function renderImports(ui) {
  const { content, state, client, path, card, el, button, message, run, show, recordRow } = ui;
  const canWrite = state.context.can_write === true;
  if (state.importId) return inspectImport(ui, state.importId);
  const upload = card("Upload a state dump"); const form = el("form", undefined, "management-form");
  const label = el("label", "Dump file"); const file = el("input"); file.type = "file"; file.required = true; file.disabled = !canWrite; label.append(file);
  const autoLabel = el("label", "Parser selection"); const auto = el("select"); auto.add(new Option("Automatically select an unambiguous parser", "true")); auto.add(new Option("Review candidates manually", "false")); auto.disabled = !canWrite; autoLabel.append(auto);
  const nodeLabel = el("label", "Node identity hint (optional)"); const nodeHint = el("input"); nodeHint.type = "text"; nodeHint.maxLength = 256; nodeHint.placeholder = "router-1"; nodeHint.disabled = !canWrite; nodeLabel.append(nodeHint);
  const submit = el("button", "Upload & queue"); submit.type = "submit"; submit.disabled = !canWrite; form.append(label, autoLabel, nodeLabel, submit);
  const progress = el("p", "File bytes are streamed to this server only. Parser choices come from the deployment allowlist. A node hint supplies an explicit identity to parsers that accept it; use up to 256 printable ASCII characters without whitespace, or leave it blank for detection.");
  form.addEventListener("submit", (event) => { event.preventDefault(); run(async () => {
    if (!file.files?.length) throw new Error("Select a dump file."); const selected = file.files[0]; if (!selected.size) throw new Error("The selected file is empty.");
    submit.disabled = true; const spinner = el("progress"); spinner.setAttribute("aria-label", "Uploading dump"); upload.append(spinner); progress.textContent = `Uploading ${selected.name} (${selected.size.toLocaleString()} bytes)…`;
    try {
      const query = new URLSearchParams({ original_name: selected.name, auto_select: auto.value });
      const record = await client.request(`${path("imports")}?${query}`, { method: "POST", file: selected, ...(nodeHint.value === "" ? {} : { nodeHint: nodeHint.value }) });
      state.importId = record.import_id; await show(); message("Upload admitted. Follow its durable status below; manual parser selection may be required.");
    } finally { spinner.remove(); if (submit.isConnected) submit.disabled = !canWrite || client.uncertain; }
  }); });
  upload.append(form, progress); content.append(upload);
  const list = card("Import queue"); content.append(list);
  const cursors = state.importCursors || [null]; state.importCursors = cursors;
  const current = cursors[cursors.length - 1]; const params = new URLSearchParams({ limit: "50", ...(current || {}) });
  const page = await client.request(`${path("imports")}?${params}`); if (!list.isConnected) return;
  if (!page.items.length) list.append(el("p", "No uploads yet."));
  for (const item of page.items) list.append(recordRow(item.original_name, `${item.state} · ${item.byte_count.toLocaleString()} bytes${item.error ? ` · ${item.error.message}` : ""}`, [button("Inspect import", async () => { state.importId = item.import_id; await show(); })]));
  const pager = el("div", undefined, "management-pager"); pager.append(button("Previous imports", async () => { cursors.pop(); await show(); }, cursors.length <= 1), button("Next imports", async () => { cursors.push(page.next_cursor); await show(); }, !page.next_cursor)); list.append(pager);
}

async function inspectImport(ui, id) {
  const { content, state, path, client, el, card, button, message, show } = ui;
  const root = card("Import details"); content.append(button("Back to import queue", async () => { state.importId = null; state.importEventsAfter = 0; await show(); }), root);
  const record = await client.request(path("imports", id)); if (!root.isConnected) return;
  root.append(el("h3", record.original_name), el("p", record.state, "metric"), el("p", `${record.byte_count.toLocaleString()} bytes · attempt ${record.attempt_count}/${record.max_attempts} · revision ${record.revision_id || "not published"}`));
  if (!record.terminal && record.state !== "awaiting_selection") { const p = el("progress"); p.setAttribute("aria-label", "Import processing"); root.append(p); }
  if (record.state === "awaiting_selection") root.append(el("p", "Action required: choose a parser below. No parsing is running while selection is pending."));
  const followLabel = el("label", "Follow progress while processing "); const follow = el("input"); follow.type = "checkbox"; follow.checked = state.followImport !== false; follow.addEventListener("change", () => { state.followImport = follow.checked; ui.run(show); }); followLabel.append(follow); root.append(followLabel);
  if (record.error) root.append(el("p", `${record.error.code}: ${record.error.message}`));
  root.append(button("Refresh import", show));
  const writable = state.context.can_write === true;
  if (!record.terminal) root.append(button("Cancel import", async () => {
    const current = await client.request(path("imports", id)); await client.request(path("imports", id, "cancel"), { method: "POST", version: current.version }); await show(); message("Import cancellation requested.");
  }, !writable, true));
  if (record.error?.retryable) root.append(button("Resume import", async () => { await client.request(path("imports", id, "resume"), { method: "POST" }); await show(); }, !writable));
  if (record.revision_id) root.append(button("Inspect published revision", () => ui.openAnalysis({ revision_ids: [record.revision_id] })));
  root.append(disclosure(ui, "Import identity & metadata", record));
  const candidates = await client.request(path("imports", id, "candidates")); if (!root.isConnected) return;
  const choices = card("Parser candidates"); content.append(choices);
  if (!candidates.items.length) choices.append(el("p", "No candidates available yet."));
  if (!candidates.items.length && record.error) choices.append(el("p", "No validated parser candidate is available. Check the expected file format and artifact names/layout, and the deployment's registered parsers before resuming. A retry does not change the uploaded bytes."));
  for (const candidate of candidates.items) {
    const row = el("div"); row.append(ui.recordRow(`${candidate.plugin_id} @ ${candidate.plugin_version}`, `${candidate.match_kind} · confidence ${candidate.confidence}`, [button("Select parser", async () => {
      await client.request(path("imports", id, "selection"), { method: "POST", body: candidateSelection(record, candidate) }); await show(); message("Parser selected using its exact probed execution identity.");
    }, !writable || record.state !== "awaiting_selection")]), disclosure(ui, "Match evidence", candidate)); choices.append(row);
  }
  const events = await client.request(path("imports", id, "events") + `?limit=100&after_sequence=${state.importEventsAfter || 0}`); if (!root.isConnected) return;
  const history = card("Processing events"); content.append(history);
  for (const item of events.items) history.append(ui.recordRow(`${item.sequence} · ${item.event_type}`, `${item.state}: ${item.message}`), disclosure(ui, "Event detail", item.payload));
  history.append(button("Next events", async () => { state.importEventsAfter = events.items.at(-1).sequence; await show(); }, events.items.length < 100), button("First events", async () => { state.importEventsAfter = 0; await show(); }, !state.importEventsAfter));
  if (!record.terminal && record.state !== "awaiting_selection" && state.followImport !== false && root.isConnected) ui.scheduleRefresh(2500);
}

export async function renderSessions(ui) {
  const { content, state, path, client, card, el, button, inputForm, collection, recordRow, show, message } = ui;
  if (state.sessionId) return inspectSession(ui, state.sessionId);
  content.append(inputForm("Create session", [["label", "Session name"], ["session_id", "Stable session ID", crypto.randomUUID()]], async (body) => {
    const record = await client.request(path("sessions"), { method: "POST", body }); state.sessionId = record.session_id; await show(); message("Session created. Add published revisions below.");
  }, { disabled: !state.context.can_write }));
  const sessions = card("Live sessions"); const snapshots = card("Immutable snapshots"); content.append(sessions, snapshots);
  await collection(path("sessions"), "sessions", sessions, (item) => recordRow(item.label, `${item.members.length} members · version ${item.version}`, [button("Manage session", async () => { state.sessionId = item.session_id; await show(); }), button("Inspect member analysis", () => ui.openAnalysis({ session_id: item.session_id }), !item.members.length)]));
  if (!snapshots.isConnected) return;
  await collection(path("snapshots"), "snapshots", snapshots, (item) => recordRow(item.snapshot_id, `${item.members.length} members · session ${item.session_id} @ ${item.session_version}`, [button("Inspect frozen analysis", () => ui.openAnalysis({ snapshot_id: item.snapshot_id }), !item.members.length), button("Snapshot details", async () => { const data = await client.request(path("snapshots", item.snapshot_id)); if (!snapshots.isConnected) return; const box = card("Immutable snapshot"); box.append(ui.json(data)); content.append(box); })]));
}

async function inspectSession(ui, id) {
  const { content, state, path, client, card, el, button, inputForm, show, message } = ui;
  const root = card("Session members"); content.append(button("Back to sessions", async () => { state.sessionId = null; await show(); }), root);
  const record = await client.request(path("sessions", id)); if (!root.isConnected) return; const writable = state.context.can_write === true;
  root.append(el("h3", record.label), el("p", `${record.session_id} · version ${record.version}`));
  for (const member of record.members) root.append(ui.recordRow(member.member_id, `${member.node_id} · ${member.revision_id}${member.member_id === record.default_member_id ? " · default" : ""}`, [button("Remove member", async () => {
    await client.request(path("sessions", id, "members", member.member_id), { method: "DELETE", version: record.version }); await show();
  }, !writable, true)]));
  if (!record.members.length) root.append(el("p", "No revisions selected yet."));
  root.append(button("Create immutable snapshot", async () => { const snapshot = await client.request(path("sessions", id, "snapshots"), { method: "POST", version: record.version }); message(`Snapshot created: ${snapshot.snapshot_id}. It protects this session from deletion.`); await show(); }, !writable || !record.members.length), button("Inspect session analysis", () => ui.openAnalysis({ session_id: id }), !record.members.length));
  content.append(inputForm("Rename session", [["label", "Session name", record.label]], async (body) => { await client.request(path("sessions", id), { method: "PATCH", version: record.version, body }); await show(); }, { disabled: !writable, submitText: "Save name" }));
  const add = card("Add or replace a member"); const form = el("form", undefined, "management-form");
  const memberLabel = el("label", "Member ID"); const memberInput = el("input"); memberInput.required = true; memberInput.maxLength = 256; memberInput.value = crypto.randomUUID(); memberLabel.append(memberInput);
  const revisionLabel = el("label", "Published revision"); const revisions = el("select"); revisionLabel.append(revisions);
  const page = await client.request(path("revisions") + "?limit=50&offset=" + (state.memberRevisionOffset || 0)); if (!root.isConnected) return;
  for (const item of page.items) revisions.add(new Option(`${item.node_id} · ${item.revision_id}`, item.revision_id));
  const defaultLabel = el("label", "Default member"); const makeDefault = el("input"); makeDefault.type = "checkbox"; defaultLabel.append(makeDefault);
  const save = el("button", "Save member"); save.type = "submit"; save.disabled = !writable || !page.items.length; form.append(memberLabel, revisionLabel, defaultLabel, save);
  form.addEventListener("submit", (event) => { event.preventDefault(); ui.run(async () => { save.disabled = true; try {
    await client.request(path("sessions", id, "members", memberInput.value), { method: "PUT", version: record.version, body: sessionMemberBody(page.items.find((item) => item.revision_id === revisions.value), "member", makeDefault.checked) }); await show(); message("Session membership saved.");
  } finally { if (save.isConnected) save.disabled = !writable || client.uncertain; } }); });
  add.append(form, el("p", "Use an existing member ID only to intentionally replace it. A revision cannot appear twice; multiple revisions of one node remain distinct members."));
  ui.pager(add, page.next_offset, state.memberRevisionOffset || 0, async (offset) => { state.memberRevisionOffset = offset; await show(); }); content.append(add);
  const remove = inputForm("Delete empty/unprotected session", [["confirm", `Type session ID: ${id}`]], async (body) => {
    if (body.confirm !== id) throw new Error("The confirmation must match this session ID exactly.");
    await client.request(path("sessions", id), { method: "DELETE", version: record.version }); state.sessionId = null; await show(); message("Session deleted; published revisions were not deleted.");
  }, { disabled: !writable, submitText: "Delete session" });
  remove.append(el("p", "The server refuses deletion if immutable snapshots protect this session. Published data remains in its catalog.")); content.append(remove);
}

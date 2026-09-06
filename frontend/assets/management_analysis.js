export function analysisTimeAt(start, end, position) {
  if (!Number.isInteger(position) || position < 0 || position > 1000) throw new RangeError("Timeline position must be 0–1000.");
  const first = BigInt(start), last = BigInt(end);
  if (last < first) throw new RangeError("Timeline bounds are reversed.");
  return String(first + (last - first) * BigInt(position) / 1000n);
}

export function analysisQuery(state) {
  if (!state.analysisSelector) throw new Error("Select a durable revision, session or snapshot first.");
  const section = state.analysisSection || "summary";
  const query = { selector: state.analysisSelector, section, offset: state.analysisOffset || 0, limit: 50 };
  if (state.analysisMember) query.selected_member_id = state.analysisMember;
  if (state.analysisDigest) query.expected_revision_vector_digest = state.analysisDigest;
  if (state.analysisTime !== undefined) query.time_ns = analysisNanoseconds(state.analysisTime);
  if (section !== "summary" && state.analysisSearch) query.search = state.analysisSearch;
  if (section === "events" && state.analysisRange) {
    const start = analysisNanoseconds(state.analysisRange.start_ns); const end = analysisNanoseconds(state.analysisRange.end_ns);
    if (BigInt(start) > BigInt(end)) throw new RangeError("Enter an ordered integer time range.");
    Object.assign(query, { start_ns: start, end_ns: end });
  }
  return query;
}

export async function renderDurableAnalysis(ui) {
  const { content, client, state, path, card, el, json, button, show, run, message } = ui;
  const root = card("Durable revision analysis"); content.append(root);
  root.append(el("p", "This view reads the selected published data under your workspace permissions. It never changes the server's startup demo or another user's selection."));
  const serial = state.serial; const generation = client.generation; const selector = state.analysisSelector;
  const current = () => root.isConnected && state.serial === serial && client.generation === generation && state.analysisSelector === selector;
  root.append(button("Reset analysis filters", async () => {
    if (!current()) return;
    for (const key of ["analysisTime", "analysisRange", "analysisSearch"]) delete state[key];
    state.analysisOffset = 0; state.analysisSection = "summary";
    await show();
  }));
  if (selector?.session_id) root.append(button("Reload current session membership", async () => {
    if (!current()) return;
    for (const key of ["analysisDigest", "analysisMember", "analysisResult", "analysisTime", "analysisRange"]) delete state[key];
    state.analysisOffset = 0;
    message("Reloading live session membership by explicit request. Use an immutable snapshot when the selection must not change.");
    await show();
  }));
  let result;
  try { result = await client.request(path("analysis", "query"), { method: "POST", mutation: false, body: analysisQuery(state) }); }
  catch (error) {
    if (!current()) return;
    root.append(el("p", error.status === 409 && selector?.session_id
      ? "The live session selection no longer matches the pinned revision vector. No replacement was accepted automatically. Explicitly reload current session membership to inspect its latest selection, or return to an immutable snapshot."
      : "This analysis request did not return a verified result. Reset filters or retry the same selection; a pinned vector is never silently replaced."));
    message(error.message, true);
    return;
  }
  if (!current()) return;
  state.analysisResult = result; state.analysisDigest = result.selection.revision_vector_digest;
  const memberLabel = el("label", "Session member / revision"); const members = el("select");
  for (const member of result.revision_vector) members.add(new Option(`${member.node_id} · ${member.member_id} · ${member.revision_id}`, member.member_id));
  members.value = result.selected_member.member_id;
  members.addEventListener("change", () => run(async () => { state.analysisMember = members.value; state.analysisOffset = 0; delete state.analysisTime; delete state.analysisRange; await show(); }));
  memberLabel.append(members); root.append(memberLabel);
  root.append(el("p", `Exact vector: ${result.selection.revision_vector_digest} · ${result.revision_vector.length} revision(s). Multiple revisions of one node remain separate members.`));
  const vector = el("details"); vector.append(el("summary", "Frozen selection & provenance"), json(result.revision_vector)); root.append(vector);
  const tabs = el("div", undefined, "management-tabs");
  for (const section of ["summary", "resources", "events", "relationships", "findings"]) {
    const tab = button(section[0].toUpperCase() + section.slice(1), async () => { state.analysisSection = section; state.analysisOffset = 0; await show(); });
    tab.setAttribute("aria-pressed", String(result.section === section)); tabs.append(tab);
  }
  root.append(tabs);
  const timeBox = card("Reconstructed moment"); root.append(timeBox);
  timeBox.append(el("p", `Time basis: ${result.timeline.time_basis || "not declared; no cross-node clock equivalence assumed"}. Nanosecond coordinates stay exact.`));
  const timeForm = el("form", undefined, "management-form"); const label = el("label", "Moment (nanoseconds)"); const moment = el("input"); moment.name = "time"; moment.value = result.time_ns; moment.inputMode = "numeric"; label.append(moment);
  const apply = el("button", "Apply moment"); apply.type = "submit"; timeForm.append(label, apply);
  timeForm.addEventListener("submit", (event) => { event.preventDefault(); run(async () => { state.analysisTime = analysisNanoseconds(moment.value); state.analysisOffset = 0; await show(); }); }); timeBox.append(timeForm);
  const range = el("input"); range.type = "range"; range.min = "0"; range.max = "1000"; range.step = "1"; range.setAttribute("aria-label", "Reconstruction timeline");
  const start = BigInt(result.timeline.start_ns), end = BigInt(result.timeline.end_ns), selected = BigInt(result.time_ns);
  range.disabled = start === end; range.value = String(end === start ? 1000 : Number((selected - start) * 1000n / (end - start)));
  range.addEventListener("input", () => { moment.value = analysisTimeAt(start, end, Number(range.value)); });
  range.addEventListener("change", () => run(async () => { state.analysisTime = moment.value; state.analysisOffset = 0; await show(); }));
  timeBox.append(range, el("p", `${start} → ${end}`));
  if (result.section !== "summary") {
    const form = el("form", undefined, "management-form"); const searchLabel = el("label", "Search visible fields"); const search = el("input"); search.maxLength = 256; search.value = state.analysisSearch || ""; searchLabel.append(search); const submit = el("button", "Search"); submit.type = "submit"; form.append(searchLabel, submit);
    form.addEventListener("submit", (event) => { event.preventDefault(); run(async () => { state.analysisSearch = search.value; state.analysisOffset = 0; await show(); }); }); root.append(form);
  }
  if (result.section === "events") {
    const form = el("form", undefined, "management-form"); const fields = [];
    for (const [key, labelText, value] of [["start_ns", "Range start (ns)", result.timeline.start_ns], ["end_ns", "Range end (ns)", result.timeline.end_ns]]) {
      const label = el("label", labelText); const input = el("input"); input.name = key; input.value = state.analysisRange?.[key] || value; label.append(input); form.append(label); fields.push(input);
    }
    const apply = el("button", "Filter duration"); apply.type = "submit"; form.append(apply, button("Full duration", async () => { delete state.analysisRange; state.analysisOffset = 0; await show(); }));
    form.addEventListener("submit", (event) => { event.preventDefault(); run(async () => { const [a, b] = fields.map((field) => analysisNanoseconds(field.value)); if (BigInt(a) > BigInt(b)) throw new Error("Enter an ordered integer time range."); state.analysisRange = { start_ns: a, end_ns: b }; state.analysisOffset = 0; await show(); }); }); root.append(form);
  }
  root.append(el("p", `${result.count} shown · ${result.total_count.toLocaleString()} matching ${result.section}.`));
  if (!result.items.length) root.append(el("p", "No matching data for this selection and moment."));
  if (result.section === "summary") {
    const table = el("table"); for (const [key, value] of Object.entries(result.items[0] || {})) { const row = el("tr"); row.append(el("th", key.replaceAll("_", " ")), el("td", typeof value === "object" ? JSON.stringify(value) : value)); table.append(row); } root.append(table);
  } else {
    const list = el("div", undefined, "management-list");
    for (const item of result.items) {
      const row = el("details", undefined, "management-record"); const summary = el("summary");
      const title = item.label || item.resource_id || item.event_name || item.event_type || item.finding_id || item.relation_type || "Observation";
      const observation = result.section === "relationships"
        ? (item.present === true ? "confirmed present" : "presence unknown")
        : item.status || item.outcome || item.severity || item.quality || "details";
      summary.textContent = `${title} · ${observation}${item.timestamp_ns ? ` · ${item.timestamp_ns} ns` : ""}`; row.append(summary, json(item)); list.append(row);
    }
    root.append(list);
    ui.pager(root, result.next_offset, result.offset, async (offset) => { state.analysisOffset = offset; await show(); });
  }
  const capabilities = card("Analysis capabilities"); capabilities.append(el("p", result.capabilities.route.reason), el("p", result.capabilities.topology.reason), el("p", "Use the Fabric and Node pages for the currently configured startup runtime. Those links do not switch to this durable selection.")); root.append(capabilities);
}
export function analysisNanoseconds(value) {
  if (typeof value !== "string" || value.length > 20 || !/^(0|-?[1-9][0-9]*)$/.test(value)
      || BigInt(value) < -9223372036854775808n || BigInt(value) > 9223372036854775807n) {
    throw new TypeError("Use a canonical signed 64-bit integer nanosecond coordinate.");
  }
  return value;
}

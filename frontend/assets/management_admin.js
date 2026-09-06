import { managementVersion } from "./management_controller.js";

const POLICY_VERSION = "router_dump_analyzer.workspace_disclosure_policy.v1";
const NS_MAX = 9223372036854775807n;
const SEQUENCE_MAX = 9007199254740991n;
const CATALOG_CUTOFFS = ["idempotency_before_ns", "snapshot_before_ns", "revision_before_ns", "fixture_before_ns"];
const REVIEW_CUTOFFS = ["tombstone_before_ns", "idempotency_before_ns"];
const PROTECTED_IDS = ["protected_fixture_ids", "protected_revision_ids", "protected_snapshot_ids"];

export function canManageAdministration(context) {
  return context?.can_admin === true;
}

function closedObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${label} must be a JSON object.`);
  }
  if (Object.keys(value).some((key) => !fields.includes(key))) {
    throw new TypeError(`${label} contains unsupported fields.`);
  }
  return value;
}

function decimal(value, label, maximum = NS_MAX) {
  if (value === null) return null;
  if (typeof value !== "string" || value.length > 19 || !/^(0|[1-9][0-9]*)$/.test(value)
      || BigInt(value) > maximum) {
    throw new TypeError(`${label} must be null or a canonical decimal string between 0 and ${maximum}.`);
  }
  return value;
}

function boolean(value, label) {
  if (typeof value !== "boolean") throw new TypeError(`${label} must be true or false.`);
  return value;
}

export function validateDisclosurePolicy(value) {
  const policy = closedObject(value, ["policy_version", "mode", "transports"], "Policy");
  if (policy.policy_version !== POLICY_VERSION || !["disabled", "client_safe", "full_fidelity"].includes(policy.mode)) {
    throw new TypeError("Choose a supported disclosure mode and policy version.");
  }
  if (!Array.isArray(policy.transports) || policy.transports.length > 2
      || policy.transports.some((transport) => !["in_process", "local_subprocess"].includes(transport))
      || new Set(policy.transports).size !== policy.transports.length
      || policy.transports.join() !== [...policy.transports].sort().join()) {
    throw new TypeError("Policy transports must be supported, unique, and lexically sorted.");
  }
  if ((policy.mode === "disabled") !== (policy.transports.length === 0)) {
    throw new TypeError("Disabled mode requires no transports; enabled modes require an explicit transport.");
  }
  return { policy_version: POLICY_VERSION, mode: policy.mode, transports: [...policy.transports] };
}

export function validateRetentionPayload(value) {
  if (typeof value === "string") {
    if (value.length > 1_048_576) throw new RangeError("Retention JSON is too large.");
    value = JSON.parse(value);
  }
  const payload = closedObject(value, ["catalog", "review"], "Retention request");
  const result = {};
  for (const name of ["catalog", "review"]) {
    const cutoffs = name === "catalog" ? CATALOG_CUTOFFS : REVIEW_CUTOFFS;
    const extras = name === "catalog" ? ["preserve_latest_snapshot_per_session", ...PROTECTED_IDS] : ["audit_mode", "audit_before_sequence"];
    const policy = closedObject(payload[name] === undefined ? {} : payload[name], ["enabled", "maximum_candidates", ...cutoffs, ...extras], `${name} policy`);
    const normalized = { enabled: boolean(policy.enabled === undefined ? false : policy.enabled, `${name}.enabled`) };
    for (const field of cutoffs) normalized[field] = decimal(policy[field] === undefined ? null : policy[field], `${name}.${field}`);
    const maximum = policy.maximum_candidates === undefined ? 1000 : policy.maximum_candidates;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 5000) {
      throw new TypeError(`${name}.maximum_candidates must be an integer from 1 to 5000.`);
    }
    normalized.maximum_candidates = maximum;
    if (name === "catalog") {
      normalized.preserve_latest_snapshot_per_session = boolean(policy.preserve_latest_snapshot_per_session === undefined ? true : policy.preserve_latest_snapshot_per_session, "preserve_latest_snapshot_per_session");
      for (const field of PROTECTED_IDS) {
        const ids = policy[field] === undefined ? [] : policy[field];
        if (!Array.isArray(ids) || ids.length > 5000 || new Set(ids).size !== ids.length
            || ids.some((id) => typeof id !== "string" || !id || id.length > 256 || id !== id.trim() || /[\p{C}\p{Zl}\p{Zp}]/u.test(id))) {
          throw new TypeError(`${field} must contain at most 5000 unique, bounded IDs.`);
        }
        normalized[field] = [...ids];
      }
    } else {
      normalized.audit_mode = policy.audit_mode === undefined ? "preserve" : policy.audit_mode;
      normalized.audit_before_sequence = decimal(policy.audit_before_sequence === undefined ? null : policy.audit_before_sequence, "audit_before_sequence", SEQUENCE_MAX);
      if (!["preserve", "prune_explicit"].includes(normalized.audit_mode)
          || (normalized.audit_mode === "preserve") !== (normalized.audit_before_sequence === null)) {
        throw new TypeError("Audit pruning requires prune_explicit and an explicit audit_before_sequence; preserve requires no cutoff.");
      }
    }
    result[name] = normalized;
  }
  if (new TextEncoder().encode(JSON.stringify(result)).length > 1_048_576) throw new RangeError("Retention JSON exceeds the request limit.");
  return result;
}

export function retentionPreviewSummary(result) {
  const inventories = [result?.catalog?.inventory ?? result?.catalog, result?.review?.inventory ?? result?.review];
  const valid = result?.executed === false && result?.observation_mode === "best_effort_preview";
  const knownInventories = inventories.every((item) => typeof item?.policy?.enabled === "boolean" && Array.isArray(item?.candidates) && Number.isSafeInteger(item?.total_candidate_count) && item.total_candidate_count >= 0);
  return {
    valid,
    complete: valid && knownInventories && inventories.every((item) => item?.truncated === false) && result?.ingestion?.truncated === false && typeof result?.ingestion?.policy_enabled === "boolean",
    enabled: inventories.some((item) => item?.policy?.enabled === true) || result?.ingestion?.policy_enabled === true,
    candidateCount: inventories.reduce((total, item) => total + (Number.isSafeInteger(item?.total_candidate_count) ? item.total_candidate_count : 0), 0),
    eligibleShown: inventories.reduce((total, item) => total + (Array.isArray(item?.candidates) ? item.candidates.filter((candidate) => Array.isArray(candidate.blockers) && candidate.blockers.length === 0).length : 0), 0),
    hostInventory: result?.ingestion?.host_storage_orphan_inventory === "bounded_host_scan" ? "bounded host scan" : "not observed",
  };
}

export async function renderAdministration(ui) {
  const { content, client, state, path, el, card, json, button, message } = ui;
  function detail(label, value) {
    const section = el("details");
    section.append(el("summary", label), json(value));
    return section;
  }
  const root = el("div", undefined, "management-list-admin");
  content.append(root);
  const serial = state.serial; const generation = client.generation;
  const project = state.project; const workspace = state.workspace;
  const current = () => root.isConnected && serial === state.serial && generation === client.generation && project === state.project && workspace === state.workspace;
  const requireAdmin = () => {
    if (!current()) throw new Error("Scope changed; reopen Administration before acting.");
    if (!canManageAdministration(state.context)) throw new Error("The separate tenant-administrator capability is required.");
  };
  const settings = card("Deployment configuration — read only");
  settings.append(el("p", "Deployment configuration is owned by the host operator and cannot be edited here. No paths, credentials, environment variables, or raw settings are exposed."));
  const facts = el("table");
  for (const [name, value] of [
    ["Control plane", state.context?.enabled === true ? "Enabled" : "Unavailable"],
    ["Identity", state.context?.identity_mode === "trusted_headers" ? "Local trusted headers (not authentication)" : "Deployment-managed identity"],
    ["Workspace access", state.context?.can_write === true ? "Read and write" : "Read only"],
    ["Tenant administration", canManageAdministration(state.context) ? "Granted" : "Not granted"],
    ["Instance operator", state.context?.can_instance_operator === true ? "Granted separately" : "Not granted"],
  ]) {
    const row = el("tr");
    row.append(el("th", name), el("td", value));
    facts.append(row);
  }
  settings.append(facts);
  root.append(settings);
  if (!state.context || !project || !workspace) {
    root.append(el("p", "Connect and select a project and workspace for policy and retention administration."));
    return;
  }
  const admin = canManageAdministration(state.context);
  const policyPath = path("private-analysis-policy");
  const retentionPath = path("retention");
  const policyCard = card("Workspace private-analysis disclosure policy");
  const policyStatus = el("p", "Loading the current policy…");
  const policyDetail = el("div");
  const policyForm = el("div", undefined, "management-form");
  function field(parent, label, node) { const holder = el("label", label); holder.append(node); parent.append(holder); return node; }
  function checkbox(parent, label, checked = false) { const node = el("input"); node.type = "checkbox"; node.checked = checked; node.style.width = "auto"; return field(parent, label, node); }
  function textField(parent, label, value = "") { const node = el("input"); node.type = "text"; node.value = value; node.inputMode = "numeric"; return field(parent, label, node); }
  const mode = field(policyForm, "Disclosure mode", el("select"));
  for (const value of ["disabled", "client_safe", "full_fidelity"]) { const option = el("option", value.replaceAll("_", " ")); option.value = value; mode.append(option); }
  mode.value = "disabled";
  const inProcess = checkbox(policyForm, "Allow in-process runners");
  const subprocess = checkbox(policyForm, "Allow local subprocess runners");
  const policyConfirm = checkbox(policyForm, `I confirm this disclosure-policy change for workspace ${workspace}.`);
  let loadedPolicy = null; let policyFresh = false; let policyBusy = false;
  function policyControls() {
    mode.disabled = !admin || !loadedPolicy || policyBusy;
    inProcess.disabled = subprocess.disabled = mode.disabled || mode.value === "disabled";
    policyConfirm.disabled = !admin || !policyFresh || policyBusy;
    savePolicy.disabled = !admin || !policyFresh || policyBusy || !policyConfirm.checked || client.uncertain;
  }
  const savePolicy = button("Save confirmed policy", async () => {
    requireAdmin();
    if (!policyFresh || !loadedPolicy || !policyConfirm.checked) throw new Error("Refresh and explicitly confirm the policy before saving.");
    const body = validateDisclosurePolicy({ policy_version: POLICY_VERSION, mode: mode.value, transports: [inProcess.checked ? "in_process" : null, subprocess.checked ? "local_subprocess" : null].filter(Boolean) });
    policyBusy = true; policyControls();
    try {
      const result = await client.request(policyPath, { method: "PUT", version: loadedPolicy.version, body });
      if (!current()) return;
      applyPolicy(result);
      message("Disclosure policy saved. Any further change requires another confirmation.");
    } catch (error) {
      if (current()) { policyFresh = false; policyConfirm.checked = false; policyStatus.textContent = "Save did not complete with a verified response. Refresh the policy and review it before another confirmation; no automatic retry was made."; }
      throw error;
    } finally { policyBusy = false; if (current()) policyControls(); }
  }, true);
  function applyPolicy(record) {
    const value = validateDisclosurePolicy(record.policy); managementVersion(record.version);
    loadedPolicy = record; policyFresh = true; policyConfirm.checked = false;
    mode.value = value.mode; inProcess.checked = value.transports.includes("in_process"); subprocess.checked = value.transports.includes("local_subprocess");
    policyStatus.textContent = `Version ${record.version} · ${record.explicit === true ? "Explicit workspace policy" : "Fail-closed default (not explicitly configured)"}`;
    policyDetail.replaceChildren(detail("Current policy document", { version: record.version, explicit: record.explicit === true, policy: value }));
    policyControls();
  }
  async function loadPolicy() {
    if (!current() || policyBusy) return;
    policyBusy = true; policyControls();
    try { const value = await client.request(policyPath); if (current()) applyPolicy(value); }
    finally { policyBusy = false; if (current()) policyControls(); }
  }
  for (const control of [mode, inProcess, subprocess]) control.addEventListener("change", () => {
    policyConfirm.checked = false;
    if (mode.value === "disabled") { inProcess.checked = false; subprocess.checked = false; }
    policyControls();
  });
  policyConfirm.addEventListener("change", policyControls);
  policyCard.append(policyStatus, el("p", "Disabled is fail closed. Client-safe mode restricts evidence disclosure. Full fidelity authorizes proprietary workspace evidence for approved private runners; it never overrides never_assistant declarations. Saving never starts a run."), policyDetail, policyForm, savePolicy, button("Refresh policy", loadPolicy));
  if (!admin) policyCard.append(el("p", "Policy editing and retention require tenant-administrator permission. Write or instance-operator permission alone is insufficient."));
  root.append(policyCard);
  policyControls();

  if (admin) {
    const retention = card("Workspace retention — preview before deletion");
    retention.append(el("p", "Catalog and review retention are disabled by default. Enable only the desired stores and enter explicit cutoffs as exact nanosecond decimal strings, for example 1750000000000000000. Blank cutoffs mean no cutoff for that category. Ingestion retention uses deployment-owned policy and cannot be changed here."));
    const forms = el("div", undefined, "management-grid");
    const controls = {};
    for (const [name, cutoffs] of [["catalog", CATALOG_CUTOFFS], ["review", REVIEW_CUTOFFS]]) {
      const group = card(name === "catalog" ? "Catalog retention" : "Review retention");
      const form = el("div", undefined, "management-form");
      controls[name] = { enabled: checkbox(form, `Enable ${name} retention`), maximum_candidates: textField(form, "Maximum candidates (1–5000)", "1000") };
      for (const cutoff of cutoffs) controls[name][cutoff] = textField(form, cutoff.replaceAll("_", " "));
      if (name === "catalog") controls[name].preserve_latest_snapshot_per_session = checkbox(form, "Preserve the latest snapshot of each session", true);
      group.append(form); forms.append(group);
    }
    const advanced = el("details"); advanced.append(el("summary", "Advanced protected IDs and explicit audit pruning"));
    const extra = field(advanced, "Optional JSON: catalog protected_*_ids arrays; review audit_mode and audit_before_sequence only", el("textarea"));
    extra.rows = 7; extra.value = '{\n  "catalog": {},\n  "review": { "audit_mode": "preserve" }\n}';
    advanced.append(el("p", "To prune review audit records, explicitly select prune_explicit and supply audit_before_sequence as a canonical decimal string. Protected IDs supplement live server-side reference protections."));
    const previewOutput = el("div"); const executionOutput = el("div");
    const confirmation = el("div", undefined, "management-form");
    const acknowledge = checkbox(confirmation, "I reviewed the preview and understand execution rechecks live references and policy; the preview is advisory, not an atomic plan.");
    const typedWorkspace = textField(confirmation, `Type the exact workspace ID to authorize deletion: ${workspace}`); typedWorkspace.inputMode = "text";
    let preview = null; let edit = 0; let busy = false;
    function retentionBody() {
      if (extra.value.length > 1_048_576) throw new RangeError("Advanced retention JSON is too large.");
      const additions = closedObject(JSON.parse(extra.value || "{}"), ["catalog", "review"], "Advanced retention JSON");
      closedObject(additions.catalog ?? {}, PROTECTED_IDS, "Advanced catalog policy");
      closedObject(additions.review ?? {}, ["audit_mode", "audit_before_sequence"], "Advanced review policy");
      const body = {};
      for (const [name, cutoffs] of [["catalog", CATALOG_CUTOFFS], ["review", REVIEW_CUTOFFS]]) {
        const limit = controls[name].maximum_candidates.value;
        if (!/^[1-9][0-9]{0,3}$/.test(limit)) throw new TypeError("Maximum candidates must be an integer from 1 to 5000.");
        body[name] = { ...additions[name], enabled: controls[name].enabled.checked, maximum_candidates: Number(limit) };
        for (const cutoff of cutoffs) body[name][cutoff] = controls[name][cutoff].value === "" ? null : controls[name][cutoff].value;
      }
      body.catalog.preserve_latest_snapshot_per_session = controls.catalog.preserve_latest_snapshot_per_session.checked;
      return validateRetentionPayload(body);
    }
    function retentionControls() {
      execute.disabled = busy || !preview || !preview.summary.complete || !preview.summary.enabled || !acknowledge.checked || typedWorkspace.value !== workspace || client.uncertain;
      previewButton.disabled = busy;
    }
    function invalidatePreview() { edit++; preview = null; acknowledge.checked = false; typedWorkspace.value = ""; retentionControls(); }
    const previewButton = button("Preview retention (no deletion)", async () => {
      requireAdmin(); const body = retentionBody(); const edited = edit;
      preview = null; acknowledge.checked = false; typedWorkspace.value = ""; busy = true; retentionControls();
      try {
        const result = await client.request(`${retentionPath}/preview`, { method: "POST", mutation: false, body });
        if (!current() || edit !== edited) return;
        const summary = retentionPreviewSummary(result);
        if (!summary.valid) throw new Error("The server did not return a verified non-executing retention preview.");
        preview = { body: JSON.stringify(body), summary };
        previewOutput.replaceChildren(el("h4", "Advisory preview and completeness"), el("p", `${summary.candidateCount} catalog/review candidates; ${summary.eligibleShown} displayed candidates without blockers. ${summary.complete ? "No truncation reported in this bounded workspace observation." : "Inventory is truncated or its completeness is unknown. Narrow the cutoffs or adjust the bound and preview again; execution is disabled."} Host-global orphan inventory: ${summary.hostInventory}. This is not proof of a complete host inventory.`), el("p", summary.enabled ? "Execution re-evaluates current protected references and live policy." : "All observed retention policies are disabled. An empty result is not a cleanup proof; execution is disabled."), detail("Candidate inventory and blockers", result));
      } finally { busy = false; if (current()) retentionControls(); }
    });
    const execute = button("Execute confirmed retention", async () => {
      requireAdmin();
      const body = retentionBody();
      if (busy || !preview || !preview.summary.complete || !preview.summary.enabled || !acknowledge.checked || typedWorkspace.value !== workspace || JSON.stringify(body) !== preview.body) {
        throw new Error("Preview this exact request, review completeness, acknowledge the warning, and type the workspace ID before execution.");
      }
      busy = true; preview = null; acknowledge.checked = false; typedWorkspace.value = ""; retentionControls();
      try {
        const result = await client.request(`${retentionPath}/execute`, { method: "POST", body });
        if (!current()) return;
        executionOutput.replaceChildren(el("h4", "Retention execution response"), json(result));
        message("Retention response received. Inspect deletion counts, failures, and the audit; preview and confirmation are required for any new operation.");
      } catch (error) {
        if (current()) executionOutput.replaceChildren(el("p", "Execution did not return a verified result. Inspect retention audit and server state before any further action. No retry was made; uncertain writes remain blocked by the shared client."));
        throw error;
      } finally { busy = false; if (current()) retentionControls(); }
    }, true, true);
    forms.addEventListener("input", invalidatePreview); forms.addEventListener("change", invalidatePreview); extra.addEventListener("input", invalidatePreview);
    acknowledge.addEventListener("change", retentionControls); typedWorkspace.addEventListener("input", retentionControls);
    retention.append(forms, advanced, previewButton, previewOutput, confirmation, execute, executionOutput);
    retentionControls(); root.append(retention);

    const audit = card("Retention audit — bounded journals"); const auditOutput = el("div");
    audit.append(el("p", "Catalog and review journals have independent continuation cursors. Ingestion shows only its latest bounded entries and has no history continuation. A page is not a complete audit history."));
    let auditPage = null; let auditSerial = 0; let catalogCursor = "0"; let reviewCursor = "0";
    async function loadAudit(catalog = "0", review = "0") {
      requireAdmin(); const token = ++auditSerial;
      decimal(catalog, "catalog audit cursor", SEQUENCE_MAX); decimal(review, "review audit cursor", SEQUENCE_MAX);
      const page = await client.request(`${retentionPath}/audit?limit=100&catalog_after_sequence=${catalog}&review_after_sequence=${review}`);
      if (!current() || token !== auditSerial) return;
      auditPage = page; catalogCursor = catalog; reviewCursor = review;
      auditOutput.replaceChildren(json(page));
      nextCatalog.disabled = !Number.isSafeInteger(page.catalog_next_after_sequence) || page.catalog_next_after_sequence <= Number(catalog);
      nextReview.disabled = !Number.isSafeInteger(page.review_next_after_sequence) || page.review_next_after_sequence <= Number(review);
    }
    const nextCatalog = button("Next catalog audit page", () => loadAudit(String(auditPage.catalog_next_after_sequence), reviewCursor), true);
    const nextReview = button("Next review audit page", () => loadAudit(catalogCursor, String(auditPage.review_next_after_sequence)), true);
    audit.append(button("Load / refresh retention audit", () => loadAudit()), nextCatalog, nextReview, auditOutput); root.append(audit);
  }
  try { await loadPolicy(); } catch (error) { if (current()) { policyStatus.textContent = `Policy could not be loaded: ${error.message}`; message(error.message, true); } }
}

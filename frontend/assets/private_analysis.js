import {
  StalePrivateAnalysisResponseError,
  createPrivateAnalysisController,
  privateAnalysisSubmissionAvailable,
  privateAnalysisSubmissionUnavailableReason,
} from "./private_analysis_controller.js";

const element = (id) => document.getElementById(id);
const scopeForm = element("pa-scope-form");
const runForm = element("pa-run-form");
const reloadForm = element("pa-reload-form");
const status = element("pa-status");
const compose = element("pa-compose");
const revisionsHost = element("pa-revisions");
const revisionCount = element("pa-revision-count");
const taskSelect = element("pa-task");
const runnerSelect = element("pa-runner");
const submitButton = element("pa-submit");
const clockSelect = element("pa-clock");
const timeField = element("pa-time-field");
const cancelButton = element("pa-cancel");
const runSummary = element("pa-run-summary");
const runState = element("pa-run-state");
const runFacts = element("pa-run-facts");
const results = element("pa-results");

function appendText(parent, tag, value, className = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value ?? "");
  parent.append(node);
  return node;
}

function emptyMessage(parent, message) {
  appendText(parent, "p", message, "pa-empty");
}

function showStatus(message, { error = false, focus = false } = {}) {
  status.textContent = String(message || "");
  status.dataset.error = String(error);
  if (focus) status.focus({ preventScroll: false });
}

function renderSubmissionAvailability(snapshot) {
  const available = privateAnalysisSubmissionAvailable(snapshot);
  submitButton.disabled = !available;
  if (available) {
    submitButton.removeAttribute("title");
  } else {
    submitButton.title = privateAnalysisSubmissionUnavailableReason(snapshot);
  }
}

function selectedRevisionIds() {
  return [...revisionsHost.querySelectorAll("input[type=checkbox]:checked")]
    .map((input) => input.value);
}

function updateRevisionCount() {
  const count = selectedRevisionIds().length;
  revisionCount.textContent = `${count} selected`;
  for (const input of revisionsHost.querySelectorAll("input[type=checkbox]")) {
    input.disabled = !input.checked && count >= 128;
  }
}

function replaceOptions(select, values, { value, label }) {
  const options = values.map((item) => {
    const option = document.createElement("option");
    option.value = value(item);
    option.textContent = label(item);
    return option;
  });
  select.replaceChildren(...options);
  select.disabled = options.length === 0;
}

function renderDiscovery(snapshot) {
  if (snapshot.phase !== "ready") return;
  const capabilities = Array.isArray(snapshot.capabilities?.capabilities)
    ? snapshot.capabilities.capabilities
    : [];
  replaceOptions(taskSelect, capabilities, {
    value: (item) => item.id,
    label: (item) => item.label,
  });
  replaceOptions(runnerSelect, snapshot.runners, {
    value: (item) => `${item.runner_id}\u0000${item.runner_version}`,
    label: (item) => `${item.runner_id} · ${item.runner_version} · ${item.transport}`,
  });
  const revisionNodes = snapshot.revisions.map((revision) => {
    const label = document.createElement("label");
    label.className = "pa-revision-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = revision.revision_id;
    input.addEventListener("change", updateRevisionCount);
    const copy = document.createElement("span");
    appendText(copy, "strong", revision.node_id);
    appendText(copy, "small", revision.revision_id);
    label.append(input, copy);
    return label;
  });
  revisionsHost.replaceChildren(...revisionNodes);
  updateRevisionCount();
  compose.hidden = false;
  const firstRevision = revisionsHost.querySelector("input");
  if (firstRevision) firstRevision.focus({ preventScroll: true });
}

function fact(label, value) {
  const container = document.createElement("div");
  appendText(container, "dt", label);
  appendText(container, "dd", value);
  return container;
}

function renderRun(run, cancelLocked) {
  if (!run) {
    runSummary.hidden = true;
    runState.textContent = "";
    runFacts.replaceChildren();
    element("pa-run-id").value = "";
    cancelButton.disabled = true;
    return;
  }
  runSummary.hidden = false;
  runState.textContent = run.cleanup_pending
    ? `${run.state} · cleanup pending`
    : run.state;
  runFacts.replaceChildren(
    fact("Run ID", run.run_id),
    fact("Version", run.version),
    fact("Task", run.task_kind),
    fact("Revisions", Array.isArray(run.revision_ids) ? run.revision_ids.length : 0),
    fact("Created (ns)", run.created_at_ns),
    fact("Updated (ns)", run.updated_at_ns),
    fact("Request digest", run.request_digest),
    fact("Outcome digest", run.outcome_digest || "not available"),
  );
  element("pa-run-id").value = run.run_id;
  cancelButton.disabled = Boolean(cancelLocked || (run.terminal && !run.cleanup_pending));
}

function citationList(citations) {
  const list = document.createElement("ul");
  list.className = "pa-citation-list";
  for (const citation of Array.isArray(citations) ? citations : []) {
    const item = document.createElement("li");
    const reference = document.createElement("code");
    reference.textContent = citation.evidence_reference_digest;
    const citationIdentity = document.createElement("code");
    citationIdentity.textContent = citation.citation_digest;
    item.append(reference, document.createTextNode(" · "), citationIdentity);
    list.append(item);
  }
  return list;
}

function renderClaim(claim) {
  const article = document.createElement("article");
  article.className = "pa-claim";
  appendText(article, "p", claim.text);
  appendText(article, "code", claim.claim_id);
  article.append(citationList(claim.citations));
  return article;
}

function decisionReceipt(decision, recovering) {
  const receipt = document.createElement("section");
  receipt.className = "pa-decision-receipt";
  receipt.setAttribute("aria-label", "Durable human review decision");
  appendText(
    receipt,
    "strong",
    `${decision.disposition} · ${decision.state}`,
  );
  appendText(receipt, "p", decision.rationale || "No review rationale supplied.");
  appendText(
    receipt,
    "code",
    decision.target_id
      ? `${decision.target_kind} · ${decision.target_id}`
      : `decision · ${decision.decision_id}`,
  );
  appendText(receipt, "small", `Human actor: ${decision.actor}`);
  if (decision.state === "pending" && decision.disposition === "promote") {
    const recover = document.createElement("button");
    recover.type = "button";
    recover.className = "secondary-action";
    recover.textContent = recovering ? "Recovering…" : "Resume pending promotion";
    recover.disabled = recovering;
    recover.addEventListener("click", async () => {
      try {
        await controller.recoverDecision(decision.decision_id);
      } catch (error) {
        if (error instanceof StalePrivateAnalysisResponseError) return;
        showStatus(error.message || "Promotion recovery failed.", { error: true, focus: true });
      }
    });
    receipt.append(recover);
  }
  return receipt;
}

function renderProposal(proposal, {
  decision,
  reviewAvailable,
  reviewing,
  recovering,
}) {
  const article = document.createElement("article");
  article.className = "pa-proposal";
  appendText(article, "h4", `${proposal.title} · not applied`);
  appendText(article, "p", proposal.rationale);
  appendText(article, "code", `${proposal.kind} · ${proposal.confidence_basis_points} basis points`);
  appendText(article, "code", proposal.proposal_digest, "pa-proposal-digest");
  appendText(article, "pre", JSON.stringify(proposal.payload ?? null));
  article.append(citationList(proposal.citations));
  if (decision) {
    article.append(decisionReceipt(decision, recovering));
    return article;
  }
  if (!reviewAvailable) {
    appendText(
      article,
      "p",
      "Review actions are unavailable. Reload the exact terminal run before deciding.",
      "pa-review-unavailable",
    );
    return article;
  }
  const details = document.createElement("details");
  details.className = "pa-proposal-review";
  const summary = document.createElement("summary");
  summary.textContent = reviewing ? "Recording durable decision…" : "Record human decision";
  details.append(summary);
  const form = document.createElement("form");
  form.className = "pa-proposal-review-form";
  const dispositionLabel = document.createElement("label");
  dispositionLabel.textContent = "Decision";
  const disposition = document.createElement("select");
  for (const [value, label] of [
    ["reject", "Reject proposal"],
    ["promote", "Promote a separately authored target"],
  ]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    disposition.append(option);
  }
  dispositionLabel.append(disposition);
  const rationaleLabel = document.createElement("label");
  rationaleLabel.textContent = "Human rationale";
  const rationale = document.createElement("textarea");
  rationale.rows = 4;
  rationale.maxLength = 65_536;
  rationale.placeholder = "Record what you verified and why this decision is justified.";
  rationaleLabel.append(rationale);
  const targetLabel = document.createElement("label");
  targetLabel.className = "pa-promotion-target";
  targetLabel.hidden = true;
  targetLabel.textContent = "Human-authored target JSON";
  const target = document.createElement("textarea");
  target.rows = 10;
  target.placeholder = [
    "Create an annotation or manual_event_correlation target from your own review.",
    "The model proposal payload is never copied into this field automatically.",
  ].join("\n");
  targetLabel.append(target);
  const acknowledgementLabel = document.createElement("label");
  acknowledgementLabel.className = "pa-review-acknowledgement";
  const acknowledgement = document.createElement("input");
  acknowledgement.type = "checkbox";
  acknowledgement.required = true;
  acknowledgementLabel.append(
    acknowledgement,
    document.createTextNode(
      " I reviewed the cited evidence and understand this final decision is durable.",
    ),
  );
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.className = "secondary-action";
  submit.textContent = reviewing ? "Recording…" : "Record once";
  submit.disabled = reviewing;
  for (const control of [disposition, rationale, target, acknowledgement]) {
    control.disabled = reviewing;
  }
  disposition.addEventListener("change", () => {
    const promoted = disposition.value === "promote";
    targetLabel.hidden = !promoted;
    target.required = promoted;
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!acknowledgement.checked) return;
    let targetDocument = null;
    if (disposition.value === "promote") {
      try {
        targetDocument = JSON.parse(target.value);
      } catch (_error) {
        showStatus("Human-authored promotion target must be valid JSON.", { error: true, focus: true });
        return;
      }
      if (!targetDocument || typeof targetDocument !== "object" || Array.isArray(targetDocument)) {
        showStatus("Human-authored promotion target must be a JSON object.", { error: true, focus: true });
        return;
      }
    }
    try {
      await controller.decideProposal(proposal.proposal_id, {
        disposition: disposition.value,
        rationale: rationale.value,
        target: targetDocument,
      });
    } catch (error) {
      if (error instanceof StalePrivateAnalysisResponseError) return;
      showStatus(error.message || "Proposal review failed.", { error: true, focus: true });
    }
  });
  form.append(
    dispositionLabel,
    rationaleLabel,
    targetLabel,
    acknowledgementLabel,
    submit,
  );
  details.append(form);
  article.append(details);
  return article;
}

function renderEvidenceReference(reference) {
  const article = document.createElement("article");
  article.className = "pa-citation";
  appendText(article, "code", reference.reference_digest);
  const revision = reference.revision || {};
  const producer = reference.producer || {};
  const timeRange = reference.time_range || {};
  appendText(article, "p", `${revision.node_id || "unknown node"} · ${revision.revision_id || "unknown revision"}`);
  appendText(article, "p", `${reference.kind || "unknown kind"} · ${reference.evidence_class || "unknown class"} · ${reference.fact_provenance || "unknown provenance"}`);
  appendText(article, "p", `${producer.authority || "unknown authority"} · ${producer.producer_id || "unknown producer"} · ${reference.subject_kind || "unknown subject"}`);
  appendText(article, "p", `${reference.payload_schema || "unknown schema"} · ${timeRange.basis || "unknown time basis"} · ${timeRange.start_ns ?? "open"}…${timeRange.end_ns ?? "open"}`);
  return article;
}

function renderReport(
  report,
  decisions = [],
  reviewAvailable = false,
  reviewingProposalIds = [],
  recoveringDecisionIds = [],
) {
  if (!report) {
    results.hidden = true;
    element("pa-result-kind").textContent = "";
    element("pa-report-query").textContent = "";
    for (const id of ["pa-supported", "pa-hypotheses", "pa-proposals", "pa-citations"]) {
      element(id).replaceChildren();
    }
    return;
  }
  results.hidden = false;
  const outcome = report.outcome || {};
  element("pa-report-query").textContent = `Submitted query: ${report.query || ""}`;
  element("pa-result-kind").textContent = outcome.kind === "result"
    ? "Validated evidence result."
    : `Validated terminal error: ${outcome.error?.stage || "unknown stage"} · ${outcome.error?.code || "unknown code"}.`;
  const supportedHost = element("pa-supported");
  const hypothesesHost = element("pa-hypotheses");
  const proposalsHost = element("pa-proposals");
  const citationsHost = element("pa-citations");
  supportedHost.replaceChildren();
  hypothesesHost.replaceChildren();
  proposalsHost.replaceChildren();
  citationsHost.replaceChildren();
  const result = outcome.result;
  if (result) {
    const claims = [result.summary, ...(Array.isArray(result.claims) ? result.claims : [])]
      .filter(Boolean);
    for (const claim of claims) {
      if (claim.support === "evidence_supported") {
        supportedHost.append(renderClaim(claim));
      } else if (claim.support === "unsupported_hypothesis") {
        hypothesesHost.append(renderClaim(claim));
      }
    }
    for (const proposal of Array.isArray(result.proposals) ? result.proposals : []) {
      const decision = decisions.find(
        (item) => item.proposal_id === proposal.proposal_id,
      );
      proposalsHost.append(renderProposal(proposal, {
        decision,
        reviewAvailable,
        reviewing: reviewingProposalIds.includes(proposal.proposal_id),
        recovering: recoveringDecisionIds.includes(decision?.decision_id),
      }));
    }
  }
  if (!supportedHost.childElementCount) emptyMessage(supportedHost, "No evidence-supported claims were returned.");
  if (!hypothesesHost.childElementCount) emptyMessage(hypothesesHost, "No unsupported hypotheses were returned.");
  if (!proposalsHost.childElementCount) emptyMessage(proposalsHost, "No proposals were returned.");
  for (const reference of Array.isArray(report.evidence_references) ? report.evidence_references : []) {
    citationsHost.append(renderEvidenceReference(reference));
  }
  if (!citationsHost.childElementCount) emptyMessage(citationsHost, "No cited evidence references were returned.");
  element("pa-results-title").focus({ preventScroll: false });
}

let lastDiscovery = null;
const controller = createPrivateAnalysisController({
  onChange(snapshot) {
    showStatus(snapshot.message);
    renderSubmissionAvailability(snapshot);
    if (snapshot.phase === "ready" && snapshot !== lastDiscovery) {
      lastDiscovery = snapshot;
      renderDiscovery(snapshot);
    }
    renderRun(snapshot.run, snapshot.cancelLocked);
    renderReport(
      snapshot.report,
      snapshot.decisions,
      snapshot.reviewAvailable,
      snapshot.reviewingProposalIds,
      snapshot.recoveringDecisionIds,
    );
  },
});

scopeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  compose.hidden = true;
  runForm.reset();
  revisionsHost.replaceChildren();
  taskSelect.replaceChildren();
  runnerSelect.replaceChildren();
  timeField.hidden = true;
  lastDiscovery = null;
  try {
    await controller.connect({
      tenantId: element("pa-tenant").value,
      projectId: element("pa-project").value,
      workspaceId: element("pa-workspace").value,
      principalId: element("pa-principal").value,
    });
  } catch (error) {
    if (error instanceof StalePrivateAnalysisResponseError) return;
    showStatus(error.message || "Workspace discovery failed.", { error: true, focus: true });
  }
});

element("pa-disconnect").addEventListener("click", () => {
  controller.disconnect();
  scopeForm.reset();
  runForm.reset();
  reloadForm.reset();
  compose.hidden = true;
  revisionsHost.replaceChildren();
  results.hidden = true;
  runSummary.hidden = true;
  element("pa-tenant").focus();
});

clockSelect.addEventListener("change", () => {
  timeField.hidden = clockSelect.value === "latest_per_revision";
  element("pa-time").required = !timeField.hidden;
});

runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const [runnerId, runnerVersion] = runnerSelect.value.split("\u0000");
  try {
    await controller.submit({
      revisionIds: selectedRevisionIds(),
      runner: { runner_id: runnerId, runner_version: runnerVersion },
      taskKind: taskSelect.value,
      query: element("pa-query").value,
      clockMode: clockSelect.value,
      selectedTimeNs: timeField.hidden ? null : element("pa-time").value,
    });
  } catch (error) {
    if (error instanceof StalePrivateAnalysisResponseError) return;
    showStatus(error.message || "Private-analysis submission failed.", { error: true, focus: true });
  }
});

reloadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await controller.reload(element("pa-run-id").value);
  } catch (error) {
    if (error instanceof StalePrivateAnalysisResponseError) return;
    showStatus(error.message || "Run lookup failed.", { error: true, focus: true });
  }
});

cancelButton.addEventListener("click", async () => {
  try {
    await controller.cancel();
  } catch (error) {
    if (error instanceof StalePrivateAnalysisResponseError) return;
    showStatus(error.message || "Cancellation failed.", { error: true, focus: true });
  }
});

window.addEventListener("pagehide", () => controller.disconnect(), { once: true });

import {
  ControlPlaneRequestError,
  requestControlPlane,
} from "./durable_review_controller.js";

export const CONTROL_PLANE_PREFIX = "/v1/control-plane";
export const PRIVATE_ANALYSIS_MAX_REVISIONS = 128;
export const PRIVATE_ANALYSIS_POLL_DELAYS_MS = Object.freeze([
  250, 500, 1_000, 2_000, 4_000, 8_000,
]);

const TOKEN_PATTERN = /^[^\u0000-\u001f\u007f/?#]+$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const SIGNED_DECIMAL_PATTERN = /^(?:0|-?[1-9][0-9]*)$/;
const STRONG_ETAG_PATTERN = /^"(0|[1-9][0-9]*)"$/;
const SHA256_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const PROPOSAL_REVIEW_CONTRACT = "router_dump_analyzer.private_analysis.proposal_review.v1";
const PRIVATE_ANALYSIS_JSON_MAX_DEPTH = 32;
const PRIVATE_ANALYSIS_JSON_MAX_NODES = 50_000;
const PRIVATE_ANALYSIS_JSON_MAX_STRING_LENGTH = 1_048_576;

export class StalePrivateAnalysisResponseError extends Error {
  constructor(message = "A stale private-analysis response was ignored.") {
    super(message);
    this.name = "StalePrivateAnalysisResponseError";
  }
}

function token(value, label, maximum = 256) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value !== value.trim()
    || !TOKEN_PATTERN.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty token`);
  }
  return value;
}

function exactObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function detachedFrozenJson(value, label) {
  const budget = { nodes: 0 };
  const ancestors = new Set();
  const copy = (candidate, depth) => {
    budget.nodes += 1;
    if (budget.nodes > PRIVATE_ANALYSIS_JSON_MAX_NODES) {
      throw new RangeError(`${label} exceeds the browser JSON node limit`);
    }
    if (candidate === null || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "string") {
      if (candidate.length > PRIVATE_ANALYSIS_JSON_MAX_STRING_LENGTH) {
        throw new RangeError(`${label} contains an oversized string`);
      }
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate)) {
        throw new TypeError(`${label} contains a non-finite number`);
      }
      return candidate;
    }
    if (!candidate || typeof candidate !== "object") {
      throw new TypeError(`${label} contains a non-JSON value`);
    }
    if (depth >= PRIVATE_ANALYSIS_JSON_MAX_DEPTH) {
      throw new RangeError(`${label} exceeds the browser JSON depth limit`);
    }
    if (ancestors.has(candidate)) {
      throw new TypeError(`${label} contains a cyclic value`);
    }
    ancestors.add(candidate);
    try {
      if (Array.isArray(candidate)) {
        return Object.freeze(candidate.map((item) => copy(item, depth + 1)));
      }
      const prototype = Object.getPrototypeOf(candidate);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError(`${label} contains a non-JSON object`);
      }
      const descriptors = Object.getOwnPropertyDescriptors(candidate);
      const keys = Object.keys(candidate);
      if (
        Reflect.ownKeys(descriptors).length !== keys.length
        || keys.some((key) => !("value" in descriptors[key]) || !descriptors[key].enumerable)
      ) {
        throw new TypeError(`${label} contains accessor or hidden properties`);
      }
      const result = {};
      for (const key of keys) {
        if (key.length > 512) throw new RangeError(`${label} contains an oversized key`);
        result[key] = copy(descriptors[key].value, depth + 1);
      }
      return Object.freeze(result);
    } finally {
      ancestors.delete(candidate);
    }
  };
  return copy(value, 0);
}

function normalizedCapabilities(value) {
  const result = exactObject(
    detachedFrozenJson(value, "private-analysis capabilities"),
    "private-analysis capabilities",
  );
  if (typeof result.enabled !== "boolean" || !Array.isArray(result.capabilities)) {
    throw new TypeError("private-analysis capabilities are malformed");
  }
  const identifiers = new Set();
  for (const capability of result.capabilities) {
    const item = exactObject(capability, "private-analysis task capability");
    const identifier = token(item.id, "private-analysis task id");
    token(item.label, "private-analysis task label", 512);
    if (identifiers.has(identifier)) {
      throw new TypeError("private-analysis task capabilities contain duplicate ids");
    }
    identifiers.add(identifier);
  }
  return result;
}

function normalizedRunners(value) {
  const page = exactObject(
    detachedFrozenJson(value, "private-analysis runner page"),
    "private-analysis runner page",
  );
  if (!Array.isArray(page.items)) {
    throw new TypeError("private-analysis runner page must contain an items array");
  }
  const identities = new Set();
  for (const runner of page.items) {
    const item = exactObject(runner, "private-analysis runner");
    const identity = `${token(item.runner_id, "runner_id")}\u0000${token(item.runner_version, "runner_version")}`;
    token(item.transport, "runner transport");
    if (identities.has(identity)) {
      throw new TypeError("private-analysis runners contain duplicate identities");
    }
    identities.add(identity);
  }
  return page.items;
}

function decimalBigInt(value, label) {
  if (typeof value !== "string" || !DECIMAL_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a canonical decimal string`);
  }
  return BigInt(value);
}

function sha256Digest(value, label) {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a canonical sha256 digest`);
  }
  return value;
}

export function parsePrivateAnalysisEtag(value) {
  if (typeof value !== "string") {
    throw new TypeError("private-analysis response requires a strong numeric ETag");
  }
  const match = STRONG_ETAG_PATTERN.exec(value);
  if (!match) {
    throw new TypeError("private-analysis response requires a strong numeric ETag");
  }
  return Object.freeze({ header: value, version: BigInt(match[1]) });
}

export function privateAnalysisCreateRequestOptions({
  idempotencyKey,
  body,
  ...options
}) {
  return {
    ...options,
    method: "POST",
    mutate: true,
    responseType: "response",
    body: exactObject(body, "private-analysis create body"),
    headers: {
      ...(options.headers || {}),
      "Idempotency-Key": token(idempotencyKey, "idempotencyKey", 512),
    },
  };
}

export function privateAnalysisConditionalPostOptions({
  etag,
  ...options
}) {
  return {
    ...options,
    method: "POST",
    mutate: true,
    responseType: "response",
    headers: {
      ...(options.headers || {}),
      "If-Match": parsePrivateAnalysisEtag(etag).header,
    },
  };
}

export function privateAnalysisDecisionPostOptions({
  etag,
  idempotencyKey,
  body,
  ...options
}) {
  return {
    ...privateAnalysisConditionalPostOptions({ etag, ...options }),
    body: exactObject(body, "proposal decision body"),
    headers: {
      ...(options.headers || {}),
      "If-Match": parsePrivateAnalysisEtag(etag).header,
      "Idempotency-Key": token(idempotencyKey, "idempotencyKey", 512),
    },
  };
}

export function privateAnalysisDecisionBody({
  proposalDigest,
  resultDigest,
  disposition,
  rationale = "",
  target = null,
}) {
  if (!new Set(["promote", "reject"]).has(disposition)) {
    throw new TypeError("proposal decision disposition is unsupported");
  }
  if (
    typeof rationale !== "string"
    || rationale.length > 65_536
    || /[\u0000\u000b\u000c\u000e-\u001f\u007f]/.test(rationale)
  ) {
    throw new TypeError("proposal decision rationale is invalid");
  }
  if (disposition === "reject" && target !== null) {
    throw new TypeError("a rejection cannot contain a promotion target");
  }
  if (disposition === "promote" && target === null) {
    throw new TypeError("a promotion requires a separately authored target");
  }
  const body = {
    proposal_digest: sha256Digest(proposalDigest, "proposal_digest"),
    result_digest: sha256Digest(resultDigest, "result_digest"),
    disposition,
    rationale,
  };
  if (target !== null) {
    body.target = exactObject(
      detachedFrozenJson(target, "human-authored promotion target"),
      "human-authored promotion target",
    );
  }
  return detachedFrozenJson(body, "proposal decision request");
}

export function privateAnalysisReportDecisionAuthority(value) {
  const report = exactObject(value, "private-analysis report authority");
  const outcome = exactObject(report.outcome, "private-analysis report outcome");
  const result = exactObject(outcome.result, "private-analysis report result");
  const resultDigest = sha256Digest(
    result.result_digest,
    "private-analysis report result_digest",
  );
  if (!Array.isArray(result.proposals) || result.proposals.length > 5_000) {
    throw new TypeError("private-analysis report proposals are invalid");
  }
  const proposalDigests = Object.create(null);
  for (const value of result.proposals) {
    const proposal = exactObject(value, "private-analysis report proposal");
    const proposalId = token(proposal.proposal_id, "proposal_id", 512);
    const proposalDigest = sha256Digest(
      proposal.proposal_digest,
      "proposal_digest",
    );
    if (Object.prototype.hasOwnProperty.call(proposalDigests, proposalId)) {
      throw new TypeError("private-analysis report contains duplicate proposal ids");
    }
    Object.defineProperty(proposalDigests, proposalId, {
      value: proposalDigest,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze({
    resultDigest,
    proposalDigests: Object.freeze(proposalDigests),
  });
}

function normalizedDecision(value, {
  scope,
  runId,
  runVersion,
  reportAuthority,
}) {
  const decision = exactObject(
    detachedFrozenJson(value, "proposal review decision"),
    "proposal review decision",
  );
  if (decision.contract !== PROPOSAL_REVIEW_CONTRACT) {
    throw new TypeError("proposal review decision contract is unsupported");
  }
  const decisionScope = exactObject(decision.scope, "proposal review decision scope");
  if (
    decisionScope.tenant_id !== scope.tenantId
    || decisionScope.project_id !== scope.projectId
    || decisionScope.workspace_id !== scope.workspaceId
  ) {
    throw new StalePrivateAnalysisResponseError("Proposal decision scope changed.");
  }
  if (token(decision.run_id, "decision run_id", 512) !== runId) {
    throw new StalePrivateAnalysisResponseError("Proposal decision run changed.");
  }
  token(decision.decision_id, "decision_id", 512);
  const proposalId = token(decision.proposal_id, "proposal_id", 512);
  const proposalDigest = sha256Digest(
    decision.proposal_digest,
    "decision proposal_digest",
  );
  const resultDigest = sha256Digest(
    decision.result_digest,
    "decision result_digest",
  );
  const authority = exactObject(
    reportAuthority,
    "private-analysis report decision authority",
  );
  if (
    resultDigest !== authority.resultDigest
    || !Object.prototype.hasOwnProperty.call(authority.proposalDigests, proposalId)
    || authority.proposalDigests[proposalId] !== proposalDigest
  ) {
    throw new StalePrivateAnalysisResponseError(
      "Proposal decision provenance does not match the frozen report.",
    );
  }
  const pinnedVersion = decimalBigInt(decision.run_version, "decision.run_version");
  const version = decimalBigInt(decision.version, "decision.version");
  if (pinnedVersion !== runVersion || version < 1n) {
    throw new StalePrivateAnalysisResponseError("Proposal decision version changed.");
  }
  if (!new Set(["promote", "reject"]).has(decision.disposition)) {
    throw new TypeError("proposal decision disposition is unsupported");
  }
  if (!new Set(["pending", "completed"]).has(decision.state)) {
    throw new TypeError("proposal decision state is unsupported");
  }
  token(decision.actor, "decision.actor", 512);
  if (
    typeof decision.rationale !== "string"
    || decision.rationale.length > 65_536
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(decision.rationale)
  ) {
    throw new TypeError("proposal decision rationale is invalid");
  }
  sha256Digest(decision.request_digest, "decision.request_digest");
  const createdAt = decimalBigInt(decision.created_at_ns, "decision.created_at_ns");
  const updatedAt = decimalBigInt(decision.updated_at_ns, "decision.updated_at_ns");
  if (updatedAt < createdAt) {
    throw new TypeError("proposal decision update precedes creation");
  }
  if (
    decision.disposition === "reject"
    && (decision.target_kind !== null || decision.target_id !== null)
  ) {
    throw new TypeError("rejected proposal decision contains a target");
  }
  if (
    decision.disposition === "promote"
    && (
      !new Set(["annotation", "manual_event_correlation"]).has(decision.target_kind)
      || typeof decision.target_id !== "string"
      || decision.target_id.length < 1
    )
  ) {
    throw new TypeError("promoted proposal decision target is invalid");
  }
  return decision;
}

export function acceptPrivateAnalysisDecisionEnvelope(
  payload,
  etagValue,
  context,
) {
  const decision = normalizedDecision(payload, context);
  const etag = parsePrivateAnalysisEtag(etagValue);
  if (etag.version !== decimalBigInt(decision.version, "decision.version")) {
    throw new StalePrivateAnalysisResponseError(
      "Proposal decision ETag and body version disagree.",
    );
  }
  return Object.freeze({ decision, etag: etag.header, version: etag.version });
}

function normalizedDecisionPage(value, context) {
  const page = exactObject(
    detachedFrozenJson(value, "proposal review decision page"),
    "proposal review decision page",
  );
  if (!Array.isArray(page.items) || page.items.length > 5_000) {
    throw new TypeError("proposal review decision page is invalid");
  }
  const decisions = page.items.map((item) => normalizedDecision(item, context));
  const decisionIds = new Set(decisions.map((item) => item.decision_id));
  const proposalIds = new Set(decisions.map((item) => item.proposal_id));
  if (decisionIds.size !== decisions.length || proposalIds.size !== decisions.length) {
    throw new TypeError("proposal review decision page contains duplicates");
  }
  return Object.freeze(decisions);
}

function sameDecisionRecoveryAuthority(before, after) {
  const scalarFields = [
    "contract",
    "decision_id",
    "run_id",
    "proposal_id",
    "proposal_digest",
    "result_digest",
    "run_version",
    "disposition",
    "actor",
    "rationale",
    "request_digest",
    "target_kind",
    "target_id",
    "created_at_ns",
  ];
  if (scalarFields.some((field) => before[field] !== after[field])) return false;
  if (
    before.scope.tenant_id !== after.scope.tenant_id
    || before.scope.project_id !== after.scope.project_id
    || before.scope.workspace_id !== after.scope.workspace_id
  ) {
    return false;
  }
  const beforeVersion = decimalBigInt(before.version, "decision.version");
  const afterVersion = decimalBigInt(after.version, "decision.version");
  if (after.state === "pending") {
    return (
      before.state === "pending"
      && afterVersion === beforeVersion
      && after.updated_at_ns === before.updated_at_ns
    );
  }
  return (
    before.state === "pending"
    && after.state === "completed"
    && afterVersion === beforeVersion + 1n
    && decimalBigInt(after.updated_at_ns, "decision.updated_at_ns")
      >= decimalBigInt(before.updated_at_ns, "decision.updated_at_ns")
  );
}

export function privateAnalysisWorkspacePath(scope) {
  const selected = exactObject(scope, "private-analysis scope");
  const projectId = token(selected.projectId, "projectId");
  const workspaceId = token(selected.workspaceId, "workspaceId");
  return `${CONTROL_PLANE_PREFIX}/projects/${encodeURIComponent(projectId)}`
    + `/workspaces/${encodeURIComponent(workspaceId)}`;
}

export function assertPrivateAnalysisPath(path) {
  if (
    typeof path !== "string"
    || !path.startsWith(`${CONTROL_PLANE_PREFIX}/`)
    || path.startsWith("//")
    || path.includes("\\")
    || /[\u0000-\u001f\u007f]/.test(path)
  ) {
    throw new TypeError("private-analysis requests must use the same-origin control-plane prefix");
  }
  const parsed = new URL(path, "http://same-origin.invalid");
  if (parsed.origin !== "http://same-origin.invalid" || parsed.hash) {
    throw new TypeError("private-analysis requests must remain same-origin");
  }
  return `${parsed.pathname}${parsed.search}`;
}

export function acceptPrivateAnalysisRunEnvelope(
  payload,
  etagValue,
  { runId = null, minimumVersion = null } = {},
) {
  const run = exactObject(
    detachedFrozenJson(payload, "private-analysis run"),
    "private-analysis run",
  );
  const selectedRunId = token(run.run_id, "run_id", 512);
  if (runId !== null && selectedRunId !== runId) {
    throw new StalePrivateAnalysisResponseError("Private-analysis run identity changed.");
  }
  const bodyVersion = decimalBigInt(run.version, "run.version");
  const etag = parsePrivateAnalysisEtag(etagValue);
  if (etag.version !== bodyVersion) {
    throw new StalePrivateAnalysisResponseError("Private-analysis ETag and body version disagree.");
  }
  if (minimumVersion !== null && bodyVersion < minimumVersion) {
    throw new StalePrivateAnalysisResponseError();
  }
  if (typeof run.terminal !== "boolean" || typeof run.cleanup_pending !== "boolean") {
    throw new TypeError("private-analysis run lifecycle flags are invalid");
  }
  return Object.freeze({ run, etag: etag.header, version: bodyVersion });
}

export function eligiblePrivateAnalysisRevisions(items) {
  if (!Array.isArray(items)) throw new TypeError("revision items must be an array");
  if (items.length > 20_000) throw new RangeError("revision page exceeds its browser bound");
  const result = [];
  for (const item of items) {
    if (
      !item
      || typeof item !== "object"
      || Array.isArray(item)
      || item.execution_plan === null
      || typeof item.execution_plan !== "object"
      || Array.isArray(item.execution_plan)
    ) continue;
    const revision = exactObject(
      detachedFrozenJson(item, "private-analysis revision"),
      "private-analysis revision",
    );
    token(revision.revision_id, "revision_id", 512);
    token(revision.node_id, "node_id", 512);
    exactObject(revision.execution_plan, "revision execution_plan");
    result.push(revision);
  }
  return Object.freeze(result);
}

export function privateAnalysisSubmissionAvailable(snapshot) {
  return Boolean(
    snapshot
    && new Set(["ready", "terminal"]).has(snapshot.phase)
    && snapshot.capabilities?.enabled === true
    && Array.isArray(snapshot.capabilities?.capabilities)
    && snapshot.capabilities.capabilities.length > 0
    && Array.isArray(snapshot.runners)
    && snapshot.runners.length > 0
    && Array.isArray(snapshot.revisions)
    && snapshot.revisions.length > 0
  );
}

export function privateAnalysisSubmissionUnavailableReason(snapshot) {
  if (privateAnalysisSubmissionAvailable(snapshot)) return "";
  if (snapshot?.capabilities?.enabled === false) {
    return "Private analysis is disabled by this workspace policy.";
  }
  if (new Set(["ready", "terminal"]).has(snapshot?.phase)) {
    if (!Array.isArray(snapshot?.runners) || snapshot.runners.length === 0) {
      return "No approved private runner is configured.";
    }
    if (!Array.isArray(snapshot?.revisions) || snapshot.revisions.length === 0) {
      return "No eligible immutable revision with an executable plug-in plan is available.";
    }
    if (
      !Array.isArray(snapshot?.capabilities?.capabilities)
      || snapshot.capabilities.capabilities.length === 0
    ) {
      return "No private-analysis task is available for this workspace.";
    }
  }
  if (new Set(["creating", "executing", "polling", "loading", "cancelling"]).has(snapshot?.phase)) {
    return "A private-analysis operation is already active.";
  }
  if (snapshot?.phase === "connecting") {
    return "Workspace discovery is still in progress.";
  }
  if (snapshot?.phase === "error") {
    return "Reconnect an eligible workspace before submitting.";
  }
  return "Connect an eligible workspace before submitting.";
}

export function privateAnalysisSubmissionBody({
  revisionIds,
  runner,
  taskKind,
  query,
  clockMode = "latest_per_revision",
  selectedTimeNs = null,
  limits = null,
}) {
  if (
    !Array.isArray(revisionIds)
    || revisionIds.length < 1
    || revisionIds.length > PRIVATE_ANALYSIS_MAX_REVISIONS
  ) {
    throw new RangeError("select 1 to 128 revisions");
  }
  const revisions = revisionIds.map((value) => token(value, "revision_id", 512));
  if (new Set(revisions).size !== revisions.length) {
    throw new TypeError("selected revisions must be unique");
  }
  const selectedRunner = exactObject(runner, "runner");
  const clock = { mode: token(clockMode, "clock.mode") };
  if (selectedTimeNs !== null) {
    const selectedTime = String(selectedTimeNs);
    if (!SIGNED_DECIMAL_PATTERN.test(selectedTime)) {
      throw new TypeError("selected_time_ns must be a canonical decimal string");
    }
    if (clock.mode === "absolute_unix_ns" && BigInt(selectedTime) < 0n) {
      throw new RangeError("absolute selected_time_ns cannot be negative");
    }
    clock.selected_time_ns = selectedTime;
  }
  if (typeof query !== "string" || query.length < 1 || query !== query.trim()) {
    throw new TypeError("query must be non-empty text");
  }
  const body = {
    revision_ids: revisions,
    runner: {
      runner_id: token(selectedRunner.runner_id, "runner_id"),
      runner_version: token(selectedRunner.runner_version, "runner_version"),
    },
    task_kind: token(taskKind, "task_kind"),
    query,
    clock,
  };
  if (limits !== null) {
    body.limits = exactObject(
      detachedFrozenJson(limits, "limits"),
      "limits",
    );
  }
  return detachedFrozenJson(body, "private-analysis submission");
}

function defaultOperationKey() {
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new Error("secure operation identity generation is unavailable");
  }
  return `analysis-${globalThis.crypto.randomUUID()}`;
}

function sleep(delay, setTimer) {
  return new Promise((resolve) => setTimer(resolve, delay));
}

export function createPrivateAnalysisController({
  request = requestControlPlane,
  operationKey = defaultOperationKey,
  createAbortController = () => new AbortController(),
  setTimer = globalThis.setTimeout,
  onChange = () => {},
} = {}) {
  if (typeof request !== "function" || typeof operationKey !== "function") {
    throw new TypeError("private-analysis controller dependencies must be callable");
  }
  let generation = 0;
  let scope = null;
  let basePath = null;
  let accepted = null;
  let report = null;
  let pollPromise = null;
  let executeIssuedForRun = null;
  let cancelAttempt = null;
  const decisionAttempts = new Map();
  const recoveryAttempts = new Map();
  const activeControllers = new Set();
  const state = {
    phase: "disconnected",
    capabilities: null,
    runners: [],
    revisions: [],
    run: null,
    etag: null,
    report: null,
    decisions: [],
    reviewAvailable: false,
    reviewingProposalIds: [],
    recoveringDecisionIds: [],
    cancelLocked: false,
    message: "Enter an authorized workspace scope.",
  };

  const snapshot = () => Object.freeze({
    ...state,
    runners: [...state.runners],
    revisions: [...state.revisions],
    decisions: [...state.decisions],
    reviewingProposalIds: [...state.reviewingProposalIds],
    recoveringDecisionIds: [...state.recoveringDecisionIds],
  });
  const publish = (updates = {}) => {
    Object.assign(state, updates);
    onChange(snapshot());
  };
  const assertGeneration = (expected) => {
    if (expected !== generation) throw new StalePrivateAnalysisResponseError();
  };
  const abortActive = () => {
    for (const controller of activeControllers) controller.abort();
    activeControllers.clear();
  };
  const headers = (hasBody = false) => ({
    Accept: "application/json",
    "X-Tenant-ID": scope.tenantId,
    "X-Principal-ID": scope.principalId,
    ...(hasBody ? { "Content-Type": "application/json" } : {}),
  });
  const send = async (path, options = {}, expected = generation) => {
    assertGeneration(expected);
    const controller = createAbortController();
    activeControllers.add(controller);
    try {
      const value = await request(assertPrivateAnalysisPath(path), {
        ...options,
        headers: { ...headers(options.body !== undefined && options.body !== null), ...(options.headers || {}) },
        createAbortController: () => controller,
      });
      assertGeneration(expected);
      return value;
    } finally {
      activeControllers.delete(controller);
    }
  };
  const responseEnvelope = async (response, expected, expectedRunId = null) => {
    const payload = await response.json();
    assertGeneration(expected);
    const envelope = acceptPrivateAnalysisRunEnvelope(payload, response.headers.get("etag"), {
      runId: expectedRunId,
      minimumVersion: accepted?.version ?? null,
    });
    accepted = envelope;
    publish({
      run: envelope.run,
      etag: envelope.etag,
      report: null,
      decisions: [],
      reviewAvailable: false,
      reviewingProposalIds: [],
      recoveringDecisionIds: [],
    });
    return envelope;
  };
  const getRun = async (runId, expected = generation) => {
    const response = await send(
      `${basePath}/private-analysis-runs/${encodeURIComponent(token(runId, "runId", 512))}`,
      { responseType: "response" },
      expected,
    );
    return responseEnvelope(response, expected, runId);
  };
  const getDecisions = async (
    runId,
    runVersion,
    reportAuthority,
    expected = generation,
  ) => {
    const page = await send(
      `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}`
        + "/proposal-decisions?limit=5000&offset=0",
      {},
      expected,
    );
    assertGeneration(expected);
    return normalizedDecisionPage(page, {
      scope,
      runId,
      runVersion,
      reportAuthority,
    });
  };
  const getReport = async (runId, expected = generation) => {
    const current = accepted;
    if (
      !current
      || current.run.run_id !== runId
      || !current.run.terminal
      || current.run.cleanup_pending
    ) {
      throw new StalePrivateAnalysisResponseError(
        "A report can be accepted only for the current cleanup-complete terminal run.",
      );
    }
    const response = await send(
      `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}/report`,
      { responseType: "response" },
      expected,
    );
    const payload = exactObject(
      detachedFrozenJson(await response.json(), "private-analysis report"),
      "private-analysis report",
    );
    assertGeneration(expected);
    const envelope = acceptPrivateAnalysisRunEnvelope(payload.run, response.headers.get("etag"), {
      runId,
      minimumVersion: current.version,
    });
    if (
      envelope.version !== current.version
      || !accepted
      || accepted.run.run_id !== runId
      || accepted.version !== current.version
    ) {
      throw new StalePrivateAnalysisResponseError(
        "Private-analysis report does not match the exact current run version.",
      );
    }
    if (!envelope.run.terminal || envelope.run.cleanup_pending) {
      throw new StalePrivateAnalysisResponseError(
        "Private-analysis report run is not cleanup-complete and terminal.",
      );
    }
    const reportAuthority = payload.outcome?.result == null
      ? null
      : privateAnalysisReportDecisionAuthority(payload);
    accepted = envelope;
    report = payload;
    let decisions = [];
    let reviewAvailable = false;
    let decisionMessage = "Durable private-analysis report loaded.";
    if (reportAuthority === null) {
      decisionMessage = "Durable report loaded without reviewable proposals.";
    } else {
      try {
        decisions = await getDecisions(
          runId,
          envelope.version,
          reportAuthority,
          expected,
        );
        reviewAvailable = true;
      } catch (error) {
        assertGeneration(expected);
        if (error instanceof StalePrivateAnalysisResponseError) throw error;
        decisionMessage = "Report loaded. Proposal review is unavailable until the run is reloaded.";
      }
    }
    publish({
      phase: "terminal",
      run: envelope.run,
      etag: envelope.etag,
      report,
      decisions,
      reviewAvailable,
      reviewingProposalIds: [],
      recoveringDecisionIds: [],
      message: decisionMessage,
    });
    return report;
  };
  const poll = (runId, expected = generation) => {
    if (pollPromise) return pollPromise;
    const activePoll = (async () => {
      publish({ phase: "polling", message: "Waiting for durable run state and cleanup." });
      let attempt = 0;
      while (true) {
        assertGeneration(expected);
        const envelope = await getRun(runId, expected);
        if (envelope.run.terminal && !envelope.run.cleanup_pending) {
          return getReport(runId, expected);
        }
        const delay = PRIVATE_ANALYSIS_POLL_DELAYS_MS[
          Math.min(attempt, PRIVATE_ANALYSIS_POLL_DELAYS_MS.length - 1)
        ];
        attempt += 1;
        await sleep(delay, setTimer);
      }
    })();
    const wrappedPoll = activePoll.finally(() => {
      if (pollPromise === wrappedPoll) pollPromise = null;
    });
    pollPromise = wrappedPoll;
    return pollPromise;
  };

  return Object.freeze({
    snapshot() {
      return snapshot();
    },
    disconnect() {
      generation += 1;
      abortActive();
      scope = null;
      basePath = null;
      accepted = null;
      report = null;
      pollPromise = null;
      executeIssuedForRun = null;
      cancelAttempt = null;
      decisionAttempts.clear();
      recoveryAttempts.clear();
      publish({ phase: "disconnected", capabilities: null, runners: [], revisions: [], run: null, etag: null, report: null, decisions: [], reviewAvailable: false, reviewingProposalIds: [], recoveringDecisionIds: [], cancelLocked: false, message: "Workspace scope cleared from memory." });
    },
    async connect(nextScope) {
      generation += 1;
      abortActive();
      pollPromise = null;
      const expected = generation;
      scope = null;
      basePath = null;
      accepted = null;
      report = null;
      executeIssuedForRun = null;
      cancelAttempt = null;
      decisionAttempts.clear();
      recoveryAttempts.clear();
      publish({ phase: "connecting", capabilities: null, runners: [], revisions: [], run: null, etag: null, report: null, decisions: [], reviewAvailable: false, reviewingProposalIds: [], recoveringDecisionIds: [], cancelLocked: false, message: "Discovering private-analysis capabilities." });
      try {
        const candidate = exactObject(nextScope, "private-analysis scope");
        scope = Object.freeze({
          tenantId: token(candidate.tenantId, "tenantId"),
          projectId: token(candidate.projectId, "projectId"),
          workspaceId: token(candidate.workspaceId, "workspaceId"),
          principalId: token(candidate.principalId, "principalId"),
        });
        basePath = privateAnalysisWorkspacePath(scope);
      } catch (error) {
        publish({ phase: "error", message: "Workspace scope is invalid. Reconnect with an authorized scope." });
        throw error;
      }
      const [capabilities, runnerPage] = await Promise.all([
        send(`${basePath}/private-analysis-capabilities`, {}, expected),
        send(`${basePath}/private-analysis-runners`, {}, expected),
      ]);
      const admittedCapabilities = normalizedCapabilities(capabilities);
      const runners = normalizedRunners(runnerPage);
      const revisions = [];
      let catalogCount = 0;
      let offset = 0;
      do {
        const page = await send(`${basePath}/revisions?limit=1000&offset=${offset}`, {}, expected);
        const items = Array.isArray(page?.items) ? page.items : [];
        catalogCount += items.length;
        revisions.push(...eligiblePrivateAnalysisRevisions(items));
        if (page?.next_offset === null || page?.next_offset === undefined) break;
        if (!Number.isSafeInteger(page.next_offset) || page.next_offset <= offset || catalogCount > 20_000) {
          throw new TypeError("revision catalog pagination is invalid or exceeds its browser bound");
        }
        offset = page.next_offset;
      } while (true);
      assertGeneration(expected);
      publish({
        phase: "ready",
        capabilities: admittedCapabilities,
        runners,
        revisions,
        message: admittedCapabilities.enabled === false
          ? "Private analysis is disabled by this workspace policy."
          : runners.length === 0
            ? "No approved private runner is configured."
            : revisions.length === 0
              ? "No eligible immutable revision with an executable plug-in plan is available."
              : !Array.isArray(admittedCapabilities.capabilities)
                || admittedCapabilities.capabilities.length === 0
                ? "No private-analysis task is available for this workspace."
                : "Select revisions, a task, and an approved local runner.",
      });
      return snapshot();
    },
    async submit(spec) {
      if (!scope || !basePath) throw new Error("connect an authorized scope first");
      if (!privateAnalysisSubmissionAvailable(snapshot())) {
        throw new Error(privateAnalysisSubmissionUnavailableReason(snapshot()));
      }
      const body = privateAnalysisSubmissionBody(spec);
      const selected = new Set(state.revisions.map((item) => item.revision_id));
      if (body.revision_ids.some((revisionId) => !selected.has(revisionId))) {
        throw new TypeError("every selected revision must have an execution plan in this workspace");
      }
      if (!state.runners.some((runner) => (
        runner?.runner_id === body.runner.runner_id
        && runner?.runner_version === body.runner.runner_version
      ))) {
        throw new TypeError("the selected private runner is not approved for this workspace");
      }
      if (!state.capabilities.capabilities.some((capability) => capability?.id === body.task_kind)) {
        throw new TypeError("the selected private-analysis task is not available for this workspace");
      }
      generation += 1;
      abortActive();
      pollPromise = null;
      const expected = generation;
      accepted = null;
      report = null;
      executeIssuedForRun = null;
      cancelAttempt = null;
      decisionAttempts.clear();
      recoveryAttempts.clear();
      const idempotencyKey = token(operationKey(), "generated idempotency key", 512);
      publish({ phase: "creating", decisions: [], reviewAvailable: false, reviewingProposalIds: [], recoveringDecisionIds: [], cancelLocked: false, message: "Admitting one durable private-analysis run. This mutation is not retried automatically." });
      const createResponse = await send(
        `${basePath}/private-analysis-runs`,
        privateAnalysisCreateRequestOptions({ idempotencyKey, body }),
        expected,
      );
      const created = await responseEnvelope(createResponse, expected);
      const runId = created.run.run_id;
      if (executeIssuedForRun === runId) throw new Error("execute was already issued for this run");
      executeIssuedForRun = runId;
      publish({ phase: "executing", message: "Execution was submitted once. Ambiguous transport results are reconciled by read-only polling." });
      try {
        const executeResponse = await send(
          `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}/execute`,
          privateAnalysisConditionalPostOptions({ etag: created.etag }),
          expected,
        );
        const executed = await responseEnvelope(executeResponse, expected, runId);
        if (executed.run.terminal && !executed.run.cleanup_pending) {
          return getReport(runId, expected);
        }
      } catch (error) {
        if (!(error instanceof ControlPlaneRequestError) || !error.ambiguous) throw error;
      }
      return poll(runId, expected);
    },
    async reload(runId) {
      if (!scope || !basePath) throw new Error("connect an authorized scope first");
      generation += 1;
      abortActive();
      pollPromise = null;
      const expected = generation;
      accepted = null;
      report = null;
      executeIssuedForRun = null;
      cancelAttempt = null;
      decisionAttempts.clear();
      recoveryAttempts.clear();
      publish({ phase: "loading", run: null, etag: null, report: null, decisions: [], reviewAvailable: false, reviewingProposalIds: [], recoveringDecisionIds: [], cancelLocked: false, message: "Loading the opaque run ID from this workspace." });
      const envelope = await getRun(token(runId, "runId", 512), expected);
      if (envelope.run.terminal && !envelope.run.cleanup_pending) {
        return getReport(envelope.run.run_id, expected);
      }
      return poll(envelope.run.run_id, expected);
    },
    async decideProposal(proposalId, intent) {
      if (
        !scope
        || !basePath
        || !accepted
        || !report
        || !state.reviewAvailable
        || !accepted.run.terminal
        || accepted.run.cleanup_pending
      ) {
        throw new Error("load a review-enabled terminal report first");
      }
      const selectedProposalId = token(proposalId, "proposalId", 512);
      const result = exactObject(report.outcome?.result, "private-analysis result");
      const reportAuthority = privateAnalysisReportDecisionAuthority(report);
      const proposals = Array.isArray(result.proposals) ? result.proposals : [];
      const matches = proposals.filter((item) => item?.proposal_id === selectedProposalId);
      if (matches.length !== 1) {
        throw new TypeError("proposal is not present exactly once in the current report");
      }
      const existing = state.decisions.find(
        (item) => item.proposal_id === selectedProposalId,
      );
      if (existing) {
        throw new Error(
          "this proposal already has a durable decision; inspect or recover it instead",
        );
      }
      if (decisionAttempts.has(selectedProposalId)) {
        return decisionAttempts.get(selectedProposalId);
      }
      const selectedIntent = exactObject(intent, "human proposal decision");
      const body = privateAnalysisDecisionBody({
        proposalDigest: matches[0].proposal_digest,
        resultDigest: result.result_digest,
        disposition: selectedIntent.disposition,
        rationale: selectedIntent.rationale ?? "",
        target: selectedIntent.target ?? null,
      });
      const expected = generation;
      const runId = accepted.run.run_id;
      const runVersion = accepted.version;
      const runEtag = accepted.etag;
      const idempotencyKey = token(operationKey(), "generated idempotency key", 512);
      const attempt = Promise.resolve().then(async () => {
        assertGeneration(expected);
        try {
          const response = await send(
            `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}`
              + `/proposals/${encodeURIComponent(selectedProposalId)}/decision`,
            privateAnalysisDecisionPostOptions({
              etag: runEtag,
              idempotencyKey,
              body,
              responseType: "response",
            }),
            expected,
          );
          const envelope = acceptPrivateAnalysisDecisionEnvelope(
            await response.json(),
            response.headers.get("etag"),
            { scope, runId, runVersion, reportAuthority },
          );
          assertGeneration(expected);
          if (
            envelope.decision.proposal_id !== selectedProposalId
            || envelope.decision.proposal_digest !== body.proposal_digest
            || envelope.decision.result_digest !== body.result_digest
          ) {
            throw new StalePrivateAnalysisResponseError(
              "Proposal decision provenance does not match the selected proposal.",
            );
          }
          const decisions = [
            ...state.decisions.filter(
              (item) => item.proposal_id !== selectedProposalId,
            ),
            envelope.decision,
          ].sort((left, right) => left.proposal_id.localeCompare(right.proposal_id));
          publish({
            decisions,
            message: envelope.decision.disposition === "promote"
              ? "Human-authored review target was promoted durably."
              : "Proposal rejection was recorded durably.",
          });
          return envelope.decision;
        } catch (error) {
          if (!(error instanceof ControlPlaneRequestError) || !error.ambiguous) {
            throw error;
          }
          publish({
            reviewAvailable: false,
            message: "Proposal review outcome is ambiguous. Refreshing durable state before requiring a reload.",
          });
          const decisions = await getDecisions(
            runId,
            runVersion,
            reportAuthority,
            expected,
          );
          publish({
            decisions,
            message: "Proposal review outcome is ambiguous. Durable state was refreshed, but the attempted human intent cannot be proven; reload and inspect before another action.",
          });
          throw error;
        }
      }).finally(() => {
        if (generation !== expected) return;
        decisionAttempts.delete(selectedProposalId);
        publish({ reviewingProposalIds: [...decisionAttempts.keys()] });
      });
      decisionAttempts.set(selectedProposalId, attempt);
      publish({
        reviewingProposalIds: [...decisionAttempts.keys()],
        message: "Recording one explicit human proposal decision. This mutation is not replayed automatically.",
      });
      return attempt;
    },
    async recoverDecision(decisionId) {
      if (!scope || !basePath || !accepted || !report || !state.reviewAvailable) {
        throw new Error("load a review-enabled terminal report first");
      }
      const selectedDecisionId = token(decisionId, "decisionId", 512);
      const decision = state.decisions.find(
        (item) => item.decision_id === selectedDecisionId,
      );
      if (!decision) throw new TypeError("decision is not present in the current run");
      if (decision.state === "completed") return decision;
      if (decision.disposition !== "promote") {
        throw new TypeError("only a pending promotion can be recovered");
      }
      if (recoveryAttempts.has(selectedDecisionId)) {
        return recoveryAttempts.get(selectedDecisionId);
      }
      const expected = generation;
      const runId = accepted.run.run_id;
      const runVersion = accepted.version;
      const reportAuthority = privateAnalysisReportDecisionAuthority(report);
      const attempt = Promise.resolve().then(async () => {
        assertGeneration(expected);
        try {
          const response = await send(
            `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}`
              + `/proposal-decisions/${encodeURIComponent(selectedDecisionId)}/recover`,
            privateAnalysisConditionalPostOptions({
              etag: `"${decision.version}"`,
              responseType: "response",
            }),
            expected,
          );
          const envelope = acceptPrivateAnalysisDecisionEnvelope(
            await response.json(),
            response.headers.get("etag"),
            { scope, runId, runVersion, reportAuthority },
          );
          if (!sameDecisionRecoveryAuthority(decision, envelope.decision)) {
            throw new StalePrivateAnalysisResponseError(
              "Recovered proposal decision authority changed.",
            );
          }
          const decisions = state.decisions.map((item) => (
            item.decision_id === selectedDecisionId ? envelope.decision : item
          ));
          publish({
            decisions,
            message: envelope.decision.state === "completed"
              ? "Pending human promotion was recovered durably."
              : "Human promotion remains pending.",
          });
          return envelope.decision;
        } catch (error) {
          if (!(error instanceof ControlPlaneRequestError) || !error.ambiguous) {
            throw error;
          }
          publish({
            reviewAvailable: false,
            message: "Promotion recovery outcome is ambiguous. Refreshing durable state before requiring a reload.",
          });
          const decisions = await getDecisions(
            runId,
            runVersion,
            reportAuthority,
            expected,
          );
          const reconciled = decisions.find(
            (item) => item.decision_id === selectedDecisionId,
          );
          if (!reconciled || !sameDecisionRecoveryAuthority(decision, reconciled)) {
            publish({
              reviewAvailable: false,
              message: "Promotion recovery authority is ambiguous. Reload the run before another action.",
            });
            throw error;
          }
          publish({
            decisions,
            reviewAvailable: true,
            message: reconciled.state === "completed"
              ? "Ambiguous recovery response was reconciled from durable state."
              : "Promotion is still pending; another recovery requires an explicit click.",
          });
          return reconciled;
        }
      }).finally(() => {
        if (generation !== expected) return;
        recoveryAttempts.delete(selectedDecisionId);
        publish({ recoveringDecisionIds: [...recoveryAttempts.keys()] });
      });
      recoveryAttempts.set(selectedDecisionId, attempt);
      publish({
        recoveringDecisionIds: [...recoveryAttempts.keys()],
        message: "Resuming one pending human-authored promotion from durable state.",
      });
      return attempt;
    },
    async cancel() {
      if (!accepted || !basePath) throw new Error("no private-analysis run is loaded");
      const expected = generation;
      const runId = accepted.run.run_id;
      if (
        cancelAttempt
        && cancelAttempt.generation === expected
        && cancelAttempt.runId === runId
      ) {
        return cancelAttempt.promise;
      }

      const attempt = { generation: expected, runId, promise: null };
      cancelAttempt = attempt;
      attempt.promise = Promise.resolve().then(async () => {
        assertGeneration(expected);
        const beforeRefresh = accepted;
        let current;
        try {
          current = await getRun(runId, expected);
        } catch (error) {
          if (
            !(error instanceof StalePrivateAnalysisResponseError)
            || accepted === beforeRefresh
            || accepted?.run.run_id !== runId
            || accepted.version <= beforeRefresh.version
          ) {
            throw error;
          }
          current = accepted;
        }
        assertGeneration(expected);
        if (cancelAttempt !== attempt) throw new StalePrivateAnalysisResponseError();
        if (
          accepted?.run.run_id === runId
          && accepted.version > current.version
        ) {
          current = accepted;
        }
        if (current.run.terminal && !current.run.cleanup_pending) {
          return getReport(runId, expected);
        }
        publish({ phase: "cancelling", cancelLocked: true, message: "Cancellation was submitted once with the latest durable version." });
        try {
          const response = await send(
            `${basePath}/private-analysis-runs/${encodeURIComponent(runId)}/cancel`,
            privateAnalysisConditionalPostOptions({ etag: current.etag }),
            expected,
          );
          const cancelled = await responseEnvelope(response, expected, runId);
          if (cancelled.run.terminal && !cancelled.run.cleanup_pending) {
            return getReport(runId, expected);
          }
        } catch (error) {
          if (!(error instanceof ControlPlaneRequestError) || !error.ambiguous) throw error;
        }
        return poll(runId, expected);
      });
      publish({ phase: "cancelling", cancelLocked: true, message: "Cancellation is locked to this run while its latest durable version is refreshed." });
      return attempt.promise;
    },
  });
}

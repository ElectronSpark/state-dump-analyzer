import assert from "node:assert/strict";
import test from "node:test";

import { ControlPlaneRequestError } from "../assets/durable_review_controller.js";
import {
  StalePrivateAnalysisResponseError,
  acceptPrivateAnalysisDecisionEnvelope,
  acceptPrivateAnalysisRunEnvelope,
  assertPrivateAnalysisPath,
  createPrivateAnalysisController,
  parsePrivateAnalysisEtag,
  privateAnalysisConditionalPostOptions,
  privateAnalysisCreateRequestOptions,
  privateAnalysisDecisionBody,
  privateAnalysisDecisionPostOptions,
  privateAnalysisReportDecisionAuthority,
  privateAnalysisSubmissionAvailable,
  privateAnalysisSubmissionBody,
  privateAnalysisSubmissionUnavailableReason,
} from "../assets/private_analysis_controller.js";

function run(version, {
  state = "queued",
  terminal = false,
  cleanupPending = false,
  runId = "run-a",
} = {}) {
  return {
    run_id: runId,
    version: String(version),
    state,
    terminal,
    cleanup_pending: cleanupPending,
    revision_ids: ["revision-a"],
  };
}

function response(payload, etag) {
  return {
    headers: { get: (name) => name.toLowerCase() === "etag" ? etag : null },
    async json() { return payload; },
  };
}

function discovery(path) {
  if (path.endsWith("/private-analysis-capabilities")) {
    return { enabled: true, capabilities: [{ id: "route_trace_analysis", label: "Route trace" }] };
  }
  if (path.endsWith("/private-analysis-runners")) {
    return { items: [{ runner_id: "local", runner_version: "1", transport: "in_process" }] };
  }
  if (path.includes("/revisions?")) {
    return {
      items: [
        { revision_id: "legacy", node_id: "old", execution_plan: null },
        { revision_id: "revision-a", node_id: "router-a", execution_plan: { plan_digest: "sha256:x" } },
      ],
      next_offset: null,
    };
  }
  return null;
}

const scope = {
  tenantId: "tenant-a",
  projectId: "project-a",
  workspaceId: "workspace-a",
  principalId: "analyst-a",
};

const proposalDigest = `sha256:${"8".repeat(64)}`;
const resultDigest = `sha256:${"9".repeat(64)}`;

function resultReport(version = 4) {
  return {
    run: run(version, { state: "completed", terminal: true }),
    outcome: {
      kind: "result",
      result: {
        result_digest: resultDigest,
        proposals: [{
          proposal_id: "proposal-a",
          proposal_digest: proposalDigest,
          title: "Inspect route",
          rationale: "Advisory rationale",
          kind: "event_correlation",
          confidence_basis_points: 7500,
          payload: { model_owned: "must-not-be-applied" },
          citations: [],
        }],
      },
    },
  };
}

function decision({ version = 1, disposition = "reject", state = "completed" } = {}) {
  return {
    contract: "router_dump_analyzer.private_analysis.proposal_review.v1",
    scope: {
      tenant_id: scope.tenantId,
      project_id: scope.projectId,
      workspace_id: scope.workspaceId,
    },
    decision_id: "decision-a",
    run_id: "run-a",
    proposal_id: "proposal-a",
    proposal_digest: proposalDigest,
    result_digest: resultDigest,
    run_version: "4",
    disposition,
    state,
    actor: scope.principalId,
    rationale: "Human-reviewed rejection.",
    request_digest: `sha256:${"a".repeat(64)}`,
    target_kind: disposition === "promote" ? "annotation" : null,
    target_id: disposition === "promote" ? "annotation-a" : null,
    created_at_ns: "100",
    updated_at_ns: "100",
    version: String(version),
  };
}

test("submission availability requires enabled policy, a runner, and an eligible revision", () => {
  const ready = {
    phase: "ready",
    capabilities: {
      enabled: true,
      capabilities: [{ id: "route_trace_analysis" }],
    },
    runners: [{ runner_id: "local" }],
    revisions: [{ revision_id: "revision-a" }],
  };
  assert.equal(privateAnalysisSubmissionAvailable(ready), true);
  assert.equal(privateAnalysisSubmissionAvailable({ ...ready, phase: "terminal" }), true);
  for (const phase of [
    "disconnected",
    "connecting",
    "creating",
    "executing",
    "polling",
    "loading",
    "cancelling",
    "error",
  ]) {
    assert.equal(privateAnalysisSubmissionAvailable({ ...ready, phase }), false, phase);
  }
  assert.equal(privateAnalysisSubmissionAvailable({
    ...ready,
    capabilities: { ...ready.capabilities, enabled: false },
  }), false);
  assert.equal(privateAnalysisSubmissionAvailable({ ...ready, runners: [] }), false);
  assert.equal(privateAnalysisSubmissionAvailable({ ...ready, revisions: [] }), false);
  assert.equal(privateAnalysisSubmissionAvailable({
    ...ready,
    capabilities: { enabled: true, capabilities: [] },
  }), false);
  assert.equal(
    privateAnalysisSubmissionUnavailableReason({ ...ready, revisions: [] }),
    "No eligible immutable revision with an executable plug-in plan is available.",
  );
  assert.equal(
    privateAnalysisSubmissionUnavailableReason({ ...ready, phase: "executing" }),
    "A private-analysis operation is already active.",
  );
});

test("controller mutation boundary rejects unavailable, unapproved, and unknown selections", async () => {
  const cases = [
    {
      label: "disabled policy",
      override(path, found) {
        return path.endsWith("/private-analysis-capabilities")
          ? { ...found, enabled: false }
          : found;
      },
      expected: /disabled by this workspace policy/,
    },
    {
      label: "no runner",
      override(path, found) {
        return path.endsWith("/private-analysis-runners") ? { items: [] } : found;
      },
      expected: /No approved private runner/,
    },
    {
      label: "no eligible revision",
      override(path, found) {
        return path.includes("/revisions?")
          ? { items: [{ revision_id: "legacy", node_id: "old", execution_plan: null }], next_offset: null }
          : found;
      },
      expected: /No eligible immutable revision/,
    },
  ];
  for (const item of cases) {
    const calls = [];
    const controller = createPrivateAnalysisController({
      request: async (path, options = {}) => {
        calls.push({ path, options });
        const found = discovery(path);
        if (found) return item.override(path, found);
        throw new Error(`unexpected request ${path}`);
      },
    });
    const connected = await controller.connect(scope);
    await assert.rejects(
      controller.submit({
        revisionIds: [connected.revisions[0]?.revision_id ?? "revision-a"],
        runner: { runner_id: "local", runner_version: "1" },
        taskKind: "route_trace_analysis",
        query: "Do not mutate when unavailable.",
      }),
      item.expected,
      item.label,
    );
    assert.equal(
      calls.filter((call) => call.options?.method === "POST").length,
      0,
      item.label,
    );
  }

  const calls = [];
  const controller = createPrivateAnalysisController({
    request: async (path, options = {}) => {
      calls.push({ path, options });
      const found = discovery(path);
      if (found) return found;
      throw new Error(`unexpected request ${path}`);
    },
  });
  await controller.connect(scope);
  const baseSpec = {
    revisionIds: ["revision-a"],
    runner: { runner_id: "local", runner_version: "1" },
    taskKind: "route_trace_analysis",
    query: "Validate the discovered selections.",
  };
  await assert.rejects(
    controller.submit({ ...baseSpec, runner: { runner_id: "other", runner_version: "1" } }),
    /not approved/,
  );
  await assert.rejects(
    controller.submit({ ...baseSpec, taskKind: "undeclared_task" }),
    /not available/,
  );
  assert.equal(calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("invalid reconnect clears the prior workspace before validation fails", async () => {
  const calls = [];
  const controller = createPrivateAnalysisController({
    request: async (path, options = {}) => {
      calls.push({ path, options });
      const found = discovery(path);
      if (found) return found;
      throw new Error(`unexpected request ${path}`);
    },
  });
  await controller.connect(scope);
  assert.equal(privateAnalysisSubmissionAvailable(controller.snapshot()), true);
  await assert.rejects(
    controller.connect({ ...scope, tenantId: " " }),
    /tenantId/,
  );
  assert.equal(controller.snapshot().phase, "error");
  assert.equal(privateAnalysisSubmissionAvailable(controller.snapshot()), false);
  await assert.rejects(
    controller.submit({
      revisionIds: ["revision-a"],
      runner: { runner_id: "local", runner_version: "1" },
      taskKind: "route_trace_analysis",
      query: "The stale workspace must not submit.",
    }),
    /connect an authorized scope first/,
  );
  assert.equal(calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("returned snapshots cannot rewrite controller-owned discovery authority", async () => {
  const calls = [];
  const controller = createPrivateAnalysisController({
    request: async (path, options = {}) => {
      calls.push({ path, options });
      const found = discovery(path);
      if (found) return found;
      throw new Error(`unexpected request ${path}`);
    },
  });
  const ready = await controller.connect(scope);
  assert.equal(Object.isFrozen(ready.capabilities), true);
  assert.equal(Object.isFrozen(ready.capabilities.capabilities), true);
  assert.equal(Object.isFrozen(ready.capabilities.capabilities[0]), true);
  assert.equal(Object.isFrozen(ready.runners[0]), true);
  assert.equal(Object.isFrozen(ready.revisions[0]), true);
  assert.equal(Object.isFrozen(ready.revisions[0].execution_plan), true);
  assert.throws(() => { ready.capabilities.enabled = false; }, TypeError);
  assert.throws(
    () => { ready.capabilities.capabilities.push({ id: "forged-task" }); },
    TypeError,
  );
  assert.throws(() => { ready.runners[0].runner_id = "forged-runner"; }, TypeError);
  assert.throws(() => { ready.revisions[0].revision_id = "forged-revision"; }, TypeError);

  // The returned outer arrays are detached copies. Mutating them does not add
  // authority to the controller's internal allowlists.
  ready.runners.push({ runner_id: "forged-runner", runner_version: "1" });
  ready.revisions.push({ revision_id: "forged-revision" });
  await assert.rejects(
    controller.submit({
      revisionIds: ["forged-revision"],
      runner: { runner_id: "forged-runner", runner_version: "1" },
      taskKind: "forged-task",
      query: "Snapshot mutation must not grant authority.",
    }),
    /execution plan|approved|available/,
  );
  assert.equal(calls.filter((call) => call.options?.method === "POST").length, 0);
  assert.deepEqual(controller.snapshot().runners.map((item) => item.runner_id), ["local"]);
  assert.deepEqual(controller.snapshot().revisions.map((item) => item.revision_id), ["revision-a"]);
});

test("disabled discovery snapshots cannot be mutated into an enabled policy", async () => {
  const calls = [];
  const controller = createPrivateAnalysisController({
    request: async (path, options = {}) => {
      calls.push({ path, options });
      const found = discovery(path);
      if (found) {
        return path.endsWith("/private-analysis-capabilities")
          ? { ...found, enabled: false }
          : found;
      }
      throw new Error(`unexpected request ${path}`);
    },
  });
  const disabled = await controller.connect(scope);
  assert.throws(() => { disabled.capabilities.enabled = true; }, TypeError);
  await assert.rejects(
    controller.submit({
      revisionIds: ["revision-a"],
      runner: { runner_id: "local", runner_version: "1" },
      taskKind: "route_trace_analysis",
      query: "The policy remains disabled.",
    }),
    /disabled by this workspace policy/,
  );
  assert.equal(calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("private-analysis request builders enforce the POST-specific mutation contract", () => {
  assert.deepEqual(
    privateAnalysisCreateRequestOptions({ idempotencyKey: "stable-a", body: { query: "q" } }),
    {
      method: "POST",
      mutate: true,
      responseType: "response",
      body: { query: "q" },
      headers: { "Idempotency-Key": "stable-a" },
    },
  );
  assert.deepEqual(
    privateAnalysisConditionalPostOptions({ etag: '"9007199254740993"' }),
    {
      method: "POST",
      mutate: true,
      responseType: "response",
      headers: { "If-Match": '"9007199254740993"' },
    },
  );
  assert.throws(() => privateAnalysisConditionalPostOptions({ etag: 'W/"1"' }), /strong numeric ETag/);
  assert.equal(
    assertPrivateAnalysisPath("/v1/control-plane/projects/a/workspaces/b/private-analysis-runs"),
    "/v1/control-plane/projects/a/workspaces/b/private-analysis-runs",
  );
  assert.throws(() => assertPrivateAnalysisPath("https://elsewhere.invalid/v1/control-plane"), /same-origin/);
});

test("proposal review builders pin lossless authority and never derive a target from model payload", () => {
  const reportAuthority = privateAnalysisReportDecisionAuthority(resultReport());
  const rejected = privateAnalysisDecisionBody({
    proposalDigest,
    resultDigest,
    disposition: "reject",
    rationale: "Human-reviewed rejection.",
  });
  assert.deepEqual(Object.keys(rejected).sort(), [
    "disposition", "proposal_digest", "rationale", "result_digest",
  ]);
  assert.equal("payload" in rejected, false);
  assert.equal("target" in rejected, false);
  assert.throws(
    () => privateAnalysisDecisionBody({
      proposalDigest,
      resultDigest,
      disposition: "promote",
    }),
    /separately authored target/,
  );
  const promoted = privateAnalysisDecisionBody({
    proposalDigest,
    resultDigest,
    disposition: "promote",
    target: { kind: "annotation", annotation_kind: "note", subjects: [] },
  });
  assert.equal(promoted.target.kind, "annotation");
  assert.deepEqual(
    privateAnalysisDecisionPostOptions({
      etag: '"4"',
      idempotencyKey: "decision-operation-a",
      body: rejected,
    }),
    {
      method: "POST",
      mutate: true,
      responseType: "response",
      body: rejected,
      headers: {
        "If-Match": '"4"',
        "Idempotency-Key": "decision-operation-a",
      },
    },
  );
  const accepted = acceptPrivateAnalysisDecisionEnvelope(
    decision(),
    '"1"',
    {
      scope,
      runId: "run-a",
      runVersion: 4n,
      reportAuthority,
    },
  );
  assert.equal(accepted.decision.decision_id, "decision-a");
  assert.throws(
    () => acceptPrivateAnalysisDecisionEnvelope(
      { ...decision(), run_version: "5" },
      '"1"',
      {
        scope,
        runId: "run-a",
        runVersion: 4n,
        reportAuthority,
      },
    ),
    StalePrivateAnalysisResponseError,
  );
  assert.throws(
    () => acceptPrivateAnalysisDecisionEnvelope(
      { ...decision(), proposal_digest: `sha256:${"7".repeat(64)}` },
      '"1"',
      { scope, runId: "run-a", runVersion: 4n, reportAuthority },
    ),
    StalePrivateAnalysisResponseError,
  );
  assert.throws(
    () => acceptPrivateAnalysisDecisionEnvelope(
      { ...decision(), result_digest: `sha256:${"6".repeat(64)}` },
      '"1"',
      { scope, runId: "run-a", runVersion: 4n, reportAuthority },
    ),
    StalePrivateAnalysisResponseError,
  );
});

test("ETag and body versions agree losslessly and stale responses are rejected", () => {
  const parsed = parsePrivateAnalysisEtag('"900719925474099312345"');
  assert.equal(parsed.version, 900719925474099312345n);
  const accepted = acceptPrivateAnalysisRunEnvelope(
    run("900719925474099312345"),
    '"900719925474099312345"',
  );
  assert.equal(accepted.version, 900719925474099312345n);
  assert.throws(
    () => acceptPrivateAnalysisRunEnvelope(run("900719925474099312345"), '"900719925474099312346"'),
    StalePrivateAnalysisResponseError,
  );
  assert.throws(
    () => acceptPrivateAnalysisRunEnvelope(run("8"), '"8"', { minimumVersion: 9n }),
    StalePrivateAnalysisResponseError,
  );
});

test("explicit proposal review sends one pinned mutation and records the durable receipt", async () => {
  const calls = [];
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) return { items: [] };
    if (path.endsWith("/run-a/proposals/proposal-a/decision")) {
      return response(decision(), '"1"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    operationKey: () => "decision-operation-a",
  });
  await controller.connect(scope);
  await controller.reload("run-a");
  assert.equal(controller.snapshot().reviewAvailable, true);

  const first = controller.decideProposal("proposal-a", {
    disposition: "reject",
    rationale: "Human-reviewed rejection.",
  });
  const parallel = controller.decideProposal("proposal-a", {
    disposition: "reject",
    rationale: "Human-reviewed rejection.",
  });
  const [firstDecision, parallelDecision] = await Promise.all([first, parallel]);
  assert.equal(firstDecision.decision_id, "decision-a");
  assert.equal(parallelDecision.decision_id, "decision-a");
  const mutations = calls.filter((item) => item.path.endsWith("/decision"));
  assert.equal(mutations.length, 1);
  assert.equal(mutations[0].options.headers["If-Match"], '"4"');
  assert.equal(mutations[0].options.headers["Idempotency-Key"], "decision-operation-a");
  assert.equal(mutations[0].options.body.proposal_digest, proposalDigest);
  assert.equal(mutations[0].options.body.result_digest, resultDigest);
  assert.equal("payload" in mutations[0].options.body, false);
  assert.equal("target" in mutations[0].options.body, false);
  assert.equal(controller.snapshot().decisions.length, 1);
  assert.equal(controller.snapshot().reviewingProposalIds.length, 0);

  const before = calls.length;
  await assert.rejects(
    controller.decideProposal("proposal-a", {
      disposition: "reject",
      rationale: "Different caller input cannot create a second decision.",
    }),
    /already has a durable decision/,
  );
  assert.equal(calls.length, before);
});

test("ambiguous proposal review refreshes authority but fails closed and is never replayed", async () => {
  const calls = [];
  let decisionReads = 0;
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) {
      decisionReads += 1;
      return { items: decisionReads === 1 ? [] : [decision()] };
    }
    if (path.endsWith("/run-a/proposals/proposal-a/decision")) {
      throw new ControlPlaneRequestError("timed out", 0, { ambiguous: true });
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    operationKey: () => "decision-operation-a",
  });
  await controller.connect(scope);
  await controller.reload("run-a");
  await assert.rejects(
    controller.decideProposal("proposal-a", {
      disposition: "reject",
      rationale: "Human-reviewed rejection.",
    }),
    ControlPlaneRequestError,
  );
  await assert.rejects(
    controller.decideProposal("proposal-a", {
      disposition: "reject",
      rationale: "Must not replay.",
    }),
    /review-enabled terminal report/,
  );
  assert.equal(calls.filter((item) => item.path.endsWith("/decision")).length, 1);
  assert.equal(decisionReads, 2);
  assert.equal(controller.snapshot().decisions[0].decision_id, "decision-a");
  assert.equal(controller.snapshot().reviewAvailable, false);
});

test("pending promotion recovery is explicit, conditional, and shared across clicks", async () => {
  const calls = [];
  const pending = decision({ disposition: "promote", state: "pending" });
  const completed = decision({
    version: 2,
    disposition: "promote",
    state: "completed",
  });
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) return { items: [pending] };
    if (path.endsWith("/proposal-decisions/decision-a/recover")) {
      return response(completed, '"2"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({ request });
  await controller.connect(scope);
  await controller.reload("run-a");
  assert.equal(controller.snapshot().decisions[0].state, "pending");
  const first = controller.recoverDecision("decision-a");
  const parallel = controller.recoverDecision("decision-a");
  await Promise.all([first, parallel]);
  const recoveries = calls.filter((item) => item.path.endsWith("/recover"));
  assert.equal(recoveries.length, 1);
  assert.equal(recoveries[0].options.headers["If-Match"], '"1"');
  assert.equal(controller.snapshot().decisions[0].state, "completed");
  assert.equal(controller.snapshot().recoveringDecisionIds.length, 0);
  const before = calls.length;
  await controller.recoverDecision("decision-a");
  assert.equal(calls.length, before);
});

test("ambiguous pending recovery requires and permits a second explicit click", async () => {
  const calls = [];
  let recoveryCount = 0;
  const pending = decision({ disposition: "promote", state: "pending" });
  const completed = decision({
    version: 2,
    disposition: "promote",
    state: "completed",
  });
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) return { items: [pending] };
    if (path.endsWith("/proposal-decisions/decision-a/recover")) {
      recoveryCount += 1;
      if (recoveryCount === 1) {
        throw new ControlPlaneRequestError("timed out", 0, { ambiguous: true });
      }
      return response(completed, '"2"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({ request });
  await controller.connect(scope);
  await controller.reload("run-a");

  const first = controller.recoverDecision("decision-a");
  const parallel = controller.recoverDecision("decision-a");
  const [firstResult, parallelResult] = await Promise.all([first, parallel]);
  assert.equal(firstResult.state, "pending");
  assert.equal(parallelResult.state, "pending");
  assert.equal(recoveryCount, 1);
  assert.equal(controller.snapshot().reviewAvailable, true);
  assert.equal(controller.snapshot().decisions[0].state, "pending");

  const recovered = await controller.recoverDecision("decision-a");
  assert.equal(recovered.state, "completed");
  assert.equal(recoveryCount, 2);
  assert.deepEqual(
    calls
      .filter((item) => item.path.endsWith("/recover"))
      .map((item) => item.options.headers["If-Match"]),
    ['"1"', '"1"'],
  );
});

test("ambiguous recovery never re-enables review for changed decision authority", async () => {
  const calls = [];
  let decisionReads = 0;
  const pending = decision({ disposition: "promote", state: "pending" });
  const forged = {
    ...pending,
    actor: "different-reviewer",
    rationale: "different human intent",
    request_digest: `sha256:${"b".repeat(64)}`,
    target_id: "different-annotation",
  };
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) {
      decisionReads += 1;
      return { items: [decisionReads === 1 ? pending : forged] };
    }
    if (path.endsWith("/proposal-decisions/decision-a/recover")) {
      throw new ControlPlaneRequestError("timed out", 0, { ambiguous: true });
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({ request });
  await controller.connect(scope);
  await controller.reload("run-a");
  await assert.rejects(
    controller.recoverDecision("decision-a"),
    ControlPlaneRequestError,
  );
  assert.equal(controller.snapshot().reviewAvailable, false);
  assert.equal(controller.snapshot().decisions[0].actor, pending.actor);
  await assert.rejects(
    controller.recoverDecision("decision-a"),
    /review-enabled terminal report/,
  );
  assert.equal(
    calls.filter((item) => item.path.endsWith("/recover")).length,
    1,
  );
});

test("decision-list receipts with foreign report digests cannot enable recovery", async () => {
  const calls = [];
  const foreign = {
    ...decision({ disposition: "promote", state: "pending" }),
    proposal_digest: `sha256:${"7".repeat(64)}`,
  };
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      return response(run(4, { state: "completed", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/report")) return response(resultReport(), '"4"');
    if (path.includes("/run-a/proposal-decisions?")) return { items: [foreign] };
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({ request });
  await controller.connect(scope);
  await assert.rejects(
    controller.reload("run-a"),
    StalePrivateAnalysisResponseError,
  );
  assert.equal(controller.snapshot().reviewAvailable, false);
  assert.equal(controller.snapshot().decisions.length, 0);
  await assert.rejects(
    controller.recoverDecision("decision-a"),
    /review-enabled terminal report/,
  );
  assert.equal(calls.filter((item) => item.path.endsWith("/recover")).length, 0);
});

test("submission sends one stable create, one conditional execute, and only eligible revisions", async () => {
  const calls = [];
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/private-analysis-runs")) {
      return response(run("9007199254740993"), '"9007199254740993"');
    }
    if (path.endsWith("/run-a/execute")) {
      return response(
        run("9007199254740994", { state: "completed", terminal: true }),
        '"9007199254740994"',
      );
    }
    if (path.endsWith("/run-a/report")) {
      return response({ run: run("9007199254740994", { state: "completed", terminal: true }), outcome: { kind: "result", result: null } }, '"9007199254740994"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({ request, operationKey: () => "submission-a" });
  const connected = await controller.connect(scope);
  assert.deepEqual(connected.revisions.map((item) => item.revision_id), ["revision-a"]);
  await controller.submit({
    revisionIds: ["revision-a"],
    runner: { runner_id: "local", runner_version: "1" },
    taskKind: "route_trace_analysis",
    query: "Why did the route change?",
  });

  const createCalls = calls.filter((item) => item.path.endsWith("/private-analysis-runs"));
  const executeCalls = calls.filter((item) => item.path.endsWith("/execute"));
  assert.equal(createCalls.length, 1);
  assert.equal(executeCalls.length, 1);
  assert.equal(createCalls[0].options.headers["Idempotency-Key"], "submission-a");
  assert.equal(executeCalls[0].options.headers["If-Match"], '"9007199254740993"');
  assert.equal(createCalls[0].options.headers["X-Tenant-ID"], "tenant-a");
  assert.equal(createCalls[0].options.headers["X-Principal-ID"], "analyst-a");
  assert.deepEqual(Object.keys(createCalls[0].options.body).sort(), [
    "clock", "query", "revision_ids", "runner", "task_kind",
  ]);
  assert.equal(controller.snapshot().phase, "terminal");
});

test("an ambiguous execute timeout is never replayed and is reconciled by bounded GET polling", async () => {
  const calls = [];
  let getCount = 0;
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/private-analysis-runs")) return response(run(1), '"1"');
    if (path.endsWith("/execute")) {
      throw new ControlPlaneRequestError("timed out", 0, { ambiguous: true });
    }
    if (path.endsWith("/run-a")) {
      getCount += 1;
      return getCount === 1
        ? response(run(2, { state: "running" }), '"2"')
        : response(run(3, { state: "completed", terminal: true }), '"3"');
    }
    if (path.endsWith("/report")) {
      return response({ run: run(3, { state: "completed", terminal: true }), outcome: { kind: "error", error: { stage: "runner", code: "timeout" } } }, '"3"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    operationKey: () => "submission-timeout",
    setTimer: (callback) => { queueMicrotask(callback); return 1; },
  });
  await controller.connect(scope);
  await controller.submit({
    revisionIds: ["revision-a"],
    runner: { runner_id: "local", runner_version: "1" },
    taskKind: "route_trace_analysis",
    query: "Bounded question",
  });
  assert.equal(calls.filter((item) => item.path.endsWith("/execute")).length, 1);
  assert.equal(calls.filter((item) => item.path.endsWith("/run-a")).length, 2);
  assert.equal(controller.snapshot().phase, "terminal");
});

test("cancel refreshes the latest ETag, sends once, and waits for cleanup-aware terminal state", async () => {
  const calls = [];
  const timers = [];
  let getCount = 0;
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      getCount += 1;
      if (getCount < 3) return response(run(1, { state: "running" }), '"1"');
      if (getCount === 3) return response(run(2, { state: "running" }), '"2"');
      return response(run(3, { state: "cancelled", terminal: true }), '"3"');
    }
    if (path.endsWith("/cancel")) {
      return response(run(3, { state: "cancelled", terminal: true }), '"3"');
    }
    if (path.endsWith("/report")) {
      return response({ run: run(3, { state: "cancelled", terminal: true }), outcome: { kind: "error", error: { stage: "runner", code: "cancelled" } } }, '"3"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    setTimer: (callback) => { timers.push(callback); return timers.length; },
  });
  await controller.connect(scope);
  const loading = controller.reload("run-a");
  while (timers.length === 0) await Promise.resolve();
  await controller.cancel();
  assert.equal(calls.filter((item) => item.path.endsWith("/cancel")).length, 1);
  const cancelCall = calls.find((item) => item.path.endsWith("/cancel"));
  assert.equal(cancelCall.options.headers["If-Match"], '"2"');
  timers.shift()();
  await loading;
  assert.equal(controller.snapshot().run.cleanup_pending, false);
  assert.equal(controller.snapshot().phase, "terminal");
});

test("report acceptance rejects malformed, stale, wrong-run, and cleanup-pending run views", async (t) => {
  const completed = run(5, { state: "completed", terminal: true });
  const cases = [
    {
      name: "cleanup remains pending",
      payload: { run: run(5, { state: "completed", terminal: true, cleanupPending: true }), outcome: { kind: "result", result: null } },
      etag: '"5"',
      error: StalePrivateAnalysisResponseError,
    },
    {
      name: "report run is not terminal",
      payload: { run: run(5, { state: "running" }), outcome: { kind: "result", result: null } },
      etag: '"5"',
      error: StalePrivateAnalysisResponseError,
    },
    {
      name: "report names another run",
      payload: { run: run(5, { state: "completed", terminal: true, runId: "run-b" }), outcome: { kind: "result", result: null } },
      etag: '"5"',
      error: StalePrivateAnalysisResponseError,
    },
    {
      name: "report run version is stale",
      payload: { run: run(4, { state: "completed", terminal: true }), outcome: { kind: "result", result: null } },
      etag: '"4"',
      error: StalePrivateAnalysisResponseError,
    },
    {
      name: "report has no run view",
      payload: { outcome: { kind: "result", result: null } },
      etag: '"5"',
      error: TypeError,
    },
  ];

  for (const item of cases) {
    await t.test(item.name, async () => {
      const request = async (path) => {
        const found = discovery(path);
        if (found) return found;
        if (path.endsWith("/run-a")) return response(completed, '"5"');
        if (path.endsWith("/run-a/report")) return response(item.payload, item.etag);
        throw new Error(`unexpected request ${path}`);
      };
      const controller = createPrivateAnalysisController({ request });
      await controller.connect(scope);
      await assert.rejects(controller.reload("run-a"), item.error);
      const snapshot = controller.snapshot();
      assert.equal(snapshot.report, null);
      assert.notEqual(snapshot.phase, "terminal");
      assert.equal(snapshot.run.run_id, "run-a");
      assert.equal(snapshot.run.version, "5");
    });
  }
});

test("parallel and repeated cancel calls share one run-bound attempt across version advances", async () => {
  const calls = [];
  const timers = [];
  let getCount = 0;
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      getCount += 1;
      if (getCount < 3) return response(run(1, { state: "running" }), '"1"');
      if (getCount === 3) return response(run(2, { state: "running" }), '"2"');
      return response(run(4, { state: "cancelled", terminal: true }), '"4"');
    }
    if (path.endsWith("/run-a/cancel")) {
      return response(run(3, { state: "cancelling" }), '"3"');
    }
    if (path.endsWith("/run-a/report")) {
      return response({ run: run(4, { state: "cancelled", terminal: true }), outcome: { kind: "error", error: { stage: "runner", code: "cancelled" } } }, '"4"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    setTimer: (callback) => { timers.push(callback); return timers.length; },
  });
  await controller.connect(scope);
  const loading = controller.reload("run-a");
  while (timers.length === 0) await Promise.resolve();

  const firstCancel = controller.cancel();
  assert.equal(controller.snapshot().cancelLocked, true);
  const parallelCancel = controller.cancel();
  while (!calls.some((item) => item.path.endsWith("/run-a/cancel"))) await Promise.resolve();
  assert.equal(calls.filter((item) => item.path.endsWith("/run-a/cancel")).length, 1);
  assert.equal(
    calls.find((item) => item.path.endsWith("/run-a/cancel")).options.headers["If-Match"],
    '"2"',
  );

  timers.shift()();
  await Promise.all([loading, firstCancel, parallelCancel]);
  const callCount = calls.length;
  await controller.cancel();
  assert.equal(calls.length, callCount);
  assert.equal(calls.filter((item) => item.path.endsWith("/run-a/cancel")).length, 1);
  assert.equal(controller.snapshot().run.version, "4");
  assert.equal(controller.snapshot().phase, "terminal");
});

test("an ambiguous cancel is reconciled only by GET and cannot be replayed", async () => {
  const calls = [];
  const timers = [];
  let getCount = 0;
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    if (path.endsWith("/run-a")) {
      getCount += 1;
      if (getCount < 3) return response(run(1, { state: "running" }), '"1"');
      if (getCount === 3) return response(run(2, { state: "running" }), '"2"');
      return response(run(3, { state: "cancelled", terminal: true }), '"3"');
    }
    if (path.endsWith("/run-a/cancel")) {
      throw new ControlPlaneRequestError("cancel timed out", 0, { ambiguous: true });
    }
    if (path.endsWith("/run-a/report")) {
      return response({ run: run(3, { state: "cancelled", terminal: true }), outcome: { kind: "error", error: { stage: "runner", code: "cancelled" } } }, '"3"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    setTimer: (callback) => { timers.push(callback); return timers.length; },
  });
  await controller.connect(scope);
  const loading = controller.reload("run-a");
  while (timers.length === 0) await Promise.resolve();
  const cancelling = controller.cancel();
  while (!calls.some((item) => item.path.endsWith("/run-a/cancel"))) await Promise.resolve();
  const mutationIndex = calls.findIndex((item) => item.path.endsWith("/run-a/cancel"));
  timers.shift()();
  await Promise.all([loading, cancelling]);
  await controller.cancel();

  assert.equal(calls.filter((item) => item.options.method === "POST").length, 1);
  assert.ok(calls.slice(mutationIndex + 1).every((item) => item.options.method !== "POST"));
  assert.equal(controller.snapshot().phase, "terminal");
});

test("run reload and scope replacement reset the cancellation guard", async () => {
  const calls = [];
  const timers = [];
  const getCounts = new Map();
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    const found = discovery(path);
    if (found) return found;
    const match = /\/(run-[ab])$/.exec(path);
    if (match) {
      const runId = match[1];
      const count = (getCounts.get(runId) || 0) + 1;
      getCounts.set(runId, count);
      if (count < 3) return response(run(1, { state: "running", runId }), '"1"');
      if (count === 3) return response(run(2, { state: "running", runId }), '"2"');
      return response(run(3, { state: "cancelled", terminal: true, runId }), '"3"');
    }
    const cancelMatch = /\/(run-[ab])\/cancel$/.exec(path);
    if (cancelMatch) {
      return response(run(3, { state: "cancelled", terminal: true, runId: cancelMatch[1] }), '"3"');
    }
    const reportMatch = /\/(run-[ab])\/report$/.exec(path);
    if (reportMatch) {
      return response({ run: run(3, { state: "cancelled", terminal: true, runId: reportMatch[1] }), outcome: { kind: "error", error: { stage: "runner", code: "cancelled" } } }, '"3"');
    }
    throw new Error(`unexpected request ${path}`);
  };
  const controller = createPrivateAnalysisController({
    request,
    setTimer: (callback) => { timers.push(callback); return timers.length; },
  });
  await controller.connect(scope);

  const finishRun = async (runId, loading) => {
    while (timers.length === 0) await Promise.resolve();
    await controller.cancel();
    timers.shift()();
    await loading;
    assert.equal(controller.snapshot().phase, "terminal");
    assert.equal(controller.snapshot().run.run_id, runId);
  };

  await finishRun("run-a", controller.reload("run-a"));
  const loadingRunB = controller.reload("run-b");
  assert.equal(controller.snapshot().cancelLocked, false);
  await finishRun("run-b", loadingRunB);
  assert.equal(calls.filter((item) => item.path.endsWith("/cancel")).length, 2);

  await controller.connect({ ...scope, projectId: "project-b" });
  assert.equal(controller.snapshot().cancelLocked, false);
});

test("scope replacement aborts old requests and rejects their late response", async () => {
  let releaseOldCapabilities;
  let releaseOldRunners;
  let aborts = 0;
  const oldCapabilities = new Promise((resolve) => { releaseOldCapabilities = resolve; });
  const oldRunners = new Promise((resolve) => { releaseOldRunners = resolve; });
  const request = async (path) => {
    if (path.includes("/projects/old/")) {
      if (path.endsWith("capabilities")) return oldCapabilities;
      if (path.endsWith("runners")) return oldRunners;
    }
    return discovery(path);
  };
  const controller = createPrivateAnalysisController({
    request,
    createAbortController: () => ({ signal: {}, abort() { aborts += 1; } }),
  });
  const oldConnection = controller.connect({ ...scope, projectId: "old" });
  await Promise.resolve();
  await controller.connect({ ...scope, projectId: "new" });
  releaseOldCapabilities(discovery("/private-analysis-capabilities"));
  releaseOldRunners(discovery("/private-analysis-runners"));
  await assert.rejects(oldConnection, StalePrivateAnalysisResponseError);
  assert.ok(aborts >= 2);
  assert.equal(controller.snapshot().phase, "ready");
});

test("submission body exposes only caller intent and preserves selected time as text", () => {
  const body = privateAnalysisSubmissionBody({
    revisionIds: ["revision-a"],
    runner: { runner_id: "local", runner_version: "1" },
    taskKind: "general_evidence_review",
    query: "Review evidence.",
    clockMode: "absolute_unix_ns",
    selectedTimeNs: "9007199254740993123",
  });
  assert.equal(body.clock.selected_time_ns, "9007199254740993123");
  assert.deepEqual(Object.keys(body.runner).sort(), ["runner_id", "runner_version"]);
  assert.throws(() => privateAnalysisSubmissionBody({ ...body, revisionIds: [] }), /1 to 128/);
  assert.equal(
    privateAnalysisSubmissionBody({
      revisionIds: ["revision-a"],
      runner: { runner_id: "local", runner_version: "1" },
      taskKind: "general_evidence_review",
      query: "Review evidence.",
      clockMode: "revision_end_relative_ns",
      selectedTimeNs: "-9007199254740993123",
    }).clock.selected_time_ns,
    "-9007199254740993123",
  );
});

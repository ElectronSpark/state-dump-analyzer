# Private AI analysis boundary

Status: normative architecture decision with an incrementally implemented
local contract and trusted read-only evidence-tool boundary.

## Decision

Router Dump Analyzer may use an operator-approved private model to examine
proprietary state-dump and LTTng evidence. The core does not ship or configure
an integration with any public model API. It contains no public-provider SDK,
API-key setting, model endpoint, or automatic network fallback.

The only model transports supplied by core are:

1. a trusted in-process runner; and
2. a local subprocess using a versioned bounded JSONL protocol over standard
   input and output, launched without a shell.

A deployment that hosts a model behind private infrastructure owns any adapter
between that infrastructure and the local runner contract. That adapter is not
part of the analyzer core or a device plug-in.

## Authority and provenance

Deterministic reconstruction remains authoritative. Device plug-ins own device,
firmware, chip, event, key, resource, and forwarding semantics. Core owns
identity, temporal/revision scope, orchestration, validation, persistence,
authorization, and generic algorithms.

Model output is always advisory. It first has
`assistant_suggested` provenance and is kept separate from:

- `plugin_inferred` device evidence;
- `core_corroboration` deterministic facts; and
- `user_asserted` review conclusions.

An assistant suggestion cannot mutate an immutable revision, create a
plug-in-inferred fact, call a plug-in directly, execute a host command, or
establish an inter-node identity. Core may submit a bounded read-only request
to a selected plug-in on the model's behalf and records the result as plug-in
evidence.

Promotion is explicit:

```text
assistant suggestion
  -> deterministic core/plug-in validation
  -> human acceptance
  -> user assertion, user-approved derived mapping, or counterfactual rule
```

Confidence is metadata, not evidence. A counterfactual route never replaces
the observed route. An approved mapping may be replayed into a new immutable
derived revision, but never edits the revision on which it was proposed.

Correlation report version 2 remains unchanged. Assistant proposals belong in
a separate run/proposal document until a later schema explicitly introduces a
dedicated section.

## Proprietary information and secrets

Every workspace resolves to an explicit, versioned disclosure policy. Absence
means immutable synthetic version `0` with mode `disabled`; policy-looking
workspace metadata has no effect. The closed modes are:

- `disabled`: disclose nothing;
- `client_safe`: permit only public metadata and the same redacted,
  client-safe class that core may publish to an authorized browser; and
- `full_fidelity`: additionally permit proprietary workspace evidence.

An enabled policy also names one or both approved local transports,
`in_process` and `local_subprocess`. No string or adapter can add a third
transport. A runner's own capability ceiling is intersected with this
workspace policy; neither side can grant what the other denies.
`never_assistant` dominates every mode and transport.

An authorized workspace may therefore deliberately select full-fidelity
private analysis. That mode may expose proprietary resource identifiers,
UUIDs, addresses, event payloads, platform names, chip names, route state, and
decoded source records to the approved model. It is not a public egress path.

Full fidelity does not mean unlimited transfer. Queries remain tenant,
workspace, revision, time, and byte scoped; results are paged and every item
has a stable evidence reference. This is required for deterministic replay and
100K-scale operation rather than for semantic restriction.

Credentials, private keys, tokens, and fields declared `never_assistant` are
not exposed even in full-fidelity mode. Every run records a disclosure ledger
with the immutable revision vector and context digest.

Policy administration is durable and fail-closed. `GET
/v1/control-plane/projects/{project_id}/workspaces/{workspace_id}/private-analysis-policy`
requires workspace read scope and returns a strong numeric `ETag`. `PUT` is
restricted to `control-plane:admin`, requires that ETag in `If-Match`, and
appends a new immutable policy revision. Stale updates return `409`; missing or
non-canonical policy fields return `422`. The policy digest and payload-free
decision reason can be recorded without copying the evidence being evaluated.
The workspace row carries a version-zero root and current chain tip. Every
explicit revision is sealed over scope, version, policy, actor, timestamp, and
its predecessor; a redundant current head and exact-revision idempotency
receipt are reconciled with the complete contiguous history on every read and
write. Missing or independently corrupted rows therefore fail closed instead
of silently reactivating an older permission.

This is catalog-integrity checking, not protection from the catalog
administrator. The local SQLite file, its schema/triggers, and the state
directory are inside the trusted single-host boundary. A privileged writer who
can remove those controls and coherently replace the workspace root/tip, head,
history, seals, and receipts—or restore all of them from one older snapshot—can
roll policy state back. Deployments requiring protection from that actor must
put policy checkpoints in an independently administered append-only/WORM
system. The v1-to-v2 migration similarly authenticates the valid legacy prefix
it can observe; it cannot prove that a privileged writer did not erase a suffix
before the first migration.

## Immutable evidence values

Core now exports versioned evidence-reference and evidence-envelope values;
this is a library/tool-wire contract, not a model runner or an HTTP analysis
endpoint. One reference identifies one atomic projection from one immutable
revision. It binds tenant, project, workspace, fixture content digest, catalog
revision and dataset digest, node, execution-plan basis and digest, producer,
evidence kind, plug-in-defined subject kind, payload schema, disclosure class,
fact provenance, explicit time coordinate, and content digest. Planless legacy
revisions are not eligible for this contract.

Plug-in producers are qualified by the exact plan's `instance_id`, `plugin_id`,
and declared capability. `plugin_id` alone, registration order, a live plug-in
object, mutable session, route/topology context handle, and `plugin_run_id` are
never evidence identity. A catalog-aware verifier reconstructs the binding
from trusted workspace, fixture, revision, and execution-plan descriptors and
fails closed on any mismatch. Core authority remains distinct from plug-in
inference: core producer IDs are a closed enum, while plug-in IDs remain bound
to exact plan pins. Fact provenance is another closed general enum: `observed`,
`snapshot_observed`, `log_derived`, `state_reconstructed`,
`relationship_inferred`, `route_resolved`, `topology_inferred`,
`core_corroborated`, or `not_applicable`. Plug-in-specific vocabulary belongs
in subject kinds and payload schemas, not authority-like provenance text.
Assistant suggestions are not admitted as evidence, and mutable user
annotations wait for a later binding that includes their exact version, audit
watermark, payload digest, and referenced revisions.

The coarse evidence kinds are closed core vocabulary (`revision_metadata`,
`artifact_excerpt`, `source_record`, `event`, `resource_identity`,
`resource_state_interval`, `relationship_interval`, and `plugin_schema`). The
specific subject kind and payload schema remain plug-in vocabulary. A state
claim must identify an interval rather than a top-level resource row. Raw
locator identity is hashed through a versioned, typed canonical wrapper, so a
citation contains no source locator, resource key, filesystem path, callback,
database handle, or mutable runtime context.

References are projection-bound: the disclosure class, payload schema, and
domain-separated content digest are all covered by the self digest. Thus a
client-safe and a full-fidelity projection of one source record have different
references. Payloads are detached into strict canonical JSON and every new
evidence digest uses a `sha256:` prefix; existing catalog SHA fields retain
their established bare-hex format. Integers in payload JSON are restricted to
the interoperable JSON-safe range, while larger opaque or nanosecond values
are canonical decimal strings. Each payload is limited to 1 MiB, 16 container
levels, 1,024 items per container, 4,096 value units, and 65,536 characters per
atom.

An envelope additionally binds the payload-free disclosure decision and can
be constructed only for an allowed decision whose evidence class matches the
reference. A domain-separated scope digest binds that decision to the exact
tenant/project/workspace without repeating those IDs inside the decision;
cross-workspace replay fails closed. `never_assistant` cannot produce an
envelope. Wire parsers require non-empty reference and envelope digests and
never switch into construction mode for missing identity. This decision object
is not an authorization token. The implemented trusted read-only tool service
resolves references through deployment adapters, requires an independent
catalog-binding validator, re-authorizes the exact request, re-evaluates
current policy before release, and records every disclosed reference in its
request-local citation ledger.

Multi-node claims cite multiple atomic references. They do not turn a mutable
session, snapshot member, transient topology context, or route-trace ID into a
synthetic source fact.

## Typed request and advisory-output values

Core exports a versioned request/result contract for the implemented evidence
tool service and later model-runner stages. The values alone remain a library
and local wire contract: they do not enable a model, retrieve evidence,
authorize a caller, persist a run, or add an HTTP analysis endpoint.

A `PrivateAnalysisRequest` binds all authority-relevant inputs before model
execution:

- the exact tenant/project/workspace scope;
- a non-empty, canonical, duplicate-free vector of at most 128 immutable
  revision bindings;
- runner ID, runner version, one of the two closed transports, and a runner
  configuration digest;
- workspace disclosure-policy, trusted instruction-profile, and exact
  read-only tool-catalog digests;
- a closed task kind, an untrusted user query, an explicit clock mode and
  optional time coordinate; and
- bounded evidence, tool-call, output, claim, proposal, and deadline limits.

The request self-digest covers all of those fields. Nanosecond coordinates use
canonical decimal strings on the wire; `latest_per_revision` deliberately has
no numeric coordinate. Parsing a request verifies its exact shape and digest
but does not prove authorization, policy freshness, runner availability, or
revision existence.

A `PrivateAnalysisResult` is bound to one request digest and contains a
support-labeled summary claim, additional claims, and proposals. The summary
is not a free-form escape hatch: it follows the same evidence-supported versus
unsupported-hypothesis rules as every other claim and consumes one slot from
the request's positive `max_claims` budget. Every evidence-supported claim has
at least one unique, canonically ordered `PrivateAnalysisCitation`; an
explicitly unsupported hypothesis has none. A citation contains only an
immutable evidence-reference digest. Before accepting a result, core must call
`validate_private_analysis_result` with the original request and the exact
reference ledger actually disclosed during that run. The validator rejects a
different request, scope, revision vector, undisclosed citation, duplicate
ledger entry, or request-specific output-budget violation. Constructing or
parsing a reference is not a substitute for that ledger.

Proposals are always `assistant_suggested`, cite disclosed evidence, and carry
a producer-named payload schema plus a deep-detached, bounded, strict-canonical
JSON object. Their confidence is metadata. No proposal mutates a revision,
becomes plug-in evidence, or enters the annotation store until later
deterministic validation and explicit human promotion.

Failures use a closed stage/code/retryability matrix and a static payload-free
safe message. Arbitrary exception text, file paths, model output, and runner
diagnostics are not part of the error wire value. A versioned outcome is an
exact exclusive choice between one result and one error. Each nested value and
the outcome have content-verified self-digests; strict parsers reject duplicate
members, unknown fields, missing digests, noncanonical JSON, unsafe integers,
and oversized wire values.

Summary, claim, and proposal text is proprietary analysis output, not
automatically client-safe text. Display and export surfaces added later must
apply their own authorization, disclosure, and safe-rendering boundaries.
Run storage, durable disclosure-ledger persistence, model execution, and
promotion remain separate implementation stages. The ephemeral evidence-tool
service described below now supplies retrieval and a request-local citation
ledger only.

## Inert read-only tool contract

Core exports one closed, self-digested catalog containing exactly
`query_evidence` and `read_evidence`. It is a value contract, not a service:
definitions carry only closed names and argument/result contract versions.
There is no handler, Python callable, database or filesystem handle, shell,
network socket, dynamic loader, or plug-in callback in the catalog or its wire
values.

Every tool binding names one tool and binds the exact request digest and
catalog digest. Query and read arguments are separately typed so a read cannot
be dispatched with query arguments or vice versa. Query filters stay generic
and plug-in-neutral; they select immutable evidence references by declared
evidence kind and bounded producer, node, or subject vocabulary. Query pages
contain unique references in strict `reference_digest` order. They do not
contain evidence payloads. Filter families are ANDed and values inside one
family are ORed; an empty family means unrestricted inside the parent request.
The pure paging helper accepts only an already authorized,
disclosure-eligible frozen reference set and rejects a member outside those
filters. It does not discover or authorize that set.

Paging uses a typed keyset cursor, never a mutable offset. The cursor binds the
request, tool catalog, canonical query fingerprint, immutable eligible-set
snapshot digest, and last returned reference digest. Replaying it under a
different request, catalog, query, or snapshot fails closed. `read_evidence`
accepts exactly one reference digest and its result contains exactly one
matching, already disclosure-gated `EvidenceEnvelope`.

Tool calls and results are canonical, bounded, self-digested values. Tool
errors use a closed, payload-free taxonomy and static local messages; runner
or storage exception text does not cross the wire. The catalog and its wire
values still do not look up a revision, authorize a caller, evaluate
disclosure, materialize payloads, record a ledger, or execute a model. A
separate trusted service now interprets those inert values; this does not add
executable authority to the catalog itself.

## Trusted ephemeral evidence-tool service

`PrivateAnalysisToolService` is the implemented request-local adapter between
the inert tool contract and deployment-owned evidence stores. Construction
deep-detaches one exact `PrivateAnalysisRequest`, requires the catalog digest
to equal the shipped closed catalog, and requires the supplied runner policy's
transport to equal the request transport. Every call is parsed into a detached
value and must bind that same request digest and catalog digest. Reusing a
`call_id` is a runner protocol error.

The service receives six deliberately separate trusted callbacks:

- an authorizer returning a `PrivateAnalysisAuthorizationDecision` bound to
  the exact request and tenant/project/workspace scope digest;
- a current workspace-policy resolver returning a
  `PrivateAnalysisWorkspacePolicySnapshot` with the exact scope, version,
  policy, and verified policy digest;
- a reference query that returns the complete bounded candidate set for one
  query;
- an exact reference lookup for one digest;
- a required trusted-catalog binding validator; and
- a payload materializer that is callable only after reference, scope,
  revision, binding, and initial disclosure checks.

The separation prevents a payload callback from becoming a discovery API and
prevents a reference lookup from claiming catalog validity. The callbacks are
trusted deployment composition, but their returned values are not: the
service detaches and validates them. Callback exceptions other than process
control are contained and become static payload-free service or tool errors;
arbitrary callback diagnostics never cross the tool wire.

Authorization and disclosure are live decisions, not construction-time
capabilities. The authorizer is called on every tool call and again immediately
before any successful release. Current policy is resolved on every call and
again before release; its digest must remain the digest bound into the
request. Query candidates from another scope or an unrelated requested
revision are omitted without revealing their existence. A same-node,
same-revision identity conflict fails the query closed. A direct read of a
foreign or disclosure-denied reference returns the same `evidence_not_found`
shape as an absent reference. Binding failures and malformed provider values
fail unavailable rather than becoming citations.

Queries ledger the returned references even though they contain no payload.
This is intentional: a model can cite metadata learned from a query page.
Every continuation re-runs the reference query and reconstructs the eligible
set. The keyset cursor's snapshot digest therefore detects membership or
policy-eligibility drift rather than silently continuing over a changed set.
Payload reads return one freshly disclosure-bound `EvidenceEnvelope`.

One lock protects the request-local call-ID set, unique-reference ledger, and
cumulative budgets. An authorized call that passes runner-protocol admission
consumes one tool-call unit before evidence-provider work. Authorization
denials and malformed runner calls do not consume request budget. The item
budget counts unique disclosed reference digests across query
and read results; the byte budget counts every successful transfer, including
repeated references. Query bytes are the UTF-8 sizes of canonical reference
objects, while read bytes are the UTF-8 size of the canonical envelope.
Ledger additions and cumulative byte charging commit atomically; a result that
would exceed either limit returns `budget_exceeded` without partially adding
references or bytes. `budget_state` and `disclosed_references` expose detached
snapshots for later result validation.

For runner composition, a pristine service can issue one exclusive
`PrivateAnalysisToolRunLease`. Acquiring it is race-safe with direct calls,
requires empty call/budget/ledger state, and permanently makes the service a
single-run object. While the lease is open, calls without that exact authority
fail closed; after release, no further calls are admitted. Its budget-neutral
run-access check re-authorizes the exact request and resolves the current
pinned workspace policy without materializing evidence.

Direct-call and runner modes are mutually exclusive by an explicit lifetime
latch, not inferred only from counters. The first admitted direct attempt
permanently prevents lease acquisition even if a zero-call budget returns
`budget_exceeded` or authorization fails before a call unit is charged.

This service is intentionally ephemeral and read-only. It owns no database,
filesystem, network, shell, model runner, plug-in invocation, HTTP endpoint,
run lifecycle, durable accounting, or promotion authority. Durable run and
ledger storage, subprocess isolation, API composition, and user-visible model
workflows remain later stages.

## Trusted in-process runner

`ConfiguredPrivateAnalysisInProcessRunner` is the first executable model
transport. It is configured with one exact `PrivateAnalysisRunnerSelection`,
the trusted instruction-profile digest already pinned by the request, and an
operator-supplied callback. Only `in_process` selections are admitted. Runner
ID, version, configuration digest, instruction-profile digest, shipped catalog
digest, and the tool service's complete canonical request must all agree
before the callback can run.

The callback is invoked exactly once. It receives fresh detached request and
catalog values plus a narrow request-local gateway as its supported interface;
core does not expose a public tool-service, provider callback, store, plug-in,
filesystem, shell, or socket handle through that interface. Calls cross the
gateway as bounded canonical
`PrivateAnalysisToolCall` JSON and return freshly detached typed results or
errors. The gateway is synchronous, owner-thread-affine, non-reentrant, and
closed before finalization. Malformed, duplicate, cross-thread, recursive, or
retained calls terminal-latch a static runner error even if the trusted
callback catches the local abort. One extra exchange may report that the tool
budget is exhausted; later attempts fail terminally, so rejected calls cannot
grow an unbounded transcript.

The supported callback interface does not expose terminal state, exchange
counts, metadata-byte counters, or chain digests. Core obtains those values as
one private atomic snapshot only after it closes the gateway on the owner
thread; callback-visible execution, deadline, and close operations remain
thread-affine.

Access is checked before the request/query reaches the callback and again
after the gateway closes. Only then does core snapshot the disclosure ledger,
parse the callback's canonical `PrivateAnalysisResult` JSON, apply the
request-specific byte/claim/proposal ceilings, and validate every citation
against that exact ledger. The returned internal receipt contains detached
outcome and ledger snapshots plus counters and a payload-free transcript
digest. The transcript is a domain-separated constant-memory hash chain over
validated call/result identities and its final outcome; it retains no query,
evidence payload, model text, exception, path, or timestamp.

The request deadline is enforced cooperatively with a monotonic clock before
and after admission, each gateway exchange, callback return, final access
check, and result validation. A result that crosses the deadline while being
parsed or citation-validated is discarded as `timeout`. Python cannot safely
kill an arbitrary callback in the same process, so a callback that never
returns and never reaches the gateway can still hang the host indefinitely. No worker
thread is left behind to simulate cancellation. Durable cancellation and the
hard-kill local-subprocess boundary are separate stages.

Deadline precedence is systematic: if an authorization, policy, tool,
malformed-call, or result-validation operation crosses the monotonic deadline,
the run records `timeout` rather than the otherwise applicable error returned
by that late operation.

The callback is process-trusted and unsandboxed. It may already possess Python
process authority supplied by its deployment; this adapter cannot prevent a
deliberately hostile callback from finding globals or opening its own files,
network connections, or child processes. The same rule applies to deliberate
reflection into or mutation of the gateway's private lease/transcript state:
that behavior is outside this trusted adapter's contract, though detected
private-state bypass fails with a static protocol result rather than leaking a
constructor diagnostic. Core itself imports and grants none of those
capabilities through the supported interface. The adapter adds no public
provider SDK, model
endpoint or key setting, automatic network fallback, HTTP/CLI entry point,
database, durable run, retry loop, annotation write, promotion, or plug-in
invocation.

## Tool and instruction boundary

The model receives a closed catalog of read-only analysis tools rather than a
database handle, Python object, filesystem path, shell, plug-in callback, or
network socket. Tool arguments and model output are untrusted input and pass
the same typed validation, tenant isolation, pagination, and budget checks as
human/API requests.

Dump text, LTTng messages, source records, annotations, and plug-in descriptions
are always represented as evidence data. They are never concatenated into the
trusted instruction channel. Every model claim cites immutable evidence or is
marked as an unsupported hypothesis.

## Multi-plug-in prerequisite

AI analysis operates on exact plug-in execution plans, not whichever plug-in
happens to be installed later. Each new durable node/revision now pins plug-in
instance, version, package, configuration, schema, and any decoder actually
used. Same-node
component results remain producer-qualified, and cross-plug-in or cross-node
equivalence requires exact canonical keys or an explicit federation linker.

This prerequisite permits different platforms, firmware versions, and chip
observers to coexist without disclosing their vocabulary to core and without a
last-writer-wins merge.

## Reopening this decision

Adding a network model transport, a public-provider dependency, direct model
mutation authority, or automatic promotion of model output requires a new
version of this decision, an explicit user request, a threat-model update, and
updated structural and behavioral tests. It must not be introduced as an
adapter option or configuration default.

Repository tests conservatively detect new dependencies, import capabilities,
dynamic loading, and endpoint/key configuration on deployable surfaces. They
are change-control guardrails, not a proof against intentionally malicious
source code or a substitute for deployment egress controls. Production must
also deny network access to the analyzer and its local model process at the OS
or container boundary.

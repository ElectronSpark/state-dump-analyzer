# Private AI analysis boundary

Status: normative architecture decision with implemented local value/tool
contracts, trusted in-process and shell-free local-subprocess runners, a
durable local-only run/lifecycle store, a core-owned synchronous execution
coordinator, and an authenticated application/HTTP lifecycle facade.

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
Model execution and promotion remain separate from the value contract. The
ephemeral evidence-tool service described below supplies retrieval and a
request-local citation ledger; the durable run store described later records
that ledger only through an explicit write-ahead accounting boundary.

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

This tool service is intentionally ephemeral and read-only. It owns no
database, filesystem, network, shell, model runner, plug-in invocation, HTTP
endpoint, run lifecycle, durable accounting, or promotion authority. The two
adjacent runner adapters consume an exclusive service lease. Durable run and
ledger storage plus the authenticated lifecycle facade are separate implemented
layers; a browser workflow and proposal promotion remain later stages.

## Trusted in-process runner

`ConfiguredPrivateAnalysisInProcessRunner` is one executable model
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

Both executable adapters use the same detached last-complete accounting
snapshot. It is refreshed after successful tool execution and during normal
finalization, then reused if a later lease snapshot, close, transcript seal, or
receipt construction fails. A static failure therefore cannot erase calls or
evidence already disclosed. Receipt constructors revalidate and detach their
transcript arguments before storing them. For the process-trusted callback,
detected reflection that invokes the private lease without the supported
gateway is reported as `runner_protocol_error`; the payload-free transcript
keeps the real ledger/budget and records those calls as unattributed rather
than fabricating a zero-use run.

The request deadline is enforced cooperatively with a monotonic clock before
and after admission, each gateway exchange, callback return, final access
check, and result validation. A result that crosses the deadline while being
parsed or citation-validated is discarded as `timeout`. Python cannot safely
kill an arbitrary callback in the same process, so a callback that never
returns and never reaches the gateway can still hang the host indefinitely. No worker
thread is left behind to simulate cancellation. Durable cancellation remains
separate; the implemented hard-kill local-subprocess boundary is described
below.

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

## Shell-free local subprocess runner

`ConfiguredPrivateAnalysisSubprocessRunner` implements the second executable
transport as one ephemeral, direct-child adapter. Construction admits only an
exact `local_subprocess` runner selection whose configuration digest equals a
sealed `PrivateAnalysisSubprocessLaunchConfiguration`. The request must bind
that selection, the same trusted instruction-profile digest, and the shipped
tool-catalog digest before core launches anything or discloses the request.

The launch value is deliberately complete rather than an overlay on host
state. `argv` is an exact tuple of 1 to 128 bounded scalar strings; `argv[0]`
must be an absolute path, `.bat` and `.cmd` command-interpreter scripts are
rejected, and the portable Windows command-line projection is capped at 30,000
UTF-16 units. On Windows, no executable or working-directory component may end
in a period or space; validation rejects these Win32-normalization-ambiguous
paths before checking the normalized executable extension. The working
directory is a bounded absolute scalar path. The
environment is an exact tuple of at most 256 `NAME=value` pairs with restricted
ASCII names, case-insensitive uniqueness, bounded scalar values, and a 256 KiB
aggregate limit. Core sorts that environment and passes it as the complete
child environment; it does not merge ambient variables. The self digest also
covers the adapter identity, stderr limit, terminate/kill grace periods, and
`descendant_policy: forbidden`.

Launch passes the exact argument vector and executable to `Popen` with
`shell=False`, the explicit working directory and environment, binary
unbuffered stdin/stdout/stderr pipes, `close_fds=True`, and no new session. On
Windows the child is hidden with `CREATE_NO_WINDOW` when available. There is no
shell expansion, command-string parsing, ambient-environment inheritance, or
`PATH` lookup for the executable.

The wire version is
`router_dump_analyzer.private_analysis.local_subprocess_protocol.v1`. Each
message is an exact object with only `contract_version`, `run_digest`,
`sequence`, `kind`, `payload`, and `message_digest`; the self digest excludes
only `message_digest`. The run digest binds request, catalog, instruction
profile, runner configuration, and launch-configuration digests. Payloads are
deep-detached bounded strict JSON objects and nested request/tool/result values
remain opaque until their existing typed parser admits them. Encoding is
strict canonical UTF-8 JSON followed by exactly one LF. Decoding accepts one
complete frame only and rejects blank or oversized data, missing LF, CR/CRLF,
BOM, invalid UTF-8, duplicate members, noncanonical JSON, `NaN`/infinity,
non-object roots, unknown or missing fields, invalid digests, and unsafe or
out-of-order sequences.

The pre-disclosure handshake is exact:

1. parent sends `HELLO` sequence 0 with an empty payload and the bound run
   digest;
2. child returns empty `READY` sequence 1 with that same run digest;
3. core rechecks current authorization and pinned policy; and
4. parent sends `START` sequence 2 containing exactly `request` and
   `tool_catalog`.

After `START`, the child may send `TOOL_CALL`; the parent parses the nested
typed call and returns one `TOOL_RESULT` or `TOOL_ERROR`. The child may repeat
that exchange or terminate with `ANALYSIS_RESULT` or `RUNNER_FAILURE`. Every
message in both directions increments one global JSON-safe sequence by exactly
one and echoes the run digest. A tool call after the one permitted
budget-exhaustion response becomes `budget_exceeded`; malformed typed calls or
an unexpected kind become `runner_protocol_error`.
The monotonic deadline is checked before and after lease admission, after typed
call parsing but before provider entry, and after provider return. It is also
checked after result construction and final transcript/receipt attestation.
Ordinary cleanup or lease-finalizer failures become `runner_failed`; a pending
process-control exception is preserved while those finalizers run best effort.

A terminal message alone is not success. Core closes the child's stdin and
requires the next stdout read to be EOF, not another frame, then requires the
direct child to exit with status zero before the same monotonic request
deadline. It performs another live access check before mapping a payload-free
`RUNNER_FAILURE` or validating an analysis result. A trailing frame is
`runner_protocol_error`; premature EOF, pipe failure, stderr overflow, nonzero
exit, generic child failure, or failed cleanup is `runner_failed`; waiting past
the deadline is `timeout`. Launch `OSError`, selection mismatch, and child
reason `unavailable` map to `runner_unavailable`; child reason `failed` maps to
`runner_failed`. Invalid final model values map to `invalid_result` or
`budget_exceeded` at output validation. Static errors contain no exception,
path, stderr, or child diagnostic, and a measured late operation is reported as
`timeout` instead of its otherwise applicable error. This includes late final
attestation of error outcomes, not only successful results.

Stdout and stderr are drained concurrently by non-daemon helpers so neither
pipe can block the other. Stderr text is never retained; only the admitted byte
count is sealed. Cleanup runs in `finally`, signals the pump, applies bounded
terminate-then-kill waits while the direct child remains live, closes
stdin/stdout, and preserves stderr until its helper drains buffered bytes to
EOF after child exit. A still-live child has stderr closed to unblock the
helper; both helpers are bounded-joined before sealing. Failure to observe child exit
and stopped helpers becomes static `runner_failed` (or `timeout` when the
deadline has expired). This is a fail-closed receipt condition, not an
unconditional OS guarantee that every direct child can be reaped.

This is direct-child fault isolation, not a portable process-tree sandbox. An
adapter is explicitly forbidden to create descendants because Python's
portable subprocess API supplies no Windows Job Object guarantee here; core
cannot promise to reap a prohibited grandchild. The child still runs with the
host user's filesystem and network authority unless deployment containment
removes it, and this adapter sets no CPU or memory quota. Production must use
an OS/container boundary when those authorities are outside the adapter's
trust policy.

The payload-free subprocess transcript seals request, catalog, instruction,
runner, launch, and run digests; direction, sequence, kind, message digest and
frame-size links; message/tool-call counts; the discarded-stderr byte count;
budget and evidence-ledger snapshots; and the final outcome digest. It retains
no request/query, evidence payload, tool payload, model text, stderr,
exception, path, timestamp, argument, or environment value. The receipt is an
internal detached value. Both runner receipts expose a transport-neutral,
payload-free `PrivateAnalysisTranscriptSummary` suitable for the durable
store; a separate coordinator must route it and the runner itself still owns
no persistence.

Unlike the subprocess child, the in-process callback is deployment-trusted,
unsandboxed Python and cannot be forcibly preempted; it can acquire process
globals outside its supported gateway. The subprocess peer is treated as
untrusted at every frame and its direct process is killable, but it is still
not an OS security sandbox. Neither transport itself adds a public model
provider, network client, endpoint/API-key setting, automatic fallback,
HTTP/CLI route, UI workflow, automatic retry, annotation write, or promotion
path. The separate application facade can invoke only an explicitly registered
local transport through a durable fenced run.

## Durable local run and disclosure store

`SqlitePrivateAnalysisRunStore` is the first durable orchestration layer. It
is a core-owned, model-neutral SQLite store with exact
tenant/project/workspace keys and a closed lifecycle: `queued`, `running`,
`cancel_requested`, `completed`, or `cancelled`. Admission persists the exact
canonical `PrivateAnalysisRequest` and its complete ordered revision vector
only after a trusted catalog validator re-derives every fixture, revision,
node, identity, and immutable plug-in execution-plan binding. The
`ControlPlane` supplies that validator and holds its existing cross-store file
fence across validation and insertion, so catalog retention cannot remove a
revision between those operations.

Every mutation is optimistic-versioned. A claim creates one opaque execution
fence and bounded lease; no expired attempt is retried automatically. Recovery
turns an expired running attempt into the static `runner_failed` outcome, or
an already cancel-requested attempt into `cancelled`, preserving the last
durable accounting. Queued cancellation completes immediately. In-process
cancellation remains cooperative: setting `cancel_requested` does not claim
that arbitrary Python was preempted. Once that request commits, however, an
ordinary worker result cannot overwrite it. Subprocess termination belongs to
the execution coordinator that owns the child, not this storage module.

The runner accounting snapshot accepts an optional observer. After a tool
operation, it invokes that observer with a complete detached reference ledger
and budget before publishing the local snapshot and before the tool response
returns to the model. An observer/store failure propagates and leaves the last
complete snapshot unchanged. `commit_accounting` enforces an append-only
reference set, monotonic counters, exact request ceilings, exact scope and
revision bindings, and a canonical ledger digest. `complete_run` accepts a
terminal value only when the persisted ledger/budget exactly equals the
receipt. Successful results are revalidated at this storage boundary against
that exact ledger and the request's output, claim, and proposal ceilings. The
transport summary must also bind the request, catalog, instruction profile,
runner configuration, outcome, and ledger. Thus a future coordinator cannot
persist only a terminal receipt after evidence was already disclosed or seal
a result that cites evidence outside the durable ledger.

Each transition appends one bounded audit row. The row contains scope,
run/version/attempt identity, closed reason and states, actor, timestamp, and
request/ledger/transcript/outcome digests—never the query, result text,
proposal, evidence/tool payload, stderr, exception, path, argv, or environment.
Entries are contiguous, predecessor-sealed, and checked against a redundant
run head and state-snapshot digest on one SQLite read snapshot. The state seal
includes the exact budget and creation/update/completion times, so accounting
or retention-time edits also fail closed. This detects torn or independently
corrupted rows inside the trusted local database. One run is capped at 10,000
audit transitions, with slots reserved for cancellation and terminalization,
so record reconstruction cannot grow without bound. `ControlPlane` additionally
binds the database's opaque installation identity to a root-level record and
refuses a missing binding, zero-length or missing database, or replacement
database after first initialization. A privileged administrator can still coherently replace or
roll back both files; that stronger threat model requires independently
administered append-only/WORM checkpoints.

The run database deliberately does contain proprietary data at rest: canonical
requests and successful outcomes, plus disclosed references. Its active WAL
and every pre-purge backup or storage-layer copy can retain them. It therefore
uses a dedicated database, `foreign_keys=ON`, WAL, `synchronous=FULL`,
`secure_delete=ON`, bounded busy waits, snapshot-consistent reads,
`BEGIN IMMEDIATE`, a schema lock, strict tables, self-digest reconstruction,
and fail-closed integrity checks. Deployments must apply state-directory ACLs,
backup controls, and disk encryption appropriate to the admitted disclosure
mode.

Run retention is disabled by default. Preview and execution are bounded;
execution is operation-ID idempotent and purges only terminal proprietary run
rows. Queued, running, and cancel-requested runs are never candidates. A
payload-free tombstone and separate self-digested retention journal preserve
the request/ledger/transcript/outcome and audit-tip commitments. While a run is
retained, all of its revision IDs join review references in the catalog's
protected set under the same cross-store retention fence. Independent
active-run guard and live-admission anchors make whole-head or paired-row loss
observable, and admission refuses
more than 10,000 active runs in one scope so catalog-reference reconstruction
has a hard bound. Logical deletion uses SQLite secure deletion inside the
bounded candidate transaction and then a truncating WAL checkpoint. It does
not run a full-database `VACUUM`, whose work would scale with unrelated runs.
If the checkpoint is busy or fails, the committed idempotency journal makes
the same operation safe to retry and the call does not report successful
purge completion. Freelist page reclamation, if desired, is separate offline
database maintenance; secure deletion has already removed the retained
payload bytes from those cells. Retention replaces the live admission with a
scoped idempotency-key digest in the tombstone, preserving replay conflict
semantics without retaining the raw key or growing live-reference scans.

`finalize_unstarted_attempt` is the one transcript-free active transition. It
requires the exact live fence, an unexpired lease, and zero disclosed evidence
and tool consumption. It exists so a request-bound service factory that fails
after the winner has claimed the run can be sealed as a static runner failure
without inventing a transcript. A concurrently committed cancellation wins
and seals the same unstarted attempt as cancelled.

## Core-owned local execution coordinator

`PrivateAnalysisExecutionCoordinator` is the synchronous composition boundary
between the durable store, one exact configured runner, and one trusted
request-bound `PrivateAnalysisToolService` factory. Registrations are a closed
tuple keyed by the complete runner ID, version, transport, and configuration
digest. The runner's sealed instruction-profile digest must also equal the
request. There is no selection by prefix, transport fallback, registration
order, or live plug-in state. Duplicate exact selections are rejected.

An execution reads one scoped queued record, resolves its exact registration,
and claims the durable fence before invoking the service factory. This means
two coordinators racing on one run cannot both create services or invoke a
model. A factory failure, wrong-request service, or service whose visible
accounting or permanent zero-tool lifetime latch is non-pristine seals the
claimed zero-disclosure attempt without a fabricated transcript. An
unknown runner or instruction profile is rejected before claim and leaves the
run queued.

One non-daemon monitor per active attempt polls the durable state, observes
cross-process cancellation, and renews the lease. Heartbeats, accounting, and
completion share one per-attempt optimistic-version owner. A stale mutation is
reconciled at most once and only when the same execution fence is still active
and unexpired. Fence loss, expiry, repeated churn, or monitor/store failure
fails closed and leaves recovery—not a second model invocation—to own the
terminal transition. The configured local concurrency bound and one lock owned
by each runner instance prevent accidental concurrent use of a non-thread-safe
model callback even when that same runner object is registered with multiple
coordinators, while different runner instances can operate concurrently.
Immediately after local registration, the coordinator re-reads the durable
record before it constructs a service. This closes the claim-to-registration
window: a cancellation committed while the attempt was not yet locally visible
finishes without creating or consuming a tool service.

Both runner transports accept the same cancellation probe. The in-process
adapter observes it cooperatively before/after tool and callback boundaries;
Python that never returns and never uses the gateway still cannot be forcibly
preempted. The subprocess adapter polls while writing, reading, and waiting for
exit, then closes input and uses its existing terminate/kill/join cleanup.
`cancelled` is attestable only after the direct child and helpers are stopped;
a cleanup-unattested receipt remains `runner_failed`. If cancellation commits
after a runner sealed an ordinary receipt but before durable completion, the
same transcript metadata, ledger, and budget are re-sealed against a closed
cancelled outcome rather than discarded or rewritten.

Accounting remains write-ahead: an identical snapshot is checked but not
appended again, while every new complete ledger/budget pair commits before the
tool response reaches the model. If cancellation is already durable at that
commit, the observer still returns after the commit so the runner can publish
the identical local accounting snapshot; the immediately following probe then
performs the cooperative cancellation. Completion uses the latest durable version
and exact transport-neutral transcript summary. A terminal race is accepted
only when the store proves the local receipt exactly equals the already-sealed
receipt; a conflicting recovery or writer is never treated as idempotent.
Terminal replay before execution returns the stored record and never invokes
the runner again. Ordinary runner errors are
stored as typed receipts; process-control signals propagate after bounded
cleanup and leave the fence for explicit expiry recovery. There is no
automatic retry.

`ControlPlane` constructs this coordinator over its bound run store. Its
runner-registration tuple is empty by default, so merely starting the product
does not configure a model. Shutdown closes the execution coordinator before
its store; if trusted in-process code does not cooperate before the timeout,
shutdown fails and leaves dependent stores open for a later retry.

The coordinator itself exposes no HTTP, CLI/UI, provider, network, plug-in,
annotation, or promotion authority. The adjacent application facade described
below is the only supported route from authenticated caller intent to this
durable coordinator and preserves its write-ahead and fence rules.

## Authorized run application service and HTTP lifecycle

`PrivateAnalysisService` is a core-owned application facade over the session
catalog, durable run store, and execution coordinator. Its request spec contains
only caller-owned intent: a workspace scope, a canonical set of revision IDs,
one public runner ID/version pair, task kind, query, clock selection, and bounded
limits. The service re-resolves the workspace and every immutable revision,
requires plan-bound catalog identity, reads the current workspace disclosure
policy, resolves one unambiguous local runner registration, and derives the
policy, instruction-profile, runner-configuration, and closed tool-catalog
digests. Callers cannot submit or override those authority-bearing values.

Runner discovery returns detached identities only and filters them through the
current workspace policy. Registrations must have a unique public
`(runner_id, runner_version)` pair even when their complete internal selections
differ, preventing an advertised choice from routing ambiguously. The default
registration tuple remains empty.

Authenticated control-plane routes expose the resulting lifecycle under
`/v1/control-plane/projects/{project_id}/workspaces/{workspace_id}`: list local
runners, create/list/read runs, execute or cancel an exact version, and read a
terminal report. Reads require `control-plane:read`; mutations require
`control-plane:write`. Create requires `Idempotency-Key`; execute and cancel
require a strong numeric `If-Match`. Create, single-run read, execute, cancel,
and report responses carry numeric ETags; list responses do not. Run views use
decimal strings for nanosecond coordinates and omit query text, evidence
payloads, transcripts, execution IDs, leases, callback objects, and internal
audit state. The terminal report adds the original query and canonical advisory
outcome through a display-safe projection that is not canonical wire/digest
input; it remains advisory and has no
mutation or proposal-promotion authority. Execution runs the already durable,
fenced request once off the event loop through the server's thread executor;
the application service first requires the current run version and rechecks
that the workspace policy still enables the request transport, while the tool
service performs the final race-safe policy check before disclosure. The
coordinator limits concurrently active executions. Even a terminal replay
requires the current version. Execution never retries or falls back to another
transport.

This lifecycle is not model-provider configuration. The public contract has no
endpoint, API-key, SDK, arbitrary command, environment, network-transport, or
plug-in-selection field. Deployment composition must supply an approved local
runner and request-bound tool-service factory before any run can execute.

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

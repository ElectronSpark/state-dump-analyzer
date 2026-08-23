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

Correlation report version 2 remains unchanged. Assistant proposals stay in
their separate run/result document. The implemented review service records a
digest-pinned human decision and, for promotion, writes an ordinary
human-authored annotation or manual correlation through the existing review
overlay; it does not inject model payload into the correlation-report schema.

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
and exactly one declared capability or execution-plan role. Generic normalized
records bind the exact `primary_parser` role; optional projections bind their
declared capability. Version-1 capability references remain wire compatible,
version 2 adds the mutually exclusive `plugin_role` field and unknown-time
representation, and version 3 adds the closed `plugin_capability_result` kind
and `plugin_analyzed` provenance. V1/v2 references cannot be minted with the
new v3 semantics. `plugin_id`
alone, registration order, a live plug-in
object, mutable session, route/topology context handle, and `plugin_run_id` are
never evidence identity. A catalog-aware verifier reconstructs the binding
from trusted workspace, fixture, revision, and execution-plan descriptors and
fails closed on any mismatch. Core authority remains distinct from plug-in
inference: core producer IDs are a closed enum, while plug-in IDs remain bound
to exact plan pins. Fact provenance is another closed general enum: `observed`,
`snapshot_observed`, `log_derived`, `state_reconstructed`,
`relationship_inferred`, `route_resolved`, `topology_inferred`,
`core_corroborated`, `plugin_analyzed`, or `not_applicable`. Plug-in-specific vocabulary belongs
in subject kinds and payload schemas, not authority-like provenance text.
Assistant suggestions are not admitted as evidence, and mutable user
annotations wait for a later binding that includes their exact version, audit
watermark, payload digest, and referenced revisions.

Temporal evidence never invents a timestamp. Retained events and source
records with no producer timestamp are included in `latest_per_revision`
analysis with the explicit `unknown` time basis. Absolute and
revision-end-relative historical requests fail closed when such a fact is
present because the core cannot prove on which side of the requested cutoff it
belongs. `not_applicable` remains reserved for genuinely non-temporal evidence
such as revision and plug-in metadata.

The revision adapter also never assumes that a normalized node timestamp is
Unix time. A loader-verified `_ingestion.timeline_time_basis` may declare
`absolute_unix_ns` or `source_clock_ns` (the latter requires
`timeline_clock_domain`). Without that proof, signed timeline coordinates are
preserved as `revision_start_relative_ns`. Declared/default relative values are
already offsets from revision start: `_ingestion.timeline_start_ns` is only the
lower bound and is never subtracted as an origin. Absolute analysis fails
closed for such a revision; latest and revision-end-relative analysis remain
available. An uncertain observation whose possible interval overlaps a
historical cutoff is retained with its uncertainty, while one whose entire
interval is later is excluded.

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

An unsafe or path-shaped source execution-plan basis is projected to a
domain-separated opaque digest before it enters a reference. The exact plan
digest still binds the original basis, so this prevents path disclosure
without creating a second interpretation identity.

Multi-node claims cite multiple atomic references. They do not turn a mutable
session, snapshot member, transient topology context, or route-trace ID into a
synthetic source fact.

## Frozen revision evidence corpus

`ControlPlane` can provide a runner registration with
`core_revision_evidence_policy` instead of a custom evidence-service factory.
Immediately before runner entry, core revalidates the request's current
workspace, fixture, revision, dataset, execution-plan, and disclosure-policy
bindings. It loads exactly the requested revisions, resolves absolute,
latest-per-revision, or revision-end-relative time independently for every
member, and refuses an out-of-range time rather than clamping it.

The adapter freezes revision metadata, execution-plan pins, retained source
records, normalized events, active resource identities/states, and present
relationships into one immutable indexed corpus. Future records are excluded,
and lifecycle/state/relationship intervals use half-open
`[valid_from, valid_to)` semantics. References remain qualified by each
revision's exact primary parser, so different platforms and firmware may use
the same evidence kind without being merged by name or registration order.
Indexes cover scope, revision, kind, node, producer, and subject; a narrow
query does not rescan a 100K-event revision. Construction is bounded by
independent deployment ceilings for count (at most two million entries) and
aggregate canonical payload (512 MiB by default, 2 GiB hard maximum), while
tool snapshot, page, citation, byte, and call budgets remain smaller.
Cancellation/deadline probes run during chunked dataset reads, JSON indexing,
client-safe descriptor/resource redaction-policy compilation, projection, and
corpus indexing rather than only between revisions. Deterministic active-
resource ordering uses cancellable chunked sort/merge, and probes bracket each
selected record's normalization, payload hash, reference construction, and
immutable payload freeze.

Client-safe mode uses the existing descriptor-aware event/resource and
source-record projections. If, and only if, both the workspace policy is
`full_fidelity` and the selected local runner explicitly permits full-fidelity
workspace data, plug-in-owned normalized fields and retained `copy_text` are
instead frozen as `proprietary` evidence. This is the local bridge for
proprietary LTTng and state-dump vocabulary; it adds no public model API and
never generates `never_assistant` evidence.

Mixed device and firmware families do not share a mutable global plug-in
choice. Durable ingestion first selects one exact primary parser for each
fixture, then applies a deployment-owned `PluginCompositionPolicy` keyed by
that primary instance and its content-addressed executable identity. A rule can
add only its explicit, canonically ordered auxiliary identities and roles. The
policy digest is stored on the import and every worker phase refuses drift.
It is also stored as the current plan's `composition_policy_digest`, so an
unrelated policy edit changes revision and downstream analysis identity even
when this primary selects the same auxiliaries. The resulting immutable
execution plan therefore qualifies every evidence
producer without relying on registration order, matching product names, or a
synthetic composite plug-in.

The `plugin_schema.v1` evidence payload includes a current plan-v3 pin's exact
content-addressed `registered_execution_identity`. A retained plan-v1 pin had
neither that field nor the current timeline/composition semantics. Such a plan
remains catalog-readable but is rejected before corpus construction; its
internal all-zero sentinel is never emitted as evidence authority. Changing a
v2 identity changes the payload content digest, evidence reference digest, and
corpus snapshot identity. Retained plan-v2 pins carry the same registered
execution identity but decode without invented execution authority.

## Typed request and advisory-output values

Core exports a versioned request/result contract for the implemented evidence
tool service and later model-runner stages. The values alone remain a library
and local wire contract: they do not enable a model, retrieve evidence,
authorize a caller, persist a run, or add an HTTP analysis endpoint.

New requests use `private_analysis.request.v3`, which binds the selected
deployment-owned evidence-service digest as well as the runner, policy,
instruction, configuration, and tool-catalog identities. Retained request v2
decodes with an explicit legacy zero digest and cannot execute against a
current registration.

A `PrivateAnalysisRequest` binds all authority-relevant inputs before model
execution:

- the exact tenant/project/workspace scope;
- a non-empty, canonical, duplicate-free vector of at most 128 immutable
  revision bindings;
- runner ID, runner version, one of the two closed transports, and a runner
  configuration digest;
- workspace disclosure-policy, trusted instruction-profile, exact read-only
  tool-catalog digest, and deployment-owned evidence-service digest;
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
becomes plug-in evidence, or enters the annotation store. The explicit human
review workflow can create a separately authored, independently validated
review overlay pinned to that proposal and result.

Failures use a closed stage/code/retryability matrix and a static payload-free
safe message. Arbitrary exception text, file paths, model output, and runner
diagnostics are not part of the error wire value. A versioned outcome is an
exact exclusive choice between one result and one error. Each nested value and
the outcome have content-verified self-digests; strict parsers reject duplicate
members, unknown fields, missing digests, noncanonical JSON, unsafe integers,
and oversized wire values.

Summary, claim, and proposal text is proprietary analysis output, not
automatically client-safe text. Display and export surfaces apply their own
authorization, disclosure, and safe-rendering boundaries.
Model execution and promotion remain separate from the value contract. The
ephemeral evidence-tool service described below supplies retrieval and a
request-local citation ledger; the durable run store described later records
that ledger only through an explicit write-ahead accounting boundary.

## Inert read-only tool contract

Core exports one closed, self-digested catalog containing exactly
`query_evidence`, `read_evidence`, and `analyze_evidence`. It is a value contract, not a service:
definitions carry only closed names and argument/result contract versions.
There is no handler, Python callable, database or filesystem handle, shell,
network socket, dynamic loader, or live plug-in object in the catalog or its wire
values.

Every tool binding names one tool and binds the exact request digest and
catalog digest. Query and read arguments are separately typed so a read cannot
be dispatched with query arguments or vice versa. Query filters stay generic
and plug-in-neutral; they select immutable evidence references by declared
evidence kind and bounded producer, node, or subject vocabulary. Query pages
contain unique references in strict `reference_digest` order. They do not
contain evidence payloads. Filter families are ANDed and values inside one
family are ORed; an empty family means unrestricted inside the parent request.
The v2 query arguments may also carry one inclusive overlapping time window:
`time_basis`, `time_start_ns`, and `time_end_ns` are supplied together, with
`time_clock_domain` required only by source-clock coordinates. Nanosecond
bounds are canonical decimal strings on the wire. A bounded window excludes
unknown/not-applicable time, expands reference intervals by their declared
uncertainty, and is served from the corpus time index.

The pure paging helper accepts only an already authorized,
disclosure-eligible frozen reference set and rejects a member outside those
filters. It does not discover or authorize that set.

Paging uses a typed keyset cursor, never a mutable offset. The cursor binds the
request, tool catalog, canonical query fingerprint, immutable eligible-set
snapshot digest, and last returned reference digest. Replaying it under a
different request, catalog, query, or snapshot fails closed. `read_evidence`
accepts exactly one reference digest and its result contains exactly one
matching, already disclosure-gated `EvidenceEnvelope`.

`analyze_evidence` arguments contain only an exact node ID, revision ID,
one closed route/trace/correlation intent,
canonically ordered parent-reference digests, bounded JSON parameters, and an
observation ceiling. They never contain evidence payloads, package/platform
selectors, configuration values, executable callbacks, or model-chosen
provider identity. The trusted host resolves the unique exact configured
provider from the retained revision plan. A successful value is one derived
evidence envelope. Its producer must bind that provider and standard
`evidence_analysis` capability; its revision must match the arguments; and its
payload must repeat the argument digest, intent and exact parents and contain
only canonical, bounded observations whose citation sets are subsets of those
parents. A model cannot
turn this advisory hook into state mutation, annotation write, shell/network
access, or automatic proposal promotion.

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

The service receives deliberately separate trusted callbacks:

- an authorizer returning a `PrivateAnalysisAuthorizationDecision` bound to
  the exact request and tenant/project/workspace scope digest;
- a current workspace-policy resolver returning a
  `PrivateAnalysisWorkspacePolicySnapshot` with the exact scope, version,
  policy, and verified policy digest;
- either a legacy reference query that returns one complete, at-most-100,000
  candidate set, or the core v2 page query that returns one bounded page plus
  an immutable snapshot digest and continuation bit. The page-query callback
  receives a fourth `Callable[[], bool] | None` cancellation/deadline probe;
- an exact reference lookup for one digest;
- a required trusted-catalog binding validator, with an optional batch
  validator for page results; and
- a payload materializer that is callable only after reference, scope,
  revision, binding, and initial disclosure checks; and
- an optional capability-analysis callback. It receives the exact request,
  provider-free analysis arguments, already-materialized parent envelopes, and
  a cancellation probe. The deployment callback resolves one exact provider
  from the target revision plan and returns only a candidate reference plus
  bounded payload; the service performs the final binding, schema, citation,
  disclosure, and accounting checks. When absent, `analyze_evidence` returns
  the closed `capability_unavailable` error.

The generic service keeps that callback optional for non-catalog deployments.
The shipped `ControlPlane` core-revision-evidence composition provides it. It
selects exactly one `EVIDENCE_ANALYSIS` route from the target revision's
retained plan, converts only request-local materialized envelopes into
immutable `EvidenceAnalysisFact` values, invokes the plan-bound executor, and
mints the v3 derived reference. The model never supplies an instance ID; zero,
multiple, stale, or identity-drifted providers fail closed. Repeated identical
arguments are request-locally idempotent, and a provider that returns a
different result for the same argument digest is rejected.

The separation prevents a payload callback from becoming a discovery API and
prevents a reference lookup from claiming catalog validity. The callbacks are
trusted deployment composition, but their returned values are not: the
service detaches and validates them. Callback exceptions other than process
control are contained and become static payload-free service or tool errors;
arbitrary callback diagnostics never cross the tool wire.

The catalog wire contracts are version 2 after adding the third tool; the
query/read subcontracts retain their own existing versions. Runs admitted
against the former two-tool catalog remain readable as immutable history but
cannot execute with a silently substituted catalog. They must be resubmitted
to bind the current catalog digest and instruction profile.

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
Analysis is stricter: every parent digest must first have been materialized by
`read_evidence` (or by a prior successful analysis) in this same request.
Successful derived envelopes enter the citation ledger and a request-local
materialized overlay atomically with byte/item accounting. Exact reads and
chained analysis can address that overlay; query snapshots remain source-corpus
snapshots and do not change underneath an existing cursor.

The core corpus freezes canonical matching digest membership once per query,
caches that immutable snapshot under a bounded LRU, and returns only the
requested page on continuations. The cursor binds the exact cached membership
digest, request, catalog, and query, so replay remains deterministic without
materializing or revalidating 100,000 references on every page. Corpuses above
100,000 homogeneous events remain queryable; the legacy complete-snapshot
adapter retains its former 100,000 compatibility ceiling. If bounded-cache
eviction removes a cursor's exact snapshot, continuation fails
`cursor_invalid` immediately and never rebuilds membership from that cursor.
Admission also fails while a cursorless rebuild of the same query is in
flight; a continuation never joins that producer to extend cache durability
implicitly.
Core invokes the page-query probe before and after provider execution. The
corpus also invokes it during candidate materialization, predicate scanning,
bounded-chunk sorting, membership hashing, and page copying. A same-key
singleflight waiter uses bounded timed waits and probes outside the corpus
lock; cancellation therefore stops only that waiter, while a cancelled
producer releases its build ownership and wakes all waiters. Process-control
exceptions propagate. Probe failures, non-boolean results, cancellation, and
deadline expiry fail closed as static `evidence_unavailable` tool errors.

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
layers. The core-owned browser workflow and adjacent explicit human
proposal-review service are implemented. Review remains a separate authority
boundary: the evidence tool and model runner still cannot write annotations or
correlations.

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

The v2 launch value is deliberately complete rather than an overlay on host
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
child environment; it does not merge ambient variables. The actual executable
and up to 128 ordered `helper_artifacts` are sealed by canonical absolute path,
regular-file metadata, and bounded content bytes (512 MiB each, 1 GiB total).
Every argv file operand, including `--name=/path`, must be an attested helper
unless its index is explicitly listed in `runtime_data_argument_indices`;
every non-option operand follows the same rule. Runtime-data arguments must
never identify, import, or load code and cannot also name a helper. Generic
`-c` and `-m` dynamic-code forms are rejected regardless of executable name.
The self digest covers those artifact/classification inputs as well as adapter
identity, stderr limit, terminate/kill grace periods, and
`descendant_policy: forbidden`.

Launch passes the exact argument vector and executable to `Popen` with
`shell=False`, the explicit working directory and environment, binary
unbuffered stdin/stdout/stderr pipes, `close_fds=True`, and no new session. On
Windows the child is hidden with `CREATE_NO_WINDOW` when available. There is no
shell expansion, command-string parsing, ambient-environment inheritance, or
`PATH` lookup for the executable. Core repeats argv coverage and bounded
artifact hashing, with cancellation/deadline checks, immediately before
`Popen`; a new file, canonical-path change, or byte/metadata drift fails before
child creation. Raw artifact paths and bytes are not exposed in durable state,
wire values, or representations.

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
helper; both helpers are bounded-joined before sealing. Failure to observe
child exit and stopped helpers withholds the receipt behind the run's durable
cleanup fence. The exact live session/process handle remains owned for bounded
retry; only confirmed cleanup reseals and releases the receipt. No PID is
persisted or reconstructed. This is a fail-closed terminal condition, not an
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
durable accounting—unless a child cleanup fence exists. The same payload-free
fence is created before an evidence-factory or local model-adapter spawn,
contains no PID, and blocks both terminal completion and expiry recovery until
its exact live owner confirms reap. A local model receipt is withheld and
resealed only after that confirmation. Queued cancellation completes
immediately. In-process
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
request-bound evidence mode. Each registration contains exactly one of a
deployment-owned `tool_service_process_factory`, an explicitly cooperative
`trusted_inline_tool_service_factory`, or a `core_revision_evidence_policy`;
the latter requires a composition root such as `ControlPlane` that can build
the verified corpus described above.
Registrations are a closed
tuple keyed by the complete runner ID, version, transport, and configuration
digest. The runner's sealed instruction-profile digest must also equal the
request. There is no selection by prefix, transport fallback, registration
order, or live plug-in state. Duplicate exact selections are rejected. For an
in-process runner, registration owns a detached runner clone and a bounded
same-process seal of the exact callback. The seal covers source-backed code,
referenced imports/globals, defaults, closures, function-owned executable
state, and callable class/instance behavior. Frozen configuration values bind
by value; retained native synchronization capabilities bind by exact live
identity and type/code provenance while their volatile lock/event state does
not. Core recomputes the seal immediately before callback entry and repeats
access, deadline, and cancellation checks after that work. Callback-slot,
closure, class, instance, or executable-state drift therefore fails before
model invocation. Detached clones continue sharing the original runner's
cross-coordinator execution gate.

An execution reads one scoped queued record, resolves its exact registration,
and claims the durable fence before invoking the service factory. This means
two coordinators racing on one run cannot both create services or invoke a
model. A factory failure, wrong-request service, or service whose visible
accounting or permanent zero-tool lifetime latch is non-pristine seals the
claimed zero-disclosure attempt without a fabricated transcript. An
unknown runner or instruction profile is rejected before claim and leaves the
run queued.

The production custom-factory mode is a
`PrivateAnalysisToolServiceProcessFactory`. It contains only a module-level
`PACKAGE:ATTRIBUTE` target and a bounded canonical JSON configuration object.
Core starts a fixed, non-daemon `spawn` child, resolves and invokes the target
there, and retains the exact pristine service and its lease in that child. A
closed core-owned service proxy exchanges only bounded canonical JSON messages,
admits one in-flight call, and revalidates an append-only evidence ledger plus
monotonic request-bound budget snapshots before write-ahead accounting. The
request evidence-service identity domain-separately binds the target,
configuration digest, deployment-supplied semantic digest, and exact
content-addressed executable identity. Registration resolves the inert target
under the shared process-control boundary and accepts only an exact
source-backed module function, class, or module-level callable instance. Its
identity covers the resolved
module/qualified attribute and either the top-level module bytes or complete
regular/namespace-package import scope. Statically resolvable local imports,
function-owned executable state, and recursively referenced external helpers
participate in the same bounded identity. Dynamic aliases, dynamic or unloaded
imports, built-ins, sourceless bytecode, and other unverifiable targets fail
closed.
Only the detached executable digest is stored; raw paths and executable bytes
are absent from durable state, IPC, and representations. Canonical
configuration crosses only the child bootstrap and is not persisted or shown
in representations. Core re-imports and rehashes immediately before spawn,
and the child independently does so again before factory invocation, so
module-attribute swaps or file-byte
drift cannot retain the admitted request authority. Preparation polls the
absolute request
deadline and durable cancellation. Timeout or cancellation terminates, then
kills if necessary, joins, and closes the direct child before sealing the
payload-free unstarted outcome. Child import, factory, service, protocol, and
process-control failures expose only the same static failure vocabulary; child
tracebacks and deployment exception text never cross the protocol.

Evidence-factory and local model-adapter launch each first generate a random
256-bit release capability and commit an independent cleanup fence keyed by the
scope, run, and execution.
Only a domain-separated SHA-256 verifier is durable; the capability remains
beside the live process object and is suppressed from representations and
bounded store diagnostics. Cleanup attempts update only bounded timestamps and
a count; no PID, path, command, or proprietary payload is stored. A failed
bootstrap or post-execution reap leaves the exact process/session owner and
capability in the originating coordinator, whose
`retry_pending_cleanup`, expiry-recovery entry point, and shutdown each perform
at most one bounded retry per selected run. Only confirmed reap and capability
verification can enter an atomic terminal transition that removes the fence;
there is no standalone fence-clear operation. If process control interrupts
in-process receipt sealing after its callback returns, the shared runner owner
retains the started transcript/accounting state. Cleanup retry seals that exact
ledger into a `runner_failed` receipt and commits it atomically with fence
removal; it never substitutes the transcript-free unstarted transition.
On restart there is deliberately
no PID-based adoption or credential recovery from persisted fields: the
unmatched fence remains visible and the run remains nonterminal until child
death is independently established.

`trusted_inline_tool_service_factory` is compatibility-only trusted Python. It
runs synchronously in the coordinator process and is therefore cooperative and
unbounded: Python provides no safe thread cancellation, and a callable that
never returns can block that execution. It is excluded from the hard
preparation-deadline guarantee. Production registrations that require bounded
preparation use the process factory or core revision-evidence mode.

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
runners, read the core workflow capabilities, create/list/read runs, execute
or cancel an exact version, and read a terminal report. Reads require
`control-plane:read`; mutations require
`control-plane:write`. Create requires `Idempotency-Key`; execute and cancel
require a strong numeric `If-Match`. Create, single-run read, execute, cancel,
and report responses carry numeric ETags; list responses do not. Run views use
decimal strings for nanosecond coordinates and omit query text, evidence
payloads, transcripts, execution IDs, leases, callback objects, and internal
audit state. The terminal report adds the original query and canonical advisory
outcome plus canonically ordered metadata for exactly the cited evidence
reference digests through a display-safe projection that is not canonical
wire/digest input. References are resolved only from the run's stored
disclosure ledger. The projection preserves generic producer/optional plug-in,
revision/node, evidence-kind/class/schema/provenance, and time metadata, but
never exposes the evidence payload, locator/path, locator or raw-content
digest, fixture/plan identity, or unrelated disclosed references. It remains
advisory and grants no mutation or proposal-promotion authority by itself. The
separately authorized review service described below accepts a new human
decision; it never treats display data as mutation authority. Execution runs the already durable,
fenced request once off the event loop through the server's thread executor;
the application service first requires the current run version and rechecks
that the workspace policy still enables the request transport, while the tool
service performs the final race-safe policy check before disclosure. The
coordinator limits concurrently active executions. Even a terminal replay
requires the current version. Execution never retries or falls back to another
transport.

`GET .../private-analysis-capabilities` returns the contract-versioned, scoped,
core-owned browser vocabulary: task descriptors, current deployment limit
ceilings, workspace-policy-approved local transports, lifecycle states, and
actions. It uses the normal read role and concealed scope resolution, is
non-cacheable, and has no ETag because it is not a versioned run resource. It
does not expose configured runner, model/provider, endpoint/key, or plug-in-
specific fields; runner discovery remains separate.

This lifecycle is not model-provider configuration. The public contract has no
endpoint, API-key, SDK, arbitrary command, environment, network-transport, or
plug-in-selection field. Deployment composition must supply an approved local
runner and exactly one request-bound evidence mode before any run can execute.

The core-owned `/analysis` browser page keeps workspace identity, unsent query
text, run identity, and report state in memory only. Its controller—not merely
the disabled HTML button—admits submission only after discovery proves that the
workspace policy is enabled and the selected task, local runner, and immutable
revision all belong to the current discovered allowlists. Reconnect invalidates
the previous scope before validating or fetching the replacement. Discovery,
run, and report JSON is bounded, recursively detached, and frozen before it can
be exposed to rendering callbacks, so caller-side mutation cannot rewrite the
controller's authority. Active lifecycle phases and cleanup-pending terminal
records remain non-submittable; ambiguous execute/cancel outcomes reconcile by
read-only polling without replay. Disabled reasons are published through the
visible live status region as well as the submit control's title.

### Explicit human proposal review and durable promotion

Review is a second, authenticated workflow after a cleanup-complete terminal
report. The model result remains advisory. A reviewer may reject one exact
proposal or supply a separately authored annotation or manual-correlation
target. Core never interprets a proposal payload as an overlay, never copies it
into a target, and never allows model output to select an author. The actor is
the authenticated principal.

The decision mutation is:

```text
POST .../private-analysis-runs/{run_id}/proposals/{proposal_id}/decision
```

It requires `control-plane:write`, the current strong run `If-Match`, and an
`Idempotency-Key`. The closed request pins both the proposal digest and terminal
result digest, declares `promote` or `reject`, carries an optional human
rationale, and contains a target only for promotion. Human targets use the
existing validated review-overlay subjects and either:

- one annotation kind, subject set, title/body, and tags; or
- one manual event correlation with subjects, edges, rationale, tags, and
  optional confidence.

Only an `event_correlation` proposal may be reviewed into a manual event
correlation. Every target subject must belong to one of the run's immutable
revisions and must resolve to an existing resource, event, source record,
relationship, or bounded time range. A rejection cannot carry a target. The
service requires a cleanup-complete terminal run, re-reads the report to prove
run version, result digest, proposal ID, and proposal digest, and resolves the
subjects while holding the same single-host admission fence used by catalog
retention. All validation finishes before any durable reservation.

`SqliteProposalReviewStore` records one scoped decision for an exact
run/proposal and idempotency request. Its wire contract is
`router_dump_analyzer.private_analysis.proposal_review.v1`; versions and
nanosecond coordinates cross JSON as decimal strings. Rejection completes
without writing an overlay. Promotion reserves a `pending` saga with the exact
validated human target, then creates one deterministic, idempotent annotation
or correlation authored by the reviewer and tagged `assistant-promoted`, and
finally marks the decision `completed`. A process interruption can therefore
leave a visible pending decision without duplicating the overlay. Repeating the
original decision POST is observational: it returns the existing pending or
completed receipt but never resumes the saga. Only recovery may do that.
Replay accepts the idempotency receipt only when both its request digest and
decision ID equal the deterministic candidate, and the referenced signed
decision is revalidated before it is returned.

The canonical request digest includes the exact tenant/project/workspace
scope. The decision ID and, for promotion, target ID are distinct
domain-separated deterministic projections of that digest; the overlay
idempotency key is derived only from the verified decision ID. Every decision
that a read, replay, or recovery materializes is authenticated before its
generated identity is used. Retention scans the complete decision table,
authenticates each row, and only then applies scope and pending-state
classification, so moving a row between scopes cannot hide its protections.
Each reservation also carries an HMAC-SHA-256 attestation over the scope,
request digest, disposition, decision/target IDs, derived overlay key, and
current lifecycle state/version/timestamps. Completion replaces the lifecycle
fields and attestation atomically. Retention never filters on unauthenticated
scope or lifecycle columns. Its
32-byte authority key is supplied separately from the SQLite store; the core
composition persists it as
`.private-analysis-proposal-review.authority.key`, outside the decision
database, with exclusive creation and owner-only permissions where the host
supports them. A coherent rewrite of every public projection still fails the
attestation. The key and database form one backup/restore unit; a missing key
beside any pre-existing database, even one with no current decisions, fails
startup rather than minting replacement authority. Legacy adoption therefore
requires an explicit migration.

Decision list/detail reads never resume a saga. An explicit conditional

```text
POST .../private-analysis-runs/{run_id}/proposal-decisions/{decision_id}/recover
```

with the decision's strong `If-Match` verifies that the canonical retained
target still produces the original human request digest, re-resolves its
subjects, and idempotently finishes it. If the overlay receipt was lost after
an overlay commit, recovery accepts only the exact version-1, live target whose
actor and complete content equal the retained intent; a modified, deleted, or
different target fails closed. Pending decisions protect both their target
revision IDs from catalog retention and their decision-derived overlay receipt
from review retention. The matching list and detail routes are read-only and
`Cache-Control: no-store`. A completed recovery is also idempotent.

The `/analysis` page displays model text read-only, requires a reviewer
acknowledgement, and leaves promotion-target JSON empty until the human writes
it. It pins every decision receipt to the proposal/result digests in the
controller's validated frozen report. Concurrent clicks share one mutation.
After an ambiguous decision response, the controller may refresh durable
decision state for display, but it never treats a same-proposal receipt as
proof of the attempted rationale, disposition, or target; review stays disabled
until reload and inspection. Pending decisions expose a separate **Resume
pending promotion** action; another attempt always requires another explicit
click. If a recovery response is ambiguous, one read-only refresh may re-enable
that action only after it proves the same frozen report and durable decision
remain authoritative; the refresh never sends a second recovery POST.
Untrusted content is rendered as text, not HTML.

## Trusted local deployment and headless lifecycle

The shipped composition remains inert: `ControlPlane`, `router-dump-server`,
and the embedded analyzer register no private-analysis runner unless an
operator explicitly selects
`--private-analysis-deployment-module PACKAGE:ATTRIBUTE`. The embedded analyzer
accepts that option only with `--control-plane-dir`; omitting the option always
keeps runner discovery empty and execution unavailable.

The selected target is a process-trust boundary, not device plug-in discovery
or model-provider configuration. It is either one exact frozen
`PrivateAnalysisDeployment` or a factory called exactly once with a detached,
frozen `PrivateAnalysisDeploymentContext`. That context contains only the
canonical absolute durable state directory: no tenant, request, credential,
plug-in object, model setting, or network handle is ambiently supplied. The
descriptor contains a bounded non-empty tuple of exact
`PrivateAnalysisRunnerRegistration` values, plus optional detached execution
limits and application ceilings. A spawned process factory, a trusted-inline
compatibility factory, and a core revision-evidence policy are mutually
exclusive, and a core policy's transport must equal its runner transport.
Public runner ID/version pairs must be
unique; registrations are sorted deterministically. Import, attribute,
factory, and descriptor failures become static load errors while
`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` retain their normal
process-control behavior. Deployment code nevertheless has the full authority
of the Python host and must be trusted accordingly.

`router-dump-private-analysis` is the scriptable adapter over the same durable
application service. All commands require one plain plug-in allowlist family
or one trusted `--plugin-deployment-module`, plus the state directory,
tenant/project/workspace scope, and the separate private-model deployment
target. The plug-in deployment supplies exact parser/capability authority; the
private-analysis deployment supplies only approved local runners and limits.
Neither may select the other by platform name or registration order.
Its subcommands are:

| Command | Operation |
|---|---|
| `runners` | List local runners allowed by the current workspace policy. |
| `create` | Idempotently admit a queued run from a request document. |
| `get` / `list` | Read one run or a bounded keyset page. |
| `execute` / `cancel` | Mutate one exact durable version. |
| `recover-expired` | Terminalize a bounded page of expired attempts in the selected workspace without retrying the model. |
| `report` | Read a display-safe terminal report. |
| `decide-proposal` | Reject or explicitly promote one exact digest-pinned proposal from a human-authored decision document. |
| `list-decisions` / `get-decision` | Read durable proposal-review receipts. |
| `recover-decision` | Explicitly resume one pending promotion at its exact decision version. |
| `run` | Idempotently create, execute, and emit the terminal report. |

`create` and `run` require `--request PATH`, `--actor`, and
`--idempotency-key`. The bounded UTF-8 JSON document has exactly the HTTP
caller-intent shape; it is capped at 1 MiB, rejects duplicate keys and
non-finite constants, and carries the proprietary query. There is no query
command-line option, avoiding process-list and shell-history disclosure.
Execute and cancel require `--run-id`, `--actor`, and `--expected-version`;
list uses the paired `--after-created-at-ns`/`--after-run-id` cursor.
`recover-expired` requires `--actor` and accepts a bounded `--limit`. It is
strictly scoped to the selected tenant/project/workspace. It first retries any
matching cleanup handle still owned by this process, then terminalizes only
expired `running` or `cancel_requested` rows that have no cleanup fence. It
never re-executes a runner. An orphaned cleanup fence from an earlier process
remains nonterminal because a restarted process cannot prove that child was
reaped.
`decide-proposal` additionally requires `--proposal-id`, the current run
version, an idempotency key, and a bounded request file containing the human
decision. `recover-decision` requires the durable decision ID and its current
version. Global
`--output` and `--pretty` control the bounded JSON projection.

The command opens the existing catalog, workspace, revisions, disclosure
policy, run store, review store, and review overlay. It does not create a
project or policy, start the web application or ingestion workers, retry a
run, choose a different runner or transport, or automatically promote any
assistant proposal. Promotion is possible only through the explicit
human-authored, digest-pinned `decide-proposal` operation above. Output schema
`router_dump_analyzer.private_analysis_cli_result.v1` goes to stdout and the
optional file. Exit `0` is successful, `2` means the `run` command produced a
terminal advisory error with no result, and `1` is a bounded command/service
failure. A local model adapter remains deployment-owned; core still contains
no public-provider SDK, API-key or endpoint option, network fallback,
arbitrary shell, or automatic retry/promotion path.

## Tool and instruction boundary

The model receives a closed catalog of evidence tools rather than a database
handle, Python object, filesystem path, shell, live plug-in object, or network
socket. `query_evidence` and `read_evidence` are read-only retrieval;
`analyze_evidence` is an advisory derivation over evidence already disclosed
through that request. Tool arguments and model output are untrusted input and pass
the same typed validation, tenant isolation, pagination, and budget checks as
human/API requests.

Dump text, LTTng messages, source records, annotations, and plug-in descriptions
are always represented as evidence data. They are never concatenated into the
trusted instruction channel. Every model claim cites immutable evidence or is
marked as an unsupported hypothesis.

## Multi-plug-in prerequisite

AI analysis operates on exact current plug-in execution plans, not whichever
plug-in happens to be installed later. Retained plan v1 is display-only and
cannot produce an evidence corpus. Each new durable node/revision now pins plug-in
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

# Private AI analysis boundary

Status: normative architecture decision for the implementation backlog.

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

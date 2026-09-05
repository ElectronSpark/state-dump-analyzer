# Documentation audit repair checklist — 2026-09-05

All changes remain uncommitted. Existing working-tree changes are preserved.
The implementation order follows the numbered findings; independent review
and preparation may run alongside the active fix.

## Todo and pass gates

- [x] D01 — Hidden resource keys must not affect public search. Reuse the
  client-publication policy; test hidden/sensitive/undeclared/public keys,
  empty redacted keys, and indexed/scanning consumers.
- [x] D02 — Temporal queries must honor later snapshot intervals, not just
  timeline-start state. Test empty states, deletion, exact and uncertain
  boundaries, selected perspectives, and event/snapshot interaction.
- [x] D03 — Document reducer scheduling accurately. Separate automatically
  materialized ingestion capabilities from explicit executor-only hooks and
  unavailable host features; exercise that boundary in a small conformance test.
- [x] D04 — Make state-query requests and examples agree on supported time
  bases and relationship inclusion/filtering; execute the documented shape.
- [x] D05 — Correct state/topology cursor documentation and compatibility
  handling; prove page two advances and conflicting handles fail closed.
- [x] D06 — Make the minimal parser recover from malformed JSON field types
  with bounded diagnostics, then continue to a valid next row.
- [x] D07 — Make preferred-plug-in versus automatic-selection precedence
  explicit; test the combined CLI flags without running a large import.
- [x] D08 — Specify generator validation JSON, stderr, and exit-code behavior
  for both load failures and semantic validation failures; test each path.
- [x] D09 — Make the introductory generator workflow runnable by inserting
  the required topology authoring step before validation/generation.
- [x] D10 — Correct sample-generation concurrency and memory guidance using
  the actual worker-selection policy.
- [x] D11 — Describe retention's admin-role override accurately, retaining
  separate instance-operator authorization for process-wide diagnostics.
- [x] Complete documentation stewardship, example smoke, exported-interface,
  frontend, focused Python, and whitespace checks with explicit timeouts.
- [x] Run a fresh independent full-scope audit of current documentation and
  related code after all fixes; fix confirmed new findings and recheck.

## Ownership and scope

Core owns publication policy, temporal selection, query admission, and host
capability scheduling. Plug-ins own device semantics and malformed-input
diagnostics. The generator remains independent from the analyzer and demo
plug-in. D03 closes a misleading support claim; it does not silently introduce
a new reducer orchestration engine or change replay ordering.

## Results and additional findings

D01: publication and search now share `redact_resource_view`; empty projected
keys do not fall back to raw keys. A sibling defect dropped the parent path
when redacting top-level declared objects; that is fixed too. The normalized
data suite passes 27 tests, including new negative search and nested-field
cases. Targeted checks are not a claim of a complete Python-suite run.

Independent D01 review also caught raw private keys in core-generated resource
and event-subject labels. Ingestion now builds those labels through the same
publication policy; a real coordinator-to-search regression covers mixed and
all-hidden keys. Seven targeted ingestion/runtime tests pass. Search projects
only candidate fields, avoiding a newly detected traversal of large unrelated
non-searchable payloads (now covered by a traversal regression).

D02: selected-time snapshot/lifecycle anchors, perspective-aware reads, and
interior uncertainty transitions are covered by 38 focused tests. Same-time
snapshot/event order that cannot be proven remains unknown rather than exact.

D07: the pipeline CLI gate passes three selection/preference cases. D08:
four generator CLI tests cover valid/semantic-invalid reports plus load,
encoding, model, filesystem, and argument failures.

Additional documentation findings found while repairing D04/D05: the state
response example described a typed world envelope rather than the shipped
adapter, and the change-stream section incorrectly promised complete snapshot
replay despite snapshot-only transitions and an excluded end boundary. Both
claims are corrected; no new replay engine is implied.

## Validation

### Additional findings from repair and the independent final audit

- [x] A01 — Preserve parent paths when redacting nested declared objects.
- [x] A02 — Prevent hidden keys leaking through generated resource/event labels.
- [x] A03 — Avoid re-traversing large non-searchable payloads during search.
- [x] A04 — Replace the idealized state-query response with the shipped adapter
  contract; document that change pages are not a complete snapshot-replay log.
- [x] A05 — Apply the union sensitive-condition policy to events whose subjects
  are unresolved, not only the union property redaction. The regression failed
  before the fix and now passes for direct, bootstrap, and range consumers.
- [x] A06 — Clear nested current resource state when a requested perspective
  has no evidence; preserve unknown rather than borrowing another perspective.
- [x] A07 — Relationship-only endpoint placeholders without lifecycle evidence
  must be unknown, not asserted absent.
- [x] A08 — Correct two interactive launch commands that supplied a JSONL
  parser fixture to the archive-only demo adapter; test non-generating preflight.
- [x] A09 — Make split-process development proxy writes pass origin validation
  only for the configured frontend origin; reject foreign origins before forwarding.
- [x] A10 — Correct resource-row enrichment promises: relationships and event
  histories require their separate APIs, not an implicit resource-query join.
- [x] A11 — Correct the lazy-normalization claim: standard ingestion eagerly
  builds observation intervals; indexed/lazy demo history is a separate adapter.
- [x] A12 — Correct quarantine retention guidance: exact core-owned aged
  quarantine names are reclaimable; malformed/unowned names are not.
- [x] A13 — Generator CLI notices/errors must survive non-UTF-8 Windows
  consoles; JSON reports must remain valid JSON with Unicode values preserved.
- [x] A14 — Document indexed resource pagination separately from the legacy
  unindexed, unpaged compatibility response.
- [x] A15 — A gap in declared state history must not borrow the final snapshot;
  preserve capture fallback only for legacy resources with no state history.
- [x] A16 — Bound decoded cursor positions and checked page-count arithmetic
  to JSON-safe integers; correctly checksummed forged cursors cannot bypass it.

All executable checks use explicit subprocess timeouts. Counts overlap and
must not be added together as a unique full-suite total.

| Gate | Result |
| --- | --- |
| D02/D04/D05 temporal, HTTP request/cursor, history, provider and reconstruction checks | 59 passed |
| D03 scheduling sentinel, direct executor calls, labels, reconstruction fixtures and author docs | 32 passed |
| Source deduplication, reconstruction/shared contracts, snapshots, normalized data, author docs | 87 passed |
| Final combined ingestion, normalized data, temporal/query, reconstruction/truth, shared contracts, docs, deduplication | 149 passed |
| Complete demo test directory | 29 passed; includes 21 malformed-field recovery cases and programmer-error propagation |
| Complete independent generator test directory, after console fixes | 97 run: 94 passed, 3 Windows symlink-privilege skips |
| Complete frontend JS suite and frontend contract, after proxy repairs | 152 passed; 4 routes and 9 modules validated |
| Example generator verification and documented plug-in validation | Passed |
| Generated public interfaces | 128 module stubs verified across 4 packages |
| Strict typing of both documented API consumers | Passed |
| Documentation inventory and local Markdown paths | 22 files, 116 local links, no missing targets |
| Fatal Python lint and working-tree whitespace | Passed |

D09's regression uses a temporary one-node archive, not the full-scale sample.
D10's worker gate uses five in-memory assertions; D11 reuses three behavioral
authorization tests. Root README, quickstart, normative contract, example and
README, API/architecture, operator/generator guides, and sample guidance were
reviewed for drift together. Existing unrelated changes remain untouched.

The complete large core Python suite and expensive route/scale matrices are
not claimed as rerun. No persistent server or million-event regeneration was
started. Frontend validation is executable testing, not a new screenshot-based
walkthrough. External documentation URLs were not checked for freshness.

## Final audit outcome

Three independent reviewers covered author contracts and publication/reconstruction,
launch/CLI/operator/generator documentation, and API/architecture/private-analysis/
frontend contracts. They reviewed areas different from their initial repair
assignments and exercised small reproductions. Confirmed findings were fixed
and rechecked, including a second independent reconstruction review (26 tests
and 56 subtests), real ephemeral HTTP proxy tests with listener cleanup, and
forged-cursor HTTP overflow regressions. No confirmed finding remains open in
this checklist; this is not a claim of an exhaustive or defect-free repository.

Core retains generic validation, publication, query, and proxy policy; device
semantics remain in plug-ins and the generator remains independent. Missing
host-scheduled features are stated as limitations rather than claimed as newly
implemented. No commit or push was performed.

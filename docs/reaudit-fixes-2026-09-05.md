# Re-audit repair ledger — 2026-09-05

This batch repairs the 15 findings from the 2026-09-05 working-tree audit.
Changes remain uncommitted. Existing in-progress deduplication is preserved.

## Checklist

- [x] R01: bound review subjects before any revision load; bound revision reads.
- [x] R02: preserve explicitly empty historical states.
- [x] R03: preserve false/unknown relationships through all graph consumers.
- [x] R04: filter catalog source identity before the uniqueness limit.
- [x] R05: preserve log-only final-state defaults through generator round-trip.
- [x] R06: propagate to every same-node physical attachment.
- [x] R07: generate valid node-local partial-multiaccess observations.
- [x] R08: preserve the canonical omitted resource-type default.
- [x] R09: preserve exact generator clock integers.
- [x] R10: refresh generic tables when selecting a different resource kind.
- [x] R11: retain incomplete packet continuity even for equal packet values.
- [x] R12: distinguish generic packet drops from proven MTU drops.
- [x] R13: approve only the reviewed shared imports at the private-AI boundary.
- [x] R14: make the full-fidelity disclosure guarantee precise and executable.
- [x] R15: make executable test fixtures agree with their actual import identity.
- [x] Consolidate the four residual helper copies without weakening boundaries.
- [x] Run bounded regression checks, independent review, and documentation/stub checks.

## Implementation principles

Use existing temporal, canonical-value, annotation, catalog, and generator
semantics modules. Extract a common helper only when actual callers share a
contract. Core preserves evidence, bounds work, and coordinates execution;
plug-ins decide device meaning. Generator ground truth stays in the independent
generator. Never replace an executable-identity check with a permissive fallback
to accommodate a test fixture.

## Repair details and shared interfaces

| Items | Resolution and permanent regression coverage |
| --- | --- |
| R01, R04 | Shared bounded `normalize_review_subjects`; explicit `ControlPlaneLimits` revision/byte admission budgets; preflight every scoped file before any decode; per-revision grouping without another decoded-dataset collection. Source identity is an indexed, bound SQL predicate before pagination. `tests/test_review_admission.py` exercises malformed, duplicate, singleton, oversized, cross-scope, exact-boundary, generator, and ambiguity cases. |
| R02, R03 | Empty selected intervals no longer fall back to final state. Shared half-open containment and tri-state presence serve indexed/scanning graph, topology, table traversal, and browser projections. Tombstones remain in history; unknown presence remains ambiguous. `tests/test_reconstruction_truth.py` and executable frontend renderer tests cover these paths. |
| R05–R09 | Independent generator semantics preserve log-only flags, omitted defaults, exact clock strings, qualified port identity, and all same-node attachments. Partial-multiaccess generation uses validated node-local identities; propagation preserves explicit local/failure outcomes. `state-dump-generator/tests/test_semantics.py` executes real browser functions as well as compiler paths. |
| R10 | Cross-kind resource selection reuses the existing abort/latest-request controller, resets generic-table paging, and preserves bundle scope. Executable production-function tests plus an independent out-of-order-response probe cover selection and request ownership. |
| R11, R12 | Incomplete packet identities remain incomplete independently of equality or delivery. Generic DROP is not automatically an MTU failure; an exact `exceeds` evaluation is required. Forced paths retain counterfactual attribution, including downstream segments. Packet-core and `tests/test_route_packet_projection.py` tests exercise the production evaluator/projector. |
| R13 | Private-AI import approval lists only the specific shared digest/integer members actually used. Negative architecture tests still reject unapproved imports. |
| R14 | Corrected the guarantee, not the user's authorized proprietary-data workflow: `NEVER_ASSISTANT` evidence cannot be released, but full-fidelity payloads are not heuristically credential-filtered. Synthetic credential-shaped data and nested `disclosure_class` tests make that limitation explicit. |
| R15 | Process test targets use actual module identities under package and unittest-discovery imports. Production executable fingerprinting remains strict. CLI discovery and affected ingestion/attestation tests pass. |

The original four repeated helper families now use existing core modules:

- D1: half-open containment in `temporal_core.contains_time`; old adapter names
  remain compatibility aliases.
- D2: bare SHA-256 grammar in `canonical.validate_lowercase_sha256`, also used
  by the existing prefixed validator without changing its public errors.
- D3: decoder identity detachment in
  `plugin_execution_plan._snapshot_decoder_identity`; ingestion delegates with
  its contextual type-error label.
- D4: private-analysis integer validation delegates to
  `value_core.require_bounded_integer`, preserving boundary-specific errors.

No device protocol inference moved into core. The independent generator still
owns its saving format and ground truth; plug-ins retain device meaning,
packet actions, and evidence semantics.

## Validation

Every Python test invocation used the existing explicit-timeout runner
`.runtime/run_dedup_checks.py` and the `router-dump-analyzer-demo` environment.
Node checks used explicit subprocess timeouts and serial test concurrency.
The following groups are reported separately because several overlap; their
counts must not be summed as a unique full-suite total.

| Validation | Result |
| --- | --- |
| Review admission, annotation store, session catalog, private revision evidence, private evidence contracts | 158 passed; subsequently expanded admission suite passed all 11 tests |
| Existing exact-subject resolution and deterministic/causal control-plane reports | 3 passed |
| Reconstruction boundaries, shared contracts, tri-state regression, route projection, remaining helpers, source deduplication | 53 passed |
| Generator suite | 88 run: 85 passed, 3 Windows symlink-privilege skips |
| Core frontend contract + complete JS suite | 139 passed |
| Demo tests | 27 passed |
| Tiny generated conformance fixture verification + documented example plug-in validation | Passed |
| Packet core/projector independent review | 22 passed, plus independent inter-node/MTU probe |
| Reconstruction/legacy graph/temporal focused checks | 33 passed |
| Topology/world/shared contracts | 34 passed |
| Digest, decoder, private contracts/evidence, exact architecture guard | 83 passed |
| Decoder identity and private-analysis run store | 30 passed |
| CLI discovery | 17 passed; affected ingestion tests also pass in package/discovery modes |
| Fatal Python lint, frontend contract, generated API stubs | Passed; 128 module stubs across 4 packages |

Independent reviewers checked admission/catalog, frontend selection/presence,
packet attribution, and private-evidence guarantees. The first packet review
found a counterfactual-prefix sibling; it was fixed across all dispositions and
the second review found no remaining concrete defect. The private-evidence
review corrected one documentation distinction between retaining a generic
corpus entry and releasing an evidence envelope.

Documentation stewardship covered the quickstart, normative contract, example
and its README, root author commands, API/architecture, generator, and operational
guides. Relevant documented smoke/conformance commands were rerun. Shared
interfaces were included in generated stubs rather than introducing duplicate
implementations.

### Limits of this validation

This is not a claim that the entire repository is defect-free. The complete
large Python suite and expensive advanced-route matrices were not rerun in this
batch; earlier audit runs exceeded their budgets. No million-event regeneration
or persistent server was launched. Browser code was exercised through production
functions in executable Node tests and independent controller probes, not a new
interactive screenshot walkthrough. Per-field private-AI secret classification
remains outside the current contract and is explicitly documented, not silently
claimed as implemented. No commit or push was performed.

## Additional defects and duplication discovered during repair

All concrete defects below were fixed; these are additional to the original
15-item list.

- **N01 — relationship-consumer bypasses:** browser local/transport/timeline
  normalization, indexed graph correlation, and indexed bundled-resource table
  traversal could resurrect false edges or erase unknown presence.
- **N02 — admission siblings:** direct overlay calls eagerly consumed arbitrary
  subject iterables; singleton correlations were rejected only after revision
  reads; report and explicit capability revision selectors consumed an
  unbounded iterable. They now share bounded admission before expensive work.
- **N03 — forced-path misattribution:** user-forced DROP, later plug-in DROP on
  a forced branch, and initially observed forced-prefix/downstream segments
  could still claim observed device behavior. Counterfactual attribution now
  covers the affected suffix while preserving earlier observed evidence and
  the actual actor of each plug-in action.
- **N04 — propagation masked by stale properties:** static attachment
  `oper_status` could override a successfully propagated link-down observation.
  The observed operational field now wins without overwriting administrative
  fields or deliberately stale/failed outcomes.
- **N05 — qualified attachment identity:** the browser could turn
  `interface:p` into `interface:interface:p`, breaking round-trip identity.
- **N06 — disclosure documentation ambiguity:** a generic corpus can retain a
  `NEVER_ASSISTANT` entry even though release is prohibited. The quickstart now
  distinguishes storage, built-in corpus classification, and disclosure.
- **Additional repetition:** four nearly identical catalog SQL branches became
  one bound-predicate query; reconstruction-time parsing and the private-contract
  positional integer adapter now delegate to existing integer helpers; frontend
  graph consumers share one tri-state presence projection. Cross-language
  generator/browser semantics remain separate implementations with executable
  parity tests, not imports from analyzer core.

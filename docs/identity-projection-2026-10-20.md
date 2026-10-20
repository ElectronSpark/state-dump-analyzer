# Identity repair and projection optimization — 2026-10-20

The existing navigation and audit work was committed first as `45179d0`
(`Reduce navigation memory and address browser audit findings`). This change
implements the first two recommendations from the
[follow-up investigation](followup-investigation-2026-10-20.md).

## Implementation

GPT 6.1 Sol used the updated author skill in two fresh agents with disjoint
source ownership. The parent reviewed the changes and independently ran the
regression, integration, skill-trial, and scale checks described below.

Executable identity now uses identity comparisons at all 17 identified
exact-type membership guards: 14 literal groups and three checks against the
hidden-built-in type group. This includes aliased values, which the earlier
16-site prototype did not fully cover. Custom metaclass equality or hashing
can no longer classify a mutable callable as an immutable built-in container.
Both public fingerprint APIs detect changes to its state and implementation.
Unhashable metaclasses follow normal verifiable-class handling; unsupported
iterator state still raises `PluginExecutableIdentityError`.

Safe event projection returns immediately for exact built-in scalars and tries
ordinary dictionary dispatch before generic `Mapping` dispatch in resource-kind
collection and nested-record redaction. Generic mappings, scalar subclasses
that implement Mapping, container ownership, conservative policies, and exact
JSON search text retain their previous behavior. The implementation adds no
retained event-projection cache or dependency.

## Independent validation

- Parent production regression run: 143 tests, 142 passed and one Windows
  symlink-privilege skip. Includes the new projection cases, public identity
  mutation checks, normalized-data and revision queries, HTTP event redaction,
  and both core search suites.
- Parent integration run: 133 tests passed. Includes executable identity,
  execution plans, isolated plug-in processes, capability execution, and all
  documented authoring smoke tests.
- Projection differential coverage: 2,000 seeded nested values with generic
  mappings and subclasses, plus hostile metaclasses, a scalar subclass that
  implements Mapping, independently mutable output containers, and literal
  Unicode/NUL/numeric safe-text assertions.
- Stub export check verified 146 modules across four packages; no public
  signatures or generated stubs changed.
- Conformance inventory passes. The foundation group now includes both identity
  suites, and the runtime group includes the new projection regression module.
- Focused strict mypy has 89 existing errors across the two production files,
  compared with 93 in the checkpoint. Normalized diagnostic comparison finds
  no introduced errors and four removed identity type-narrowing errors.
  Seven notes remain in each run. This is not a clean repository-wide typing
  result. Ruff has no new diagnostics; the pre-existing import-order and
  redaction-guard SIM101 diagnostics in `normalized_data.py` remain. The two
  new measured dict-first guards have local SIM101 explanations.

The parent used the configured Python 3.12.13 environment. HTTP/process checks
ran with the execution permission needed on this Windows host and workspace
`TEMP`/`TMP`. Stub generation needed inherited `PYTHONUTF8=1` for its children;
the initial default-temp/encoding failures are environment limitations, not
successful check results. Final logs are under
`.runtime/identity-projection-2026-10-20/`: `parent-focused.log`,
`parent-integration.log`, `stubs.log`, `conformance.log`, and `mypy-*.log`.

## Skill use and independent trials

Both skills now explain identity-safe type guards, adversarial metaclass
validation, generic projection fallback, and complete safe-text parity. The
API validation map adds the associated checks and bounded Windows test-setup
diagnostics. Both skill-format validators pass.

Two additional fresh GPT 6.1 Sol agents used short prompts that supplied the
skill, task, allowed inputs, and output directory. Prior investigation reports
and all other runtime artifacts were explicitly excluded. The skills stayed
fixed during the batch; later map edits only add test/conformance discovery.
The exact prompts and hashes are recorded in
`.runtime/identity-projection-2026-10-20/skill-trials.json`.

- Individual identity trial: three runnable tests, including 12 direct/wrapped
  callable cases across ordinary, tuple/dict/list/set-spoofing, and unhashable
  metaclasses. Both public APIs remain stable before mutation, change after
  state and implementation changes, and reject opaque iterator state. A real
  nested container control also changes correctly. The parent inspected and
  reran the trial successfully.
- Combined author trial: actual trusted-inline durable ingestion persists two
  resources, two source records, one projected relationship, and one
  consistency pass. It checks retained revision/plan identities, public and
  sensitive resource search, exact ordered evidence pages, omitted raw fields,
  and malformed/oversized input rejection. The parent inspected the plug-in and
  runner, then reran them successfully against newly persisted state. This trial
  uses a recording publisher and core queries; it does not establish catalog,
  PROCESS, HTTP, or million-event performance. Those have separate checks where
  stated above.

Author skill SHA-256:
`0ded71dbc15018e444a925f07ceb56913b924014831a0e261b20b8af87d04c22`.
Validator skill SHA-256:
`9075cb74dc1974d139bbd4053adfd360a749bb6dc85203d5e483dcec6cb86f8a`.

## Million-event measurement method

The checkpoint source was extracted from Git into an isolated baseline tree.
Both implementations use the same configured interpreter and the same
286,496,584-byte `router-state-lab-algorithms-2026-10-02.tgz` archive. PE-A has
1,250,005 events; PE-B has 1,250,002. Every run starts a fresh process with a new
search sidecar and bytecode-cache directory. The actual production code is
measured, without monkeypatching.

The driver records load, bootstrap, cold/warm/refined/dense queries, repeated
filtered pages, density, A → B → A navigation, sidecar reopening, and shutdown.
This run uses five repeated dense queries and therefore 36 phase occurrences;
the previous audit used seven and recorded 38. Comparisons retain every
occurrence and verify complete returned search-page hashes in addition to
counts and cache summaries. Phase CPU sums from the two task reports must not
be compared as identical workloads.

Memory is sampled every 100 ms, with Windows process lifetime peaks also
recorded. Navigation peaks are sampled specifically during destination loads;
overall lifetime peaks include search construction. CPU is the benchmark
process only, excluding the browser and separate ingestion workers. This is a
backend load/query/navigation measurement, not browser readiness or a concurrent
import test. OS disk caches are not flushed.

The first pair ran during light test/agent activity with ordinary randomized
Python hashing. Cold-search CPU changed from 89.094 to 64.734 seconds and wall
time from 92.234 to 66.717 seconds. Loaded RSS changed from 2.3550 to 2.3780 GiB;
lifetime peak RSS changed from 2.4351 to 2.4567 GiB. Unchanged loading phases also
improved by 19–30%, so this pair cannot isolate the optimization's speedup.
All 36 phase results and retirement records match; sidecar metadata, size and
stored corpus digest match. Raw runs remain as `before-1` and `after-1`.

The second pair ran in reverse order (optimized, then checkpoint), with
`PYTHONHASHSEED=0` and no concurrent validation workload. Loading CPU differed
by at most 1.4%, giving a more useful comparison of the projection change:

| Measurement | Checkpoint (`before-2`) | Optimized (`after-2`) | Change |
| --- | ---: | ---: | ---: |
| First search CPU | 70.578 s | 64.406 s | −8.7% |
| First search wall time | 72.699 s | 66.366 s | −8.7% |
| Sum of phase CPU | 234.844 s | 226.656 s | −3.5% |
| Total elapsed time | 241.859 s | 236.562 s | −2.2% |
| Loaded PE-A RSS | 2.3968 GiB | 2.3568 GiB | −1.7% |
| Sampled navigation peak RSS | 2.4123 GiB | 2.3680 GiB | −1.8% |
| Process lifetime peak RSS | 2.4768 GiB | 2.4332 GiB | −1.8% |
| Search sidecar size | 71.5625 MiB | 71.5625 MiB | unchanged |

The measured cold-search CPU improvement is 8.7% in this quieter pair; it is
not a guarantee across hosts or workloads. Warm searches, refined searches,
filtered pages, and density queries show no material regression. Memory moves
in opposite directions across the two pairs: loaded RSS spans 2.3550–2.3968 GiB
at the checkpoint and 2.3568–2.3780 GiB after the change. These four runs support
broadly stable memory use, not a demonstrated memory reduction. The change
adds no long-lived projection storage.

The parent compared all 36 ordered phase results, including complete returned
page hashes, and verified matching cache-retirement records. It independently
decoded and hashed every persisted document in both final sidecars, checked
block framing, ordinals and hashes, and compared the complete ordered search
matches against direct literal matching: 24,925 `failure`, 1,225,080 `success`,
and zero absent-term matches. Both SQLite integrity checks passed. All
1,250,005 projected documents have the same complete corpus SHA-256:
`e822d341feb8f3d1172725004d2e286614416d42c07e21446f4de725faef6b36`.

The unchanged fixture SHA-256 is
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
The driver records the actual source hashes, interpreter, hash seed, memory
samples, and every phase result in each run directory. Final production hashes
match the measured optimized sources. Full comparison data and the independent
checker are preserved under `.runtime/identity-projection-2026-10-20/`:
`comparison-before-2-after-2.json`, `comparison-final.log`, and `compare.py`.
The successful verification command was:

```powershell
python .runtime/identity-projection-2026-10-20/compare.py --before before-2 --after after-2 --exact
```

## Documentation stewardship

The repair restores existing executable-identity and disclosure guarantees.
It changes no public hook, signature, parser workflow, supported projection
semantics, or author command. The quickstart, normative contract, and runnable
example remain applicable; their smoke tests passed. The documentation drift
check required no changes to those maintained materials. Skills and the API
validation map were updated for the demonstrated validation gaps.

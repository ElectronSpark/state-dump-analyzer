# Audit fixes and validation — 2026-10-20

This follows [the manual browser audit](manual-browser-audit-2026-10-20.md).
Further profiling and newly discovered correctness issues are recorded in
[the follow-up investigation](followup-investigation-2026-10-20.md).
The starting point was `aaf9758` plus the existing uncommitted navigation-memory
change. Those navigation changes were preserved in both measurement versions.
GPT 6.1 Sol agents used the repository author skill for implementation; the
parent reviewed the changes, reran checks, and exercised the browser.

## Changes and remaining findings

| Original finding | Outcome |
| --- | --- |
| Cold full-text search | Reuses the JSON encoder and a bounded policy-local sensitive-path transition cache. Reports counts during indexing every 1,024 documents. The final measured cold-search CPU gain is 2.7%; the large first-query cost remains. |
| Slow tiny durable import | Reuses immutable dependency-disassembly results with exact weak code identity, a 256-entry limit, and a 512 KiB result-data budget. Search also yields briefly while another thread executes a durable import. The matched overlapping import improved from 46.762 to 24.988 seconds, with all identity checks retained. Concurrent imports still take longer than quiet imports. |
| Ctrl-click selection | Rechecked in the live browser: Ctrl adds a second row, Ctrl toggles it off, and single-click followed by Shift-click selects three consecutive rows. No application selection change was justified. Physical-mouse delivery was not tested. |
| Header overflow | Navigation wraps inside the available grid column. Document and viewport both measure 1,265 CSS px; Review gaps ends at 1,236.8 px. The loading banner also follows the measured 84.4 px header height, with its sticky top at 92.4 px. |
| Windows connection-reset traceback | Remains an upstream runtime issue. The installed Python 3.12.13 cleanup routine reproduces the failure without repository imports. No blanket exception suppression or private runtime patch was added. |
| Stale session error after removal | Successful removal sets “Session member removed.” Browser reproduction went from the duplicate-revision error to this success message at session version 6; the removed member was restored at version 7. |
| Stale upload progress after rejection | The form replaces “Uploading…” with the validation error beside the upload button. Retry remains enabled. Browser retest verified the rejected whitespace-containing node hint and subsequent successful imports. |

The sensitive-path accelerator caches derived rule transitions, never event
projections. Exact-name checks make hash collisions harmless; ancestor-sensitive
paths still take the complete traversal. The dependency cache never reuses a
trust decision, and its weak references do not retain loaded code generations.
Scheduling stays in core: every claimed durable stage owns a counted activity
scope, including nested and concurrent imports. Errors and cancellation release
the scope. Search requests a 100 µs pause every 64 documents only while another
thread is importing; idle and same-thread searches never request a pause. The
tracking lock is released before sleeping.

## Matched million-event measurements

Both runs use Python 3.12.13 and the same 286,496,584-byte
`demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`: PE-A has 1,250,005
events and 7,510 resources; PE-B has 1,250,002 events and 7,509 resources.
Each run uses a new process and empty search-cache directory. The driver includes
cold loading, exact safe-text projection and search construction, warm/refined
queries, dense queries, filtered pages, density queries, and A → B → A navigation.

| Measurement | Before | After |
| --- | ---: | ---: |
| A cold-load process CPU | 28.734 s | 30.188 s |
| A cold-load retained RSS | 2.3516 GiB | 2.3555 GiB |
| First `failure` search CPU | 66.109 s | 64.344 s |
| First `failure` search wall time | 67.470 s | 65.978 s |
| Warm other-term search CPU | 1.984 s | 2.063 s |
| B cold-load CPU | 31.422 s | 29.234 s |
| Return-to-A load CPU | 29.969 s | 29.375 s |
| Reopened-sidecar search CPU | 5.688 s | 5.063 s |
| Lifetime peak RSS across the run | 2.4316 GiB | 2.4345 GiB |
| Final RSS after close and GC | 0.1562 GiB | 0.1510 GiB |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |
| Sum of measured phase CPU | 198.047 s | 193.266 s |
| Whole-run wall time | 204.469 s | 199.188 s |

This is one pair, not a statistical estimate of a general speedup. Cold-search
CPU improved 2.67%; measured phase CPU improved 2.41% and whole-run wall time
improved 2.58%. Peak RSS increased 0.12%, or 2.91 MiB. Some warm and load
phases regressed in this pair. Other light validation work ran on the host,
so wall time is especially sensitive to scheduling. Process CPU excludes browser
and separate ingestion-worker CPU. Memory sampling runs every 100 ms and also
records Windows lifetime peaks. The final candidate includes conditional import
cooperation. A preliminary candidate without that scheduling change is retained
as `after-1`; its phase CPU was 199.188 seconds and peak RSS was 2.4332 GiB.

The driver records 38 phase results, including repeated filtered-page requests.
The comparison must retain each occurrence rather than keying by phase name
alone; the original comparison omitted three repeated occurrences and was
corrected during parent review. All 38 ordered result summaries and retirement
records match, confirmed again by a fresh skill-driven measurement trial.
Both SQLite sidecars pass `quick_check`; metadata, block totals, size, revision
identity, and stored complete-corpus digest match. The first query returns
24,925 matches. This checks recorded summaries and persisted digests, not every
returned event body independently. Separate exact-projection regression tests
check Unicode, JSON types, hidden nested fields, and encoding equivalence.

Reproduction and raw data are under `.runtime/audit-fixes-2026-10-20/`:
`baseline-tree`, `baseline-manifest.json`, `before-1`, `after-2`,
`compare_final_measurements.py`, and `final-search-comparison.*`.
The preliminary `after-1` and its corrected comparison are also preserved.
The benchmark driver is `.runtime/algorithm-improvements/measure.py`;
the baseline copy is preserved in the snapshot.

## Browser and import observations

The final source is served on loopback port 8883 with the full demo composition,
the same million-event archive, and the approved synthetic control plane under
`.runtime/manual-browser-2026-10-20/control-plane`. Private-analysis access stays
disabled. The existing frozen snapshot remains unchanged.

The browser showed indexing counts at 90,112, 398,336, and 850,944 documents.
Cold search was complete by the 83.44-second observation, including concurrent
import activity; this is an observation bound, not a precise request latency.
The expected 24,925 results were displayed. Node warning/error console logs were
empty in the final check. A later warm search, after a confirmed zero-result
refinement, reached visible completion in 579 ms including browser transport
and debounce. Management warning/error console logs were also empty.

Two isolated full-composition PROCESS imports, using a null catalog publisher,
improved from a mean of 6.799 to 5.956 seconds. Their dataset digest, revision
identity, counts, and execution-plan digest match. These measurements exclude
real catalog publication and concurrent search. The artifacts are
`.runtime/measure_tiny_import.py` and `.runtime/tiny-import-*-results.json`.

A real browser import during cold search took 49.817 seconds between durable
upload and publication timestamps, including 44.687 seconds from ingestion start
to revision staging. Another import after reloading the node page took 23.889
seconds, including 17.227 seconds probing and 4.233 seconds ingesting. The latter
may overlap warm page-startup queries and is not a clean isolated measurement.
The dependency cache alone did not resolve the original overlapping-workload
delay; these observations preceded the conditional scheduling fix.

A third browser import, after heavy page requests had settled, took 6.285
seconds: 0.894 seconds probing and 4.205 seconds ingesting. This confirms that a
loaded million-event model alone does not impose the long delay.

Separate overlap diagnostics identified parent scheduling contention: 19 fresh
identity checks took 33.721 seconds wall time but 4.000 seconds of thread CPU.
Child ingestion stayed near 2.7 seconds; 88 GC collections took about 11 ms,
with no generation-2 collection. These observations distinguish scheduling
delay from CPU spent doing extra ingestion work.

Task-local experiments, before any production scheduling change:

| Search cooperation | Import wall | Cold query wall |
| --- | ---: | ---: |
| No deliberate pause | 46.762 s | 73.562 s |
| `sleep(0)` every 64 documents | 43.633 s | 70.213 s |
| `sleep(0)` every 8 documents | 39.392 s | 70.403 s |
| 100 µs requested pause every 64 documents | 21.852 s | 80.163 s |
| Final production: 100 µs every 64 documents only during another thread's import | 24.988 s | 72.799 s |

All five returned 24,925 matches and the same complete query-response digest.
The low-overhead span runs still include child profiling, so these are
attribution/experiment timings, not uninstrumented browser latency. A requested
100 µs sleep averaged 574 µs in a 2,000-call host calibration. Unconditional
positive pauses slow cold search by 9% and are not an acceptable idle-search
default. Evidence and raw profile locations are recorded in
`.runtime/audit-fixes-2026-10-20/ingestion-contention-evidence.json`.

The final scoped implementation reduced import wall time by 46.6% in the
matched pair without a measured cold-query wall regression. All 19 parent
identity checks still ran; their combined wall time fell from 33.721 to 14.516
seconds, while thread CPU changed from 4.000 to 3.516 seconds. The final query's
process CPU was 73.328 seconds including concurrent parent import work; the
ungated baseline did not record that counter, so it is not a CPU comparison.

The parent then restarted the actual demo with final source and a fresh search
cache and repeated the browser workflow. The same 752-byte input completed in
24.175 seconds between durable upload and publication timestamps, including
2.124 seconds probing and 20.213 seconds ingesting. Search was visibly indexing
at 185,344 documents before upload, 489,472 during ingestion, and 809,984 after
publication. The exact 24,925 results were visible by the 80.94-second
observation after typing the query; this is an observation bound rather than
precise request latency. Both browser warning/error consoles and the final
server error log contained no errors. The corresponding pre-scheduling browser
import took 49.817 seconds; this is a separate browser pair from the instrumented
matched trial above.

Browser evidence is under `.runtime/audit-fixes-2026-10-20/`:
`header-fixed.jpg`, `upload-feedback-fixed.jpg`, `session-feedback-fixed.jpg`,
`index-progress-fixed.jpg`, `selection-verified.jpg`,
`browser-concurrent-import.json`, `browser-isolated-import.json`, and
`browser-quiet-import.json`, `browser-final-concurrent-import.json`, and
`import-final-completed.jpg`.

## Skills and checks

Updated both author and validator skills and the API validation map with
cold-path measurement guidance, bounded immutable reuse, exact safe projection,
live identity-change checks, and browser failure/recovery verification.

Fresh GPT 6.1 Sol trials used short prompts with only the skill, task, artifact
scope, and exclusion of previous reports/diagnoses. The parent inspected and
reran the artifacts:

- Validator: “Use .agents/skills/router-plugin-validate/SKILL.md to validate
  executable-identity reuse across plug-in changes with a small runnable scenario.”
  Four checks pass, covering source/live-target mutations, runtime imports,
  exact code identity, collection, and bounded eviction.
- Author: “Use .agents/skills/router-plugin-author/SKILL.md to build and validate
  a small synthetic plug-in workflow from durable import through searchable
  evidence, including failure recovery.”
  The workflow persists and reopens a revision with two retained sources, one
  relationship, and one finding; safe corpus search resolves both evidence UIDs.
  A truncated content-addressed blob is quarantined and repaired. This is an
  inline core-corpus scenario, not HTTP search or an isolated-worker trial.
- Validator: “Use .agents/skills/router-plugin-validate/SKILL.md to validate cold
  search progress and exact safe search results with a small runnable scenario.”
  One scenario passes with 2,057 events and ten independently checked query
  results, including hidden values, Unicode, literal punctuation, escaped NUL,
  and document boundaries. Progress advances at 1,024, 2,048, and 2,057 records;
  warm queries reuse the corpus and a second instance reopens its sidecar.
- Validator measurement follow-up: “Use .agents/skills/router-plugin-validate/SKILL.md
  to compare the measurements in .runtime/audit-fixes-2026-10-20/before-1 and
  after-1.” After the skill gained explicit repeated-phase guidance, a new agent
  independently retained all 38 occurrences, checked raw child records against
  results, recomputed sampled memory maxima, and obtained the corrected CPU
  preliminary totals. A second fresh trial compared `before-1` and final
  `after-2`, independently confirming all 38 summaries and the final totals
  above. Its runnable artifacts are in `final-measure-skill-trial/`.
- Validator: “Use .agents/skills/router-plugin-validate/SKILL.md to validate
  durable-import/search cooperation and failure recovery with a small runnable
  scenario.” Seven scheduling tests and a separate 4,096-document scenario
  passed. The parent inspected and reran the scenario: success, error, and
  cancellation preserve 586 exact matches and refinement ordinal 4,095, then
  release activity so idle and same-thread searches do not pause. The claimed
  stage body is synthetic; full publication is covered separately.

Skill SHA-256 values at dispatch:

```text
author:    6c681b3f765e20f0861c9bf7f209002d6e78519428ced97eebae9891fc9bcb8c
validator: b217b16a52db14c6988eba8da3307c8c89b65d8e8f270e883f4285bce7214e89
```

Validator after the repeated-phase clarification, used by the independent
measurement trial:
`136da47711fb0c2fffd747a98b3204944c39bf92e99996473e8b06b61760dd15`.

Final skills also document conditional scheduling, cleanup, and paired import
and search measurements. SHA-256 values:

```text
author:    7b556894435b18b4ac0961a67fa147bb6334777f509e995721963b8c4825b360
validator: 5e54f84bf67900d4d2596952d9cff77b82b9cb2e8e3b120d1bf4f56c9f6b4855
```

Validation includes:

- Full frontend check: 392 passed.
- Focused search/projection suites: 95 tests run, one Windows symlink privilege skip.
- Identity, capability-router, and provider-boundary suites: 107 tests run,
  102 passed and five skipped; the durable publication/restart regression also
  passed.
- Documentation smoke: 18 passed, including the documented teaching workflow.
- Parent final integration rerun: 27 passed, combining those 18 documentation
  checks with seven scheduling checks and actual durable success/restart and
  failed-state telemetry cases.
- Final scheduling, corpus, and durable-boundary checks: 44 run, 43 passed and
  one skipped, including actual publication/restart and changed-source rejection.
- Both skill-format checks pass; plug-in conformance inventory passes.
- Generated stubs verified: 146 modules across four packages.
- Fatal Ruff checks pass. Focused strict mypy has the same 93 existing errors
  and seven notes as the baseline; no introduced diagnostic after normalizing
  shifted source coordinates.
- The new internal scheduling helper passes strict mypy independently.

Some Windows sandbox/default-TEMP checks stalled or failed. Search tests also
captured OneDrive `WinError 5` during atomic sidecar replacement; exact in-memory
fallback remained available. The final focused search suite passed using a
fresh writable local TEMP outside OneDrive. Failed runs remain in the evidence;
they are not counted as passing checks.

The upstream transport reproducer is
`.runtime/audit-fixes-2026-10-20/proactor-cleanup-reproducer.py`. Run it with the
configured interpreter and `-I -S`: it reports WinError 10054, one protocol
notification, zero socket closes, and incomplete cleanup. It uses a synthetic
socket and makes no network connections. Suppressing this exception would hide
incomplete cleanup.

Plug-in documentation drift check completed: public plug-in signatures,
discovery, manifests, parsing semantics, identity authority, and authoring
commands are unchanged. The quickstart, normative contracts, and runnable
example require no changes for these internal accelerators and UI corrections.

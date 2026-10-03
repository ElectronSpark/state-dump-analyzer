# Search storage and projection improvements — 2026-10-03

The preceding history and million-event scrolling work was committed as
`a1ee694` (`Optimize history query algorithms and fix million-event scrolling`)
before this implementation. This follow-up completes the recommended storage
work and the measured cold-search projection improvement:

- [x] Preserve 4 KiB pages for small plain sidecars; use 64 KiB pages for large
  plain or compressed sidecars.
- [x] Store large safe-text corpora in bounded, versioned zlib blocks, retaining
  exact literal searches, ordered ordinals, disclosure and corruption recovery.
- [x] Profile cold construction and remove redundant nested redaction, repeated
  empty-policy path matching and avoidable mapping dispatch.

Compact event rows and ranked mixed event/source merging remain future work.
Neither was implemented or measured as part of this change. Device interpretation
remains in the plug-in; these changes operate on core-owned safe projections.

## Controlled storage comparison

The checkpoint implementation and new storage queried the same 1,250,005 already
safe documents (1,768,382,872 characters). Six terms ran three times each with
result retention disabled. Every count and SHA-256 of ordered result ordinals
matched. CPU figures are medians; this is a local sequential comparison without
flushing the OS file cache, not a cross-platform benchmark.

| Query | Checkpoint CPU | Compressed CPU |
| --- | ---: | ---: |
| `failure` | 2.766 s | 2.000 s |
| `success` | 3.188 s | 2.031 s |
| absent literal | 2.938 s | 1.797 s |
| `dte-000000` | 3.172 s | 1.828 s |
| `":` | 2.328 s | 1.875 s |
| `fa` | 2.797 s | 1.969 s |

The sidecar shrank from **2,492,391,424 to 75,038,720 bytes**, about **97.0%**.
Uncached scan CPU fell **19.5–42.4%** across these terms. This reduction concerns
derived search storage, not the archive or retained event dictionaries.

Reopen still validates the complete corpus, including UTF-8, framing, counts,
per-block raw digests, canonical document digest and revision identity. Query
readers verify the compressed bytes against generation-pinned hashes before
bounded decompression. This avoids hashing 1.77 GB of expanded text on each query
while retaining the guarantee that it is the previously validated corpus.

The cold profile attributed 80.8% of its instrumented search time to client-safe
projection; SQLite insertion was only 2.3%. Cumulative profile rows overlap.
Profile timing includes substantial instrumentation overhead and is not request
latency. Independent synthetic projection comparisons preserved exact serialized
output and measured 3.12× speedup with an empty policy and 2.07× with sensitive
paths; these are component measurements, not full-application speedups.

## Full demo and remaining costs

A fresh process and empty sidecar directory completed the 1,250,005-event PE-A
scenario in **192.80 s**, with no error or memory guard activation. The newly
projected corpus exactly matched the pre-change identity, count, character count
and canonical document SHA-256:
`e822d341feb8f3d1172725004d2e286614416d42c07e21446f4de725faef6b36`.
This checks complete disclosure output parity across the real archive, beyond
the query-result comparisons and synthetic redaction tests.

| Operation | Earlier run | Current run |
| --- | ---: | ---: |
| Archive preparation | 18.468 s | 19.206 s |
| PE-A load | 25.877 s | 27.24 s |
| First `failure`, including safe corpus construction | 80.423 s | 59.668 s |
| First ready-corpus `success` | 3.181 s | 2.15 s |
| Refine cached `fail` to `failu` | 1.807 s | 2.548 s |
| Refine `failure` with absent suffix | 0.109 s | 0.445 s |
| First Control plane + `success` page | 1.535 s | 1.60 s |
| Return to A and validate/reuse its sidecar | 4.736 s | 5.600 s |

These single full-application runs are historical comparisons, not a controlled
A/B attribution of the entire latency difference. The earlier evidence is in
[the algorithm report](algorithm-improvements-2026-10-02.md). The controlled
same-corpus comparison above isolates ready-corpus full scans.

Repeated `failure` took 3.18 ms; five cached `success` requests took 7.50–8.03 ms.
The first 256-bin density query took 7.36 ms and repeats took 1.05–1.09 ms.

Compressed blocks improve full scans but can cost more for scattered candidate
refinements because several requested documents share a decompression unit.
Validated reopening also retains a complete decode pass. These measured costs
remain optimization opportunities; the change does not make every query faster.

PE-A load retained **3.21 GiB**, navigation peaked at **6.35 GiB**, and close/GC
returned the process to **0.15 GiB**. The old A generation was reclaimed after
switching to B; service-rooted query caches were empty. Total history RAM is
essentially unchanged. Compact event representation and navigation overlap are
still the next memory targets. The input archive was reused unchanged because
this work changes neither its schema nor generated device content.

## Skills and independent validation

GPT-6.1 Sol implemented using `router-plugin-author`; the parent reviewed the
diff and ran independent reference checks and measurements. Two fresh Sol agents
then received short prompts with no inherited conversation or API recipe:

> Use router-plugin-author to exercise the new history search storage in a small runnable example. Keep changes under .runtime/storage-skill-author-trial; do not edit production or run large benchmarks. Report what works and any skill gaps.

> Use router-plugin-validate to audit the current search storage and event projection changes, including combined API behavior. Keep any artifacts under .runtime/storage-skill-validator-trial; do not edit production or run large benchmarks. Report failures and skill gaps.

The author trial exercised exact Unicode/NUL/empty/boundary matching, bounded
result retention, one-block sparse refinement, reopen, corrupt-cache fallback
and compact small sidecars. The combined trial exercised real
`RevisionQueryService` redaction, exact search, paging and same-timestamp timeline
membership. Both supplied runnable artifacts and exact commands. The map now
provides a direct focused storage test command and Windows UTF-8 guidance.

Skill SHA-256 values used by the trials:

- Author: `29ce3503e6cd7a14a5d124765840df9bcc31c8a7cba8fbf2c8afb15663189cd9`.
- Validator: `92b4a396b1685c6c2d8978d7673679d767e8a74da9a2aa015cc4ef3fb94fd1e0`.

The parent checks cover randomized literal parity, selective decoder work and
corrupt framing. Projection tests use an independent segment-path oracle and
mutable-output isolation. The documentation smoke executes the documented
quickstart commands. These focused checks do not constitute a new exhaustive
audit of every repository API.

Parent checks passed: 22 independent storage assertions; the author and combined
trial drivers; 34 final storage/projection tests (one Windows symlink privilege
skip); and the documented authoring smoke in the earlier 51-test run (one skip).
The Sol validator also ran the history algorithm and revision-query suites.
Both skill format checks and parity for 145 generated module stubs passed.
Strict typing passed for the search core; the projection module retains the
same 16 pre-existing strict typing diagnostics as its saved baseline.

Validation found and repaired small-sidecar size/budget regressions, dense scan
CPU overhead and a corrupt-existing-cache pin-publication bug. In the last case,
a rejected cache could replace the new generation's hashes and cause unnecessary
memory fallback. Pins now publish only after complete canonical validation; both
the independent reproduction and new regression confirm the rebuilt cache stays
in SQLite mode. This final change affects rejected-cache recovery, which was not
encountered by the successful full-scale timing scenario.

## Browser check

Restarted the task-owned demo at `http://127.0.0.1:8883/node#overview` with the
final source and the measured compressed sidecar. The UI loaded 1,250,005 events
and 7,510 resources. `success` returned 1,225,080 exact records; adding Control
plane returned 354,505. End reached the last matching row in both cases, and the
filtered tail rendered nine visible rows with final selection index 354,504.
No browser warning/error entries or visible alerts were captured. The server is
left running for review. This check does not measure browser startup latency;
the backend timings above exclude HTTP and frontend initialization.

Screenshot: `.runtime/search-storage-validation/final-browser.jpg`.

## Reproduction and evidence

Use the configured Python 3.12 environment from the repository root:

```powershell
python -X utf8 .runtime/search-storage-validation/check_storage.py
python -X utf8 .runtime/search-storage-validation/measure_storage.py --output .runtime/search-storage-validation/reproduction --source .runtime/search-storage-profile/cold-current/search-cache/000-node-a-0da3fb94be475d5b46153f5a.history-search.sqlite3
python -X utf8 .runtime/algorithm-improvements/measure.py --archive demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --output .runtime/search-storage-validation/application-reproduction --repeats 5 --dense-term success
python -m unittest tests.test_history_search_core tests.test_event_projection_performance tests.test_plugin_authoring_docs -v
```

Measurement output directories must be new. Task-local evidence includes
`full-v4/result.json`, `application-final/result.json`, `final-summary.json`,
parent test logs and both skill trial directories. The profiling harness,
original projection module and differential driver are under
`.runtime/search-storage-profile`. These local evidence artifacts are not
distributed plug-in APIs.

Documentation drift check: the API contract and validation map describe the new
internal storage format and guarantees. No parser capability, required history
protocol, discovery mechanism or device semantics changed. The quickstart,
normative plug-in contract and teaching example remain valid without changes.

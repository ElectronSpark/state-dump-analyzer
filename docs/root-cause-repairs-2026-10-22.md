# Loading, search, disconnect and Windows cleanup repairs

## Scope and causes

1. **Cold member navigation:** the compatibility loader retained new immutable
   dictionaries and affected-resource lists for each event even when complete
   values repeated. Extended its existing load-local value pool to reuse bounded
   complete states and ordered identifier lists. Nested values and ambiguous
   numeric types retain ordinary owned freezing. Archive validation, sorting,
   identity and the one-generation cache policy are unchanged.
2. **First search and cold reopen:** empty disclosure policies repeatedly resolved
   event resource associations that could not change the effective policy; cold
   compressed validation decoded and re-encoded every document before hashing.
   Empty policies now skip only association resolution. Ordinary allowlisting and
   owned projection remain. Reopen validates bounded UTF-8 blocks and every
   document boundary, then hashes original framed bytes. The v7 format, complete
   digest, corruption fallback and safe-text output remain unchanged.
3. **Abandoned reads:** disconnect scopes covered only timeline/density, and other
   core loops did not observe request cancellation. Reused the existing scope
   across analysis reads and added batched core checkpoints. Durable mutation
   routes remain separate. Search waiters can cancel independently; interrupted
   builders release waiters without caching cancellation as a permanent error.
4. **Windows reset cleanup:** CPython 3.12.13's Proactor shutdown can raise a peer
   reset before transport close/server detach. The CLI now creates an app-owned
   Proactor loop with a reset-safe socket subclass at two transport construction
   hooks. It preserves the socket object and descriptor, allowing existing
   CPython cleanup to finish. An initial descriptor-rewrapping approach failed
   real outgoing TCP/TLS tests and was replaced before completion. No global
   patch, selector fallback or traceback filter is used.

## Fresh 1M measurement

The unchanged 52-phase harness ran serially in fresh child processes with separate
empty search caches, frozen before/after source trees and `PYTHONHASHSEED=0`.
The fixture has 1,250,005 events in node A and 1,250,002 in node B; archive size
286,496,584 bytes, SHA-256
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
Baseline source reference: `de05a522bb5bf222c132cb6911b587561e5a8ff0`, with the
working-tree snapshot retaining the pre-existing audit tests.

| Metric | Before | After |
| --- | ---: | ---: |
| Node A loaded RSS | 2.355 GiB | 2.174 GiB |
| Sampled navigation peak RSS | 2.370 GiB | 2.189 GiB |
| Process lifetime peak RSS | 2.433 GiB | 2.254 GiB |
| Process lifetime peak private commit | 2.428 GiB | 2.248 GiB |
| All 52 phase CPU times summed | 205.406 s | 185.406 s |
| Supervisor elapsed time | 210.579 s | 189.766 s |
| Initial member load, wall / CPU | 35.247 / 34.516 s | 33.664 / 32.953 s |
| First search, wall / CPU | 58.975 / 57.547 s | 46.726 / 45.781 s |
| Switch to B, wall / CPU | 36.121 / 35.469 s | 33.407 / 32.766 s |
| Return to A, wall / CPU | 36.773 / 36.266 s | 33.770 / 33.281 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

All 52 ordered phase summaries, all 35 complete response hashes, and cache
retirement observations match. Repeated phase names are counted separately.
Total measured CPU fell 9.74%; peak RSS fell 183.14 MiB. Warm same-term wall time
was 3.05 / 2.29 ms; the Windows CPU timer is too coarse for that individual call.

A separate fresh-process validation of the same existing 1M sidecar took
6.096 / 5.588 s wall and 6.000 / 5.469 s CPU. Both returned the same 24,925
ordered matches, SHA-256
`c4acdf07a3d97c79d44755c6b4b40a3841faf78dd898502e4a97294804d6a8c0`.
These are single before/after observations, not statistical estimates. OS file
caches were not cleared. Service phases exclude HTTP/browser rendering and
response-summary hashing; HTTP cancellation overhead is assessed separately by
integration checks. Host available RAM stayed above 34.9 GiB. Cold parsing and
first safe-text construction remain linear and still take tens of seconds.

Raw commands, snapshots, hashes, process samples and comparison results are in
`.runtime/root-cause-repairs-2026-10-22/`. The before/after harness is identical
to the preceding 52-phase workload, SHA-256
`05a586a092289fe65a10462bba61e79f988bc8588d121bad727df1eed752a92a`.

## Validation and limits

- `npm --prefix frontend run check`: **601/601 passed**. Initial sandbox proxy
  failures were `EACCES` on loopback; the permitted loopback rerun passed.
- `tests.test_scale_data`: **29 passed**, including pooled/unpooled JSON parity,
  nested ownership, ordering, bool/int/float distinctions and pool bounds.
- Search-focused suite: **73 passed, one Windows symlink-privilege skip**.
- Cancellation/history/core focused suite: **127 passed, one symlink skip**.
  Actual ASGI messages exercise mid-scan disconnects, early body abort, independent
  readers, lease release, durable-router exclusion and retry after cancellation.
- Windows/Uvicorn suite: **16 passed**. Includes exact-once cleanup, unrelated
  errors, 600 simultaneous TCP connections, 300 reset closes, TLS in both
  directions, subprocess support and actual CLI HTTP/lifespan shutdown.
- Generated stubs: **149 modules verified**; documented strict public typing
  fixtures pass. Architecture guards, conformance inventory and focused Ruff pass.
- Stable-source broader replay: **173/173 tests passed**, then route application
  setup and cleanup passed. An earlier combined run completed 188 tests but one
  route class setup returned a sanitized HTTP 500. It did not recur in isolated
  route setup/seven cases, a 39-test topology replay, or the same eight-module
  prelude replay. Its original underlying exception was not captured, so the
  cause remains unattributed; the full 77 route cases were not rerun.
- A fresh GPT-6.1 Sol trial used the updated skills with no inherited conversation,
  API hints or access to prior outputs. **36 focused checks passed**. The trial
  documented its sandbox Proactor socketpair block instead of claiming real
  transport coverage; the separate permitted transport runs above cover it.

## Native browser verification

Restarted the actual CLI on `127.0.0.1:8883` with the full fixture, the existing
isolated synthetic control plane and an empty, task-local search cache.
All actions used the browser's real controls; no injected application state,
programmatic fetches or delayed-response proxy was used.

- Node A visibly loaded all 1,250,005 events / 7,510 resources.
- Started a cold `failure` search, cleared it while the page was loading, and
  observed the unfiltered 1,250,005-record log return. The interrupted temporary
  sidecar was removed. Retrying completed with the expected 24,925 matches.
- Changed and cleared resource filters while the independent event index was
  building; the final resource table recovered its 1,875 bundles / 500 visible
  resources, and the event search retained its own filter and exact count.
- Selected `node-a/scale-event-01000759` from the filtered log, revealed its
  `dte-000009` lane, zoomed and used Back. The inspector retained its exact
  event identity, failure outcome and affected resource.
- Returned through the fabric and opened node B: all 1,250,002 events / 7,509
  resources loaded. Returned through the fabric to A and verified the complete
  original dataset again.
- Searched after return, superseded it with `failure missing-literal-probe`
  (zero matches), then restored `failure` (24,925 matches).
- Repeated Home/End cursor operations while dependent temporal reads were pending
  and checked that the latest selected moment settled across components.

Browser console inspection returned no warnings/errors; the restarted server
logs contained no traceback, HTTP 500 or Windows reset-cleanup error. This native
pass establishes integrated behavior, not exhaustive timing or deterministic RST
reproduction. The ASGI and Windows transport tests establish those lower-level
properties. Browser observations are in the task's `browser.jsonl` and console log.

Cancellation is cooperative. Shared synchronous runtime/provider construction,
opaque plug-in callbacks and the demo resource-search cache's contended lock
cannot be preempted internally. An independently active builder remains valid.
Windows compatibility relies on two private CPython transport construction hooks
and accepts plain/already-adapted sockets; tests must be rerun on runtime upgrades.

The author and validator skills and their performance map were updated. The
`AGENTS.md` drift check found no changed public plug-in signatures, declarations,
emissions, disclosure semantics or author commands, so the maintained quickstart,
normative contracts and runnable teaching example required no changes.

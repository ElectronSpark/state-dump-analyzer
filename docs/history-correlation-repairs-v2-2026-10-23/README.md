# Historical route and resource-correlation repairs — 2026-10-23

Follow-up to the [second 100-move audit](../history-correlation-100-browser-audit-v2-2026-10-23/README.md), against base commit `141836e649510e21c56d469d9c93de3cc18f11ce`.

## Root causes and changes

| Finding | Cause | Repair |
| --- | --- | --- |
| HCR2-01: direction-dependent historical VPN validity | The demo generator copied a route owner's native observation timestamp into every executing hop, although those devices have different clock offsets. | Convert the observation through UTC into the executing node's native clock in the existing assignment. Keep the core's independent decision and source-evidence validity gates. Regenerate the persisted projections. |
| HCR2-02: false zero correlations | The relationship index treated absence from a bounded/representative response as evidence that the selected resource had no relationships. The empty canvas also assumed the root was inactive. | Use the existing returned nodes and explicit inactive/unknown metadata to distinguish coverage from lifecycle. Qualify counts as returned; retain the existing Focus selected recovery and graph bounds. |
| HCR2-03: service popup blocks graph controls | Horizontal viewport clamping moved the card over its own trigger and the adjacent mode toolbar when neither side had room. | In the existing positioner, use an above/below gap that excludes the trigger and toolbar, constrain the scrollable card to that gap, and dismiss when no space exists. Preserve pinned content and focus. |

No core API, plug-in hook, cache bound, or graph limit was added.

## Automated validation

- `npm --prefix frontend run check`: **635 passed, 0 failed**. The first sandbox run passed 624 and encountered loopback `EACCES` in the proxy suite (ten children plus their parent); the approved host rerun passed the full suite.
- Six focused generator/history/API tests passed in **279.303 s**. The new API regression contains 32 direct/table-seeded, bidirectional trace cases across both A/B origins and both missing-hop policies. It checks +601.006 s, +601.009 s, +601.008999999 s, and +601.010 s, including backward repetition. These policy variations are route resolution policies, not topology clock policies.
- The generator regression checks every inventory continuation against the source observation's UTC instant using unequal device offsets.
- Updated author and validation skills pass `quick_validate.py`.
- Plug-in documentation drift review: these changes restore the existing native-clock and response-coverage contracts and repair internal rendering. No public API or author command changed; the quickstart, normative contract, and runnable example require no change. The skills and API validation map now include the missing checks.

The historical HTTP test initially blocked in the sandbox's Windows Proactor socketpair setup before reaching assertions; the host retry passed. Fixture generation initially encountered a sandbox temporary-directory permission error; the successful retry uses a workspace-local temporary directory. Failure logs are retained separately from successful evidence.

## Browser validation

Sixteen saved workflow records cover repeated and cross-component checks through
the real browser UI. They are evidence of these specific workflows, not an
exhaustive browser matrix.

- Narrow-layout service card: the center of Focused path hit the button while
  the card was open. Pointer switching succeeded repeatedly after pointer and
  keyboard service activation, both directions, internal card scrolling, and a
  trip through the node workspace. The constrained card scrolled internally.
- DTE1874 at +720 s: full graph reported **Not covered**, with existing Focus
  selected recovery; focused graph returned its `next_hop` to ETG1874. At
  +120.187399999 s the table showed absent and the focused graph reported outside
  lifecycle; at +120.187400000 s both showed the active resource/relationship.
  Full/focused and past/latest repetitions retained the correct distinction.
  A requested +720 s range clamped to +719.485 s in the repeat check; that record
  is not claimed as another exact +720 s observation.
- On the regenerated archive, B→A direct traces were unresolved in both
  directions at UTC +601.006 s and resolved at +601.009 s under Best effort
  topology clock policy. Strict clock policy also rejected +601.008999999 s and
  resolved +601.010 s. PE-A table-seeded A→B checks then resolved at +601.010 s,
  rejected +601.006 s despite the valid PE-A source row, and resolved at the
  exact +601.009 s boundary. The table row was freshly seeded after each
  reconstruction, rather than relying on a retired seed.
- No browser console warnings/errors were returned by the final diagnostic read.

Popup/correlation checks used the repaired assets with the prior fixture while
the replacement archive generated. Historical boundary checks used the restarted
server and the replacement archive. Route projections are the only generated
semantics changed by this repair.

The replacement is `demo/fixtures/router-state-lab-history-clock-2026-10-23.tgz`,
286,523,508 bytes, SHA-256
`fb1ef97c01ef7306d0e4104cedcaba2fd3615bb701c5d9cc3aa6abc92f273470`.
The generator and `--check-launchable` passed: ten full-scale nodes, 41 coverage
cases, canonical defaults of 1,250,000 events and 7,500 resources per node, seed
20260725. PE-A's normalized workspace includes 1,250,005 events and 7,510 resources.
The previous fixture was preserved. The demo on port 8883 serves the new archive.

## Cursor investigation and 1M measurements

The isolated production-service probe measured eight exact audit timestamps in
two rounds, reversing empty/active search order, with an exact repeat for each
component: 128 calls, followed by four separate cProfile runs. The search
snapshot was cleared before each fresh timestamp case; history stayed warm after
the separately measured lazy initialization. Limits stayed at 500 resource rows
and 500 graph nodes, depth 3. These are direct-service timings, excluding HTTP,
serialization, browser rendering, automation, and topology-follow requests.

| Component | Fresh median wall / CPU | Exact-repeat median wall / CPU |
| --- | ---: | ---: |
| Resource table, search empty | 84.5 / 78.1 ms | 87.1 / 78.1 ms |
| Resource table, search active | 1.524 / 1.500 s | 2.83 ms / below CPU timer resolution |
| Focused correlations | 25.7 / 31.3 ms | 25.4 / 31.3 ms |
| Open live dashboards | 1.104 / 1.094 s | 1.126 / 1.094 s |

Small focused graphs took about 3 ms; graph cases reaching the existing
500-node bound took about 0.25 s. One exact-repeat dashboard call took 3.642 s,
with 3.578 s CPU and unchanged before/after RSS, so its median does not establish
an upper bound. This measurement does not identify GC or scheduling as the cause
of that outlier.

The first searched cursor required **6.888 s wall / 6.703 s CPU** and increased
RSS from 2.174 to 2.761 GiB. The largest before/after RSS snapshot in this broader
cursor workload was **2.779 GiB**. This is neither a continuously sampled peak
nor the same workload as the navigation benchmark below.

The remaining CPU cost is population-wide reconstruction and projection:

- Search builds safe searchable text for all 7,510 resources at a new timestamp
  to preserve cross-kind counts. In the separate instrumented occurrence,
  search-text projection accounts for 3.520 of 5.087 cumulative seconds, with
  repeated declared-field selection and state-interval traversal prominent.
  These profile seconds include instrumentation overhead and are not latency.
- The default-open `forwarding-population` and `neighbor-health` dashboards
  reconstruct and redact 7,125 resource states on every call. In their separate
  profile, `resource_state_at` accounts for 3.239 of 3.342 cumulative seconds.
  They do not reuse the resource-search text snapshot on an identical timestamp.

All 64 exact-repeat output pairs and 64 cross-round pairs matched; the four
profile outputs also matched uninstrumented results. Full saved response digests
were verified. The controlled sequence retained at most one search snapshot
(7,510 documents), within the unchanged two-timestamp capacity.

The three correctness bugs are fixed; this investigation does **not** claim a
cursor speedup. The next target is the existing state/field projection path,
particularly dashboard population reconstruction and repeated declared-field
walks. Any optimization must preserve disclosure, overlapping historical
perspectives, and cross-kind counts; increasing graph bounds or caching every
cursor position would address neither the root cost nor the memory constraint.

The separate 52-phase measurement completed successfully. Its unchanged harness has SHA-256
`05a586a092289fe65a10462bba61e79f988bc8588d121bad727df1eed752a92a`; the baseline is
the previous repair's `after-1m-quiet/result.json`.

| Metric | Previous quiet run | Repaired fixture run |
| --- | ---: | ---: |
| Loaded RSS | 2.1785 GiB | 2.1750 GiB |
| Lifetime peak RSS | 2.2556 GiB | 2.2543 GiB |
| Lifetime peak private commit | 2.2508 GiB | 2.2493 GiB |
| Sum of 52 phase CPU times | 155.7188 s | 158.2813 s |
| Elapsed | 161.625 s | 161.813 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

Both runs exited 0 with no memory/time guard triggered. All 52 ordered phase
results, 35 complete page hashes, and search/retirement/validation-cache
invariants match. CPU is +1.65% and elapsed +0.12% in this single comparison;
there is no measured speedup claim or statistical regression conclusion.

This fresh-process, fresh-search-cache Windows workload uses 100 ms memory
sampling and process lifetime counters, with no concurrent test, generation,
cursor profile, or browser interaction. OS caches are not flushed; browser and
the idle demo server's memory are excluded. The new archive has repaired route
projections and a different archive fingerprint, so this is not a byte-identical
input comparison; the measured normalized results match exactly. The separate
2.779 GiB cursor snapshot above demonstrates that this navigation workload does
not bound memory for every frontend operation.

## Evidence

- [Measurement comparison](comparison.json)
- [Evidence archive](evidence.zip), including browser observations, complete
  cursor responses/profiles, source hashes, baseline/final measurement outputs,
  and successful/blocked validation logs
- [Evidence file hashes](evidence-manifest.json)
- [Popup controls](popup-controls-clear.png), [correlation coverage](correlation-not-covered.png),
  and [historical bidirectional boundary](clock-boundary-both-directions.png)

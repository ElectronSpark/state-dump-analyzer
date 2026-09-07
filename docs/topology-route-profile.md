# Cold topology and warm route profiling

Measured on 2026-09-07 against commit
`26158751d8f33ab1f876e29df428dfccb6e6a3b8`. These measurements separate
construction, first query, and repeated route execution. No product code,
identity validation, safety limit, or cache policy was changed for this work.

Use [`profile_topology_routes.py`](../scripts/profile_topology_routes.py) from
a stable checkout. It creates a bounded fixture in the output directory, runs
three fresh Python processes for latency measurements, then runs a separate
process under cProfile. Each worker has a 300-second deadline by default.
The output directory must be outside the measured repository. The script
checks source bytes before and after the run and verifies that imported
core/demo modules came from the selected checkout.

```powershell
python -B scripts/profile_topology_routes.py --repository . --output ../topology-profile-direct --samples 3 --warm-traces 3 --timeout 300
python -B scripts/profile_topology_routes.py --repository . --output ../topology-profile-context --samples 3 --warm-traces 3 --timeout 300 --reuse-topology-context
```

`--reuse-topology-context` supplies the first topology query's context ID,
matching the topology browser's route request. Without it, each trace constructs
a new selected topology snapshot. Both modes retain the separate route-evidence
query and all live provider checks. The two topology queries have different
projection scopes; removing one would require a separate correctness analysis.

This run used
`C:/Users/82046/anaconda3/envs/router-dump-analyzer-demo/python.exe`, an isolated
`git archive` snapshot named `o5-source-26158751d8f3`, and the commands above
with `--source-label 26158751d8f33ab1f876e29df428dfccb6e6a3b8`.
Raw outputs are in the audit artifact directory's `remaining-fixes/o5-profile`
and `remaining-fixes/o5-profile-context` subdirectories. Each contains
`summary.json`, individual `timing-*.json` results, `fixture.json`, `profile.json`,
per-phase `.pstats` files, and worker logs. Inspect profiles with standard
`pstats.Stats(...).sort_stats("cumulative").print_stats(30)`; cumulative rows
include their callees and must not be added together.

## Fixture and measurement boundary

The fixed seed is `20260725`. The generator requests 120 events and 120
resources per node; mandatory scenario records produce these actual totals:

| Dimension | Value |
| --- | ---: |
| Nodes | 10 |
| Events | 1,233 |
| Resources | 1,252 |
| Route rows | 741 |
| Topology claims | 50 |
| Packet cases | 40 |
| Compressed fixture bytes | 1,252,184 |
| First query resources / segments / attachments | 88 / 31 / 50 |

The route scenario is `single-active-primary`, with `max_hops=32` and
`max_recursion=8`. Every measured call must return two resolved five-segment
paths and exactly one active path. The selected topology query caps resources
at 100, network segments at 100, and segment attachments at 200.

The machine reported Windows 11 build 26200, Python 3.12.13 from conda-forge,
Intel64 Family 6 Model 154 Stepping 3, and 16 logical CPUs. The source digest
covered 295 files / 7,354,013 bytes and remained
`ecbc131cf2738a0a998751df1466be0de9dd14007c7fbedbdc41f07548de5e39`.
The fixture SHA-256 is
`04487181f3adda56579fe5fe207cc893bfc8d860721335f11b00bbf5e7b70594`.

## Uninstrumented latency

Each request mode used three fresh processes and nine subsequent warm trace
calls. Each first trace followed construction and one explicit topology query.
Times are wall-clock seconds, with the observed range retained because this
was a shared development host. The context choice affects route requests only;
differences in earlier phases reflect run variation, not a context-mode effect.

| Phase | New context median | Range | Recorded context median | Range |
| --- | ---: | ---: | ---: | ---: |
| Runtime import | 1.310 | 0.982–1.656 | 1.461 | 1.382–1.835 |
| Runtime open | <0.001 | <0.001–<0.001 | <0.001 | <0.001–<0.001 |
| Cold topology construction | 16.352 | 13.658–26.987 | 24.526 | 22.633–27.826 |
| First topology query | 6.546 | 5.509–8.900 | 8.428 | 6.621–10.693 |
| Route service construction | 0.016 | 0.015–0.019 | 0.017 | 0.016–0.017 |
| First route trace | 12.282 | 11.069–19.442 | 9.949 | 8.762–10.145 |
| Warm route trace | 14.224 | 10.741–22.661 | 9.189 | 7.991–11.123 |

Cold topology construction includes archive/dataset access, projection setup,
and provider registration/attestation. `runtime.open()` is lazy; its tiny
duration does not represent readiness. The median sum of import, open,
construction, and first query was 24.208 seconds in the first batch and 36.283
seconds in the context-reuse batch. Fixture generation, process
startup/shutdown, HTTP serving, response serialization, and browser rendering
are outside that sum.

## Attribution from the separate profiler run

The first topology query executed ten provider invocations and twenty
`_validated_executor` calls: the router revalidates each provider before and
after invocation. A trace without a recorded context performs two topology
queries, producing forty validations. Three warm traces performed 120
validations without context reuse and 60 with context reuse. Reuse of the
service does not turn these live checks into a one-time startup cost.

| Instrumented work | Cold construction, first batch | Three warm traces, new contexts | Three warm traces, recorded context |
| --- | ---: | ---: | ---: |
| Phase wall time | 27.923 s | 91.901 s | 37.131 s |
| Module-target fingerprint calls | 50 | 120 | 60 |
| Module-target fingerprint cumulative time | 26.190 s | 86.018 s | 34.613 s |
| Package-scope fingerprint calls | 140 | 360 | 180 |
| Package-scope fingerprint cumulative time | 2.763 s | 10.185 s | 4.018 s |
| Built-in source compilation calls | 450 | 1,080 | 540 |
| Built-in compilation self time | 7.270 s | 22.692 s | 9.293 s |
| `ast.parse` calls | 0 | 0 | 0 |

Provider validation accounted for 9.688 of the first topology query's 9.858
instrumented seconds, and 89.831 of the three new-context warm traces' 91.901
seconds. With recorded context reuse it consumed 36.141 of 37.131 seconds.
The package-scope hash walk is a material contributor, but it does not explain
most of the cost. Live code/class/dependency attestation dominates the sampled
path. Compilation contributes about 26% of instrumented cold construction and
25% of the warm-trace batch. The explicit `ast.parse` and Python AST helper
paths were not exercised. Parsing performed internally by the compiler is
included in its compilation time; these results do not isolate that cost or
justify an optimization of the separate AST helpers.

The current identity implementation already has caches scoped to an individual
attestation and an optional batch compilation cache. The measured trace path
still performed 360 compilation calls per new-context trace and 180 with a
recorded context. A useful next experiment would measure
bounded reuse of immutable compiled code keyed by freshly verified source bytes,
while retaining package-byte reads and all live object/global/descriptor checks.
This report neither implements that cache nor establishes that it would be safe
or deliver the profiler's theoretical upper-bound saving.

## Limits

- Fresh processes and `-B` prevent reuse of Python import state and bytecode
  writes, but the OS filesystem cache was not flushed. This is process-cold,
  not disk-cold, measurement.
- The host was shared, and other development checks overlapped parts of the
  measurement window. Source isolation prevents file drift, not CPU contention
  or changes in filesystem cache state. The observed ranges are not latency
  percentiles or SLAs.
- The small fixture exercises typed federation, identity checks, and two route
  candidates. It does not model million-event ingestion, high fan-out routes,
  concurrent users, remote storage, or adversarial inputs.
- cProfile changes timing. Its separate run identifies call counts and likely
  contributors; instrumented seconds must not be substituted for request latency.
- Context reuse is existing behavior. An evidence query still needs current
  provider validation; a cached context is not permission to skip that boundary.
- Re-measure after architectural changes such as the route/topology interface
  extraction. These numbers describe the recorded commit, not later source.

The plug-in-author documentation drift check found no public boundary change.
The profiling script and this report introduce no new plug-in requirement.

# Reproducing the repair measurements

Run from a repository checkout containing the repaired sources and the synthetic
fixture named in the report. Use the configured `router-dump-analyzer-demo` Conda
environment, or an equivalent installed Python 3.12 environment with the
repository dependencies. The memory harness uses Windows process APIs.

Extract `evidence.zip` to a new task directory, then verify the recorded results:

```powershell
$EvidenceRoot = Join-Path (Get-Location) '.runtime/route-topology-repair-evidence'
Expand-Archive -LiteralPath 'docs/route-topology-audit-repairs-2026-10-23/evidence.zip' -DestinationPath $EvidenceRoot
conda run -n router-dump-analyzer-demo python "$EvidenceRoot/scripts/verify_results.py" "$EvidenceRoot"
```

For a fresh 52-phase run, choose a new output directory and keep other heavy
processes idle. This creates task-local caches and measurements; it does not
change the fixture or product sources. The OS file cache is not flushed.

```powershell
$RepoRoot = (Get-Location).Path
$MeasurementTemp = Join-Path $EvidenceRoot 'measurement-temp'
New-Item -ItemType Directory -Path $MeasurementTemp | Out-Null
$env:TEMP = $MeasurementTemp
$env:TMP = $MeasurementTemp
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONHASHSEED = '0'
$env:RSL_MEASURE_SOURCE_ROOT = $RepoRoot
conda run -n router-dump-analyzer-demo python "$EvidenceRoot/scripts/measure.py" --archive 'demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz' --output "$EvidenceRoot/new-1m-run"
```

Run a separate route probe to measure unchanged warm repetitions. Its first
load and first trace establish state; the three subsequent unprofiled trace
phases supply the reported median. `--profile-trace` adds a separate diagnostic
trace after those timed repetitions.

```powershell
conda run -n router-dump-analyzer-demo python "$EvidenceRoot/scripts/probe.py" --source $RepoRoot --archive 'demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz' --output "$EvidenceRoot/new-route-run" --profile-trace
```

For the separate sequential initialization diagnostic:

```powershell
conda run -n router-dump-analyzer-demo python "$EvidenceRoot/scripts/probe.py" --source $RepoRoot --archive 'demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz' --output "$EvidenceRoot/new-initialization-run" --node-initialization --only-load
```

That diagnostic queries all dashboards and is not an exact browser replay.
To investigate cold-load call counts, use `--profile --only-load` in another fresh
output directory. Profiled timings include instrumentation overhead and must not
be mixed into the unprofiled medians.

The packaged `scripts/measure.py` is the recorded task harness. The packaged
`scripts/probe.py` differs from the recorded original only in importing its
memory helper from the included sibling `measure.py`, removing the dependency on
the preceding task's runtime directory. The original is retained as
`scripts/probe-original.py`. `scripts/verify_results.py` recomputes the recorded
result/hash equality and route medians without running the workload.

For a new baseline/after comparison, use equivalent source snapshots, the same
fixture and environment, separate processes/cache directories, and repeated
unprofiled runs. The archived historical baseline is evidence of the earlier
run, not a substitute for a fresh paired timing experiment. Do not compare a
profiled baseline against an unprofiled after run.

Frontend validation is `npm --prefix frontend run check`. Identity test commands
and trial-selected composed checks are recorded in `skill-trial/*-command.json`
and `skill-trial/run_checks.ps1`. The original trial script records its host
interpreter path; use your configured interpreter and task-local TEMP/TMP paths
when replaying those arguments elsewhere. Five initially skipped junction cases
required a supported Windows host run; the archived host log records the final
successful coverage.

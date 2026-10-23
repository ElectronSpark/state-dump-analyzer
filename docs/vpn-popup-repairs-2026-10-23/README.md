# VPN service-popup repairs — 2026-10-23

All three findings from the [lane/VPN browser audit](../lane-vpn-browser-audit-2026-10-23/README.md) are repaired. Changes extend the existing service-popup lifecycle and renderer; no new UI controls or plug-in APIs were introduced.

## Changes and validation

| Finding | Root-cause repair | Browser result |
| --- | --- | --- |
| LV01: detached popup overlays unrelated sections | The existing captured scroll handler repositions the service popup, and its positioner dismisses disconnected or fully clipped anchors. Visibility accounts for the sticky header. Scrolling inside the card does not dismiss it. | A trigger partly below the 68 px header retained the popup; moving the remaining trigger behind the header dismissed it. Fully off-screen scrolling also dismissed it. Scrolling back did not reopen it. |
| LV02: passive re-entry resets scroll and steals focus | Re-entering the same pinned context retains its existing DOM. Only explicit activation moves focus to Close. | After reading lower EVPN facts, the popup retained scrollTop=51 and focus stayed on graph Zoom in when the pointer returned to the service label. |
| LV03: delayed resize discards activation and focus | Service-strip rendering moved from graph geometry redraws to the route-state renderer. ResizeObserver frames retain the live service trigger and popup. Semantic route changes still replace them. | Four immediate Focused → All → Space sequences each retained a pinned dialog and Close focus. Pointer mode changes followed immediately by Enter also passed. |

The shared positioner now constrains actual popup height as well as placement, so service details fit below the header in short viewports. A regression checks the shared path preview releases the service-specific height allowance.

Browser checks used the reloaded frontend on the existing port-8883 demo. Direction changes dismissed old service details; ordinary MPLS transport removed the strip; restoring the original blue MPLS L3VPN trace restored its details. Escape returned focus without reopening. The original focused forward route is left open for inspection.

These are native browser actions and read-only DOM observations, not injected application events. The short-viewport limit is covered by the executable regression; the browser run used its existing 1905×933 viewport. The audit's separate native Ctrl/Alt-wheel input limitation is unchanged and is not presented as validated by this repair.

## Automated checks

- `npm --prefix frontend run check`: contract validation and **616/616 tests passed**, with no skips or failures. The host-level retry was required because the sandbox denied the transport tests' local listener (`EACCES`); that environmental failure was not an assertion failure.
- Five focused regressions were added to the existing route audit suite. The original four bug regressions were also run against the unfixed HEAD source and failed, establishing that they detect the reported behavior.
- `python scripts/check_plugin_conformance.py --list`: inventory passed. This is declaration inventory, not a claim of executing all plug-in API conformance groups.
- `quick_validate.py .agents/skills/router-plugin-validate`: passed.

The validation skill and its API map now distinguish layout-only redraws from route replacement, require activation during transitions as well as settled controls, and cover clipped service anchors and passive pin re-entry.

## Million-event measurement

The final comparable run and comparison are recorded in `comparison.json` and the evidence archive. It uses the unchanged earlier measurement harness, the same generated fixture, a fresh process and search cache, and no concurrent browser actions or test runs. It measures server/Python memory and CPU, not browser renderer memory.

The earlier exploratory `after-1m` run completed successfully but briefly overlapped frontend tests. Its wall time is excluded from the final comparison. The quiet rerun is authoritative.

| Metric | Historical baseline | Quiet rerun |
| --- | ---: | ---: |
| Loaded RSS | 2.1748 GiB | 2.1756 GiB |
| Peak RSS | 2.2524 GiB | 2.2544 GiB |
| Peak private commit | 2.2470 GiB | 2.2496 GiB |
| Sum of phase CPU | 178.734 s | 168.266 s |
| Harness elapsed | 183.953 s | 172.984 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

All **52 ordered phase occurrences** and their results match, including repeated
phase names; all **35 complete page hashes** match. Search reopening, cache
retirement, shared-result reuse and validation-cache invariants also match.
The fixture SHA-256 is
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
The workload covers 1,250,005 events and 7,510 resources in PE-A, then navigation
to another full node and return/reopen. It exited successfully without a guard stop.

Memory differs by less than 0.12%. CPU and elapsed time were about 5.9% lower,
but these are historical observations, not a demonstrated speedup from a
frontend repair. OS caches were not flushed. The measured core module texts are
unchanged after newline normalization; the historical application snapshot
predates the already-committed route-step ownership and service-description
changes. No backend implementation changed in this task.

## Reproduction and evidence

From the repository root, use the configured Python environment and fresh output directories:

```powershell
$runRoot = Join-Path (Get-Location).Path '.runtime/vpn-popup-repair-repro'
New-Item -ItemType Directory -Path (Join-Path $runRoot 'tmp') -Force | Out-Null
$env:TEMP = Join-Path $runRoot 'tmp'
$env:TMP = $env:TEMP
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONHASHSEED = '0'
$env:RSL_MEASURE_SOURCE_ROOT = (Get-Location).Path
Expand-Archive 'docs/vpn-popup-repairs-2026-10-23/evidence.zip' (Join-Path $runRoot 'evidence')
& 'C:/Users/82046/anaconda3/envs/router-dump-analyzer-demo/python.exe' `
  (Join-Path $runRoot 'evidence/scripts/measure.py') `
  --archive 'demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz' `
  --output (Join-Path $runRoot 'measurement')
npm --prefix frontend run check
```

Keep the browser and other measurements idle during the measurement run. Its output directory must not already exist. The stress fixture is not included in the archive.

[browser-ledger.json](browser-ledger.json) contains the live observations. [evidence.zip](evidence.zip) contains screenshots, test logs, console observations, the unchanged measurement harness, final raw measurement results and the comparison. [manifest.json](manifest.json) records evidence hashes.

Plug-in documentation drift check completed: discovery, manifests, provider semantics, contracts, examples and author-facing commands are unchanged. No maintained authoring-document update was required. The existing audit remains the historical defect record; this document records its resolution.

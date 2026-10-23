# Lane wheel and VPN route browser audit — 2026-10-23

Three functional defects were reproduced in the VPN service-context popup. No new lane defect or independently established performance regression was found in the exercised operations. This is an audit record; product code was not changed.

Audited commit: `f8f5de77a5124a12317f9e71d23b4a5f7562df25`, branch `codex/comprehensive-router-dump-demo`. The live demo used port 8883, process 10856, and `router-state-lab-algorithms-2026-10-02.tgz`. PE-A contains 1,250,005 events; the P1 workspace loaded 1,250,004 events. Interactions used the actual in-app browser, native scrolling and keyboard/pointer actions, and read-only DOM observations. A separate agent reviewed source causes; it did not substitute for browser reproduction.

## Confirmed defects

### LV01 — P2: pinned service context remains over unrelated sections after its anchor leaves view

1. Trace the blue MPLS L3VPN route, select All paths, and open its service-context details with Space.
2. Scroll the page downward outside the popup and graph until the service strip is above the viewport.
3. The popup remains fixed over the route-table heading and filters.

Reproduced twice (`V04`, `V06`). The trigger was entirely off-screen at y=-300 to -263, while the 430×330 popup remained visible at its old viewport location. Escape closes it and restores trigger focus (`V07`). Expected: maintain a valid visible anchor, or dismiss when that anchor is clipped, as the existing topology inspector does.

Cause: `showRoutePresentationPreview` moves the card into `document.body` and positions it once (`frontend/assets/topology.js:8408`). Pinned leave/blur events retain it. The captured scroll listener (`:10254`) only repositions the topology inspector; route service previews receive no equivalent anchor visibility check. The card uses fixed positioning (`frontend/assets/topology.css:1427`).

Evidence: `V06-detached-context.png` in [evidence.zip](evidence.zip).

### LV02 — P2: passive re-entry resets service details and steals keyboard focus

1. In EVPN multihoming All paths, pin the service context containing both candidate paths.
2. Scroll the popup down to its second encapsulation fact (observed scrollTop=51).
3. Focus the graph's Zoom in button without activating it.
4. Move the wheel pointer back onto the service label. The audit used a small native horizontal scroll at the label; no click or explicit popup activation occurred.
5. Popup scrollTop becomes 0 and keyboard focus moves from Zoom in to Close service context.

Reproduced twice (`V15`–`V18`). Expected: passive re-entry preserves the pinned panel's reading position and current keyboard focus.

Cause: `showRoutePresentationPreview` preserves the pin flag, but then unconditionally replaces the popup HTML, resets scrollTop, and focuses Close whenever the resulting state is pinned (`frontend/assets/topology.js:8413–8437`). The existing topology inspector distinguishes explicit activation from passive re-entry and preserves scroll (`:6491–6516`).

Evidence: before/after focus and scroll values in [ledger.json](ledger.json); `V17-popup-reentry.png` in the evidence archive.

### LV03 — P2: rapid graph-mode changes discard service activation and focus

1. Trace Packet evolution · nested VPN over VPN.
2. Press Space on Focused path, then All paths, then the service-context trigger in immediate succession.
3. The service popup is absent, focus has fallen to BODY, and the page has scrolled so the trigger is above the viewport.

Reproduced three times in `V23` and again in `V26`. The same sequence with an observation/settling interval after each mode switch opens a pinned dialog and focuses Close correctly (`V24`). A pointer-mode-switch → Enter variant ended with BODY focus and only an unpinned tooltip (`V25`), rather than the requested dialog.

Cause: changing graph mode changes graph dimensions, including a 160 ms height transition. The ResizeObserver schedules another `renderFocusedRouteMap` (`frontend/assets/topology.js:10238–10246`). In All mode this calls `renderAllPathsRouteMap` and `renderRoutePresentations` (`:8807`, `:8718`). That function clears the current service preview and replaces the trigger's HTML (`:8314–8316`). A delayed layout redraw can therefore destroy newly activated popup/focus state. Space scrolling after focus falls to BODY is consistent with the observations; the exact native event ordering was not instrumented.

Expected: a layout-only redraw preserves valid service selection and focus. Repeated redraws during the transition are also a performance investigation candidate, not a separately measured performance defect.

Evidence: `V23`–`V26` in the ledger; `V26-rapid-keyboard-loss.png` in the evidence archive.

## Exercised behavior that held up

| Area | Browser observations |
| --- | --- |
| Lane wheel isolation | Horizontal wheel changed the visible time interval without changing zoom or vertical lane position. Plain vertical wheel moved the lane scroller without changing the time interval. Tested over tracks and labels. |
| Repetition and history | Three left/right cycles alternated exactly between +174–654 s and +240–720 s at zoom 1.5. Back/Forward restored those bounds. |
| Range and navigation commands | Zoom followed by Fit restored +0–720 s. Applying 200–300 s and zooming worked; later pan and Fit preserved the selected range inputs. |
| Cross-node lanes | From the EVPN graph, P1's timeline accepted zoom, horizontal pan and vertical scroll. Its resulting viewport was +197.2–677.2 s at zoom 1.5 with vertical scroll 188. |
| VPN grouping | EVPN forward context retained both Remote VTEP facts (10.254.0.2 and 10.254.0.5). Return context correctly had its own service facts. Service context stayed separate from forwarding nodes. |
| Shared popup replacement | Focusing a P2 path replaced service details with the path preview; selecting it cleared the preview and emphasized P2 while suppressing P1. |
| Direction and mode repetition | Three Forward/Return × Focused/All cycles restored the expected three-node focused routes and cleared old popups. |
| Service transitions | EVPN → ordinary MPLS transport removed the service strip; nested VPN restored it. Graph zoom/Fit kept the strip outside the graph. |
| History recovery | Back and reload restored route configuration. Results required an explicit Trace, which recovered the same route. This is deliberate existing behavior, enforced by `frontend/tests/topology_progressive.test.mjs`, rather than an additional defect. |

## Performance observations

The repeated direction/mode sequence used 1.203125 seconds of server process CPU across a 44.68-second observation window. Sampled private bytes stayed at 3,040,673,792; working set rose by only 4 KiB. These are process samples around the browser sequence, not renderer profiling or an isolated benchmark. They show no sustained server memory growth in this sequence and cannot rule out a short renderer spike.

Opening P1 from Fabric was visibly expensive: the page displayed parsing progress before loading its 1,250,004 events and 7,506 resources. Server CPU increased by 55.375 seconds across the enclosing navigation/readiness observation window; this includes associated requests and is not an isolated parser measurement. Sampled private memory after readiness was 3,023,556,608 bytes. No continuous memory peak was measured.

This cold-node cost matches a documented tradeoff: `demo/README.md:896–906` describes the one-materialized-node LRU, and Fabric's bounded projections do not contain the complete event history needed by a node workspace. Opening a new or evicted node reparses its history. Existing measurements in `docs/navigation-memory-2026-10-20.md` and `docs/route-topology-audit-repairs-2026-10-23/README.md` use different measurement scopes; this audit does not claim a regression by comparing their timings directly. Persistent compact history/reopen optimization remains an opportunity.

## Coverage limits and evidence

- **Ctrl+wheel and Alt+wheel remain unverified as native modified gestures in this browser audit.** The exposed scroll API has no modifier argument, and the available key API cannot retain a modifier across scroll. Horizontal wheel and zoom buttons exercise related behavior but are not substitutes for those exact mappings. Existing unit coverage is not relabeled as manual coverage.
- Mid-drag wheel ownership and sub-frame lane gesture/command races were not exercised. The audit does not claim complete input-device coverage.
- Early scroll attempts hit the existing popup rather than an uncovered lane. Those attempts (`L01`–`L04`) are not counted as successful pan checks; uncovered-track and label controls are recorded separately.
- One long browser-tool batch timed out after recording `L08`; the persisted journal and current Back-view state were recovered. This is not classified as an application stall.
- Both captured console warning/error lists were empty. No synthetic browser events, hidden application-state access, or API warmups were used to replace UI operations.

[ledger.json](ledger.json) records actions and raw observations, including intermediate loading states. [evidence.zip](evidence.zip) contains screenshots, console observations and process samples. [manifest.json](manifest.json) lists archive entries and hashes. Intermediate states are not failures unless the findings above establish reproduction after the relevant state change.

Plug-in documentation drift check completed: this audit changes no author-visible API, runtime behavior, examples or commands, so the maintained authoring documents require no update. `scripts/check_plugin_conformance.py --list` succeeded. No product changes were made and frontend tests were not rerun for this documentation-only audit.

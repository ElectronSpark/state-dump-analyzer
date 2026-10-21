# MN004 — P2: withdrawn history obscures complete active failover

The `evpn-es-withdraw-failover` scenario retains a known withdrawn candidate
beside a complete active failover path. Under **Strict** policy, the UI correctly
shows the active path as **Resolved / Complete · Forwarding Observed**, yet the
direction indicator says **best effort** and the route outcome says **Trace is
incomplete**, claiming missing, unresolved, or inferred node-local evidence.
The aggregate diagnosis mixes retained historical candidates with the active
forwarding result. This is one unique finding across both directions and the
selection/repetition expansions below.

## Browser evidence

The primary auditor performed these interactions on the existing local demo at
`http://127.0.0.1:8883/`, revision `112d346`. This note's author reviewed saved DOM
evidence and source; its separate function probe is described below.

- [M034: Both directions](../../.runtime/audit-600-2026-10-21/multi-node/M034.json),
  visible settled states 1–3: Forward → Return → Forward.
- [M035: repeated Forward only](../../.runtime/audit-600-2026-10-21/multi-node/M035.json),
  visible settled states 1–2.
- [M036: repeated Return only](../../.runtime/audit-600-2026-10-21/multi-node/M036.json),
  visible settled states 1–2.
- [MX005: withdrawn → active selection](../../.runtime/audit-600-2026-10-21/multi-node/MX005.json),
  visible states 0–2, continuing M034's Forward result.
- [MN004 screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN004-active-complete-incomplete-banner.png)
  shows the active Return path through P2, its **Resolved / Complete** evidence,
  the **best effort** direction indicator, and the contradictory incomplete
  banner together.

M034–M036 use Strict policy and restored limits. Each direction has one active
path and a distinct withdrawn candidate. The active Forward route passes
through P2 to PE-E; Return passes through P2 to PE-A. Active selected-path
evidence is **Resolved**, **Complete · Forwarding Observed**, with **No findings
returned**. The retained P1 candidate is explicitly **Dead / dropped: Evpn Es
Withdrawn**. Both direction indicators nevertheless say **best effort**, and
the overall banner says:

> Trace is incomplete
> At least one node-local resolution step is missing, unresolved, or inferred.

MX005 verifies that the selected path and graph actually change. Selecting the
withdrawn PE-B candidate shows **Incomplete · Withdrawn History** and the dead
path. Reselecting active PE-E restores **Complete · Forwarding Observed** and
the correct active graph. The aggregate incomplete banner remains in both
states. The repeated submissions and direction round trip reproduce the same
scope error; this is not evidence of stale path selection.

Hidden state-0 result descendants in M034–M036 are excluded. The separate UI
count of the withdrawn candidate as control-plane only is recorded context,
not an additional finding here. The service endpoint label concern from M031
is also not counted by this note.

## Source diagnosis

The plug-in declares successful failover after withdrawal, with the dead path
retained for inspection
([scenario_registry.py:339–350](../../demo/rsl_demo_plugin/scenario_registry.py)).
The generator explicitly gives `withdrawn_dead` the terminal semantics
`failed`, `withdrawn`, and `evpn_es_withdrawn`
([assembly.py:3177–3181](../../demo/rsl_demo_generator/assembly.py)). This is known
unusable historical evidence, not a declaration that the active failover step
is missing.

The server's trace-level `complete` and `observationally_complete` aggregates
cover **all returned paths**
([multi_node_route.py:6473–6478,6678–6685](../../src/router_dump_analyzer/multi_node_route.py)).
Its endpoint reachability uses a different scope: selected active branches and
their typed terminal evidence
([multi_node_route.py:7476–7527](../../src/router_dump_analyzer/multi_node_route.py)).
The retained candidate remains `ineligible_dead`, with its terminal reason
preserved. An all-candidate coverage value therefore cannot alone establish
that the active endpoint result is uncertain.

The frontend loses that distinction. `traceIsIncomplete()` accepts either the
trace's aggregate partial state or **any** unresolved/inferred path, without
excluding the known withdrawn candidate
([topology.js:4504–4508](../../frontend/assets/topology.js)).
`traceDirectionState()` consequently returns **best effort** even when a usable
active path has resolved. `bidirectionalSummary()` treats that derived state as
incomplete before considering established bidirectional reachability
([topology.js:4569–4575,4707–4715](../../frontend/assets/topology.js)).
`routeTraceOutcome()` uses the same broad completeness test for the banner
([topology.js:4865–4878](../../frontend/assets/topology.js)).

## Separate function probe

The [probe script](../../.runtime/audit-600-2026-10-21/multi-node/failover-completeness-probe.cjs)
extracts the actual production classifiers. Its inputs are synthetic normalized
traces modeled from the source, with one complete selected active path, one
known excluded withdrawn path, and explicit endpoint metadata: one active
branch reached, zero failed or unresolved active branches. It does not run the
normalizer, capture the server's live response, or execute browser actions.

The [saved result](../../.runtime/audit-600-2026-10-21/multi-node/failover-completeness-probe.json)
shows that retaining the withdrawn path produces **best effort**, **Endpoint
validation incomplete**, and **Trace is incomplete**. Removing only that path
produces the reachable result. A further control sets trace-level completeness
to complete while retaining the withdrawn path; the false incomplete result
remains because the frontend also scans every candidate. This establishes that
changing only the server aggregate would not repair the frontend classification.

```powershell
node .runtime/audit-600-2026-10-21/multi-node/failover-completeness-probe.cjs
```

A separate read-only localhost API query was blocked by socket permissions, so
no live API response is claimed. No CPU, RSS, heap, or latency measurement was
performed for this finding.

## Small root-cause repair

Keep retained-candidate coverage separate from active forwarding qualification
in the shared frontend outcome classification. Use the existing typed endpoint
verdict and candidate selection state; a known excluded withdrawn candidate
must not turn an established complete active route into best-effort forwarding.
Preserve the candidate's own incomplete/dead evidence and any genuine
consistency finding. Do not hide history, rewrite its status to complete, or
discard unknown eligible branches to force a reachable result.

Extend [route_outcomes.test.mjs](../../frontend/tests/route_outcomes.test.mjs)
around “a usable active path keeps inactive terminal alternatives branch-local.”
That test currently gives the inactive candidates complete coverage and misses
the real incomplete withdrawn shape. Cover a complete active path with
incomplete withdrawn history, both single and paired directions, while retaining
the existing unknown-selected-branch, partial active reachability, inferred
active-path, and real-drop controls. No new public API is required.

Only this audit note and ignored probe artifacts were added. The plug-in
documentation drift check found no changed author-visible behavior or API.
No product, skill, main findings report, or result ledger was edited.

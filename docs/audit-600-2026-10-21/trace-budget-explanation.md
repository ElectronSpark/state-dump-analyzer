# MN008 — P2: traversal-limit termination is hidden and attributed to missing evidence

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: confirmed in the browser on eight scenarios, in Forward and Return,
covering hop and recursion limits.

When the user lowers **Maximum hops** to 1 or **Maximum recursion** to 0, the
result reports an incomplete trace but explains it as missing, unresolved or
inferred node-local evidence.
The selected-path panel never explains that the requested traversal limit
stopped resolution. The retained resolution steps can still describe the
destination operation, making that generic explanation particularly confusing.

This finding concerns diagnosis and presentation. It does **not** claim that
the backend ignores the budget, that a retained terminal visit is erroneous,
or that destination-operation prose proves actual packet delivery.

## Browser reproductions

The primary auditor operated the browser against the existing local demo. This
report's author inspected the saved observations and source; no additional
browser execution is claimed here.

### M157: router-to-router

[M157.json](../../.runtime/audit-600-2026-10-21/multi-node/M157.json) records:

1. Trace `router-to-router` with **Both** directions, **observed** steering and
   the advertised default limits. The baseline is reachable.
2. Change **Maximum hops** to 1 and trace again.
3. Inspect Forward, then Return. Both report **Trace is incomplete** with
   **Resolution quality** and the explanation: "At least one node-local
   resolution step is missing, unresolved, or inferred."
4. Inspect the complete selected-path content. It retains the A–P1–B outline
   and five supplied resolution steps, including the destination's deliver
   operation, without a hop-limit or budget-stop explanation. The terminal
   hop opens generic node details, not termination evidence.
5. **Restore trace limits** restores the advertised values and invalidates
   the result while preserving unrelated inputs. Explicitly tracing again
   returns the baseline reachable outcome. These restore/retry controls pass.

### M166: recursive static route to an external subnet

[M166.json](../../.runtime/audit-600-2026-10-21/multi-node/M166.json)
records a second scenario, `recursive-static-to-external`, with **Both**
directions and **observed** steering. Its default-limit baseline is reachable.
After setting Maximum hops to 1, the `limited` and `reverse` observations
repeat the same missing-evidence explanation. The full selected-path content
retains all five supplied resolution steps and offers no hop-limit/budget
termination reason. This reproduces the same defect across a different route
type; it is not another unique bug.

The [browser screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN008-hop-limit-explanation.png)
preserves the misleading limited-trace presentation. M166's completed restore
and explicit retrace return the original reachable outcome. All four restore
assertions pass: advertised budgets return, unrelated inputs are preserved,
the old result is invalidated until retry, and retry clears the reminder and
restores the baseline outcome. Both scenarios therefore include a completed
restore/retrace control.

### M170: recursion limit before a recursive-resolution cycle

[M170.json](../../.runtime/audit-600-2026-10-21/multi-node/M170.json) confirms the
same explanation defect for **Maximum recursion**, rather than a hop limit.
The `recursive-resolution-cycle` baseline uses maximum hops 64 and recursion
16 and reports a loop in both directions. Setting recursion to 0 and tracing
again produces an earlier incomplete stop in both Forward and Return. The
later loop classification and its closing visit disappear, as expected for
the earlier stop, but the result again attributes incompleteness to missing,
unresolved or inferred node-local evidence. No visible explanation identifies
the recursion limit.

The limited Forward path shows two PE-A visits and three supplied resolution
steps; Return similarly shows two PE-B visits. Restoring the advertised limits
and explicitly retracing returns the original loop outcome in both directions.
All four restore assertions pass. This extends MN008's browser-confirmed scope
to recursion budgets; the restored baseline is a detected loop, not a reachable
route, and no new unique defect is added.

### M172 and M175: cross-node loop and native IP repetitions

[M172.json](../../.runtime/audit-600-2026-10-21/multi-node/M172.json) repeats the
hop-limit failure on `cross-node-forwarding-loop`. With Both directions and
the default limits, the result reports a loop forward and return. Maximum hops
1 stops the trace before that later loop classification; both limited
directions instead show the generic missing/unresolved/inferred explanation
without identifying the requested hop limit. Restore and explicit retrace
recover the original loop outcome.

[M175.json](../../.runtime/audit-600-2026-10-21/multi-node/M175.json) repeats the
same misleading explanation on `packet-native-ip`, whose default baseline is
reachable. At maximum hops 1, Forward and Return each show a two-transition
packet prefix marked **Continuation Required**, with both transitions labeled
**Continue** and no **Deliver** transition. That packet presentation correctly
avoids claiming delivery; the defect remains the missing hop-limit explanation
in the route outcome. Restoring the defaults and retracing returns the reachable
outcome and the three-transition packet sequence ending in Deliver.

Both cases pass all four restore assertions. These are further reproductions
of MN008, not additional unique bugs or evidence that budget enforcement is
broken.

### M178: nested VPN packet prefix

[M178.json](../../.runtime/audit-600-2026-10-21/multi-node/M178.json) repeats
MN008 on `packet-vpn-over-vpn`, with Both directions, strict policy and observed
steering. The accepted sequence starts from the visible default 64-hop/16-
recursion form and explicitly submits maximum hops 1. Both directions report
the same missing/unresolved/inferred explanation without identifying the hop
limit. Their packet displays correctly retain only two transitions, both
Continue, with **Continuation Required** and no Deliver transition.

Restore and explicit retry recover the reachable baseline and the four-
transition packet sequence ending in removal of the MPLS L3VPN and nested
VXLAN wrappers followed by delivery. All four restore assertions pass. The
earlier ambiguous input/navigation attempt is excluded; the final evidence
records the rerun from the visible form. This is another reproduction of
MN008, with bounded packet-prefix behavior passing.

### M181 and M184: incomparable MTU and observed-steering repetitions

[M181.json](../../.runtime/audit-600-2026-10-21/multi-node/M181.json) repeats
the hop-limit explanation defect on `packet-mtu-incomparable`. At maximum
hops 1, both directions show a two-transition **Continuation Required** prefix
without delivery, but the route outcome again attributes the stop to missing,
unresolved or inferred evidence. The packet transitions retain **MTU BASIS
DIFFERS**, correctly preserving the incomparable size bases without claiming
a known MTU failure. Restoring defaults and retracing returns the reachable
three-transition sequence ending in **DELIVER · MTU BASIS DIFFERS**.

[M184.json](../../.runtime/audit-600-2026-10-21/multi-node/M184.json) reproduces
the same hop-limit result on `packet-forced-steering` while the actual steering
setting remains **observed** throughout. The scenario name is not evidence
that a forced profile was selected. Both directions show a two-transition
Continue prefix and the misleading generic explanation. Restore and explicit
retry recover the reachable four-transition Deliver baseline. Both M181 and
M184 pass all four restore assertions and add reproductions of MN008, not
unique findings.

[M182.json](../../.runtime/audit-600-2026-10-21/multi-node/M182.json) is a passing
control: recursion 0 leaves the nonrecursive incomparable-MTU path reachable
with its explicit size-basis caveat. Its final record supersedes a preliminary
assertion that incorrectly required the chip text to end with `DELIVER`,
ignoring the valid `MTU BASIS DIFFERS` suffix. That assertion error is not a
product defect or an MN008 reproduction.

## Source diagnosis and available controls

The form exposes **Maximum hops**, **Maximum recursion**, and **Restore trace
limits** at [topology.html:376–388](../../frontend/pages/topology.html). Their
IDs are `mn-route-max-hops`, `mn-route-max-recursion`, and
`mn-route-restore-limits`. The help text says a lower limit can be used to
inspect a bounded partial trace. These controls configure another request;
they do not expose why the returned trace stopped.

The frontend retains the relevant path fields but does not present them for
this result class:

- `normalizeRoutePath()` retains `terminal_reason` and spreads the original
  path, including its budget metadata
  ([topology.js:2489–2528](../../frontend/assets/topology.js)).
- `pathStatusSummary()` displays a specific terminal reason for cycles and
  dead/dropped paths, but returns only "Incomplete" for an unresolved path
  ([topology.js:4920–4946](../../frontend/assets/topology.js)). Its terminal-
  result classification list does not include `hop_limit_exceeded` or
  `recursion_limit_exceeded`.
- `routeTraceOutcome()` assigns the missing/unresolved/inferred explanation
  to the generic incomplete result, without a prior budget classification
  ([topology.js:4867](../../frontend/assets/topology.js)).
  `renderRouteOutcome()` labels that result "Resolution quality"
  ([topology.js:5114–5127](../../frontend/assets/topology.js)).
- `routeDiagnosticItems()` adds typed diagnostics for cycles and policy
  decisions, but not resolution budgets
  ([topology.js:4962–4996](../../frontend/assets/topology.js)). The selected-path
  steps and path preview render the supplied steps plus those diagnostics
  ([topology.js:5268–5277](../../frontend/assets/topology.js),
  [topology.js:8371–8385](../../frontend/assets/topology.js)).

There is no output reader for `resolution_budget` in this frontend file.
Findings render returned records; they do not synthesize a budget explanation.
Clicking the terminal hop explicitly invokes `focusNode()`, scrolls the generic
node detail into view and announces that node focus
([topology.js:5293–5301](../../frontend/assets/topology.js)). It is not a hidden
budget-inspection control.

## Retained terminal visits are not evidence of ignored limits

The core traversal evaluator stops when the zero-based hop index exceeds the
configured maximum
([route_trace_core.py:1004–1012](../../src/router_dump_analyzer/route_trace_core.py)).
The path projector retains the prefix through the offending visit, changes
its local segment to `resolution_budget`, sets `operational=budget_exhausted`
and carries the typed terminal outcome and budget kind/limit/observed values
([multi_node_route.py:2731–2779](../../src/router_dump_analyzer/multi_node_route.py)).
For a three-node candidate with hop indices 0, 1 and 2, a maximum of 1 can
therefore leave the third node visible as the attempted terminal visit.

That budget branch preserves the segment's plug-in-authored resolution text.
The refreshed path copies it into the resolution sequence
([multi_node_route.py:9877–9884](../../src/router_dump_analyzer/multi_node_route.py)).
The frontend should identify the typed stop beside this retained prose instead
of implying missing source evidence or deriving delivery from the text.
This source analysis explains the mechanism; it is not a captured-response
assertion of every budget field for these browser runs.

## Repair and validation invariant

Present a traversal-limit result separately from missing evidence, unreachable
forwarding, cycles and policy blocks. Show the budget kind, configured limit,
observed stopping position and terminal reason when supplied. Keep intentional
terminal visits and plug-in resolution prose, with a clear explanation that
the visit was stopped by the requested limit.

Validate Forward and Return with low and default hop and recursion budgets,
including these eight scenarios, and retain the passing restore/retrace
behavior. M170 now supplies browser evidence for the recursion-limit case as
well as the hop-limit cases above.

No product code or skills changed, and no frontend or backend tests were run
for this diagnosis. Documentation drift check: this report records existing
behavior and changes no public plug-in boundary, so no maintained authoring
update or conformance run was required.

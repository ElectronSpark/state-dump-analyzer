# Multi-node route-trace findings

Source reviewed: `112d346`. Browser execution was performed by the primary
auditor on the existing `http://127.0.0.1:8883/` demo. The source-review agent
read the saved evidence and implementation; its function probes are separate
from browser execution. This note records two findings and one uncounted metadata
concern. It does not modify the main findings ledger or claim completion of the
300-case multi-node plan.

## MN001 — P3: cross-node handoff mismatch labeled “Layer disagreement”

**Evidence:** [M007: both directions](../../.runtime/audit-600-2026-10-21/multi-node/M007.json)
and [M008: repeated forward-only trace](../../.runtime/audit-600-2026-10-21/multi-node/M008.json).
Use settled M007 states 1–3 and M008 states 1–2 (zero-based). State 0 in each
file has hidden result content and is not evidence of a current visible result.

Reproduction:

1. Select **Cross-node MPLS label handoff mismatch**, **Both directions**, and
   **Strict** missing-hop policy with restored trace limits. Submit and wait.
2. Inspect Forward, switch to Return, then return to Forward.
3. Select **Forward only**, submit, and repeat the same submission.

The forward finding correctly compares PE-A's outgoing label `16011` with P1's
expected incoming label `16012`, retaining each node's resource and revision
provenance. However, **Selected-path evidence**, the candidate-path status, and
the focused graph note all say **“Layer disagreement.”** This falsely narrows
the discrepancy to different layers, although the declared check compares two
nodes' handoff observations. The actual badge says **“Inconsistent”**; it is not
the incorrect layer-specific wording.

The underlying result remains appropriately separated from delivery. In M007,
the UI says both traffic endpoints are reachable while showing the forward
consistency finding. Return shows **Resolved**, **No findings returned**, and
the correct PE-B → P1 → PE-A path. Switching back restores the forward finding.
M008 reproduces the wording on both settled submissions, with the opposite
direction disabled; it does not establish a return result for that single-
direction request. The finding explicitly describes evidence inconsistency,
not packet-continuity failure or an inferred drop.

**Cause:** `pathStatusSummary()` returns the literal “Layer disagreement” for
every `pathIsInconsistent(path)` result
([topology.js:4939](../../frontend/assets/topology.js)). That summary is reused
by selected-path evidence, path tabs, and graph notes. The plug-in emits
`category: boundary`, `finding_type: mpls_label_handoff`, and
`semantic_owner: plugin`
([cross_node_consistency.py:108–117](../../demo/rsl_demo_plugin/cross_node_consistency.py)).
The [scenario declaration](../../demo/rsl_demo_plugin/scenario_registry.py)
explicitly distinguishes this case from a control/FIB comparison. The
[API contract](../api-contract.md), around line 3906, specifies that explicit
`affects_consistency: true` affects the verdict independently of category and
does not prove a reachable path drops traffic.

**Small correction to consider:** use a neutral generic status such as
“Inconsistent evidence,” leaving the specific cause in the finding. No new
API or protocol/category inference is needed. This issue is distinct from the
[focused graph query-scope warning investigation](graph-scope-investigation.md).

**Related expansion completed:**
[M010: VXLAN both directions](../../.runtime/audit-600-2026-10-21/multi-node/M010.json)
and [M011: repeated VXLAN forward-only](../../.runtime/audit-600-2026-10-21/multi-node/M011.json)
reproduce the same layer-specific wording for a cross-node VNI handoff finding.
M010's settled forward states retain the specific VNI finding while stating
that both endpoints are reachable; its return state is **Resolved** with
**No findings returned**. The repeated
[M012 return-only trace](../../.runtime/audit-600-2026-10-21/multi-node/M012.json)
also resolves without inheriting the forward finding. These are additional
reproductions of MN001, not separate bugs.

The genuine control/forwarding mismatch provides a contrasting control:
[M013 both directions](../../.runtime/audit-600-2026-10-21/multi-node/M013.json),
[M014 repeated forward-only](../../.runtime/audit-600-2026-10-21/multi-node/M014.json),
and [M015 repeated return-only](../../.runtime/audit-600-2026-10-21/multi-node/M015.json)
retain an active observed path through P1 and a separate control-only candidate
through P2. Here **“Layer disagreement”** is compatible with the declared cause.
M013 states that both endpoints remain reachable; each single-direction case
retains its corresponding observed path and explicit inconsistency. The
control-only candidate is correctly labeled **“Control-plane only — not
installed.”** These controls did not add another finding.

Only settled visible results were used: states 1–3 of M010/M013 and states 1–2
of M011/M012/M014/M015. Hidden state-0 descendants were excluded. No CPU or
memory measurement was performed for this wording finding.

## MN002 — P2: missing resolution is reported as evidence disagreement

**Browser evidence:** [M016 both directions](../../.runtime/audit-600-2026-10-21/multi-node/M016.json),
[M017 repeated forward-only](../../.runtime/audit-600-2026-10-21/multi-node/M017.json),
and [M018 repeated return-only](../../.runtime/audit-600-2026-10-21/multi-node/M018.json).
Use visible settled states 1–3 of M016 and states 1–2 of M017/M018; their hidden
state-0 descendants describe previous results and are excluded.

Reproduction:

1. Select **Incomplete node-local resolution**, **Strict** missing-hop policy,
   and **Both directions**, restore the trace limits, and submit.
2. Inspect Forward, Return, then Forward again. Repeat with **Forward only** and
   **Return only**.
3. For Return only, submit with **Best effort**, then restore **Strict** and
   submit again.

The strict results correctly show an unresolved path, **Selected-path evidence:
Incomplete**, and **No findings returned**. However, the route outcome claims
**“Incomplete and inconsistent”** and **“Evidence is missing and the available
nodes or status layers also disagree.”** The fixture declares missing local
resolution, not a disagreement. This is a false additional diagnostic verdict,
not merely the narrower wording issue in MN001.

The [MX002 policy expansion](../../.runtime/audit-600-2026-10-21/multi-node/MX002.json)
reproduces the false disagreement for **Best effort**: its settled state 1 has
one active path, **Best-effort continuation**, and no findings, but retains the
same overall inconsistency claim. State 2 restores the strict unresolved path
and retains the false claim. The recovery controls
[M019 both directions](../../.runtime/audit-600-2026-10-21/multi-node/M019.json),
[M020 forward-only](../../.runtime/audit-600-2026-10-21/multi-node/M020.json), and
[M021 return-only](../../.runtime/audit-600-2026-10-21/multi-node/M021.json)
show **Route is reachable**, resolved paths, and no findings for the clean
router-to-router scenario. This recovery and the function probe below support
a deterministic classification error rather than a previous result leaking
into the current scenario.

**Source cause:** the server assigns `consistency.state: incomplete` or
`best_effort_with_gap` for the generated incomplete case, then computes the
compatibility Boolean as `consistency_state.startswith("consistent")`
([multi_node_route.py:6345–6349,6656–6658](../../src/router_dump_analyzer/multi_node_route.py)).
Consequently, `consistent: false` means that this result is not established as
consistent; it is also false for the explicitly incomplete states. The client
preserves the richer state string but unconditionally derives
`inconsistent: !traceConsistent` when that Boolean is available
([topology.js:2568–2594](../../frontend/assets/topology.js)). The actual outcome
renderer then treats this derived flag as positive disagreement evidence
([topology.js:4865–4871](../../frontend/assets/topology.js)).

**Separate function evidence:** the audit-only
[probe script](../../.runtime/audit-600-2026-10-21/multi-node/incomplete-consistency-probe.cjs)
extracts the production normalizer and outcome helpers and runs minimal
synthetic core-shaped traces with empty paths/findings. Its
[saved result](../../.runtime/audit-600-2026-10-21/multi-node/incomplete-consistency-probe.json)
reproduces `incomplete_inconsistent` for both incomplete state strings when
`consistent: false` is supplied. Omitting only that Boolean produces
`incomplete`. An explicitly `inconsistent` state retains the disagreement
verdict with or without the Boolean, so the issue is not inferred merely from
the absence of findings. This probe does not capture a server response or
execute the browser, and its empty paths do not model the full best-effort path.

Run the probe from the repository root:

```powershell
node .runtime/audit-600-2026-10-21/multi-node/incomplete-consistency-probe.cjs
```

**Small correction to consider:** preserve the distinction between an explicit
disagreement and incomplete/inferred consistency evidence when normalizing the
rich server state. A false compatibility Boolean must not override the
explicit incomplete state into positive disagreement. Retain genuine
inconsistent states and path-scoped consistency findings. Extend
[route_outcomes.test.mjs](../../frontend/tests/route_outcomes.test.mjs) through
the real normalizer with the core's nested `consistency` object; its current
unresolved fixtures start with normalized `consistency: consistent`, which
does not exercise this boundary. Include Strict, Best effort, an explicit
disagreement control, and clean recovery. No CPU or memory measurement was
performed for this finding.

## Metadata concern — malformed legacy hop IDs; not a counted functional bug

The primary auditor observed hop metadata such as
`transit-p-1@demo/node-a/revision-0001` in `data-route-id` and legacy member
tokens, while `data-route-hop-node` held the correct canonical P1 identity.
These are synthesized fallback member IDs, not the separate path-occurrence IDs.

Source analysis found that `normalizedRouteOccurrences()` finds a fallback node,
but `refIdentity()` ignores that fallback for object-shaped references; missing
revision/member fields therefore fall through to the bootstrap revision
([topology.js:326,568–585,1952–1959](../../frontend/assets/topology.js)). A probe
using the actual functions and a synthetic core-shaped occurrence reproduced
the malformed ref. The same probe resolved the canonical node successfully and
showed that the focus handler preferred canonical exact focus targets over the
legacy tokens. This is source/function evidence, not a live hover test.

[MX001 browser evidence](../../.runtime/audit-600-2026-10-21/multi-node/MX001.json)
records **P1 forward → PE-B forward → P1 return** hop clicks. Each selected-device
panel and generated Open link retained the correct member and revision:

- P1: `member:transit-p-1`, `demo/transit-p-1/revision-0001`.
- PE-B: `member:node-b`, `demo/node-b/revision-0001`.

No user-visible navigation failure was demonstrated. MX001 checks hop selection
and link destinations, not completion of navigation through those links or
exhaustive hover behavior. Keep the malformed metadata as an uncounted concern
unless a separate functional failure is reproduced.

Only this audit document changed. The plug-in documentation drift check found
no author-visible behavior or API change requiring maintained authoring updates.

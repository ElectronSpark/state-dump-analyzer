# MN012 — P2: a transit row rejects equivalent start descriptors as conflicting

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in M202 and repeated in MX014/M204, with an
equivalent manual-input control and a successful main Return-row control in
M203.

The enabled P1-owned route-table row for `transit-start-endpoint-reachability`
correctly seeds observation start P1, traffic source A and destination B.
Explicit submission nevertheless fails with **trace start selectors for the
requested direction disagree**. Re-entering the same destination clears the
row association without changing any of the twelve recorded form values;
the equivalent manual Forward trace then succeeds from P1 to B while retaining
the original A-to-B flow.

This is distinct from [MN009](route-table-seed-identity.md): that defect loses a
logical destination's ID/value distinction. Here the visible endpoint and
start identities are correct. The row reference causes two representations
of the same P1 start to be compared as whole dictionaries before their
identities are resolved.

## Browser evidence

The primary auditor performed the browser actions. This report's author
reviewed the latest saved records, the screenshot and source; no additional
browser execution, request-body capture or frontend test execution is claimed.

### M202: correct P1 seed, rejected trace, correct source navigation

The latest [M202.json](../../.runtime/audit-600-2026-10-21/multi-node/M202.json),
recorded at `2026-10-21T12:22:48.381Z`, supersedes the earlier source-navigation
assertion that used the wrong expected owner.

1. Trace `transit-start-endpoint-reachability` using Both directions, Strict,
   observed steering and default limits 64 / 16. The visible result succeeds.
   Its Forward directional goal is P1 → B, its original flow is A → B, and
   the comparison explains that Return need not revisit the observation node.
2. Find the actual enabled Forward row
   `transit-p-1/route/transit-start-endpoint-reachability`. Its owner is P1,
   not source A. Inspect **Plug-in details**: the query declares
   `starting_point: {node_id: "transit-p-1"}`, source
   `{node_id: "node-a"}`, destination `{node_id: "node-b"}` and Forward
   Default / `ipv4_unicast` context.
3. Click **Use in trace**. The form correctly shows **P1 / Gamma routing
   daemon**, `node-a`, `node-b` and **Forward only**. The seed association
   identifies the exact P1 row, and the old result is invalidated.
4. Explicitly trace. The error is
   `trace start selectors for the requested direction disagree`, the current
   result remains hidden and the button is enabled for retry.
5. **Show source row** correctly selects P1, opens its group and finds the
   exact original row still `is-pending-trace`. This navigation control passes.

The old successful summary and hopline remain in hidden DOM after failure.
They are not a result for the rejected seed. Initial closed-group and
horizontal-table-scroll setup issues were recovered before the actual action;
they are not additional findings.

### MX014: same visible parameters succeed after clearing the row association

The latest [MX014.json](../../.runtime/audit-600-2026-10-21/multi-node/MX014.json),
recorded at `2026-10-21T12:24:14.37Z`, starts from another successful Both
baseline, reseeds the exact P1 Forward row and reproduces the same rejection.

The auditor then re-enters the identical `node-b` destination. The normal input
handler clears the seed notice. Comparing `seed` and `manualDraft` shows all
twelve recorded form values are unchanged: scenario, start, source,
destination, VRF, direction, family, type, policy, steering and both limits.
The mode remains Forward in both observations.

Submitting this manual equivalent succeeds with no error and a visible
resolved result. `manualHopline` is P1 → B; the directional goal is P1 → B
while the flow remains A → B. The seed stays cleared after completion.
The final record's hopline comparison ignores rendered line breaks; an earlier
string-format assertion is not a separate functional defect.

The [conflict screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN012-transit-row-start-conflict.png)
shows the correct P1/A/B fields, Forward mode, exact conflict error, P1 seed
notice, enabled retry and empty current-result panel together. The manual
control establishes that the requested observation point and flow are
executable; it does not repair the row-driven workflow or retain its source-row
association.

### M203: the main Return row executes without revisiting P1

[M203.json](../../.runtime/audit-600-2026-10-21/multi-node/M203.json), recorded at
`2026-10-21T12:25:04.436Z`, starts from a fresh successful Both baseline and
uses the inspected node-B main Return row,
`node-b/route/transit-start-endpoint-reachability`. Its original source A and
destination B remain unchanged in the form while direction becomes Return.
Explicit submission succeeds with no error, a visible B → P2 → A hopline and
the exact Return row marked `is-focused-trace`. Omitting P1 is correct for this
scenario's endpoint-based Return goal.

This passes the MN012 execution control. M203's overall finding status records
the separate [MN010 start-control presentation defect](route-table-start-state.md);
it does not mean that this Return seed suffered the selector conflict.

[M204.json](../../.runtime/audit-600-2026-10-21/multi-node/M204.json), recorded at
`2026-10-21T12:25:50.833Z`, repeats the P1 Forward rejection after zero-match
search and filter recovery. The empty state and restoration of the exact row
pass. Explicit tracing still returns the same selector-conflict error, with
the result hidden; source-row navigation correctly returns to the pending P1
row. This is another reproduction of MN012, not a filter or navigation defect.

## Source cause

- [useRouteTableEntry](../../frontend/assets/topology.js), lines 9567–9571,
  reads the row's `starting_point`. The start helpers at lines 2887–2924 map
  its node identity to the advertised P1 start point. The seed retains the
  route-row reference at lines 9597–9598.
- `buildRouteTraceRequest` at lines 3083–3087 uses the full advertised start
  object for both `ingress` and `trace_starts.forward`. These two frontend
  descriptors agree with each other. Lines 3100–3103 also include the selected
  row reference and route-table context.
- When a row is referenced, [multi_node_route.py](../../src/router_dump_analyzer/multi_node_route.py),
  lines 5984–6008, fills omitted selector fields from its declared query using
  `setdefault`. Because the frontend did not send a `starting_point` field,
  this adds the row's minimal `{node_id: "transit-p-1"}` descriptor alongside
  the full advertised P1 aliases.
- `_resolve_trace_start` at lines 7977–7986 collects all three aliases. At
  lines 8003–8010 it serializes each entire dictionary and requires the JSON
  strings to match. The full advertised object and the minimal node-only
  object differ structurally, producing the exact observed error.
- Actual node/start/member/resource identity resolution occurs afterward,
  beginning at lines 8051–8072. It never gets the opportunity to establish that
  the supplied descriptors identify the same P1 observation point.

The generator intentionally declares the minimal node-based start in
[assembly.py](../../demo/rsl_demo_generator/assembly.py), lines 4465–4469.
The declared scenario separately identifies source A, destination B and start
P1 in [scenario_registry.py](../../demo/rsl_demo_plugin/scenario_registry.py),
lines 244–259. This separation is meaningful; changing the flow source to P1
would not be an equivalent correction.

The frontend input/change handlers at topology.js lines 9940–9949 clear the
row reference even when the resulting displayed text is unchanged. Without
that reference, the row's third, minimal alias is no longer merged. This
explains the successful identical-form control. These request-construction
details are source analysis, not assertions from captured network bodies.
The Return branch of `_resolve_trace_start` at lines 7977–7988 reads only its
directional start and optional `reverse_ingress`, so it does not combine the
Forward-only aliases that conflict in M202/MX014. This is consistent with the
successful M203 control.

## Repair invariant and limits

Resolve compatible start descriptors to canonical identity before deciding
that multiple aliases disagree. Equivalent node/start/member representations
must not conflict solely because one carries additional advertised metadata.
Preserve checks for genuinely different nodes or more specific attachment
selectors, the distinction between observation start and traffic source, and
the route-row association. Dropping all validation or changing source A to P1
would not satisfy that invariant.

The confirmed failure scope is the P1 Forward row. The manual-equivalence
and main Return-row controls pass. Broader descriptor
combinations are source-level implications, not
independently executed cases. No race, memory, CPU or latency conclusion is
drawn from this rejection.

Only this report was changed for this reporting task. No product code, skill,
aggregate count or execution ledger was edited. Documentation drift check
found no author-visible behavior change from recording this existing defect;
maintained plug-in authoring materials did not require an update.

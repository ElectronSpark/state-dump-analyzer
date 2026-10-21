# MN009 — P2: a traceable route-table row loses its logical endpoint identity

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: confirmed in the browser for the main Forward rows of
`single-active-primary` and `all-active-ecmp`, with a repeated failure and
successful candidate-row, Return-row and prefix controls.

**Use in trace** loads a valid logical destination identifier from an enabled
route-table row, but the subsequent **Trace route** request rejects that same
identifier as an unknown destination value. The working scenario baseline
does not make this row-driven workflow executable.

This is separate from [MN005's endpoint-label loss](multi-node-endpoint-labels.md).
MN005 retains a successful trace but labels a subnet as its attachment router.
MN009 prevents the seeded trace from producing a result. Both involve logical
endpoints absent from the generated router-only capability list, but fail at
different stages and have different user-visible effects.

## Browser evidence

The primary auditor performed the browser interactions. This report's author
reviewed the saved DOM observations and source; no additional browser execution
or frontend test execution is claimed here.

[M187.json](../../.runtime/audit-600-2026-10-21/multi-node/M187.json), recorded at
`2026-10-21T11:47:41.64Z`, contains the baseline, exact row details, seeded form,
settled error and source-row return. The
[screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN009-route-table-seed-rejected.png)
shows the seeded form; the error lies below its viewport. The final DOM record,
not this screenshot alone, establishes the rejected request.

1. Reconstruct the existing ten-node demo and trace `single-active-primary`
   with **Both directions**, **Strict**, **observed** steering and default
   limits of 64 hops / 16 recursion. The visible baseline is reachable, with
   two candidates in each direction and no error.
2. Open **Route tables**, clear filters, search `single-active-primary`, then
   select node A, VRF `default`, family `mpls_labeled_unicast` and type
   `mpls_transport`. Both the active main row and its standby candidate are
   retained by these combined filters.
3. Inspect the enabled main row `node-a/route/single-active-primary`. Its
   **Plug-in details** supplies this destination in `trace_query`:

   ```json
   {
     "destination_id": "destination:blue-service-prefix",
     "endpoint_id": "endpoint:blue-service-prefix",
     "node_id": "node-b",
     "value": "203.0.113.0/24"
   }
   ```

4. Click **Use in trace**. The form now has source `node-a`, destination
   `destination:blue-service-prefix`, **Forward only**, and the row's routing
   context. The old result is hidden, the seed notice identifies the original
   main row, and that row is `is-pending-trace` with **loaded into trace**.
   Seeding correctly waits for an explicit submission.
5. Click **Trace route**. The settled visible error is
   `unknown destination value: destination:blue-service-prefix`. The result
   remains hidden and the submit button is enabled for another attempt. The
   row remains pending rather than becoming a correlated used row.
6. **Show source row** successfully clears the search and context filters,
   selects node A, opens that group and reveals the exact original row. This
   navigation control passes; it does not repair the rejected endpoint.

The saved form contains text from the old successful result inside hidden DOM.
That text is not a result for the failed seeded request. Horizontal table
scrolling exposed the partly occluded details column during the audit; this
was recovered and is not classified as an additional finding.

### MX011: successful candidate, repeated failure and prefix recovery

[MX011.json](../../.runtime/audit-600-2026-10-21/multi-node/MX011.json), recorded
at `2026-10-21T11:52:14.408Z`, repeats the failure between two successful controls:

1. From the failed main-row seed, use the same scenario's retained candidate
   `node-a/route/candidate/single-active-primary/1`. It seeds destination
   `node-b` and **Forward only**. Explicit submission succeeds with a visible
   reachable result, no error and **Available alternative** selected-path
   evidence. The exact candidate row becomes `is-focused-trace`; the main row
   does not retain a pending or focused class. Focusing this standby remains
   distinct from making it an active path.
2. Reseed the main Forward row and submit again. The same
   `unknown destination value: destination:blue-service-prefix` error returns,
   with the result hidden and the submit button enabled.
3. Replace the destination with the row's advertised value,
   `203.0.113.0/24`, then submit. The settled result is visible and reachable,
   without an error, and selected-path evidence is **Resolved**. Editing the
   endpoint correctly clears the seed notice.

The prefix control demonstrates an executable manual recovery. It does not
make **Use in trace** correct: the user must replace the rejected identifier,
and that edit also retires the route-table seed association.

### M188: the node-only main Return row executes

[M188.json](../../.runtime/audit-600-2026-10-21/multi-node/M188.json), recorded at
`2026-10-21T11:53:50.722Z`, provides a second row-driven passing control. After a
fresh successful Both-direction baseline, the auditor inspected the actual
main Return row `node-b/route/single-active-primary`, filtered its observed
protocol and prefix, then used it in the trace form.

Its displayed query declares source `{node_id: "node-a"}`, destination
`{node_id: "node-b"}` and direction `reverse`. Seeding preserves the original
flow endpoints as `node-a` / `node-b` and selects **Return only**; it does not
swap the inputs. Explicit submission succeeds with the Return path
B → P1 → A, no error, visible resolved evidence and the exact main Return row
marked `is-focused-trace`. **Show source row** also succeeds.

This control passes the MN009 endpoint-serialization checks. M188 separately
records a stale enabled/used start field after Return seeding, tracked as
MN010; its overall `finding` status must not be read as failure to execute
this Return route.

### M190: the same rejection on an ECMP main row

[M190.json](../../.runtime/audit-600-2026-10-21/multi-node/M190.json), recorded at
`2026-10-21T11:57:35.541Z`, repeats MN009 on `all-active-ecmp`. Its successful
Both-direction baseline has two active Forward candidates and no alternatives.
The auditor filters the exact scenario, node A and its Default/MPLS context,
then uses the active main row `node-a/route/all-active-ecmp`.

That row declares the same Blue service destination ID, endpoint ID, node B
and `203.0.113.0/24` value. The seed changes the form to Forward with the
literal destination identifier. Explicit submission produces the same unknown
destination-value error, hides the result and leaves retry enabled. Returning
to the source shows the exact ECMP row still `is-pending-trace` and exposes its
declared query. This is another scenario exhibiting MN009, not a separate
unique finding.

[M192.json](../../.runtime/audit-600-2026-10-21/multi-node/M192.json), recorded at
`2026-10-21T11:59:20.646Z`, repeats the ECMP failure after an explicit zero-match
search and filter recovery. The table correctly restores the exact main row,
but seeding and submitting it again produces the same endpoint error.
The [ECMP error screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN009-ecmp-seed-error-visible.png)
shows this retained final state with the literal destination ID, exact error,
seed notice and empty result together. Advanced options were collapsed only
to frame the evidence; this screenshot is not an additional executed case.

## Expected invariant

An enabled traceable row's declared source and destination descriptors must
survive **Use in trace → Trace route** with their identity and meaning intact.
The frontend must preserve a logical endpoint even when it is not one of the
router choices in the input's capability list. A canonical destination ID
must not silently become an arbitrary destination value. Replacing the
logical endpoint with its attachment router would also lose the row's
semantics and is not an equivalent repair.

## Source diagnosis

The following is source analysis of the browser-observed failure, not a claim
that the audit captured the network request body.

- [routeEndpointSeedValue](../../frontend/assets/view_models.js), lines
  378–391, reduces an endpoint object to one string, preferring
  `destination_id` over `endpoint_id`, `node_id` and `value`.
  [useRouteTableEntry](../../frontend/assets/topology.js), lines 9557–9589,
  passes that string to the destination input and retains no copy of the
  endpoint descriptor for request construction.
- The generated capability endpoint builder,
  [_generated_route_endpoints](../../src/router_dump_analyzer/multi_node_route.py),
  lines 4484–4542, advertises router-based destination choices. Its destination
  list at lines 4530–4541 does not include the logical Blue service endpoint.
- `routeEndpointMatch` in `topology.js`, lines 2803–2813, can recover a
  canonical endpoint only from that capability list. With this unmatched ID,
  `setRouteEndpointInput` at lines 2839–2850 keeps the literal string and
  clears the canonical endpoint dataset. `selectedRouteEndpoint` at lines
  2864–2869 consequently has no endpoint object to return.
- `buildRouteTraceRequest` at lines 3064–3072 constructs both `destination`
  and `flow.destination` from that missing capability or the fallback
  `{kind: "plugin_owned", value: <input text>}`. The extra `destination_id`
  assignment at line 3089 also depends on a matched capability. The canonical
  string is therefore reclassified as a value rather than retained as an ID.
- `_resolve_endpoints` in `multi_node_route.py` has distinct ID and value
  handling. Lines 8309–8313 map declared logical destination IDs to their
  router. The value resolver at lines 8327–8355 instead accepts node IDs,
  labels, prefixes and declared destination values. Lines 8418–8427 send the
  malformed value into that resolver, producing the exact observed error;
  destination-ID resolution at lines 8436–8499 cannot restore the discarded
  descriptor.

The plug-in declares `destination:blue-service-prefix` and
`endpoint:blue-service-prefix` as destination IDs, while `203.0.113.0/24`,
`203.0.113.0` and `blue service` are destination values. See
[scenario_registry.py](../../demo/rsl_demo_plugin/scenario_registry.py), lines
31–39, and the Blue service profile in
[route_policy.py](../../demo/rsl_demo_plugin/route_policy.py), lines 185–191.
This distinction explains why the row's ID is valid in its original field
and rejected after the frontend changes its role.

## Related paths and remaining source predictions

Source inspection explains the candidate control and identifies additional
unconfirmed scope:

- `_apply_scenario_destination_identity` in
  [assembly.py](../../demo/rsl_demo_generator/assembly.py), lines 3332–3382,
  enriches only Forward destinations. Its main-row call at lines 4332–4338
  explains the full logical descriptor in M187.
- Retained-candidate rows use node-only endpoints from `_route_trace_query`
  at lines 3865–3875, and main Return rows skip Forward-only enrichment.
  MX011 confirms that the selected retained candidate executes successfully
  while the main Forward row fails; M188 confirms successful main Return-row
  execution with its node-only endpoint descriptors.
- M190 confirms the Blue service failure on `all-active-ecmp`. The main Forward
  row of `cross-layer-inconsistent` also declares the Blue service role, and
  `recursive-static-to-external` declares an external-subnet role. Those two
  remain unconfirmed candidates for the same serialization failure. The two
  cross-node mismatch scenarios retain the default router endpoint role and
  provide different control cases.

No product code, skill, aggregate finding count or execution ledger was changed
for this report. The plug-in-documentation drift check found no author-visible
behavior change from recording the existing defect; maintained authoring
materials did not require an update. No CPU, memory or latency regression is
inferred from this failed request.

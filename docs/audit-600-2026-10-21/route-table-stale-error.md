# MN011 — P3: replacing trace inputs or reconstruction scope leaves an obsolete error

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed twice in MX013, with candidate and Return replacements,
and extended to successful reconstruction recovery in M215.

After a failed main-row trace, **Use in trace** replaces the form parameters
and source-row association but leaves the old error immediately beneath the
new form. Nothing identifies that alert as belonging to the previous request.
In both recorded replacements, the current destination is `node-b` while the
alert rejects the previous `destination:blue-service-prefix` identifier.
Explicitly submitting the replacement trace clears the alert and returns a
valid result.

M215 extends the same attribution defect to the applied device scope: after
PE-A is restored and a ten-device reconstruction succeeds, the trace form still
says PE-A is outside the reconstructed device set. Explicit trace retry clears
the obsolete alert and succeeds in both directions.

This is a presentation and request-attribution defect. It does not prevent
submission, demonstrate that either replacement request failed, or establish
incorrect forwarding. It is separate from [MN009](route-table-seed-identity.md),
which causes the original main-row rejection by converting a logical
destination ID into a value. MN011 concerns the stale alert after that failed
input has been replaced.

## Browser reproductions

The primary auditor operated the browser. This report's author reviewed the
final [MX013.json](../../.runtime/audit-600-2026-10-21/multi-node/MX013.json),
recorded at `2026-10-21T12:16:24.755Z`, the M215 evidence below, all three
screenshots and the current source.
No additional browser execution or frontend test execution is claimed here.

### Replace the failed main row with a control candidate

1. Start from the `cross-layer-inconsistent` main Forward row's failed trace:
   `unknown destination value: destination:blue-service-prefix`.
2. Inspect **Plug-in details** for the enabled retained candidate
   `node-a/route/candidate/cross-layer-inconsistent/1`. Its query declares
   source `{node_id: "node-a"}`, destination `{node_id: "node-b"}`, direction
   `forward` and blue / `l2vpn_evpn` / `evpn_service` context. It is a
   non-selected, not-installed control-plane candidate.
3. Click that row's **Use in trace**, then inspect the form before submitting.
   The form now displays source `node-a`, destination `node-b` and **Forward
   only**. The exact candidate row is `is-pending-trace`, the new seed notice
   is visible, the prior result is hidden and **Trace route** is enabled.
   The old service-ID error remains visible unchanged.
4. Explicitly click **Trace route**. The error clears and the result becomes
   visible. Selected-path evidence correctly says **Control-plane only — not
   installed**, with **Complete · Control Expected**. The exact candidate row
   becomes `is-focused-trace`.

The [candidate replacement screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN011-old-error-after-candidate-seed.png)
shows the new `node-b` destination, Forward mode, enabled submit button, seed
notice and old service-ID alert together. The exact candidate identity comes
from the saved row and query observations; the seed notice alone does not
distinguish every candidate sharing that node and prefix.

### Repeat with the main Return row

1. Reseed the failing main Forward row and explicitly trace again. The same
   service-ID error returns, with no visible current result.
2. Inspect and use `node-b/route/cross-layer-inconsistent`. Its query preserves
   original source A and destination B, with direction `reverse` and the same
   blue EVPN context.
3. Before submitting, the form displays `node-a` / `node-b` and **Return only**.
   The new node-B seed notice is visible and the exact Return row is pending,
   but the old service-ID error still remains beneath the replacement form.
4. Explicitly trace. The error clears, a visible Return result is produced and
   the exact Return row becomes focused. The result retains the scenario's
   expected control/forwarding disagreement; successful request execution does
   not mean the deliberately inconsistent scenario became healthy.

The [Return replacement screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN011-old-error-after-return-seed.png)
shows the new destination and Return mode, node-B seed notice and retained
old alert together. `candidateSeed` and `returnSeed` in MX013 are the states
before the corresponding explicit submission; `candidateAfter` and
`returnAfter` establish successful execution and error clearing.

### M215: restore the excluded source and reconstruct successfully

[M215.json](../../.runtime/audit-600-2026-10-21/multi-node/M215.json), finalized
at `2026-10-21T13:07:03.977Z`, starts from the successful
`single-active-primary` Both-directions trace at relative offset zero, Strict,
observed steering and the default 64 / 16 limits, with all ten devices applied.

1. Uncheck the actual PE-A device, `node-a`, and reconstruct. The settled result
   has nine devices, an applied capture context different from the baseline and
   no visible old trace result.
2. Explicitly trace. The form correctly reports **The endpoint PE-A / Alpha NOS
   is outside the reconstructed device set. Select its device and reconstruct
   before tracing.** This is a valid rejection in the nine-device context.
3. Recheck PE-A and reconstruct. `restoredApplied` records all ten devices
   checked, ten applied nodes, no reconstruction error, enabled controls and
   **APPLIED** relative zero. The topology context ID and route-table context
   return to the original baseline; the table again reports ten node tables.
4. Before retrying the trace, that same excluded-source error remains visible.
   `beforeRetry` confirms the trace result is hidden and **Trace route** is
   enabled. The successful reconstruction has not retired the obsolete alert.
5. Explicit trace retry clears the error and produces the visible reachable
   result. Forward primary is A → P1 → B and Return primary is B → P1 → A;
   both list the P2 standby as an available alternative.

The [restored-source screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN011-restored-source-stale-error.png)
shows PE-A in the current source field, Both directions, enabled Trace route,
the excluded-source alert and the restored ten-node route-table summary together.
The complete reconstruction/context comparison comes from the saved DOM states,
not the screenshot alone. Hidden text from the earlier trace is not treated as
a current successful result; success is established only by `retry` and
`directions`. This is one additional scope for MN011, not a new unique finding
or a failed reconstruction/forwarding result.

## Source cause and expected invariant

In [topology.html](../../frontend/pages/topology.html), lines 391–394,
`#mn-route-error` is an unlabeled `<p role="alert">` immediately after the
current form and before the seed notice. There is no previous-request label,
request identity, timestamp or historical-input description attached to it.

[useRouteTableEntry](../../frontend/assets/topology.js), lines 9554–9602,
replaces the endpoint, context and direction controls, assigns the new row
reference, invalidates the old trace and says **Route parameters loaded.
Review them, then trace the route.** Its `invalidateRouteTraceResult` helper
at lines 9605–9618 clears the old bundle, directions, path selections and
associated visual state, but does not clear or relabel `#mn-route-error`.

`runRouteTrace`, lines 9732–9739, clears the alert only after the next request
passes local construction; it replaces the alert for a new construction
failure or backend failure at lines 9738 and 9785. **Restore trace limits**
separately clears it at line 1237. This explains why replacing a seed leaves
the old message visible until the user explicitly submits the new request.

M215 reaches the same stale-alert outcome through `runQuery`, rather than the
route-table seed helper. At topology.js lines 9805–9812 it clears the
reconstruction error (`mn-query-error`), not the route error. Lines 9820–9839
invalidate route requests, results, paths and the row association; lines
9847–9862 commit the successful reconstruction and reload its route tables.
The final render at lines 9874–9883 does not clear or reattribute `mn-route-error`.
The original exclusion message is generated by `routeEndpointScopeIssue` at
lines 2996–3002 and thrown during local request construction at lines 3042–3043.
It therefore does not establish a rejected network trace request. Once the
restored scope passes construction, `runRouteTrace` clears it at line 9736,
consistent with the successful explicit retry.

Replacing the trace's input identity should also retire its prior failure
attribution. Either clear the obsolete alert when the new seed is applied or
present it explicitly as a previous request's error with that request's
identity. The current seed must remain pending until submission; removing a
stale alert must not imply that the new request was already validated by the
backend. Keep the correct trace results, control-plane qualification and
seed-to-row correlations demonstrated by the passing controls.
Likewise, a successful replacement reconstruction should retire or explicitly
qualify a trace failure tied to the superseded device scope. Keep the correct
excluded-source rejection when the applied scope still omits that source, and
do not imply that reconstruction alone has executed a new trace.

Source inspection shows that scenario changes call the same invalidator
without clearing this alert. Endpoint and context edit handlers call it only
when a trace result, bundle or request is present; after a settled failure,
that condition may already be false. Those additional entry points were not
independently browser-tested for MN011 and are not counted as further
confirmed reproductions here. No asynchronous
race, failed cancellation, latency, CPU or memory issue is inferred.

Only this report was changed for this reporting task. No product code, skill,
aggregate count or execution ledger was edited. The documentation drift check
found no author-visible behavior or public plug-in boundary change from
recording this existing defect; maintained authoring materials need no update.

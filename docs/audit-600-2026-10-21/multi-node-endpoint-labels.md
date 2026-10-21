# MN005 — P2: route summaries hide a logical subnet behind its router label

The connected external-subnet trace preserves an explicitly entered
`203.0.113.0/24` in the form, but the result describes its flow and comparison
as **PE-E / Eta border NOS → PE-E / Eta border NOS**. The result loses the
distinction between the source router and its external subnet, although the
route correctly terminates locally on one PE-E occurrence.

This is a presentation finding. The observed reachability, single-node path
and absence of an invented remote hop remain correct. It is separate from the
route-outcome and direction-context findings.

## Browser evidence

The primary auditor performed the browser interactions. This note's author
reviewed the saved DOM states, screenshot and source at `112d346`, and ran the
small synthetic production-function probe described below. No additional
browser execution is claimed here.

- [M055: connected scenario and direction round trip](../../.runtime/audit-600-2026-10-21/multi-node/M055.json),
  recorded at `2026-10-21T06:36:55.313Z`. Settled, visible states 1–3 show
  Forward, Return and restored Forward. The comparison and flow descriptions
  collapse both logical endpoints to PE-E. State 0 contains hidden previous
  EVPN output while the new request is pending; it is excluded.
- [MX007: explicit-prefix reproduction and repeated submission](../../.runtime/audit-600-2026-10-21/multi-node/MX007.json),
  recorded at `2026-10-21T06:39:07.015Z`. All three recorded states are settled
  and visible, with no error and the destination input still equal to
  `203.0.113.0/24`. State 0 shows Return; states 1–2 show Forward and the
  repeated submission. The direction mode remains **Both directions**;
  selecting the Forward result tab does not mean **Forward only** mode.
- [Screenshot: explicit prefix alongside the masked result](../../.runtime/audit-600-2026-10-21/multi-node/MN005-subnet-label-masked.png)
  shows the destination field, route comparison, Forward flow description
  and selected-path evidence together. The selected path is resolved.
- [Execution ledger](multi-node-results.jsonl) records M055's successful route
  assertions and MX007's failed endpoint-label assertion. M055's route pass
  does not establish correct endpoint presentation.

All state indexes are zero-based. No CPU, memory or latency finding is inferred
from these observations.

## Reproduction and expected result

1. Reconstruct the existing demo topology and select
   `connected-external-subnet`, **Both directions**, **Strict** policy and the
   default trace limits (`64` hops, `16` recursion).
2. Replace Traffic destination with `203.0.113.0/24`, leave the field and submit.
3. Inspect both direction tabs, their flow captions, the comparison and the
   Forward directional goal after the request settles.
4. Select the Forward result tab and submit again. The input remains the
   prefix while the result continues to identify both flow endpoints as PE-E.

The result should retain the logical destination's declared label or value,
for example **PE-E external subnet (203.0.113.0/24)**. A reader should be able
to distinguish the forward router-to-subnet flow and the return
subnet-to-router flow. Device cards may still show one PE-E node. The trace
start is an observation point, so its router label need not become a subnet
label; the defect concerns the traffic endpoint description.

The saved resolution step says only that the plug-in resolves the local
destination attachment. It does not restore the missing subnet identity.
The scenario/path title mentions an external subnet, but does not identify
which subnet was requested.

## Source diagnosis

[routeFlowEndpointLabel in topology.js](../../frontend/assets/topology.js),
lines 4589–4601, reads the resolved flow endpoint, then searches the advertised
capabilities by endpoint identity. If that fails, it chooses the first
capability with the same `node_id`. Its return expression prefers that
capability's label over the resolved endpoint's own `label` and `value`.
Consequently a router capability masks a more specific logical endpoint
attached to that router.

The distinction is available in the source contract:

- [Demo endpoint policy](../../demo/rsl_demo_plugin/route_policy.py), lines
  202–209, declares endpoint `endpoint:eta-external-subnet`, destination
  `destination:eta-external-subnet`, kind `ip_prefix`, value `203.0.113.0/24`
  and label `PE-E external subnet`.
- [Core endpoint resolution](../../src/router_dump_analyzer/multi_node_route.py),
  `_resolve_endpoints` at line 8234 and `resolved_destination` at line 8602,
  retains the profile's identity, kind, value and label for the presented
  destination. It permits this profile's two logical endpoints to use the
  same router.
- In the same core file, `_generated_route_endpoints` at line 4484 advertises
  router-based source and destination choices. The subnet profile's logical
  endpoint is absent from that list, so the frontend's node fallback can
  replace its label with the PE-E capability label.

The helper feeds the direction-tab descriptions (lines 4624–4630), route
comparison (line 5127), directional summary (lines 5203–5210) and focused-map
flow note (lines 8724–8734). This explains the repeated label loss across
components without requiring separate findings for each rendering site.

The default form's `node-e` destination is a related capability/default
presentation limitation, rather than proof that the browser discarded typed
input. `routeEndpointDisplayValue` at line 2816 uses the advertised
destination value; MX007 demonstrates that an explicit prefix survives the
form but is still masked in the result.

There is no logical-flow endpoint inspector in the reviewed UI path:
`topologyNodeInspectorItem` at line 6154 exposes node, snapshot, plug-in, time
and coverage details; `routePathPreviewMarkup` at line 8371 displays node
labels and resolution steps. This is source inspection, not a claim that
every possible UI surface was exercised in MX007.

## Synthetic probe and linked scope

A read-only Node probe extracted the production `routeFlowEndpointLabel`
function from `topology.js` and supplied a router capability for node-e plus
each distinct logical endpoint below. Both calls returned
`PE-E / Eta border NOS`:

| Supplied logical endpoint label | Supplied value | Returned label |
| --- | --- | --- |
| PE-E external subnet | `203.0.113.0/24` | PE-E / Eta border NOS |
| East EVPN multihomed service | `esi-east:vlan-320` | PE-E / Eta border NOS |

The probe confirms the helper's label precedence; its inputs are synthetic
and do not add browser cases or establish live routing behavior.

[M031](../../.runtime/audit-600-2026-10-21/multi-node/M031.json) raised the linked
service-versus-router labeling concern during the all-active EVPN scenario.
The policy also declares a distinct `East EVPN multihomed service` endpoint
(lines 193–200 of `route_policy.py`), so the same source mechanism applies.
No equivalent explicit-service-input browser expansion is claimed here.
The independently valid PE-B and PE-E service attachments must not be reported
as an incorrect route or counted as another confirmed finding.

## Repair boundary and validation target

Preserve the resolved endpoint's explicit identity and descriptive label or
value before using a capability matched only by router ID. Keep exact endpoint
matches distinct from node fallback. A correction should not add fake device
hops, alter reachability or rewrite canonical endpoint IDs.

Validation should cover distinct logical endpoints sharing a router, an exact
capability match, and an endpoint with no usable descriptive label. Repeat the
explicit-prefix browser sequence across both result directions and repeated
submission, and confirm that the one-node connected route remains resolved.
The linked EVPN service should receive its own browser expansion before broader
UI coverage is claimed.

Documentation drift check: this addition records audit evidence only. It does
not change plug-in behavior, public APIs, examples or author commands; no
maintained authoring-document update or conformance rerun was required.

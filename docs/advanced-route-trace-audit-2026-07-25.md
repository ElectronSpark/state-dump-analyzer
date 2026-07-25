# Advanced route-trace audit — 2026-07-25

## Status and scope

This document records the executable generic forwarding-packet boundary, its
ownership rules, the intended scenario coverage, and remaining integration
work. It distinguishes three things that must not be conflated:

1. the public packet IR and protocol-neutral core helpers, which are
   implemented and unit tested;
2. node and federation plug-in responsibilities, which are normative; and
3. the bundled multi-node route demo, whose advanced scenarios now evaluate
   demo-provider packet transitions, but which does not yet discover and
   orchestrate `resolve_forwarding_step()` across every installed member.

The packet IR is not a claim that core understands MPLS, SR-MPLS, SRv6, EVPN,
VPN, IP-in-IP, MTU behavior, or vendor policy. It is a bounded way for plug-ins
to declare those effects as ordered opaque packet state.

## Ownership

| Owner | Owns | Must not do |
|---|---|---|
| Core | IR/version validation; outermost-to-innermost ordering; exact packet-state continuity; identity-based layer diffs; exact-basis integer MTU comparison; step/hop/recursion budgets; exact cycle detection; typed policy comparison; counterfactual provenance; branch and endpoint aggregation | Infer protocol meaning, overhead, PHP, SR behavior, fragmentation, a drop, a remote action, or a missing packet layer |
| Node plug-in | Forwarding-object interpretation; candidate and device-policy selection; layer contract IDs and fields; push/swap/pop/decap semantics; effective size/MTU basis; fragmentation/drop/punt/deliver decision; next local object/context; terminal classification; explanation and evidence | Traverse another node, manufacture a linker result, return an end-to-end route, or hide a machine-relevant action only in display text |
| Federation/linker plug-in | Match bounded egress and remote-ingress claims; preserve an exact compatible packet/scope contract or perform an explicit linker-owned mapping; retain ambiguity and evidence | Choose a node's route, reinterpret protocol fields, or silently add/remove/reorder packet layers |
| User steering | Request one explicit counterfactual candidate, packet-after state, or disposition at one exact step | Replace stored projection, masquerade as `node_plugin`, or become reachability ground truth |
| Demo provider | Generate product-shaped MPLS, SR, EVPN, tunnel, MTU, failure, and uncertainty fixtures | Move product/protocol meaning into core |

## Implemented packet boundary

The following public types are implemented in `plugin_api.py`:

- `ForwardingPacketLayer`: opaque stable identity, versioned contract, typed
  fields, optional byte size, completeness;
- `ForwardingSizeObservation` and `ForwardingMtuConstraint`: complete integer
  values qualified by one opaque measurement-basis contract;
- `ForwardingPacketState`: at most 256 unique ordered layers plus optional
  size and overall completeness;
- `ForwardingPacketTransition`: exact before/after state, action contract and
  label, normalized disposition, origin, actor, optional MTU, forced-rule
  provenance, and contributions;
- `ForwardingSteeringRule`: exact step target, optional expected packet state,
  bounded priority, and candidate/packet/disposition override;
- `ForwardingStepRequest` and `ForwardingStepResult`: one bounded node-local
  trace question and answer;
- `FORWARDING_TRACE` and the optional `resolve_forwarding_step()` plug-in hook;
  and
- `ForwardingTraversalStateKey.packet_state`, so complete packet identity
  participates in exact loop detection.

The following protocol-neutral helpers are implemented in
`route_trace_core.py`:

- `diff_forwarding_packet_states()`;
- `evaluate_forwarding_mtu()`;
- `evaluate_forwarding_packet_transition()`;
- `select_forwarding_steering_rule()`;
- `apply_forwarding_steering_rule()`;
- `evaluate_forwarding_packet_trace()`; and
- existing typed policy, cycle/budget, and endpoint-pair evaluators.

Complete before/after discontinuity is a contract error. Incomplete identity
retains `unknown_incomplete` continuity and cannot prove a loop. MTU is
`fits`/`exceeds` only for the same complete `basis_contract_id`; otherwise it
is `unknown`, `unknown_basis_mismatch`, or `not_declared`. An `exceeds` result
does not independently choose fragmentation or drop.

## Executable generic conformance matrix

`tests/test_packet_trace_core.py` currently exercises these packet profiles:

| Profile | Ordered outer-to-inner example | Generic operations exercised |
|---|---|---|
| Native IP | Inner IPv4 | Encapsulation/no-op shape, transit change, delivery |
| SR-MPLS-shaped | Transport-label layer, inner IPv4 | Outer layer add/change/remove |
| MPLS L3VPN-shaped | Transport label, VPN label, inner IPv4 | Nested label continuity and inner retention |
| SRv6-shaped | Outer IPv6, SRH with ordered SID data, inner IPv6 | Wrapper add/change/remove |
| IPv6-over-IPv4-shaped | Outer IPv4, inner IPv6 | IP tunnel add/change/remove |
| VPN-over-VPN-shaped | Transport label, outer IPv6, UDP, VXLAN, Ethernet, VPN label, inner IPv4 | Deep nesting and exact order |

Each profile is run through ingress encapsulation, a transit modification, and
egress decapsulation/delivery. It is also crossed with MTU limits one byte
below, exactly equal to, and one byte above the declared packet size. Separate
tests cover:

- canonical layer fields and unique IDs;
- protocol-neutral structural diffs;
- missing, incomplete, and unequal MTU bases;
- the fact that MTU arithmetic does not choose fragment/drop;
- exact bounded counterfactual steering and ambiguous priority rejection;
- strict complete continuity versus incomplete unknown continuity; and
- complete versus incomplete packet identity in loop detection.

This matrix demonstrates representational capability. The advanced demo adds
product-shaped teaching fixtures for PHP, SRv6 endpoint processing, nested
wrappers, and a plug-in-declared MTU drop; it still does not claim vendor
accuracy.

## Constrained route-scenario matrix

The following matrix is the tractable target for product-shaped demo coverage.
“Demo” means an existing dedicated scenario, “IR” means the generic packet
profile exists but the route demo is shallow, and “Open” means a dedicated
fixture is still needed.

| ID | Service and transport | Selection/start | Expected interaction | Status |
|---|---|---|---|---|
| R01 | IPv4 native/connected | Single, source | Exact connected terminal | Demo |
| R02 | IPv6 native | Single, transit | Return reaches source without revisiting start | Open |
| R03 | IPv4 recursive | Single, source | Exact recursive-state loop | Demo |
| R04 | IPv6 native | Active/standby | Non-shortest device policy plus unknown alternate | Open |
| R05 | Classic MPLS/LDP | All-active | Push, transit swap, pop; every branch reaches | Open |
| R06 | SR-MPLS | Single | Node-SID PHP; outer layer removed at penultimate hop | Demo |
| R07 | SR-MPLS | Active/standby, transit | Explicit-null/no-PHP plus retained dead alternate | Open |
| R08 | MPLS L3VPN | Single, asymmetric return | Outer PHP retains VPN layer, then VRF lookup | Demo |
| R09 | MPLS L3VPN | All-active | One selected branch exceeds MTU; known partial reachability | Open |
| R10 | SR-MPLS policy/BSID | Forced non-shortest | Selected observed path plus unknown standby | Open |
| R11 | SRv6 | Single | Encap, segment processing, decap and lookup | Demo |
| R12 | SRv6 | All-active, transit | One success plus one incomplete SID path | Open |
| R13 | SRv6 | Single, asymmetric return | Forward MTU/PTB failure; healthy MPLS return | Open |
| R14 | EVPN Type 2/VXLAN | All-active multihoming | Two selected VTEPs reach | Demo |
| R15 | EVPN Type 2 BUM | DF/single-active | Exact split-horizon block | Demo |
| R16 | EVPN known unicast | Transit/all-active | Incomplete ingress scope remains unknown | Open |
| R17 | EVPN Type 5 over SR-MPLS | All-active | Stale FIB/encapsulation disagreement | Open |
| R18 | IPv4-in-IPv6 or GRE | Single, transit | Tunnel overhead plus DF creates one-way failure | Open |
| R19 | IPv6-in-IPv4 | Active/standby | Decapsulation or inner lookup unknown | Demo (healthy single path) |
| R20 | Carrier-supporting-carrier L3VPN | Forced steering | Remove outer carrier context, retain tenant VPN | Demo (nested stack + separate forced path) |
| R21 | EVPN overlay over SRv6 | All-active | One selected branch fails decapsulation | Open |
| R22 | IP-in-IP inside L3VPN service chain | Forced hairpin | Changed packet context makes revisit legitimate | IR |
| R23 | Same nested service chain | Recursive | Complete packet/lookup state repeats and loops | IR |
| R24 | Multihomed source and destination | All-active, transit | Attachment uncertainty and return bypass | Open |

The executable checker iterates every advertised advanced profile in both
directions and every advertised steering preset. Core tests cross packet
profiles with below/equal/above MTU boundaries. Future additions should keep
covering valid interaction pairs rather than an unbounded Cartesian product:

- every applicable service family over at least two transport shapes;
- every transport with a healthy and a failed/unknown case;
- every multipath mode with healthy and partial/unknown coverage;
- MTU with label, SRv6, and IP-tunnel shapes;
- forced steering with both simple and nested packet state;
- loop detection before and after a packet-context change; and
- source-start, transit-start, asymmetric, and one-way endpoint goals.

## Manual browser validation

The live split frontend/backend demo was exercised at
`http://127.0.0.1:8765/#route-trace` against the packed 125,000-event,
10,000-resource fixture. The browser pass used the visible controls rather
than calling the route endpoint directly.

The following scenarios were traced in both forward and return directions:

- native IPv4;
- SR-MPLS push, swap, and PHP;
- MPLS L3VPN over SR-MPLS, including retention of the VPN label after PHP;
- SRv6 encapsulation, segment advancement, and decapsulation;
- IPv6 over IPv4;
- nested VPN over VPN;
- an MTU-exceeded terminal drop; and
- observed plus all three advertised forced-steering profiles.

For each result the pass checked the selected direction, transition sequence,
terminal disposition, packet summary, and continuity status. It additionally
verified that:

- forward and return inner IP source/destination fields are independently
  reversed;
- native transit TTL changes are 64 to 63 to 62, with no extra decrement at
  destination delivery;
- the 1,510-byte packet versus 1,500-byte MTU failure and its measurement
  basis appear in the pinned detail;
- forced alternate selection chooses P2 in each direction;
- forced ingress and mid-path wrappers remain continuous until a declared
  removal;
- hover and keyboard focus open the same packet preview and highlight the
  correlated graph node/link;
- click pins complete before/diff/after state and provenance;
- Escape clears the packet pin;
- changing to a legacy basic-route scenario removes all packet focus,
  preview, detail, and rail state while preserving the basic route result; and
- the browser console remains free of warnings and errors.

The pass found one direction-specific explanation defect: the mid-path forced
rule named P1 even when the return trace correctly applied it on P2. That
plug-in-owned text now refers to the selected transit result, and the corrected
wording was rechecked on P1 forward and P2 return.

## Audit resolution

### Implemented/fixed in the generic boundary

- Ordered packet layers no longer need to be inferred from display text.
- Push/swap/pop/decap-shaped changes are expressible through exact
  before/after snapshots without protocol branches in core.
- Complete continuity errors and incomplete continuity are distinct.
- Packet identity participates in loop detection only when complete.
- MTU comparison is bounded, integer, and exact-basis; it cannot silently
  choose fragmentation or drop.
- User-forced steering has exact targeting, bounded priority, actor/rule
  provenance, and explicit counterfactual origin.
- Packet-step, hop, and recursion limits are independent.
- The optional node-local request/result hook is defined without giving node
  plug-ins cross-node authority.

### Known remaining work

- The demo server consumes generic packet-transition evaluations from its
  demo provider, but does not yet discover and invoke
  `resolve_forwarding_step()` across arbitrary installed node plug-ins.
- The browser-facing multi-node route result remains a large demo dictionary
  rather than a typed core `RouteTraceResult`.
- Most dedicated reverse directions still fall back to a generic shortest-path
  builder instead of independently modeling withdraw and every legacy policy
  scenario. The eight advanced packet scenarios do declare forward and return
  node sequences independently.
- Default return start does not yet branch a plug-in-declared multihomed
  destination attachment set.
- MPLS versus SR-MPLS, PHP versus explicit-null, and device-specific MTU
  behavior remain plug-in/demo semantics. The demo covers SR-MPLS PHP and one
  MTU drop; explicit-null, fragmentation/PTB, and vendor-specific variants
  remain future fixtures. Core must not fill these gaps by inference.

### Integration defects found and fixed

- A demo MPLS field named `label` collided with the layer display-label
  argument and prevented the profile from executing. The typed field is now
  `label_value`.
- A user-forced outer wrapper changed only the first transition, causing a
  complete-state continuity error at the next node. The demo plug-in now
  carries that wrapper through the declared transit states and removes it at
  delivery.
- Two conclusive terminal MTU drops were classified as
  `unknown_incomplete` because path completeness was confused with endpoint
  classification completeness. Explicit `not_reached` outcomes now aggregate
  to `both_unreachable`.
- Directional `partial_active_reachability` is preserved by the pair
  evaluator instead of being flattened to an unknown boolean.
- All-active path relation compares complete branch multisets; it no longer
  depends on whichever active path appeared first.
- Path symmetry is not evaluated across incomplete endpoint spans.
- When no candidate is selected active, a retained standby/first/primary path
  is no longer promoted to forwarding truth. A complete non-forwarding
  terminal remains a known failure; other selection gaps remain unknown.
- `replicate` now terminates the current linear evaluation as a branch request,
  and an all-`continue` prefix reports `continuation_required` instead of
  pretending to be resolved.
- A valid 500-character steering reason could overflow the transition's
  160-character action-label contract. The derived label is now bounded while
  the coordinator retains the full rule reason separately.
- Capability dispatch now has focused coverage for the
  `FORWARDING_TRACE`/`resolve_forwarding_step` mapping.
- Reverse packet fixtures now swap inner addresses, tunnel endpoints, SRv6
  addresses/SIDs, tenant MACs, and forced-wrapper endpoints independently
  rather than reusing the forward packet identity.
- Native destination delivery no longer performs an extra TTL decrement.
- Structural packet diff treats display labels as non-semantic, does not mark
  retained layers as moved merely because an outer layer was pushed or
  popped, and exposes whether the diff itself is complete.
- The browser serializer preserves contribution resources, topology
  references, evidence, MTU provenance, and transition-local continuity.
- Packet transitions now correlate to normalized resolution steps even when a
  provider identifies the transition by segment.
- Same-router but different-attachment starts no longer count as a complete
  source-to-destination endpoint span.
- A mid-path steering explanation no longer hard-codes P1 when the same rule
  applies to the return-direction P2 transit step.

These open items do not invalidate the generic packet IR. They limit which
current demo screens can claim to exercise it end to end.

## Documentation maintenance rule

Any change to packet-layer fields, transitions, MTU basis comparison, steering
provenance, the step hook, federation transfer, or route aggregation must update
the plug-in contract, architecture, API contract, quickstart, this audit, and
the corresponding executable tests in the same change.

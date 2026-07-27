# Advanced route-trace audit — 2026-07-25

## Status and scope

This document records the executable generic forwarding-packet boundary, its
ownership rules, the versioned generated-demo coverage, and remaining
production integration work. It distinguishes four things that must not be
conflated:

1. the public packet IR and protocol-neutral core helpers, which are
   implemented and unit tested;
2. node and federation plug-in responsibilities, which are normative; and
3. the bundled multi-node route demo, whose generated scenarios evaluate
   demo-provider packet transitions, but which does not yet discover and
   orchestrate `resolve_forwarding_step()` across every installed member; and
4. arbitrary vendor/protocol combinations that are not entries in the
   generated demo's versioned coverage registry.

For this 2026-07-25 audit, **all demo cases** meant exactly every entry then in
`generator.catalog.COVERAGE_CASES`. The inspected
registry contained 35 cases. It was not shorthand for every possible protocol,
vendor, release, packet shape, or deployment policy.

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

At the time of this audit, `tests/test_packet_trace_core.py` exercised these
packet profiles:

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

## Versioned generated-demo registry — 2026-07-25 snapshot

> The format versions, provider IDs, case counts, and capability descriptions
> in this section record the repository on 2026-07-25. The
> [demo guide](../demo/README.md#generated-mock-dumps) is the source for the
> current implementation contract; this dated audit is not updated in place to
> mirror later registry changes.

In the audited implementation, `COVERAGE_CASES` was the behavior registry for
the one generated demo.
The generator writes the exact registry to `coverage.json`; full-demo
validation fails if a registry entry is absent, lacks its declared nodes, or
does not carry its generated evidence. Route and packet entries must also map
to an executable scenario with the same route type, route family, address
family, and VRF.

Topology entries now carry exact generated `topology_claim` evidence, including
the attachment, matcher/segment key, classification, validity, and calculation
metadata. Temporal entries carry a real generated `temporal_event` UID selected
by phase and event shape, including resource, outcome, and state-change
semantics. This closes the earlier loophole where an unrelated but valid
resource/event ID could make non-route coverage look complete.

The installed `demo.example-router` plug-in was also the single source of the
demo-only `generated_projection_policy`. Generation wrote that policy ID,
plug-in version, projection format, and
`projection_materialization: precomputed_during_generation` into the archive.
Generator validation and runtime loading compared those values with the
installed policy and rejected drift. `parser_replayed: false` was intentional:
the runtime validated immutable precomputed evidence rather than pretending
the small status parser regenerated the comprehensive projection. This was not
a generic core hook.

The assembly, coverage registry, and precomputed projection audited on
2026-07-25 used format version 2. The projection capability enumerated each
immutable member's path,
media type, serialization, and record collection; the archive carries matching
`precomputed_projection_capability` and `generated_schema_contract`
descriptors. The installed example entry point exposed those declarations with
`describe_generated_fixture()` so generator, validator, and runtime agreed.
This was an offline-demo extension, not a required live-parser hook.

| Category | Count | Executed by route trace | Coverage focus |
|---|---:|---:|---|
| Route | 18 | 18 | Single-active and all-active paths, arbitrary router pairs, transit starts, asymmetric and one-way reachability, EVPN failover and stale FIB, SRv6, recursion, loops, split horizon, connected external delivery, and incomplete resolution |
| Packet | 8 | 8 | Native IP, SR-MPLS/PHP, L3VPN over SR-MPLS, SRv6, IPv6 over IPv4, nested VPN, MTU drop, and forced steering |
| Topology | 4 | 0 | Shared multi-access subnet, compact two-party segment, VLAN/LAG/subinterface evidence, and external/management/loopback/VPN classification |
| Temporal | 5 | 0 | Single-home to multihome, mass ES withdraw, mass ES restore, next-hop churn, and cross-layer lag/failure |
| **Total** | **35** | **26** | Every entry in the audited `COVERAGE_CASES` snapshot |

The 26 route-executable cases are the 18 `route` entries plus the eight
`packet` entries. The remaining nine entries belong to topology or temporal
coverage and are deliberately not mislabeled as packet-forwarding paths.

The generated route trace validates more than scenario names. Every executable
case declares all forward and reverse `candidate_paths`; every involved node
contributes one revision-qualified route decision plus
`directional_decisions` for each exact `(candidate_id, visit_index)`
occurrence. Each non-local decision names one exact connectivity-domain
matcher/key and both attachment resources. Packet cases additionally
contribute a plug-in-owned packet declaration. The coordinator rejects
missing, duplicate, cross-node, cross-revision, mismatched, ambiguous,
truncated, or unusable route/forwarding/topology/packet references rather than
falling back to a hand-written scenario answer.

The automated suite:

- compares generated `coverage.json` with the exact `COVERAGE_CASES` set;
- requires all full-demo cases to be generated;
- executes all 26 route/packet cases in both forward and reverse directions;
- verifies route rows, forwarding rows, packet declarations, provider
  identity, revision identity, checksums, candidate occurrences, exact
  connectivity-domain/attachment joins, and evidence references; and
- proves that removing or tampering with generated forwarding, topology, or
  packet rows makes trace execution fail closed.

A fresh all-node development assembly (`allow_small=True`) is exercised through
FastAPI's generated assembly route endpoint. Every one of the 26
capability-advertised route or packet cases must return a bound candidate for
both `direction=forward` and `direction=reverse`, including strict/best-effort
and steering variants where declared. This is an automated API/runtime matrix,
not a claim that every combination was manually inspected.

## Production expansion is separate from demo completeness

The former R01-R24 table mixed the then-current demo behavior with an aspirational
vendor matrix and therefore made generated coverage look incomplete even when
every declared case was present. Those entries are no longer demo pass/fail
criteria. They remain useful design dimensions for future registry versions or
production plug-ins:

- explicit-null/no-PHP and vendor-specific MPLS behavior;
- additional IPv6, SRv6, EVPN-over-SRv6, GRE, and service-chain variants;
- fragmentation, PTB/ICMP generation, and device-specific MTU bases;
- more all-active partial-reachability and multihomed attachment combinations;
- more independently modeled reverse-direction withdraw/policy states; and
- arbitrary installed-node plug-in orchestration across heterogeneous
  providers.

Adding one of these behaviors to the advertised demo requires a new
`COVERAGE_CASES` entry, generated evidence, validation, executable API coverage,
and documentation in the same change. Until then it is an explicit production
or future-demo extension, not a hidden failure of the audited 35-case registry.

## Manual browser validation

The core frontend and demo backend were exercised together at
`http://127.0.0.1:8765/#route-trace` against the generated assembly whose node
revisions contain 125,000 events and 7,500 resources each. The browser pass
used the visible controls rather than calling the route endpoint directly.

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

### Production integration and future registry work

The 35-case generated registry audited on 2026-07-25 was complete on its own
terms. The
following work is deliberately outside that bounded claim:

- A production coordinator still needs to discover installed node plug-ins,
  negotiate their capabilities, and invoke `resolve_forwarding_step()` at each
  heterogeneous member boundary. The demo consumes its one provider's
  generated declarations directly.
- The browser-facing multi-node route result remains a large demo dictionary
  rather than a typed core `RouteTraceResult`.
- The 26-case API matrix covers both declared directions, but it remains the
  bounded generated registry rather than an exhaustive set of vendor or future
  protocol behaviors.
- Additional multihomed attachment branches, independent withdraw/policy
  states, and vendor-specific behaviors can become future registry entries
  when they have generated evidence and executable assertions.
- MPLS versus SR-MPLS, PHP versus explicit-null, fragmentation/PTB, and
  device-specific MTU outcomes remain plug-in semantics. Core must not fill
  missing variants by inference.

### Integration defects found and fixed

- Generated route traces now bind each scenario to the exact
  revision-qualified route and forwarding rows named by `coverage.json`;
  missing, duplicate, or mismatched rows fail closed instead of silently using
  only the in-memory scenario catalog.
- Generated packet cases now bind their declared profile, initial state, and
  action contracts to the demo executor while retaining the generated provider
  and evidence identities. Tampered packet declarations are rejected.
- Selecting a generated route-table row preserves its scenario, route ID,
  revision evidence, and correlated forwarding decisions through the trace
  request.
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

These production and future-registry items did not invalidate the generic
packet IR or make an unadvertised case part of the audited demo contract.

## Documentation maintenance rule

Any later change to packet-layer fields, transitions, MTU basis comparison,
steering provenance, the step hook, federation transfer, or route aggregation
must update the current plug-in contract, architecture, API contract,
quickstart, demo guide, and corresponding executable tests in the same change.
This audit remains the 2026-07-25 record; create a new dated audit when a new
review snapshot is needed.

After this snapshot, any change to `COVERAGE_CASES` must regenerate
`coverage.json` and its node-local route/forwarding/packet evidence, update the
current [demo guide](../demo/README.md#generated-mock-dumps), and add or update
executable validation before the new case is advertised. Do not rewrite the
historical totals above; create a new dated audit when another snapshot is
needed.

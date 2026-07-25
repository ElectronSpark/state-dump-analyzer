"""Demo-only packet evolution semantics for advanced route traces.

This module intentionally lives with the demo plug-ins.  It knows what IPv4,
MPLS, SRv6, VXLAN, and the fixture's forced actions mean.  The reusable core
only validates the generic packet-layer and before/after transition contracts.
"""

from __future__ import annotations

from collections.abc import Sequence

from router_dump_analyzer.plugin_api import (
    ForwardingMtuConstraint,
    ForwardingPacketDisposition,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingSizeObservation,
    ForwardingSteeringRule,
    ForwardingTransitionOrigin,
    ResourceKey,
)
from router_dump_analyzer.route_trace_core import (
    apply_forwarding_steering_rule,
)


ADVANCED_TRACE_SCENARIOS: tuple[dict[str, object], ...] = (
    {
        "scenario_id": "packet-native-ip",
        "packet_profile_id": "native-ip",
        "label": "Packet evolution · native IPv4",
        "description": (
            "Native IPv4 forwarding changes only hop-local header state. This "
            "is the compatibility baseline for basic IP routing."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv4_unicast",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-sr-mpls-php",
        "packet_profile_id": "sr-mpls-php",
        "label": "Packet evolution · SR-MPLS swap and PHP",
        "description": (
            "Ingress pushes a transport label, transit swaps it, the penultimate "
            "hop performs PHP, and egress receives native IPv4."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-l3vpn-over-sr-mpls",
        "packet_profile_id": "l3vpn-over-sr-mpls",
        "label": "Packet evolution · L3VPN over SR-MPLS",
        "description": (
            "An IPv4 tenant packet gains VPN and transport labels. Transit swaps "
            "and PHP affect only the transport layer before egress removes the VPN "
            "label and performs the tenant lookup."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_l3vpn",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "vpnv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-srv6-encap",
        "packet_profile_id": "srv6-encap",
        "label": "Packet evolution · SRv6 encapsulation",
        "description": (
            "Ingress adds an outer IPv6 header and SRH, an SR endpoint advances "
            "the declared SID list, and egress decapsulates the inner IPv6 packet."
        ),
        "multipath_mode": "single_active",
        "route_type": "srv6_policy",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-ipv6-over-ipv4",
        "packet_profile_id": "ipv6-over-ipv4",
        "label": "Packet evolution · IPv6 over IPv4",
        "description": (
            "An IPv6 packet is recursively resolved through an IPv4 tunnel, "
            "retaining both header layers until tunnel egress."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv6_unicast",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-vpn-over-vpn",
        "packet_profile_id": "vpn-over-vpn",
        "label": "Packet evolution · nested VPN over VPN",
        "description": (
            "A tenant IPv4 packet is wrapped by Ethernet/VXLAN/UDP/IPv6 and then "
            "carried inside an MPLS L3VPN transport, demonstrating multiple nested "
            "wrappers without protocol branches in core."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_l3vpn",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "vpnv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-mtu-drop",
        "packet_profile_id": "mtu-drop",
        "label": "Packet evolution · MTU drop after encapsulation",
        "description": (
            "The node plug-in declares a DF packet drop after tunnel overhead "
            "exceeds an egress wire-size constraint. Core performs only the size "
            "comparison."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv4_unicast",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "packet-forced-steering",
        "packet_profile_id": "sr-mpls-php",
        "label": "Packet evolution · forced steering sandbox",
        "description": (
            "The observed node decision uses P1. An advertised user rule can force "
            "the alternate P2 candidate or inject an outer IPv4 wrapper; every "
            "forced result remains visibly counterfactual."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
        "steering_profiles": (
            "observed",
            "force-alternate-p2",
            "force-outer-ipv4",
            "force-mid-wrapper",
        ),
    },
)


ADVANCED_TRACE_SCENARIO_IDS = frozenset(
    str(item["scenario_id"]) for item in ADVANCED_TRACE_SCENARIOS
)


STEERING_PROFILES: tuple[dict[str, str], ...] = (
    {
        "profile_id": "observed",
        "label": "Observed plug-in decision",
        "description": "Do not override the node plug-in.",
    },
    {
        "profile_id": "force-alternate-p2",
        "label": "Force alternate path through P2",
        "description": (
            "Select the plug-in-declared P2 candidate at ingress. The result is "
            "counterfactual and does not modify observed forwarding state."
        ),
    },
    {
        "profile_id": "force-outer-ipv4",
        "label": "Force an extra outer IPv4 wrapper",
        "description": (
            "Replace the ingress packet result with a bounded user-provided packet "
            "snapshot and retain forced-rule provenance."
        ),
    },
    {
        "profile_id": "force-mid-wrapper",
        "label": "Inject a wrapper at the transit step",
        "description": (
            "Replace the selected transit result with a bounded packet snapshot "
            "that adds a user wrapper. Later plug-in states retain and remove it."
        ),
    },
)


_PLUGIN_ACTOR_BY_NODE = {
    "node-a": "demo.alpha.platform",
    "node-b": "demo.beta.forwarding",
    "node-c": "demo.epsilon.forwarding",
    "node-d": "demo.zeta.fabric",
    "node-e": "demo.eta.border",
    "transit-p-1": "demo.gamma.isis",
    "transit-p-2": "demo.delta.sr-isis",
}


def _header(
    layer_id: str,
    contract_id: str,
    label: str,
    size_bytes: int,
    **fields: int | str | tuple[str, ...],
) -> ForwardingPacketLayer:
    return ForwardingPacketLayer(
        layer_id=layer_id,
        contract_id=contract_id,
        label=label,
        fields=tuple(fields.items()),
        size_bytes=size_bytes,
    )


def _state(
    layers: Sequence[ForwardingPacketLayer],
    size_bytes: int,
) -> ForwardingPacketState:
    return ForwardingPacketState(
        layers=tuple(layers),
        size=ForwardingSizeObservation(
            basis_contract_id="demo.wire-size.v1",
            size_bytes=size_bytes,
        ),
    )


def _directional_pair(
    direction: str,
    forward_source: str,
    forward_destination: str,
) -> tuple[str, str]:
    if direction == "forward":
        return forward_source, forward_destination
    if direction == "reverse":
        return forward_destination, forward_source
    raise ValueError(f"unsupported packet trace direction: {direction}")


def _inner_ipv4(
    *,
    direction: str,
    large: bool = False,
) -> ForwardingPacketState:
    source, destination = _directional_pair(
        direction,
        "192.0.2.10",
        "198.51.100.20",
    )
    return _state(
        (
            _header(
                "inner-ipv4",
                "demo.ipv4.v1",
                "Inner IPv4",
                20,
                source=source,
                destination=destination,
                ttl=64,
                df="set" if large else "clear",
            ),
        ),
        1_490 if large else 1_420,
    )


def _inner_ipv6(*, direction: str) -> ForwardingPacketState:
    source, destination = _directional_pair(
        direction,
        "2001:db8:10::10",
        "2001:db8:20::20",
    )
    return _state(
        (
            _header(
                "inner-ipv6",
                "demo.ipv6.v1",
                "Inner IPv6",
                40,
                source=source,
                destination=destination,
                hop_limit=64,
            ),
        ),
        1_440,
    )


def preferred_node_sequence(
    profile_id: str,
    direction: str,
) -> list[str]:
    """Return the demo plug-in's independently declared path for one direction."""

    if profile_id in {
        "sr-mpls-php",
        "l3vpn-over-sr-mpls",
        "vpn-over-vpn",
    }:
        return (
            ["node-a", "transit-p-1", "transit-p-2", "node-b"]
            if direction == "forward"
            else ["node-b", "transit-p-2", "transit-p-1", "node-a"]
        )
    return (
        ["node-a", "transit-p-1", "node-b"]
        if direction == "forward"
        else ["node-b", "transit-p-1", "node-a"]
    )


def forced_node_sequence(
    direction: str,
    steering_profile_id: str,
) -> list[str] | None:
    if steering_profile_id != "force-alternate-p2":
        return None
    return (
        ["node-a", "transit-p-2", "node-b"]
        if direction == "forward"
        else ["node-b", "transit-p-2", "node-a"]
    )


def _mpls_transport_states(
    *,
    with_vpn: bool,
    nested_vpn: bool,
    direction: str,
) -> tuple[list[ForwardingPacketState], list[str]]:
    inner = _inner_ipv4(direction=direction)
    inner_layers = list(inner.layers)
    if nested_vpn:
        outer_source, outer_destination = _directional_pair(
            direction,
            "2001:db8:100::a",
            "2001:db8:100::b",
        )
        tenant_source, tenant_destination = _directional_pair(
            direction,
            "02:00:00:00:00:0a",
            "02:00:00:00:00:0b",
        )
        inner_layers = [
            _header(
                "outer-ipv6",
                "demo.ipv6.v1",
                "Outer IPv6 underlay",
                40,
                source=outer_source,
                destination=outer_destination,
                hop_limit=64,
            ),
            _header(
                "udp",
                "demo.udp.v1",
                "UDP tunnel",
                8,
                source_port=49152,
                destination_port=4789,
            ),
            _header(
                "vxlan",
                "demo.vxlan.v1",
                "Nested VXLAN VPN",
                8,
                vni=10320,
            ),
            _header(
                "tenant-ethernet",
                "demo.ethernet.v1",
                "Tenant Ethernet",
                14,
                source=tenant_source,
                destination=tenant_destination,
            ),
            *inner_layers,
        ]
    vpn_layers = (
        [
            _header(
                "vpn-label",
                "demo.mpls-label.v1",
                "VPN label 24001",
                4,
                label_value=24001,
                traffic_class=0,
                bottom_of_stack="set",
            )
        ]
        if with_vpn
        else []
    )
    transport = _header(
        "transport-label",
        "demo.mpls-label.v1",
        "Transport label 16002",
        4,
        label_value=16002,
        traffic_class=0,
        bottom_of_stack="clear" if with_vpn else "set",
    )
    ingress_layers = [transport, *vpn_layers, *inner_layers]
    ingress = _state(
        ingress_layers,
        inner.size.size_bytes  # type: ignore[union-attr]
        + sum(layer.size_bytes or 0 for layer in ingress_layers[:-1]),
    )
    swapped_layers = [
        _header(
            "transport-label",
            "demo.mpls-label.v1",
            "Transport label 16003",
            4,
            label_value=16003,
            traffic_class=0,
            bottom_of_stack="clear" if with_vpn else "set",
        ),
        *vpn_layers,
        *inner_layers,
    ]
    swapped = _state(swapped_layers, ingress.size.size_bytes)  # type: ignore[union-attr]
    php_layers = [*vpn_layers, *inner_layers]
    php = _state(
        php_layers,
        ingress.size.size_bytes - 4,  # type: ignore[union-attr]
    )
    return (
        [inner, ingress, swapped, php, inner],
        [
            "Push transport label"
            if not with_vpn
            else "Push transport and VPN labels",
            "Swap transport label",
            "Penultimate-hop pop transport label",
            "Remove service encapsulation and deliver",
        ],
    )


def _profile_states(
    profile_id: str,
    direction: str,
) -> tuple[list[ForwardingPacketState], list[str], int | None]:
    if profile_id == "native-ip":
        initial = _inner_ipv4(direction=direction)
        initial_fields = dict(initial.layers[0].fields)
        forwarded = []
        for ttl in (63, 62):
            forwarded.append(
                _state(
                    (
                        _header(
                            "inner-ipv4",
                            "demo.ipv4.v1",
                            f"Inner IPv4 · TTL {ttl}",
                            20,
                            source=str(initial_fields["source"]),
                            destination=str(
                                initial_fields["destination"]
                            ),
                            ttl=ttl,
                            df="clear",
                        ),
                    ),
                    initial.size.size_bytes,  # type: ignore[union-attr]
                )
            )
        return (
            [initial, *forwarded, forwarded[-1]],
            ["Forward IPv4", "Forward IPv4", "Deliver IPv4"],
            None,
        )
    if profile_id == "sr-mpls-php":
        states, actions = _mpls_transport_states(
            with_vpn=False,
            nested_vpn=False,
            direction=direction,
        )
        return states, actions, None
    if profile_id == "l3vpn-over-sr-mpls":
        states, actions = _mpls_transport_states(
            with_vpn=True,
            nested_vpn=False,
            direction=direction,
        )
        return states, actions, None
    if profile_id == "vpn-over-vpn":
        states, actions = _mpls_transport_states(
            with_vpn=True,
            nested_vpn=True,
            direction=direction,
        )
        actions[-1] = "Remove MPLS L3VPN and nested VXLAN wrappers; deliver"
        return states, actions, None
    if profile_id == "srv6-encap":
        inner = _inner_ipv6(direction=direction)
        if direction == "forward":
            outer_source = "2001:db8:100::a"
            sid_list = (
                "2001:db8:100::1",
                "2001:db8:200::b",
            )
        else:
            outer_source = "2001:db8:200::b"
            sid_list = (
                "2001:db8:200::1",
                "2001:db8:100::a",
            )
        outer = _header(
            "outer-ipv6",
            "demo.ipv6.v1",
            "Outer IPv6",
            40,
            source=outer_source,
            destination=sid_list[0],
            hop_limit=64,
        )
        srh = _header(
            "srh",
            "demo.srv6-srh.v1",
            "SRH · 2 SIDs",
            40,
            sid_list=sid_list,
            segments_left=1,
        )
        encap = _state(
            (outer, srh, *inner.layers),
            inner.size.size_bytes + 80,  # type: ignore[union-attr]
        )
        advanced = _state(
            (
                _header(
                    "outer-ipv6",
                    "demo.ipv6.v1",
                    "Outer IPv6",
                    40,
                    source=outer_source,
                    destination=sid_list[1],
                    hop_limit=63,
                ),
                _header(
                    "srh",
                    "demo.srv6-srh.v1",
                    "SRH · final SID",
                    40,
                    sid_list=sid_list,
                    segments_left=0,
                ),
                *inner.layers,
            ),
            encap.size.size_bytes,  # type: ignore[union-attr]
        )
        return (
            [inner, encap, advanced, inner],
            [
                "Encapsulate with outer IPv6 and SRH",
                "Advance SRv6 segment list",
                "Decapsulate SRv6 and deliver",
            ],
            None,
        )
    if profile_id == "ipv6-over-ipv4":
        inner = _inner_ipv6(direction=direction)
        outer_source, outer_destination = _directional_pair(
            direction,
            "192.0.2.1",
            "198.51.100.1",
        )
        encap = _state(
            (
                _header(
                    "outer-ipv4",
                    "demo.ipv4.v1",
                    "Outer IPv4 tunnel",
                    20,
                    source=outer_source,
                    destination=outer_destination,
                    ttl=64,
                    df="set",
                ),
                *inner.layers,
            ),
            inner.size.size_bytes + 20,  # type: ignore[union-attr]
        )
        transit = _state(
            (
                _header(
                    "outer-ipv4",
                    "demo.ipv4.v1",
                    "Outer IPv4 tunnel · TTL 63",
                    20,
                    source=outer_source,
                    destination=outer_destination,
                    ttl=63,
                    df="set",
                ),
                *inner.layers,
            ),
            encap.size.size_bytes,  # type: ignore[union-attr]
        )
        return (
            [inner, encap, transit, inner],
            [
                "Encapsulate IPv6 inside IPv4",
                "Forward outer IPv4 tunnel",
                "Decapsulate IPv4 and deliver IPv6",
            ],
            None,
        )
    if profile_id == "mtu-drop":
        inner = _inner_ipv4(direction=direction, large=True)
        outer_source, outer_destination = _directional_pair(
            direction,
            "192.0.2.1",
            "198.51.100.1",
        )
        wrapped = _state(
            (
                _header(
                    "outer-ipv4",
                    "demo.ipv4.v1",
                    "Outer IPv4 tunnel",
                    20,
                    source=outer_source,
                    destination=outer_destination,
                    ttl=64,
                    df="set",
                ),
                *inner.layers,
            ),
            inner.size.size_bytes + 20,  # type: ignore[union-attr]
        )
        return [inner, wrapped], ["Encapsulate then drop: MTU exceeded"], 1_500
    raise ValueError(f"unknown demo packet profile: {profile_id}")


def build_packet_transitions(
    *,
    profile_id: str,
    step_ids: Sequence[str],
    node_ids: Sequence[str],
    direction: str,
    steering_profile_id: str = "observed",
) -> tuple[ForwardingPacketState, tuple[ForwardingPacketTransition, ...]]:
    """Return plug-in-declared transitions for the route coordinator to validate."""

    states, actions, mtu_limit = _profile_states(profile_id, direction)
    if steering_profile_id == "force-outer-ipv4":
        forced_source, forced_destination = _directional_pair(
            direction,
            "203.0.113.10",
            "203.0.113.20",
        )
        wrapped_states = [states[0]]
        for index, state in enumerate(states[1:-1], start=1):
            wrapped_states.append(
                _state(
                    (
                        _header(
                            "forced-outer-ipv4",
                            "demo.ipv4.v1",
                            f"User-forced outer IPv4 · TTL {33 - index}",
                            20,
                            source=forced_source,
                            destination=forced_destination,
                            ttl=33 - index,
                            df="set",
                        ),
                        *state.layers,
                    ),
                    state.size.size_bytes + 20,  # type: ignore[union-attr]
                )
            )
        wrapped_states.append(states[-1])
        states = wrapped_states
        actions[-1] = "Remove user-forced wrapper and deliver"
    elif steering_profile_id == "force-mid-wrapper":
        wrapped_states = list(states[:2])
        for state in states[2:-1]:
            wrapped_states.append(
                _state(
                    (
                        _header(
                            "forced-mid-wrapper",
                            "demo.user-mid-wrapper.v1",
                            "User-forced mid-path wrapper",
                            12,
                            policy_id="diagnostic-mid-path-override",
                        ),
                        *state.layers,
                    ),
                    state.size.size_bytes + 12,  # type: ignore[union-attr]
                )
            )
        wrapped_states.append(states[-1])
        states = wrapped_states
        actions[-1] = "Remove mid-path wrapper and deliver"
    transition_count = min(len(step_ids), len(states) - 1)
    if profile_id == "mtu-drop":
        transition_count = 1
    if transition_count <= 0:
        raise ValueError("advanced packet profiles require at least one route step")
    transitions: list[ForwardingPacketTransition] = []
    for index in range(transition_count):
        disposition = (
            ForwardingPacketDisposition.DROP
            if profile_id == "mtu-drop"
            else ForwardingPacketDisposition.DELIVER
            if index == transition_count - 1
            else ForwardingPacketDisposition.CONTINUE
        )
        node_id = str(node_ids[index])
        base = ForwardingPacketTransition(
            transition_id=f"packet-transition:{direction}:{step_ids[index]}",
            step_id=str(step_ids[index]),
            before=states[index],
            after=states[index + 1],
            action_contract_id=f"demo.{profile_id}.v1",
            action_label=actions[index],
            disposition=disposition,
            origin=ForwardingTransitionOrigin.NODE_PLUGIN,
            actor_id=_PLUGIN_ACTOR_BY_NODE[node_id],
            mtu=(
                ForwardingMtuConstraint(
                    basis_contract_id="demo.wire-size.v1",
                    limit_bytes=mtu_limit,
                )
                if mtu_limit is not None
                else None
            ),
        )
        steering_index = (
            1 if steering_profile_id == "force-mid-wrapper" else 0
        )
        if index == steering_index and steering_profile_id != "observed":
            candidate = None
            forced_after = None
            if steering_profile_id == "force-alternate-p2":
                candidate = ResourceKey(
                    namespace="demo",
                    node=node_id,
                    layer="forwarding",
                    kind="NEXTHOP",
                    parts=(("candidate", "transit-p-2"),),
                )
            elif steering_profile_id == "force-outer-ipv4":
                forced_after = states[1]
            elif steering_profile_id == "force-mid-wrapper":
                forced_after = states[index + 1]
            else:
                raise ValueError(
                    f"unknown demo steering profile: {steering_profile_id}"
                )
            rule = ForwardingSteeringRule(
                rule_id=f"demo-user-rule:{steering_profile_id}",
                target_step_id=base.step_id,
                action_contract_id=f"demo.user.{steering_profile_id}.v1",
                reason=next(
                    item["description"]
                    for item in STEERING_PROFILES
                    if item["profile_id"] == steering_profile_id
                ),
                priority=100,
                expected_before=base.before,
                selected_candidate=candidate,
                packet_after=forced_after,
            )
            base = apply_forwarding_steering_rule(
                base,
                rule,
                actor_id="user:advanced-trace-options",
            )
        transitions.append(base)
    return states[0], tuple(transitions)

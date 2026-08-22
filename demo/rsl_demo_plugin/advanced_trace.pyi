from . import PLUGIN_ID as PLUGIN_ID
from .scenario_registry import PACKET_TRACE_SCENARIOS as PACKET_TRACE_SCENARIOS
from collections.abc import Sequence
from router_dump_analyzer.plugin_api import ForwardingPacketState, ForwardingPacketTransition
from typing import Final

ADVANCED_TRACE_SCENARIOS = PACKET_TRACE_SCENARIOS
ADVANCED_TRACE_SCENARIO_IDS: Final[frozenset[str]]
STEERING_PROFILES: tuple[dict[str, str], ...]

def build_packet_transitions(*, profile_id: str, step_ids: Sequence[str], node_ids: Sequence[str], direction: str, steering_profile_id: str = 'observed') -> tuple[ForwardingPacketState, tuple[ForwardingPacketTransition, ...]]: ...

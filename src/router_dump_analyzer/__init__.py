"""Protocol-neutral Router Dump Analyzer core, runtime, and plug-in contracts."""

from .plugin_api import (
    CORE_PLUGIN_API_VERSION,
    FORWARDING_IR_VERSION,
    PLUGIN_ENTRY_POINT_GROUP,
)
from .plugin_loading import (
    load_plugin_entry_point,
    load_plugin_module,
)
from .runtime import (
    CoreRuntimeSession,
    PLUGIN_RUNTIME_CAPABILITY_ID,
    PluginRuntimeCapability,
    PluginRuntimeCapabilityError,
    PluginRuntimeSession,
    RuntimeApplicationFactory,
    RuntimeApplicationRequest,
    RuntimeRouteProvider,
    RuntimeTemporalProvider,
    RuntimeTopologyProvider,
    require_plugin_runtime,
    validate_runtime_session,
)
from .normalized_data import (
    IndexedHistory,
    NormalizedDataPolicy,
    NormalizedDataService,
    NormalizedDatasetSource,
)

__all__ = [
    "CORE_PLUGIN_API_VERSION",
    "CoreRuntimeSession",
    "FORWARDING_IR_VERSION",
    "PLUGIN_ENTRY_POINT_GROUP",
    "PLUGIN_RUNTIME_CAPABILITY_ID",
    "PluginRuntimeCapability",
    "PluginRuntimeCapabilityError",
    "PluginRuntimeSession",
    "RuntimeApplicationFactory",
    "RuntimeApplicationRequest",
    "IndexedHistory",
    "NormalizedDataPolicy",
    "NormalizedDataService",
    "NormalizedDatasetSource",
    "RuntimeRouteProvider",
    "RuntimeTemporalProvider",
    "RuntimeTopologyProvider",
    "load_plugin_entry_point",
    "load_plugin_module",
    "require_plugin_runtime",
    "validate_runtime_session",
]

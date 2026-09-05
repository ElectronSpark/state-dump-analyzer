from .capability_router import CapabilityProviderRef as CapabilityProviderRef
from typing import Any

def materialization_provider_projection(provider: CapabilityProviderRef) -> dict[str, Any]: ...

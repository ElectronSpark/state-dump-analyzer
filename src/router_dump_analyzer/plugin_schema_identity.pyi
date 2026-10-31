from .plugin_api import PluginSchema
from _typeshed import Incomplete
from typing import Any

__all__ = ['MAX_SCHEMA_UNITS', 'MAX_SCHEMA_TEXT_BYTES', 'MAX_SOURCE_RECORD_TYPES', 'PluginSchemaIdentityError', 'snapshot_plugin_schema', 'plugin_schema_dataset', 'plugin_schema_digest']

MAX_SCHEMA_UNITS: int
MAX_SCHEMA_TEXT_BYTES: Incomplete
MAX_SOURCE_RECORD_TYPES: int

class PluginSchemaIdentityError(ValueError): ...

def snapshot_plugin_schema(schema: PluginSchema) -> PluginSchema: ...
def plugin_schema_dataset(schema: PluginSchema) -> dict[str, Any]: ...
def plugin_schema_digest(schema: PluginSchema) -> str: ...

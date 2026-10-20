from collections.abc import Mapping, Sequence
from typing import Any

SOURCE_RECORD_GROUP_DESCRIPTORS: list[dict[str, Any]]
SOURCE_RECORD_DESCRIPTORS: list[dict[str, Any]]
RECORD_LANE_PRESETS: list[dict[str, Any]]

def demo_ctf_copy_text(event: Mapping[str, Any], *, sequence: int | None = None) -> str: ...
def lazy_demo_ctf_source_record(event: Mapping[str, Any]) -> dict[str, Any]: ...
def build_demo_source_records(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]: ...

"""Small normalized source/policy adapters for core service unit tests."""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Mapping

from router_dump_analyzer.normalized_data import NormalizedDataService


class StaticDatasetSource:
    def __init__(self, dataset: dict[str, Any]) -> None:
        self.dataset = dataset

    def revision_scope(self, revision_id: str):
        if revision_id != self.revision_id(self.dataset):
            raise KeyError(revision_id)
        return nullcontext()

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        if revision_id is not None and revision_id != self.revision_id(
            self.dataset
        ):
            raise KeyError(revision_id)
        return self.dataset

    def revision_id(self, dataset: Mapping[str, Any]) -> str:
        workspace = dataset.get("workspace")
        if isinstance(workspace, Mapping) and workspace.get("revision_id"):
            return str(workspace["revision_id"])
        metadata = dataset.get("demo")
        if isinstance(metadata, Mapping) and metadata.get("revision_id"):
            return str(metadata["revision_id"])
        return "test/revision"

    def indexed_history(self, dataset: Mapping[str, Any]):
        return dataset.get("_scale_runtime")


class StaticDataPolicy:
    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        metadata = dataset.get("demo")
        return dict(metadata) if isinstance(metadata, Mapping) else {}

    def workspace_metadata(
        self,
        dataset: Mapping[str, Any],
        *,
        revision_id: str,
        history_mode: str,
    ) -> Mapping[str, Any]:
        metadata = self.analysis_metadata(dataset)
        return {
            "workspace_id": f"test:{revision_id}",
            "revision_id": revision_id,
            "scope": "node",
            "workspace_kind": "node",
            "history_mode": history_mode,
            "capabilities": {
                "historical_state": True,
                "server_windowed_history": (
                    history_mode == "server-windowed"
                ),
            },
            "node_id": str(metadata.get("node") or "test-node"),
            "node_label": str(metadata.get("node_label") or "Test node"),
            "label": str(metadata.get("name") or "Test workspace"),
            "event_count": int(
                metadata.get("event_count", len(dataset.get("events", [])))
            ),
            "matched_event_count": int(
                metadata.get(
                    "matched_event_count",
                    len(dataset.get("events", [])),
                )
            ),
            "resource_count": int(
                metadata.get(
                    "resource_count",
                    len(dataset.get("resources", [])),
                )
            ),
            "source_record_count": int(
                metadata.get(
                    "source_record_count",
                    len(dataset.get("source_records", [])),
                )
            ),
        }

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return {"available": False, "routes": []}

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        raise KeyError(route_id)

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return {
            "source_record_uid": f"source:{event.get('event_uid', 'unknown')}",
            "timestamp_ns": event.get("timestamp_ns"),
            "source_type": "test",
            "record_name": str(event.get("event_type") or "event"),
        }


def static_data_service(dataset: dict[str, Any]) -> NormalizedDataService:
    return NormalizedDataService(
        StaticDatasetSource(dataset),
        StaticDataPolicy(),
    )


__all__ = [
    "StaticDataPolicy",
    "StaticDatasetSource",
    "static_data_service",
]

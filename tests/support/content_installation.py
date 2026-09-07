"""Compose production content primitives for focused install and race tests."""

from __future__ import annotations

from pathlib import Path

from router_dump_analyzer.ingestion_pipeline import (
    DurableIngestionPipeline,
    _PreparedContentFile,
)


def install_content_file(
    pipeline: DurableIngestionPipeline,
    temporary: Path,
    *,
    root: Path,
    relative: Path,
    expected_sha256: str,
    expected_bytes: int,
) -> Path:
    """Prepare and publish one object while always releasing staging ownership."""

    prepared: _PreparedContentFile | None = None
    try:
        prepared = pipeline._prepare_content_file(
            temporary,
            root=root,
            relative=relative,
            expected_sha256=expected_sha256,
            expected_bytes=expected_bytes,
        )
        return pipeline._publish_prepared_content_file(prepared)
    finally:
        pipeline._discard_prepared_content_file(prepared)

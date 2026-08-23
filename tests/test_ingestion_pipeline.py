from __future__ import annotations

import hashlib
import importlib
import json
import multiprocessing
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import fields, replace
from pathlib import Path, PureWindowsPath
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from router_dump_analyzer.artifact_core import ArtifactLimits
from router_dump_analyzer.canonical import canonical_json
from router_dump_analyzer.filesystem_lock import (
    exclusive_file_lock,
    try_exclusive_file_lock,
    try_existing_exclusive_file_lock,
)
from router_dump_analyzer.ingestion import (
    IngestionCoordinator,
    IngestionLimits,
    IngestionResult,
)
from router_dump_analyzer.ingestion_pipeline import (
    PUBLIC_INGESTION_FAILURE_MESSAGES,
    RETENTION_CLEANUP_FENCE_BATCH,
    WINDOWS_DATASET_STAGING_RESERVE_UNITS,
    WINDOWS_FIXTURE_STAGING_PREFIX_RESERVE_UNITS,
    WINDOWS_MAX_STATE_ROOT_UNITS,
    WINDOWS_MAX_USABLE_PATH_UNITS,
    DurableIngestionPipeline,
    ImportConflictError,
    ImportNotFoundError,
    ImportQuotaExceededError,
    ImportScope,
    ImportState,
    IngestionPipelineError,
    IngestionStateRootPathError,
    PipelineLimits,
    PluginExecutionMode,
    PluginExecutionProcessError,
    PluginExecutionTimeoutError,
    PluginRegistry,
    RegisteredPlugin,
    RetentionHostInventoryCoverage,
    RetentionPolicy,
    _execution_plan_for_result,
    _ingest_plugin_child,
    _path_for_containment_comparison,
    _probe_plugin_child,
    _publisher_accepts_execution_plan,
    _register_process_bootstrap,
    _registry_from_process_bootstraps,
    _RetentionWorkItem,
    _run_plugin_child,
    _run_plugin_inline,
    _validate_ingestion_state_root,
    _validate_plugin_child_spawn_args,
    _windows_path_units,
    inspect_durable_queue,
    validate_ingestion_state_root,
)
from router_dump_analyzer.plugin_api import (
    PluginCapability,
    ProbeReport,
    TimelineTimeBasis,
)
from router_dump_analyzer.plugin_composition import (
    PluginCompositionPolicy,
    PluginCompositionRule,
)
from router_dump_analyzer.plugin_execution_plan import (
    DecoderIdentity,
    PluginExecutionPlan,
    plugin_execution_plan_dict,
    plugin_execution_plan_from_dict,
)
from router_dump_analyzer.plugin_identity import PluginExecutableIdentityError
from tests.test_ingestion import (
    DiagnosticPlugin,
    FixedNodePlugin,
    InvalidProbeDiagnosticPlugin,
    ParseOnlyPlugin,
)

PRIVATE_FAILURE_MARKER = "PRIVATE-INGESTION-FAILURE-7f3e2d"


class Boom(BaseException):
    """Adversarial non-process-control throwable supplied by a plug-in."""


class _HostileString(str):
    def __new__(cls, value: str, error: BaseException):
        instance = super().__new__(cls, value)
        instance.error = error
        return instance

    def __len__(self) -> int:
        raise self.error

    def __iter__(self):
        raise self.error

    def __eq__(self, other: object) -> bool:
        del other
        raise self.error

    __hash__ = str.__hash__


class _NoopTraceDecoder:
    def iter_ctf(self, *args: Any, **kwargs: Any) -> tuple[()]:
        del args, kwargs
        return ()


class _FalseyCoordinator(IngestionCoordinator):
    def __bool__(self) -> bool:
        return False


def _fixture_bytes() -> bytes:
    return (
        "\n".join(
            (
                json.dumps(
                    {
                        "captured_at_ns": 100,
                        "ifindex": 7,
                        "name": "xe-0/0/0",
                        "oper_status": "down",
                    }
                ),
                json.dumps(
                    {
                        "captured_at_ns": 200,
                        "ifindex": 7,
                        "name": "xe-0/0/0",
                        "oper_status": "up",
                    }
                ),
            )
        )
        + "\n"
    ).encode()


def _external_process_components_source(marker: str) -> str:
    return (
        "from router_dump_analyzer.ingestion import IngestionCoordinator\n"
        "\n"
        "class ExternalCoordinator(IngestionCoordinator):\n"
        f"    marker = {marker!r}\n"
        "\n"
        "coordinator = ExternalCoordinator()\n"
        "\n"
        "class ExternalDecoder:\n"
        f"    marker = {marker!r}\n"
        "\n"
        "    def iter_ctf(self, *args, **kwargs):\n"
        "        del args, kwargs\n"
        "        return ()\n"
        "\n"
        "decoder = ExternalDecoder()\n"
    )


def _write_content_address(
    root: Path,
    payload: bytes,
    *,
    dataset: bool = False,
) -> tuple[str, Path]:
    digest = hashlib.sha256(payload).hexdigest()
    leaf = f"{digest}.json" if dataset else digest
    reference = f"{digest[:2]}/{digest[2:4]}/{leaf}"
    path = root / Path(reference)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return reference, path


def _install_content_process(
    root_value: str,
    source_value: str,
    digest: str,
    byte_count: int,
    start: Any,
) -> None:
    """Publish one content object from an independent spawned process."""

    pipeline = object.__new__(DurableIngestionPipeline)
    pipeline.limits = PipelineLimits(
        max_upload_bytes=1024 * 1024,
        upload_chunk_bytes=4096,
        max_workers=1,
    )
    if not start.wait(10):
        raise TimeoutError("content install start barrier timed out")
    pipeline._install_content_file(
        Path(source_value),
        root=Path(root_value),
        relative=Path(digest[:2]) / digest[2:4] / digest,
        expected_sha256=digest,
        expected_bytes=byte_count,
    )


def _hold_prepared_content_process(
    state_root_value: str,
    source_value: str,
    digest: str,
    byte_count: int,
    entered: Any,
) -> None:
    """Hold a prepared candidate so its process can be hard-terminated."""

    state_root = Path(state_root_value)
    pipeline = object.__new__(DurableIngestionPipeline)
    pipeline.blob_root = state_root / "blobs"
    pipeline.dataset_root = state_root / "revisions"
    pipeline.content_lock_root = state_root / "locks" / "content"
    pipeline.limits = PipelineLimits(
        max_upload_bytes=1024 * 1024,
        upload_chunk_bytes=4096,
        max_workers=1,
    )
    prepared = pipeline._prepare_content_file(
        Path(source_value),
        root=pipeline.blob_root,
        relative=Path(digest[:2]) / digest[2:4] / digest,
        expected_sha256=digest,
        expected_bytes=byte_count,
    )
    entered.set()
    # Keep both the candidate and its advisory activity lock live. The parent
    # intentionally terminates this process to model an ungraceful crash.
    time.sleep(10)
    pipeline._discard_prepared_content_file(prepared)


def _hold_dynamic_spool_lock_process(
    gate_value: str,
    lock_value: str,
    entered: Any,
    release: Any,
) -> None:
    """Hold one dynamic spool lock from an independent spawned process."""

    pipeline = object.__new__(DurableIngestionPipeline)
    pipeline._spool_namespace_lock_path = Path(gate_value)
    with pipeline._spool_active_file_lock(Path(lock_value)):
        entered.set()
        if not release.wait(10):
            raise TimeoutError("dynamic spool lock release timed out")


class _Publisher:
    def __init__(self) -> None:
        self.fixtures: list[tuple[ImportScope, dict[str, Any]]] = []
        self.revisions: list[tuple[ImportScope, dict[str, Any]]] = []

    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        self.fixtures.append((scope, values))

    def publish_revision(self, scope: ImportScope, **values: Any) -> None:
        self.revisions.append((scope, values))


class _SpawnPickleHostilePublisher(_Publisher):
    def __reduce__(self) -> object:
        raise AssertionError("parent serialized the live catalog publisher")

    def __getstate__(self) -> object:
        raise AssertionError("parent inspected live catalog publisher pickle state")


class _LegacyPublisher(_Publisher):
    """Exact pre-execution-plan publication contract from the prior release."""

    def publish_revision(
        self,
        scope: ImportScope,
        *,
        operation_id: str,
        fixture_id: str,
        source_revision_id: str,
        node_id: str,
        plugin_id: str,
        plugin_version: str,
        dataset_ref: str,
        dataset_sha256: str,
        event_count: int,
        source_record_count: int,
        resource_count: int,
        call_context: Any,
    ) -> None:
        self.revisions.append(
            (
                scope,
                {
                    "operation_id": operation_id,
                    "fixture_id": fixture_id,
                    "source_revision_id": source_revision_id,
                    "node_id": node_id,
                    "plugin_id": plugin_id,
                    "plugin_version": plugin_version,
                    "dataset_ref": dataset_ref,
                    "dataset_sha256": dataset_sha256,
                    "event_count": event_count,
                    "source_record_count": source_record_count,
                    "resource_count": resource_count,
                    "call_context": call_context,
                },
            )
        )


class _PositionalExecutionPlanPublisher:
    def publish_revision(self, scope: ImportScope, execution_plan: Any, /) -> None:
        del scope, execution_plan


class _PositionalExecutionPlanKwargsPublisher:
    def publish_revision(
        self,
        scope: ImportScope,
        execution_plan: Any,
        /,
        **values: Any,
    ) -> None:
        del scope, execution_plan, values


class _LostPublicationResponsePublisher(_Publisher):
    """Model a catalog commit whose first response is lost."""

    def __init__(self) -> None:
        super().__init__()
        self.publications_by_operation: dict[str, dict[str, Any]] = {}
        self.calls = 0

    def publish_revision(
        self,
        scope: ImportScope,
        **values: Any,
    ) -> str:
        self.calls += 1
        operation_id = str(values["operation_id"])
        semantic_values = {
            key: value for key, value in values.items() if key != "call_context"
        }
        prior = self.publications_by_operation.get(operation_id)
        if prior is None:
            self.publications_by_operation[operation_id] = semantic_values
            self.revisions.append((scope, semantic_values))
            raise RuntimeError("catalog response lost after commit")
        if prior != semantic_values:
            raise AssertionError("publication payload changed across retry")
        return f"catalog-{hashlib.sha256(operation_id.encode()).hexdigest()}"


class _LostAdmissionResponsePublisher(_Publisher):
    """Model a fixture catalog commit whose first response is lost."""

    def __init__(self) -> None:
        super().__init__()
        self.admissions_by_operation: dict[str, dict[str, Any]] = {}
        self.calls = 0

    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        self.calls += 1
        operation_id = str(values["operation_id"])
        semantic_values = {
            key: value for key, value in values.items() if key != "call_context"
        }
        prior = self.admissions_by_operation.get(operation_id)
        if prior is None:
            self.admissions_by_operation[operation_id] = semantic_values
            self.fixtures.append((scope, semantic_values))
            raise RuntimeError("catalog admission response lost after commit")
        if prior != semantic_values:
            raise AssertionError("admission payload changed across retry")


class _CountingCoordinator(IngestionCoordinator):
    def __init__(self) -> None:
        super().__init__()
        self.ingest_calls = 0

    def ingest(
        self,
        plugin: Any,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> IngestionResult:
        self.ingest_calls += 1
        return super().ingest(
            plugin,
            input_path,
            node_hint=node_hint,
            metadata=metadata,
        )


class _FailingAdmissionPublisher(_Publisher):
    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        del scope, values
        raise RuntimeError("catalog unavailable")


class _SlowAdmissionPublisher(_Publisher):
    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        time.sleep(0.075)
        super().admit_fixture(scope, **values)


class _SlowPublicationPublisher(_Publisher):
    def publish_revision(self, scope: ImportScope, **values: Any) -> None:
        time.sleep(0.075)
        super().publish_revision(scope, **values)


class _IgnoringDeadlineAdmissionPublisher(_Publisher):
    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        del scope, values
        time.sleep(60)


class _ExplodingCoordinator(IngestionCoordinator):
    def ingest(
        self,
        plugin: Any,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> IngestionResult:
        del plugin, input_path, node_hint, metadata
        raise RuntimeError((PRIVATE_FAILURE_MARKER + "\n") * 2_000)


class _HungCoordinator(IngestionCoordinator):
    def ingest(
        self,
        plugin: Any,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> IngestionResult:
        del plugin, input_path, node_hint, metadata
        while True:
            time.sleep(60)


class _SlowCoordinator(IngestionCoordinator):
    def ingest(
        self,
        plugin: Any,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> IngestionResult:
        time.sleep(0.075)
        return super().ingest(
            plugin,
            input_path,
            node_hint=node_hint,
            metadata=metadata,
        )


class _PragmaFailureConnection:
    def __init__(self) -> None:
        self.row_factory: Any = None
        self.closed = False

    def execute(self, statement: str) -> None:
        del statement
        raise RuntimeError("pragma rejected")

    def close(self) -> None:
        self.closed = True


class _SecondPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.parse-second",
    )


class _NoMatchPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.no-match",
    )

    def probe(self, inventory: Any) -> ProbeReport:
        del inventory
        return ProbeReport(result=None)


class _HungProbePlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.hung-probe",
    )

    def probe(self, inventory: Any) -> ProbeReport:
        del inventory
        while True:
            time.sleep(60)


class _SlowProbePlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.slow-probe",
    )

    def probe(self, inventory: Any) -> ProbeReport:
        time.sleep(0.075)
        return super().probe(inventory)


class _SpawnPickleHostilePlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.spawn-pickle-hostile",
    )

    def __reduce__(self) -> object:
        raise AssertionError("parent serialized the live plug-in instance")

    def __getstate__(self) -> object:
        raise AssertionError("parent inspected live plug-in pickle state")


class _SpawnPickleHostileHungProbePlugin(_SpawnPickleHostilePlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.spawn-pickle-hostile-hung",
    )

    def probe(self, inventory: Any) -> ProbeReport:
        del inventory
        while True:
            time.sleep(60)


class _SpawnPickleHostileCoordinator(IngestionCoordinator):
    def __reduce__(self) -> object:
        raise AssertionError("parent serialized the live coordinator instance")

    def __getstate__(self) -> object:
        raise AssertionError("parent inspected live coordinator pickle state")


class _ConfiguredProcessPlugin(_SpawnPickleHostilePlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.configured-process",
    )

    def __init__(self, mode: str = "default") -> None:
        self.mode = mode


class _ConfiguredProcessCoordinator(IngestionCoordinator):
    def __init__(self, mode: str = "default") -> None:
        super().__init__()
        self.mode = mode


class _ConfiguredProcessDecoder:
    def __init__(self, mode: str = "default") -> None:
        self.mode = mode

    def iter_ctf(self, *args: Any, **kwargs: Any) -> tuple[()]:
        del args, kwargs
        return ()


_CONFIGURED_PROCESS_PLUGIN = _ConfiguredProcessPlugin("configured")
_CONFIGURED_PROCESS_COORDINATOR = _ConfiguredProcessCoordinator("configured")
_CONFIGURED_PROCESS_DECODER = _ConfiguredProcessDecoder("configured")


class _BoundaryProbePlugin(ParseOnlyPlugin):
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def probe(self, inventory: Any) -> ProbeReport:
        del inventory
        raise self.error


class _BoundaryManifestPlugin:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def manifest(self):
        raise self.error


class _BoundaryIterable:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __iter__(self):
        raise self.error


class _BoundaryModuleMeta(type):
    def __getattribute__(cls, name: str):
        if name in {"__module__", "__qualname__"}:
            error = type.__getattribute__(cls, "_boundary_module_error")
            if error is not None:
                raise error
        return super().__getattribute__(name)


class _BoundaryModulePlugin(ParseOnlyPlugin, metaclass=_BoundaryModuleMeta):
    _boundary_module_error: BaseException | None = None


class _BoundaryDecoderCoordinator(IngestionCoordinator):
    def __init__(
        self,
        error: BaseException,
        *,
        trace_decoder: Any | None = None,
    ) -> None:
        object.__setattr__(self, "_boundary_ready", False)
        object.__setattr__(self, "_boundary_error", error)
        object.__setattr__(self, "_fail_decoder_get", False)
        object.__setattr__(self, "_fail_decoder_set", False)
        super().__init__(trace_decoder=trace_decoder)
        object.__setattr__(self, "_boundary_ready", True)

    def __getattribute__(self, name: str):
        if (
            name == "trace_decoder"
            and object.__getattribute__(self, "_boundary_ready")
            and object.__getattribute__(self, "_fail_decoder_get")
        ):
            raise object.__getattribute__(self, "_boundary_error")
        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if (
            name == "trace_decoder"
            and object.__getattribute__(self, "_boundary_ready")
            and object.__getattribute__(self, "_fail_decoder_set")
        ):
            raise object.__getattribute__(self, "_boundary_error")
        super().__setattr__(name, value)


class _BoundaryChildConnection:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[bytes] = []

    def send_bytes(self, payload: bytes) -> None:
        self.sent.append(payload)

    def close(self) -> None:
        self.closed = True


class _BoundaryChildRegistry:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def probe(self, *args: Any, **kwargs: Any) -> tuple[()]:
        del args, kwargs
        raise self.error


class _BoundaryChildCoordinator(IngestionCoordinator):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def ingest(self, *args: Any, **kwargs: Any) -> IngestionResult:
        del args, kwargs
        raise self.error


class DurableIngestionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = ImportScope("tenant-a", "project-a", "workspace-a")
        self.other_scope = ImportScope(
            "tenant-b",
            "project-a",
            "workspace-a",
        )

    @staticmethod
    def _limits() -> PipelineLimits:
        return PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            lease_seconds=30,
            poll_interval_seconds=0.01,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )

    def test_inline_plugin_boundary_contains_boom_and_preserves_process_controls(
        self,
    ) -> None:
        supplied = r"inline plug-in failed at C:\private\tenant\plugin.py"

        def explode(error: BaseException) -> None:
            raise error

        with self.assertRaises(PluginExecutionProcessError) as caught:
            _run_plugin_inline(
                lambda: explode(Boom(supplied)),
                stage="probe",
            )
        self.assertEqual(
            str(caught.exception),
            "plug-in probe failed during trusted inline execution",
        )
        self.assertNotIn(supplied, str(caught.exception))
        self.assertEqual(caught.exception.private_exception_type, "Boom")

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(
                exception_type=exception_type.__name__
            ), self.assertRaises(exception_type):
                _run_plugin_inline(
                    lambda exception_type=exception_type: explode(
                        exception_type("process control")
                    ),
                    stage="probe",
                )

    def test_registry_plugin_boundaries_contain_boom_and_preserve_process_controls(
        self,
    ) -> None:
        supplied = r"registry plug-in failed at C:\private\tenant\plugin.py"
        registry = PluginRegistry(allow_manifest_identity=True)
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "could not resolve required descriptors",
        ) as caught:
            registry.register(
                _BoundaryManifestPlugin(Boom(supplied)),
                package_hash="sha256:" + ("a" * 64),
            )
        self.assertNotIn(supplied, str(caught.exception))

        with self.assertRaises(KeyboardInterrupt):
            registry.register(
                _BoundaryManifestPlugin(KeyboardInterrupt("process control")),
                package_hash="sha256:" + ("a" * 64),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "status.jsonl"
            fixture.write_bytes(_fixture_bytes())

            boom_registry = PluginRegistry(allow_manifest_identity=True)
            boom_registry.register(
                _BoundaryProbePlugin(Boom(supplied)),
                package_hash="sha256:" + ("a" * 64),
            )
            self.assertEqual(boom_registry.probe(fixture), ())

            process_registry = PluginRegistry(allow_manifest_identity=True)
            process_registry.register(
                _BoundaryProbePlugin(SystemExit("process control")),
                package_hash="sha256:" + ("a" * 64),
            )
            with self.assertRaises(SystemExit):
                process_registry.probe(fixture)

    def test_registry_execution_identity_resolution_contains_hostile_descriptors(
        self,
    ) -> None:
        supplied = r"identity resolution failed at C:\private\tenant\plugin.py"
        package_hash = "sha256:" + ("a" * 64)

        manifest_plugin = ParseOnlyPlugin()
        hostile_manifest = replace(manifest_plugin.manifest)
        object.__setattr__(
            hostile_manifest,
            "supported_platforms",
            _BoundaryIterable(Boom(supplied)),
        )
        manifest_plugin.manifest = hostile_manifest
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "could not resolve required descriptors",
        ) as manifest_failure:
            PluginRegistry().register(
                manifest_plugin,
                package_hash=package_hash,
            )

        _BoundaryModulePlugin._boundary_module_error = Boom(supplied)
        try:
            with self.assertRaisesRegex(
                IngestionPipelineError,
                "module identity could not be resolved",
            ) as module_failure:
                PluginRegistry().register(
                    _BoundaryModulePlugin(),
                    package_hash=package_hash,
                )
        finally:
            _BoundaryModulePlugin._boundary_module_error = None

        decoder_identity = DecoderIdentity(
            decoder_id="tests.decoder",
            decoder_version="1",
            executable_digest="sha256:" + ("d" * 64),
        )
        get_coordinator = _BoundaryDecoderCoordinator(Boom(supplied))
        get_coordinator._fail_decoder_get = True
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "trace_decoder descriptor could not be resolved",
        ) as decoder_get_failure:
            PluginRegistry().register(
                ParseOnlyPlugin(),
                coordinator=get_coordinator,
                package_hash=package_hash,
            )

        set_coordinator = _BoundaryDecoderCoordinator(
            Boom(supplied),
            trace_decoder=_NoopTraceDecoder(),
        )
        set_coordinator._fail_decoder_set = True
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "trace_decoder binding could not be installed",
        ) as decoder_set_failure:
            PluginRegistry().register(
                ParseOnlyPlugin(),
                coordinator=set_coordinator,
                package_hash=package_hash,
                decoder_identity=decoder_identity,
            )

        revalidation_coordinator = _BoundaryDecoderCoordinator(Boom(supplied))
        record = PluginRegistry().register(
            ParseOnlyPlugin(),
            coordinator=revalidation_coordinator,
            package_hash=package_hash,
        )
        revalidation_coordinator._fail_decoder_get = True
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "trace decoder binding could not be revalidated",
        ) as decoder_revalidation_failure:
            PluginRegistry.revalidate_registered_identity(record)

        for caught in (
            manifest_failure,
            module_failure,
            decoder_get_failure,
            decoder_set_failure,
            decoder_revalidation_failure,
        ):
            self.assertNotIn(supplied, str(caught.exception))

        process_manifest = replace(ParseOnlyPlugin.manifest)
        object.__setattr__(
            process_manifest,
            "supported_platforms",
            _BoundaryIterable(KeyboardInterrupt("process control")),
        )
        process_plugin = ParseOnlyPlugin()
        process_plugin.manifest = process_manifest
        with self.assertRaises(KeyboardInterrupt):
            PluginRegistry().register(
                process_plugin,
                package_hash=package_hash,
            )

    def test_child_plugin_boundaries_preserve_process_control_exceptions(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(
                boundary="probe",
                exception_type=exception_type.__name__,
            ):
                connection = _BoundaryChildConnection()
                with (
                    patch(
                        "router_dump_analyzer.ingestion_pipeline."
                        "_registry_from_process_bootstraps",
                        return_value=_BoundaryChildRegistry(
                            exception_type("process control")
                        ),
                    ),
                    self.assertRaises(exception_type),
                ):
                    _probe_plugin_child(connection, (), "unused", None, {})
                self.assertTrue(connection.closed)
                self.assertEqual(connection.sent, [])

            with self.subTest(
                boundary="ingest",
                exception_type=exception_type.__name__,
            ):
                connection = _BoundaryChildConnection()
                with (
                    patch(
                        "router_dump_analyzer.ingestion_pipeline."
                        "_register_process_bootstrap",
                        side_effect=exception_type("process control"),
                    ),
                    self.assertRaises(exception_type),
                ):
                    _ingest_plugin_child(
                        connection,
                        object(),  # type: ignore[arg-type]
                        "unused",
                        None,
                        {},
                        "unused",
                    )
                self.assertTrue(connection.closed)
                self.assertEqual(connection.sent, [])

    def _admit_staged(
        self,
        pipeline: DurableIngestionPipeline,
        import_id: str,
    ) -> None:
        claim = pipeline._claim()
        assert claim is not None
        self.assertEqual(claim["import_id"], import_id)
        self.assertEqual(claim["state"], ImportState.ADMITTING.value)
        pipeline._run_admission(claim)

    def _peer_thread_can_acquire(self, path: Path) -> bool:
        outcomes: list[bool] = []

        def attempt() -> None:
            with try_exclusive_file_lock(path) as acquired:
                outcomes.append(acquired)

        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive(), "peer lock probe did not finish")
        self.assertEqual(len(outcomes), 1)
        return outcomes[0]

    @staticmethod
    def _child_root_with_windows_units(
        base: Path,
        target_units: int,
        *,
        fill: str = "s",
    ) -> Path:
        base = base.resolve()
        remaining = target_units - _windows_path_units(base) - 1
        if not 1 <= remaining <= 255:
            raise AssertionError("test base cannot represent the requested path length")
        candidate = base / (fill * remaining)
        if _windows_path_units(candidate) != target_units:
            raise AssertionError("constructed test root has the wrong path length")
        return candidate

    def test_windows_path_budget_covers_the_deepest_core_owned_candidate(
        self,
    ) -> None:
        digest = "a" * 64
        token = "b" * 32
        relatives = {
            "dataset candidate": PureWindowsPath(
                "revisions",
                "aa",
                "aa",
                f".{digest}.json.{token}.partial",
            ),
            "blob candidate": PureWindowsPath(
                "blobs",
                "aa",
                "aa",
                f".{digest}.{token}.partial",
            ),
            "dataset child active lock": PureWindowsPath(
                "spool",
                f".{token}.dataset.child.partial.active.lock",
            ),
            "content activity lock": PureWindowsPath(
                "locks",
                "content",
                "dataset",
                "staging",
                f"{token}.active.lock",
            ),
            "content install lock": PureWindowsPath(
                "locks",
                "content",
                "dataset",
                "aa",
                f"{digest}.install.lock",
            ),
        }
        reserves = {
            name: 1 + _windows_path_units(path) for name, path in relatives.items()
        }

        self.assertEqual(
            max(reserves, key=reserves.__getitem__),
            "dataset candidate",
        )
        self.assertEqual(
            reserves["dataset candidate"],
            WINDOWS_DATASET_STAGING_RESERVE_UNITS,
        )
        self.assertEqual(WINDOWS_DATASET_STAGING_RESERVE_UNITS, 128)
        self.assertEqual(WINDOWS_MAX_STATE_ROOT_UNITS, 131)
        self.assertEqual(
            WINDOWS_MAX_STATE_ROOT_UNITS + WINDOWS_DATASET_STAGING_RESERVE_UNITS,
            WINDOWS_MAX_USABLE_PATH_UNITS,
        )
        self.assertEqual(WINDOWS_FIXTURE_STAGING_PREFIX_RESERVE_UNITS, 93)

    def test_state_root_preflight_is_windows_only(self) -> None:
        long_root = Path("p" * (WINDOWS_MAX_STATE_ROOT_UNITS + 32))
        resolved = _validate_ingestion_state_root(
            long_root,
            platform_name="posix",
        )
        self.assertGreater(
            _windows_path_units(resolved),
            WINDOWS_MAX_STATE_ROOT_UNITS,
        )

    def test_state_root_resolution_error_does_not_disclose_host_path(self) -> None:
        private_path = r"C:\Users\private\durable-state"
        for error in (
            OSError(123, "invalid path", private_path),
            ValueError(f"embedded NUL in {private_path}"),
        ):
            with (
                self.subTest(error_type=type(error).__name__),
                patch.object(Path, "resolve", side_effect=error),
                self.assertRaises(IngestionStateRootPathError) as raised,
            ):
                validate_ingestion_state_root(Path("state"))

            self.assertNotIn(private_path, str(raised.exception))
            self.assertIn("could not be resolved safely", str(raised.exception))

    def test_exact_idempotent_replay_does_not_revalidate_fixture_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
                idempotency_key="path-relocation-replay",
            )

            with patch.object(
                pipeline,
                "_validate_fixture_basename_path_budget",
                side_effect=AssertionError("replay tried to create a fixture path"),
            ):
                replayed = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="path-relocation-replay",
                )

            self.assertEqual(replayed.import_id, admitted.import_id)

    @unittest.skipUnless(os.name == "nt", "exercises the Windows path budget")
    def test_state_root_preflight_fails_before_filesystem_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            accepted_root = self._child_root_with_windows_units(
                base,
                WINDOWS_MAX_STATE_ROOT_UNITS,
                fill="a",
            )
            pipeline = DurableIngestionPipeline(
                accepted_root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            self.assertEqual(_windows_path_units(pipeline.root), 131)

            rejected_root = self._child_root_with_windows_units(
                base,
                WINDOWS_MAX_STATE_ROOT_UNITS + 1,
                fill="r",
            )
            with self.assertRaises(IngestionStateRootPathError) as raised:
                DurableIngestionPipeline(
                    rejected_root,
                    registry=PluginRegistry((ParseOnlyPlugin(),)),
                    publisher=_Publisher(),
                    limits=self._limits(),
                )
            detail = str(raised.exception)
            self.assertIn("resolved length 132", detail)
            self.assertIn("supported maximum of 131", detail)
            self.assertIn("reserve 128", detail)
            self.assertIn("259-unit path budget", detail)
            self.assertIn("shorter --state-dir", detail)
            self.assertNotIn(str(rejected_root), detail)
            self.assertFalse(rejected_root.exists())

    @unittest.skipUnless(os.name == "nt", "exercises the Windows path budget")
    def test_exact_windows_state_root_budget_completes_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._child_root_with_windows_units(
                Path(directory),
                WINDOWS_MAX_STATE_ROOT_UNITS,
                fill="b",
            )
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertIsNotNone(completed.revision_id)
            datasets = tuple((root / "revisions").rglob("*.json"))
            self.assertEqual(len(datasets), 1)
            self.assertTrue(datasets[0].is_file())

    @unittest.skipUnless(os.name == "nt", "exercises the Windows path budget")
    def test_fixture_basename_budget_is_checked_before_upload_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._child_root_with_windows_units(
                Path(directory),
                WINDOWS_MAX_STATE_ROOT_UNITS,
                fill="f",
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            maximum = (
                WINDOWS_MAX_USABLE_PATH_UNITS
                - _windows_path_units(root)
                - WINDOWS_FIXTURE_STAGING_PREFIX_RESERVE_UNITS
            )
            self.assertEqual(maximum, 35)
            too_long = "n" * (maximum - 1) + "\U0001f600"

            with self.assertRaises(IngestionPipelineError) as raised:
                pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name=too_long,
                )
            detail = str(raised.exception)
            self.assertIn("length 36 UTF-16 code units", detail)
            self.assertIn("supported maximum of 35", detail)
            self.assertNotIn(str(root), detail)
            self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())
            self.assertEqual(tuple(pipeline.blob_root.rglob("*")), ())
            self.assertEqual(tuple(pipeline.fixture_root.iterdir()), ())

            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="n" * maximum,
            )
            self.assertEqual(admitted.state, ImportState.ADMITTING)

    def test_upload_uses_a_bounded_activity_lock_under_a_deep_state_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target_root_characters = 128
            component_characters = max(
                8,
                target_root_characters - len(str(base)) - 1,
            )
            root = base / ("s" * component_characters)
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            payload = _fixture_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            token = "1" * 32
            legacy_lock = (
                pipeline.content_lock_root
                / "blob"
                / "staging"
                / f"{digest}.{token}.active.lock"
            )
            bounded_activity_lock = pipeline._content_staging_activity_lock(
                "blob",
                digest,
                token,
            )
            activity_lock = bounded_activity_lock

            self.assertGreater(len(str(legacy_lock)), 260)
            self.assertLess(len(str(activity_lock)), 220)
            self.assertEqual(
                activity_lock,
                pipeline._content_staging_activity_lock("blob", digest, token),
            )
            self.assertNotEqual(
                activity_lock,
                pipeline._content_staging_activity_lock(
                    "dataset",
                    digest,
                    token,
                ),
            )
            self.assertNotEqual(
                activity_lock,
                pipeline._content_staging_activity_lock(
                    "blob",
                    "2" * 64,
                    token,
                ),
            )

            admitted = pipeline.submit_bytes(
                self.scope,
                payload,
                original_name="deep-state-root.jsonl",
            )

            self.assertEqual(admitted.state, ImportState.ADMITTING)
            self.assertEqual(admitted.content_sha256, digest)

    def test_stall_threshold_covers_bounded_execution_and_heartbeats(self) -> None:
        self.assertIs(
            PipelineLimits().plugin_execution_mode,
            PluginExecutionMode.PROCESS,
        )
        self.assertIs(
            PipelineLimits().effective_publisher_execution_mode,
            PluginExecutionMode.PROCESS,
        )
        self.assertIs(
            self._limits().effective_publisher_execution_mode,
            PluginExecutionMode.INLINE,
        )
        with self.assertRaisesRegex(
            ValueError,
            "plug-in execution timeout plus two lease heartbeats",
        ):
            PipelineLimits(
                lease_seconds=30,
                plugin_execution_timeout_seconds=10,
                stalled_import_seconds=19.99,
            )
        limits = PipelineLimits(
            lease_seconds=30,
            plugin_execution_timeout_seconds=10,
            stalled_import_seconds=20,
        )
        self.assertEqual(limits.stalled_import_seconds, 20)

    def test_upload_probe_ingest_and_publish_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="ci-run-1",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(completed.node_id, "router-a")
            self.assertTrue(completed.revision_id)
            self.assertEqual(len(publisher.fixtures), 1)
            self.assertEqual(len(publisher.revisions), 1)
            execution_plan = publisher.revisions[0][1]["execution_plan"]
            self.assertIsInstance(execution_plan, PluginExecutionPlan)
            assert isinstance(execution_plan, PluginExecutionPlan)
            self.assertEqual(execution_plan.node_id, "router-a")
            self.assertEqual(
                execution_plan.basis_revision_id,
                publisher.revisions[0][1]["source_revision_id"],
            )
            self.assertEqual(len(execution_plan.plugins), 1)
            self.assertEqual(execution_plan.plugins[0].plugin_id, "tests.parse-only")
            with pipeline._connect() as connection:
                staged_row = connection.execute(
                    "SELECT staged_execution_plan_json, "
                    "staged_execution_plan_digest FROM ingestion_imports "
                    "WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            self.assertEqual(
                staged_row["staged_execution_plan_digest"],
                execution_plan.plan_digest,
            )
            self.assertEqual(
                json.loads(staged_row["staged_execution_plan_json"])["plan_digest"],
                execution_plan.plan_digest,
            )
            self.assertTrue(
                (
                    Path(directory)
                    / "revisions"
                    / publisher.revisions[0][1]["dataset_ref"]
                ).is_file()
            )
            dataset = json.loads(
                (
                    Path(directory)
                    / "revisions"
                    / publisher.revisions[0][1]["dataset_ref"]
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                dataset["_ingestion"]["plugin_execution_plan_digest"],
                execution_plan.plan_digest,
            )

            reopened = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            persisted = reopened.get_import(
                self.scope,
                admitted.import_id,
            )
            self.assertEqual(persisted.state, ImportState.COMPLETED)
            self.assertEqual(
                [
                    item.event_type
                    for item in reopened.events(
                        self.scope,
                        admitted.import_id,
                    )
                ],
                [
                    "upload_staged",
                    "admission_started",
                    "upload_admitted",
                    "probe_started",
                    "plugin_auto_selected",
                    "ingestion_started",
                    "revision_staged",
                    "publication_started",
                    "revision_published",
                ],
            )

    def test_admission_telemetry_brackets_the_durable_catalog_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            claim = pipeline._claim()
            assert claim is not None
            operation_id = f"admission:{admitted.import_id}"
            observations: list[
                tuple[str, dict[str, Any], ImportState, tuple[str, ...], int]
            ] = []

            def observe(event: str, /, **fields: Any) -> bool:
                descriptor = pipeline.get_import(
                    self.scope,
                    admitted.import_id,
                )
                event_types = tuple(
                    item.event_type
                    for item in pipeline.events(
                        self.scope,
                        admitted.import_id,
                    )
                )
                with pipeline._connect() as connection:
                    pin_count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_artifact_pins "
                            "WHERE owner_operation_id = ?",
                            (operation_id,),
                        ).fetchone()[0]
                    )
                observations.append(
                    (event, dict(fields), descriptor.state, event_types, pin_count)
                )
                return True

            with patch(
                "router_dump_analyzer.ingestion_pipeline.emit_operational_event",
                side_effect=observe,
            ):
                pipeline._run_admission(claim)

            self.assertEqual(len(observations), 2)
            started, completed = observations
            self.assertEqual(started[0], "ingestion.catalog_call.started")
            self.assertEqual(
                started[1],
                {
                    "import_id": admitted.import_id,
                    "stage": "admission",
                    "operation_id": operation_id,
                    "attempt": 1,
                    "timeout_ms": 300_000,
                },
            )
            self.assertIs(started[2], ImportState.ADMITTING)
            self.assertNotIn("upload_admitted", started[3])
            self.assertEqual(started[4], 1)

            self.assertEqual(completed[0], "ingestion.catalog_call.completed")
            self.assertEqual(
                set(completed[1]),
                {
                    "import_id",
                    "stage",
                    "operation_id",
                    "attempt",
                    "duration_ms",
                    "next_state",
                },
            )
            self.assertEqual(
                {
                    key: value
                    for key, value in completed[1].items()
                    if key != "duration_ms"
                },
                {
                    "import_id": admitted.import_id,
                    "stage": "admission",
                    "operation_id": operation_id,
                    "attempt": 1,
                    "next_state": "queued",
                },
            )
            self.assertIs(type(completed[1]["duration_ms"]), int)
            self.assertGreaterEqual(completed[1]["duration_ms"], 0)
            self.assertIs(completed[2], ImportState.QUEUED)
            self.assertIn("upload_admitted", completed[3])
            self.assertEqual(completed[4], 1)

    def test_failure_telemetry_is_emitted_only_after_failed_state_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            claim = pipeline._claim()
            assert claim is not None
            observations: list[
                tuple[str, dict[str, Any], ImportState, int, tuple[str, ...]]
            ] = []

            def observe(event: str, /, **fields: Any) -> bool:
                descriptor = pipeline.get_import(
                    self.scope,
                    admitted.import_id,
                )
                observations.append(
                    (
                        event,
                        dict(fields),
                        descriptor.state,
                        descriptor.attempt_count,
                        tuple(
                            item.event_type
                            for item in pipeline.events(
                                self.scope,
                                admitted.import_id,
                            )
                        ),
                    )
                )
                return True

            with patch(
                "router_dump_analyzer.ingestion_pipeline.emit_operational_event",
                side_effect=observe,
            ):
                pipeline._fail_claimed_import(
                    claim,
                    RuntimeError("private catalog diagnostic"),
                )

            self.assertEqual(
                observations,
                [
                    (
                        "ingestion.attempt.failed",
                        {
                            "import_id": admitted.import_id,
                            "stage": "admission",
                            "attempt": 1,
                            "error_code": "worker_failure",
                            "retryable": True,
                            "ambiguous_external_outcome": False,
                            "operation_id": f"admission:{admitted.import_id}",
                        },
                        ImportState.FAILED,
                        1,
                        ("upload_staged", "admission_started", "import_failed"),
                    )
                ],
            )
            self.assertNotIn("private catalog diagnostic", repr(observations))

    def test_stale_catalog_acknowledgement_is_discarded_after_lease_handoff(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            claim = pipeline._claim()
            assert claim is not None
            operation_id = f"admission:{admitted.import_id}"
            observations: list[
                tuple[str, dict[str, Any], ImportState, str | None, tuple[str, ...]]
            ] = []

            def acknowledge_after_lease_handoff(
                scope: ImportScope,
                **values: Any,
            ) -> None:
                del scope, values
                with pipeline._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "UPDATE ingestion_imports SET lease_owner = ? "
                        "WHERE import_id = ?",
                        ("replacement-worker", admitted.import_id),
                    )
                    connection.commit()

            def observe(event: str, /, **fields: Any) -> bool:
                descriptor = pipeline.get_import(
                    self.scope,
                    admitted.import_id,
                )
                with pipeline._connect() as connection:
                    row = connection.execute(
                        "SELECT lease_owner FROM ingestion_imports WHERE import_id = ?",
                        (admitted.import_id,),
                    ).fetchone()
                assert row is not None
                observations.append(
                    (
                        event,
                        dict(fields),
                        descriptor.state,
                        (
                            str(row["lease_owner"])
                            if row["lease_owner"] is not None
                            else None
                        ),
                        tuple(
                            item.event_type
                            for item in pipeline.events(
                                self.scope,
                                admitted.import_id,
                            )
                        ),
                    )
                )
                return True

            with (
                patch.object(
                    publisher,
                    "admit_fixture",
                    side_effect=acknowledge_after_lease_handoff,
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.emit_operational_event",
                    side_effect=observe,
                ),
            ):
                pipeline._run_admission(claim)

            self.assertEqual(len(observations), 2)
            self.assertEqual(observations[0][0], "ingestion.catalog_call.started")
            discarded = observations[1]
            self.assertEqual(discarded[0], "ingestion.catalog_call.discarded")
            self.assertEqual(
                set(discarded[1]),
                {
                    "import_id",
                    "stage",
                    "operation_id",
                    "attempt",
                    "duration_ms",
                    "reason",
                    "remote_acknowledged",
                },
            )
            self.assertEqual(
                {
                    key: value
                    for key, value in discarded[1].items()
                    if key != "duration_ms"
                },
                {
                    "import_id": admitted.import_id,
                    "stage": "admission",
                    "operation_id": operation_id,
                    "attempt": 1,
                    "reason": "lease_lost",
                    "remote_acknowledged": True,
                },
            )
            self.assertIs(type(discarded[1]["duration_ms"]), int)
            self.assertGreaterEqual(discarded[1]["duration_ms"], 0)
            self.assertIs(discarded[2], ImportState.ADMITTING)
            self.assertEqual(discarded[3], "replacement-worker")
            self.assertNotIn("upload_admitted", discarded[4])

    def test_lost_publication_response_retries_without_reingestion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _LostPublicationResponsePublisher()
            coordinator = _CountingCoordinator()
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                coordinator=coordinator,
            )
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=publisher,
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertEqual(failed.state, ImportState.FAILED)
                self.assertEqual(coordinator.ingest_calls, 1)
                resumed = pipeline.resume(
                    self.scope,
                    admitted.import_id,
                )
                self.assertEqual(resumed.state, ImportState.PUBLISHING)
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(coordinator.ingest_calls, 1)
            self.assertEqual(publisher.calls, 2)
            self.assertEqual(len(publisher.revisions), 1)
            replayed_plan = publisher.revisions[0][1]["execution_plan"]
            self.assertIsInstance(replayed_plan, PluginExecutionPlan)
            with pipeline._connect() as connection:
                staged_digest = connection.execute(
                    "SELECT staged_execution_plan_digest "
                    "FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()[0]
            self.assertEqual(replayed_plan.plan_digest, staged_digest)
            operation_ids = {
                event.payload.get("operation_id")
                for event in pipeline.events(
                    self.scope,
                    admitted.import_id,
                )
                if event.event_type in {"revision_staged", "revision_published"}
            }
            self.assertEqual(
                operation_ids,
                {f"publication:{admitted.import_id}"},
            )

    def test_execution_plan_changes_with_package_configuration_and_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            coordinator = IngestionCoordinator()
            plugin = ParseOnlyPlugin()
            result = coordinator.ingest(plugin, input_path)

            def registered(
                package_character: str,
                configuration_character: str,
            ) -> RegisteredPlugin:
                registry = PluginRegistry()
                return registry.register(
                    plugin,
                    coordinator=coordinator,
                    package_hash="module-sha256:" + package_character * 64,
                    configuration_digest=(
                        "sha256:" + configuration_character * 64
                    ),
                )

            baseline = _execution_plan_for_result(registered("1", "a"), result)
            package_changed = _execution_plan_for_result(
                registered("2", "a"), result
            )
            configuration_changed = _execution_plan_for_result(
                registered("1", "b"), result
            )
            changed_dataset = dict(result.dataset)
            changed_schema = dict(changed_dataset["schema"])
            changed_schema["test_extension"] = "changed"
            changed_dataset["schema"] = changed_schema
            schema_changed = _execution_plan_for_result(
                registered("1", "a"),
                replace(result, dataset=changed_dataset),
            )

            self.assertEqual(
                len(
                    {
                        baseline.plan_digest,
                        package_changed.plan_digest,
                        configuration_changed.plan_digest,
                        schema_changed.plan_digest,
                    }
                ),
                4,
            )

    def test_catalog_admission_deadline_is_durable_and_pins_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_SlowAdmissionPublisher(),
                limits=replace(
                    self._limits(),
                    publisher_execution_timeout_seconds=0.05,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=5,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "catalog_execution_timeout")
            self.assertTrue(failed.retryable)
            with pipeline._connect() as connection:
                pins = connection.execute(
                    "SELECT artifact_kind, artifact_ref FROM ingestion_artifact_pins"
                ).fetchall()
            self.assertEqual(len(pins), 1)
            self.assertEqual(str(pins[0]["artifact_kind"]), "blob")
            self.assertEqual(pipeline.worker_health().catalog_attention_imports, 1)

    def test_catalog_process_deadline_kills_uncooperative_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_IgnoringDeadlineAdmissionPublisher(),
                limits=replace(
                    self._limits(),
                    publisher_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_timeout_seconds=0.05,
                ),
            )
            started = time.monotonic()
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=5,
                )
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 3.0)
            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "catalog_execution_timeout")
            self.assertEqual(pipeline.worker_health().catalog_attention_imports, 1)
            self.assertFalse(
                any(
                    child.name.startswith("rda-catalog-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_catalog_process_never_serializes_live_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_SpawnPickleHostilePublisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.PROCESS,
                    plugin_execution_timeout_seconds=30,
                    publisher_execution_timeout_seconds=30,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=60,
                )

        self.assertEqual(completed.state, ImportState.COMPLETED)
        self.assertFalse(
            any(
                child.name.startswith("rda-catalog-")
                for child in multiprocessing.active_children()
            )
        )

    def test_catalog_publication_deadline_is_durable_and_pins_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_SlowPublicationPublisher(),
                limits=replace(
                    self._limits(),
                    publisher_execution_timeout_seconds=0.05,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=5,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "catalog_execution_timeout")
            self.assertTrue(failed.retryable)
            with pipeline._connect() as connection:
                pins = connection.execute(
                    "SELECT artifact_kind, artifact_ref "
                    "FROM ingestion_artifact_pins ORDER BY artifact_kind"
                ).fetchall()
            self.assertEqual(
                [str(row["artifact_kind"]) for row in pins],
                ["blob", "dataset"],
            )
            self.assertEqual(pipeline.worker_health().catalog_attention_imports, 1)

    def test_lost_admission_response_replays_exact_staged_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _LostAdmissionResponsePublisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertEqual(failed.state, ImportState.FAILED)
                resumed = pipeline.resume(
                    self.scope,
                    admitted.import_id,
                )
                self.assertEqual(resumed.state, ImportState.ADMITTING)
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(publisher.calls, 2)
            self.assertEqual(len(publisher.fixtures), 1)
            operation_ids = {
                event.payload.get("operation_id")
                for event in pipeline.events(
                    self.scope,
                    admitted.import_id,
                )
                if event.event_type in {"upload_staged", "upload_admitted"}
            }
            self.assertEqual(
                operation_ids,
                {f"admission:{admitted.import_id}"},
            )

    def test_multiple_candidates_require_stale_safe_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(), _SecondPlugin())),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    auto_select=False,
                )
                awaiting = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertEqual(
                    awaiting.state,
                    ImportState.AWAITING_SELECTION,
                )
                candidates = pipeline.candidates(
                    self.scope,
                    awaiting.import_id,
                )
                self.assertEqual(len(candidates), 2)
                selected = candidates[0]
                with self.assertRaisesRegex(
                    ImportConflictError,
                    "stale",
                ):
                    pipeline.select_plugin(
                        self.scope,
                        awaiting.import_id,
                        probe_set_hash="sha256:stale",
                        plugin_id=selected.plugin_id,
                        plugin_version=selected.plugin_version,
                        package_hash=selected.package_hash,
                        idempotency_key="selection-1",
                    )
                ready = pipeline.select_plugin(
                    self.scope,
                    awaiting.import_id,
                    probe_set_hash=str(awaiting.probe_set_hash),
                    plugin_id=selected.plugin_id,
                    plugin_version=selected.plugin_version,
                    package_hash=selected.package_hash,
                    idempotency_key="selection-1",
                )
                repeated = pipeline.select_plugin(
                    self.scope,
                    awaiting.import_id,
                    probe_set_hash=str(awaiting.probe_set_hash),
                    plugin_id=selected.plugin_id,
                    plugin_version=selected.plugin_version,
                    package_hash=selected.package_hash,
                    idempotency_key="selection-1",
                )
                self.assertEqual(ready.import_id, repeated.import_id)
                different = candidates[1]
                with self.assertRaisesRegex(
                    ImportConflictError,
                    "different plug-in selection request",
                ):
                    pipeline.select_plugin(
                        self.scope,
                        awaiting.import_id,
                        probe_set_hash=str(awaiting.probe_set_hash),
                        plugin_id=different.plugin_id,
                        plugin_version=different.plugin_version,
                        package_hash=different.package_hash,
                        idempotency_key="selection-1",
                    )
                completed = pipeline.wait(
                    self.scope,
                    awaiting.import_id,
                    timeout=10,
                )
                self.assertEqual(completed.state, ImportState.COMPLETED)

    def test_probe_order_is_independent_of_registration_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            first_registry = PluginRegistry((ParseOnlyPlugin(), _SecondPlugin()))
            second_registry = PluginRegistry((_SecondPlugin(), ParseOnlyPlugin()))
            first = first_registry.probe(input_path)
            second = second_registry.probe(input_path)

            self.assertEqual(first, second)
            self.assertEqual(
                first_registry.fingerprint(),
                second_registry.fingerprint(),
            )
            self.assertEqual(
                [candidate.plugin_id for candidate in first],
                sorted(candidate.plugin_id for candidate in first),
            )

    def test_probe_uses_the_registered_ingestion_artifact_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            coordinator = IngestionCoordinator(
                limits=IngestionLimits(
                    artifact_limits=ArtifactLimits(max_artifact_bytes=16)
                )
            )
            registry = PluginRegistry()
            registry.register(ParseOnlyPlugin(), coordinator=coordinator)

            self.assertEqual(registry.probe(input_path), ())

    def test_probe_revalidates_diagnostics_before_selecting_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            for failure in ("stage", "bool"):
                with self.subTest(failure=failure):
                    registry = PluginRegistry((InvalidProbeDiagnosticPlugin(failure),))
                    self.assertEqual(registry.probe(input_path), ())

    def test_registry_prefers_package_fingerprint_and_honors_loader_digest(
        self,
    ) -> None:
        derived = PluginRegistry((ParseOnlyPlugin(),))
        supplied = PluginRegistry()
        supplied_digest = "sha256:" + ("a" * 64)
        supplied.register(
            ParseOnlyPlugin(),
            package_hash=supplied_digest,
        )

        self.assertTrue(derived.records()[0].package_hash.startswith("package-sha256:"))
        self.assertTrue(derived.records()[0].verify_package_bytes)
        self.assertEqual(
            supplied.records()[0].package_hash,
            supplied_digest,
        )
        self.assertNotEqual(
            derived.fingerprint(),
            supplied.fingerprint(),
        )

    def test_registration_rejects_malformed_trusted_hash_before_plugin_access(
        self,
    ) -> None:
        registry = PluginRegistry()
        with self.assertRaisesRegex(ValueError, "package_hash"):
            registry.register(
                _BoundaryManifestPlugin(Boom("manifest must not be accessed")),
                package_hash="sha256:not-a-digest",
            )

    def test_registered_execution_identity_covers_configuration_and_candidates(
        self,
    ) -> None:
        package_hash = "sha256:" + ("a" * 64)
        first = PluginRegistry()
        first.register(
            ParseOnlyPlugin(),
            package_hash=package_hash,
            configuration_digest="sha256:" + ("1" * 64),
        )
        second = PluginRegistry()
        second.register(
            ParseOnlyPlugin(),
            package_hash=package_hash,
            configuration_digest="sha256:" + ("2" * 64),
        )
        self.assertNotEqual(first.fingerprint(), second.fingerprint())
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            first_candidate = first.probe(input_path)[0]
            second_candidate = second.probe(input_path)[0]
        self.assertNotEqual(
            first_candidate.registered_execution_identity,
            second_candidate.registered_execution_identity,
        )
        self.assertEqual(
            first_candidate.registered_execution_identity,
            first.records()[0].registered_execution_identity,
        )

    def test_registry_distinguishes_same_release_configured_instances(self) -> None:
        package_hash = "sha256:" + ("a" * 64)
        registry = PluginRegistry()
        first = registry.register(
            ParseOnlyPlugin(),
            package_hash=package_hash,
            instance_id="tests.parse-only.blue",
            configuration_digest="sha256:" + ("1" * 64),
        )
        second = registry.register(
            ParseOnlyPlugin(),
            package_hash=package_hash,
            instance_id="tests.parse-only.green",
            configuration_digest="sha256:" + ("2" * 64),
        )

        self.assertEqual(len(registry.records()), 2)
        self.assertNotEqual(
            first.registered_execution_identity,
            second.registered_execution_identity,
        )
        with self.assertRaises(KeyError):
            registry.get("tests.parse-only", "1.0")
        self.assertIs(
            registry.get(
                "tests.parse-only",
                "1.0",
                instance_id=second.instance_id,
                registered_execution_identity=(
                    second.registered_execution_identity
                ),
            ),
            second,
        )
        with self.assertRaisesRegex(
            ValueError,
            "duplicate registered plug-in execution coordinate",
        ):
            registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
                instance_id="tests.parse-only.blue",
                configuration_digest="sha256:" + ("1" * 64),
            )

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            candidates = registry.probe(input_path)
        self.assertEqual(
            {candidate.instance_id for candidate in candidates},
            {first.instance_id, second.instance_id},
        )
        self.assertEqual(
            {candidate.registered_execution_identity for candidate in candidates},
            {
                first.registered_execution_identity,
                second.registered_execution_identity,
            },
        )

    def test_exact_configured_primary_selection_survives_restart(self) -> None:
        package_hash = "sha256:" + ("a" * 64)

        def configured_registry() -> tuple[PluginRegistry, RegisteredPlugin]:
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
                instance_id="tests.parse-only.blue",
                configuration_digest="sha256:" + ("1" * 64),
            )
            selected = registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
                instance_id="tests.parse-only.green",
                configuration_digest="sha256:" + ("2" * 64),
            )
            return registry, selected

        with tempfile.TemporaryDirectory() as directory:
            registry, selected = configured_registry()
            first = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)
            awaiting = first.get_import(self.scope, admitted.import_id)
            self.assertEqual(awaiting.state, ImportState.AWAITING_SELECTION)
            candidates = first.candidates(self.scope, admitted.import_id)
            self.assertEqual(len(candidates), 2)

            with self.assertRaisesRegex(ImportConflictError, "ambiguous"):
                first.select_plugin(
                    self.scope,
                    admitted.import_id,
                    probe_set_hash=str(awaiting.probe_set_hash),
                    plugin_id=selected.plugin_id,
                    plugin_version=selected.plugin_version,
                    package_hash=selected.package_hash,
                    idempotency_key="ambiguous-selection",
                )
            with self.assertRaisesRegex(ValueError, "provided together"):
                first.select_plugin(
                    self.scope,
                    admitted.import_id,
                    probe_set_hash=str(awaiting.probe_set_hash),
                    plugin_id=selected.plugin_id,
                    plugin_version=selected.plugin_version,
                    package_hash=selected.package_hash,
                    instance_id=selected.instance_id,
                    idempotency_key="partial-selection",
                )
            ready = first.select_plugin(
                self.scope,
                admitted.import_id,
                probe_set_hash=str(awaiting.probe_set_hash),
                plugin_id=selected.plugin_id,
                plugin_version=selected.plugin_version,
                package_hash=selected.package_hash,
                instance_id=selected.instance_id,
                registered_execution_identity=(
                    selected.registered_execution_identity
                ),
                idempotency_key="exact-selection",
            )
            self.assertEqual(ready.state, ImportState.READY)

            restarted_registry, restarted_selected = configured_registry()
            publisher = _Publisher()
            restarted = DurableIngestionPipeline(
                Path(directory),
                registry=restarted_registry,
                publisher=publisher,
                limits=self._limits(),
            )
            with restarted:
                completed = restarted.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(len(publisher.revisions), 1)
            plan = publisher.revisions[0][1]["execution_plan"]
            self.assertEqual(plan.plugins[0].instance_id, restarted_selected.instance_id)
            self.assertEqual(
                plan.plugins[0].registered_execution_identity,
                restarted_selected.registered_execution_identity,
            )

    def test_candidate_identity_schema_migration_preserves_ready_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            first = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)
            self.assertEqual(
                first.get_import(self.scope, admitted.import_id).state,
                ImportState.READY,
            )
            with first._connect() as connection:
                connection.executescript(
                    """
                    ALTER TABLE ingestion_candidates
                        RENAME TO ingestion_candidates_current;
                    CREATE TABLE ingestion_candidates (
                        import_id TEXT NOT NULL REFERENCES ingestion_imports(
                            import_id
                        ) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        plugin_id TEXT NOT NULL,
                        plugin_version TEXT NOT NULL,
                        package_hash TEXT NOT NULL,
                        registered_execution_identity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        match_kind TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        PRIMARY KEY (import_id, ordinal),
                        UNIQUE (
                            import_id, plugin_id, plugin_version, package_hash
                        )
                    );
                    INSERT INTO ingestion_candidates (
                        import_id, ordinal, plugin_id, plugin_version,
                        package_hash, registered_execution_identity,
                        confidence, match_kind, payload_json
                    )
                    SELECT import_id, ordinal, plugin_id, plugin_version,
                           package_hash, registered_execution_identity,
                           confidence, match_kind, payload_json
                    FROM ingestion_candidates_current;
                    DROP TABLE ingestion_candidates_current;
                    """
                )

            publisher = _Publisher()
            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )
            with reopened._connect() as connection:
                columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(ingestion_candidates)"
                    ).fetchall()
                }
            self.assertIn("instance_id", columns)
            self.assertEqual(len(reopened.candidates(self.scope, admitted.import_id)), 1)
            with reopened:
                completed = reopened.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(len(publisher.revisions), 1)

    def test_registered_execution_identity_binds_complete_process_bootstrap(
        self,
    ) -> None:
        common = {
            "package_hash": "sha256:" + "a" * 64,
            "instance_id": "tests.process-authority",
            "distribution_name": "tests-process-authority",
            "distribution_version": "1",
            "entry_point_name": "tests-process-authority",
            "module_target": "tests.test_ingestion:ParseOnlyPlugin",
            "plugin_process_construct_class": True,
        }
        diagnostic = PluginRegistry().register(
            DiagnosticPlugin(),
            plugin_process_module_target=("tests.test_ingestion:DiagnosticPlugin"),
            **common,
        )
        fixed_node = PluginRegistry().register(
            FixedNodePlugin(),
            plugin_process_module_target="tests.test_ingestion:FixedNodePlugin",
            **common,
        )
        self.assertEqual(diagnostic.module_target, fixed_node.module_target)
        self.assertEqual(diagnostic.package_hash, fixed_node.package_hash)
        self.assertEqual(
            diagnostic.configuration_digest,
            fixed_node.configuration_digest,
        )
        self.assertNotEqual(
            diagnostic.registered_execution_identity,
            fixed_node.registered_execution_identity,
        )

        bootstrap = diagnostic.process_bootstrap
        baseline_identity = diagnostic.registered_execution_identity
        self.assertEqual(
            set(diagnostic.execution_identity_material()["process_bootstrap"]),
            {
                field.name
                for field in fields(bootstrap)
                if field.name != "expected_registered_execution_identity"
            },
        )
        mutations = (
            replace(
                bootstrap,
                plugin_target="tests.test_ingestion:FixedNodePlugin",
            ),
            replace(
                bootstrap,
                coordinator_loader_kind="module_attribute",
                coordinator_target="tests.test_ingestion:coordinator",
                coordinator_target_executable_identity=(
                    "target-sha256:" + "b" * 64
                ),
            ),
            replace(
                bootstrap,
                decoder_loader_kind="module_attribute",
                decoder_target="tests.test_ingestion:decoder",
                decoder_target_executable_identity=(
                    "target-sha256:" + "c" * 64
                ),
            ),
            replace(
                bootstrap,
                ingestion_limit_values=(
                    bootstrap.ingestion_limit_values[0] + 1,
                    *bootstrap.ingestion_limit_values[1:],
                ),
            ),
            replace(
                bootstrap,
                artifact_limit_values=(
                    bootstrap.artifact_limit_values[0] + 1,
                    *bootstrap.artifact_limit_values[1:],
                ),
            ),
        )
        for changed in mutations:
            with self.subTest(changed=changed):
                mutated = replace(diagnostic, _process_bootstrap=changed)
                self.assertNotEqual(
                    mutated.registered_execution_identity,
                    baseline_identity,
                )
        self.assertEqual(
            replace(
                diagnostic,
                _process_bootstrap=replace(
                    bootstrap,
                    expected_registered_execution_identity="sha256:" + "f" * 64,
                ),
            ).registered_execution_identity,
            baseline_identity,
        )

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            result = IngestionCoordinator().ingest(ParseOnlyPlugin(), input_path)
        self.assertNotEqual(
            _execution_plan_for_result(diagnostic, result).plan_digest,
            _execution_plan_for_result(fixed_node, result).plan_digest,
        )

        forged = replace(
            bootstrap,
            plugin_target="tests.test_ingestion:FixedNodePlugin",
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "child plug-in bootstrap does not match",
        ):
            _register_process_bootstrap(PluginRegistry(), forged)

        object.__setattr__(diagnostic, "_process_bootstrap", forged)
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "process bootstrap changed after registration",
        ):
            _ = diagnostic.process_bootstrap
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "execution identity changed after registration",
        ):
            PluginRegistry.revalidate_registered_identity(diagnostic)

    def test_process_target_fingerprints_detect_real_coordinator_decoder_drift(
        self,
    ) -> None:
        for component in ("coordinator", "decoder"):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                module_name = f"rda_external_process_{component}_{uuid4().hex}"
                source = root / f"{module_name}.py"
                source.write_text(
                    _external_process_components_source("A"),
                    encoding="utf-8",
                )
                sys.path.insert(0, str(root))
                importlib.invalidate_caches()
                try:
                    module = importlib.import_module(module_name)
                    registration: dict[str, Any]
                    if component == "coordinator":
                        registration = {
                            "coordinator": module.coordinator,
                            "coordinator_module_target": (
                                f"{module_name}:coordinator"
                            ),
                        }
                    else:
                        registration = {
                            "coordinator": IngestionCoordinator(
                                trace_decoder=module.decoder
                            ),
                            "decoder_identity": DecoderIdentity(
                                "tests.external-decoder",
                                "1",
                                "sha256:" + "d" * 64,
                            ),
                            "decoder_module_target": f"{module_name}:decoder",
                        }
                    record = PluginRegistry().register(
                        ParseOnlyPlugin(),
                        package_hash="sha256:" + "a" * 64,
                        **registration,
                    )
                    bootstrap = record.process_bootstrap
                    target_identity = getattr(
                        bootstrap,
                        f"{component}_target_executable_identity",
                    )
                    self.assertRegex(
                        target_identity,
                        r"\Atarget-sha256:[0-9a-f]{64}\Z",
                    )
                    unchanged = _register_process_bootstrap(
                        PluginRegistry(),
                        bootstrap,
                    )
                    self.assertEqual(
                        unchanged.registered_execution_identity,
                        record.registered_execution_identity,
                    )

                    source.write_text(
                        _external_process_components_source("B"),
                        encoding="utf-8",
                    )
                    importlib.invalidate_caches()
                    with self.assertRaisesRegex(
                        IngestionPipelineError,
                        "process target executable changed",
                    ):
                        PluginRegistry.revalidate_registered_identity(record)
                    with self.assertRaisesRegex(
                        IngestionPipelineError,
                        "child plug-in bootstrap does not match",
                    ):
                        _register_process_bootstrap(
                            PluginRegistry(),
                            bootstrap,
                        )
                finally:
                    sys.modules.pop(module_name, None)
                    sys.path.remove(str(root))

    def test_process_parent_rejects_target_file_drift_after_child_returns(
        self,
    ) -> None:
        for component in ("coordinator", "decoder"):
            with self.subTest(component=component):  # noqa: SIM117
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    module_name = (
                        f"rda_post_child_{component}_{uuid4().hex}"
                    )
                    source = root / f"{module_name}.py"
                    source.write_text(
                        _external_process_components_source("A"),
                        encoding="utf-8",
                    )
                    sys.path.insert(0, str(root))
                    importlib.invalidate_caches()
                    try:
                        module = importlib.import_module(module_name)
                        registration: dict[str, Any]
                        if component == "coordinator":
                            registration = {
                                "coordinator": module.coordinator,
                                "coordinator_module_target": (
                                    f"{module_name}:coordinator"
                                ),
                            }
                        else:
                            registration = {
                                "coordinator": IngestionCoordinator(
                                    trace_decoder=module.decoder
                                ),
                                "decoder_identity": DecoderIdentity(
                                    "tests.external-decoder",
                                    "1",
                                    "sha256:" + "d" * 64,
                                ),
                                "decoder_module_target": (
                                    f"{module_name}:decoder"
                                ),
                            }
                        registry = PluginRegistry()
                        registry.register(
                            ParseOnlyPlugin(),
                            package_hash="sha256:" + "a" * 64,
                            **registration,
                        )
                        publisher = _Publisher()
                        pipeline = DurableIngestionPipeline(
                            root / "state",
                            registry=registry,
                            publisher=publisher,
                            limits=replace(
                                self._limits(),
                                max_attempts=1,
                                plugin_execution_mode=(
                                    PluginExecutionMode.PROCESS
                                ),
                                publisher_execution_mode=(
                                    PluginExecutionMode.INLINE
                                ),
                                plugin_execution_timeout_seconds=30,
                            ),
                        )
                        status = {"child_returned": False}

                        def run_then_modify(
                            target,
                            args,
                            *,
                            timeout_seconds: float,
                            stage: str,
                            selected_source: Path = source,
                            run_status: dict[str, bool] = status,
                        ):
                            payload = _run_plugin_child(
                                target,
                                args,
                                timeout_seconds=timeout_seconds,
                                stage=stage,
                            )
                            if stage == "ingest":
                                run_status["child_returned"] = True
                                selected_source.write_text(
                                    _external_process_components_source("B"),
                                    encoding="utf-8",
                                )
                                importlib.invalidate_caches()
                            return payload

                        with (
                            patch(
                                "router_dump_analyzer.ingestion_pipeline."
                                "_run_plugin_child",
                                side_effect=run_then_modify,
                            ),
                            pipeline,
                        ):
                            admitted = pipeline.submit_bytes(
                                self.scope,
                                _fixture_bytes(),
                                original_name="status.jsonl",
                            )
                            completed = pipeline.wait(
                                self.scope,
                                admitted.import_id,
                                timeout=60,
                            )
                        with pipeline._connect() as connection:
                            staged = connection.execute(
                                """
                                SELECT staged_dataset_ref,
                                       staged_execution_plan_digest
                                FROM ingestion_imports
                                WHERE import_id = ?
                                """,
                                (admitted.import_id,),
                            ).fetchone()

                        self.assertTrue(status["child_returned"])
                        self.assertEqual(completed.state, ImportState.FAILED)
                        self.assertEqual(
                            completed.error_code,
                            "plugin_execution_failed",
                        )
                        self.assertEqual(publisher.revisions, [])
                        assert staged is not None
                        self.assertIsNone(staged["staged_dataset_ref"])
                        self.assertIsNone(
                            staged["staged_execution_plan_digest"]
                        )
                    finally:
                        sys.modules.pop(module_name, None)
                        sys.path.remove(str(root))

    def test_registered_execution_identity_covers_all_probe_manifest_fields(
        self,
    ) -> None:
        package_hash = "sha256:" + ("a" * 64)
        first = PluginRegistry()
        first_record = first.register(
            ParseOnlyPlugin(),
            package_hash=package_hash,
        )
        changed_plugin = ParseOnlyPlugin()
        changed_plugin.manifest = replace(
            changed_plugin.manifest,
            supported_platforms=("changed-platform",),
            supported_software_versions=">=999",
        )
        changed = PluginRegistry()
        changed_record = changed.register(
            changed_plugin,
            package_hash=package_hash,
        )

        self.assertNotEqual(
            first_record._manifest_identity_snapshot,
            changed_record._manifest_identity_snapshot,
        )
        self.assertNotEqual(
            first_record.registered_execution_identity,
            changed_record.registered_execution_identity,
        )
        self.assertNotEqual(first.fingerprint(), changed.fingerprint())

    def test_registered_execution_identity_covers_timeline_basis_and_domain(
        self,
    ) -> None:
        package_hash = "sha256:" + ("a" * 64)

        def registered_with_timeline(
            basis: TimelineTimeBasis,
            clock_domain: str | None,
        ) -> tuple[str, str]:
            plugin = ParseOnlyPlugin()
            plugin.manifest = replace(
                plugin.manifest,
                timeline_time_basis=basis,
                timeline_clock_domain=clock_domain,
            )
            registry = PluginRegistry()
            record = registry.register(plugin, package_hash=package_hash)
            return record._manifest_identity_snapshot, record.registered_execution_identity

        relative = registered_with_timeline(
            TimelineTimeBasis.REVISION_START_RELATIVE_NS,
            None,
        )
        absolute = registered_with_timeline(
            TimelineTimeBasis.ABSOLUTE_UNIX_NS,
            None,
        )
        source_a = registered_with_timeline(
            TimelineTimeBasis.SOURCE_CLOCK_NS,
            "node-a-monotonic",
        )
        source_b = registered_with_timeline(
            TimelineTimeBasis.SOURCE_CLOCK_NS,
            "node-b-monotonic",
        )

        self.assertNotEqual(relative, absolute)
        self.assertNotEqual(source_a, source_b)

    def test_registration_defaults_only_when_identity_values_are_none(self) -> None:
        package_hash = "sha256:" + ("a" * 64)
        for field_name in (
            "instance_id",
            "distribution_name",
            "distribution_version",
            "entry_point_name",
            "module_target",
            "configuration_digest",
        ):
            with self.subTest(field=field_name), self.assertRaises(
                (TypeError, ValueError)
            ):
                PluginRegistry().register(
                    ParseOnlyPlugin(),
                    package_hash=package_hash,
                    **{field_name: ""},
                )

        coordinator = _FalseyCoordinator()
        registered = PluginRegistry().register(
            ParseOnlyPlugin(),
            coordinator=coordinator,
            package_hash=package_hash,
        )
        self.assertIs(registered.coordinator, coordinator)

    def test_registration_rejects_hostile_string_subclasses_before_use(self) -> None:
        supplied = r"string hook ran at C:\private\tenant\plugin.py"
        hostile = _HostileString("apparently-valid", Boom(supplied))
        package_hash = "sha256:" + ("a" * 64)
        for field_name in ("distribution_name", "configuration_digest"):
            with self.subTest(field=field_name), self.assertRaises(
                (TypeError, ValueError)
            ) as caught:
                PluginRegistry().register(
                    ParseOnlyPlugin(),
                    package_hash=package_hash,
                    **{field_name: hostile},
                )
            self.assertNotIn(supplied, str(caught.exception))

    def test_decoder_identity_comparison_contains_hostile_scalar_mutation(
        self,
    ) -> None:
        supplied = r"decoder equality ran at C:\private\tenant\decoder.py"
        package_hash = "sha256:" + ("a" * 64)
        active_identity = DecoderIdentity(
            decoder_id="tests.decoder",
            decoder_version="1",
            executable_digest="sha256:" + ("d" * 64),
        )
        coordinator = IngestionCoordinator(trace_decoder=_NoopTraceDecoder())
        registry = PluginRegistry()
        record = registry.register(
            ParseOnlyPlugin(),
            coordinator=coordinator,
            package_hash=package_hash,
            decoder_identity=active_identity,
        )
        baseline_execution_identity = record.registered_execution_identity
        object.__setattr__(
            active_identity,
            "decoder_id",
            _HostileString("tests.decoder", Boom(supplied)),
        )
        self.assertIsNot(record.decoder_identity, active_identity)
        assert coordinator.trace_decoder is not None
        self.assertIsNot(coordinator.trace_decoder.identity, record.decoder_identity)
        PluginRegistry.revalidate_registered_identity(record)
        self.assertEqual(
            record.registered_execution_identity,
            baseline_execution_identity,
        )

        assert record.decoder_identity is not None
        object.__setattr__(
            record.decoder_identity,
            "decoder_id",
            _HostileString("tests.decoder", Boom(supplied)),
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "identity could not be compared",
        ) as revalidation_failure:
            PluginRegistry.revalidate_registered_identity(record)
        self.assertNotIn(supplied, str(revalidation_failure.exception))

    def test_manifest_and_decoder_identity_are_bound_to_the_executed_run(
        self,
    ) -> None:
        plugin = ParseOnlyPlugin()
        registry = PluginRegistry()
        registered_manifest = registry.register(
            plugin,
            package_hash="sha256:" + ("a" * 64),
        )
        bound_manifest = registered_manifest.execution_plugin.manifest
        self.assertIsNot(bound_manifest, plugin.manifest)
        original_capabilities = plugin.manifest.capabilities
        object.__setattr__(
            plugin.manifest,
            "capabilities",
            frozenset(
                {
                    PluginCapability.STATUS_PARSE,
                    PluginCapability.TEXT_TRACE_PARSE,
                }
            ),
        )
        self.assertFalse(bound_manifest.supports(PluginCapability.TEXT_TRACE_PARSE))
        object.__setattr__(
            plugin.manifest,
            "capabilities",
            original_capabilities,
        )
        plugin.manifest = replace(plugin.manifest, forwarding_ir_versions=("changed",))
        with self.assertRaisesRegex(IngestionPipelineError, "manifest changed"):
            registry.probe(Path(__file__))

        decoder_identity = DecoderIdentity(
            decoder_id="tests.decoder",
            decoder_version="1",
            executable_digest="sha256:" + ("d" * 64),
        )
        with self.assertRaisesRegex(ValueError, "decoder_identity"):
            PluginRegistry().register(
                ParseOnlyPlugin(),
                coordinator=IngestionCoordinator(trace_decoder=_NoopTraceDecoder()),
                package_hash="sha256:" + ("b" * 64),
            )
        with self.assertRaisesRegex(ValueError, "exactly when"):
            PluginRegistry().register(
                ParseOnlyPlugin(),
                package_hash="sha256:" + ("b" * 64),
                decoder_identity=decoder_identity,
            )

        coordinator = IngestionCoordinator(trace_decoder=_NoopTraceDecoder())
        decoder_registry = PluginRegistry()
        registered = decoder_registry.register(
            ParseOnlyPlugin(),
            coordinator=coordinator,
            package_hash="sha256:" + ("c" * 64),
            decoder_identity=decoder_identity,
        )
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "status.jsonl"
            input_path.write_bytes(_fixture_bytes())
            result = coordinator.ingest(registered.execution_plugin, input_path)
        self.assertIsNone(_execution_plan_for_result(registered, result).decoder)
        assert coordinator.trace_decoder is not None
        tuple(coordinator.trace_decoder.iter_ctf(None, None))
        self.assertEqual(
            _execution_plan_for_result(registered, result).decoder,
            decoder_identity,
        )

    def test_decoder_implementation_is_bound_to_the_registered_identity(self) -> None:
        class ReplacementDecoder:
            def iter_ctf(self, *args: Any, **kwargs: Any) -> tuple[str]:
                del args, kwargs
                return ("REPLACEMENT",)

        coordinator = IngestionCoordinator(trace_decoder=_NoopTraceDecoder())
        identity = DecoderIdentity(
            decoder_id="tests.decoder",
            decoder_version="1",
            executable_digest="sha256:" + ("d" * 64),
        )
        record = PluginRegistry().register(
            ParseOnlyPlugin(),
            coordinator=coordinator,
            package_hash="sha256:" + ("a" * 64),
            decoder_identity=identity,
        )
        bound = coordinator.trace_decoder
        assert bound is not None

        with self.assertRaises(AttributeError):
            object.__setattr__(bound, "decoder", ReplacementDecoder())

        object.__setattr__(bound, "_decoder", ReplacementDecoder())
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "decoder binding changed",
        ):
            PluginRegistry.revalidate_registered_identity(record)

    def test_registry_manifest_fallback_requires_explicit_compatibility_opt_out(
        self,
    ) -> None:
        uninspectable_type = type(
            "_UninspectablePlugin",
            (ParseOnlyPlugin,),
            {"__module__": "missing_plugin_package_for_identity_test"},
        )
        local = PluginRegistry(
            (uninspectable_type(),),
            allow_manifest_identity=True,
        )
        compatibility_record = local.records()[0]
        self.assertTrue(
            compatibility_record.package_hash.startswith("manifest-sha256:")
        )
        self.assertIsNone(compatibility_record._process_bootstrap)
        PluginRegistry.revalidate_registered_identity(compatibility_record)
        with self.assertRaisesRegex(
            ValueError,
            "cannot authorize PROCESS execution",
        ):
            local.process_bootstraps()

        with self.assertRaisesRegex(
            ValueError,
            "no bounded executable package identity",
        ):
            PluginRegistry((uninspectable_type(),))
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            PluginRegistry(allow_manifest_identity=1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "conflict"):
            PluginRegistry(
                require_executable_identity=True,
                allow_manifest_identity=True,
            )

        strict = PluginRegistry(require_executable_identity=True)
        with self.assertRaisesRegex(
            ValueError,
            "manifest-only plug-in identity",
        ):
            strict.register(
                ParseOnlyPlugin(),
                package_hash="manifest-sha256:" + ("a" * 64),
            )

    def test_non_strict_derived_identity_can_register_inline_without_target_attestation(
        self,
    ) -> None:
        package_identity = "package-sha256:" + ("4" * 64)
        changed_package_identity = "package-sha256:" + ("5" * 64)
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=package_identity,
            ) as package_attestation,
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ) as target_attestation,
        ):
            registry = PluginRegistry(allow_manifest_identity=True)
            registered = registry.register(ParseOnlyPlugin())

            self.assertEqual(registered.package_hash, package_identity)
            self.assertTrue(registered.verify_package_bytes)
            self.assertIsNone(registered._process_bootstrap)
            identity_material = registered.execution_identity_material()
            self.assertFalse(identity_material["process_bootstrap_available"])
            self.assertIsNone(identity_material["process_bootstrap"])
            self.assertEqual(
                identity_material["process_bootstrap_compatibility"],
                "inline_only",
            )
            registered_identity = registered.registered_execution_identity

            PluginRegistry.revalidate_registered_identity(registered)
            self.assertEqual(target_attestation.call_count, 1)
            self.assertEqual(
                registered.registered_execution_identity,
                registered_identity,
            )

            package_attestation.return_value = changed_package_identity
            with self.assertRaisesRegex(
                IngestionPipelineError,
                "executable bytes changed after registration",
            ):
                PluginRegistry.revalidate_registered_identity(registered)

            package_attestation.return_value = package_identity
            with tempfile.TemporaryDirectory() as directory:
                input_path = Path(directory) / "status.jsonl"
                input_path.write_bytes(_fixture_bytes())
                candidates = registry.probe(input_path)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].package_hash, package_identity)
            self.assertNotIn("process_compatibility", candidates[0].as_dict())
            self.assertNotIn(
                "process_bootstrap_compatibility",
                candidates[0].as_dict(),
            )
            self.assertEqual(target_attestation.call_count, 1)

            repeated = PluginRegistry(allow_manifest_identity=True).register(
                ParseOnlyPlugin()
            )
            self.assertEqual(
                repeated.registered_execution_identity,
                registered_identity,
            )
            self.assertEqual(target_attestation.call_count, 2)

    def test_target_attestation_failure_stays_strict_for_required_and_explicit_hashes(
        self,
    ) -> None:
        package_identity = "package-sha256:" + ("6" * 64)
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
            self.assertRaisesRegex(
                IngestionPipelineError,
                "process target executable identity is unavailable",
            ),
        ):
            PluginRegistry(require_executable_identity=True).register(ParseOnlyPlugin())

        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=RuntimeError("unexpected evaluator failure"),
            ),
            self.assertRaisesRegex(
                IngestionPipelineError,
                "process target executable identity is unavailable",
            ),
        ):
            PluginRegistry(allow_manifest_identity=True).register(ParseOnlyPlugin())

        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint"
            ) as package_attestation,
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
            self.assertRaisesRegex(
                IngestionPipelineError,
                "process target executable identity is unavailable",
            ),
        ):
            PluginRegistry(allow_manifest_identity=True).register(
                ParseOnlyPlugin(),
                package_hash="sha256:" + ("7" * 64),
            )
        package_attestation.assert_not_called()

    def test_inline_only_target_compatibility_is_rejected_for_process_and_durable_use(
        self,
    ) -> None:
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value="package-sha256:" + ("8" * 64),
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
        ):
            registry = PluginRegistry(allow_manifest_identity=True)
            registry.register(ParseOnlyPlugin())

        with self.assertRaisesRegex(
            ValueError,
            "INLINE-only.*cannot authorize PROCESS execution",
        ):
            registry.process_bootstraps()
        with self.assertRaisesRegex(
            ValueError,
            "durable ingestion requires executable plug-in identities",
        ):
            registry.require_executable_identities()

        for mode in (PluginExecutionMode.INLINE, PluginExecutionMode.PROCESS):
            limits = replace(
                self._limits(),
                plugin_execution_mode=mode,
                publisher_execution_mode=PluginExecutionMode.INLINE,
            )
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                state_dir = Path(directory) / "state"
                with self.assertRaisesRegex(
                    ValueError,
                    "durable ingestion requires executable plug-in identities",
                ):
                    DurableIngestionPipeline(
                        state_dir,
                        registry=registry,
                        publisher=_Publisher(),
                        limits=limits,
                    )
                self.assertFalse(state_dir.exists())

    def test_durable_pipeline_seals_registry_against_late_inline_only_registration(
        self,
    ) -> None:
        package_identity = "package-sha256:" + ("9" * 64)
        registry = PluginRegistry(allow_manifest_identity=True)
        publisher = _Publisher()
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=publisher,
                limits=self._limits(),
            )
            self.assertIsNot(pipeline.registry, registry)
            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline."
                    "executable_plugin_fingerprint",
                    return_value=package_identity,
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline."
                    "executable_module_target_fingerprint",
                    side_effect=PluginExecutableIdentityError(
                        "target attestation unavailable"
                    ),
                ),
            ):
                late = registry.register(ParseOnlyPlugin(), instance_id="late-local")

            self.assertEqual(registry.records(), (late,))
            self.assertEqual(pipeline.registry.records(), ())
            with self.assertRaisesRegex(RuntimeError, "sealed"):
                pipeline.registry.register(ParseOnlyPlugin())

            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

        self.assertEqual(failed.state, ImportState.FAILED)
        self.assertIsNone(failed.revision_id)
        self.assertEqual(publisher.revisions, [])

    def test_inline_only_primary_cannot_be_frozen_into_execution_plan(self) -> None:
        package_identity = "package-sha256:" + ("a" * 64)
        plugin = ParseOnlyPlugin()
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
        ):
            registered = PluginRegistry(allow_manifest_identity=True).register(
                plugin
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = registered.coordinator.ingest(plugin, path)
        with self.assertRaisesRegex(ValueError, "PROCESS-capable"):
            _execution_plan_for_result(registered, result)

    def test_non_strict_registry_keeps_normal_process_bootstrap_unchanged(
        self,
    ) -> None:
        strict = PluginRegistry().register(ParseOnlyPlugin())
        non_strict_registry = PluginRegistry(allow_manifest_identity=True)
        non_strict = non_strict_registry.register(ParseOnlyPlugin())

        self.assertEqual(
            non_strict.registered_execution_identity,
            strict.registered_execution_identity,
        )
        self.assertEqual(non_strict.process_bootstrap, strict.process_bootstrap)
        self.assertNotIn(
            "process_bootstrap_compatibility",
            non_strict.execution_identity_material(),
        )
        self.assertEqual(
            non_strict_registry.process_bootstraps(),
            (non_strict.process_bootstrap,),
        )
        PluginRegistry.revalidate_registered_identity(non_strict)

    def test_derived_package_identity_is_revalidated_before_probe(self) -> None:
        registry = PluginRegistry((ParseOnlyPlugin(),))
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value="package-sha256:" + ("0" * 64),
            ),
            self.assertRaisesRegex(
                IngestionPipelineError,
                "executable bytes changed after registration",
            ),
        ):
            registry.probe(Path(__file__))

    def test_derived_module_identity_is_revalidated_before_probe(self) -> None:
        first = "module-sha256:" + ("1" * 64)
        second = "module-sha256:" + ("2" * 64)
        registry = PluginRegistry()
        with patch(
            "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
            return_value=first,
        ):
            record = registry.register(ParseOnlyPlugin())
        self.assertTrue(record.verify_package_bytes)
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=second,
            ),
            self.assertRaisesRegex(
                IngestionPipelineError,
                "executable bytes changed after registration",
            ),
        ):
            registry.probe(Path(__file__))

    def test_derived_package_identity_is_revalidated_before_ingestion(
        self,
    ) -> None:
        coordinator = _CountingCoordinator()
        registry = PluginRegistry()
        registry.register(ParseOnlyPlugin(), coordinator=coordinator)
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            probe_claim = pipeline._claim()
            assert probe_claim is not None
            pipeline._run_probe(probe_claim)
            ingestion_claim = pipeline._claim()
            assert ingestion_claim is not None

            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline."
                    "executable_plugin_fingerprint",
                    return_value="package-sha256:" + ("0" * 64),
                ),
                self.assertRaisesRegex(
                    IngestionPipelineError,
                    "executable bytes changed after registration",
                ),
            ):
                pipeline._run_ingestion(ingestion_claim)
            self.assertEqual(coordinator.ingest_calls, 0)

    def test_process_probe_timeout_kills_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((_HungProbePlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=1.5,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            claim = pipeline._claim()
            assert claim is not None

            with self.assertRaisesRegex(
                PluginExecutionTimeoutError,
                "probe exceeded",
            ):
                pipeline._run_probe(claim)
            self.assertFalse(
                any(
                    child.name.startswith("rda-plugin-probe-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_process_spawn_never_serializes_live_plugin_or_coordinator(self) -> None:
        registry = PluginRegistry()
        registry.register(
            _SpawnPickleHostilePlugin(),
            coordinator=_SpawnPickleHostileCoordinator(),
        )
        bootstraps = registry.process_bootstraps()
        _validate_plugin_child_spawn_args((bootstraps, "input", None, {}))
        with self.assertRaisesRegex(
            PluginExecutionProcessError,
            "live or unsupported object",
        ):
            _validate_plugin_child_spawn_args((registry,))
        with tempfile.TemporaryDirectory() as directory:
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=publisher,
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=30,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=60,
                )

        self.assertEqual(completed.state, ImportState.COMPLETED)
        self.assertEqual(len(publisher.revisions), 1)

    def test_configured_process_components_require_module_level_instances(
        self,
    ) -> None:
        configured_digest = "sha256:" + "7" * 64
        package_hash = "sha256:" + "8" * 64

        unsafe = PluginRegistry()
        unsafe.register(
            _ConfiguredProcessPlugin("configured"),
            package_hash=package_hash,
            configuration_digest=configured_digest,
        )
        with self.assertRaisesRegex(
            ValueError,
            "plugin_process_module_target",
        ):
            unsafe.process_bootstraps()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            ValueError,
            "plugin_process_module_target",
        ):
            DurableIngestionPipeline(
                Path(directory),
                registry=unsafe,
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                ),
            )

        constructor = PluginRegistry()
        constructor.register(
            _ConfiguredProcessPlugin("configured"),
            package_hash=package_hash,
            configuration_digest=configured_digest,
            plugin_process_module_target=(
                "tests.test_ingestion_pipeline:_ConfiguredProcessPlugin"
            ),
            plugin_process_construct_class=True,
        )
        with self.assertRaisesRegex(
            ValueError,
            "plugin_process_module_target",
        ):
            constructor.process_bootstraps()

        explicit_plugin = PluginRegistry()
        explicit_plugin.register(
            _CONFIGURED_PROCESS_PLUGIN,
            package_hash=package_hash,
            configuration_digest=configured_digest,
            plugin_process_module_target=(
                "tests.test_ingestion_pipeline:_CONFIGURED_PROCESS_PLUGIN"
            ),
        )
        self.assertEqual(
            explicit_plugin.process_bootstraps()[0].plugin_loader_kind,
            "module_attribute",
        )

        configured_coordinator = PluginRegistry()
        configured_coordinator.register(
            _CONFIGURED_PROCESS_PLUGIN,
            coordinator=_CONFIGURED_PROCESS_COORDINATOR,
            package_hash=package_hash,
            configuration_digest=configured_digest,
            plugin_process_module_target=(
                "tests.test_ingestion_pipeline:_CONFIGURED_PROCESS_PLUGIN"
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "coordinator_module_target",
        ):
            configured_coordinator.process_bootstraps()

        decoder_identity = DecoderIdentity(
            "tests.configured-decoder",
            "1",
            "sha256:" + "9" * 64,
        )
        configured_decoder = PluginRegistry()
        configured_decoder.register(
            _CONFIGURED_PROCESS_PLUGIN,
            coordinator=IngestionCoordinator(
                trace_decoder=_CONFIGURED_PROCESS_DECODER
            ),
            package_hash=package_hash,
            configuration_digest=configured_digest,
            decoder_identity=decoder_identity,
            plugin_process_module_target=(
                "tests.test_ingestion_pipeline:_CONFIGURED_PROCESS_PLUGIN"
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "decoder_module_target",
        ):
            configured_decoder.process_bootstraps()

        fully_explicit = PluginRegistry()
        fully_explicit.register(
            _CONFIGURED_PROCESS_PLUGIN,
            coordinator=IngestionCoordinator(
                trace_decoder=_CONFIGURED_PROCESS_DECODER
            ),
            package_hash=package_hash,
            configuration_digest=configured_digest,
            decoder_identity=decoder_identity,
            plugin_process_module_target=(
                "tests.test_ingestion_pipeline:_CONFIGURED_PROCESS_PLUGIN"
            ),
            decoder_module_target=(
                "tests.test_ingestion_pipeline:_CONFIGURED_PROCESS_DECODER"
            ),
        )
        self.assertEqual(
            fully_explicit.process_bootstraps()[0].decoder_loader_kind,
            "module_attribute",
        )

    def test_process_timeout_starts_without_live_plugin_pickle_hook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((_SpawnPickleHostileHungProbePlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=1.5,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            claim = pipeline._claim()
            assert claim is not None

            started = time.monotonic()
            with self.assertRaisesRegex(
                PluginExecutionTimeoutError,
                "probe exceeded",
            ):
                pipeline._run_probe(claim)
            self.assertLess(time.monotonic() - started, 10)
            self.assertFalse(
                any(
                    child.name.startswith("rda-plugin-probe-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_process_child_defers_duplicate_attestation_to_probe_boundary(
        self,
    ) -> None:
        parent_registry = PluginRegistry()
        parent_registry.register(
            ParseOnlyPlugin(),
            coordinator=_HungCoordinator(),
        )
        bootstrap = parent_registry.process_bootstraps()[0]
        changed_coordinator_identity = "target-sha256:" + ("0" * 64)

        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_plugin_fingerprint",
                return_value=bootstrap.package_hash,
            ) as package_fingerprint,
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=(
                    bootstrap.plugin_target_executable_identity,
                    changed_coordinator_identity,
                ),
            ) as target_fingerprint,
        ):
            child_registry = _registry_from_process_bootstraps((bootstrap,))
            self.assertEqual(package_fingerprint.call_count, 0)
            self.assertEqual(target_fingerprint.call_count, 0)

            with tempfile.TemporaryDirectory() as directory:
                input_path = Path(directory) / "status.jsonl"
                input_path.write_bytes(_fixture_bytes())
                with self.assertRaisesRegex(
                    IngestionPipelineError,
                    "process target executable changed",
                ):
                    child_registry.probe(input_path)

        self.assertEqual(package_fingerprint.call_count, 1)
        self.assertEqual(target_fingerprint.call_count, 2)

    def test_process_timeout_becomes_bounded_durable_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((_HungProbePlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    plugin_execution_timeout_seconds=1.5,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(
                failed.error_code,
                "plugin_execution_timeout",
            )
            self.assertEqual(
                failed.error_message,
                PUBLIC_INGESTION_FAILURE_MESSAGES["plugin_execution_timeout"],
            )
            self.assertFalse(
                any(
                    child.name.startswith("rda-plugin-probe-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_process_ingestion_timeout_removes_stage_and_reaps_child(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                coordinator=_HungCoordinator(),
            )
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    # This test targets the ingest child, not process-startup
                    # latency in the preceding healthy probe. Give that
                    # independent phase enough headroom on loaded Windows
                    # hosts, then narrow the budget before the hung ingest.
                    plugin_execution_timeout_seconds=10.0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            probe_claim = pipeline._claim()
            assert probe_claim is not None
            pipeline._run_probe(probe_claim)
            pipeline.limits = replace(
                pipeline.limits,
                plugin_execution_timeout_seconds=1.5,
            )
            ingestion_claim = pipeline._claim()
            assert ingestion_claim is not None

            with self.assertRaisesRegex(
                PluginExecutionTimeoutError,
                "ingest exceeded",
            ):
                pipeline._run_ingestion(ingestion_claim)
            self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())
            self.assertFalse(
                any(
                    child.name.startswith("rda-plugin-ingest-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_inline_probe_is_synchronous_and_never_leaves_helper_threads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((_SlowProbePlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=0.05,
                ),
            )
            started = time.monotonic()
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=5,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertGreaterEqual(time.monotonic() - started, 0.05)
            self.assertFalse(
                any(
                    thread.name.startswith("rda-plugin-inline-")
                    for thread in threading.enumerate()
                )
            )

    def test_inline_ingestion_is_synchronous_and_never_leaves_helper_threads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                coordinator=_SlowCoordinator(),
            )
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=publisher,
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=0.05,
                ),
            )
            started = time.monotonic()
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=5,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertGreaterEqual(time.monotonic() - started, 0.05)
            self.assertEqual(len(publisher.revisions), 1)
            self.assertFalse(
                any(
                    thread.name.startswith("rda-plugin-inline-")
                    for thread in threading.enumerate()
                )
            )

    def test_process_execution_stages_and_installs_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                    # Process spawn/import latency is load-sensitive on the
                    # Windows full-suite runner. This test verifies staging
                    # semantics, not the timeout boundary (covered above), so
                    # leave enough headroom to keep the signal deterministic.
                    plugin_execution_timeout_seconds=30,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=60,
                )

            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(len(publisher.revisions), 1)
            dataset_ref = publisher.revisions[0][1]["dataset_ref"]
            dataset_path = pipeline.dataset_root / dataset_ref
            self.assertTrue(dataset_path.is_file())
            self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())
            self.assertFalse(
                any(
                    child.name.startswith("rda-plugin-")
                    for child in multiprocessing.active_children()
                )
            )

    def test_workspace_active_import_cap_excludes_terminal_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    max_active_imports_per_workspace=1,
                ),
            )
            first = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="first.jsonl",
            )
            with self.assertRaisesRegex(
                ImportConflictError,
                "active import limit reached",
            ):
                pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="blocked.jsonl",
                )

            self._admit_staged(pipeline, first.import_id)
            queued = pipeline.get_import(self.scope, first.import_id)
            cancelled = pipeline.cancel(
                self.scope,
                first.import_id,
                expected_version=queued.version,
            )
            self.assertEqual(cancelled.state, ImportState.CANCELLED)
            second = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="second.jsonl",
            )
            self.assertEqual(second.state, ImportState.ADMITTING)

    def test_restart_fails_closed_when_selected_package_hash_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_registry = PluginRegistry()
            first_registry.register(
                ParseOnlyPlugin(),
                package_hash="sha256:" + ("1" * 64),
            )
            first = DurableIngestionPipeline(
                Path(directory),
                registry=first_registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)
            self.assertEqual(
                first.get_import(self.scope, admitted.import_id).state,
                ImportState.READY,
            )

            changed_registry = PluginRegistry()
            changed_registry.register(
                ParseOnlyPlugin(),
                package_hash="sha256:" + ("2" * 64),
            )
            publisher = _Publisher()
            restarted = DurableIngestionPipeline(
                Path(directory),
                registry=changed_registry,
                publisher=publisher,
                limits=self._limits(),
            )
            with restarted:
                failed = restarted.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "ingestion_rejected")
            self.assertEqual(
                failed.error_message,
                PUBLIC_INGESTION_FAILURE_MESSAGES["ingestion_rejected"],
            )
            self.assertEqual(publisher.revisions, [])

    def test_restart_fails_closed_when_selected_configuration_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package_hash = "sha256:" + ("1" * 64)
            first_registry = PluginRegistry()
            first_registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
                configuration_digest="sha256:" + ("a" * 64),
            )
            first = DurableIngestionPipeline(
                Path(directory),
                registry=first_registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)

            changed_registry = PluginRegistry()
            changed_registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
                configuration_digest="sha256:" + ("b" * 64),
            )
            publisher = _Publisher()
            restarted = DurableIngestionPipeline(
                Path(directory),
                registry=changed_registry,
                publisher=publisher,
                limits=self._limits(),
            )
            with restarted:
                failed = restarted.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "ingestion_rejected")
            self.assertEqual(publisher.revisions, [])

    def test_restart_fails_closed_when_probe_manifest_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package_hash = "sha256:" + ("1" * 64)
            first_registry = PluginRegistry()
            first_registry.register(
                ParseOnlyPlugin(),
                package_hash=package_hash,
            )
            first = DurableIngestionPipeline(
                Path(directory),
                registry=first_registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)

            changed_plugin = ParseOnlyPlugin()
            changed_plugin.manifest = replace(
                changed_plugin.manifest,
                supported_platforms=("changed-platform",),
                supported_software_versions=">=999",
            )
            changed_registry = PluginRegistry()
            changed_registry.register(
                changed_plugin,
                package_hash=package_hash,
            )
            publisher = _Publisher()
            restarted = DurableIngestionPipeline(
                Path(directory),
                registry=changed_registry,
                publisher=publisher,
                limits=self._limits(),
            )
            with restarted:
                failed = restarted.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "ingestion_rejected")
            self.assertEqual(publisher.revisions, [])

    def test_legacy_unstaged_selections_are_reprobed_under_the_new_contract(
        self,
    ) -> None:
        for legacy_state in (
            ImportState.AWAITING_SELECTION,
            ImportState.READY,
            ImportState.FAILED,
        ):
            with self.subTest(state=legacy_state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                registry = PluginRegistry((ParseOnlyPlugin(),))
                first = DurableIngestionPipeline(
                    root,
                    registry=registry,
                    publisher=_Publisher(),
                    limits=self._limits(),
                )
                admitted = first.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    auto_select=legacy_state is not ImportState.AWAITING_SELECTION,
                )
                self._admit_staged(first, admitted.import_id)
                probe_claim = first._claim()
                assert probe_claim is not None
                first._run_probe(probe_claim)
                with first._connect() as connection:
                    connection.execute(
                        "DROP TRIGGER ingestion_execution_plan_contract_no_downgrade"
                    )
                    connection.execute(
                        """
                        UPDATE ingestion_imports
                        SET execution_plan_required = 0,
                            state = ?
                        WHERE import_id = ?
                        """,
                        (legacy_state.value, admitted.import_id),
                    )

                reopened = DurableIngestionPipeline(
                    root,
                    registry=registry,
                    publisher=_Publisher(),
                    limits=self._limits(),
                )
                migrated = reopened.get_import(self.scope, admitted.import_id)
                if legacy_state is ImportState.FAILED:
                    self.assertEqual(migrated.state, ImportState.FAILED)
                    migrated = reopened.resume(self.scope, admitted.import_id)
                self.assertEqual(migrated.state, ImportState.QUEUED)
                self.assertIsNone(migrated.selected_plugin_id)
                self.assertEqual(
                    migrated.plugin_composition_policy_digest,
                    reopened.composition_policy.policy_digest,
                )
                self.assertEqual(reopened.candidates(self.scope, admitted.import_id), ())
                with reopened._connect() as connection:
                    row = connection.execute(
                        "SELECT execution_plan_required, composition_policy_digest "
                        "FROM ingestion_imports "
                        "WHERE import_id = ?",
                        (admitted.import_id,),
                    ).fetchone()
                    assert row is not None
                self.assertEqual(row["execution_plan_required"], 1)
                self.assertEqual(
                    row["composition_policy_digest"],
                    reopened.composition_policy.policy_digest,
                )

    def test_legacy_unfinished_resume_adopts_active_non_default_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            primary = registry.get("tests.parse-only", "1.0")
            active_policy = PluginCompositionPolicy(
                (
                    PluginCompositionRule(
                        primary_instance_id=primary.instance_id,
                        primary_registered_execution_identity=(
                            primary.registered_execution_identity
                        ),
                        auxiliaries=(),
                    ),
                )
            )

            historical = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with historical:
                published_admission = historical.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                published = historical.wait(
                    self.scope,
                    published_admission.import_id,
                    timeout=10,
                )
            self.assertEqual(published.state, ImportState.COMPLETED)

            legacy = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = legacy.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(legacy, admitted.import_id)
            probe_claim = legacy._claim()
            assert probe_claim is not None
            legacy._run_probe(probe_claim)
            selected_before = legacy.get_import(self.scope, admitted.import_id)
            self.assertEqual(selected_before.state, ImportState.READY)
            self.assertIsNotNone(selected_before.selected_plugin_id)

            with legacy._connect() as connection:
                default_digest = str(
                    connection.execute(
                        "SELECT composition_policy_digest FROM ingestion_imports "
                        "WHERE import_id = ?",
                        (admitted.import_id,),
                    ).fetchone()[0]
                )
                self.assertNotEqual(default_digest, active_policy.policy_digest)
                connection.execute(
                    "DROP TRIGGER ingestion_execution_plan_contract_no_downgrade"
                )
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET execution_plan_required = 0,
                        state = ?
                    WHERE import_id = ?
                    """,
                    (ImportState.FAILED.value, admitted.import_id),
                )
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET execution_plan_required = 0
                    WHERE import_id = ?
                    """,
                    (published.import_id,),
                )

            publisher = _Publisher()
            reopened = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=publisher,
                limits=self._limits(),
                composition_policy=active_policy,
            )
            migrated = reopened.get_import(self.scope, admitted.import_id)
            self.assertEqual(migrated.state, ImportState.FAILED)
            self.assertIsNone(migrated.selected_plugin_id)
            self.assertEqual(
                migrated.plugin_composition_policy_digest,
                active_policy.policy_digest,
            )
            self.assertEqual(reopened.candidates(self.scope, admitted.import_id), ())

            with reopened._connect() as connection:
                migrated_row = connection.execute(
                    """
                    SELECT execution_plan_required, composition_policy_digest,
                           selected_plugin_id, publication_operation_id
                    FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
                published_row = connection.execute(
                    """
                    SELECT state, execution_plan_required,
                           composition_policy_digest, selected_plugin_id,
                           publication_operation_id
                    FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (published.import_id,),
                ).fetchone()
                assert migrated_row is not None and published_row is not None
            self.assertEqual(migrated_row["execution_plan_required"], 1)
            self.assertEqual(
                migrated_row["composition_policy_digest"],
                active_policy.policy_digest,
            )
            self.assertIsNone(migrated_row["selected_plugin_id"])
            self.assertIsNone(migrated_row["publication_operation_id"])
            self.assertEqual(published_row["state"], ImportState.COMPLETED.value)
            self.assertEqual(published_row["execution_plan_required"], 0)
            self.assertEqual(
                published_row["composition_policy_digest"],
                default_digest,
            )
            self.assertEqual(
                published_row["selected_plugin_id"],
                published.selected_plugin_id,
            )
            self.assertIsNotNone(published_row["publication_operation_id"])

            resumed = reopened.resume(self.scope, admitted.import_id)
            self.assertEqual(resumed.state, ImportState.QUEUED)
            with reopened:
                completed = reopened.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            self.assertEqual(
                completed.selected_plugin_id,
                selected_before.selected_plugin_id,
            )
            self.assertEqual(
                completed.plugin_composition_policy_digest,
                active_policy.policy_digest,
            )
            self.assertEqual(len(publisher.revisions), 1)
            with reopened._connect() as connection:
                staged_plan_json = connection.execute(
                    "SELECT staged_execution_plan_json FROM ingestion_imports "
                    "WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()[0]
            staged_plan = plugin_execution_plan_from_dict(
                json.loads(str(staged_plan_json))
            )
            self.assertEqual(
                staged_plan.composition_policy_digest,
                active_policy.policy_digest,
            )

    def test_staged_plan_is_immutable_and_must_match_dataset_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=publisher,
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            probe_claim = pipeline._claim()
            assert probe_claim is not None
            pipeline._run_probe(probe_claim)
            ingestion_claim = pipeline._claim()
            assert ingestion_claim is not None
            pipeline._run_ingestion(ingestion_claim)

            with pipeline._connect() as connection:
                row = connection.execute(
                    """
                    SELECT staged_execution_plan_json
                    FROM ingestion_imports WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
                assert row is not None
                plan = plugin_execution_plan_from_dict(
                    json.loads(row["staged_execution_plan_json"])
                )
                changed_pin = replace(
                    plan.plugins[0],
                    configuration_digest="sha256:" + ("f" * 64),
                )
                changed_plan = replace(
                    plan,
                    plugins=(changed_pin,),
                    plan_digest="",
                )
                changed_json = canonical_json(
                    plugin_execution_plan_dict(changed_plan)
                )
                for column, changed_value in (
                    ("tenant_id", "tenant-b"),
                    ("project_id", "project-b"),
                    ("workspace_id", "workspace-b"),
                    ("fixture_id", "fixture-b"),
                ):
                    with self.subTest(
                        staged_scope_column=column
                    ), self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            f"UPDATE ingestion_imports SET {column} = ? "
                            "WHERE import_id = ?",
                            (changed_value, admitted.import_id),
                        )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        UPDATE ingestion_imports
                        SET staged_execution_plan_json = ?,
                            staged_execution_plan_digest = ?
                        WHERE import_id = ?
                        """,
                        (
                            changed_json,
                            changed_plan.plan_digest,
                            admitted.import_id,
                        ),
                    )
                connection.execute(
                    "DROP TRIGGER ingestion_staged_publication_immutable"
                )
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET staged_execution_plan_json = ?,
                        staged_execution_plan_digest = ?
                    WHERE import_id = ?
                    """,
                    (
                        changed_json,
                        changed_plan.plan_digest,
                        admitted.import_id,
                    ),
                )

            publication_claim = pipeline._claim()
            assert publication_claim is not None
            with self.assertRaisesRegex(
                IngestionPipelineError,
                "dataset execution-plan digest",
            ):
                pipeline._run_publication(publication_claim)
            self.assertEqual(publisher.revisions, [])

    def test_legacy_publishing_can_replay_planless_but_new_rows_cannot_downgrade(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            first = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with first._connect() as connection:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE ingestion_imports "
                        "SET execution_plan_required = 0 WHERE import_id = ?",
                        (admitted.import_id,),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE ingestion_imports "
                        "SET publication_operation_id = 'publication:missing-plan' "
                        "WHERE import_id = ?",
                        (admitted.import_id,),
                    )
            self._admit_staged(first, admitted.import_id)
            probe_claim = first._claim()
            assert probe_claim is not None
            first._run_probe(probe_claim)
            ingestion_claim = first._claim()
            assert ingestion_claim is not None
            first._run_ingestion(ingestion_claim)
            with first._connect() as connection:
                staged = connection.execute(
                    """
                    SELECT staged_dataset_ref FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
                assert staged is not None
                modern_path = first.dataset_root / Path(
                    str(staged["staged_dataset_ref"])
                )
                legacy_dataset = json.loads(modern_path.read_text("utf-8"))
                legacy_dataset["_ingestion"].pop(
                    "plugin_execution_plan_digest"
                )
                legacy_bytes = canonical_json(legacy_dataset).encode("utf-8")
                legacy_sha256 = hashlib.sha256(legacy_bytes).hexdigest()
                legacy_relative = (
                    Path(legacy_sha256[:2])
                    / legacy_sha256[2:4]
                    / f"{legacy_sha256}.json"
                )
                legacy_path = first.dataset_root / legacy_relative
                legacy_path.parent.mkdir(parents=True, exist_ok=True)
                legacy_path.write_bytes(legacy_bytes)
                connection.execute(
                    "DROP TRIGGER ingestion_execution_plan_contract_no_downgrade"
                )
                connection.execute(
                    "DROP TRIGGER ingestion_staged_publication_immutable"
                )
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET execution_plan_required = 0,
                        staged_execution_plan_json = NULL,
                        staged_execution_plan_digest = NULL,
                        staged_dataset_ref = ?,
                        staged_dataset_sha256 = ?
                    WHERE import_id = ?
                    """,
                    (
                        legacy_relative.as_posix(),
                        legacy_sha256,
                        admitted.import_id,
                    ),
                )

            # A pre-contract publisher may have accepted arbitrary keywords
            # while hashing the exact request for idempotency.  Planless replay
            # must not acquire a new ``execution_plan=None`` field merely
            # because ``**values`` can technically bind it.
            publisher = _Publisher()
            reopened = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=publisher,
                limits=self._limits(),
            )
            publication_claim = reopened._claim()
            assert publication_claim is not None
            reopened._run_publication(publication_claim)
            self.assertNotIn("execution_plan", publisher.revisions[0][1])
            self.assertEqual(
                reopened.get_import(self.scope, admitted.import_id).state,
                ImportState.COMPLETED,
            )

    def test_planful_publication_rejects_a_legacy_publisher_before_call(self) -> None:
        self.assertFalse(
            _publisher_accepts_execution_plan(_PositionalExecutionPlanPublisher())
        )
        self.assertFalse(
            _publisher_accepts_execution_plan(
                _PositionalExecutionPlanKwargsPublisher()
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            publisher = _LegacyPublisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            probe_claim = pipeline._claim()
            assert probe_claim is not None
            pipeline._run_probe(probe_claim)
            ingestion_claim = pipeline._claim()
            assert ingestion_claim is not None
            pipeline._run_ingestion(ingestion_claim)
            publication_claim = pipeline._claim()
            assert publication_claim is not None
            with self.assertRaisesRegex(
                IngestionPipelineError,
                "does not support immutable execution plans",
            ):
                pipeline._run_publication(publication_claim)
            self.assertEqual(publisher.revisions, [])

    def test_upload_idempotency_and_tenant_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            first = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
                idempotency_key="same-request",
            )
            replay = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
                idempotency_key="same-request",
            )
            self.assertEqual(first.import_id, replay.import_id)
            with self.assertRaises(ImportConflictError):
                pipeline.submit_bytes(
                    self.scope,
                    b"different",
                    original_name="status.jsonl",
                    idempotency_key="same-request",
                )
            with self.assertRaises(ImportNotFoundError):
                pipeline.get_import(
                    self.other_scope,
                    first.import_id,
                )
            self.assertEqual(
                len(tuple(pipeline.fixture_root.iterdir())),
                1,
            )

    def test_import_pagination_cursor_preserves_tied_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            import_ids = {
                pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name=f"status-{ordinal}.jsonl",
                    idempotency_key=f"page-{ordinal}",
                ).import_id
                for ordinal in range(3)
            }
            tied_timestamp = 123_456_789
            with pipeline._connect() as connection:
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET created_at_ns = ?, updated_at_ns = ?
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ?
                    """,
                    (
                        tied_timestamp,
                        tied_timestamp,
                        self.scope.tenant_id,
                        self.scope.project_id,
                        self.scope.workspace_id,
                    ),
                )

            first = pipeline.list_imports(self.scope, limit=2)
            second = pipeline.list_imports(
                self.scope,
                limit=2,
                before_created_at_ns=first[-1].created_at_ns,
                before_import_id=first[-1].import_id,
            )

            self.assertEqual(len(first), 2)
            self.assertEqual(len(second), 1)
            self.assertEqual(
                {descriptor.import_id for descriptor in (*first, *second)},
                import_ids,
            )
            with self.assertRaisesRegex(ValueError, "before_import_id"):
                pipeline.list_imports(
                    self.scope,
                    before_created_at_ns=tied_timestamp,
                )

    def test_concurrent_idempotent_upload_has_one_fixture_and_admission(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            publisher = _Publisher()
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=publisher,
                limits=self._limits(),
            )

            def submit() -> str:
                return pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="concurrent-request",
                ).import_id

            with ThreadPoolExecutor(max_workers=8) as executor:
                import_ids = tuple(executor.map(lambda _index: submit(), range(32)))

            self.assertEqual(len(set(import_ids)), 1)
            self._admit_staged(pipeline, import_ids[0])
            self.assertEqual(len(publisher.fixtures), 1)
            self.assertEqual(
                len(tuple(pipeline.fixture_root.iterdir())),
                1,
            )

    @unittest.skipUnless(os.name == "nt", "Windows device path regression")
    def test_windows_device_prefix_does_not_change_containment_identity(
        self,
    ) -> None:
        normal = Path("C:/state/root/fixture/input.json")
        extended = Path(r"\\?\C:\state\root\fixture\input.json")

        self.assertEqual(
            _path_for_containment_comparison(normal),
            _path_for_containment_comparison(extended),
        )

    def test_catalog_admission_failure_is_durable_and_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_FailingAdmissionPublisher(),
                limits=self._limits(),
            )

            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="failed-admission",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertTrue(failed.retryable)
            self.assertEqual(len(pipeline.list_imports(self.scope)), 1)
            self.assertEqual(len(tuple(pipeline.fixture_root.iterdir())), 1)

    def test_partial_content_address_is_quarantined_and_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            content = _fixture_bytes()
            digest = hashlib.sha256(content).hexdigest()
            corrupted = Path(directory) / "blobs" / digest[:2] / digest[2:4] / digest
            corrupted.parent.mkdir(parents=True)
            poisoned = content[:7]
            corrupted.write_bytes(poisoned)
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )

            # Exercise the copy fallback as well as recovery from a final-name
            # object left by an abruptly terminated older writer.
            with patch(
                "router_dump_analyzer.ingestion_pipeline.os.link",
                side_effect=OSError("hard links disabled"),
            ):
                admitted = pipeline.submit_bytes(
                    self.scope,
                    content,
                    original_name="status.jsonl",
                )

            self.assertEqual(admitted.state, ImportState.ADMITTING)
            self.assertEqual(corrupted.read_bytes(), content)
            quarantines = tuple(corrupted.parent.glob(f".{digest}.corrupt-*"))
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(quarantines[0].read_bytes(), poisoned)
            self.assertEqual(
                tuple(corrupted.parent.glob(f".{digest}.*.partial")),
                (),
            )

    def test_wrong_digest_content_address_is_quarantined_and_repaired(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            content = _fixture_bytes()
            digest = hashlib.sha256(content).hexdigest()
            corrupted = Path(directory) / "blobs" / digest[:2] / digest[2:4] / digest
            corrupted.parent.mkdir(parents=True)
            poisoned = b"x" * len(content)
            corrupted.write_bytes(poisoned)
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )

            admitted = pipeline.submit_bytes(
                self.scope,
                content,
                original_name="status.jsonl",
            )

            self.assertEqual(admitted.state, ImportState.ADMITTING)
            self.assertEqual(corrupted.read_bytes(), content)
            quarantines = tuple(corrupted.parent.glob(f".{digest}.corrupt-*"))
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(quarantines[0].read_bytes(), poisoned)

    def test_concurrent_processes_publish_one_verified_content_object(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "blobs"
            root.mkdir()
            source = Path(directory) / "upload.partial"
            content = _fixture_bytes() * 64
            source.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            target = root / digest[:2] / digest[2:4] / digest
            target.parent.mkdir(parents=True)
            target.write_bytes(b"interrupted")

            context = multiprocessing.get_context("spawn")
            start = context.Event()
            processes = tuple(
                context.Process(
                    target=_install_content_process,
                    args=(
                        str(root),
                        str(source),
                        digest,
                        len(content),
                        start,
                    ),
                )
                for _index in range(4)
            )
            for process in processes:
                process.start()
            start.set()
            try:
                for process in processes:
                    process.join(30)
                self.assertTrue(all(not process.is_alive() for process in processes))
                self.assertEqual(
                    tuple(process.exitcode for process in processes),
                    (0, 0, 0, 0),
                )
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(5)

            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(
                tuple(target.parent.glob(f".{digest}.*.partial")),
                (),
            )
            self.assertEqual(
                len(tuple(target.parent.glob(f".{digest}.corrupt-*"))),
                1,
            )

    def test_upload_preparation_does_not_hold_global_maintenance_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            original_copy = shutil.copyfileobj
            original_verify = pipeline._verify_content_file
            original_publish = pipeline._publish_prepared_fixture_view
            copy_count = 0
            verify_count = 0
            publish_count = 0

            def copy_while_catalog_is_writeable(
                source: Any,
                output: Any,
                length: int = 0,
            ) -> None:
                nonlocal copy_count
                copy_count += 1
                self.assertTrue(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path),
                    "byte copy unexpectedly held the maintenance lock",
                )
                with pipeline._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.rollback()
                original_copy(source, output, length=length)

            def verify_while_maintenance_is_available(
                path: Path,
                *,
                expected_sha256: str,
                expected_bytes: int,
            ) -> None:
                nonlocal verify_count
                verify_count += 1
                self.assertTrue(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path),
                    "content verification unexpectedly held the maintenance lock",
                )
                original_verify(
                    path,
                    expected_sha256=expected_sha256,
                    expected_bytes=expected_bytes,
                )

            def publish_while_maintenance_is_exclusive(
                prepared: Any,
            ) -> tuple[Path, Path]:
                nonlocal publish_count
                publish_count += 1
                result = original_publish(prepared)
                self.assertFalse(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path),
                    "atomic publication did not hold the maintenance lock",
                )
                return result

            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline.os.link",
                    side_effect=OSError("hard links disabled"),
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.shutil.copyfileobj",
                    side_effect=copy_while_catalog_is_writeable,
                ),
                patch.object(
                    pipeline,
                    "_verify_content_file",
                    side_effect=verify_while_maintenance_is_available,
                ),
                patch.object(
                    pipeline,
                    "_publish_prepared_fixture_view",
                    side_effect=publish_while_maintenance_is_exclusive,
                ),
            ):
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )

            self.assertEqual(admitted.state, ImportState.ADMITTING)
            self.assertEqual(copy_count, 2)
            self.assertGreaterEqual(verify_count, 2)
            self.assertEqual(publish_count, 1)
            self.assertTrue(
                self._peer_thread_can_acquire(pipeline._maintenance_lock_path)
            )

    def test_dataset_preparation_does_not_hold_global_maintenance_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            probe_claim = pipeline._claim()
            assert probe_claim is not None
            pipeline._run_probe(probe_claim)
            ingestion_claim = pipeline._claim()
            assert ingestion_claim is not None
            original_copy = shutil.copyfileobj
            original_verify = pipeline._verify_content_file
            copy_count = 0
            verify_count = 0

            def copy_while_maintenance_is_available(
                source: Any,
                output: Any,
                length: int = 0,
            ) -> None:
                nonlocal copy_count
                copy_count += 1
                self.assertTrue(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path)
                )
                original_copy(source, output, length=length)

            def verify_while_maintenance_is_available(
                path: Path,
                *,
                expected_sha256: str,
                expected_bytes: int,
            ) -> None:
                nonlocal verify_count
                verify_count += 1
                self.assertTrue(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path)
                )
                original_verify(
                    path,
                    expected_sha256=expected_sha256,
                    expected_bytes=expected_bytes,
                )

            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline.os.link",
                    side_effect=OSError("hard links disabled"),
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.shutil.copyfileobj",
                    side_effect=copy_while_maintenance_is_available,
                ),
                patch.object(
                    pipeline,
                    "_verify_content_file",
                    side_effect=verify_while_maintenance_is_available,
                ),
            ):
                pipeline._run_ingestion(ingestion_claim)

            descriptor = pipeline.get_import(
                self.scope,
                admitted.import_id,
            )
            self.assertEqual(descriptor.state, ImportState.PUBLISHING)
            self.assertEqual(copy_count, 1)
            self.assertGreaterEqual(verify_count, 2)

    def test_stored_input_must_belong_to_its_own_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            foreign_directory = pipeline.fixture_root / "fixture-foreign"
            foreign_directory.mkdir()
            (foreign_directory / "status.jsonl").write_bytes(_fixture_bytes())
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET input_ref = ? WHERE import_id = ?",
                    (
                        "fixture-foreign/status.jsonl",
                        admitted.import_id,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            assert row is not None

            with self.assertRaisesRegex(
                Exception,
                "does not belong to its fixture",
            ):
                pipeline._blob_path(row)

    def test_expired_job_is_recovered_by_polling_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                worker_id="worker-first",
            )
            admitted = first.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(first, admitted.import_id)
            first_claim = first._claim()
            assert first_claim is not None
            self.assertEqual(
                first_claim["state"],
                ImportState.PROBING.value,
            )

            second = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                worker_id="worker-second",
            )
            with first._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET lease_expires_ns = 0 "
                    "WHERE import_id = ?",
                    (admitted.import_id,),
                )

            recovered_claim = second._claim()

            assert recovered_claim is not None
            self.assertEqual(
                str(recovered_claim["lease_owner"]).split(":", 1)[0],
                "worker-second",
            )
            self.assertEqual(
                [
                    event.event_type
                    for event in second.events(
                        self.scope,
                        admitted.import_id,
                    )
                ],
                [
                    "upload_staged",
                    "admission_started",
                    "upload_admitted",
                    "probe_started",
                    "job_recovered",
                    "probe_started",
                ],
            )

    def test_lease_renewal_is_owner_and_state_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                worker_id="lease-owner",
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            claimed = pipeline._claim()
            assert claimed is not None
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET lease_expires_ns = 1 "
                    "WHERE import_id = ?",
                    (admitted.import_id,),
                )

            self.assertTrue(
                pipeline._renew_lease(
                    admitted.import_id,
                    ImportState.PROBING,
                    str(claimed["lease_owner"]),
                )
            )
            self.assertFalse(
                pipeline._renew_lease(
                    admitted.import_id,
                    ImportState.INGESTING,
                    str(claimed["lease_owner"]),
                )
            )

    def test_lease_heartbeat_does_not_hide_stalled_stage_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    lease_seconds=5,
                    plugin_execution_timeout_seconds=0.05,
                    stalled_import_seconds=5,
                ),
                worker_id="stalled-owner",
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            claimed = pipeline._claim()
            assert claimed is not None
            progress_at_ns = 10_000_000_000
            heartbeat_at_ns = 16_000_000_000
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET updated_at_ns = ? "
                    "WHERE import_id = ?",
                    (progress_at_ns, admitted.import_id),
                )

            with patch.object(pipeline, "_now_ns", return_value=heartbeat_at_ns):
                self.assertTrue(
                    pipeline._renew_lease(
                        admitted.import_id,
                        ImportState.PROBING,
                        str(claimed["lease_owner"]),
                    )
                )
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT updated_at_ns, lease_expires_ns "
                    "FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            assert row is not None
            self.assertEqual(int(row["updated_at_ns"]), progress_at_ns)
            self.assertGreater(int(row["lease_expires_ns"]), heartbeat_at_ns)

            health = inspect_durable_queue(
                pipeline.database_path,
                stall_after_seconds=5,
                now_ns=heartbeat_at_ns,
            )
            self.assertEqual(health.pending_imports, 1)
            self.assertEqual(health.stalled_imports, 1)

    def test_reclaimed_job_uses_a_fencing_token_per_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                worker_id="shared-worker",
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            first_claim = pipeline._claim()
            assert first_claim is not None
            first_token = str(first_claim["lease_owner"])
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET lease_expires_ns = 0 "
                    "WHERE import_id = ?",
                    (admitted.import_id,),
                )

            second_claim = pipeline._claim()

            assert second_claim is not None
            second_token = str(second_claim["lease_owner"])
            self.assertNotEqual(first_token, second_token)
            self.assertFalse(
                pipeline._renew_lease(
                    admitted.import_id,
                    ImportState.PROBING,
                    first_token,
                )
            )
            self.assertTrue(
                pipeline._renew_lease(
                    admitted.import_id,
                    ImportState.PROBING,
                    second_token,
                )
            )

    def test_claimed_job_heartbeat_renews_before_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=replace(self._limits(), lease_seconds=5),
                worker_id="heartbeat-owner",
            )
            pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            claimed = pipeline._claim()
            assert claimed is not None
            renewed = threading.Event()

            def record_renewal(
                import_id: str,
                state: ImportState,
                lease_token: str,
            ) -> bool:
                del import_id, state, lease_token
                renewed.set()
                return True

            with (
                patch.object(
                    pipeline,
                    "_renew_lease",
                    side_effect=record_renewal,
                ),
                pipeline._lease_heartbeat(claimed),
            ):
                self.assertTrue(renewed.wait(3))

    def test_active_stage_cannot_race_with_cancellation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            claimed = pipeline._claim()
            assert claimed is not None
            active = pipeline.get_import(self.scope, admitted.import_id)

            with self.assertRaisesRegex(
                ImportConflictError,
                "in-progress",
            ):
                pipeline.cancel(
                    self.scope,
                    admitted.import_id,
                    expected_version=active.version,
                )

            self.assertEqual(
                pipeline.get_import(
                    self.scope,
                    admitted.import_id,
                ).state,
                ImportState.PROBING,
            )

    def test_long_worker_error_is_bounded_and_durably_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                coordinator=_ExplodingCoordinator(),
            )
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )

            self.assertEqual(failed.state, ImportState.FAILED)
            self.assertEqual(failed.error_code, "worker_failure")
            self.assertEqual(
                failed.error_message,
                PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
            )
            self.assertNotIn(
                PRIVATE_FAILURE_MARKER,
                json.dumps(failed.as_dict(), sort_keys=True),
            )
            failure_event = pipeline.events(
                self.scope,
                admitted.import_id,
            )[-1]
            self.assertEqual(failure_event.event_type, "import_failed")
            self.assertEqual(
                failure_event.message,
                PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
            )
            self.assertEqual(
                failure_event.payload,
                {"error_code": "worker_failure"},
            )
            self.assertNotIn(
                PRIVATE_FAILURE_MARKER,
                json.dumps(failure_event.as_dict(), sort_keys=True),
            )
            with closing(sqlite3.connect(pipeline.database_path)) as connection:
                public_import = connection.execute(
                    """
                    SELECT error_code, error_message
                    FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
                public_event = connection.execute(
                    """
                    SELECT message, payload_json
                    FROM ingestion_events
                    WHERE import_id = ? AND event_type = 'import_failed'
                    """,
                    (admitted.import_id,),
                ).fetchone()
                diagnostic = connection.execute(
                    """
                    SELECT public_error_code, exception_type,
                           exception_message
                    FROM ingestion_failure_diagnostics
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
            self.assertEqual(
                public_import,
                (
                    "worker_failure",
                    PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
                ),
            )
            self.assertEqual(
                public_event,
                (
                    PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
                    canonical_json({"error_code": "worker_failure"}),
                ),
            )
            self.assertNotIn(
                PRIVATE_FAILURE_MARKER,
                repr((public_import, public_event)),
            )
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self.assertEqual(diagnostic[0], "worker_failure")
            self.assertEqual(diagnostic[1], "builtins.RuntimeError")
            self.assertIn(PRIVATE_FAILURE_MARKER, diagnostic[2])

    def test_process_plugin_failure_preserves_secret_only_privately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = PluginRegistry()
            registry.register(
                ParseOnlyPlugin(),
                coordinator=_ExplodingCoordinator(),
            )
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=registry,
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    plugin_execution_timeout_seconds=10,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=20,
                )

            events = pipeline.events(self.scope, admitted.import_id)
            public_document = canonical_json(
                {
                    "descriptor": failed.as_dict(),
                    "events": [event.as_dict() for event in events],
                }
            )
            self.assertEqual(failed.error_code, "plugin_execution_failed")
            self.assertNotIn(PRIVATE_FAILURE_MARKER, public_document)
            with closing(sqlite3.connect(pipeline.database_path)) as connection:
                diagnostic = connection.execute(
                    """
                    SELECT exception_type, exception_message
                    FROM ingestion_failure_diagnostics
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self.assertEqual(diagnostic[0], "RuntimeError")
            self.assertIn(PRIVATE_FAILURE_MARKER, diagnostic[1])

    def test_legacy_public_failures_migrate_to_private_diagnostics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            pipeline = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            legacy_payload = canonical_json(
                {
                    "error_code": "legacy_plugin_crash",
                    "detail": PRIVATE_FAILURE_MARKER,
                }
            )
            with closing(sqlite3.connect(pipeline.database_path)) as connection:
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET state = 'failed', attempt_count = 1,
                        error_code = 'legacy_plugin_crash',
                        error_message = ?
                    WHERE import_id = ?
                    """,
                    (PRIVATE_FAILURE_MARKER, admitted.import_id),
                )
                connection.execute(
                    """
                    INSERT INTO ingestion_events (
                        import_id, state, event_type, message,
                        payload_json, created_at_ns
                    ) VALUES (?, 'failed', 'import_failed', ?, ?, ?)
                    """,
                    (
                        admitted.import_id,
                        PRIVATE_FAILURE_MARKER,
                        legacy_payload,
                        time.time_ns(),
                    ),
                )
                connection.commit()

            restarted = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            descriptor = restarted.get_import(
                self.scope,
                admitted.import_id,
            )
            events = restarted.events(self.scope, admitted.import_id)
            public_document = canonical_json(
                {
                    "descriptor": descriptor.as_dict(),
                    "events": [event.as_dict() for event in events],
                }
            )
            self.assertNotIn(PRIVATE_FAILURE_MARKER, public_document)
            self.assertEqual(descriptor.error_code, "worker_failure")
            self.assertEqual(
                descriptor.error_message,
                PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
            )
            self.assertEqual(events[-1].payload, {"error_code": "worker_failure"})

            with closing(sqlite3.connect(restarted.database_path)) as connection:
                public_row = connection.execute(
                    """
                    SELECT error_code, error_message
                    FROM ingestion_imports WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()
                public_event = connection.execute(
                    """
                    SELECT message, payload_json
                    FROM ingestion_events
                    WHERE import_id = ? AND event_type = 'import_failed'
                    """,
                    (admitted.import_id,),
                ).fetchone()
                private_rows = connection.execute(
                    """
                    SELECT exception_message
                    FROM ingestion_failure_diagnostics
                    WHERE import_id = ?
                    ORDER BY diagnostic_id
                    """,
                    (admitted.import_id,),
                ).fetchall()
            self.assertEqual(
                public_row,
                (
                    "worker_failure",
                    PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
                ),
            )
            self.assertEqual(
                public_event,
                (
                    PUBLIC_INGESTION_FAILURE_MESSAGES["worker_failure"],
                    canonical_json({"error_code": "worker_failure"}),
                ),
            )
            self.assertGreaterEqual(len(private_rows), 2)
            self.assertTrue(
                all(PRIVATE_FAILURE_MARKER in row[0] for row in private_rows)
            )

    def test_connection_closes_when_pragma_setup_fails(self) -> None:
        pipeline = object.__new__(DurableIngestionPipeline)
        pipeline.database_path = Path("unused.sqlite3")
        connection = _PragmaFailureConnection()

        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.sqlite3.connect",
                return_value=connection,
            ),
            self.assertRaisesRegex(RuntimeError, "pragma rejected"),
            pipeline._connect(),
        ):
            self.fail("connection setup should have failed")

        self.assertTrue(connection.closed)

    def test_no_match_is_durable_failure_and_can_be_resumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((_NoMatchPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                failed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertEqual(failed.state, ImportState.FAILED)
                self.assertEqual(
                    failed.error_code,
                    "ingestion_rejected",
                )
                resumed = pipeline.resume(
                    self.scope,
                    admitted.import_id,
                )
                self.assertEqual(resumed.state, ImportState.QUEUED)

    def test_retry_projection_uses_the_configured_attempt_limit(self) -> None:
        for max_attempts, expected_remaining, expected_retryable in (
            (1, 0, False),
            (5, 4, True),
        ):
            with (
                self.subTest(max_attempts=max_attempts),
                tempfile.TemporaryDirectory() as directory,
            ):
                pipeline = DurableIngestionPipeline(
                    Path(directory),
                    registry=PluginRegistry((_NoMatchPlugin(),)),
                    publisher=_Publisher(),
                    limits=replace(
                        self._limits(),
                        max_attempts=max_attempts,
                    ),
                )
                with pipeline:
                    admitted = pipeline.submit_bytes(
                        self.scope,
                        _fixture_bytes(),
                        original_name="status.jsonl",
                    )
                    failed = pipeline.wait(
                        self.scope,
                        admitted.import_id,
                        timeout=10,
                    )

                self.assertEqual(failed.attempt_count, 1)
                self.assertEqual(failed.max_attempts, max_attempts)
                self.assertEqual(
                    failed.attempts_remaining,
                    expected_remaining,
                )
                self.assertEqual(
                    failed.retryable,
                    expected_retryable,
                )
                projected_error = failed.as_dict()["error"]
                assert isinstance(projected_error, dict)
                self.assertEqual(
                    projected_error["attempts_remaining"],
                    expected_remaining,
                )
                self.assertEqual(
                    projected_error["retryable"],
                    expected_retryable,
                )

    def test_upload_limit_is_enforced_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=PipelineLimits(
                    max_upload_bytes=4,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                ),
            )
            with self.assertRaisesRegex(Exception, "byte limit"):
                pipeline.submit_bytes(
                    self.scope,
                    b"12345",
                    original_name="status.jsonl",
                )
            self.assertEqual(pipeline.list_imports(self.scope), ())

    def test_retention_is_dry_run_by_default_and_deletes_bounded_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET state = ?, updated_at_ns = 0
                    WHERE import_id = ?
                    """,
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
                row = connection.execute(
                    "SELECT blob_ref FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            assert row is not None
            blob = pipeline.blob_root / Path(str(row["blob_ref"]))
            inventory = pipeline.run_retention(
                self.scope,
                now_ns=time.time_ns() + 1_000_000_000,
            )
            self.assertFalse(inventory.executed)
            self.assertEqual(inventory.eligible_imports, 1)
            self.assertTrue(blob.exists())
            self.assertEqual(len(pipeline.list_imports(self.scope)), 1)

            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1_000_000_000,
            )
            self.assertTrue(result.executed)
            self.assertEqual(result.deleted_imports, 1)
            self.assertGreaterEqual(result.deleted_files, 2)
            self.assertFalse(blob.exists())
            self.assertEqual(pipeline.list_imports(self.scope), ())
            audits = pipeline.list_retention_audits(self.scope)
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0].audit_id, result.audit_id)
            self.assertEqual(audits[0].report["deleted_imports"], 1)

    def test_destructive_retention_operation_replays_exact_stable_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            first = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="retention operator",
                operation_id="retention-run-001",
            )

            # Reopening proves the stable result is journaled rather than held
            # in process memory.
            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            replay = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="retention operator",
                operation_id="retention-run-001",
            )
            self.assertEqual(replay, first)
            audits = reopened.list_retention_audits(self.scope)
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0].actor, "retention operator")
            self.assertEqual(audits[0].operation_id, "retention-run-001")
            self.assertEqual(audits[0].effective_now_ns, effective_now)
            self.assertEqual(audits[0].state, "completed")
            self.assertIsNotNone(audits[0].request_digest)

    def test_retention_operation_conflict_fails_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            first = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="first.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, first.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="operator-a",
                operation_id="retention-conflict",
            )
            second = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="second.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, second.import_id),
                )

            with self.assertRaisesRegex(
                ImportConflictError,
                "different request",
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="operator-b",
                    operation_id="retention-conflict",
                )
            changed_policy_pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=999,
                ),
            )
            with self.assertRaisesRegex(
                ImportConflictError,
                "different request",
            ):
                changed_policy_pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="operator-a",
                    operation_id="retention-conflict",
                )
            self.assertEqual(
                pipeline.get_import(self.scope, second.import_id).state,
                ImportState.CANCELLED,
            )
            self.assertEqual(len(pipeline.list_retention_audits(self.scope)), 1)

    def test_retention_operation_reuses_persisted_implicit_clock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            with patch.object(pipeline, "_now_ns", return_value=effective_now):
                first = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    actor="operator-a",
                    operation_id="retention-implicit-clock",
                )

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            with patch.object(
                reopened,
                "_now_ns",
                side_effect=AssertionError("replay must not read a new clock"),
            ):
                replay = reopened.run_retention(
                    self.scope,
                    dry_run=False,
                    actor="operator-a",
                    operation_id="retention-implicit-clock",
                )
            self.assertEqual(replay, first)
            self.assertEqual(replay.evaluated_at_ns, effective_now)

    def test_schema_initialization_is_independent_from_retention_fence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            pipeline = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            self.assertNotEqual(
                pipeline._schema_lock_path,
                pipeline._maintenance_lock_path,
            )
            with (
                ThreadPoolExecutor(max_workers=1) as executor,
                exclusive_file_lock(pipeline._maintenance_lock_path),
            ):
                reopened_future = executor.submit(
                    DurableIngestionPipeline,
                    root,
                    registry=registry,
                    publisher=_Publisher(),
                    limits=self._limits(),
                    worker_id="constructor-during-retention",
                )
                reopened = reopened_future.result(timeout=3)
            reopened.close(timeout=3)

    def test_retention_sizes_are_measured_outside_publication_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            stale_directory = pipeline.fixture_root / f"fixture-{'a' * 32}"
            stale_directory.mkdir()
            (stale_directory / "payload.bin").write_bytes(b"payload")
            os.utime(stale_directory, ns=(0, 0))
            original_path_bytes = pipeline._path_bytes
            measurements = 0

            def measure(path: Path) -> int:
                nonlocal measurements
                measurements += 1
                self.assertTrue(
                    self._peer_thread_can_acquire(pipeline._maintenance_lock_path),
                    f"recursive size walk for {path} held publication fence",
                )
                return original_path_bytes(path)

            with patch.object(pipeline, "_path_bytes", side_effect=measure):
                result = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns(),
                    actor="size-fence-test",
                    operation_id="size-fence-001",
                )
            self.assertGreater(measurements, 0)
            self.assertGreater(result.estimated_bytes, 0)
            self.assertFalse(stale_directory.exists())

    def test_incremental_cleanup_journal_is_linear_and_reuses_connection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1_000,
                    max_scan_entries=2_000,
                ),
            )
            item_count = 320
            for index in range(item_count):
                path = pipeline.spool_root / f"linear-{index:04d}.partial"
                path.write_bytes(b"x")
                os.utime(path, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("pause after immutable plan commit"),
                ),
                self.assertRaisesRegex(RuntimeError, "immutable plan"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="linear-journal-test",
                    operation_id="linear-journal-001",
                )
            audit = pipeline.list_retention_audits(self.scope)[0]
            original_connect = pipeline._connect
            connection_count = 0
            traced_statements: list[str] = []

            @contextmanager
            def traced_connect() -> Any:
                nonlocal connection_count
                connection_count += 1
                with original_connect() as connection:
                    connection.set_trace_callback(traced_statements.append)
                    yield connection

            with patch.object(pipeline, "_connect", side_effect=traced_connect):
                result = pipeline._resume_retention_cleanup(
                    self.scope,
                    audit_id=audit.audit_id,
                )
            progress_inserts = [
                statement
                for statement in traced_statements
                if statement.lstrip().startswith(
                    "INSERT INTO ingestion_retention_cleanup_progress"
                )
            ]
            transaction_begins = [
                statement
                for statement in traced_statements
                if statement.strip().upper() == "BEGIN IMMEDIATE"
            ]
            transaction_commits = [
                statement
                for statement in traced_statements
                if statement.strip().upper() == "COMMIT"
            ]
            expected_cleanup_batches = (
                item_count + RETENTION_CLEANUP_FENCE_BATCH - 1
            ) // RETENTION_CLEANUP_FENCE_BATCH
            self.assertEqual(result.deleted_files, item_count)
            self.assertEqual(connection_count, 1)
            self.assertEqual(len(progress_inserts), item_count)
            # One bounded transaction checkpoints each maintenance-fence
            # batch; the final transaction publishes the aggregate report.
            self.assertEqual(
                len(transaction_begins),
                expected_cleanup_batches + 1,
            )
            self.assertEqual(transaction_commits, ["COMMIT"] * len(transaction_begins))
            self.assertLess(
                sum(len(statement.encode("utf-8")) for statement in progress_inserts),
                item_count * 1_024,
            )
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT cleanup_progress_json FROM ingestion_retention_audit "
                    "WHERE audit_id = ?",
                    (audit.audit_id,),
                ).fetchone()
                progress_count = int(
                    connection.execute(
                        "SELECT COUNT(*) "
                        "FROM ingestion_retention_cleanup_progress "
                        "WHERE audit_id = ?",
                        (audit.audit_id,),
                    ).fetchone()[0]
                )
            assert row is not None
            self.assertEqual(str(row["cleanup_progress_json"]), "{}")
            self.assertEqual(progress_count, item_count)

    def test_legacy_aggregate_cleanup_checkpoint_migrates_exactly_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            for name in ("legacy-a.partial", "legacy-b.partial"):
                path = pipeline.spool_root / name
                path.write_bytes(name.encode())
                os.utime(path, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("legacy checkpoint setup"),
                ),
                self.assertRaisesRegex(RuntimeError, "legacy checkpoint"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="legacy-progress-test",
                    operation_id="legacy-progress-001",
                )
            audit = pipeline.list_retention_audits(self.scope)[0]
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT plan_json FROM ingestion_retention_audit "
                    "WHERE audit_id = ?",
                    (audit.audit_id,),
                ).fetchone()
            assert row is not None
            plan = json.loads(str(row["plan_json"]))
            first = plan["work_items"][0]
            first_path = pipeline.spool_root / Path(first["relative_path"])
            first_path.unlink()
            legacy_progress = canonical_json(
                {
                    "0": {
                        "state": "deleted",
                        "bytes": first["planned_bytes"],
                        "detail": None,
                    }
                }
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_retention_audit "
                    "SET cleanup_progress_json = ? WHERE audit_id = ?",
                    (legacy_progress, audit.audit_id),
                )

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            resumed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at,
                actor="legacy-progress-test",
                operation_id="legacy-progress-001",
            )
            with reopened._connect() as connection:
                migrated = connection.execute(
                    "SELECT sequence, state FROM "
                    "ingestion_retention_cleanup_progress "
                    "WHERE audit_id = ? ORDER BY sequence",
                    (audit.audit_id,),
                ).fetchall()
                aggregate = connection.execute(
                    "SELECT cleanup_progress_json "
                    "FROM ingestion_retention_audit WHERE audit_id = ?",
                    (audit.audit_id,),
                ).fetchone()
            self.assertEqual(resumed.deleted_files, 2)
            self.assertEqual(
                [(int(row["sequence"]), str(row["state"])) for row in migrated],
                [(0, "deleted"), (1, "deleted")],
            )
            assert aggregate is not None
            self.assertEqual(str(aggregate["cleanup_progress_json"]), "{}")

    def test_legacy_cleanup_sequence_uses_bounded_canonical_grammar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            item = _RetentionWorkItem(
                sequence=0,
                action="partial",
                root="spool",
                reference=None,
                relative_path="legacy.partial",
                planned_bytes=1,
            )
            with pipeline._connect() as connection:
                for raw_sequence in ("00", "-0", "+0", "1", "100000000000000000000"):
                    with (
                        self.subTest(raw_sequence=raw_sequence),
                        self.assertRaisesRegex(
                            IngestionPipelineError,
                            "cleanup progress is invalid",
                        ),
                    ):
                        pipeline._migrate_legacy_retention_progress(
                            connection,
                            audit_id="not-reached",
                            legacy_json=canonical_json({raw_sequence: {}}),
                            items_by_sequence={0: item},
                        )

    def test_cleanup_batch_rolls_back_and_replays_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            paths = tuple(
                pipeline.spool_root / f"uncommitted-{index}.partial"
                for index in range(2)
            )
            for path in paths:
                path.write_bytes(b"x")
                os.utime(path, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("pause after plan commit"),
                ),
                self.assertRaisesRegex(RuntimeError, "plan commit"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="uncommitted-batch-test",
                    operation_id="uncommitted-batch-001",
                )
            audit = pipeline.list_retention_audits(self.scope)[0]
            original_connect = pipeline._connect

            class FailSecondCheckpoint:
                def __init__(self, connection: sqlite3.Connection) -> None:
                    self.connection = connection
                    self.progress_inserts = 0

                def execute(
                    self,
                    statement: str,
                    parameters: Any = (),
                ) -> sqlite3.Cursor:
                    if statement.lstrip().startswith(
                        "INSERT INTO ingestion_retention_cleanup_progress"
                    ):
                        self.progress_inserts += 1
                        if self.progress_inserts == 2:
                            raise RuntimeError("simulated loss before batch commit")
                    return self.connection.execute(statement, parameters)

                def __getattr__(self, name: str) -> Any:
                    return getattr(self.connection, name)

            @contextmanager
            def failing_connect() -> Any:
                with original_connect() as connection:
                    yield FailSecondCheckpoint(connection)

            with (
                patch.object(pipeline, "_connect", side_effect=failing_connect),
                self.assertRaisesRegex(RuntimeError, "before batch commit"),
            ):
                pipeline._resume_retention_cleanup(
                    self.scope,
                    audit_id=audit.audit_id,
                )
            self.assertTrue(all(not path.exists() for path in paths))
            with pipeline._connect() as connection:
                progress_count = int(
                    connection.execute(
                        "SELECT COUNT(*) "
                        "FROM ingestion_retention_cleanup_progress "
                        "WHERE audit_id = ?",
                        (audit.audit_id,),
                    ).fetchone()[0]
                )
            self.assertEqual(progress_count, 0)

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            resumed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at,
                actor="uncommitted-batch-test",
                operation_id="uncommitted-batch-001",
            )
            self.assertEqual(resumed.deleted_files, len(paths))
            self.assertEqual(resumed.deletion_failures, 0)

    def test_concurrent_direct_cleanup_resumes_converge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1_000,
                    max_scan_entries=2_000,
                ),
            )
            item_count = RETENTION_CLEANUP_FENCE_BATCH + 3
            for index in range(item_count):
                path = pipeline.spool_root / f"concurrent-{index:04d}.partial"
                path.write_bytes(b"x")
                os.utime(path, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("pause before concurrent resume"),
                ),
                self.assertRaisesRegex(RuntimeError, "concurrent resume"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="concurrent-resume-test",
                    operation_id="concurrent-resume-001",
                )
            audit = pipeline.list_retention_audits(self.scope)[0]
            original_migrate = pipeline._migrate_legacy_retention_progress
            original_process = pipeline._process_retention_work_item
            readers_aligned = threading.Barrier(2)
            first_process = True
            process_guard = threading.Lock()
            process_calls = 0

            def align_readers(*args: Any, **kwargs: Any) -> None:
                original_migrate(*args, **kwargs)
                readers_aligned.wait(timeout=10)

            def observed_process(*args: Any, **kwargs: Any) -> Any:
                nonlocal first_process, process_calls
                with process_guard:
                    process_calls += 1
                    delay = first_process
                    first_process = False
                if delay:
                    time.sleep(0.1)
                return original_process(*args, **kwargs)

            with (
                patch.object(
                    pipeline,
                    "_migrate_legacy_retention_progress",
                    side_effect=align_readers,
                ),
                patch.object(
                    pipeline,
                    "_process_retention_work_item",
                    side_effect=observed_process,
                ),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                futures = tuple(
                    executor.submit(
                        pipeline._resume_retention_cleanup,
                        self.scope,
                        audit_id=audit.audit_id,
                    )
                    for _index in range(2)
                )
                results = tuple(future.result(timeout=20) for future in futures)

            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0].deleted_files, item_count)
            self.assertEqual(process_calls, item_count)
            with pipeline._connect() as connection:
                progress_count = int(
                    connection.execute(
                        "SELECT COUNT(*) "
                        "FROM ingestion_retention_cleanup_progress "
                        "WHERE audit_id = ?",
                        (audit.audit_id,),
                    ).fetchone()[0]
                )
            self.assertEqual(progress_count, item_count)

    def test_upload_can_publish_between_bounded_cleanup_batches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1_000,
                    max_scan_entries=2_000,
                ),
            )
            for index in range(65):
                path = pipeline.spool_root / f"yield-{index:04d}.partial"
                path.write_bytes(b"x")
                os.utime(path, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("pause before batched cleanup"),
                ),
                self.assertRaisesRegex(RuntimeError, "batched cleanup"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="cleanup-yield-test",
                    operation_id="cleanup-yield-001",
                )

            first_batch_released = threading.Event()
            allow_more_cleanup = threading.Event()
            retention_thread_id: int | None = None

            @contextmanager
            def observed_lock(path: Path) -> Any:
                with exclusive_file_lock(path):
                    yield
                if (
                    path == pipeline._maintenance_lock_path
                    and threading.get_ident() == retention_thread_id
                    and not first_batch_released.is_set()
                ):
                    first_batch_released.set()
                    if not allow_more_cleanup.wait(10):
                        raise TimeoutError("upload did not finish between batches")

            def resume() -> Any:
                nonlocal retention_thread_id
                retention_thread_id = threading.get_ident()
                return pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="cleanup-yield-test",
                    operation_id="cleanup-yield-001",
                )

            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline.exclusive_file_lock",
                    side_effect=observed_lock,
                ),
                ThreadPoolExecutor(max_workers=1) as executor,
            ):
                retention = executor.submit(resume)
                self.assertTrue(first_batch_released.wait(10))
                try:
                    admitted = pipeline.submit_bytes(
                        self.scope,
                        _fixture_bytes(),
                        original_name="published-between-cleanup-batches.jsonl",
                    )
                finally:
                    allow_more_cleanup.set()
                result = retention.result(timeout=10)

            self.assertEqual(result.deleted_files, 65)
            self.assertEqual(
                pipeline.get_import(self.scope, admitted.import_id).import_id,
                admitted.import_id,
            )

    def test_retention_operation_resumes_after_database_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("simulated process loss after commit"),
                ),
                self.assertRaisesRegex(RuntimeError, "after commit"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="operator-a",
                    operation_id="retention-after-commit",
                )
            self.assertEqual(pipeline.list_imports(self.scope), ())
            pending = pipeline.list_retention_audits(self.scope)
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].state, "cleanup_pending")

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            completed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="operator-a",
                operation_id="retention-after-commit",
            )
            self.assertEqual(completed.deleted_imports, 1)
            self.assertEqual(
                reopened.list_retention_audits(self.scope)[0].state,
                "completed",
            )

    def test_retention_operation_resumes_after_file_delete_before_progress(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            original_delete = pipeline._delete_path

            def delete_then_crash(path: Path) -> tuple[bool, int]:
                original_delete(path)
                raise RuntimeError("simulated loss before cleanup checkpoint")

            with (
                patch.object(
                    pipeline,
                    "_delete_path",
                    side_effect=delete_then_crash,
                ),
                self.assertRaisesRegex(RuntimeError, "before cleanup"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="operator-a",
                    operation_id="retention-mid-cleanup",
                )

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            completed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="operator-a",
                operation_id="retention-mid-cleanup",
            )
            replay = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=effective_now,
                actor="operator-a",
                operation_id="retention-mid-cleanup",
            )
            self.assertEqual(replay, completed)
            self.assertGreaterEqual(completed.deleted_files, 2)
            self.assertGreater(completed.deleted_bytes, 0)
            self.assertEqual(completed.deletion_failures, 0)

    def test_legacy_retention_audit_schema_is_upgraded_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "control-plane.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    CREATE TABLE ingestion_retention_audit (
                        audit_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        project_id TEXT NOT NULL,
                        workspace_id TEXT NOT NULL,
                        report_json TEXT NOT NULL,
                        created_at_ns INTEGER NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO ingestion_retention_audit VALUES "
                    "('legacy-audit', 'tenant-a', 'project-a', "
                    "'workspace-a', '{}', 17)"
                )
                connection.commit()

            def initialize(index: int) -> DurableIngestionPipeline:
                return DurableIngestionPipeline(
                    root,
                    registry=PluginRegistry((ParseOnlyPlugin(),)),
                    publisher=_Publisher(),
                    limits=self._limits(),
                    worker_id=f"migration-worker-{index}",
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                pipelines = tuple(executor.map(initialize, range(4)))
            pipeline = pipelines[0]
            audit = pipeline.list_retention_audits(self.scope)[0]
            self.assertEqual(audit.audit_id, "legacy-audit")
            self.assertEqual(audit.state, "completed")
            self.assertIsNone(audit.operation_id)
            with pipeline._connect() as connection:
                columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(ingestion_retention_audit)"
                    )
                }
            self.assertTrue(
                {
                    "actor",
                    "operation_id",
                    "request_digest",
                    "effective_now_ns",
                    "plan_json",
                    "cleanup_progress_json",
                    "state",
                }.issubset(columns)
            )

    def test_legacy_artifact_pin_backfill_runs_once_across_release_and_restart(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            pipeline = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM ingestion_imports WHERE import_id = ?",
                    (completed.import_id,),
                ).fetchone()
                assert row is not None
                # Reproduce a database created before the pin schema
                # migration: catalog ownership is present in the durable
                # import row, but neither pins nor a migration ledger exist.
                connection.execute("DROP TABLE ingestion_artifact_pins")
                connection.execute("DROP TABLE ingestion_schema_migrations")

            with (
                patch.object(
                    DurableIngestionPipeline,
                    "_now_ns",
                    side_effect=RuntimeError("migration marker clock failed"),
                ),
                self.assertRaisesRegex(RuntimeError, "marker clock failed"),
            ):
                DurableIngestionPipeline(
                    root,
                    registry=registry,
                    publisher=_Publisher(),
                    limits=self._limits(),
                )
            with closing(sqlite3.connect(root / "control-plane.sqlite3")) as connection:
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_artifact_pins"
                        ).fetchone()[0]
                    ),
                    0,
                )
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_schema_migrations"
                        ).fetchone()[0]
                    ),
                    1,
                )

            migrated = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with migrated._connect() as connection:
                pin_kinds = {
                    str(pin["artifact_kind"])
                    for pin in connection.execute(
                        "SELECT artifact_kind FROM ingestion_artifact_pins"
                    ).fetchall()
                }
                migration_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM ingestion_schema_migrations"
                    ).fetchone()[0]
                )
            self.assertEqual(pin_kinds, {"blob", "dataset"})
            self.assertEqual(migration_count, 2)

            self.assertTrue(
                migrated.release_artifact_pin(
                    self.scope,
                    artifact_kind="blob",
                    artifact_ref=str(row["blob_ref"]),
                    owner_operation_id=str(row["admission_operation_id"]),
                )
            )
            self.assertTrue(
                migrated.release_artifact_pin(
                    self.scope,
                    artifact_kind="dataset",
                    artifact_ref=str(row["staged_dataset_ref"]),
                    owner_operation_id=str(row["publication_operation_id"]),
                )
            )
            migrated.close(timeout=5)

            reopened = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with reopened._connect() as connection:
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_artifact_pins"
                        ).fetchone()[0]
                    ),
                    0,
                )
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_schema_migrations"
                        ).fetchone()[0]
                    ),
                    2,
                )
            reopened.close(timeout=5)

    def test_pin_aware_database_upgrade_preserves_prior_catalog_release(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = PluginRegistry((ParseOnlyPlugin(),))
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM ingestion_imports WHERE import_id = ?",
                    (completed.import_id,),
                ).fetchone()
            assert row is not None
            blob_path = pipeline.blob_root / Path(str(row["blob_ref"]))
            dataset_path = pipeline.dataset_root / Path(str(row["staged_dataset_ref"]))
            # Leave one pin present and one absent. A pin-aware database from
            # the old build can also reach this shape if it crashes between
            # its two non-transactional INSERT statements. That state is
            # indistinguishable from this deliberate dataset release, so the
            # migration must preserve the absence rather than synthesize it.
            self.assertTrue(
                pipeline.release_artifact_pin(
                    self.scope,
                    artifact_kind="dataset",
                    artifact_ref=str(row["staged_dataset_ref"]),
                    owner_operation_id=str(row["publication_operation_id"]),
                )
            )
            # Model deployment from the pin-aware buggy build: its pin table
            # exists, its release already committed, and only the new explicit
            # migration ledger is absent.
            with pipeline._connect() as connection:
                connection.execute("DROP TABLE ingestion_schema_migrations")
                connection.execute(
                    "UPDATE ingestion_imports SET updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (completed.import_id,),
                )

            reopened = DurableIngestionPipeline(
                root,
                registry=registry,
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            with reopened._connect() as connection:
                pins = connection.execute(
                    "SELECT artifact_kind FROM ingestion_artifact_pins"
                ).fetchall()
                self.assertEqual(
                    {str(pin["artifact_kind"]) for pin in pins},
                    {"blob"},
                )
                self.assertEqual(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_schema_migrations"
                        ).fetchone()[0]
                    ),
                    1,
                )
            self.assertTrue(
                reopened.release_artifact_pin(
                    self.scope,
                    artifact_kind="blob",
                    artifact_ref=str(row["blob_ref"]),
                    owner_operation_id=str(row["admission_operation_id"]),
                )
            )
            retained = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1_000_000_000,
            )
            self.assertEqual(retained.deleted_imports, 1)
            self.assertEqual(retained.content_blobs, 1)
            self.assertEqual(retained.revision_datasets, 1)
            self.assertFalse(blob_path.exists())
            self.assertFalse(dataset_path.exists())
            reopened.close(timeout=5)

    def test_catalog_pin_requires_exact_coordinated_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self._admit_staged(pipeline, admitted.import_id)
            queued = pipeline.get_import(self.scope, admitted.import_id)
            cancelled = pipeline.cancel(
                self.scope,
                admitted.import_id,
                expected_version=queued.version,
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (cancelled.import_id,),
                )
                row = connection.execute(
                    "SELECT blob_ref FROM ingestion_imports WHERE import_id = ?",
                    (cancelled.import_id,),
                ).fetchone()
            assert row is not None
            blob_ref = str(row["blob_ref"])
            blob = pipeline.blob_root / Path(blob_ref)

            first = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1_000_000_000,
            )
            self.assertEqual(first.deleted_imports, 0)
            self.assertEqual(first.content_blobs, 0)
            self.assertTrue(blob.exists())
            self.assertEqual(
                pipeline.get_import(self.scope, admitted.import_id).state,
                ImportState.CANCELLED,
            )
            self.assertFalse(
                pipeline.release_artifact_pin(
                    self.scope,
                    artifact_kind="blob",
                    artifact_ref=blob_ref,
                    owner_operation_id="wrong-operation",
                )
            )
            self.assertTrue(blob.exists())
            self.assertTrue(
                pipeline.release_artifact_pin(
                    self.scope,
                    artifact_kind="blob",
                    artifact_ref=blob_ref,
                    owner_operation_id=f"admission:{admitted.import_id}",
                )
            )
            second = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 2_000_000_000,
            )
            self.assertEqual(second.deleted_imports, 1)
            self.assertEqual(second.content_blobs, 1)
            self.assertFalse(blob.exists())
            third = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 3_000_000_000,
            )
            self.assertEqual(third.eligible_imports, 0)
            self.assertEqual(third.content_blobs, 0)

    def test_completed_blob_and_dataset_remain_pinned_until_catalog_release(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            with pipeline:
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(
                    self.scope,
                    admitted.import_id,
                    timeout=10,
                )
            self.assertEqual(completed.state, ImportState.COMPLETED)
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (completed.import_id,),
                )
                row = connection.execute(
                    "SELECT * FROM ingestion_imports WHERE import_id = ?",
                    (completed.import_id,),
                ).fetchone()
            assert row is not None
            blob_ref = str(row["blob_ref"])
            dataset_ref = str(row["staged_dataset_ref"])
            blob = pipeline.blob_root / Path(blob_ref)
            dataset = pipeline.dataset_root / Path(dataset_ref)

            first = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1_000_000_000,
            )
            self.assertEqual(first.deleted_imports, 0)
            self.assertTrue(blob.exists())
            self.assertTrue(dataset.exists())
            self.assertTrue(
                pipeline.release_artifact_pin(
                    self.scope,
                    artifact_kind="blob",
                    artifact_ref=blob_ref,
                    owner_operation_id=str(row["admission_operation_id"]),
                )
            )
            self.assertTrue(
                pipeline.release_artifact_pin(
                    self.scope,
                    artifact_kind="dataset",
                    artifact_ref=dataset_ref,
                    owner_operation_id=str(row["publication_operation_id"]),
                )
            )
            second = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 2_000_000_000,
            )
            self.assertEqual(second.deleted_imports, 1)
            self.assertEqual(second.content_blobs, 1)
            self.assertEqual(second.revision_datasets, 1)
            self.assertFalse(blob.exists())
            self.assertFalse(dataset.exists())
            third = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 3_000_000_000,
            )
            self.assertEqual(third.eligible_imports, 0)
            self.assertEqual(third.content_blobs, 0)
            self.assertEqual(third.revision_datasets, 0)

    def test_retention_audit_records_bounded_file_cleanup_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )

            with patch.object(
                pipeline,
                "_delete_path",
                side_effect=PermissionError("injected cleanup denial"),
            ):
                result = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns() + 1_000_000_000,
                )

            self.assertGreaterEqual(result.deletion_failures, 1)
            self.assertLessEqual(len(result.failure_details), 100)
            self.assertIn("PermissionError", result.failure_details[0])
            audit = pipeline.list_retention_audits(self.scope)[0]
            self.assertEqual(
                audit.report["deletion_failures"],
                result.deletion_failures,
            )
            self.assertIn("PermissionError", audit.report["failure_details"][0])

    def test_admission_row_and_byte_quotas_apply_while_retention_disabled(
        self,
    ) -> None:
        content = _fixture_bytes()
        for policy in (
            RetentionPolicy(max_workspace_imports=1),
            RetentionPolicy(max_workspace_bytes=len(content)),
            RetentionPolicy(max_tenant_imports=1),
            RetentionPolicy(max_tenant_bytes=len(content)),
        ):
            with (
                self.subTest(policy=policy),
                tempfile.TemporaryDirectory() as directory,
            ):
                pipeline = DurableIngestionPipeline(
                    Path(directory),
                    registry=PluginRegistry((ParseOnlyPlugin(),)),
                    publisher=_Publisher(),
                    limits=self._limits(),
                    retention_policy=policy,
                )
                pipeline.submit_bytes(
                    self.scope,
                    content,
                    original_name="first.jsonl",
                )
                with self.assertRaises(ImportQuotaExceededError):
                    pipeline.submit_bytes(
                        self.scope,
                        content,
                        original_name="second.jsonl",
                    )
                self.assertEqual(len(pipeline.list_imports(self.scope)), 1)
                self.assertEqual(len(tuple(pipeline.fixture_root.iterdir())), 1)

    def test_enabled_retention_construction_preserves_aged_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "spool"
            spool.mkdir(parents=True)
            stale = spool / "abandoned.partial"
            stale.write_bytes(b"partial")
            os.utime(stale, ns=(0, 0))

            enabled = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    stale_partial_seconds=1,
                ),
            )
            self.assertTrue(stale.exists())
            system_scope = ImportScope(
                "system-retention",
                "system-retention",
                "startup-sweep",
            )
            self.assertEqual(enabled.list_retention_audits(system_scope), ())

    def test_dynamic_spool_lock_handoff_retires_one_inode_without_deadlock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            lock_path = pipeline.spool_root / ".shared.partial.active.lock"
            first_entered = threading.Event()
            release_first = threading.Event()
            second_entered = threading.Event()

            def first() -> None:
                with pipeline._spool_active_file_lock(lock_path):
                    first_entered.set()
                    if not release_first.wait(5):
                        raise TimeoutError("test did not release first spool lock")

            def second() -> None:
                if not first_entered.wait(5):
                    raise TimeoutError("first spool lock was not acquired")
                with pipeline._spool_active_file_lock(lock_path):
                    second_entered.set()

            with ThreadPoolExecutor(max_workers=2) as executor:
                first_future = executor.submit(first)
                second_future = executor.submit(second)
                self.assertTrue(first_entered.wait(5))
                self.assertFalse(second_entered.wait(0.05))
                release_first.set()
                first_future.result(timeout=5)
                second_future.result(timeout=5)

            self.assertTrue(second_entered.is_set())
            self.assertFalse(lock_path.exists())

    def test_dynamic_spool_lock_handoff_is_process_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = root / "spool-namespace.lock"
            lock_path = root / ".shared.partial.active.lock"
            context = multiprocessing.get_context("spawn")
            first_entered = context.Event()
            release_first = context.Event()
            second_entered = context.Event()
            release_second = context.Event()
            first = context.Process(
                target=_hold_dynamic_spool_lock_process,
                args=(str(gate), str(lock_path), first_entered, release_first),
            )
            second = context.Process(
                target=_hold_dynamic_spool_lock_process,
                args=(str(gate), str(lock_path), second_entered, release_second),
            )
            first.start()
            try:
                self.assertTrue(first_entered.wait(10))
                second.start()
                self.assertFalse(second_entered.wait(0.1))
                release_first.set()
                self.assertTrue(second_entered.wait(10))
                release_second.set()
                first.join(timeout=10)
                second.join(timeout=10)
                self.assertFalse(first.is_alive())
                self.assertFalse(second.is_alive())
                self.assertEqual(first.exitcode, 0)
                self.assertEqual(second.exitcode, 0)
                self.assertFalse(lock_path.exists())
            finally:
                release_first.set()
                release_second.set()
                for process in (first, second):
                    if process.pid is not None and process.is_alive():
                        process.terminate()
                    if process.pid is not None:
                        process.join(timeout=5)

    def test_try_existing_lock_never_recreates_an_absent_dynamic_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "absent.lock"
            with try_existing_exclusive_file_lock(lock_path) as acquired:
                self.assertFalse(acquired)
            self.assertFalse(lock_path.exists())

    def test_host_reaper_prunes_only_exact_empty_content_shards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            canonical = pipeline.blob_root / "aa" / "bb"
            canonical.mkdir(parents=True)
            malformed = pipeline.blob_root / "GG" / "hh"
            malformed.mkdir(parents=True)
            nonempty = pipeline.dataset_root / "cc" / "dd"
            nonempty.mkdir(parents=True)
            (nonempty / "unknown-object").write_bytes(b"preserve")
            for path in (
                canonical.parent,
                canonical,
                malformed.parent,
                malformed,
                nonempty.parent,
                nonempty,
                nonempty / "unknown-object",
            ):
                os.utime(path, ns=(0, 0))

            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="shard-prune-test",
                operation_id="shard-prune-exact-001",
            )

            self.assertGreaterEqual(result.deleted_files, 1)
            self.assertFalse(canonical.exists())
            self.assertFalse(canonical.parent.exists())
            self.assertTrue(malformed.exists())
            self.assertTrue(nonempty.exists())
            self.assertTrue((nonempty / "unknown-object").exists())

    def test_content_shard_remains_until_its_last_leaf_is_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1,
                ),
            )
            shared_parent = pipeline.blob_root / "aa" / "aa"
            shared_parent.mkdir(parents=True)
            first = shared_parent / ("a" * 64)
            second = shared_parent / ("aaaa" + "b" * 60)
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            for path in (shared_parent.parent, shared_parent, first, second):
                os.utime(path, ns=(0, 0))

            first_pass = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="shard-sibling-test",
                operation_id="shard-sibling-001",
            )
            self.assertEqual(first_pass.deleted_files, 1)
            self.assertTrue(shared_parent.exists())
            self.assertEqual(len(tuple(shared_parent.iterdir())), 1)

            second_pass = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1,
                actor="shard-sibling-test",
                operation_id="shard-sibling-002",
            )
            self.assertEqual(second_pass.deleted_files, 1)
            self.assertFalse(shared_parent.exists())
            self.assertFalse(shared_parent.parent.exists())

    def test_retention_v1_plan_remains_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            payload = canonical_json(
                {
                    "version": 1,
                    "work_items": [
                        {
                            "sequence": 0,
                            "action": "partial",
                            "root": "spool",
                            "reference": None,
                            "relative_path": "legacy.partial",
                            "planned_bytes": 0,
                            "expected_identity": None,
                        }
                    ],
                }
            )

            (item,) = pipeline._deserialize_retention_work_items(payload)
            self.assertEqual(item.action, "partial")
            self.assertEqual(item.relative_path, "legacy.partial")

    def test_workspace_retention_excludes_unrelated_durable_artifacts_but_an_execute_runs_the_host_spool_janitor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            orphan_fixture = pipeline.fixture_root / "fixture-unowned"
            orphan_fixture.mkdir()
            (orphan_fixture / "input.bin").write_bytes(b"fixture")
            orphan_blob = pipeline.blob_root / "aa" / "bb" / ("c" * 64)
            orphan_blob.parent.mkdir(parents=True)
            orphan_blob.write_bytes(b"blob")
            orphan_dataset = pipeline.dataset_root / "dd" / "ee" / f"{'f' * 64}.json"
            orphan_dataset.parent.mkdir(parents=True)
            orphan_dataset.write_bytes(b"dataset")
            stale_partial = pipeline.spool_root / "unowned.partial"
            stale_partial.write_bytes(b"partial")
            stale_lock = stale_partial.with_name(f".{stale_partial.name}.active.lock")
            stale_lock.write_bytes(b"")
            for path in (
                orphan_fixture,
                orphan_fixture / "input.bin",
                orphan_blob,
                orphan_dataset,
                stale_partial,
                stale_lock,
            ):
                os.utime(path, ns=(0, 0))

            preview = pipeline.run_retention(self.scope, now_ns=time.time_ns())
            self.assertIs(
                preview.host_storage_orphan_inventory,
                RetentionHostInventoryCoverage.NOT_OBSERVED,
            )
            self.assertEqual(
                preview.as_dict()["host_storage_orphan_inventory"],
                "not_observed",
            )
            self.assertEqual(preview.fixture_views, 0)
            self.assertEqual(preview.content_blobs, 0)
            self.assertEqual(preview.revision_datasets, 0)
            self.assertEqual(preview.stale_partials, 0)
            self.assertEqual(preview.estimated_bytes, 0)

            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="retention-test",
                operation_id="workspace-only-retention",
            )
            self.assertIs(
                result.host_storage_orphan_inventory,
                RetentionHostInventoryCoverage.BOUNDED_HOST_SCAN,
            )
            self.assertEqual(
                result.as_dict()["host_storage_orphan_inventory"],
                "bounded_host_scan",
            )
            self.assertEqual(result.stale_partials, 1)
            self.assertEqual(result.deleted_files, 1)
            self.assertTrue(orphan_fixture.exists())
            self.assertTrue(orphan_blob.exists())
            self.assertTrue(orphan_dataset.exists())
            self.assertFalse(stale_partial.exists())
            self.assertFalse(stale_lock.exists())

    def test_preview_does_not_wait_for_destructive_operation_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                ),
            )
            for index in range(2):
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name=f"preview-lock-{index}.jsonl",
                )
                with pipeline._connect() as connection:
                    connection.execute(
                        "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                        "WHERE import_id = ?",
                        (ImportState.CANCELLED.value, admitted.import_id),
                    )

            lock_entered = threading.Event()
            release_lock = threading.Event()

            def hold_destructive_operation_lock() -> None:
                with exclusive_file_lock(pipeline._retention_operation_lock_path):
                    lock_entered.set()
                    if not release_lock.wait(5):
                        raise TimeoutError("retention lock release timed out")

            with ThreadPoolExecutor(max_workers=2) as executor:
                holder = executor.submit(hold_destructive_operation_lock)
                self.assertTrue(lock_entered.wait(2))
                preview = executor.submit(
                    pipeline.run_retention,
                    self.scope,
                    now_ns=time.time_ns() + 1_000_000_000,
                )
                try:
                    report = preview.result(timeout=1)
                finally:
                    release_lock.set()
                    holder.result(timeout=2)

            self.assertEqual(report.eligible_imports, 2)
            self.assertFalse(report.executed)

    def test_host_retention_gives_each_root_an_independent_bounded_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1,
                    max_scan_entries=10_000,
                ),
            )
            stale = pipeline.spool_root / "must-not-starve.partial"
            stale.write_bytes(b"stale")
            stale_lock = stale.with_name(f".{stale.name}.active.lock")
            stale_lock.write_bytes(b"")
            os.utime(stale, ns=(0, 0))
            os.utime(stale_lock, ns=(0, 0))

            def synthetic_walk(
                root: Path,
                *,
                recursive: bool,
            ) -> Any:
                del recursive
                if root == pipeline.spool_root:
                    for path in sorted(root.iterdir()):
                        yield (
                            path.relative_to(root).as_posix(),
                            path,
                            False,
                            path.stat().st_mtime_ns,
                        )
                    return
                # Exercise the production 10K bound without creating 20K
                # throwaway directories. Each durable root has one entry past
                # the limit, which used to consume a shared budget forever.
                for index in range(10_001):
                    relative = f"noise-{index:05d}"
                    yield relative, root / relative, True, 0

            with patch.object(
                pipeline,
                "_walk_host_root",
                side_effect=synthetic_walk,
            ) as walk:
                preview = pipeline.run_retention(
                    self.scope,
                    dry_run=True,
                    now_ns=time.time_ns(),
                )
                self.assertEqual(preview.stale_partials, 0)
                self.assertEqual(walk.call_count, 0)
                self.assertTrue(stale.exists())
                with pipeline._connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM ingestion_host_retention_cursor"
                        ).fetchone()[0],
                        0,
                    )

                executed = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns(),
                    actor="fairness-test",
                    operation_id="fair-host-roots-001",
                )
                self.assertEqual(walk.call_count, 4)
            self.assertEqual(executed.stale_partials, 1)
            self.assertFalse(stale.exists())
            self.assertFalse(stale_lock.exists())
            with pipeline._connect() as connection:
                cursors = connection.execute(
                    "SELECT root_name, cursor "
                    "FROM ingestion_host_retention_cursor ORDER BY root_name"
                ).fetchall()
            self.assertEqual(
                [str(row["root_name"]) for row in cursors],
                ["blob", "dataset", "fixture", "spool"],
            )
            self.assertTrue(
                all(
                    str(row["cursor"]) for row in cursors if row["root_name"] != "spool"
                )
            )

    def test_host_cursor_uses_the_same_global_lexical_order_as_traversal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=10,
                    max_scan_entries=2,
                ),
            )
            punctuation_directory = pipeline.blob_root / ".foo"
            punctuation_directory.mkdir()
            (punctuation_directory / "z").write_bytes(b"not a candidate")
            stale_lock = pipeline.blob_root / ".foo-bar.install.lock"
            stale_lock.write_bytes(b"")
            os.utime(stale_lock, ns=(0, 0))

            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="lexical-cursor-test",
                operation_id="lexical-cursor-001",
            )

            self.assertEqual(result.stale_partials, 1)
            self.assertFalse(stale_lock.exists())
            with pipeline._connect() as connection:
                cursor = connection.execute(
                    "SELECT cursor FROM ingestion_host_retention_cursor "
                    "WHERE root_name = 'blob'"
                ).fetchone()
            assert cursor is not None
            self.assertEqual(str(cursor["cursor"]), ".foo-bar.install.lock")

    def test_failed_fixture_delete_converges_through_host_reaper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="fixture-delete.jsonl",
            )
            fixture = pipeline.fixture_root / admitted.fixture_id
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            original_delete = pipeline._delete_path
            failed_once = False

            def fail_fixture_once(path: Path) -> tuple[bool, int]:
                nonlocal failed_once
                if path == fixture and not failed_once:
                    failed_once = True
                    raise PermissionError("injected one-shot fixture denial")
                return original_delete(path)

            evaluated_at = time.time_ns() + 1_000_000_000
            with patch.object(
                pipeline,
                "_delete_path",
                side_effect=fail_fixture_once,
            ):
                first = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="fixture-reaper-test",
                    operation_id="fixture-failure-001",
                )
            self.assertEqual(first.deleted_imports, 1)
            self.assertEqual(first.deletion_failures, 1)
            self.assertTrue(fixture.exists())

            exact_replay = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at,
                actor="fixture-reaper-test",
                operation_id="fixture-failure-001",
            )
            self.assertEqual(exact_replay.as_dict(), first.as_dict())
            self.assertTrue(fixture.exists())

            converged = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at + 1,
                actor="fixture-reaper-test",
                operation_id="fixture-failure-002",
            )
            self.assertEqual(converged.fixture_views, 1)
            self.assertFalse(fixture.exists())

    def test_host_orphan_cursor_survives_restart_and_converges(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
                max_delete_batch=1,
                max_scan_entries=3,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            orphan_paths = []
            for index in range(7):
                _reference, path = _write_content_address(
                    pipeline.blob_root,
                    f"orphan-{index}".encode(),
                )
                os.utime(path, ns=(0, 0))
                orphan_paths.append(path)

            first_clock = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("simulated crash after commit"),
                ),
                self.assertRaisesRegex(RuntimeError, "simulated crash"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=first_clock,
                    actor="cursor-test",
                    operation_id="cursor-pass-000",
                )
            self.assertEqual(sum(path.exists() for path in orphan_paths), 7)
            with pipeline._connect() as connection:
                stored_cursor = connection.execute(
                    "SELECT cursor FROM ingestion_host_retention_cursor "
                    "WHERE root_name = 'blob'"
                ).fetchone()
            assert stored_cursor is not None
            self.assertTrue(str(stored_cursor["cursor"]))

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            resumed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=first_clock,
                actor="cursor-test",
                operation_id="cursor-pass-000",
            )
            self.assertEqual(resumed.content_blobs, 1)
            self.assertEqual(sum(path.exists() for path in orphan_paths), 6)
            for index in range(1, 60):
                reopened.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns() + index,
                    actor="cursor-test",
                    operation_id=f"cursor-pass-{index:03d}",
                )
                if not any(path.exists() for path in orphan_paths):
                    break

            self.assertFalse(any(path.exists() for path in orphan_paths))
            remaining_locks = tuple(reopened.blob_root.rglob("*.install.lock"))
            self.assertEqual(remaining_locks, ())
            final = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 100,
                actor="cursor-test",
                operation_id="cursor-final-empty",
            )
            self.assertEqual(final.content_blobs, 0)

    def test_empty_host_scan_cycle_converges_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                idempotency_replay_seconds=3_600,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
                max_delete_batch=10,
                max_scan_entries=3,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            # Directories count toward the bounded scan but are never cleanup
            # candidates.  More entries than one budget used to wrap forever
            # and keep every report spuriously truncated.
            for index in range(7):
                (pipeline.spool_root / f"stable-{index:02d}").mkdir()

            first = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="cycle-test",
                operation_id="empty-cycle-001",
            )
            self.assertTrue(first.truncated)

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            second = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 1,
                actor="cycle-test",
                operation_id="empty-cycle-002",
            )
            final = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns() + 2,
                actor="cycle-test",
                operation_id="empty-cycle-003",
            )
            self.assertTrue(second.truncated)
            self.assertFalse(final.truncated)
            self.assertEqual(final.deleted_files, 0)
            with reopened._connect() as connection:
                cursor = connection.execute(
                    "SELECT cursor FROM ingestion_host_retention_cursor "
                    "WHERE root_name = 'spool'"
                ).fetchone()
            assert cursor is not None
            self.assertEqual(str(cursor["cursor"]), "")

    def test_host_scan_does_not_hold_upload_publication_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            scan_started = threading.Event()
            release_scan = threading.Event()
            original_scan = pipeline._scan_host_cleanup

            def slow_scan(*, now_ns: int) -> Any:
                scan_started.set()
                if not release_scan.wait(10):
                    raise TimeoutError("test did not release the host scan")
                return original_scan(now_ns=now_ns)

            with (
                patch.object(pipeline, "_scan_host_cleanup", side_effect=slow_scan),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                retention = executor.submit(
                    pipeline.run_retention,
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns(),
                    actor="slow-scan-test",
                    operation_id="slow-scan-001",
                )
                self.assertTrue(scan_started.wait(10))
                upload = executor.submit(
                    pipeline.submit_bytes,
                    self.scope,
                    _fixture_bytes(),
                    original_name="while-scanning.jsonl",
                )
                try:
                    admitted = upload.result(timeout=5)
                finally:
                    release_scan.set()
                retained = retention.result(timeout=10)

            self.assertIsNotNone(retained.audit_id)
            self.assertEqual(
                pipeline.get_import(self.scope, admitted.import_id).import_id,
                admitted.import_id,
            )

    def test_crash_resume_skips_replacement_at_scanned_host_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            _reference, orphan = _write_content_address(
                pipeline.blob_root,
                b"stale-host-object",
            )
            os.utime(orphan, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("simulated crash before cleanup"),
                ),
                self.assertRaisesRegex(RuntimeError, "before cleanup"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="identity-test",
                    operation_id="identity-crash-001",
                )

            orphan.unlink()
            orphan.write_bytes(b"replacement-at-the-same-address")
            replacement_identity = pipeline._content_file_identity(orphan)
            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            resumed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at,
                actor="identity-test",
                operation_id="identity-crash-001",
            )
            self.assertTrue(orphan.exists())
            self.assertEqual(
                reopened._content_file_identity(orphan),
                replacement_identity,
            )
            self.assertEqual(resumed.deleted_files, 0)

    def test_explicit_host_reaper_recovers_publish_before_database_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=60,
                    stale_partial_seconds=60,
                ),
            )
            payload = b"published-before-database-commit"
            digest = hashlib.sha256(payload).hexdigest()
            source = root / "crash-window-source.tmp"
            source.write_bytes(payload)
            prepared = pipeline._prepare_content_file(
                source,
                root=pipeline.blob_root,
                relative=Path(digest[:2]) / digest[2:4] / digest,
                expected_sha256=digest,
                expected_bytes=len(payload),
            )
            crash_window_blob = pipeline._publish_prepared_content_file(prepared)
            pipeline._discard_prepared_content_file(prepared)
            source.unlink()
            os.utime(crash_window_blob, ns=(0, 0))
            os.utime(prepared.install_lock, ns=(0, 0))

            _dataset_ref, leaked_dataset = _write_content_address(
                pipeline.dataset_root,
                b"legacy-leaked-dataset",
                dataset=True,
            )
            os.utime(leaked_dataset, ns=(0, 0))
            _fresh_ref, fresh_blob = _write_content_address(
                pipeline.blob_root,
                b"fresh-uncommitted-publication",
            )
            evaluated_at = time.time_ns()

            preview = pipeline.run_retention(
                self.scope,
                dry_run=True,
                now_ns=evaluated_at,
            )
            self.assertEqual(preview.content_blobs, 0)
            self.assertEqual(preview.revision_datasets, 0)
            self.assertTrue(crash_window_blob.exists())
            self.assertTrue(leaked_dataset.exists())

            executed = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at,
                actor="orphan-reaper-test",
                operation_id="orphan-crash-window-001",
            )
            self.assertEqual(executed.content_blobs, 1)
            self.assertEqual(executed.revision_datasets, 1)
            self.assertFalse(crash_window_blob.exists())
            self.assertTrue(prepared.install_lock.exists())
            self.assertFalse(crash_window_blob.parent.exists())
            self.assertFalse(leaked_dataset.exists())
            self.assertTrue(fresh_blob.exists())

    def test_host_reaper_reclaims_only_exact_crash_leaked_content_transients(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=60,
                    stale_partial_seconds=60,
                ),
            )

            specifications = (
                ("blob", "1234" + "a" * 60, "1" * 32, "partial"),
                ("blob", "2345" + "b" * 60, "2" * 32, "corrupt"),
                ("dataset", "3456" + "c" * 60, "3" * 32, "partial"),
                ("dataset", "4567" + "d" * 60, "4" * 32, "corrupt"),
            )
            leaked: list[Path] = []
            activity_locks: list[Path] = []
            for root_name, digest, token, transient_kind in specifications:
                root = (
                    pipeline.blob_root if root_name == "blob" else pipeline.dataset_root
                )
                target_leaf = f"{digest}.json" if root_name == "dataset" else digest
                if transient_kind == "partial":
                    name = f".{target_leaf}.{token}.partial"
                else:
                    name = f".{target_leaf}.corrupt-{token}"
                path = root / digest[:2] / digest[2:4] / name
                path.parent.mkdir(parents=True)
                path.write_bytes(f"leaked-{transient_kind}".encode())
                os.utime(path, ns=(0, 0))
                leaked.append(path)
                if transient_kind == "partial":
                    activity = pipeline._content_staging_activity_lock(
                        root_name,
                        digest,
                        token,
                    )
                    activity.parent.mkdir(parents=True, exist_ok=True)
                    activity.write_bytes(b"\0")
                    activity_locks.append(activity)

            # These names are deliberately close to the private vocabulary but
            # are not exact core-owned staging/quarantine files.
            arbitrary = pipeline.blob_root / "56" / "78" / ".operator.partial"
            malformed = (
                pipeline.dataset_root
                / "67"
                / "89"
                / f".{('e' * 64)}.json.short.partial"
            )
            for path in (arbitrary, malformed):
                path.parent.mkdir(parents=True)
                path.write_bytes(b"operator-owned")
                os.utime(path, ns=(0, 0))

            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="content-transient-reaper",
                operation_id="content-transient-reaper-001",
            )

            self.assertEqual(result.stale_partials, 4)
            self.assertEqual(result.deleted_files, 4)
            self.assertTrue(all(not path.exists() for path in leaked))
            self.assertTrue(all(not path.exists() for path in activity_locks))
            self.assertTrue(arbitrary.exists())
            self.assertTrue(malformed.exists())
            # Every leaked file occupied a distinct exact shard, so cleanup can
            # prune both canonical shard levels immediately.
            for root_name, digest, _token, _kind in specifications:
                root = (
                    pipeline.blob_root if root_name == "blob" else pipeline.dataset_root
                )
                self.assertFalse((root / digest[:2]).exists())

    def test_host_reaper_recovers_a_candidate_after_hard_process_termination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            payload = _fixture_bytes() * 32
            digest = hashlib.sha256(payload).hexdigest()
            source = root / "crash-source.tmp"
            source.write_bytes(payload)
            context = multiprocessing.get_context("spawn")
            entered = context.Event()
            process = context.Process(
                target=_hold_prepared_content_process,
                args=(
                    str(root),
                    str(source),
                    digest,
                    len(payload),
                    entered,
                ),
            )
            process.start()
            try:
                self.assertTrue(entered.wait(10))
                candidates = tuple(
                    (pipeline.blob_root / digest[:2] / digest[2:4]).glob(
                        f".{digest}.*.partial"
                    )
                )
                self.assertEqual(len(candidates), 1)
                activity_locks = tuple(
                    (pipeline.content_lock_root / "blob" / "staging").glob(
                        "*.active.lock"
                    )
                )
                self.assertEqual(len(activity_locks), 1)
                process.terminate()
                process.join(10)
                self.assertFalse(process.is_alive())
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(5)

            os.utime(candidates[0], ns=(0, 0))
            result = pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="hard-crash-reaper",
                operation_id="hard-crash-reaper-001",
            )

            self.assertEqual(result.stale_partials, 1)
            self.assertEqual(result.deleted_files, 1)
            self.assertFalse(candidates[0].exists())
            self.assertFalse(activity_locks[0].exists())
            self.assertFalse((pipeline.blob_root / digest[:2]).exists())

    def test_host_reaper_does_not_trust_false_path_exists_for_a_live_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            digest = "1234" + "a" * 60
            token = "5" * 32
            candidate = (
                pipeline.blob_root
                / digest[:2]
                / digest[2:4]
                / f".{digest}.{token}.partial"
            )
            candidate.parent.mkdir(parents=True)
            candidate.write_bytes(b"live candidate")
            os.utime(candidate, ns=(0, 0))
            bounded_activity_lock = pipeline._content_staging_activity_lock(
                "blob",
                digest,
                token,
            )
            # Model a writer from the immediately previous build. The reaper
            # must honor its long-form lock during a rolling upgrade, and must
            # not trust Path.exists() if Windows suppresses a path error.
            activity_lock = bounded_activity_lock.with_name(
                f"{digest}.{token}.active.lock"
            )
            entered = threading.Event()
            release = threading.Event()

            def hold_activity_lock() -> None:
                with exclusive_file_lock(activity_lock):
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("activity-lock release timed out")

            original_exists = Path.exists

            def misleading_exists(path: Path) -> bool:
                if path == activity_lock:
                    return False
                return original_exists(path)

            holder = threading.Thread(target=hold_activity_lock, daemon=True)
            holder.start()
            try:
                self.assertTrue(entered.wait(5))
                with patch.object(
                    Path,
                    "exists",
                    autospec=True,
                    side_effect=misleading_exists,
                ):
                    result = pipeline.run_retention(
                        self.scope,
                        dry_run=False,
                        now_ns=time.time_ns(),
                        actor="false-exists-guard",
                        operation_id="false-exists-guard-001",
                    )
                self.assertEqual(result.stale_partials, 1)
                self.assertEqual(result.deleted_files, 0)
                self.assertTrue(candidate.exists())
            finally:
                release.set()
                holder.join(5)
            self.assertFalse(holder.is_alive())

    def test_host_reaper_never_deletes_a_live_content_staging_candidate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            payload = _fixture_bytes() * 128
            digest = hashlib.sha256(payload).hexdigest()
            source = Path(directory) / "slow-copy-source.tmp"
            source.write_bytes(payload)
            entered = threading.Event()
            release = threading.Event()
            original_copy = shutil.copyfileobj

            def blocking_copy(source_stream: Any, output: Any, length: int = 0) -> None:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test copy release timed out")
                original_copy(source_stream, output, length=length)

            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline.os.link",
                    side_effect=OSError("hard links disabled"),
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.shutil.copyfileobj",
                    side_effect=blocking_copy,
                ),
                ThreadPoolExecutor(max_workers=1) as executor,
            ):
                future = executor.submit(
                    pipeline._install_content_file,
                    source,
                    root=pipeline.blob_root,
                    relative=Path(digest[:2]) / digest[2:4] / digest,
                    expected_sha256=digest,
                    expected_bytes=len(payload),
                )
                self.assertTrue(entered.wait(5))
                candidates = tuple(
                    (pipeline.blob_root / digest[:2] / digest[2:4]).glob(
                        f".{digest}.*.partial"
                    )
                )
                self.assertEqual(len(candidates), 1)
                os.utime(candidates[0], ns=(0, 0))

                result = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns(),
                    actor="concurrent-content-reaper",
                    operation_id="concurrent-content-reaper-001",
                )
                self.assertEqual(result.stale_partials, 1)
                self.assertEqual(result.deleted_files, 0)
                self.assertTrue(candidates[0].exists())
                release.set()
                target = future.result(timeout=10)

            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(candidates[0].exists())
            self.assertEqual(
                tuple(
                    (pipeline.content_lock_root / "blob" / "staging").glob(
                        "*.active.lock"
                    )
                ),
                (),
            )

    def test_anonymous_interrupted_retention_is_discovered_and_resumed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = RetentionPolicy(
                enabled=True,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            )
            pipeline = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            stale = pipeline.spool_root / "anonymous-crash.partial"
            stale.write_bytes(b"stale")
            os.utime(stale, ns=(0, 0))
            evaluated_at = time.time_ns()
            with (
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("simulated anonymous cleanup crash"),
                ),
                self.assertRaisesRegex(RuntimeError, "anonymous cleanup crash"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=evaluated_at,
                    actor="anonymous-crash",
                )

            with pipeline._connect() as connection:
                pending = connection.execute(
                    "SELECT audit_id, operation_id, state "
                    "FROM ingestion_retention_audit"
                ).fetchall()
            self.assertEqual(len(pending), 1)
            self.assertIsNone(pending[0]["operation_id"])
            self.assertEqual(pending[0]["state"], "cleanup_pending")
            audit_id = str(pending[0]["audit_id"])

            reopened = DurableIngestionPipeline(
                root,
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=policy,
            )
            resumed = reopened.run_retention(
                self.scope,
                dry_run=False,
                now_ns=evaluated_at + 1,
                actor="different-retry-actor",
            )

            self.assertEqual(resumed.audit_id, audit_id)
            self.assertEqual(resumed.deleted_files, 1)
            self.assertFalse(stale.exists())
            with reopened._connect() as connection:
                rows = connection.execute(
                    "SELECT audit_id, state FROM ingestion_retention_audit"
                ).fetchall()
            self.assertEqual(
                [(str(row["audit_id"]), str(row["state"])) for row in rows],
                [(audit_id, "completed")],
            )

    def test_host_orphan_reaper_honors_global_rows_and_cross_tenant_pins(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            pinned_ref, pinned_blob = _write_content_address(
                pipeline.blob_root,
                b"owned-by-another-tenant",
            )
            os.utime(pinned_blob, ns=(0, 0))
            pin_owner = "catalog:tenant-b"
            with pipeline._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO ingestion_artifact_pins (
                        artifact_kind, artifact_ref,
                        tenant_id, project_id, workspace_id,
                        owner_operation_id, created_at_ns
                    ) VALUES ('blob', ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        pinned_ref,
                        *pipeline._scope_predicate(self.other_scope),
                        pin_owner,
                    ),
                )

            other_import = pipeline.submit_bytes(
                self.other_scope,
                b"other-tenant-live-import",
                original_name="other.bin",
            )
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT blob_ref FROM ingestion_imports WHERE import_id = ?",
                    (other_import.import_id,),
                ).fetchone()
            assert row is not None
            live_blob = pipeline.blob_root / Path(str(row["blob_ref"]))
            live_fixture = pipeline.fixture_root / other_import.fixture_id
            os.utime(live_blob, ns=(0, 0))
            os.utime(live_fixture, ns=(0, 0))

            pipeline.run_retention(
                self.scope,
                dry_run=False,
                now_ns=time.time_ns(),
                actor="tenant-isolation-test",
                operation_id="tenant-isolation-001",
            )
            self.assertTrue(pinned_blob.exists())
            self.assertTrue(live_blob.exists())
            self.assertTrue(live_fixture.exists())

            self.assertTrue(
                pipeline.release_artifact_pin(
                    self.other_scope,
                    artifact_kind="blob",
                    artifact_ref=pinned_ref,
                    owner_operation_id=pin_owner,
                )
            )
            for index in range(10):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns() + index,
                    actor="tenant-isolation-test",
                    operation_id=f"tenant-isolation-release-{index:02d}",
                )
                if not pinned_blob.exists():
                    break
            self.assertFalse(pinned_blob.exists())
            self.assertTrue(live_blob.exists())
            self.assertTrue(live_fixture.exists())

    def test_invalid_host_cursor_fails_closed_only_on_explicit_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            stale = pipeline.spool_root / "untouched.partial"
            stale.write_bytes(b"partial")
            os.utime(stale, ns=(0, 0))
            with pipeline._connect() as connection:
                connection.execute(
                    "INSERT INTO ingestion_host_retention_cursor "
                    "(root_name, cursor, updated_at_ns) VALUES ('blob', '../escape', 0)"
                )

            preview = pipeline.run_retention(
                self.scope,
                dry_run=True,
                now_ns=time.time_ns(),
            )
            self.assertEqual(preview.stale_partials, 0)
            with self.assertRaises(IngestionPipelineError):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns(),
                    actor="cursor-safety-test",
                    operation_id="invalid-cursor-001",
                )
            self.assertTrue(stale.exists())
            self.assertEqual(pipeline.list_retention_audits(self.scope), ())

    def test_repeated_explicit_retention_converges_files_locks_and_audits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
                row = connection.execute(
                    "SELECT blob_ref FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            assert row is not None
            blob = pipeline.blob_root / Path(str(row["blob_ref"]))
            other_scope = ImportScope("tenant-b", "project-b", "workspace-b")
            other_now = time.time_ns() + 5_000_000_000
            pipeline.run_retention(
                other_scope,
                dry_run=False,
                now_ns=other_now,
                actor="convergence-test",
                operation_id="other-scope-audit",
            )
            abandoned = pipeline.spool_root / "abandoned.partial"
            abandoned.write_bytes(b"unfinished")
            abandoned_lock = abandoned.with_name(f".{abandoned.name}.active.lock")
            abandoned_lock.write_bytes(b"")
            orphan_lock = pipeline.spool_root / ".gone.partial.active.lock"
            orphan_lock.write_bytes(b"")
            for path in (abandoned, abandoned_lock, orphan_lock):
                os.utime(path, ns=(0, 0))

            preview = pipeline.run_retention(
                self.scope,
                dry_run=True,
                now_ns=time.time_ns(),
            )
            self.assertEqual(preview.stale_partials, 0)
            self.assertTrue(abandoned.exists())
            self.assertTrue(abandoned_lock.exists())

            base_now = other_now + 1
            results = []
            for index in range(3):
                results.append(
                    pipeline.run_retention(
                        self.scope,
                        dry_run=False,
                        now_ns=base_now + index,
                        actor="convergence-test",
                        operation_id=f"convergence-{index}",
                    )
                )
                self.assertLessEqual(
                    len(pipeline.list_retention_audits(self.scope, limit=500)),
                    1,
                )
                self.assertEqual(
                    len(pipeline.list_retention_audits(other_scope, limit=500)),
                    1,
                )

            self.assertEqual(results[0].deleted_imports, 1)
            self.assertGreaterEqual(results[0].stale_partials, 2)
            self.assertEqual(results[1].deleted_retention_audits, 1)
            self.assertEqual(results[2].deleted_retention_audits, 1)
            self.assertFalse(blob.exists())
            self.assertFalse(abandoned.exists())
            self.assertFalse(abandoned_lock.exists())
            self.assertFalse(orphan_lock.exists())
            self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())
            remaining_content_locks = tuple(
                path
                for root in (pipeline.blob_root, pipeline.dataset_root)
                for path in root.rglob("*.lock")
            )
            self.assertEqual(remaining_content_locks, ())
            self.assertEqual(results[-1].eligible_imports, 0)
            self.assertEqual(results[-1].content_blobs, 0)
            self.assertEqual(results[-1].revision_datasets, 0)

    def test_execute_only_host_cleanup_cannot_race_upload_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            prepared = threading.Event()
            allow_publication = threading.Event()
            original_prepare = pipeline._prepare_content_file

            def pause_after_preparation(*args: Any, **kwargs: Any) -> Any:
                result = original_prepare(*args, **kwargs)
                prepared.set()
                if not allow_publication.wait(10):
                    raise TimeoutError("admission publication was not released")
                return result

            with (
                patch.object(
                    pipeline,
                    "_prepare_content_file",
                    side_effect=pause_after_preparation,
                ),
                ThreadPoolExecutor(max_workers=1) as executor,
            ):
                future = executor.submit(
                    pipeline.submit_bytes,
                    self.scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                self.assertTrue(prepared.wait(10))
                retained = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=time.time_ns() + 1_000_000_000,
                    actor="race-test",
                    operation_id="race-test-001",
                )
                allow_publication.set()
                admitted = future.result(timeout=10)

            self.assertGreaterEqual(retained.stale_partials, 1)
            stored = pipeline.get_import(self.scope, admitted.import_id)
            self.assertEqual(stored.fixture_id, admitted.fixture_id)
            with pipeline._connect() as connection:
                row = connection.execute(
                    "SELECT blob_ref FROM ingestion_imports WHERE import_id = ?",
                    (admitted.import_id,),
                ).fetchone()
            assert row is not None
            self.assertTrue((pipeline.blob_root / Path(str(row["blob_ref"]))).is_file())
            self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())

    def test_worker_survives_one_shot_sqlite_claim_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            calls = 0

            def flaky_claim() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise sqlite3.OperationalError("database is busy")

            with patch.object(pipeline, "_claim", side_effect=flaky_claim):
                pipeline.start()
                deadline = time.monotonic() + 3
                while calls < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                health = pipeline.worker_health()
                self.assertGreaterEqual(health.total_claim_errors, 1)
                self.assertEqual(health.consecutive_claim_errors, 0)
                self.assertEqual(health.live_workers, 1)
                pipeline.close(timeout=3)

    def test_worker_survives_unexpected_claim_failure_without_text_leak(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            calls = 0
            private_detail = "claim contained private dump material"

            def flaky_claim() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError(private_detail)

            with patch.object(pipeline, "_claim", side_effect=flaky_claim):
                pipeline.start()
                deadline = time.monotonic() + 3
                while calls < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                health = pipeline.worker_health()
                self.assertGreaterEqual(health.total_claim_errors, 1)
                self.assertEqual(health.consecutive_claim_errors, 0)
                self.assertEqual(health.last_claim_error, "RuntimeError")
                self.assertNotIn(private_detail, repr(health))
                self.assertEqual(health.live_workers, 1)
                pipeline.close(timeout=3)

    def test_worker_supervises_unexpected_iteration_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            calls = 0

            def invalid_then_idle() -> dict[str, str] | None:
                nonlocal calls
                calls += 1
                return {"state": "private-invalid-state"} if calls == 1 else None

            with patch.object(
                pipeline,
                "_claim",
                side_effect=invalid_then_idle,
            ):
                pipeline.start()
                deadline = time.monotonic() + 3
                health = pipeline.worker_health()
                while health.total_iteration_errors < 1 and time.monotonic() < deadline:
                    time.sleep(0.01)
                    health = pipeline.worker_health()
                self.assertEqual(health.total_iteration_errors, 1)
                self.assertEqual(health.last_iteration_error, "ValueError")
                self.assertNotIn("private-invalid-state", repr(health))
                self.assertEqual(health.live_workers, 1)
                pipeline.close(timeout=3)

    def test_repeated_claim_failures_are_visible_and_stop_aware(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with patch.object(
                pipeline,
                "_claim",
                side_effect=sqlite3.OperationalError("permanent failure"),
            ):
                pipeline.start()
                deadline = time.monotonic() + 3
                health = pipeline.worker_health()
                while health.total_claim_errors < 3 and time.monotonic() < deadline:
                    time.sleep(0.01)
                    health = pipeline.worker_health()
                self.assertGreaterEqual(health.total_claim_errors, 3)
                self.assertGreaterEqual(health.consecutive_claim_errors, 3)
                self.assertEqual(health.last_claim_error, "OperationalError")
                self.assertEqual(health.live_workers, 1)
                started = time.monotonic()
                pipeline.close(timeout=3)
                self.assertLess(time.monotonic() - started, 1)

    def test_worker_health_reports_stalled_queue_and_selection_waits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=replace(
                    self._limits(),
                    lease_seconds=5,
                    plugin_execution_timeout_seconds=0.05,
                    stalled_import_seconds=5,
                ),
            )
            first = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="stalled.jsonl",
            )
            second = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="selection.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (first.import_id,),
                )
                connection.execute(
                    "UPDATE ingestion_imports "
                    "SET state = ?, updated_at_ns = 0 WHERE import_id = ?",
                    (ImportState.AWAITING_SELECTION.value, second.import_id),
                )

            health = pipeline.worker_health()
            self.assertEqual(health.pending_imports, 1)
            self.assertEqual(health.awaiting_selection_imports, 1)
            self.assertEqual(health.stalled_imports, 1)
            self.assertEqual(health.oldest_pending_updated_at_ns, 0)
            self.assertEqual(
                dict(health.state_counts),
                {"admitting": 1, "awaiting_selection": 1},
            )
            self.assertIsNone(health.queue_observation_error)

    def test_queue_health_query_is_backed_by_active_state_age_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            with pipeline._connect() as connection:
                plan = connection.execute(
                    "EXPLAIN QUERY PLAN "
                    "SELECT state, COUNT(*), MIN(updated_at_ns) "
                    "FROM ingestion_imports WHERE state IN (?, ?) "
                    "GROUP BY state",
                    (ImportState.QUEUED.value, ImportState.PROBING.value),
                ).fetchall()
            details = " ".join(str(row["detail"]) for row in plan)
            self.assertIn("ingestion_import_health", details)

    def test_system_exit_in_claim_is_attributed_without_killing_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
            )
            calls = 0
            private_detail = "private SystemExit detail from plug-in state"
            operational_events: list[tuple[str, dict[str, bool | int | str]]] = []

            def exit_then_idle() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise SystemExit(private_detail)

            def capture_operational_event(
                event: str,
                /,
                **fields: bool | int | str,
            ) -> bool:
                operational_events.append((event, fields))
                return True

            with (
                patch.object(pipeline, "_claim", side_effect=exit_then_idle),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.emit_operational_event",
                    side_effect=capture_operational_event,
                ),
            ):
                pipeline.start()
                deadline = time.monotonic() + 3
                while calls < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                health = pipeline.worker_health()
                pipeline.close(timeout=3)

            self.assertGreaterEqual(calls, 2)
            self.assertEqual(health.total_claim_errors, 1)
            self.assertEqual(health.last_claim_error, "SystemExit")
            self.assertEqual(health.unexpected_worker_exits, 0)
            self.assertEqual(health.live_workers, 1)
            self.assertNotIn(private_detail, repr(health))
            self.assertEqual(
                operational_events,
                [
                    (
                        "ingestion.worker.failure_sampled",
                        {
                            "phase": "claim",
                            "error_family": "system_exit",
                            "consecutive": 1,
                        },
                    )
                ],
            )
            self.assertNotIn(private_detail, repr(operational_events))


class RetentionOperationalTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = ImportScope(
            "tenant-private", "project-private", "workspace-private"
        )

    @staticmethod
    def _limits() -> PipelineLimits:
        return PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            lease_seconds=30,
            poll_interval_seconds=0.01,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )

    @staticmethod
    def _capture_events() -> tuple[
        list[tuple[str, dict[str, bool | int | str]]],
        Any,
    ]:
        events: list[tuple[str, dict[str, bool | int | str]]] = []

        def capture(event: str, **fields: bool | int | str) -> bool:
            events.append((event, fields))
            return True

        return events, patch(
            "router_dump_analyzer.ingestion_pipeline.emit_operational_event",
            side_effect=capture,
        )

    def test_preview_reports_each_bounded_source_without_scope_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                    max_delete_batch=1,
                ),
            )
            for index in range(2):
                admitted = pipeline.submit_bytes(
                    self.scope,
                    _fixture_bytes(),
                    original_name=f"status-{index}.jsonl",
                )
                with pipeline._connect() as connection:
                    connection.execute(
                        "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                        "WHERE import_id = ?",
                        (ImportState.CANCELLED.value, admitted.import_id),
                    )

            events, capture = self._capture_events()
            with capture:
                report = pipeline.run_retention(
                    self.scope,
                    now_ns=time.time_ns() + 1_000_000_000,
                )

            self.assertTrue(report.truncated)
            names = [event for event, _fields in events]
            self.assertEqual(names[0], "retention.run.started")
            self.assertEqual(names[-1], "retention.preview.completed")
            truncations = [
                fields
                for event, fields in events
                if event == "retention.scan.truncated"
            ]
            self.assertIn(
                {
                    "run_id": events[0][1]["run_id"],
                    "source": "imports",
                    "limit": 1,
                    "observed_at_least": 2,
                },
                truncations,
            )
            self.assertNotIn("tenant-private", json.dumps(events))
            self.assertNotIn("workspace-private", json.dumps(events))

    def test_execute_cleanup_and_replay_share_one_run_id_per_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(
                    enabled=True,
                    terminal_import_grace_seconds=0,
                    idempotency_replay_seconds=0,
                    orphan_artifact_grace_seconds=0,
                    stale_partial_seconds=0,
                ),
            )
            admitted = pipeline.submit_bytes(
                self.scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            with pipeline._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ?, updated_at_ns = 0 "
                    "WHERE import_id = ?",
                    (ImportState.CANCELLED.value, admitted.import_id),
                )
            effective_now = time.time_ns() + 1_000_000_000
            events, capture = self._capture_events()
            with capture:
                first = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="PRIVATE retention operator",
                    operation_id="operation-telemetry-1",
                )
                replay = pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    now_ns=effective_now,
                    actor="PRIVATE retention operator",
                    operation_id="operation-telemetry-1",
                )

            self.assertEqual(replay, first)
            starts = [
                fields["run_id"]
                for event, fields in events
                if event == "retention.run.started"
            ]
            self.assertEqual(len(starts), 2)
            self.assertNotEqual(starts[0], starts[1])
            first_run_events = [
                event for event, fields in events if fields.get("run_id") == starts[0]
            ]
            self.assertIn("retention.plan.committed", first_run_events)
            self.assertIn("retention.cleanup.started", first_run_events)
            self.assertIn("retention.cleanup.batch_completed", first_run_events)
            self.assertIn("retention.run.completed", first_run_events)
            replay_events = [
                event for event, fields in events if fields.get("run_id") == starts[1]
            ]
            self.assertIn("retention.run.replayed", replay_events)
            self.assertNotIn("PRIVATE retention operator", json.dumps(events))

    def test_post_commit_failure_is_attributed_without_exception_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                publisher=_Publisher(),
                limits=self._limits(),
                retention_policy=RetentionPolicy(enabled=True),
            )
            events, capture = self._capture_events()
            with (
                capture,
                patch.object(
                    pipeline,
                    "_resume_retention_cleanup",
                    side_effect=RuntimeError("PRIVATE post-commit filesystem detail"),
                ),
                self.assertRaisesRegex(RuntimeError, "PRIVATE post-commit"),
            ):
                pipeline.run_retention(
                    self.scope,
                    dry_run=False,
                    operation_id="operation-telemetry-failure",
                )

            failures = [
                fields for event, fields in events if event == "retention.run.failed"
            ]
            self.assertEqual(len(failures), 1)
            self.assertTrue(failures[0]["mutation_started"])
            self.assertIn("audit_id", failures[0])
            self.assertEqual(failures[0]["error_family"], "exception")
            self.assertNotIn("PRIVATE post-commit", json.dumps(events))


if __name__ == "__main__":
    unittest.main()

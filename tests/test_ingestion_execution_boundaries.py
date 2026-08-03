from __future__ import annotations

import tempfile
import unittest
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from router_dump_analyzer.ingestion import IngestionCoordinator, IngestionError
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    DumpInventory,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
    SourceRecordEmission,
)


class Boom(BaseException):
    pass


_PRIVATE_DETAIL = r"C:\private\router\dump\boundary-secret"


class _WorkingPlugin(AnalyzerPluginBase):
    manifest = PluginManifest(
        plugin_id="tests.ingestion-boundary",
        plugin_version="1.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("test",),
        supported_software_versions="1",
        capabilities=frozenset({PluginCapability.STATUS_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self) -> PluginSchema:
        return PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            source_record_types=(),
        )

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        return ProbeReport(
            result=ProbeResult(
                confidence=1.0,
                reasons=("boundary fixture",),
                match_kind=ProbeMatchKind.EXACT,
            )
        )

    def locate_inputs(self, inventory: DumpInventory) -> Iterable[InputSpec]:
        artifact = inventory.artifacts[0]
        return (
            InputSpec(
                artifact_ids=(artifact.artifact_id,),
                role="status",
                node=inventory.node_hint or "node-a",
                layer="test",
                parser_id="tests.boundary.status.v1",
                parser_kind=InputParserKind.STATUS,
            ),
        )

    def parse_status(self, reader: Any, spec: InputSpec) -> Iterable[Any]:
        return ()


class _CountingPlugin(_WorkingPlugin):
    def __init__(self) -> None:
        self.accesses = {
            name: 0
            for name in (
                "manifest",
                "describe",
                "probe",
                "locate_inputs",
                "parse_status",
            )
        }

    def __getattribute__(self, name: str) -> Any:
        if name in {
            "manifest",
            "describe",
            "probe",
            "locate_inputs",
            "parse_status",
        }:
            accesses = object.__getattribute__(self, "accesses")
            accesses[name] += 1
        return super().__getattribute__(name)


class _FaultPlugin(_WorkingPlugin):
    def __init__(
        self,
        *,
        stage: str,
        failure: BaseException,
        descriptor: bool,
    ) -> None:
        self._failure_stage = stage
        self._failure = failure
        self._descriptor_failure = descriptor

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("_failure") or name == "_descriptor_failure":
            return object.__getattribute__(self, name)
        stage = object.__getattribute__(self, "_failure_stage")
        failure = object.__getattribute__(self, "_failure")
        descriptor = object.__getattribute__(self, "_descriptor_failure")
        if name == stage and descriptor:
            raise failure
        value = super().__getattribute__(name)
        if name == stage and not descriptor:
            def explode(*args: Any, **kwargs: Any) -> Any:
                raise failure

            return explode
        return value


class _LifecycleIterator(Iterator[Any]):
    def __init__(
        self,
        values: tuple[Any, ...] = (),
        *,
        iter_failure: BaseException | None = None,
        next_failure: BaseException | None = None,
        close_failure: BaseException | None = None,
    ) -> None:
        self._values = iter(values)
        self._iter_failure = iter_failure
        self._next_failure = next_failure
        self._close_failure = close_failure

    def __iter__(self) -> _LifecycleIterator:
        if self._iter_failure is not None:
            raise self._iter_failure
        return self

    def __next__(self) -> Any:
        if self._next_failure is not None:
            failure, self._next_failure = self._next_failure, None
            raise failure
        return next(self._values)

    def close(self) -> None:
        if self._close_failure is not None:
            raise self._close_failure


class _LocateLifecyclePlugin(_WorkingPlugin):
    def __init__(self, iterator: _LifecycleIterator) -> None:
        self._iterator = iterator

    def locate_inputs(self, inventory: DumpInventory) -> _LifecycleIterator:
        return self._iterator


class _ParserLifecyclePlugin(_WorkingPlugin):
    def __init__(self, iterator: _LifecycleIterator) -> None:
        self._iterator = iterator

    def parse_status(self, reader: Any, spec: InputSpec) -> _LifecycleIterator:
        return self._iterator


class _GeneratorClosePlugin(_WorkingPlugin):
    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def parse_status(self, reader: Any, spec: InputSpec) -> Iterator[Any]:
        try:
            # The unsupported first value makes the core close this generator
            # while it is still suspended, exercising real generator.close().
            yield object()
        finally:
            raise self._failure


class _ExplodingMapping(Mapping[str, Any]):
    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def __getitem__(self, key: str) -> Any:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        raise self._failure


class _LocateOutputPlugin(_WorkingPlugin):
    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def locate_inputs(self, inventory: DumpInventory) -> tuple[InputSpec, ...]:
        spec = next(iter(super().locate_inputs(inventory)))
        return (
            InputSpec(
                artifact_ids=spec.artifact_ids,
                role=spec.role,
                node=spec.node,
                layer=spec.layer,
                parser_id=spec.parser_id,
                parser_kind=spec.parser_kind,
                options=_ExplodingMapping(self._failure),
            ),
        )


class _ParserOutputPlugin(_WorkingPlugin):
    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def parse_status(
        self,
        reader: Any,
        spec: InputSpec,
    ) -> tuple[SourceRecordEmission, ...]:
        return (
            SourceRecordEmission(
                timestamp_ns=1,
                timestamp_uncertainty_ns=0,
                source_type="test",
                source_name="input.bin",
                record_name="record",
                message="record",
                layer=spec.layer,
                attributes=_ExplodingMapping(self._failure),
            ),
        )


class _FailingSupportsManifest(PluginManifest):
    __slots__ = ("_failure",)
    _failure: BaseException

    def __init__(self, failure: BaseException) -> None:
        base = _WorkingPlugin.manifest
        super().__init__(
            plugin_id=base.plugin_id,
            plugin_version=base.plugin_version,
            core_api_version=base.core_api_version,
            supported_platforms=base.supported_platforms,
            supported_software_versions=base.supported_software_versions,
            capabilities=base.capabilities,
            reconstruction_default=base.reconstruction_default,
            forwarding_ir_versions=base.forwarding_ir_versions,
        )
        object.__setattr__(self, "_failure", failure)

    def supports(self, capability: PluginCapability | str) -> bool:
        raise self._failure


class _SupportsPlugin(_WorkingPlugin):
    def __init__(self, failure: BaseException) -> None:
        self.manifest = _FailingSupportsManifest(failure)


class IngestionExecutionBoundaryTests(unittest.TestCase):
    def _fixture(self, directory: str) -> Path:
        root = Path(directory)
        (root / "input.bin").write_bytes(b"fixture")
        return root

    def _assert_bounded(self, plugin: Any, fixture: Path) -> None:
        with self.assertRaises(IngestionError) as raised:
            IngestionCoordinator().ingest(plugin, fixture, node_hint="node-a")
        self.assertNotIn(_PRIVATE_DETAIL, str(raised.exception))
        self.assertIn("plug-in", str(raised.exception))

    def test_manifest_and_hook_descriptors_resolve_once_per_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin = _CountingPlugin()
            IngestionCoordinator().ingest(
                plugin,
                self._fixture(directory),
                node_hint="node-a",
            )
        self.assertEqual(
            plugin.accesses,
            {
                "manifest": 1,
                "describe": 1,
                "probe": 1,
                "locate_inputs": 1,
                "parse_status": 1,
            },
        )

    def test_custom_base_exception_from_descriptors_is_contained(self) -> None:
        for stage in ("manifest", "describe", "probe", "locate_inputs", "parse_status"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                self._assert_bounded(
                    _FaultPlugin(
                        stage=stage,
                        failure=Boom(_PRIVATE_DETAIL),
                        descriptor=True,
                    ),
                    self._fixture(directory),
                )

    def test_custom_base_exception_from_hook_execution_is_contained(self) -> None:
        for stage in ("describe", "probe", "locate_inputs", "parse_status"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                self._assert_bounded(
                    _FaultPlugin(
                        stage=stage,
                        failure=Boom(_PRIVATE_DETAIL),
                        descriptor=False,
                    ),
                    self._fixture(directory),
                )

    def test_lazy_iter_next_and_close_failures_are_contained(self) -> None:
        phases = (
            ("iter", {"iter_failure": Boom(_PRIVATE_DETAIL)}),
            ("next", {"next_failure": Boom(_PRIVATE_DETAIL)}),
            ("close", {"close_failure": Boom(_PRIVATE_DETAIL)}),
        )
        for plugin_type in (_LocateLifecyclePlugin, _ParserLifecyclePlugin):
            for phase, failures in phases:
                with (
                    self.subTest(plugin=plugin_type.__name__, phase=phase),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    values = (
                        _WorkingPlugin().locate_inputs(
                            self._inventory_for(directory)
                        )
                        if plugin_type is _LocateLifecyclePlugin and phase == "close"
                        else ()
                    )
                    self._assert_bounded(
                        plugin_type(_LifecycleIterator(tuple(values), **failures)),
                        self._fixture(directory),
                    )

    def _inventory_for(self, directory: str) -> DumpInventory:
        fixture = self._fixture(directory)
        from router_dump_analyzer.artifact_core import CoreArtifactReader

        with CoreArtifactReader(fixture, node_hint="node-a") as reader:
            return reader.inventory

    def test_manifest_supports_and_output_lifecycle_are_contained(self) -> None:
        plugins = (
            _SupportsPlugin(Boom(_PRIVATE_DETAIL)),
            _LocateOutputPlugin(Boom(_PRIVATE_DETAIL)),
            _ParserOutputPlugin(Boom(_PRIVATE_DETAIL)),
        )
        for plugin in plugins:
            with self.subTest(plugin=type(plugin).__name__), tempfile.TemporaryDirectory() as directory:
                self._assert_bounded(plugin, self._fixture(directory))

    def test_real_generator_close_failure_is_contained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self._assert_bounded(
                _GeneratorClosePlugin(Boom(_PRIVATE_DETAIL)),
                self._fixture(directory),
            )

    def test_all_process_controls_rethrow_from_hook_and_close(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for phase in ("hook", "close"):
                interruption = exception_type(_PRIVATE_DETAIL)
                plugin: Any = (
                    _FaultPlugin(
                        stage="describe",
                        failure=interruption,
                        descriptor=False,
                    )
                    if phase == "hook"
                    else _ParserLifecyclePlugin(
                        _LifecycleIterator(close_failure=interruption)
                    )
                )
                with (
                    self.subTest(exception=exception_type.__name__, phase=phase),
                    tempfile.TemporaryDirectory() as directory,
                    self.assertRaises(exception_type) as raised,
                ):
                    IngestionCoordinator().ingest(
                        plugin,
                        self._fixture(directory),
                        node_hint="node-a",
                    )
                self.assertIs(raised.exception, interruption)

    def test_ordinary_exceptions_keep_their_identity(self) -> None:
        for phase in ("hook", "close"):
            failure = ValueError(_PRIVATE_DETAIL)
            plugin: Any = (
                _FaultPlugin(
                    stage="describe",
                    failure=failure,
                    descriptor=False,
                )
                if phase == "hook"
                else _ParserLifecyclePlugin(
                    _LifecycleIterator(close_failure=failure)
                )
            )
            with (
                self.subTest(phase=phase),
                tempfile.TemporaryDirectory() as directory,
                self.assertRaises(ValueError) as raised,
            ):
                IngestionCoordinator().ingest(
                    plugin,
                    self._fixture(directory),
                    node_hint="node-a",
                )
            self.assertIs(raised.exception, failure)


if __name__ == "__main__":
    unittest.main()

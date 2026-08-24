from __future__ import annotations

import asyncio
import io
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from router_dump_analyzer.cli import main
from router_dump_analyzer.cli import run as run_cli
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
)
from router_dump_analyzer.plugin_loading import (
    load_plugin_entry_point,
    load_plugin_module,
)
from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS
from router_dump_analyzer.revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
)
from router_dump_analyzer.runtime import (
    PLUGIN_RUNTIME_CAPABILITY_ID,
    PluginRuntimeCapabilityError,
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
    validate_runtime_session,
)
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource

_PRIVATE_PATH = r"C:\Users\private-operator\secret\plug-in.py"


class _HostileFailure(BaseException):
    pass


class _BodyFailure(Exception):
    pass


class _UnrenderableRuntimeError(RuntimeError):
    def __init__(self, render_failure: BaseException) -> None:
        super().__init__()
        self.render_failure = render_failure

    def __str__(self) -> str:
        raise self.render_failure


class _RevisionStore:
    def __init__(self) -> None:
        self._revision = RevisionDescriptor(
            node_id="node-a",
            revision_id="revision-a",
            label="Revision A",
            event_count=0,
            resource_count=0,
        )
        self._assembly = AssemblyDescriptor(
            assembly_id="assembly-a",
            revisions=(self._revision,),
        )

    @property
    def assembly(self) -> AssemblyDescriptor:
        return self._assembly

    @property
    def default_revision_id(self) -> str:
        return self._revision.revision_id

    def revision(self, revision_id: str) -> RevisionDescriptor:
        if revision_id != self._revision.revision_id:
            raise KeyError(revision_id)
        return self._revision

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        if node_id != self._revision.node_id:
            raise KeyError(node_id)
        return self._revision

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        self.revision(revision_id)
        return _dataset()

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        self.revision_for_node(node_id)
        return _dataset()

    def loaded_revision_ids(self) -> Sequence[str]:
        return (self._revision.revision_id,)


def _dataset() -> dict[str, Any]:
    return {
        "workspace": {"revision_id": "revision-a"},
        "inventory": {"selected_revision_id": "revision-a"},
        "events": [],
        "resources": [],
        "relationships": [],
        "state_intervals": {},
        "lifecycle_intervals": {},
    }


class _Session:
    def __init__(
        self,
        *,
        failure_field: str | None = None,
        failure: BaseException | None = None,
    ) -> None:
        self._values = {
            "revision_store": _RevisionStore(),
            "data_source": StaticDatasetSource(_dataset()),
            "data_policy": StaticDataPolicy(),
            "temporal_provider": None,
            "topology_provider": None,
            "route_provider": None,
        }
        self.failure_field = failure_field
        self.failure = failure
        self.reads = {name: 0 for name in self._values}

    def _read(self, name: str) -> Any:
        self.reads[name] += 1
        if name == self.failure_field:
            assert self.failure is not None
            raise self.failure
        return self._values[name]

    @property
    def revision_store(self) -> Any:
        return self._read("revision_store")

    @property
    def data_source(self) -> Any:
        return self._read("data_source")

    @property
    def data_policy(self) -> Any:
        return self._read("data_policy")

    @property
    def temporal_provider(self) -> Any:
        return self._read("temporal_provider")

    @property
    def topology_provider(self) -> Any:
        return self._read("topology_provider")

    @property
    def route_provider(self) -> Any:
        return self._read("route_provider")


class _RuntimeContext:
    def __init__(
        self,
        session: Any,
        *,
        enter_failure: BaseException | None = None,
        exit_failure: BaseException | None = None,
        exit_result: bool = False,
    ) -> None:
        self.session = session
        self.enter_failure = enter_failure
        self.exit_failure = exit_failure
        self.exit_result = exit_result
        self.enter_count = 0
        self.exit_count = 0

    def __enter__(self) -> Any:
        self.enter_count += 1
        if self.enter_failure is not None:
            raise self.enter_failure
        return self.session

    def __exit__(self, *_exception: object) -> bool:
        self.exit_count += 1
        if self.exit_failure is not None:
            raise self.exit_failure
        return self.exit_result


class _DescriptorCountingContext(_RuntimeContext):
    def __init__(self, session: Any) -> None:
        super().__init__(session)
        self.descriptor_reads = {"__enter__": 0, "__exit__": 0}

    def __getattribute__(self, name: str) -> Any:
        if name in {"__enter__", "__exit__"}:
            reads = object.__getattribute__(self, "descriptor_reads")
            reads[name] += 1
        return object.__getattribute__(self, name)


class _Runtime:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    def __init__(
        self,
        context: _RuntimeContext | None = None,
        *,
        open_failure: BaseException | None = None,
    ) -> None:
        self.context = context or _RuntimeContext(_Session())
        self.open_failure = open_failure
        self.open_count = 0

    def open(self, _input_path: Path) -> _RuntimeContext:
        self.open_count += 1
        if self.open_failure is not None:
            raise self.open_failure
        return self.context


class _CountingRuntime:
    def __init__(self, *, repeated_open_failure: BaseException | None = None) -> None:
        self.capability_reads = 0
        self.open_reads = 0
        self.repeated_open_failure = repeated_open_failure

    @property
    def capability_id(self) -> str:
        self.capability_reads += 1
        return PLUGIN_RUNTIME_CAPABILITY_ID

    @property
    def open(self):
        self.open_reads += 1
        if self.open_reads > 1 and self.repeated_open_failure is not None:
            raise self.repeated_open_failure

        def open_session(_input_path: Path) -> _RuntimeContext:
            return _RuntimeContext(_Session())

        return open_session


class _OpenDescriptorRuntime:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    def __init__(self, context: _RuntimeContext) -> None:
        self.context = context
        self.open_reads = 0

    @property
    def open(self):
        self.open_reads += 1
        return lambda _input_path: self.context


class _CountingPlugin:
    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self.runtime_reads = 0

    @property
    def runtime(self) -> Any:
        self.runtime_reads += 1
        return self._runtime


class _EntryPoint:
    name = "hostile"
    dist = None

    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    def load(self) -> Any:
        raise self.failure


class _HostileModule:
    def __init__(self, failure: BaseException) -> None:
        self.failure = failure

    def __getattribute__(self, name: str) -> Any:
        if name == "plugin":
            raise object.__getattribute__(self, "failure")
        return object.__getattribute__(self, name)


class _ManifestFailurePlugin:
    @property
    def manifest(self) -> Any:
        raise _HostileFailure(_PRIVATE_PATH)


class _RuntimeFailurePlugin:
    @property
    def runtime(self) -> Any:
        raise _HostileFailure(_PRIVATE_PATH)


class _ParserPlugin:
    manifest = PluginManifest(
        plugin_id="tests.runtime-boundary",
        plugin_version="1.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("test",),
        supported_software_versions="1",
        capabilities=frozenset(),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self) -> PluginSchema:
        return PluginSchema(resource_kinds=(), relationship_types=())

    def probe(self, _inventory: Any) -> ProbeReport:
        return ProbeReport(
            result=ProbeResult(
                confidence=1.0,
                reasons=("runtime boundary fixture",),
                match_kind=ProbeMatchKind.EXACT,
            )
        )

    def locate_inputs(self, _inventory: Any) -> tuple[()]:
        return ()


class _HookFailurePlugin(_ParserPlugin):
    def describe(self):
        raise _HostileFailure(_PRIVATE_PATH)


class _GeneratorFailurePlugin(_ParserPlugin):
    def locate_inputs(self, inventory):
        del inventory
        if False:
            yield None
        raise _HostileFailure(_PRIVATE_PATH)


async def _drive_lifespan(
    application: Any,
    *,
    body_failure: BaseException | None = None,
) -> None:
    async with application.router.lifespan_context(application):
        if body_failure is not None:
            raise body_failure


def _application(runtime: Any, input_path: Path | None = None) -> Any:
    return create_runtime_application(
        RuntimeApplicationRequest(
            runtime=runtime,
            input_path=input_path or Path("unused"),
            serve_frontend=False,
        )
    )


class RuntimeExecutionBoundaryTests(unittest.TestCase):
    def assertContained(self, error: BaseException, phrase: str) -> None:
        rendered = str(error)
        self.assertIn(phrase, rendered)
        self.assertNotIn(_PRIVATE_PATH, rendered)
        self.assertLessEqual(len(rendered), 256)

    def test_entry_point_and_module_loading_contain_hostile_failures(self) -> None:
        with self.assertRaises(RuntimeError) as entry_failure:
            load_plugin_entry_point(
                "hostile",
                candidates=cast(
                    Any,
                    (_EntryPoint(_HostileFailure(_PRIVATE_PATH)),),
                ),
            )
        self.assertContained(entry_failure.exception, "failed to load")

        with (
            patch(
                "router_dump_analyzer.plugin_loading.importlib.import_module",
                return_value=_HostileModule(_HostileFailure(_PRIVATE_PATH)),
            ),
            self.assertRaises(RuntimeError) as attribute_failure,
        ):
            load_plugin_module("hostile.module")
        self.assertContained(attribute_failure.exception, "could not resolve")

        with (
            patch(
                "router_dump_analyzer.plugin_loading.importlib.import_module",
                side_effect=_HostileFailure(_PRIVATE_PATH),
            ),
            self.assertRaises(RuntimeError) as import_failure,
        ):
            load_plugin_module("hostile.module")
        self.assertContained(import_failure.exception, "failed to import")

    def test_loading_rethrows_every_process_control_signal(self) -> None:
        for control_type in PROCESS_CONTROL_EXCEPTIONS:
            with (
                self.subTest(
                    boundary="entry-point",
                    control=control_type.__name__,
                ),
                self.assertRaises(control_type),
            ):
                load_plugin_entry_point(
                    "hostile",
                    candidates=cast(
                        Any,
                        (_EntryPoint(control_type()),),
                    ),
                )
            with (
                self.subTest(
                    boundary="module-attribute",
                    control=control_type.__name__,
                ),
                patch(
                    "router_dump_analyzer.plugin_loading.importlib.import_module",
                    return_value=_HostileModule(control_type()),
                ),
                self.assertRaises(control_type),
            ):
                load_plugin_module("hostile.module")
            with (
                self.subTest(
                    boundary="module-import",
                    control=control_type.__name__,
                ),
                patch(
                    "router_dump_analyzer.plugin_loading.importlib.import_module",
                    side_effect=control_type(),
                ),
                self.assertRaises(control_type),
            ):
                load_plugin_module("hostile.module")

    def test_runtime_and_capability_descriptors_are_resolved_once(self) -> None:
        runtime = _CountingRuntime()
        plugin = _CountingPlugin(runtime)

        selected = require_plugin_runtime(plugin)

        self.assertEqual(selected.capability_id, PLUGIN_RUNTIME_CAPABILITY_ID)
        self.assertTrue(callable(selected.open))
        self.assertEqual(plugin.runtime_reads, 1)
        self.assertEqual(runtime.capability_reads, 1)
        self.assertEqual(runtime.open_reads, 1)

    def test_runtime_descriptors_are_snapshotted_once_across_selection_and_lifespan(
        self,
    ) -> None:
        runtime = _CountingRuntime()
        plugin = _CountingPlugin(runtime)

        selected = require_plugin_runtime(plugin)
        application = _application(selected)
        asyncio.run(_drive_lifespan(application))

        self.assertEqual(plugin.runtime_reads, 1)
        self.assertEqual(runtime.capability_reads, 1)
        self.assertEqual(runtime.open_reads, 1)

    def test_selection_snapshot_never_retouches_a_hostile_open_descriptor(
        self,
    ) -> None:
        failures = (_HostileFailure(_PRIVATE_PATH),) + tuple(
            control_type() for control_type in PROCESS_CONTROL_EXCEPTIONS
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                runtime = _CountingRuntime(repeated_open_failure=failure)
                selected = require_plugin_runtime(_CountingPlugin(runtime))

                asyncio.run(_drive_lifespan(_application(selected)))

                self.assertEqual(runtime.open_reads, 1)

    def test_runtime_descriptor_failure_is_contained(self) -> None:
        class Plugin:
            @property
            def runtime(self) -> Any:
                raise _HostileFailure(_PRIVATE_PATH)

        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            require_plugin_runtime(Plugin())
        self.assertContained(raised.exception, "runtime descriptor")

        class CapabilityFailureRuntime:
            @property
            def capability_id(self) -> Any:
                raise _HostileFailure(_PRIVATE_PATH)

            def open(self, _input_path: Path) -> Any:
                raise AssertionError

        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            require_plugin_runtime(_CountingPlugin(CapabilityFailureRuntime()))
        self.assertContained(raised.exception, "capability_id descriptor")

        class OpenFailureRuntime:
            capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

            @property
            def open(self) -> Any:
                raise _HostileFailure(_PRIVATE_PATH)

        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            require_plugin_runtime(_CountingPlugin(OpenFailureRuntime()))
        self.assertContained(raised.exception, "open(input_path) descriptor")

        class UnsupportedRuntime:
            capability_id = _PRIVATE_PATH

            def open(self, _input_path: Path) -> None:
                return None

        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            require_plugin_runtime(_CountingPlugin(UnsupportedRuntime()))
        self.assertContained(raised.exception, "unsupported")

    def test_manifest_failure_is_contained_at_runtime_selection(self) -> None:
        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            require_plugin_runtime(_ManifestFailurePlugin())
        self.assertContained(raised.exception, "parser contract")

    def test_hook_and_generator_failures_are_contained_at_open(self) -> None:
        for plugin_type in (_HookFailurePlugin, _GeneratorFailurePlugin):
            with self.subTest(plugin=plugin_type.__name__), tempfile.TemporaryDirectory() as directory:
                runtime = require_plugin_runtime(plugin_type())
                application = _application(runtime, Path(directory))
                with self.assertRaises(PluginRuntimeCapabilityError) as raised:
                    asyncio.run(_drive_lifespan(application))
                self.assertContained(raised.exception, "default revision load")

    def test_open_enter_and_exit_failures_are_contained(self) -> None:
        cases = (
            ("open", _Runtime(open_failure=_HostileFailure(_PRIVATE_PATH))),
            (
                "enter",
                _Runtime(
                    _RuntimeContext(
                        _Session(),
                        enter_failure=_HostileFailure(_PRIVATE_PATH),
                    )
                ),
            ),
            (
                "exit",
                _Runtime(
                    _RuntimeContext(
                        _Session(),
                        exit_failure=_HostileFailure(_PRIVATE_PATH),
                    )
                ),
            ),
        )
        for stage, runtime in cases:
            with self.subTest(stage=stage):
                application = _application(runtime)
                with self.assertRaises(PluginRuntimeCapabilityError) as raised:
                    asyncio.run(_drive_lifespan(application))
                self.assertContained(raised.exception, f"session {stage}")

    def test_open_context_and_session_descriptors_are_resolved_once(self) -> None:
        session = _Session()
        context = _DescriptorCountingContext(session)
        runtime = _OpenDescriptorRuntime(context)
        application = _application(runtime)

        asyncio.run(_drive_lifespan(application))

        self.assertEqual(runtime.open_reads, 1)
        self.assertEqual(
            context.descriptor_reads,
            {"__enter__": 1, "__exit__": 1},
        )
        self.assertEqual(session.reads, {name: 1 for name in session.reads})

    def test_exit_failure_never_replaces_an_in_flight_body_failure(self) -> None:
        context = _RuntimeContext(
            _Session(),
            exit_failure=_HostileFailure(_PRIVATE_PATH),
        )
        application = _application(_Runtime(context))
        body_failure = _BodyFailure("body failure remains authoritative")

        with self.assertRaises(_BodyFailure) as raised:
            asyncio.run(
                _drive_lifespan(
                    application,
                    body_failure=body_failure,
                )
            )

        self.assertIs(raised.exception, body_failure)
        self.assertEqual(context.exit_count, 1)
        notes = getattr(raised.exception, "__notes__", ())
        self.assertIn("plug-in runtime session cleanup also failed", notes)
        self.assertNotIn(_PRIVATE_PATH, "\n".join(notes))

    def test_context_cannot_suppress_an_in_flight_body_failure(self) -> None:
        context = _RuntimeContext(_Session(), exit_result=True)
        application = _application(_Runtime(context))
        body_failure = _BodyFailure("must not be suppressed")

        with self.assertRaises(_BodyFailure) as raised:
            asyncio.run(
                _drive_lifespan(
                    application,
                    body_failure=body_failure,
                )
            )

        self.assertIs(raised.exception, body_failure)

    def test_session_descriptors_are_snapshotted_exactly_once(self) -> None:
        session = _Session()

        self.assertIs(validate_runtime_session(session), session)

        self.assertEqual(
            session.reads,
            {name: 1 for name in session.reads},
        )

    def test_session_descriptor_failure_is_contained(self) -> None:
        session = _Session(
            failure_field="data_source",
            failure=_HostileFailure(_PRIVATE_PATH),
        )
        with self.assertRaises(PluginRuntimeCapabilityError) as raised:
            validate_runtime_session(session)
        self.assertContained(raised.exception, "data_source")

    def test_runtime_boundaries_rethrow_every_process_control_signal(self) -> None:
        for control_type in PROCESS_CONTROL_EXCEPTIONS:
            with self.subTest(boundary="runtime", control=control_type.__name__):
                class Plugin:
                    signal_type: type[BaseException]

                    @property
                    def runtime(self) -> Any:
                        raise self.signal_type()

                Plugin.signal_type = control_type

                with self.assertRaises(control_type):
                    require_plugin_runtime(Plugin())

            with self.subTest(boundary="session", control=control_type.__name__):
                session = _Session(
                    failure_field="data_policy",
                    failure=control_type(),
                )
                with self.assertRaises(control_type):
                    validate_runtime_session(session)

            for stage in ("open", "enter", "exit"):
                with self.subTest(stage=stage, control=control_type.__name__):
                    control = control_type()
                    context = _RuntimeContext(
                        _Session(),
                        enter_failure=(control if stage == "enter" else None),
                        exit_failure=(control if stage == "exit" else None),
                    )
                    runtime = _Runtime(
                        context,
                        open_failure=(control if stage == "open" else None),
                    )
                    with self.assertRaises(control_type):
                        asyncio.run(_drive_lifespan(_application(runtime)))

    def test_hook_and_generator_rethrow_every_process_control_signal(self) -> None:
        for control_type in PROCESS_CONTROL_EXCEPTIONS:
            class HookControlPlugin(_ParserPlugin):
                def describe(
                    self,
                    selected: type[BaseException] = control_type,
                ):
                    raise selected()

            class GeneratorControlPlugin(_ParserPlugin):
                def locate_inputs(
                    self,
                    inventory,
                    selected: type[BaseException] = control_type,
                ):
                    del inventory
                    if False:
                        yield None
                    raise selected()

            for plugin_type in (HookControlPlugin, GeneratorControlPlugin):
                with (
                    self.subTest(
                        plugin=plugin_type.__name__,
                        control=control_type.__name__,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    runtime = require_plugin_runtime(plugin_type())
                    with self.assertRaises(control_type):
                        asyncio.run(
                            _drive_lifespan(
                                _application(runtime, Path(directory))
                            )
                        )

    def test_cli_last_resort_contains_unknown_base_exception(self) -> None:
        stderr = io.StringIO()
        with (
            patch(
                "router_dump_analyzer.cli.run",
                side_effect=_HostileFailure(_PRIVATE_PATH),
            ),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(
                [
                    "--plugin",
                    "hostile",
                    "--input",
                    "unused.tgz",
                    "--no-browser",
                ]
            )

        self.assertEqual(stopped.exception.code, 1)
        rendered = stderr.getvalue()
        self.assertEqual(
            rendered,
            "router-dump-analyzer: error: "
            "analyzer configuration or startup failed\n",
        )
        self.assertNotIn(_PRIVATE_PATH, rendered)
        self.assertNotIn("Traceback", rendered)

        stderr = io.StringIO()
        with (
            patch(
                "router_dump_analyzer.cli.run",
                side_effect=_UnrenderableRuntimeError(
                    _HostileFailure(_PRIVATE_PATH)
                ),
            ),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(
                [
                    "--plugin",
                    "hostile",
                    "--input",
                    "unused.tgz",
                    "--no-browser",
                ]
            )
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(
            stderr.getvalue(),
            "router-dump-analyzer: error: "
            "analyzer configuration or startup failed\n",
        )

    def test_main_cli_contains_manifest_runtime_hook_and_generator_failures(
        self,
    ) -> None:
        def launcher_for(selected_plugin: object):
            def launch(configuration: Any) -> None:
                run_cli(
                    configuration,
                    module_loader=lambda _name: selected_plugin,
                    application_factory=create_runtime_application,
                    server_runner=(
                        lambda application, **_kwargs: asyncio.run(
                            _drive_lifespan(application)
                        )
                    ),
                )

            return launch

        cases = (
            ("manifest", _ManifestFailurePlugin()),
            ("runtime", _RuntimeFailurePlugin()),
            ("hook", _HookFailurePlugin()),
            ("generator", _GeneratorFailurePlugin()),
        )
        for label, plugin in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                stderr = io.StringIO()

                with (
                    patch(
                        "router_dump_analyzer.cli.run",
                        side_effect=launcher_for(plugin),
                    ),
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    main(
                        [
                            "--plugin-module",
                            "hostile.module",
                            "--input",
                            directory,
                            "--no-browser",
                            "--api-only",
                        ]
                    )
                self.assertEqual(stopped.exception.code, 1)
                rendered = stderr.getvalue()
                self.assertNotIn(_PRIVATE_PATH, rendered)
                self.assertNotIn("Traceback", rendered)
                self.assertLessEqual(len(rendered), 512)

    def test_cli_last_resort_rethrows_every_process_control_signal(self) -> None:
        arguments = [
            "--plugin",
            "hostile",
            "--input",
            "unused.tgz",
            "--no-browser",
        ]
        for control_type in PROCESS_CONTROL_EXCEPTIONS:
            with (
                self.subTest(control=control_type.__name__),
                patch(
                    "router_dump_analyzer.cli.run",
                    side_effect=control_type(),
                ),
                self.assertRaises(control_type),
            ):
                main(arguments)
            with (
                self.subTest(
                    boundary="error rendering",
                    control=control_type.__name__,
                ),
                patch(
                    "router_dump_analyzer.cli.run",
                    side_effect=_UnrenderableRuntimeError(control_type()),
                ),
                self.assertRaises(control_type),
            ):
                main(arguments)


if __name__ == "__main__":
    unittest.main()

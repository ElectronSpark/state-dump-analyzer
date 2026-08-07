from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTransport,
)
from router_dump_analyzer.private_analysis_deployment import (
    MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS,
    PrivateAnalysisDeployment,
    PrivateAnalysisDeploymentContext,
    PrivateAnalysisDeploymentLoadError,
    load_private_analysis_deployment,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisExecutionLimits,
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
)
from router_dump_analyzer.private_analysis_service import (
    PrivateAnalysisDeploymentCeilings,
)


class _HostileFailure(BaseException):
    pass


def _registration(
    *,
    runner_id: str = "deployment.local-model",
    runner_version: str = "1.0.0",
    configuration_character: str = "a",
) -> PrivateAnalysisRunnerRegistration:
    selection = PrivateAnalysisRunnerSelection(
        runner_id=runner_id,
        runner_version=runner_version,
        transport=PrivateAnalysisTransport.IN_PROCESS,
        configuration_digest="sha256:" + configuration_character * 64,
    )
    runner = ConfiguredPrivateAnalysisInProcessRunner(
        selection,
        instruction_profile_digest="sha256:" + "b" * 64,
        model_callback=lambda _context, _gateway: "{}",
    )
    return PrivateAnalysisRunnerRegistration(
        runner=runner,
        trusted_inline_tool_service_factory=lambda _request: None,  # type: ignore[arg-type]
        custom_evidence_service_digest="sha256:" + "f" * 64,
    )


def _deployment() -> PrivateAnalysisDeployment:
    return PrivateAnalysisDeployment(
        registrations=(_registration(),),
        execution_limits=PrivateAnalysisExecutionLimits(
            max_concurrent_runs=3,
            lease_duration_ns=3_000_000_000,
            heartbeat_interval_ns=1_000_000_000,
            cancellation_poll_interval_ns=100_000_000,
            monitor_join_timeout_ns=2_000_000_000,
        ),
        ceilings=PrivateAnalysisDeploymentCeilings(max_revisions=17, max_list_runs=23),
    )


class PrivateAnalysisDeploymentTests(unittest.TestCase):
    def test_context_is_frozen_and_resolves_one_absolute_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relative = Path(directory) / "child" / ".." / "state"
            context = PrivateAnalysisDeploymentContext(relative)
            self.assertTrue(context.state_dir.is_absolute())
            self.assertEqual(context.state_dir, (Path(directory) / "state").resolve())
            with self.assertRaises(dataclasses.FrozenInstanceError):
                context.state_dir = Path(directory)  # type: ignore[misc]

    def test_descriptor_has_closed_fields_and_detaches_nested_values(self) -> None:
        registration = _registration()
        limits = PrivateAnalysisExecutionLimits()
        ceilings = PrivateAnalysisDeploymentCeilings()
        deployment = PrivateAnalysisDeployment(
            registrations=(registration,),
            execution_limits=limits,
            ceilings=ceilings,
        )
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(deployment)),
            ("registrations", "execution_limits", "ceilings"),
        )
        self.assertIsNot(deployment.registrations[0], registration)
        self.assertIsNot(deployment.execution_limits, limits)
        self.assertIsNot(deployment.ceilings, ceilings)
        assert deployment.ceilings is not None
        self.assertIsNot(deployment.ceilings.request_limits, ceilings.request_limits)

    def test_descriptor_enforces_exact_bounded_nonempty_unique_registrations(
        self,
    ) -> None:
        registration = _registration()
        with self.assertRaises(TypeError):
            PrivateAnalysisDeployment(registrations=[registration])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            PrivateAnalysisDeployment(registrations=())
        with self.assertRaises(ValueError):
            PrivateAnalysisDeployment(
                registrations=(registration,)
                * (MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS + 1)
            )
        with self.assertRaises(TypeError):
            PrivateAnalysisDeployment(registrations=(object(),))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "selection is duplicated"):
            PrivateAnalysisDeployment(registrations=(registration, registration))

        same_public_identity = _registration(configuration_character="c")
        with self.assertRaisesRegex(ValueError, "ID and version are duplicated"):
            PrivateAnalysisDeployment(
                registrations=(registration, same_public_identity)
            )

    def test_descriptor_rejects_nonexact_optional_contract_values(self) -> None:
        registration = _registration()
        with self.assertRaises(TypeError):
            PrivateAnalysisDeployment(
                registrations=(registration,),
                execution_limits=object(),  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            PrivateAnalysisDeployment(
                registrations=(registration,),
                ceilings=object(),  # type: ignore[arg-type]
            )

    def test_descriptor_canonicalizes_runner_registration_order(self) -> None:
        later = _registration(runner_id="runner-z")
        earlier = _registration(runner_id="runner-a", configuration_character="c")
        deployment = PrivateAnalysisDeployment(registrations=(later, earlier))

        self.assertEqual(
            tuple(
                item.runner.selection.runner_id for item in deployment.registrations
            ),
            ("runner-a", "runner-z"),
        )

    def test_loader_accepts_exact_value_and_returns_a_detached_descriptor(self) -> None:
        deployment = _deployment()
        with tempfile.TemporaryDirectory() as directory:
            context = PrivateAnalysisDeploymentContext(Path(directory))
            with patch(
                "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                return_value=SimpleNamespace(configured=deployment),
            ):
                loaded = load_private_analysis_deployment(
                    "trusted.private_model:configured",
                    context=context,
                )
        self.assertIsNot(loaded, deployment)
        self.assertIsNot(loaded.registrations[0], deployment.registrations[0])
        self.assertEqual(
            loaded.registrations[0].runner.selection,
            deployment.registrations[0].runner.selection,
        )

    def test_loader_calls_factory_once_with_only_a_detached_exact_context(self) -> None:
        deployment = _deployment()
        received: list[PrivateAnalysisDeploymentContext] = []

        def factory(context: PrivateAnalysisDeploymentContext) -> object:
            received.append(context)
            return deployment

        with tempfile.TemporaryDirectory() as directory:
            supplied = PrivateAnalysisDeploymentContext(Path(directory))
            with patch(
                "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                return_value=SimpleNamespace(build=factory),
            ):
                loaded = load_private_analysis_deployment(
                    "trusted.private_model:build",
                    context=supplied,
                )
        self.assertEqual(len(received), 1)
        self.assertIs(type(received[0]), PrivateAnalysisDeploymentContext)
        self.assertIsNot(received[0], supplied)
        self.assertEqual(received[0].state_dir, supplied.state_dir)
        self.assertIsNot(loaded, deployment)

    def test_loader_rejects_malformed_targets_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = PrivateAnalysisDeploymentContext(Path(directory))
            for target in (
                "",
                "module",
                ":value",
                "module:",
                "module:value:extra",
                " module:value",
                "module:bad-value",
                "bad-module:value",
            ):
                with (
                    self.subTest(target=target),
                    patch(
                        "router_dump_analyzer.private_analysis_deployment.importlib.import_module"
                    ) as importer,
                    self.assertRaises(ValueError),
                ):
                    load_private_analysis_deployment(target, context=context)
                importer.assert_not_called()

    def test_loader_preserves_process_control_at_every_extension_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = PrivateAnalysisDeploymentContext(Path(directory))
            for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
                with (
                    self.subTest(boundary="import", exception=exception_type),
                    patch(
                        "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                        side_effect=exception_type(),
                    ),
                    self.assertRaises(exception_type),
                ):
                    load_private_analysis_deployment(
                        "trusted.module:value",
                        context=context,
                    )

                def factory(
                    _context: PrivateAnalysisDeploymentContext,
                    selected_exception: type[BaseException] = exception_type,
                ) -> object:
                    raise selected_exception()

                with (
                    self.subTest(boundary="factory", exception=exception_type),
                    patch(
                        "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                        return_value=SimpleNamespace(value=factory),
                    ),
                    self.assertRaises(exception_type),
                ):
                    load_private_analysis_deployment(
                        "trusted.module:value",
                        context=context,
                    )

    def test_loader_contains_hostile_import_attribute_and_factory_failures(
        self,
    ) -> None:
        secret = "failed at C:\\Users\\alice\\secret\\provider.py"

        class HostileAttribute:
            def __getattribute__(self, _name: str) -> object:
                raise _HostileFailure(secret)

        def hostile_factory(_context: PrivateAnalysisDeploymentContext) -> object:
            raise _HostileFailure(secret)

        cases = (
            (
                _HostileFailure(secret),
                None,
                "private-analysis deployment module could not be imported",
            ),
            (
                None,
                HostileAttribute(),
                "private-analysis deployment target could not be resolved",
            ),
            (
                None,
                SimpleNamespace(value=hostile_factory),
                "private-analysis deployment factory failed",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            context = PrivateAnalysisDeploymentContext(Path(directory))
            for import_failure, imported, message in cases:
                with self.subTest(message=message):
                    patcher = patch(
                        "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                        side_effect=import_failure,
                        return_value=imported,
                    )
                    with (
                        patcher,
                        self.assertRaises(PrivateAnalysisDeploymentLoadError) as caught,
                    ):
                        load_private_analysis_deployment(
                            "trusted.module:value",
                            context=context,
                        )
                    self.assertEqual(str(caught.exception), message)
                    self.assertNotIn(secret, str(caught.exception))
                    self.assertIsNone(caught.exception.__cause__)

    def test_loader_rejects_nonexact_or_wrong_arity_factory_results(self) -> None:
        class DeploymentSubclass(PrivateAnalysisDeployment):
            pass

        deployment = _deployment()
        subclass = DeploymentSubclass(
            registrations=deployment.registrations,
            execution_limits=deployment.execution_limits,
            ceilings=deployment.ceilings,
        )
        factories = (
            lambda _context: object(),
            lambda _context: subclass,
            lambda: deployment,
        )
        expected = (
            "private-analysis deployment descriptor is invalid",
            "private-analysis deployment descriptor is invalid",
            "private-analysis deployment factory failed",
        )
        with tempfile.TemporaryDirectory() as directory:
            context = PrivateAnalysisDeploymentContext(Path(directory))
            for factory, message in zip(factories, expected, strict=True):
                with (
                    self.subTest(message=message),
                    patch(
                        "router_dump_analyzer.private_analysis_deployment.importlib.import_module",
                        return_value=SimpleNamespace(value=factory),
                    ),
                    self.assertRaisesRegex(
                        PrivateAnalysisDeploymentLoadError,
                        f"^{message}$",
                    ),
                ):
                    load_private_analysis_deployment(
                        "trusted.module:value",
                        context=context,
                    )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.annotation_store import ReviewScope
from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.private_analysis import (
    EvidenceScope,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisLimits,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    private_analysis_result_json,
)
from router_dump_analyzer.private_analysis_cli import (
    EXIT_ADVISORY_ERROR,
    EXIT_FAILURE,
    EXIT_SUCCESS,
    MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES,
    PrivateAnalysisCliConfiguration,
    PrivateAnalysisCliInputError,
    PrivateAnalysisCliOperation,
    _read_request_document,
    build_parser,
    main,
    parse_args,
    run,
)
from router_dump_analyzer.private_analysis_deployment import (
    PrivateAnalysisDeployment,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
)
from router_dump_analyzer.private_analysis_promotion import (
    ProposalReviewDecision,
    ProposalReviewDisposition,
    ProposalReviewState,
)
from router_dump_analyzer.private_analysis_service import PrivateAnalysisRequestSpec
from tests.test_private_ai_in_process_runner import (
    _Harness,
    _selection,
    _unsupported_result,
)
from tests.test_private_analysis_service import _PROFILE_DIGEST, _digest, _plan


def _durable_cli_model_callback(context: Any, _gateway: Any) -> str:
    """Return a stable result without mutating retained callback state."""

    return private_analysis_result_json(_unsupported_result(context.request))


class _Registry:
    def __init__(self, **options: Any) -> None:
        self.options = options
        self.registered: list[tuple[Any, dict[str, Any]]] = []

    def register(self, plugin: Any, **coordinates: Any) -> None:
        self.registered.append((plugin, coordinates))


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.result = object()
        self.report = SimpleNamespace(outcome=SimpleNamespace(result=object()))

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((name, args, kwargs))
        return self.result

    def list_runners(self, *args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (self._call("list_runners", *args, **kwargs),)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("create", args, kwargs))
        return SimpleNamespace(run_id="run-1", version=3)

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("get", *args, **kwargs)

    def list(self, *args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (self._call("list", *args, **kwargs),)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("execute", args, kwargs))
        return SimpleNamespace(run_id="run-1")

    def cancel(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("cancel", *args, **kwargs)

    def recover_expired(self, *args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (self._call("recover_expired", *args, **kwargs),)

    def get_report(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("get_report", args, kwargs))
        return self.report


def _decision() -> ProposalReviewDecision:
    return ProposalReviewDecision(
        scope=ReviewScope("tenant-a", "project-a", "workspace-a"),
        decision_id="decision-1",
        run_id="run-1",
        proposal_id="proposal-1",
        proposal_digest="sha256:" + "8" * 64,
        result_digest="sha256:" + "9" * 64,
        run_version=3,
        disposition=ProposalReviewDisposition.REJECT,
        state=ProposalReviewState.COMPLETED,
        actor="ci",
        rationale="Reviewed.",
        request_digest="sha256:" + "a" * 64,
        target_kind=None,
        target_id=None,
        created_at_ns=100,
        updated_at_ns=100,
        version=1,
    )


class _ReviewService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def decide(self, *args: Any, **kwargs: Any) -> ProposalReviewDecision:
        self.calls.append(("decide", args, kwargs))
        return _decision()

    def list(self, *args: Any, **kwargs: Any) -> tuple[ProposalReviewDecision, ...]:
        self.calls.append(("list", args, kwargs))
        return (_decision(),)

    def get(self, *args: Any, **kwargs: Any) -> ProposalReviewDecision:
        self.calls.append(("get", args, kwargs))
        return _decision()

    def recover(self, *args: Any, **kwargs: Any) -> ProposalReviewDecision:
        self.calls.append(("recover", args, kwargs))
        return _decision()


class _ControlPlane:
    def __init__(
        self,
        service: _Service,
        values: dict[str, Any],
        review_service: _ReviewService | None = None,
    ) -> None:
        self.private_analysis = service
        self.private_analysis_reviews = review_service or _ReviewService()
        self.values = values
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class PrivateAnalysisCliTests(unittest.TestCase):
    def _configuration(
        self,
        root: Path,
        operation: PrivateAnalysisCliOperation,
        **overrides: Any,
    ) -> PrivateAnalysisCliConfiguration:
        values: dict[str, Any] = {
            "state_dir": root / "state",
            "tenant_id": "tenant-a",
            "project_id": "project-a",
            "workspace_id": "workspace-a",
            "plugin_names": (),
            "plugin_modules": ("vendor.router:plugin",),
            "deployment_module": "deployment.private:build",
            "operation": operation,
        }
        values.update(overrides)
        return PrivateAnalysisCliConfiguration(**values)

    def test_parser_requires_local_deployment_and_never_accepts_query_text(
        self,
    ) -> None:
        common = [
            "--plugin",
            "vendor",
            "--state-dir",
            "state",
            "--tenant",
            "tenant-a",
            "--project",
            "project-a",
            "--workspace",
            "workspace-a",
        ]
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args([*common, "runners"])

        parsed = parse_args(
            [
                *common,
                "--private-analysis-deployment-module",
                "deployment.private:build",
                "runners",
            ]
        )
        self.assertEqual(parsed.operation, PrivateAnalysisCliOperation.RUNNERS)
        option_strings = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
        }
        self.assertNotIn("--query", option_strings)
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args(
                [
                    *common,
                    "--private-analysis-deployment-module",
                    "deployment.private:build",
                    "runners",
                    "--query",
                    "proprietary text",
                ]
            )

        composed = parse_args(
            [
                "--plugin-deployment-module",
                "deployment.plugins:build",
                "--state-dir",
                "state",
                "--tenant",
                "tenant-a",
                "--project",
                "project-a",
                "--workspace",
                "workspace-a",
                "--private-analysis-deployment-module",
                "deployment.private:build",
                "runners",
            ]
        )
        self.assertEqual(composed.plugin_names, ())
        self.assertEqual(composed.plugin_modules, ())
        self.assertEqual(
            composed.plugin_deployment_module,
            "deployment.plugins:build",
        )

    def test_plugin_composition_deployment_reaches_private_analysis_control_plane(
        self,
    ) -> None:
        registry = object()
        providers = object()
        policy = object()
        composition = SimpleNamespace(
            primary_registry=registry,
            capability_providers=providers,
            policy=policy,
            allow_inline_only=True,
            requires_inline_execution=True,
        )
        service = SimpleNamespace(list_runners=lambda _scope: ())
        control_plane = _ControlPlane(service, {})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = self._configuration(
                root,
                PrivateAnalysisCliOperation.RUNNERS,
                plugin_names=(),
                plugin_modules=(),
                plugin_deployment_module="deployment.plugins:build",
            )
            exit_code = run(
                configuration,
                entry_point_loader=lambda _name: self.fail(),
                module_loader=lambda _target: self.fail(),
                plugin_deployment_loader=lambda _target, **_values: composition,
                deployment_loader=lambda _target, **_values: SimpleNamespace(
                    registrations=(),
                    execution_limits=None,
                    ceilings=None,
                ),
                registry_factory=lambda **_values: self.fail(),
                control_plane_factory=lambda _root, **values: (
                    control_plane.values.update(values) or control_plane
                ),
                stdout=io.StringIO(),
            )

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertIs(control_plane.values["registry"], registry)
        self.assertIs(control_plane.values["capability_providers"], providers)
        self.assertIs(control_plane.values["plugin_composition_policy"], policy)
        self.assertIs(control_plane.values["allow_inline_only"], True)

    def test_list_cursor_is_an_exact_pair_and_versions_are_canonical(self) -> None:
        common = [
            "--plugin",
            "vendor",
            "--state-dir",
            "state",
            "--tenant",
            "tenant-a",
            "--project",
            "project-a",
            "--workspace",
            "workspace-a",
            "--private-analysis-deployment-module",
            "deployment.private:build",
        ]
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args([*common, "list", "--after-created-at-ns", "1"])
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args(
                [
                    *common,
                    "execute",
                    "--run-id",
                    "run-1",
                    "--actor",
                    "ci",
                    "--expected-version",
                    "+1",
                ]
            )

        recovery = parse_args(
            [
                *common,
                "recover-expired",
                "--actor",
                "ci-recovery",
                "--limit",
                "7",
            ]
        )
        self.assertIs(
            recovery.operation,
            PrivateAnalysisCliOperation.RECOVER_EXPIRED,
        )
        self.assertEqual(recovery.actor_id, "ci-recovery")
        self.assertEqual(recovery.limit, 7)
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args([*common, "recover-expired", "--limit", "7"])

    def test_headless_expired_recovery_is_scoped_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = _Service()
            control_plane = _ControlPlane(service, {})
            output = io.StringIO()
            with patch(
                "router_dump_analyzer.private_analysis_cli."
                "private_analysis_run_to_wire",
                return_value={"run_id": "recovered"},
            ):
                exit_code = run(
                    self._configuration(
                        root,
                        PrivateAnalysisCliOperation.RECOVER_EXPIRED,
                        actor_id="ci-recovery",
                        limit=7,
                    ),
                    module_loader=lambda _target: object(),
                    deployment_loader=lambda _target, **_values: SimpleNamespace(
                        registrations=(),
                        execution_limits=None,
                        ceilings=None,
                    ),
                    registry_factory=_Registry,
                    control_plane_factory=lambda _root, **_values: control_plane,
                    stdout=output,
                )

        self.assertEqual(exit_code, EXIT_SUCCESS)
        name, args, keywords = service.calls[0]
        self.assertEqual(name, "recover_expired")
        self.assertEqual(args[0].tenant_id, "tenant-a")
        self.assertEqual(keywords, {"actor_id": "ci-recovery", "limit": 7})
        self.assertEqual(json.loads(output.getvalue())["operation"], "recover-expired")

    def test_proposal_review_parser_keeps_human_intent_out_of_argv(self) -> None:
        common = [
            "--plugin",
            "vendor",
            "--state-dir",
            "state",
            "--tenant",
            "tenant-a",
            "--project",
            "project-a",
            "--workspace",
            "workspace-a",
            "--private-analysis-deployment-module",
            "deployment.private:build",
        ]
        parsed = parse_args(
            [
                *common,
                "decide-proposal",
                "--run-id",
                "run-1",
                "--proposal-id",
                "proposal-1",
                "--actor",
                "ci",
                "--expected-version",
                "3",
                "--idempotency-key",
                "review-1",
                "--request",
                "decision.json",
            ]
        )
        self.assertEqual(
            parsed.operation,
            PrivateAnalysisCliOperation.DECIDE_PROPOSAL,
        )
        self.assertEqual(parsed.proposal_id, "proposal-1")
        with self.assertRaises(PrivateAnalysisCliInputError):
            parse_args(
                [
                    *common,
                    "decide-proposal",
                    "--run-id",
                    "run-1",
                    "--proposal-id",
                    "proposal-1",
                    "--actor",
                    "ci",
                    "--expected-version",
                    "3",
                    "--idempotency-key",
                    "review-1",
                    "--request",
                    "decision.json",
                    "--rationale",
                    "proprietary review text",
                ]
            )

    def test_headless_proposal_decide_list_and_get_share_the_durable_service(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "decision.json"
            request.write_text(
                json.dumps(
                    {
                        "proposal_digest": "sha256:" + "8" * 64,
                        "result_digest": "sha256:" + "9" * 64,
                        "disposition": "reject",
                        "rationale": "Reviewed.",
                    }
                ),
                encoding="utf-8",
            )
            cases = (
                (
                    PrivateAnalysisCliOperation.DECIDE_PROPOSAL,
                    {
                        "run_id": "run-1",
                        "proposal_id": "proposal-1",
                        "actor_id": "ci",
                        "expected_version": 3,
                        "idempotency_key": "review-1",
                        "request_path": request,
                    },
                    "decide",
                    "decision",
                ),
                (
                    PrivateAnalysisCliOperation.LIST_DECISIONS,
                    {"run_id": "run-1", "limit": 10, "offset": 2},
                    "list",
                    "decisions",
                ),
                (
                    PrivateAnalysisCliOperation.GET_DECISION,
                    {"run_id": "run-1", "decision_id": "decision-1"},
                    "get",
                    "decision",
                ),
                (
                    PrivateAnalysisCliOperation.RECOVER_DECISION,
                    {
                        "run_id": "run-1",
                        "decision_id": "decision-1",
                        "expected_version": 1,
                    },
                    ("get", "recover"),
                    "decision",
                ),
            )
            for operation, overrides, expected_call, output_field in cases:
                with self.subTest(operation=operation):
                    service = _Service()
                    reviews = _ReviewService()
                    control_plane = _ControlPlane(service, {}, reviews)
                    output = io.StringIO()
                    exit_code = run(
                        self._configuration(root, operation, **overrides),
                        module_loader=lambda _target: object(),
                        deployment_loader=lambda _target, **_values: SimpleNamespace(
                            registrations=(), execution_limits=None, ceilings=None
                        ),
                        registry_factory=_Registry,
                        control_plane_factory=(
                            lambda *_args, selected=control_plane, **_values: selected
                        ),
                        stdout=output,
                    )
                    self.assertEqual(exit_code, EXIT_SUCCESS)
                    if isinstance(expected_call, tuple):
                        self.assertEqual(
                            tuple(item[0] for item in reviews.calls),
                            expected_call,
                        )
                    else:
                        self.assertEqual(reviews.calls[0][0], expected_call)
                    self.assertEqual(control_plane.close_count, 1)
                    document = json.loads(output.getvalue())
                    self.assertIn(output_field, document)
                    if operation is PrivateAnalysisCliOperation.DECIDE_PROPOSAL:
                        call = reviews.calls[0]
                        self.assertEqual(call[2]["actor"], "ci")
                        self.assertEqual(call[2]["expected_run_version"], 3)
                        self.assertIsNone(call[2]["target"])
                    if operation is PrivateAnalysisCliOperation.LIST_DECISIONS:
                        self.assertEqual(reviews.calls[0][2]["offset"], 2)
                    projected = (
                        document["decisions"][0]
                        if output_field == "decisions"
                        else document["decision"]
                    )
                    self.assertEqual(projected["version"], "1")
                    self.assertEqual(projected["run_version"], "3")

    def test_main_maps_argument_errors_to_closed_exit_one_json(self) -> None:
        proprietary = "proprietary-query-must-not-appear"
        stderr = io.StringIO()
        with (
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(["--query", proprietary])

        self.assertEqual(stopped.exception.code, EXIT_FAILURE)
        rendered = stderr.getvalue()
        self.assertNotIn("usage:", rendered)
        self.assertNotIn(proprietary, rendered)
        document = json.loads(rendered)
        self.assertEqual(document["exit_code"], EXIT_FAILURE)
        self.assertEqual(document["error"]["code"], "command_failed")

    def test_request_file_rejects_duplicate_nonfinite_and_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"query":"a","query":"b"}', encoding="utf-8")
            with self.assertRaises(PrivateAnalysisCliInputError):
                _read_request_document(duplicate)

            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"query":NaN}', encoding="utf-8")
            with self.assertRaises(PrivateAnalysisCliInputError):
                _read_request_document(nonfinite)

            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(PrivateAnalysisCliInputError):
                _read_request_document(oversized)

            class _GrowingRequestFile(io.BytesIO):
                def __init__(self) -> None:
                    super().__init__(
                        b"x" * (MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES + 64)
                    )
                    self.read_sizes: list[int] = []

                def fileno(self) -> int:
                    return 17

                def read(self, size: int = -1) -> bytes:
                    self.read_sizes.append(size)
                    return super().read(size)

            growing = _GrowingRequestFile()
            bounded = root / "growing.json"
            bounded.touch()
            with (
                patch.object(Path, "open", return_value=growing),
                patch(
                    "router_dump_analyzer.private_analysis_cli.os.fstat",
                    return_value=SimpleNamespace(st_size=1),
                ),
                self.assertRaises(PrivateAnalysisCliInputError),
            ):
                _read_request_document(bounded)
            self.assertEqual(
                growing.read_sizes,
                [MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES + 1],
            )

    def test_every_lifecycle_operation_dispatches_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            request.write_text("{}", encoding="utf-8")
            cases = (
                (PrivateAnalysisCliOperation.RUNNERS, {}, "list_runners"),
                (
                    PrivateAnalysisCliOperation.CREATE,
                    {
                        "request_path": request,
                        "actor_id": "ci",
                        "idempotency_key": "idem",
                    },
                    "create",
                ),
                (PrivateAnalysisCliOperation.GET, {"run_id": "run-1"}, "get"),
                (PrivateAnalysisCliOperation.LIST, {}, "list"),
                (
                    PrivateAnalysisCliOperation.EXECUTE,
                    {
                        "run_id": "run-1",
                        "actor_id": "ci",
                        "expected_version": 2,
                    },
                    "execute",
                ),
                (
                    PrivateAnalysisCliOperation.CANCEL,
                    {
                        "run_id": "run-1",
                        "actor_id": "ci",
                        "expected_version": 2,
                    },
                    "cancel",
                ),
                (
                    PrivateAnalysisCliOperation.REPORT,
                    {"run_id": "run-1"},
                    "get_report",
                ),
            )
            for operation, overrides, expected_call in cases:
                with self.subTest(operation=operation):
                    service = _Service()
                    control_planes: list[_ControlPlane] = []

                    def control_plane_factory(
                        _root: Path,
                        *,
                        selected_service: _Service = service,
                        selected_planes: list[_ControlPlane] = control_planes,
                        **values: Any,
                    ) -> _ControlPlane:
                        result = _ControlPlane(selected_service, values)
                        selected_planes.append(result)
                        return result

                    output = io.StringIO()
                    with (
                        patch(
                            "router_dump_analyzer.private_analysis_cli."
                            "parse_private_analysis_request_spec",
                            return_value=object(),
                        ),
                        patch(
                            "router_dump_analyzer.private_analysis_cli."
                            "private_analysis_runner_to_wire",
                            return_value={"runner_id": "local"},
                        ),
                        patch(
                            "router_dump_analyzer.private_analysis_cli."
                            "private_analysis_run_to_wire",
                            return_value={"run_id": "run-1"},
                        ),
                        patch(
                            "router_dump_analyzer.private_analysis_cli."
                            "private_analysis_report_to_wire",
                            return_value={"outcome": "result"},
                        ),
                    ):
                        exit_code = run(
                            self._configuration(root, operation, **overrides),
                            module_loader=lambda _target: object(),
                            deployment_loader=lambda _target, **_values: (
                                SimpleNamespace(
                                    registrations=(object(),),
                                    execution_limits=object(),
                                    ceilings=object(),
                                )
                            ),
                            registry_factory=_Registry,
                            control_plane_factory=control_plane_factory,
                            stdout=output,
                        )
                    self.assertEqual(exit_code, EXIT_SUCCESS)
                    self.assertEqual(service.calls[0][0], expected_call)
                    self.assertEqual(control_planes[0].close_count, 1)
                    self.assertEqual(
                        len(control_planes[0].values["private_analysis_runners"]),
                        1,
                    )
                    document = json.loads(output.getvalue())
                    self.assertTrue(document["success"])
                    self.assertEqual(document["operation"], operation.value)

    def test_run_uses_current_created_version_and_reports_advisory_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            request.write_text("{}", encoding="utf-8")
            service = _Service()
            service.report = SimpleNamespace(outcome=SimpleNamespace(result=None))
            control_plane = _ControlPlane(service, {})
            output = io.StringIO()
            with (
                patch(
                    "router_dump_analyzer.private_analysis_cli."
                    "parse_private_analysis_request_spec",
                    return_value=object(),
                ),
                patch(
                    "router_dump_analyzer.private_analysis_cli."
                    "private_analysis_report_to_wire",
                    return_value={"outcome": {"kind": "error"}},
                ),
            ):
                exit_code = run(
                    self._configuration(
                        root,
                        PrivateAnalysisCliOperation.RUN,
                        request_path=request,
                        actor_id="ci",
                        idempotency_key="idem",
                    ),
                    module_loader=lambda _target: object(),
                    deployment_loader=lambda _target, **_values: SimpleNamespace(
                        registrations=(), execution_limits=None, ceilings=None
                    ),
                    registry_factory=_Registry,
                    control_plane_factory=lambda *_args, **_values: control_plane,
                    stdout=output,
                )

            self.assertEqual(exit_code, EXIT_ADVISORY_ERROR)
            self.assertEqual(
                [name for name, _args, _kwargs in service.calls],
                ["create", "execute", "get_report"],
            )
            execute = service.calls[1]
            self.assertEqual(execute[1][1], "run-1")
            self.assertEqual(execute[2]["expected_version"], 3)
            self.assertEqual(control_plane.close_count, 1)
            document = json.loads(output.getvalue())
            self.assertFalse(document["success"])
            self.assertEqual(document["exit_code"], EXIT_ADVISORY_ERROR)

    def test_control_plane_closes_when_service_or_process_control_fails(self) -> None:
        for failure in (RuntimeError("failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                service = _Service()

                def fail(
                    *_args: Any,
                    selected_failure: BaseException = failure,
                    **_kwargs: Any,
                ) -> Any:
                    raise selected_failure

                service.list_runners = fail  # type: ignore[method-assign]
                control_plane = _ControlPlane(service, {})
                with (
                    tempfile.TemporaryDirectory() as directory,
                    self.assertRaises(type(failure)),
                ):
                    run(
                        self._configuration(
                            Path(directory),
                            PrivateAnalysisCliOperation.RUNNERS,
                        ),
                        module_loader=lambda _target: object(),
                        deployment_loader=lambda _target, **_values: SimpleNamespace(
                            registrations=(),
                            execution_limits=None,
                            ceilings=None,
                        ),
                        registry_factory=_Registry,
                        control_plane_factory=(
                            lambda *_args, selected=control_plane, **_values: selected
                        ),
                        stdout=io.StringIO(),
                    )
                self.assertEqual(control_plane.close_count, 1)

    def test_cleanup_completes_before_stdout_or_output_file_is_published(self) -> None:
        service = _Service()
        service.list_runners = lambda *_args, **_kwargs: ()  # type: ignore[method-assign]
        control_plane = _ControlPlane(service, {})

        def fail_close() -> None:
            control_plane.close_count += 1
            raise RuntimeError("hostile cleanup detail")

        control_plane.close = fail_close  # type: ignore[method-assign]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "result.json"
            output = io.StringIO()
            with self.assertRaisesRegex(RuntimeError, "hostile cleanup"):
                run(
                    self._configuration(
                        root,
                        PrivateAnalysisCliOperation.RUNNERS,
                        output_path=artifact,
                    ),
                    module_loader=lambda _target: object(),
                    deployment_loader=lambda _target, **_values: SimpleNamespace(
                        registrations=(),
                        execution_limits=None,
                        ceilings=None,
                    ),
                    registry_factory=_Registry,
                    control_plane_factory=(
                        lambda *_args, selected=control_plane, **_values: selected
                    ),
                    stdout=output,
                )

            self.assertEqual(control_plane.close_count, 1)
            self.assertEqual(output.getvalue(), "")
            self.assertFalse(artifact.exists())

    def test_main_contains_hostile_details_and_preserves_process_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            configuration = self._configuration(
                Path(directory),
                PrivateAnalysisCliOperation.RUNNERS,
            )
            hostile_detail = (
                r"C:\Users\alice\secret\deployment.py?query=proprietary-token"
            )
            stderr = io.StringIO()
            with (
                patch(
                    "router_dump_analyzer.private_analysis_cli.parse_args",
                    return_value=configuration,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_cli.run",
                    side_effect=RuntimeError(hostile_detail),
                ),
                redirect_stderr(stderr),
                self.assertRaises(SystemExit) as stopped,
            ):
                main([])

            self.assertEqual(stopped.exception.code, 1)
            rendered = stderr.getvalue()
            self.assertNotIn("alice", rendered)
            self.assertNotIn("proprietary-token", rendered)
            self.assertNotIn("deployment.py", rendered)
            document = json.loads(rendered)
            self.assertEqual(document["error"]["code"], "command_failed")
            self.assertEqual(document["operation"], "runners")

            with (
                patch(
                    "router_dump_analyzer.private_analysis_cli.parse_args",
                    return_value=configuration,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_cli.run",
                    side_effect=KeyboardInterrupt(),
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                main([])

    def test_real_durable_run_is_terminal_and_idempotent_across_cli_replay(
        self,
    ) -> None:
        callback_count = 0

        def count_model_callback_calls(
            frame: Any,
            event: str,
            _argument: Any,
        ) -> None:
            nonlocal callback_count
            if event == "call" and frame.f_code is _durable_cli_model_callback.__code__:
                callback_count += 1

        selection = _selection()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            selection,
            instruction_profile_digest=_PROFILE_DIGEST,
            model_callback=_durable_cli_model_callback,
        )
        policy = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        deployment = PrivateAnalysisDeployment(
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    runner=runner,
                    trusted_inline_tool_service_factory=lambda request: _Harness(
                        request,
                        policy=policy,
                    ).service(),
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            empty_registry = PluginRegistry(require_executable_identity=True)
            initial = ControlPlane(
                state,
                registry=empty_registry,
                private_analysis_runners=deployment.registrations,
            )
            initial.sessions.create_project(
                "tenant-a", "Project A", project_id="project-a"
            )
            initial.sessions.create_workspace(
                "tenant-a",
                "project-a",
                "Workspace A",
                workspace_id="workspace-a",
            )
            initial.sessions.attach_fixture(
                "tenant-a",
                "workspace-a",
                "fixture-a",
                label="Fixture A",
                content_digest=_digest("fixture-a"),
            )
            initial.sessions.publish_revision(
                "tenant-a",
                "workspace-a",
                "fixture-a",
                "revision-a",
                node_id="node-a",
                identity_digest=_digest("revision-a"),
                plugin_ids=("test.private-analysis",),
                execution_plan=_plan("node-a", "a"),
            )
            initial.sessions.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                policy,
                actor_id="admin",
                expected_version=0,
            )
            recovery_scope = EvidenceScope(
                "tenant-a",
                "project-a",
                "workspace-a",
            )
            queued_for_recovery = initial.private_analysis.create(
                PrivateAnalysisRequestSpec(
                    scope=recovery_scope,
                    revision_ids=("revision-a",),
                    runner_id=selection.runner_id,
                    runner_version=selection.runner_version,
                    task_kind=PrivateAnalysisTaskKind.RESOURCE_CORRELATION,
                    query="Recover this interrupted local run.",
                    clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                    selected_time_ns=None,
                    limits=PrivateAnalysisLimits(),
                ),
                actor_id="ci",
                idempotency_key="expired-cli-run",
                run_id="expired-cli-run",
            )
            initial.private_analysis_runs.claim_run(
                recovery_scope,
                queued_for_recovery.run_id,
                expected_version=queued_for_recovery.version,
                actor_id="worker",
                execution_id="interrupted-attempt",
                lease_duration_ns=1,
                now_ns=queued_for_recovery.created_at_ns,
            )
            initial.close()

            request = root / "request.json"
            request.write_text(
                json.dumps(
                    {
                        "revision_ids": ["revision-a"],
                        "runner": {
                            "runner_id": selection.runner_id,
                            "runner_version": selection.runner_version,
                        },
                        "task_kind": "resource_correlation",
                        "query": "Correlate this proprietary transition.",
                        "clock": {"mode": "latest_per_revision"},
                    }
                ),
                encoding="utf-8",
            )
            configuration = self._configuration(
                root,
                PrivateAnalysisCliOperation.RUN,
                request_path=request,
                actor_id="ci",
                idempotency_key="stable-ci-run",
            )

            def real_control_plane_factory(
                selected_root: Path,
                **values: Any,
            ) -> ControlPlane:
                values["registry"] = PluginRegistry(require_executable_identity=True)
                return ControlPlane(selected_root, **values)

            recovery_output = io.StringIO()
            recovery_exit = run(
                self._configuration(
                    root,
                    PrivateAnalysisCliOperation.RECOVER_EXPIRED,
                    actor_id="ci-recovery",
                    limit=10,
                ),
                module_loader=lambda _target: object(),
                deployment_loader=lambda _target, **_values: deployment,
                registry_factory=_Registry,
                control_plane_factory=real_control_plane_factory,
                stdout=recovery_output,
            )
            self.assertEqual(recovery_exit, EXIT_SUCCESS)
            recovery_document = json.loads(recovery_output.getvalue())
            self.assertEqual(len(recovery_document["runs"]), 1)
            self.assertEqual(
                recovery_document["runs"][0]["run_id"],
                "expired-cli-run",
            )
            self.assertEqual(
                recovery_document["runs"][0]["state"],
                "completed",
            )

            documents: list[dict[str, Any]] = []
            previous_profile = sys.getprofile()
            sys.setprofile(count_model_callback_calls)
            try:
                for _attempt in range(2):
                    output = io.StringIO()
                    exit_code = run(
                        configuration,
                        module_loader=lambda _target: object(),
                        deployment_loader=lambda _target, **_values: deployment,
                        registry_factory=_Registry,
                        control_plane_factory=real_control_plane_factory,
                        stdout=output,
                    )
                    self.assertEqual(exit_code, EXIT_SUCCESS)
                    documents.append(json.loads(output.getvalue()))
            finally:
                sys.setprofile(previous_profile)

        self.assertEqual(callback_count, 1)
        self.assertEqual(
            documents[0]["report"]["run"]["run_id"],
            documents[1]["report"]["run"]["run_id"],
        )
        self.assertEqual(
            documents[0]["report"]["run"]["outcome_digest"],
            documents[1]["report"]["run"]["outcome_digest"],
        )
        self.assertEqual(documents[0]["report"]["outcome"]["kind"], "result")


if __name__ == "__main__":
    unittest.main()

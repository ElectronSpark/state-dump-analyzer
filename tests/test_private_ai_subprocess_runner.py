from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import PropertyMock, patch

import router_dump_analyzer.private_analysis_subprocess_runner as subprocess_runner_module
from router_dump_analyzer.canonical import strict_canonical_json
from router_dump_analyzer.private_analysis import (
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisPolicy,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    default_private_analysis_tool_catalog,
    private_analysis_request_dict,
    private_analysis_result_dict,
    private_analysis_tool_call_dict,
    private_analysis_tool_catalog_dict,
    private_analysis_tool_result_dict,
)
from router_dump_analyzer.private_analysis.local_subprocess_protocol import (
    MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES,
    PrivateAnalysisLocalSubprocessMessage,
    PrivateAnalysisLocalSubprocessMessageKind,
    PrivateAnalysisLocalSubprocessRunnerFailureReason,
    encode_private_analysis_local_subprocess_message,
)
from router_dump_analyzer.private_analysis_runner_support import (
    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
    private_analysis_transcript_summary_from_json,
    private_analysis_transcript_summary_json,
)
from router_dump_analyzer.private_analysis_subprocess_runner import (
    ConfiguredPrivateAnalysisSubprocessRunner,
    PrivateAnalysisSubprocessCleanupPending,
    PrivateAnalysisSubprocessExecutionReceipt,
    PrivateAnalysisSubprocessLaunchConfiguration,
    PrivateAnalysisSubprocessTranscript,
    private_analysis_subprocess_run_digest,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolRunLease,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
)

try:
    from tests.test_private_ai_in_process_runner import (
        _INSTRUCTION_PROFILE_DIGEST,
        _Harness,
        _limits,
        _query_call,
        _reference,
        _request,
        _selection,
        _supported_result,
        _unsupported_result,
    )
except ModuleNotFoundError:  # Direct execution from the tests directory.
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _INSTRUCTION_PROFILE_DIGEST,
        _Harness,
        _limits,
        _query_call,
        _reference,
        _request,
        _selection,
        _supported_result,
        _unsupported_result,
    )


_CONTROL_VERSION = "private-analysis-child-peer-control.v1"
_FIXTURE_MAX_FRAME_BYTES = 8 * 1024 * 1024
_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "private_analysis_child_peer.py"
)
_ADAPTER_IDENTITY_DIGEST = "sha256:" + hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()
_OTHER_PROFILE_DIGEST = "sha256:" + "d" * 64
_HOSTILE_STDERR = b"C:\\Users\\alice\\private.txt bearer prod-super-secret"


@dataclass(frozen=True, slots=True)
class _FixtureCase:
    control_path: Path
    launch: PrivateAnalysisSubprocessLaunchConfiguration
    selection: PrivateAnalysisRunnerSelection
    policy: WorkspaceDisclosurePolicy
    request: Any
    runner: ConfiguredPrivateAnalysisSubprocessRunner
    run_digest: str


def _local_policy() -> WorkspaceDisclosurePolicy:
    return WorkspaceDisclosurePolicy(
        mode=PrivateAnalysisDisclosureMode.FULL_FIDELITY,
        transports=(PrivateAnalysisTransport.LOCAL_SUBPROCESS,),
    )


def _build_case(
    directory: Path,
    *,
    environment: tuple[tuple[str, str], ...] = (),
    executable: str | None = None,
    helper_artifact: Path = _FIXTURE,
    instruction_profile_digest: str = _INSTRUCTION_PROFILE_DIGEST,
    limits: PrivateAnalysisLimits | None = None,
    stderr_limit_bytes: int = 256 * 1024,
    terminate_grace_ms: int = 100,
    kill_grace_ms: int = 500,
) -> _FixtureCase:
    control_path = directory / "child-control.json"
    launch = PrivateAnalysisSubprocessLaunchConfiguration(
        argv=(
            executable or str(Path(sys.executable).resolve()),
            "-I",
            "-u",
            str(helper_artifact),
            str(control_path),
        ),
        working_directory=str(directory.resolve()),
        environment=environment,
        adapter_identity_digest=_ADAPTER_IDENTITY_DIGEST,
        helper_artifacts=(str(helper_artifact.resolve()),),
        runtime_data_argument_indices=(4,),
        stderr_limit_bytes=stderr_limit_bytes,
        terminate_grace_ms=terminate_grace_ms,
        kill_grace_ms=kill_grace_ms,
    )
    selection = _selection(
        transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
        configuration_digest=launch.configuration_digest,
    )
    policy = _local_policy()
    request = _request(
        selection=selection,
        policy=policy,
        instruction_profile_digest=instruction_profile_digest,
        limits=limits or _limits(deadline_ms=5_000),
    )
    runner = ConfiguredPrivateAnalysisSubprocessRunner(
        selection,
        instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
        launch_configuration=launch,
    )
    run_digest = private_analysis_subprocess_run_digest(
        request,
        default_private_analysis_tool_catalog(),
        instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
        launch_configuration=launch,
    )
    return _FixtureCase(
        control_path=control_path,
        launch=launch,
        selection=selection,
        policy=policy,
        request=request,
        runner=runner,
        run_digest=run_digest,
    )


def _service(
    case: _FixtureCase,
    harness: _Harness | None = None,
) -> tuple[PrivateAnalysisToolService, _Harness]:
    selected_harness = harness or _Harness(case.request, policy=case.policy)
    return (
        PrivateAnalysisToolService(
            case.request,
            runner_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
            ),
            authorize=selected_harness.authorize,
            resolve_policy=selected_harness.resolve_policy,
            query_references=selected_harness.query_references,
            resolve_reference=selected_harness.resolve_reference,
            validate_reference=selected_harness.validate_reference,
            materialize_payload=selected_harness.materialize_payload,
        ),
        selected_harness,
    )


def _message(
    case: _FixtureCase,
    sequence: int,
    kind: PrivateAnalysisLocalSubprocessMessageKind,
    payload: dict[str, object],
    *,
    run_digest: str | None = None,
) -> PrivateAnalysisLocalSubprocessMessage:
    return PrivateAnalysisLocalSubprocessMessage(
        run_digest=run_digest or case.run_digest,
        sequence=sequence,
        kind=kind,
        payload=payload,
    )


def _read_action(
    expected: PrivateAnalysisLocalSubprocessMessage | None = None,
) -> dict[str, object]:
    action: dict[str, object] = {
        "kind": "read_lf_frame",
        # The fixture bounds each individual action at 8 MiB.  All frames in
        # this suite are far smaller; the production decoder independently
        # enforces its (slightly larger, envelope-inclusive) wire limit.
        "max_bytes": min(
            MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES,
            _FIXTURE_MAX_FRAME_BYTES,
        ),
    }
    if expected is not None:
        action["sha256"] = hashlib.sha256(
            encode_private_analysis_local_subprocess_message(expected)
        ).hexdigest()
    return action


def _raw_stdout_action(
    data: bytes,
    *,
    chunked: bool = False,
) -> dict[str, object]:
    action: dict[str, object] = {
        "kind": "write_stdout",
        "data_b64": base64.b64encode(data).decode("ascii"),
    }
    if chunked:
        if len(data) < 4:
            raise AssertionError("chunked test data must have at least four bytes")
        action["chunk_sizes"] = [1, 2, len(data) - 3]
    return action


def _write_action(
    message: PrivateAnalysisLocalSubprocessMessage,
    *,
    chunked: bool = False,
) -> dict[str, object]:
    return _raw_stdout_action(
        encode_private_analysis_local_subprocess_message(message),
        chunked=chunked,
    )


def _write_control(
    path: Path,
    actions: list[dict[str, object]],
    *,
    sidecar_path: Path | None = None,
) -> None:
    value: dict[str, object] = {
        "version": _CONTROL_VERSION,
        "actions": actions,
    }
    if sidecar_path is not None:
        value["sidecar_path"] = str(sidecar_path)
    path.write_bytes(strict_canonical_json(value).encode("utf-8"))


def _hello(case: _FixtureCase) -> PrivateAnalysisLocalSubprocessMessage:
    return _message(
        case,
        0,
        PrivateAnalysisLocalSubprocessMessageKind.HELLO,
        {},
    )


def _ready(case: _FixtureCase) -> PrivateAnalysisLocalSubprocessMessage:
    return _message(
        case,
        1,
        PrivateAnalysisLocalSubprocessMessageKind.READY,
        {},
    )


def _start(case: _FixtureCase) -> PrivateAnalysisLocalSubprocessMessage:
    return _message(
        case,
        2,
        PrivateAnalysisLocalSubprocessMessageKind.START,
        {
            "request": private_analysis_request_dict(case.request),
            "tool_catalog": private_analysis_tool_catalog_dict(
                default_private_analysis_tool_catalog()
            ),
        },
    )


def _analysis_result(
    case: _FixtureCase,
    result: PrivateAnalysisResult,
    *,
    sequence: int = 3,
) -> PrivateAnalysisLocalSubprocessMessage:
    return _message(
        case,
        sequence,
        PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT,
        {"analysis_result": private_analysis_result_dict(result)},
    )


def _zero_tool_actions(
    case: _FixtureCase,
    result: PrivateAnalysisResult,
    *,
    chunked: bool = False,
) -> list[dict[str, object]]:
    return [
        _read_action(_hello(case)),
        _write_action(_ready(case), chunked=chunked),
        _read_action(_start(case)),
        _write_action(_analysis_result(case, result), chunked=chunked),
    ]


def _assert_error(
    testcase: unittest.TestCase,
    receipt: PrivateAnalysisSubprocessExecutionReceipt,
    code: PrivateAnalysisErrorCode,
    stage: PrivateAnalysisErrorStage | None = None,
) -> None:
    outcome = receipt.outcome
    testcase.assertIs(outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
    testcase.assertIsNone(outcome.result)
    testcase.assertIsNotNone(outcome.error)
    assert outcome.error is not None
    testcase.assertIs(outcome.error.code, code)
    if stage is not None:
        testcase.assertIs(outcome.error.stage, stage)


class PrivateAnalysisSubprocessLaunchTests(unittest.TestCase):
    def test_launch_configuration_rejects_shell_ambiguous_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
            }
            with self.assertRaisesRegex(ValueError, "absolute"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=("python", "child.py"),
                    **base,
                )
            with self.assertRaisesRegex(ValueError, "command-interpreter"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(directory / "child.cmd"),),
                    **base,
                )
            for executable in (directory / ".cmd", directory / ".bat"):
                with (
                    self.subTest(executable=executable),
                    self.assertRaisesRegex(ValueError, "command-interpreter"),
                ):
                    PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(executable),),
                        **base,
                    )
            if os.name == "nt":
                for executable in (directory / "child.cmd.", directory / "child.bat "):
                    with (
                        self.subTest(executable=executable),
                        self.assertRaisesRegex(ValueError, "Win32-normalization"),
                    ):
                        PrivateAnalysisSubprocessLaunchConfiguration(
                            argv=(str(executable),),
                            **base,
                        )
                for executable in (
                    r"\\server.\share\peer.exe",
                    r"\\server\share.\peer.exe",
                    r"\\server\share \peer.exe",
                    r"\\?\UNC\server\share.\peer.exe",
                ):
                    with (
                        self.subTest(executable=executable),
                        self.assertRaisesRegex(ValueError, "Win32-normalization"),
                    ):
                        PrivateAnalysisSubprocessLaunchConfiguration(
                            argv=(executable,),
                            **base,
                        )
                with self.assertRaisesRegex(ValueError, "Win32-normalization"):
                    PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(Path(sys.executable).resolve()),),
                        working_directory=str(directory / "ambiguous. "),
                        environment=(),
                        adapter_identity_digest=_ADAPTER_IDENTITY_DIGEST,
                    )
            with self.assertRaisesRegex(ValueError, "unique"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(Path(sys.executable).resolve()),),
                    environment=(("TOKEN", "one"), ("token", "two")),
                    working_directory=str(directory),
                    adapter_identity_digest=_ADAPTER_IDENTITY_DIGEST,
                )

    def test_launch_requires_complete_argument_artifact_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "runner.py"
            helper.write_text("print('runner')\n", encoding="utf-8")
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
            }
            with self.assertRaisesRegex(ValueError, "attested helper artifact"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(Path(sys.executable).resolve()), str(helper)),
                    **base,
                )
            with self.assertRaisesRegex(ValueError, "argv file"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(
                        str(Path(sys.executable).resolve()),
                        f"--adapter={helper}",
                    ),
                    **base,
                )
            with self.assertRaisesRegex(ValueError, "inline or module"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(Path(sys.executable).resolve()), "-m", "private_runner"),
                    runtime_data_argument_indices=(2,),
                    **base,
                )
            renamed_interpreter = directory / "proprietary-runner-host.exe"
            shutil.copy2(Path(sys.executable).resolve(), renamed_interpreter)
            with self.assertRaisesRegex(ValueError, "inline or module"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(renamed_interpreter), "-c", "run_dynamic_code()"),
                    runtime_data_argument_indices=(2,),
                    **base,
                )
            with self.assertRaisesRegex(ValueError, "unique argv indices"):
                PrivateAnalysisSubprocessLaunchConfiguration(
                    argv=(str(Path(sys.executable).resolve()), "runtime-data"),
                    runtime_data_argument_indices=(1, 1),
                    **base,
                )
            future = directory / "created-after-registration.py"
            future_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(
                    str(Path(sys.executable).resolve()),
                    f"--adapter={future}",
                ),
                **base,
            )
            future.write_text("print('late code')\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "coverage changed"):
                future_launch.revalidate_executable_artifacts()

            data = directory / "runtime-input.json"
            data_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(str(Path(sys.executable).resolve()), f"--input={data}"),
                runtime_data_argument_indices=(1,),
                **base,
            )
            data.write_text("{}", encoding="utf-8")
            data_launch.revalidate_executable_artifacts()

    def test_launch_rejects_attached_and_clustered_execution_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            renamed_interpreter = directory / "proprietary-runner-host.exe"
            shutil.copy2(Path(sys.executable).resolve(), renamed_interpreter)
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
            }
            dynamic_forms = (
                (("-c", "pass"), (2,)),
                (("-cpass",), ()),
                (("-c=pass",), ()),
                (("-m", "private_runner"), (2,)),
                (("-mprivate_runner",), ()),
                (("-Bcpython_payload",), ()),
                (("-Bmprivate_runner",), ()),
            )
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen"
            ) as spawn:
                for arguments, runtime_indices in dynamic_forms:
                    with (
                        self.subTest(arguments=arguments),
                        self.assertRaisesRegex(ValueError, "inline or module"),
                    ):
                        PrivateAnalysisSubprocessLaunchConfiguration(
                            argv=(str(renamed_interpreter), *arguments),
                            runtime_data_argument_indices=runtime_indices,
                            **base,
                        )
            spawn.assert_not_called()

    def test_option_values_cannot_disguise_a_helper_before_dynamic_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "private-analysis-peer.py"
            helper.write_text("print('runner')\n", encoding="utf-8")
            renamed_interpreter = directory / "proprietary-runner-host.exe"
            shutil.copy2(Path(sys.executable).resolve(), renamed_interpreter)
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
                "helper_artifacts": (str(helper),),
            }
            bypass_forms = (
                (("-W", str(helper), "-cpass"), ()),
                (("-W", str(helper), "-mprivate_runner"), ()),
                (("-X", str(helper), "-c", "pass"), (4,)),
                (("-BX", str(helper), "-m", "private_runner"), (4,)),
                (("--check-hash-based-pycs", str(helper), "-cpass"), ()),
                ((f"--adapter={helper}", "-mprivate_runner"), ()),
            )

            for arguments, runtime_indices in bypass_forms:
                with (
                    self.subTest(arguments=arguments),
                    self.assertRaisesRegex(ValueError, "inline or module"),
                ):
                    PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(renamed_interpreter), *arguments),
                        runtime_data_argument_indices=runtime_indices,
                        **base,
                    )

    def test_safe_common_launcher_options_reach_an_exact_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "private-analysis-peer.py"
            helper.write_text("print('runner')\n", encoding="utf-8")
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
                "helper_artifacts": (str(helper),),
            }
            safe_forms = (
                (("-Wmodule", str(helper), "-c", "-mprivate_runner"), ()),
                (("-BWmodule", str(helper)), ()),
                (("-Xdev", str(helper)), ()),
                (("-IBu", str(helper)), ()),
                (("--check-hash-based-pycs=always", str(helper)), ()),
                (("-W", "ignore", str(helper)), (2,)),
                (("-X", "dev", str(helper)), (2,)),
                (
                    ("--check-hash-based-pycs", "always", str(helper)),
                    (2,),
                ),
            )

            for arguments, runtime_indices in safe_forms:
                with self.subTest(arguments=arguments):
                    launch = PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(Path(sys.executable).resolve()), *arguments),
                        runtime_data_argument_indices=runtime_indices,
                        **base,
                    )
                    self.assertEqual(launch.argv[1:], arguments)

    def test_launcher_control_prefix_rejects_ambiguous_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "private-analysis-peer.py"
            helper.write_text("print('runner')\n", encoding="utf-8")
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
                "helper_artifacts": (str(helper),),
            }
            ambiguous_forms = (
                (("-Z", str(helper)), ()),
                (("--unknown", str(helper)), ()),
                (("-",), ()),
                (("-W",), ()),
                (("runtime-data", str(helper)), (1,)),
            )

            for arguments, runtime_indices in ambiguous_forms:
                with (
                    self.subTest(arguments=arguments),
                    self.assertRaisesRegex(ValueError, "launcher-control prefix"),
                ):
                    PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(Path(sys.executable).resolve()), *arguments),
                        runtime_data_argument_indices=runtime_indices,
                        **base,
                    )

    def test_execution_mode_words_are_allowed_after_control_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "private-analysis-peer.py"
            helper.write_text("print('runner')\n", encoding="utf-8")
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
            }

            helper_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(
                    str(Path(sys.executable).resolve()),
                    str(helper),
                    "-c",
                    "-mprivate_runner",
                ),
                helper_artifacts=(str(helper),),
                **base,
            )
            delimiter_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(
                    str(Path(sys.executable).resolve()),
                    "--",
                    "-cpass",
                    "-mprivate_runner",
                ),
                **base,
            )
            option_value_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(
                    str(Path(sys.executable).resolve()),
                    "--command=-cpass",
                    "--module=-mprivate_runner",
                ),
                **base,
            )

            self.assertEqual(helper_launch.argv[2:], ("-c", "-mprivate_runner"))
            self.assertEqual(delimiter_launch.argv[1], "--")
            self.assertEqual(option_value_launch.argv[1], "--command=-cpass")

    def test_runner_revalidation_rejects_attached_execution_before_popen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            object.__setattr__(
                case.runner._launch_configuration,
                "argv",
                (case.launch.argv[0], "-cpass"),
            )
            service, _harness = _service(case)
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen"
            ) as spawn:
                receipt = case.runner.execute(service)
            spawn.assert_not_called()
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_runner_revalidation_rejects_value_option_helper_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bypass_forms = (
                (("-W", str(_FIXTURE.resolve()), "-cpass"), ()),
                (("-W", str(_FIXTURE.resolve()), "-mprivate_runner"), ()),
                (("-X", str(_FIXTURE.resolve()), "-c", "pass"), (4,)),
                (("-BX", str(_FIXTURE.resolve()), "-m", "private_runner"), (4,)),
            )
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen"
            ) as spawn:
                for arguments, runtime_indices in bypass_forms:
                    with self.subTest(arguments=arguments):
                        case = _build_case(directory)
                        object.__setattr__(
                            case.runner._launch_configuration,
                            "argv",
                            (case.launch.argv[0], *arguments),
                        )
                        object.__setattr__(
                            case.runner._launch_configuration,
                            "runtime_data_argument_indices",
                            runtime_indices,
                        )
                        service, _harness = _service(case)
                        receipt = case.runner.execute(service)
                        _assert_error(
                            self,
                            receipt,
                            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                            PrivateAnalysisErrorStage.RUNNER,
                        )
            spawn.assert_not_called()

    def test_helper_identity_binds_ordered_canonical_path_not_only_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            left = directory / "left-runner.py"
            right = directory / "right-runner.py"
            content = b"print('same bytes')\n"
            left.write_bytes(content)
            right.write_bytes(content)
            base = {
                "working_directory": str(directory),
                "environment": (),
                "adapter_identity_digest": _ADAPTER_IDENTITY_DIGEST,
            }
            left_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(str(Path(sys.executable).resolve()), str(left)),
                helper_artifacts=(str(left),),
                **base,
            )
            right_launch = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=(str(Path(sys.executable).resolve()), str(right)),
                helper_artifacts=(str(right),),
                **base,
            )

            self.assertNotEqual(
                left_launch.executable_artifact_digest,
                right_launch.executable_artifact_digest,
            )
            self.assertNotEqual(
                left_launch.configuration_digest,
                right_launch.configuration_digest,
            )
            self.assertNotIn(str(left), repr(left_launch))
            self.assertNotIn(str(right), repr(right_launch))

    def test_constructor_requires_local_selection_bound_to_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            with self.assertRaisesRegex(ValueError, "local_subprocess"):
                ConfiguredPrivateAnalysisSubprocessRunner(
                    _selection(
                        transport=PrivateAnalysisTransport.IN_PROCESS,
                        configuration_digest=case.launch.configuration_digest,
                    ),
                    instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                    launch_configuration=case.launch,
                )
            with self.assertRaisesRegex(ValueError, "bind"):
                ConfiguredPrivateAnalysisSubprocessRunner(
                    _selection(
                        transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                        configuration_digest="sha256:" + "e" * 64,
                    ),
                    instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                    launch_configuration=case.launch,
                )

    def test_runner_revalidates_and_detaches_the_launch_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            tampered = PrivateAnalysisSubprocessLaunchConfiguration(
                argv=case.launch.argv,
                working_directory=case.launch.working_directory,
                environment=case.launch.environment,
                adapter_identity_digest=case.launch.adapter_identity_digest,
                helper_artifacts=case.launch.helper_artifacts,
                runtime_data_argument_indices=(
                    case.launch.runtime_data_argument_indices
                ),
            )
            object.__setattr__(tampered, "argv", ("relative-python",))
            with self.assertRaises(ValueError):
                ConfiguredPrivateAnalysisSubprocessRunner(
                    case.selection,
                    instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                    launch_configuration=tampered,
                )

            _write_control(
                case.control_path,
                _zero_tool_actions(case, _unsupported_result(case.request)),
            )
            object.__setattr__(case.launch, "argv", ("relative-python",))
            service, _harness = _service(case)
            receipt = case.runner.execute(service)
            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)

    def test_runner_refuses_helper_bytes_changed_after_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            helper = directory / "private-analysis-peer.py"
            shutil.copy2(_FIXTURE, helper)
            case = _build_case(directory, helper_artifact=helper)
            helper.write_bytes(
                helper.read_bytes() + b"\n# replaced after registration\n"
            )
            service, _harness = _service(case)
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen"
            ) as spawn:
                receipt = case.runner.execute(service)
            spawn.assert_not_called()
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_runner_refuses_executable_bytes_changed_after_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            executable = directory / Path(sys.executable).name
            shutil.copy2(Path(sys.executable).resolve(), executable)
            case = _build_case(directory, executable=str(executable))
            executable.write_bytes(executable.read_bytes() + b"changed")
            service, _harness = _service(case)
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen"
            ) as spawn:
                receipt = case.runner.execute(service)
            spawn.assert_not_called()
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_auto_seal_sentinels_require_exact_strings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            for invalid in (None, 0, False, b""):
                with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                    PrivateAnalysisSubprocessLaunchConfiguration(
                        argv=(str(Path(sys.executable).resolve()),),
                        working_directory=str(directory),
                        environment=(),
                        adapter_identity_digest=_ADAPTER_IDENTITY_DIGEST,
                        configuration_digest=invalid,  # type: ignore[arg-type]
                    )

    def test_binding_rejections_do_not_spawn_or_claim_the_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            mismatched_selection = _selection(
                runner_id="deployment.other-runner",
                transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                configuration_digest=case.launch.configuration_digest,
            )
            variants = (
                (
                    _request(selection=mismatched_selection, policy=case.policy),
                    PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                    PrivateAnalysisErrorStage.RUNNER,
                ),
                (
                    _request(
                        selection=case.selection,
                        policy=case.policy,
                        instruction_profile_digest=_OTHER_PROFILE_DIGEST,
                    ),
                    PrivateAnalysisErrorCode.INVALID_REQUEST,
                    PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                ),
            )
            for request, code, stage in variants:
                with self.subTest(code=code):
                    variant = _FixtureCase(
                        control_path=case.control_path,
                        launch=case.launch,
                        selection=case.selection,
                        policy=case.policy,
                        request=request,
                        runner=case.runner,
                        run_digest=private_analysis_subprocess_run_digest(
                            request,
                            default_private_analysis_tool_catalog(),
                            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                            launch_configuration=case.launch,
                        ),
                    )
                    service, _harness = _service(variant)
                    with patch(
                        "router_dump_analyzer.private_analysis_subprocess_runner."
                        "subprocess.Popen"
                    ) as spawn:
                        receipt = case.runner.execute(service)
                    _assert_error(self, receipt, code, stage)
                    spawn.assert_not_called()
                    lease = service.acquire_run_lease()
                    lease.close()
                    self.assertEqual(receipt.transcript.message_count, 0)

    def test_used_service_is_rejected_without_spawning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            service.execute(_query_call(case.request))

            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner.subprocess.Popen"
            ) as spawn:
                receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                PrivateAnalysisErrorStage.RUNNER,
            )
            spawn.assert_not_called()
            self.assertEqual(receipt.transcript.message_count, 0)


class PrivateAnalysisSubprocessExecutionTests(unittest.TestCase):
    def test_deadline_precedence_covers_lease_admission_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))

            pristine, _harness = _service(case)
            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    return_value=True,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_spawn_local_child",
                ) as spawn,
            ):
                pre_expired = case.runner.execute(pristine)
            _assert_error(
                self,
                pre_expired,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )
            spawn.assert_not_called()
            lease = pristine.acquire_run_lease()
            lease.close()

            mismatched_selection = _selection(
                runner_id="deployment.other-runner",
                transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                configuration_digest=case.launch.configuration_digest,
            )
            mismatched_request = _request(
                selection=mismatched_selection,
                policy=case.policy,
            )
            mismatched_case = _FixtureCase(
                control_path=case.control_path,
                launch=case.launch,
                selection=case.selection,
                policy=case.policy,
                request=mismatched_request,
                runner=case.runner,
                run_digest=private_analysis_subprocess_run_digest(
                    mismatched_request,
                    default_private_analysis_tool_catalog(),
                    instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                    launch_configuration=case.launch,
                ),
            )
            mismatched_service, _harness = _service(mismatched_case)
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "private_analysis_deadline_expired",
                return_value=True,
            ):
                mismatched_receipt = case.runner.execute(mismatched_service)
            _assert_error(
                self,
                mismatched_receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )

            used, _harness = _service(case)
            used.execute(_query_call(case.request))
            deadline_checks = iter((False, True))
            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    side_effect=lambda _deadline: next(deadline_checks),
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_spawn_local_child",
                ) as spawn,
            ):
                post_expired = case.runner.execute(used)
            _assert_error(
                self,
                post_expired,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )
            spawn.assert_not_called()

    def test_post_acquire_process_control_closes_the_run_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            close_calls: list[PrivateAnalysisToolRunLease] = []
            real_close = PrivateAnalysisToolRunLease.close

            def tracked_close(lease: PrivateAnalysisToolRunLease) -> None:
                close_calls.append(lease)
                real_close(lease)

            with (
                patch.object(
                    PrivateAnalysisToolRunLease,
                    "budget_state",
                    new_callable=PropertyMock,
                    side_effect=KeyboardInterrupt,
                ),
                patch.object(
                    PrivateAnalysisToolRunLease,
                    "close",
                    new=tracked_close,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                case.runner.execute(service)
            self.assertEqual(len(close_calls), 1)

    def test_finalizer_failures_are_contained_without_masking_process_control(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            real_cleanup = subprocess_runner_module._LocalChildSession.cleanup

            def cleanup_then_fail(session: Any) -> bool:
                real_cleanup(session)
                raise RuntimeError("synthetic cleanup failure")

            with (
                patch.object(
                    ConfiguredPrivateAnalysisSubprocessRunner,
                    "_drive_protocol",
                    side_effect=KeyboardInterrupt,
                ),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    new=cleanup_then_fail,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                case.runner.execute(service)

        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            _write_control(
                case.control_path,
                _zero_tool_actions(case, _unsupported_result(case.request)),
            )
            service, _harness = _service(case)
            real_cleanup = subprocess_runner_module._LocalChildSession.cleanup

            def cleanup_then_fail(session: Any) -> bool:
                real_cleanup(session)
                raise RuntimeError("synthetic cleanup failure")

            with patch.object(
                subprocess_runner_module._LocalChildSession,
                "cleanup",
                new=cleanup_then_fail,
            ):
                receipt = case.runner.execute(service)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_live_child_cleanup_failure_withholds_receipt_until_bounded_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[subprocess.Popen[bytes]] = []
            real_popen = subprocess.Popen

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            runner_failure = subprocess_runner_module._static_runner_error(
                case.request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(
                    ConfiguredPrivateAnalysisSubprocessRunner,
                    "_drive_protocol",
                    return_value=(runner_failure, None),
                ),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    return_value=False,
                ),
                self.assertRaises(PrivateAnalysisSubprocessCleanupPending),
            ):
                case.runner.execute(service)

            self.assertEqual(len(processes), 1)
            self.assertIsNone(processes[0].poll())
            self.assertTrue(case.runner.cleanup_pending)

            detached = case.runner.detached()
            self.assertTrue(detached.cleanup_pending)
            cleaned, receipt = detached.retry_pending_cleanup()
            self.assertTrue(cleaned)
            self.assertTrue(case.runner.cleanup_pending)
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertTrue(receipt.cancellation_attested)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertIsNotNone(processes[0].poll())
            detached.acknowledge_pending_cleanup()
            self.assertFalse(case.runner.cleanup_pending)

    def test_partial_helper_start_failure_reaps_child_without_thread_leak(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[Any] = []
            real_popen = subprocess.Popen
            real_start = threading.Thread.start

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            def fail_stderr_start(thread: threading.Thread) -> None:
                if thread.name == "private-analysis-stderr-drain":
                    raise RuntimeError("synthetic second helper start failure")
                real_start(thread)

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(threading.Thread, "start", new=fail_stderr_start),
            ):
                receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll())
            leaked = [
                thread.name
                for thread in threading.enumerate()
                if thread.name.startswith("private-analysis-")
            ]
            self.assertEqual(leaked, [])

    def test_partial_helper_start_retains_session_until_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[subprocess.Popen[bytes]] = []
            real_popen = subprocess.Popen
            real_start = threading.Thread.start
            real_cleanup = subprocess_runner_module._LocalChildSession.cleanup
            cleanup_calls = 0

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            def fail_stderr_start(thread: threading.Thread) -> None:
                if thread.name == "private-analysis-stderr-drain":
                    raise RuntimeError("synthetic second helper start failure")
                real_start(thread)

            def defer_first_cleanup(session: Any) -> bool:
                nonlocal cleanup_calls
                cleanup_calls += 1
                if cleanup_calls == 1:
                    return False
                return real_cleanup(session)

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(threading.Thread, "start", new=fail_stderr_start),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    new=defer_first_cleanup,
                ),
                self.assertRaises(PrivateAnalysisSubprocessCleanupPending),
            ):
                case.runner.execute(service)

            self.assertTrue(case.runner.cleanup_pending)
            self.assertEqual(len(processes), 1)
            cleaned, receipt = case.runner.retry_pending_cleanup()
            self.assertTrue(cleaned)
            self.assertIsNotNone(receipt)
            self.assertTrue(case.runner.cleanup_pending)
            self.assertIsNotNone(processes[0].poll())
            case.runner.acknowledge_pending_cleanup()
            self.assertFalse(case.runner.cleanup_pending)

    def test_receipt_sealing_control_retains_protocol_transcript_for_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            _write_control(
                case.control_path,
                _zero_tool_actions(case, _unsupported_result(case.request)),
            )
            service, _harness = _service(case)
            real_receipt = subprocess_runner_module._deadline_checked_execution_receipt
            receipt_calls = 0

            def interrupt_first_receipt(*args: Any, **kwargs: Any) -> Any:
                nonlocal receipt_calls
                receipt_calls += 1
                if receipt_calls == 1:
                    raise KeyboardInterrupt("synthetic receipt sealing control")
                return real_receipt(*args, **kwargs)

            with (
                patch.object(
                    subprocess_runner_module,
                    "_deadline_checked_execution_receipt",
                    new=interrupt_first_receipt,
                ),
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "synthetic receipt sealing control",
                ),
            ):
                case.runner.execute(service)

            self.assertTrue(case.runner.cleanup_pending)
            cleaned, receipt = case.runner.retry_pending_cleanup()
            self.assertTrue(cleaned)
            self.assertIsNotNone(receipt)
            assert receipt is not None
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertGreater(receipt.transcript.message_count, 0)
            self.assertTrue(receipt.cancellation_attested)
            case.runner.acknowledge_pending_cleanup()
            self.assertFalse(case.runner.cleanup_pending)

    def test_cleanup_process_control_retains_exact_session_until_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[subprocess.Popen[bytes]] = []
            real_popen = subprocess.Popen

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    side_effect=KeyboardInterrupt("synthetic cleanup control"),
                ),
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "synthetic cleanup control",
                ),
            ):
                case.runner.execute(service)

            self.assertTrue(case.runner.cleanup_pending)
            self.assertEqual(len(processes), 1)
            cleaned, receipt = case.runner.retry_pending_cleanup()
            self.assertTrue(cleaned)
            self.assertIsNotNone(receipt)
            assert receipt is not None
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertTrue(case.runner.cleanup_pending)
            self.assertIsNotNone(processes[0].poll())
            case.runner.acknowledge_pending_cleanup()
            self.assertFalse(case.runner.cleanup_pending)

    def test_cleanup_success_cannot_release_live_session_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[subprocess.Popen[bytes]] = []
            real_popen = subprocess.Popen

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            runner_failure = subprocess_runner_module._static_runner_error(
                case.request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(
                    ConfiguredPrivateAnalysisSubprocessRunner,
                    "_drive_protocol",
                    return_value=(runner_failure, None),
                ),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    return_value=True,
                ),
                self.assertRaises(PrivateAnalysisSubprocessCleanupPending),
            ):
                case.runner.execute(service)

            self.assertTrue(case.runner.cleanup_pending)
            with patch.object(
                subprocess_runner_module._LocalChildSession,
                "cleanup",
                return_value=True,
            ):
                cleaned, receipt = case.runner.retry_pending_cleanup()
            self.assertFalse(cleaned)
            self.assertIsNone(receipt)
            self.assertTrue(case.runner.cleanup_pending)
            cleaned, receipt = case.runner.retry_pending_cleanup()
            self.assertTrue(cleaned)
            self.assertIsNotNone(receipt)
            self.assertTrue(case.runner.cleanup_pending)
            self.assertIsNotNone(processes[0].poll())
            case.runner.acknowledge_pending_cleanup()
            self.assertFalse(case.runner.cleanup_pending)

    def test_partial_start_cleanup_failure_preserves_process_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            processes: list[Any] = []
            real_popen = subprocess.Popen
            real_start = threading.Thread.start
            real_cleanup = subprocess_runner_module._LocalChildSession.cleanup

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            def interrupt_stderr_start(thread: threading.Thread) -> None:
                if thread.name == "private-analysis-stderr-drain":
                    raise KeyboardInterrupt
                real_start(thread)

            def cleanup_then_report_failure(session: Any) -> bool:
                real_cleanup(session)
                return False

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch.object(threading.Thread, "start", new=interrupt_stderr_start),
                patch.object(
                    subprocess_runner_module._LocalChildSession,
                    "cleanup",
                    new=cleanup_then_report_failure,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                case.runner.execute(service)

            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll())
            leaked = [
                thread.name
                for thread in threading.enumerate()
                if thread.name.startswith("private-analysis-")
            ]
            self.assertEqual(leaked, [])

    def test_failed_unmanaged_reap_still_closes_every_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))

            class NeverReaped:
                def __init__(self) -> None:
                    self.stdin = io.BytesIO()
                    self.stdout = io.BytesIO()
                    self.stderr = io.BytesIO()
                    self.terminated = False
                    self.killed = False

                def poll(self) -> None:
                    return None

                def terminate(self) -> None:
                    self.terminated = True

                def kill(self) -> None:
                    self.killed = True

                def wait(self, timeout: float) -> None:
                    raise subprocess.TimeoutExpired("synthetic", timeout)

            process = NeverReaped()
            reaped = subprocess_runner_module._reap_unmanaged_child(
                process,  # type: ignore[arg-type]
                case.launch,
            )
            self.assertFalse(reaped)
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertTrue(process.stdin.closed)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)

    def test_cleanup_wait_oserror_still_closes_pipes_and_stops_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))

            class WaitFailure:
                def __init__(self) -> None:
                    self.stdin = io.BytesIO()
                    self.stdout = io.BytesIO()
                    self.stderr = io.BytesIO()

                def poll(self) -> None:
                    return None

                def terminate(self) -> None:
                    return None

                def kill(self) -> None:
                    return None

                def wait(self, timeout: float) -> None:
                    del timeout
                    raise OSError("synthetic wait failure")

            unmanaged = WaitFailure()
            self.assertFalse(
                subprocess_runner_module._reap_unmanaged_child(
                    unmanaged,  # type: ignore[arg-type]
                    case.launch,
                )
            )
            self.assertTrue(unmanaged.stdin.closed)
            self.assertTrue(unmanaged.stdout.closed)
            self.assertTrue(unmanaged.stderr.closed)

            managed_process = WaitFailure()

            class JoinedThread:
                def __init__(self) -> None:
                    self.join_calls = 0

                def join(self, timeout: float) -> None:
                    del timeout
                    self.join_calls += 1

                def is_alive(self) -> bool:
                    return False

            pump = JoinedThread()
            stderr_thread = JoinedThread()
            session = object.__new__(subprocess_runner_module._LocalChildSession)
            object.__setattr__(session, "_process", managed_process)
            object.__setattr__(session, "_configuration", case.launch)
            object.__setattr__(session, "_commands", queue.Queue(maxsize=1))
            object.__setattr__(session, "_stop", threading.Event())
            object.__setattr__(session, "_pump", pump)
            object.__setattr__(session, "_stderr", stderr_thread)
            object.__setattr__(session, "_pump_started", True)
            object.__setattr__(session, "_stderr_started", True)
            self.assertFalse(session.cleanup())
            self.assertTrue(managed_process.stdin.closed)
            self.assertTrue(managed_process.stdout.closed)
            self.assertTrue(managed_process.stderr.closed)
            self.assertEqual(pump.join_calls, 1)
            self.assertEqual(stderr_thread.join_calls, 1)

    def test_exact_shell_free_launch_and_explicit_environment_isolation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private runner argv ") as temporary:
            directory = Path(temporary).resolve()
            case = _build_case(
                directory,
                environment=(("RDA_CHILD_VISIBLE", "exact child value"),),
            )
            sidecar = directory / "child-facts.json"
            actions = [
                {
                    "kind": "record_facts",
                    "facts": ["argv", "env", "cwd", "stdin", "stdout", "stderr"],
                    "env_keys": ["RDA_CHILD_VISIBLE", "RDA_PARENT_SECRET"],
                },
                *_zero_tool_actions(case, _unsupported_result(case.request)),
            ]
            _write_control(case.control_path, actions, sidecar_path=sidecar)
            service, _harness = _service(case)
            observed: list[tuple[tuple[object, ...], dict[str, object], Any]] = []
            real_popen = subprocess.Popen

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                observed.append((args, kwargs, process))
                return process

            with (
                patch.dict(
                    os.environ,
                    {"RDA_PARENT_SECRET": "must-not-cross-boundary"},
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
            ):
                receipt = case.runner.execute(service)

            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
            self.assertEqual(len(observed), 1)
            positional, keyword, process = observed[0]
            self.assertEqual(positional, (list(case.launch.argv),))
            self.assertEqual(keyword["executable"], case.launch.argv[0])
            self.assertIs(keyword["shell"], False)
            self.assertIs(keyword["stdin"], subprocess.PIPE)
            self.assertIs(keyword["stdout"], subprocess.PIPE)
            self.assertIs(keyword["stderr"], subprocess.PIPE)
            self.assertIs(keyword["text"], False)
            self.assertEqual(keyword["bufsize"], 0)
            self.assertEqual(keyword["cwd"], case.launch.working_directory)
            self.assertEqual(
                keyword["env"],
                {"RDA_CHILD_VISIBLE": "exact child value"},
            )
            self.assertIs(keyword["close_fds"], True)
            self.assertIs(keyword["start_new_session"], False)
            self.assertIsNotNone(process.poll(), "direct child was not reaped")

            facts = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(
                facts["argv"],
                [str(_FIXTURE), str(case.control_path)],
            )
            self.assertEqual(facts["cwd"], case.launch.working_directory)
            self.assertEqual(facts["env"]["RDA_CHILD_VISIBLE"], "exact child value")
            self.assertIsNone(facts["env"]["RDA_PARENT_SECRET"])
            for name, descriptor in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
                self.assertEqual(facts[name]["fileno"], descriptor)
                self.assertIs(facts[name]["isatty"], False)

    def test_zero_tool_success_is_bound_and_chunking_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                limits=_limits(max_tool_calls=0, deadline_ms=5_000),
            )
            result = _unsupported_result(case.request)
            receipts: list[PrivateAnalysisSubprocessExecutionReceipt] = []
            harnesses: list[_Harness] = []
            for chunked in (False, True):
                _write_control(
                    case.control_path,
                    _zero_tool_actions(case, result, chunked=chunked),
                )
                service, harness = _service(case)
                receipts.append(case.runner.execute(service))
                harnesses.append(harness)

            for receipt, harness in zip(receipts, harnesses, strict=True):
                self.assertIs(
                    type(receipt),
                    PrivateAnalysisSubprocessExecutionReceipt,
                )
                self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
                self.assertEqual(receipt.outcome.result, result)
                self.assertEqual(receipt.disclosed_references, ())
                self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
                self.assertEqual(receipt.transcript.message_count, 4)
                self.assertEqual(receipt.transcript.tool_call_count, 0)
                self.assertEqual(receipt.transcript.stderr_bytes, 0)
                self.assertEqual(
                    receipt.transcript.request_digest,
                    case.request.request_digest,
                )
                self.assertEqual(
                    receipt.transcript.catalog_digest,
                    case.request.tool_catalog_digest,
                )
                self.assertEqual(
                    receipt.transcript.instruction_profile_digest,
                    _INSTRUCTION_PROFILE_DIGEST,
                )
                self.assertEqual(
                    receipt.transcript.runner_configuration_digest,
                    case.selection.configuration_digest,
                )
                self.assertEqual(
                    receipt.transcript.launch_configuration_digest,
                    case.launch.configuration_digest,
                )
                self.assertEqual(receipt.transcript.run_digest, case.run_digest)
                self.assertEqual(
                    receipt.transcript.outcome_digest,
                    receipt.outcome.outcome_digest,
                )
                self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)
                self.assertGreater(receipt.transcript.message_metadata_bytes, 0)
                summary = receipt.transcript_summary
                self.assertIs(
                    summary.transport,
                    PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                )
                self.assertEqual(
                    summary.request_digest,
                    receipt.transcript.request_digest,
                )
                self.assertEqual(
                    summary.outcome_digest,
                    receipt.outcome.outcome_digest,
                )
                self.assertEqual(summary.budget_state, receipt.budget_state)
                self.assertIs(
                    type(summary.metadata),
                    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
                )
                assert isinstance(
                    summary.metadata,
                    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
                )
                self.assertEqual(
                    summary.metadata.transcript_digest,
                    receipt.transcript.transcript_digest,
                )
                self.assertEqual(
                    private_analysis_transcript_summary_from_json(
                        private_analysis_transcript_summary_json(summary)
                    ),
                    summary,
                )
                self.assertEqual(harness.authorization_calls, 3)
                self.assertEqual(harness.policy_calls, 3)
            self.assertEqual(receipts[0].transcript, receipts[1].transcript)
            detached_summary = receipts[0].transcript_summary
            assert isinstance(
                detached_summary.metadata,
                PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
            )
            object.__setattr__(detached_summary.metadata, "message_count", 999)
            self.assertEqual(
                receipts[0].transcript_summary.metadata.message_count,
                4,
            )

            source = receipts[0].transcript
            transcript_fields = {
                "request_digest": source.request_digest,
                "catalog_digest": source.catalog_digest,
                "instruction_profile_digest": source.instruction_profile_digest,
                "runner_configuration_digest": source.runner_configuration_digest,
                "launch_configuration_digest": source.launch_configuration_digest,
                "run_digest": source.run_digest,
                "message_count": source.message_count,
                "tool_call_count": source.tool_call_count,
                "message_metadata_bytes": source.message_metadata_bytes,
                "message_chain_digest": source.message_chain_digest,
                "stderr_bytes": source.stderr_bytes,
                "evidence_ledger_digest": source.evidence_ledger_digest,
                "budget_state": source.budget_state,
                "outcome_digest": source.outcome_digest,
            }
            for invalid in (None, 0, False, b""):
                with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                    PrivateAnalysisSubprocessTranscript(
                        **transcript_fields,
                        transcript_digest=invalid,  # type: ignore[arg-type]
                    )

    def test_tool_flow_checks_parent_frames_and_returns_detached_accounting(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            expected_harness = _Harness(case.request, (reference,), policy=case.policy)
            expected_service, _ = _service(case, expected_harness)
            expected_response = expected_service.execute(call)
            expected_tool_result = _message(
                case,
                4,
                PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                {"tool_result": private_analysis_tool_result_dict(expected_response)},
            )
            result = _supported_result(case.request, reference)
            actions = [
                _read_action(_hello(case)),
                _write_action(_ready(case), chunked=True),
                _read_action(_start(case)),
                _write_action(
                    _message(
                        case,
                        3,
                        PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                        {"tool_call": private_analysis_tool_call_dict(call)},
                    ),
                    chunked=True,
                ),
                _read_action(expected_tool_result),
                _write_action(_analysis_result(case, result, sequence=5), chunked=True),
            ]
            _write_control(case.control_path, actions)
            harness = _Harness(case.request, (reference,), policy=case.policy)
            service, _ = _service(case, harness)

            receipt = case.runner.execute(service)

            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
            self.assertEqual(receipt.outcome.result, result)
            self.assertEqual(receipt.disclosed_references, (reference,))
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
            self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
            self.assertEqual(receipt.transcript.message_count, 6)
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)
            self.assertEqual(harness.query_calls, 1)
            self.assertGreaterEqual(harness.authorization_calls, 4)
            self.assertGreaterEqual(harness.policy_calls, 4)
            with self.assertRaises(PrivateAnalysisToolServiceError):
                service.execute(_query_call(case.request, call_id="after-run"))

            constructor_transcript = receipt.transcript
            reconstructed_receipt = PrivateAnalysisSubprocessExecutionReceipt(
                outcome=receipt.outcome,
                transcript=constructor_transcript,
                disclosed_references=receipt.disclosed_references,
                budget_state=receipt.budget_state,
            )
            expected_outcome_digest = reconstructed_receipt.outcome.outcome_digest
            object.__setattr__(
                constructor_transcript,
                "outcome_digest",
                "sha256:" + "e" * 64,
            )
            object.__setattr__(constructor_transcript, "transcript_digest", "")
            self.assertEqual(
                reconstructed_receipt.transcript.outcome_digest,
                expected_outcome_digest,
            )
            self.assertEqual(
                reconstructed_receipt.transcript.outcome_digest,
                reconstructed_receipt.outcome.outcome_digest,
            )

            references = receipt.disclosed_references
            object.__setattr__(references[0], "subject_kind", "mutated reference")
            self.assertEqual(
                receipt.disclosed_references[0].subject_kind,
                "route_event",
            )
            outcome = receipt.outcome
            assert outcome.result is not None
            object.__setattr__(outcome.result.summary, "text", "mutated outcome")
            assert receipt.outcome.result is not None
            self.assertNotEqual(receipt.outcome.result.summary.text, "mutated outcome")
            transcript = receipt.transcript
            object.__setattr__(transcript, "message_count", 999)
            self.assertEqual(receipt.transcript.message_count, 6)
            budget = receipt.budget_state
            object.__setattr__(budget, "tool_calls_consumed", 999)
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)

    def test_accounting_observer_is_write_ahead_and_fails_closed(self) -> None:
        real_exchange = subprocess_runner_module._exchange_message

        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            expected_harness = _Harness(case.request, (reference,), policy=case.policy)
            expected_service, _ = _service(case, expected_harness)
            expected_response = expected_service.execute(call)
            expected_tool_result = _message(
                case,
                4,
                PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                {"tool_result": private_analysis_tool_result_dict(expected_response)},
            )
            result = _supported_result(case.request, reference)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    _read_action(expected_tool_result),
                    _write_action(_analysis_result(case, result, sequence=5)),
                ],
            )
            committed: list[tuple[tuple[Any, ...], Any]] = []
            tool_result_saw_complete_accounting = False

            def observer(references: tuple[Any, ...], budget_state: Any) -> None:
                committed.append((references, budget_state))

            def exchange_after_observer(
                session: Any,
                outbound: PrivateAnalysisLocalSubprocessMessage,
                previous: PrivateAnalysisLocalSubprocessMessage | None,
                transcript: Any,
                deadline_ns: int,
            ) -> Any:
                nonlocal tool_result_saw_complete_accounting
                if outbound.kind is (
                    PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT
                ):
                    observed_references, observed_budget = committed[-1]
                    self.assertEqual(observed_references, (reference,))
                    self.assertEqual(observed_budget.tool_calls_consumed, 1)
                    self.assertEqual(observed_budget.evidence_items_disclosed, 1)
                    self.assertGreater(observed_budget.evidence_bytes_disclosed, 0)
                    tool_result_saw_complete_accounting = True
                return real_exchange(
                    session,
                    outbound,
                    previous,
                    transcript,
                    deadline_ns,
                )

            service, _ = _service(
                case,
                _Harness(case.request, (reference,), policy=case.policy),
            )
            with patch.object(
                subprocess_runner_module,
                "_exchange_message",
                new=exchange_after_observer,
            ):
                receipt = case.runner.execute(
                    service,
                    accounting_observer=observer,
                )

            self.assertTrue(tool_result_saw_complete_accounting)
            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
            self.assertEqual(receipt.outcome.result, result)
            self.assertEqual(
                committed[-1],
                (receipt.disclosed_references, receipt.budget_state),
            )

        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    _read_action(),
                ],
            )
            failed_commits: list[tuple[tuple[Any, ...], Any]] = []
            failed_attempts: list[tuple[tuple[Any, ...], Any]] = []
            published_tool_responses: list[
                PrivateAnalysisLocalSubprocessMessageKind
            ] = []

            def failing_observer(
                references: tuple[Any, ...],
                budget_state: Any,
            ) -> None:
                failed_attempts.append((references, budget_state))
                if budget_state.tool_calls_consumed:
                    raise RuntimeError("durable accounting unavailable")
                failed_commits.append((references, budget_state))

            def capture_tool_response(
                session: Any,
                outbound: PrivateAnalysisLocalSubprocessMessage,
                previous: PrivateAnalysisLocalSubprocessMessage | None,
                transcript: Any,
                deadline_ns: int,
            ) -> Any:
                if outbound.kind in {
                    PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                    PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR,
                }:
                    published_tool_responses.append(outbound.kind)
                return real_exchange(
                    session,
                    outbound,
                    previous,
                    transcript,
                    deadline_ns,
                )

            failed_harness = _Harness(
                case.request,
                (reference,),
                policy=case.policy,
            )
            failed_service, _ = _service(case, failed_harness)
            with patch.object(
                subprocess_runner_module,
                "_exchange_message",
                new=capture_tool_response,
            ):
                failed = case.runner.execute(
                    failed_service,
                    accounting_observer=failing_observer,
                )

            self.assertEqual(published_tool_responses, [])
            self.assertTrue(
                any(
                    references == (reference,)
                    and budget.tool_calls_consumed == 1
                    and budget.evidence_items_disclosed == 1
                    for references, budget in failed_attempts
                )
            )
            self.assertEqual(len(failed_commits), 1)
            self.assertEqual(failed_commits[0][0], ())
            self.assertEqual(failed_commits[0][1].tool_calls_consumed, 0)
            _assert_error(
                self,
                failed,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(failed_harness.query_calls, 1)
            self.assertEqual(failed.disclosed_references, ())
            self.assertEqual(failed.budget_state, failed_commits[0][1])
            self.assertEqual(failed.transcript.message_count, 4)
            self.assertEqual(failed.transcript.tool_call_count, 1)

    def test_attestation_fallback_preserves_real_disclosure_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            expected_harness = _Harness(case.request, (reference,), policy=case.policy)
            expected_service, _ = _service(case, expected_harness)
            expected_response = expected_service.execute(call)
            result = _supported_result(case.request, reference)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    _read_action(
                        _message(
                            case,
                            4,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                            {
                                "tool_result": private_analysis_tool_result_dict(
                                    expected_response
                                )
                            },
                        )
                    ),
                    _write_action(_analysis_result(case, result, sequence=5)),
                ],
            )
            harness = _Harness(case.request, (reference,), policy=case.policy)
            service, _ = _service(case, harness)
            seal_attempts = 0
            real_seal = subprocess_runner_module._sealed_subprocess_transcript

            def fail_first_seal(*args: Any, **kwargs: Any) -> Any:
                nonlocal seal_attempts
                seal_attempts += 1
                if seal_attempts == 1:
                    raise RuntimeError("synthetic final attestation failure")
                return real_seal(*args, **kwargs)

            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "_sealed_subprocess_transcript",
                new=fail_first_seal,
            ):
                receipt = case.runner.execute(service)

            self.assertEqual(seal_attempts, 2)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(harness.query_calls, 1)
            self.assertEqual(receipt.disclosed_references, (reference,))
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
            self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
            self.assertEqual(receipt.transcript.message_count, 6)
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)
            self.assertEqual(
                receipt.transcript.evidence_ledger_digest,
                subprocess_runner_module.evidence_snapshot_digest((reference,)),
            )

    def test_final_snapshot_failure_retains_last_complete_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            expected_harness = _Harness(case.request, (reference,), policy=case.policy)
            expected_service, _ = _service(case, expected_harness)
            expected_response = expected_service.execute(call)
            result = _supported_result(case.request, reference)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    _read_action(
                        _message(
                            case,
                            4,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                            {
                                "tool_result": private_analysis_tool_result_dict(
                                    expected_response
                                )
                            },
                        )
                    ),
                    _write_action(_analysis_result(case, result, sequence=5)),
                ],
            )
            harness = _Harness(case.request, (reference,), policy=case.policy)
            service, _ = _service(case, harness)
            disclosed_reads = 0
            disclosed_property = PrivateAnalysisToolRunLease.disclosed_references
            assert disclosed_property.fget is not None

            def fail_final_disclosed_read(
                lease: PrivateAnalysisToolRunLease,
            ) -> Any:
                nonlocal disclosed_reads
                disclosed_reads += 1
                if disclosed_reads == 3:
                    raise RuntimeError("synthetic final accounting failure")
                return disclosed_property.fget(lease)

            with patch.object(
                PrivateAnalysisToolRunLease,
                "disclosed_references",
                new=property(fail_final_disclosed_read),
            ):
                receipt = case.runner.execute(service)

            self.assertEqual(disclosed_reads, 3)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(harness.query_calls, 1)
            self.assertEqual(receipt.disclosed_references, (reference,))
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
            self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
            self.assertEqual(receipt.transcript.tool_call_count, 1)

    def test_deadline_after_tool_parse_prevents_provider_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            call = _query_call(case.request)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    {"kind": "block"},
                ],
            )
            service, harness = _service(case)
            parse_completed = False
            real_parse = subprocess_runner_module.private_analysis_tool_call_from_dict

            def parse_then_expire(value: object) -> Any:
                nonlocal parse_completed
                parsed = real_parse(value)
                parse_completed = True
                return parsed

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_tool_call_from_dict",
                    new=parse_then_expire,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    side_effect=lambda _deadline: parse_completed,
                ),
            ):
                receipt = case.runner.execute(service)

            self.assertTrue(parse_completed)
            self.assertEqual(harness.query_calls, 0)
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_malformed_framing_state_and_sequence_fail_closed(self) -> None:
        scenarios = (
            "invalid-json",
            "missing-lf",
            "noncanonical-json",
            "foreign-run",
            "unexpected-ready-state",
            "skipped-sequence",
            "trailing-frame",
        )
        for scenario in scenarios:
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as temporary,
            ):
                case = _build_case(Path(temporary))
                result = _unsupported_result(case.request)
                if scenario == "invalid-json":
                    actions = [
                        _read_action(_hello(case)),
                        _raw_stdout_action(b"not-json\n"),
                    ]
                elif scenario == "missing-lf":
                    actions = [
                        _read_action(_hello(case)),
                        _raw_stdout_action(
                            encode_private_analysis_local_subprocess_message(
                                _ready(case)
                            )[:-1]
                        ),
                    ]
                elif scenario == "noncanonical-json":
                    frame = encode_private_analysis_local_subprocess_message(
                        _ready(case)
                    )
                    actions = [
                        _read_action(_hello(case)),
                        _raw_stdout_action(b"{ " + frame[1:]),
                    ]
                elif scenario == "foreign-run":
                    actions = [
                        _read_action(_hello(case)),
                        _write_action(
                            _message(
                                case,
                                1,
                                PrivateAnalysisLocalSubprocessMessageKind.READY,
                                {},
                                run_digest="sha256:" + "f" * 64,
                            )
                        ),
                    ]
                elif scenario == "unexpected-ready-state":
                    envelope = {
                        "contract_version": (_ready(case).contract_version),
                        "run_digest": case.run_digest,
                        "sequence": 1,
                        "kind": (
                            PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT.value
                        ),
                        "payload": {
                            "analysis_result": private_analysis_result_dict(result)
                        },
                    }
                    envelope["message_digest"] = (
                        "sha256:"
                        + hashlib.sha256(
                            strict_canonical_json(envelope).encode("utf-8")
                        ).hexdigest()
                    )
                    actions = [
                        _read_action(_hello(case)),
                        _raw_stdout_action(
                            strict_canonical_json(envelope).encode("utf-8") + b"\n"
                        ),
                    ]
                elif scenario == "skipped-sequence":
                    actions = [
                        _read_action(_hello(case)),
                        _write_action(_ready(case)),
                        _read_action(_start(case)),
                        _write_action(
                            _message(
                                case,
                                5,
                                PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT,
                                {
                                    "analysis_result": private_analysis_result_dict(
                                        result
                                    )
                                },
                            )
                        ),
                    ]
                else:
                    terminal = encode_private_analysis_local_subprocess_message(
                        _analysis_result(case, result)
                    )
                    trailing = encode_private_analysis_local_subprocess_message(
                        _analysis_result(case, result, sequence=4)
                    )
                    actions = [
                        _read_action(_hello(case)),
                        _write_action(_ready(case)),
                        _read_action(_start(case)),
                        _raw_stdout_action(terminal + trailing),
                    ]
                _write_control(case.control_path, actions)
                service, _harness = _service(case)

                receipt = case.runner.execute(service)

                _assert_error(
                    self,
                    receipt,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    PrivateAnalysisErrorStage.RUNNER,
                )
                self.assertEqual(receipt.disclosed_references, ())
                self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)

    def test_malformed_nested_tool_call_is_protocol_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            actions = [
                _read_action(_hello(case)),
                _write_action(_ready(case)),
                _read_action(_start(case)),
                _write_action(
                    _message(
                        case,
                        3,
                        PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                        {"tool_call": {}},
                    )
                ),
            ]
            _write_control(case.control_path, actions)
            service, _harness = _service(case)

            receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)

    def test_child_reported_failure_exit_failure_and_spawn_unavailable(self) -> None:
        for reason, expected in (
            (
                PrivateAnalysisLocalSubprocessRunnerFailureReason.UNAVAILABLE,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            ),
            (
                PrivateAnalysisLocalSubprocessRunnerFailureReason.FAILED,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            ),
        ):
            with (
                self.subTest(reason=reason),
                tempfile.TemporaryDirectory() as temporary,
            ):
                case = _build_case(Path(temporary))
                failure = _message(
                    case,
                    3,
                    PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
                    {"reason": reason.value},
                )
                _write_control(
                    case.control_path,
                    [
                        _read_action(_hello(case)),
                        _write_action(_ready(case)),
                        _read_action(_start(case)),
                        _write_action(failure),
                    ],
                )
                service, _harness = _service(case)
                receipt = case.runner.execute(service)
                _assert_error(
                    self,
                    receipt,
                    expected,
                    PrivateAnalysisErrorStage.RUNNER,
                )

        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _analysis_result(case, _unsupported_result(case.request))
                    ),
                    {"kind": "exit", "code": 7},
                ],
            )
            service, _harness = _service(case)
            receipt = case.runner.execute(service)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            missing = str((directory / "missing-private-adapter.exe").resolve())
            with self.assertRaisesRegex(RuntimeError, "cannot be attested"):
                _build_case(directory, executable=missing)

    def test_deadline_terminates_and_reaps_the_direct_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                limits=_limits(deadline_ms=1_200),
                terminate_grace_ms=100,
                kill_grace_ms=500,
            )
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    {"kind": "block"},
                ],
            )
            service, _harness = _service(case)
            processes: list[Any] = []
            real_popen = subprocess.Popen

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            started = time.monotonic()
            with patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen",
                new=capture_spawn,
            ):
                receipt = case.runner.execute(service)
            elapsed = time.monotonic() - started

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll(), "timed-out child was not reaped")
            self.assertLess(elapsed, 5.0)
            leaked = [
                thread.name
                for thread in threading.enumerate()
                if thread.name.startswith("private-analysis-")
            ]
            self.assertEqual(leaked, [], f"runner leaked threads: {leaked!r}")

    def test_deadline_expiry_during_final_attestation_cannot_return_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary), limits=_limits(deadline_ms=5_000))
            _write_control(
                case.control_path,
                _zero_tool_actions(case, _unsupported_result(case.request)),
            )
            service, _harness = _service(case)
            final_attestation_completed = False
            seal_calls = 0
            real_seal = subprocess_runner_module._sealed_subprocess_transcript

            def expires_during_receipt(_deadline_ns: int) -> bool:
                return final_attestation_completed

            def seal_then_expire(*args: Any, **kwargs: Any) -> Any:
                nonlocal final_attestation_completed, seal_calls
                sealed = real_seal(*args, **kwargs)
                seal_calls += 1
                final_attestation_completed = True
                return sealed

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    new=expires_during_receipt,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_sealed_subprocess_transcript",
                    new=seal_then_expire,
                ),
            ):
                receipt = case.runner.execute(service)

            self.assertTrue(final_attestation_completed)
            self.assertEqual(seal_calls, 2)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(
                receipt.transcript.outcome_digest,
                receipt.outcome.outcome_digest,
            )

    def test_final_attestation_deadline_overrides_errors_and_fallbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary), limits=_limits(deadline_ms=5_000))
            failure = _message(
                case,
                3,
                PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
                {
                    "reason": (
                        PrivateAnalysisLocalSubprocessRunnerFailureReason.FAILED.value
                    )
                },
            )
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(failure),
                ],
            )
            service, _harness = _service(case)
            attestation_completed = False
            seal_calls = 0
            real_seal = subprocess_runner_module._sealed_subprocess_transcript

            def seal_then_expire(*args: Any, **kwargs: Any) -> Any:
                nonlocal attestation_completed, seal_calls
                sealed = real_seal(*args, **kwargs)
                seal_calls += 1
                attestation_completed = True
                return sealed

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    side_effect=lambda _deadline: attestation_completed,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_sealed_subprocess_transcript",
                    new=seal_then_expire,
                ),
            ):
                receipt = case.runner.execute(service)
            self.assertEqual(seal_calls, 2)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )

        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary), limits=_limits(deadline_ms=5_000))
            _write_control(
                case.control_path,
                _zero_tool_actions(case, _unsupported_result(case.request)),
            )
            service, _harness = _service(case)
            expired = False
            seal_attempts = 0
            real_seal = subprocess_runner_module._sealed_subprocess_transcript

            def fail_first_seal(*args: Any, **kwargs: Any) -> Any:
                nonlocal expired, seal_attempts
                seal_attempts += 1
                if seal_attempts == 1:
                    raise RuntimeError("synthetic attestation failure")
                sealed = real_seal(*args, **kwargs)
                if seal_attempts == 2:
                    expired = True
                return sealed

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "private_analysis_deadline_expired",
                    side_effect=lambda _deadline: expired,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_sealed_subprocess_transcript",
                    new=fail_first_seal,
                ),
            ):
                receipt = case.runner.execute(service)
            self.assertEqual(seal_attempts, 3)
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.TIMEOUT,
                PrivateAnalysisErrorStage.RUNNER,
            )

    def test_stderr_overflow_is_bounded_failed_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                stderr_limit_bytes=64,
                limits=_limits(deadline_ms=3_000),
            )
            _write_control(
                case.control_path,
                [
                    {
                        "kind": "write_stderr",
                        "data_b64": base64.b64encode(_HOSTILE_STDERR).decode("ascii"),
                        "repeat": 2,
                    },
                    {"kind": "block"},
                ],
            )
            service, _harness = _service(case)

            receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(receipt.transcript.stderr_bytes, 64)
            rendered = " ".join(
                (repr(receipt), repr(receipt.outcome), repr(receipt.transcript))
            ).casefold()
            for secret in ("alice", "bearer", "prod-super-secret", "private.txt"):
                self.assertNotIn(secret, rendered)

    def test_delayed_stderr_overflow_cannot_race_a_successful_terminal_frame(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                stderr_limit_bytes=64,
                limits=_limits(deadline_ms=3_000),
            )
            result = _unsupported_result(case.request)
            actions = _zero_tool_actions(case, result)
            actions.insert(
                -1,
                {
                    "kind": "write_stderr",
                    "data_b64": base64.b64encode(_HOSTILE_STDERR).decode("ascii"),
                    "repeat": 2,
                },
            )
            _write_control(case.control_path, actions)
            service, _harness = _service(case)
            processes: list[Any] = []
            receipt_box: list[PrivateAnalysisSubprocessExecutionReceipt] = []
            failure_box: list[BaseException] = []
            release_stderr = threading.Event()
            real_popen = subprocess.Popen
            real_stderr_drain = subprocess_runner_module._stderr_drain

            def capture_spawn(*args: object, **kwargs: object) -> Any:
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            def delayed_stderr_drain(*args: Any, **kwargs: Any) -> None:
                if not release_stderr.wait(timeout=2.0):
                    raise AssertionError("stderr regression test was not released")
                real_stderr_drain(*args, **kwargs)

            def execute() -> None:
                try:
                    receipt_box.append(case.runner.execute(service))
                except BaseException as error:  # noqa: BLE001
                    failure_box.append(error)

            with (
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "subprocess.Popen",
                    new=capture_spawn,
                ),
                patch(
                    "router_dump_analyzer.private_analysis_subprocess_runner."
                    "_stderr_drain",
                    new=delayed_stderr_drain,
                ),
            ):
                worker = threading.Thread(target=execute, daemon=False)
                worker.start()
                child_exit_deadline = time.monotonic() + 2.0
                while (
                    not processes or processes[0].poll() is None
                ) and time.monotonic() < child_exit_deadline:
                    time.sleep(0.005)
                self.assertTrue(processes, "runner did not spawn the child")
                self.assertIsNotNone(processes[0].poll(), "child did not exit")
                # Let the runner enter cleanup while the stderr reader remains
                # deliberately stalled.  Cleanup must preserve the pipe until
                # the reader observes all buffered bytes.
                time.sleep(0.05)
                release_stderr.set()
                worker.join(timeout=3.0)

            self.assertFalse(worker.is_alive(), "runner did not finish cleanup")
            self.assertEqual(failure_box, [])
            self.assertEqual(len(receipt_box), 1)
            receipt = receipt_box[0]
            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(receipt.transcript.stderr_bytes, 64)

    def test_output_validation_rejects_wrong_binding_citation_and_byte_budget(
        self,
    ) -> None:
        scenarios = ("wrong-request", "undisclosed-citation", "output-bytes")
        for scenario in scenarios:
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as temporary,
            ):
                limits = (
                    _limits(max_output_bytes=1, deadline_ms=5_000)
                    if scenario == "output-bytes"
                    else _limits(deadline_ms=5_000)
                )
                case = _build_case(Path(temporary), limits=limits)
                if scenario == "wrong-request":
                    other_request = _request(
                        selection=case.selection,
                        policy=case.policy,
                        limits=limits,
                        query="A different bound request.",
                    )
                    result = _unsupported_result(other_request)
                    expected = PrivateAnalysisErrorCode.INVALID_RESULT
                elif scenario == "undisclosed-citation":
                    result = _supported_result(case.request, _reference())
                    expected = PrivateAnalysisErrorCode.INVALID_RESULT
                else:
                    result = _unsupported_result(case.request)
                    expected = PrivateAnalysisErrorCode.BUDGET_EXCEEDED
                _write_control(
                    case.control_path,
                    _zero_tool_actions(case, result),
                )
                service, _harness = _service(case)

                receipt = case.runner.execute(service)

                _assert_error(
                    self,
                    receipt,
                    expected,
                    PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                )
                self.assertEqual(receipt.transcript.message_count, 4)

    def test_error_after_tool_call_preserves_lease_accounting_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    _read_action(),
                    _raw_stdout_action(b"malformed-after-tool\n"),
                ],
            )
            harness = _Harness(case.request, (reference,), policy=case.policy)
            service, _ = _service(case, harness)

            receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(harness.query_calls, 1)
            self.assertEqual(receipt.disclosed_references, (reference,))
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
            self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
            self.assertEqual(receipt.transcript.message_count, 5)
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)
            self.assertEqual(
                receipt.transcript.outcome_digest,
                receipt.outcome.outcome_digest,
            )
            with self.assertRaises(PrivateAnalysisToolServiceError):
                service.acquire_run_lease()

    def test_post_exhaustion_tool_call_fails_without_extra_budget_consumption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                limits=_limits(max_tool_calls=0, deadline_ms=5_000),
            )
            first = _query_call(case.request, call_id="over-budget-1")
            second = _query_call(case.request, call_id="over-budget-2")
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(first)},
                        )
                    ),
                    _read_action(),
                    _write_action(
                        _message(
                            case,
                            5,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(second)},
                        )
                    ),
                ],
            )
            service, harness = _service(case)

            receipt = case.runner.execute(service)

            _assert_error(
                self,
                receipt,
                PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                PrivateAnalysisErrorStage.RUNNER,
            )
            self.assertEqual(harness.query_calls, 0)
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(receipt.transcript.message_count, 6)

    def test_transcript_and_safe_reprs_are_payload_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            secret = "bearer private-query-token at C:\\Users\\alice"
            request = _request(
                selection=case.selection,
                policy=case.policy,
                query=secret,
                limits=_limits(deadline_ms=5_000),
            )
            variant = _FixtureCase(
                control_path=case.control_path,
                launch=case.launch,
                selection=case.selection,
                policy=case.policy,
                request=request,
                runner=case.runner,
                run_digest=private_analysis_subprocess_run_digest(
                    request,
                    default_private_analysis_tool_catalog(),
                    instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                    launch_configuration=case.launch,
                ),
            )
            _write_control(
                variant.control_path,
                _zero_tool_actions(variant, _unsupported_result(request)),
            )
            service, _harness = _service(variant)

            receipt = variant.runner.execute(service)

            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
            rendered = " ".join(
                (
                    repr(variant.launch),
                    repr(variant.runner),
                    repr(receipt),
                    repr(receipt.transcript),
                )
            ).casefold()
            for fragment in ("private-query-token", "users", "alice", "bearer"):
                self.assertNotIn(fragment, rendered)
            fields = set(receipt.transcript.__dataclass_fields__)
            for forbidden in (
                "query",
                "payload",
                "frame",
                "stdout",
                "stderr_content",
                "exception",
                "path",
                "timestamp",
            ):
                self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()

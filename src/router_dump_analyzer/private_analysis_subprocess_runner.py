"""Shell-free local-child execution boundary for private analysis.

The parent launches one operator-approved executable from an exact argv tuple,
passes only an explicit environment and working directory, and exchanges the
closed private-analysis JSONL protocol over binary standard streams.  Normal
completion requires direct-child exit and stopped helper threads; bounded
cleanup failure is projected as a static runner failure.  Descendant creation
is forbidden by contract because this portable adapter does not provide a
Windows Job Object process-tree guarantee.
"""

from __future__ import annotations

import os
import queue
import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Event, Thread
from time import monotonic_ns
from typing import IO, BinaryIO, Final, cast

from .canonical import strict_canonical_json, strict_canonical_json_sha256
from .private_analysis import (
    EvidenceReference,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisToolCatalog,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolResult,
    PrivateAnalysisTransport,
    default_private_analysis_tool_catalog,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_from_json,
    private_analysis_request_dict,
    private_analysis_tool_call_from_dict,
    private_analysis_tool_catalog_dict,
    private_analysis_tool_error_dict,
    private_analysis_tool_result_dict,
)
from .private_analysis.local_subprocess_protocol import (
    MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES,
    PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
    PrivateAnalysisLocalSubprocessMessage,
    PrivateAnalysisLocalSubprocessMessageKind,
    PrivateAnalysisLocalSubprocessRunnerFailureReason,
    decode_private_analysis_local_subprocess_message,
    encode_private_analysis_local_subprocess_message,
    validate_private_analysis_local_subprocess_sequence,
)
from .private_analysis_runner_support import (
    PrivateAnalysisRunAccountingSnapshot,
    detached_private_analysis_budget_state,
    detached_private_analysis_error,
    empty_private_analysis_budget_state,
    private_analysis_budget_payload,
    private_analysis_deadline_expired,
    private_analysis_error,
    private_analysis_error_outcome,
    private_analysis_execution_receipt_values,
    private_analysis_prefixed_sha256,
    private_analysis_run_access_error,
    validate_private_analysis_result_json,
)
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolRunLease,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

PRIVATE_ANALYSIS_SUBPROCESS_LAUNCH_VERSION: Final = (
    "router_dump_analyzer.private_analysis.subprocess_launch.v1"
)
PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.subprocess_transcript.v1"
)
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARGV_ITEMS: Final = 128
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARG_BYTES: Final = 32_768
MAX_PRIVATE_ANALYSIS_SUBPROCESS_COMMAND_UTF16_UNITS: Final = 30_000
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_ITEMS: Final = 256
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_BYTES: Final = 256 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES: Final = 256 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES: Final = 8 * 1024 * 1024
MIN_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS: Final = 10
MAX_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS: Final = 10_000

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_STOP_PUMP: Final = object()
_FINISH_PUMP: Final = object()


def _bounded_scalar_text(
    value: object,
    label: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not value and not allow_empty) or "\x00" in value:
        raise ValueError(f"{label} must be bounded scalar text")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} must not contain control characters")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds its encoded byte limit")
    return value


def _utf16_units(value: str) -> int:
    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise ValueError(
            "subprocess launch text must contain Unicode scalar values"
        ) from error


def _reject_win32_normalization_ambiguous_path(value: str, label: str) -> None:
    if os.name != "nt":
        return
    # pathlib represents a UNC server/share pair as one anchor.  Split the raw
    # Windows spelling instead so server, share, extended-UNC, drive, and
    # ordinary components are all checked by the same rule.
    for component in re.split(r"[\\/]+", value):
        if not component:
            continue
        if component.endswith((" ", ".")):
            raise ValueError(
                f"{label} contains a Win32-normalization-ambiguous component"
            )


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisSubprocessLaunchConfiguration:
    """Exact internal launch inputs for one operator-approved local adapter."""

    argv: tuple[str, ...]
    working_directory: str
    environment: tuple[tuple[str, str], ...]
    adapter_identity_digest: str
    stderr_limit_bytes: int = MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES
    terminate_grace_ms: int = 500
    kill_grace_ms: int = 2_000
    contract_version: str = PRIVATE_ANALYSIS_SUBPROCESS_LAUNCH_VERSION
    configuration_digest: str = ""

    def __post_init__(self) -> None:
        if self.contract_version != PRIVATE_ANALYSIS_SUBPROCESS_LAUNCH_VERSION:
            raise ValueError("unsupported subprocess launch contract version")
        if type(self.argv) is not tuple or not 1 <= len(self.argv) <= (
            MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARGV_ITEMS
        ):
            raise ValueError("subprocess argv must be a bounded non-empty tuple")
        argv = tuple(
            _bounded_scalar_text(
                item,
                "subprocess argument",
                maximum_bytes=MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARG_BYTES,
            )
            for item in self.argv
        )
        _reject_win32_normalization_ambiguous_path(
            argv[0],
            "subprocess executable",
        )
        executable = Path(argv[0])
        if not executable.is_absolute():
            raise ValueError("subprocess executable must be an absolute path")
        normalized_executable_name = executable.name.rstrip(" .")
        if normalized_executable_name.casefold().endswith((".bat", ".cmd")):
            raise ValueError("command-interpreter scripts are not executable adapters")
        if _utf16_units(subprocess.list2cmdline(argv)) > (
            MAX_PRIVATE_ANALYSIS_SUBPROCESS_COMMAND_UTF16_UNITS
        ):
            raise ValueError("subprocess command line exceeds its portable limit")

        working_directory = _bounded_scalar_text(
            self.working_directory,
            "subprocess working directory",
            maximum_bytes=16_384,
        )
        if not Path(working_directory).is_absolute():
            raise ValueError("subprocess working directory must be absolute")
        _reject_win32_normalization_ambiguous_path(
            working_directory,
            "subprocess working directory",
        )

        if type(self.environment) is not tuple or len(self.environment) > (
            MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_ITEMS
        ):
            raise ValueError("subprocess environment must be a bounded tuple")
        normalized_environment: list[tuple[str, str]] = []
        names: set[str] = set()
        environment_bytes = 0
        for entry in self.environment:
            if type(entry) is not tuple or len(entry) != 2:
                raise ValueError("subprocess environment entries must be pairs")
            name, raw_value = entry
            if type(name) is not str or _ENVIRONMENT_NAME.fullmatch(name) is None:
                raise ValueError("subprocess environment name is invalid")
            value = _bounded_scalar_text(
                raw_value,
                "subprocess environment value",
                maximum_bytes=65_536,
                allow_empty=True,
            )
            folded = name.casefold()
            if folded in names:
                raise ValueError("subprocess environment names must be unique")
            names.add(folded)
            environment_bytes += len(name.encode("ascii")) + len(value.encode("utf-8"))
            if environment_bytes > MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_BYTES:
                raise ValueError("subprocess environment exceeds its byte limit")
            normalized_environment.append((name, value))
        environment = tuple(sorted(normalized_environment, key=lambda item: item[0]))

        private_analysis_prefixed_sha256(
            self.adapter_identity_digest,
            "adapter_identity_digest",
        )
        if (
            type(self.stderr_limit_bytes) is not int
            or not 1
            <= self.stderr_limit_bytes
            <= MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES
        ):
            raise ValueError("stderr_limit_bytes is outside its bounded domain")
        for grace_value, label in (
            (self.terminate_grace_ms, "terminate_grace_ms"),
            (self.kill_grace_ms, "kill_grace_ms"),
        ):
            if (
                type(grace_value) is not int
                or not MIN_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS
                <= grace_value
                <= MAX_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS
            ):
                raise ValueError(f"{label} is outside its bounded domain")

        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "working_directory", working_directory)
        object.__setattr__(self, "environment", environment)
        expected = "sha256:" + strict_canonical_json_sha256(
            _launch_configuration_payload(self)
        )
        if type(self.configuration_digest) is not str:
            raise TypeError("configuration_digest must be a string")
        if self.configuration_digest != "":
            private_analysis_prefixed_sha256(
                self.configuration_digest,
                "configuration_digest",
            )
            if self.configuration_digest != expected:
                raise ValueError("configuration_digest does not match launch inputs")
        else:
            object.__setattr__(self, "configuration_digest", expected)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisSubprocessLaunchConfiguration("
            f"argument_count={len(self.argv)}, "
            f"environment_count={len(self.environment)}, "
            f"configuration_digest={self.configuration_digest!r})"
        )


def _launch_configuration_payload(
    value: PrivateAnalysisSubprocessLaunchConfiguration,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "argv": list(value.argv),
        "working_directory": value.working_directory,
        "environment": [list(item) for item in value.environment],
        "adapter_identity_digest": value.adapter_identity_digest,
        "stderr_limit_bytes": value.stderr_limit_bytes,
        "terminate_grace_ms": value.terminate_grace_ms,
        "kill_grace_ms": value.kill_grace_ms,
        "descendant_policy": "forbidden",
    }


def private_analysis_subprocess_run_digest(
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    *,
    instruction_profile_digest: str,
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
) -> str:
    """Return the payload-free binding digest echoed by one child protocol run."""

    if type(request) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    if type(catalog) is not PrivateAnalysisToolCatalog:
        raise TypeError("catalog must be PrivateAnalysisToolCatalog")
    if type(launch_configuration) is not PrivateAnalysisSubprocessLaunchConfiguration:
        raise TypeError(
            "launch_configuration must be PrivateAnalysisSubprocessLaunchConfiguration"
        )
    profile_digest = private_analysis_prefixed_sha256(
        instruction_profile_digest,
        "instruction_profile_digest",
    )
    return "sha256:" + strict_canonical_json_sha256(
        {
            "contract_version": PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
            "domain": "local_subprocess_run",
            "request_digest": request.request_digest,
            "catalog_digest": catalog.catalog_digest,
            "instruction_profile_digest": profile_digest,
            "runner_configuration_digest": request.runner.configuration_digest,
            "launch_configuration_digest": (launch_configuration.configuration_digest),
        }
    )


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisSubprocessTranscript:
    """Payload-free digest seal for one shell-free child execution."""

    request_digest: str
    catalog_digest: str
    instruction_profile_digest: str
    runner_configuration_digest: str
    launch_configuration_digest: str
    run_digest: str
    message_count: int
    tool_call_count: int
    message_metadata_bytes: int
    message_chain_digest: str
    stderr_bytes: int
    evidence_ledger_digest: str
    budget_state: PrivateAnalysisToolBudgetState
    outcome_digest: str
    contract_version: str = PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION
    transcript_digest: str = ""

    def __post_init__(self) -> None:
        if self.contract_version != PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION:
            raise ValueError("unsupported subprocess transcript version")
        for digest_value, label in (
            (self.request_digest, "request_digest"),
            (self.catalog_digest, "catalog_digest"),
            (self.instruction_profile_digest, "instruction_profile_digest"),
            (self.runner_configuration_digest, "runner_configuration_digest"),
            (self.launch_configuration_digest, "launch_configuration_digest"),
            (self.run_digest, "run_digest"),
            (self.message_chain_digest, "message_chain_digest"),
            (self.evidence_ledger_digest, "evidence_ledger_digest"),
            (self.outcome_digest, "outcome_digest"),
        ):
            private_analysis_prefixed_sha256(digest_value, label)
        for counter_value, label in (
            (self.message_count, "message_count"),
            (self.tool_call_count, "tool_call_count"),
            (self.message_metadata_bytes, "message_metadata_bytes"),
            (self.stderr_bytes, "stderr_bytes"),
        ):
            if type(counter_value) is not int or counter_value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if (
            self.message_metadata_bytes
            > MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES
        ):
            raise ValueError("subprocess transcript metadata exceeds its byte limit")
        if self.stderr_bytes > MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES:
            raise ValueError("subprocess stderr count exceeds its admitted limit")
        budget = detached_private_analysis_budget_state(self.budget_state)
        object.__setattr__(self, "budget_state", budget)
        if not (
            budget.tool_calls_consumed
            <= self.tool_call_count
            <= budget.tool_calls_consumed + 1
        ):
            raise ValueError("subprocess tool-call count disagrees with tool budget")
        expected = "sha256:" + strict_canonical_json_sha256(
            _subprocess_transcript_payload(self)
        )
        if type(self.transcript_digest) is not str:
            raise TypeError("transcript_digest must be a string")
        if self.transcript_digest != "":
            private_analysis_prefixed_sha256(
                self.transcript_digest,
                "transcript_digest",
            )
            if self.transcript_digest != expected:
                raise ValueError("subprocess transcript digest does not match")
        else:
            object.__setattr__(self, "transcript_digest", expected)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisSubprocessTranscript("
            f"request_digest={self.request_digest!r}, "
            f"message_count={self.message_count}, "
            f"tool_call_count={self.tool_call_count}, "
            f"transcript_digest={self.transcript_digest!r})"
        )


def _detached_subprocess_transcript(
    value: PrivateAnalysisSubprocessTranscript,
) -> PrivateAnalysisSubprocessTranscript:
    return PrivateAnalysisSubprocessTranscript(
        request_digest=value.request_digest,
        catalog_digest=value.catalog_digest,
        instruction_profile_digest=value.instruction_profile_digest,
        runner_configuration_digest=value.runner_configuration_digest,
        launch_configuration_digest=value.launch_configuration_digest,
        run_digest=value.run_digest,
        message_count=value.message_count,
        tool_call_count=value.tool_call_count,
        message_metadata_bytes=value.message_metadata_bytes,
        message_chain_digest=value.message_chain_digest,
        stderr_bytes=value.stderr_bytes,
        evidence_ledger_digest=value.evidence_ledger_digest,
        budget_state=value.budget_state,
        outcome_digest=value.outcome_digest,
        contract_version=value.contract_version,
        transcript_digest=value.transcript_digest,
    )


class PrivateAnalysisSubprocessExecutionReceipt:
    """Detached internal result of one shell-free local-child execution."""

    __slots__ = ("_budget", "_outcome_json", "_references", "_transcript")

    def __init__(
        self,
        *,
        outcome: PrivateAnalysisOutcome,
        transcript: PrivateAnalysisSubprocessTranscript,
        disclosed_references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
    ) -> None:
        if type(transcript) is not PrivateAnalysisSubprocessTranscript:
            raise TypeError("transcript must be PrivateAnalysisSubprocessTranscript")
        detached_transcript = _detached_subprocess_transcript(transcript)
        outcome_json, references, budget = private_analysis_execution_receipt_values(
            outcome=outcome,
            disclosed_references=disclosed_references,
            budget_state=budget_state,
            transcript_request_digest=detached_transcript.request_digest,
            transcript_evidence_ledger_digest=(
                detached_transcript.evidence_ledger_digest
            ),
            transcript_budget_state=detached_transcript.budget_state,
            transcript_outcome_digest=detached_transcript.outcome_digest,
        )
        self._outcome_json = outcome_json
        self._transcript = detached_transcript
        self._references = references
        self._budget = budget

    @property
    def outcome(self) -> PrivateAnalysisOutcome:
        return private_analysis_outcome_from_json(self._outcome_json)

    @property
    def transcript(self) -> PrivateAnalysisSubprocessTranscript:
        value = self._transcript
        return PrivateAnalysisSubprocessTranscript(
            request_digest=value.request_digest,
            catalog_digest=value.catalog_digest,
            instruction_profile_digest=value.instruction_profile_digest,
            runner_configuration_digest=value.runner_configuration_digest,
            launch_configuration_digest=value.launch_configuration_digest,
            run_digest=value.run_digest,
            message_count=value.message_count,
            tool_call_count=value.tool_call_count,
            message_metadata_bytes=value.message_metadata_bytes,
            message_chain_digest=value.message_chain_digest,
            stderr_bytes=value.stderr_bytes,
            evidence_ledger_digest=value.evidence_ledger_digest,
            budget_state=value.budget_state,
            outcome_digest=value.outcome_digest,
            contract_version=value.contract_version,
            transcript_digest=value.transcript_digest,
        )

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]:
        return tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in self._references
        )

    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState:
        return detached_private_analysis_budget_state(self._budget)

    def __repr__(self) -> str:
        outcome = self.outcome
        return (
            "PrivateAnalysisSubprocessExecutionReceipt("
            f"outcome={outcome.kind.value!r}, "
            f"outcome_digest={outcome.outcome_digest!r}, "
            f"transcript_digest={self._transcript.transcript_digest!r})"
        )


def _subprocess_transcript_payload(
    value: PrivateAnalysisSubprocessTranscript,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "catalog_digest": value.catalog_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
        "runner_configuration_digest": value.runner_configuration_digest,
        "launch_configuration_digest": value.launch_configuration_digest,
        "run_digest": value.run_digest,
        "message_count": value.message_count,
        "tool_call_count": value.tool_call_count,
        "message_metadata_bytes": value.message_metadata_bytes,
        "message_chain_digest": value.message_chain_digest,
        "stderr_bytes": value.stderr_bytes,
        "evidence_ledger_digest": value.evidence_ledger_digest,
        "budget_state": private_analysis_budget_payload(value.budget_state),
        "outcome_digest": value.outcome_digest,
    }


class _PumpEventKind(StrEnum):
    FRAME = "frame"
    EOF = "eof"
    IO_FAILED = "io_failed"
    STDERR_LIMIT = "stderr_limit"


@dataclass(frozen=True, slots=True)
class _PumpEvent:
    kind: _PumpEventKind
    frame: bytes = b""


@dataclass(frozen=True, slots=True)
class _PumpCommand:
    frame: bytes | None = None
    finish: bool = False


@dataclass(slots=True)
class _StderrCount:
    admitted_bytes: int = 0
    overflowed: bool = False
    io_failed: bool = False


@dataclass(slots=True)
class _ProcessCleanupState:
    exited: bool = False
    failed: bool = False
    process_control: BaseException | None = None


def _remember_cleanup_process_control(
    state: _ProcessCleanupState,
    error: BaseException,
) -> None:
    state.failed = True
    if state.process_control is None:
        state.process_control = error


def _best_effort_stop_process(
    process: subprocess.Popen[bytes],
    *,
    terminate_grace_ms: int,
    kill_grace_ms: int,
) -> _ProcessCleanupState:
    state = _ProcessCleanupState()
    try:
        state.exited = process.poll() is not None
    except PROCESS_CONTROL_EXCEPTIONS as error:
        _remember_cleanup_process_control(state, error)
    except BaseException:  # noqa: BLE001 - cleanup must continue to pipe closure.
        state.failed = True

    if not state.exited:
        try:
            process.terminate()
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - cleanup continues with wait/kill.
            state.failed = True
        try:
            process.wait(timeout=terminate_grace_ms / 1_000)
            state.exited = True
        except subprocess.TimeoutExpired:
            pass
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - cleanup continues with kill.
            state.failed = True

    if not state.exited:
        try:
            process.kill()
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - cleanup still closes pipes.
            state.failed = True
        try:
            process.wait(timeout=kill_grace_ms / 1_000)
            state.exited = True
        except subprocess.TimeoutExpired:
            state.failed = True
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - cleanup still closes pipes.
            state.failed = True

    if not state.exited:
        try:
            state.exited = process.poll() is not None
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - failure is reported after closure.
            state.failed = True
    return state


def _close_cleanup_stream(
    stream: IO[bytes] | None,
    state: _ProcessCleanupState,
) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except PROCESS_CONTROL_EXCEPTIONS as error:
        _remember_cleanup_process_control(state, error)
    except BaseException:  # noqa: BLE001 - remaining finalizers must run.
        state.failed = True


def _join_cleanup_thread(
    thread: Thread,
    timeout_seconds: float,
    state: _ProcessCleanupState,
) -> None:
    try:
        thread.join(timeout=max(0.0, timeout_seconds))
    except PROCESS_CONTROL_EXCEPTIONS as error:
        _remember_cleanup_process_control(state, error)
    except BaseException:  # noqa: BLE001 - remaining finalizers must run.
        state.failed = True


def _cleanup_thread_is_alive(
    thread: Thread,
    state: _ProcessCleanupState,
) -> bool:
    try:
        return thread.is_alive()
    except PROCESS_CONTROL_EXCEPTIONS as error:
        _remember_cleanup_process_control(state, error)
    except BaseException:  # noqa: BLE001 - report cleanup failure.
        state.failed = True
    return True


def _raise_cleanup_process_control(state: _ProcessCleanupState) -> None:
    if state.process_control is not None:
        raise state.process_control.with_traceback(state.process_control.__traceback__)


class _SubprocessTranscriptAccumulator:
    __slots__ = (
        "_chain_digest",
        "_message_count",
        "_metadata_bytes",
        "_tool_call_count",
    )

    def __init__(
        self,
        *,
        request_digest: str,
        catalog_digest: str,
        instruction_profile_digest: str,
        runner_configuration_digest: str,
        launch_configuration_digest: str,
        run_digest: str,
    ) -> None:
        self._message_count = 0
        self._tool_call_count = 0
        self._metadata_bytes = 0
        self._chain_digest = "sha256:" + strict_canonical_json_sha256(
            {
                "contract_version": PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION,
                "domain": "message_seed",
                "request_digest": request_digest,
                "catalog_digest": catalog_digest,
                "instruction_profile_digest": instruction_profile_digest,
                "runner_configuration_digest": runner_configuration_digest,
                "launch_configuration_digest": launch_configuration_digest,
                "run_digest": run_digest,
            }
        )

    def record(
        self,
        direction: str,
        message: PrivateAnalysisLocalSubprocessMessage,
        frame_bytes: int,
    ) -> None:
        metadata = {
            "direction": direction,
            "sequence": message.sequence,
            "kind": message.kind.value,
            "message_digest": message.message_digest,
            "frame_bytes": frame_bytes,
        }
        encoded = strict_canonical_json(metadata).encode("utf-8")
        next_size = self._metadata_bytes + len(encoded)
        if next_size > MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES:
            raise ValueError("subprocess transcript metadata budget was exceeded")
        self._chain_digest = "sha256:" + strict_canonical_json_sha256(
            {
                "contract_version": PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION,
                "domain": "message_link",
                "previous_chain_digest": self._chain_digest,
                "message": metadata,
            }
        )
        self._metadata_bytes = next_size
        self._message_count += 1

    def record_admitted_tool_call(self) -> None:
        self._tool_call_count += 1

    @property
    def message_count(self) -> int:
        return self._message_count

    @property
    def tool_call_count(self) -> int:
        return self._tool_call_count

    @property
    def metadata_bytes(self) -> int:
        return self._metadata_bytes

    @property
    def chain_digest(self) -> str:
        return self._chain_digest


def _write_all(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise OSError("subprocess stdin stopped accepting bytes")
        view = view[written:]
    stream.flush()


def _pipe_pump(
    stdin: BinaryIO,
    stdout: BinaryIO,
    commands: queue.Queue[object],
    events: queue.Queue[_PumpEvent],
    stop: Event,
) -> None:
    try:
        while not stop.is_set():
            command = commands.get()
            if command is _STOP_PUMP:
                return
            if type(command) is not _PumpCommand:
                events.put(_PumpEvent(_PumpEventKind.IO_FAILED))
                return
            typed = command
            if typed.finish:
                stdin.close()
                trailing = stdout.readline(
                    MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES + 1
                )
                if trailing:
                    events.put(_PumpEvent(_PumpEventKind.FRAME, trailing))
                else:
                    events.put(_PumpEvent(_PumpEventKind.EOF))
                return
            if typed.frame is None:
                events.put(_PumpEvent(_PumpEventKind.IO_FAILED))
                return
            _write_all(stdin, typed.frame)
            frame = stdout.readline(
                MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES + 1
            )
            if frame:
                events.put(_PumpEvent(_PumpEventKind.FRAME, frame))
            else:
                events.put(_PumpEvent(_PumpEventKind.EOF))
                return
    except BaseException:  # noqa: BLE001 - worker cannot propagate across threads.
        events.put(_PumpEvent(_PumpEventKind.IO_FAILED))


def _stderr_drain(
    stderr: BinaryIO,
    events: queue.Queue[_PumpEvent],
    state: _StderrCount,
    limit: int,
) -> None:
    try:
        while True:
            chunk = stderr.read(65_536)
            if not chunk:
                return
            if not state.overflowed:
                remaining = max(0, limit - state.admitted_bytes)
                state.admitted_bytes += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    state.overflowed = True
                    events.put(_PumpEvent(_PumpEventKind.STDERR_LIMIT))
    except BaseException:  # noqa: BLE001 - diagnostics are never retained.
        state.io_failed = True
        events.put(_PumpEvent(_PumpEventKind.IO_FAILED))


class _LocalChildSession:
    __slots__ = (
        "_commands",
        "_configuration",
        "_events",
        "_process",
        "_pump",
        "_pump_started",
        "_stderr",
        "_stderr_started",
        "_stderr_state",
        "_stop",
    )

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("subprocess standard streams were not created")
        self._process = process
        self._configuration = configuration
        self._commands: queue.Queue[object] = queue.Queue(maxsize=1)
        self._events: queue.Queue[_PumpEvent] = queue.Queue()
        self._stop = Event()
        self._stderr_state = _StderrCount()
        self._pump_started = False
        self._stderr_started = False
        self._pump = Thread(
            target=_pipe_pump,
            args=(
                cast(BinaryIO, process.stdin),
                cast(BinaryIO, process.stdout),
                self._commands,
                self._events,
                self._stop,
            ),
            name="private-analysis-stdio-pump",
            daemon=False,
        )
        self._stderr = Thread(
            target=_stderr_drain,
            args=(
                cast(BinaryIO, process.stderr),
                self._events,
                self._stderr_state,
                configuration.stderr_limit_bytes,
            ),
            name="private-analysis-stderr-drain",
            daemon=False,
        )
        try:
            self._pump.start()
            self._pump_started = True
            self._stderr.start()
            self._stderr_started = True
        except PROCESS_CONTROL_EXCEPTIONS:
            try:
                self.cleanup()
            except BaseException:  # noqa: BLE001, S110 - preserve control flow.
                pass
            raise
        except BaseException as error:
            if not self.cleanup():
                raise RuntimeError(
                    "subprocess helper startup cleanup did not complete"
                ) from error
            raise

    @property
    def stderr_bytes(self) -> int:
        return self._stderr_state.admitted_bytes

    @property
    def stderr_failed(self) -> bool:
        return self._stderr_state.overflowed or self._stderr_state.io_failed

    def exchange(self, frame: bytes, deadline_ns: int) -> _PumpEvent | None:
        if not self._put_command(_PumpCommand(frame=frame), deadline_ns):
            return None
        return self._wait_event(deadline_ns)

    def finish(self, deadline_ns: int) -> _PumpEvent | None:
        if not self._put_command(_PumpCommand(finish=True), deadline_ns):
            return None
        return self._wait_event(deadline_ns)

    def wait_for_exit(self, deadline_ns: int) -> int | None:
        remaining = deadline_ns - monotonic_ns()
        if remaining <= 0:
            return None
        try:
            return self._process.wait(timeout=remaining / 1_000_000_000)
        except subprocess.TimeoutExpired:
            return None

    def _put_command(self, command: _PumpCommand, deadline_ns: int) -> bool:
        remaining = deadline_ns - monotonic_ns()
        if remaining <= 0:
            return False
        try:
            self._commands.put(command, timeout=remaining / 1_000_000_000)
        except queue.Full:
            return False
        return True

    def _wait_event(self, deadline_ns: int) -> _PumpEvent | None:
        remaining = deadline_ns - monotonic_ns()
        if remaining <= 0:
            return None
        try:
            return self._events.get(timeout=remaining / 1_000_000_000)
        except queue.Empty:
            return None

    def cleanup(self) -> bool:
        state = _ProcessCleanupState()
        try:
            self._stop.set()
            self._commands.put_nowait(_STOP_PUMP)
        except queue.Full:
            pass
        except PROCESS_CONTROL_EXCEPTIONS as error:
            _remember_cleanup_process_control(state, error)
        except BaseException:  # noqa: BLE001 - cleanup still stops the child.
            state.failed = True
        process_state = _best_effort_stop_process(
            self._process,
            terminate_grace_ms=self._configuration.terminate_grace_ms,
            kill_grace_ms=self._configuration.kill_grace_ms,
        )
        state.exited = process_state.exited
        state.failed = state.failed or process_state.failed
        if state.process_control is None:
            state.process_control = process_state.process_control
        # Once the child has exited, leave stderr open until its dedicated
        # reader reaches EOF.  Closing it first can discard buffered bytes and
        # let a delayed overflow race a successful terminal response.
        _close_cleanup_stream(self._process.stdin, state)
        _close_cleanup_stream(self._process.stdout, state)
        stderr = self._process.stderr
        if not state.exited:
            _close_cleanup_stream(stderr, state)
        join_deadline_ns = (
            monotonic_ns()
            + int(
                self._configuration.terminate_grace_ms
                + self._configuration.kill_grace_ms
            )
            * 1_000_000
        )
        if self._pump_started:
            _join_cleanup_thread(
                self._pump,
                max(0, join_deadline_ns - monotonic_ns()) / 1_000_000_000,
                state,
            )
        if self._stderr_started:
            _join_cleanup_thread(
                self._stderr,
                max(0, join_deadline_ns - monotonic_ns()) / 1_000_000_000,
                state,
            )
        _close_cleanup_stream(stderr, state)
        if self._stderr_started and _cleanup_thread_is_alive(self._stderr, state):
            _join_cleanup_thread(
                self._stderr,
                self._configuration.kill_grace_ms / 1_000,
                state,
            )
        pump_stopped = not self._pump_started or not _cleanup_thread_is_alive(
            self._pump,
            state,
        )
        stderr_stopped = not self._stderr_started or not _cleanup_thread_is_alive(
            self._stderr,
            state,
        )
        _raise_cleanup_process_control(state)
        return not state.failed and state.exited and pump_stopped and stderr_stopped


def _static_runner_error(
    request: PrivateAnalysisRequest,
    code: PrivateAnalysisErrorCode,
) -> PrivateAnalysisError:
    return private_analysis_error(
        request.request_digest,
        PrivateAnalysisErrorStage.RUNNER,
        code,
    )


def _is_timeout_outcome(outcome: PrivateAnalysisOutcome) -> bool:
    return (
        outcome.kind is PrivateAnalysisOutcomeKind.ERROR
        and outcome.error is not None
        and outcome.error.code is PrivateAnalysisErrorCode.TIMEOUT
    )


def _access_or_deadline_error(
    lease: PrivateAnalysisToolRunLease,
    request: PrivateAnalysisRequest,
    deadline_ns: int,
) -> PrivateAnalysisError | None:
    return private_analysis_run_access_error(
        lease,
        request,
        deadline_ns,
        deadline_expired=private_analysis_deadline_expired,
    )


def _spawn_local_child(
    configuration: PrivateAnalysisSubprocessLaunchConfiguration,
) -> subprocess.Popen[bytes]:
    creationflags = 0
    if os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return subprocess.Popen(
        list(configuration.argv),
        executable=configuration.argv[0],
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        cwd=configuration.working_directory,
        env=dict(configuration.environment),
        close_fds=True,
        creationflags=creationflags,
        start_new_session=False,
    )


def _reap_unmanaged_child(
    process: subprocess.Popen[bytes],
    configuration: PrivateAnalysisSubprocessLaunchConfiguration,
) -> bool:
    state = _best_effort_stop_process(
        process,
        terminate_grace_ms=configuration.terminate_grace_ms,
        kill_grace_ms=configuration.kill_grace_ms,
    )
    _close_cleanup_stream(process.stdin, state)
    _close_cleanup_stream(process.stdout, state)
    _close_cleanup_stream(process.stderr, state)
    _raise_cleanup_process_control(state)
    return not state.failed and state.exited


def _exchange_message(
    session: _LocalChildSession,
    outbound: PrivateAnalysisLocalSubprocessMessage,
    previous: PrivateAnalysisLocalSubprocessMessage | None,
    transcript: _SubprocessTranscriptAccumulator,
    deadline_ns: int,
) -> tuple[
    PrivateAnalysisLocalSubprocessMessage | None,
    PrivateAnalysisErrorCode | None,
]:
    try:
        validate_private_analysis_local_subprocess_sequence(previous, outbound)
        frame = encode_private_analysis_local_subprocess_message(outbound)
        transcript.record("parent_to_child", outbound, len(frame))
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - internal protocol integrity boundary.
        return None, PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR
    event = session.exchange(frame, deadline_ns)
    if event is None:
        return None, PrivateAnalysisErrorCode.TIMEOUT
    if event.kind is _PumpEventKind.STDERR_LIMIT:
        return None, PrivateAnalysisErrorCode.RUNNER_FAILED
    if event.kind in {_PumpEventKind.EOF, _PumpEventKind.IO_FAILED}:
        return None, PrivateAnalysisErrorCode.RUNNER_FAILED
    try:
        incoming = decode_private_analysis_local_subprocess_message(event.frame)
        validate_private_analysis_local_subprocess_sequence(outbound, incoming)
        transcript.record("child_to_parent", incoming, len(event.frame))
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - untrusted child protocol boundary.
        return None, PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR
    return incoming, None


def _finish_child_protocol(
    session: _LocalChildSession,
    deadline_ns: int,
) -> PrivateAnalysisErrorCode | None:
    event = session.finish(deadline_ns)
    if event is None:
        return PrivateAnalysisErrorCode.TIMEOUT
    if event.kind is _PumpEventKind.STDERR_LIMIT:
        return PrivateAnalysisErrorCode.RUNNER_FAILED
    if event.kind is not _PumpEventKind.EOF:
        return (
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR
            if event.kind is _PumpEventKind.FRAME
            else PrivateAnalysisErrorCode.RUNNER_FAILED
        )
    return_code = session.wait_for_exit(deadline_ns)
    if return_code is None:
        return PrivateAnalysisErrorCode.TIMEOUT
    if return_code != 0:
        return PrivateAnalysisErrorCode.RUNNER_FAILED
    return None


class ConfiguredPrivateAnalysisSubprocessRunner:
    """Run one request through an exact, shell-free direct-child adapter."""

    __slots__ = (
        "_instruction_profile_digest",
        "_launch_configuration",
        "_selection",
    )

    def __init__(
        self,
        selection: PrivateAnalysisRunnerSelection,
        *,
        instruction_profile_digest: str,
        launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    ) -> None:
        if type(selection) is not PrivateAnalysisRunnerSelection:
            raise TypeError("selection must be PrivateAnalysisRunnerSelection")
        detached = PrivateAnalysisRunnerSelection(
            runner_id=selection.runner_id,
            runner_version=selection.runner_version,
            transport=selection.transport,
            configuration_digest=selection.configuration_digest,
        )
        if detached.transport is not PrivateAnalysisTransport.LOCAL_SUBPROCESS:
            raise ValueError("subprocess runner requires local_subprocess transport")
        if (
            type(launch_configuration)
            is not PrivateAnalysisSubprocessLaunchConfiguration
        ):
            raise TypeError(
                "launch_configuration must be PrivateAnalysisSubprocessLaunchConfiguration"
            )
        private_launch = PrivateAnalysisSubprocessLaunchConfiguration(
            argv=launch_configuration.argv,
            working_directory=launch_configuration.working_directory,
            environment=launch_configuration.environment,
            adapter_identity_digest=launch_configuration.adapter_identity_digest,
            stderr_limit_bytes=launch_configuration.stderr_limit_bytes,
            terminate_grace_ms=launch_configuration.terminate_grace_ms,
            kill_grace_ms=launch_configuration.kill_grace_ms,
            contract_version=launch_configuration.contract_version,
            configuration_digest=launch_configuration.configuration_digest,
        )
        if detached.configuration_digest != private_launch.configuration_digest:
            raise ValueError("runner selection does not bind the launch configuration")
        self._selection = detached
        self._instruction_profile_digest = private_analysis_prefixed_sha256(
            instruction_profile_digest,
            "instruction_profile_digest",
        )
        self._launch_configuration = private_launch

    @property
    def selection(self) -> PrivateAnalysisRunnerSelection:
        value = self._selection
        return PrivateAnalysisRunnerSelection(
            runner_id=value.runner_id,
            runner_version=value.runner_version,
            transport=value.transport,
            configuration_digest=value.configuration_digest,
        )

    def execute(
        self,
        tool_service: PrivateAnalysisToolService,
    ) -> PrivateAnalysisSubprocessExecutionReceipt:
        if type(tool_service) is not PrivateAnalysisToolService:
            raise TypeError("tool_service must be PrivateAnalysisToolService")
        request = tool_service.request
        deadline_ns = monotonic_ns() + request.limits.deadline_ms * 1_000_000
        catalog = default_private_analysis_tool_catalog()
        run_digest = private_analysis_subprocess_run_digest(
            request,
            catalog,
            instruction_profile_digest=self._instruction_profile_digest,
            launch_configuration=self._launch_configuration,
        )
        binding_error = self._binding_error(request, catalog)
        if binding_error is not None:
            return _deadline_checked_standalone_subprocess_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                outcome=private_analysis_error_outcome(binding_error),
                references=(),
                budget_state=empty_private_analysis_budget_state(request),
                deadline_ns=deadline_ns,
            )

        outcome_error: PrivateAnalysisError | None = None
        raw_result: str | None = None
        budget_state = empty_private_analysis_budget_state(request)
        accounting = PrivateAnalysisRunAccountingSnapshot((), budget_state)
        transcript = _SubprocessTranscriptAccumulator(
            request_digest=request.request_digest,
            catalog_digest=catalog.catalog_digest,
            instruction_profile_digest=self._instruction_profile_digest,
            runner_configuration_digest=self._selection.configuration_digest,
            launch_configuration_digest=(
                self._launch_configuration.configuration_digest
            ),
            run_digest=run_digest,
        )
        session: _LocalChildSession | None = None
        stderr_bytes = 0
        stderr_failed = False
        cleanup_succeeded = True

        if private_analysis_deadline_expired(deadline_ns):
            return _deadline_checked_standalone_subprocess_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                outcome=private_analysis_error_outcome(
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.TIMEOUT,
                    )
                ),
                references=(),
                budget_state=budget_state,
                deadline_ns=deadline_ns,
            )
        try:
            lease = tool_service.acquire_run_lease()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisToolServiceError as error:
            admission_error = (
                _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
                if private_analysis_deadline_expired(deadline_ns)
                else error.error
            )
            return _deadline_checked_standalone_subprocess_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                outcome=private_analysis_error_outcome(admission_error),
                references=(),
                budget_state=budget_state,
                deadline_ns=deadline_ns,
            )

        pending_process_control: BaseException | None = None
        pending_failure: BaseException | None = None
        finalizer_failed = False
        try:
            try:
                accounting.refresh(lease)
                budget_state = accounting.budget_state
                outcome_error = _access_or_deadline_error(
                    lease,
                    request,
                    deadline_ns,
                )
                if outcome_error is None:
                    process: subprocess.Popen[bytes] | None = None
                    try:
                        process = _spawn_local_child(self._launch_configuration)
                        session = _LocalChildSession(
                            process,
                            self._launch_configuration,
                        )
                    except PROCESS_CONTROL_EXCEPTIONS:
                        if process is not None:
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except BaseException:  # noqa: BLE001, S110
                                pass
                        raise
                    except OSError:
                        if process is not None:
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except PROCESS_CONTROL_EXCEPTIONS:
                                raise
                            except BaseException:  # noqa: BLE001
                                cleanup_succeeded = False
                        outcome_error = _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                        )
                    except BaseException:  # noqa: BLE001 - executable boundary.
                        if process is not None:
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except PROCESS_CONTROL_EXCEPTIONS:
                                raise
                            except BaseException:  # noqa: BLE001
                                cleanup_succeeded = False
                        outcome_error = _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.RUNNER_FAILED,
                        )
                if outcome_error is None and session is not None:
                    outcome_error, raw_result = self._drive_protocol(
                        session=session,
                        lease=lease,
                        request=request,
                        catalog=catalog,
                        run_digest=run_digest,
                        deadline_ns=deadline_ns,
                        transcript=transcript,
                        accounting=accounting,
                    )
            except PROCESS_CONTROL_EXCEPTIONS as error:
                pending_process_control = error
            except BaseException as error:  # noqa: BLE001 - runner boundary.
                pending_failure = error
        finally:
            if session is not None:
                try:
                    cleanup_succeeded = session.cleanup()
                    stderr_bytes = session.stderr_bytes
                    stderr_failed = session.stderr_failed
                except PROCESS_CONTROL_EXCEPTIONS as error:
                    if pending_process_control is None:
                        pending_process_control = error
                except BaseException:  # noqa: BLE001 - finalizer boundary.
                    cleanup_succeeded = False
                    finalizer_failed = True
            try:
                accounting.refresh(lease)
            except PROCESS_CONTROL_EXCEPTIONS as error:
                if pending_process_control is None:
                    pending_process_control = error
            except BaseException:  # noqa: BLE001 - finalizer boundary.
                finalizer_failed = True
            try:
                lease.close()
            except PROCESS_CONTROL_EXCEPTIONS as error:
                if pending_process_control is None:
                    pending_process_control = error
            except BaseException:  # noqa: BLE001 - finalizer boundary.
                finalizer_failed = True

        if pending_process_control is not None:
            raise pending_process_control.with_traceback(
                pending_process_control.__traceback__
            )
        if pending_failure is not None or finalizer_failed:
            cleanup_succeeded = False

        references = accounting.references
        budget_state = accounting.budget_state

        if not cleanup_succeeded or stderr_failed:
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        if private_analysis_deadline_expired(deadline_ns):
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.TIMEOUT,
            )
        if outcome_error is None:
            result, result_error = validate_private_analysis_result_json(
                raw_result,
                request,
                references,
            )
            if private_analysis_deadline_expired(deadline_ns):
                outcome_error = _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            elif result_error is not None:
                outcome_error = result_error
            elif result is not None:
                outcome = PrivateAnalysisOutcome(
                    kind=PrivateAnalysisOutcomeKind.RESULT,
                    result=result,
                )
            else:
                outcome_error = private_analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                    PrivateAnalysisErrorCode.INVALID_RESULT,
                )
        if outcome_error is not None:
            outcome = private_analysis_error_outcome(outcome_error)
        if not _is_timeout_outcome(outcome) and private_analysis_deadline_expired(
            deadline_ns
        ):
            outcome = private_analysis_error_outcome(
                _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )

        try:
            return _deadline_checked_execution_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                accumulator=transcript,
                stderr_bytes=stderr_bytes,
                references=references,
                budget_state=budget_state,
                outcome=outcome,
                deadline_ns=deadline_ns,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - receipt integrity boundary.
            fallback_code = (
                PrivateAnalysisErrorCode.TIMEOUT
                if private_analysis_deadline_expired(deadline_ns)
                else PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR
            )
            return _deadline_checked_execution_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                accumulator=transcript,
                stderr_bytes=stderr_bytes,
                outcome=private_analysis_error_outcome(
                    _static_runner_error(
                        request,
                        fallback_code,
                    )
                ),
                references=references,
                budget_state=budget_state,
                deadline_ns=deadline_ns,
            )

    def _drive_protocol(
        self,
        *,
        session: _LocalChildSession,
        lease: PrivateAnalysisToolRunLease,
        request: PrivateAnalysisRequest,
        catalog: PrivateAnalysisToolCatalog,
        run_digest: str,
        deadline_ns: int,
        transcript: _SubprocessTranscriptAccumulator,
        accounting: PrivateAnalysisRunAccountingSnapshot,
    ) -> tuple[PrivateAnalysisError | None, str | None]:
        hello = PrivateAnalysisLocalSubprocessMessage(
            run_digest=run_digest,
            sequence=0,
            kind=PrivateAnalysisLocalSubprocessMessageKind.HELLO,
            payload={},
        )
        incoming, code = _exchange_message(
            session,
            hello,
            None,
            transcript,
            deadline_ns,
        )
        if code is not None:
            return _static_runner_error(request, code), None
        if incoming is None or incoming.kind is not (
            PrivateAnalysisLocalSubprocessMessageKind.READY
        ):
            return (
                _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                ),
                None,
            )

        access_error = _access_or_deadline_error(lease, request, deadline_ns)
        if access_error is not None:
            return access_error, None
        start = PrivateAnalysisLocalSubprocessMessage(
            run_digest=run_digest,
            sequence=2,
            kind=PrivateAnalysisLocalSubprocessMessageKind.START,
            payload={
                "request": private_analysis_request_dict(request),
                "tool_catalog": private_analysis_tool_catalog_dict(catalog),
            },
        )
        incoming, code = _exchange_message(
            session,
            start,
            incoming,
            transcript,
            deadline_ns,
        )
        budget_exhausted = False
        while (
            code is None
            and incoming is not None
            and incoming.kind is (PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL)
        ):
            if budget_exhausted:
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                    ),
                    None,
                )
            transcript.record_admitted_tool_call()
            try:
                call = private_analysis_tool_call_from_dict(
                    incoming.payload["tool_call"]
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except (KeyError, TypeError, ValueError):
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    ),
                    None,
                )
            if private_analysis_deadline_expired(deadline_ns):
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.TIMEOUT,
                    ),
                    None,
                )
            try:
                response = lease.execute(call)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except PrivateAnalysisToolServiceError as error:
                if private_analysis_deadline_expired(deadline_ns):
                    return (
                        _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.TIMEOUT,
                        ),
                        None,
                    )
                return detached_private_analysis_error(error.error), None
            except BaseException:  # noqa: BLE001 - service boundary.
                if private_analysis_deadline_expired(deadline_ns):
                    return (
                        _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.TIMEOUT,
                        ),
                        None,
                    )
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                    ),
                    None,
                )
            try:
                accounting.refresh(lease)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001 - accounting boundary.
                if private_analysis_deadline_expired(deadline_ns):
                    return (
                        _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.TIMEOUT,
                        ),
                        None,
                    )
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                    ),
                    None,
                )
            if private_analysis_deadline_expired(deadline_ns):
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.TIMEOUT,
                    ),
                    None,
                )
            next_sequence = incoming.sequence + 1
            if type(response) is PrivateAnalysisToolResult:
                outbound = PrivateAnalysisLocalSubprocessMessage(
                    run_digest=run_digest,
                    sequence=next_sequence,
                    kind=PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                    payload={
                        "tool_result": private_analysis_tool_result_dict(response)
                    },
                )
            elif type(response) is PrivateAnalysisToolError:
                budget_exhausted = (
                    response.code is PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED
                )
                outbound = PrivateAnalysisLocalSubprocessMessage(
                    run_digest=run_digest,
                    sequence=next_sequence,
                    kind=PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR,
                    payload={"tool_error": private_analysis_tool_error_dict(response)},
                )
            else:
                return (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                    ),
                    None,
                )
            incoming, code = _exchange_message(
                session,
                outbound,
                incoming,
                transcript,
                deadline_ns,
            )

        if code is not None:
            return _static_runner_error(request, code), None
        if incoming is None or incoming.kind not in {
            PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT,
            PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
        }:
            return (
                _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                ),
                None,
            )
        finish_code = _finish_child_protocol(session, deadline_ns)
        if finish_code is not None:
            return _static_runner_error(request, finish_code), None
        access_error = _access_or_deadline_error(lease, request, deadline_ns)
        if access_error is not None:
            return access_error, None
        if incoming.kind is PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE:
            reason = incoming.payload["reason"]
            code = (
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE
                if reason
                == PrivateAnalysisLocalSubprocessRunnerFailureReason.UNAVAILABLE.value
                else PrivateAnalysisErrorCode.RUNNER_FAILED
            )
            return _static_runner_error(request, code), None
        try:
            raw_result = strict_canonical_json(incoming.payload["analysis_result"])
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - untrusted child payload.
            return (
                private_analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                    PrivateAnalysisErrorCode.INVALID_RESULT,
                ),
                None,
            )
        return None, raw_result

    def _binding_error(
        self,
        request: PrivateAnalysisRequest,
        catalog: PrivateAnalysisToolCatalog,
    ) -> PrivateAnalysisError | None:
        if request.runner != self._selection:
            return _static_runner_error(
                request,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            )
        if (
            request.instruction_profile_digest != self._instruction_profile_digest
            or request.tool_catalog_digest != catalog.catalog_digest
        ):
            return private_analysis_error(
                request.request_digest,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        return None

    def __repr__(self) -> str:
        return (
            "ConfiguredPrivateAnalysisSubprocessRunner("
            f"runner_id={self._selection.runner_id!r}, "
            f"runner_version={self._selection.runner_version!r}, "
            f"configuration_digest={self._selection.configuration_digest!r})"
        )


def _sealed_subprocess_transcript(
    *,
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    instruction_profile_digest: str,
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    run_digest: str,
    accumulator: _SubprocessTranscriptAccumulator,
    stderr_bytes: int,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    outcome: PrivateAnalysisOutcome,
) -> PrivateAnalysisSubprocessTranscript:
    return PrivateAnalysisSubprocessTranscript(
        request_digest=request.request_digest,
        catalog_digest=catalog.catalog_digest,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=request.runner.configuration_digest,
        launch_configuration_digest=launch_configuration.configuration_digest,
        run_digest=run_digest,
        message_count=accumulator.message_count,
        tool_call_count=accumulator.tool_call_count,
        message_metadata_bytes=accumulator.metadata_bytes,
        message_chain_digest=accumulator.chain_digest,
        stderr_bytes=stderr_bytes,
        evidence_ledger_digest=evidence_snapshot_digest(references),
        budget_state=budget_state,
        outcome_digest=outcome.outcome_digest,
    )


def _deadline_checked_execution_receipt(
    *,
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    instruction_profile_digest: str,
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    run_digest: str,
    accumulator: _SubprocessTranscriptAccumulator,
    stderr_bytes: int,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    deadline_ns: int,
) -> PrivateAnalysisSubprocessExecutionReceipt:
    transcript = _sealed_subprocess_transcript(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        launch_configuration=launch_configuration,
        run_digest=run_digest,
        accumulator=accumulator,
        stderr_bytes=stderr_bytes,
        references=references,
        budget_state=budget_state,
        outcome=outcome,
    )
    receipt = PrivateAnalysisSubprocessExecutionReceipt(
        outcome=outcome,
        transcript=transcript,
        disclosed_references=references,
        budget_state=budget_state,
    )
    if _is_timeout_outcome(outcome) or not private_analysis_deadline_expired(
        deadline_ns
    ):
        return receipt
    timeout_outcome = private_analysis_error_outcome(
        _static_runner_error(
            request,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    )
    timeout_transcript = _sealed_subprocess_transcript(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        launch_configuration=launch_configuration,
        run_digest=run_digest,
        accumulator=accumulator,
        stderr_bytes=stderr_bytes,
        references=references,
        budget_state=budget_state,
        outcome=timeout_outcome,
    )
    return PrivateAnalysisSubprocessExecutionReceipt(
        outcome=timeout_outcome,
        transcript=timeout_transcript,
        disclosed_references=references,
        budget_state=budget_state,
    )


def _standalone_subprocess_receipt(
    *,
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    instruction_profile_digest: str,
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    run_digest: str,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
) -> PrivateAnalysisSubprocessExecutionReceipt:
    accumulator = _SubprocessTranscriptAccumulator(
        request_digest=request.request_digest,
        catalog_digest=catalog.catalog_digest,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=request.runner.configuration_digest,
        launch_configuration_digest=launch_configuration.configuration_digest,
        run_digest=run_digest,
    )
    transcript = _sealed_subprocess_transcript(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        launch_configuration=launch_configuration,
        run_digest=run_digest,
        accumulator=accumulator,
        stderr_bytes=0,
        references=references,
        budget_state=budget_state,
        outcome=outcome,
    )
    return PrivateAnalysisSubprocessExecutionReceipt(
        outcome=outcome,
        transcript=transcript,
        disclosed_references=references,
        budget_state=budget_state,
    )


def _deadline_checked_standalone_subprocess_receipt(
    *,
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    instruction_profile_digest: str,
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    run_digest: str,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    deadline_ns: int,
) -> PrivateAnalysisSubprocessExecutionReceipt:
    receipt = _standalone_subprocess_receipt(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        launch_configuration=launch_configuration,
        run_digest=run_digest,
        outcome=outcome,
        references=references,
        budget_state=budget_state,
    )
    if _is_timeout_outcome(outcome) or not private_analysis_deadline_expired(
        deadline_ns
    ):
        return receipt
    timeout_outcome = private_analysis_error_outcome(
        _static_runner_error(
            request,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    )
    return _standalone_subprocess_receipt(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        launch_configuration=launch_configuration,
        run_digest=run_digest,
        outcome=timeout_outcome,
        references=references,
        budget_state=budget_state,
    )


__all__ = [
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARGV_ITEMS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARG_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_COMMAND_UTF16_UNITS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_ITEMS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES",
    "PRIVATE_ANALYSIS_SUBPROCESS_LAUNCH_VERSION",
    "PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION",
    "ConfiguredPrivateAnalysisSubprocessRunner",
    "PrivateAnalysisSubprocessExecutionReceipt",
    "PrivateAnalysisSubprocessLaunchConfiguration",
    "PrivateAnalysisSubprocessTranscript",
    "private_analysis_subprocess_run_digest",
]

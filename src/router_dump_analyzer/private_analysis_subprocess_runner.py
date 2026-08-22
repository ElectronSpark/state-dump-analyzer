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

import hashlib
import os
import queue
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from threading import Event, Lock, Thread
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
from .private_analysis_factory_process import (
    PrivateAnalysisRemoteToolRunLease,
    PrivateAnalysisRemoteToolService,
)
from .private_analysis_runner_support import (
    MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES,
    MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES,
    PrivateAnalysisAccountingObserver,
    PrivateAnalysisCancellationProbe,
    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
    PrivateAnalysisRunAccountingSnapshot,
    PrivateAnalysisRunnerExecutionOwner,
    PrivateAnalysisTranscriptSummary,
    detached_private_analysis_budget_state,
    detached_private_analysis_error,
    detached_private_analysis_transcript_summary,
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
    "router_dump_analyzer.private_analysis.subprocess_launch.v2"
)
PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.subprocess_transcript.v1"
)
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARGV_ITEMS: Final = 128
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARG_BYTES: Final = 32_768
MAX_PRIVATE_ANALYSIS_SUBPROCESS_COMMAND_UTF16_UNITS: Final = 30_000
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_ITEMS: Final = 256
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_BYTES: Final[int] = 256 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_HELPER_ARTIFACTS: Final = 128
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_BYTES: Final[int] = 512 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_TOTAL_BYTES: Final[int] = 1024 * 1024 * 1024
MIN_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS: Final = 10
MAX_PRIVATE_ANALYSIS_SUBPROCESS_REAP_GRACE_MS: Final = 10_000
PRIVATE_ANALYSIS_SUBPROCESS_CANCELLATION_POLL_MS: Final = 50

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_STOP_PUMP: Final = object()
_FINISH_PUMP: Final = object()
_EXECUTABLE_ATTESTATION_SCHEMA: Final = (
    b"router_dump_analyzer.private_analysis.subprocess_artifacts.v1\0"
)
_ARTIFACT_READ_CHUNK_BYTES: Final = 1024 * 1024


class _PrivateAnalysisSubprocessArtifactChanged(RuntimeError):
    """A registered local executable artifact no longer matches its seal."""


class _PrivateAnalysisSubprocessAttestationInterrupted(RuntimeError):
    """A bounded executable-artifact scan observed cancellation or timeout."""


class PrivateAnalysisSubprocessCleanupPending(RuntimeError):
    """Local child cleanup or its exact receipt requires bounded retry."""


@dataclass(frozen=True, slots=True, repr=False)
class _ExecutableArtifactAttestation:
    digest: str
    file_identities: tuple[tuple[int, int, int, int, int], ...]
    total_bytes: int


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


def _artifact_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return stable same-host metadata used to detect replacement or touching."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _artifact_handle_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int]:
    """Normalize platform-specific handle permission reporting for race checks."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(stat.S_IFMT(value.st_mode)),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _argument_regular_file_keys(
    argument: str,
    working_directory: str,
) -> tuple[str, ...]:
    """Return canonical existing file operands encoded by one argv item."""

    candidates = [argument]
    if argument.startswith("-") and "=" in argument:
        candidates.append(argument.split("=", maxsplit=1)[1])
    keys: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute():
            path = Path(working_directory) / path
        try:
            candidate_stat = os.stat(path, follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(candidate_stat.st_mode):
            keys.append(os.path.normcase(os.path.normpath(str(path))))
    return tuple(keys)


def _validate_argument_artifact_coverage(
    argv: tuple[str, ...],
    working_directory: str,
    helper_artifacts: tuple[str, ...],
    runtime_data_indices: set[int],
) -> None:
    """Require every observable argv file to be attested or declared as data."""

    helper_keys = {
        os.path.normcase(os.path.normpath(value)) for value in helper_artifacts
    }
    for index, argument in enumerate(argv[1:], start=1):
        file_keys = _argument_regular_file_keys(argument, working_directory)
        if index in runtime_data_indices:
            if any(key in helper_keys for key in file_keys):
                raise ValueError(
                    "runtime data arguments cannot name attested helper artifacts"
                )
            continue
        if any(key not in helper_keys for key in file_keys):
            raise ValueError(
                "every subprocess argv file must be an attested helper artifact "
                "or explicitly declared runtime data"
            )
        argument_key = os.path.normcase(os.path.normpath(argument))
        if not argument.startswith("-") and argument_key not in helper_keys:
            raise ValueError(
                "every non-option subprocess argument must be an attested "
                "helper artifact or explicitly declared runtime data"
            )


_DYNAMIC_EXECUTION_FLAGS = frozenset({"c", "m"})
_NO_VALUE_SHORT_OPTIONS = frozenset("bBdEhiIOPqRsSuvVx?")
_VALUE_SHORT_OPTIONS = frozenset({"W", "X"})
_NO_VALUE_LONG_OPTIONS = frozenset(
    {
        "--help",
        "--help-all",
        "--help-env",
        "--help-xoptions",
        "--version",
    }
)
_SEPARATED_VALUE_LONG_OPTIONS = frozenset({"--check-hash-based-pycs"})
_LONG_OPTION_NAME = re.compile(r"--[A-Za-z][A-Za-z0-9-]*\Z")


def _is_exact_helper_operand(argument: str, helper_keys: set[str]) -> bool:
    """Return whether one direct operand names a declared helper exactly."""

    if argument.startswith("-"):
        return False
    argument_key = os.path.normcase(os.path.normpath(argument))
    return argument_key in helper_keys


def _short_option_requires_separated_value(argument: str) -> bool:
    """Validate one supported short-option cluster and classify its value."""

    short_options = argument[1:]
    if not short_options:
        raise ValueError(
            "subprocess launcher-control prefix contains an ambiguous operand"
        )
    for index, option in enumerate(short_options):
        if option in _DYNAMIC_EXECUTION_FLAGS:
            raise ValueError(
                "inline or module execution cannot provide exact artifact attestation"
            )
        if option in _NO_VALUE_SHORT_OPTIONS:
            continue
        if option in _VALUE_SHORT_OPTIONS:
            return index == len(short_options) - 1
        raise ValueError(
            "subprocess launcher-control prefix contains an unsupported "
            "or ambiguous option"
        )
    return False


def _validate_dynamic_execution_mode(
    argv: tuple[str, ...],
    _working_directory: str,
    helper_artifacts: tuple[str, ...],
) -> None:
    """Parse the launcher-control prefix without relying on executable names.

    Only supported switch-only flags and unambiguous attached/separated value
    options are admitted.  ``--`` and an exact direct helper operand terminate
    launcher option parsing; a helper consumed as an option value does not.
    """

    helper_keys = {
        os.path.normcase(os.path.normpath(value)) for value in helper_artifacts
    }
    consume_separated_value = False
    for argument in argv[1:]:
        if consume_separated_value:
            consume_separated_value = False
            continue
        if argument == "--":
            return
        if _is_exact_helper_operand(argument, helper_keys):
            return
        if not argument.startswith("-"):
            raise ValueError(
                "subprocess launcher-control prefix contains an ambiguous operand"
            )
        if argument.startswith("--"):
            if argument in _NO_VALUE_LONG_OPTIONS:
                continue
            if argument in _SEPARATED_VALUE_LONG_OPTIONS:
                consume_separated_value = True
                continue
            option_name, separator, _value = argument.partition("=")
            if separator and _LONG_OPTION_NAME.fullmatch(option_name) is not None:
                continue
            raise ValueError(
                "subprocess launcher-control prefix contains an unsupported "
                "or ambiguous option"
            )
        consume_separated_value = _short_option_requires_separated_value(argument)
    if consume_separated_value:
        raise ValueError(
            "subprocess launcher-control prefix ends before an option value"
        )


def _validate_launch_argument_contract(
    argv: tuple[str, ...],
    working_directory: str,
    helper_artifacts: tuple[str, ...],
    runtime_data_indices: set[int],
) -> None:
    """Validate argv artifact classification and execution-mode safety."""

    _validate_argument_artifact_coverage(
        argv,
        working_directory,
        helper_artifacts,
        runtime_data_indices,
    )
    _validate_dynamic_execution_mode(
        argv,
        working_directory,
        helper_artifacts,
    )


def _attest_executable_artifacts(
    executable: str,
    helper_artifacts: tuple[str, ...],
    *,
    continue_attestation: Callable[[], bool] | None = None,
) -> _ExecutableArtifactAttestation:
    """Content-address bounded executable inputs without retaining their bytes."""

    paths = (executable, *helper_artifacts)
    digest = hashlib.sha256()
    digest.update(_EXECUTABLE_ATTESTATION_SCHEMA)
    identities: list[tuple[int, int, int, int, int]] = []
    total_bytes = 0
    for index, raw_path in enumerate(paths):
        if continue_attestation is not None and not continue_attestation():
            raise _PrivateAnalysisSubprocessAttestationInterrupted(
                "private-analysis executable attestation was interrupted"
            )
        try:
            path_stat = os.stat(raw_path, follow_symlinks=False)
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
                raise _PrivateAnalysisSubprocessArtifactChanged(
                    "private-analysis executable artifact is not a regular file"
                )
            file_hash = hashlib.sha256()
            with open(raw_path, "rb", buffering=0) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise _PrivateAnalysisSubprocessArtifactChanged(
                        "private-analysis executable artifact is not a regular file"
                    )
                artifact_bytes = 0
                while True:
                    if continue_attestation is not None and not continue_attestation():
                        raise _PrivateAnalysisSubprocessAttestationInterrupted(
                            "private-analysis executable attestation was interrupted"
                        )
                    chunk = stream.read(_ARTIFACT_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    artifact_bytes += len(chunk)
                    total_bytes += len(chunk)
                    if artifact_bytes > MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_BYTES:
                        raise _PrivateAnalysisSubprocessArtifactChanged(
                            "private-analysis executable artifact exceeds its byte limit"
                        )
                    if total_bytes > (
                        MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_TOTAL_BYTES
                    ):
                        raise _PrivateAnalysisSubprocessArtifactChanged(
                            "private-analysis executable artifacts exceed their byte limit"
                        )
                    file_hash.update(chunk)
                after = os.fstat(stream.fileno())
            final_path_stat = os.stat(raw_path, follow_symlinks=False)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except _PrivateAnalysisSubprocessAttestationInterrupted:
            raise
        except _PrivateAnalysisSubprocessArtifactChanged:
            raise
        except (OSError, ValueError) as error:
            raise _PrivateAnalysisSubprocessArtifactChanged(
                "private-analysis executable artifact cannot be attested"
            ) from error
        identity = _artifact_file_identity(path_stat)
        if (
            _artifact_handle_identity(before) != _artifact_handle_identity(after)
            or _artifact_handle_identity(before) != _artifact_handle_identity(path_stat)
            or identity != _artifact_file_identity(final_path_stat)
            or artifact_bytes != before.st_size
        ):
            raise _PrivateAnalysisSubprocessArtifactChanged(
                "private-analysis executable artifact changed while being attested"
            )
        identities.append(identity)
        digest.update(index.to_bytes(4, "big"))
        canonical_path = os.path.normcase(os.path.abspath(raw_path)).encode("utf-8")
        digest.update(len(canonical_path).to_bytes(4, "big"))
        digest.update(canonical_path)
        digest.update(identity[2].to_bytes(8, "big", signed=False))
        digest.update(identity[3].to_bytes(8, "big", signed=False))
        digest.update(file_hash.digest())
    if continue_attestation is not None and not continue_attestation():
        raise _PrivateAnalysisSubprocessAttestationInterrupted(
            "private-analysis executable attestation was interrupted"
        )
    return _ExecutableArtifactAttestation(
        digest="sha256:" + digest.hexdigest(),
        file_identities=tuple(identities),
        total_bytes=total_bytes,
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
    helper_artifacts: tuple[str, ...] = ()
    runtime_data_argument_indices: tuple[int, ...] = ()
    executable_artifact_digest: str = field(init=False, repr=False)
    _artifact_attestation: _ExecutableArtifactAttestation = field(
        init=False,
        repr=False,
        compare=False,
    )

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

        if (
            type(self.helper_artifacts) is not tuple
            or len(self.helper_artifacts)
            > MAX_PRIVATE_ANALYSIS_SUBPROCESS_HELPER_ARTIFACTS
        ):
            raise ValueError("subprocess helper_artifacts must be a bounded tuple")
        helper_artifacts: list[str] = []
        helper_keys: set[str] = set()
        executable_key = os.path.normcase(os.path.normpath(argv[0]))
        for raw_helper in self.helper_artifacts:
            helper = _bounded_scalar_text(
                raw_helper,
                "subprocess helper artifact",
                maximum_bytes=16_384,
            )
            helper_path = Path(helper)
            if not helper_path.is_absolute():
                raise ValueError("subprocess helper artifacts must use absolute paths")
            _reject_win32_normalization_ambiguous_path(
                helper,
                "subprocess helper artifact",
            )
            helper_key = os.path.normcase(os.path.normpath(helper))
            if helper_key == executable_key or helper_key in helper_keys:
                raise ValueError("subprocess executable artifacts must be unique")
            helper_keys.add(helper_key)
            helper_artifacts.append(helper)
        normalized_helpers = tuple(helper_artifacts)

        if type(self.runtime_data_argument_indices) is not tuple:
            raise ValueError(
                "runtime_data_argument_indices must be a bounded integer tuple"
            )
        runtime_data_indices: set[int] = set()
        for index in self.runtime_data_argument_indices:
            if (
                type(index) is not int
                or not 1 <= index < len(argv)
                or index in runtime_data_indices
            ):
                raise ValueError(
                    "runtime_data_argument_indices must contain unique argv indices"
                )
            runtime_data_indices.add(index)
        _validate_launch_argument_contract(
            argv,
            working_directory,
            normalized_helpers,
            runtime_data_indices,
        )
        artifact_attestation = _attest_executable_artifacts(
            argv[0],
            normalized_helpers,
        )

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
        object.__setattr__(self, "helper_artifacts", normalized_helpers)
        object.__setattr__(
            self,
            "runtime_data_argument_indices",
            tuple(sorted(runtime_data_indices)),
        )
        object.__setattr__(
            self,
            "executable_artifact_digest",
            artifact_attestation.digest,
        )
        object.__setattr__(self, "_artifact_attestation", artifact_attestation)
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

    def revalidate_executable_artifacts(
        self,
        *,
        continue_attestation: Callable[[], bool] | None = None,
    ) -> None:
        """Fail closed unless the executable byte/metadata seal still matches."""

        try:
            _validate_launch_argument_contract(
                self.argv,
                self.working_directory,
                self.helper_artifacts,
                set(self.runtime_data_argument_indices),
            )
        except ValueError as error:
            raise _PrivateAnalysisSubprocessArtifactChanged(
                "private-analysis argv artifact coverage changed"
            ) from error
        current = _attest_executable_artifacts(
            self.argv[0],
            self.helper_artifacts,
            continue_attestation=continue_attestation,
        )
        if current != self._artifact_attestation:
            raise _PrivateAnalysisSubprocessArtifactChanged(
                "private-analysis executable artifact identity changed"
            )
        try:
            _validate_launch_argument_contract(
                self.argv,
                self.working_directory,
                self.helper_artifacts,
                set(self.runtime_data_argument_indices),
            )
        except ValueError as error:
            raise _PrivateAnalysisSubprocessArtifactChanged(
                "private-analysis argv artifact coverage changed"
            ) from error

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisSubprocessLaunchConfiguration("
            f"argument_count={len(self.argv)}, "
            f"environment_count={len(self.environment)}, "
            f"helper_artifact_count={len(self.helper_artifacts)}, "
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
        "executable_artifact_digest": value.executable_artifact_digest,
        "helper_artifact_count": len(value.helper_artifacts),
        "helper_artifacts": list(value.helper_artifacts),
        "runtime_data_argument_indices": list(value.runtime_data_argument_indices),
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


def _subprocess_transcript_summary(
    value: PrivateAnalysisSubprocessTranscript,
) -> PrivateAnalysisTranscriptSummary:
    """Project one sealed child transcript into the shared payload-free contract."""

    transcript = _detached_subprocess_transcript(value)
    return PrivateAnalysisTranscriptSummary(
        transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
        request_digest=transcript.request_digest,
        catalog_digest=transcript.catalog_digest,
        instruction_profile_digest=transcript.instruction_profile_digest,
        runner_configuration_digest=transcript.runner_configuration_digest,
        outcome_digest=transcript.outcome_digest,
        evidence_ledger_digest=transcript.evidence_ledger_digest,
        budget_state=transcript.budget_state,
        metadata=PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
            transcript_digest=transcript.transcript_digest,
            launch_configuration_digest=transcript.launch_configuration_digest,
            run_digest=transcript.run_digest,
            message_count=transcript.message_count,
            tool_call_count=transcript.tool_call_count,
            message_metadata_bytes=transcript.message_metadata_bytes,
            message_chain_digest=transcript.message_chain_digest,
            stderr_bytes=transcript.stderr_bytes,
        ),
    )


class PrivateAnalysisSubprocessExecutionReceipt:
    """Detached internal result of one shell-free local-child execution."""

    __slots__ = (
        "_budget",
        "_cancellation_attested",
        "_outcome_json",
        "_references",
        "_transcript",
        "_transcript_summary",
    )

    def __init__(
        self,
        *,
        outcome: PrivateAnalysisOutcome,
        transcript: PrivateAnalysisSubprocessTranscript,
        disclosed_references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
        cancellation_attested: bool = False,
    ) -> None:
        if type(transcript) is not PrivateAnalysisSubprocessTranscript:
            raise TypeError("transcript must be PrivateAnalysisSubprocessTranscript")
        detached_transcript = _detached_subprocess_transcript(transcript)
        if type(cancellation_attested) is not bool:
            raise TypeError("cancellation_attested must be a boolean")
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
        self._cancellation_attested = cancellation_attested
        self._transcript_summary = _subprocess_transcript_summary(detached_transcript)

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

    @property
    def transcript_summary(self) -> PrivateAnalysisTranscriptSummary:
        """Return a detached transport-neutral transcript summary."""

        return detached_private_analysis_transcript_summary(self._transcript_summary)

    @property
    def cancellation_attested(self) -> bool:
        """Return whether direct-child and helper cleanup completed."""

        return self._cancellation_attested

    def _with_cleanup_attested(self) -> PrivateAnalysisSubprocessExecutionReceipt:
        """Reseal a withheld receipt after its owned child is confirmed stopped."""

        if self._cancellation_attested:
            return self
        return PrivateAnalysisSubprocessExecutionReceipt(
            outcome=self.outcome,
            transcript=self._transcript,
            disclosed_references=self._references,
            budget_state=self._budget,
            cancellation_attested=True,
        )

    def as_cancelled(self) -> PrivateAnalysisSubprocessExecutionReceipt:
        """Reseal this receipt as cancelled after attested transport cleanup."""

        if not self._cancellation_attested:
            raise RuntimeError(
                "subprocess receipt cannot be cancelled without cleanup attestation"
            )
        cancelled_outcome = private_analysis_error_outcome(
            private_analysis_error(
                self._transcript.request_digest,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.CANCELLED,
            )
        )
        transcript = self._transcript
        cancelled_transcript = PrivateAnalysisSubprocessTranscript(
            request_digest=transcript.request_digest,
            catalog_digest=transcript.catalog_digest,
            instruction_profile_digest=transcript.instruction_profile_digest,
            runner_configuration_digest=transcript.runner_configuration_digest,
            launch_configuration_digest=transcript.launch_configuration_digest,
            run_digest=transcript.run_digest,
            message_count=transcript.message_count,
            tool_call_count=transcript.tool_call_count,
            message_metadata_bytes=transcript.message_metadata_bytes,
            message_chain_digest=transcript.message_chain_digest,
            stderr_bytes=transcript.stderr_bytes,
            evidence_ledger_digest=transcript.evidence_ledger_digest,
            budget_state=transcript.budget_state,
            outcome_digest=cancelled_outcome.outcome_digest,
            contract_version=transcript.contract_version,
        )
        return PrivateAnalysisSubprocessExecutionReceipt(
            outcome=cancelled_outcome,
            transcript=cancelled_transcript,
            disclosed_references=self._references,
            budget_state=self._budget,
            cancellation_attested=True,
        )

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
    CANCELLED = "cancelled"


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


class _CancellationState:
    """Memoized, strictly typed view of one external cancellation probe."""

    __slots__ = ("_probe", "_requested")

    def __init__(self, probe: PrivateAnalysisCancellationProbe | None) -> None:
        self._probe = probe
        self._requested = False

    @property
    def requested(self) -> bool:
        return self._requested

    def poll(self) -> bool:
        if self._requested:
            return True
        if self._probe is None:
            return False
        value = self._probe()
        if type(value) is not bool:
            raise TypeError("cancellation_probe must return a boolean")
        self._requested = value
        return value


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
        "_cancellation",
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
        cancellation: _CancellationState,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("subprocess standard streams were not created")
        self._process = process
        self._configuration = configuration
        self._cancellation = cancellation
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

    def start(self) -> None:
        """Start helpers after the caller has retained this exact session.

        A thread start can fail after the helper became live.  Mark each start
        as attempted first so cleanup treats an uninspectable helper as owned,
        and let the caller's single finalizer perform the bounded cleanup.
        """

        self._pump_started = True
        self._pump.start()
        self._stderr_started = True
        self._stderr.start()

    @property
    def stderr_bytes(self) -> int:
        return self._stderr_state.admitted_bytes

    @property
    def stderr_failed(self) -> bool:
        return self._stderr_state.overflowed or self._stderr_state.io_failed

    @property
    def cancellation_requested(self) -> bool:
        return self._cancellation.requested

    def exchange(self, frame: bytes, deadline_ns: int) -> _PumpEvent | None:
        if not self._put_command(_PumpCommand(frame=frame), deadline_ns):
            return (
                _PumpEvent(_PumpEventKind.CANCELLED)
                if self._cancellation.requested
                else None
            )
        return self._wait_event(deadline_ns)

    def finish(self, deadline_ns: int) -> _PumpEvent | None:
        if not self._put_command(_PumpCommand(finish=True), deadline_ns):
            return (
                _PumpEvent(_PumpEventKind.CANCELLED)
                if self._cancellation.requested
                else None
            )
        return self._wait_event(deadline_ns)

    def wait_for_exit(self, deadline_ns: int) -> int | None:
        while True:
            remaining = deadline_ns - monotonic_ns()
            if remaining <= 0:
                return None
            if self._cancellation.poll():
                return None
            wait_ns = min(
                remaining,
                PRIVATE_ANALYSIS_SUBPROCESS_CANCELLATION_POLL_MS * 1_000_000,
            )
            try:
                return self._process.wait(timeout=wait_ns / 1_000_000_000)
            except subprocess.TimeoutExpired:
                continue

    def _put_command(self, command: _PumpCommand, deadline_ns: int) -> bool:
        while True:
            remaining = deadline_ns - monotonic_ns()
            if remaining <= 0:
                return False
            if self._cancellation.poll():
                return False
            wait_ns = min(
                remaining,
                PRIVATE_ANALYSIS_SUBPROCESS_CANCELLATION_POLL_MS * 1_000_000,
            )
            try:
                self._commands.put(command, timeout=wait_ns / 1_000_000_000)
            except queue.Full:
                continue
            return True

    def _wait_event(self, deadline_ns: int) -> _PumpEvent | None:
        while True:
            remaining = deadline_ns - monotonic_ns()
            if remaining <= 0:
                return None
            if self._cancellation.poll():
                return _PumpEvent(_PumpEventKind.CANCELLED)
            wait_ns = min(
                remaining,
                PRIVATE_ANALYSIS_SUBPROCESS_CANCELLATION_POLL_MS * 1_000_000,
            )
            try:
                return self._events.get(timeout=wait_ns / 1_000_000_000)
            except queue.Empty:
                continue

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
        # Closing stdin first prevents a blocked peer from waiting for more
        # protocol input while bounded terminate/kill/reap cleanup proceeds.
        _close_cleanup_stream(self._process.stdin, state)
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

    def cleanup_authority_required(self) -> bool:
        """Return whether this live object still owns child/thread cleanup.

        This deliberately treats an uninspectable process or helper thread as
        live.  Cleanup authority may be released only after direct observation
        that the child and both non-daemon helpers stopped.
        """

        if not _process_exit_confirmed(self._process):
            return True
        for started, thread in (
            (self._pump_started, self._pump),
            (self._stderr_started, self._stderr),
        ):
            if not started:
                continue
            try:
                if thread.is_alive():
                    return True
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001 - unknown means still owned.
                return True
        return False


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


def _is_cancelled_outcome(outcome: PrivateAnalysisOutcome) -> bool:
    return (
        outcome.kind is PrivateAnalysisOutcomeKind.ERROR
        and outcome.error is not None
        and outcome.error.code is PrivateAnalysisErrorCode.CANCELLED
    )


def _access_or_deadline_error(
    lease: PrivateAnalysisToolRunLease | PrivateAnalysisRemoteToolRunLease,
    request: PrivateAnalysisRequest,
    deadline_ns: int,
) -> PrivateAnalysisError | None:
    return private_analysis_run_access_error(
        cast(PrivateAnalysisToolRunLease, lease),
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


def _process_exit_confirmed(process: subprocess.Popen[bytes]) -> bool:
    """Observe direct-child exit without converting uncertainty into success."""

    try:
        return process.poll() is not None
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - an uninspectable handle remains owned.
        return False


@dataclass(slots=True)
class _DeferredSubprocessReceipt:
    """Receipt-capable state retained when process control interrupts sealing."""

    request: PrivateAnalysisRequest
    catalog: PrivateAnalysisToolCatalog
    instruction_profile_digest: str
    launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration
    run_digest: str
    accumulator: _SubprocessTranscriptAccumulator
    stderr_bytes: int
    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState

    def seal(self) -> PrivateAnalysisSubprocessExecutionReceipt:
        outcome = private_analysis_error_outcome(
            _static_runner_error(
                self.request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        )
        transcript = _sealed_subprocess_transcript(
            request=self.request,
            catalog=self.catalog,
            instruction_profile_digest=self.instruction_profile_digest,
            launch_configuration=self.launch_configuration,
            run_digest=self.run_digest,
            accumulator=self.accumulator,
            stderr_bytes=self.stderr_bytes,
            references=self.references,
            budget_state=self.budget_state,
            outcome=outcome,
        )
        return PrivateAnalysisSubprocessExecutionReceipt(
            outcome=outcome,
            transcript=transcript,
            disclosed_references=self.references,
            budget_state=self.budget_state,
            cancellation_attested=True,
        )


@dataclass(slots=True)
class _PendingLocalChildCleanup:
    """Same-process child authority or receipt state awaiting durable handoff."""

    configuration: PrivateAnalysisSubprocessLaunchConfiguration
    session: _LocalChildSession | None = None
    process: subprocess.Popen[bytes] | None = None
    receipt: PrivateAnalysisSubprocessExecutionReceipt | None = None
    deferred_receipt: _DeferredSubprocessReceipt | None = None
    retry_lock: Lock = field(default_factory=Lock)

    def __post_init__(self) -> None:
        if (self.session is None) == (self.process is None):
            raise ValueError("pending cleanup requires exactly one live owner")

    def authority_required(self) -> bool:
        if self.session is not None:
            return self.session.cleanup_authority_required()
        if self.process is None:
            raise RuntimeError("pending subprocess cleanup lost its child handle")
        return not _process_exit_confirmed(self.process)

    def cleanup(self) -> bool:
        if self.session is not None:
            return self.session.cleanup()
        if self.process is None:
            raise RuntimeError("pending subprocess cleanup lost its child handle")
        return _reap_unmanaged_child(self.process, self.configuration)


@dataclass(slots=True)
class _LocalChildCleanupOwner:
    """Cleanup state shared by every detached view of one configured runner."""

    lock: Lock = field(default_factory=Lock)
    pending: _PendingLocalChildCleanup | None = None


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
    if event.kind is _PumpEventKind.CANCELLED:
        return None, PrivateAnalysisErrorCode.CANCELLED
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
    if event.kind is _PumpEventKind.CANCELLED:
        return PrivateAnalysisErrorCode.CANCELLED
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
        return (
            PrivateAnalysisErrorCode.CANCELLED
            if session.cancellation_requested
            else PrivateAnalysisErrorCode.TIMEOUT
        )
    if return_code != 0:
        return PrivateAnalysisErrorCode.RUNNER_FAILED
    return None


class ConfiguredPrivateAnalysisSubprocessRunner(PrivateAnalysisRunnerExecutionOwner):
    """Run one request through an exact, shell-free direct-child adapter."""

    __slots__ = ("_cleanup_owner", "_launch_configuration")

    def __init__(
        self,
        selection: PrivateAnalysisRunnerSelection,
        *,
        instruction_profile_digest: str,
        launch_configuration: PrivateAnalysisSubprocessLaunchConfiguration,
    ) -> None:
        super().__init__(
            selection,
            instruction_profile_digest=instruction_profile_digest,
        )
        if self._selection.transport is not PrivateAnalysisTransport.LOCAL_SUBPROCESS:
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
            helper_artifacts=launch_configuration.helper_artifacts,
            runtime_data_argument_indices=(
                launch_configuration.runtime_data_argument_indices
            ),
            stderr_limit_bytes=launch_configuration.stderr_limit_bytes,
            terminate_grace_ms=launch_configuration.terminate_grace_ms,
            kill_grace_ms=launch_configuration.kill_grace_ms,
            contract_version=launch_configuration.contract_version,
            configuration_digest=launch_configuration.configuration_digest,
        )
        if self._selection.configuration_digest != private_launch.configuration_digest:
            raise ValueError("runner selection does not bind the launch configuration")
        self._launch_configuration = private_launch
        self._cleanup_owner = _LocalChildCleanupOwner()

    def detached(self) -> ConfiguredPrivateAnalysisSubprocessRunner:
        """Return an independently sealed runner for an owning registration."""

        detached = ConfiguredPrivateAnalysisSubprocessRunner(
            self.selection,
            instruction_profile_digest=self.instruction_profile_digest,
            launch_configuration=self._launch_configuration,
        )
        # Independent launch seals remain one configured runner authority and
        # therefore share both its cross-coordinator execution gate and the
        # only live cleanup handle retained after a failed bounded reap.
        detached._private_analysis_execution_lock = self.execution_lock
        detached._cleanup_owner = self._cleanup_owner
        return detached

    @property
    def cleanup_pending(self) -> bool:
        """Return whether child cleanup or receipt handoff remains pending."""

        with self._cleanup_owner.lock:
            return self._cleanup_owner.pending is not None

    def _retain_pending_cleanup(
        self,
        *,
        session: _LocalChildSession | None = None,
        process: subprocess.Popen[bytes] | None = None,
    ) -> _PendingLocalChildCleanup:
        pending = _PendingLocalChildCleanup(
            configuration=self._launch_configuration,
            session=session,
            process=process,
        )
        with self._cleanup_owner.lock:
            if self._cleanup_owner.pending is not None:
                raise RuntimeError("subprocess cleanup ownership already exists")
            self._cleanup_owner.pending = pending
        return pending

    def _attach_pending_receipt(
        self,
        pending: _PendingLocalChildCleanup,
        receipt: PrivateAnalysisSubprocessExecutionReceipt,
    ) -> None:
        with self._cleanup_owner.lock:
            if self._cleanup_owner.pending is not pending:
                raise RuntimeError("subprocess cleanup ownership changed")
            pending.receipt = receipt

    def _attach_deferred_receipt(
        self,
        pending: _PendingLocalChildCleanup,
        receipt: _DeferredSubprocessReceipt,
    ) -> None:
        with self._cleanup_owner.lock:
            if self._cleanup_owner.pending is not pending:
                raise RuntimeError("subprocess cleanup ownership changed")
            if pending.receipt is not None or pending.deferred_receipt is not None:
                raise RuntimeError("subprocess cleanup receipt already exists")
            pending.deferred_receipt = receipt

    def retry_pending_cleanup(
        self,
    ) -> tuple[bool, PrivateAnalysisSubprocessExecutionReceipt | None]:
        """Perform one bounded retry using the retained direct-child handle.

        ``False`` means the same live handle remains owned.  ``True`` means no
        process or helper cleanup authority remains; the optional receipt is
        the result that was deliberately withheld while the child was live.
        """

        with self._cleanup_owner.lock:
            pending = self._cleanup_owner.pending
        if pending is None:
            return True, None
        if not pending.retry_lock.acquire(blocking=False):
            return False, None
        try:
            try:
                pending.cleanup()
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001, S110 - inspect authority below.
                pass
            if pending.authority_required():
                return False, None
            receipt = pending.receipt
            if receipt is None and pending.deferred_receipt is not None:
                receipt = pending.deferred_receipt.seal()
                pending.receipt = receipt
                pending.deferred_receipt = None
            return (
                True,
                None if receipt is None else receipt._with_cleanup_attested(),
            )
        finally:
            pending.retry_lock.release()

    def acknowledge_pending_cleanup(self) -> None:
        """Release a reaped child journal after coordinator terminal handoff."""

        with self._cleanup_owner.lock:
            pending = self._cleanup_owner.pending
        if pending is None:
            return
        if not pending.retry_lock.acquire(blocking=False):
            raise RuntimeError("subprocess cleanup handoff is already active")
        try:
            if pending.authority_required():
                raise RuntimeError("subprocess cleanup authority is still required")
            with self._cleanup_owner.lock:
                if self._cleanup_owner.pending is not pending:
                    raise RuntimeError("subprocess cleanup ownership changed")
                self._cleanup_owner.pending = None
        finally:
            pending.retry_lock.release()

    def execute(
        self,
        tool_service: PrivateAnalysisToolService | PrivateAnalysisRemoteToolService,
        *,
        accounting_observer: PrivateAnalysisAccountingObserver | None = None,
        cancellation_probe: PrivateAnalysisCancellationProbe | None = None,
        absolute_deadline_ns: int | None = None,
    ) -> PrivateAnalysisSubprocessExecutionReceipt:
        if self.cleanup_pending:
            raise PrivateAnalysisSubprocessCleanupPending(
                "private-analysis subprocess cleanup is pending"
            )
        if type(tool_service) not in {
            PrivateAnalysisToolService,
            PrivateAnalysisRemoteToolService,
        }:
            raise TypeError("tool_service must be a core private-analysis service")
        if accounting_observer is not None and not callable(accounting_observer):
            raise TypeError("accounting_observer must be callable or None")
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")
        cancellation = _CancellationState(cancellation_probe)
        request = tool_service.request
        now_ns = monotonic_ns()
        if absolute_deadline_ns is not None and (
            type(absolute_deadline_ns) is not int or absolute_deadline_ns < 0
        ):
            raise ValueError(
                "absolute_deadline_ns must be a non-negative integer or None"
            )
        deadline_ns = (
            now_ns + request.limits.deadline_ms * 1_000_000
            if absolute_deadline_ns is None
            else absolute_deadline_ns
        )
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
        accounting = PrivateAnalysisRunAccountingSnapshot(
            (),
            budget_state,
            observer=accounting_observer,
        )
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
        cleanup_authority_required = False
        cleanup_process_control = False
        pending_cleanup: _PendingLocalChildCleanup | None = None
        process: subprocess.Popen[bytes] | None = None

        try:
            cancellation_before_lease = cancellation.poll()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - deployment-owned probe boundary.
            cancellation_before_lease = False
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        if cancellation_before_lease:
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.CANCELLED,
            )
        if outcome_error is not None:
            return _deadline_checked_standalone_subprocess_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                launch_configuration=self._launch_configuration,
                run_digest=run_digest,
                outcome=private_analysis_error_outcome(outcome_error),
                references=(),
                budget_state=budget_state,
                deadline_ns=deadline_ns,
            )

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
                accounting.refresh(cast(PrivateAnalysisToolRunLease, lease))
                budget_state = accounting.budget_state
                outcome_error = (
                    _static_runner_error(
                        request,
                        PrivateAnalysisErrorCode.CANCELLED,
                    )
                    if cancellation.poll()
                    else _access_or_deadline_error(
                        lease,
                        request,
                        deadline_ns,
                    )
                )
                if outcome_error is None:
                    try:
                        # This is deliberately the final operation before the
                        # shell-free launch. Registration-time content identity
                        # alone cannot authorize bytes replaced in the interim.
                        self._launch_configuration.revalidate_executable_artifacts(
                            continue_attestation=lambda: (
                                not cancellation.poll()
                                and not private_analysis_deadline_expired(deadline_ns)
                            )
                        )
                        process = _spawn_local_child(self._launch_configuration)
                        session = _LocalChildSession(
                            process,
                            self._launch_configuration,
                            cancellation,
                        )
                        session.start()
                    except PROCESS_CONTROL_EXCEPTIONS:
                        if process is not None and session is None:
                            pending_cleanup = self._retain_pending_cleanup(
                                process=process
                            )
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except BaseException:  # noqa: BLE001, S110 - owner retained.
                                pass
                        raise
                    except _PrivateAnalysisSubprocessAttestationInterrupted:
                        outcome_error = _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.CANCELLED
                            if cancellation.requested
                            else PrivateAnalysisErrorCode.TIMEOUT,
                        )
                    except (
                        OSError,
                        _PrivateAnalysisSubprocessArtifactChanged,
                    ):
                        if process is not None and session is None:
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except PROCESS_CONTROL_EXCEPTIONS:
                                raise
                            except BaseException:  # noqa: BLE001
                                cleanup_succeeded = False
                            if not _process_exit_confirmed(process):
                                pending_cleanup = self._retain_pending_cleanup(
                                    process=process
                                )
                        outcome_error = _static_runner_error(
                            request,
                            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                        )
                    except BaseException:  # noqa: BLE001 - executable boundary.
                        if process is not None and session is None:
                            try:
                                cleanup_succeeded = _reap_unmanaged_child(
                                    process,
                                    self._launch_configuration,
                                )
                            except PROCESS_CONTROL_EXCEPTIONS:
                                raise
                            except BaseException:  # noqa: BLE001
                                cleanup_succeeded = False
                            if not _process_exit_confirmed(process):
                                pending_cleanup = self._retain_pending_cleanup(
                                    process=process
                                )
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
                    cleanup_succeeded = False
                    cleanup_process_control = True
                    if pending_process_control is None:
                        pending_process_control = error
                except BaseException:  # noqa: BLE001 - finalizer boundary.
                    cleanup_succeeded = False
                    finalizer_failed = True
                try:
                    cleanup_authority_required = (
                        session.cleanup_authority_required()
                    )
                except PROCESS_CONTROL_EXCEPTIONS as error:
                    cleanup_authority_required = True
                    cleanup_process_control = True
                    if pending_process_control is None:
                        pending_process_control = error
                except BaseException:  # noqa: BLE001 - uncertainty remains live.
                    cleanup_authority_required = True
                    finalizer_failed = True
                if (
                    (cleanup_process_control or cleanup_authority_required)
                    and pending_cleanup is None
                ):
                    pending_cleanup = self._retain_pending_cleanup(session=session)
                if cleanup_authority_required:
                    cleanup_succeeded = False
            try:
                accounting.refresh(cast(PrivateAnalysisToolRunLease, lease))
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

        if session is None and process is not None:
            try:
                cleanup_authority_required = not _process_exit_confirmed(process)
            except PROCESS_CONTROL_EXCEPTIONS as error:
                cleanup_authority_required = True
                if pending_process_control is None:
                    pending_process_control = error
            if cleanup_authority_required and pending_cleanup is None:
                pending_cleanup = self._retain_pending_cleanup(process=process)

        cancellation_attested = not cleanup_authority_required
        if pending_failure is not None or finalizer_failed:
            cleanup_succeeded = False

        try:
            cancellation.poll()
        except PROCESS_CONTROL_EXCEPTIONS as error:
            if pending_process_control is None:
                pending_process_control = error
        except BaseException:  # noqa: BLE001 - cancellation probe boundary.
            pending_failure = pending_failure or RuntimeError(
                "private-analysis cancellation probe failed"
            )

        references = accounting.references
        budget_state = accounting.budget_state

        if (
            not cleanup_succeeded
            or stderr_failed
            or pending_failure is not None
            or finalizer_failed
            or pending_process_control is not None
        ):
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        elif cancellation.requested:
            outcome_error = _static_runner_error(
                request,
                PrivateAnalysisErrorCode.CANCELLED,
            )
        elif private_analysis_deadline_expired(deadline_ns):
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
        if (
            not _is_timeout_outcome(outcome)
            and not _is_cancelled_outcome(outcome)
            and private_analysis_deadline_expired(deadline_ns)
        ):
            outcome = private_analysis_error_outcome(
                _static_runner_error(
                    request,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )

        try:
            receipt = _deadline_checked_execution_receipt(
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
                cancellation_attested=cancellation_attested,
            )
        except PROCESS_CONTROL_EXCEPTIONS as error:
            if session is not None:
                if pending_cleanup is None:
                    pending_cleanup = self._retain_pending_cleanup(session=session)
                self._attach_deferred_receipt(
                    pending_cleanup,
                    _DeferredSubprocessReceipt(
                        request=request,
                        catalog=catalog,
                        instruction_profile_digest=self._instruction_profile_digest,
                        launch_configuration=self._launch_configuration,
                        run_digest=run_digest,
                        accumulator=transcript,
                        stderr_bytes=stderr_bytes,
                        references=references,
                        budget_state=budget_state,
                    ),
                )
            raise error.with_traceback(error.__traceback__)
        except BaseException:  # noqa: BLE001 - receipt integrity boundary.
            fallback_code = (
                PrivateAnalysisErrorCode.TIMEOUT
                if private_analysis_deadline_expired(deadline_ns)
                else PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR
            )
            receipt = _deadline_checked_execution_receipt(
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
                cancellation_attested=cancellation_attested,
            )
        if (
            pending_cleanup is None
            and pending_process_control is not None
            and session is not None
        ):
            pending_cleanup = self._retain_pending_cleanup(session=session)
        if pending_cleanup is not None:
            self._attach_pending_receipt(pending_cleanup, receipt)
            if pending_process_control is not None:
                raise pending_process_control.with_traceback(
                    pending_process_control.__traceback__
                )
            raise PrivateAnalysisSubprocessCleanupPending(
                "private-analysis subprocess cleanup is pending"
            )
        if pending_process_control is not None:
            raise pending_process_control.with_traceback(
                pending_process_control.__traceback__
            )
        return receipt

    def _drive_protocol(
        self,
        *,
        session: _LocalChildSession,
        lease: PrivateAnalysisToolRunLease | PrivateAnalysisRemoteToolRunLease,
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
                accounting.refresh(cast(PrivateAnalysisToolRunLease, lease))
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
    cancellation_attested: bool,
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
        cancellation_attested=cancellation_attested,
    )
    if (
        _is_timeout_outcome(outcome)
        or _is_cancelled_outcome(outcome)
        or not private_analysis_deadline_expired(deadline_ns)
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
        cancellation_attested=cancellation_attested,
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
        cancellation_attested=True,
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
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ARTIFACT_TOTAL_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_COMMAND_UTF16_UNITS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_ENVIRONMENT_ITEMS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_HELPER_ARTIFACTS",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES",
    "PRIVATE_ANALYSIS_SUBPROCESS_CANCELLATION_POLL_MS",
    "PRIVATE_ANALYSIS_SUBPROCESS_LAUNCH_VERSION",
    "PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_VERSION",
    "ConfiguredPrivateAnalysisSubprocessRunner",
    "PrivateAnalysisSubprocessCleanupPending",
    "PrivateAnalysisSubprocessExecutionReceipt",
    "PrivateAnalysisSubprocessLaunchConfiguration",
    "PrivateAnalysisSubprocessTranscript",
    "private_analysis_subprocess_run_digest",
]

"""Killable process boundary for deployment-owned evidence-service factories.

The parent sends a module-level target, canonical configuration JSON, and one
canonical private-analysis request to a fixed core-owned child entry point.
The constructed service never crosses the process boundary.  It remains in
the child behind a closed canonical request/response protocol while a small
core-owned service proxy exposes the exact runner-facing surface in the
parent.
"""

from __future__ import annotations

import importlib
import json
import multiprocessing
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final
from uuid import uuid4

from .canonical import strict_canonical_json, strict_canonical_json_sha256
from .plugin_identity import executable_module_target_fingerprint
from .private_analysis._wire import reject_duplicate_json_object_pairs
from .private_analysis.contracts import (
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisRequest,
    private_analysis_error_dict,
    private_analysis_error_from_dict,
    private_analysis_request_from_json,
    private_analysis_request_json,
)
from .private_analysis.evidence import (
    EvidenceReference,
    evidence_reference_dict,
    evidence_reference_from_dict,
)
from .private_analysis.tool_catalog import (
    PrivateAnalysisToolCall,
    PrivateAnalysisToolError,
    PrivateAnalysisToolResult,
    private_analysis_tool_call_dict,
    private_analysis_tool_call_from_dict,
    private_analysis_tool_error_dict,
    private_analysis_tool_error_from_dict,
    private_analysis_tool_result_dict,
    private_analysis_tool_result_from_dict,
)
from .private_analysis_runner_support import private_analysis_budget_payload
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
    _PrivateAnalysisToolRunLeaseFacade,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

_PROTOCOL: Final = "router_dump_analyzer.private_analysis.factory_process.v1"
_MAX_CONFIGURATION_BYTES: Final = 64 * 1024
_MAX_IPC_MESSAGE_BYTES: Final = 72 * 1024 * 1024
_MAX_JSON_DEPTH: Final = 24
_MAX_JSON_CONTAINER_ITEMS: Final = 4096
_MAX_JSON_UNITS: Final = 2_000_000
_MAX_JSON_ATOM_CHARACTERS: Final = 2 * 1024 * 1024
_MAX_TARGET_CHARACTERS: Final = 512
_MAX_REAP_SECONDS: Final = 1.0


class _PrivateAnalysisFactoryProcessMessageKind(StrEnum):
    """Closed discriminator vocabulary for the canonical child protocol."""

    READY = "ready"
    EXECUTE = "execute"
    RESPONSE = "response"
    CLOSE = "close"
    CLOSED = "closed"
    FAILED = "failed"


class PrivateAnalysisFactoryProcessError(RuntimeError):
    """Base class for payload-free factory-process failures."""

    __slots__ = ("_cleanup_owner",)

    def __init__(
        self,
        message: str,
        *,
        cleanup_owner: PrivateAnalysisFactoryProcessCleanupOwner | None = None,
    ) -> None:
        super().__init__(message)
        self._cleanup_owner = cleanup_owner

    @property
    def cleanup_owner(self) -> PrivateAnalysisFactoryProcessCleanupOwner | None:
        """Return same-process cleanup authority retained by this failure."""

        return self._cleanup_owner

    def _retain_cleanup_owner(
        self,
        owner: PrivateAnalysisFactoryProcessCleanupOwner,
    ) -> None:
        if self._cleanup_owner is not None and self._cleanup_owner is not owner:
            raise RuntimeError("factory cleanup ownership already exists")
        self._cleanup_owner = owner


class PrivateAnalysisFactoryPreparationFailed(PrivateAnalysisFactoryProcessError):
    """The process factory failed before a pristine service was ready."""


class PrivateAnalysisFactoryPreparationTimedOut(PrivateAnalysisFactoryProcessError):
    """The process factory exceeded the request's absolute deadline."""


class PrivateAnalysisFactoryPreparationCancelled(PrivateAnalysisFactoryProcessError):
    """Durable cancellation won while the process factory was preparing."""


class PrivateAnalysisFactoryProcessCleanupError(PrivateAnalysisFactoryProcessError):
    """The direct factory child could not be synchronously reaped."""


class PrivateAnalysisFactoryExecutableIdentityError(
    PrivateAnalysisFactoryProcessError
):
    """A factory target has no stable executable identity or no longer matches it."""


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolServiceProcessFactory:
    """Inert bootstrap for one module-level spawned service factory.

    The target receives ``(request, configuration)``.  Configuration crosses
    the boundary only as a bounded canonical JSON object; no live callable,
    closure, provider client, credential object, or pickle payload is sent.
    """

    target: str
    configuration_json: str = field(default="{}", repr=False)
    executable_identity: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _validate_target(self.target)
        configuration = _decode_canonical_json(
            self.configuration_json,
            maximum_bytes=_MAX_CONFIGURATION_BYTES,
        )
        if type(configuration) is not dict:
            raise TypeError("factory configuration must be a canonical JSON object")
        if self.executable_identity is not None:
            _validate_executable_identity(self.executable_identity)

    @staticmethod
    def detached(
        value: object,
    ) -> PrivateAnalysisToolServiceProcessFactory:
        """Reconstruct an exact descriptor without retaining its owner."""

        if type(value) is not PrivateAnalysisToolServiceProcessFactory:
            raise TypeError(
                "factory must be PrivateAnalysisToolServiceProcessFactory"
            )
        target = value.target
        configuration_json = value.configuration_json
        return PrivateAnalysisToolServiceProcessFactory(
            target=target,
            configuration_json=configuration_json,
            executable_identity=value.executable_identity,
        )

    @staticmethod
    def resolved(
        value: object,
    ) -> PrivateAnalysisToolServiceProcessFactory:
        """Bind and revalidate exact import provenance without retaining code."""

        snapshot = PrivateAnalysisToolServiceProcessFactory.detached(value)
        executable_identity = _resolve_factory_executable_identity(snapshot.target)
        if (
            snapshot.executable_identity is not None
            and executable_identity != snapshot.executable_identity
        ):
            raise PrivateAnalysisFactoryExecutableIdentityError(
                "private-analysis evidence factory executable identity changed"
            )
        return PrivateAnalysisToolServiceProcessFactory(
            target=snapshot.target,
            configuration_json=snapshot.configuration_json,
            executable_identity=executable_identity,
        )

    @property
    def configuration(self) -> dict[str, Any]:
        value = _decode_canonical_json(
            self.configuration_json,
            maximum_bytes=_MAX_CONFIGURATION_BYTES,
        )
        if type(value) is not dict:
            raise TypeError("factory configuration must be a canonical JSON object")
        return value

    @property
    def configuration_digest(self) -> str:
        return "sha256:" + strict_canonical_json_sha256(self.configuration)

    def evidence_service_digest(self, semantic_digest: str) -> str:
        if (
            type(semantic_digest) is not str
            or len(semantic_digest) != 71
            or not semantic_digest.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in semantic_digest[7:]
            )
        ):
            raise ValueError("semantic_digest must be a sha256-prefixed digest")
        executable_identity = self.executable_identity
        if executable_identity is None:
            executable_identity = _resolve_factory_executable_identity(self.target)
        return "sha256:" + strict_canonical_json_sha256(
            {
                "contract_version": (
                    "router_dump_analyzer.private_analysis."
                    "evidence_factory_process_binding.v1"
                ),
                "target": self.target,
                "configuration_digest": self.configuration_digest,
                "executable_identity": executable_identity,
                "semantic_digest": semantic_digest,
            }
        )


def _validate_target(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_TARGET_CHARACTERS
        or value != value.strip()
    ):
        raise ValueError("factory target must be bounded canonical text")
    module_name, separator, attribute = value.partition(":")
    if (
        separator != ":"
        or not module_name
        or not attribute
        or ":" in attribute
        or any(
            not component.isidentifier()
            for component in (*module_name.split("."), *attribute.split("."))
        )
        or any(component in {"<locals>", "<lambda>"} for component in attribute.split("."))
    ):
        raise ValueError(
            "factory target must use 'package.module:module_level_attribute' syntax"
        )
    return value


def _validate_executable_identity(value: object) -> str:
    prefix = "target-sha256:"
    if (
        type(value) is not str
        or not value.startswith(prefix)
        or len(value) != len(prefix) + 64
        or any(character not in "0123456789abcdef" for character in value[len(prefix) :])
    ):
        raise ValueError("factory executable identity is invalid")
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constants are forbidden")


def _validate_json_shape(
    value: object,
    *,
    depth: int = 0,
    units: list[int] | None = None,
) -> None:
    if units is None:
        units = [0]
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("factory-process JSON exceeds its depth limit")
    units[0] += 1
    if units[0] > _MAX_JSON_UNITS:
        raise ValueError("factory-process JSON exceeds its value-unit limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(1 << 63) <= value < 1 << 63:
            raise ValueError("factory-process JSON integer is out of range")
        return
    if type(value) is str:
        if len(value) > _MAX_JSON_ATOM_CHARACTERS:
            raise ValueError("factory-process JSON string exceeds its limit")
        return
    if type(value) is list:
        if len(value) > _MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("factory-process JSON array exceeds its item limit")
        for item in value:
            _validate_json_shape(item, depth=depth + 1, units=units)
        return
    if type(value) is dict:
        if len(value) > _MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("factory-process JSON object exceeds its item limit")
        for key, item in value.items():
            if type(key) is not str or len(key) > _MAX_JSON_ATOM_CHARACTERS:
                raise ValueError("factory-process JSON object key is invalid")
            _validate_json_shape(item, depth=depth + 1, units=units)
        return
    raise ValueError("factory-process JSON contains an unsupported scalar")


def _decode_canonical_json(value: object, *, maximum_bytes: int) -> object:
    if type(value) is not str:
        raise TypeError("factory-process JSON must be exact text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("factory-process JSON must be UTF-8 encodable") from error
    if len(encoded) > maximum_bytes:
        raise ValueError("factory-process JSON exceeds its byte limit")
    try:
        decoded = json.loads(
            value,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=_reject_json_constant,
        )
        _validate_json_shape(decoded)
        if strict_canonical_json(decoded) != value:
            raise ValueError("factory-process JSON is not canonical")
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError) as error:
        raise ValueError("factory-process JSON is invalid") from error
    return decoded


def _encode_message(value: dict[str, Any]) -> bytes:
    encoded = strict_canonical_json(value).encode("utf-8")
    if len(encoded) > _MAX_IPC_MESSAGE_BYTES:
        raise ValueError("factory-process IPC message exceeds its byte limit")
    return encoded


def _decode_message(value: bytes) -> dict[str, Any]:
    if type(value) is not bytes or len(value) > _MAX_IPC_MESSAGE_BYTES:
        raise ValueError("factory-process IPC message is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("factory-process IPC message is invalid") from error
    decoded = _decode_canonical_json(text, maximum_bytes=_MAX_IPC_MESSAGE_BYTES)
    if type(decoded) is not dict:
        raise ValueError("factory-process IPC message must be an object")
    return decoded


def _send_message(connection: Any, value: dict[str, Any]) -> None:
    connection.send_bytes(_encode_message(value))


def _receive_message(connection: Any) -> dict[str, Any]:
    try:
        encoded = connection.recv_bytes(_MAX_IPC_MESSAGE_BYTES)
    except (EOFError, OSError) as error:
        raise PrivateAnalysisFactoryProcessError(
            "private-analysis factory child returned no valid message"
        ) from error
    return _decode_message(encoded)


def _exact_message(
    value: object,
    *,
    kind: _PrivateAnalysisFactoryProcessMessageKind,
    fields: frozenset[str],
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        raise ValueError("factory-process IPC message has invalid fields")
    if (
        value.get("contract_version") != _PROTOCOL
        or _message_kind(value) is not kind
    ):
        raise ValueError("factory-process IPC message has an invalid discriminator")
    return value


def _message_kind(
    value: dict[str, Any],
) -> _PrivateAnalysisFactoryProcessMessageKind:
    raw_kind = value.get("kind")
    if type(raw_kind) is not str:
        raise ValueError("factory-process IPC message has an invalid discriminator")
    try:
        return _PrivateAnalysisFactoryProcessMessageKind(raw_kind)
    except ValueError:
        raise ValueError(
            "factory-process IPC message has an invalid discriminator"
        ) from None


def _load_factory_target(target: str) -> Callable[[PrivateAnalysisRequest, dict[str, Any]], object]:
    normalized = _validate_target(target)
    module_name, _, attribute = normalized.partition(":")
    try:
        module = importlib.import_module(module_name)
        selected: object = module
        for component in attribute.split("."):
            selected = getattr(selected, component)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - dynamic-loader trust boundary.
        raise PrivateAnalysisFactoryPreparationFailed(
            "private-analysis evidence factory target could not be loaded"
        ) from None
    if not callable(selected):
        raise TypeError("factory process target is not callable")
    return selected


def _factory_executable_identity(
    target: str,
    factory: Callable[[PrivateAnalysisRequest, dict[str, Any]], object],
) -> str:
    module_name, _, attribute = target.partition(":")
    try:
        return executable_module_target_fingerprint(
            module_name,
            attribute,
            factory,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - executable-provenance trust boundary.
        raise PrivateAnalysisFactoryExecutableIdentityError(
            "private-analysis evidence factory executable identity is unavailable"
        ) from None


def _resolve_factory_executable_identity(target: str) -> str:
    factory = _load_factory_target(target)
    return _factory_executable_identity(target, factory)


def _snapshot_payload(
    lease: Any,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    references = lease.disclosed_references
    budget = lease.budget_state
    if type(references) is not tuple or type(budget) is not PrivateAnalysisToolBudgetState:
        raise TypeError("factory service returned an invalid accounting snapshot")
    return (
        [evidence_reference_dict(reference) for reference in references],
        private_analysis_budget_payload(budget),
    )


def _factory_process_child(
    connection: Any,
    target: str,
    configuration_json: str,
    request_json: str,
    executable_identity: str,
) -> None:
    """Fixed spawn target; all deployment code is resolved inside the child."""

    lease: Any = None
    try:
        configuration = _decode_canonical_json(
            configuration_json,
            maximum_bytes=_MAX_CONFIGURATION_BYTES,
        )
        if type(configuration) is not dict:
            raise TypeError("factory configuration must be an object")
        request = private_analysis_request_from_json(request_json)
        factory = _load_factory_target(target)
        if (
            _factory_executable_identity(target, factory)
            != _validate_executable_identity(executable_identity)
        ):
            raise PrivateAnalysisFactoryExecutableIdentityError(
                "private-analysis evidence factory executable identity changed"
            )
        service = factory(request, configuration)
        if (
            type(service) is not PrivateAnalysisToolService
            or service.request != request
            or not service.runner_lease_eligible
            or service.disclosed_references
            or any(
                (
                    service.budget_state.tool_calls_consumed,
                    service.budget_state.evidence_items_disclosed,
                    service.budget_state.evidence_bytes_disclosed,
                )
            )
        ):
            raise TypeError("factory did not return a pristine bound service")
        lease = service.acquire_run_lease()
        _send_message(
            connection,
            {
                "contract_version": _PROTOCOL,
                "kind": _PrivateAnalysisFactoryProcessMessageKind.READY.value,
                "request_digest": request.request_digest,
            },
        )
        while True:
            incoming = _receive_message(connection)
            message_kind = _message_kind(incoming)
            if message_kind is _PrivateAnalysisFactoryProcessMessageKind.CLOSE:
                _exact_message(
                    incoming,
                    kind=_PrivateAnalysisFactoryProcessMessageKind.CLOSE,
                    fields=frozenset({"contract_version", "kind"}),
                )
                _send_message(
                    connection,
                    {
                        "contract_version": _PROTOCOL,
                        "kind": _PrivateAnalysisFactoryProcessMessageKind.CLOSED.value,
                    },
                )
                return
            message = _exact_message(
                incoming,
                kind=_PrivateAnalysisFactoryProcessMessageKind.EXECUTE,
                fields=frozenset(
                    {"contract_version", "kind", "sequence", "tool_call"}
                ),
            )
            sequence = message["sequence"]
            if type(sequence) is not int or not 0 <= sequence < 1 << 63:
                raise ValueError("factory-process sequence is invalid")
            call = private_analysis_tool_call_from_dict(message["tool_call"])
            response: PrivateAnalysisToolResult | PrivateAnalysisToolError | None = None
            analysis_error: PrivateAnalysisError | None = None
            failed = False
            try:
                selected = lease.execute(call)
                if type(selected) in {PrivateAnalysisToolResult, PrivateAnalysisToolError}:
                    response = selected
                else:
                    failed = True
            except PrivateAnalysisToolServiceError as error:
                analysis_error = error.error
            except BaseException:  # noqa: BLE001 - child service trust boundary.
                failed = True
            references, budget = _snapshot_payload(lease)
            _send_message(
                connection,
                {
                    "contract_version": _PROTOCOL,
                    "kind": _PrivateAnalysisFactoryProcessMessageKind.RESPONSE.value,
                    "sequence": sequence,
                    "tool_result": (
                        private_analysis_tool_result_dict(response)
                        if type(response) is PrivateAnalysisToolResult
                        else None
                    ),
                    "tool_error": (
                        private_analysis_tool_error_dict(response)
                        if type(response) is PrivateAnalysisToolError
                        else None
                    ),
                    "analysis_error": (
                        private_analysis_error_dict(analysis_error)
                        if analysis_error is not None
                        else None
                    ),
                    "service_failed": failed,
                    "references": references,
                    "budget_state": budget,
                },
            )
    except BaseException:  # noqa: BLE001 - contain all child diagnostics/signals.
        try:
            _send_message(
                connection,
                {
                    "contract_version": _PROTOCOL,
                    "kind": _PrivateAnalysisFactoryProcessMessageKind.FAILED.value,
                },
            )
        except BaseException:  # noqa: BLE001, S110 - child is exiting.
            pass
    finally:
        if lease is not None:
            try:
                lease.close()
            except BaseException:  # noqa: BLE001, S110 - child is exiting.
                pass
        try:
            connection.close()
        except BaseException:  # noqa: BLE001, S110 - child is exiting.
            pass


def _runner_error(
    request: PrivateAnalysisRequest,
    code: PrivateAnalysisErrorCode,
) -> PrivateAnalysisToolServiceError:
    return PrivateAnalysisToolServiceError(
        PrivateAnalysisError(
            request_digest=request.request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=code,
            retryable=code
            in {
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorCode.TIMEOUT,
            },
        )
    )


def _budget_from_payload(
    value: object,
    request: PrivateAnalysisRequest,
) -> PrivateAnalysisToolBudgetState:
    fields = frozenset(
        {
            "max_tool_calls",
            "tool_calls_consumed",
            "max_evidence_items",
            "evidence_items_disclosed",
            "max_evidence_bytes",
            "evidence_bytes_disclosed",
        }
    )
    if type(value) is not dict or frozenset(value) != fields:
        raise ValueError("factory-process budget snapshot is invalid")
    budget = PrivateAnalysisToolBudgetState(**value)
    if (
        budget.max_tool_calls != request.limits.max_tool_calls
        or budget.max_evidence_items != request.limits.max_evidence_items
        or budget.max_evidence_bytes != request.limits.max_evidence_bytes
    ):
        raise ValueError("factory-process budget snapshot is not request-bound")
    return budget


class PrivateAnalysisRemoteToolService:
    """Core-owned exact proxy for one child-retained tool service."""

    __slots__ = (
        "_budget_state",
        "_cancelled",
        "_claimed",
        "_cleanup_confirmed",
        "_cleanup_lock",
        "_closed",
        "_connection",
        "_deadline_ns",
        "_in_flight",
        "_ledger",
        "_lock",
        "_poll_interval_ns",
        "_process",
        "_request_json",
        "_sequence",
    )

    def __init__(
        self,
        request: PrivateAnalysisRequest,
        *,
        process: Any,
        connection: Any,
        cancellation_probe: Callable[[], bool],
        deadline_ns: int,
        poll_interval_ns: int,
    ) -> None:
        self._request_json = private_analysis_request_json(request)
        self._process = process
        self._connection = connection
        self._cancelled = cancellation_probe
        self._deadline_ns = deadline_ns
        self._poll_interval_ns = poll_interval_ns
        self._budget_state = PrivateAnalysisToolBudgetState(
            max_tool_calls=request.limits.max_tool_calls,
            tool_calls_consumed=0,
            max_evidence_items=request.limits.max_evidence_items,
            evidence_items_disclosed=0,
            max_evidence_bytes=request.limits.max_evidence_bytes,
            evidence_bytes_disclosed=0,
        )
        self._ledger: dict[str, EvidenceReference] = {}
        self._lock = threading.Lock()
        self._cleanup_lock = threading.Lock()
        self._claimed = False
        self._cleanup_confirmed = False
        self._closed = False
        self._in_flight = False
        self._sequence = 0

    @property
    def request(self) -> PrivateAnalysisRequest:
        return private_analysis_request_from_json(self._request_json)

    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState:
        with self._lock:
            value = self._budget_state
            return PrivateAnalysisToolBudgetState(
                max_tool_calls=value.max_tool_calls,
                tool_calls_consumed=value.tool_calls_consumed,
                max_evidence_items=value.max_evidence_items,
                evidence_items_disclosed=value.evidence_items_disclosed,
                max_evidence_bytes=value.max_evidence_bytes,
                evidence_bytes_disclosed=value.evidence_bytes_disclosed,
            )

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]:
        with self._lock:
            values = tuple(self._ledger[digest] for digest in sorted(self._ledger))
        return tuple(
            evidence_reference_from_dict(evidence_reference_dict(value))
            for value in values
        )

    @property
    def runner_lease_eligible(self) -> bool:
        with self._lock:
            return (
                not self._claimed
                and not self._closed
                and not self._in_flight
                and self._budget_state.tool_calls_consumed == 0
                and not self._ledger
            )

    def acquire_run_lease(self) -> PrivateAnalysisRemoteToolRunLease:
        with self._lock:
            if (
                self._claimed
                or self._closed
                or self._in_flight
                or self._budget_state.tool_calls_consumed
                or self._ledger
            ):
                raise _runner_error(
                    self.request,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            self._claimed = True
        return PrivateAnalysisRemoteToolRunLease(self)

    def _require_access(self) -> None:
        with self._lock:
            unavailable = self._closed or not self._claimed
        if unavailable:
            raise _runner_error(
                self.request,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        self._terminal_probe()

    def _terminal_probe(self) -> None:
        request = self.request
        try:
            cancelled = self._cancelled()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - callback trust boundary.
            raise _runner_error(request, PrivateAnalysisErrorCode.RUNNER_FAILED) from None
        if type(cancelled) is not bool:
            raise _runner_error(request, PrivateAnalysisErrorCode.RUNNER_FAILED)
        if cancelled:
            self.close()
            raise _runner_error(request, PrivateAnalysisErrorCode.CANCELLED)
        if time.monotonic_ns() >= self._deadline_ns:
            self.close()
            raise _runner_error(request, PrivateAnalysisErrorCode.TIMEOUT)

    def _execute(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        if type(call) is not PrivateAnalysisToolCall:
            raise _runner_error(
                self.request,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        with self._lock:
            if self._closed or not self._claimed or self._in_flight:
                raise _runner_error(
                    self.request,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            self._in_flight = True
            sequence = self._sequence
            self._sequence += 1
        try:
            self._terminal_probe()
            _send_message(
                self._connection,
                {
                    "contract_version": _PROTOCOL,
                    "kind": _PrivateAnalysisFactoryProcessMessageKind.EXECUTE.value,
                    "sequence": sequence,
                    "tool_call": private_analysis_tool_call_dict(call),
                },
            )
            while True:
                self._terminal_probe()
                remaining_ns = self._deadline_ns - time.monotonic_ns()
                wait_seconds = max(
                    0.0,
                    min(self._poll_interval_ns, remaining_ns) / 1_000_000_000,
                )
                if self._connection.poll(wait_seconds):
                    break
            message = _receive_message(self._connection)
            response = _exact_message(
                message,
                kind=_PrivateAnalysisFactoryProcessMessageKind.RESPONSE,
                fields=frozenset(
                    {
                        "contract_version",
                        "kind",
                        "sequence",
                        "tool_result",
                        "tool_error",
                        "analysis_error",
                        "service_failed",
                        "references",
                        "budget_state",
                    }
                ),
            )
            if response["sequence"] != sequence:
                raise ValueError("factory-process response sequence is invalid")
            self._accept_snapshot(response["references"], response["budget_state"])
            variants = (
                response["tool_result"] is not None,
                response["tool_error"] is not None,
                response["analysis_error"] is not None,
                response["service_failed"] is True,
            )
            if type(response["service_failed"]) is not bool or sum(variants) != 1:
                raise ValueError("factory-process response variant is invalid")
            if response["tool_result"] is not None:
                result = private_analysis_tool_result_from_dict(response["tool_result"])
                if result.call != call:
                    raise ValueError("factory-process result is not call-bound")
                return result
            if response["tool_error"] is not None:
                error = private_analysis_tool_error_from_dict(response["tool_error"])
                if error.call != call:
                    raise ValueError("factory-process error is not call-bound")
                return error
            if response["analysis_error"] is not None:
                analysis_error = private_analysis_error_from_dict(
                    response["analysis_error"]
                )
                if analysis_error.request_digest != self.request.request_digest:
                    raise ValueError("factory-process analysis error is not request-bound")
                raise PrivateAnalysisToolServiceError(analysis_error)
            raise _runner_error(self.request, PrivateAnalysisErrorCode.RUNNER_FAILED)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisToolServiceError:
            raise
        except BaseException:  # noqa: BLE001 - child protocol trust boundary.
            self.close()
            raise _runner_error(
                self.request,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            ) from None
        finally:
            with self._lock:
                self._in_flight = False

    def _accept_snapshot(self, references_value: object, budget_value: object) -> None:
        request = self.request
        if type(references_value) is not list:
            raise ValueError("factory-process reference snapshot is invalid")
        references = tuple(
            evidence_reference_from_dict(value) for value in references_value
        )
        if len(references) != len({item.reference_digest for item in references}):
            raise ValueError("factory-process reference snapshot has duplicates")
        if tuple(item.reference_digest for item in references) != tuple(
            sorted(item.reference_digest for item in references)
        ):
            raise ValueError("factory-process reference snapshot is not canonical")
        if any(
            item.scope != request.scope or item.revision not in request.revisions
            for item in references
        ):
            raise ValueError("factory-process reference snapshot is not request-bound")
        budget = _budget_from_payload(budget_value, request)
        if budget.evidence_items_disclosed != len(references):
            raise ValueError("factory-process accounting snapshot disagrees")
        with self._lock:
            prior_budget = self._budget_state
            if (
                budget.tool_calls_consumed < prior_budget.tool_calls_consumed
                or budget.tool_calls_consumed
                > prior_budget.tool_calls_consumed + 1
                or budget.evidence_items_disclosed
                < prior_budget.evidence_items_disclosed
                or budget.evidence_bytes_disclosed
                < prior_budget.evidence_bytes_disclosed
            ):
                raise ValueError("factory-process accounting snapshot regressed")
            incoming = {item.reference_digest: item for item in references}
            if any(incoming.get(digest) != item for digest, item in self._ledger.items()):
                raise ValueError("factory-process evidence ledger is not append-only")
            self._ledger = incoming
            self._budget_state = budget

    def close(self) -> None:
        with self._cleanup_lock:
            if self._cleanup_confirmed:
                return
            with self._lock:
                first_attempt = not self._closed
                self._closed = True
            process_control_error: BaseException | None = None
            if first_attempt:
                try:
                    if self._process.is_alive():
                        _send_message(
                            self._connection,
                            {
                                "contract_version": _PROTOCOL,
                                "kind": (
                                    _PrivateAnalysisFactoryProcessMessageKind.CLOSE.value
                                ),
                            },
                        )
                        if self._connection.poll(_MAX_REAP_SECONDS):
                            try:
                                message = _receive_message(self._connection)
                                _exact_message(
                                    message,
                                    kind=(
                                        _PrivateAnalysisFactoryProcessMessageKind.CLOSED
                                    ),
                                    fields=frozenset({"contract_version", "kind"}),
                                )
                            except PROCESS_CONTROL_EXCEPTIONS:
                                raise
                            except BaseException:  # noqa: BLE001, S110 - reap below.
                                pass
                except PROCESS_CONTROL_EXCEPTIONS as error:
                    process_control_error = error
                except BaseException:  # noqa: BLE001, S110 - force reap below.
                    pass
            try:
                self._connection.close()
            except PROCESS_CONTROL_EXCEPTIONS as error:
                if process_control_error is None:
                    process_control_error = error
            except BaseException:  # noqa: BLE001, S110 - process reap is authoritative.
                pass
            try:
                _reap_process(self._process)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except PrivateAnalysisFactoryProcessCleanupError:
                raise
            except BaseException:  # noqa: BLE001 - normalize process boundary.
                raise PrivateAnalysisFactoryProcessCleanupError(
                    "private-analysis factory child could not be reaped"
                ) from None
            self._cleanup_confirmed = True
            if process_control_error is not None:
                raise process_control_error


class PrivateAnalysisRemoteToolRunLease(
    _PrivateAnalysisToolRunLeaseFacade
):
    """Exclusive runner lease over a core-owned remote service proxy."""

    __slots__ = ()

    def __init__(self, service: PrivateAnalysisRemoteToolService) -> None:
        if type(service) is not PrivateAnalysisRemoteToolService:
            raise TypeError("service must be PrivateAnalysisRemoteToolService")
        super().__init__(service)

    def _require_service_access(self) -> None:
        self._service._require_access()

    def _execute_service_call(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        return self._service._execute(call)

    def _release_service_access(self) -> None:
        pass

    def _closed_lease_error(self) -> PrivateAnalysisToolServiceError:
        return _runner_error(
            self._service.request,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )


class PrivateAnalysisFactoryProcessCleanupOwner:
    """Retryable same-process ownership of one exact bootstrap child handle."""

    __slots__ = ("_cleanup_confirmed", "_cleanup_lock", "_process")

    def __init__(self, process: Any) -> None:
        self._process = process
        self._cleanup_lock = threading.Lock()
        self._cleanup_confirmed = False

    @property
    def cleanup_confirmed(self) -> bool:
        with self._cleanup_lock:
            return self._cleanup_confirmed

    def close(self) -> None:
        """Perform one bounded reap retry against the retained exact handle."""

        with self._cleanup_lock:
            if self._cleanup_confirmed:
                return
            try:
                _reap_process(self._process)
            except PROCESS_CONTROL_EXCEPTIONS as error:
                _retain_factory_process_cleanup_owner(error, self)
                raise
            except PrivateAnalysisFactoryProcessCleanupError as error:
                raise PrivateAnalysisFactoryProcessCleanupError(
                    str(error),
                    cleanup_owner=self,
                ) from error
            except BaseException as error:
                raise PrivateAnalysisFactoryProcessCleanupError(
                    "private-analysis factory child could not be reaped",
                    cleanup_owner=self,
                ) from error
            self._cleanup_confirmed = True


_PROCESS_CONTROL_CLEANUP_OWNER_ATTRIBUTE: Final = (
    "_private_analysis_factory_process_cleanup_owner"
)


def _retain_factory_process_cleanup_owner(
    error: BaseException,
    owner: PrivateAnalysisFactoryProcessCleanupOwner,
) -> None:
    """Attach exact cleanup authority without changing exception precedence."""

    if isinstance(error, PrivateAnalysisFactoryProcessError):
        error._retain_cleanup_owner(owner)
        return
    setattr(error, _PROCESS_CONTROL_CLEANUP_OWNER_ATTRIBUTE, owner)


def private_analysis_factory_process_cleanup_owner(
    error: BaseException,
) -> PrivateAnalysisFactoryProcessCleanupOwner | None:
    """Recover exact bootstrap cleanup authority from an internal failure."""

    if isinstance(error, PrivateAnalysisFactoryProcessError):
        return error.cleanup_owner
    value = getattr(error, _PROCESS_CONTROL_CLEANUP_OWNER_ATTRIBUTE, None)
    return value if type(value) is PrivateAnalysisFactoryProcessCleanupOwner else None


def _reap_process(process: Any) -> None:
    initially_alive = process.is_alive()
    if not initially_alive:
        try:
            pid = process.pid
            exitcode = process.exitcode
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise PrivateAnalysisFactoryProcessCleanupError(
                "private-analysis factory child state could not be inspected"
            ) from error
        if pid is None and exitcode is None:
            try:
                process.close()
            except ValueError:
                pass
            return
    if initially_alive:
        process.terminate()
        process.join(_MAX_REAP_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(_MAX_REAP_SECONDS)
    if process.is_alive():
        raise PrivateAnalysisFactoryProcessCleanupError(
            "private-analysis factory child could not be reaped"
        )
    process.join(0)
    try:
        process.close()
    except ValueError:
        pass


def _poll_cancellation(cancellation_probe: Callable[[], bool]) -> bool:
    value = cancellation_probe()
    if type(value) is not bool:
        raise TypeError("cancellation_probe must return a boolean")
    return value


def _close_unlaunched_pipe_endpoints(
    *connections: Any,
) -> BaseException | None:
    """Close every endpoint and return the first process-control failure."""

    process_control_error: BaseException | None = None
    for connection in connections:
        if connection is None:
            continue
        try:
            connection.close()
        except PROCESS_CONTROL_EXCEPTIONS as error:
            if process_control_error is None:
                process_control_error = error
        except BaseException:  # noqa: BLE001, S110 - every endpoint is attempted.
            pass
    return process_control_error


def start_private_analysis_tool_service_process(
    factory: PrivateAnalysisToolServiceProcessFactory,
    request: PrivateAnalysisRequest,
    *,
    cancellation_probe: Callable[[], bool],
    absolute_deadline_ns: int,
    poll_interval_ns: int,
) -> PrivateAnalysisRemoteToolService:
    """Start and await one bounded, cancellation-aware service child."""

    if type(factory) is not PrivateAnalysisToolServiceProcessFactory:
        raise TypeError("factory must be PrivateAnalysisToolServiceProcessFactory")
    if type(request) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    if not callable(cancellation_probe):
        raise TypeError("cancellation_probe must be callable")
    if type(absolute_deadline_ns) is not int or absolute_deadline_ns < 0:
        raise ValueError("absolute_deadline_ns must be a non-negative integer")
    if type(poll_interval_ns) is not int or poll_interval_ns <= 0:
        raise ValueError("poll_interval_ns must be a positive integer")
    factory_snapshot = PrivateAnalysisToolServiceProcessFactory.resolved(factory)
    executable_identity = factory_snapshot.executable_identity
    if executable_identity is None:  # pragma: no cover - resolved() guarantees it.
        raise PrivateAnalysisFactoryExecutableIdentityError(
            "private-analysis evidence factory executable identity is unavailable"
        )
    parent: Any = None
    child: Any = None
    try:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_factory_process_child,
            args=(
                child,
                factory_snapshot.target,
                factory_snapshot.configuration_json,
                private_analysis_request_json(request),
                executable_identity,
            ),
            name=f"private-analysis-evidence-factory-{uuid4().hex[:12]}",
            daemon=False,
        )
    except PROCESS_CONTROL_EXCEPTIONS as error:
        _close_unlaunched_pipe_endpoints(child, parent)
        raise error.with_traceback(error.__traceback__)
    except BaseException:  # noqa: BLE001 - no Process handle was created.
        endpoint_control = _close_unlaunched_pipe_endpoints(child, parent)
        if endpoint_control is not None:
            raise endpoint_control.with_traceback(endpoint_control.__traceback__)
        raise PrivateAnalysisFactoryPreparationFailed(
            "private-analysis evidence factory process could not be created"
        ) from None
    cleanup_owner = PrivateAnalysisFactoryProcessCleanupOwner(process)
    launch_attempted = False
    handed_off = False
    try:
        launch_attempted = True
        process.start()
        child.close()
        while True:
            if _poll_cancellation(cancellation_probe):
                raise PrivateAnalysisFactoryPreparationCancelled(
                    "private-analysis evidence preparation was cancelled"
                )
            remaining_ns = absolute_deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise PrivateAnalysisFactoryPreparationTimedOut(
                    "private-analysis evidence preparation timed out"
                )
            wait_seconds = min(poll_interval_ns, remaining_ns) / 1_000_000_000
            if parent.poll(wait_seconds):
                break
            if not process.is_alive():
                raise PrivateAnalysisFactoryPreparationFailed(
                    "private-analysis evidence factory process exited"
                )
        message = _receive_message(parent)
        message_kind = _message_kind(message)
        if message_kind is _PrivateAnalysisFactoryProcessMessageKind.FAILED:
            _exact_message(
                message,
                kind=_PrivateAnalysisFactoryProcessMessageKind.FAILED,
                fields=frozenset({"contract_version", "kind"}),
            )
            raise PrivateAnalysisFactoryPreparationFailed(
                "private-analysis evidence factory failed"
            )
        ready = _exact_message(
            message,
            kind=_PrivateAnalysisFactoryProcessMessageKind.READY,
            fields=frozenset({"contract_version", "kind", "request_digest"}),
        )
        if ready["request_digest"] != request.request_digest:
            raise PrivateAnalysisFactoryPreparationFailed(
                "private-analysis evidence factory returned the wrong request"
            )
        service = PrivateAnalysisRemoteToolService(
            request,
            process=process,
            connection=parent,
            cancellation_probe=cancellation_probe,
            deadline_ns=absolute_deadline_ns,
            poll_interval_ns=poll_interval_ns,
        )
        handed_off = True
        return service
    except PROCESS_CONTROL_EXCEPTIONS as error:
        if launch_attempted:
            try:
                cleanup_owner.close()
            except PROCESS_CONTROL_EXCEPTIONS as cleanup_error:
                _retain_factory_process_cleanup_owner(
                    cleanup_error,
                    cleanup_owner,
                )
                raise
            except BaseException:  # noqa: BLE001 - original control keeps authority.
                _retain_factory_process_cleanup_owner(error, cleanup_owner)
                raise error.with_traceback(error.__traceback__)
            _retain_factory_process_cleanup_owner(error, cleanup_owner)
        raise
    except (
        PrivateAnalysisFactoryPreparationCancelled,
        PrivateAnalysisFactoryPreparationTimedOut,
        PrivateAnalysisFactoryPreparationFailed,
    ) as error:
        if launch_attempted:
            try:
                cleanup_owner.close()
            except PROCESS_CONTROL_EXCEPTIONS as cleanup_error:
                _retain_factory_process_cleanup_owner(cleanup_error, cleanup_owner)
                raise
            _retain_factory_process_cleanup_owner(error, cleanup_owner)
        raise
    except BaseException:  # noqa: BLE001 - process/bootstrap trust boundary.
        cleanup_failed = False
        if launch_attempted:
            try:
                cleanup_owner.close()
            except PROCESS_CONTROL_EXCEPTIONS as cleanup_error:
                _retain_factory_process_cleanup_owner(cleanup_error, cleanup_owner)
                raise
            except BaseException:  # noqa: BLE001 - owner remains retryable.
                cleanup_failed = True
        raise PrivateAnalysisFactoryPreparationFailed(
            (
                "private-analysis evidence factory process cleanup failed"
                if cleanup_failed
                else "private-analysis evidence factory process failed"
            ),
            cleanup_owner=cleanup_owner if launch_attempted else None,
        ) from None
    finally:
        try:
            child.close()
        except BaseException:  # noqa: BLE001, S110 - best-effort handle close.
            pass
        if not handed_off:
            try:
                parent.close()
            except BaseException:  # noqa: BLE001, S110 - best-effort handle close.
                pass
        if not launch_attempted:
            try:
                process.close()
            except BaseException:  # noqa: BLE001, S110 - no child was launched.
                pass


__all__ = [
    "PrivateAnalysisFactoryPreparationCancelled",
    "PrivateAnalysisFactoryPreparationFailed",
    "PrivateAnalysisFactoryPreparationTimedOut",
    "PrivateAnalysisRemoteToolRunLease",
    "PrivateAnalysisRemoteToolService",
    "PrivateAnalysisToolServiceProcessFactory",
    "start_private_analysis_tool_service_process",
]

"""Inert, canonical JSONL values for the local private-analysis transport.

This module defines framing and value validation only.  It deliberately owns
no process, stream, filesystem, thread, dynamic-loading, or network behavior.
Nested private-analysis values remain opaque JSON objects here and are parsed
by their typed contracts only after a transport message has been admitted.
"""

from __future__ import annotations

from enum import StrEnum
from json import JSONDecodeError, loads
from typing import Any, Final

from ..canonical import (
    strict_canonical_json,
    strict_canonical_json_sha256,
)
from ..canonical import (
    validate_prefixed_lowercase_sha256 as _prefixed_sha256,
)
from ..contract_validation import validate_bounded_json_value
from ..value_core import MAX_JSON_SAFE_INTEGER
from ._wire import (
    SealedContractValue,
    exact_contract_version,
    exact_json_object,
    reject_duplicate_json_object_pairs,
    strict_string_enum,
)

PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION: Final = (
    "router_dump_analyzer.private_analysis.local_subprocess_protocol.v1"
)
MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PAYLOAD_BYTES: Final[int] = 8 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES: Final[int] = (
    MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PAYLOAD_BYTES + 64 * 1024
)

_MAX_PAYLOAD_DEPTH: Final = 20
_MAX_PAYLOAD_CONTAINER_ITEMS: Final = 1_024
_MAX_PAYLOAD_UNITS: Final = 2_000_000
_MAX_PAYLOAD_ATOM_UNITS: Final = 1_048_576
_ENVELOPE_FIELDS: Final = {
    "contract_version",
    "run_digest",
    "sequence",
    "kind",
    "payload",
    "message_digest",
}


class PrivateAnalysisLocalSubprocessMessageKind(StrEnum):
    """Closed, direction-neutral message vocabulary for one local run."""

    HELLO = "hello"
    READY = "ready"
    START = "start"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_ERROR = "tool_error"
    ANALYSIS_RESULT = "analysis_result"
    RUNNER_FAILURE = "runner_failure"


class PrivateAnalysisLocalSubprocessRunnerFailureReason(StrEnum):
    """Payload-free reasons a local runner may fail."""

    UNAVAILABLE = "unavailable"
    FAILED = "failed"


_NESTED_PAYLOAD_FIELD: Final = {
    PrivateAnalysisLocalSubprocessMessageKind.START: None,
    PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL: "tool_call",
    PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT: "tool_result",
    PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR: "tool_error",
    PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT: "analysis_result",
}


def _sequence(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_SAFE_INTEGER:
        raise ValueError(
            "local subprocess sequence must be a nonnegative JSON-safe integer"
        )
    return value


def _validate_kind_sequence(
    kind: PrivateAnalysisLocalSubprocessMessageKind,
    sequence: int,
) -> None:
    required = {
        PrivateAnalysisLocalSubprocessMessageKind.HELLO: 0,
        PrivateAnalysisLocalSubprocessMessageKind.READY: 1,
        PrivateAnalysisLocalSubprocessMessageKind.START: 2,
    }.get(kind)
    if required is not None and sequence != required:
        raise ValueError(f"{kind.value} message must use sequence {required}")
    if required is None and sequence < 3:
        raise ValueError(f"{kind.value} message sequence must be at least 3")


def _snapshot_payload(
    kind: PrivateAnalysisLocalSubprocessMessageKind,
    value: object,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("local subprocess payload must be a JSON object")
    detached: Any = validate_bounded_json_value(
        value,
        "local subprocess payload",
        maximum_depth=_MAX_PAYLOAD_DEPTH,
        maximum_container_items=_MAX_PAYLOAD_CONTAINER_ITEMS,
        maximum_units=_MAX_PAYLOAD_UNITS,
        maximum_atom_units=_MAX_PAYLOAD_ATOM_UNITS,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PAYLOAD_BYTES,
        snapshot=True,
    )
    payload: dict[str, object] = exact_json_object(
        detached,
        "local subprocess payload",
        {key for key in detached if type(key) is str},
    )

    if kind in {
        PrivateAnalysisLocalSubprocessMessageKind.HELLO,
        PrivateAnalysisLocalSubprocessMessageKind.READY,
    }:
        exact_json_object(payload, f"{kind.value} payload", set())
        return payload

    if kind is PrivateAnalysisLocalSubprocessMessageKind.START:
        item = exact_json_object(
            payload,
            "start payload",
            {"request", "tool_catalog"},
        )
        if type(item["request"]) is not dict:
            raise ValueError("start request must be a JSON object")
        if type(item["tool_catalog"]) is not dict:
            raise ValueError("start tool_catalog must be a JSON object")
        return payload

    nested_field = _NESTED_PAYLOAD_FIELD.get(kind)
    if nested_field is not None:
        item = exact_json_object(payload, f"{kind.value} payload", {nested_field})
        if type(item[nested_field]) is not dict:
            raise ValueError(f"{kind.value} {nested_field} must be a JSON object")
        return payload

    if kind is PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE:
        item = exact_json_object(payload, "runner_failure payload", {"reason"})
        strict_string_enum(
            PrivateAnalysisLocalSubprocessRunnerFailureReason,
            item["reason"],
            "runner_failure reason",
        )
        return payload

    raise ValueError("local subprocess message kind is unsupported")


def _digest_payload(
    *,
    contract_version: str,
    run_digest: str,
    sequence: int,
    kind: PrivateAnalysisLocalSubprocessMessageKind,
    payload: dict[str, object],
) -> dict[str, object]:
    return {
        "contract_version": contract_version,
        "run_digest": run_digest,
        "sequence": sequence,
        "kind": kind.value,
        "payload": payload,
    }


class PrivateAnalysisLocalSubprocessMessage(SealedContractValue):
    """One immutable, self-digested local-subprocess protocol message."""

    _contract_version: str
    _kind: PrivateAnalysisLocalSubprocessMessageKind
    _message_digest: str
    _payload_json: str
    _run_digest: str
    _sequence: int

    __slots__ = (
        "_contract_version",
        "_kind",
        "_message_digest",
        "_payload_json",
        "_run_digest",
        "_sequence",
    )

    def __init__(
        self,
        *,
        run_digest: object,
        sequence: object,
        kind: object,
        payload: object,
        contract_version: object = PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
        message_digest: object = "",
    ) -> None:
        version = exact_contract_version(
            contract_version,
            PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
            "local subprocess protocol",
        )
        digest = _prefixed_sha256(run_digest, "run_digest")
        position = _sequence(sequence)
        if type(kind) is not PrivateAnalysisLocalSubprocessMessageKind:
            raise TypeError("kind must be a PrivateAnalysisLocalSubprocessMessageKind")
        typed_kind = kind
        _validate_kind_sequence(typed_kind, position)
        detached_payload = _snapshot_payload(typed_kind, payload)
        payload_json = strict_canonical_json(detached_payload)

        identity = _digest_payload(
            contract_version=version,
            run_digest=digest,
            sequence=position,
            kind=typed_kind,
            payload=detached_payload,
        )
        expected_digest = "sha256:" + strict_canonical_json_sha256(identity)
        if type(message_digest) is str and message_digest == "":
            sealed_digest = expected_digest
        else:
            sealed_digest = _prefixed_sha256(message_digest, "message_digest")
            if sealed_digest != expected_digest:
                raise ValueError("message_digest does not match message content")

        framed = dict(identity)
        framed["message_digest"] = sealed_digest
        encoded_size = len(strict_canonical_json(framed).encode("utf-8")) + 1
        if encoded_size > MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES:
            raise ValueError(
                "local subprocess frame exceeds "
                f"{MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES} bytes"
            )

        object.__setattr__(self, "_contract_version", version)
        object.__setattr__(self, "_run_digest", digest)
        object.__setattr__(self, "_sequence", position)
        object.__setattr__(self, "_kind", typed_kind)
        object.__setattr__(self, "_payload_json", payload_json)
        object.__setattr__(self, "_message_digest", sealed_digest)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("local subprocess messages are immutable")

    @property
    def contract_version(self) -> str:
        return self._contract_version

    @property
    def run_digest(self) -> str:
        return self._run_digest

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def kind(self) -> PrivateAnalysisLocalSubprocessMessageKind:
        return self._kind

    @property
    def payload(self) -> dict[str, object]:
        try:
            value = loads(
                self._payload_json,
                object_pairs_hook=reject_duplicate_json_object_pairs,
                parse_constant=_reject_json_constant,
            )
        except (JSONDecodeError, TypeError, ValueError, RecursionError) as error:
            raise ValueError("stored local subprocess payload is invalid") from error
        if type(value) is not dict:
            raise ValueError("stored local subprocess payload is invalid")
        return value

    @property
    def message_digest(self) -> str:
        return self._message_digest

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(kind={self.kind.value!r}, "
            f"sequence={self.sequence!r}, run_digest={self.run_digest!r}, "
            f"message_digest={self.message_digest!r})"
        )

    def __eq__(self, other: object) -> bool:
        if type(other) is not PrivateAnalysisLocalSubprocessMessage:
            return False
        typed_other = other
        return (
            self.contract_version,
            self.run_digest,
            self.sequence,
            self.kind,
            self._payload_json,
            self.message_digest,
        ) == (
            typed_other.contract_version,
            typed_other.run_digest,
            typed_other.sequence,
            typed_other.kind,
            typed_other._payload_json,
            typed_other.message_digest,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.contract_version,
                self.run_digest,
                self.sequence,
                self.kind,
                self._payload_json,
                self.message_digest,
            )
        )


def _revalidated_message(value: object) -> PrivateAnalysisLocalSubprocessMessage:
    if type(value) is not PrivateAnalysisLocalSubprocessMessage:
        raise TypeError("value must be a PrivateAnalysisLocalSubprocessMessage")
    message = value
    supplied_digest = _prefixed_sha256(
        message.message_digest,
        "message_digest",
    )
    return PrivateAnalysisLocalSubprocessMessage(
        contract_version=message.contract_version,
        run_digest=message.run_digest,
        sequence=message.sequence,
        kind=message.kind,
        payload=message.payload,
        message_digest=supplied_digest,
    )


def private_analysis_local_subprocess_message_dict(
    value: object,
) -> dict[str, object]:
    """Return a detached, revalidated exact envelope."""

    message = _revalidated_message(value)
    result = _digest_payload(
        contract_version=message.contract_version,
        run_digest=message.run_digest,
        sequence=message.sequence,
        kind=message.kind,
        payload=message.payload,
    )
    result["message_digest"] = message.message_digest
    return result


def private_analysis_local_subprocess_message_from_dict(
    value: object,
) -> PrivateAnalysisLocalSubprocessMessage:
    """Parse and verify one exact local-subprocess message envelope."""

    item = exact_json_object(value, "local subprocess message", _ENVELOPE_FIELDS)
    version = exact_contract_version(
        item["contract_version"],
        PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
        "local subprocess protocol",
    )
    kind = strict_string_enum(
        PrivateAnalysisLocalSubprocessMessageKind,
        item["kind"],
        "local subprocess message kind",
    )
    supplied_digest = _prefixed_sha256(
        item["message_digest"],
        "message_digest",
    )
    return PrivateAnalysisLocalSubprocessMessage(
        contract_version=version,
        run_digest=item["run_digest"],
        sequence=item["sequence"],
        kind=kind,
        payload=item["payload"],
        message_digest=supplied_digest,
    )


def validate_private_analysis_local_subprocess_sequence(
    previous: object | None,
    current: object,
) -> None:
    """Require the first HELLO or one same-run, globally adjacent message."""

    current_message = _revalidated_message(current)
    if previous is None:
        if (
            current_message.kind is not PrivateAnalysisLocalSubprocessMessageKind.HELLO
            or current_message.sequence != 0
        ):
            raise ValueError("local subprocess sequence must begin with HELLO 0")
        return
    previous_message = _revalidated_message(previous)
    if previous_message.run_digest != current_message.run_digest:
        raise ValueError("local subprocess sequence changed run_digest")
    if (
        previous_message.sequence == MAX_JSON_SAFE_INTEGER
        or current_message.sequence != previous_message.sequence + 1
    ):
        raise ValueError("local subprocess sequence must increment globally by one")


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def encode_private_analysis_local_subprocess_message(value: object) -> bytes:
    """Encode one message as strict canonical UTF-8 JSON plus exactly one LF."""

    envelope = private_analysis_local_subprocess_message_dict(value)
    frame = strict_canonical_json(envelope).encode("utf-8") + b"\n"
    if len(frame) > MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES:
        raise ValueError(
            "local subprocess frame exceeds "
            f"{MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES} bytes"
        )
    return frame


def decode_private_analysis_local_subprocess_message(
    frame: object,
) -> PrivateAnalysisLocalSubprocessMessage:
    """Decode exactly one complete, canonical UTF-8 JSONL frame."""

    if type(frame) is not bytes:
        raise TypeError("local subprocess frame must be bytes")
    encoded = frame
    if not encoded or len(encoded) > MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES:
        raise ValueError("local subprocess frame is empty or oversized")
    if not encoded.endswith(b"\n") or encoded.count(b"\n") != 1:
        raise ValueError("local subprocess frame must contain exactly one trailing LF")
    body = encoded[:-1]
    if not body:
        raise ValueError("local subprocess frame body must not be empty")
    if b"\r" in encoded:
        raise ValueError("local subprocess frame must not contain CR or CRLF")
    if body.startswith(b"\xef\xbb\xbf"):
        raise ValueError("local subprocess frame must not contain a UTF-8 BOM")
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("local subprocess frame must be valid UTF-8") from error
    try:
        parsed = loads(
            text,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (JSONDecodeError, TypeError, ValueError, RecursionError) as error:
        raise ValueError("local subprocess frame must contain strict JSON") from error
    if type(parsed) is not dict:
        raise ValueError("local subprocess frame must contain a JSON object")
    if strict_canonical_json(parsed) != text:
        raise ValueError("local subprocess frame must use canonical JSON")
    return private_analysis_local_subprocess_message_from_dict(parsed)


def private_analysis_local_subprocess_message_frame(value: object) -> bytes:
    """Compatibility spelling for the canonical message encoder."""

    return encode_private_analysis_local_subprocess_message(value)


def private_analysis_local_subprocess_message_from_frame(
    frame: object,
) -> PrivateAnalysisLocalSubprocessMessage:
    """Compatibility spelling for the exact single-frame decoder."""

    return decode_private_analysis_local_subprocess_message(frame)


PrivateAnalysisLocalSubprocessKind = PrivateAnalysisLocalSubprocessMessageKind
PrivateAnalysisLocalSubprocessFailureReason = (
    PrivateAnalysisLocalSubprocessRunnerFailureReason
)


__all__ = [
    "MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES",
    "MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PAYLOAD_BYTES",
    "PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION",
    "PrivateAnalysisLocalSubprocessFailureReason",
    "PrivateAnalysisLocalSubprocessKind",
    "PrivateAnalysisLocalSubprocessMessage",
    "PrivateAnalysisLocalSubprocessMessageKind",
    "PrivateAnalysisLocalSubprocessRunnerFailureReason",
    "decode_private_analysis_local_subprocess_message",
    "encode_private_analysis_local_subprocess_message",
    "private_analysis_local_subprocess_message_dict",
    "private_analysis_local_subprocess_message_frame",
    "private_analysis_local_subprocess_message_from_dict",
    "private_analysis_local_subprocess_message_from_frame",
    "validate_private_analysis_local_subprocess_sequence",
]

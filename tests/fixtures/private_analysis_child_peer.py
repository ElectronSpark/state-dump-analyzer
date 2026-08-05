"""Deterministic standalone peer used by private-analysis child-runner tests.

Launch this fixture as::

    python -I -u private_analysis_child_peer.py control.json

The peer intentionally knows nothing about the product protocol.  Its bounded
control document selects a linear sequence of byte-oriented actions so parent
tests can exercise framing, deadlines, process teardown, and launch hygiene.
It imports only the standard library and opens only the supplied control file
and, when requested, one supplied sidecar file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sys
import time
from typing import Any, Final

CONTROL_VERSION: Final = "private-analysis-child-peer-control.v1"

MAX_CONTROL_BYTES: Final = 16 * 1024 * 1024
MAX_ACTIONS: Final = 128
MAX_ACTION_PAYLOAD_BYTES: Final = 8 * 1024 * 1024
MAX_STDOUT_BYTES: Final = 16 * 1024 * 1024
MAX_STDERR_BYTES: Final = 2 * 1024 * 1024
MAX_STDERR_ATOM_BYTES: Final = 64 * 1024
MAX_SIDECAR_BYTES: Final = 1024 * 1024
MAX_FRAME_BYTES: Final = 8 * 1024 * 1024
MAX_CHUNKS: Final = 4096
MAX_REPEAT: Final = 1024
MAX_SLEEP_MILLISECONDS: Final = 60_000
MAX_TOTAL_SLEEP_MILLISECONDS: Final = 120_000
MAX_JSON_DEPTH: Final = 32
MAX_JSON_CONTAINER_ITEMS: Final = 4096
MAX_JSON_UNITS: Final = 200_000
MAX_JSON_KEY_CHARACTERS: Final = 256
MAX_PATH_CHARACTERS: Final = 4096
MAX_ENVIRONMENT_KEYS: Final = 64
MAX_ENVIRONMENT_KEY_CHARACTERS: Final = 128

_EXIT_USAGE: Final = 64
_EXIT_CONTROL_IO: Final = 65
_EXIT_INVALID_CONTROL: Final = 66
_EXIT_ACTION_FAILED: Final = 67
_EXIT_VERIFICATION_FAILED: Final = 68
_EXIT_INTERNAL_FAILURE: Final = 70

_MESSAGE_USAGE: Final = b"private-analysis child peer usage error\n"
_MESSAGE_CONTROL_IO: Final = b"private-analysis child peer control I/O error\n"
_MESSAGE_INVALID_CONTROL: Final = b"private-analysis child peer invalid control\n"
_MESSAGE_ACTION_FAILED: Final = b"private-analysis child peer action failed\n"
_MESSAGE_VERIFICATION_FAILED: Final = (
    b"private-analysis child peer frame verification failed\n"
)
_MESSAGE_INTERNAL_FAILURE: Final = b"private-analysis child peer internal failure\n"

_FACT_NAMES: Final = frozenset({"argv", "env", "cwd", "stdin", "stdout", "stderr"})
_TERMINAL_ACTIONS: Final = frozenset({"block", "exit", "os_exit"})


class _PeerFailure(Exception):
    def __init__(self, exit_code: int, message: bytes) -> None:
        super().__init__("private-analysis child peer failed")
        self.exit_code = exit_code
        self.message = message


class _DuplicateJsonKey(ValueError):
    pass


class _UnsupportedJsonNumber(ValueError):
    pass


def _invalid_control() -> _PeerFailure:
    return _PeerFailure(_EXIT_INVALID_CONTROL, _MESSAGE_INVALID_CONTROL)


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey
        value[key] = item
    return value


def _reject_json_number(_value: str) -> None:
    raise _UnsupportedJsonNumber


def _read_control(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as stream:
            encoded = stream.read(MAX_CONTROL_BYTES + 1)
    except (OSError, ValueError) as error:
        raise _PeerFailure(_EXIT_CONTROL_IO, _MESSAGE_CONTROL_IO) from error
    if not encoded or len(encoded) > MAX_CONTROL_BYTES:
        raise _invalid_control()
    try:
        text = encoded.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_closed_json_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise _invalid_control() from error
    if type(value) is not dict:
        raise _invalid_control()
    _validate_json_value(value)
    return value


def _validate_json_value(
    value: Any,
    *,
    depth: int = 0,
    units: list[int] | None = None,
) -> None:
    if units is None:
        units = [0]
    if depth > MAX_JSON_DEPTH:
        raise _invalid_control()
    units[0] += 1
    if units[0] > MAX_JSON_UNITS:
        raise _invalid_control()
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value.bit_length() > 256:
            raise _invalid_control()
        return
    if type(value) is str:
        if len(value) > MAX_CONTROL_BYTES:
            raise _invalid_control()
        return
    if type(value) is list:
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise _invalid_control()
        for item in value:
            _validate_json_value(item, depth=depth + 1, units=units)
        return
    if type(value) is dict:
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise _invalid_control()
        for key, item in value.items():
            if type(key) is not str or len(key) > MAX_JSON_KEY_CHARACTERS:
                raise _invalid_control()
            _validate_json_value(item, depth=depth + 1, units=units)
        return
    raise _invalid_control()


def _require_keys(
    value: dict[str, Any],
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    keys = frozenset(value)
    if not required <= keys or not keys <= required | optional:
        raise _invalid_control()


def _bounded_integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid_control()
    return value


def _bounded_path(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_PATH_CHARACTERS
        or "\x00" in value
    ):
        raise _invalid_control()
    return value


def _decode_base64(value: Any, maximum_bytes: int) -> bytes:
    if type(value) is not str:
        raise _invalid_control()
    maximum_characters = 4 * ((maximum_bytes + 2) // 3)
    if len(value) > maximum_characters:
        raise _invalid_control()
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise _invalid_control() from error
    if len(decoded) > maximum_bytes:
        raise _invalid_control()
    return decoded


def _chunk_sizes(value: Any, payload_bytes: int) -> tuple[int, ...]:
    if value is None:
        return (payload_bytes,) if payload_bytes else ()
    if type(value) is not list or len(value) > MAX_CHUNKS:
        raise _invalid_control()
    sizes = tuple(_bounded_integer(item, 1, MAX_ACTION_PAYLOAD_BYTES) for item in value)
    if sum(sizes) != payload_bytes:
        raise _invalid_control()
    return sizes


def _canonical_frame(value: Any) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise _invalid_control() from error
    if len(encoded) > MAX_ACTION_PAYLOAD_BYTES:
        raise _invalid_control()
    return encoded


def _environment_key(value: Any) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_ENVIRONMENT_KEY_CHARACTERS
        or "=" in value
        or "\x00" in value
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise _invalid_control()
    return value


def _normalize_control(
    value: dict[str, Any],
) -> tuple[str | None, tuple[tuple[Any, ...], ...]]:
    _require_keys(
        value,
        frozenset({"version", "actions"}),
        frozenset({"sidecar_path"}),
    )
    if value["version"] != CONTROL_VERSION:
        raise _invalid_control()
    actions_value = value["actions"]
    if (
        type(actions_value) is not list
        or not actions_value
        or len(actions_value) > MAX_ACTIONS
    ):
        raise _invalid_control()
    sidecar_path = (
        _bounded_path(value["sidecar_path"]) if "sidecar_path" in value else None
    )

    normalized: list[tuple[Any, ...]] = []
    stdout_bytes = 0
    stderr_bytes = 0
    sleep_milliseconds = 0
    record_count = 0
    for index, action in enumerate(actions_value):
        if type(action) is not dict or type(action.get("kind")) is not str:
            raise _invalid_control()
        kind = action["kind"]
        if kind in _TERMINAL_ACTIONS and index != len(actions_value) - 1:
            raise _invalid_control()

        if kind == "read_lf_frame":
            _require_keys(
                action,
                frozenset({"kind", "max_bytes"}),
                frozenset({"sha256"}),
            )
            maximum = _bounded_integer(action["max_bytes"], 1, MAX_FRAME_BYTES)
            expected = action.get("sha256")
            if expected is not None and (
                type(expected) is not str
                or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)
            ):
                raise _invalid_control()
            normalized.append((kind, maximum, expected))
            continue

        if kind == "write_stdout":
            _require_keys(
                action,
                frozenset({"kind", "data_b64"}),
                frozenset({"chunk_sizes"}),
            )
            payload = _decode_base64(
                action["data_b64"],
                MAX_ACTION_PAYLOAD_BYTES,
            )
            chunks = _chunk_sizes(action.get("chunk_sizes"), len(payload))
            stdout_bytes += len(payload)
            if stdout_bytes > MAX_STDOUT_BYTES:
                raise _invalid_control()
            normalized.append((kind, payload, chunks))
            continue

        if kind == "write_canonical_frame":
            _require_keys(
                action,
                frozenset({"kind", "frame"}),
                frozenset({"chunk_sizes"}),
            )
            payload = _canonical_frame(action["frame"])
            chunks = _chunk_sizes(action.get("chunk_sizes"), len(payload))
            stdout_bytes += len(payload)
            if stdout_bytes > MAX_STDOUT_BYTES:
                raise _invalid_control()
            normalized.append((kind, payload, chunks))
            continue

        if kind == "write_stderr":
            _require_keys(
                action,
                frozenset({"kind", "data_b64", "repeat"}),
            )
            payload = _decode_base64(action["data_b64"], MAX_STDERR_ATOM_BYTES)
            repeat = _bounded_integer(action["repeat"], 0, MAX_REPEAT)
            stderr_bytes += len(payload) * repeat
            if stderr_bytes > MAX_STDERR_BYTES:
                raise _invalid_control()
            normalized.append((kind, payload, repeat))
            continue

        if kind == "sleep":
            _require_keys(action, frozenset({"kind", "milliseconds"}))
            milliseconds = _bounded_integer(
                action["milliseconds"],
                0,
                MAX_SLEEP_MILLISECONDS,
            )
            sleep_milliseconds += milliseconds
            if sleep_milliseconds > MAX_TOTAL_SLEEP_MILLISECONDS:
                raise _invalid_control()
            normalized.append((kind, milliseconds))
            continue

        if kind == "block":
            _require_keys(action, frozenset({"kind"}))
            normalized.append((kind,))
            continue

        if kind == "record_facts":
            _require_keys(
                action,
                frozenset({"kind", "facts"}),
                frozenset({"env_keys"}),
            )
            facts_value = action["facts"]
            if (
                type(facts_value) is not list
                or not facts_value
                or len(facts_value) > len(_FACT_NAMES)
                or any(
                    type(item) is not str or item not in _FACT_NAMES
                    for item in facts_value
                )
                or len(facts_value) != len(set(facts_value))
            ):
                raise _invalid_control()
            facts = tuple(facts_value)
            env_keys_value = action.get("env_keys")
            if "env" in facts:
                if (
                    type(env_keys_value) is not list
                    or len(env_keys_value) > MAX_ENVIRONMENT_KEYS
                ):
                    raise _invalid_control()
                env_keys = tuple(_environment_key(item) for item in env_keys_value)
                if len(env_keys) != len(set(env_keys)):
                    raise _invalid_control()
            else:
                if env_keys_value is not None:
                    raise _invalid_control()
                env_keys = ()
            record_count += 1
            if record_count > 1 or sidecar_path is None:
                raise _invalid_control()
            normalized.append((kind, facts, env_keys))
            continue

        if kind in {"exit", "os_exit"}:
            _require_keys(action, frozenset({"kind", "code"}))
            code = _bounded_integer(action["code"], 0, 125)
            normalized.append((kind, code))
            continue

        raise _invalid_control()

    if (sidecar_path is None) != (record_count == 0):
        raise _invalid_control()
    return sidecar_path, tuple(normalized)


def _flush_standard_streams() -> None:
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()


def _write_chunks(stream: Any, payload: bytes, chunks: tuple[int, ...]) -> None:
    offset = 0
    for size in chunks:
        written = stream.write(payload[offset : offset + size])
        if written != size:
            raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
        stream.flush()
        offset += size


def _stream_facts(stream: Any) -> dict[str, Any]:
    descriptor = stream.fileno()
    return {
        "encoding": stream.encoding,
        "errors": stream.errors,
        "fileno": descriptor,
        "inheritable": os.get_inheritable(descriptor),
        "isatty": os.isatty(descriptor),
    }


def _record_facts(
    sidecar_path: str,
    facts: tuple[str, ...],
    env_keys: tuple[str, ...],
) -> None:
    result: dict[str, Any] = {}
    for fact in facts:
        if fact == "argv":
            result["argv"] = list(sys.argv)
        elif fact == "env":
            result["env"] = {key: os.environ.get(key) for key in env_keys}
        elif fact == "cwd":
            result["cwd"] = os.getcwd()
        elif fact == "stdin":
            result["stdin"] = _stream_facts(sys.stdin)
        elif fact == "stdout":
            result["stdout"] = _stream_facts(sys.stdout)
        elif fact == "stderr":
            result["stderr"] = _stream_facts(sys.stderr)
        else:  # Control validation makes this unreachable.
            raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
    try:
        encoded = (
            json.dumps(
                result,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED) from error
    if len(encoded) > MAX_SIDECAR_BYTES:
        raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
    try:
        with open(sidecar_path, "xb") as stream:
            written = stream.write(encoded)
            if written != len(encoded):
                raise OSError("short sidecar write")
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError) as error:
        raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED) from error


def _execute_actions(
    sidecar_path: str | None,
    actions: tuple[tuple[Any, ...], ...],
) -> int:
    for action in actions:
        kind = action[0]
        if kind == "read_lf_frame":
            maximum, expected = action[1], action[2]
            try:
                frame = sys.stdin.buffer.readline(maximum + 1)
            except (OSError, ValueError) as error:
                raise _PeerFailure(
                    _EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED
                ) from error
            if not frame or len(frame) > maximum or not frame.endswith(b"\n"):
                raise _PeerFailure(
                    _EXIT_VERIFICATION_FAILED, _MESSAGE_VERIFICATION_FAILED
                )
            if expected is not None and hashlib.sha256(frame).hexdigest() != expected:
                raise _PeerFailure(
                    _EXIT_VERIFICATION_FAILED, _MESSAGE_VERIFICATION_FAILED
                )
            continue

        if kind in {"write_stdout", "write_canonical_frame"}:
            _write_chunks(sys.stdout.buffer, action[1], action[2])
            continue

        if kind == "write_stderr":
            payload, repeat = action[1], action[2]
            for _index in range(repeat):
                written = sys.stderr.buffer.write(payload)
                if written != len(payload):
                    raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
                sys.stderr.buffer.flush()
            continue

        if kind == "sleep":
            time.sleep(action[1] / 1000.0)
            continue

        if kind == "block":
            _flush_standard_streams()
            while True:
                time.sleep(3600.0)

        if kind == "record_facts":
            if sidecar_path is None:  # Control validation makes this unreachable.
                raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
            _record_facts(sidecar_path, action[1], action[2])
            continue

        if kind == "exit":
            _flush_standard_streams()
            return action[1]

        if kind == "os_exit":
            _flush_standard_streams()
            os._exit(action[1])

        raise _PeerFailure(_EXIT_ACTION_FAILED, _MESSAGE_ACTION_FAILED)
    _flush_standard_streams()
    return 0


def _emit_failure(message: bytes) -> None:
    try:
        sys.stderr.buffer.write(message)
        sys.stderr.buffer.flush()
    except BaseException:  # noqa: BLE001,S110 - last-resort static fixture failure.
        pass


def main() -> int:
    if len(sys.argv) != 2:
        _emit_failure(_MESSAGE_USAGE)
        return _EXIT_USAGE
    control_path = sys.argv[1]
    if (
        not control_path
        or len(control_path) > MAX_PATH_CHARACTERS
        or "\x00" in control_path
    ):
        _emit_failure(_MESSAGE_USAGE)
        return _EXIT_USAGE
    try:
        control = _read_control(control_path)
        sidecar_path, actions = _normalize_control(control)
        return _execute_actions(sidecar_path, actions)
    except _PeerFailure as error:
        _emit_failure(error.message)
        return error.exit_code
    except BaseException:  # noqa: BLE001 - standalone executable failure fence.
        _emit_failure(_MESSAGE_INTERNAL_FAILURE)
        return _EXIT_INTERNAL_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())

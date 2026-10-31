"""Optional core Babeltrace decoder; device interpretation stays in plug-ins.

The configured interpreter needs the official Babeltrace 2 ``bt2`` bindings.
It runs a fixed, core-owned bridge, never an archive-provided command or script.
Only bounded JSON frames cross the process boundary; native objects never do.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cancellation import QueryCancellationProbe, check_cancellation_probe
from .plugin_api import (
    ArtifactReader,
    CtfDiscardedEvents,
    CtfDiscardedPackets,
    CtfEventRecord,
    CtfMessage,
    CtfPacketBoundary,
    CtfStreamBoundary,
    Evidence,
    InputParserKind,
    InputSpec,
)

_WORKER_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


class TraceDecodeError(RuntimeError):
    """An explicit, path-free failure at the native decoder boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class BabeltraceDecoderConfiguration:
    """Host-owned settings. Nothing in InputSpec.options changes these limits."""

    python_executable: str = sys.executable
    timeout_seconds: float = 120.0
    max_messages: int = 2_000_000
    max_frame_bytes: int = 1024 * 1024
    max_output_bytes: int = 256 * 1024 * 1024
    max_metadata_bytes: int = 16 * 1024 * 1024
    max_field_depth: int = 16
    max_field_items: int = 4096
    max_worker_memory_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.python_executable) is not str
            or not self.python_executable
            or "\x00" in self.python_executable
        ):
            raise ValueError("python_executable must be a nonempty executable path")
        if (
            (
                type(self.timeout_seconds) is not int
                and type(self.timeout_seconds) is not float
            )
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive")
        for name in (
            "max_messages",
            "max_frame_bytes",
            "max_output_bytes",
            "max_metadata_bytes",
            "max_field_depth",
            "max_field_items",
            "max_worker_memory_bytes",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")


class _FrameChannel:
    """Two-frame producer/consumer channel without native Queue exception aliases."""

    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.pending: list[Any] = []

    def put(self, frame: Any, stopped: threading.Event) -> None:
        with self.condition:
            while len(self.pending) == 2 and not stopped.is_set():
                self.condition.wait(0.05)
            if not stopped.is_set():
                self.pending.append(frame)
                self.condition.notify_all()

    def get(self, timeout: float) -> Any:
        with self.condition:
            if not self.pending:
                self.condition.wait(timeout)
            if not self.pending:
                return None
            frame = self.pending.pop(0)
            self.condition.notify_all()
            return frame


def _read_frames(
    pipe: Any, frames: _FrameChannel, stopped: threading.Event, maximum: int
) -> None:
    """Bound allocation before reading a potentially hostile worker frame."""
    try:
        while not stopped.is_set():
            line = pipe.readline(maximum + 1)
            value: Any = line
            if len(line) > maximum:
                value = TraceDecodeError("CTF_QUOTA", "decoder frame is too large")
            frames.put(value, stopped)
            if not line or isinstance(value, Exception):
                break
    except (OSError, ValueError):
        pass  # The owner closes the pipe after stopping/killing the process.


class BabeltraceProcessDecoder:
    """Decode safe materialized CTF trees in a cancellable native subprocess.

    Register this with the ordinary deployment-owned DecoderIdentity and an
    importable decoder instance when durable process execution is required.
    Each call owns its process and buffers, including concurrent calls.
    """

    def __init__(
        self,
        configuration: BabeltraceDecoderConfiguration | None = None,
        *,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.configuration = configuration or BabeltraceDecoderConfiguration()
        if type(self.configuration) is not BabeltraceDecoderConfiguration:
            raise TypeError("configuration must be BabeltraceDecoderConfiguration")
        self.cancellation_probe = cancellation_probe

    def _checkpoint(self) -> None:
        for probe in (QueryCancellationProbe(), self.cancellation_probe):
            check_cancellation_probe(
                probe,
                cancelled_error=lambda: TraceDecodeError(
                    "CTF_CANCELLED", "decoding cancelled"
                ),
                unavailable_error=lambda: TraceDecodeError(
                    "CTF_CANCEL_PROBE", "cancellation probe failed"
                ),
                invalid_result_error=lambda: TraceDecodeError(
                    "CTF_CANCEL_PROBE", "cancellation probe must return bool"
                ),
            )

    def iter_ctf(self, reader: ArtifactReader, spec: InputSpec) -> Iterator[CtfMessage]:
        self._checkpoint()
        if spec.parser_kind is not InputParserKind.CTF:
            raise TraceDecodeError("CTF_INPUT", "decoder requires a CTF input")
        # CoreArtifactReader/ScopedArtifactReader enforce archive traversal,
        # symlinks, compression, read quotas and exactly the selected artifacts.
        root = reader.materialize_private_tree(spec.artifact_ids, spec.logical_root)
        self._checkpoint()
        config = self.configuration
        worker = Path(__file__).with_name("_babeltrace_worker.py")
        limits = {
            name: getattr(config, name)
            for name in (
                "max_messages",
                "max_frame_bytes",
                "max_output_bytes",
                "max_metadata_bytes",
                "max_field_depth",
                "max_field_items",
                "max_worker_memory_bytes",
            )
        }
        command = [
            config.python_executable,
            "-I",
            "-u",
            str(worker),
            root,
            json.JSONEncoder(separators=(",", ":")).encode(limits),
        ]
        # Avoid loading archive-controlled Python modules or Babeltrace plugins.
        inherited_environment = os.environ.copy()
        environment = {
            key: value
            for key, value in inherited_environment.items()
            if not key.startswith(("PYTHON", "BABELTRACE", "BT2_"))
        }
        json_decoder = json.JSONDecoder()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(worker.parent),
                env=environment,
                creationflags=_WORKER_CREATION_FLAGS,
            )
        except OSError as error:
            raise TraceDecodeError(
                "CTF_UNAVAILABLE", "configured decoder interpreter could not start"
            ) from error
        assert process.stdout is not None
        frames = _FrameChannel()
        stopped = threading.Event()
        pump = threading.Thread(
            target=_read_frames,
            args=(process.stdout, frames, stopped, config.max_frame_bytes),
            daemon=True,
        )
        pump.start()
        deadline = time.monotonic() + config.timeout_seconds
        total_bytes = 0
        message_count = 0
        completed = False
        try:
            while True:
                self._checkpoint()
                if time.monotonic() >= deadline:
                    raise TraceDecodeError(
                        "CTF_TIMEOUT", "decoder exceeded its time limit"
                    )
                frame = frames.get(
                    timeout=min(0.05, max(0.001, deadline - time.monotonic()))
                )
                if frame is None:
                    if process.poll() is not None and not pump.is_alive():
                        raise TraceDecodeError(
                            "CTF_WORKER", "decoder ended without a completion frame"
                        )
                    continue
                if isinstance(frame, Exception):
                    raise frame
                if not frame:
                    if not completed or process.wait(timeout=1) != 0:
                        raise TraceDecodeError(
                            "CTF_WORKER", "decoder ended without successful completion"
                        )
                    break
                total_bytes += len(frame)
                if total_bytes > config.max_output_bytes:
                    raise TraceDecodeError(
                        "CTF_QUOTA", "decoder output byte limit exceeded"
                    )
                try:
                    item = json_decoder.decode(frame.decode("utf-8"))
                    if type(item) is not dict:
                        raise ValueError
                    if "error" in item:
                        code = item["error"]
                        errors = {
                            "CTF_UNAVAILABLE": "Babeltrace 2 bt2 bindings or ctf.fs are unavailable",
                            "CTF_MALFORMED": "Babeltrace could not decode the selected CTF tree",
                            "CTF_UNSUPPORTED": "CTF message or field type is unsupported",
                            "CTF_QUOTA": "native decoder resource limit exceeded",
                            "CTF_MEMORY_LIMIT": "native memory limit could not be installed",
                        }
                        raise TraceDecodeError(
                            code if code in errors else "CTF_WORKER",
                            errors.get(code, "decoder returned an invalid error"),
                        )
                    if item.get("complete") is True:
                        if completed or item.get("messages") != message_count:
                            raise ValueError
                        completed = True
                        continue
                    if completed:
                        raise ValueError
                    message_count += 1
                    if message_count > config.max_messages:
                        raise TraceDecodeError(
                            "CTF_QUOTA", "decoder message limit exceeded"
                        )
                    yield _message_from_frame(item, spec, message_count - 1)
                except TraceDecodeError:
                    raise
                except (ValueError, TypeError, KeyError, RecursionError) as error:
                    raise TraceDecodeError(
                        "CTF_PROTOCOL", "decoder returned an invalid frame"
                    ) from error
        finally:
            stopped.set()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            pump.join(timeout=1)


def _message_from_frame(
    item: dict[str, Any], spec: InputSpec, ordinal: int
) -> CtfMessage:
    """Attach evidence from the admitted selection, never a native file path."""
    kind = item.pop("kind")
    if item.get("message_ordinal") != ordinal:
        raise ValueError("unexpected message ordinal")
    trace = item["trace_uid"]
    stream = item["stream_uid"]
    if type(trace) is not str or type(stream) is not str:
        raise ValueError("invalid trace identity")
    timestamp = item.get("timestamp_ns", item.get("begin_timestamp_ns"))
    evidence = tuple(
        Evidence(
            artifact_id=artifact_id,
            locator=f"ctf:trace={trace},stream={stream},message={ordinal}",
            raw_timestamp_ns=timestamp,
            clock_domain=item.get("clock_domain"),
        )
        for artifact_id in spec.artifact_ids
    )
    models = {
        "event": CtfEventRecord,
        "stream": CtfStreamBoundary,
        "packet": CtfPacketBoundary,
        "discarded_events": CtfDiscardedEvents,
        "discarded_packets": CtfDiscardedPackets,
    }
    model = models[kind]
    return model(**item, evidence=evidence)


__all__ = [
    "BabeltraceDecoderConfiguration",
    "BabeltraceProcessDecoder",
    "TraceDecodeError",
]

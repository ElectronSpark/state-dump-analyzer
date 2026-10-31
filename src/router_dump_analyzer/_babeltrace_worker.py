"""Fixed, isolated Babeltrace bridge. Also runs under a bt2 Python >= 3.8.

This module deliberately imports only the standard library until its memory
limit is installed. The parent accepts bounded JSON, not Python serialization.
"""

import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path


class DecodeFailure(Exception):
    pass


def _memory_limit(maximum):
    if os.name != "nt":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (maximum, maximum))
        return None
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_int64),
            ("job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD),
            ("min_set", ctypes.c_size_t),
            ("max_set", ctypes.c_size_t),
            ("process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "reads",
                "writes",
                "other",
                "read_bytes",
                "write_bytes",
                "other_bytes",
            )
        ]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("basic", Basic),
            ("io", IO),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process", ctypes.c_size_t),
            ("peak_job", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    job = kernel.CreateJobObjectW(None, None)
    limits = Extended()
    limits.basic.flags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    limits.process_memory = maximum
    if not job or not kernel.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        raise DecodeFailure("CTF_MEMORY_LIMIT")
    if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
        raise DecodeFailure("CTF_MEMORY_LIMIT")
    return job  # Keep the process-owned handle alive until the worker exits.


def _is(bt, value, name):
    cls = getattr(bt, name, None)
    return cls is not None and isinstance(value, cls)


def _field(bt, value, limits, budget, depth=0):
    budget[0] += 1
    if depth > limits["max_field_depth"] or budget[0] > limits["max_field_items"]:
        raise DecodeFailure("CTF_QUOTA")
    if value is None:
        return None, {"kind": "absent"}
    cls = value.cls
    if _is(bt, value, "_StructureFieldConst"):
        if len(value) > limits["max_field_items"] - budget[0]:
            raise DecodeFailure("CTF_QUOTA")
        result, children = {}, {}
        for name in value:
            result[name], children[name] = _field(
                bt, value[name], limits, budget, depth + 1
            )
        return result, {"kind": "structure", "members": children}
    if _is(bt, value, "_ArrayFieldConst"):
        if len(value) > limits["max_field_items"] - budget[0]:
            raise DecodeFailure("CTF_QUOTA")
        pairs = [_field(bt, item, limits, budget, depth + 1) for item in value]
        return [pair[0] for pair in pairs], {
            "kind": "array",
            "elements": [pair[1] for pair in pairs],
        }
    if _is(bt, value, "_OptionFieldConst"):
        result, child = _field(bt, value.field, limits, budget, depth + 1)
        return result, {"kind": "option", "present": value.has_field, "content": child}
    if _is(bt, value, "_VariantFieldConst"):
        result, child = _field(bt, value.selected_option, limits, budget, depth + 1)
        return result, {
            "kind": "variant",
            "selected_index": value.selected_option_index,
            "content": child,
        }
    if _is(bt, value, "_BoolFieldConst"):
        return bool(value), {"kind": "boolean"}
    if _is(bt, value, "_BitArrayFieldConst"):
        return value.value_as_integer, {"kind": "bit_array", "bits": cls.length}
    if _is(bt, value, "_IntegerFieldConst"):
        signed = _is(bt, value, "_SignedIntegerFieldConst")
        enumeration = _is(bt, value, "_EnumerationFieldConst")
        info = {
            "kind": ("signed_" if signed else "unsigned_")
            + ("enumeration" if enumeration else "integer"),
            "bits": cls.field_value_range,
        }
        if enumeration:
            info["labels"] = list(value.labels)
        return int(value), info
    if _is(bt, value, "_RealFieldConst"):
        result = float(value)
        if not math.isfinite(result):
            raise DecodeFailure("CTF_UNSUPPORTED")  # JSON cannot preserve NaN/Inf.
        return result, {
            "kind": "real",
            "bits": 32 if _is(bt, value, "_SinglePrecisionRealFieldConst") else 64,
        }
    if _is(bt, value, "_StringFieldConst"):
        if len(value) > limits["max_frame_bytes"]:
            raise DecodeFailure("CTF_QUOTA")
        return str(value), {"kind": "string"}
    raise DecodeFailure("CTF_UNSUPPORTED")


def _clock(bt, snapshot, trace_uid):
    if snapshot is None or _is(bt, snapshot, "_UnknownClockSnapshot"):
        return None, None, {}
    cls = snapshot.clock_class
    uid = str(cls.uuid) if cls.uuid is not None else cls.name
    # Unknown/non-Unix origins are trace-local even when the display name matches.
    domain = (
        "unix"
        if cls.origin_is_unix_epoch
        else "ctf:" + trace_uid + ":" + (uid or "default")
    )
    details = {
        "cycles": snapshot.value,
        "frequency": cls.frequency,
        "offset_seconds": cls.offset.seconds,
        "offset_cycles": cls.offset.cycles,
        "precision_cycles": cls.precision,
        "origin_is_unix_epoch": cls.origin_is_unix_epoch,
        "name": cls.name,
        "uuid": str(cls.uuid) if cls.uuid is not None else None,
    }
    try:
        timestamp = snapshot.ns_from_origin
    except OverflowError:
        timestamp = None
    return timestamp, domain, details


def _snapshot(bt, message, stream, property_name="default_clock_snapshot"):
    if stream.cls.default_clock_class is None:
        return None
    name = type(message).__name__
    supports = {
        "_PacketBeginningMessageConst": "packets_have_beginning_default_clock_snapshot",
        "_PacketEndMessageConst": "packets_have_end_default_clock_snapshot",
        "_DiscardedEventsMessageConst": "discarded_events_have_default_clock_snapshots",
        "_DiscardedPacketsMessageConst": "discarded_packets_have_default_clock_snapshots",
    }.get(name)
    if supports is not None and not getattr(stream.cls, supports):
        return None
    return getattr(message, property_name)


def _metadata(root, limits):
    result, directories, total = [], [], 0
    for path in sorted(root.rglob("metadata")):
        if not path.is_file():
            continue
        with path.open("rb") as source:
            data = source.read(limits["max_metadata_bytes"] - total + 1)
        total += len(data)
        if total > limits["max_metadata_bytes"]:
            raise DecodeFailure("CTF_QUOTA")
        # Trace IR deliberately drops storage layout. Keep the exact original
        # metadata as evidence, plus all declarations (not guessed field order).
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.DOTALL)
        declarations = re.findall(r"\bbyte_order\s*=\s*(le|be|network|native)\b", text)
        order = {b"\x57\x1d\xd1\x75": "little", b"\x75\xd1\x1d\x57": "big"}.get(
            data[:4]
        )
        result.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "byte_order_declarations": declarations,
                "metadata_packet_byte_order": order,
            }
        )
        directories.append(str(path.parent))
    if not directories:
        raise DecodeFailure("CTF_MALFORMED")
    return result, directories


def _messages(bt, root, limits):
    metadata, directories = _metadata(root, limits)
    plugin = bt.find_plugin("ctf")
    if plugin is None or "fs" not in plugin.source_component_classes:
        raise DecodeFailure("CTF_UNAVAILABLE")
    components = [
        bt.ComponentSpec(plugin.source_component_classes["fs"], {"inputs": [path]})
        for path in directories
    ]
    iterator = bt.TraceCollectionMessageIterator(components)
    trace_ids, stream_ids, packet_sequences = {}, {}, {}
    metadata_digest = hashlib.sha256(
        json.dumps(metadata, sort_keys=True).encode()
    ).hexdigest()[:20]
    for ordinal, message in enumerate(iterator):
        if ordinal >= limits["max_messages"]:
            raise DecodeFailure("CTF_QUOTA")
        name = type(message).__name__
        event = message.event if _is(bt, message, "_EventMessageConst") else None
        packet = (
            getattr(event, "packet", None)
            if event is not None
            else getattr(message, "packet", None)
        )
        stream = (
            event.stream
            if event is not None
            else (
                packet.stream
                if packet is not None
                else getattr(message, "stream", None)
            )
        )
        if stream is None:
            # Offline ctf.fs should never emit inactivity; fail explicitly instead
            # of inventing the stream required by the public boundary model.
            raise DecodeFailure("CTF_UNSUPPORTED")
        trace = stream.trace
        trace_key = trace.addr
        if trace_key not in trace_ids:
            trace_ids[trace_key] = (
                "trace-"
                + str(len(trace_ids))
                + ":"
                + (str(trace.uuid) if trace.uuid is not None else metadata_digest)
            )
        trace_uid = trace_ids[trace_key]
        stream_key = (trace_key, stream.addr)
        if stream_key not in stream_ids:
            stream_ids[stream_key] = (
                trace_uid
                + ":class-"
                + str(stream.cls.id)
                + ":stream-"
                + str(stream.id if stream.id is not None else len(stream_ids))
            )
        if len(stream_ids) > limits["max_field_items"]:
            raise DecodeFailure("CTF_QUOTA")
        timestamp, domain, clock = _clock(
            bt,
            _snapshot(
                bt,
                message,
                stream,
                "beginning_default_clock_snapshot"
                if "Discarded" in name
                else "default_clock_snapshot",
            ),
            trace_uid,
        )
        decoder = {
            "format": "babeltrace2.v1",
            "clock": clock,
            "stream_class_id": stream.cls.id,
            "stream_id": stream.id,
        }
        if "StreamBeginning" in name:
            decoder["source_metadata"] = metadata
        common = {
            "trace_uid": trace_uid,
            "stream_uid": stream_ids[stream_key],
            "message_ordinal": ordinal,
            "clock_domain": domain,
            "decoder_metadata": decoder,
        }
        if "Discarded" in name:
            end, _end_domain, end_clock = _clock(
                bt,
                _snapshot(bt, message, stream, "end_default_clock_snapshot"),
                trace_uid,
            )
            decoder["end_clock"] = end_clock
            yield dict(
                common,
                kind="discarded_events" if "Events" in name else "discarded_packets",
                count=message.count,
                begin_timestamp_ns=timestamp,
                end_timestamp_ns=end,
            )
            continue
        common["timestamp_ns"] = timestamp
        if "StreamBeginning" in name or "StreamEnd" in name:
            yield dict(common, kind="stream", started="Beginning" in name)
        elif "PacketBeginning" in name or "PacketEnd" in name:
            if "Beginning" in name:
                packet_sequences[stream_key] = packet_sequences.get(stream_key, -1) + 1
            decoder["packet_sequence_kind"] = "decoder_ordinal"
            yield dict(
                common,
                kind="packet",
                started="Beginning" in name,
                packet_sequence=packet_sequences.get(stream_key),
            )
        elif event is not None:
            fields, types, budget = {}, {}, [0]
            for key, value in (
                ("payload", event.payload_field),
                ("common_context", event.common_context_field),
                ("specific_context", event.specific_context_field),
                (
                    "packet_context",
                    packet.context_field if packet is not None else None,
                ),
            ):
                normalized, description = _field(bt, value, limits, budget)
                fields[key] = normalized if normalized is not None else {}
                types[key] = description
            decoder["field_types"] = types
            decoder["packet_sequence_kind"] = "decoder_ordinal"
            precision = clock.get("precision_cycles")
            frequency = clock.get("frequency")
            uncertainty = (
                (precision * 1_000_000_000 + frequency - 1) // frequency
                if timestamp is not None and frequency
                else None
            )
            yield dict(
                common,
                kind="event",
                event_name=event.name,
                timestamp_uncertainty_ns=uncertainty,
                packet_sequence=packet_sequences.get(stream_key),
                **fields,
            )
        else:
            raise DecodeFailure("CTF_UNSUPPORTED")


def main():
    output_bytes, count = 0, 0
    try:
        root, limits = Path(sys.argv[1]), json.loads(sys.argv[2])
        try:
            job = _memory_limit(limits["max_worker_memory_bytes"])
        except Exception:  # noqa: BLE001 - fixed path-free process-boundary diagnostic
            raise DecodeFailure("CTF_MEMORY_LIMIT") from None
        try:
            import bt2
        except ImportError:
            raise DecodeFailure("CTF_UNAVAILABLE") from None
        for message in _messages(bt2, root, limits):
            frame = (
                json.dumps(
                    message, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                )
                + "\n"
            ).encode("ascii")
            output_bytes += len(frame)
            if (
                len(frame) > limits["max_frame_bytes"]
                or output_bytes > limits["max_output_bytes"]
            ):
                raise DecodeFailure("CTF_QUOTA")
            sys.stdout.buffer.write(frame)
            sys.stdout.buffer.flush()
            count += 1
        print(json.dumps({"complete": True, "messages": count}), flush=True)
        _ = job
        return 0
    except DecodeFailure as error:
        print(json.dumps({"error": str(error)}), flush=True)
    except MemoryError:
        print('{"error":"CTF_QUOTA"}', flush=True)
    except Exception:  # noqa: BLE001 - native decoder errors must not expose raw input
        # Native diagnostics may contain raw payloads and private paths.
        print('{"error":"CTF_MALFORMED"}', flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())

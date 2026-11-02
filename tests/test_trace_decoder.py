from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pickle
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

from router_dump_analyzer import _babeltrace_worker as worker
from router_dump_analyzer._babeltrace_worker import (
    DecodeFailure,
    _clock,
    _field,
    _metadata,
)
from router_dump_analyzer.artifact_core import (
    ArtifactBoundaryError,
    ArtifactLimits,
    CoreArtifactReader,
)
from router_dump_analyzer.cancellation import _QUERY_CANCELLED, QueryCancellationProbe
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    CtfDiscardedEvents,
    CtfDiscardedPackets,
    CtfEventRecord,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
    SourceRecordEmission,
    SourceRecordTypeDescriptor,
)
from router_dump_analyzer.plugin_execution_plan import DecoderIdentity
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_module_target_fingerprint,
)
from router_dump_analyzer.plugin_registration import PluginRegistry
from router_dump_analyzer.trace_decoder import (
    BabeltraceDecoderConfiguration,
    BabeltraceTraceDecoder,
    TraceDecodeError,
)


def write_trace(directory: Path, endian: str = "le") -> None:
    directory.mkdir(exist_ok=True)
    (directory / "metadata").write_text(
        """/* CTF 1.8 */
typealias integer { size = 32; align = 8; signed = false; byte_order = ORDER; } := uint32_t;
typealias integer { size = 64; align = 8; signed = false; byte_order = ORDER; } := uint64_t;
trace { major = 1; minor = 8; byte_order = ORDER;
  packet.header := struct { uint32_t magic; uint32_t stream_id; }; };
clock { name = monotonic; freq = 1000000000; offset = 17; };
typealias integer { size = 64; align = 8; signed = false; map = clock.monotonic.value; } := timestamp_t;
stream { id = 0; event.header := struct { uint32_t id; timestamp_t timestamp; }; };
event { name = "synthetic"; id = 0; stream_id = 0;
  fields := struct { uint32_t count; string text; }; };
""".replace("ORDER", endian),
        encoding="utf-8",
    )
    (directory / "channel0").write_bytes(
        struct.pack("<IIIQI" if endian == "le" else ">IIIQI", 0xC1FC1FC1, 0, 0, 23, 42)
        + b"hello\0"
    )


def selection(reader) -> InputSpec:
    return InputSpec(
        artifact_ids=tuple(item.artifact_id for item in reader.inventory.artifacts),
        role="trace",
        node="synthetic",
        layer="test",
        parser_id="test.ctf",
        parser_kind=InputParserKind.CTF,
    )


class NativeTracePlugin(AnalyzerPluginBase):
    manifest = PluginManifest(
        plugin_id="tests.native-ctf",
        plugin_version="1",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("synthetic",),
        supported_software_versions="1",
        capabilities=frozenset({PluginCapability.CTF_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self):
        return PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            source_record_types=(
                SourceRecordTypeDescriptor(source_type="ctf-event", label="CTF event"),
            ),
        )

    def probe(self, inventory):
        return ProbeReport(
            result=ProbeResult(
                confidence=1.0,
                reasons=("synthetic CTF",),
                match_kind=ProbeMatchKind.EXACT,
            )
        )

    def locate_inputs(self, inventory):
        yield selection(SimpleNamespace(inventory=inventory))

    def parse_ctf(self, spec, messages):
        for message in messages:
            if isinstance(message, CtfEventRecord):
                yield SourceRecordEmission(
                    timestamp_ns=message.timestamp_ns,
                    timestamp_uncertainty_ns=message.timestamp_uncertainty_ns,
                    source_type="ctf-event",
                    source_name="synthetic",
                    record_name=message.event_name,
                    message=str(message.payload["count"]),
                    layer=spec.layer,
                    evidence=message.evidence,
                )


CONFIGURED_NATIVE_DECODER = BabeltraceTraceDecoder()
NATIVE_TRACE_PLUGIN = NativeTracePlugin()


class TraceDecoderRegistrationTests(unittest.TestCase):
    def test_public_class_and_configured_instance_support_process_bootstrap(self):
        direct = executable_module_target_fingerprint(
            "router_dump_analyzer.trace_decoder",
            "BabeltraceTraceDecoder",
            BabeltraceTraceDecoder,
        )
        self.assertTrue(direct.startswith("target-sha256:"))
        registry = PluginRegistry(require_executable_identity=True)
        registry.register(
            NATIVE_TRACE_PLUGIN,
            coordinator=IngestionCoordinator(trace_decoder=CONFIGURED_NATIVE_DECODER),
            decoder_identity=DecoderIdentity(
                "tests.babeltrace", "2", "sha256:" + "8" * 64
            ),
            plugin_process_module_target=__name__ + ":NATIVE_TRACE_PLUGIN",
            decoder_module_target=__name__ + ":CONFIGURED_NATIVE_DECODER",
        )
        bootstraps = registry.process_bootstraps()
        self.assertTrue(
            bootstraps[0].decoder_target_executable_identity.startswith(
                "target-sha256:"
            )
        )
        # Exercise the real child loader, not just an import of the public class.
        script = """import json,pickle,sys
sys.path[:] = json.loads(sys.argv[1])
from router_dump_analyzer.ingestion_pipeline import _registry_from_process_bootstraps
from tests.test_trace_decoder import CONFIGURED_NATIVE_DECODER
registry = _registry_from_process_bootstraps(pickle.loads(sys.stdin.buffer.read()))
print(len(registry.process_bootstraps()), CONFIGURED_NATIVE_DECODER.configuration.max_messages)
"""
        child = subprocess.run(
            [sys.executable, "-c", script, json.dumps(sys.path)],
            input=pickle.dumps(bootstraps),
            capture_output=True,
            check=False,
            timeout=40,
            cwd=Path(__file__).resolve().parents[1],
        )
        self.assertEqual(
            child.returncode, 0, child.stderr.decode("utf-8", errors="replace")
        )
        self.assertEqual(child.stdout.strip(), b"1 2000000")
        original = executable_module_target_fingerprint(
            __name__, "CONFIGURED_NATIVE_DECODER", CONFIGURED_NATIVE_DECODER
        )
        with patch.object(
            CONFIGURED_NATIVE_DECODER,
            "configuration",
            replace(CONFIGURED_NATIVE_DECODER.configuration, max_messages=19),
        ):
            changed = executable_module_target_fingerprint(
                __name__, "CONFIGURED_NATIVE_DECODER", CONFIGURED_NATIVE_DECODER
            )
            self.assertNotEqual(original, changed)
            from router_dump_analyzer.ingestion_pipeline import (
                IngestionPipelineError,
                _registry_from_process_bootstraps,
            )

            restored = _registry_from_process_bootstraps(bootstraps)
            with self.assertRaisesRegex(
                IngestionPipelineError, "identity|changed|conflict"
            ):
                restored.process_bootstraps()

    def test_live_private_transport_replacement_is_rejected(self):
        from router_dump_analyzer._babeltrace_process import BabeltraceProcessDecoder
        from router_dump_analyzer.ingestion import IngestionError

        original = executable_module_target_fingerprint(
            "router_dump_analyzer.trace_decoder",
            "BabeltraceTraceDecoder",
            BabeltraceTraceDecoder,
        )

        def replacement(self, reader, spec):
            raise IngestionError("replacement must never run during attestation")

        with patch.object(BabeltraceProcessDecoder, "iter_ctf", replacement):
            try:
                mutated = executable_module_target_fingerprint(
                    "router_dump_analyzer.trace_decoder",
                    "BabeltraceTraceDecoder",
                    BabeltraceTraceDecoder,
                )
            except PluginExecutableIdentityError:
                pass
            else:
                self.assertNotEqual(original, mutated)

    def test_native_bridge_bytes_participate_in_public_decoder_pin(self):
        from router_dump_analyzer import plugin_identity

        entries = plugin_identity._package_entries
        visited = []
        with tempfile.TemporaryDirectory() as temporary:
            substitute = Path(temporary) / "_babeltrace_worker.py"
            worker = (
                Path(__file__).resolve().parents[1]
                / "src/router_dump_analyzer/_babeltrace_worker.py"
            )
            substitute.write_bytes(
                worker.read_bytes() + b"\n# synthetic identity change\n"
            )
            baseline = executable_module_target_fingerprint(
                "router_dump_analyzer.trace_decoder",
                "BabeltraceTraceDecoder",
                BabeltraceTraceDecoder,
            )

            def substituted(roots, **limits):
                for entry in entries(roots, **limits):
                    if entry.path == worker:
                        visited.append(entry.relative)
                        yield replace(entry, path=substitute)
                    else:
                        yield entry

            with patch.object(plugin_identity, "_package_entries", substituted):
                changed = executable_module_target_fingerprint(
                    "router_dump_analyzer.trace_decoder",
                    "BabeltraceTraceDecoder",
                    BabeltraceTraceDecoder,
                )
            self.assertTrue(
                visited, "native bridge must be in the executable package scope"
            )
            self.assertNotEqual(baseline, changed)


class TraceDecoderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ctf-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        write_trace(self.root)

    def test_native_unavailable_is_explicit_and_path_free(self):
        if importlib.util.find_spec("bt2") is not None:
            self.skipTest("host already has bt2")
        with (
            CoreArtifactReader(self.root) as reader,
            self.assertRaisesRegex(TraceDecodeError, "CTF_UNAVAILABLE") as caught,
        ):
            list(BabeltraceTraceDecoder().iter_ctf(reader, selection(reader)))
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_invalid_configuration(self):
        for arguments in (
            {"max_messages": True},
            {"timeout_seconds": float("nan")},
            {"max_frame_bytes": 0},
            {"python_executable": ""},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                BabeltraceDecoderConfiguration(**arguments)

    def test_ambient_cancellation_is_request_local_and_does_not_capture_a_context(self):
        probe = QueryCancellationProbe()
        self.assertFalse(probe())
        shared_decoder = BabeltraceTraceDecoder()
        barrier = threading.Barrier(2)

        def checkpoint(cancelled):
            event = threading.Event()
            if cancelled:
                event.set()
            token = _QUERY_CANCELLED.set(event)
            try:
                barrier.wait(timeout=5)
                self.assertEqual(probe(), cancelled)
                try:
                    shared_decoder._checkpoint()
                except TraceDecodeError as error:
                    return error.code
                return "ready"
            finally:
                _QUERY_CANCELLED.reset(token)

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(
                list(executor.map(checkpoint, (True, False))),
                ["CTF_CANCELLED", "ready"],
            )
        self.assertFalse(probe())
        event = threading.Event()
        token = _QUERY_CANCELLED.set(event)
        try:
            self.assertFalse(probe())
            event.set()
            with (
                CoreArtifactReader(self.root) as reader,
                self.assertRaisesRegex(TraceDecodeError, "CTF_CANCELLED"),
            ):
                list(shared_decoder.iter_ctf(reader, selection(reader)))
        finally:
            _QUERY_CANCELLED.reset(token)

    def test_artifact_scope_and_archive_quota_still_apply(self):
        with CoreArtifactReader(self.root) as reader:
            spec = selection(reader)
            with self.assertRaises(ArtifactBoundaryError):
                list(
                    BabeltraceTraceDecoder().iter_ctf(
                        reader.scoped(spec.artifact_ids[:1]), spec
                    )
                )
        with self.assertRaises(ArtifactBoundaryError):
            CoreArtifactReader(self.root, limits=ArtifactLimits(max_artifact_bytes=8))
        archive = self.root / "unsafe.tar"
        with tarfile.open(archive, "w") as target:
            member = tarfile.TarInfo("../metadata")
            member.size = 1
            target.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(ArtifactBoundaryError):
            CoreArtifactReader(archive)

    def test_source_metadata_keeps_byte_orders_and_digest(self):
        limits = {"max_metadata_bytes": 10000}
        records, paths = _metadata(self.root, limits)
        self.assertEqual(len(paths), 1)
        self.assertEqual(records[0]["byte_order_declarations"], ["le", "le", "le"])
        self.assertEqual(len(records[0]["sha256"]), 64)
        with self.assertRaisesRegex(DecodeFailure, "CTF_QUOTA"):
            _metadata(self.root, {"max_metadata_bytes": 5})

    def test_typed_nested_fields_preserve_integer_bool_real_and_string(self):
        class Integer(int):
            cls = SimpleNamespace(field_value_range=64)

        class Boolean(Integer):
            pass

        class Signed(Integer):
            pass

        class String(str):
            cls = None

        class Structure(dict):
            cls = None

        class Real(float):
            cls = None

        bt = SimpleNamespace(
            _IntegerFieldConst=Integer,
            _SignedIntegerFieldConst=Signed,
            _BoolFieldConst=Boolean,
            _StringFieldConst=String,
            _StructureFieldConst=Structure,
            _RealFieldConst=Real,
        )
        value, types = _field(
            bt,
            Structure(
                large=Integer(2**64 - 1),
                neg=Signed(-5),
                flag=Boolean(1),
                nested=Structure(text=String("42"), ratio=Real(1.5)),
            ),
            {"max_field_depth": 16, "max_field_items": 100, "max_frame_bytes": 1000},
            [0],
        )
        self.assertIs(type(value["large"]), int)
        self.assertIs(type(value["flag"]), bool)
        self.assertEqual(types["members"]["neg"]["kind"], "signed_integer")
        self.assertEqual(value["nested"], {"text": "42", "ratio": 1.5})
        with self.assertRaisesRegex(DecodeFailure, "CTF_QUOTA"):
            _field(
                bt,
                Structure(a=Integer(1), b=Integer(2)),
                {"max_field_depth": 16, "max_field_items": 2},
                [0],
            )

    def test_clock_cycles_offsets_precision_and_origin_are_preserved(self):
        cls = SimpleNamespace(
            uuid=None,
            name="mono",
            origin_is_unix_epoch=False,
            frequency=100,
            offset=SimpleNamespace(seconds=-2, cycles=5),
            precision=2,
        )
        snapshot = SimpleNamespace(
            clock_class=cls, value=20, ns_from_origin=-1750000000
        )
        time, domain, detail = _clock(SimpleNamespace(), snapshot, "trace-one")
        self.assertEqual(time, -1750000000)
        self.assertEqual(domain, "ctf:trace-one:mono")
        self.assertEqual(detail["cycles"], 20)
        self.assertEqual(detail["precision_cycles"], 2)
        self.assertEqual(detail["offset_seconds"], -2)

    def uuid_fixture(self, trace_uuid, clock_uuid, name="mono", unix=False):
        class Metadata(SimpleNamespace):
            @property
            def uuid(self):
                if isinstance(self.uuid_result, BaseException):
                    raise self.uuid_result
                return self.uuid_result

        class StreamBeginningMessage(SimpleNamespace):
            pass

        class StreamEndMessage(SimpleNamespace):
            pass

        trace = Metadata(addr=1, uuid_result=trace_uuid)
        clock = Metadata(
            uuid_result=clock_uuid, name=name, origin_is_unix_epoch=unix,
            frequency=100, offset=SimpleNamespace(seconds=-2, cycles=5), precision=2,
        )
        stream = SimpleNamespace(
            trace=trace, addr=2, id=7,
            cls=SimpleNamespace(id=5, default_clock_class=clock),
        )
        snapshot = SimpleNamespace(
            clock_class=clock, value=20, ns_from_origin=-1750000000,
        )
        messages = [
            kind(stream=stream, default_clock_snapshot=snapshot)
            for kind in (StreamBeginningMessage, StreamEndMessage)
        ]
        bt = SimpleNamespace(
            find_plugin=lambda name: SimpleNamespace(source_component_classes={"fs": object()}),
            ComponentSpec=lambda *args: args,
            TraceCollectionMessageIterator=lambda components: iter(messages),
        )
        limits = {
            "max_metadata_bytes": 10000, "max_messages": 2, "max_field_items": 100,
            "max_worker_memory_bytes": 1024 * 1024 * 1024,
            "max_frame_bytes": 10000, "max_output_bytes": 20000,
        }
        return SimpleNamespace(bt=bt, clock=clock, messages=messages, limits=limits)

    def test_mip_uuid_access_preserves_identity_fallbacks_and_clock_metadata(self):
        trace_uuid = UUID("00000000-0000-0000-0000-000000000001")
        clock_uuid = UUID("00000000-0000-0000-0000-000000000002")
        for mip, trace_value, clock_value in (
            (0, trace_uuid, clock_uuid),
            (0, None, None),
            (1, ValueError("trace UUID requires MIP 0"), ValueError("clock UUID requires MIP 0")),
        ):
            for name in ("mono", None):
                for unix in (False, True):
                    with self.subTest(mip=mip, uuid=trace_value, name=name, unix=unix):
                        fixture = self.uuid_fixture(trace_value, clock_value, name, unix)
                        metadata, _ = _metadata(self.root, fixture.limits)
                        digest = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()[:20]
                        expected_trace = "trace-0:" + (
                            str(trace_value) if mip == 0 and trace_value is not None else digest
                        )
                        expected_uuid = str(clock_value) if mip == 0 and clock_value is not None else None
                        records = list(worker._messages(fixture.bt, self.root, fixture.limits))
                        self.assertEqual(len(records), 2)
                        self.assertEqual(records[0]["decoder_metadata"]["source_metadata"], metadata)
                        for ordinal, record in enumerate(records):
                            self.assertEqual(record["message_ordinal"], ordinal)
                            self.assertEqual(record["trace_uid"], expected_trace)
                            self.assertEqual(record["stream_uid"], expected_trace + ":class-5:stream-7")
                            self.assertEqual(record["timestamp_ns"], -1750000000)
                            self.assertEqual(record["clock_domain"], "unix" if unix else
                                             "ctf:" + expected_trace + ":" + (expected_uuid or name or "default"))
                            self.assertEqual(record["decoder_metadata"]["clock"], {
                                "cycles": 20, "frequency": 100, "offset_seconds": -2,
                                "offset_cycles": 5, "precision_cycles": 2,
                                "origin_is_unix_epoch": unix, "name": name, "uuid": expected_uuid,
                            })

    def test_uuid_compatibility_does_not_hide_genuine_worker_failures(self):
        class InvalidUuid:
            def __str__(self):
                raise ValueError("invalid UUID value")

        for fault in ("none", "trace-access", "clock-access", "trace-value", "clock-value", "clock-time", "iterator"):
            with self.subTest(fault=fault):
                trace_uuid = RuntimeError("trace failure") if fault == "trace-access" else None
                clock_uuid = RuntimeError("clock failure") if fault == "clock-access" else None
                if fault == "trace-value":
                    trace_uuid = InvalidUuid()
                if fault == "clock-value":
                    clock_uuid = InvalidUuid()
                fixture = self.uuid_fixture(trace_uuid, clock_uuid)
                if fault == "clock-time":
                    class BrokenSnapshot(SimpleNamespace):
                        @property
                        def ns_from_origin(self):
                            raise ValueError("invalid clock time")

                    fixture.messages[0].default_clock_snapshot = BrokenSnapshot(
                        clock_class=fixture.clock, value=20,
                    )
                if fault == "iterator":
                    def broken_iterator(components):
                        raise ValueError("malformed packet")

                    fixture.bt.TraceCollectionMessageIterator = broken_iterator
                if fault != "none":
                    error_type = RuntimeError if fault.endswith("access") else ValueError
                    with self.assertRaises(error_type):
                        list(worker._messages(fixture.bt, self.root, fixture.limits))
                # The worker must still report a malformed-input frame for genuine failures.
                buffer = io.BytesIO()
                with (
                    io.TextIOWrapper(buffer, encoding="ascii") as output,
                    patch.dict(sys.modules, {"bt2": fixture.bt}),
                    patch.object(worker, "_memory_limit", return_value=None),
                    patch.object(sys, "argv", ["worker", str(self.root), json.dumps(fixture.limits)]),
                    patch.object(sys, "stdout", output),
                ):
                    self.assertEqual(worker.main(), 0 if fault == "none" else 1)
                    output.flush()
                    frames = [json.loads(line) for line in buffer.getvalue().splitlines()]
                    if fault == "none":
                        self.assertEqual(len(frames), 3)
                        self.assertEqual(frames[-1], {"complete": True, "messages": 2})
                    else:
                        self.assertEqual(frames, [{"error": "CTF_MALFORMED"}])

    def fake_process(self, script):
        original = subprocess.Popen
        processes = []

        def launch(*args, **kwargs):
            result = original(
                [sys.executable, "-I", "-u", "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            processes.append(result)
            return result

        return patch(
            "router_dump_analyzer._babeltrace_process.subprocess.Popen",
            side_effect=launch,
        ), processes

    def test_timeout_cancellation_and_early_close_terminate_native_process(self):
        for mode in ("timeout", "cancel", "close"):
            with self.subTest(mode=mode), CoreArtifactReader(self.root) as reader:
                cancelled = threading.Event()
                decoder = BabeltraceTraceDecoder(
                    BabeltraceDecoderConfiguration(timeout_seconds=0.2),
                    cancellation_probe=cancelled.is_set,
                )
                message = {
                    "kind": "event",
                    "trace_uid": "trace",
                    "stream_uid": "stream",
                    "packet_sequence": None,
                    "message_ordinal": 0,
                    "event_name": "synthetic",
                    "timestamp_ns": None,
                    "timestamp_uncertainty_ns": None,
                    "clock_domain": None,
                    "payload": {"count": 42},
                }
                script = (
                    "import time; "
                    + (
                        "print(" + repr(json.dumps(message)) + ", flush=True); "
                        if mode == "close"
                        else ""
                    )
                    + "time.sleep(30)"
                )
                mocked, processes = self.fake_process(script)
                with mocked:
                    iterator = decoder.iter_ctf(reader, selection(reader))
                    if mode == "close":
                        next(iterator)
                        iterator.close()
                    else:
                        if mode == "cancel":
                            timer = threading.Timer(0.05, cancelled.set)
                            timer.start()
                        with self.assertRaisesRegex(
                            TraceDecodeError,
                            "CTF_TIMEOUT" if mode == "timeout" else "CTF_CANCELLED",
                        ):
                            list(iterator)
                        if mode == "cancel":
                            timer.join()
                self.assertIsNotNone(processes[0].poll())

    def test_protocol_quota_and_malformed_errors(self):
        for output, code in (
            ("x" * 200, "CTF_QUOTA"),
            ('{"error":"CTF_MALFORMED"}', "CTF_MALFORMED"),
            ('{"complete":true,"messages":1}', "CTF_PROTOCOL"),
            ("not JSON", "CTF_PROTOCOL"),
        ):
            with self.subTest(code=code), CoreArtifactReader(self.root) as reader:
                mocked, _ = self.fake_process("print(" + repr(output) + ")")
                with mocked, self.assertRaisesRegex(TraceDecodeError, code):
                    list(
                        BabeltraceTraceDecoder(
                            BabeltraceDecoderConfiguration(max_frame_bytes=128)
                        ).iter_ctf(reader, selection(reader))
                    )


@unittest.skipUnless(
    importlib.util.find_spec("bt2") is not None
    or os.environ.get("RSL_BABELTRACE_PYTHON"),
    "optional native Babeltrace 2 binding is unavailable",
)
class NativeTraceDecoderTests(unittest.TestCase):
    def decoder(self, **limits):
        return BabeltraceTraceDecoder(
            BabeltraceDecoderConfiguration(
                python_executable=os.environ.get(
                    "RSL_BABELTRACE_PYTHON", sys.executable
                ),
                **limits,
            )
        )

    def test_native_endianness_clock_and_ingestion(self):
        with tempfile.TemporaryDirectory() as temporary:
            for endian in ("le", "be"):
                root = Path(temporary) / endian
                write_trace(root, endian)
                with CoreArtifactReader(root) as reader:
                    messages = list(self.decoder().iter_ctf(reader, selection(reader)))
                event = next(
                    item for item in messages if isinstance(item, CtfEventRecord)
                )
                self.assertEqual(event.payload, {"count": 42, "text": "hello"})
                self.assertEqual(event.timestamp_ns, 40)
                self.assertEqual(event.decoder_metadata["clock"]["cycles"], 23)
                self.assertEqual(
                    event.decoder_metadata["field_types"]["payload"]["members"][
                        "count"
                    ]["bits"],
                    32,
                )
                self.assertTrue(event.evidence)
                result = IngestionCoordinator(trace_decoder=self.decoder()).ingest(
                    NativeTracePlugin(), root
                )
                self.assertTrue(result.revision_id)

    def test_native_malformed_and_message_quota(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_trace(root)
            with (
                CoreArtifactReader(root) as reader,
                self.assertRaisesRegex(TraceDecodeError, "CTF_QUOTA"),
            ):
                list(self.decoder(max_messages=1).iter_ctf(reader, selection(reader)))
            (root / "channel0").write_bytes(b"broken")
            with (
                CoreArtifactReader(root) as reader,
                self.assertRaisesRegex(TraceDecodeError, "CTF_MALFORMED"),
            ):
                list(self.decoder().iter_ctf(reader, selection(reader)))

    def test_native_nested_signed_enumeration_and_array_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_trace(root)
            metadata = (root / "metadata").read_text(encoding="utf-8")
            metadata = metadata.replace(
                "uint32_t count; string text;",
                """uint32_t count; string text;
integer { size = 16; align = 8; signed = true; byte_order = le; } signed_count;
enum : uint32_t { ZERO = 0, ONE = 1 } choice;
struct { uint32_t samples[2]; } nested;""",
            )
            (root / "metadata").write_text(metadata, encoding="utf-8")
            with (root / "channel0").open("ab") as stream:
                stream.write(struct.pack("<hIII", -3, 1, 7, 8))
            with CoreArtifactReader(root) as reader:
                messages = list(self.decoder().iter_ctf(reader, selection(reader)))
            event = next(item for item in messages if isinstance(item, CtfEventRecord))
            self.assertEqual(event.payload["signed_count"], -3)
            self.assertEqual(event.payload["choice"], 1)
            self.assertEqual(event.payload["nested"], {"samples": [7, 8]})
            types = event.decoder_metadata["field_types"]["payload"]["members"]
            self.assertEqual(types["choice"]["kind"], "unsigned_enumeration")
            self.assertEqual(types["choice"]["labels"], ["ONE"])
            self.assertEqual(types["signed_count"]["kind"], "signed_integer")

    def test_native_stream_identity_includes_stream_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_trace(root)
            with (root / "metadata").open("a", encoding="utf-8") as metadata:
                metadata.write("""\nstream { id = 1; event.header := struct { uint32_t id; timestamp_t timestamp; }; };
event { name = "other"; id = 0; stream_id = 1; fields := struct { uint32_t count; string text; }; };\n""")
            (root / "channel1").write_bytes(
                struct.pack("<IIIQI", 0xC1FC1FC1, 1, 0, 24, 43) + b"world\0"
            )
            with CoreArtifactReader(root) as reader:
                events = [
                    item
                    for item in self.decoder().iter_ctf(reader, selection(reader))
                    if isinstance(item, CtfEventRecord)
                ]
            self.assertEqual(len(events), 2)
            self.assertNotEqual(events[0].stream_uid, events[1].stream_uid)
            self.assertEqual(
                {item.decoder_metadata["stream_class_id"] for item in events}, {0, 1}
            )

    def test_native_discarded_records_and_packets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_trace(root)
            metadata = (root / "metadata").read_text(encoding="utf-8")
            metadata = metadata.replace(
                "stream { id = 0;",
                """stream { id = 0;
packet.context := struct { timestamp_t timestamp_begin; timestamp_t timestamp_end;
uint64_t content_size; uint64_t packet_size; uint64_t events_discarded; uint64_t packet_seq_num; };""",
            )
            (root / "metadata").write_text(metadata, encoding="utf-8")
            packets = []
            for begin, end, stamp, discarded, sequence in (
                (10, 30, 23, 0, 0),
                (40, 60, 50, 3, 2),
            ):
                packets.append(
                    struct.pack(
                        "<IIQQQQQQIQI",
                        0xC1FC1FC1,
                        0,
                        begin,
                        end,
                        78 * 8,
                        78 * 8,
                        discarded,
                        sequence,
                        0,
                        stamp,
                        42,
                    )
                    + b"hello\0"
                )
            (root / "channel0").write_bytes(b"".join(packets))
            with CoreArtifactReader(root) as reader:
                messages = list(self.decoder().iter_ctf(reader, selection(reader)))
            lost_events = next(
                item for item in messages if isinstance(item, CtfDiscardedEvents)
            )
            lost_packets = next(
                item for item in messages if isinstance(item, CtfDiscardedPackets)
            )
            self.assertEqual(lost_events.count, 3)
            self.assertEqual(lost_packets.count, 1)
            self.assertEqual(
                lost_events.decoder_metadata["clock"]["frequency"], 1000000000
            )
            self.assertTrue(lost_packets.evidence)

    def test_concurrent_native_package_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("first", "second")]
            for index, path in enumerate(paths):
                write_trace(path)
                content = (path / "channel0").read_bytes()
                (path / "channel0").write_bytes(
                    content.replace(b"hello", (b"first", b"other")[index])
                )
            decoder = self.decoder()

            def decode(path):
                with CoreArtifactReader(path) as reader:
                    return next(
                        message.payload["text"]
                        for message in decoder.iter_ctf(reader, selection(reader))
                        if isinstance(message, CtfEventRecord)
                    )

            with ThreadPoolExecutor(max_workers=2) as executor:
                self.assertEqual(list(executor.map(decode, paths)), ["first", "other"])


if __name__ == "__main__":
    unittest.main()

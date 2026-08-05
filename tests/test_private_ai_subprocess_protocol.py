from __future__ import annotations

import ast
import json
import unittest
from hashlib import sha256
from pathlib import Path

from router_dump_analyzer.canonical import (
    strict_canonical_json,
    strict_canonical_json_sha256,
)
from router_dump_analyzer.private_analysis.local_subprocess_protocol import (
    MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES,
    PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
    PrivateAnalysisLocalSubprocessMessage,
    PrivateAnalysisLocalSubprocessMessageKind,
    PrivateAnalysisLocalSubprocessRunnerFailureReason,
    decode_private_analysis_local_subprocess_message,
    encode_private_analysis_local_subprocess_message,
    private_analysis_local_subprocess_message_dict,
    private_analysis_local_subprocess_message_frame,
    private_analysis_local_subprocess_message_from_dict,
    private_analysis_local_subprocess_message_from_frame,
    validate_private_analysis_local_subprocess_sequence,
)
from router_dump_analyzer.value_core import MAX_JSON_SAFE_INTEGER

RUN_DIGEST = "sha256:" + sha256(b"private-analysis-run").hexdigest()
OTHER_RUN_DIGEST = "sha256:" + sha256(b"other-private-analysis-run").hexdigest()


def _sequence(kind: PrivateAnalysisLocalSubprocessMessageKind) -> int:
    if kind is PrivateAnalysisLocalSubprocessMessageKind.HELLO:
        return 0
    if kind is PrivateAnalysisLocalSubprocessMessageKind.READY:
        return 1
    if kind is PrivateAnalysisLocalSubprocessMessageKind.START:
        return 2
    return 3


def _payload(kind: PrivateAnalysisLocalSubprocessMessageKind) -> dict[str, object]:
    if kind in {
        PrivateAnalysisLocalSubprocessMessageKind.HELLO,
        PrivateAnalysisLocalSubprocessMessageKind.READY,
    }:
        return {}
    if kind is PrivateAnalysisLocalSubprocessMessageKind.START:
        return {
            "request": {"contract_version": "request.v1", "nested": [1, True]},
            "tool_catalog": {"contract_version": "catalog.v1", "tools": []},
        }
    if kind is PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE:
        return {
            "reason": PrivateAnalysisLocalSubprocessRunnerFailureReason.FAILED.value
        }
    field = {
        PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL: "tool_call",
        PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT: "tool_result",
        PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR: "tool_error",
        PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT: "analysis_result",
    }[kind]
    return {field: {"contract_version": f"{field}.v1", "value": "sensitive"}}


def _message(
    kind: PrivateAnalysisLocalSubprocessMessageKind,
    *,
    sequence: int | None = None,
    payload: object | None = None,
) -> PrivateAnalysisLocalSubprocessMessage:
    return PrivateAnalysisLocalSubprocessMessage(
        run_digest=RUN_DIGEST,
        sequence=_sequence(kind) if sequence is None else sequence,
        kind=kind,
        payload=_payload(kind) if payload is None else payload,
    )


class PrivateAnalysisLocalSubprocessProtocolTests(unittest.TestCase):
    def test_closed_message_and_failure_vocabularies(self) -> None:
        self.assertEqual(
            [kind.value for kind in PrivateAnalysisLocalSubprocessMessageKind],
            [
                "hello",
                "ready",
                "start",
                "tool_call",
                "tool_result",
                "tool_error",
                "analysis_result",
                "runner_failure",
            ],
        )
        self.assertEqual(
            {
                reason.value
                for reason in PrivateAnalysisLocalSubprocessRunnerFailureReason
            },
            {"unavailable", "failed"},
        )

    def test_every_kind_round_trips_as_one_canonical_lf_frame(self) -> None:
        for kind in PrivateAnalysisLocalSubprocessMessageKind:
            with self.subTest(kind=kind):
                message = _message(kind)
                envelope = private_analysis_local_subprocess_message_dict(message)
                frame = encode_private_analysis_local_subprocess_message(message)

                self.assertEqual(
                    frame,
                    strict_canonical_json(envelope).encode("utf-8") + b"\n",
                )
                self.assertTrue(frame.endswith(b"\n"))
                self.assertEqual(frame.count(b"\n"), 1)
                self.assertNotIn(b"\r", frame)
                self.assertLessEqual(
                    len(frame), MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES
                )

                decoded = decode_private_analysis_local_subprocess_message(frame)
                self.assertEqual(decoded, message)
                self.assertEqual(
                    private_analysis_local_subprocess_message_from_frame(frame),
                    message,
                )
                self.assertEqual(
                    private_analysis_local_subprocess_message_frame(message), frame
                )
                self.assertEqual(
                    private_analysis_local_subprocess_message_from_dict(envelope),
                    message,
                )

    def test_digest_covers_every_envelope_member_except_itself(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.START)
        envelope = private_analysis_local_subprocess_message_dict(message)
        supplied_digest = envelope.pop("message_digest")
        self.assertEqual(
            supplied_digest,
            "sha256:" + strict_canonical_json_sha256(envelope),
        )

        for field, replacement in (
            ("contract_version", "unsupported.v1"),
            ("run_digest", OTHER_RUN_DIGEST),
            ("sequence", 3),
            ("kind", "tool_call"),
            ("payload", {"request": {}, "tool_catalog": {"changed": True}}),
        ):
            with self.subTest(field=field):
                tampered = private_analysis_local_subprocess_message_dict(message)
                tampered[field] = replacement
                with self.assertRaises((TypeError, ValueError)):
                    private_analysis_local_subprocess_message_from_dict(tampered)

        wrong_digest = private_analysis_local_subprocess_message_dict(message)
        wrong_digest["message_digest"] = OTHER_RUN_DIGEST
        with self.assertRaises(ValueError):
            private_analysis_local_subprocess_message_from_dict(wrong_digest)

    def test_wire_and_revalidation_reject_empty_or_tampered_digests(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.READY)
        self.assertTrue(message.message_digest.startswith("sha256:"))

        empty_wire_digest = private_analysis_local_subprocess_message_dict(message)
        empty_wire_digest["message_digest"] = ""
        with self.assertRaises(ValueError):
            private_analysis_local_subprocess_message_from_dict(empty_wire_digest)
        with self.assertRaises(ValueError):
            decode_private_analysis_local_subprocess_message(
                strict_canonical_json(empty_wire_digest).encode("utf-8") + b"\n"
            )

        object.__setattr__(message, "_message_digest", "")
        with self.assertRaises(ValueError):
            private_analysis_local_subprocess_message_dict(message)
        with self.assertRaises(ValueError):
            validate_private_analysis_local_subprocess_sequence(None, message)

    def test_payloads_are_deeply_detached_on_input_and_output(self) -> None:
        source = {
            "tool_call": {
                "arguments": {"filters": ["original"]},
                "contract_version": "tool_call.v1",
            }
        }
        message = _message(
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
            payload=source,
        )
        source_call = source["tool_call"]
        assert isinstance(source_call, dict)
        source_arguments = source_call["arguments"]
        assert isinstance(source_arguments, dict)
        source_filters = source_arguments["filters"]
        assert isinstance(source_filters, list)
        source_filters.append("input mutation")

        first = message.payload
        first_call = first["tool_call"]
        assert isinstance(first_call, dict)
        first_arguments = first_call["arguments"]
        assert isinstance(first_arguments, dict)
        first_filters = first_arguments["filters"]
        assert isinstance(first_filters, list)
        self.assertEqual(first_filters, ["original"])
        first_filters.append("output mutation")
        self.assertEqual(
            message.payload["tool_call"],
            {
                "arguments": {"filters": ["original"]},
                "contract_version": "tool_call.v1",
            },
        )

        envelope = private_analysis_local_subprocess_message_dict(message)
        payload = envelope["payload"]
        assert isinstance(payload, dict)
        tool_call = payload["tool_call"]
        assert isinstance(tool_call, dict)
        tool_call["changed"] = True
        detached_tool_call = message.payload["tool_call"]
        assert isinstance(detached_tool_call, dict)
        self.assertNotIn("changed", detached_tool_call)

    def test_repr_contains_only_kind_sequence_and_digests(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL)
        rendered = repr(message)
        self.assertIn("kind='tool_call'", rendered)
        self.assertIn("sequence=3", rendered)
        self.assertIn(RUN_DIGEST, rendered)
        self.assertIn(message.message_digest, rendered)
        for forbidden in ("payload", "sensitive", "contract_version", "value"):
            self.assertNotIn(forbidden, rendered)

        failure = _message(PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE)
        self.assertNotIn("failed", repr(failure))

    def test_handshake_positions_and_later_sequence_floor_are_closed(self) -> None:
        for kind, required in (
            (PrivateAnalysisLocalSubprocessMessageKind.HELLO, 0),
            (PrivateAnalysisLocalSubprocessMessageKind.READY, 1),
            (PrivateAnalysisLocalSubprocessMessageKind.START, 2),
        ):
            self.assertEqual(_message(kind).sequence, required)
            for invalid in {0, 1, 2} - {required}:
                with (
                    self.subTest(kind=kind, invalid=invalid),
                    self.assertRaises(ValueError),
                ):
                    _message(kind, sequence=invalid)

        for kind in (
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR,
            PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT,
            PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
        ):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    _message(kind, sequence=2)
                self.assertEqual(
                    _message(kind, sequence=MAX_JSON_SAFE_INTEGER).sequence,
                    MAX_JSON_SAFE_INTEGER,
                )

    def test_sequence_rejects_non_exact_and_out_of_range_numbers(self) -> None:
        for invalid in (-1, MAX_JSON_SAFE_INTEGER + 1, True, False, 3.0, "3", None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                PrivateAnalysisLocalSubprocessMessage(
                    run_digest=RUN_DIGEST,
                    sequence=invalid,
                    kind=PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                    payload=_payload(
                        PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL
                    ),
                )

    def test_sequence_helper_requires_one_global_same_run_increment(self) -> None:
        hello = _message(PrivateAnalysisLocalSubprocessMessageKind.HELLO)
        ready = _message(PrivateAnalysisLocalSubprocessMessageKind.READY)
        start = _message(PrivateAnalysisLocalSubprocessMessageKind.START)
        tool_call = _message(
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
            sequence=3,
        )
        tool_result = _message(
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
            sequence=4,
        )
        validate_private_analysis_local_subprocess_sequence(None, hello)
        for previous, current in zip(
            (hello, ready, start, tool_call),
            (ready, start, tool_call, tool_result),
            strict=True,
        ):
            validate_private_analysis_local_subprocess_sequence(previous, current)

        foreign_ready = PrivateAnalysisLocalSubprocessMessage(
            run_digest=OTHER_RUN_DIGEST,
            sequence=1,
            kind=PrivateAnalysisLocalSubprocessMessageKind.READY,
            payload={},
        )
        maximum = _message(
            PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
            sequence=MAX_JSON_SAFE_INTEGER,
        )
        invalid_pairs: tuple[tuple[object | None, object], ...] = (
            (None, ready),
            (hello, start),
            (hello, hello),
            (hello, foreign_ready),
            (maximum, maximum),
            ({}, ready),
            (hello, {}),
        )
        for invalid_previous, invalid_current in invalid_pairs:
            with (
                self.subTest(previous=invalid_previous, current=invalid_current),
                self.assertRaises((TypeError, ValueError)),
            ):
                validate_private_analysis_local_subprocess_sequence(
                    invalid_previous,
                    invalid_current,
                )

    def test_payload_shapes_are_exact_but_nested_values_remain_unparsed(self) -> None:
        for kind in (
            PrivateAnalysisLocalSubprocessMessageKind.HELLO,
            PrivateAnalysisLocalSubprocessMessageKind.READY,
        ):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                _message(kind, payload={"unexpected": {}})

        invalid_start_payloads: tuple[object, ...] = (
            {},
            {"request": {}},
            {"tool_catalog": {}},
            {"request": {}, "tool_catalog": {}, "unexpected": None},
            {"request": [], "tool_catalog": {}},
            {"request": {}, "tool_catalog": []},
        )
        for invalid_start in invalid_start_payloads:
            with self.subTest(start=invalid_start), self.assertRaises(ValueError):
                _message(
                    PrivateAnalysisLocalSubprocessMessageKind.START,
                    payload=invalid_start,
                )

        wrappers = {
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL: "tool_call",
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT: "tool_result",
            PrivateAnalysisLocalSubprocessMessageKind.TOOL_ERROR: "tool_error",
            PrivateAnalysisLocalSubprocessMessageKind.ANALYSIS_RESULT: "analysis_result",
        }
        for kind, field in wrappers.items():
            with self.subTest(kind=kind):
                # The protocol checks only that the nested value is a detached
                # JSON object; its typed contract validates these fields later.
                accepted = _message(kind, payload={field: {"unknown_later_field": 1}})
                self.assertEqual(accepted.payload, {field: {"unknown_later_field": 1}})
                invalid_wrappers: tuple[object, ...] = (
                    {},
                    {field: []},
                    {field: {}, "unexpected": {}},
                )
                for invalid_wrapper in invalid_wrappers:
                    with self.assertRaises(ValueError):
                        _message(kind, payload=invalid_wrapper)

    def test_runner_failure_has_only_one_closed_payload_free_reason(self) -> None:
        for reason in PrivateAnalysisLocalSubprocessRunnerFailureReason:
            message = _message(
                PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
                payload={"reason": reason.value},
            )
            self.assertEqual(message.payload, {"reason": reason.value})
        for invalid in (
            {},
            {"reason": "timeout"},
            {"reason": "failed", "message": "diagnostic"},
            {"reason": PrivateAnalysisLocalSubprocessRunnerFailureReason.FAILED},
            {"reason": 1},
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises((TypeError, ValueError)),
            ):
                _message(
                    PrivateAnalysisLocalSubprocessMessageKind.RUNNER_FAILURE,
                    payload=invalid,
                )

    def test_payload_tree_is_strict_json_safe_and_bounded(self) -> None:
        cyclic: dict[str, object] = {}
        cyclic["cycle"] = cyclic
        deep: object = "leaf"
        for _ in range(22):
            deep = [deep]
        too_many = {str(index): None for index in range(1_025)}
        invalid_nested: tuple[object, ...] = (
            b"bytes",
            ("tuple",),
            {1: "non-string key"},
            float("nan"),
            float("inf"),
            float("-inf"),
            MAX_JSON_SAFE_INTEGER + 1,
            cyclic,
            deep,
            too_many,
            "x" * 1_048_577,
        )
        for nested in invalid_nested:
            with (
                self.subTest(type=type(nested), preview=type(nested).__name__),
                self.assertRaises((TypeError, ValueError)),
            ):
                _message(
                    PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                    payload={"tool_call": {"nested": nested}},
                )

        class Dictionary(dict[str, object]):
            pass

        with self.assertRaises(ValueError):
            _message(
                PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                payload=Dictionary(tool_call={}),
            )
        with self.assertRaises(ValueError):
            _message(
                PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                payload={"tool_call": Dictionary(value=1)},
            )

    def test_envelope_fields_version_digests_and_types_are_exact(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.HELLO)
        envelope = private_analysis_local_subprocess_message_dict(message)
        for missing in tuple(envelope):
            with self.subTest(missing=missing):
                invalid = dict(envelope)
                del invalid[missing]
                with self.assertRaises(ValueError):
                    private_analysis_local_subprocess_message_from_dict(invalid)
        invalid = dict(envelope)
        invalid["unexpected"] = None
        with self.assertRaises(ValueError):
            private_analysis_local_subprocess_message_from_dict(invalid)

        for run_digest in (
            "",
            "a" * 64,
            "sha256:" + "A" * 64,
            "sha256:" + "g" * 64,
            "sha256:" + "a" * 63,
            1,
        ):
            with self.subTest(run_digest=run_digest), self.assertRaises(ValueError):
                PrivateAnalysisLocalSubprocessMessage(
                    run_digest=run_digest,
                    sequence=0,
                    kind=PrivateAnalysisLocalSubprocessMessageKind.HELLO,
                    payload={},
                )

        for invalid_kind in ("hello", 0, None):
            with self.subTest(kind=invalid_kind), self.assertRaises(TypeError):
                PrivateAnalysisLocalSubprocessMessage(
                    run_digest=RUN_DIGEST,
                    sequence=0,
                    kind=invalid_kind,
                    payload={},
                )
        with self.assertRaises(ValueError):
            PrivateAnalysisLocalSubprocessMessage(
                contract_version="unsupported.v1",
                run_digest=RUN_DIGEST,
                sequence=0,
                kind=PrivateAnalysisLocalSubprocessMessageKind.HELLO,
                payload={},
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisLocalSubprocessMessage(
                run_digest=RUN_DIGEST,
                sequence=0,
                kind=PrivateAnalysisLocalSubprocessMessageKind.HELLO,
                payload={},
                message_digest=OTHER_RUN_DIGEST,
            )

    def test_decode_rejects_incomplete_or_multiple_non_lf_frames(self) -> None:
        valid = encode_private_analysis_local_subprocess_message(
            _message(PrivateAnalysisLocalSubprocessMessageKind.HELLO)
        )
        invalid_frames = (
            b"",
            b"\n",
            valid[:-1],
            valid + b"\n",
            valid + valid,
            valid[:-1] + b"\r\n",
            b"{\r}\n",
            b"\xef\xbb\xbf" + valid,
            b"\xff\n",
            b"[]\n",
            b"null\n",
            b"true\n",
            b"1\n",
            b'"object"\n',
            b"x" * MAX_PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_FRAME_BYTES + b"\n",
        )
        for frame in invalid_frames:
            with (
                self.subTest(length=len(frame), prefix=frame[:12]),
                self.assertRaises(ValueError),
            ):
                decode_private_analysis_local_subprocess_message(frame)

    def test_decode_rejects_duplicates_constants_and_noncanonical_json(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL)
        envelope = private_analysis_local_subprocess_message_dict(message)
        canonical = encode_private_analysis_local_subprocess_message(message)
        body = canonical[:-1]
        noncanonical = (
            b'{"kind":"hello","kind":"hello"}\n',
            b'{"value":NaN}\n',
            b'{"value":Infinity}\n',
            b'{"value":-Infinity}\n',
            b"{ " + body[1:] + b"\n",
            json.dumps(envelope).encode("utf-8") + b"\n",
            body + b" \n",
        )
        for frame in noncanonical:
            with self.subTest(frame=frame[:40]), self.assertRaises(ValueError):
                decode_private_analysis_local_subprocess_message(frame)

    def test_decode_requires_exact_bytes_and_encode_revalidates(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.HELLO)

        class ByteFrame(bytes):
            pass

        for invalid in (
            bytearray(b"{}\n"),
            memoryview(b"{}\n"),
            "{}\n",
            ByteFrame(b"{}\n"),
        ):
            with self.subTest(type=type(invalid)), self.assertRaises(TypeError):
                decode_private_analysis_local_subprocess_message(invalid)
        invalid_messages: tuple[object, ...] = ({}, None, "message")
        for invalid_message in invalid_messages:
            with self.subTest(type=type(invalid_message)), self.assertRaises(TypeError):
                encode_private_analysis_local_subprocess_message(invalid_message)

        object.__setattr__(message, "_message_digest", OTHER_RUN_DIGEST)
        with self.assertRaises(ValueError):
            encode_private_analysis_local_subprocess_message(message)

    def test_message_values_are_sealed(self) -> None:
        message = _message(PrivateAnalysisLocalSubprocessMessageKind.HELLO)
        with self.assertRaises(AttributeError):
            message._message_digest = OTHER_RUN_DIGEST  # type: ignore[misc]
        with self.assertRaises(TypeError):

            class DerivedMessage(PrivateAnalysisLocalSubprocessMessage):
                pass

    def test_protocol_module_is_inert_and_has_no_authority_imports(self) -> None:
        module_path = (
            Path(__file__).parents[1]
            / "src"
            / "router_dump_analyzer"
            / "private_analysis"
            / "local_subprocess_protocol.py"
        )
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertTrue(
            imported.isdisjoint(
                {
                    "asyncio",
                    "http",
                    "importlib",
                    "multiprocessing",
                    "os",
                    "pathlib",
                    "requests",
                    "socket",
                    "subprocess",
                    "threading",
                    "urllib",
                }
            ),
            imported,
        )
        self.assertTrue(
            calls.isdisjoint({"__import__", "compile", "eval", "exec", "open"}), calls
        )

    def test_protocol_version_is_exact_and_stable(self) -> None:
        self.assertEqual(
            PRIVATE_ANALYSIS_LOCAL_SUBPROCESS_PROTOCOL_VERSION,
            "router_dump_analyzer.private_analysis.local_subprocess_protocol.v1",
        )


if __name__ == "__main__":
    unittest.main()

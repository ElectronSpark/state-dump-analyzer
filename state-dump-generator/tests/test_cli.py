from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from state_dump_generator.__main__ import main
from state_dump_generator.model import new_scenario


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _run(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = main(list(arguments))
            except SystemExit as error:
                self.assertIsInstance(error.code, int)
                result = int(error.code)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_validate_reports_json_for_valid_and_semantically_invalid_projects(
        self,
    ) -> None:
        for nodes, expected_exit in (([], 1), ([{"node_id": "r1", "kind": "router"}], 0)):
            with self.subTest(expected_exit=expected_exit):
                project = new_scenario()
                project["nodes"] = nodes
                path = self.root / "project.json"
                path.write_text(json.dumps(project), encoding="utf-8")
                result, stdout, stderr = self._run("validate", str(path))
                self.assertEqual(result, expected_exit)
                self.assertEqual(stderr, "")
                report = json.loads(stdout)
                self.assertEqual(report["ok"], expected_exit == 0)
                self.assertIsInstance(report["warnings"], list)
                if expected_exit == 1:
                    self.assertEqual(report["errors"][0]["path"], "nodes")
                    self.assertIn(
                        "at least one dump-producing node is required",
                        report["errors"][0]["message"],
                    )
                else:
                    self.assertEqual(report["errors"], [])

    def test_validate_reports_load_and_normalization_errors_on_stderr(self) -> None:
        invalid_clock = new_scenario()
        invalid_clock["capture_time_ns"] = "not-an-integer"
        cases = (
            ("malformed-json", b"{"),
            ("invalid-root", b"[]"),
            ("invalid-utf8", b"\xff"),
            ("invalid-model-field", json.dumps(invalid_clock).encode("utf-8")),
        )
        for label, content in cases:
            with self.subTest(label=label):
                path = self.root / f"{label}.json"
                path.write_bytes(content)
                result, stdout, stderr = self._run("validate", str(path))
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn("usage: state-dump-generator", stderr)
                self.assertIn("state-dump-generator: error:", stderr)

    def test_validate_reports_missing_and_non_file_paths_on_stderr(self) -> None:
        for path in (self.root / "missing.json", self.root):
            with self.subTest(path=path.name):
                result, stdout, stderr = self._run("validate", str(path))
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn("state-dump-generator: error:", stderr)

    def test_validate_reports_argument_errors_on_stderr(self) -> None:
        result, stdout, stderr = self._run("validate")
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("the following arguments are required: project", stderr)

    def test_new_author_validate_generate_workflow(self) -> None:
        project_path = self.root / "lab.json"
        output_path = self.root / "lab-state-dumps.tgz"
        result, stdout, stderr = self._run("new", str(project_path))
        self.assertEqual(result, 0)
        self.assertEqual(stdout.strip(), str(project_path))
        self.assertEqual(stderr, "")

        result, stdout, stderr = self._run("validate", str(project_path))
        self.assertEqual(result, 1)
        self.assertFalse(json.loads(stdout)["ok"])
        self.assertEqual(stderr, "")
        result, stdout, stderr = self._run(
            "generate", str(project_path), "--output", str(output_path)
        )
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertFalse(json.loads(stderr)["ok"])
        self.assertFalse(output_path.exists())

        project = json.loads(project_path.read_text(encoding="utf-8"))
        project["nodes"] = [{"node_id": "r1", "kind": "router"}]
        project_path.write_text(json.dumps(project), encoding="utf-8")
        result, stdout, stderr = self._run("validate", str(project_path))
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(stdout)["ok"])
        self.assertEqual(stderr, "")
        result, stdout, stderr = self._run(
            "generate", str(project_path), "--output", str(output_path)
        )
        self.assertEqual(result, 0)
        self.assertEqual(stdout.strip(), str(output_path))
        self.assertEqual(stderr, "")
        with tarfile.open(output_path, "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {"manifest.json", "nodes/r1.tgz"})
            stream = archive.extractfile("manifest.json")
            assert stream is not None
            with stream:
                self.assertEqual(json.load(stream)["node_count"], 1)

    def _run_encoded(self, encoding: str, *arguments: str) -> tuple[int, str, str]:
        stdout_bytes = io.BytesIO()
        stderr_bytes = io.BytesIO()
        stdout = io.TextIOWrapper(stdout_bytes, encoding=encoding)
        stderr = io.TextIOWrapper(stderr_bytes, encoding=encoding)
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = main(list(arguments))
            except SystemExit as error:
                self.assertIsInstance(error.code, int)
                result = int(error.code)
        stdout.flush()
        stderr.flush()
        return (
            result,
            stdout_bytes.getvalue().decode(encoding),
            stderr_bytes.getvalue().decode(encoding),
        )

    def test_windows_console_new_and_generate_report_non_ascii_paths(self) -> None:
        project_path = self.root / "\u6587\u6863.json"
        output_path = self.root / "\u8f93\u51fa.tgz"
        result, stdout, stderr = self._run_encoded("cp1252", "new", str(project_path))
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(r"\u6587\u6863.json", stdout)
        project = json.loads(project_path.read_text(encoding="utf-8"))
        project["nodes"] = [{"node_id": "r1", "kind": "router"}]
        project_path.write_text(json.dumps(project), encoding="utf-8")

        result, stdout, stderr = self._run_encoded(
            "cp1252", "generate", str(project_path), "--output", str(output_path)
        )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(r"\u8f93\u51fa.tgz", stdout)
        with tarfile.open(output_path, "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {"manifest.json", "nodes/r1.tgz"})

    def test_windows_console_errors_preserve_exit_status_and_escape_text(self) -> None:
        for arguments in (
            ("validate", str(self.root / "\u4e0d\u5b58\u5728.json")),
            ("validate", "--\u672a\u77e5"),
            ("\u672a\u77e5",),
        ):
            with self.subTest(arguments=arguments):
                result, stdout, stderr = self._run_encoded("cp1252", *arguments)
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn("state-dump-generator", stderr)
                self.assertNotIn("UnicodeEncodeError", stderr)
        existing = self.root / "\u5df2\u5b58\u5728.json"
        existing.write_text("{}", encoding="utf-8")
        result, stdout, stderr = self._run_encoded("cp1252", "new", str(existing))
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn(r"\u5df2\u5b58\u5728.json", stderr)

    def test_windows_console_json_reports_round_trip_non_bmp_text(self) -> None:
        report = {"ok": False, "errors": ["\u6587\u6863 \U0001f680"], "warnings": []}
        for arguments, report_stream in (
            (("validate", "project.json"), "stdout"),
            (("generate", "project.json", "--output", "out.tgz"), "stderr"),
        ):
            with (
                self.subTest(arguments=arguments),
                mock.patch("state_dump_generator.__main__.load_document", return_value={}),
                mock.patch(
                    "state_dump_generator.__main__.validate_document", return_value=report
                ),
            ):
                result, stdout, stderr = self._run_encoded("cp1252", *arguments)
                self.assertEqual(result, 1)
                self.assertEqual(
                    json.loads(stdout if report_stream == "stdout" else stderr), report
                )

    def test_utf8_console_preserves_non_ascii_output(self) -> None:
        project_path = self.root / "\u6587\u6863.json"
        result, stdout, stderr = self._run_encoded("utf-8", "new", str(project_path))
        self.assertEqual(result, 0)
        self.assertEqual(stdout.strip(), str(project_path))
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()

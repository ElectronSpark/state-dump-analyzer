"""Bounded launcher checks: no Conda setup, fixture generation, or server."""

from __future__ import annotations

import base64
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL_SOURCE = (ROOT / "scripts" / "launch_demo.ps1").read_text(encoding="utf-8")
SHELL_SOURCE = (ROOT / "scripts" / "launch_demo.sh").read_text(encoding="utf-8")
COMPOSITION = "rsl_demo_plugin.deployment:build_plugin_deployment"
OFFLINE_RUNNER = "rsl_demo_plugin.offline_analysis:build_offline_analysis_deployment"


def _powershell() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh")


def _bash() -> str | None:
    if os.name == "nt":
        # Windows' System32 bash.exe is a WSL launcher, not a local Bash shell.
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / (
            "Git/bin/bash.exe"
        )
        return str(git_bash) if git_bash.is_file() else None
    return shutil.which("bash")


def _run(
    command: list[str], *, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        input=input_text,
        timeout=10,
        check=False,
    )


class DemoLauncherTests(unittest.TestCase):
    @unittest.skipUnless(_powershell(), "PowerShell is not installed")
    def test_powershell_full_script_syntax_without_execution(self) -> None:
        result = _run(
            [
                str(_powershell()),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$parseErrors = $null; $tokens = $null; "
                    "$source = (Resolve-Path scripts/launch_demo.ps1).Path; "
                    "$null = [System.Management.Automation.Language.Parser]::ParseFile("
                    "$source, [ref]$tokens, [ref]$parseErrors); "
                    "if ($parseErrors.Count) { $parseErrors | ForEach-Object Message; exit 1 }"
                ),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(_bash(), "Native Bash is not installed")
    def test_bash_full_script_syntax_without_execution(self) -> None:
        # Git's Windows checkout may use CRLF; Bash receives the LF source
        # Linux/WSL checkouts use, without executing setup or launch commands.
        result = _run(
            [str(_bash()), "--noprofile", "--norc", "-n"], input_text=SHELL_SOURCE
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_numeric_loopback_check_is_identical_and_precedes_generation(self) -> None:
        powershell_check = re.search(
            r"\$LoopbackCheck = @'\n(.*?)\n'@", POWERSHELL_SOURCE, re.DOTALL
        )
        shell_check = re.search(r"loopback_check='(.*?)'\n", SHELL_SOURCE, re.DOTALL)
        assert powershell_check is not None and shell_check is not None
        check = powershell_check.group(1)
        self.assertEqual(check, shell_check.group(1))
        self.assertIn("if ($Workbench -or $GrantInstanceOperator)", POWERSHELL_SOURCE)
        self.assertIn(
            'if [[ "${workbench}" == true || "${grant_instance_operator}" == true ]]',
            SHELL_SOURCE,
        )
        for source, marker in (
            (POWERSHELL_SOURCE, "$LoopbackCheck ="),
            (SHELL_SOURCE, "loopback_check="),
        ):
            self.assertLess(source.index(marker), source.index("--ensure-launchable"))
            self.assertIn("cannot override this restriction", source)

        for address in ("127.0.0.1", "127.42.0.2", "::1", "0:0:0:0:0:0:0:1"):
            with self.subTest(allowed=address):
                result = _run([sys.executable, "-c", check, address])
                self.assertEqual(result.returncode, 0, result.stderr)
        for address in (
            "localhost",
            "LOCALHOST",
            "example.test",
            "0.0.0.0",
            "::",
            "192.0.2.1",
            "127.1",
            "[::1]",
            "127.0.0.1 ",
        ):
            with self.subTest(denied=address):
                result = _run([sys.executable, "-c", check, address])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")

    def test_shell_options_and_default_authority_are_explicit(self) -> None:
        self.assertIn("[switch]$Workbench", POWERSHELL_SOURCE)
        self.assertIn("[switch]$GrantInstanceOperator", POWERSHELL_SOURCE)
        self.assertIn("workbench=false", SHELL_SOURCE)
        self.assertIn("grant_instance_operator=false", SHELL_SOURCE)
        self.assertIn("--workbench)\n            workbench=true", SHELL_SOURCE)
        self.assertIn(
            "--grant-instance-operator)\n            grant_instance_operator=true",
            SHELL_SOURCE,
        )
        for source in (POWERSHELL_SOURCE, SHELL_SOURCE):
            self.assertIn("router-state-lab-demo.tgz", source)
            self.assertNotIn("minimal-status.jsonl", source)
            self.assertNotIn("router_dump_analyzer.pipeline_cli", source)
            self.assertIn("No startup data is published", source)
            self.assertIn("no private-analysis policy is enabled automatically", source)
            self.assertIn("scripted demonstration, not a model", source)
            self.assertIn("Optional compact inputs (run separately)", source)

    def _assert_arguments(
        self,
        arguments: list[str],
        *,
        workbench: bool,
        operator: bool,
        trust: bool,
        api_only: bool,
    ) -> None:
        self.assertEqual(
            arguments[:4], ["-m", "router_dump_analyzer", "--plugin", "demo_router"]
        )
        for option, value in (
            ("--input", "selected full-scale fixture.tgz"),
            ("--host", "127.0.0.1"),
            ("--port", "8876"),
            ("--frontend-dir", "frontend folder"),
            ("--control-plane-dir", "durable state folder"),
        ):
            self.assertEqual(arguments[arguments.index(option) + 1], value)
        self.assertEqual("--api-only" in arguments, api_only)
        self.assertEqual("--grant-instance-operator" in arguments, operator)
        self.assertEqual(
            arguments.count("--trust-control-plane-headers"), int(trust or workbench)
        )
        self.assertEqual(
            "--plugin-composition-deployment-module" in arguments, workbench
        )
        self.assertEqual("--private-analysis-deployment-module" in arguments, workbench)
        if workbench:
            self.assertEqual(
                arguments[
                    arguments.index("--plugin-composition-deployment-module") + 1
                ],
                COMPOSITION,
            )
            self.assertEqual(
                arguments[arguments.index("--private-analysis-deployment-module") + 1],
                OFFLINE_RUNNER,
            )
        self.assertIn("--no-browser", arguments)

    @unittest.skipUnless(_powershell(), "PowerShell is not installed")
    def test_powershell_argument_building_preserves_opt_in_boundaries(self) -> None:
        block = POWERSHELL_SOURCE.split("    $CoreArguments = @(", 1)[1].split(
            '    Write-Host "Using generated assembly:', 1
        )[0]
        block = "    $CoreArguments = @( " + block
        cases = list(itertools.product((False, True), repeat=4))
        script = [
            '$ErrorActionPreference = "Stop"',
            '$SelectedFixture = "selected full-scale fixture.tgz"',
            '$BindAddress = "127.0.0.1"',
            "$Port = 8876",
            '$FrontendRoot = "frontend folder"',
            '$ControlPlaneRoot = "durable state folder"',
            "$NoBrowser = $true",
            "function Emit-Arguments {",
            block,
            "ConvertTo-Json -InputObject $CoreArguments -Compress",
            "}",
        ]
        for workbench, operator, trust, api_only in cases:
            script.extend(
                f"${name} = ${str(value).lower()}"
                for name, value in (
                    ("Workbench", workbench),
                    ("GrantInstanceOperator", operator),
                    ("TrustControlPlaneHeaders", trust),
                    ("ApiOnly", api_only),
                )
            )
            script.append("Emit-Arguments")
        encoded = base64.b64encode("\n".join(script).encode("utf-16-le")).decode(
            "ascii"
        )
        result = _run(
            [
                str(_powershell()),
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = result.stdout.splitlines()
        self.assertEqual(len(outputs), len(cases))
        for values, output in zip(cases, outputs, strict=True):
            with self.subTest(values=values):
                self._assert_arguments(
                    json.loads(output),
                    workbench=values[0],
                    operator=values[1],
                    trust=values[2],
                    api_only=values[3],
                )

    @unittest.skipUnless(_bash(), "Native Bash is not installed")
    def test_bash_argument_building_preserves_opt_in_boundaries(self) -> None:
        block = SHELL_SOURCE.split("core_arguments=(", 1)[1].split(
            "printf 'Using generated assembly:", 1
        )[0]
        block = "core_arguments=(" + block
        cases = list(itertools.product((False, True), repeat=4))
        script = [
            "set -Eeuo pipefail",
            "selected_fixture='selected full-scale fixture.tgz'",
            "bind_address=127.0.0.1",
            "port=8876",
            "frontend_root='frontend folder'",
            "control_plane_root='durable state folder'",
            "open_browser=false",
            "emit_arguments() {",
            block,
            "printf '%s\\0' \"${core_arguments[@]}\"",
            "printf '\\n'",
            "}",
        ]
        for workbench, operator, trust, api_only in cases:
            script.extend(
                f"{name}={str(value).lower()}"
                for name, value in (
                    ("workbench", workbench),
                    ("grant_instance_operator", operator),
                    ("trust_control_plane_headers", trust),
                    ("api_only", api_only),
                )
            )
            script.append("emit_arguments")
        result = _run([str(_bash()), "--noprofile", "--norc", "-c", "\n".join(script)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = result.stdout.splitlines()
        self.assertEqual(len(outputs), len(cases))
        for values, output in zip(cases, outputs, strict=True):
            with self.subTest(values=values):
                self._assert_arguments(
                    output.rstrip("\0").split("\0"),
                    workbench=values[0],
                    operator=values[1],
                    trust=values[2],
                    api_only=values[3],
                )


if __name__ == "__main__":
    unittest.main()

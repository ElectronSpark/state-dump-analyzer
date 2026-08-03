from __future__ import annotations

import asyncio
import gc
import sys
import tomllib
import unittest
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.cli import _run_uvicorn

ROOT = Path(__file__).resolve().parents[1]


class _LoopConfigurationError(RuntimeError):
    pass


def _application(events: list[str]) -> Any:
    @asynccontextmanager
    async def lifespan(_application: Any):
        events.append("lifespan.enter")
        try:
            yield
        finally:
            events.append("lifespan.exit")

    return SimpleNamespace(
        router=SimpleNamespace(lifespan_context=lifespan),
    )


def _fake_uvicorn(
    events: list[str],
    *,
    api_generation: str,
    started: bool = True,
    loop_error: BaseException | None = None,
    loop_factory_error: BaseException | None = None,
) -> ModuleType:
    module = ModuleType("uvicorn")

    class Config:
        def __init__(
            self,
            application: Any,
            *,
            host: str,
            port: int,
            lifespan: str,
        ) -> None:
            self.application = application
            events.append(f"config:{host}:{port}:{lifespan}")

    if api_generation == "legacy":

        def setup_event_loop(_self: Any) -> None:
            events.append("setup_event_loop")
            if loop_error is not None:
                raise loop_error

        Config.setup_event_loop = setup_event_loop  # type: ignore[attr-defined]
    elif api_generation == "modern":

        def setup_event_loop(_self: Any) -> None:
            raise AssertionError("the legacy loop setup must not run")

        def get_loop_factory(_self: Any):
            events.append("get_loop_factory")
            if loop_error is not None:
                raise loop_error

            def loop_factory():
                events.append("loop_factory")
                if loop_factory_error is not None:
                    raise loop_factory_error
                return asyncio.new_event_loop()

            return loop_factory

        Config.setup_event_loop = setup_event_loop  # type: ignore[attr-defined]
        Config.get_loop_factory = get_loop_factory  # type: ignore[attr-defined]
    else:  # pragma: no cover - helper misuse.
        raise AssertionError(api_generation)

    class Server:
        def __init__(self, configuration: Any) -> None:
            self.configuration = configuration
            self.started = False
            events.append("server")

        async def serve(self) -> None:
            events.append("serve")
            self.started = started

    module.Config = Config  # type: ignore[attr-defined]
    module.Server = Server  # type: ignore[attr-defined]
    return module


class UvicornCompatibilityTests(unittest.TestCase):
    def test_legacy_loop_setup_preserves_the_complete_application_lifespan(
        self,
    ) -> None:
        events: list[str] = []
        uvicorn = _fake_uvicorn(events, api_generation="legacy")

        with patch.dict(sys.modules, {"uvicorn": uvicorn}):
            _run_uvicorn(_application(events), host="127.0.0.1", port=8765)

        self.assertEqual(
            events,
            [
                "config:127.0.0.1:8765:off",
                "server",
                "setup_event_loop",
                "lifespan.enter",
                "serve",
                "lifespan.exit",
            ],
        )

    def test_modern_loop_factory_preserves_the_complete_application_lifespan(
        self,
    ) -> None:
        events: list[str] = []
        uvicorn = _fake_uvicorn(events, api_generation="modern")

        with patch.dict(sys.modules, {"uvicorn": uvicorn}):
            _run_uvicorn(_application(events), host="127.0.0.1", port=8765)

        self.assertEqual(
            events,
            [
                "config:127.0.0.1:8765:off",
                "server",
                "get_loop_factory",
                "loop_factory",
                "lifespan.enter",
                "serve",
                "lifespan.exit",
            ],
        )

    def test_loop_configuration_failure_cannot_leak_an_unawaited_coroutine(
        self,
    ) -> None:
        cases = (
            ("legacy", "setup"),
            ("modern", "getter"),
            ("modern", "factory"),
        )
        for api_generation, failure_stage in cases:
            with self.subTest(
                api_generation=api_generation,
                failure_stage=failure_stage,
            ):
                events: list[str] = []
                failure = _LoopConfigurationError(
                    "loop configuration failed"
                )
                failure_arguments = (
                    {"loop_factory_error": failure}
                    if failure_stage == "factory"
                    else {"loop_error": failure}
                )
                uvicorn = _fake_uvicorn(
                    events,
                    api_generation=api_generation,
                    **failure_arguments,
                )

                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always")
                    with (
                        patch.dict(sys.modules, {"uvicorn": uvicorn}),
                        self.assertRaisesRegex(
                            _LoopConfigurationError,
                            "loop configuration failed",
                        ),
                    ):
                        _run_uvicorn(
                            _application(events),
                            host="127.0.0.1",
                            port=8765,
                        )
                    gc.collect()

                self.assertFalse(
                    any(
                        "was never awaited" in str(item.message)
                        for item in captured
                    ),
                    captured,
                )
                self.assertNotIn("lifespan.enter", events)

    def test_server_startup_failure_is_stable_across_uvicorn_api_generations(
        self,
    ) -> None:
        for api_generation in ("legacy", "modern"):
            with self.subTest(api_generation=api_generation):
                events: list[str] = []
                uvicorn = _fake_uvicorn(
                    events,
                    api_generation=api_generation,
                    started=False,
                )
                with (
                    patch.dict(sys.modules, {"uvicorn": uvicorn}),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    _run_uvicorn(
                        _application(events),
                        host="127.0.0.1",
                        port=8765,
                    )
                self.assertEqual(stopped.exception.code, 3)
                self.assertIn("lifespan.enter", events)
                self.assertIn("lifespan.exit", events)

    def test_minimum_uvicorn_constraint_matches_metadata_and_ci_gate(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        expected_range = "uvicorn>=0.30,<1"
        for extra in ("web", "test"):
            with self.subTest(extra=extra):
                self.assertIn(
                    expected_range,
                    project["project"]["optional-dependencies"][extra],
                )

        constraint = tuple(
            line.strip()
            for line in (ROOT / "constraints" / "uvicorn-minimum.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertEqual(constraint, ("uvicorn==0.30.0",))

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("uvicorn-minimum:", workflow)
        self.assertIn("constraints/uvicorn-minimum.txt", workflow)
        self.assertIn("version('uvicorn') == '0.30.0'", workflow)
        self.assertIn("python -m pip check", workflow)
        self.assertIn("python -m unittest discover -s tests -v", workflow)


if __name__ == "__main__":
    unittest.main()

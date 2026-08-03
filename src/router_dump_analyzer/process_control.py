"""Dependency-free process-control exception vocabulary.

Executable extension boundaries contain untrusted failures, but these three
signals belong to the hosting process and must always retain their native
control-flow semantics.
"""

from __future__ import annotations

PROCESS_CONTROL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)

__all__ = ["PROCESS_CONTROL_EXCEPTIONS"]

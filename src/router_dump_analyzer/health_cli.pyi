import argparse
from collections.abc import Sequence
from typing import TextIO

__all__ = ['HEALTH_SCHEMA_VERSION', 'EXIT_HEALTHY', 'EXIT_ERROR', 'EXIT_DEGRADED', 'build_parser', 'run', 'main']

HEALTH_SCHEMA_VERSION: str
EXIT_HEALTHY: int
EXIT_ERROR: int
EXIT_DEGRADED: int

def build_parser() -> argparse.ArgumentParser: ...
def run(argv: Sequence[str] | None = None, *, stdout: TextIO = ..., stderr: TextIO = ...) -> int: ...
def main(argv: Sequence[str] | None = None) -> int: ...

from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True, slots=True)
class _StateDirectoryContext:
    state_dir: Path
    def __post_init__(self) -> None: ...

from collections.abc import Callable as Callable, Iterator
from contextlib import contextmanager

@contextmanager
def sqlite_transaction(*, begin: Callable[[], object], commit: Callable[[], object], recover: Callable[[], object], checkpoint: Callable[[], object] | None = None) -> Iterator[None]: ...

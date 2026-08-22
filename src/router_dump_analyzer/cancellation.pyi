from collections.abc import Callable, Iterable

__all__ = ['CancellationErrorFactory', 'check_cancellation_probe', 'cooperatively_sorted']

type CancellationErrorFactory = Callable[[], BaseException]
def check_cancellation_probe(cancellation_probe: Callable[[], bool] | None, *, cancelled_error: CancellationErrorFactory, unavailable_error: CancellationErrorFactory, invalid_result_error: CancellationErrorFactory) -> None: ...
def cooperatively_sorted[Value](values: Iterable[Value], cancellation_checkpoint: Callable[[], None] | None) -> tuple[Value, ...]: ...

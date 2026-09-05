"""Shared quota and iterator lifecycle for bounded read-only world scans."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import Any, cast

from .plugin_api import (
    ReadOnlyWorld,
    RelationDirection,
    RelationshipView,
    ResourceKey,
    ResourceStateView,
    StatusPerspectiveRef,
    WorldBasis,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS


def _direct_call(operation: Callable[[], Any], _message: str) -> Any:
    return operation()


def _identity(value: Any) -> Any:
    return value


class WorldReadBudget:
    """Charge returned rows and point lookups without extending explicit pages.

    Boundaries supply their own errors and optional input-error translation.
    The shared scanner owns quota arithmetic and iterator closing, including
    the sentinel read needed only when the quota truncates the requested scan.
    """

    def __init__(
        self,
        maximum: int,
        error: Callable[[bool], Exception],
    ) -> None:
        self.maximum: int = maximum
        self.remaining: int = maximum
        self._error = error

    @property
    def used(self) -> int:
        return self.maximum - self.remaining

    def charge(self) -> None:
        if self.remaining <= 0:
            raise self._error(True)
        self.remaining -= 1

    def iterate[Item](
        self,
        producer: Callable[[int], Iterable[Item]],
        requested_limit: int | None,
        *,
        invoke: Callable[[Callable[[], Any], str], Any] = _direct_call,
        transform: Callable[[Item], Item] = _identity,
        suppress_secondary_close_errors: tuple[type[Exception], ...] = (),
    ) -> Iterator[Item]:
        if requested_limit is not None and (
            type(requested_limit) is not int or requested_limit < 0
        ):
            raise ValueError("world read limit must be a non-negative integer")
        allowed = (
            self.remaining
            if requested_limit is None
            else min(self.remaining, requested_limit)
        )
        aggregate_limited = requested_limit is None or requested_limit > self.remaining
        producer_limit = (
            allowed + 1 if aggregate_limited and requested_limit != 0 else allowed
        )
        iterator = invoke(
            lambda: iter(producer(producer_limit)),
            "world provider could not start a bounded read",
        )
        sentinel = object()
        count = 0
        completed = False
        try:
            while True:
                item = invoke(
                    lambda: next(iterator, sentinel),
                    "world provider failed during a bounded read",
                )
                if item is sentinel:
                    completed = True
                    break
                if count >= allowed:
                    raise self._error(aggregate_limited)
                self.charge()
                count += 1
                yield transform(cast(Item, item))
        finally:
            try:
                close = invoke(
                    lambda: getattr(iterator, "close", None),
                    "world provider iterator could not be closed",
                )
                if callable(close):
                    invoke(close, "world provider iterator could not be closed")
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except suppress_secondary_close_errors:
                if completed:
                    raise


class AggregateReadWorld:
    """A coordinator-owned world facade sharing one budget across providers."""

    def __init__(
        self,
        world: ReadOnlyWorld,
        *,
        basis: WorldBasis,
        perspective_ref: StatusPerspectiveRef | None,
        maximum_reads: int,
        error: Callable[[bool], Exception],
    ) -> None:
        self._world = world
        self._basis = basis
        self._perspective_ref = perspective_ref
        self._budget = WorldReadBudget(maximum_reads, error)

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._perspective_ref

    @property
    def reads_used(self) -> int:
        return self._budget.used

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self._budget.charge()
        return self._world.state_of(resource)

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]:
        return self._budget.iterate(
            lambda bounded: self._world.iter_states(
                layers=layers, kinds=kinds, limit=bounded
            ),
            limit,
        )

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        return self._budget.iterate(
            lambda bounded: self._world.related(
                resource, direction=direction, relation_types=relation_types, limit=bounded
            ),
            limit,
        )

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        return self._budget.iterate(
            lambda bounded: self._world.iter_relationships(
                relation_types=relation_types, layers=layers, limit=bounded
            ),
            limit,
        )

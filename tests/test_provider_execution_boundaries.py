from __future__ import annotations

import unittest
from contextlib import AbstractContextManager
from types import SimpleNamespace
from typing import Any, Literal

from router_dump_analyzer.multi_node_route import (
    MultiNodeRouteRequestError,
    MultiNodeRouteService,
)
from router_dump_analyzer.normalized_data import (
    NormalizedDataService,
    NormalizedProviderError,
)
from router_dump_analyzer.temporal_topology import (
    TemporalTopologyRequestError,
    TemporalTopologyService,
)

PRIVATE_DETAIL = r"provider failed at C:\Users\alice\secret\provider.py"


class Boom(BaseException):
    """Adversarial non-process-control provider failure."""


class BodyFailure(RuntimeError):
    """An in-flight core/body failure that cleanup must not replace."""


class _ProviderContext(AbstractContextManager[object]):
    def __init__(
        self,
        *,
        enter_error: BaseException | None = None,
        exit_error: BaseException | None = None,
    ) -> None:
        self.enter_error = enter_error
        self.exit_error = exit_error

    def __enter__(self) -> object:
        if self.enter_error is not None:
            raise self.enter_error
        return object()

    def __exit__(self, *_exc: object) -> Literal[False]:
        if self.exit_error is not None:
            raise self.exit_error
        return False


class _LifecycleIterator:
    def __init__(
        self,
        *,
        next_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.next_error = next_error
        self.close_error = close_error

    def __iter__(self) -> _LifecycleIterator:
        return self

    def __next__(self) -> dict[str, Any]:
        if self.next_error is not None:
            raise self.next_error
        raise StopIteration

    def close(self) -> None:
        if self.close_error is not None:
            raise self.close_error


class _Source:
    def __init__(
        self,
        *,
        load_error: BaseException | None = None,
        scope: AbstractContextManager[object] | None = None,
    ) -> None:
        self.load_error = load_error
        self.scope = scope or _ProviderContext()

    def revision_scope(self, _revision_id: str) -> AbstractContextManager[object]:
        return self.scope

    def load_dataset(
        self,
        _revision_id: str | None = None,
        **_selection: object,
    ) -> dict[str, Any]:
        if self.load_error is not None:
            raise self.load_error
        return {"resources": [], "events": [], "relationships": []}

    def revision_id(self, _dataset: object) -> str:
        return "revision-1"

    def indexed_history(self, _dataset: object) -> None:
        return None


class _Policy:
    def __init__(self, *, route_error: BaseException | None = None) -> None:
        self.route_error = route_error

    def analysis_metadata(self, _dataset: object) -> dict[str, object]:
        return {}

    def workspace_metadata(
        self,
        _dataset: object,
        *,
        revision_id: str,
        history_mode: str,
    ) -> dict[str, object]:
        del revision_id, history_mode
        return {}

    def route_resolution_capability(self, _dataset: object) -> dict[str, object]:
        return {}

    def route_row(self, _route_id: str, _dataset: object) -> dict[str, object]:
        if self.route_error is not None:
            raise self.route_error
        return {}

    def source_record_for_event(self, _event: object) -> dict[str, object]:
        return {}


def _normalized_service(
    *,
    load_error: BaseException | None = None,
    scope: AbstractContextManager[object] | None = None,
    policy: _Policy | None = None,
) -> NormalizedDataService:
    return NormalizedDataService(
        _Source(load_error=load_error, scope=scope),  # type: ignore[arg-type]
        policy or _Policy(),  # type: ignore[arg-type]
    )


def _temporal_service(
    *,
    state_reader: Any = None,
    relationship_reader: Any = lambda _timestamp_ns: [],
) -> TemporalTopologyService:
    return TemporalTopologyService(
        {
            "resources": [
                {
                    "resource_id": "node-a/layer/THING/1",
                    "layer": "layer",
                    "kind": "THING",
                    "label": "thing",
                }
            ],
            "events": [],
            "relationship_mutations": [],
        },
        state_reader,
        relationship_reader,
        contract={"nodes": []},
        temporal_metadata={
            "revision_id": "revision-1",
            "timeline_start_ns": 0,
            "timeline_end_ns": 1,
            "capture_ns": 1,
            "default_node": "node-a",
        },
    )


class ProviderExecutionBoundaryTests(unittest.TestCase):
    def test_normalized_provider_error_is_root_exported(self) -> None:
        import router_dump_analyzer

        self.assertIs(
            router_dump_analyzer.NormalizedProviderError,
            NormalizedProviderError,
        )

    def test_normalized_source_contains_boom_and_preserves_process_controls(
        self,
    ) -> None:
        with self.assertRaises(NormalizedProviderError) as caught:
            _normalized_service(load_error=Boom(PRIVATE_DETAIL)).load_dataset()
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                _normalized_service(
                    load_error=exception_type("process control")
                ).load_dataset()

    def test_normalized_context_contains_lifecycle_and_preserves_body_error(
        self,
    ) -> None:
        with self.assertRaises(NormalizedProviderError) as caught, _normalized_service(
            scope=_ProviderContext(enter_error=Boom(PRIVATE_DETAIL))
        ).revision_scope("revision-1"):
            self.fail("enter must fail")
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        body_error = BodyFailure("body failed")
        with self.assertRaises(BodyFailure) as caught_body, _normalized_service(
            scope=_ProviderContext(exit_error=Boom(PRIVATE_DETAIL))
        ).revision_scope("revision-1"):
            raise body_error
        self.assertIs(caught_body.exception, body_error)
        notes = getattr(caught_body.exception, "__notes__", ())
        self.assertIn("plug-in provider context cleanup failed", notes)
        self.assertNotIn(PRIVATE_DETAIL, "\n".join(notes))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for phase in ("enter", "exit"):
                with self.subTest(
                    exception_type=exception_type.__name__,
                    phase=phase,
                ):
                    context = _ProviderContext(
                        enter_error=(
                            exception_type("process control")
                            if phase == "enter"
                            else None
                        ),
                        exit_error=(
                            exception_type("process control")
                            if phase == "exit"
                            else None
                        ),
                    )
                    scope = _normalized_service(scope=context).revision_scope(
                        "revision-1"
                    )
                    with self.assertRaises(exception_type), scope:
                        pass

    def test_normalized_policy_contains_boom_and_preserves_process_controls(
        self,
    ) -> None:
        with self.assertRaises(NormalizedProviderError) as caught:
            _normalized_service(
                policy=_Policy(route_error=Boom(PRIVATE_DETAIL))
            ).route_row("route-1", {})
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                _normalized_service(
                    policy=_Policy(
                        route_error=exception_type("process control")
                    )
                ).route_row("route-1", {})

    def test_temporal_callbacks_contain_boom_and_preserve_process_controls(
        self,
    ) -> None:
        def state_failure(*_args: object) -> object:
            raise Boom(PRIVATE_DETAIL)

        service = _temporal_service(state_reader=state_failure)
        record = service.dataset["resources"][0]
        with self.assertRaises(TemporalTopologyRequestError) as caught:
            service._perspective_state_at(
                record,
                {"layer": "layer"},
                0,
                [],
            )
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(
                callback="state",
                exception_type=exception_type.__name__,
            ):
                def state_control(
                    *_args: object,
                    selected: type[BaseException] = exception_type,
                ) -> object:
                    raise selected("process control")

                service = _temporal_service(state_reader=state_control)
                with self.assertRaises(exception_type):
                    service._perspective_state_at(
                        service.dataset["resources"][0],
                        {"layer": "layer"},
                        0,
                        [],
                    )

        def relationship_failure(_timestamp_ns: int) -> list[dict[str, Any]]:
            raise Boom(PRIVATE_DETAIL)

        service = _temporal_service(relationship_reader=relationship_failure)
        with self.assertRaises(TemporalTopologyRequestError) as caught:
            service._relationship_candidates(0, set())
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception_type=exception_type.__name__):
                def process_control(
                    _timestamp_ns: int,
                    selected: type[BaseException] = exception_type,
                ) -> list[dict[str, Any]]:
                    raise selected("process control")

                with self.assertRaises(exception_type):
                    _temporal_service(
                        relationship_reader=process_control
                    )._relationship_candidates(0, set())

    def test_temporal_relationship_iterator_lifecycle_is_contained(self) -> None:
        for phase in ("next", "close"):
            iterator = _LifecycleIterator(
                next_error=Boom(PRIVATE_DETAIL) if phase == "next" else None,
                close_error=Boom(PRIVATE_DETAIL) if phase == "close" else None,
            )
            with self.subTest(phase=phase), self.assertRaises(
                TemporalTopologyRequestError
            ) as caught:
                _temporal_service(
                    relationship_reader=lambda _timestamp, value=iterator: value
                )._relationship_candidates(0, set())
            self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for phase in ("next", "close"):
                iterator = _LifecycleIterator(
                    next_error=(
                        exception_type("process control")
                        if phase == "next"
                        else None
                    ),
                    close_error=(
                        exception_type("process control")
                        if phase == "close"
                        else None
                    ),
                )
                with (
                    self.subTest(
                        exception_type=exception_type.__name__,
                        phase=phase,
                    ),
                    self.assertRaises(exception_type),
                ):
                    _temporal_service(
                        relationship_reader=(
                            lambda _timestamp, value=iterator: value
                        )
                    )._relationship_candidates(0, set())

    def test_packet_transition_callback_contains_boom_and_preserves_controls(
        self,
    ) -> None:
        def invoke(error: BaseException) -> None:
            def callback(**_kwargs: object) -> tuple[object, list[object]]:
                raise error

            service = object.__new__(MultiNodeRouteService)
            service.policy = SimpleNamespace(  # type: ignore[assignment]
                packet_transition_builder=callback
            )
            service._packet_transition_builder = callback
            service._attach_packet_trace(
                {"segments": []},
                profile_id="profile",
                direction="forward",
                steering_profile_id="default",
                issues=[],
            )

        with self.assertRaises(MultiNodeRouteRequestError) as caught:
            invoke(Boom(PRIVATE_DETAIL))
        self.assertNotIn(PRIVATE_DETAIL, str(caught.exception))
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                invoke(exception_type("process control"))


if __name__ == "__main__":
    unittest.main()

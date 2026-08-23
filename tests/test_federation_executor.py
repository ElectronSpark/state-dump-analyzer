from __future__ import annotations

import inspect
import threading
import unittest
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import cast

from router_dump_analyzer.federation_executor import (
    FederationExecutionProvenance,
    FederationLinkerIdentity,
    FederationLinkerLimits,
    FederationLinkerRegistry,
    FederationLinkExecutionError,
    FederationLinkExecutor,
    FederationLinkOutputError,
    FederationPolicyError,
    FederationRegistrationError,
)
from router_dump_analyzer.plugin_api import (
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    FederatedConnectorClaim,
    FederationLinkRequest,
    FederationLinkResult,
    FederationMatchCandidate,
    FederationMatchState,
    GlobalResourceRef,
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    KeyValue,
    PluginDiagnostic,
    Provenance,
    Quality,
    ResourceKey,
    Value,
)


def _policy(
    *,
    kind: ConnectorMatchPolicyKind = ConnectorMatchPolicyKind.LINKER,
    plugin_id: str = "test.fabric-linker",
) -> ConnectorMatchPolicyDescriptor:
    return ConnectorMatchPolicyDescriptor(
        policy_id="test.connector-match.v1",
        claim_contract_id="test.connector.v1",
        kind=kind,
        argument_names=("token", "side"),
        linker_plugin_id=(
            plugin_id if kind is ConnectorMatchPolicyKind.LINKER else None
        ),
    )


def _claim(
    member_id: str,
    claim_id: str,
    token: KeyValue,
    *,
    side: str = "peer",
    policy: ConnectorMatchPolicyDescriptor | None = None,
    quality: Quality = Quality.EXACT,
    link_type: str = "connector",
    route_trace: InterNodeRouteTraceRole = InterNodeRouteTraceRole.INCLUDE,
) -> FederatedConnectorClaim:
    selected = policy or _policy()
    resource = ResourceKey(
        namespace="test",
        node=f"node-{member_id}",
        layer="forwarding",
        kind="PORT",
        parts=(("id", claim_id),),
    )
    local = ConnectorClaim(
        claim_id=claim_id,
        endpoint=resource,
        claim_contract_id=selected.claim_contract_id,
        match_policy_id=selected.policy_id,
        arguments=(("token", token), ("side", side)),
        provenance=Provenance.OBSERVED,
        quality=quality,
        link_type=link_type,
        presentation=InterNodeLinkPresentation(route_trace=route_trace),
    )
    return FederatedConnectorClaim(
        endpoint=GlobalResourceRef(
            member_id=member_id,
            revision_id=f"revision-{member_id}",
            plugin_instance_id=f"instance-{member_id}",
            resource=resource,
        ),
        claim=local,
    )


def _candidate(claim: FederatedConnectorClaim) -> FederationMatchCandidate:
    return FederationMatchCandidate(
        claim_id=claim.claim.claim_id,
        endpoint=claim.endpoint,
        quality=Quality.EXACT,
    )


def _result(
    source: FederatedConnectorClaim,
    candidates: tuple[FederatedConnectorClaim, ...],
    *,
    state: FederationMatchState | None = None,
    result_id: str | None = None,
    properties: Mapping[str, Value] | None = None,
) -> FederationLinkResult:
    selected_state = state
    if selected_state is None:
        selected_state = (
            FederationMatchState.MATCHED
            if len(candidates) == 1
            else FederationMatchState.AMBIGUOUS
        )
    return FederationLinkResult(
        result_id=result_id or f"result-{source.claim.claim_id}",
        match_policy_id=source.claim.match_policy_id,
        source=source,
        state=selected_state,
        candidates=tuple(_candidate(item) for item in candidates),
        provenance=Provenance.CORRELATED,
        quality=(
            Quality.AMBIGUOUS
            if selected_state is FederationMatchState.AMBIGUOUS
            else Quality.EXACT
        ),
        properties=properties or {},
    )


class _Linker:
    linker_plugin_id = "test.fabric-linker"
    linker_plugin_version = "1.2.3"

    def __init__(self, policy: ConnectorMatchPolicyDescriptor) -> None:
        self.policy = policy
        self.requests: list[FederationLinkRequest] = []
        self.output_factory: Callable[
            [FederationLinkRequest],
            Iterable[FederationLinkResult | PluginDiagnostic],
        ] = lambda request: ()

    def describe_match_policies(
        self,
    ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
        return (self.policy,)

    def link(
        self,
        request: FederationLinkRequest,
    ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
        self.requests.append(request)
        return self.output_factory(request)


class _TextSubclass(str):
    pass


class FederationExecutorTests(unittest.TestCase):
    def test_registry_is_deterministic_and_requires_the_frozen_declaration(
        self,
    ) -> None:
        second_policy = _policy(plugin_id="test.z-linker")

        class Second(_Linker):
            linker_plugin_id = "test.z-linker"
            linker_plugin_version = "9"

        first = _Linker(_policy())
        second = Second(second_policy)
        registry = FederationLinkerRegistry((second, first))

        self.assertEqual(
            registry.identities,
            (
                FederationLinkerIdentity("test.fabric-linker", "1.2.3"),
                FederationLinkerIdentity("test.z-linker", "9"),
            ),
        )
        self.assertEqual(registry.select(_policy()), registry.identities[0])
        with self.assertRaisesRegex(FederationPolicyError, "frozen declaration"):
            registry.select(
                replace(_policy(), claim_contract_id="test.different.v1")
            )

    def test_registry_rejects_duplicate_ids_and_foreign_policy_ownership(self) -> None:
        with self.assertRaisesRegex(FederationRegistrationError, "duplicate"):
            FederationLinkerRegistry((_Linker(_policy()), _Linker(_policy())))

        linker = _Linker(_policy(plugin_id="test.someone-else"))
        with self.assertRaisesRegex(FederationRegistrationError, "invalid"):
            FederationLinkerRegistry((linker,))

    def test_registry_rejects_identity_mutation_during_declaration(self) -> None:
        policy = _policy()

        class MutatingRegistration(_Linker):
            def describe_match_policies(
                self,
            ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
                declared = super().describe_match_policies()
                self.linker_plugin_version = "changed"
                return declared

        with self.assertRaisesRegex(FederationRegistrationError, "invalid"):
            FederationLinkerRegistry((MutatingRegistration(policy),))

    def test_frozen_boundary_rejects_scalar_subclasses(self) -> None:
        exact = _policy(kind=ConnectorMatchPolicyKind.EXACT_TOKEN)
        subclass_policy = replace(exact)
        object.__setattr__(
            subclass_policy,
            "policy_id",
            _TextSubclass(exact.policy_id),
        )
        with self.assertRaisesRegex(FederationPolicyError, "malformed"):
            FederationLinkExecutor().resolve(subclass_policy, ())

        claim = _claim("member-a", "left", "wire", policy=exact)
        subclass_endpoint = replace(claim.endpoint)
        object.__setattr__(
            subclass_endpoint,
            "member_id",
            _TextSubclass(claim.endpoint.member_id),
        )
        with self.assertRaisesRegex(FederationPolicyError, "exact string"):
            FederationLinkExecutor().resolve(
                exact,
                (replace(claim, endpoint=subclass_endpoint),),
            )

    def test_exact_token_is_core_owned_source_oriented_and_deterministic(self) -> None:
        policy = _policy(kind=ConnectorMatchPolicyKind.EXACT_TOKEN)
        claims = (
            _claim("member-c", "c", 7, policy=policy),
            _claim("member-a", "a", 7, policy=policy),
            _claim("member-b", "b", 7, policy=policy),
            _claim("member-a", "same-member", 7, policy=policy),
            _claim("member-d", "unresolved", "7", policy=policy),
        )
        executor = FederationLinkExecutor()

        forward = executor.resolve(policy, claims)
        backward = executor.resolve(policy, tuple(reversed(claims)))

        self.assertEqual(forward, backward)
        self.assertTrue(forward.complete)
        self.assertFalse(forward.truncated)
        self.assertIs(
            forward.provenance,
            FederationExecutionProvenance.CORE_EXACT_TOKEN,
        )
        self.assertIsNone(forward.linker_identity)
        by_claim = {item.source.claim.claim_id: item for item in forward.results}
        self.assertEqual(len(by_claim), len(claims))
        self.assertIs(
            by_claim["unresolved"].state,
            FederationMatchState.UNRESOLVED,
        )
        self.assertEqual(by_claim["unresolved"].candidates, ())
        self.assertIs(by_claim["a"].state, FederationMatchState.AMBIGUOUS)
        self.assertEqual(
            {item.claim_id for item in by_claim["a"].candidates},
            {"b", "c"},
        )
        self.assertNotIn(
            "same-member",
            {item.claim_id for item in by_claim["a"].candidates},
        )

    def test_exact_token_pair_disagreements_fail_closed(self) -> None:
        policy = _policy(kind=ConnectorMatchPolicyKind.EXACT_TOKEN)
        type_claims = (
            _claim(
                "member-a",
                "a",
                "wire",
                policy=policy,
                link_type="underlay.adjacency",
            ),
            _claim(
                "member-b",
                "b",
                "wire",
                policy=policy,
                link_type="overlay.tunnel",
            ),
        )
        executor = FederationLinkExecutor()

        type_conflict = executor.resolve(policy, type_claims)
        self.assertEqual(
            type_conflict,
            executor.resolve(policy, tuple(reversed(type_claims))),
        )
        self.assertTrue(type_conflict.complete)
        for result in type_conflict.results:
            self.assertIs(result.state, FederationMatchState.CONFLICT)
            self.assertEqual(result.link_type, "unknown")
            self.assertEqual(
                result.properties["claimed_link_types"],
                ("overlay.tunnel", "underlay.adjacency"),
            )
            self.assertEqual(
                result.properties["reason"],
                "plugin_link_type_mismatch",
            )
            self.assertIs(result.quality, Quality.AMBIGUOUS)

        presentation_claims = (
            _claim("member-a", "a", "wire", policy=policy),
            _claim(
                "member-b",
                "b",
                "wire",
                policy=policy,
                route_trace=InterNodeRouteTraceRole.OVERLAY,
            ),
        )
        presentation_conflict = executor.resolve(policy, presentation_claims)
        for result in presentation_conflict.results:
            self.assertIs(result.state, FederationMatchState.CONFLICT)
            self.assertEqual(result.link_type, "connector")
            self.assertEqual(
                result.properties["reason"],
                "plugin_route_trace_role_mismatch",
            )
            presentation = cast(
                Mapping[str, Value],
                result.properties["presentation"],
            )
            self.assertEqual(presentation["route_trace"], "conflict")
            self.assertEqual(
                result.properties["projection_role"],
                "presentation_conflict",
            )

    def test_exact_token_respects_result_and_candidate_bounds(self) -> None:
        policy = _policy(kind=ConnectorMatchPolicyKind.EXACT_TOKEN)
        claims = tuple(
            _claim(f"member-{index}", f"claim-{index}", "shared", policy=policy)
            for index in range(5)
        )
        limits = FederationLinkerLimits(max_results=3, max_candidates_per_result=2)
        output = FederationLinkExecutor(limits=limits).resolve(policy, claims)

        self.assertEqual(len(output.results), 3)
        self.assertTrue(output.truncated)
        self.assertFalse(output.complete)
        self.assertTrue(
            all(item.state is FederationMatchState.AMBIGUOUS for item in output.results)
        )
        self.assertTrue(all(len(item.candidates) == 2 for item in output.results))

    def test_large_exact_group_indexes_sources_without_materializing_pairs(self) -> None:
        policy = _policy(kind=ConnectorMatchPolicyKind.EXACT_TOKEN)
        claims = tuple(
            _claim(
                f"member-{index:04d}",
                f"claim-{index:04d}",
                "shared",
                policy=policy,
            )
            for index in range(2_000)
        )
        limits = FederationLinkerLimits(max_results=2, max_candidates_per_result=2)

        output = FederationLinkExecutor(limits=limits).resolve(policy, claims)

        self.assertEqual(len(output.results), 2)
        self.assertTrue(output.truncated)
        self.assertTrue(
            all(item.state is FederationMatchState.AMBIGUOUS for item in output.results)
        )
        self.assertTrue(all(len(item.candidates) == 2 for item in output.results))

    def test_linker_receives_only_request_and_outputs_are_detached_and_sorted(
        self,
    ) -> None:
        policy = _policy()
        left = _claim("member-a", "left", "wire")
        right = _claim("member-b", "right", "wire")
        properties: dict[str, Value] = {"nested": {"value": 1}}
        diagnostic_details: dict[str, Value] = {"selected": "declared"}
        linker = _Linker(policy)

        def outputs(
            request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            yield _result(
                request.claims[1],
                (request.claims[0],),
                properties=properties,
            )
            yield PluginDiagnostic(
                stage=DiagnosticStage.CORRELATE,
                severity=DiagnosticSeverity.INFO,
                code="linker.note",
                message="bounded note",
                recoverable=True,
                details=diagnostic_details,
                origin=DiagnosticOrigin.PLUGIN,
            )
            yield _result(request.claims[0], (request.claims[1],))

        linker.output_factory = outputs
        output = FederationLinkExecutor(
            FederationLinkerRegistry((linker,))
        ).resolve(policy, (right, left))

        self.assertEqual(len(linker.requests), 1)
        self.assertIs(type(linker.requests[0]), FederationLinkRequest)
        self.assertEqual(
            [item.source.endpoint.member_id for item in output.results],
            ["member-a", "member-b"],
        )
        self.assertTrue(output.complete)
        self.assertIs(
            output.provenance,
            FederationExecutionProvenance.LINKER_PLUGIN,
        )
        self.assertEqual(
            output.linker_identity,
            FederationLinkerIdentity("test.fabric-linker", "1.2.3"),
        )
        properties["nested"] = {"value": 99}
        diagnostic_details["selected"] = "mutated"
        object.__setattr__(
            linker.requests[0].claims[0].claim,
            "quality",
            Quality.UNKNOWN,
        )
        result_with_properties = next(
            item for item in output.results if "nested" in item.properties
        )
        nested = cast(Mapping[str, Value], result_with_properties.properties["nested"])
        self.assertEqual(nested["value"], 1)
        self.assertEqual(output.diagnostics[0].details["selected"], "declared")
        self.assertTrue(
            all(item.source.claim.quality is Quality.EXACT for item in output.results)
        )
        self.assertIsInstance(
            result_with_properties.properties,
            type(MappingProxyType({})),
        )
        with self.assertRaises(TypeError):
            result_with_properties.properties["new"] = 1  # type: ignore[index]

    def test_linker_source_and_candidate_must_belong_to_the_request(self) -> None:
        policy = _policy()
        left = _claim("member-a", "left", "wire")
        right = _claim("member-b", "right", "wire")
        outsider = _claim("member-c", "outsider", "wire")
        linker = _Linker(policy)
        linker.output_factory = lambda request: (
            _result(request.claims[0], (outsider,)),
        )
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))

        with self.assertRaisesRegex(FederationLinkOutputError, "outside"):
            executor.resolve(policy, (left, right))

        altered = replace(
            left,
            claim=replace(left.claim, quality=Quality.UNKNOWN),
        )
        linker.output_factory = lambda request: (_result(altered, (right,)),)
        with self.assertRaisesRegex(FederationLinkOutputError, "outside"):
            executor.resolve(policy, (left, right))

    def test_linker_conflict_and_unresolved_states_are_preserved(self) -> None:
        policy = _policy()
        claims = (
            _claim("member-a", "conflict", "wire"),
            _claim("member-b", "candidate", "wire"),
            _claim("member-c", "missing", "other"),
        )
        linker = _Linker(policy)

        def outputs(
            request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            by_id = {item.claim.claim_id: item for item in request.claims}
            return (
                _result(
                    by_id["conflict"],
                    (by_id["candidate"],),
                    state=FederationMatchState.CONFLICT,
                ),
                _result(
                    by_id["candidate"],
                    (by_id["conflict"],),
                    state=FederationMatchState.CONFLICT,
                ),
                _result(
                    by_id["missing"],
                    (),
                    state=FederationMatchState.UNRESOLVED,
                ),
            )

        linker.output_factory = outputs
        output = FederationLinkExecutor(
            FederationLinkerRegistry((linker,))
        ).resolve(policy, claims)

        self.assertEqual(
            {item.state for item in output.results},
            {FederationMatchState.CONFLICT, FederationMatchState.UNRESOLVED},
        )
        self.assertTrue(output.complete)

    def test_changed_linker_identity_and_over_limit_output_fail_closed(self) -> None:
        policy = _policy()
        left = _claim("member-a", "left", "wire")
        right = _claim("member-b", "right", "wire")
        linker = _Linker(policy)
        registry = FederationLinkerRegistry((linker,))
        executor = FederationLinkExecutor(registry)
        linker.linker_plugin_version = "changed"
        with self.assertRaisesRegex(FederationLinkOutputError, "identity changed"):
            executor.resolve(policy, (left, right))

        linker.linker_plugin_version = "1.2.3"
        linker.output_factory = lambda request: (
            _result(request.claims[0], (request.claims[1],), result_id="one"),
            _result(request.claims[1], (request.claims[0],), result_id="two"),
        )
        with self.assertRaisesRegex(FederationLinkOutputError, "result limit"):
            executor.resolve(policy, (left, right), max_results=1)

    def test_linker_identity_is_rechecked_after_output_consumption(self) -> None:
        policy = _policy()
        left = _claim("member-a", "left", "wire")
        right = _claim("member-b", "right", "wire")
        linker = _Linker(policy)

        def mutate_after_outputs(
            request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            yield _result(request.claims[0], (request.claims[1],))
            yield _result(request.claims[1], (request.claims[0],))
            linker.linker_plugin_version = "changed"

        linker.output_factory = mutate_after_outputs
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))

        with self.assertRaisesRegex(FederationLinkOutputError, "during link"):
            executor.resolve(policy, (left, right))

    def test_hook_failures_are_distinct_and_output_errors_keep_diagnostics(self) -> None:
        policy = _policy()
        left = _claim("member-a", "left", "wire")
        right = _claim("member-b", "right", "wire")
        outsider = _claim("member-c", "outsider", "wire")
        linker = _Linker(policy)
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))

        def broken(
            _request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            raise ValueError("private linker failure")

        linker.output_factory = broken
        with self.assertRaises(FederationLinkExecutionError) as hook_error:
            executor.resolve(policy, (left, right))
        self.assertNotIsInstance(hook_error.exception, FederationLinkOutputError)
        self.assertNotIn("private linker failure", str(hook_error.exception))

        def invalid_after_diagnostic(
            request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            yield PluginDiagnostic(
                stage=DiagnosticStage.CORRELATE,
                severity=DiagnosticSeverity.WARNING,
                code="linker.warning",
                message="retained warning",
                recoverable=True,
            )
            yield _result(request.claims[0], (outsider,))

        linker.output_factory = invalid_after_diagnostic
        with self.assertRaises(FederationLinkOutputError) as output_error:
            executor.resolve(policy, (left, right))
        self.assertEqual(
            tuple(item.code for item in output_error.exception.diagnostics),
            ("linker.warning",),
        )

    def test_registration_and_execution_are_trusted_inline_calls(self) -> None:
        policy = _policy()
        caller_thread = threading.get_ident()
        observed_threads: list[int] = []

        class InlineRegistration(_Linker):
            def describe_match_policies(
                self,
            ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
                observed_threads.append(threading.get_ident())
                return (self.policy,)

        linker = InlineRegistration(policy)

        def inline(
            _request: FederationLinkRequest,
        ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
            observed_threads.append(threading.get_ident())
            return ()

        linker.output_factory = inline
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))
        executor.resolve(policy, ())

        self.assertEqual(observed_threads, [caller_thread, caller_thread])
        self.assertNotIn(
            "timeout_seconds",
            inspect.signature(FederationLinkExecutor.resolve).parameters,
        )
        self.assertNotIn(
            "registration_timeout_seconds",
            FederationLinkerLimits.__dataclass_fields__,
        )
        self.assertNotIn(
            "execution_timeout_seconds",
            FederationLinkerLimits.__dataclass_fields__,
        )

    def test_process_control_exceptions_retain_native_semantics(self) -> None:
        policy = _policy()

        class InterruptedRegistration(_Linker):
            def describe_match_policies(
                self,
            ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
                raise SystemExit(7)

        with self.assertRaises(SystemExit):
            FederationLinkerRegistry((InterruptedRegistration(policy),))

        linker = _Linker(policy)
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))
        claim = _claim("member-a", "left", "wire")
        for exception_type in (KeyboardInterrupt, GeneratorExit):
            with self.subTest(exception_type=exception_type):

                def interrupted(
                    _request: FederationLinkRequest,
                    exception_type: type[BaseException] = exception_type,
                ) -> Iterable[FederationLinkResult | PluginDiagnostic]:
                    raise exception_type()

                linker.output_factory = interrupted
                with self.assertRaises(exception_type):
                    executor.resolve(policy, (claim,))


if __name__ == "__main__":
    unittest.main()

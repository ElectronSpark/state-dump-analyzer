from __future__ import annotations

import unittest

from router_dump_analyzer.plugin_api import (
    ConnectorClaim,
    FederatedConnectorClaim,
    FederationLinkResult,
    FederationMatchCandidate,
    FederationMatchState,
    ForwardingMtuConstraint,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingProjectionRequest,
    ForwardingSizeObservation,
    GlobalResourceRef,
    Provenance,
    Quality,
    ResourceKey,
    StatusPerspectiveRef,
    TopologyProjectionRecord,
    TopologyResourceRecord,
    TopologyUsability,
)


def _resource(node: str = "node-a") -> ResourceKey:
    return ResourceKey(
        namespace="test",
        node=node,
        layer="forwarding",
        kind="PORT",
        parts=(("id", 1),),
    )


class _IntegerSubclass(int):
    pass


def _claim(
    *,
    valid_from_ns: int | None = None,
    valid_to_ns: int | None = None,
) -> ConnectorClaim:
    return ConnectorClaim(
        claim_id="claim-a",
        endpoint=_resource(),
        claim_contract_id="test.connector.v1",
        match_policy_id="test.connector.match.v1",
        arguments=(("token", 1),),
        provenance=Provenance.OBSERVED,
        quality=Quality.EXACT,
        valid_from_ns=valid_from_ns,
        valid_to_ns=valid_to_ns,
    )


class ContractValidationBoundaryTests(unittest.TestCase):
    def test_connector_and_topology_keep_one_sided_validity_windows(self) -> None:
        self.assertEqual(_claim(valid_from_ns=10).valid_from_ns, 10)
        self.assertEqual(_claim(valid_to_ns=20).valid_to_ns, 20)

        resource = _resource()
        record = TopologyProjectionRecord(
            projection_id="test-topology",
            status_perspective_id="hardware-observed",
            payload=TopologyResourceRecord(resource=resource),
            usability=TopologyUsability.USABLE,
            source_resources=(resource,),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            valid_from_ns=10,
        )
        self.assertEqual(record.valid_from_ns, 10)
        self.assertIsNone(record.valid_to_ns)

    def test_temporal_bounds_remain_exact_integers(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid_from_ns"):
            _claim(valid_from_ns=True)

        resource = _resource()
        with self.assertRaisesRegex(ValueError, "validity bounds must be integers"):
            TopologyProjectionRecord(
                projection_id="test-topology",
                status_perspective_id="hardware-observed",
                payload=TopologyResourceRecord(resource=resource),
                usability=TopologyUsability.USABLE,
                source_resources=(resource,),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                valid_to_ns=True,
            )

    def test_connector_tuple_and_enum_validation_remains_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "arguments must be a tuple"):
            ConnectorClaim(
                claim_id="claim-a",
                endpoint=_resource(),
                claim_contract_id="test.connector.v1",
                match_policy_id="test.connector.match.v1",
                arguments=[("token", 1)],  # type: ignore[arg-type]
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
            )
        with self.assertRaisesRegex(ValueError, "unsupported.*quality"):
            ConnectorClaim(
                claim_id="claim-a",
                endpoint=_resource(),
                claim_contract_id="test.connector.v1",
                match_policy_id="test.connector.match.v1",
                arguments=(("token", 1),),
                provenance=Provenance.OBSERVED,
                quality="invented",  # type: ignore[arg-type]
            )

    def test_federation_collections_and_booleans_stay_strict(self) -> None:
        local_claim = _claim()
        local = FederatedConnectorClaim(
            endpoint=GlobalResourceRef(
                member_id="member-a",
                revision_id="revision-a",
                plugin_instance_id="plugin-a",
                resource=local_claim.endpoint,
            ),
            claim=local_claim,
        )
        remote_resource = _resource("node-b")
        candidate = FederationMatchCandidate(
            claim_id="claim-b",
            endpoint=GlobalResourceRef(
                member_id="member-b",
                revision_id="revision-b",
                plugin_instance_id="plugin-b",
                resource=remote_resource,
            ),
            quality=Quality.EXACT,
        )
        with self.assertRaisesRegex(ValueError, "candidates must be a tuple"):
            FederationLinkResult(
                result_id="result-a",
                match_policy_id=local_claim.match_policy_id,
                source=local,
                state=FederationMatchState.MATCHED,
                candidates=[candidate],  # type: ignore[arg-type]
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
            )
        with self.assertRaisesRegex(ValueError, "directed must be a boolean"):
            FederationLinkResult(
                result_id="result-a",
                match_policy_id=local_claim.match_policy_id,
                source=local,
                state=FederationMatchState.MATCHED,
                candidates=(candidate,),
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
                directed=1,  # type: ignore[arg-type]
            )

    def test_forwarding_bounds_layers_and_flags_stay_strict(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
        )
        with self.assertRaisesRegex(ValueError, "max_records"):
            ForwardingProjectionRequest(
                ir_version="1.0",
                status_perspective=perspective,
                max_records=True,
            )
        with self.assertRaisesRegex(ValueError, "size_bytes"):
            ForwardingSizeObservation(
                basis_contract_id="test.wire-size.v1",
                size_bytes=True,
            )
        compatible_size = _IntegerSubclass(1_500)
        self.assertIs(
            ForwardingSizeObservation(
                basis_contract_id="test.wire-size.v1",
                size_bytes=compatible_size,
            ).size_bytes,
            compatible_size,
        )
        with self.assertRaisesRegex(ValueError, "completeness"):
            ForwardingMtuConstraint(
                basis_contract_id="test.wire-size.v1",
                limit_bytes=1_500,
                complete=1,  # type: ignore[arg-type]
            )

        layer = ForwardingPacketLayer(
            layer_id="outer-ip",
            contract_id="test.ipv4.v1",
            label="IPv4",
        )
        with self.assertRaisesRegex(ValueError, "identifiers must be unique"):
            ForwardingPacketState(layers=(layer, layer))
        with self.assertRaisesRegex(ValueError, "layers must be a tuple"):
            ForwardingPacketState(layers=[layer])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

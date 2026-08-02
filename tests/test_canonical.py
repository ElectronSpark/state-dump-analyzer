from __future__ import annotations

import unittest
from uuid import UUID

from router_dump_analyzer.canonical import (
    CanonicalValueError,
    canonical_json_sha256,
    canonical_normalized_opaque_value,
    canonical_opaque_value,
    normalized_opaque_value_json,
    opaque_value_json,
    packet_value_json,
    strict_canonical_json_sha256,
)
from router_dump_analyzer.multi_node_route import (
    MultiNodeRouteRequestError,
    MultiNodeRouteService,
)
from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyRequestError,
    _canonical_opaque_key,
)
from router_dump_analyzer.plugin_api import (
    ForwardingPolicyScope,
    KeyAtom,
    ResourceKey,
)


class CanonicalTypedValueTests(unittest.TestCase):
    def test_canonical_digest_profiles_are_centralized_and_explicit(self) -> None:
        value = {"label": "路由器"}

        self.assertEqual(len(canonical_json_sha256(value)), 64)
        self.assertEqual(len(strict_canonical_json_sha256(value)), 64)
        self.assertNotEqual(
            canonical_json_sha256(value),
            strict_canonical_json_sha256(value),
        )

    def test_packet_profile_retains_the_established_wire_format(self) -> None:
        identifier = UUID("7ff7d7dc-88c7-44df-8578-72b049c22500")

        encoded = packet_value_json(
            (
                identifier,
                str(identifier),
                KeyAtom("uuid", identifier.bytes),
                identifier.bytes,
                7,
                None,
            ),
            key_atom_type=KeyAtom,
        )

        self.assertEqual(
            encoded,
            {
                "type": "tuple",
                "items": [
                    {
                        "type": "uuid",
                        "encoding": "rfc4122",
                        "value": str(identifier),
                    },
                    str(identifier),
                    {
                        "type": "key_atom",
                        "type_tag": "uuid",
                        "value": {
                            "type": "bytes",
                            "encoding": "hex",
                            "length": 16,
                            "value": identifier.bytes.hex(),
                        },
                    },
                    {
                        "type": "bytes",
                        "encoding": "hex",
                        "length": 16,
                        "value": identifier.bytes.hex(),
                    },
                    7,
                    None,
                ],
            },
        )

    def test_opaque_profile_preserves_every_atom_and_container_type(self) -> None:
        identifier = UUID("7ff7d7dc-88c7-44df-8578-72b049c22500")
        values = (
            identifier,
            str(identifier),
            identifier.bytes,
            KeyAtom("uuid", identifier.bytes),
            1,
            "1",
            b"1",
            (1,),
            [1],
            True,
            1.0,
        )

        tokens = {
            canonical_opaque_value(value, key_atom_type=KeyAtom)[1] for value in values
        }

        self.assertEqual(len(tokens), len(values))
        for value in values:
            normalized, token = canonical_opaque_value(
                value,
                key_atom_type=KeyAtom,
            )
            self.assertEqual(
                canonical_normalized_opaque_value(
                    normalized,
                    typed_key=token,
                ),
                (normalized, token),
            )
        self.assertEqual(
            opaque_value_json(b"\x00\xff", key_atom_type=KeyAtom),
            {
                "type": "bytes",
                "encoding": "base64",
                "length": 2,
                "value": "AP8=",
            },
        )

    def test_opaque_mapping_order_is_deterministic(self) -> None:
        forward = {"z": 1, "a": [2, 3]}
        reverse = {"a": [2, 3], "z": 1}

        self.assertEqual(
            canonical_opaque_value(forward, key_atom_type=KeyAtom),
            canonical_opaque_value(reverse, key_atom_type=KeyAtom),
        )

    def test_normalized_profile_round_trips_without_transport_depth_inflation(
        self,
    ) -> None:
        value: object = "leaf"
        for _ in range(4):
            value = {"member": value}
        normalized, token = canonical_opaque_value(
            value,
            key_atom_type=KeyAtom,
        )

        self.assertEqual(
            canonical_normalized_opaque_value(
                normalized,
                typed_key=token,
            ),
            (normalized, token),
        )

        too_deep: object = "leaf"
        for _ in range(5):
            too_deep = {"member": too_deep}
        with self.assertRaisesRegex(
            CanonicalValueError,
            "four container levels",
        ):
            canonical_opaque_value(too_deep, key_atom_type=KeyAtom)

    def test_normalized_profile_canonicalizes_mapping_entries_and_rejects_duplicates(
        self,
    ) -> None:
        normalized = {
            "type": "mapping",
            "entries": [
                {
                    "key": {"type": "string", "value": "z"},
                    "value": {"type": "integer", "value": "2"},
                },
                {
                    "key": {"type": "string", "value": "a"},
                    "value": {"type": "integer", "value": "1"},
                },
            ],
        }
        canonical = normalized_opaque_value_json(normalized)
        self.assertEqual(
            [entry["key"]["value"] for entry in canonical["entries"]],
            ["a", "z"],
        )

        duplicate = {
            "type": "mapping",
            "entries": [
                {
                    "key": {"type": "integer", "value": "1"},
                    "value": {"type": "string", "value": "first"},
                },
                {
                    "key": {"value": "1", "type": "integer"},
                    "value": {"type": "string", "value": "second"},
                },
            ],
        }
        with self.assertRaisesRegex(CanonicalValueError, "unique keys"):
            normalized_opaque_value_json(duplicate)

    def test_normalized_profile_validates_tags_encodings_and_cached_token(
        self,
    ) -> None:
        invalid_values = (
            {"type": "integer", "value": "01"},
            {
                "type": "number",
                "encoding": "decimal",
                "value": "1.0",
            },
            {
                "type": "bytes",
                "encoding": "base64",
                "length": 2,
                "value": "AA==",
            },
            {
                "type": "key_atom",
                "type_tag": "vendor-private",
                "value": {"type": "integer", "value": "1"},
            },
            {
                "type": "tuple",
                "items": [{"type": "string", "value": "x"}],
                "extra": True,
            },
            {"type": "string", "value": "x" * 4_097},
            {"type": "integer", "value": "1" * 1_235},
            {
                "type": "list",
                "items": [
                    {"type": "integer", "value": str(index)}
                    for index in range(33)
                ],
            },
        )
        for value in invalid_values:
            with (
                self.subTest(value=value),
                self.assertRaises(CanonicalValueError),
            ):
                normalized_opaque_value_json(value)

        normalized = {"type": "string", "value": "domain"}
        with self.assertRaisesRegex(CanonicalValueError, "does not match"):
            canonical_normalized_opaque_value(
                normalized,
                typed_key="stale-token",
            )

        over_unit_budget = {
            "type": "list",
            "items": [
                {
                    "type": "list",
                    "items": [
                        {"type": "integer", "value": str(inner)}
                        for inner in range(32)
                    ],
                }
                for _ in range(32)
            ],
        }
        with self.assertRaisesRegex(CanonicalValueError, "1024 value units"):
            normalized_opaque_value_json(over_unit_budget)

    def test_opaque_profile_rejects_nonfinite_cycles_and_excess_depth(
        self,
    ) -> None:
        cyclic: list[object] = []
        cyclic.append(cyclic)
        too_deep: object = "leaf"
        for _ in range(6):
            too_deep = [too_deep]

        for value, message in (
            (float("nan"), "finite floating-point"),
            (float("inf"), "finite floating-point"),
            (cyclic, "reference cycles"),
            (too_deep, "four container levels"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    CanonicalValueError,
                    message,
                ),
            ):
                canonical_opaque_value(value, key_atom_type=KeyAtom)

    def test_resource_and_policy_contracts_reject_unordered_mappings(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            ResourceKey(
                namespace="test",
                node="node-a",
                layer="driver",
                kind="OPAQUE",
                parts={"id": 1},  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "must be a tuple"):
            ForwardingPolicyScope(
                contract_id="example.scope.v1",
                arguments={"id": 1},  # type: ignore[arg-type]
            )

    def test_packet_profile_keeps_boolean_and_mapping_out_of_key_values(self) -> None:
        with self.assertRaisesRegex(
            CanonicalValueError,
            "Boolean packet forwarding values",
        ):
            packet_value_json(True, key_atom_type=KeyAtom)
        with self.assertRaisesRegex(
            CanonicalValueError,
            "unsupported type: dict",
        ):
            packet_value_json({"id": 1}, key_atom_type=KeyAtom)

    def test_service_adapters_keep_their_public_error_types(self) -> None:
        atom = KeyAtom("opaque_uint", 7)
        self.assertEqual(
            MultiNodeRouteService._packet_value_json(atom),
            packet_value_json(atom, key_atom_type=KeyAtom),
        )
        self.assertEqual(
            _canonical_opaque_key(atom),
            canonical_opaque_value(atom, key_atom_type=KeyAtom),
        )
        with self.assertRaises(MultiNodeRouteRequestError):
            MultiNodeRouteService._packet_value_json({"id": 1})
        with self.assertRaises(MultiNodeTopologyRequestError):
            _canonical_opaque_key(object())


if __name__ == "__main__":
    unittest.main()

"""Standalone example plug-in package and its generated-fixture semantic policy.

``parse_status`` intentionally covers only the small interface-status
conformance vector.  The comprehensive demo corpus is synthesized offline by
the plug-in-owned :class:`ExampleRouterGeneratedProjectionPolicy`; immutable
generated revisions can therefore load their checked, precomputed projections
without pretending that the small parser produced them at request time.
A bounded topology snapshot retains its original selection and clock basis;
the core browser never reconstructs a replacement after a topology API error.

The public entry point remains a normal installed ``AnalyzerPlugin`` and never
depends on the generator or web application.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any, Final, Iterable, Mapping, Protocol, cast

from router_dump_analyzer.contract_validation import bounded_string
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPlugin,
    AnalyzerPluginBase,
    ArtifactReader,
    ConditionClass,
    ConsistencyFinding,
    DiagnosticSeverity,
    DiagnosticStage,
    DumpInventory,
    Evidence,
    EvidenceAnalysisKind,
    EvidenceAnalysisObservation,
    EvidenceAnalysisRequest,
    FindingResult,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    PropertyDescriptor,
    PropertyPatch,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionSupport,
    RelationshipDeclaration,
    RelationshipTypeDescriptor,
    ResourceKey,
    ResourceKindDescriptor,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordGroupDescriptor,
    SourceRecordTypeDescriptor,
    StatusParseOutput,
    TimelineTimeBasis,
)
from router_dump_analyzer.plugin_loading import (
    PluginProcessBootstrapDescriptor,
)
from ._identity import (
    EVIDENCE_PLUGIN_ID as EVIDENCE_PLUGIN_ID,
    EVIDENCE_PLUGIN_VERSION as EVIDENCE_PLUGIN_VERSION,
    PLUGIN_ID as PLUGIN_ID,
    PLUGIN_VERSION as PLUGIN_VERSION,
)

PLUGIN_ENTRY_POINT_NAME = "demo_router"
STATUS_FILENAME = "minimal-status.jsonl"
PARSER_ID = "demo.interface-status.v1"
PLATFORM_ID = "demo-router-os"
SOFTWARE_VERSION = "1"
DEVICE_CLOCK = "demo-router-realtime"
GENERATED_PROJECTION_POLICY_ID = "demo.example-router.generated-fixture-policy.v1"
GENERATED_ASSEMBLY_FORMAT_VERSION = 2
GENERATED_COVERAGE_FORMAT_VERSION = 3
GENERATED_COVERAGE_REGISTRY_ID = "router-state-lab-demo-coverage-v3"
GENERATED_PROJECTION_FORMAT_VERSION = 2
GENERATED_PROJECTION_ROOT = "plugin-projection"
GENERATED_PROJECTION_CAPABILITY_ID = (
    "demo.example-router.immutable-precomputed-projection.v1"
)
GENERATED_SCHEMA_CONTRACT_ID = "demo.example-router.generated-schema.v1"
GENERATED_SCHEMA_CONTRACT_VERSION = 1
# Canonical SHA-256 of the plug-in-owned generated schema with the
# projection_capabilities field removed.  Capability availability is declared
# separately below because it changes from the standalone scale tree to the
# fully materialized multi-node archive.
GENERATED_SCHEMA_BODY_SHA256 = (
    "a4ce55e49b792f8cba87bfb020bfa1c56aaac7f01dd4ec7b98324991ab919110"
)


@dataclass(frozen=True, slots=True)
class TopologyProfileSpec:
    """Plug-in-owned presentation contract used by generator and runtime."""

    profile_id: str
    label: str
    projection_role: str
    presentation_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneratedProjectionMemberSpec:
    """One immutable member of the example plug-in's offline projection."""

    member_id: str
    relative_path: str
    media_type: str
    serialization: str
    record_collection: str

    def descriptor(self) -> dict[str, str]:
        return {
            "path": self.relative_path,
            "media_type": self.media_type,
            "serialization": self.serialization,
            "record_collection": self.record_collection,
        }


@dataclass(frozen=True, slots=True)
class ExampleRouterGeneratedProjectionPolicy:
    """One honest semantic source for precomputed comprehensive fixtures."""

    policy_id: str
    format_version: int
    topology_profile: TopologyProfileSpec
    topology_segment_matcher_id: str
    topology_federation_plugin_id: str
    packet_profiles: Mapping[str, Mapping[str, Any]]
    projection_root: str
    projection_capability_id: str
    projection_members: tuple[GeneratedProjectionMemberSpec, ...]
    schema_contract_id: str
    schema_contract_version: int
    schema_body_sha256: str

    def __post_init__(self) -> None:
        member_ids = [item.member_id for item in self.projection_members]
        member_paths = [item.relative_path for item in self.projection_members]
        if len(member_ids) != len(set(member_ids)):
            raise ValueError("generated projection member IDs must be unique")
        if len(member_paths) != len(set(member_paths)):
            raise ValueError("generated projection member paths must be unique")
        for path_text in (self.projection_root, *member_paths):
            path = PurePosixPath(path_text)
            if (
                not path_text
                or "\\" in path_text
                or path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != path_text
            ):
                raise ValueError(f"unsafe generated projection path: {path_text!r}")

    @property
    def plugin_id(self) -> str:
        return PLUGIN_ID

    @property
    def plugin_version(self) -> str:
        return PLUGIN_VERSION

    @staticmethod
    def _detached(value: Any) -> Any:
        return json.loads(json.dumps(value))

    @staticmethod
    def _canonical_sha256(value: Any) -> str:
        content = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return sha256(content).hexdigest()

    def projection_member(
        self,
        member_id: str,
    ) -> GeneratedProjectionMemberSpec:
        for member in self.projection_members:
            if member.member_id == member_id:
                return member
        raise ValueError(f"unknown generated projection member: {member_id}")

    def projection_member_registry(self) -> dict[str, dict[str, str]]:
        return {
            member.member_id: member.descriptor() for member in self.projection_members
        }

    def projection_file_descriptor(
        self,
        member_id: str,
        *,
        records: int,
        sha256_hex: str,
    ) -> dict[str, Any]:
        member = self.projection_member(member_id)
        if records < 0:
            raise ValueError("projection record count cannot be negative")
        if len(sha256_hex) != 64 or any(
            character not in "0123456789abcdef" for character in sha256_hex
        ):
            raise ValueError("projection member requires a lowercase SHA-256")
        return {
            **member.descriptor(),
            "records": records,
            "sha256": sha256_hex,
        }

    def projection_capability_descriptor(self) -> dict[str, Any]:
        """Describe the non-live, immutable projection contract truthfully."""

        return {
            "capability_id": self.projection_capability_id,
            "format_version": self.format_version,
            "semantic_owner": "plugin",
            "materialization": "precomputed_during_generation",
            "immutable": True,
            "projection_root": self.projection_root,
            "members": self.projection_member_registry(),
        }

    def generated_schema_contract_descriptor(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_contract_id,
            "schema_version": self.schema_contract_version,
            "semantic_owner": "plugin",
            "body_sha256": self.schema_body_sha256,
        }

    def generation_materialization_descriptor(self) -> dict[str, Any]:
        return {
            "mode": "generator_synthesized_normalized_fixture",
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "projection_policy_id": self.policy_id,
            "projection_format_version": self.format_version,
            "projection_capability_id": self.projection_capability_id,
            "parser_replayed": False,
        }

    def base_projection_capabilities(self) -> dict[str, Any]:
        """Capabilities of the standalone normalized scale tree."""

        return {
            "resource_association_topology": {
                "available": True,
                "description": (
                    "Generic topology over the scale plug-in's time-valid "
                    "resource relationships."
                ),
            },
            "underlay_topology": {
                "available": False,
                "reason": (
                    "This scale fixture does not declare physical-interface, "
                    "subnet, or link-status resources, so an underlay projection "
                    "would not be evidence-backed."
                ),
            },
            "route_resolution": {
                "available": False,
                "reason": (
                    "This scale fixture models forwarding dependencies but does "
                    "not include a route catalog or a plug-in route resolver."
                ),
            },
        }

    def materialized_projection_capabilities(self) -> dict[str, Any]:
        """Capabilities supplied by the immutable assembly projection."""

        return {
            "resource_association_topology": (
                self.base_projection_capabilities()["resource_association_topology"]
            ),
            "underlay_topology": {
                "available": True,
                "source": (
                    f"{self.projection_root}/"
                    f"{self.projection_member('topology').relative_path}"
                ),
                "semantic_owner": "plugin",
            },
            "route_resolution": {
                "available": True,
                "source": (
                    f"{self.projection_root}/"
                    f"{self.projection_member('routes').relative_path}"
                ),
                "evidence_sources": [
                    (
                        f"{self.projection_root}/"
                        f"{self.projection_member('routes').relative_path}"
                    ),
                    (
                        f"{self.projection_root}/"
                        f"{self.projection_member('forwarding').relative_path}"
                    ),
                ],
                "semantic_owner": "plugin",
            },
            "packet_evolution": {
                "available": True,
                "source": (
                    f"{self.projection_root}/"
                    f"{self.projection_member('packet_cases').relative_path}"
                ),
                "semantic_owner": "plugin",
            },
        }

    def validate_generated_schema_template(
        self,
        schema: object,
    ) -> None:
        """Reject a generator-side schema that drifted from this plug-in."""

        if not isinstance(schema, Mapping):
            raise ValueError("generated fixture schema must be an object")
        capabilities = schema.get("projection_capabilities")
        if capabilities != self.base_projection_capabilities():
            raise ValueError(
                "generated fixture schema capability declarations disagree "
                "with the installed example plug-in"
            )
        body = dict(schema)
        body.pop("projection_capabilities", None)
        if self._canonical_sha256(body) != self.schema_body_sha256:
            raise ValueError(
                "generated fixture schema body disagrees with the installed "
                "example plug-in"
            )

    def materialize_generated_schema(
        self,
        schema: object,
        *,
        node_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Bind one validated schema template to an immutable node revision."""

        self.validate_generated_schema_template(schema)
        materialized = self._detached(schema)
        materialized.update(
            {
                "node_identity": self._detached(node_identity),
                "plugin_id": self.plugin_id,
                "plugin_version": self.plugin_version,
                "projection_policy_id": self.policy_id,
                "plugin_projection_root": self.projection_root,
                "generated_schema_contract": (
                    self.generated_schema_contract_descriptor()
                ),
                "precomputed_projection_capability": (
                    self.projection_capability_descriptor()
                ),
                "fixture_materialization": (
                    self.generation_materialization_descriptor()
                ),
                "projection_capabilities": (
                    self.materialized_projection_capabilities()
                ),
            }
        )
        return materialized

    def validate_materialized_generated_schema(
        self,
        schema: object,
        *,
        node_id: str,
        revision_id: str,
    ) -> None:
        if not isinstance(schema, Mapping):
            raise ValueError("materialized generated schema must be an object")
        identity = schema.get("node_identity")
        if (
            not isinstance(identity, Mapping)
            or identity.get("node_id") != node_id
            or identity.get("revision_id") != revision_id
        ):
            raise ValueError("materialized generated schema identity mismatch")
        expected_fields = {
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "projection_policy_id": self.policy_id,
            "plugin_projection_root": self.projection_root,
            "generated_schema_contract": (self.generated_schema_contract_descriptor()),
            "precomputed_projection_capability": (
                self.projection_capability_descriptor()
            ),
            "fixture_materialization": (self.generation_materialization_descriptor()),
            "projection_capabilities": (self.materialized_projection_capabilities()),
        }
        for field, expected in expected_fields.items():
            if schema.get(field) != expected:
                raise ValueError(
                    "materialized generated schema disagrees with the "
                    f"installed example plug-in at {field}"
                )
        template = dict(schema)
        for field in (
            "node_identity",
            "plugin_id",
            "plugin_version",
            "projection_policy_id",
            "plugin_projection_root",
            "generated_schema_contract",
            "precomputed_projection_capability",
            "fixture_materialization",
        ):
            template.pop(field, None)
        template["projection_capabilities"] = self.base_projection_capabilities()
        self.validate_generated_schema_template(template)

    def archive_plugin_descriptor(self) -> dict[str, Any]:
        """Describe truthful offline materialization in an archive manifest."""

        return {
            "plugin_id": self.plugin_id,
            "version": self.plugin_version,
            "projection_policy_id": self.policy_id,
            "projection_format_version": self.format_version,
            "projection_materialization": "precomputed_during_generation",
            "parser_replayed": False,
            "precomputed_projection_capability": (
                self.projection_capability_descriptor()
            ),
            "generated_schema_contract": (self.generated_schema_contract_descriptor()),
        }

    def projection_manifest_identity(
        self,
        *,
        node_id: str,
        revision_id: str,
    ) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "projection_policy_id": self.policy_id,
            "projection_materialization": "precomputed_during_generation",
            "parser_replayed": False,
            "node_id": node_id,
            "revision_id": revision_id,
            "semantic_owner": "plugin",
            "projection_capability_id": self.projection_capability_id,
        }

    def packet_declaration(
        self,
        *,
        scenario_id: str,
        profile_id: str,
    ) -> dict[str, Any]:
        """Return a detached JSON-safe declaration for one fixture scenario."""

        try:
            profile = self.packet_profiles[profile_id]
        except KeyError as error:
            raise ValueError(
                f"unknown generated packet profile: {profile_id}"
            ) from error
        # The round trip prevents callers from mutating the policy source and
        # proves that every emitted value is fixture-transport JSON.
        detached = json.loads(json.dumps(profile))
        return {
            "scenario_id": scenario_id,
            "packet_profile_id": profile_id,
            **detached,
            "executor_profile_id": detached.get(
                "executor_profile_id",
                profile_id,
            ),
        }

    def select_connectivity_domain(
        self,
        *,
        route_type: str,
        candidates: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Select one opaque next-hop domain using example-router semantics.

        The core never applies this preference.  The generated example plug-in
        records the selected matcher/key and attachment resources so runtime
        route tracing can perform only an exact, fail-closed join.
        """

        choices = [dict(item) for item in candidates]
        if not choices:
            raise ValueError("next hop has no plug-in-declared connectivity domain")
        evpn_route = route_type in {"evpn_mac_ip", "evpn_service", "evpn_ip_prefix"}
        has_evpn_access = any(
            item.get("classification") == "evpn_access" for item in choices
        )

        def rank(item: Mapping[str, Any]) -> tuple[int, int, int, str]:
            classification = str(item.get("classification", ""))
            desired_plane = (
                classification == "evpn_access"
                if evpn_route and has_evpn_access
                else classification == "underlay"
            )
            participant_count = int(item.get("participant_count", 0))
            return (
                0 if desired_plane else 1,
                0 if participant_count == 2 else 1,
                0 if item.get("attachment_kind") == "physical" else 1,
                str(item.get("segment_id", "")),
            )

        selected = min(choices, key=rank)
        if not selected.get("segment_id"):
            raise ValueError("connectivity-domain selection lacks segment_id")
        return selected

    def validate_archive_plugin_descriptor(
        self,
        descriptor: object,
    ) -> None:
        if not isinstance(descriptor, Mapping):
            raise ValueError("generated assembly lacks a plug-in descriptor")
        expected = self.archive_plugin_descriptor()
        for field, value in expected.items():
            if descriptor.get(field) != value:
                raise ValueError(
                    "generated assembly plug-in descriptor disagrees with "
                    f"the installed example policy at {field}"
                )

    def validate_projection_manifest(
        self,
        manifest: Mapping[str, Any],
        *,
        node_id: str,
        revision_id: str,
    ) -> None:
        expected = self.projection_manifest_identity(
            node_id=node_id,
            revision_id=revision_id,
        )
        for field, value in expected.items():
            if manifest.get(field) != value:
                raise ValueError(
                    "precomputed projection manifest disagrees with the "
                    f"installed example policy at {field}"
                )
        files = manifest.get("files")
        if not isinstance(files, Mapping):
            raise ValueError("precomputed projection manifest lacks a file registry")
        expected_members = self.projection_member_registry()
        if set(files) != set(expected_members):
            raise ValueError(
                "precomputed projection member registry disagrees with the "
                "installed example policy"
            )
        for member_id, expected_descriptor in expected_members.items():
            descriptor = files.get(member_id)
            if not isinstance(descriptor, Mapping):
                raise ValueError(
                    f"precomputed projection member {member_id} is invalid"
                )
            for field, expected in expected_descriptor.items():
                if descriptor.get(field) != expected:
                    raise ValueError(
                        "precomputed projection member "
                        f"{member_id} disagrees at {field}"
                    )

    def validate_coverage_registry(self, registry: object) -> None:
        """Validate the current generated coverage transport envelope."""

        if not isinstance(registry, Mapping):
            raise ValueError("coverage registry must be an object")
        if registry.get("format_version") != GENERATED_COVERAGE_FORMAT_VERSION:
            raise ValueError("unsupported demo coverage format version")
        if registry.get("registry_id") != GENERATED_COVERAGE_REGISTRY_ID:
            raise ValueError("unsupported demo coverage registry")
        cases = registry.get("cases")
        if not isinstance(cases, list):
            raise ValueError("coverage cases must be an array")
        case_ids: set[str] = set()
        for case in cases:
            self.validate_coverage_case(case)
            assert isinstance(case, Mapping)
            case_id = str(case["case_id"])
            if case_id in case_ids:
                raise ValueError("coverage case ids must be unique")
            case_ids.add(case_id)

    def validate_coverage_case(self, case: object) -> None:
        """Validate one generated case and its semantic evidence records.

        Coverage is assembly metadata, but candidate and evidence declarations
        carry example-router semantics. Keeping their validation beside the
        policy makes the generator and lazy runtime store enforce the same
        contract.
        """

        if not isinstance(case, Mapping):
            raise ValueError("coverage case must be an object")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("coverage case requires a non-empty case_id")
        capabilities = case.get("required_capabilities")
        if not isinstance(capabilities, list) or any(
            not isinstance(item, str) or not item for item in capabilities
        ):
            raise ValueError(
                f"coverage case {case_id} has invalid required_capabilities"
            )
        if "evidence_analysis" not in capabilities:
            raise ValueError(
                f"coverage case {case_id} lacks evidence_analysis capability"
            )
        analysis_intents = case.get("private_analysis_intents")
        allowed_analysis_intents = {item.value for item in EvidenceAnalysisKind}
        if (
            not isinstance(analysis_intents, list)
            or not analysis_intents
            or analysis_intents != sorted(set(analysis_intents))
            or any(
                not isinstance(item, str) or item not in allowed_analysis_intents
                for item in analysis_intents
            )
        ):
            raise ValueError(
                f"coverage case {case_id} has invalid private_analysis_intents"
            )
        involved_nodes = case.get("involved_nodes")
        if not isinstance(involved_nodes, list) or any(
            not isinstance(item, str) or not item for item in involved_nodes
        ):
            raise ValueError(f"coverage case {case_id} has invalid involved_nodes")
        evidence_refs = case.get("evidence_refs")
        if not isinstance(evidence_refs, list):
            raise ValueError(f"coverage case {case_id} has invalid evidence_refs")
        for evidence in evidence_refs:
            self.coverage_evidence_namespaced_fields(
                evidence,
                case_id=case_id,
            )
        candidate_paths = case.get("candidate_paths")
        if not isinstance(candidate_paths, list):
            raise ValueError(f"coverage case {case_id} lacks candidate_paths")
        route_case = "route_resolution" in capabilities
        if route_case and not candidate_paths:
            raise ValueError(f"route coverage case {case_id} has no candidate_paths")
        if not route_case and candidate_paths:
            raise ValueError(f"non-route coverage case {case_id} has candidate_paths")

        candidate_ids: set[str] = set()
        directions: set[str] = set()
        involved = set(involved_nodes)
        active_directions: set[str] = set()
        for path in candidate_paths:
            if not isinstance(path, Mapping):
                raise ValueError(
                    f"coverage case {case_id} has a non-object candidate path"
                )
            candidate_id = path.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id:
                raise ValueError(f"coverage case {case_id} has an invalid candidate_id")
            if candidate_id in candidate_ids:
                raise ValueError(
                    f"coverage case {case_id} has duplicate candidate_id {candidate_id}"
                )
            candidate_ids.add(candidate_id)
            direction = path.get("direction")
            if direction not in {"forward", "reverse"}:
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid direction"
                )
            directions.add(str(direction))
            sequence = path.get("node_sequence")
            if (
                not isinstance(sequence, list)
                or not sequence
                or any(
                    not isinstance(node_id, str) or not node_id for node_id in sequence
                )
            ):
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid node_sequence"
                )
            unknown_nodes = set(sequence) - involved
            if unknown_nodes:
                raise ValueError(
                    f"coverage candidate {candidate_id} references nodes "
                    f"outside involved_nodes: {sorted(unknown_nodes)}"
                )
            for field in ("selected_active", "primary"):
                if type(path.get(field)) is not bool:
                    raise ValueError(
                        f"coverage candidate {candidate_id} has invalid {field}"
                    )
            alternative = path.get("alternative_state")
            if not isinstance(alternative, str) or not alternative:
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid alternative_state"
                )
            if path["selected_active"]:
                active_directions.add(str(direction))
            if "steering_profile_id" in path and (
                not isinstance(path["steering_profile_id"], str)
                or not path["steering_profile_id"]
            ):
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid steering_profile_id"
                )
            if "counterfactual" in path and (type(path["counterfactual"]) is not bool):
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid counterfactual"
                )
            if "inferred" in path and type(path["inferred"]) is not bool:
                raise ValueError(
                    f"coverage candidate {candidate_id} has invalid inferred"
                )
            if "resolution_modes" in path:
                resolution_modes = path["resolution_modes"]
                if not isinstance(resolution_modes, list) or any(
                    not isinstance(mode, str) or not mode for mode in resolution_modes
                ):
                    raise ValueError(
                        f"coverage candidate {candidate_id} has invalid "
                        "resolution_modes"
                    )
        if route_case and directions != {"forward", "reverse"}:
            raise ValueError(
                f"route coverage case {case_id} must declare both directions"
            )
        if route_case and active_directions != {"forward", "reverse"}:
            raise ValueError(
                f"route coverage case {case_id} lacks an active candidate "
                "in both directions"
            )

    def coverage_evidence_namespaced_fields(
        self,
        evidence: object,
        *,
        case_id: str,
    ) -> tuple[str, ...]:
        """Validate one plug-in-owned evidence reference.

        The generator additionally proves that these identifiers exist in the
        selected node packs.  This method owns the semantic record shapes so
        the archive validator and lazy runtime loader reject the same stale or
        incomplete coverage declarations.
        """

        if not isinstance(evidence, Mapping):
            raise ValueError(f"coverage case {case_id} has non-object evidence")
        node_id = evidence.get("node_id")
        revision_id = evidence.get("revision_id")
        if not isinstance(node_id, str) or not node_id:
            raise ValueError(f"coverage case {case_id} evidence lacks node_id")
        if not isinstance(revision_id, str) or not revision_id:
            raise ValueError(f"coverage case {case_id} evidence lacks revision_id")
        evidence_kind = evidence.get("evidence_kind")
        required_by_kind = {
            "route_projection": (
                "resource_id",
                "event_uid",
                "route_id",
                "forwarding_id",
            ),
            "topology_claim": (
                "resource_id",
                "topology_claim_id",
            ),
            "temporal_event": (
                "resource_id",
                "event_uid",
            ),
        }
        namespaced_fields = required_by_kind.get(str(evidence_kind))
        if namespaced_fields is None:
            raise ValueError(
                f"coverage case {case_id} has unknown evidence kind {evidence_kind!r}"
            )
        required_fields = {
            "route_projection": (),
            "topology_claim": (
                "selector_kind",
                "reference_id",
                "segment_key",
                "matcher_id",
                "subnet_prefix",
                "classification",
                "attachment_kind",
                "calculation",
            ),
            "temporal_event": (
                "event_name",
                "phase",
                "timestamp_ns",
                "resource_kind",
                "action",
                "outcome",
                "state_changed",
            ),
        }[str(evidence_kind)]
        for field in (*namespaced_fields, *required_fields):
            if field not in evidence:
                raise ValueError(f"coverage {evidence_kind} evidence lacks {field}")
        for field in namespaced_fields:
            value = evidence[field]
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"coverage {evidence_kind} evidence has invalid {field}"
                )
        if evidence_kind == "topology_claim":
            calculation = evidence.get("calculation")
            if not isinstance(calculation, Mapping):
                raise ValueError(
                    "topology coverage evidence calculation must be an object"
                )
        if (
            evidence_kind == "temporal_event"
            and type(evidence.get("state_changed")) is not bool
        ):
            raise ValueError("temporal coverage evidence state_changed must be boolean")
        return namespaced_fields

    def validate_forwarding_row(
        self,
        row: object,
        *,
        node_id: str,
        revision_id: str,
    ) -> None:
        """Validate one generated forwarding row without interpreting it."""

        if not isinstance(row, Mapping):
            raise ValueError("forwarding projection row must be an object")
        forwarding_id = row.get("forwarding_id")
        if not isinstance(forwarding_id, str) or not forwarding_id.startswith(
            f"{node_id}/"
        ):
            raise ValueError(f"{node_id} forwarding row ID is not namespaced")
        if row.get("node_id") != node_id:
            raise ValueError(f"{node_id} forwarding row has wrong node identity")
        if row.get("revision_id") != revision_id:
            raise ValueError(f"{node_id} forwarding row has wrong revision")
        scenario_id = row.get("scenario_id")
        if scenario_id is None:
            return
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError(f"{node_id} forwarding row has invalid scenario_id")
        directional = row.get("directional_decisions")
        if not isinstance(directional, Mapping) or set(directional) != {
            "forward",
            "reverse",
        }:
            raise ValueError(
                f"{node_id} forwarding row {scenario_id} lacks current "
                "directional_decisions"
            )
        occurrences: set[tuple[str, int]] = set()
        for direction in ("forward", "reverse"):
            decisions = directional[direction]
            if not isinstance(decisions, list):
                raise ValueError(
                    f"{node_id} forwarding row {scenario_id} has invalid "
                    f"{direction} decisions"
                )
            for decision in decisions:
                if not isinstance(decision, Mapping):
                    raise ValueError(
                        f"{node_id} forwarding row {scenario_id} has a "
                        "non-object directional decision"
                    )
                candidate_id = decision.get("candidate_id")
                if not isinstance(candidate_id, str) or not candidate_id:
                    raise ValueError(
                        f"{node_id} forwarding row {scenario_id} has an "
                        "invalid candidate_id"
                    )
                visit_index = decision.get("visit_index")
                if type(visit_index) is not int or visit_index < 0:
                    raise ValueError(
                        f"{node_id} forwarding candidate {candidate_id} has "
                        "an invalid visit_index"
                    )
                occurrence = (candidate_id, visit_index)
                if occurrence in occurrences:
                    raise ValueError(
                        f"{node_id} forwarding row {scenario_id} duplicates "
                        f"candidate occurrence {occurrence}"
                    )
                occurrences.add(occurrence)
                for field in ("selected_active", "primary"):
                    if type(decision.get(field)) is not bool:
                        raise ValueError(
                            f"{node_id} forwarding candidate {candidate_id} "
                            f"has invalid {field}"
                        )
                for field in (
                    "alternative_state",
                    "state",
                    "disposition",
                    "resolution_text",
                ):
                    value = decision.get(field)
                    if not isinstance(value, str) or not value:
                        raise ValueError(
                            f"{node_id} forwarding candidate {candidate_id} "
                            f"has invalid {field}"
                        )
                next_node_id = decision.get("next_node_id")
                if next_node_id is not None and (
                    not isinstance(next_node_id, str) or not next_node_id
                ):
                    raise ValueError(
                        f"{node_id} forwarding candidate {candidate_id} has "
                        "invalid next_node_id"
                    )
                next_hop = decision.get("next_hop")
                if next_node_id is None or next_node_id == node_id:
                    if next_hop is not None:
                        raise ValueError(
                            f"{node_id} forwarding candidate {candidate_id} "
                            "has topology evidence for a local transition"
                        )
                    continue
                self._validate_topology_next_hop(
                    next_hop,
                    node_id=node_id,
                    next_node_id=next_node_id,
                    candidate_id=candidate_id,
                )

    def _validate_topology_next_hop(
        self,
        next_hop: object,
        *,
        node_id: str,
        next_node_id: str,
        candidate_id: str,
    ) -> None:
        if not isinstance(next_hop, Mapping):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} lacks an "
                "exact topology next hop"
            )
        if next_hop.get("node_id") != next_node_id:
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} topology "
                "next-hop identity mismatch"
            )
        local_resource = next_hop.get("interface_resource_id")
        remote_resource = next_hop.get("remote_interface_resource_id")
        if (
            not isinstance(local_resource, str)
            or not local_resource.startswith(f"{node_id}/")
            or not isinstance(remote_resource, str)
            or not remote_resource.startswith(f"{next_node_id}/")
        ):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} has invalid "
                "attachment resource identities"
            )
        if (
            next_hop.get("selection_owner") != "plugin"
            or next_hop.get("selection_policy_id") != self.policy_id
        ):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} has invalid "
                "topology selection ownership"
            )
        references = next_hop.get("topology_references")
        if not isinstance(references, list) or not references:
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} requires "
                "exactly one topology reference"
            )
        domain_references = [
            reference
            for reference in references
            if isinstance(reference, Mapping)
            and reference.get("reference_kind") == "connectivity_domain"
        ]
        typed_references = [
            reference
            for reference in references
            if isinstance(reference, Mapping)
            and reference.get("reference_kind") == "typed_inter_node_link"
        ]
        if (
            len(domain_references) != 1
            or len(typed_references) > 1
            or len(domain_references) + len(typed_references) != len(references)
        ):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} has invalid "
                "topology reference kind"
            )
        reference = domain_references[0]
        match = reference.get("match")
        if (
            not isinstance(match, Mapping)
            or match.get("matcher_id") != self.topology_segment_matcher_id
            or match.get("matcher_contract_version") != "1.0"
        ):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} has invalid "
                "topology matcher identity"
            )
        arguments = match.get("arguments")
        segment_key = (
            arguments.get("segment_key") if isinstance(arguments, Mapping) else None
        )
        if (
            not isinstance(segment_key, Mapping)
            or segment_key.get("type") != "string"
            or not isinstance(segment_key.get("value"), str)
            or not segment_key["value"].startswith("subnet:")
            or len(segment_key["value"]) == len("subnet:")
        ):
            raise ValueError(
                f"{node_id} forwarding candidate {candidate_id} has invalid "
                "connectivity-domain key"
            )
        if typed_references:
            typed_reference = typed_references[0]
            source_endpoint = typed_reference.get("source_endpoint")
            target_endpoint = typed_reference.get("target_endpoint")

            def expected_endpoint(
                endpoint_node_id: str,
                endpoint_resource_id: str,
            ) -> dict[str, object]:
                return {
                    "node_id": endpoint_node_id,
                    "resource_id": endpoint_resource_id,
                    "typed_resource_key": {
                        "namespace": "demo.generated.topology",
                        "node": endpoint_node_id,
                        "layer": "underlay",
                        "kind": "demo.topology.endpoint",
                        "parts": [
                            {
                                "name": "resource_id",
                                "value": {
                                    "type": "string",
                                    "value": endpoint_resource_id,
                                },
                            }
                        ],
                    },
                }

            if (
                type(source_endpoint) is not dict
                or type(target_endpoint) is not dict
                or source_endpoint != expected_endpoint(node_id, local_resource)
                or target_endpoint != expected_endpoint(next_node_id, remote_resource)
            ):
                raise ValueError(
                    f"{node_id} forwarding candidate {candidate_id} has "
                    "invalid typed inter-node endpoint reference"
                )

    def runtime_load_descriptor(self) -> dict[str, Any]:
        """Explain why runtime parsing is intentionally not replayed."""

        return {
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "projection_policy_id": self.policy_id,
            "projection_format_version": self.format_version,
            "projection_capability": (self.projection_capability_descriptor()),
            "generated_schema_contract": (self.generated_schema_contract_descriptor()),
            "load_mode": "validated_immutable_precomputed_projection",
            "parser_replayed": False,
        }


GENERATED_TOPOLOGY_PROFILE: Final[TopologyProfileSpec] = TopologyProfileSpec(
    profile_id="fabric-underlay",
    label="Generated subnet and interface evidence",
    projection_role="underlay",
    presentation_roles=("underlay",),
)
GENERATED_VPN_TOPOLOGY_PROFILE: Final[TopologyProfileSpec] = TopologyProfileSpec(
    profile_id="fabric-vpn",
    label="Generated VPN service membership",
    projection_role="vpn",
    presentation_roles=("vpn", "overlay"),
)
GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID = "demo.connectivity-domain-key.exact.v1"
GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID = "demo.fabric.federation-linker"

_GENERATED_PACKET_PROFILES: dict[str, dict[str, Any]] = {
    "native-ip-incomplete": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": ["lookup", "forward", "incomplete_packet_capture"],
        "expected_continuity": "unknown_incomplete",
    },
    "native-ip": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": ["lookup", "forward"],
    },
    "sr-mpls-php": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": [
            "push_label",
            "swap_label",
            "php",
            "forward",
        ],
        "label_stack": [16002],
    },
    "l3vpn-over-sr-mpls": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": [
            "push_vpn_label",
            "push_transport_label",
            "swap_label",
            "php",
            "pop_vpn_label",
        ],
        "label_stack": [24000, 16002],
    },
    "srv6-encap": {
        "initial_layers": [
            {
                "kind": "ipv6",
                "source": "2001:db8:10::10",
                "destination": "2001:db8:20::20",
            }
        ],
        "expected_actions": [
            "encapsulate_srv6",
            "advance_sid",
            "decapsulate",
        ],
        "sid_stack": [
            "2001:db8:ffff:2::1",
            "2001:db8:ffff:1::1",
        ],
    },
    "ipv6-over-ipv4": {
        "initial_layers": [
            {
                "kind": "ipv6",
                "source": "2001:db8:10::10",
                "destination": "2001:db8:20::20",
            }
        ],
        "expected_actions": [
            "encapsulate_ipv4",
            "forward",
            "decapsulate_ipv4",
        ],
    },
    "vpn-over-vpn": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": [
            "encapsulate_vxlan",
            "encapsulate_outer_vpn",
            "forward",
            "decapsulate_outer_vpn",
            "decapsulate_vxlan",
        ],
    },
    "mtu-drop": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": [
            "encapsulate_srv6",
            "mtu_check",
            "drop",
        ],
        "packet_size_bytes": 1490,
        "egress_mtu_bytes": 1500,
    },
    "mtu-fit": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": ["encapsulate_ipv4", "mtu_check", "forward"],
        "packet_size_bytes": 1420,
        "egress_mtu_bytes": 1500,
        "expected_mtu_outcome": "fits",
    },
    "mtu-exact": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": ["encapsulate_ipv4", "mtu_check", "forward"],
        "packet_size_bytes": 1480,
        "egress_mtu_bytes": 1500,
        "expected_mtu_outcome": "fits",
    },
    "mtu-incomparable": {
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": ["encapsulate_ipv4", "mtu_check", "forward"],
        "packet_size_bytes": 1490,
        "egress_mtu_bytes": 1500,
        "size_basis_contract_id": "demo.wire-size.v1",
        "mtu_basis_contract_id": "demo.ip-size.v1",
        "expected_mtu_outcome": "unknown_basis_mismatch",
    },
    "forced-steering": {
        "executor_profile_id": "sr-mpls-php",
        "initial_layers": [
            {
                "kind": "ipv4",
                "source": "192.0.2.10",
                "destination": "198.51.100.20",
            }
        ],
        "expected_actions": [
            "lookup",
            "apply_forced_rule",
            "forward",
        ],
    },
}

GENERATED_PROJECTION_MEMBERS: Final[tuple[GeneratedProjectionMemberSpec, ...]] = (
    GeneratedProjectionMemberSpec(
        member_id="topology",
        relative_path="topology.json",
        media_type="application/json",
        serialization="json-object",
        record_collection="claims",
    ),
    GeneratedProjectionMemberSpec(
        member_id="routes",
        relative_path="routes.jsonl",
        media_type="application/x-ndjson",
        serialization="json-lines",
        record_collection="rows",
    ),
    GeneratedProjectionMemberSpec(
        member_id="forwarding",
        relative_path="forwarding.jsonl",
        media_type="application/x-ndjson",
        serialization="json-lines",
        record_collection="rows",
    ),
    GeneratedProjectionMemberSpec(
        member_id="packet_cases",
        relative_path="packet-cases.json",
        media_type="application/json",
        serialization="json-object",
        record_collection="cases",
    ),
)

GENERATED_PROJECTION_POLICY: ExampleRouterGeneratedProjectionPolicy = (
    ExampleRouterGeneratedProjectionPolicy(
        policy_id=GENERATED_PROJECTION_POLICY_ID,
        format_version=GENERATED_PROJECTION_FORMAT_VERSION,
        topology_profile=GENERATED_TOPOLOGY_PROFILE,
        topology_segment_matcher_id=GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
        topology_federation_plugin_id=(GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID),
        packet_profiles=_GENERATED_PACKET_PROFILES,
        projection_root=GENERATED_PROJECTION_ROOT,
        projection_capability_id=GENERATED_PROJECTION_CAPABILITY_ID,
        projection_members=GENERATED_PROJECTION_MEMBERS,
        schema_contract_id=GENERATED_SCHEMA_CONTRACT_ID,
        schema_contract_version=GENERATED_SCHEMA_CONTRACT_VERSION,
        schema_body_sha256=GENERATED_SCHEMA_BODY_SHA256,
    )
)

CONFORMANCE_STATUS_RECORDS: tuple[dict[str, Any], ...] = (
    {
        "kind": "interface",
        "captured_at_ns": 1_759_680_000_000_000_000,
        "source_sequence": 10,
        "lifecycle": "create",
        "ifindex": 7,
        "name": "xe-0/0/0",
        "admin_status": "up",
        "oper_status": "up",
        "description": "core uplink",
    },
    {
        "kind": "interface",
        "captured_at_ns": 1_759_680_000_000_000_000,
        "source_sequence": 20,
        "lifecycle": "modify",
        "ifindex": 7,
        "name": "xe-0/0/0",
        "admin_status": "up",
        "oper_status": "down",
        "description": "same-timestamp failure update",
    },
    {
        "kind": "interface",
        "captured_at_ns": 1_759_680_000_001_000_000,
        "source_sequence": 30,
        "lifecycle": "create",
        "ifindex": 8,
        "name": "xe-0/0/1",
        "admin_status": "up",
        "oper_status": "down",
        "description": "peer link",
    },
    {
        "kind": "interface",
        "observed_at_min_ns": 1_759_680_000_002_000_000,
        "observed_at_max_ns": 1_759_680_000_002_500_000,
        "source_sequence": 40,
        "lifecycle": "create",
        "ifindex": 9,
        "name": "xe-0/0/2",
        "admin_status": "up",
        "oper_status": "unknown",
        "description": "window-only observation",
    },
)


def render_conformance_status_fixture() -> bytes:
    """Render the tiny parser vector from plug-in-owned records."""

    return b"".join(
        (
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        for record in CONFORMANCE_STATUS_RECORDS
    )


def _interface_schema() -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind="INTERFACE",
                label="Interface",
                key_fields=("ifindex",),
                properties=(
                    PropertyDescriptor(
                        name="name",
                        label="Name",
                        value_type="string",
                        searchable=True,
                    ),
                    PropertyDescriptor(
                        name="admin_status",
                        label="Admin status",
                        value_type="string",
                        indexed=True,
                    ),
                    PropertyDescriptor(
                        name="oper_status",
                        label="Operational status",
                        value_type="string",
                        indexed=True,
                    ),
                    PropertyDescriptor(
                        name="description",
                        label="Description",
                        value_type="string",
                        # Dotted names can select nested searchable leaves;
                        # core applies visibility before building search text.
                        searchable=True,
                        client_visible=True,
                    ),
                ),
                default_timeline_fields=("admin_status", "oper_status"),
                display_name_fields=("name",),
                default_table_fields=(
                    "name",
                    "admin_status",
                    "oper_status",
                    "description",
                ),
                # This display condition is public. A private ancestor or
                # matching relative property path also hides copied status.
                condition_field="oper_status",
                presentation_tags=("interface",),
            ),
        ),
        relationship_types=(
            RelationshipTypeDescriptor(
                relation_type="corresponds_to",
                label="Corresponds to",
                directed=False,
                structural=False,
            ),
        ),
        source_record_groups=(
            SourceRecordGroupDescriptor(
                group_id="status-input",
                label="Status input",
                description="Decoded status rows retained beside normalized state.",
                copy_action_label="Copy status rows",
            ),
        ),
        source_record_types=(
            SourceRecordTypeDescriptor(
                source_type="status-json",
                label="Status JSON",
                description="Validated JSONL input retained by the demo plug-in.",
                color="#66b8ff",
                stream_group="status-input",
            ),
        ),
    )


SCHEMA: PluginSchema = _interface_schema()
EVIDENCE_SCHEMA: PluginSchema = PluginSchema(
    resource_kinds=(),
    relationship_types=(),
)


class ExampleRouterPlugin(AnalyzerPluginBase):
    """Parse the conformance snapshot and own generated-fixture semantics."""

    generated_projection_policy = GENERATED_PROJECTION_POLICY
    plugin_process_bootstrap: PluginProcessBootstrapDescriptor = (
        PluginProcessBootstrapDescriptor(
            module_target="rsl_demo_plugin:ExampleRouterPlugin",
            construct_class=True,
        )
    )
    manifest: PluginManifest = PluginManifest(
        plugin_id=PLUGIN_ID,
        plugin_version=PLUGIN_VERSION,
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=(PLATFORM_ID,),
        supported_software_versions=">=1,<2",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.RELATIONSHIP_PROJECTION,
                PluginCapability.CONSISTENCY_CHECK,
            }
        ),
        reconstruction_default=ReconstructionSupport.EXACT,
        # This fixture emits Unix nanoseconds. A relative plug-in would emit
        # revision-start offsets directly; core never rebases them against the
        # declared timeline lower bound.
        timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
    )

    def describe(self) -> PluginSchema:
        return SCHEMA

    def project_relationships(
        self,
        world: ReadOnlyWorld,
    ) -> Iterable[RelationshipDeclaration | PluginDiagnostic]:
        """Relate independently keyed interface views with the same name.

        The example deliberately compares the immutable revision world rather
        than parser-local rows.  Core supplies a bounded world and later binds
        the accepted declaration to the exact revision basis and provider.
        This minimal schema has one unqualified view. Perspective-aware
        extensions must retain separate views and must not treat an ambiguous
        singular lookup (exists=None) as affirmative endpoint evidence.
        """

        scan_limit = 10_000
        scanned = tuple(
            world.iter_states(
                kinds=frozenset({"INTERFACE"}),
                limit=scan_limit + 1,
            )
        )
        if len(scanned) > scan_limit:
            return
        states = scanned
        by_name: dict[str, list[Any]] = {}
        for state in states:
            name = state.properties.get("name")
            if (
                state.exists is not True
                or type(name) is not str
                or not name
                or not state.evidence
            ):
                continue
            by_name.setdefault(name, []).append(state)

        for name in sorted(by_name):
            matching = sorted(
                by_name[name],
                key=lambda state: (
                    state.resource.namespace,
                    state.resource.node,
                    state.resource.layer,
                    state.resource.kind,
                    repr(state.resource.parts),
                ),
            )
            if len(matching) != 2:
                continue
            left, right = matching
            if left.resource == right.resource:
                continue
            yield RelationshipDeclaration(
                source=left.resource,
                target=right.resource,
                relation_type="corresponds_to",
                attributes=PropertyPatch(
                    set_values={"match_basis": "shared-interface-name"},
                    remove_fields=(),
                    unknown_fields=(),
                    field_quality={"match_basis": Quality.EXACT},
                    field_provenance={
                        "match_basis": Provenance.CORRELATED,
                    },
                    complete=True,
                ),
                evidence=(left.evidence[0], right.evidence[0]),
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
                perspective_ref=world.perspective_ref,
            )

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> Iterable[ConsistencyFinding | PluginDiagnostic]:
        """Demonstrate one bounded, revision-basis consistency rule.

        The plug-in owns the meaning of ``oper_status``. Core owns the
        immutable world, execution-plan binding, quotas, provenance envelope,
        and durable publication of this result.
        """

        scan_limit = 10_000
        scanned = tuple(
            world.iter_states(
                kinds=frozenset({"INTERFACE"}),
                # One sentinel distinguishes a complete bounded scan from a
                # clean prefix returned by a limit-aware core world.
                limit=scan_limit + 1,
            )
        )
        scan_truncated = len(scanned) > scan_limit
        states = scanned[:scan_limit]
        failing = tuple(
            state for state in states if state.properties.get("oper_status") != "up"
        )
        if failing:
            result = FindingResult.FAIL
            severity = DiagnosticSeverity.ERROR
            selected = failing[:32]
            summary = (
                f"At least {len(failing)} interface(s) are not operationally up."
                if scan_truncated
                else f"{len(failing)} interface(s) are not operationally up."
            )
        elif scan_truncated:
            result = FindingResult.UNKNOWN
            severity = DiagnosticSeverity.WARNING
            selected = ()
            summary = (
                "The bounded interface scan was truncated before completeness "
                "could be established."
            )
        elif states:
            result = FindingResult.PASS
            severity = DiagnosticSeverity.INFO
            selected = states[:1]
            summary = "All observed interfaces are operationally up."
        else:
            result = FindingResult.UNKNOWN
            severity = DiagnosticSeverity.WARNING
            selected = ()
            summary = "No interface state was available for this revision."
        evidence = tuple(item for state in selected for item in state.evidence[:1])
        yield ConsistencyFinding(
            rule_id="demo.interface-operational-status",
            severity=severity,
            result=result,
            summary=summary,
            resources=tuple(state.resource for state in selected),
            provenance=Provenance.RECONSTRUCTED,
            quality=(
                Quality.EXACT
                if states and (failing or not scan_truncated)
                else Quality.UNKNOWN
            ),
            basis=world.basis,
            evidence=evidence,
            details={
                "interface_count": len(states),
                "non_up_count": len(failing),
                "scan_limit": scan_limit,
                "scan_truncated": scan_truncated,
            },
        )

    def describe_generated_fixture(self) -> dict[str, Any]:
        """Expose the demo-only immutable projection contract.

        This is deliberately separate from the core ``AnalyzerPlugin``
        capability hooks: the large fixture is generated offline and validated
        on load, not reparsed through the tiny conformance parser.
        """

        return {
            "plugin_id": self.manifest.plugin_id,
            "plugin_version": self.manifest.plugin_version,
            "schema_contract": (
                self.generated_projection_policy.generated_schema_contract_descriptor()
            ),
            "projection_capability": (
                self.generated_projection_policy.projection_capability_descriptor()
            ),
            "runtime_load": (
                self.generated_projection_policy.runtime_load_descriptor()
            ),
        }

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        matching = tuple(
            artifact
            for artifact in inventory.artifacts
            if artifact.logical_path.name == STATUS_FILENAME
        )
        if not matching:
            return ProbeReport(result=None)

        declared_platform = inventory.metadata.get("platform")
        declared_version = inventory.metadata.get("software_version")
        exact = (
            declared_platform == PLATFORM_ID and declared_version == SOFTWARE_VERSION
        )
        incompatible = declared_platform not in (
            None,
            PLATFORM_ID,
        ) or declared_version not in (None, SOFTWARE_VERSION)
        if exact:
            match_kind = ProbeMatchKind.EXACT
            confidence = 1.0
        elif incompatible:
            match_kind = ProbeMatchKind.NONE
            confidence = 0.0
        else:
            match_kind = ProbeMatchKind.COMPATIBLE
            confidence = 0.7
        return ProbeReport(
            result=ProbeResult(
                confidence=confidence,
                reasons=(
                    f"inventory contains {STATUS_FILENAME}",
                    (
                        f"platform metadata is {declared_platform!r}; "
                        f"expected {PLATFORM_ID!r}"
                    ),
                    (
                        f"software version metadata is {declared_version!r}; "
                        f"expected {SOFTWARE_VERSION!r}"
                    ),
                ),
                detected_platform=PLATFORM_ID,
                detected_software_version=(
                    declared_version if isinstance(declared_version, str) else None
                ),
                match_kind=match_kind,
            )
        )

    def locate_inputs(
        self,
        inventory: DumpInventory,
    ) -> Iterable[InputSpec | PluginDiagnostic]:
        matching = tuple(
            artifact
            for artifact in inventory.artifacts
            if artifact.logical_path.name == STATUS_FILENAME
        )
        if not matching:
            yield PluginDiagnostic(
                stage=DiagnosticStage.LOCATE,
                severity=DiagnosticSeverity.ERROR,
                code="demo.status-input-missing",
                message=f"Required input {STATUS_FILENAME} was not inventoried.",
                recoverable=False,
            )
            return

        node = inventory.node_hint or "unknown-node"
        for artifact in matching:
            yield InputSpec(
                artifact_ids=(artifact.artifact_id,),
                role="status_snapshot",
                node=node,
                layer="interface",
                parser_id=PARSER_ID,
                parser_kind=InputParserKind.STATUS,
            )

    def parse_status(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[StatusParseOutput]:
        if len(spec.artifact_ids) != 1:
            yield PluginDiagnostic(
                stage=DiagnosticStage.STATUS_PARSE,
                severity=DiagnosticSeverity.ERROR,
                code="demo.status-input-count",
                message="The demo status parser requires exactly one artifact.",
                recoverable=False,
            )
            return

        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                raw = raw_line.strip()
                if not raw or raw.startswith(b"#"):
                    continue

                fallback_evidence = Evidence(
                    artifact_id=artifact_id,
                    locator=f"line:{line_number}",
                    raw_timestamp_ns=None,
                    clock_domain=None,
                    excerpt_sha256=sha256(raw).hexdigest(),
                )
                try:
                    record = json.loads(raw)
                    (
                        timestamp_ns,
                        observed_at_min_ns,
                        observed_at_max_ns,
                        source_sequence,
                        lifecycle,
                        ifindex,
                        name,
                        admin_status,
                        oper_status,
                        description,
                    ) = self._validated_record(
                        record,
                        default_source_sequence=line_number,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                    yield PluginDiagnostic(
                        stage=DiagnosticStage.STATUS_PARSE,
                        severity=DiagnosticSeverity.ERROR,
                        code="demo.invalid-status-record",
                        message=f"Could not parse line {line_number}: {error}",
                        recoverable=True,
                        evidence=(fallback_evidence,),
                    )
                    continue

                evidence = Evidence(
                    artifact_id=artifact_id,
                    locator=f"line:{line_number}",
                    raw_timestamp_ns=timestamp_ns,
                    clock_domain=DEVICE_CLOCK,
                    excerpt_sha256=fallback_evidence.excerpt_sha256,
                )
                # References retain this typed identity; optional forwarding
                # IR must not replace it with a display string or infer its role.
                resource = ResourceKey(
                    namespace=PLUGIN_ID,
                    node=spec.node,
                    layer=spec.layer,
                    kind="INTERFACE",
                    parts=(("ifindex", ifindex),),
                )
                # In-process Value sequences are tuples; core snapshots
                # emitted property mappings before advancing the producer.
                properties = {
                    "name": name,
                    "admin_status": admin_status,
                    "oper_status": oper_status,
                    "description": description,
                }
                yield SourceRecordEmission(
                    timestamp_ns=timestamp_ns,
                    timestamp_uncertainty_ns=(0 if timestamp_ns is not None else None),
                    source_type="status-json",
                    source_name=STATUS_FILENAME,
                    record_name="interface_status",
                    message=f"{name}: admin={admin_status}, oper={oper_status}",
                    layer=spec.layer,
                    copy_text=raw.decode("utf-8"),
                    attributes={
                        "line_number": line_number,
                        "source_sequence": source_sequence,
                        "lifecycle": lifecycle,
                        "observed_at_min_ns": observed_at_min_ns,
                        "observed_at_max_ns": observed_at_max_ns,
                    },
                    evidence=(evidence,),
                )
                # Core owns historical reconstruction; empty query windows
                # never inherit this final snapshot in the browser.
                yield SnapshotObservation(
                    resource=resource,
                    observed_at_min_ns=observed_at_min_ns,
                    observed_at_max_ns=observed_at_max_ns,
                    state=PropertyPatch(
                        set_values=properties,
                        # Metadata uses exact enums for fields in this patch;
                        # capability hooks enforce the same typed contract.
                        field_quality={
                            field_name: Quality.EXACT for field_name in properties
                        },
                        field_provenance={
                            field_name: Provenance.OBSERVED for field_name in properties
                        },
                        complete=True,
                    ),
                    provenance=Provenance.OBSERVED,
                    quality=(
                        Quality.EXACT
                        if timestamp_ns is not None
                        else Quality.BEST_EFFORT
                    ),
                    evidence=evidence,
                    condition=oper_status,
                    condition_class=self._condition_class(oper_status),
                )

    @staticmethod
    def _validated_record(
        record: object,
        *,
        default_source_sequence: int = 0,
    ) -> tuple[
        int | None,
        int,
        int,
        int,
        str,
        int,
        str,
        str,
        str,
        str,
    ]:
        if not isinstance(record, dict):
            raise ValueError("record must be a JSON object")
        if record.get("kind") != "interface":
            raise ValueError("kind must be 'interface'")

        timestamp_ns = record.get("captured_at_ns")
        if timestamp_ns is not None:
            if type(timestamp_ns) is not int:
                raise ValueError("captured_at_ns must be an integer")
            observed_at_min_ns = timestamp_ns
            observed_at_max_ns = timestamp_ns
        else:
            observed_at_min_ns = record.get("observed_at_min_ns")
            observed_at_max_ns = record.get("observed_at_max_ns")
            if (
                type(observed_at_min_ns) is not int
                or type(observed_at_max_ns) is not int
                or observed_at_min_ns > observed_at_max_ns
            ):
                raise ValueError(
                    "a record without captured_at_ns requires an ordered "
                    "integer observation window"
                )
        source_sequence = record.get(
            "source_sequence",
            default_source_sequence,
        )
        if type(source_sequence) is not int or source_sequence < 0:
            raise ValueError("source_sequence must be a non-negative integer")
        lifecycle = bounded_string(
            record.get("lifecycle", "snapshot"),
            "lifecycle",
            maximum=8,
            message="lifecycle must be create, modify, or snapshot",
        )
        if lifecycle not in {"create", "modify", "snapshot"}:
            raise ValueError("lifecycle must be create, modify, or snapshot")
        ifindex = record.get("ifindex")
        if type(ifindex) is not int or ifindex < 0:
            raise ValueError("ifindex must be a non-negative integer")

        name = record.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        admin_status = bounded_string(
            record.get("admin_status"),
            "admin_status",
            maximum=7,
            message="admin_status must be up, down, or unknown",
        )
        oper_status = bounded_string(
            record.get("oper_status"),
            "oper_status",
            maximum=7,
            message="oper_status must be up, down, or unknown",
        )
        allowed_statuses = {"up", "down", "unknown"}
        if admin_status not in allowed_statuses:
            raise ValueError("admin_status must be up, down, or unknown")
        if oper_status not in allowed_statuses:
            raise ValueError("oper_status must be up, down, or unknown")
        description = record.get("description", "")
        if not isinstance(description, str):
            raise ValueError("description must be a string")
        return (
            timestamp_ns,
            observed_at_min_ns,
            observed_at_max_ns,
            source_sequence,
            lifecycle,
            ifindex,
            name,
            admin_status,
            oper_status,
            description,
        )

    @staticmethod
    def _condition_class(oper_status: str) -> ConditionClass:
        if oper_status == "up":
            return ConditionClass.HEALTHY
        if oper_status == "down":
            return ConditionClass.ERROR
        return ConditionClass.UNKNOWN


class ExampleEvidenceAnalysisPlugin(AnalyzerPluginBase):
    """Auxiliary private-analysis semantics composed beside the parser."""

    manifest: PluginManifest = PluginManifest(
        plugin_id=EVIDENCE_PLUGIN_ID,
        plugin_version=EVIDENCE_PLUGIN_VERSION,
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=(PLATFORM_ID,),
        supported_software_versions=">=1,<2",
        capabilities=frozenset({PluginCapability.EVIDENCE_ANALYSIS}),
        reconstruction_default=ReconstructionSupport.EXACT,
        timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
    )

    def describe(self) -> PluginSchema:
        return EVIDENCE_SCHEMA

    def analyze_evidence(
        self,
        request: EvidenceAnalysisRequest,
    ) -> Iterable[EvidenceAnalysisObservation | PluginDiagnostic]:
        """Provide deterministic demo semantics over disclosed evidence only."""

        if request.analysis_kind is EvidenceAnalysisKind.ROUTE_TRACE:
            category = "route_resolution"
            summary = (
                "The selected demo router evidence participates in one "
                "route-resolution hypothesis."
            )
        elif request.analysis_kind is EvidenceAnalysisKind.TRACE_CORRELATION:
            category = "trace_event_correlation"
            summary = (
                "The selected demo trace records form one bounded temporal "
                "correlation candidate."
            )
        elif request.analysis_kind is EvidenceAnalysisKind.EVIDENCE_CORRELATION:
            category = "cross_evidence_correlation"
            summary = (
                "The selected demo evidence supports one bounded cross-source "
                "correlation candidate."
            )
        else:
            category = "evidence_interpretation"
            summary = (
                "The selected demo evidence is compatible with one "
                "plug-in-owned interpretation."
            )
        yield EvidenceAnalysisObservation(
            observation_id=(
                "demo-analysis-" + request.analysis_kind.value.replace("_", "-")
            ),
            category=category,
            summary=summary,
            cited_reference_digests=tuple(
                sorted(fact.reference_digest for fact in request.facts)
            ),
            quality=Quality.BEST_EFFORT,
            details={
                "analysis_kind": request.analysis_kind.value,
                "fact_count": len(request.facts),
                "platform_family": "private-demo-family",
                "software_generation": "private-demo-generation",
            },
        )


class RuntimeAttachedExampleRouterPlugin(AnalyzerPlugin, Protocol):
    """Public type of the installed live entry point with core runtime v2."""

    runtime: Any


# Strict executable identity never executes imports merely to discover a
# dependency. Bind the demo's optional runtime once, while the installed entry
# point is imported, so ordinary strict registration can attest it directly.
_session = __import__(f"{__name__}.session", fromlist=("runtime",))


_entry_plugin = ExampleRouterPlugin()
setattr(_entry_plugin, "runtime", _session.runtime)
plugin: RuntimeAttachedExampleRouterPlugin = cast(
    RuntimeAttachedExampleRouterPlugin,
    _entry_plugin,
)
evidence_plugin: AnalyzerPlugin = ExampleEvidenceAnalysisPlugin()


__all__ = [
    "CONFORMANCE_STATUS_RECORDS",
    "DEVICE_CLOCK",
    "EVIDENCE_PLUGIN_ID",
    "EVIDENCE_PLUGIN_VERSION",
    "EVIDENCE_SCHEMA",
    "GENERATED_ASSEMBLY_FORMAT_VERSION",
    "GENERATED_COVERAGE_FORMAT_VERSION",
    "GENERATED_COVERAGE_REGISTRY_ID",
    "GENERATED_PROJECTION_CAPABILITY_ID",
    "GENERATED_PROJECTION_FORMAT_VERSION",
    "GENERATED_PROJECTION_MEMBERS",
    "GENERATED_PROJECTION_POLICY",
    "GENERATED_PROJECTION_POLICY_ID",
    "GENERATED_PROJECTION_ROOT",
    "GENERATED_SCHEMA_BODY_SHA256",
    "GENERATED_SCHEMA_CONTRACT_ID",
    "GENERATED_SCHEMA_CONTRACT_VERSION",
    "GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID",
    "GENERATED_TOPOLOGY_PROFILE",
    "GENERATED_VPN_TOPOLOGY_PROFILE",
    "GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID",
    "PARSER_ID",
    "PLATFORM_ID",
    "PLUGIN_ENTRY_POINT_NAME",
    "PLUGIN_ID",
    "PLUGIN_VERSION",
    "SCHEMA",
    "SOFTWARE_VERSION",
    "STATUS_FILENAME",
    "ExampleEvidenceAnalysisPlugin",
    "ExampleRouterGeneratedProjectionPolicy",
    "ExampleRouterPlugin",
    "GeneratedProjectionMemberSpec",
    "RuntimeAttachedExampleRouterPlugin",
    "TopologyProfileSpec",
    "evidence_plugin",
    "plugin",
    "render_conformance_status_fixture",
]

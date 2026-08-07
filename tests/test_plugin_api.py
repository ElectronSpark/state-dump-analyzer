from __future__ import annotations

import inspect
import sys
import typing
import unittest
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import router_dump_analyzer
from router_dump_analyzer import plugin_api
from router_dump_analyzer.plugin_api import (
    INPUT_PARSER_CAPABILITIES,
    INPUT_PARSER_HOOKS,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    PLUGIN_CAPABILITY_HOOKS,
    AbsoluteTimeSelector,
    AnalyzerPlugin,
    AnalyzerPluginBase,
    CaptureRange,
    CausalLinkTypeDescriptor,
    ChangeSet,
    ClockAlignmentPolicy,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    DashboardAggregation,
    DashboardColumnDescriptor,
    DashboardDescriptor,
    DashboardFilterDescriptor,
    DashboardFilterOperator,
    DashboardStatisticDescriptor,
    DashboardTableDescriptor,
    DashboardValueFormat,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    DomainEvent,
    Evidence,
    EvidenceAnalysisFact,
    EvidenceAnalysisKind,
    EvidenceAnalysisObservation,
    EvidenceAnalysisRequest,
    FederatedConnectorClaim,
    FederationLinkerPlugin,
    FederationLinkRequest,
    FederationLinkResult,
    FederationMatchCandidate,
    FederationMatchState,
    ForwardingCandidateConstraint,
    ForwardingConstraintKind,
    ForwardingCycleReport,
    ForwardingMember,
    ForwardingMemberActivity,
    ForwardingMemberSelection,
    ForwardingMutation,
    ForwardingOperation,
    ForwardingPolicyDecision,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
    ForwardingProjectionRequest,
    ForwardingTraversalStateKey,
    GlobalResourceRef,
    IconRenderMode,
    InputParserKind,
    InputSpec,
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    KeyAtom,
    NextHopGroup,
    Outcome,
    PathGroupMode,
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
    ReconstructionSupport,
    ReconstructionWatermark,
    RecordLanePreset,
    RelationDirection,
    RelationshipCollectionObservation,
    RelationshipMutation,
    RelationshipObservation,
    RelationshipTypeDescriptor,
    RelationshipView,
    RelativeToWatermarkSelector,
    ResolutionContribution,
    ResolvedNodeBasis,
    ResourceEffect,
    ResourceIconDescriptor,
    ResourceKey,
    ResourceKindDescriptor,
    ResourceStateView,
    ResourceTableRelationLevelDescriptor,
    ResourceTableViewDescriptor,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordGroupDescriptor,
    SourceRecordRef,
    SourceRecordTypeDescriptor,
    StateMutation,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRef,
    StatusPerspectiveRole,
    StatusSourceCombinationPolicy,
    TimelineTimeBasis,
    TopologyDomainRole,
    TopologyEndpointRecord,
    TopologyEndpointReference,
    TopologyExternalClassification,
    TopologyLinkRecord,
    TopologyMatchReference,
    TopologyPluginSemanticsDescriptor,
    TopologyProjectionDescriptor,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourcePresentation,
    TopologyResourceRecord,
    TopologyTwoParticipantShape,
    TopologyUsability,
    UnknownField,
    VrfForwardingState,
    WatermarkScope,
    WorldBasis,
    WorldBasisKind,
    derive_event_uid,
    validate_plugin_diagnostic,
    validate_probe_report,
)


class PluginApiTests(unittest.TestCase):
    def test_public_contract_annotations_resolve(self) -> None:
        for name, value in vars(plugin_api).items():
            if name.startswith("_") or not inspect.isclass(value):
                continue
            with self.subTest(name=name):
                typing.get_type_hints(value)
                for member in vars(value).values():
                    if inspect.isfunction(member):
                        typing.get_type_hints(member)

    def test_domain_event_timestamps_are_signed_int64_at_construction(self) -> None:
        def event(timestamp_ns: int | None, uncertainty_ns: int | None) -> DomainEvent:
            return DomainEvent(
                event_uid=b"event",
                timestamp_ns=timestamp_ns,
                timestamp_uncertainty_ns=uncertainty_ns,
                source_sequence=0,
                event_type="test.event",
                action=None,
                outcome=Outcome.SUCCESS,
                attributes={},
                subjects=(),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                source=SourceRecordRef(source_id="test", message_ordinal=0),
                evidence=Evidence(
                    artifact_id=UUID(int=1),
                    locator="line:1",
                    raw_timestamp_ns=None,
                    clock_domain=None,
                ),
            )

        for timestamp_ns in (-(1 << 63), (1 << 63) - 1):
            with self.subTest(timestamp_ns=timestamp_ns):
                self.assertEqual(event(timestamp_ns, 0).timestamp_ns, timestamp_ns)
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            event(1 << 63, 0)
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            event(-(1 << 63) - 1, 0)
        with self.assertRaisesRegex(ValueError, "non-negative signed 64-bit"):
            event(0, -1)
        with self.assertRaisesRegex(ValueError, "non-negative signed 64-bit"):
            event(0, 1 << 63)
        with self.assertRaisesRegex(ValueError, "without a timestamp"):
            event(None, 0)
        with self.assertRaisesRegex(ValueError, "interval must fit"):
            event((1 << 63) - 1, 1)
        with self.assertRaisesRegex(ValueError, "interval must fit"):
            event(-(1 << 63), 1)

    def test_topology_projection_declares_status_combination_and_tri_state_existence(
        self,
    ) -> None:
        descriptor = TopologyProjectionDescriptor(
            projection_id="synthetic.topology",
            label="Synthetic topology",
            supported_status_perspective_ids=("observed",),
            default_status_perspective_id="observed",
            status_source_combination_policy=(
                StatusSourceCombinationPolicy.ANY_DECLARED_USABLE
            ),
        )
        self.assertEqual(
            descriptor.status_source_combination_policy,
            StatusSourceCombinationPolicy.ANY_DECLARED_USABLE,
        )
        with self.assertRaisesRegex(ValueError, "combination policy"):
            TopologyProjectionDescriptor(
                projection_id="invalid.topology",
                label="Invalid topology",
                supported_status_perspective_ids=("observed",),
                status_source_combination_policy="majority",  # type: ignore[arg-type]
            )

    def test_property_patch_distinguishes_null_remove_and_unknown(self) -> None:
        patch = PropertyPatch(
            set_values={"nullable": None},
            remove_fields=("removed",),
            unknown_fields=(UnknownField("unclear", "missing", "not captured"),),
            field_quality={
                "nullable": Quality.EXACT,
                "removed": Quality.EXACT,
                "unclear": Quality.UNKNOWN,
            },
            field_provenance={
                "nullable": Provenance.OBSERVED,
                "removed": Provenance.EVENT_DERIVED,
                "unclear": Provenance.RECONSTRUCTED,
            },
        )
        self.assertIsNone(patch.set_values["nullable"])

    def test_property_patch_rejects_contradictory_or_orphan_metadata(self) -> None:
        invalid = (
            {"set_values": {"field": 1}, "remove_fields": ("field",)},
            {"remove_fields": ("field", "field")},
            {
                "unknown_fields": (
                    UnknownField("field", "one", "first"),
                    UnknownField("field", "two", "second"),
                )
            },
            {"set_values": {"field": 1}, "field_quality": {"other": Quality.EXACT}},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                PropertyPatch(**arguments)

    def test_ctf_hook_receives_records_not_native_decoder_or_reader(self) -> None:
        parameters = inspect.signature(AnalyzerPlugin.parse_ctf).parameters
        self.assertEqual(tuple(parameters), ("self", "spec", "messages"))
        self.assertNotIn("reader", parameters)
        self.assertNotIn("decoder", parameters)

    def test_event_uid_derivation_is_stable_and_type_separated(self) -> None:
        source = plugin_api.SourceRecordRef(
            source_id="artifact:control/events",
            message_ordinal=17,
            trace_uid="trace-a",
            stream_uid="stream-2",
            packet_sequence=3,
        )
        uid = derive_event_uid(
            "example.router",
            "example.ctf.v1",
            source,
            "interface-update",
        )
        self.assertEqual(
            uid.hex(),
            "19ba7a9f8dedf47a0bbf89a4fd6a63dba2f5ec18c9c19a9500135c83a9a4e3d3",
        )
        self.assertEqual(
            uid,
            derive_event_uid(
                "example.router",
                "example.ctf.v1",
                source,
                "interface-update",
            ),
        )
        self.assertNotEqual(
            derive_event_uid("example.router", "example.ctf.v1", source, 1),
            derive_event_uid("example.router", "example.ctf.v1", source, "1"),
        )
        with self.assertRaisesRegex(ValueError, "local_discriminator"):
            derive_event_uid(
                "example.router",
                "example.ctf.v1",
                source,
                True,  # type: ignore[arg-type]
            )

    def test_manifest_normalizes_standard_capabilities_and_preserves_extensions(
        self,
    ) -> None:
        manifest = PluginManifest(
            plugin_id="example.router",
            plugin_version="1.0.0",
            core_api_version="1.0",
            supported_platforms=("example-os",),
            supported_software_versions=">=1",
            capabilities=frozenset(
                {
                    "status_parse",
                    PluginCapability.CTF_PARSE,
                    "vendor.example.special-projection",
                }
            ),
            reconstruction_default=ReconstructionSupport.BEST_EFFORT,
        )

        self.assertIn(PluginCapability.STATUS_PARSE, manifest.capabilities)
        self.assertTrue(manifest.supports("ctf_parse"))
        self.assertTrue(manifest.supports(PluginCapability.CTF_PARSE))
        self.assertTrue(manifest.supports("vendor.example.special-projection"))
        self.assertFalse(manifest.supports(PluginCapability.CORRELATION))

        with self.assertRaisesRegex(ValueError, "opaque identifiers"):
            PluginManifest(
                plugin_id="example.router",
                plugin_version="1.0.0",
                core_api_version="1.0",
                supported_platforms=("example-os",),
                supported_software_versions=">=1",
                capabilities=frozenset({"not a safe capability"}),
                reconstruction_default=ReconstructionSupport.UNSUPPORTED,
            )

    def test_manifest_declares_one_strict_timeline_clock_basis(self) -> None:
        relative = PluginManifest(
            plugin_id="example.relative",
            plugin_version="1",
            core_api_version="1.0",
            supported_platforms=("example-os",),
            supported_software_versions=">=1",
            capabilities=frozenset(),
            reconstruction_default=ReconstructionSupport.UNSUPPORTED,
        )
        self.assertIs(
            relative.timeline_time_basis,
            TimelineTimeBasis.REVISION_START_RELATIVE_NS,
        )
        self.assertIsNone(relative.timeline_clock_domain)

        source = replace(
            relative,
            plugin_id="example.source-clock",
            timeline_time_basis=TimelineTimeBasis.SOURCE_CLOCK_NS,
            timeline_clock_domain="vendor.clock.asic-0",
        )
        self.assertEqual(source.timeline_clock_domain, "vendor.clock.asic-0")
        for invalid in ("", "../clock", "clock\\domain", " clock", "clock domain"):
            with self.subTest(invalid=invalid), self.assertRaises(
                (TypeError, ValueError)
            ):
                replace(source, timeline_clock_domain=invalid)
        with self.assertRaisesRegex(ValueError, "require timeline_clock_domain"):
            replace(source, timeline_clock_domain=None)
        with self.assertRaisesRegex(ValueError, "valid only"):
            replace(relative, timeline_clock_domain="vendor.clock")

    def test_capability_and_parser_dispatch_matrices_are_complete(self) -> None:
        self.assertEqual(set(PLUGIN_CAPABILITY_HOOKS), set(PluginCapability))
        self.assertEqual(
            PLUGIN_CAPABILITY_HOOKS[PluginCapability.EVENT_REDUCTION],
            ("apply",),
        )
        self.assertEqual(
            PLUGIN_CAPABILITY_HOOKS[PluginCapability.FORWARDING_TRACE],
            ("resolve_forwarding_step",),
        )
        self.assertEqual(
            tuple(inspect.signature(AnalyzerPlugin.resolve_forwarding_step).parameters),
            ("self", "request", "world"),
        )
        self.assertEqual(
            PLUGIN_CAPABILITY_HOOKS[PluginCapability.EVIDENCE_ANALYSIS],
            ("analyze_evidence",),
        )
        self.assertEqual(
            tuple(inspect.signature(AnalyzerPlugin.analyze_evidence).parameters),
            ("self", "request"),
        )
        self.assertEqual(set(INPUT_PARSER_HOOKS), set(InputParserKind))
        self.assertEqual(INPUT_PARSER_HOOKS[InputParserKind.CTF], "parse_ctf")
        self.assertEqual(
            INPUT_PARSER_CAPABILITIES[InputParserKind.CTF],
            PluginCapability.CTF_PARSE,
        )

    def test_evidence_analysis_values_are_bounded_and_deeply_detached(self) -> None:
        digest = "sha256:" + "a" * 64
        payload = {"nested": {"values": [1, 2]}}
        fact = EvidenceAnalysisFact(
            reference_digest=digest,
            evidence_kind="source_record",
            subject_kind="normalized_source_record",
            node_id="node-a",
            revision_id="revision-a",
            payload_schema="example.source.v1",
            fact_provenance="log_derived",
            time_basis="source_clock_ns",
            time_start_ns=10,
            time_end_ns=12,
            time_clock_domain="trace.clock",
            payload=payload,
        )
        payload["nested"]["values"].append(3)
        self.assertEqual(tuple(fact.payload["nested"]["values"]), (1, 2))
        parameters = {"route": {"vrf": "blue"}}
        request = EvidenceAnalysisRequest(
            invocation_id="invocation-a",
            analysis_kind=EvidenceAnalysisKind.TRACE_CORRELATION,
            facts=(fact,),
            parameters=parameters,
            max_observations=4,
        )
        self.assertIsNot(request.facts[0], fact)
        object.__setattr__(fact, "subject_kind", "mutated-after-request")
        self.assertEqual(
            request.facts[0].subject_kind,
            "normalized_source_record",
        )
        parameters["route"]["vrf"] = "red"
        self.assertEqual(request.parameters["route"]["vrf"], "blue")
        details = {"tracepoints": ["fib.lookup", "nh.resolve"]}
        observation = EvidenceAnalysisObservation(
            observation_id="observation-a",
            category="route_resolution",
            summary="The lookup resolves through the retained next hop.",
            cited_reference_digests=(digest,),
            quality=Quality.BEST_EFFORT,
            details=details,
        )
        details["tracepoints"].append("late.mutation")
        self.assertEqual(
            tuple(observation.details["tracepoints"]),
            ("fib.lookup", "nh.resolve"),
        )
        with self.assertRaisesRegex(ValueError, "reversed"):
            replace(fact, time_start_ns=13)
        self.assertEqual(replace(fact), fact)

        cycle: dict[str, object] = {}
        cycle["self"] = cycle
        with self.assertRaisesRegex(ValueError, "reference cycle"):
            replace(fact, payload=cycle)
        with self.assertRaises((TypeError, ValueError)):
            replace(fact, payload={"not_json": (1, 2)})

    def test_input_spec_dispatch_is_explicit_but_legacy_specs_still_load(self) -> None:
        artifact_id = UUID(int=1)
        legacy = InputSpec(
            artifact_ids=(artifact_id,),
            role="vendor-status",
            node="node-a",
            layer="hardware",
            parser_id="example.status.v1",
        )
        explicit = InputSpec(
            artifact_ids=(artifact_id,),
            role="event-stream",
            node="node-a",
            layer="control-plane",
            parser_id="example.ctf.v1",
            parser_kind="ctf",  # type: ignore[arg-type]
        )

        self.assertIsNone(legacy.parser_kind)
        self.assertIsNone(legacy.dispatch_hook)
        self.assertIsNone(legacy.required_capability)
        self.assertIs(explicit.parser_kind, InputParserKind.CTF)
        self.assertEqual(explicit.dispatch_hook, "parse_ctf")
        self.assertIs(explicit.required_capability, PluginCapability.CTF_PARSE)

        with self.assertRaisesRegex(ValueError, "parser kind"):
            InputSpec(
                artifact_ids=(artifact_id,),
                role="unknown",
                node="node-a",
                layer="unknown",
                parser_id="example.unknown.v1",
                parser_kind="xml",  # type: ignore[arg-type]
            )

    def test_parser_outputs_include_generic_source_record_emissions(self) -> None:
        parse_status_return = typing.get_type_hints(AnalyzerPlugin.parse_status)[
            "return"
        ]
        parse_ctf_return = typing.get_type_hints(AnalyzerPlugin.parse_ctf)["return"]
        status_output = typing.get_args(parse_status_return)[0]
        trace_output = typing.get_args(parse_ctf_return)[0]

        self.assertIn(SourceRecordEmission, typing.get_args(status_output.__value__))
        self.assertIn(SourceRecordEmission, typing.get_args(trace_output.__value__))
        source_fields = {field.name for field in dataclass_fields(SourceRecordEmission)}
        self.assertIn("copy_text", source_fields)
        self.assertIn("matched_event_uids", source_fields)

    def test_plugin_base_noops_only_for_undeclared_capabilities(self) -> None:
        def manifest_with(
            *capabilities: PluginCapability,
        ) -> PluginManifest:
            return PluginManifest(
                plugin_id="example.router",
                plugin_version="1.0.0",
                core_api_version="1.0",
                supported_platforms=("example-os",),
                supported_software_versions=">=1",
                capabilities=frozenset(capabilities),
                reconstruction_default=ReconstructionSupport.UNSUPPORTED,
            )

        class PassivePlugin(AnalyzerPluginBase):
            manifest = manifest_with()

        class IncompleteStatusPlugin(AnalyzerPluginBase):
            manifest = manifest_with(PluginCapability.STATUS_PARSE)

        spec = InputSpec(
            artifact_ids=(UUID(int=1),),
            role="status",
            node="node-a",
            layer="hardware",
            parser_id="example.status.v1",
            parser_kind=InputParserKind.STATUS,
        )
        passive = PassivePlugin()

        self.assertEqual(tuple(passive.parse_status(None, spec)), ())  # type: ignore[arg-type]
        self.assertEqual(passive.apply(None, None), ChangeSet())  # type: ignore[arg-type]
        self.assertEqual(tuple(passive.check_consistency(None)), ())  # type: ignore[arg-type]
        with self.assertRaisesRegex(NotImplementedError, "describe"):
            passive.describe()
        with self.assertRaisesRegex(NotImplementedError, "status_parse"):
            tuple(
                IncompleteStatusPlugin().parse_status(None, spec)  # type: ignore[arg-type]
            )

    def test_forwarding_projection_uses_a_typed_bounded_request(self) -> None:
        parameters = inspect.signature(AnalyzerPlugin.project_forwarding).parameters
        self.assertEqual(
            tuple(parameters),
            ("self", "request", "world"),
        )
        request = ForwardingProjectionRequest(
            ir_version="1.0",
            status_perspective=StatusPerspectiveRef(
                perspective_id="hardware.observed",
                plugin_instance_id="node-a/vendor-forwarding",
                schema_digest="sha256:" + "a" * 64,
            ),
            changes=ChangeSet(),
            max_records=2_000,
            max_world_reads=8_000,
        )
        self.assertEqual(request.ir_version, "1.0")
        self.assertIsInstance(request.changes, ChangeSet)
        with self.assertRaisesRegex(ValueError, "max_records"):
            ForwardingProjectionRequest(
                ir_version="1.0",
                status_perspective=request.status_perspective,
                max_records=0,
            )
        with self.assertRaisesRegex(ValueError, "StatusPerspectiveRef"):
            ForwardingProjectionRequest(
                ir_version="1.0",
                status_perspective="hardware.observed",  # type: ignore[arg-type]
            )

    def test_resource_keys_reject_boolean_integer_aliasing(self) -> None:
        with self.assertRaisesRegex(ValueError, "Boolean"):
            ResourceKey(
                namespace="test",
                node="node-a",
                layer="control-plane",
                kind="flagged",
                parts=(("flag", True),),  # type: ignore[arg-type]
            )

    def test_resource_keys_enforce_the_bounded_typed_key_contract(self) -> None:
        invalid_values = (
            1.5,
            ["not", "a", "key"],
            {"not": "a key"},
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "KeyValue"):
                    ResourceKey(
                        namespace="test",
                        node="node-a",
                        layer="control-plane",
                        kind="opaque",
                        parts=(("id", value),),  # type: ignore[arg-type]
                    )

        with self.assertRaisesRegex(ValueError, "requires 1 to 32"):
            ResourceKey(
                namespace="test",
                node="node-a",
                layer="control-plane",
                kind="opaque",
                parts=(),
            )
        with self.assertRaisesRegex(ValueError, "without whitespace"):
            ResourceKey(
                namespace="test",
                node="node a",
                layer="control-plane",
                kind="opaque",
                parts=(("id", 1),),
            )

    def test_key_atoms_disambiguate_shared_scalar_representations(self) -> None:
        sixteen_bytes = bytes.fromhex("20010db8000000000000000000000001")
        atoms = {
            KeyAtom("opaque_int", 1),
            KeyAtom("opaque_uint", 1),
            KeyAtom("ipv4", 1),
            KeyAtom("ipv6", sixteen_bytes),
            KeyAtom("uuid", sixteen_bytes),
            KeyAtom("bytes", sixteen_bytes),
            KeyAtom("plugin:example.driver:table-index", 1),
        }
        self.assertEqual(len(atoms), 7)

        key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="driver",
            kind="TYPED",
            parts=(
                ("hardware_id", KeyAtom("opaque_uint", 1)),
                ("address", KeyAtom("ipv4", 1)),
                (
                    "compound",
                    (
                        KeyAtom("uuid", sixteen_bytes),
                        KeyAtom("bytes", sixteen_bytes),
                    ),
                ),
            ),
        )
        self.assertNotEqual(key.parts[0][1], key.parts[1][1])

        legacy_uuid = UUID("123e4567-e89b-12d3-a456-426614174000")
        legacy = ResourceKey(
            namespace="test",
            node="node-a",
            layer="driver",
            kind="LEGACY",
            parts=(
                ("integer", 7),
                ("string", "7"),
                ("binary", b"7"),
                ("uuid", legacy_uuid),
                ("compound", (7, "7", b"7", legacy_uuid)),
            ),
        )
        self.assertEqual(legacy.parts[0][1], 7)
        self.assertEqual(legacy.parts[-1][1], (7, "7", b"7", legacy_uuid))

    def test_key_atoms_validate_tags_and_standard_payload_shapes(self) -> None:
        invalid = (
            ("vendor-ipv4", 1, "supported standard tag"),
            ("plugin:vendor", 1, "supported standard tag"),
            ("x" * 129, 1, "supported standard tag"),
            ("opaque_int", "1", "must be an integer"),
            ("opaque_uint", -1, "must be non-negative"),
            ("ipv4", 1 << 32, "between 0 and 2\\^32"),
            ("ipv6", b"\x00" * 15, "exactly 16 bytes"),
            ("uuid", UUID(int=0), "exactly 16 bytes"),
            ("bytes", "bytes", "must be bytes"),
            ("plugin:example.driver:table-index", True, "Boolean"),
            (
                "plugin:example.driver:table-index",
                1.5,
                "must be int, str, bytes, or UUID",
            ),
        )
        for type_tag, value, message in invalid:
            with (
                self.subTest(type_tag=type_tag, value=value),
                self.assertRaisesRegex(
                    ValueError,
                    message,
                ),
            ):
                KeyAtom(type_tag, value)  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, "exceeds 4096"):
            KeyAtom("bytes", b"x" * 4097)
        with self.assertRaisesRegex(ValueError, "exceeds 4096"):
            KeyAtom("plugin:example.driver:opaque", "x" * 4097)

    def test_probe_result_declares_match_without_core_version_parsing(self) -> None:
        legacy = ProbeResult(confidence=0.5, reasons=("legacy probe",))
        self.assertEqual(legacy.match_kind, ProbeMatchKind.COMPATIBLE)
        exact = ProbeResult(
            confidence=1.0,
            reasons=("manifest version matched",),
            detected_platform="synthetic",
            detected_software_version="release/vendor-owned",
            match_kind=ProbeMatchKind.EXACT,
        )
        self.assertEqual(exact.match_kind, ProbeMatchKind.EXACT)
        invalid_fields = (
            (
                {"confidence": True, "reasons": ("invalid",)},
                "confidence",
            ),
            (
                {"confidence": float("nan"), "reasons": ("invalid",)},
                "confidence",
            ),
            (
                {"confidence": 0.5, "reasons": ()},
                "probe reasons",
            ),
            (
                {"confidence": 0.5, "reasons": ("",)},
                "probe reason 0",
            ),
            (
                {"confidence": 0.5, "reasons": ("contains\x00nul",)},
                "NUL",
            ),
            (
                {
                    "confidence": 0.5,
                    "reasons": ("invalid",),
                    "detected_platform": "x" * 257,
                },
                "detected_platform",
            ),
        )
        for fields, message in invalid_fields:
            with (
                self.subTest(fields=fields),
                self.assertRaisesRegex(
                    ValueError,
                    message,
                ),
            ):
                ProbeResult(**fields)
        with self.assertRaisesRegex(ValueError, "probe match kind"):
            ProbeResult(
                confidence=0.5,
                reasons=("invalid",),
                match_kind="range-parse-in-core",  # type: ignore[arg-type]
            )

    def test_probe_report_uses_the_declared_diagnostic_contract(self) -> None:
        diagnostic = PluginDiagnostic(
            stage=DiagnosticStage.PROBE,
            severity=DiagnosticSeverity.WARNING,
            code="example.probe-warning",
            message="bounded warning",
            recoverable=True,
            origin=DiagnosticOrigin.PLUGIN,
        )
        report = ProbeReport(
            result=ProbeResult(confidence=0.5, reasons=("recognized",)),
            diagnostics=(diagnostic,),
        )
        self.assertIs(validate_probe_report(report), report)
        self.assertIs(validate_plugin_diagnostic(diagnostic), diagnostic)

        object.__setattr__(diagnostic, "message", "x" * 8_193)
        with self.assertRaisesRegex(ValueError, "message"):
            validate_plugin_diagnostic(diagnostic)
        with self.assertRaisesRegex(
            ValueError,
            r"probe\.diagnostics\[0\]\.message",
        ):
            validate_probe_report(report)

    def test_status_perspective_refs_are_optional_and_core_qualifiable(self) -> None:
        local = StatusPerspectiveRef("hardware-observed")
        self.assertIsNone(local.plugin_instance_id)
        self.assertIsNone(local.schema_digest)

        qualified = StatusPerspectiveRef(
            perspective_id="hardware-observed",
            plugin_instance_id="node-a/driver:v2",
            schema_digest="sha256:" + "a1" * 32,
        )
        self.assertEqual(qualified.plugin_instance_id, "node-a/driver:v2")

        carriers = (
            SnapshotObservation,
            RelationshipObservation,
            RelationshipCollectionObservation,
            StateMutation,
            RelationshipMutation,
            ResourceStateView,
            RelationshipView,
        )
        for carrier in carriers:
            with self.subTest(carrier=carrier.__name__):
                perspective_field = next(
                    item
                    for item in dataclass_fields(carrier)
                    if item.name == "perspective_ref"
                )
                self.assertIsNone(perspective_field.default)

        world_property = plugin_api.ReadOnlyWorld.__dict__["perspective_ref"]
        self.assertIsInstance(world_property, property)
        self.assertEqual(
            typing.get_type_hints(world_property.fget)["return"],
            StatusPerspectiveRef | None,
        )

        with self.assertRaisesRegex(ValueError, "perspective reference ID"):
            StatusPerspectiveRef("Hardware observed")
        with self.assertRaisesRegex(ValueError, "plugin_instance_id"):
            StatusPerspectiveRef(
                "hardware-observed",
                plugin_instance_id="node a",
            )
        with self.assertRaisesRegex(ValueError, "schema_digest"):
            StatusPerspectiveRef(
                "hardware-observed",
                schema_digest="SHA256:" + "AA" * 32,
            )

    def test_compound_child_key_keeps_parent_and_path_identity_typed(self) -> None:
        parent_id = UUID("123e4567-e89b-12d3-a456-426614174000")
        primary = ResourceKey(
            namespace="test",
            node="node-a",
            layer="data-bridge-layer",
            kind="SYNTHETIC_PATH",
            parts=(("parent_resource_id", parent_id), ("path_id", 7)),
        )
        backup = ResourceKey(
            namespace="test",
            node="node-a",
            layer="data-bridge-layer",
            kind="SYNTHETIC_PATH",
            parts=(("parent_resource_id", parent_id), ("path_id", 8)),
        )
        self.assertNotEqual(primary, backup)
        self.assertIsInstance(primary.parts[0][1], UUID)
        self.assertIsInstance(primary.parts[1][1], int)

    def test_resource_presentation_is_generic_and_empty_change_set_is_valid(
        self,
    ) -> None:
        icon = ResourceIconDescriptor(
            path="M4 12h16M12 4v16",
            render_mode=IconRenderMode.STROKE,
            stroke_width=1.5,
        )
        descriptor = ResourceKindDescriptor(
            kind="SYNTHETIC_CONNECTOR",
            label="Synthetic connector",
            key_fields=("id",),
            properties=(PropertyDescriptor("condition", "Condition", "string"),),
            display_name_fields=("id",),
            default_table_fields=("condition",),
            condition_field="condition",
            presentation_tags=("connector", "compact"),
            icon=icon,
        )
        self.assertIn("connector", descriptor.presentation_tags)
        self.assertIs(descriptor.icon, icon)
        with self.assertRaisesRegex(ValueError, "property names must be unique"):
            ResourceKindDescriptor(
                kind="DUPLICATE_PROPERTIES",
                label="Duplicate properties",
                key_fields=("id",),
                properties=(
                    PropertyDescriptor("status", "Status", "string"),
                    PropertyDescriptor("status", "Status again", "string"),
                ),
            )
        with self.assertRaisesRegex(ValueError, "key fields must be unique"):
            ResourceKindDescriptor(
                kind="DUPLICATE_KEYS",
                label="Duplicate keys",
                key_fields=("id", "id"),
                properties=(),
            )
        with self.assertRaisesRegex(ValueError, "searchable must be a boolean"):
            PropertyDescriptor(
                "status",
                "Status",
                "string",
                searchable=1,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            ValueError,
            "client_visible must be a boolean",
        ):
            PropertyDescriptor(
                "status",
                "Status",
                "string",
                client_visible=1,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "SVG path geometry"):
            ResourceIconDescriptor(path="<svg onload=alert(1)>")
        with self.assertRaisesRegex(ValueError, "positive size"):
            ResourceIconDescriptor(path="M0 0", view_box=(0, 0, 0, 24))
        with self.assertRaisesRegex(ValueError, "stroke or fill"):
            ResourceIconDescriptor(
                path="M0 0",
                render_mode="paint",  # type: ignore[arg-type]
            )
        self.assertEqual(ChangeSet().state, ())
        self.assertEqual(ResourceEffect.MODIFIED.value, "modified")

    def test_plugin_dashboards_use_validated_common_widgets(self) -> None:
        resource = ResourceKindDescriptor(
            kind="SYNTHETIC_RESOURCE",
            label="Synthetic resource",
            key_fields=("id",),
            properties=(PropertyDescriptor("status", "Status", "string"),),
        )
        dashboard = DashboardDescriptor(
            dashboard_id="synthetic.health",
            title="Synthetic health",
            description="Generic point-in-time health.",
            statistics=(
                DashboardStatisticDescriptor(
                    statistic_id="resource-count",
                    label="Resources",
                    aggregation=DashboardAggregation.COUNT,
                    resource_kinds=("SYNTHETIC_RESOURCE",),
                    filters=(
                        DashboardFilterDescriptor(
                            field="status",
                            operator=DashboardFilterOperator.NOT_EQ,
                            value="deleted",
                        ),
                    ),
                ),
            ),
            tables=(
                DashboardTableDescriptor(
                    table_id="resource-table",
                    title="Resources",
                    resource_kinds=("SYNTHETIC_RESOURCE",),
                    columns=(
                        DashboardColumnDescriptor(
                            field="label",
                            label="Resource",
                            value_format=DashboardValueFormat.RESOURCE,
                        ),
                        DashboardColumnDescriptor(
                            field="status",
                            label="Status",
                            value_format=DashboardValueFormat.STATUS,
                        ),
                    ),
                ),
            ),
            default_open=True,
        )
        schema = PluginSchema(
            resource_kinds=(resource,),
            relationship_types=(),
            dashboards=(dashboard,),
        )
        self.assertEqual(schema.dashboards[0].dashboard_id, "synthetic.health")
        with self.assertRaisesRegex(
            ValueError,
            "resource kind identifiers must be unique",
        ):
            PluginSchema(
                resource_kinds=(resource, resource),
                relationship_types=(),
            )
        causal = CausalLinkTypeDescriptor(
            link_type="caused",
            label="Caused",
        )
        with self.assertRaisesRegex(
            ValueError,
            "causal link type identifiers must be unique",
        ):
            PluginSchema(
                resource_kinds=(resource,),
                relationship_types=(),
                causal_link_types=(causal, causal),
            )
        with self.assertRaisesRegex(ValueError, "unknown resource kinds"):
            PluginSchema(
                resource_kinds=(resource,),
                relationship_types=(),
                dashboards=(
                    DashboardDescriptor(
                        dashboard_id="invalid.resources",
                        title="Invalid",
                        description="References a missing kind.",
                        statistics=(
                            DashboardStatisticDescriptor(
                                statistic_id="missing-count",
                                label="Missing",
                                aggregation=DashboardAggregation.COUNT,
                                resource_kinds=("MISSING_KIND",),
                            ),
                        ),
                    ),
                ),
            )
        with self.assertRaisesRegex(ValueError, "tuple"):
            DashboardFilterDescriptor(
                field="status",
                operator=DashboardFilterOperator.IN,
                value="up",
            )

    def test_dashboard_table_max_rows_requires_an_exact_integer(self) -> None:
        columns = (
            DashboardColumnDescriptor(
                field="label",
                label="Resource",
            ),
        )
        for max_rows in (True, 1.5, "50", None):
            with self.subTest(max_rows=max_rows):
                with self.assertRaisesRegex(
                    ValueError,
                    "must be an integer between 1 and 500",
                ):
                    DashboardTableDescriptor(
                        table_id="resources",
                        title="Resources",
                        resource_kinds=(),
                        columns=columns,
                        max_rows=max_rows,  # type: ignore[arg-type]
                    )

    def test_plugin_resource_table_views_group_by_declared_relationships(self) -> None:
        parent = ResourceKindDescriptor(
            kind="SYNTHETIC_PARENT",
            label="Synthetic parent",
            key_fields=("id",),
            properties=(PropertyDescriptor("status", "Status", "string"),),
        )
        child = ResourceKindDescriptor(
            kind="SYNTHETIC_CHILD",
            label="Synthetic child",
            key_fields=("id",),
            properties=(PropertyDescriptor("status", "Status", "string"),),
        )
        owns = RelationshipTypeDescriptor(
            relation_type="owns",
            label="Owns",
            directed=True,
            structural=True,
        )
        with self.assertRaisesRegex(
            ValueError,
            "relationship type identifiers must be unique",
        ):
            PluginSchema(
                resource_kinds=(parent, child),
                relationship_types=(owns, owns),
            )
        view = ResourceTableViewDescriptor(
            view_id="parent-paths",
            label="Parent paths",
            description="Children are grouped beneath their active parent.",
            root_kinds=("SYNTHETIC_PARENT",),
            levels=(
                ResourceTableRelationLevelDescriptor(
                    label="Children",
                    relation_types=("owns",),
                    target_kinds=("SYNTHETIC_CHILD",),
                    direction=RelationDirection.OUTGOING,
                ),
            ),
            columns=(
                DashboardColumnDescriptor(
                    field="state.status",
                    label="Status detail",
                    value_format=DashboardValueFormat.STATUS,
                ),
            ),
            default_selected=True,
        )
        schema = PluginSchema(
            resource_kinds=(parent, child),
            relationship_types=(owns,),
            resource_table_views=(view,),
        )
        self.assertEqual(
            schema.resource_table_views[0].levels[0].relation_types, ("owns",)
        )

        with self.assertRaisesRegex(ValueError, "unknown resource kinds"):
            PluginSchema(
                resource_kinds=(parent, child),
                relationship_types=(owns,),
                resource_table_views=(
                    ResourceTableViewDescriptor(
                        view_id="invalid-kind",
                        label="Invalid kind",
                        description="References an undeclared target.",
                        root_kinds=("SYNTHETIC_PARENT",),
                        levels=(
                            ResourceTableRelationLevelDescriptor(
                                label="Missing",
                                relation_types=("owns",),
                                target_kinds=("MISSING",),
                            ),
                        ),
                    ),
                ),
            )
        with self.assertRaisesRegex(ValueError, "unknown relationship types"):
            PluginSchema(
                resource_kinds=(parent, child),
                relationship_types=(owns,),
                resource_table_views=(
                    ResourceTableViewDescriptor(
                        view_id="invalid-relation",
                        label="Invalid relation",
                        description="References an undeclared relationship.",
                        root_kinds=("SYNTHETIC_PARENT",),
                        levels=(
                            ResourceTableRelationLevelDescriptor(
                                label="Children",
                                relation_types=("missing_relation",),
                                target_kinds=("SYNTHETIC_CHILD",),
                            ),
                        ),
                    ),
                ),
            )

    def test_plugin_topology_projections_reference_declared_status_perspectives(
        self,
    ) -> None:
        intended = StatusPerspectiveDescriptor(
            perspective_id="control-intended",
            label="Control-plane intent",
            layer_id="control-plane",
            role=StatusPerspectiveRole.INTENDED,
        )
        observed = StatusPerspectiveDescriptor(
            perspective_id="hardware-observed",
            label="Observed hardware",
            layer_id="hardware-driver-plane",
            role=StatusPerspectiveRole.OBSERVED,
        )
        projection = TopologyProjectionDescriptor(
            projection_id="underlay-connectivity",
            label="Underlay connectivity",
            supported_status_perspective_ids=(
                intended.perspective_id,
                observed.perspective_id,
            ),
            default_status_perspective_id=observed.perspective_id,
        )
        schema = PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            status_perspectives=(intended, observed),
            topology_projections=(projection,),
        )
        self.assertEqual(
            schema.topology_projections[0].default_status_perspective_id,
            "hardware-observed",
        )

        with self.assertRaisesRegex(
            ValueError, "status perspective identifiers must be unique"
        ):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                status_perspectives=(intended, intended),
            )
        with self.assertRaisesRegex(
            ValueError, "topology projection identifiers must be unique"
        ):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                status_perspectives=(intended, observed),
                topology_projections=(projection, projection),
            )
        with self.assertRaisesRegex(ValueError, "unknown status perspectives"):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                status_perspectives=(intended,),
                topology_projections=(projection,),
            )
        with self.assertRaisesRegex(ValueError, "must be one of the supported"):
            TopologyProjectionDescriptor(
                projection_id="invalid-default",
                label="Invalid default",
                supported_status_perspective_ids=("control-intended",),
                default_status_perspective_id="hardware-observed",
            )

    def test_absolute_and_relative_temporal_contracts_are_explicit(self) -> None:
        scope = WatermarkScope(
            node_id="node-a",
            status_perspective_id="hardware-observed",
            topology_projection_id="underlay-connectivity",
        )
        absolute = AbsoluteTimeSelector(
            time_ns=1_759_680_005_000_000_000,
            clock_domain="utc",
        )
        relative = RelativeToWatermarkSelector(
            offset_ns=-5_000_000_000,
            scope=scope,
            clock_policy=ClockAlignmentPolicy.BEST_EFFORT,
        )
        watermark = ReconstructionWatermark(
            scope=scope,
            local_time_ns=8_123_450_000,
            clock_domain="node-a-monotonic",
            absolute_min_ns=1_759_680_004_998_000_000,
            absolute_max_ns=1_759_680_005_002_000_000,
            mapping_method="piecewise_clock_anchors",
            provenance=Provenance.CORRELATED,
            quality=Quality.BEST_EFFORT,
        )
        resolved = ResolvedNodeBasis(
            node_id="node-a",
            local_clock_domain="node-a-monotonic",
            local_min_ns=8_123_449_000,
            local_max_ns=8_123_453_000,
            absolute_min_ns=1_759_680_004_998_000_000,
            absolute_max_ns=1_759_680_005_002_000_000,
            mapping_method="piecewise_clock_anchors",
            quality=Quality.BEST_EFFORT,
        )
        basis = WorldBasis(
            kind=WorldBasisKind.ABSOLUTE_TIME,
            requested_time_ns=absolute.time_ns,
            resolved_at_min_ns=resolved.absolute_min_ns,
            resolved_at_max_ns=resolved.absolute_max_ns,
            capture_ranges=(
                CaptureRange("node-a", 1, 1, clock_domain="node-a-monotonic"),
            ),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.BEST_EFFORT,
            clock_domain="utc",
            selector=absolute,
            node_resolutions=(resolved,),
        )
        self.assertEqual(basis.selector, absolute)
        self.assertEqual(relative.scope, watermark.scope)
        self.assertEqual(basis.capture_ranges[0].clock_domain, "node-a-monotonic")

        # The original constructors remain valid and all new fields default away.
        legacy = WorldBasis(
            kind=WorldBasisKind.RECONSTRUCTED_TIME,
            requested_time_ns=1,
            resolved_at_min_ns=1,
            resolved_at_max_ns=1,
            capture_ranges=(CaptureRange("legacy", 1, 1),),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.EXACT,
        )
        self.assertIsNone(legacy.selector)
        self.assertIsNone(legacy.capture_ranges[0].clock_domain)

        with self.assertRaisesRegex(ValueError, "clock_domain"):
            AbsoluteTimeSelector(time_ns=1, clock_domain="")
        with self.assertRaisesRegex(ValueError, "zero or negative"):
            RelativeToWatermarkSelector(offset_ns=1, scope=scope)
        with self.assertRaisesRegex(ValueError, "both be present"):
            ReconstructionWatermark(
                scope=scope,
                local_time_ns=1,
                clock_domain="node-a-monotonic",
                absolute_min_ns=1,
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.UNKNOWN,
            )
        with self.assertRaisesRegex(ValueError, "requires a reason_code"):
            ResolvedNodeBasis(
                node_id="node-b",
                local_clock_domain=None,
                local_min_ns=None,
                local_max_ns=None,
                absolute_min_ns=None,
                absolute_max_ns=None,
                mapping_method=None,
                quality=Quality.UNKNOWN,
            )
        unaligned = ResolvedNodeBasis(
            node_id="node-b",
            local_clock_domain=None,
            local_min_ns=None,
            local_max_ns=None,
            absolute_min_ns=None,
            absolute_max_ns=None,
            mapping_method=None,
            quality=Quality.UNKNOWN,
            reason_code="clock_unaligned",
        )
        self.assertEqual(unaligned.reason_code, "clock_unaligned")

        # Every public selector and resolved-coordinate contract uses the same
        # signed 64-bit nanosecond domain as the temporal core.
        self.assertEqual(
            AbsoluteTimeSelector(MIN_TIMESTAMP_NS, "utc").time_ns,
            MIN_TIMESTAMP_NS,
        )
        self.assertEqual(
            AbsoluteTimeSelector(MAX_TIMESTAMP_NS, "utc").time_ns,
            MAX_TIMESTAMP_NS,
        )
        self.assertEqual(
            RelativeToWatermarkSelector(MIN_TIMESTAMP_NS, scope).offset_ns,
            MIN_TIMESTAMP_NS,
        )
        for invalid in (MIN_TIMESTAMP_NS - 1, MAX_TIMESTAMP_NS + 1, True):
            with (
                self.subTest(selector_value=invalid),
                self.assertRaisesRegex(ValueError, "signed 64-bit"),
            ):
                AbsoluteTimeSelector(invalid, "utc")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            RelativeToWatermarkSelector(MIN_TIMESTAMP_NS - 1, scope)
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            ReconstructionWatermark(
                scope=scope,
                local_time_ns=MAX_TIMESTAMP_NS + 1,
                clock_domain="node-a-monotonic",
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.UNKNOWN,
            )
        with self.assertRaisesRegex(ValueError, "signed 64-bit"):
            ResolvedNodeBasis(
                node_id="node-a",
                local_clock_domain="node-a-monotonic",
                local_min_ns=MIN_TIMESTAMP_NS - 1,
                local_max_ns=0,
                absolute_min_ns=None,
                absolute_max_ns=None,
                mapping_method=None,
                quality=Quality.UNKNOWN,
            )

    def test_topology_projection_hook_is_bounded_typed_and_generic(self) -> None:
        local = ResourceKey(
            namespace="test",
            node="node-a",
            layer="hardware-driver-plane",
            kind="INTERFACE",
            parts=(("ifindex", 7),),
        )
        remote = ResourceKey(
            namespace="test",
            node="node-b",
            layer="hardware-driver-plane",
            kind="INTERFACE",
            parts=(("ifindex", 9),),
        )
        exact = TopologyEndpointReference(resource=local)
        matched = TopologyEndpointReference(
            match=TopologyMatchReference(
                matcher_id="synthetic.peer-by-system-id",
                arguments={"system_id": "0000.0000.0002"},
                resolved_candidates=(remote,),
            )
        )
        request = TopologyProjectionRequest(
            projection_id="underlay-connectivity",
            status_perspective_id="hardware-observed",
            max_records=256,
            seed_resources=(local,),
        )
        payloads = (
            TopologyResourceRecord(resource=local, role="local-port"),
            TopologyEndpointRecord(
                endpoint_id="node-a:ifindex-7",
                target=exact,
                role="local",
            ),
            TopologyLinkRecord(
                link_id="node-a:ifindex-7--node-b:ifindex-9",
                source=exact,
                target=matched,
            ),
        )
        records = tuple(
            TopologyProjectionRecord(
                projection_id=request.projection_id,
                status_perspective_id=request.status_perspective_id,
                payload=payload,
                usability=TopologyUsability.UNKNOWN,
                source_resources=(local,),
                provenance=Provenance.CORRELATED,
                quality=Quality.AMBIGUOUS,
                exists=None,
                unknown_fields=(
                    UnknownField(
                        name="usability",
                        reason_code="remote_status_missing",
                        message="The selected perspective has no remote status.",
                    ),
                ),
                valid_from_ns=100,
                valid_to_ns=200,
            )
            for payload in payloads
        )
        self.assertEqual(len(records), 3)
        self.assertIsInstance(records[-1].payload, TopologyLinkRecord)
        self.assertIsNone(records[-1].exists)
        self.assertEqual(
            records[-1].payload.target.match.resolved_candidates,
            (remote,),
        )
        project_signature = inspect.signature(AnalyzerPlugin.project_topology)
        self.assertEqual(
            tuple(project_signature.parameters), ("self", "request", "world")
        )

        with self.assertRaisesRegex(ValueError, "exactly one"):
            TopologyEndpointReference()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            TopologyEndpointReference(
                resource=local,
                match=TopologyMatchReference(
                    matcher_id="synthetic.peer",
                    arguments={},
                ),
            )
        with self.assertRaisesRegex(ValueError, "between 1 and 100000"):
            TopologyProjectionRequest(
                projection_id="underlay-connectivity",
                status_perspective_id="hardware-observed",
                max_records=0,
            )
        with self.assertRaisesRegex(ValueError, "max_world_reads"):
            TopologyProjectionRequest(
                projection_id="underlay-connectivity",
                status_perspective_id="hardware-observed",
                max_world_reads=0,
            )
        with self.assertRaisesRegex(ValueError, "reversed"):
            TopologyProjectionRecord(
                projection_id=request.projection_id,
                status_perspective_id=request.status_perspective_id,
                payload=payloads[0],
                usability=TopologyUsability.USABLE,
                source_resources=(local,),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.EXACT,
                valid_from_ns=200,
                valid_to_ns=100,
            )
        with self.assertRaisesRegex(ValueError, "existence"):
            TopologyProjectionRecord(
                projection_id=request.projection_id,
                status_perspective_id=request.status_perspective_id,
                payload=payloads[0],
                usability=TopologyUsability.UNKNOWN,
                source_resources=(local,),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.UNKNOWN,
                exists="maybe",  # type: ignore[arg-type]
            )

    def test_multi_access_media_reuses_resource_and_attachment_link_records(
        self,
    ) -> None:
        segment = ResourceKey(
            namespace="test",
            node="node-a",
            layer="underlay",
            kind="CONNECTIVITY_DOMAIN",
            parts=(("opaque_domain_id", "vrf-default:vlan-101:domain-7"),),
        )
        port_a = ResourceKey(
            namespace="test",
            node="node-a",
            layer="hardware-driver-plane",
            kind="SUBINTERFACE",
            parts=(("ifindex", 7), ("vlan", 101)),
        )
        port_b = ResourceKey(
            namespace="test",
            node="node-a",
            layer="hardware-driver-plane",
            kind="SUBINTERFACE",
            parts=(("ifindex", 9), ("vlan", 101)),
        )
        segment_ref = TopologyEndpointReference(resource=segment)
        records = (
            TopologyProjectionRecord(
                projection_id="underlay-connectivity",
                status_perspective_id="hardware-observed",
                payload=TopologyResourceRecord(
                    resource=segment,
                    role="connectivity-domain",
                ),
                usability=TopologyUsability.USABLE,
                source_resources=(port_a, port_b),
                provenance=Provenance.CORRELATED,
                quality=Quality.BEST_EFFORT,
                properties={
                    "plugin_semantics": {
                        "role": "transit",
                        "prefix": "192.0.2.0/29",
                        "routing_scope": "default",
                    }
                },
            ),
            *(
                TopologyProjectionRecord(
                    projection_id="underlay-connectivity",
                    status_perspective_id="hardware-observed",
                    payload=TopologyLinkRecord(
                        link_id=f"attachment:{index}",
                        source=TopologyEndpointReference(resource=port),
                        target=segment_ref,
                    ),
                    usability=TopologyUsability.USABLE,
                    source_resources=(port,),
                    provenance=Provenance.CORRELATED,
                    quality=Quality.BEST_EFFORT,
                    properties={
                        "attachment_model": {
                            "logical_interface": index,
                            "vlan": 101,
                        }
                    },
                )
                for index, port in enumerate((port_a, port_b), start=1)
            ),
        )
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].payload.role, "connectivity-domain")
        self.assertTrue(
            all(
                isinstance(record.payload, TopologyLinkRecord) for record in records[1:]
            )
        )
        self.assertTrue(
            all(record.payload.target.resource == segment for record in records[1:])
        )

    def test_topology_resource_can_declare_safe_two_participant_presentation(
        self,
    ) -> None:
        segment = ResourceKey(
            namespace="test",
            node="node-a",
            layer="underlay",
            kind="CONNECTIVITY_DOMAIN",
            parts=(("opaque_domain_id", "pair-7"),),
        )
        record = TopologyResourceRecord(
            resource=segment,
            role="connectivity-domain",
            presentation=TopologyResourcePresentation(
                two_participant_shape=TopologyTwoParticipantShape.COMPACT_EDGE
            ),
        )
        self.assertEqual(
            record.presentation.two_participant_shape,
            TopologyTwoParticipantShape.COMPACT_EDGE,
        )
        self.assertEqual(
            TopologyResourceRecord(resource=segment).presentation.two_participant_shape,
            TopologyTwoParticipantShape.DOMAIN_NODE,
        )
        with self.assertRaisesRegex(ValueError, "two-participant shape"):
            TopologyResourcePresentation(two_participant_shape="diagonal")  # type: ignore[arg-type]

    def test_topology_external_and_inter_node_roles_are_typed(self) -> None:
        self.assertIs(
            router_dump_analyzer.TopologyDomainRole,
            TopologyDomainRole,
        )
        self.assertIs(
            router_dump_analyzer.InterNodeRouteTraceRole,
            InterNodeRouteTraceRole,
        )
        semantics = TopologyPluginSemanticsDescriptor(
            role=TopologyDomainRole.EXTERNAL,
            coverage_complete=True,
        )
        self.assertEqual(
            semantics.external_classification,
            TopologyExternalClassification(
                role=TopologyDomainRole.EXTERNAL,
                coverage_complete=True,
            ),
        )
        self.assertIsNone(
            TopologyPluginSemanticsDescriptor(
                role="plugin-owned-transit-role",
                coverage_complete=True,
            ).external_classification
        )
        for coverage_complete in (None, False):
            with self.subTest(coverage_complete=coverage_complete):
                self.assertIsNone(
                    TopologyPluginSemanticsDescriptor(
                        role=TopologyDomainRole.EXTERNAL,
                        coverage_complete=coverage_complete,
                    ).external_classification
                )
        presentation = InterNodeLinkPresentation(route_trace="overlay")  # type: ignore[arg-type]
        self.assertIs(
            presentation.route_trace,
            InterNodeRouteTraceRole.OVERLAY,
        )
        with self.assertRaisesRegex(ValueError, "coverage_complete"):
            TopologyPluginSemanticsDescriptor(
                role="external",
                coverage_complete="yes",  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "route_trace"):
            InterNodeLinkPresentation(route_trace="mirror")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "core-produced"):
            InterNodeLinkPresentation(route_trace=InterNodeRouteTraceRole.CONFLICT)

    def test_plugin_source_types_and_regex_lane_presets_are_declarative(self) -> None:
        source_group = SourceRecordGroupDescriptor(
            group_id="external",
            label="External records",
            description="Records retained outside the normalized event stream.",
            default_included=True,
            copy_action_label="Copy vendor text",
        )
        source_type = SourceRecordTypeDescriptor(
            source_type="vendor-syslog",
            label="Vendor syslog",
            description="Decoded lines retained before normalization.",
            color="#f5b85b",
            stream_group="external",
        )
        preset = RecordLanePreset(
            lane_id="vendor.unmatched-es",
            label="Unmatched ES signals",
            pattern="ESI|mass withdraw",
            source_types=("vendor-syslog",),
            unmatched_only=True,
            default_enabled=True,
        )
        schema = PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            source_record_groups=(source_group,),
            source_record_types=(source_type,),
            record_lane_presets=(preset,),
        )
        self.assertTrue(schema.record_lane_presets[0].default_enabled)
        self.assertTrue(schema.source_record_groups[0].default_included)
        self.assertEqual(
            schema.source_record_groups[0].copy_action_label,
            "Copy vendor text",
        )
        self.assertEqual(schema.source_record_types[0].stream_group, "external")
        with self.assertRaisesRegex(ValueError, "default_included must be a boolean"):
            SourceRecordGroupDescriptor(
                group_id="invalid-default",
                label="Invalid default",
                default_included=1,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "copy_action_label"):
            SourceRecordGroupDescriptor(
                group_id="invalid-copy-label",
                label="Invalid copy label",
                copy_action_label="",
            )
        self.assertIsNone(
            SourceRecordTypeDescriptor(
                source_type="ungrouped",
                label="Ungrouped",
            ).stream_group
        )
        with self.assertRaisesRegex(ValueError, "source record stream_group"):
            SourceRecordTypeDescriptor(
                source_type="invalid-group",
                label="Invalid group",
                stream_group="External logs",
            )
        with self.assertRaisesRegex(ValueError, "unknown source groups"):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                source_record_types=(source_type,),
            )
        with self.assertRaisesRegex(ValueError, "source record groups must be unique"):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                source_record_groups=(source_group, source_group),
            )
        with self.assertRaisesRegex(ValueError, "unknown source types"):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                source_record_groups=(source_group,),
                source_record_types=(source_type,),
                record_lane_presets=(
                    RecordLanePreset(
                        lane_id="invalid.unknown",
                        label="Unknown",
                        pattern=".+",
                        source_types=("missing-source",),
                    ),
                ),
            )
        with self.assertRaisesRegex(ValueError, "invalid record lane pattern"):
            RecordLanePreset(
                lane_id="invalid.regex",
                label="Invalid",
                pattern="[",
            )
        with self.assertRaisesRegex(ValueError, "unsupported regex"):
            RecordLanePreset(
                lane_id="invalid.extension",
                label="Invalid",
                pattern="(?=ESI)",
            )
        with self.assertRaisesRegex(ValueError, "unsupported regex"):
            RecordLanePreset(
                lane_id="invalid.ambiguous-repeat",
                label="Invalid repeat",
                pattern=r"(a|a)+z",
            )

    def test_forwarding_groups_declare_mode_member_state_and_explanations(self) -> None:
        group_key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="GROUP",
            parts=(("id", KeyAtom("opaque_uint", 10)),),
        )
        member_key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("id", KeyAtom("opaque_uint", 11)),),
        )
        evidence = Evidence(
            artifact_id=UUID(int=1),
            locator="json-pointer:/groups/10/members/0",
            raw_timestamp_ns=100,
            clock_domain="node-a-forwarding",
        )
        contribution = ResolutionContribution(
            phase="candidate.selection",
            text="Hardware member 11 is the selected primary.",
            quality=Quality.EXACT,
            resource_references=(group_key, member_key),
            topology_references=(TopologyEndpointReference(resource=member_key),),
            evidence=(evidence,),
        )
        member = ForwardingMember(
            target=member_key,
            weight=1,
            priority=10,
            eligible=True,
            activity=ForwardingMemberActivity.ACTIVE,
            selection=ForwardingMemberSelection.SELECTED,
            contributions=(contribution,),
        )
        group = NextHopGroup(
            key=group_key,
            members=(member,),
            hash_policy=None,
            attributes={},
            mode=PathGroupMode.SINGLE_ACTIVE,
            contributions=(contribution,),
        )
        self.assertEqual(group.mode, PathGroupMode.SINGLE_ACTIVE)
        self.assertEqual(group.members[0].activity, ForwardingMemberActivity.ACTIVE)
        self.assertEqual(group.contributions[0].phase, "candidate.selection")

        second_selected = ForwardingMember(
            target=ResourceKey(
                namespace="test",
                node="node-a",
                layer="forwarding",
                kind="NEXTHOP",
                parts=(("id", KeyAtom("opaque_uint", 12)),),
            ),
            activity=ForwardingMemberActivity.ACTIVE,
            selection=ForwardingMemberSelection.SELECTED,
        )
        with self.assertRaisesRegex(ValueError, "at most one"):
            NextHopGroup(
                key=group_key,
                members=(member, second_selected),
                hash_policy=None,
                attributes={},
                mode=PathGroupMode.SINGLE_ACTIVE,
            )
        with self.assertRaisesRegex(ValueError, "1 to 2000"):
            ResolutionContribution(
                phase="candidate.selection",
                text="x" * 2_001,
                quality=Quality.EXACT,
            )

    def test_forwarding_policy_scopes_use_only_exact_typed_equality(self) -> None:
        scope = ForwardingPolicyScope(
            contract_id="example.split-horizon.v1",
            arguments=(
                ("bridge_domain", KeyAtom("opaque_uint", 100)),
                ("horizon", KeyAtom("plugin:example.evpn:esi", "esi-a")),
            ),
        )
        same_scope = ForwardingPolicyScope(
            contract_id="example.split-horizon.v1",
            arguments=scope.arguments,
        )
        scalar_alias = ForwardingPolicyScope(
            contract_id="example.split-horizon.v1",
            arguments=(
                ("bridge_domain", KeyAtom("ipv4", 100)),
                ("horizon", KeyAtom("plugin:example.evpn:esi", "esi-a")),
            ),
        )
        reordered = ForwardingPolicyScope(
            contract_id="example.split-horizon.v1",
            arguments=tuple(reversed(scope.arguments)),
        )
        other_contract = ForwardingPolicyScope(
            contract_id="example.other-policy.v1",
            arguments=scope.arguments,
        )

        self.assertEqual(scope, same_scope)
        self.assertEqual(hash(scope), hash(same_scope))
        self.assertNotEqual(scope, scalar_alias)
        self.assertNotEqual(scope, reordered)
        self.assertNotEqual(scope, other_contract)
        with self.assertRaisesRegex(ValueError, "Boolean"):
            ForwardingPolicyScope(
                contract_id="example.invalid.v1",
                arguments=(("scope", True),),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "names must be unique"):
            ForwardingPolicyScope(
                contract_id="example.invalid.v1",
                arguments=(("scope", 1), ("scope", 2)),
            )

    def test_candidate_constraints_are_traffic_class_aware_and_explainable(
        self,
    ) -> None:
        candidate = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("id", 11),),
        )
        scope = ForwardingPolicyScope(
            contract_id="example.horizon.v1",
            arguments=(("domain_id", KeyAtom("opaque_uint", 7)),),
        )
        contribution = ResolutionContribution(
            phase="policy.split-horizon",
            text="The plug-in maps this egress to opaque horizon 7.",
            quality=Quality.EXACT,
            resource_references=(candidate,),
        )
        constraint = ForwardingCandidateConstraint(
            constraint_id="candidate-11-horizon-7",
            kind="exclude_exact_scope",  # type: ignore[arg-type]
            candidate_scope=scope,
            traffic_classes=frozenset(
                {"ethernet.broadcast", "ethernet.unknown-unicast"}
            ),
            contributions=(contribution,),
        )

        self.assertIs(
            constraint.kind,
            ForwardingConstraintKind.EXCLUDE_EXACT_SCOPE,
        )
        self.assertTrue(constraint.applies_to("ethernet.broadcast"))
        self.assertFalse(constraint.applies_to("ip.unicast"))
        self.assertIsNone(constraint.applies_to(None))
        blocked = ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict="blocked",  # type: ignore[arg-type]
            traffic_class="ethernet.broadcast",
            ingress_scopes=frozenset({scope}),
        )
        self.assertIs(blocked.verdict, ForwardingPolicyVerdict.BLOCKED)
        self.assertTrue(blocked.ingress_scopes_complete)
        self.assertEqual(
            blocked.constraint.contributions[0].phase,
            "policy.split-horizon",
        )
        ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.NOT_APPLICABLE,
            traffic_class="ip.unicast",
            ingress_scopes=frozenset({scope}),
        )
        ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.PERMITTED,
            traffic_class="ethernet.broadcast",
            ingress_scopes=frozenset(
                {
                    ForwardingPolicyScope(
                        contract_id=scope.contract_id,
                        arguments=(("domain_id", KeyAtom("opaque_uint", 8)),),
                    )
                }
            ),
        )

        with self.assertRaisesRegex(ValueError, "requires a permitted"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.BLOCKED,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset(),
            )
        with self.assertRaisesRegex(ValueError, "requires a blocked"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.PERMITTED,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset({scope}),
            )
        with self.assertRaisesRegex(ValueError, "requires a blocked"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.NOT_APPLICABLE,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset({scope}),
            )
        with self.assertRaisesRegex(ValueError, "requires an unknown"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.PERMITTED,
                traffic_class=None,
                ingress_scopes=frozenset(),
            )
        unknown = ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.UNKNOWN,
            traffic_class=None,
            ingress_scopes=frozenset(),
        )
        self.assertIs(unknown.verdict, ForwardingPolicyVerdict.UNKNOWN)
        incomplete_unknown = ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.UNKNOWN,
            traffic_class="ethernet.broadcast",
            ingress_scopes=frozenset(),
            ingress_scopes_complete=False,
        )
        self.assertFalse(incomplete_unknown.ingress_scopes_complete)
        incomplete_match = ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.BLOCKED,
            traffic_class="ethernet.broadcast",
            ingress_scopes=frozenset({scope}),
            ingress_scopes_complete=False,
        )
        self.assertIs(
            incomplete_match.verdict,
            ForwardingPolicyVerdict.BLOCKED,
        )
        with self.assertRaisesRegex(ValueError, "incomplete.*requires an unknown"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.PERMITTED,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset(),
                ingress_scopes_complete=False,
            )
        with self.assertRaisesRegex(ValueError, "complete.*requires a permitted"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.UNKNOWN,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset(),
            )
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.UNKNOWN,
                traffic_class="ethernet.broadcast",
                ingress_scopes=frozenset(),
                ingress_scopes_complete=0,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "ingress_scopes must be a frozenset"):
            ForwardingPolicyDecision(
                candidate=candidate,
                constraint=constraint,
                verdict=ForwardingPolicyVerdict.BLOCKED,
                traffic_class="ethernet.broadcast",
                ingress_scopes=(scope,),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "frozenset"):
            ForwardingCandidateConstraint(
                constraint_id="invalid-classes",
                kind=ForwardingConstraintKind.EXCLUDE_EXACT_SCOPE,
                candidate_scope=scope,
                traffic_classes={"ethernet.broadcast"},  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "must be strings"):
            ForwardingCandidateConstraint(
                constraint_id="invalid-class-value",
                kind=ForwardingConstraintKind.EXCLUDE_EXACT_SCOPE,
                candidate_scope=scope,
                traffic_classes=frozenset({1}),  # type: ignore[arg-type]
            )

        member = ForwardingMember(
            target=candidate,
            policy_constraints=(constraint,),
        )
        self.assertEqual(member.policy_constraints, (constraint,))
        with self.assertRaisesRegex(ValueError, "identifiers must be unique"):
            ForwardingMember(
                target=candidate,
                policy_constraints=(constraint, constraint),
            )

    def test_unrestricted_candidate_constraint_applies_without_traffic_class(
        self,
    ) -> None:
        candidate = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("id", 12),),
        )
        scope = ForwardingPolicyScope(
            contract_id="example.universal-horizon.v1",
            arguments=(("scope", "local"),),
        )
        constraint = ForwardingCandidateConstraint(
            constraint_id="universal-horizon",
            kind=ForwardingConstraintKind.EXCLUDE_EXACT_SCOPE,
            candidate_scope=scope,
        )

        self.assertTrue(constraint.applies_to(None))
        decision = ForwardingPolicyDecision(
            candidate=candidate,
            constraint=constraint,
            verdict=ForwardingPolicyVerdict.BLOCKED,
            traffic_class=None,
            ingress_scopes=frozenset({scope}),
        )
        self.assertIs(decision.verdict, ForwardingPolicyVerdict.BLOCKED)

    def test_traversal_state_requires_full_canonical_equality_for_cycles(
        self,
    ) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example-forwarding",
        )
        vrf = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="VRF",
            parts=(("name", "blue"),),
        )
        ingress_a = ResourceKey(
            namespace="test",
            node="node-a",
            layer="interfaces",
            kind="PORT",
            parts=(("ifindex", 1),),
        )
        ingress_b = ResourceKey(
            namespace="test",
            node="node-a",
            layer="interfaces",
            kind="PORT",
            parts=(("ifindex", 2),),
        )
        fib_a = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="FIB",
            parts=(("index", 101),),
        )
        fib_b = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="FIB",
            parts=(("index", 102),),
        )
        scope = ForwardingPolicyScope(
            contract_id="example.horizon.v1",
            arguments=(("id", KeyAtom("opaque_uint", 7)),),
        )

        def state(
            *,
            forwarding_object: ResourceKey = fib_a,
            ingress_resource: ResourceKey = ingress_a,
            lookup: str = "203.0.113.8/32",
            label: int = 16_002,
            scopes: frozenset[ForwardingPolicyScope] = frozenset({scope}),
            scopes_complete: bool = True,
        ) -> ForwardingTraversalStateKey:
            return ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=forwarding_object,
                forwarding_domain=vrf,
                ingress_resource=ingress_resource,
                lookup_context=(("destination", lookup),),
                packet_context=(
                    (
                        "label_stack",
                        (KeyAtom("opaque_uint", label),),
                    ),
                ),
                policy_scopes=scopes,
                policy_scopes_complete=scopes_complete,
            )

        original = state()
        exact_copy = state()
        variants = (
            state(forwarding_object=fib_b),
            state(ingress_resource=ingress_b),
            state(lookup="203.0.113.9/32"),
            state(label=16_003),
            state(scopes=frozenset()),
            state(scopes_complete=False),
        )

        self.assertEqual(original, exact_copy)
        self.assertEqual(hash(original), hash(exact_copy))
        self.assertTrue(all(original != variant for variant in variants))
        self.assertEqual(
            len({original, *variants}),
            1 + len(variants),
        )
        with self.assertRaisesRegex(ValueError, "Boolean"):
            ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=fib_a,
                lookup_context=(("flag", True),),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=fib_a,
                policy_scopes_complete=1,  # type: ignore[arg-type]
            )

    def test_cycle_reports_preserve_the_closing_state_and_exact_step_span(
        self,
    ) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example-forwarding",
        )

        def key(index: int) -> ForwardingTraversalStateKey:
            return ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=ResourceKey(
                    namespace="test",
                    node="node-a",
                    layer="forwarding",
                    kind="OBJECT",
                    parts=(("index", index),),
                ),
                lookup_context=(("destination", "203.0.113.8/32"),),
            )

        first = key(1)
        second = key(2)
        report = ForwardingCycleReport(
            first_seen_step=4,
            repeated_at_step=6,
            cycle_states=(first, second, first),
        )
        self.assertEqual(report.cycle_states[0], report.cycle_states[-1])
        self.assertEqual(report.repeated_at_step, 6)

        with self.assertRaisesRegex(ValueError, "exactly repeated"):
            ForwardingCycleReport(
                first_seen_step=4,
                repeated_at_step=5,
                cycle_states=(first, second),
            )
        with self.assertRaisesRegex(ValueError, "step span"):
            ForwardingCycleReport(
                first_seen_step=4,
                repeated_at_step=8,
                cycle_states=(first, second, first),
            )
        with self.assertRaisesRegex(ValueError, "first repeated"):
            ForwardingCycleReport(
                first_seen_step=0,
                repeated_at_step=3,
                cycle_states=(first, second, second, first),
            )

    def test_connector_claims_are_local_typed_and_federated_separately(self) -> None:
        linker_policy = ConnectorMatchPolicyDescriptor(
            policy_id="test.fabric-linker.v1",
            claim_contract_id="test.circuit.v1",
            kind=ConnectorMatchPolicyKind.LINKER,
            argument_names=("circuit_id", "side"),
            linker_plugin_id="test.fabric-linker",
        )
        exact_policy = ConnectorMatchPolicyDescriptor(
            policy_id="test.exact-token.v1",
            claim_contract_id="test.circuit.v1",
            kind=ConnectorMatchPolicyKind.EXACT_TOKEN,
            argument_names=("circuit_id", "side"),
        )
        with self.assertRaisesRegex(ValueError, "must not name a linker"):
            ConnectorMatchPolicyDescriptor(
                policy_id="test.invalid-exact.v1",
                claim_contract_id="test.circuit.v1",
                kind=ConnectorMatchPolicyKind.EXACT_TOKEN,
                argument_names=("circuit_id",),
                linker_plugin_id="test.fabric-linker",
            )
        with self.assertRaisesRegex(ValueError, "require a linker_plugin_id"):
            ConnectorMatchPolicyDescriptor(
                policy_id="test.invalid-linker.v1",
                claim_contract_id="test.circuit.v1",
                kind=ConnectorMatchPolicyKind.LINKER,
                argument_names=("circuit_id",),
            )

        local_resource = ResourceKey(
            namespace="test.alpha",
            node="node-a",
            layer="interfaces",
            kind="PORT",
            parts=(("port_id", KeyAtom("opaque_uint", 17)),),
        )
        local_claim = ConnectorClaim(
            claim_id="claim-a-17",
            endpoint=local_resource,
            claim_contract_id="test.circuit.v1",
            match_policy_id="test.fabric-linker.v1",
            arguments=(
                (
                    "circuit_id",
                    KeyAtom("plugin:test.fabric:circuit-id", 10_017),
                ),
                ("side", KeyAtom("plugin:test.fabric:side", "west")),
            ),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            status_perspective=StatusPerspectiveRef(
                perspective_id="hardware.observed",
                plugin_instance_id="member-a/plugin-alpha",
            ),
            role="local-egress",
        )
        self.assertNotIn(
            "candidates",
            {item.name for item in dataclass_fields(ConnectorClaim)},
        )
        local = FederatedConnectorClaim(
            endpoint=GlobalResourceRef(
                member_id="member-a",
                revision_id="revision-a-1",
                plugin_instance_id="member-a/plugin-alpha",
                resource=local_resource,
            ),
            claim=local_claim,
        )
        request = FederationLinkRequest(
            policy=linker_policy,
            claims=(local,),
            max_results=100,
            max_candidates_per_result=8,
        )
        self.assertEqual(request.claims[0].claim.arguments[0][0], "circuit_id")
        with self.assertRaisesRegex(ValueError, "resolved by the core"):
            FederationLinkRequest(policy=exact_policy, claims=())

        remote_resource = ResourceKey(
            namespace="test.beta",
            node="node-b",
            layer="interfaces",
            kind="PORT",
            parts=(("port_id", KeyAtom("opaque_uint", 29)),),
        )
        candidate = FederationMatchCandidate(
            claim_id="claim-b-29",
            endpoint=GlobalResourceRef(
                member_id="member-b",
                revision_id="revision-b-4",
                plugin_instance_id="member-b/plugin-beta",
                resource=remote_resource,
            ),
            quality=Quality.BEST_EFFORT,
            confidence=0.91,
        )
        result = FederationLinkResult(
            result_id="result-a-17",
            match_policy_id=linker_policy.policy_id,
            source=local,
            state=FederationMatchState.MATCHED,
            candidates=(candidate,),
            provenance=Provenance.CORRELATED,
            quality=Quality.BEST_EFFORT,
            link_type="underlay.adjacency",
        )
        self.assertEqual(result.candidates[0].endpoint.member_id, "member-b")
        with self.assertRaisesRegex(ValueError, "at least two candidates"):
            FederationLinkResult(
                result_id="result-ambiguous-a-17",
                match_policy_id=linker_policy.policy_id,
                source=local,
                state=FederationMatchState.AMBIGUOUS,
                candidates=(candidate,),
                provenance=Provenance.CORRELATED,
                quality=Quality.AMBIGUOUS,
            )
        with self.assertRaisesRegex(ValueError, "at most 64 candidates"):
            FederationLinkResult(
                result_id="result-overflow-a-17",
                match_policy_id=linker_policy.policy_id,
                source=local,
                state=FederationMatchState.CONFLICT,
                candidates=(candidate,) * 65,
                provenance=Provenance.CORRELATED,
                quality=Quality.AMBIGUOUS,
            )
        self.assertEqual(
            tuple(inspect.signature(FederationLinkerPlugin.link).parameters),
            ("self", "request"),
        )

    def test_forwarding_mutation_enforces_operation_shape(self) -> None:
        key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="control-plane",
            kind="VRF",
            parts=(("name", "blue"),),
        )
        other_key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="control-plane",
            kind="VRF",
            parts=(("name", "red"),),
        )
        record = VrfForwardingState(key=key, name="blue", active=True, attributes={})
        other_record = VrfForwardingState(
            key=other_key,
            name="red",
            active=True,
            attributes={},
        )
        basis = WorldBasis(
            kind=WorldBasisKind.RECONSTRUCTED_TIME,
            requested_time_ns=1,
            resolved_at_min_ns=1,
            resolved_at_max_ns=1,
            capture_ranges=(CaptureRange("test", 1, 1),),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.EXACT,
        )
        common = {
            "key": key,
            "effective_time_ns": 1,
            "time_uncertainty_ns": 0,
            "cause_event_uid": None,
            "provenance": Provenance.RECONSTRUCTED,
            "quality": Quality.EXACT,
            "basis": basis,
        }
        ForwardingMutation(
            operation=ForwardingOperation.UPSERT,
            record=record,
            **common,
        )
        with self.assertRaisesRegex(ValueError, "requires a record"):
            ForwardingMutation(
                operation=ForwardingOperation.UPSERT,
                record=None,
                **common,
            )
        with self.assertRaisesRegex(ValueError, "must not include"):
            ForwardingMutation(
                operation=ForwardingOperation.DELETE,
                record=record,
                **common,
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            ForwardingMutation(
                operation=ForwardingOperation.UPSERT,
                record=other_record,
                **common,
            )


if __name__ == "__main__":
    unittest.main()

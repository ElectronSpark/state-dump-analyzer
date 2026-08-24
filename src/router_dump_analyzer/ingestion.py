"""Core-owned parser orchestration and in-memory normalized runtime.

This is the executable path for ordinary parser plug-ins.  The core owns
artifact discovery, reader lifetime, parser dispatch, stable identity,
normalization, and revision storage.  A legacy/precomputed fixture adapter may
still expose ``runtime.v1`` while it migrates, but a normal plug-in no longer
needs an ``open(Path)`` hook.
"""

from __future__ import annotations

import unicodedata
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, nullcontext
from copy import deepcopy
from dataclasses import dataclass, field, fields, is_dataclass, replace
from enum import Enum
from functools import partial
from hashlib import sha256
from math import copysign, isfinite
from pathlib import Path, PurePosixPath
from threading import RLock
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from .artifact_core import (
    ArtifactBoundaryError,
    ArtifactLimits,
    CoreArtifactReader,
    normalize_artifact_path,
)
from .canonical import canonical_json
from .load_progress import AnalysisLoadStage, report_analysis_load
from .plugin_api import (
    CORE_PLUGIN_API_VERSION,
    INPUT_PARSER_HOOKS,
    MAX_DIAGNOSTIC_EVIDENCE_ITEMS,
    MAX_PROBE_DIAGNOSTICS,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    AnalyzerPlugin,
    ArtifactInfo,
    ConditionClass,
    CtfDiscardedEvents,
    CtfDiscardedPackets,
    CtfEventRecord,
    CtfMessage,
    CtfPacketBoundary,
    CtfStreamActivityBoundary,
    CtfStreamBoundary,
    DiagnosticOrigin,
    DiagnosticStage,
    DomainEvent,
    DumpInventory,
    Evidence,
    InputParserKind,
    InputSpec,
    KeyAtom,
    Outcome,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    PropertyPatch,
    Provenance,
    Quality,
    RelationDirection,
    RelationshipCollectionObservation,
    RelationshipObservation,
    ResourceKey,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordRef,
    StatusPerspectiveRef,
    TimelineTimeBasis,
    TraceDecoder,
    UnknownField,
    validate_plugin_diagnostic,
    validate_probe_report,
    validate_probe_result,
)
from .plugin_execution_plan import validate_execution_identity
from .plugin_schema_identity import (
    PluginSchemaIdentityError,
    plugin_schema_dataset,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
    RevisionStore,
)
from .revision_world import _canonical_resource_identity

CORE_INGESTION_RUNTIME_CAPABILITY_ID = "router_dump_analyzer.runtime.v2"
MAX_LOCATED_INPUTS = 10_000
MAX_PARSED_OUTPUTS = 2_000_000
MAX_OUTPUT_DEPTH = 16
MAX_OUTPUT_CONTAINER_ITEMS = 1_024
MAX_OUTPUT_UNITS = 4_096
MAX_OUTPUT_ATOM_UNITS = 65_536
MAX_OUTPUT_INTEGER_BITS = 4_096
MAX_TOTAL_OUTPUTS = 2_000_000
MAX_DECODER_OUTPUTS = 2_000_000
MAX_EVIDENCE_ITEMS = 4_000_000
MAX_SUBJECT_REFERENCES = 4_000_000
MAX_EVENT_LINKS = 4_000_000
MAX_TOTAL_VALUE_UNITS = 64_000_000
MAX_TOTAL_TEXT_BYTES = 256 * 1024 * 1024
MAX_SUBJECTS_PER_EVENT = 4_096
MAX_EVENT_LINKS_PER_RECORD = 4_096


class IngestionError(RuntimeError):
    """A plug-in or input violated the executable ingestion contract."""


def _plugin_execution_boundary(
    operation: str,
    callback: Callable[[], Any],
) -> Any:
    """Contain non-standard plug-in failures without changing Exception flow.

    Ordinary ``Exception`` subclasses remain part of the established ingestion
    contract. Process controls must always reach the host. Only hostile or
    defective ``BaseException`` subclasses outside those two groups are
    translated to a fixed, path-free core diagnostic.
    """

    try:
        return callback()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException as error:
        raise IngestionError(
            f"plug-in {operation} failed during core ingestion"
        ) from error


@dataclass(frozen=True, slots=True)
class _IngestionManifestSnapshot:
    """Core-owned one-shot projection of the executable manifest."""

    plugin_id: str
    plugin_version: str
    core_api_version: str
    supported_platforms: tuple[str, ...]
    supported_software_versions: str
    capabilities: frozenset[PluginCapability | str]
    reconstruction_default: Any
    forwarding_ir_versions: tuple[str, ...]
    timeline_time_basis: TimelineTimeBasis
    timeline_clock_domain: str | None
    _supports: Callable[[PluginCapability | str], Any] = field(
        repr=False,
        compare=False,
    )

    def supports(self, capability: PluginCapability | str) -> Any:
        return _plugin_execution_boundary(
            "manifest supports() execution",
            lambda: self._supports(capability),
        )


@dataclass(slots=True)
class _PluginOutputIterator(Iterator[Any]):
    """Fence construction, lazy iteration, and closing of one plug-in stream."""

    operation: str
    iterator: Iterator[Any]

    @classmethod
    def open(
        cls,
        operation: str,
        producer: Callable[[], Iterable[Any]],
    ) -> _PluginOutputIterator:
        outputs = _plugin_execution_boundary(
            f"{operation} invocation",
            producer,
        )
        iterator = _plugin_execution_boundary(
            f"{operation} iterator construction",
            lambda: iter(outputs),
        )
        return cls(operation=operation, iterator=iterator)

    def __iter__(self) -> _PluginOutputIterator:
        return self

    def __next__(self) -> Any:
        return _plugin_execution_boundary(
            f"{self.operation} iteration",
            lambda: next(self.iterator),
        )

    def close(self) -> None:
        close = _plugin_execution_boundary(
            f"{self.operation} close descriptor resolution",
            lambda: getattr(self.iterator, "close", None),
        )
        if callable(close):
            _plugin_execution_boundary(
                f"{self.operation} close execution",
                close,
            )


@dataclass(slots=True)
class _IngestionPluginSnapshot:
    """Resolve every plug-in descriptor at most once for one ingestion."""

    original: Any
    manifest: _IngestionManifestSnapshot
    _describe: Callable[[], Any]
    _probe: Callable[[DumpInventory], Any]
    _locate_inputs: Callable[[DumpInventory], Iterable[Any]]
    _parser_hooks: dict[str, Callable[..., Iterable[Any]] | None] = field(
        default_factory=dict,
    )

    @classmethod
    def resolve(cls, plugin: Any) -> _IngestionPluginSnapshot:
        manifest = _plugin_execution_boundary(
            "manifest descriptor resolution",
            lambda: getattr(plugin, "manifest", None),
        )
        if not isinstance(manifest, PluginManifest):
            raise IngestionError("core ingestion requires a PluginManifest")

        def manifest_snapshot() -> _IngestionManifestSnapshot:
            if manifest.core_api_version != CORE_PLUGIN_API_VERSION:
                raise IngestionError(
                    "plug-in core API version is incompatible with this core"
                )
            plugin_id = _bounded_text(
                manifest.plugin_id,
                "manifest.plugin_id",
                maximum=256,
            )
            plugin_version = _bounded_text(
                manifest.plugin_version,
                "manifest.plugin_version",
                maximum=128,
            )
            supports = getattr(manifest, "supports", None)
            if not callable(supports):
                raise IngestionError("plug-in manifest requires supports()")
            return _IngestionManifestSnapshot(
                plugin_id=plugin_id,
                plugin_version=plugin_version,
                core_api_version=manifest.core_api_version,
                supported_platforms=manifest.supported_platforms,
                supported_software_versions=manifest.supported_software_versions,
                capabilities=manifest.capabilities,
                reconstruction_default=manifest.reconstruction_default,
                forwarding_ir_versions=manifest.forwarding_ir_versions,
                timeline_time_basis=manifest.timeline_time_basis,
                timeline_clock_domain=manifest.timeline_clock_domain,
                _supports=supports,
            )

        projected_manifest = _plugin_execution_boundary(
            "manifest projection",
            manifest_snapshot,
        )

        def resolve_required_hook(name: str) -> Any:
            return getattr(plugin, name, None)

        resolved: dict[str, Callable[..., Any]] = {}
        for name in ("describe", "probe", "locate_inputs"):
            hook = _plugin_execution_boundary(
                f"{name} descriptor resolution",
                partial(resolve_required_hook, name),
            )
            if not callable(hook):
                raise IngestionError(
                    "core ingestion requires an AnalyzerPlugin with manifest, "
                    "describe(), probe(), and locate_inputs()"
                )
            resolved[name] = hook
        return cls(
            original=plugin,
            manifest=projected_manifest,
            _describe=resolved["describe"],
            _probe=resolved["probe"],
            _locate_inputs=resolved["locate_inputs"],
        )

    def describe(self) -> Any:
        return _plugin_execution_boundary(
            "describe() execution",
            self._describe,
        )

    def probe(self, inventory: DumpInventory) -> Any:
        return _plugin_execution_boundary(
            "probe() execution",
            lambda: self._probe(inventory),
        )

    def locate_inputs(self, inventory: DumpInventory) -> _PluginOutputIterator:
        return _PluginOutputIterator.open(
            "locate_inputs()",
            lambda: self._locate_inputs(inventory),
        )

    def parser_hook(
        self,
        parser_kind: InputParserKind,
    ) -> Callable[..., Iterable[Any]]:
        hook_name = INPUT_PARSER_HOOKS[parser_kind]
        if hook_name not in self._parser_hooks:
            hook = _plugin_execution_boundary(
                f"{hook_name} descriptor resolution",
                lambda: getattr(self.original, hook_name, None),
            )
            self._parser_hooks[hook_name] = hook if callable(hook) else None
        hook = self._parser_hooks[hook_name]
        if hook is None:
            raise IngestionError(f"InputSpec requires missing hook {hook_name}()")
        return hook

    def parse(
        self,
        parser_kind: InputParserKind,
        *args: Any,
    ) -> _PluginOutputIterator:
        hook_name = INPUT_PARSER_HOOKS[parser_kind]
        hook = self.parser_hook(parser_kind)
        return _PluginOutputIterator.open(
            f"{hook_name}()",
            lambda: hook(*args),
        )


@dataclass(frozen=True, slots=True)
class IngestionLimits:
    """Bounds for plug-in-generated discovery and parser output."""

    max_located_inputs: int = MAX_LOCATED_INPUTS
    max_parsed_outputs: int = MAX_PARSED_OUTPUTS
    max_total_outputs: int = MAX_TOTAL_OUTPUTS
    max_decoder_outputs: int = MAX_DECODER_OUTPUTS
    max_diagnostics: int = MAX_PROBE_DIAGNOSTICS
    max_evidence_items: int = MAX_EVIDENCE_ITEMS
    max_subject_references: int = MAX_SUBJECT_REFERENCES
    max_event_links: int = MAX_EVENT_LINKS
    max_total_value_units: int = MAX_TOTAL_VALUE_UNITS
    max_total_text_bytes: int = MAX_TOTAL_TEXT_BYTES
    max_evidence_per_output: int = MAX_DIAGNOSTIC_EVIDENCE_ITEMS
    max_subjects_per_event: int = MAX_SUBJECTS_PER_EVENT
    max_event_links_per_record: int = MAX_EVENT_LINKS_PER_RECORD
    artifact_limits: ArtifactLimits = field(default_factory=ArtifactLimits)

    def __post_init__(self) -> None:
        if type(self.artifact_limits) is not ArtifactLimits:
            raise ValueError("artifact_limits must be an exact ArtifactLimits")
        for name in (
            "max_located_inputs",
            "max_parsed_outputs",
            "max_total_outputs",
            "max_decoder_outputs",
            "max_diagnostics",
            "max_evidence_items",
            "max_subject_references",
            "max_event_links",
            "max_total_value_units",
            "max_total_text_bytes",
            "max_evidence_per_output",
            "max_subjects_per_event",
            "max_event_links_per_record",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class SourceRecordOrigin:
    """Core parser coordinates needed to reproduce one normalized source row."""

    parser_id: str
    input_ordinal: int
    output_ordinal: int

    def __post_init__(self) -> None:
        if (
            type(self.parser_id) is not str
            or not self.parser_id
            or len(self.parser_id) > 256
            or "\x00" in self.parser_id
        ):
            raise ValueError("parser_id must contain 1 to 256 safe characters")
        for name in ("input_ordinal", "output_ordinal"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= (1 << 53) - 1:
                raise ValueError(
                    f"{name} must be a JSON-safe non-negative integer"
                )


@dataclass(frozen=True, slots=True)
class IngestionResult:
    """Detached normalized result of one complete parser run."""

    inventory: DumpInventory
    schema: PluginSchema
    revision_id: str
    node_id: str
    dataset: dict[str, Any]
    diagnostics: tuple[PluginDiagnostic, ...]
    snapshots: tuple[SnapshotObservation, ...]
    relationship_observations: tuple[RelationshipObservation, ...]
    relationship_collections: tuple[
        RelationshipCollectionObservation,
        ...,
    ]
    events: tuple[DomainEvent, ...]
    source_records: tuple[SourceRecordEmission, ...]
    source_record_origins: tuple[SourceRecordOrigin, ...] = ()

    def __post_init__(self) -> None:
        if type(self.inventory) is not DumpInventory:
            raise TypeError("inventory must be an exact DumpInventory")
        if type(self.schema) is not PluginSchema:
            raise TypeError("schema must be an exact PluginSchema")
        validate_execution_identity(self.revision_id, "revision_id")
        validate_execution_identity(self.node_id, "node_id")
        if type(self.dataset) is not dict:
            raise TypeError("dataset must be an exact dictionary")
        for name, expected in (
            ("diagnostics", PluginDiagnostic),
            ("snapshots", SnapshotObservation),
            ("relationship_observations", RelationshipObservation),
            (
                "relationship_collections",
                RelationshipCollectionObservation,
            ),
            ("events", DomainEvent),
            ("source_records", SourceRecordEmission),
            ("source_record_origins", SourceRecordOrigin),
        ):
            values = getattr(self, name)
            if type(values) is not tuple or any(
                type(item) is not expected for item in values
            ):
                raise TypeError(
                    f"{name} must be an exact tuple of {expected.__name__} values"
                )
        if len(self.source_records) != len(self.source_record_origins):
            raise ValueError(
                "source_records and source_record_origins must have equal lengths"
            )


@dataclass(frozen=True, slots=True)
class _ParsedSourceRecord:
    parser_id: str
    input_ordinal: int
    output_ordinal: int
    emission: SourceRecordEmission


def _json_value(
    value: Any,
    *,
    _depth: int = 0,
    _units: list[int] | None = None,
    _active: set[int] | None = None,
) -> Any:
    """Convert one plug-in value to bounded JSON without lossy fallback."""

    if _units is None:
        _units = [0]
    if _active is None:
        _active = set()
    if _depth > MAX_OUTPUT_DEPTH:
        raise IngestionError("plug-in output exceeds the maximum value depth")
    _units[0] += 1
    if _units[0] > MAX_OUTPUT_UNITS:
        raise IngestionError("plug-in output exceeds the maximum value unit count")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, Enum):
        return _json_value(
            value.value,
            _depth=_depth,
            _units=_units,
            _active=_active,
        )
    if isinstance(value, int):
        if value.bit_length() > MAX_OUTPUT_INTEGER_BITS:
            raise IngestionError("plug-in output contains an oversized integer")
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise IngestionError("plug-in output contains a non-finite float")
        return value
    if isinstance(value, str):
        if len(value) > MAX_OUTPUT_ATOM_UNITS:
            raise IngestionError("plug-in output contains an oversized string")
        return value
    if isinstance(value, bytes):
        if len(value) > MAX_OUTPUT_ATOM_UNITS:
            raise IngestionError("plug-in output contains oversized bytes")
        return {
            "type": "bytes",
            "encoding": "hex",
            "value": value.hex(),
        }
    if isinstance(value, UUID):
        return str(value)
    is_mapping = isinstance(value, Mapping)
    is_sequence = isinstance(value, (tuple, list))
    is_record = is_dataclass(value) and not isinstance(value, type)
    if is_mapping or is_sequence or is_record:
        container_id = id(value)
        if container_id in _active:
            raise IngestionError("plug-in output contains a reference cycle")
        _active.add(container_id)
        try:
            if is_mapping:
                if len(value) > MAX_OUTPUT_CONTAINER_ITEMS:
                    raise IngestionError(
                        "plug-in output mapping exceeds the item limit"
                    )
                if any(not isinstance(key, str) for key in value):
                    raise IngestionError("plug-in output mappings require string keys")
                return {
                    key: _json_value(
                        item,
                        _depth=_depth + 1,
                        _units=_units,
                        _active=_active,
                    )
                    for key, item in value.items()
                }
            if is_sequence:
                if len(value) > MAX_OUTPUT_CONTAINER_ITEMS:
                    raise IngestionError(
                        "plug-in output sequence exceeds the item limit"
                    )
                return [
                    _json_value(
                        item,
                        _depth=_depth + 1,
                        _units=_units,
                        _active=_active,
                    )
                    for item in value
                ]
            descriptors = fields(value)
            if len(descriptors) > MAX_OUTPUT_CONTAINER_ITEMS:
                raise IngestionError("plug-in output record exceeds the field limit")
            return {
                descriptor.name: _json_value(
                    getattr(value, descriptor.name),
                    _depth=_depth + 1,
                    _units=_units,
                    _active=_active,
                )
                for descriptor in descriptors
            }
        finally:
            _active.remove(container_id)
    raise IngestionError(
        f"plug-in output contains unsupported value type {type(value).__name__}"
    )


def _snapshot_parser_output_value(
    value: Any,
    *,
    _depth: int = 0,
    _units: list[int] | None = None,
    _active: set[int] | None = None,
) -> Any:
    """Deeply detach one already-validated parser output graph."""

    units = _units if _units is not None else [0]
    active = _active if _active is not None else set()
    if _depth > MAX_OUTPUT_DEPTH:
        raise IngestionError("plug-in output exceeds the maximum value depth")
    units[0] += 1
    if units[0] > MAX_OUTPUT_UNITS:
        raise IngestionError("plug-in output exceeds the maximum value unit count")
    value_type = type(value)
    if value is None or value_type in (bool, int, float, str):
        return value
    if isinstance(value, Enum):
        return value_type(value.value)
    if value_type is bytes:
        return bytes(value)
    if value_type is UUID:
        return UUID(bytes=value.bytes)
    if value_type is PurePosixPath:
        return PurePosixPath(value.as_posix())
    is_mapping = isinstance(value, Mapping)
    is_sequence = isinstance(value, (tuple, list))
    is_record = is_dataclass(value) and not isinstance(value, type)
    if not (is_mapping or is_sequence or is_record):
        raise IngestionError(
            f"plug-in output contains unsupported value type {value_type.__name__}"
        )
    identity = id(value)
    if identity in active:
        raise IngestionError("plug-in output contains a reference cycle")
    active.add(identity)
    try:
        if is_mapping:
            detached: dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= MAX_OUTPUT_CONTAINER_ITEMS:
                    raise IngestionError(
                        "plug-in output mapping exceeds the item limit"
                    )
                if type(key) is not str:
                    raise IngestionError("plug-in output mappings require string keys")
                detached[key] = _snapshot_parser_output_value(
                    item,
                    _depth=_depth + 1,
                    _units=units,
                    _active=active,
                )
            return MappingProxyType(detached)
        if is_sequence:
            if len(value) > MAX_OUTPUT_CONTAINER_ITEMS:
                raise IngestionError("plug-in output sequence exceeds the item limit")
            return tuple(
                _snapshot_parser_output_value(
                    item,
                    _depth=_depth + 1,
                    _units=units,
                    _active=active,
                )
                for item in value
            )
        if value_type.__module__ != "router_dump_analyzer.plugin_api":
            raise IngestionError("plug-in output contains an unsupported record type")
        descriptors = fields(value)
        if len(descriptors) > MAX_OUTPUT_CONTAINER_ITEMS:
            raise IngestionError("plug-in output record exceeds the field limit")
        return replace(
            value,
            **{
                descriptor.name: _snapshot_parser_output_value(
                    getattr(value, descriptor.name),
                    _depth=_depth + 1,
                    _units=units,
                    _active=active,
                )
                for descriptor in descriptors
                if descriptor.init
            },
        )
    finally:
        active.remove(identity)


def _normalized_value_size(value: Any) -> tuple[int, int]:
    """Return value-unit and UTF-8 text budgets for normalized JSON."""

    units = 0
    text_bytes = 0
    pending = [value]
    while pending:
        item = pending.pop()
        units += 1
        if isinstance(item, str):
            text_bytes += len(item.encode("utf-8"))
        elif isinstance(item, Mapping):
            for key, nested in item.items():
                text_bytes += len(str(key).encode("utf-8"))
                pending.append(nested)
        elif isinstance(item, list):
            pending.extend(item)
    return units, text_bytes


def _output_cardinality(value: Any) -> tuple[int, int, int]:
    """Return evidence, subject, and event-link counts for one output."""

    evidence_count = 0
    subject_count = 0
    event_link_count = 0
    if isinstance(value, PluginDiagnostic):
        evidence_count = len(value.evidence)
    elif isinstance(value, SnapshotObservation):
        evidence_count = 1 + sum(
            len(item.evidence) for item in value.state.unknown_fields
        )
    elif isinstance(value, RelationshipObservation):
        evidence_count = 1 + sum(
            len(item.evidence) for item in value.attributes.unknown_fields
        )
    elif isinstance(value, RelationshipCollectionObservation):
        evidence_count = 1
    elif isinstance(value, DomainEvent):
        evidence_count = 1
        subject_count = len(value.subjects)
    elif isinstance(value, SourceRecordEmission):
        evidence_count = len(value.evidence)
        event_link_count = len(value.matched_event_uids) + (
            1 if value.matched_event_uid is not None else 0
        )
    elif isinstance(
        value,
        (
            CtfEventRecord,
            CtfStreamBoundary,
            CtfPacketBoundary,
            CtfDiscardedEvents,
            CtfDiscardedPackets,
            CtfStreamActivityBoundary,
        ),
    ):
        evidence_count = len(value.evidence)
    return evidence_count, subject_count, event_link_count


@dataclass(slots=True)
class _IngestionBudget:
    """Aggregate fail-closed budget shared by one complete ingestion."""

    limits: IngestionLimits
    outputs: int = 0
    decoder_outputs: int = 0
    diagnostics: int = 0
    evidence_items: int = 0
    subject_references: int = 0
    event_links: int = 0
    value_units: int = 0
    text_bytes: int = 0

    def consume(
        self,
        value: Any,
        *,
        label: str,
        output: bool = True,
        decoder: bool = False,
    ) -> None:
        if type(value) is InputSpec:
            normalized = _json_value(
                {
                    "artifact_ids": [
                        str(artifact_id) for artifact_id in value.artifact_ids
                    ],
                    "role": value.role,
                    "node": value.node,
                    "layer": value.layer,
                    "parser_id": value.parser_id,
                    "logical_root": (
                        value.logical_root.as_posix()
                        if value.logical_root is not None
                        else None
                    ),
                    "options": value.options,
                    "parser_kind": value.parser_kind,
                }
            )
        else:
            normalized = _json_value(value)
        units, text_bytes = _normalized_value_size(normalized)
        self.value_units += units
        self.text_bytes += text_bytes
        if self.value_units > self.limits.max_total_value_units:
            raise IngestionError(
                "plug-in outputs exceeded the aggregate value-unit limit"
            )
        if self.text_bytes > self.limits.max_total_text_bytes:
            raise IngestionError(
                "plug-in outputs exceeded the aggregate text-byte limit"
            )
        if output:
            self.outputs += 1
            if self.outputs > self.limits.max_total_outputs:
                raise IngestionError(
                    "plug-in and decoder outputs exceeded the aggregate output limit"
                )
        if decoder:
            self.decoder_outputs += 1
            if self.decoder_outputs > self.limits.max_decoder_outputs:
                raise IngestionError("CTF decoder exceeded the configured output limit")
        if isinstance(value, PluginDiagnostic):
            self.diagnostics += 1
            if self.diagnostics > self.limits.max_diagnostics:
                raise IngestionError(
                    "diagnostics exceeded the configured aggregate limit"
                )
        evidence, subjects, links = _output_cardinality(value)
        if evidence > self.limits.max_evidence_per_output:
            raise IngestionError(f"{label} exceeds the per-output evidence limit")
        if subjects > self.limits.max_subjects_per_event:
            raise IngestionError(f"{label} exceeds the per-event subject limit")
        if links > self.limits.max_event_links_per_record:
            raise IngestionError(f"{label} exceeds the per-record event-link limit")
        self.evidence_items += evidence
        self.subject_references += subjects
        self.event_links += links
        if self.evidence_items > self.limits.max_evidence_items:
            raise IngestionError("evidence references exceeded the aggregate limit")
        if self.subject_references > self.limits.max_subject_references:
            raise IngestionError("event subjects exceeded the aggregate limit")
        if self.event_links > self.limits.max_event_links:
            raise IngestionError("source-to-event links exceeded the aggregate limit")


def _resource_identity(resource: ResourceKey) -> tuple[str, dict[str, Any]]:
    return _canonical_resource_identity(resource)


def _resource_label(resource: ResourceKey) -> str:
    values: list[str] = []
    for _name, value in resource.parts:
        if isinstance(value, KeyAtom):
            value = value.value
        if isinstance(value, bytes):
            values.append(value.hex())
        else:
            values.append(str(value))
    return "/".join(values) or resource.kind


def _patch(
    current: Mapping[str, Any],
    current_unknown: Mapping[str, dict[str, Any]],
    current_quality: Mapping[str, str],
    current_provenance: Mapping[str, str],
    patch: PropertyPatch,
    *,
    default_quality: Quality,
    default_provenance: Provenance,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    result = dict(current) if not patch.complete else {}
    unknown = dict(current_unknown) if not patch.complete else {}
    field_quality = dict(current_quality) if not patch.complete else {}
    field_provenance = dict(current_provenance) if not patch.complete else {}
    for name in patch.remove_fields:
        result.pop(name, None)
        unknown.pop(name, None)
        field_quality.pop(name, None)
        field_provenance.pop(name, None)
    for name, value in patch.set_values.items():
        key = str(name)
        result[key] = _json_value(value)
        unknown.pop(key, None)
    for item in patch.unknown_fields:
        # Unknown masks a formerly known value. Keeping that stale value would
        # silently turn missing evidence into a positive state assertion.
        result.pop(item.name, None)
        unknown[item.name] = _json_value(item)
    mentioned = {
        *(str(name) for name in patch.set_values),
        *patch.remove_fields,
        *(item.name for item in patch.unknown_fields),
    }
    for name in mentioned:
        field_quality[name] = patch.field_quality.get(
            name,
            default_quality,
        ).value
        field_provenance[name] = patch.field_provenance.get(
            name,
            default_provenance,
        ).value
    return result, unknown, field_quality, field_provenance


def _evidence(value: Any) -> dict[str, Any]:
    result = _json_value(value)
    assert isinstance(result, dict)
    return result


def _exact_optional_integer(
    value: Any,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise IngestionError(f"{label} must be an integer or null")
    if minimum is not None and value < minimum:
        raise IngestionError(f"{label} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise IngestionError(f"{label} must be at most {maximum}")
    if value.bit_length() > MAX_OUTPUT_INTEGER_BITS:
        raise IngestionError(f"{label} exceeds the integer size limit")
    return value


def _time_bounds(
    minimum_ns: Any,
    maximum_ns: Any,
    label: str,
) -> tuple[int | None, int | None]:
    minimum = _exact_optional_integer(
        minimum_ns,
        f"{label}.observed_at_min_ns",
        minimum=MIN_TIMESTAMP_NS,
        maximum=MAX_TIMESTAMP_NS,
    )
    maximum = _exact_optional_integer(
        maximum_ns,
        f"{label}.observed_at_max_ns",
        minimum=MIN_TIMESTAMP_NS,
        maximum=MAX_TIMESTAMP_NS,
    )
    if (minimum is None) != (maximum is None):
        raise IngestionError(
            f"{label} observation bounds must both be present or absent"
        )
    if minimum is not None and maximum is not None and minimum > maximum:
        raise IngestionError(f"{label} observation minimum exceeds its maximum")
    return minimum, maximum


def _bounded_text(
    value: Any,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > maximum
        or "\x00" in value
    ):
        qualifier = "zero to" if allow_empty else "one to"
        raise IngestionError(
            f"{label} must contain {qualifier} {maximum} safe characters"
        )
    return value


def _validate_evidence(
    evidence: Any,
    *,
    artifact_ids: set[UUID],
    label: str,
) -> Evidence:
    if type(evidence) is not Evidence:
        raise IngestionError(f"{label} must be an exact Evidence")
    if evidence.artifact_id not in artifact_ids:
        raise IngestionError(f"{label} references an artifact outside its input")
    _bounded_text(evidence.locator, f"{label}.locator", maximum=4_096)
    _exact_optional_integer(
        evidence.raw_timestamp_ns,
        f"{label}.raw_timestamp_ns",
        minimum=MIN_TIMESTAMP_NS,
        maximum=MAX_TIMESTAMP_NS,
    )
    if evidence.clock_domain is not None:
        _bounded_text(
            evidence.clock_domain,
            f"{label}.clock_domain",
            maximum=256,
        )
    if evidence.excerpt_sha256 is not None:
        digest = evidence.excerpt_sha256
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in digest)
        ):
            raise IngestionError(
                f"{label}.excerpt_sha256 must be a 64-digit hex digest"
            )
    return evidence


@dataclass(frozen=True, slots=True)
class _SchemaIndex:
    key_fields_by_kind: dict[str, tuple[str, ...]]
    property_roots_by_kind: dict[str, frozenset[str]]
    relationship_types: frozenset[str]
    source_types: frozenset[str]
    perspective_ids: frozenset[str]

    @classmethod
    def build(cls, schema: PluginSchema) -> _SchemaIndex:
        return cls(
            key_fields_by_kind={
                descriptor.kind: descriptor.key_fields
                for descriptor in schema.resource_kinds
            },
            property_roots_by_kind={
                descriptor.kind: frozenset(
                    property_descriptor.name.split(".", 1)[0]
                    for property_descriptor in descriptor.properties
                )
                for descriptor in schema.resource_kinds
            },
            relationship_types=frozenset(
                descriptor.relation_type for descriptor in schema.relationship_types
            ),
            source_types=frozenset(
                descriptor.source_type for descriptor in schema.source_record_types
            ),
            perspective_ids=frozenset(
                descriptor.perspective_id for descriptor in schema.status_perspectives
            ),
        )


def _validate_resource(
    resource: Any,
    schema_index: _SchemaIndex,
    label: str,
    *,
    expected_node: str | None = None,
) -> ResourceKey:
    if type(resource) is not ResourceKey:
        raise IngestionError(f"{label} must be an exact ResourceKey")
    if expected_node is not None and resource.node != expected_node:
        raise IngestionError(
            f"{label} belongs to node {resource.node!r}, not selected "
            f"node {expected_node!r}"
        )
    expected_fields = schema_index.key_fields_by_kind.get(resource.kind)
    if expected_fields is None:
        raise IngestionError(
            f"{label} references undeclared resource kind {resource.kind!r}"
        )
    actual_fields = tuple(name for name, _value in resource.parts)
    if actual_fields != expected_fields:
        raise IngestionError(
            f"{label} key fields do not match the declared order for {resource.kind!r}"
        )
    _json_value(resource)
    return resource


def _validate_patch(
    patch: Any,
    *,
    allowed_roots: frozenset[str],
    artifact_ids: set[UUID],
    label: str,
) -> PropertyPatch:
    if type(patch) is not PropertyPatch:
        raise IngestionError(f"{label} must be an exact PropertyPatch")
    if type(patch.complete) is not bool:
        raise IngestionError(f"{label}.complete must be a boolean")
    if not isinstance(patch.set_values, Mapping):
        raise IngestionError(f"{label}.set_values must be a mapping")
    if not isinstance(patch.remove_fields, tuple):
        raise IngestionError(f"{label}.remove_fields must be a tuple")
    if not isinstance(patch.unknown_fields, tuple):
        raise IngestionError(f"{label}.unknown_fields must be a tuple")
    if not isinstance(patch.field_quality, Mapping):
        raise IngestionError(f"{label}.field_quality must be a mapping")
    if not isinstance(patch.field_provenance, Mapping):
        raise IngestionError(f"{label}.field_provenance must be a mapping")
    if any(not isinstance(name, str) for name in patch.set_values):
        raise IngestionError(f"{label}.set_values keys must be strings")
    if any(not isinstance(name, str) for name in patch.remove_fields):
        raise IngestionError(f"{label}.remove_fields values must be strings")
    if any(type(item) is not UnknownField for item in patch.unknown_fields):
        raise IngestionError(
            f"{label}.unknown_fields values must be exact UnknownField records"
        )
    set_names = set(patch.set_values)
    remove_names = set(patch.remove_fields)
    unknown_names = {item.name for item in patch.unknown_fields}
    if len(remove_names) != len(patch.remove_fields):
        raise IngestionError(f"{label}.remove_fields contains duplicate names")
    if len(unknown_names) != len(patch.unknown_fields):
        raise IngestionError(f"{label}.unknown_fields contains duplicate names")
    if overlap := (
        (set_names & remove_names)
        | (set_names & unknown_names)
        | (remove_names & unknown_names)
    ):
        raise IngestionError(
            f"{label} mentions fields in incompatible operations: "
            + ", ".join(sorted(overlap))
        )
    metadata_names = set(patch.field_quality) | set(patch.field_provenance)
    if any(not isinstance(name, str) for name in metadata_names):
        raise IngestionError(f"{label} field metadata keys must be strings")
    if unrelated := metadata_names - (set_names | remove_names | unknown_names):
        raise IngestionError(
            f"{label} field metadata references unmentioned fields: "
            + ", ".join(sorted(unrelated))
        )
    mentioned = {
        *(str(name).split(".", 1)[0] for name in patch.set_values),
        *(str(name).split(".", 1)[0] for name in patch.remove_fields),
        *(str(unknown.name).split(".", 1)[0] for unknown in patch.unknown_fields),
    }
    if unknown := mentioned - allowed_roots:
        raise IngestionError(
            f"{label} references undeclared properties: " + ", ".join(sorted(unknown))
        )
    for name in (
        *patch.set_values,
        *patch.remove_fields,
        *(item.name for item in patch.unknown_fields),
    ):
        _bounded_text(name, f"{label}.field", maximum=1_024)
    for index, unknown_field in enumerate(patch.unknown_fields):
        if not isinstance(unknown_field.evidence, tuple):
            raise IngestionError(
                f"{label}.unknown_fields[{index}].evidence must be a tuple"
            )
        _bounded_text(
            unknown_field.reason_code,
            f"{label}.unknown_fields[{index}].reason_code",
            maximum=256,
        )
        _bounded_text(
            unknown_field.message,
            f"{label}.unknown_fields[{index}].message",
            maximum=8_192,
            allow_empty=True,
        )
        for evidence_index, evidence in enumerate(unknown_field.evidence):
            _validate_evidence(
                evidence,
                artifact_ids=artifact_ids,
                label=(f"{label}.unknown_fields[{index}].evidence[{evidence_index}]"),
            )
    for name, quality in patch.field_quality.items():
        if not isinstance(quality, Quality):
            raise IngestionError(f"{label}.field_quality[{name!r}] is invalid")
    for name, provenance in patch.field_provenance.items():
        if not isinstance(provenance, Provenance):
            raise IngestionError(f"{label}.field_provenance[{name!r}] is invalid")
    _json_value(patch)
    return patch


def _validate_perspective(
    perspective: Any,
    *,
    schema_index: _SchemaIndex,
    label: str,
) -> StatusPerspectiveRef | None:
    if perspective is None:
        return None
    if type(perspective) is not StatusPerspectiveRef:
        raise IngestionError(f"{label} must be an exact StatusPerspectiveRef or null")
    if perspective.perspective_id not in schema_index.perspective_ids:
        raise IngestionError(
            f"{label} references undeclared perspective {perspective.perspective_id!r}"
        )
    _json_value(perspective)
    return perspective


def _validate_diagnostic(
    diagnostic: Any,
    *,
    artifact_ids: set[UUID],
    label: str,
    expected_origin: DiagnosticOrigin | None = None,
    expected_stage: DiagnosticStage | None = None,
) -> PluginDiagnostic:
    try:
        validated = validate_plugin_diagnostic(
            diagnostic,
            label=label,
            expected_origin=expected_origin,
            expected_stage=expected_stage,
            artifact_ids=artifact_ids,
        )
    except ValueError as error:
        raise IngestionError(str(error)) from error
    _json_value(diagnostic.details)
    return validated


def _validate_parser_output(
    output: Any,
    *,
    schema_index: _SchemaIndex,
    artifact_ids: set[UUID],
    expected_node: str,
    expected_diagnostic_stage: DiagnosticStage,
    label: str,
) -> None:
    if type(output) is PluginDiagnostic:
        _validate_diagnostic(
            output,
            artifact_ids=artifact_ids,
            label=label,
            expected_origin=DiagnosticOrigin.PLUGIN,
            expected_stage=expected_diagnostic_stage,
        )
        return
    if type(output) is SnapshotObservation:
        resource = _validate_resource(
            output.resource,
            schema_index,
            label,
            expected_node=expected_node,
        )
        _time_bounds(
            output.observed_at_min_ns,
            output.observed_at_max_ns,
            label,
        )
        _validate_patch(
            output.state,
            allowed_roots=schema_index.property_roots_by_kind[resource.kind],
            artifact_ids=artifact_ids,
            label=f"{label}.state",
        )
        if not isinstance(output.provenance, Provenance):
            raise IngestionError(f"{label}.provenance is invalid")
        if not isinstance(output.quality, Quality):
            raise IngestionError(f"{label}.quality is invalid")
        if not isinstance(output.condition_class, ConditionClass):
            raise IngestionError(f"{label}.condition_class is invalid")
        _validate_evidence(
            output.evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence",
        )
        _json_value(output.condition)
        _validate_perspective(
            output.perspective_ref,
            schema_index=schema_index,
            label=f"{label}.perspective_ref",
        )
        return
    if type(output) is RelationshipObservation:
        _validate_resource(
            output.source,
            schema_index,
            f"{label}.source",
            expected_node=expected_node,
        )
        _validate_resource(
            output.target,
            schema_index,
            f"{label}.target",
            expected_node=expected_node,
        )
        if output.relation_type not in schema_index.relationship_types:
            raise IngestionError(
                f"{label} references undeclared relationship type "
                f"{output.relation_type!r}"
            )
        _time_bounds(
            output.observed_at_min_ns,
            output.observed_at_max_ns,
            label,
        )
        if output.present is not None and type(output.present) is not bool:
            raise IngestionError(f"{label}.present must be boolean or null")
        _validate_patch(
            output.attributes,
            allowed_roots=frozenset(
                str(name).split(".", 1)[0]
                for name in (
                    *output.attributes.set_values,
                    *output.attributes.remove_fields,
                    *(item.name for item in output.attributes.unknown_fields),
                )
            ),
            artifact_ids=artifact_ids,
            label=f"{label}.attributes",
        )
        if not isinstance(output.provenance, Provenance):
            raise IngestionError(f"{label}.provenance is invalid")
        if not isinstance(output.quality, Quality):
            raise IngestionError(f"{label}.quality is invalid")
        _validate_evidence(
            output.evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence",
        )
        _validate_perspective(
            output.perspective_ref,
            schema_index=schema_index,
            label=f"{label}.perspective_ref",
        )
        return
    if type(output) is RelationshipCollectionObservation:
        _validate_resource(
            output.owner,
            schema_index,
            f"{label}.owner",
            expected_node=expected_node,
        )
        if not isinstance(output.direction, RelationDirection):
            raise IngestionError(f"{label}.direction is invalid")
        if output.relation_type not in schema_index.relationship_types:
            raise IngestionError(
                f"{label} references undeclared relationship type "
                f"{output.relation_type!r}"
            )
        _time_bounds(
            output.observed_at_min_ns,
            output.observed_at_max_ns,
            label,
        )
        if type(output.complete) is not bool:
            raise IngestionError(f"{label}.complete must be a boolean")
        if not isinstance(output.provenance, Provenance):
            raise IngestionError(f"{label}.provenance is invalid")
        if not isinstance(output.quality, Quality):
            raise IngestionError(f"{label}.quality is invalid")
        _validate_evidence(
            output.evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence",
        )
        _validate_perspective(
            output.perspective_ref,
            schema_index=schema_index,
            label=f"{label}.perspective_ref",
        )
        return
    if type(output) is DomainEvent:
        if (
            not isinstance(output.event_uid, bytes)
            or not 1 <= len(output.event_uid) <= 256
        ):
            raise IngestionError(f"{label}.event_uid must contain 1 to 256 bytes")
        _exact_optional_integer(
            output.timestamp_ns,
            f"{label}.timestamp_ns",
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
        uncertainty = _exact_optional_integer(
            output.timestamp_uncertainty_ns,
            f"{label}.timestamp_uncertainty_ns",
            minimum=0,
            maximum=MAX_TIMESTAMP_NS,
        )
        if output.timestamp_ns is None and uncertainty is not None:
            raise IngestionError(f"{label} cannot have uncertainty without a timestamp")
        if (
            output.timestamp_ns is not None
            and uncertainty is not None
            and (
                output.timestamp_ns - uncertainty < MIN_TIMESTAMP_NS
                or output.timestamp_ns + uncertainty > MAX_TIMESTAMP_NS
            )
        ):
            raise IngestionError(
                f"{label} timestamp uncertainty interval must fit signed 64-bit"
            )
        if type(output.source_sequence) is not int:
            raise IngestionError(f"{label}.source_sequence must be an integer")
        if output.source_sequence < 0:
            raise IngestionError(f"{label}.source_sequence must be non-negative")
        _bounded_text(
            output.event_type,
            f"{label}.event_type",
            maximum=256,
        )
        if output.action is not None:
            _bounded_text(
                output.action,
                f"{label}.action",
                maximum=256,
            )
        if not isinstance(output.outcome, Outcome):
            raise IngestionError(f"{label}.outcome is invalid")
        if not isinstance(output.provenance, Provenance):
            raise IngestionError(f"{label}.provenance is invalid")
        if not isinstance(output.quality, Quality):
            raise IngestionError(f"{label}.quality is invalid")
        if not isinstance(output.subjects, tuple):
            raise IngestionError(f"{label}.subjects must be a tuple")
        for index, resource in enumerate(output.subjects):
            _validate_resource(
                resource,
                schema_index,
                f"{label}.subjects[{index}]",
                expected_node=expected_node,
            )
        _validate_evidence(
            output.evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence",
        )
        _json_value(output.attributes)
        if type(output.source) is not SourceRecordRef:
            raise IngestionError(f"{label}.source must be an exact SourceRecordRef")
        _bounded_text(
            output.source.source_id,
            f"{label}.source.source_id",
            maximum=1_024,
        )
        if type(output.source.message_ordinal) is not int:
            raise IngestionError(f"{label}.source.message_ordinal must be an integer")
        if output.source.message_ordinal < 0:
            raise IngestionError(f"{label}.source.message_ordinal must be non-negative")
        for field_name, value in (
            ("trace_uid", output.source.trace_uid),
            ("stream_uid", output.source.stream_uid),
        ):
            if value is not None:
                _bounded_text(
                    value,
                    f"{label}.source.{field_name}",
                    maximum=1_024,
                )
        _exact_optional_integer(
            output.source.packet_sequence,
            f"{label}.source.packet_sequence",
            minimum=0,
        )
        return
    assert type(output) is SourceRecordEmission
    if not isinstance(output.evidence, tuple):
        raise IngestionError(f"{label}.evidence must be a tuple")
    if not isinstance(output.matched_event_uids, tuple):
        raise IngestionError(f"{label}.matched_event_uids must be a tuple")
    timestamp = _exact_optional_integer(
        output.timestamp_ns,
        f"{label}.timestamp_ns",
        minimum=MIN_TIMESTAMP_NS,
        maximum=MAX_TIMESTAMP_NS,
    )
    uncertainty = _exact_optional_integer(
        output.timestamp_uncertainty_ns,
        f"{label}.timestamp_uncertainty_ns",
        minimum=0,
        maximum=MAX_TIMESTAMP_NS,
    )
    if timestamp is None and uncertainty is not None:
        raise IngestionError(f"{label} cannot have uncertainty without a timestamp")
    if (
        timestamp is not None
        and uncertainty is not None
        and (
            timestamp - uncertainty < MIN_TIMESTAMP_NS
            or timestamp + uncertainty > MAX_TIMESTAMP_NS
        )
    ):
        raise IngestionError(
            f"{label} timestamp uncertainty interval must fit signed 64-bit"
        )
    if output.source_type not in schema_index.source_types:
        raise IngestionError(
            f"{label} references undeclared source type {output.source_type!r}"
        )
    _bounded_text(
        output.source_name,
        f"{label}.source_name",
        maximum=1_024,
    )
    _bounded_text(
        output.record_name,
        f"{label}.record_name",
        maximum=256,
    )
    _bounded_text(
        output.message,
        f"{label}.message",
        maximum=8_192,
        allow_empty=True,
    )
    if output.layer is not None:
        _bounded_text(
            output.layer,
            f"{label}.layer",
            maximum=256,
        )
    if output.copy_text is not None and (
        not isinstance(output.copy_text, str)
        or "\x00" in output.copy_text
        or len(output.copy_text.encode("utf-8")) > 65_536
    ):
        raise IngestionError(f"{label}.copy_text exceeds its safe text contract")
    event_links = (
        *(
            (output.matched_event_uid,)
            if output.matched_event_uid is not None
            else ()
        ),
        *output.matched_event_uids,
    )
    if any(
        not isinstance(event_uid, bytes) or not 1 <= len(event_uid) <= 256
        for event_uid in event_links
    ):
        raise IngestionError(f"{label} contains an invalid matched event identifier")
    for index, evidence in enumerate(output.evidence):
        _validate_evidence(
            evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence[{index}]",
        )
    _json_value(output.attributes)


def _validate_ctf_message(
    message: Any,
    *,
    artifact_ids: set[UUID],
    label: str,
) -> CtfMessage:
    allowed = (
        CtfEventRecord,
        CtfStreamBoundary,
        CtfPacketBoundary,
        CtfDiscardedEvents,
        CtfDiscardedPackets,
        CtfStreamActivityBoundary,
    )
    if type(message) not in allowed:
        raise IngestionError(f"{label} must be an exact dependency-free CtfMessage")
    typed = cast(CtfMessage, message)
    for field_name in ("trace_uid", "stream_uid"):
        _bounded_text(
            getattr(typed, field_name),
            f"{label}.{field_name}",
            maximum=1_024,
        )
    message_ordinal = typed.message_ordinal
    if type(message_ordinal) is not int or message_ordinal < 0:
        raise IngestionError(f"{label}.message_ordinal must be a non-negative integer")
    clock_domain = typed.clock_domain
    if clock_domain is not None:
        _bounded_text(
            clock_domain,
            f"{label}.clock_domain",
            maximum=256,
        )
    evidence_items = typed.evidence
    if not isinstance(evidence_items, tuple):
        raise IngestionError(f"{label}.evidence must be a tuple")
    for index, evidence in enumerate(evidence_items):
        _validate_evidence(
            evidence,
            artifact_ids=artifact_ids,
            label=f"{label}.evidence[{index}]",
        )
    if isinstance(typed, CtfEventRecord):
        event_record = typed
        _bounded_text(
            event_record.event_name,
            f"{label}.event_name",
            maximum=1_024,
        )
        timestamp = _exact_optional_integer(
            event_record.timestamp_ns,
            f"{label}.timestamp_ns",
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
        uncertainty = _exact_optional_integer(
            event_record.timestamp_uncertainty_ns,
            f"{label}.timestamp_uncertainty_ns",
            minimum=0,
            maximum=MAX_TIMESTAMP_NS,
        )
        if timestamp is None and uncertainty is not None:
            raise IngestionError(f"{label} cannot have uncertainty without a timestamp")
        if (
            timestamp is not None
            and uncertainty is not None
            and (
                timestamp - uncertainty < MIN_TIMESTAMP_NS
                or timestamp + uncertainty > MAX_TIMESTAMP_NS
            )
        ):
            raise IngestionError(
                f"{label} timestamp uncertainty interval must fit signed 64-bit"
            )
        _exact_optional_integer(
            event_record.packet_sequence,
            f"{label}.packet_sequence",
            minimum=0,
        )
        _json_value(event_record.payload)
        _json_value(event_record.common_context)
        _json_value(event_record.specific_context)
    elif isinstance(typed, (CtfStreamBoundary, CtfPacketBoundary)):
        boundary = typed
        if type(boundary.started) is not bool:
            raise IngestionError(f"{label}.started must be a boolean")
        _exact_optional_integer(
            boundary.timestamp_ns,
            f"{label}.timestamp_ns",
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
        if isinstance(boundary, CtfPacketBoundary):
            _exact_optional_integer(
                boundary.packet_sequence,
                f"{label}.packet_sequence",
                minimum=0,
            )
    elif isinstance(typed, CtfStreamActivityBoundary):
        activity = typed
        if type(activity.began) is not bool:
            raise IngestionError(f"{label}.began must be a boolean")
        _exact_optional_integer(
            activity.timestamp_ns,
            f"{label}.timestamp_ns",
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
    else:
        assert isinstance(
            typed,
            (CtfDiscardedEvents, CtfDiscardedPackets),
        )
        discarded = typed
        _exact_optional_integer(
            discarded.count,
            f"{label}.count",
            minimum=0,
        )
        begin, end = _time_bounds(
            discarded.begin_timestamp_ns,
            discarded.end_timestamp_ns,
            label,
        )
        if begin is not None and end is not None and begin > end:
            raise IngestionError(f"{label} begin timestamp exceeds end timestamp")
    return typed


def _schema_dataset(schema: PluginSchema) -> dict[str, Any]:
    try:
        return plugin_schema_dataset(schema)
    except PluginSchemaIdentityError as error:
        raise IngestionError("plug-in schema cannot be normalized") from error


def _source_uid(
    *,
    plugin_id: str,
    node_id: str,
    parser_id: str,
    input_ordinal: int,
    ordinal: int,
    emission: SourceRecordEmission,
) -> str:
    digest = sha256()
    digest.update(b"router-dump-source-record:v1")
    for value in (
        plugin_id,
        node_id,
        parser_id,
        str(input_ordinal),
        str(ordinal),
        str(emission.timestamp_ns),
        emission.source_type,
        emission.source_name,
        emission.record_name,
    ):
        payload = value.encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    for evidence in emission.evidence:
        digest.update(evidence.artifact_id.bytes)
        payload = evidence.locator.encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _build_dataset(
    *,
    plugin_id: str,
    inventory: DumpInventory,
    schema: PluginSchema,
    revision_id: str,
    node_id: str,
    snapshots: Sequence[SnapshotObservation],
    relationship_observations: Sequence[RelationshipObservation],
    relationship_collections: Sequence[RelationshipCollectionObservation],
    events: Sequence[DomainEvent],
    source_records: Sequence[_ParsedSourceRecord],
    diagnostics: Sequence[PluginDiagnostic],
    timeline_time_basis: TimelineTimeBasis,
    timeline_clock_domain: str | None,
) -> dict[str, Any]:
    resources_by_key: dict[ResourceKey, dict[str, Any]] = {}
    snapshots_by_key: dict[ResourceKey, list[SnapshotObservation]] = defaultdict(list)
    for observation in snapshots:
        snapshots_by_key[observation.resource].append(observation)
    for relationship_observation in relationship_observations:
        resources_by_key.setdefault(
            relationship_observation.source,
            {},
        )
        resources_by_key.setdefault(
            relationship_observation.target,
            {},
        )
    for collection in relationship_collections:
        resources_by_key.setdefault(collection.owner, {})
    for event in events:
        for subject in event.subjects:
            resources_by_key.setdefault(subject, {})
    for resource in snapshots_by_key:
        resources_by_key.setdefault(resource, {})

    resource_ids = {
        resource: _resource_identity(resource)[0] for resource in resources_by_key
    }
    resources: list[dict[str, Any]] = []
    state_intervals: list[dict[str, Any]] = []
    lifecycle_intervals: list[dict[str, Any]] = []
    time_values: list[int] = []

    def add_observation_time_bounds(
        timestamp_ns: int,
        uncertainty_ns: int | None,
    ) -> None:
        if (
            timeline_time_basis is TimelineTimeBasis.ABSOLUTE_UNIX_NS
            and timestamp_ns < 0
        ):
            raise IngestionError(
                "absolute-unix plug-in timelines cannot contain negative timestamps"
            )
        uncertainty = uncertainty_ns or 0
        minimum = (
            0
            if timeline_time_basis is TimelineTimeBasis.ABSOLUTE_UNIX_NS
            else MIN_TIMESTAMP_NS
        )
        time_values.append(max(minimum, timestamp_ns - uncertainty))
        time_values.append(min(MAX_TIMESTAMP_NS, timestamp_ns + uncertainty))

    for resource in sorted(
        resources_by_key,
        key=lambda item: resource_ids[item],
    ):
        identifier, identity = _resource_identity(resource)
        observations = sorted(
            snapshots_by_key.get(resource, ()),
            key=lambda item: (
                item.observed_at_min_ns is None,
                item.observed_at_min_ns or 0,
                item.observed_at_max_ns is None,
                item.observed_at_max_ns or 0,
                item.evidence.artifact_id.bytes,
                item.evidence.locator,
            ),
        )
        current: dict[str, Any] = {}
        current_unknown: dict[str, dict[str, Any]] = {}
        current_field_quality: dict[str, str] = {}
        current_field_provenance: dict[str, str] = {}
        resource_intervals: list[dict[str, Any]] = []
        for index, observation in enumerate(observations):
            (
                current,
                current_unknown,
                current_field_quality,
                current_field_provenance,
            ) = _patch(
                current,
                current_unknown,
                current_field_quality,
                current_field_provenance,
                observation.state,
                default_quality=observation.quality,
                default_provenance=observation.provenance,
            )
            valid_from = observation.observed_at_min_ns
            next_observation = (
                observations[index + 1] if index + 1 < len(observations) else None
            )
            valid_to = (
                next_observation.observed_at_min_ns
                if next_observation is not None
                else None
            )
            if valid_from is not None:
                time_values.append(valid_from)
            if observation.observed_at_max_ns is not None:
                time_values.append(observation.observed_at_max_ns)
            interval = {
                "resource": identifier,
                "valid_from_ns": (str(valid_from) if valid_from is not None else None),
                "valid_to_ns": (str(valid_to) if valid_to is not None else None),
                "observed_at_min_ns": (
                    str(observation.observed_at_min_ns)
                    if observation.observed_at_min_ns is not None
                    else None
                ),
                "observed_at_max_ns": (
                    str(observation.observed_at_max_ns)
                    if observation.observed_at_max_ns is not None
                    else None
                ),
                "status": (
                    str(observation.condition)
                    if isinstance(
                        observation.condition,
                        (str, int, float, bool),
                    )
                    else observation.condition_class.value
                ),
                "status_class": observation.condition_class.value,
                "condition": _json_value(observation.condition),
                "properties": dict(current),
                "unknown_fields": list(current_unknown.values()),
                "field_quality": dict(current_field_quality),
                "field_provenance": dict(current_field_provenance),
                "provenance": observation.provenance.value,
                "quality": observation.quality.value,
                "evidence": [_evidence(observation.evidence)],
                "perspective_ref": (
                    _json_value(observation.perspective_ref)
                    if observation.perspective_ref is not None
                    else None
                ),
            }
            state_intervals.append(interval)
            resource_intervals.append(interval)
        first_seen = observations[0].observed_at_min_ns if observations else None
        if observations:
            lifecycle_intervals.append(
                {
                    "resource": identifier,
                    "valid_from_ns": (
                        str(first_seen) if first_seen is not None else None
                    ),
                    "valid_to_ns": None,
                }
            )
        latest = resource_intervals[-1] if resource_intervals else None
        resources.append(
            {
                "resource_id": identifier,
                "canonical_resource_id": identifier,
                "kind": resource.kind,
                "layer": resource.layer,
                "label": _resource_label(resource),
                "key": identity,
                "placeholder": not observations,
                "state": (dict(latest["properties"]) if latest is not None else {}),
                "unknown_fields": (
                    list(latest["unknown_fields"]) if latest is not None else []
                ),
                "field_quality": (
                    dict(latest["field_quality"]) if latest is not None else {}
                ),
                "field_provenance": (
                    dict(latest["field_provenance"]) if latest is not None else {}
                ),
                "status": (latest.get("status") if latest is not None else "unknown"),
                "status_class": (
                    latest.get("status_class")
                    if latest is not None
                    else ConditionClass.UNKNOWN.value
                ),
            }
        )

    relationship_intervals: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    grouped_relationships: dict[
        tuple[ResourceKey, ResourceKey, str],
        list[RelationshipObservation],
    ] = defaultdict(list)
    for relationship_observation in relationship_observations:
        grouped_relationships[
            (
                relationship_observation.source,
                relationship_observation.target,
                relationship_observation.relation_type,
            )
        ].append(relationship_observation)
    for key, relationship_items in sorted(
        grouped_relationships.items(),
        key=lambda item: (
            resource_ids[item[0][0]],
            resource_ids[item[0][1]],
            item[0][2],
        ),
    ):
        source, target, relation_type = key
        ordered_relationships = sorted(
            relationship_items,
            key=lambda item: (
                item.observed_at_min_ns is None,
                item.observed_at_min_ns or 0,
                item.observed_at_max_ns is None,
                item.observed_at_max_ns or 0,
                item.evidence.artifact_id.bytes,
                item.evidence.locator,
            ),
        )
        relationship_state: dict[str, Any] = {}
        relationship_unknown: dict[str, dict[str, Any]] = {}
        relationship_field_quality: dict[str, str] = {}
        relationship_field_provenance: dict[str, str] = {}
        latest_interval: dict[str, Any] | None = None
        for index, relationship_observation in enumerate(ordered_relationships):
            (
                relationship_state,
                relationship_unknown,
                relationship_field_quality,
                relationship_field_provenance,
            ) = _patch(
                relationship_state,
                relationship_unknown,
                relationship_field_quality,
                relationship_field_provenance,
                relationship_observation.attributes,
                default_quality=relationship_observation.quality,
                default_provenance=relationship_observation.provenance,
            )
            valid_from = relationship_observation.observed_at_min_ns
            valid_to = (
                ordered_relationships[index + 1].observed_at_min_ns
                if index + 1 < len(ordered_relationships)
                else None
            )
            interval = {
                "source": resource_ids[source],
                "target": resource_ids[target],
                "type": relation_type,
                "relation_type": relation_type,
                "present": relationship_observation.present,
                "valid_from_ns": (str(valid_from) if valid_from is not None else None),
                "valid_to_ns": (str(valid_to) if valid_to is not None else None),
                "observed_at_min_ns": (
                    str(relationship_observation.observed_at_min_ns)
                    if relationship_observation.observed_at_min_ns is not None
                    else None
                ),
                "observed_at_max_ns": (
                    str(relationship_observation.observed_at_max_ns)
                    if relationship_observation.observed_at_max_ns is not None
                    else None
                ),
                "attributes": dict(relationship_state),
                "unknown_fields": list(relationship_unknown.values()),
                "field_quality": dict(relationship_field_quality),
                "field_provenance": dict(relationship_field_provenance),
                "provenance": relationship_observation.provenance.value,
                "quality": relationship_observation.quality.value,
                "evidence": [_evidence(relationship_observation.evidence)],
                "perspective_ref": (
                    _json_value(relationship_observation.perspective_ref)
                    if relationship_observation.perspective_ref is not None
                    else None
                ),
            }
            if valid_from is not None:
                time_values.append(valid_from)
            if relationship_observation.observed_at_max_ns is not None:
                time_values.append(relationship_observation.observed_at_max_ns)
            relationship_intervals.append(interval)
            latest_interval = interval
        # Unknown presence is not an active edge. A current relationship is
        # asserted only by an explicit latest `present=True` observation.
        if ordered_relationships[-1].present is True and latest_interval is not None:
            relationships.append(dict(latest_interval))

    normalized_events: list[dict[str, Any]] = []
    for event in sorted(
        events,
        key=lambda item: (
            item.timestamp_ns is None,
            item.timestamp_ns or 0,
            item.source_sequence,
            item.event_uid,
        ),
    ):
        if event.timestamp_ns is not None:
            add_observation_time_bounds(
                event.timestamp_ns,
                event.timestamp_uncertainty_ns,
            )
        normalized_events.append(
            {
                "event_uid": event.event_uid.hex(),
                "timestamp_ns": (
                    str(event.timestamp_ns) if event.timestamp_ns is not None else None
                ),
                "timestamp_uncertainty_ns": (
                    str(event.timestamp_uncertainty_ns)
                    if event.timestamp_uncertainty_ns is not None
                    else None
                ),
                "source_sequence": event.source_sequence,
                "event_type": event.event_type,
                "event_name": event.event_type,
                "action": event.action,
                "outcome": event.outcome.value,
                "attributes": _json_value(event.attributes),
                "subjects": [
                    {
                        "resource_id": resource_ids[subject],
                        "kind": subject.kind,
                        "layer": subject.layer,
                        "label": _resource_label(subject),
                    }
                    for subject in event.subjects
                ],
                "resource_id": (
                    resource_ids[event.subjects[0]] if event.subjects else None
                ),
                "layer": (event.subjects[0].layer if event.subjects else None),
                "provenance": event.provenance.value,
                "quality": event.quality.value,
                "evidence": _evidence(event.evidence),
            }
        )

    normalized_source_records: list[dict[str, Any]] = []
    ordered_source_records = sorted(
        source_records,
        key=lambda item: (
            item.emission.timestamp_ns is None,
            item.emission.timestamp_ns or 0,
            item.input_ordinal,
            item.output_ordinal,
        ),
    )
    for parsed_record in ordered_source_records:
        parser_id = parsed_record.parser_id
        ordinal = parsed_record.output_ordinal
        emission = parsed_record.emission
        if emission.timestamp_ns is not None:
            add_observation_time_bounds(
                emission.timestamp_ns,
                emission.timestamp_uncertainty_ns,
            )
        matched = [value.hex() for value in emission.matched_event_uids]
        if emission.matched_event_uid is not None:
            matched.insert(0, emission.matched_event_uid.hex())
        matched = list(dict.fromkeys(matched))
        normalized_source_records.append(
            {
                "source_record_uid": _source_uid(
                    plugin_id=plugin_id,
                    node_id=node_id,
                    parser_id=parser_id,
                    input_ordinal=parsed_record.input_ordinal,
                    ordinal=ordinal,
                    emission=emission,
                ),
                "timestamp_ns": (
                    str(emission.timestamp_ns)
                    if emission.timestamp_ns is not None
                    else None
                ),
                "timestamp_uncertainty_ns": (
                    str(emission.timestamp_uncertainty_ns)
                    if emission.timestamp_uncertainty_ns is not None
                    else None
                ),
                "source_type": emission.source_type,
                "source_name": emission.source_name,
                "record_name": emission.record_name,
                "message": emission.message,
                "layer": emission.layer,
                "attributes": _json_value(emission.attributes),
                "matched_event_uid": matched[0] if matched else None,
                "matched_event_uids": matched,
                "evidence": [_evidence(item) for item in emission.evidence],
                "copy_text": emission.copy_text,
            }
        )
    ordered_collections = sorted(
        relationship_collections,
        key=lambda item: (
            item.observed_at_min_ns is None,
            item.observed_at_min_ns or 0,
            item.observed_at_max_ns is None,
            item.observed_at_max_ns or 0,
            resource_ids[item.owner],
            item.relation_type,
            item.direction.value,
            item.evidence.artifact_id.bytes,
            item.evidence.locator,
        ),
    )
    normalized_collections = [
        {
            "owner": resource_ids[item.owner],
            "direction": item.direction.value,
            "relation_type": item.relation_type,
            "observed_at_min_ns": (
                str(item.observed_at_min_ns)
                if item.observed_at_min_ns is not None
                else None
            ),
            "observed_at_max_ns": (
                str(item.observed_at_max_ns)
                if item.observed_at_max_ns is not None
                else None
            ),
            "complete": item.complete,
            "provenance": item.provenance.value,
            "quality": item.quality.value,
            "evidence": [_evidence(item.evidence)],
            "perspective_ref": (
                _json_value(item.perspective_ref)
                if item.perspective_ref is not None
                else None
            ),
        }
        for item in ordered_collections
    ]
    for item in ordered_collections:
        if item.observed_at_min_ns is not None:
            time_values.append(item.observed_at_min_ns)
        if item.observed_at_max_ns is not None:
            time_values.append(item.observed_at_max_ns)

    schema_fields = _schema_dataset(schema)
    layer_names = sorted({resource.layer for resource in resources_by_key})
    timeline_start = min(time_values) if time_values else 0
    timeline_end = max(time_values) if time_values else timeline_start
    if timeline_time_basis is TimelineTimeBasis.ABSOLUTE_UNIX_NS and timeline_start < 0:
        raise IngestionError(
            "absolute-unix plug-in timelines cannot contain negative timestamps"
        )
    if (
        timeline_time_basis is TimelineTimeBasis.REVISION_START_RELATIVE_NS
        and timeline_end - timeline_start > MAX_TIMESTAMP_NS
    ):
        raise IngestionError(
            "revision-relative timeline span exceeds signed 64-bit nanoseconds"
        )
    matched_event_uids = {
        event_uid
        for record in normalized_source_records
        for event_uid in record["matched_event_uids"]
    }
    normalized_diagnostics = [_json_value(item) for item in diagnostics]
    runtime_gaps = [
        {
            "id": "runtime-v2-temporal-query",
            "area": "Temporal reconstruction",
            "status": "unavailable",
            "title": "Temporal state query provider unavailable",
            "detail": (
                "Embedded normalized history is available, but this "
                "runtime does not expose an executable temporal state "
                "query provider."
            ),
        },
        {
            "id": "runtime-v2-topology",
            "area": "Topology",
            "status": "unavailable",
            "title": "Topology projection unavailable",
            "detail": (
                "The selected plug-in/runtime does not expose a topology "
                "projection provider."
            ),
        },
        {
            "id": "runtime-v2-route",
            "area": "Route trace",
            "status": "unavailable",
            "title": "Route resolution unavailable",
            "detail": (
                "The selected plug-in/runtime does not expose a forwarding "
                "or route-resolution provider."
            ),
        },
        {
            "id": "runtime-v2-worker-isolation",
            "area": "Runtime isolation",
            "status": "unavailable",
            "title": "Parser worker isolation unavailable",
            "detail": (
                "Parser calls are quota-bounded but currently execute "
                "in-process without a killable worker or execution timeout."
            ),
        },
    ]
    if normalized_collections:
        runtime_gaps.append(
            {
                "id": "runtime-v2-relationship-collection-materialization",
                "area": "Relationship materialization",
                "status": "unavailable",
                "title": "Relationship collection inference unavailable",
                "detail": (
                    "Collection completeness markers are retained, but "
                    "runtime-v2 does not yet infer absent edges from them."
                ),
            }
        )
    return {
        **schema_fields,
        "_ingestion": {
            "revision_id": revision_id,
            "node": node_id,
            "node_id": node_id,
            "node_label": node_id,
            "name": f"{node_id} parsed dump",
            "event_count": len(normalized_events),
            "matched_event_count": len(matched_event_uids),
            "resource_count": len(resources),
            "source_record_count": len(normalized_source_records),
            "timeline_start_ns": str(timeline_start),
            "timeline_end_ns": str(timeline_end),
            "timeline_time_basis": timeline_time_basis.value,
            "timeline_clock_domain": timeline_clock_domain,
            "capture_ns": str(timeline_end),
            "history_mode": "embedded-history",
            "historical_state_mode": "embedded",
            "temporal_state_query": False,
            "topology_query": False,
            "route_query": False,
            "relationship_collection_materialization": False,
            "worker_isolation": False,
            "execution_timeout": False,
            "workspace_kind": "node",
            "scope": "node",
        },
        "resources": resources,
        "state_intervals": state_intervals,
        "lifecycle_intervals": lifecycle_intervals,
        "relationships": relationships,
        "relationship_intervals": relationship_intervals,
        "_relationship_collection_observations": normalized_collections,
        "relationship_mutations": [],
        "events": normalized_events,
        "source_records": normalized_source_records,
        "causal_links": [],
        "findings": [],
        "gaps": runtime_gaps,
        "diagnostics": normalized_diagnostics,
        "review_prompts": [],
        "layers": [
            {
                "layer": name,
                "label": name,
            }
            for name in layer_names
        ],
        "presentation": {
            "layers": [
                {
                    "layer": name,
                    "label": name,
                }
                for name in layer_names
            ]
        },
        "inventory": {
            "mode": "core-ingestion-v2",
            "archive": f"{node_id} core-owned input",
            "compressed_size": sum(
                item.compressed_size
                if item.compressed_size is not None
                else item.uncompressed_size or 0
                for item in inventory.artifacts
            ),
            "artifacts": len(inventory.artifacts),
            "members": [
                {
                    "artifact_id": str(item.artifact_id),
                    "path": item.logical_path.as_posix(),
                    "logical_path": item.logical_path.as_posix(),
                    "kind": "file",
                    "size": (
                        item.uncompressed_size
                        if item.uncompressed_size is not None
                        else item.compressed_size or 0
                    ),
                    "media_type": item.media_type,
                    "compressed_size": item.compressed_size,
                    "uncompressed_size": item.uncompressed_size,
                }
                for item in inventory.artifacts
            ],
        },
        "summary": {
            "parse": {
                "artifacts": len(inventory.artifacts),
                "errors": sum(item.severity.value == "error" for item in diagnostics),
                "diagnostics": len(diagnostics),
                "matched_events": len(matched_event_uids),
            },
            "consistency": {"pass": 0, "fail": 0, "unknown": 0},
        },
        "coverage": {
            "exact_outputs": sum(item.quality.value == "exact" for item in snapshots),
            "best_effort_outputs": sum(
                item.quality.value == "best_effort" for item in snapshots
            ),
            "unknown_outputs": sum(
                item.quality.value == "unknown" for item in snapshots
            ),
        },
        "topology_capabilities": {
            "available": False,
            "reason": "no topology projection provider is installed",
        },
        "runtime_capabilities": {
            "historical_state": True,
            "historical_state_mode": "embedded",
            "temporal_state_query": False,
            "topology_query": False,
            "route_query": False,
            "relationship_collection_materialization": False,
            "worker_isolation": False,
            "execution_timeout": False,
        },
        "topology_nodes": [],
    }


def _snapshot_publication_inventory(
    value: DumpInventory,
    *,
    node_id: str,
    limits: ArtifactLimits,
) -> DumpInventory:
    """Detach and validate the inventory retained by a coordinator result."""

    if type(value) is not DumpInventory:
        raise IngestionError("inventory must be an exact DumpInventory")
    captured_node_hint = value.node_hint
    captured_artifacts = value.artifacts
    captured_metadata = value.metadata
    if captured_node_hint is not None:
        try:
            node_hint = validate_execution_identity(captured_node_hint, "inventory node")
        except (TypeError, ValueError) as error:
            raise IngestionError(
                "inventory node must be an opaque execution identity"
            ) from error
        if node_hint != node_id:
            raise IngestionError("inventory node does not match the selected node")
    else:
        node_hint = None
    if type(captured_artifacts) is not tuple:
        raise IngestionError("inventory artifacts must be an exact tuple")
    if len(captured_artifacts) > limits.max_artifacts:
        raise IngestionError("inventory artifacts exceed the configured limit")

    artifacts: list[ArtifactInfo] = []
    artifact_ids: set[UUID] = set()
    logical_paths: set[PurePosixPath] = set()
    portable_paths: set[tuple[str, ...]] = set()
    total_uncompressed = 0
    for index, raw_artifact in enumerate(captured_artifacts):
        if type(raw_artifact) is not ArtifactInfo:
            raise IngestionError(
                f"inventory.artifacts[{index}] must be an exact ArtifactInfo"
            )
        artifact = _snapshot_parser_output_value(raw_artifact)
        assert type(artifact) is ArtifactInfo
        if type(artifact.artifact_id) is not UUID:
            raise IngestionError("inventory artifact identifier must be a UUID")
        if artifact.artifact_id in artifact_ids:
            raise IngestionError("inventory artifact identifiers must be unique")
        artifact_ids.add(artifact.artifact_id)
        if type(artifact.logical_path) is not PurePosixPath:
            raise IngestionError("inventory artifact path must be a POSIX path")
        try:
            normalized_path = normalize_artifact_path(
                artifact.logical_path.as_posix()
            )
        except ArtifactBoundaryError as error:
            raise IngestionError("inventory artifact path is invalid") from error
        if normalized_path != artifact.logical_path:
            raise IngestionError("inventory artifact path is not canonical")
        if len(normalized_path.parts) > limits.max_path_depth:
            raise IngestionError("inventory artifact path exceeds the depth limit")
        if normalized_path in logical_paths:
            raise IngestionError("inventory artifact paths must be unique")
        logical_paths.add(normalized_path)
        portable_path = tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in normalized_path.parts
        )
        if portable_path in portable_paths:
            raise IngestionError(
                "inventory artifact paths must be unique on portable filesystems"
            )
        portable_paths.add(portable_path)
        if artifact.parent_artifact_id is not None and type(
            artifact.parent_artifact_id
        ) is not UUID:
            raise IngestionError("inventory parent artifact identifier is invalid")
        _bounded_text(
            artifact.media_type,
            "inventory artifact media_type",
            maximum=256,
        )
        for field_name in ("compressed_size", "uncompressed_size"):
            size = getattr(artifact, field_name)
            if size is not None and (type(size) is not int or size < 0):
                raise IngestionError(
                    f"inventory artifact {field_name} must be non-negative or null"
                )
        if (
            artifact.compressed_size is not None
            and artifact.compressed_size > limits.max_total_uncompressed_bytes
        ):
            raise IngestionError(
                "inventory compressed size exceeds the configured byte domain"
            )
        if (
            artifact.uncompressed_size is not None
            and artifact.uncompressed_size > limits.max_artifact_bytes
        ):
            raise IngestionError("inventory artifact exceeds the configured byte limit")
        total_uncompressed += artifact.uncompressed_size or 0
        if (
            artifact.compressed_size is not None
            and artifact.uncompressed_size is not None
            and artifact.uncompressed_size
            > max(1, artifact.compressed_size) * limits.max_compression_ratio
        ):
            raise IngestionError(
                "inventory artifact exceeds the configured compression ratio"
            )
        digest = artifact.sha256
        if digest is not None and (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise IngestionError("inventory artifact sha256 is invalid")
        artifacts.append(artifact)
    if total_uncompressed > limits.max_total_uncompressed_bytes:
        raise IngestionError("inventory exceeds the configured total byte limit")
    for artifact in artifacts:
        if (
            artifact.parent_artifact_id is not None
            and artifact.parent_artifact_id not in artifact_ids
        ):
            raise IngestionError("inventory parent artifact is not in the inventory")

    parents = {
        artifact.artifact_id: artifact.parent_artifact_id for artifact in artifacts
    }
    visit_state: dict[UUID, int] = {}
    for artifact_id in parents:
        if visit_state.get(artifact_id) == 2:
            continue
        trail: list[UUID] = []
        current: UUID | None = artifact_id
        while current is not None and visit_state.get(current, 0) == 0:
            visit_state[current] = 1
            trail.append(current)
            current = parents.get(current)
        if current is not None and visit_state.get(current) == 1:
            raise IngestionError("inventory parent artifacts contain a cycle")
        for visited in trail:
            visit_state[visited] = 2

    detached_metadata = _snapshot_parser_output_value(captured_metadata)
    if not isinstance(detached_metadata, Mapping):
        raise IngestionError("inventory metadata must be a mapping")
    _json_value(detached_metadata)
    return DumpInventory(
        node_hint=node_hint,
        artifacts=tuple(artifacts),
        metadata=detached_metadata,
    )


def _require_exact_dataset_projection(
    supplied: Any,
    expected: Any,
    *,
    label: str = "dataset",
) -> None:
    """Compare only the bounded expected graph; never traverse supplied extras."""

    expected_type = type(expected)
    if type(supplied) is not expected_type:
        raise IngestionError(
            "ingestion coordinator dataset is not bound to its typed result"
        )
    if expected_type is dict:
        if len(supplied) != len(expected):
            raise IngestionError(
                "ingestion coordinator dataset is not bound to its typed result"
            )
        for key, nested_expected in expected.items():
            if key not in supplied:
                raise IngestionError(
                    "ingestion coordinator dataset is not bound to its typed result"
                )
            _require_exact_dataset_projection(
                supplied[key],
                nested_expected,
                label=f"{label}.{key}",
            )
        return
    if expected_type is list:
        if len(supplied) != len(expected):
            raise IngestionError(
                "ingestion coordinator dataset is not bound to its typed result"
            )
        for index, nested_expected in enumerate(expected):
            _require_exact_dataset_projection(
                supplied[index],
                nested_expected,
                label=f"{label}[{index}]",
            )
        return
    if expected_type is float:
        matches = supplied == expected and (
            supplied != 0.0 or copysign(1.0, supplied) == copysign(1.0, expected)
        )
    else:
        matches = supplied == expected
    if not matches:
        raise IngestionError(
            "ingestion coordinator dataset is not bound to its typed result"
        )


def snapshot_ingestion_result_for_publication(
    value: object,
    *,
    limits: IngestionLimits,
    plugin_id: str,
    timeline_time_basis: TimelineTimeBasis,
    timeline_clock_domain: str | None,
    expected_node_id: str | None,
) -> IngestionResult:
    """Detach, revalidate, and canonically rebuild a coordinator handoff.

    A deployment may supply a custom coordinator, and even an exact stock
    coordinator instance is mutable Python state.  Therefore publication never
    trusts either the coordinator's class or its convenient JSON projection.
    The typed result is admitted again under the same semantic and aggregate
    parser budgets, and the supplied dataset must equal the closed projection
    rebuilt from those detached values.
    """

    if type(limits) is not IngestionLimits:
        raise TypeError("limits must be an exact IngestionLimits")
    _bounded_text(plugin_id, "plugin_id", maximum=256)
    if type(timeline_time_basis) is not TimelineTimeBasis:
        raise TypeError("timeline_time_basis must be an exact TimelineTimeBasis")
    if timeline_clock_domain is not None:
        _bounded_text(
            timeline_clock_domain,
            "timeline_clock_domain",
            maximum=256,
        )
    if type(value) is not IngestionResult:
        raise IngestionError(
            "ingestion coordinator must return an exact IngestionResult"
        )
    # Capture every coordinator-owned top-level reference once. Frozen
    # dataclasses can still be mutated with low-level operations from another
    # thread, so rereading fields after admission would create a TOCTOU split.
    captured_inventory = value.inventory
    captured_schema = value.schema
    captured_revision_id = value.revision_id
    captured_node_id = value.node_id
    captured_dataset = value.dataset
    captured_diagnostics = value.diagnostics
    captured_snapshots = value.snapshots
    captured_relationship_observations = value.relationship_observations
    captured_relationship_collections = value.relationship_collections
    captured_events = value.events
    captured_source_records = value.source_records
    captured_source_record_origins = value.source_record_origins

    if type(captured_inventory) is not DumpInventory:
        raise IngestionError("inventory must be an exact DumpInventory")
    if type(captured_schema) is not PluginSchema:
        raise IngestionError("schema must be an exact PluginSchema")
    if type(captured_dataset) is not dict:
        raise IngestionError("dataset must be an exact dictionary")
    try:
        revision_id = validate_execution_identity(
            captured_revision_id,
            "revision_id",
        )
        node_id = validate_execution_identity(captured_node_id, "node_id")
    except (TypeError, ValueError) as error:
        raise IngestionError(
            "coordinator result identity is invalid"
        ) from error
    tuple_groups: tuple[tuple[str, object, int], ...] = (
        ("diagnostics", captured_diagnostics, limits.max_diagnostics),
        ("snapshots", captured_snapshots, limits.max_parsed_outputs),
        (
            "relationship_observations",
            captured_relationship_observations,
            limits.max_parsed_outputs,
        ),
        (
            "relationship_collections",
            captured_relationship_collections,
            limits.max_parsed_outputs,
        ),
        ("events", captured_events, limits.max_parsed_outputs),
        ("source_records", captured_source_records, limits.max_parsed_outputs),
        (
            "source_record_origins",
            captured_source_record_origins,
            limits.max_parsed_outputs,
        ),
    )
    for label, items, maximum in tuple_groups:
        if type(items) is not tuple:
            raise IngestionError(f"{label} must be an exact tuple")
        if len(items) > maximum:
            raise IngestionError(f"{label} exceed the configured limit")
    output_count = sum(
        len(items)
        for label, items, _maximum in tuple_groups
        if label
        in {
            "snapshots",
            "relationship_observations",
            "relationship_collections",
            "events",
            "source_records",
        }
    )
    if output_count > limits.max_parsed_outputs:
        raise IngestionError("coordinator result exceeds the parsed output limit")
    if output_count + len(captured_diagnostics) > limits.max_total_outputs:
        raise IngestionError("coordinator result exceeds the aggregate output limit")
    if len(captured_source_record_origins) != len(captured_source_records):
        raise IngestionError(
            "source_record_origins must align one-for-one with source_records"
        )
    if expected_node_id is not None:
        try:
            expected_node = validate_execution_identity(
                expected_node_id,
                "expected_node_id",
            )
        except (TypeError, ValueError) as error:
            raise IngestionError("expected_node_id is invalid") from error
        if node_id != expected_node:
            raise IngestionError(
                "coordinator result node does not match the requested node_hint"
            )

    inventory = _snapshot_publication_inventory(
        captured_inventory,
        node_id=node_id,
        limits=limits.artifact_limits,
    )
    schema = _snapshot_parser_output_value(captured_schema)
    if type(schema) is not PluginSchema:
        raise IngestionError("schema must be an exact PluginSchema")
    schema_index = _SchemaIndex.build(schema)
    artifact_ids = {artifact.artifact_id for artifact in inventory.artifacts}
    budget = _IngestionBudget(limits)
    budget.consume(schema, label="schema", output=False)

    diagnostics: list[PluginDiagnostic] = []
    allowed_diagnostic_pairs = frozenset(
        {
            (DiagnosticOrigin.PLUGIN, DiagnosticStage.PROBE),
            (DiagnosticOrigin.PLUGIN, DiagnosticStage.LOCATE),
            (DiagnosticOrigin.PLUGIN, DiagnosticStage.STATUS_PARSE),
            (DiagnosticOrigin.PLUGIN, DiagnosticStage.TRACE_MAP),
            (DiagnosticOrigin.CORE_DECODER, DiagnosticStage.TRACE_DECODE),
        }
    )
    decoder_diagnostic_count = 0
    for index, item in enumerate(captured_diagnostics):
        if type(item) is not PluginDiagnostic:
            raise IngestionError(
                f"diagnostics[{index}] must be an exact PluginDiagnostic"
            )
        detached = _snapshot_parser_output_value(item)
        _validate_diagnostic(
            detached,
            artifact_ids=artifact_ids,
            label=f"diagnostics[{index}]",
        )
        if (
            (detached.origin, detached.stage) not in allowed_diagnostic_pairs
            or not detached.recoverable
        ):
            raise IngestionError(
                "coordinator result contains an impossible ingestion diagnostic"
            )
        if detached.origin is DiagnosticOrigin.CORE_DECODER:
            decoder_diagnostic_count += 1
        budget.consume(detached, label=f"diagnostics[{index}]")
        diagnostics.append(detached)
    if decoder_diagnostic_count > limits.max_decoder_outputs:
        raise IngestionError("coordinator result exceeds the decoder output limit")

    output_groups: tuple[
        tuple[str, tuple[Any, ...], type[Any]],
        ...,
    ] = (
        ("snapshots", captured_snapshots, SnapshotObservation),
        (
            "relationship_observations",
            captured_relationship_observations,
            RelationshipObservation,
        ),
        (
            "relationship_collections",
            captured_relationship_collections,
            RelationshipCollectionObservation,
        ),
        ("events", captured_events, DomainEvent),
        ("source_records", captured_source_records, SourceRecordEmission),
    )
    parser_diagnostic_count = sum(
        diagnostic.stage
        in {DiagnosticStage.STATUS_PARSE, DiagnosticStage.TRACE_MAP}
        for diagnostic in diagnostics
    )
    if output_count + parser_diagnostic_count > limits.max_parsed_outputs:
        raise IngestionError("coordinator result exceeds the parsed output limit")
    if output_count + len(diagnostics) > limits.max_total_outputs:
        raise IngestionError("coordinator result exceeds the aggregate output limit")

    detached_groups: dict[str, tuple[Any, ...]] = {}
    for group_name, items, expected_type in output_groups:
        detached_items: list[Any] = []
        for index, item in enumerate(items):
            if type(item) is not expected_type:
                raise IngestionError(
                    f"{group_name}[{index}] must be an exact "
                    f"{expected_type.__name__}"
                )
            detached = _snapshot_parser_output_value(item)
            _validate_parser_output(
                detached,
                schema_index=schema_index,
                artifact_ids=artifact_ids,
                expected_node=node_id,
                expected_diagnostic_stage=DiagnosticStage.STATUS_PARSE,
                label=f"{group_name}[{index}]",
            )
            budget.consume(detached, label=f"{group_name}[{index}]")
            detached_items.append(detached)
        detached_groups[group_name] = tuple(detached_items)

    detached_origins: list[SourceRecordOrigin] = []
    for index, origin in enumerate(captured_source_record_origins):
        if type(origin) is not SourceRecordOrigin:
            raise IngestionError(
                f"source_record_origins[{index}] must be an exact SourceRecordOrigin"
            )
        detached_origins.append(
            SourceRecordOrigin(
                parser_id=origin.parser_id,
                input_ordinal=origin.input_ordinal,
                output_ordinal=origin.output_ordinal,
            )
        )
    origins = tuple(detached_origins)
    for index, origin in enumerate(origins):
        if origin.input_ordinal >= limits.max_located_inputs:
            raise IngestionError(
                "source record input ordinal exceeds the located-input limit"
            )
        if origin.output_ordinal >= limits.max_parsed_outputs:
            raise IngestionError(
                "source record output ordinal exceeds the parsed-output limit"
            )
        budget.consume(
            {
                "parser_id": origin.parser_id,
                "input_ordinal": origin.input_ordinal,
                "output_ordinal": origin.output_ordinal,
            },
            label=f"source_record_origins[{index}]",
            output=False,
        )
    coordinates = tuple(
        (origin.parser_id, origin.input_ordinal, origin.output_ordinal)
        for origin in origins
    )
    if len(coordinates) != len(set(coordinates)):
        raise IngestionError("source record parser coordinates must be unique")

    events = tuple(detached_groups["events"])
    event_uids = tuple(event.event_uid for event in events)
    if len(event_uids) != len(set(event_uids)):
        raise IngestionError("coordinator result contains duplicate event identifiers")
    known_event_uids = set(event_uids)
    source_emissions = tuple(detached_groups["source_records"])
    for emission in source_emissions:
        linked = {
            *(
                (emission.matched_event_uid,)
                if emission.matched_event_uid is not None
                else ()
            ),
            *emission.matched_event_uids,
        }
        if linked - known_event_uids:
            raise IngestionError(
                "coordinator source record references an unknown event identifier"
            )
    parsed_source_records = tuple(
        _ParsedSourceRecord(
            parser_id=origin.parser_id,
            input_ordinal=origin.input_ordinal,
            output_ordinal=origin.output_ordinal,
            emission=emission,
        )
        for origin, emission in zip(origins, source_emissions, strict=True)
    )

    rebuilt_dataset = _build_dataset(
        plugin_id=plugin_id,
        inventory=inventory,
        schema=schema,
        revision_id=revision_id,
        node_id=node_id,
        snapshots=detached_groups["snapshots"],
        relationship_observations=detached_groups["relationship_observations"],
        relationship_collections=detached_groups["relationship_collections"],
        events=events,
        source_records=parsed_source_records,
        diagnostics=tuple(diagnostics),
        timeline_time_basis=timeline_time_basis,
        timeline_clock_domain=timeline_clock_domain,
    )
    _require_exact_dataset_projection(captured_dataset, rebuilt_dataset)
    return IngestionResult(
        inventory=inventory,
        schema=schema,
        revision_id=revision_id,
        node_id=node_id,
        dataset=rebuilt_dataset,
        diagnostics=tuple(diagnostics),
        snapshots=tuple(detached_groups["snapshots"]),
        relationship_observations=tuple(
            detached_groups["relationship_observations"]
        ),
        relationship_collections=tuple(
            detached_groups["relationship_collections"]
        ),
        events=events,
        source_records=source_emissions,
        source_record_origins=origins,
    )


def _fingerprint(
    reader: CoreArtifactReader,
    manifest: _IngestionManifestSnapshot,
    schema: PluginSchema,
    specs: Sequence[InputSpec],
) -> str:
    def add(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    digest = sha256()
    digest.update(b"router-dump-ingestion-revision:v2")
    add(
        canonical_json(
            {
                "plugin_id": manifest.plugin_id,
                "plugin_version": manifest.plugin_version,
                "core_api_version": manifest.core_api_version,
                "supported_platforms": list(manifest.supported_platforms),
                "supported_software_versions": (manifest.supported_software_versions),
                "capabilities": sorted(
                    str(capability.value)
                    if isinstance(capability, PluginCapability)
                    else str(capability)
                    for capability in manifest.capabilities
                ),
                "reconstruction_default": (manifest.reconstruction_default.value),
                "forwarding_ir_versions": list(manifest.forwarding_ir_versions),
                "timeline_time_basis": manifest.timeline_time_basis.value,
                "timeline_clock_domain": manifest.timeline_clock_domain,
            }
        ).encode("utf-8")
    )
    add(canonical_json(_json_value(schema)).encode("utf-8"))
    add(canonical_json(_json_value(reader.inventory.node_hint)).encode("utf-8"))
    add(canonical_json(_json_value(reader.inventory.metadata)).encode("utf-8"))
    logical_path_by_id = {
        artifact.artifact_id: artifact.logical_path.as_posix()
        for artifact in reader.inventory.artifacts
    }
    parent_path_by_id = {
        artifact.artifact_id: (
            logical_path_by_id.get(artifact.parent_artifact_id)
            if artifact.parent_artifact_id is not None
            else None
        )
        for artifact in reader.inventory.artifacts
    }
    for artifact in reader.inventory.artifacts:
        add(
            canonical_json(
                {
                    "logical_path": artifact.logical_path.as_posix(),
                    "parent_logical_path": parent_path_by_id[artifact.artifact_id],
                    "media_type": artifact.media_type,
                    "compressed_size": artifact.compressed_size,
                    "uncompressed_size": artifact.uncompressed_size,
                    "sha256": artifact.sha256,
                }
            ).encode("utf-8")
        )
        with reader.open_binary(artifact.artifact_id) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    add(
        canonical_json(
            [
                {
                    "artifact_paths": [
                        logical_path_by_id[artifact_id]
                        for artifact_id in spec.artifact_ids
                    ],
                    "role": spec.role,
                    "node": spec.node,
                    "layer": spec.layer,
                    "parser_id": spec.parser_id,
                    "logical_root": (
                        spec.logical_root.as_posix()
                        if spec.logical_root is not None
                        else None
                    ),
                    "options": _json_value(spec.options),
                    "parser_kind": (
                        spec.parser_kind.value if spec.parser_kind is not None else None
                    ),
                }
                for spec in specs
            ]
        ).encode("utf-8")
    )
    return digest.hexdigest()


class IngestionCoordinator:
    """Discover, dispatch, validate, and normalize one plug-in input."""

    def __init__(
        self,
        *,
        trace_decoder: TraceDecoder | None = None,
        limits: IngestionLimits | None = None,
    ) -> None:
        self.trace_decoder: TraceDecoder | None = trace_decoder
        self.limits: IngestionLimits = limits or IngestionLimits()

    @staticmethod
    def _plugin(plugin: Any) -> AnalyzerPlugin:
        try:
            snapshot = _IngestionPluginSnapshot.resolve(plugin)
        except IngestionError as error:
            # ``PluginRegistry.register`` owns the surrounding registration
            # boundary and its established public error classification. Keep
            # this private compatibility validator transparent to a hostile
            # non-Exception failure so that outer boundary remains effective.
            cause = error.__cause__
            if (
                cause is not None
                and not isinstance(cause, Exception)
                and not isinstance(cause, PROCESS_CONTROL_EXCEPTIONS)
            ):
                raise cause
            raise
        return cast(AnalyzerPlugin, snapshot.original)

    @staticmethod
    def _snapshot_plugin(plugin: Any) -> _IngestionPluginSnapshot:
        if isinstance(plugin, _IngestionPluginSnapshot):
            return plugin
        return _IngestionPluginSnapshot.resolve(plugin)

    def _schema(
        self,
        plugin: _IngestionPluginSnapshot,
        budget: _IngestionBudget,
    ) -> tuple[PluginSchema, _SchemaIndex]:
        def process() -> tuple[PluginSchema, _SchemaIndex]:
            output = plugin.describe()
            if type(output) is not PluginSchema:
                raise IngestionError("describe() must return an exact PluginSchema")
            schema = _snapshot_parser_output_value(output)
            if type(schema) is not PluginSchema:
                raise IngestionError("describe() must return an exact PluginSchema")
            budget.consume(schema, label="describe", output=False)
            return schema, _SchemaIndex.build(schema)

        return _plugin_execution_boundary(
            "describe() output processing",
            process,
        )

    def _probe(
        self,
        plugin: _IngestionPluginSnapshot,
        inventory: DumpInventory,
        budget: _IngestionBudget,
    ) -> tuple[PluginDiagnostic, ...]:
        def process() -> tuple[PluginDiagnostic, ...]:
            raw_report = plugin.probe(inventory)
            inventory_artifact_ids = {item.artifact_id for item in inventory.artifacts}
            try:
                report = validate_probe_report(
                    raw_report,
                    artifact_ids=inventory_artifact_ids,
                    maximum_diagnostics=self.limits.max_diagnostics,
                    maximum_evidence_items=(self.limits.max_evidence_per_output),
                )
            except ValueError as error:
                raise IngestionError(f"probe report is invalid: {error}") from error
            detached_report = _snapshot_parser_output_value(report)
            if type(detached_report) is not ProbeReport:
                raise IngestionError("probe() must return an exact ProbeReport")
            try:
                report = validate_probe_report(
                    detached_report,
                    artifact_ids=inventory_artifact_ids,
                    maximum_diagnostics=self.limits.max_diagnostics,
                    maximum_evidence_items=(self.limits.max_evidence_per_output),
                )
            except ValueError as error:
                raise IngestionError(f"probe report is invalid: {error}") from error
            probe_diagnostics = tuple(report.diagnostics)
            for index, diagnostic in enumerate(probe_diagnostics):
                budget.consume(
                    diagnostic,
                    label=f"probe.diagnostics[{index}]",
                )
                if not diagnostic.recoverable:
                    raise IngestionError(
                        f"probe() failed: {diagnostic.code}: {diagnostic.message}"
                    )
            if report.result is not None:
                try:
                    probe_result = validate_probe_result(report.result)
                except ValueError as error:
                    raise IngestionError(f"probe result is invalid: {error}") from error
                budget.consume(
                    probe_result,
                    label="probe.result",
                    output=False,
                )
                match_kind = ProbeMatchKind(probe_result.match_kind)
                _json_value(probe_result)
            else:
                match_kind = ProbeMatchKind.NONE
            if report.result is None or match_kind is ProbeMatchKind.NONE:
                raise IngestionError(
                    "plug-in probe did not match the inventoried input"
                )
            return probe_diagnostics

        return _plugin_execution_boundary(
            "probe() output processing",
            process,
        )

    def _located(
        self,
        plugin: _IngestionPluginSnapshot,
        inventory: DumpInventory,
        budget: _IngestionBudget,
    ) -> tuple[tuple[InputSpec, ...], tuple[PluginDiagnostic, ...]]:
        return _plugin_execution_boundary(
            "locate_inputs() output processing",
            lambda: self._located_outputs(plugin, inventory, budget),
        )

    def _located_outputs(
        self,
        plugin: _IngestionPluginSnapshot,
        inventory: DumpInventory,
        budget: _IngestionBudget,
    ) -> tuple[tuple[InputSpec, ...], tuple[PluginDiagnostic, ...]]:
        specs: list[InputSpec] = []
        diagnostics: list[PluginDiagnostic] = []
        artifact_ids = {item.artifact_id for item in inventory.artifacts}
        artifacts_by_id = {
            artifact.artifact_id: artifact for artifact in inventory.artifacts
        }
        iterator = plugin.locate_inputs(inventory)
        try:
            for index, output in enumerate(iterator):
                if index >= self.limits.max_located_inputs:
                    raise IngestionError(
                        "locate_inputs() exceeded the configured output limit"
                    )
                if type(output) not in (PluginDiagnostic, InputSpec):
                    raise IngestionError(
                        "locate_inputs() outputs must be exact InputSpec or "
                        "PluginDiagnostic"
                    )
                output = _snapshot_parser_output_value(output)
                budget.consume(
                    output,
                    label=f"locate_inputs[{index}]",
                )
                if type(output) is PluginDiagnostic:
                    _validate_diagnostic(
                        output,
                        artifact_ids=artifact_ids,
                        label=f"locate_inputs[{index}]",
                        expected_origin=DiagnosticOrigin.PLUGIN,
                        expected_stage=DiagnosticStage.LOCATE,
                    )
                    diagnostics.append(output)
                    if not output.recoverable:
                        raise IngestionError(
                            f"locate_inputs() failed: {output.code}: {output.message}"
                        )
                    continue
                assert type(output) is InputSpec
                if output.parser_kind is None:
                    raise IngestionError(
                        "core ingestion requires InputSpec.parser_kind"
                    )
                _bounded_text(
                    output.role,
                    f"locate_inputs[{index}].role",
                    maximum=256,
                )
                _bounded_text(
                    output.node,
                    f"locate_inputs[{index}].node",
                    maximum=256,
                )
                _bounded_text(
                    output.layer,
                    f"locate_inputs[{index}].layer",
                    maximum=256,
                )
                _bounded_text(
                    output.parser_id,
                    f"locate_inputs[{index}].parser_id",
                    maximum=256,
                )
                _json_value(output.options)
                if not isinstance(output.artifact_ids, tuple) or any(
                    not isinstance(artifact_id, UUID)
                    for artifact_id in output.artifact_ids
                ):
                    raise IngestionError(
                        "InputSpec.artifact_ids must be a tuple of UUIDs"
                    )
                if not output.artifact_ids:
                    raise IngestionError("InputSpec requires at least one artifact")
                if len(output.artifact_ids) != len(set(output.artifact_ids)):
                    raise IngestionError("InputSpec repeats an artifact identifier")
                if unknown := set(output.artifact_ids) - artifact_ids:
                    raise IngestionError(
                        f"InputSpec references {len(unknown)} unknown artifact(s)"
                    )
                if output.logical_root is not None:
                    if not isinstance(
                        output.logical_root,
                        PurePosixPath,
                    ):
                        raise IngestionError(
                            "InputSpec.logical_root must be a PurePosixPath"
                        )
                    logical_root = normalize_artifact_path(
                        output.logical_root.as_posix()
                    )
                    for artifact_id in output.artifact_ids:
                        logical_path = artifacts_by_id[artifact_id].logical_path
                        try:
                            logical_path.relative_to(logical_root)
                        except ValueError as error:
                            raise IngestionError(
                                f"InputSpec artifact {logical_path} is "
                                f"outside logical root {logical_root}"
                            ) from error
                required_capability = output.required_capability
                assert required_capability is not None
                if not plugin.manifest.supports(required_capability):
                    raise IngestionError(
                        "InputSpec parser kind "
                        f"{output.parser_kind.value!r} requires undeclared "
                        f"capability {required_capability.value!r}"
                    )
                plugin.parser_hook(output.parser_kind)
                specs.append(output)
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        if not specs:
            raise IngestionError("locate_inputs() selected no parser inputs")
        return tuple(specs), tuple(diagnostics)

    def _parse(
        self,
        plugin: _IngestionPluginSnapshot,
        reader: CoreArtifactReader,
        specs: Sequence[InputSpec],
        *,
        schema_index: _SchemaIndex,
        budget: _IngestionBudget,
        initial_diagnostics: Sequence[PluginDiagnostic] = (),
    ) -> tuple[
        list[SnapshotObservation],
        list[RelationshipObservation],
        list[RelationshipCollectionObservation],
        list[DomainEvent],
        list[_ParsedSourceRecord],
        list[PluginDiagnostic],
    ]:
        return _plugin_execution_boundary(
            "parser output processing",
            lambda: self._parse_outputs(
                plugin,
                reader,
                specs,
                schema_index=schema_index,
                budget=budget,
                initial_diagnostics=initial_diagnostics,
            ),
        )

    def _parse_outputs(
        self,
        plugin: _IngestionPluginSnapshot,
        reader: CoreArtifactReader,
        specs: Sequence[InputSpec],
        *,
        schema_index: _SchemaIndex,
        budget: _IngestionBudget,
        initial_diagnostics: Sequence[PluginDiagnostic] = (),
    ) -> tuple[
        list[SnapshotObservation],
        list[RelationshipObservation],
        list[RelationshipCollectionObservation],
        list[DomainEvent],
        list[_ParsedSourceRecord],
        list[PluginDiagnostic],
    ]:
        snapshots: list[SnapshotObservation] = []
        relationships: list[RelationshipObservation] = []
        collections: list[RelationshipCollectionObservation] = []
        events: list[DomainEvent] = []
        source_records: list[_ParsedSourceRecord] = []
        diagnostics: list[PluginDiagnostic] = list(initial_diagnostics)
        output_count = 0

        def consume(
            spec: InputSpec,
            input_ordinal: int,
            outputs: Iterable[Any],
            allowed: tuple[type[Any], ...],
        ) -> None:
            nonlocal output_count
            iterator = iter(outputs)
            try:
                for ordinal, output in enumerate(iterator):
                    output_count += 1
                    if output_count % 1_024 == 0:
                        report_analysis_load(
                            AnalysisLoadStage.PARSING,
                            completed=input_ordinal,
                            total=len(specs),
                            records_processed=output_count,
                        )
                    if output_count > self.limits.max_parsed_outputs:
                        raise IngestionError(
                            "parser outputs exceeded the configured limit"
                        )
                    if not isinstance(output, allowed):
                        raise IngestionError(
                            f"{spec.dispatch_hook}() emitted unsupported "
                            f"{type(output).__name__}"
                        )
                    budget.consume(
                        output,
                        label=(f"{spec.dispatch_hook}[{input_ordinal}:{ordinal}]"),
                    )
                    _validate_parser_output(
                        output,
                        schema_index=schema_index,
                        artifact_ids=set(spec.artifact_ids),
                        expected_node=spec.node,
                        expected_diagnostic_stage=(
                            DiagnosticStage.STATUS_PARSE
                            if spec.parser_kind is InputParserKind.STATUS
                            else DiagnosticStage.TRACE_MAP
                        ),
                        label=(f"{spec.dispatch_hook}[{input_ordinal}:{ordinal}]"),
                    )
                    detached_output = _snapshot_parser_output_value(output)
                    _validate_parser_output(
                        detached_output,
                        schema_index=schema_index,
                        artifact_ids=set(spec.artifact_ids),
                        expected_node=spec.node,
                        expected_diagnostic_stage=(
                            DiagnosticStage.STATUS_PARSE
                            if spec.parser_kind is InputParserKind.STATUS
                            else DiagnosticStage.TRACE_MAP
                        ),
                        label=(f"{spec.dispatch_hook}[{input_ordinal}:{ordinal}]"),
                    )
                    if isinstance(detached_output, SnapshotObservation):
                        snapshots.append(detached_output)
                    elif isinstance(detached_output, RelationshipObservation):
                        relationships.append(detached_output)
                    elif isinstance(
                        detached_output,
                        RelationshipCollectionObservation,
                    ):
                        collections.append(detached_output)
                    elif isinstance(detached_output, DomainEvent):
                        events.append(detached_output)
                    elif isinstance(detached_output, SourceRecordEmission):
                        source_records.append(
                            _ParsedSourceRecord(
                                parser_id=spec.parser_id,
                                input_ordinal=input_ordinal,
                                output_ordinal=ordinal,
                                emission=detached_output,
                            )
                        )
                    else:
                        assert isinstance(detached_output, PluginDiagnostic)
                        diagnostics.append(detached_output)
                        if not detached_output.recoverable:
                            raise IngestionError(
                                f"{spec.dispatch_hook}() failed: "
                                f"{detached_output.code}: {detached_output.message}"
                            )
            finally:
                close = getattr(iterator, "close", None)
                if callable(close):
                    close()

        for input_ordinal, spec in enumerate(specs):
            scoped_reader = reader.scoped(spec.artifact_ids)
            if spec.parser_kind is InputParserKind.STATUS:
                consume(
                    spec,
                    input_ordinal,
                    plugin.parse(
                        InputParserKind.STATUS,
                        scoped_reader,
                        spec,
                    ),
                    (
                        SnapshotObservation,
                        RelationshipObservation,
                        RelationshipCollectionObservation,
                        SourceRecordEmission,
                        PluginDiagnostic,
                    ),
                )
            elif spec.parser_kind is InputParserKind.TEXT_TRACE:
                consume(
                    spec,
                    input_ordinal,
                    plugin.parse(
                        InputParserKind.TEXT_TRACE,
                        scoped_reader,
                        spec,
                    ),
                    (
                        DomainEvent,
                        SourceRecordEmission,
                        PluginDiagnostic,
                    ),
                )
            else:
                assert spec.parser_kind is InputParserKind.CTF
                if self.trace_decoder is None:
                    raise IngestionError("CTF input requires a core TraceDecoder")

                def decoded_messages(
                    input_spec: InputSpec,
                    decoder_input_ordinal: int = input_ordinal,
                    decoder_reader: Any = scoped_reader,
                ) -> Iterator[CtfMessage]:
                    assert self.trace_decoder is not None
                    decoder_iterator = iter(
                        self.trace_decoder.iter_ctf(
                            decoder_reader,
                            input_spec,
                        )
                    )
                    try:
                        for decoder_ordinal, message in enumerate(decoder_iterator):
                            label = (
                                f"trace_decoder[{decoder_input_ordinal}:"
                                f"{decoder_ordinal}]"
                            )
                            if type(message) is PluginDiagnostic:
                                budget.consume(
                                    message,
                                    label=label,
                                    decoder=True,
                                )
                                _validate_diagnostic(
                                    message,
                                    artifact_ids=set(input_spec.artifact_ids),
                                    label=label,
                                    expected_origin=(DiagnosticOrigin.CORE_DECODER),
                                    expected_stage=(DiagnosticStage.TRACE_DECODE),
                                )
                                diagnostics.append(message)
                                if not message.recoverable:
                                    raise IngestionError(
                                        "CTF decoder failed: "
                                        f"{message.code}: "
                                        f"{message.message}"
                                    )
                                continue
                            validated = _validate_ctf_message(
                                message,
                                artifact_ids=set(input_spec.artifact_ids),
                                label=label,
                            )
                            budget.consume(
                                validated,
                                label=label,
                                decoder=True,
                            )
                            yield validated
                    finally:
                        close = getattr(decoder_iterator, "close", None)
                        if callable(close):
                            close()

                consume(
                    spec,
                    input_ordinal,
                    plugin.parse(
                        InputParserKind.CTF,
                        spec,
                        decoded_messages(spec),
                    ),
                    (
                        DomainEvent,
                        SourceRecordEmission,
                        PluginDiagnostic,
                    ),
                )
            report_analysis_load(
                AnalysisLoadStage.PARSING,
                completed=input_ordinal + 1,
                total=len(specs),
                records_processed=output_count,
            )
        return (
            snapshots,
            relationships,
            collections,
            events,
            source_records,
            diagnostics,
        )

    def ingest(
        self,
        plugin: Any,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> IngestionResult:
        report_analysis_load(AnalysisLoadStage.STARTING)
        selected = self._snapshot_plugin(plugin)
        budget = _IngestionBudget(self.limits)
        schema, schema_index = self._schema(selected, budget)
        serialized_metadata = _json_value(metadata or {})
        assert isinstance(serialized_metadata, dict)
        safe_metadata = serialized_metadata
        report_analysis_load(
            AnalysisLoadStage.INVENTORYING,
            completed=0,
            total=1,
        )
        with CoreArtifactReader(
            input_path,
            node_hint=node_hint,
            metadata=safe_metadata,
            limits=self.limits.artifact_limits,
        ) as reader:
            report_analysis_load(
                AnalysisLoadStage.INVENTORYING,
                completed=1,
                total=1,
            )
            report_analysis_load(
                AnalysisLoadStage.PROBING,
                completed=0,
                total=1,
            )
            probe_diagnostics = self._probe(
                selected,
                reader.inventory,
                budget,
            )
            report_analysis_load(
                AnalysisLoadStage.PROBING,
                completed=1,
                total=1,
            )
            report_analysis_load(
                AnalysisLoadStage.LOCATING_INPUTS,
                completed=0,
                total=1,
            )
            specs, locate_diagnostics = self._located(
                selected,
                reader.inventory,
                budget,
            )
            report_analysis_load(
                AnalysisLoadStage.LOCATING_INPUTS,
                completed=1,
                total=1,
            )
            report_analysis_load(
                AnalysisLoadStage.PARSING,
                completed=0,
                total=len(specs),
                records_processed=0,
            )

            def selected_node() -> str:
                nodes = {spec.node for spec in specs}
                if node_hint is not None and nodes != {node_hint}:
                    raise IngestionError(
                        "all located inputs must match the requested node_hint"
                    )
                if len(nodes) != 1:
                    raise IngestionError(
                        "one core-ingestion revision must select exactly one node"
                    )
                node = next(iter(nodes))
                try:
                    return validate_execution_identity(node, "selected node")
                except (TypeError, ValueError) as error:
                    raise IngestionError(
                        "selected node must be an opaque execution identity"
                    ) from error

            node_id = _plugin_execution_boundary(
                "locate_inputs() result finalization",
                selected_node,
            )
            fingerprint = _plugin_execution_boundary(
                "ingestion fingerprint finalization",
                lambda: _fingerprint(
                    reader,
                    selected.manifest,
                    schema,
                    specs,
                ),
            )
            (
                snapshots,
                relationships,
                collections,
                events,
                source_records,
                diagnostics,
            ) = self._parse(
                selected,
                reader,
                specs,
                schema_index=schema_index,
                budget=budget,
                initial_diagnostics=(
                    *probe_diagnostics,
                    *locate_diagnostics,
                ),
            )

            def validate_event_links() -> None:
                event_uids = [event.event_uid for event in events]
                if len(event_uids) != len(set(event_uids)):
                    raise IngestionError(
                        "parser outputs contain duplicate event identifiers"
                    )
                known_event_uids = set(event_uids)
                for source_record in source_records:
                    emission = source_record.emission
                    linked = {
                        *(
                            (emission.matched_event_uid,)
                            if emission.matched_event_uid is not None
                            else ()
                        ),
                        *emission.matched_event_uids,
                    }
                    if unknown_links := linked - known_event_uids:
                        raise IngestionError(
                            "source record references "
                            f"{len(unknown_links)} unknown event identifier(s)"
                        )

            _plugin_execution_boundary(
                "parser result finalization",
                validate_event_links,
            )
            inventory = reader.inventory

        report_analysis_load(AnalysisLoadStage.NORMALIZING)

        def finalize_dataset() -> tuple[str, dict[str, Any]]:
            # Revision identity must fit the same closed executable-plan domain
            # for every legal node. Preserve the established node-prefixed ID
            # whenever it fits; use a visibly versioned, full-digest fallback
            # only at the long-node boundary rather than silently rekeying
            # existing revisions.
            legacy_revision_id = f"ingested/{node_id}/{fingerprint[:32]}"
            revision_id = (
                legacy_revision_id
                if len(legacy_revision_id) <= 256
                else f"ingested-v2/{fingerprint}"
            )
            return revision_id, _build_dataset(
                plugin_id=selected.manifest.plugin_id,
                inventory=inventory,
                schema=schema,
                revision_id=revision_id,
                node_id=node_id,
                snapshots=snapshots,
                relationship_observations=relationships,
                relationship_collections=collections,
                events=events,
                source_records=source_records,
                diagnostics=diagnostics,
                timeline_time_basis=selected.manifest.timeline_time_basis,
                timeline_clock_domain=selected.manifest.timeline_clock_domain,
            )

        revision_id, dataset = _plugin_execution_boundary(
            "normalized output finalization",
            finalize_dataset,
        )
        report_analysis_load(
            AnalysisLoadStage.NORMALIZING,
            completed=1,
            total=1,
        )
        return IngestionResult(
            inventory=inventory,
            schema=schema,
            revision_id=revision_id,
            node_id=node_id,
            dataset=dataset,
            diagnostics=tuple(diagnostics),
            snapshots=tuple(snapshots),
            relationship_observations=tuple(relationships),
            relationship_collections=tuple(collections),
            events=tuple(events),
            source_records=tuple(item.emission for item in source_records),
            source_record_origins=tuple(
                SourceRecordOrigin(
                    parser_id=item.parser_id,
                    input_ordinal=item.input_ordinal,
                    output_ordinal=item.output_ordinal,
                )
                for item in source_records
            ),
        )


class InMemoryRevisionStore:
    """One immutable core-normalized revision."""

    def __init__(
        self,
        result: IngestionResult,
        *,
        plugin_id: str,
    ) -> None:
        # The coordinator result is a hand-off value, not a mutable backing
        # store. Detach it once here and detach every public read below.
        self._dataset = deepcopy(result.dataset)
        self._revision = RevisionDescriptor(
            node_id=result.node_id,
            revision_id=result.revision_id,
            label=result.node_id,
            event_count=len(result.events),
            resource_count=len(self._dataset.get("resources", ())),
            plugin_ids=(plugin_id,),
            metadata={"ingestion": "core-v2"},
        )
        self._assembly = AssemblyDescriptor(
            assembly_id=f"single:{result.revision_id}",
            revisions=(self._revision,),
            metadata={"ingestion": "core-v2"},
        )

    @property
    def assembly(self) -> AssemblyDescriptor:
        return deepcopy(self._assembly)

    @property
    def default_revision_id(self) -> str:
        return self._revision.revision_id

    def revision(self, revision_id: str) -> RevisionDescriptor:
        if revision_id != self._revision.revision_id:
            raise KeyError(revision_id)
        return deepcopy(self._revision)

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        if node_id != self._revision.node_id:
            raise KeyError(node_id)
        return deepcopy(self._revision)

    def dataset_for_revision(
        self,
        revision_id: str,
    ) -> Mapping[str, Any]:
        self.revision(revision_id)
        return deepcopy(self._dataset)

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        self.revision_for_node(node_id)
        return deepcopy(self._dataset)

    def loaded_revision_ids(self) -> Sequence[str]:
        return (self._revision.revision_id,)


class _LazyInMemoryRevisionStore:
    """Single-flight wrapper that defers parser work until data is requested.

    The hosted frontend must be reachable before a potentially large dump is
    parsed so its progress surface can observe that work. Runtime/session
    validation therefore opens this lightweight store synchronously, while
    the first normalized-data request performs the actual ingestion under the
    core service's bound load operation.
    """

    def __init__(
        self,
        loader: Callable[[], IngestionResult],
        *,
        plugin_id: str,
    ) -> None:
        self._loader = loader
        self._plugin_id = plugin_id
        self._lock = RLock()
        self._store: InMemoryRevisionStore | None = None

    def _loaded(self) -> InMemoryRevisionStore:
        with self._lock:
            if self._store is None:
                result = self._loader()
                self._store = InMemoryRevisionStore(
                    result,
                    plugin_id=self._plugin_id,
                )
            return self._store

    @property
    def assembly(self) -> AssemblyDescriptor:
        return self._loaded().assembly

    @property
    def default_revision_id(self) -> str:
        return self._loaded().default_revision_id

    def revision(self, revision_id: str) -> RevisionDescriptor:
        return self._loaded().revision(revision_id)

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        return self._loaded().revision_for_node(node_id)

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        return self._loaded().dataset_for_revision(revision_id)

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        return self._loaded().dataset_for_node(node_id)

    def loaded_revision_ids(self) -> Sequence[str]:
        with self._lock:
            if self._store is None:
                return ()
            return self._store.loaded_revision_ids()


class IngestedDatasetSource:
    """Normalized source for one immutable in-memory ingestion result."""

    def __init__(self, store: RevisionStore) -> None:
        self.store: RevisionStore = store

    def revision_scope(self, revision_id: str) -> Any:
        self.store.revision(revision_id)
        return nullcontext()

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        if selection:
            node_id = selection.get("node_id")
            if node_id is not None:
                return dict(self.store.dataset_for_node(str(node_id)))
        selected = revision_id or self.store.default_revision_id
        return dict(self.store.dataset_for_revision(selected))

    def revision_id(self, dataset: Mapping[str, Any]) -> str:
        metadata = dataset.get("_ingestion")
        if isinstance(metadata, Mapping) and metadata.get("revision_id"):
            return str(metadata["revision_id"])
        raise IngestionError("normalized dataset lacks revision_id")

    def indexed_history(self, dataset: Mapping[str, Any]) -> None:
        return None


class IngestedDataPolicy:
    """Domain-neutral metadata policy for core-ingested revisions."""

    def __init__(self, store: RevisionStore) -> None:
        self._store = store
        self._source_lock = RLock()
        self._source_by_event_uid: dict[str, dict[str, Any]] | None = None

    def _source_records_by_event(self) -> dict[str, dict[str, Any]]:
        with self._source_lock:
            if self._source_by_event_uid is None:
                dataset = self._store.dataset_for_revision(
                    self._store.default_revision_id
                )
                index: dict[str, dict[str, Any]] = {}
                for record in dataset.get("source_records", ()):
                    if not isinstance(record, Mapping):
                        continue
                    for event_uid in record.get("matched_event_uids", ()):
                        index.setdefault(
                            str(event_uid),
                            deepcopy(dict(record)),
                        )
                self._source_by_event_uid = index
            return self._source_by_event_uid

    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        metadata = dataset.get("_ingestion")
        return deepcopy(dict(metadata)) if isinstance(metadata, Mapping) else {}

    def workspace_metadata(
        self,
        dataset: Mapping[str, Any],
        *,
        revision_id: str,
        history_mode: str,
    ) -> Mapping[str, Any]:
        metadata = self.analysis_metadata(dataset)
        runtime_capabilities = dataset.get("runtime_capabilities")
        capabilities = (
            dict(runtime_capabilities)
            if isinstance(runtime_capabilities, Mapping)
            else {}
        )
        capabilities["core_ingestion"] = True
        capabilities["server_windowed_history"] = False
        return {
            "workspace_id": f"core-ingestion:{revision_id}",
            "revision_id": revision_id,
            "scope": "node",
            "workspace_kind": "node",
            "history_mode": history_mode,
            "capabilities": capabilities,
            "node_id": str(metadata.get("node_id") or "unknown-node"),
            "node_label": str(
                metadata.get("node_label") or metadata.get("node_id") or "Unknown node"
            ),
            "label": str(metadata.get("name") or "Parsed dump"),
            "event_count": len(dataset.get("events", ())),
            "matched_event_count": int(metadata.get("matched_event_count") or 0),
            "resource_count": len(dataset.get("resources", ())),
            "source_record_count": len(dataset.get("source_records", ())),
        }

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return {
            "available": False,
            "routes": [],
            "reason": "the selected plug-in declared no route provider",
        }

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        raise KeyError(route_id)

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        event_uid = str(event.get("event_uid") or "")
        return deepcopy(self._source_records_by_event().get(event_uid, {}))


@dataclass(slots=True)
class CoreIngestionSession:
    """Core-built session exposed through the existing application lifetime."""

    revision_store: RevisionStore
    data_source: IngestedDatasetSource
    data_policy: IngestedDataPolicy
    temporal_provider: None = None
    topology_provider: None = None
    route_provider: None = None


class CoreIngestionRuntime:
    """Adapter that turns a normal parser plug-in into a runtime session."""

    capability_id = CORE_INGESTION_RUNTIME_CAPABILITY_ID

    def __init__(
        self,
        plugin: Any,
        *,
        coordinator: IngestionCoordinator | None = None,
    ) -> None:
        self.coordinator: IngestionCoordinator = coordinator or IngestionCoordinator()
        self._plugin_snapshot = self.coordinator._snapshot_plugin(plugin)
        self.plugin: AnalyzerPlugin = cast(
            AnalyzerPlugin,
            self._plugin_snapshot.original,
        )

    def open(
        self,
        input_path: Path,
    ) -> AbstractContextManager[Any]:
        return self._open(input_path)

    @contextmanager
    def _open(self, input_path: Path) -> Iterator[CoreIngestionSession]:
        store = _LazyInMemoryRevisionStore(
            lambda: self.coordinator.ingest(self._plugin_snapshot, input_path),
            plugin_id=self._plugin_snapshot.manifest.plugin_id,
        )
        source = IngestedDatasetSource(store)
        yield CoreIngestionSession(
            revision_store=store,
            data_source=source,
            data_policy=IngestedDataPolicy(store),
        )


__all__ = [
    "CORE_INGESTION_RUNTIME_CAPABILITY_ID",
    "CoreIngestionRuntime",
    "CoreIngestionSession",
    "InMemoryRevisionStore",
    "IngestedDataPolicy",
    "IngestedDatasetSource",
    "IngestionCoordinator",
    "IngestionError",
    "IngestionLimits",
    "IngestionResult",
    "SourceRecordOrigin",
    "snapshot_ingestion_result_for_publication",
]

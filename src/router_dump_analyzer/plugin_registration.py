"""Sealed plug-in registration and executable identity, independent of queue storage."""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from types import CodeType
from typing import Any, Final

from .artifact_core import ArtifactLimits, CoreArtifactReader
from .canonical import canonical_json
from .ingestion import IngestionCoordinator, IngestionError, IngestionLimits
from .ingestion_contracts import (
    IngestionPipelineError,
    _bounded_identifier,
    _normalized_explicit_bootstrap_target,
)
from .load_progress import AnalysisLoadStage, _analysis_load_stage
from .plugin_api import (
    AnalyzerPlugin,
    PluginCapability,
    PluginManifest,
    ProbeMatchKind,
    ReconstructionSupport,
    TimelineTimeBasis,
    validate_probe_report,
    validate_probe_result,
)
from .plugin_execution_plan import (
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    plugin_execution_pin_uses_legacy_identity,
)
from .plugin_execution_plan import (
    _snapshot_decoder_identity as _plan_snapshot_decoder_identity,
)
from .plugin_identity import (
    PluginExecutableIdentityError,
    executable_module_target_fingerprint,
    executable_plugin_fingerprint,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

__all__ = [
    "PluginCandidate",
    "PluginRegistry",
    "RegisteredPlugin",
    "registered_plugin_matches_execution_pin",
]

MAX_PLUGIN_CANDIDATES = 256

_PACKAGE_HASH_PATTERN = re.compile(
    r"^(?:(?:manifest|module|package)-sha256|sha256):[0-9a-f]{64}$"
)

_ACTIVE_DECODER_IDENTITY: ContextVar[DecoderIdentity | None] = ContextVar(
    "ingestion_active_decoder_identity",
    default=None,
)

_DEFAULT_PLUGIN_CONFIGURATION_DIGEST: Final = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)

_MANIFEST_PROCESS_BOOTSTRAP_ERROR: Final = (
    "manifest-only plug-in identity cannot authorize PROCESS execution"
)

_PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR: Final = (
    "unattested plug-in process target is INLINE-only and cannot authorize "
    "PROCESS execution"
)

_INLINE_ONLY_PROCESS_COMPATIBILITY: Final = "inline_only"


class _ProcessTargetKind(StrEnum):
    """Closed process-target vocabulary used by identity diagnostics."""

    PLUGIN = "plug-in"
    COORDINATOR = "coordinator"
    DECODER = "decoder"


class _ProcessTargetIdentityUnavailable(IngestionPipelineError):
    """A classified, compatibility-eligible target-attestation failure."""

    reason_code: Final = "process_target_executable_identity_unavailable"

    def __init__(self, target_kind: _ProcessTargetKind) -> None:
        if type(target_kind) is not _ProcessTargetKind:
            raise TypeError("target_kind must be an exact _ProcessTargetKind")
        self.target_kind: _ProcessTargetKind = target_kind
        super().__init__(
            f"{target_kind.value} process target executable identity is unavailable"
        )


@dataclass(frozen=True, slots=True)
class PluginCandidate:
    plugin_id: str
    plugin_version: str
    package_hash: str
    confidence: float
    match_kind: str
    instance_id: str = ""
    registered_execution_identity: str = ""
    reasons: tuple[str, ...] = ()
    detected_platform: str | None = None
    detected_software_version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "package_hash": self.package_hash,
            "instance_id": self.instance_id,
            "registered_execution_identity": self.registered_execution_identity,
            "confidence": self.confidence,
            "match_kind": self.match_kind,
            "reasons": list(self.reasons),
            "detected_platform": self.detected_platform,
            "detected_software_version": self.detected_software_version,
        }


@dataclass(frozen=True, slots=True)
class _PinnedManifestPlugin:
    """Execute one plug-in through the manifest validated at registration."""

    original: Any
    manifest: PluginManifest

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


class _IdentityBoundTraceDecoder:
    """Mark the exact registered decoder when a CTF input invokes it."""

    __slots__ = ("_decoder", "_identity")
    _decoder: Any
    _identity: DecoderIdentity

    def __init__(self, decoder: Any, identity: DecoderIdentity) -> None:
        object.__setattr__(self, "_decoder", decoder)
        object.__setattr__(
            self,
            "_identity",
            _snapshot_decoder_identity(identity),
        )

    @property
    def identity(self) -> DecoderIdentity:
        return _snapshot_decoder_identity(self._identity)

    def _implementation(self) -> Any:
        return self._decoder

    def _matches(
        self,
        implementation: Any,
        identity: DecoderIdentity,
    ) -> bool:
        return self._decoder is implementation and self._identity == identity

    def iter_ctf(self, *args: Any, **kwargs: Any) -> Any:
        _ACTIVE_DECODER_IDENTITY.set(_snapshot_decoder_identity(self._identity))
        return self._decoder.iter_ctf(*args, **kwargs)


def _snapshot_decoder_identity(identity: DecoderIdentity) -> DecoderIdentity:
    """Detach an exact decoder identity from caller-owned mutable aliases."""

    return _plan_snapshot_decoder_identity(
        identity,
        type_error_message="decoder identity must be an exact DecoderIdentity",
    )


def _snapshot_plugin_manifest(manifest: PluginManifest) -> PluginManifest:
    """Detach executable dispatch vocabulary from a caller-owned manifest."""

    if type(manifest) is not PluginManifest:
        raise TypeError("manifest must be an exact PluginManifest")
    normalized_capabilities: set[PluginCapability | str] = set()
    for item in manifest.capabilities:
        candidate = str(item)
        try:
            normalized_capabilities.add(PluginCapability(candidate))
        except ValueError:
            normalized_capabilities.add(candidate)
    return PluginManifest(
        plugin_id=str(manifest.plugin_id),
        plugin_version=str(manifest.plugin_version),
        core_api_version=str(manifest.core_api_version),
        supported_platforms=tuple(str(item) for item in manifest.supported_platforms),
        supported_software_versions=str(manifest.supported_software_versions),
        capabilities=frozenset(normalized_capabilities),
        reconstruction_default=ReconstructionSupport(
            str(manifest.reconstruction_default)
        ),
        forwarding_ir_versions=tuple(
            str(item) for item in manifest.forwarding_ir_versions
        ),
        timeline_time_basis=TimelineTimeBasis(manifest.timeline_time_basis),
        timeline_clock_domain=(
            str(manifest.timeline_clock_domain)
            if manifest.timeline_clock_domain is not None
            else None
        ),
    )


_INGESTION_LIMIT_BOOTSTRAP_FIELDS = (
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
)

_ARTIFACT_LIMIT_BOOTSTRAP_FIELDS = (
    "max_artifacts",
    "max_inventory_entries",
    "max_path_depth",
    "max_artifact_bytes",
    "max_total_uncompressed_bytes",
    "max_compression_ratio",
)


@dataclass(frozen=True, slots=True)
class _PluginProcessBootstrap:
    """Core-owned spawn payload for one exact registered plug-in.

    Every field is an exact scalar or a tuple of exact scalars.  In
    particular, no plug-in, coordinator, decoder, registry, provider, bound
    method, or deployment object may enter this value.  Windows ``spawn`` can
    therefore serialize it without invoking attacker-controlled pickle hooks
    in the parent before the child deadline can be enforced.
    """

    schema_version: str
    plugin_loader_kind: str
    plugin_target: str
    plugin_target_executable_identity: str
    coordinator_loader_kind: str
    coordinator_target: str | None
    coordinator_target_executable_identity: str | None
    decoder_loader_kind: str
    decoder_target: str | None
    decoder_target_executable_identity: str | None
    ingestion_limit_values: tuple[int, ...]
    artifact_limit_values: tuple[int, ...]
    package_hash: str
    verify_package_bytes: bool
    instance_id: str
    distribution_name: str
    distribution_version: str
    entry_point_name: str
    module_target: str
    configuration_digest: str
    decoder_identity_values: tuple[str, str, str] | None
    expected_registered_execution_identity: str


def _plugin_process_bootstrap_identity_material(
    bootstrap: _PluginProcessBootstrap,
) -> dict[str, Any]:
    """Project the complete non-recursive child execution authority."""

    if type(bootstrap) is not _PluginProcessBootstrap:
        raise TypeError("process bootstrap must be an exact descriptor")
    required_strings = (
        bootstrap.schema_version,
        bootstrap.plugin_loader_kind,
        bootstrap.plugin_target,
        bootstrap.plugin_target_executable_identity,
        bootstrap.coordinator_loader_kind,
        bootstrap.decoder_loader_kind,
        bootstrap.package_hash,
        bootstrap.instance_id,
        bootstrap.distribution_name,
        bootstrap.distribution_version,
        bootstrap.entry_point_name,
        bootstrap.module_target,
        bootstrap.configuration_digest,
    )
    if any(type(value) is not str for value in required_strings):
        raise TypeError("process bootstrap string coordinates are invalid")
    optional_strings = (
        bootstrap.coordinator_target,
        bootstrap.coordinator_target_executable_identity,
        bootstrap.decoder_target,
        bootstrap.decoder_target_executable_identity,
    )
    if any(value is not None and type(value) is not str for value in optional_strings):
        raise TypeError("process bootstrap optional targets are invalid")
    target_identities = (
        bootstrap.plugin_target_executable_identity,
        bootstrap.coordinator_target_executable_identity,
        bootstrap.decoder_target_executable_identity,
    )
    if any(
        value is not None and re.fullmatch(r"target-sha256:[0-9a-f]{64}", value) is None
        for value in target_identities
    ):
        raise ValueError("process bootstrap target executable identity is invalid")
    if (bootstrap.coordinator_target is None) != (
        bootstrap.coordinator_target_executable_identity is None
    ) or (bootstrap.decoder_target is None) != (
        bootstrap.decoder_target_executable_identity is None
    ):
        raise ValueError("process bootstrap target executable identity is incomplete")
    if type(bootstrap.verify_package_bytes) is not bool:
        raise TypeError("process bootstrap verification mode is invalid")
    for values, label in (
        (bootstrap.ingestion_limit_values, "ingestion"),
        (bootstrap.artifact_limit_values, "artifact"),
    ):
        if type(values) is not tuple or any(type(value) is not int for value in values):
            raise TypeError(f"process bootstrap {label} limits are invalid")
    decoder_identity = bootstrap.decoder_identity_values
    if decoder_identity is not None and (
        type(decoder_identity) is not tuple
        or len(decoder_identity) != 3
        or any(type(value) is not str for value in decoder_identity)
    ):
        raise TypeError("process bootstrap decoder identity is invalid")
    return {
        "schema_version": bootstrap.schema_version,
        "plugin_loader_kind": bootstrap.plugin_loader_kind,
        "plugin_target": bootstrap.plugin_target,
        "plugin_target_executable_identity": (
            bootstrap.plugin_target_executable_identity
        ),
        "coordinator_loader_kind": bootstrap.coordinator_loader_kind,
        "coordinator_target": bootstrap.coordinator_target,
        "coordinator_target_executable_identity": (
            bootstrap.coordinator_target_executable_identity
        ),
        "decoder_loader_kind": bootstrap.decoder_loader_kind,
        "decoder_target": bootstrap.decoder_target,
        "decoder_target_executable_identity": (
            bootstrap.decoder_target_executable_identity
        ),
        "ingestion_limit_values": list(bootstrap.ingestion_limit_values),
        "artifact_limit_values": list(bootstrap.artifact_limit_values),
        "package_hash": bootstrap.package_hash,
        "verify_package_bytes": bootstrap.verify_package_bytes,
        "instance_id": bootstrap.instance_id,
        "distribution_name": bootstrap.distribution_name,
        "distribution_version": bootstrap.distribution_version,
        "entry_point_name": bootstrap.entry_point_name,
        "module_target": bootstrap.module_target,
        "configuration_digest": bootstrap.configuration_digest,
        "decoder_identity_values": (
            list(decoder_identity) if decoder_identity is not None else None
        ),
    }


def _plugin_process_bootstrap_digest(
    bootstrap: _PluginProcessBootstrap,
) -> str:
    """Bind one PROCESS plan pin to its complete inert child bootstrap."""

    material = _plugin_process_bootstrap_identity_material(bootstrap)
    return (
        "sha256:" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    )


@dataclass(frozen=True, slots=True)
class RegisteredPlugin:
    plugin: Any
    coordinator: IngestionCoordinator
    package_hash: str
    verify_package_bytes: bool
    instance_id: str = "legacy.default"
    distribution_name: str = "legacy.plugin"
    distribution_version: str = "0"
    entry_point_name: str = "legacy.plugin"
    module_target: str = "legacy.plugin:plugin"
    configuration_digest: str = (
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )
    core_api_version: str = "1.0"
    capabilities: tuple[str, ...] = ()
    schema_versions: tuple[str, ...] = ("router_dump_analyzer.plugin_schema.v1",)
    timeline_time_basis: str = TimelineTimeBasis.REVISION_START_RELATIVE_NS.value
    timeline_clock_domain: str | None = None
    decoder_identity: DecoderIdentity | None = None
    _plugin_id_snapshot: str | None = None
    _plugin_version_snapshot: str | None = None
    _manifest_identity_snapshot: str | None = None
    _execution_plugin: Any | None = None
    _decoder_implementation_snapshot: Any | None = None
    _registered_execution_identity_snapshot: str | None = None
    _ingestion_limit_values_snapshot: tuple[int, ...] = ()
    _artifact_limit_values_snapshot: tuple[int, ...] = ()
    _process_bootstrap: _PluginProcessBootstrap | None = None
    _process_bootstrap_error: str | None = None

    @property
    def plugin_id(self) -> str:
        if self._plugin_id_snapshot is not None:
            return self._plugin_id_snapshot
        try:
            return str(self.plugin.manifest.plugin_id)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "registered plug-in identity could not be resolved"
            ) from error

    @property
    def plugin_version(self) -> str:
        if self._plugin_version_snapshot is not None:
            return self._plugin_version_snapshot
        try:
            return str(self.plugin.manifest.plugin_version)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "registered plug-in identity could not be resolved"
            ) from error

    @property
    def execution_plugin(self) -> Any:
        """Return the plug-in view whose manifest is frozen for execution."""

        return (
            self._execution_plugin
            if self._execution_plugin is not None
            else self.plugin
        )

    def execution_identity_material(self) -> dict[str, Any]:
        """Project every registered coordinate that can affect one execution."""

        decoder = self.decoder_identity
        process_bootstrap = self._process_bootstrap
        process_bootstrap_available = (
            self._process_bootstrap_error is None
            and type(process_bootstrap) is _PluginProcessBootstrap
        )
        material = {
            "schema_version": "router_dump_analyzer.registered_execution.v4",
            "instance_id": self.instance_id,
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "core_api_version": self.core_api_version,
            "manifest_digest": self._manifest_identity_snapshot,
            "artifact": {
                "distribution_name": self.distribution_name,
                "distribution_version": self.distribution_version,
                "package_hash": self.package_hash,
                "entry_point_name": self.entry_point_name,
                "module_target": self.module_target,
            },
            "configuration_digest": self.configuration_digest,
            "capabilities": list(self.capabilities),
            "schema_versions": list(self.schema_versions),
            "timeline_time_basis": self.timeline_time_basis,
            "timeline_clock_domain": self.timeline_clock_domain,
            "process_bootstrap_available": process_bootstrap_available,
            "process_bootstrap": (
                _plugin_process_bootstrap_identity_material(process_bootstrap)
                if type(process_bootstrap) is _PluginProcessBootstrap
                else None
            ),
            "decoder": (
                {
                    "decoder_id": decoder.decoder_id,
                    "decoder_version": decoder.decoder_version,
                    "executable_digest": decoder.executable_digest,
                }
                if decoder is not None
                else None
            ),
        }
        if (
            type(process_bootstrap) is not _PluginProcessBootstrap
            and self._process_bootstrap_error == _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR
        ):
            # Compatibility is an execution restriction, so it participates in
            # the frozen identity. Keep the normal PROCESS-capable projection
            # byte-for-byte stable by omitting the key outside this opt-out.
            material["process_bootstrap_compatibility"] = (
                _INLINE_ONLY_PROCESS_COMPATIBILITY
            )
        if type(process_bootstrap) is not _PluginProcessBootstrap:
            material["trusted_inline_ingestion_limits"] = {
                "ingestion": list(self._ingestion_limit_values_snapshot),
                "artifact": list(self._artifact_limit_values_snapshot),
            }
        return material

    @property
    def registered_execution_identity(self) -> str:
        material = self.execution_identity_material()
        return (
            "sha256:"
            + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
        )

    @property
    def process_bootstrap(self) -> _PluginProcessBootstrap:
        """Return the inert child bootstrap frozen at registration."""

        bootstrap = self._process_bootstrap
        if type(bootstrap) is not _PluginProcessBootstrap:
            if self._process_bootstrap_error is not None:
                raise ValueError(self._process_bootstrap_error)
            raise IngestionPipelineError(
                "registered plug-in has no process bootstrap descriptor"
            )
        expected_identity = self._registered_execution_identity_snapshot
        try:
            current_identity = self.registered_execution_identity
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "registered process bootstrap identity cannot be revalidated"
            ) from error
        if (
            type(expected_identity) is not str
            or type(bootstrap.expected_registered_execution_identity) is not str
            or current_identity != expected_identity
            or bootstrap.expected_registered_execution_identity != expected_identity
        ):
            raise IngestionPipelineError(
                "registered process bootstrap changed after registration"
            )
        _revalidate_process_target_executable_identities(self)
        if self._process_bootstrap_error is not None:
            raise ValueError(self._process_bootstrap_error)
        return replace(bootstrap)

    @property
    def process_bootstrap_digest(self) -> str | None:
        """Return the canonical PROCESS bootstrap digest, or ``None`` inline."""

        if (
            type(self._process_bootstrap) is not _PluginProcessBootstrap
            or self._process_bootstrap_error is not None
        ):
            return None
        return _plugin_process_bootstrap_digest(self.process_bootstrap)


def _require_no_inline_only_plugin_compatibility(
    records: Iterable[RegisteredPlugin],
    *,
    boundary: str,
) -> None:
    """Reject every non-PROCESS record at a process authority boundary."""

    if type(boundary) is not str or not boundary:
        raise ValueError("plug-in compatibility boundary must be a non-empty string")
    selected = tuple(records)
    if any(type(record) is not RegisteredPlugin for record in selected):
        raise TypeError("plug-in compatibility checks require registered plug-ins")
    inline_only = tuple(
        f"{record.plugin_id}@{record.plugin_version}"
        for record in selected
        if (
            type(record._process_bootstrap) is not _PluginProcessBootstrap
            or record._process_bootstrap_error is not None
        )
    )
    if inline_only:
        raise ValueError(
            f"{boundary}; INLINE-only registrations: " + ", ".join(inline_only)
        )


def _registered_plugin_uses_inline_only_compatibility(
    record: RegisteredPlugin,
) -> bool:
    """Return whether a registry explicitly admitted INLINE compatibility."""

    if type(record) is not RegisteredPlugin:
        raise TypeError("plug-in compatibility checks require registered plug-ins")
    if type(record._process_bootstrap) is _PluginProcessBootstrap:
        return False
    return record._process_bootstrap_error in (
        _MANIFEST_PROCESS_BOOTSTRAP_ERROR,
        _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR,
    )


def _registered_plugin_is_process_capable(record: RegisteredPlugin) -> bool:
    """Return whether registration retained a fully validated child bootstrap."""

    if type(record) is not RegisteredPlugin:
        raise TypeError("plug-in capability checks require registered plug-ins")
    return (
        type(record._process_bootstrap) is _PluginProcessBootstrap
        and record._process_bootstrap_error is None
    )


def _registered_plugin_is_trusted_inline_capable(record: RegisteredPlugin) -> bool:
    """Return whether one frozen registration may run under explicit trust.

    Trusted-inline authority is broader than the manifest compatibility tier:
    a configured registration can retain an exact registered execution identity
    while lacking the child-reconstructable bootstrap required by PROCESS mode.
    The explicit ``allow_inline_only`` decision may authorize that registration,
    but never an ad-hoc/direct ``RegisteredPlugin`` value without a frozen
    identity.
    """

    if type(record) is not RegisteredPlugin:
        raise TypeError("plug-in capability checks require registered plug-ins")
    return record._registered_execution_identity_snapshot is not None and (
        record.verify_package_bytes
        or type(record._process_bootstrap) is _PluginProcessBootstrap
        or _registered_plugin_uses_inline_only_compatibility(record)
    )


def _validated_allow_inline_only(value: object) -> bool:
    """Validate one authority-bearing trusted-inline switch exactly."""

    if type(value) is not bool:
        raise TypeError("allow_inline_only must be an exact boolean")
    return value


def _registered_plugins_require_inline_execution(
    records: Iterable[RegisteredPlugin],
) -> bool:
    """Return whether any selected registration is explicitly INLINE-only."""

    return any(
        not _registered_plugin_is_process_capable(record) for record in tuple(records)
    )


def registered_plugin_matches_execution_pin(
    pin: PluginExecutionPin,
    registered: RegisteredPlugin,
) -> bool:
    """Compare immutable pin coordinates shared by ingestion and routing."""

    if type(pin) is not PluginExecutionPin:
        raise TypeError("pin must be an exact PluginExecutionPin")
    if type(registered) is not RegisteredPlugin:
        raise TypeError("registered must be an exact RegisteredPlugin")
    artifact = pin.artifact
    bootstrap_digest_matches = pin.process_bootstrap_digest is None
    if not bootstrap_digest_matches:
        bootstrap = registered._process_bootstrap
        if type(bootstrap) is _PluginProcessBootstrap:
            try:
                bootstrap_digest_matches = (
                    _plugin_process_bootstrap_digest(bootstrap)
                    == pin.process_bootstrap_digest
                )
            except (TypeError, ValueError):
                bootstrap_digest_matches = False
    return (
        pin.instance_id == registered.instance_id
        and pin.plugin_id == registered.plugin_id
        and pin.plugin_version == registered.plugin_version
        and pin.core_api_version == registered.core_api_version
        and artifact.distribution_name == registered.distribution_name
        and artifact.distribution_version == registered.distribution_version
        and artifact.package_hash == registered.package_hash
        and artifact.entry_point_name == registered.entry_point_name
        and artifact.module_target == registered.module_target
        and pin.configuration_digest == registered.configuration_digest
        and not plugin_execution_pin_uses_legacy_identity(pin)
        and pin.registered_execution_identity
        == registered.registered_execution_identity
        and bootstrap_digest_matches
        and pin.schema_versions == registered.schema_versions
        and pin.capabilities == registered.capabilities
    )


def _bootstrap_class_target(value: object, label: str) -> str:
    """Return an importable class target without touching instance pickling."""

    implementation = type(value)
    try:
        module_name = implementation.__module__
        qualified_name = implementation.__qualname__
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            f"{label} process bootstrap target could not be resolved"
        ) from error
    if (
        type(module_name) is not str
        or type(qualified_name) is not str
        or not module_name
        or not qualified_name
        or "<locals>" in qualified_name
        or ":" in module_name
        or ":" in qualified_name
    ):
        raise ValueError(f"{label} must have an importable module-level class")
    return _bounded_identifier(
        f"{module_name}:{qualified_name}",
        f"{label}_process_target",
        512,
    )


def _snapshot_ingestion_limit_bootstrap(
    coordinator: IngestionCoordinator,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Freeze coordinator quotas into primitive tuples at registration."""

    try:
        limits = coordinator.limits
        if type(limits) is not IngestionLimits:
            raise TypeError("coordinator limits must be an exact IngestionLimits")
        artifact_limits = limits.artifact_limits
        if type(artifact_limits) is not ArtifactLimits:
            raise TypeError("artifact limits must be an exact ArtifactLimits")
        ingestion_values = tuple(
            getattr(limits, name) for name in _INGESTION_LIMIT_BOOTSTRAP_FIELDS
        )
        artifact_values = tuple(
            getattr(artifact_limits, name) for name in _ARTIFACT_LIMIT_BOOTSTRAP_FIELDS
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            "coordinator process bootstrap limits could not be resolved"
        ) from error
    if any(type(value) is not int for value in (*ingestion_values, *artifact_values)):
        raise IngestionPipelineError(
            "coordinator process bootstrap limits are not exact integers"
        )
    return ingestion_values, artifact_values


def _ingestion_limits_from_snapshot(
    ingestion_values: tuple[int, ...],
    artifact_values: tuple[int, ...],
) -> IngestionLimits:
    if (
        type(ingestion_values) is not tuple
        or len(ingestion_values) != len(_INGESTION_LIMIT_BOOTSTRAP_FIELDS)
        or any(type(value) is not int for value in ingestion_values)
        or type(artifact_values) is not tuple
        or len(artifact_values) != len(_ARTIFACT_LIMIT_BOOTSTRAP_FIELDS)
        or any(type(value) is not int for value in artifact_values)
    ):
        raise IngestionPipelineError(
            "registered coordinator limits snapshot is invalid"
        )
    artifact_limits = ArtifactLimits(
        **dict(
            zip(
                _ARTIFACT_LIMIT_BOOTSTRAP_FIELDS,
                artifact_values,
                strict=True,
            )
        )
    )
    return IngestionLimits(
        **dict(
            zip(
                _INGESTION_LIMIT_BOOTSTRAP_FIELDS,
                ingestion_values,
                strict=True,
            )
        ),
        artifact_limits=artifact_limits,
    )


def _registered_ingestion_limits(record: RegisteredPlugin) -> IngestionLimits:
    """Return immutable registration quotas and reject live coordinator drift."""

    if type(record) is not RegisteredPlugin:
        raise TypeError("registered must be an exact RegisteredPlugin")
    registration_values = (
        record._ingestion_limit_values_snapshot,
        record._artifact_limit_values_snapshot,
    )
    bootstrap = record._process_bootstrap
    frozen_values = (
        (bootstrap.ingestion_limit_values, bootstrap.artifact_limit_values)
        if type(bootstrap) is _PluginProcessBootstrap
        else registration_values
    )
    if registration_values != frozen_values:
        raise IngestionPipelineError(
            "registered coordinator limits snapshot disagrees with its bootstrap"
        )
    limits = _ingestion_limits_from_snapshot(*frozen_values)
    current_values = _snapshot_ingestion_limit_bootstrap(record.coordinator)
    if current_values != frozen_values:
        raise IngestionPipelineError(
            "registered coordinator limits changed after registration"
        )
    return limits


def _process_target_executable_identity(
    target: str,
    subject: object,
    *,
    target_kind: _ProcessTargetKind,
    declared_code_cache: dict[tuple[str, Path, str], tuple[CodeType, ...]]
    | None = None,
) -> str:
    """Snapshot one exact module target and its executable implementation."""

    if type(target_kind) is not _ProcessTargetKind:
        raise TypeError("target_kind must be an exact _ProcessTargetKind")
    normalized = _normalized_explicit_bootstrap_target(
        target,
        f"{target_kind.value}_target",
    )
    module_name, _, attribute = normalized.partition(":")
    try:
        identity = executable_module_target_fingerprint(
            module_name,
            attribute,
            subject,
            _batch_declared_code_cache=declared_code_cache,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PluginExecutableIdentityError as error:
        raise _ProcessTargetIdentityUnavailable(target_kind) from error
    except BaseException as error:
        raise IngestionPipelineError(
            f"{target_kind.value} process target executable identity is unavailable"
        ) from error
    if (
        type(identity) is not str
        or re.fullmatch(r"target-sha256:[0-9a-f]{64}", identity) is None
    ):
        raise IngestionPipelineError(
            f"{target_kind.value} process target executable identity is invalid"
        )
    return identity


def _process_target_identity_subject(
    loader_kind: str,
    value: object,
    *,
    label: str,
) -> object:
    if loader_kind == "module_attribute":
        return value
    if loader_kind == "class_constructor":
        return type(value)
    raise IngestionPipelineError(f"unknown {label} process loader kind")


def _current_process_target_executable_identities(
    record: RegisteredPlugin,
    bootstrap: _PluginProcessBootstrap,
) -> tuple[str, str | None, str | None]:
    declared_code_cache: dict[tuple[str, Path, str], tuple[CodeType, ...]] = {}
    plugin_identity = _process_target_executable_identity(
        bootstrap.plugin_target,
        _process_target_identity_subject(
            bootstrap.plugin_loader_kind,
            record.plugin,
            label="plug-in",
        ),
        target_kind=_ProcessTargetKind.PLUGIN,
        declared_code_cache=declared_code_cache,
    )
    if bootstrap.coordinator_loader_kind == "core_default":
        coordinator_identity = None
    else:
        coordinator_target = bootstrap.coordinator_target
        if type(coordinator_target) is not str:
            raise IngestionPipelineError(
                "coordinator process target executable identity is unavailable"
            )
        coordinator_identity = _process_target_executable_identity(
            coordinator_target,
            _process_target_identity_subject(
                bootstrap.coordinator_loader_kind,
                record.coordinator,
                label="coordinator",
            ),
            target_kind=_ProcessTargetKind.COORDINATOR,
            declared_code_cache=declared_code_cache,
        )
    if bootstrap.decoder_loader_kind == "none":
        decoder_identity = None
    else:
        decoder_target = bootstrap.decoder_target
        decoder_implementation = record._decoder_implementation_snapshot
        if type(decoder_target) is not str or decoder_implementation is None:
            raise IngestionPipelineError(
                "decoder process target executable identity is unavailable"
            )
        decoder_identity = _process_target_executable_identity(
            decoder_target,
            _process_target_identity_subject(
                bootstrap.decoder_loader_kind,
                decoder_implementation,
                label="decoder",
            ),
            target_kind=_ProcessTargetKind.DECODER,
            declared_code_cache=declared_code_cache,
        )
    return plugin_identity, coordinator_identity, decoder_identity


def _revalidate_process_target_executable_identities(
    record: RegisteredPlugin,
) -> None:
    bootstrap = record._process_bootstrap
    if type(bootstrap) is not _PluginProcessBootstrap:
        manifest_only_compatibility = (
            record.package_hash.startswith("manifest-sha256:")
            and not record.verify_package_bytes
            and record._process_bootstrap_error == _MANIFEST_PROCESS_BOOTSTRAP_ERROR
        )
        derived_package_compatibility = (
            record.package_hash.startswith(("package-sha256:", "module-sha256:"))
            and record.verify_package_bytes
            and record._process_bootstrap_error
            == _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR
        )
        if manifest_only_compatibility or derived_package_compatibility:
            return
        if record._registered_execution_identity_snapshot is None:
            return
        raise IngestionPipelineError(
            "registered process target executable identity is unavailable"
        )
    try:
        current = _current_process_target_executable_identities(record, bootstrap)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            "registered process target executable identity cannot be revalidated"
        ) from error
    expected = (
        bootstrap.plugin_target_executable_identity,
        bootstrap.coordinator_target_executable_identity,
        bootstrap.decoder_target_executable_identity,
    )
    if current != expected:
        raise IngestionPipelineError(
            "registered process target executable changed after registration"
        )


class PluginRegistry:
    """Allowlisted plug-in identities used by queue workers.

    A trusted loader may pass an immutable artifact digest to
    :meth:`register` as ``package_hash``.  Otherwise the registry fingerprints
    the defining importable package under strict resource bounds.  Registries
    fail closed by default. Compatibility-only embeddings must explicitly opt
    into inline-only identity fallback with ``allow_manifest_identity=True``;
    this also covers a registry-derived package whose process target cannot be
    attested. Durable execution and loader-supplied executable package hashes
    never use that opt-out.
    """

    def __init__(
        self,
        plugins: Iterable[Any] = (),
        *,
        require_executable_identity: bool | None = None,
        allow_manifest_identity: bool = False,
    ) -> None:
        if type(allow_manifest_identity) is not bool:
            raise ValueError("allow_manifest_identity must be a boolean")
        if (
            require_executable_identity is not None
            and type(require_executable_identity) is not bool
        ):
            raise ValueError("require_executable_identity must be a boolean or None")
        if require_executable_identity is None:
            require_executable_identity = not allow_manifest_identity
        elif require_executable_identity and allow_manifest_identity:
            raise ValueError(
                "require_executable_identity and allow_manifest_identity conflict"
            )
        self._plugins: dict[tuple[str, str, str, str], RegisteredPlugin] = {}
        self._require_executable_identity = require_executable_identity
        self._sealed = False
        self._mutation_lock = threading.RLock()
        for plugin in plugins:
            self.register(plugin)

    @staticmethod
    def _manifest_fingerprint(manifest: Any) -> str:
        material = {
            "schema_version": "router_dump_analyzer.plugin_manifest_identity.v1",
            "plugin_id": str(manifest.plugin_id),
            "plugin_version": str(manifest.plugin_version),
            "core_api_version": str(manifest.core_api_version),
            "capabilities": sorted(str(item) for item in manifest.capabilities),
            "supported_platforms": [str(item) for item in manifest.supported_platforms],
            "supported_software_versions": str(manifest.supported_software_versions),
            "reconstruction_default": str(manifest.reconstruction_default.value),
            "forwarding_ir_versions": [
                str(item) for item in manifest.forwarding_ir_versions
            ],
            "timeline_time_basis": manifest.timeline_time_basis.value,
            "timeline_clock_domain": manifest.timeline_clock_domain,
        }
        return (
            "manifest-sha256:"
            + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
        )

    @_analysis_load_stage(AnalysisLoadStage.VALIDATING_PROVIDERS)
    def register(
        self,
        plugin: AnalyzerPlugin,
        *,
        coordinator: IngestionCoordinator | None = None,
        package_hash: str | None = None,
        instance_id: str | None = None,
        distribution_name: str | None = None,
        distribution_version: str | None = None,
        entry_point_name: str | None = None,
        module_target: str | None = None,
        configuration_digest: str | None = None,
        decoder_identity: DecoderIdentity | None = None,
        plugin_process_module_target: str | None = None,
        plugin_process_construct_class: bool = False,
        coordinator_module_target: str | None = None,
        decoder_module_target: str | None = None,
    ) -> RegisteredPlugin:
        return self._register(
            plugin,
            coordinator=coordinator,
            package_hash=package_hash,
            instance_id=instance_id,
            distribution_name=distribution_name,
            distribution_version=distribution_version,
            entry_point_name=entry_point_name,
            module_target=module_target,
            configuration_digest=configuration_digest,
            decoder_identity=decoder_identity,
            plugin_process_module_target=plugin_process_module_target,
            plugin_process_construct_class=plugin_process_construct_class,
            coordinator_module_target=coordinator_module_target,
            decoder_module_target=decoder_module_target,
        )

    def _register(
        self,
        plugin: AnalyzerPlugin,
        *,
        coordinator: IngestionCoordinator | None = None,
        package_hash: str | None = None,
        instance_id: str | None = None,
        distribution_name: str | None = None,
        distribution_version: str | None = None,
        entry_point_name: str | None = None,
        module_target: str | None = None,
        configuration_digest: str | None = None,
        decoder_identity: DecoderIdentity | None = None,
        plugin_process_module_target: str | None = None,
        plugin_process_construct_class: bool = False,
        coordinator_module_target: str | None = None,
        decoder_module_target: str | None = None,
        _deferred_process_bootstrap: _PluginProcessBootstrap | None = None,
    ) -> RegisteredPlugin:
        if self._sealed:
            raise RuntimeError("plug-in registry is sealed")
        if (
            _deferred_process_bootstrap is not None
            and type(_deferred_process_bootstrap) is not _PluginProcessBootstrap
        ):
            raise TypeError("deferred process bootstrap must be an exact descriptor")
        if _deferred_process_bootstrap is not None:
            try:
                _plugin_process_bootstrap_identity_material(_deferred_process_bootstrap)
            except (TypeError, ValueError) as error:
                raise IngestionPipelineError(
                    "child plug-in bootstrap identity is invalid"
                ) from error
        if type(plugin_process_construct_class) is not bool:
            raise TypeError("plugin_process_construct_class must be a boolean")
        if plugin_process_construct_class and plugin_process_module_target is None:
            raise ValueError(
                "plugin_process_construct_class requires a process module target"
            )
        selected_package_hash = (
            _deferred_process_bootstrap.package_hash
            if _deferred_process_bootstrap is not None
            else package_hash
        )
        if selected_package_hash is not None:
            # A loader-supplied digest is a trust assertion. Reject malformed
            # assertions before resolving any executable plug-in descriptor.
            resolved_package_hash = _bounded_identifier(
                selected_package_hash,
                "package_hash",
                80,
            )
            if _PACKAGE_HASH_PATTERN.fullmatch(resolved_package_hash) is None:
                raise ValueError(
                    "package_hash must be a lowercase SHA-256 package digest"
                )
        else:
            resolved_package_hash = None
        active_coordinator = (
            coordinator if coordinator is not None else IngestionCoordinator()
        )
        if not isinstance(active_coordinator, IngestionCoordinator):
            raise TypeError("coordinator must be an IngestionCoordinator")
        try:
            manifest = plugin.manifest
            if type(manifest) is not PluginManifest:
                raise IngestionError("core ingestion requires a PluginManifest")
            projected_manifest = _snapshot_plugin_manifest(manifest)
            execution_plugin = _PinnedManifestPlugin(plugin, projected_manifest)
            active_coordinator._plugin(execution_plugin)
            plugin_id = str(projected_manifest.plugin_id)
            plugin_version = str(projected_manifest.plugin_version)
            core_api_version = str(projected_manifest.core_api_version)
            capabilities = tuple(
                sorted(str(item) for item in projected_manifest.capabilities)
            )
            schema_versions = (
                "router_dump_analyzer.plugin_schema.v1",
                *(str(item) for item in projected_manifest.forwarding_ir_versions),
            )
            manifest_identity = self._manifest_fingerprint(projected_manifest)
            if self._manifest_fingerprint(manifest) != manifest_identity:
                raise IngestionError(
                    "plug-in manifest changed while it was being registered"
                )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except IngestionError:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "plug-in registration could not resolve required descriptors"
            ) from error
        if _deferred_process_bootstrap is not None:
            verify_package_bytes = _deferred_process_bootstrap.verify_package_bytes
        elif resolved_package_hash is None:
            fingerprint_error: PluginExecutableIdentityError | None = None
            try:
                resolved_package_hash = executable_plugin_fingerprint(plugin)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except PluginExecutableIdentityError as error:
                resolved_package_hash = None
                fingerprint_error = error
            except BaseException as error:
                raise IngestionPipelineError(
                    "plug-in executable identity evaluation failed"
                ) from error
            if resolved_package_hash is None:
                if self._require_executable_identity:
                    detail = (
                        f": {fingerprint_error}"
                        if fingerprint_error is not None
                        else ""
                    )
                    raise ValueError(
                        "plug-in "
                        f"{plugin_id}@{plugin_version} has no bounded "
                        f"executable package identity{detail}"
                    ) from fingerprint_error
                try:
                    resolved_package_hash = manifest_identity
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException as error:
                    raise IngestionPipelineError(
                        "plug-in manifest identity evaluation failed"
                    ) from error
            verify_package_bytes = resolved_package_hash.startswith(
                ("package-sha256:", "module-sha256:")
            )
        else:
            verify_package_bytes = False
        assert resolved_package_hash is not None
        if self._require_executable_identity and resolved_package_hash.startswith(
            "manifest-sha256:"
        ):
            raise ValueError(
                "manifest-only plug-in identity is not permitted by this registry"
            )
        manifest_identity_compatibility = resolved_package_hash.startswith(
            "manifest-sha256:"
        )
        plugin_type = type(plugin)
        if module_target is None:
            try:
                resolved_module_target = (
                    f"{plugin_type.__module__}:{plugin_type.__qualname__}"
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise IngestionPipelineError(
                    "plug-in module identity could not be resolved"
                ) from error
        else:
            resolved_module_target = module_target
        if plugin_process_module_target is not None:
            plugin_loader_kind = (
                "class_constructor"
                if plugin_process_construct_class
                else "module_attribute"
            )
            plugin_process_target = _normalized_explicit_bootstrap_target(
                plugin_process_module_target,
                "plugin_process_module_target",
            )
        else:
            plugin_loader_kind = (
                "class_constructor" if module_target is None else "module_attribute"
            )
            plugin_process_target = (
                _bootstrap_class_target(plugin, "plug-in")
                if module_target is None
                else _normalized_explicit_bootstrap_target(
                    resolved_module_target,
                    "module_target",
                )
            )
        resolved_configuration_digest = (
            configuration_digest
            if configuration_digest is not None
            else _DEFAULT_PLUGIN_CONFIGURATION_DIGEST
        )
        if (
            type(resolved_configuration_digest) is not str
            or len(resolved_configuration_digest) != 71
            or not resolved_configuration_digest.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in resolved_configuration_digest[7:]
            )
        ):
            raise ValueError("configuration_digest must be a lowercase SHA-256 digest")
        resolved_decoder_identity = (
            _snapshot_decoder_identity(decoder_identity)
            if decoder_identity is not None
            else None
        )
        try:
            active_decoder = getattr(active_coordinator, "trace_decoder", None)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "coordinator trace_decoder descriptor could not be resolved"
            ) from error
        decoder_implementation: Any | None = None
        if type(active_decoder) is _IdentityBoundTraceDecoder:
            try:
                decoder_matches = active_decoder.identity == resolved_decoder_identity
                decoder_implementation = active_decoder._implementation()
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise IngestionPipelineError(
                    "coordinator trace_decoder identity could not be compared"
                ) from error
            if not decoder_matches:
                raise ValueError(
                    "coordinator trace_decoder identity conflicts with registration"
                )
        elif (active_decoder is None) != (resolved_decoder_identity is None):
            raise ValueError(
                "decoder_identity is required exactly when the coordinator has "
                "a trace_decoder"
            )
        if (
            active_decoder is not None
            and type(active_decoder) is not _IdentityBoundTraceDecoder
        ):
            assert resolved_decoder_identity is not None
            decoder_implementation = active_decoder
            try:
                active_coordinator.trace_decoder = _IdentityBoundTraceDecoder(
                    active_decoder,
                    _snapshot_decoder_identity(resolved_decoder_identity),
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise IngestionPipelineError(
                    "coordinator trace_decoder binding could not be installed"
                ) from error
        if coordinator_module_target is not None:
            coordinator_loader_kind = "module_attribute"
            coordinator_process_target = _normalized_explicit_bootstrap_target(
                coordinator_module_target,
                "coordinator_module_target",
            )
        elif type(active_coordinator) is IngestionCoordinator:
            coordinator_loader_kind = "core_default"
            coordinator_process_target = None
        else:
            coordinator_loader_kind = "class_constructor"
            coordinator_process_target = _bootstrap_class_target(
                active_coordinator,
                "coordinator",
            )
        if decoder_implementation is None:
            decoder_loader_kind = "none"
            decoder_process_target = None
        elif decoder_module_target is not None:
            decoder_loader_kind = "module_attribute"
            decoder_process_target = _normalized_explicit_bootstrap_target(
                decoder_module_target,
                "decoder_module_target",
            )
        else:
            decoder_loader_kind = "class_constructor"
            decoder_process_target = _bootstrap_class_target(
                decoder_implementation,
                "decoder",
            )
        inline_only_process_compatibility = manifest_identity_compatibility
        process_bootstrap_error: str | None = (
            _MANIFEST_PROCESS_BOOTSTRAP_ERROR
            if manifest_identity_compatibility
            else None
        )
        if manifest_identity_compatibility:
            plugin_target_executable_identity = None
            coordinator_target_executable_identity = None
            decoder_target_executable_identity = None
        elif _deferred_process_bootstrap is not None:
            plugin_target_executable_identity = (
                _deferred_process_bootstrap.plugin_target_executable_identity
            )
            coordinator_target_executable_identity = (
                _deferred_process_bootstrap.coordinator_target_executable_identity
            )
            decoder_target_executable_identity = (
                _deferred_process_bootstrap.decoder_target_executable_identity
            )
        else:
            try:
                declared_code_cache: dict[
                    tuple[str, Path, str], tuple[CodeType, ...]
                ] = {}
                plugin_target_executable_identity = _process_target_executable_identity(
                    plugin_process_target,
                    _process_target_identity_subject(
                        plugin_loader_kind,
                        plugin,
                        label="plug-in",
                    ),
                    target_kind=_ProcessTargetKind.PLUGIN,
                    declared_code_cache=declared_code_cache,
                )
                coordinator_target_executable_identity = (
                    None
                    if coordinator_process_target is None
                    else _process_target_executable_identity(
                        coordinator_process_target,
                        _process_target_identity_subject(
                            coordinator_loader_kind,
                            active_coordinator,
                            label="coordinator",
                        ),
                        target_kind=_ProcessTargetKind.COORDINATOR,
                        declared_code_cache=declared_code_cache,
                    )
                )
                decoder_target_executable_identity = (
                    None
                    if decoder_process_target is None
                    else _process_target_executable_identity(
                        decoder_process_target,
                        _process_target_identity_subject(
                            decoder_loader_kind,
                            decoder_implementation,
                            label="decoder",
                        ),
                        target_kind=_ProcessTargetKind.DECODER,
                        declared_code_cache=declared_code_cache,
                    )
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except _ProcessTargetIdentityUnavailable:
                # A registry-derived package digest remains useful for trusted
                # inline compatibility, but it cannot authorize a child target
                # that was not separately attested. Explicit loader-supplied
                # package hashes and non-identity evaluator faults retain their
                # fail-closed behavior.
                if (
                    self._require_executable_identity
                    or selected_package_hash is not None
                    or not verify_package_bytes
                ):
                    raise
                plugin_target_executable_identity = None
                coordinator_target_executable_identity = None
                decoder_target_executable_identity = None
                inline_only_process_compatibility = True
                process_bootstrap_error = _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR
        ingestion_limit_values, artifact_limit_values = (
            _snapshot_ingestion_limit_bootstrap(active_coordinator)
        )
        if (
            not inline_only_process_compatibility
            and resolved_configuration_digest != _DEFAULT_PLUGIN_CONFIGURATION_DIGEST
        ):
            missing_targets: list[str] = []
            if plugin_process_module_target is None or plugin_process_construct_class:
                missing_targets.append("plugin_process_module_target")
            if (
                coordinator is not None
                and type(active_coordinator) is not IngestionCoordinator
                and coordinator_module_target is None
            ):
                missing_targets.append("coordinator_module_target")
            if decoder_implementation is not None and decoder_module_target is None:
                missing_targets.append("decoder_module_target")
            if missing_targets:
                process_bootstrap_error = (
                    "configured/stateful PROCESS registration requires explicit "
                    "module-level process targets: " + ", ".join(missing_targets)
                )
        record = RegisteredPlugin(
            plugin=plugin,
            coordinator=active_coordinator,
            package_hash=resolved_package_hash,
            verify_package_bytes=verify_package_bytes,
            instance_id=_bounded_identifier(
                (instance_id if instance_id is not None else f"{plugin_id}.default"),
                "instance_id",
                256,
            ),
            distribution_name=_bounded_identifier(
                (distribution_name if distribution_name is not None else plugin_id),
                "distribution_name",
                256,
            ),
            distribution_version=_bounded_identifier(
                (
                    distribution_version
                    if distribution_version is not None
                    else plugin_version
                ),
                "distribution_version",
                128,
            ),
            entry_point_name=_bounded_identifier(
                (entry_point_name if entry_point_name is not None else plugin_id),
                "entry_point_name",
                256,
            ),
            module_target=_bounded_identifier(
                resolved_module_target,
                "module_target",
                512,
            ),
            configuration_digest=resolved_configuration_digest,
            core_api_version=core_api_version,
            capabilities=capabilities,
            schema_versions=schema_versions,
            timeline_time_basis=projected_manifest.timeline_time_basis.value,
            timeline_clock_domain=projected_manifest.timeline_clock_domain,
            decoder_identity=resolved_decoder_identity,
            _plugin_id_snapshot=plugin_id,
            _plugin_version_snapshot=plugin_version,
            _manifest_identity_snapshot=manifest_identity,
            _execution_plugin=execution_plugin,
            _decoder_implementation_snapshot=decoder_implementation,
            _ingestion_limit_values_snapshot=ingestion_limit_values,
            _artifact_limit_values_snapshot=artifact_limit_values,
            _process_bootstrap_error=process_bootstrap_error,
        )
        # Validate the same artifact projection used later by execution plans
        # now, at the registration boundary.
        PluginArtifactIdentity(
            distribution_name=record.distribution_name,
            distribution_version=record.distribution_version,
            package_hash=record.package_hash,
            entry_point_name=record.entry_point_name,
            module_target=record.module_target,
        )
        if inline_only_process_compatibility:
            record = replace(
                record,
                _registered_execution_identity_snapshot=(
                    record.registered_execution_identity
                ),
            )
        else:
            assert plugin_target_executable_identity is not None
            process_bootstrap = _PluginProcessBootstrap(
                schema_version="router_dump_analyzer.plugin_process_bootstrap.v2",
                plugin_loader_kind=plugin_loader_kind,
                plugin_target=plugin_process_target,
                plugin_target_executable_identity=(plugin_target_executable_identity),
                coordinator_loader_kind=coordinator_loader_kind,
                coordinator_target=coordinator_process_target,
                coordinator_target_executable_identity=(
                    coordinator_target_executable_identity
                ),
                decoder_loader_kind=decoder_loader_kind,
                decoder_target=decoder_process_target,
                decoder_target_executable_identity=(decoder_target_executable_identity),
                ingestion_limit_values=ingestion_limit_values,
                artifact_limit_values=artifact_limit_values,
                package_hash=record.package_hash,
                verify_package_bytes=record.verify_package_bytes,
                instance_id=record.instance_id,
                distribution_name=record.distribution_name,
                distribution_version=record.distribution_version,
                entry_point_name=record.entry_point_name,
                module_target=record.module_target,
                configuration_digest=record.configuration_digest,
                decoder_identity_values=(
                    (
                        record.decoder_identity.decoder_id,
                        record.decoder_identity.decoder_version,
                        record.decoder_identity.executable_digest,
                    )
                    if record.decoder_identity is not None
                    else None
                ),
                # This field attests the material after its non-recursive
                # projection has been hashed; it is deliberately excluded from
                # that projection.
                expected_registered_execution_identity="",
            )
            record = replace(record, _process_bootstrap=process_bootstrap)
            registered_execution_identity = record.registered_execution_identity
            record = replace(
                record,
                _registered_execution_identity_snapshot=registered_execution_identity,
                _process_bootstrap=replace(
                    process_bootstrap,
                    expected_registered_execution_identity=(
                        registered_execution_identity
                    ),
                ),
            )
        if _deferred_process_bootstrap is not None and (
            record._process_bootstrap != _deferred_process_bootstrap
            or record.registered_execution_identity
            != _deferred_process_bootstrap.expected_registered_execution_identity
        ):
            raise IngestionPipelineError(
                "child plug-in bootstrap does not match the registered execution identity"
            )
        key = (
            record.plugin_id,
            record.plugin_version,
            record.instance_id,
            record.registered_execution_identity,
        )
        with self._mutation_lock:
            if self._sealed:
                raise RuntimeError("plug-in registry is sealed")
            if key in self._plugins:
                raise ValueError(
                    "duplicate registered plug-in execution coordinate "
                    f"{record.plugin_id}@{record.plugin_version} "
                    f"instance {record.instance_id}"
                )
            self._plugins[key] = record
            if len(self._plugins) > MAX_PLUGIN_CANDIDATES:
                self._plugins.pop(key, None)
                raise ValueError(
                    f"at most {MAX_PLUGIN_CANDIDATES} plug-ins may be registered"
                )
        return record

    def get(
        self,
        plugin_id: str,
        plugin_version: str | None = None,
        *,
        instance_id: str | None = None,
        registered_execution_identity: str | None = None,
    ) -> RegisteredPlugin:
        """Resolve one registered execution, rejecting every ambiguity.

        The two positional identity fields retain the legacy unambiguous lookup
        contract.  Durable callers bind the configured execution with either
        or both keyword-only coordinates.
        """

        matches = [
            record
            for record in self._plugins.values()
            if record.plugin_id == plugin_id
            and (plugin_version is None or record.plugin_version == plugin_version)
            and (instance_id is None or record.instance_id == instance_id)
            and (
                registered_execution_identity is None
                or record.registered_execution_identity == registered_execution_identity
            )
        ]
        if len(matches) != 1:
            raise KeyError(
                (
                    plugin_id,
                    plugin_version,
                    instance_id,
                    registered_execution_identity,
                )
            )
        return matches[0]

    def records(self) -> tuple[RegisteredPlugin, ...]:
        with self._mutation_lock:
            return tuple(self._plugins[key] for key in sorted(self._plugins))

    def _sealed_snapshot(self) -> PluginRegistry:
        """Freeze the exact current allowlist for one authority owner."""

        with self._mutation_lock:
            snapshot = PluginRegistry(
                require_executable_identity=self._require_executable_identity
            )
            snapshot._plugins = dict(self._plugins)
            snapshot._sealed = True
        return snapshot

    def process_bootstraps(self) -> tuple[_PluginProcessBootstrap, ...]:
        """Return the inert spawn descriptors for the complete allowlist."""

        return tuple(record.process_bootstrap for record in self.records())

    def get_by_execution_identity(
        self,
        instance_id: str,
        registered_execution_identity: str,
    ) -> RegisteredPlugin:
        """Resolve one exact configured instance without first-match behavior."""

        selected_instance = _bounded_identifier(instance_id, "instance_id", 256)
        selected_identity = _bounded_identifier(
            registered_execution_identity,
            "registered_execution_identity",
            71,
        )
        matches = tuple(
            record
            for record in self.records()
            if record.instance_id == selected_instance
            and record.registered_execution_identity == selected_identity
        )
        if len(matches) != 1:
            raise KeyError((selected_instance, selected_identity))
        return matches[0]

    @staticmethod
    def revalidate_executable_identity(record: RegisteredPlugin) -> None:
        """Re-hash registry-derived executable bytes immediately before use."""

        if not record.verify_package_bytes:
            return
        try:
            current = executable_plugin_fingerprint(record.plugin)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PluginExecutableIdentityError as error:
            raise IngestionPipelineError(
                "registered plug-in executable can no longer be fingerprinted"
            ) from error
        except BaseException as error:
            raise IngestionPipelineError(
                "registered plug-in executable identity evaluation failed"
            ) from error
        if current != record.package_hash:
            raise IngestionPipelineError(
                "registered plug-in executable bytes changed after registration: "
                f"{record.plugin_id}@{record.plugin_version}"
            )

    @classmethod
    def revalidate_manifest_identity(cls, record: RegisteredPlugin) -> None:
        """Reject mutation of any manifest coordinate frozen for execution."""

        expected = record._manifest_identity_snapshot
        if expected is None:
            # Compatibility for direct RegisteredPlugin construction in
            # boundary tests; registry-created records always carry a snapshot.
            return
        # Preserve the declared plug-in receiver type at this trust boundary.
        # Besides improving static checking, this keeps descriptor execution
        # visible to the repository-wide derived boundary census.
        plugin: AnalyzerPlugin = record.plugin
        try:
            manifest = plugin.manifest
            if type(manifest) is not PluginManifest:
                raise TypeError("registered plug-in manifest is invalid")
            current = cls._manifest_fingerprint(manifest)
            execution_plugin = record.execution_plugin
            if (
                type(execution_plugin) is not _PinnedManifestPlugin
                or execution_plugin.original is not record.plugin
                or cls._manifest_fingerprint(execution_plugin.manifest) != expected
            ):
                raise TypeError("registered execution manifest is invalid")
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "registered plug-in manifest identity cannot be revalidated"
            ) from error
        if current != expected:
            raise IngestionPipelineError(
                "registered plug-in manifest changed after registration: "
                f"{record.plugin_id}@{record.plugin_version}"
            )

    @classmethod
    @_analysis_load_stage(AnalysisLoadStage.VALIDATING_PROVIDERS)
    def revalidate_registered_identity(cls, record: RegisteredPlugin) -> None:
        cls.revalidate_executable_identity(record)
        cls.revalidate_manifest_identity(record)
        _registered_ingestion_limits(record)
        try:
            active_decoder = getattr(record.coordinator, "trace_decoder", None)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "registered trace decoder binding could not be revalidated"
            ) from error
        if record.decoder_identity is None:
            decoder_matches = (
                active_decoder is None
                and record._decoder_implementation_snapshot is None
            )
        else:
            if type(active_decoder) is not _IdentityBoundTraceDecoder:
                decoder_matches = False
            else:
                try:
                    decoder_matches = active_decoder._matches(
                        record._decoder_implementation_snapshot,
                        record.decoder_identity,
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException as error:
                    raise IngestionPipelineError(
                        "registered trace decoder identity could not be compared"
                    ) from error
        if not decoder_matches:
            raise IngestionPipelineError(
                "registered trace decoder binding changed after registration"
            )
        expected_execution_identity = record._registered_execution_identity_snapshot
        if expected_execution_identity is not None:
            try:
                current_execution_identity = record.registered_execution_identity
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise IngestionPipelineError(
                    "registered execution identity could not be revalidated"
                ) from error
            if current_execution_identity != expected_execution_identity:
                raise IngestionPipelineError(
                    "registered execution identity changed after registration"
                )
        _revalidate_process_target_executable_identities(record)

    def require_executable_identities(self) -> None:
        """Reject compatibility records that cannot authorize durable execution."""

        manifest_only = tuple(
            f"{record.plugin_id}@{record.plugin_version}"
            for record in self.records()
            if record.package_hash.startswith("manifest-sha256:")
        )
        if manifest_only:
            raise ValueError(
                "durable ingestion requires executable plug-in identities; "
                "manifest-only identities: " + ", ".join(manifest_only)
            )
        for record in self.records():
            if (
                not _registered_plugin_is_process_capable(record)
                and record._process_bootstrap_error is not None
                and "requires explicit module-level process targets"
                in record._process_bootstrap_error
            ):
                raise ValueError(record._process_bootstrap_error)
        _require_no_inline_only_plugin_compatibility(
            self.records(),
            boundary="durable ingestion requires executable plug-in identities",
        )

    def fingerprint(self) -> str:
        """Return a deterministic identity for the complete allowlisted set."""

        material = {
            "schema_version": "router_dump_analyzer.plugin_registry.v2",
            "plugins": [
                {
                    "plugin_id": record.plugin_id,
                    "plugin_version": record.plugin_version,
                    "package_hash": record.package_hash,
                    "registered_execution_identity": (
                        record.registered_execution_identity
                    ),
                }
                for record in self.records()
            ],
        }
        return (
            "sha256:"
            + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
        )

    def probe(
        self,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> tuple[PluginCandidate, ...]:
        candidates: list[PluginCandidate] = []
        for record in self.records():
            self.revalidate_registered_identity(record)
            try:
                registered_limits = _registered_ingestion_limits(record)
                with CoreArtifactReader(
                    input_path,
                    node_hint=node_hint,
                    metadata=metadata,
                    limits=registered_limits.artifact_limits,
                ) as reader:
                    report = validate_probe_report(
                        record.execution_plugin.probe(reader.inventory),
                        artifact_ids={
                            artifact.artifact_id
                            for artifact in reader.inventory.artifacts
                        },
                        maximum_diagnostics=(registered_limits.max_diagnostics),
                        maximum_evidence_items=(
                            registered_limits.max_evidence_per_output
                        ),
                    )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001, S112 - isolated plug-in probe.
                # Probe isolation is fail-closed per plug-in: an invalid
                # candidate is absent and cannot block other allowlisted
                # candidates. Full diagnostics are emitted during ingestion.
                continue
            if report.result is None or any(
                not diagnostic.recoverable for diagnostic in report.diagnostics
            ):
                continue
            try:
                probe_result = validate_probe_result(report.result)
                match_kind = ProbeMatchKind(probe_result.match_kind)
            except ValueError:
                continue
            if match_kind is ProbeMatchKind.NONE:
                continue
            candidates.append(
                PluginCandidate(
                    plugin_id=record.plugin_id,
                    plugin_version=record.plugin_version,
                    package_hash=record.package_hash,
                    instance_id=record.instance_id,
                    registered_execution_identity=(
                        record.registered_execution_identity
                    ),
                    confidence=float(probe_result.confidence),
                    match_kind=match_kind.value,
                    reasons=probe_result.reasons,
                    detected_platform=probe_result.detected_platform,
                    detected_software_version=(probe_result.detected_software_version),
                )
            )
        return tuple(
            sorted(
                candidates,
                key=lambda item: (
                    -item.confidence,
                    item.plugin_id,
                    item.plugin_version,
                    item.package_hash,
                    item.registered_execution_identity,
                ),
            )
        )

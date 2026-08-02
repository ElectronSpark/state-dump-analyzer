"""Small, dependency-free validation entry point for plug-in authors.

This module intentionally validates the cold-start authoring path rather than
trying to execute a complete analysis job. Product conformance still requires
the synthetic corpus described in ``docs/plugin-contract.md``.
"""

from __future__ import annotations

import argparse
import mimetypes
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .plugin_api import (
    CORE_PLUGIN_API_VERSION,
    INPUT_PARSER_HOOKS,
    PLUGIN_CAPABILITY_HOOKS,
    PLUGIN_ENTRY_POINT_GROUP,
    AnalyzerPluginBase,
    ArtifactInfo,
    DiagnosticOrigin,
    DiagnosticStage,
    DumpInventory,
    InputSpec,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ReconstructionSupport,
    validate_plugin_diagnostic,
    validate_probe_report,
)
from .plugin_loading import load_plugin_entry_point
from .public_text import bounded_public_error_detail

_MAX_DISCOVERY_OUTPUTS = 1_000
_MAX_PUBLIC_DIAGNOSTIC_CHARACTERS = 1_024


@dataclass(frozen=True, slots=True)
class PluginValidationResult:
    """One bounded validation report suitable for CLI and test use."""

    plugin_id: str
    errors: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


def _standard_capabilities(manifest: PluginManifest) -> set[PluginCapability]:
    capabilities: set[PluginCapability] = set()
    for value in manifest.capabilities:
        try:
            capabilities.add(PluginCapability(value))
        except ValueError:
            continue
    return capabilities


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _public_dynamic_text(value: object, *, fallback: str) -> str:
    """Project one plug-in/caller-owned fragment for public CLI display.

    Closed validator prose stays outside this helper so useful stable context
    is never replaced merely because one untrusted fragment is unsafe.
    """

    try:
        rendered = value if type(value) is str else str(value)
    except Exception:  # noqa: BLE001 - hostile diagnostic rendering is data.
        return fallback
    return str(
        bounded_public_error_detail(
            rendered,
            fallback=fallback,
            maximum_characters=_MAX_PUBLIC_DIAGNOSTIC_CHARACTERS,
        )
    )


def _public_dynamic_repr(value: object, *, fallback: str) -> str:
    try:
        rendered = repr(value)
    except Exception:  # noqa: BLE001 - hostile diagnostic rendering is data.
        return fallback
    return _public_dynamic_text(rendered, fallback=fallback)


def _public_exception_summary(error: Exception) -> str:
    try:
        summary = f"{type(error).__name__}: {error}"
    except Exception:  # noqa: BLE001 - hostile exception rendering is data.
        summary = ""
    return _public_dynamic_text(
        summary,
        fallback="plug-in exception details unavailable",
    )


def _bounded_outputs(
    values: Iterable[InputSpec | PluginDiagnostic],
) -> tuple[tuple[InputSpec | PluginDiagnostic, ...], bool]:
    outputs = tuple(islice(values, _MAX_DISCOVERY_OUTPUTS + 1))
    return outputs[:_MAX_DISCOVERY_OUTPUTS], len(outputs) > _MAX_DISCOVERY_OUTPUTS


def _validate_inventory_calls(
    plugin: Any,
    inventory: DumpInventory,
    *,
    label: str,
    capabilities: set[PluginCapability],
    errors: list[str],
    warnings: list[str],
    allow_legacy_input_dispatch: bool,
    require_match: bool,
) -> None:
    probe = getattr(plugin, "probe", None)
    if callable(probe):
        try:
            report = probe(inventory)
        except Exception as error:  # noqa: BLE001 - report plug-in boundary errors.
            errors.append(
                f"probe() must handle {label}; "
                f"raised {_public_exception_summary(error)}"
            )
        else:
            inventory_artifact_ids = {
                artifact.artifact_id for artifact in inventory.artifacts
            }
            try:
                valid_report = validate_probe_report(
                    report,
                    artifact_ids=inventory_artifact_ids,
                )
            except ValueError as error:
                valid_report = None
                detail = _public_dynamic_text(
                    error,
                    fallback="invalid report details unavailable",
                )
                errors.append(f"probe({label}) returned an invalid report: {detail}")
            if valid_report is not None and require_match and (
                valid_report.result is None
                or valid_report.result.match_kind == ProbeMatchKind.NONE
            ):
                errors.append(
                    f"probe({label}) returned no match; use a representative "
                    "author fixture and metadata"
                )

    locate_inputs = getattr(plugin, "locate_inputs", None)
    if not callable(locate_inputs):
        return
    try:
        outputs, truncated = _bounded_outputs(locate_inputs(inventory))
    except Exception as error:  # noqa: BLE001 - report plug-in boundary errors.
        errors.append(
            f"locate_inputs() must handle {label}; "
            f"raised {_public_exception_summary(error)}"
        )
        return

    if truncated:
        errors.append(
            "locate_inputs() emitted more than "
            f"{_MAX_DISCOVERY_OUTPUTS} records for {label}"
        )

    input_specs = tuple(output for output in outputs if isinstance(output, InputSpec))
    if require_match and not input_specs:
        errors.append(
            f"locate_inputs({label}) selected no InputSpec; use a representative "
            "author fixture"
        )

    inventory_artifact_ids = {artifact.artifact_id for artifact in inventory.artifacts}
    for index, output in enumerate(outputs):
        if type(output) is PluginDiagnostic:
            try:
                validate_plugin_diagnostic(
                    output,
                    label=f"locate_inputs({label}) output {index}",
                    expected_origin=DiagnosticOrigin.PLUGIN,
                    expected_stage=DiagnosticStage.LOCATE,
                    artifact_ids=inventory_artifact_ids,
                )
            except ValueError as error:
                errors.append(
                    _public_dynamic_text(
                        error,
                        fallback="invalid plug-in diagnostic details unavailable",
                    )
                )
            continue
        if not isinstance(output, InputSpec):
            errors.append(
                f"locate_inputs({label}) output {index} is not "
                "InputSpec or PluginDiagnostic"
            )
            continue
        if not output.artifact_ids:
            errors.append(f"InputSpec output {index} has no artifact_ids")
        elif len(output.artifact_ids) != len(set(output.artifact_ids)):
            errors.append(f"InputSpec output {index} repeats an artifact_id")
        if unknown := set(output.artifact_ids) - inventory_artifact_ids:
            errors.append(
                f"InputSpec output {index} references {len(unknown)} artifact(s) "
                f"outside {label}"
            )
        for field_name in ("role", "node", "layer", "parser_id"):
            if not _has_text(getattr(output, field_name)):
                errors.append(
                    f"InputSpec output {index} {field_name} must be a non-empty string"
                )
        if output.parser_kind is None:
            message = (
                f"InputSpec output {index} has no parser_kind; new plug-ins "
                "must use InputParserKind"
            )
            if allow_legacy_input_dispatch:
                warnings.append(message)
            else:
                errors.append(message)
            continue
        capability = output.required_capability
        assert capability is not None
        if capability not in capabilities:
            errors.append(
                f"InputSpec output {index} dispatches to "
                f"{INPUT_PARSER_HOOKS[output.parser_kind]}() but the manifest "
                f"does not declare {capability.value!r}"
            )


def validate_plugin(
    plugin: Any,
    *,
    inventory: DumpInventory | None = None,
    allow_legacy_input_dispatch: bool = False,
) -> PluginValidationResult:
    """Validate one loaded entry-point object without device-specific knowledge."""

    errors: list[str] = []
    warnings: list[str] = []
    manifest = getattr(plugin, "manifest", None)
    if not isinstance(manifest, PluginManifest):
        return PluginValidationResult(
            plugin_id="<unknown>",
            errors=("entry point must resolve to an object with a PluginManifest",),
        )

    plugin_id = (
        _public_dynamic_text(
            manifest.plugin_id,
            fallback="<invalid-plugin-id>",
        )
        if _has_text(manifest.plugin_id)
        else "<invalid-plugin-id>"
    )
    if not _has_text(manifest.plugin_id):
        errors.append("manifest.plugin_id must be a non-empty string")
    if not _has_text(manifest.plugin_version):
        errors.append("manifest.plugin_version must be a non-empty string")
    if manifest.core_api_version != CORE_PLUGIN_API_VERSION:
        supplied_version = _public_dynamic_repr(
            manifest.core_api_version,
            fallback="<unavailable>",
        )
        errors.append(
            "manifest.core_api_version "
            f"{supplied_version} does not match core API "
            f"{CORE_PLUGIN_API_VERSION!r}"
        )
    if (
        not isinstance(manifest.supported_platforms, tuple)
        or not manifest.supported_platforms
        or any(not _has_text(item) for item in manifest.supported_platforms)
    ):
        errors.append("manifest.supported_platforms must contain at least one platform")
    if not _has_text(manifest.supported_software_versions):
        errors.append(
            "manifest.supported_software_versions must be a non-empty string"
        )
    try:
        ReconstructionSupport(manifest.reconstruction_default)
    except (TypeError, ValueError):
        errors.append("manifest.reconstruction_default is not supported")

    for hook_name in ("describe", "probe", "locate_inputs"):
        if not callable(getattr(plugin, hook_name, None)):
            errors.append(f"required hook {hook_name}() is missing")

    capabilities = _standard_capabilities(manifest)
    for capability, hook_names in PLUGIN_CAPABILITY_HOOKS.items():
        for hook_name in hook_names:
            hook = getattr(plugin, hook_name, None)
            if capability in capabilities and not callable(hook):
                errors.append(
                    f"capability {capability.value!r} requires {hook_name}()"
                )
                continue
            if (
                capability in capabilities
                and isinstance(plugin, AnalyzerPluginBase)
                and getattr(type(plugin), hook_name, None)
                is getattr(AnalyzerPluginBase, hook_name)
            ):
                errors.append(
                    f"capability {capability.value!r} requires an override of "
                    f"{hook_name}()"
                )

    describe = getattr(plugin, "describe", None)
    if callable(describe):
        try:
            first_schema = describe()
            second_schema = describe()
        except Exception as error:  # noqa: BLE001 - report plug-in boundary errors.
            errors.append(f"describe() raised {_public_exception_summary(error)}")
        else:
            if not isinstance(first_schema, PluginSchema):
                errors.append("describe() must return PluginSchema")
            elif first_schema != second_schema:
                errors.append("describe() must be deterministic")

    empty_inventory = DumpInventory(node_hint=None, artifacts=())
    _validate_inventory_calls(
        plugin,
        empty_inventory,
        label="an empty safe inventory",
        capabilities=capabilities,
        errors=errors,
        warnings=warnings,
        allow_legacy_input_dispatch=allow_legacy_input_dispatch,
        require_match=False,
    )
    if inventory is not None:
        _validate_inventory_calls(
            plugin,
            inventory,
            label="the author fixture inventory",
            capabilities=capabilities,
            errors=errors,
            warnings=warnings,
            allow_legacy_input_dispatch=allow_legacy_input_dispatch,
            require_match=True,
        )

    custom_capabilities = sorted(
        _public_dynamic_text(
            value,
            fallback="<unavailable custom capability>",
        )
        for value in manifest.capabilities
        if not isinstance(value, PluginCapability)
    )
    if custom_capabilities:
        warnings.append(
            "custom capabilities are not interpreted by the core validator: "
            + ", ".join(custom_capabilities)
        )

    return PluginValidationResult(
        plugin_id=plugin_id,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _entry_points() -> tuple[metadata.EntryPoint, ...]:
    return tuple(
        metadata.entry_points().select(group=PLUGIN_ENTRY_POINT_GROUP)
    )


def load_entry_point(name: str) -> Any:
    """Load exactly one installed analyzer plug-in by entry-point name."""

    return load_plugin_entry_point(name, candidates=_entry_points())


def _inventory_from_arguments(
    artifact_paths: list[str],
    *,
    node_hint: str | None,
    metadata_items: list[str],
) -> DumpInventory | None:
    if not artifact_paths and node_hint is None and not metadata_items:
        return None

    inventory_metadata: dict[str, str] = {}
    for item in metadata_items:
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise ValueError("--metadata values must use non-empty KEY=VALUE syntax")
        inventory_metadata[key] = value

    artifacts: list[ArtifactInfo] = []
    for index, raw_path in enumerate(artifact_paths):
        path = Path(raw_path).resolve()
        if not path.is_file():
            raise ValueError(f"--artifact is not a readable file: {raw_path}")
        size = path.stat().st_size
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        artifacts.append(
            ArtifactInfo(
                artifact_id=uuid5(NAMESPACE_URL, path.as_uri()),
                logical_path=PurePosixPath("author-fixture", str(index), path.name),
                parent_artifact_id=None,
                media_type=media_type,
                compressed_size=size,
                uncompressed_size=size,
                sha256=None,
            )
        )
    return DumpInventory(
        node_hint=node_hint,
        artifacts=tuple(artifacts),
        metadata=inventory_metadata,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-plugin-validate",
        description="Validate an installed router dump analyzer plug-in.",
    )
    parser.add_argument(
        "entry_point",
        nargs="?",
        help=f"name in the {PLUGIN_ENTRY_POINT_GROUP!r} entry-point group",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list installed analyzer plug-in entry points and exit",
    )
    parser.add_argument(
        "--allow-legacy-input-dispatch",
        action="store_true",
        help="warn instead of failing when an InputSpec omits parser_kind",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="PATH",
        help="add a representative file to the author fixture inventory",
    )
    parser.add_argument(
        "--node-hint",
        help="node hint supplied with the author fixture inventory",
    )
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="add representative inventory metadata; may be repeated",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.list:
        for entry_point in sorted(_entry_points(), key=lambda item: item.name):
            distribution = (
                entry_point.dist.name
                if entry_point.dist is not None
                else "<unknown distribution>"
            )
            name = _public_dynamic_text(
                entry_point.name,
                fallback="<invalid entry point>",
            )
            public_distribution = _public_dynamic_text(
                distribution,
                fallback="<invalid distribution>",
            )
            target = _public_dynamic_text(
                entry_point.value,
                fallback="<invalid target>",
            )
            print(f"{name}\t{public_distribution}\t{target}")
        return 0
    if not arguments.entry_point:
        _parser().error("provide ENTRY_POINT or use --list")

    try:
        plugin = load_entry_point(arguments.entry_point)
        inventory = _inventory_from_arguments(
            arguments.artifact,
            node_hint=arguments.node_hint,
            metadata_items=arguments.metadata,
        )
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        detail = _public_dynamic_text(
            error,
            fallback="plug-in validation request failed",
        )
        print(f"ERROR: {detail}")
        return 2

    result = validate_plugin(
        plugin,
        inventory=inventory,
        allow_legacy_input_dispatch=arguments.allow_legacy_input_dispatch,
    )
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    for validation_error in result.errors:
        print(f"ERROR: {validation_error}")
    if result.ok:
        print(f"OK: {result.plugin_id}")
        return 0
    print(f"FAILED: {result.plugin_id} ({len(result.errors)} error(s))")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

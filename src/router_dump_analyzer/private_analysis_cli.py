"""Scriptable lifecycle client for local private-analysis execution.

The command composes the same durable application service used by HTTP.  It
does not start ingestion workers or a web server, and it accepts the
proprietary query only inside a bounded request document rather than in the
process command line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Never, TextIO

from .cli import _add_repeatable_plugin_allowlist_arguments
from .control_plane import ControlPlane
from .ingestion_pipeline import PluginRegistry
from .plugin_composition_deployment import (
    _control_plane_composition_options,
    PluginCompositionDeploymentContext,
    load_plugin_composition_deployment,
)
from .plugin_loading import (
    LoadedPlugin,
    load_plugin_entry_point,
    load_plugin_module,
    loaded_entry_point,
    loaded_module,
)
from .private_analysis import EvidenceScope
from .private_analysis._wire import reject_duplicate_json_object_pairs
from .private_analysis_application_wire import (
    PrivateAnalysisApplicationWireLimitError,
    PrivateAnalysisApplicationWireRequestError,
    parse_private_analysis_request_spec,
    private_analysis_report_to_wire,
    private_analysis_run_to_wire,
    private_analysis_runner_to_wire,
)
from .private_analysis_deployment import (
    PrivateAnalysisDeploymentContext,
    load_private_analysis_deployment,
)
from .private_analysis_promotion import (
    ProposalReviewError,
    ProposalReviewNotFoundError,
)
from .private_analysis_promotion_wire import (
    ProposalReviewWireError,
    parse_proposal_review_request,
    proposal_review_decision_to_wire,
)
from .private_analysis_service import PrivateAnalysisServiceError
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .value_core import parse_canonical_decimal_integer

PRIVATE_ANALYSIS_CLI_RESULT_VERSION: Final = (
    "router_dump_analyzer.private_analysis_cli_result.v1"
)
MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES: Final[int] = 1 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_CLI_LIST_LIMIT: Final = 1_000
MAX_PRIVATE_ANALYSIS_CLI_ID_CHARACTERS: Final = 256
_MAX_SIGNED_64: Final = (1 << 63) - 1

EXIT_SUCCESS: Final = 0
EXIT_FAILURE: Final = 1
EXIT_ADVISORY_ERROR: Final = 2


class PrivateAnalysisCliOperation(StrEnum):
    RUNNERS = "runners"
    CREATE = "create"
    GET = "get"
    LIST = "list"
    EXECUTE = "execute"
    CANCEL = "cancel"
    RECOVER_EXPIRED = "recover-expired"
    REPORT = "report"
    RUN = "run"
    DECIDE_PROPOSAL = "decide-proposal"
    LIST_DECISIONS = "list-decisions"
    GET_DECISION = "get-decision"
    RECOVER_DECISION = "recover-decision"


class PrivateAnalysisCliInputError(ValueError):
    """A bounded command or request-document value is invalid."""


class _ClosedArgumentParser(argparse.ArgumentParser):
    """Turn invalid command lines into the CLI's closed JSON error boundary."""

    def error(self, message: str) -> Never:
        del message
        raise PrivateAnalysisCliInputError(
            "private-analysis command arguments are invalid"
        )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCliConfiguration:
    state_dir: Path
    tenant_id: str
    project_id: str
    workspace_id: str
    plugin_names: tuple[str, ...]
    plugin_modules: tuple[str, ...]
    deployment_module: str
    operation: PrivateAnalysisCliOperation
    request_path: Path | None = None
    actor_id: str | None = None
    idempotency_key: str | None = None
    run_id: str | None = None
    execution_id: str | None = None
    proposal_id: str | None = None
    decision_id: str | None = None
    expected_version: int | None = None
    limit: int = 100
    offset: int = 0
    after_created_at_ns: int | None = None
    after_run_id: str | None = None
    output_path: Path | None = None
    pretty: bool = False
    plugin_deployment_module: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state_dir, Path):
            raise TypeError("state_dir must be a Path")
        if type(self.operation) is not PrivateAnalysisCliOperation:
            raise TypeError("operation must be PrivateAnalysisCliOperation")
        if (
            type(self.plugin_names) is not tuple
            or type(self.plugin_modules) is not tuple
        ):
            raise TypeError("plug-in allowlists must be tuples")
        if (
            sum(
                (
                    bool(self.plugin_names),
                    bool(self.plugin_modules),
                    self.plugin_deployment_module is not None,
                )
            )
            != 1
        ):
            raise ValueError(
                "configure exactly one plug-in allowlist or composition deployment"
            )
        for values in (self.plugin_names, self.plugin_modules):
            for plugin_selector in values:
                _bounded_cli_text(plugin_selector, "plug-in selector")
        if self.plugin_deployment_module is not None:
            _bounded_cli_text(
                self.plugin_deployment_module,
                "plug-in deployment module",
            )
        _bounded_cli_text(self.tenant_id, "tenant")
        _bounded_cli_text(self.project_id, "project")
        _bounded_cli_text(self.workspace_id, "workspace")
        _bounded_cli_text(self.deployment_module, "deployment module")
        if type(self.pretty) is not bool:
            raise TypeError("pretty must be a boolean")
        if self.output_path is not None and not isinstance(self.output_path, Path):
            raise TypeError("output_path must be a Path or None")
        for optional_value, label in (
            (self.actor_id, "actor"),
            (self.idempotency_key, "idempotency_key"),
            (self.run_id, "run_id"),
            (self.execution_id, "execution_id"),
            (self.proposal_id, "proposal_id"),
            (self.decision_id, "decision_id"),
            (self.after_run_id, "after_run_id"),
        ):
            if optional_value is not None:
                _bounded_cli_text(optional_value, label)
        if (self.after_created_at_ns is None) is not (self.after_run_id is None):
            raise ValueError("run list cursor fields must be provided together")
        if type(self.limit) is not int or not 1 <= self.limit <= (
            MAX_PRIVATE_ANALYSIS_CLI_LIST_LIMIT
        ):
            raise ValueError("limit is outside its bounded domain")
        if type(self.offset) is not int or not 0 <= self.offset <= _MAX_SIGNED_64:
            raise ValueError("offset is outside its bounded domain")
        if self.after_created_at_ns is not None and (
            type(self.after_created_at_ns) is not int
            or not 0 <= self.after_created_at_ns <= _MAX_SIGNED_64
        ):
            raise ValueError("after_created_at_ns is outside its bounded domain")
        if self.expected_version is not None and (
            type(self.expected_version) is not int
            or not 1 <= self.expected_version <= _MAX_SIGNED_64
        ):
            raise ValueError("expected_version is outside its bounded domain")
        create_like = self.operation in {
            PrivateAnalysisCliOperation.CREATE,
            PrivateAnalysisCliOperation.RUN,
        }
        if create_like and (
            self.request_path is None
            or self.actor_id is None
            or self.idempotency_key is None
        ):
            raise ValueError(
                "create operations require request, actor, and idempotency"
            )
        if self.request_path is not None and not isinstance(self.request_path, Path):
            raise TypeError("request_path must be a Path or None")
        if (
            self.operation
            in {
                PrivateAnalysisCliOperation.GET,
                PrivateAnalysisCliOperation.EXECUTE,
                PrivateAnalysisCliOperation.CANCEL,
                PrivateAnalysisCliOperation.REPORT,
                PrivateAnalysisCliOperation.DECIDE_PROPOSAL,
                PrivateAnalysisCliOperation.LIST_DECISIONS,
                PrivateAnalysisCliOperation.GET_DECISION,
                PrivateAnalysisCliOperation.RECOVER_DECISION,
            }
            and self.run_id is None
        ):
            raise ValueError("the selected operation requires run_id")
        if self.operation in {
            PrivateAnalysisCliOperation.EXECUTE,
            PrivateAnalysisCliOperation.CANCEL,
        } and (self.actor_id is None or self.expected_version is None):
            raise ValueError(
                "the selected mutation requires actor and expected_version"
            )
        if (
            self.operation is PrivateAnalysisCliOperation.RECOVER_EXPIRED
            and self.actor_id is None
        ):
            raise ValueError("expired-run recovery requires actor")
        if self.operation is PrivateAnalysisCliOperation.DECIDE_PROPOSAL and (
            self.proposal_id is None
            or self.actor_id is None
            or self.expected_version is None
            or self.idempotency_key is None
            or self.request_path is None
        ):
            raise ValueError("proposal decision configuration is incomplete")
        if (
            self.operation
            in {
                PrivateAnalysisCliOperation.GET_DECISION,
                PrivateAnalysisCliOperation.RECOVER_DECISION,
            }
            and self.decision_id is None
        ):
            raise ValueError("decision lookup requires decision_id")
        if (
            self.operation is PrivateAnalysisCliOperation.RECOVER_DECISION
            and self.expected_version is None
        ):
            raise ValueError("decision recovery requires expected_version")


def _canonical_integer(
    value: str,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            label,
            minimum=minimum,
            maximum=maximum,
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _positive_version(value: str) -> int:
    return _canonical_integer(
        value,
        label="expected_version",
        minimum=1,
        maximum=_MAX_SIGNED_64,
    )


def _list_limit(value: str) -> int:
    return _canonical_integer(
        value,
        label="limit",
        minimum=1,
        maximum=MAX_PRIVATE_ANALYSIS_CLI_LIST_LIMIT,
    )


def _nonnegative_time(value: str) -> int:
    return _canonical_integer(
        value,
        label="after_created_at_ns",
        minimum=0,
        maximum=_MAX_SIGNED_64,
    )


def _nonnegative_offset(value: str) -> int:
    return _canonical_integer(
        value,
        label="offset",
        minimum=0,
        maximum=_MAX_SIGNED_64,
    )


def _bounded_cli_text(value: str, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > MAX_PRIVATE_ANALYSIS_CLI_ID_CHARACTERS
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PrivateAnalysisCliInputError(f"{label} must be bounded visible text")
    return value


def _add_mutation_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor", required=True, dest="actor_id")


def _add_run_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True)


def _add_create_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--request",
        required=True,
        type=Path,
        dest="request_path",
        help=(
            "bounded UTF-8 caller-intent JSON; the proprietary query is read "
            "from this file and never accepted as a command-line value"
        ),
    )
    _add_mutation_identity(parser)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--run-id")


def build_parser() -> argparse.ArgumentParser:
    parser = _ClosedArgumentParser(
        prog="router-dump-private-analysis",
        description=(
            "Operate the durable local-only private-analysis lifecycle without "
            "starting a web server or ingestion worker."
        ),
    )
    _add_repeatable_plugin_allowlist_arguments(parser)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--tenant", required=True, dest="tenant_id")
    parser.add_argument("--project", required=True, dest="project_id")
    parser.add_argument("--workspace", required=True, dest="workspace_id")
    parser.add_argument(
        "--private-analysis-deployment-module",
        required=True,
        metavar="PACKAGE:ATTRIBUTE",
        dest="deployment_module",
        help=(
            "process-trusted local deployment descriptor or factory; this is "
            "not a device plug-in or a network provider setting"
        ),
    )
    parser.add_argument("--output", type=Path, dest="output_path")
    parser.add_argument("--pretty", action="store_true")

    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("runners", help="list policy-eligible local runners")

    create = commands.add_parser("create", help="admit one durable queued run")
    _add_create_arguments(create)

    get = commands.add_parser("get", help="read one payload-free run view")
    _add_run_identity(get)

    listing = commands.add_parser("list", help="page durable run views")
    listing.add_argument("--limit", type=_list_limit, default=100)
    listing.add_argument("--after-created-at-ns", type=_nonnegative_time)
    listing.add_argument("--after-run-id")

    execute = commands.add_parser("execute", help="execute one exact run version")
    _add_run_identity(execute)
    _add_mutation_identity(execute)
    execute.add_argument("--expected-version", required=True, type=_positive_version)
    execute.add_argument("--execution-id")

    cancel = commands.add_parser("cancel", help="cancel one exact run version")
    _add_run_identity(cancel)
    _add_mutation_identity(cancel)
    cancel.add_argument("--expected-version", required=True, type=_positive_version)

    recover_expired = commands.add_parser(
        "recover-expired",
        help=(
            "terminalize expired attempts in this workspace without retrying the model"
        ),
    )
    _add_mutation_identity(recover_expired)
    recover_expired.add_argument("--limit", type=_list_limit, default=100)

    report = commands.add_parser("report", help="read one terminal report")
    _add_run_identity(report)

    decide = commands.add_parser(
        "decide-proposal",
        help="durably reject or explicitly promote one exact proposal",
    )
    _add_run_identity(decide)
    decide.add_argument("--proposal-id", required=True)
    _add_mutation_identity(decide)
    decide.add_argument("--expected-version", required=True, type=_positive_version)
    decide.add_argument("--idempotency-key", required=True)
    decide.add_argument(
        "--request",
        required=True,
        type=Path,
        dest="request_path",
        help=(
            "bounded UTF-8 JSON containing the human decision and, for a "
            "promotion, a separately authored annotation or correlation target"
        ),
    )

    decisions = commands.add_parser(
        "list-decisions",
        help="page durable human decisions for one run",
    )
    _add_run_identity(decisions)
    decisions.add_argument("--limit", type=_list_limit, default=100)
    decisions.add_argument("--offset", type=_nonnegative_offset, default=0)

    decision = commands.add_parser(
        "get-decision",
        help="read one exact durable proposal decision",
    )
    _add_run_identity(decision)
    decision.add_argument("--decision-id", required=True)

    recover = commands.add_parser(
        "recover-decision",
        help="explicitly resume one pending human-authored promotion",
    )
    _add_run_identity(recover)
    recover.add_argument("--decision-id", required=True)
    recover.add_argument("--expected-version", required=True, type=_positive_version)

    run = commands.add_parser(
        "run",
        help="idempotently create, execute, and emit one terminal report",
    )
    _add_create_arguments(run)
    run.add_argument("--execution-id")
    return parser


def parse_args(
    argv: Sequence[str] | None = None,
) -> PrivateAnalysisCliConfiguration:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    operation = PrivateAnalysisCliOperation(namespace.operation)
    after_time = getattr(namespace, "after_created_at_ns", None)
    after_id = getattr(namespace, "after_run_id", None)
    if (after_time is None) is not (after_id is None):
        parser.error(
            "--after-created-at-ns and --after-run-id must be provided together"
        )
    try:
        tenant_id = _bounded_cli_text(namespace.tenant_id, "tenant")
        project_id = _bounded_cli_text(namespace.project_id, "project")
        workspace_id = _bounded_cli_text(namespace.workspace_id, "workspace")
        actor_id = (
            None
            if getattr(namespace, "actor_id", None) is None
            else _bounded_cli_text(namespace.actor_id, "actor")
        )
        idempotency_key = (
            None
            if getattr(namespace, "idempotency_key", None) is None
            else _bounded_cli_text(namespace.idempotency_key, "idempotency_key")
        )
        run_id = (
            None
            if getattr(namespace, "run_id", None) is None
            else _bounded_cli_text(namespace.run_id, "run_id")
        )
        execution_id = (
            None
            if getattr(namespace, "execution_id", None) is None
            else _bounded_cli_text(namespace.execution_id, "execution_id")
        )
        proposal_id = (
            None
            if getattr(namespace, "proposal_id", None) is None
            else _bounded_cli_text(namespace.proposal_id, "proposal_id")
        )
        decision_id = (
            None
            if getattr(namespace, "decision_id", None) is None
            else _bounded_cli_text(namespace.decision_id, "decision_id")
        )
        after_run_id = (
            None if after_id is None else _bounded_cli_text(after_id, "after_run_id")
        )
    except PrivateAnalysisCliInputError as error:
        parser.error(str(error))
    return PrivateAnalysisCliConfiguration(
        state_dir=namespace.state_dir,
        tenant_id=tenant_id,
        project_id=project_id,
        workspace_id=workspace_id,
        plugin_names=tuple(namespace.plugin),
        plugin_modules=tuple(namespace.plugin_module),
        deployment_module=namespace.deployment_module,
        operation=operation,
        request_path=getattr(namespace, "request_path", None),
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        run_id=run_id,
        execution_id=execution_id,
        proposal_id=proposal_id,
        decision_id=decision_id,
        expected_version=getattr(namespace, "expected_version", None),
        limit=getattr(namespace, "limit", 100),
        offset=getattr(namespace, "offset", 0),
        after_created_at_ns=after_time,
        after_run_id=after_run_id,
        output_path=namespace.output_path,
        pretty=namespace.pretty,
        plugin_deployment_module=namespace.plugin_deployment_module,
    )


def _reject_json_constant(_value: str) -> None:
    raise PrivateAnalysisCliInputError(
        "private-analysis request contains a non-finite JSON constant"
    )


def _read_request_document(path: Path) -> Mapping[str, Any]:
    try:
        selected = path.expanduser().resolve()
        with selected.open("rb") as request_file:
            size_before = os.fstat(request_file.fileno()).st_size
            if not 1 <= size_before <= MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES:
                raise PrivateAnalysisCliInputError(
                    "private-analysis request file exceeds its byte limit"
                )
            encoded = request_file.read(MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES + 1)
            size_after = os.fstat(request_file.fileno()).st_size
        if (
            len(encoded) > MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES
            or size_after != size_before
            or len(encoded) != size_after
        ):
            raise PrivateAnalysisCliInputError(
                "private-analysis request file changed while it was read"
            )
        text = encoded.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisCliInputError:
        raise
    except (
        OSError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise PrivateAnalysisCliInputError(
            "private-analysis request file is not valid bounded UTF-8 JSON"
        ) from error
    if type(value) is not dict:
        raise PrivateAnalysisCliInputError(
            "private-analysis request document must be an object"
        )
    return value


def _load_plugins(
    configuration: PrivateAnalysisCliConfiguration,
    *,
    entry_point_loader: Callable[[str], Any],
    module_loader: Callable[[str], Any],
) -> tuple[LoadedPlugin, ...]:
    if bool(configuration.plugin_names) == bool(configuration.plugin_modules):
        raise PrivateAnalysisCliInputError(
            "configure exactly one plug-in allowlist mode"
        )
    if configuration.plugin_names:
        return tuple(
            loaded_entry_point(name, loader=entry_point_loader)
            for name in configuration.plugin_names
        )
    return tuple(
        loaded_module(target, loader=module_loader)
        for target in configuration.plugin_modules
    )


def _encode_document(value: Mapping[str, Any], *, pretty: bool) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        indent=2 if pretty else None,
        sort_keys=True,
        separators=None if pretty else (",", ":"),
    )


def _write_document(
    document: Mapping[str, Any],
    *,
    configuration: PrivateAnalysisCliConfiguration,
    stdout: TextIO,
) -> None:
    encoded = _encode_document(document, pretty=configuration.pretty)
    if configuration.output_path is not None:
        output = configuration.output_path.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded + "\n", encoding="utf-8")
    stdout.write(encoded)
    stdout.write("\n")


def _base_document(
    configuration: PrivateAnalysisCliConfiguration,
) -> dict[str, Any]:
    return {
        "schema_version": PRIVATE_ANALYSIS_CLI_RESULT_VERSION,
        "operation": configuration.operation.value,
        "scope": {
            "tenant_id": configuration.tenant_id,
            "project_id": configuration.project_id,
            "workspace_id": configuration.workspace_id,
        },
    }


def run(
    configuration: PrivateAnalysisCliConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    deployment_loader: Callable[..., Any] = load_private_analysis_deployment,
    plugin_deployment_loader: Callable[..., Any] = (load_plugin_composition_deployment),
    registry_factory: Callable[..., Any] = PluginRegistry,
    control_plane_factory: Callable[..., Any] = ControlPlane,
    stdout: TextIO = sys.stdout,
) -> int:
    """Execute one local lifecycle operation and emit a bounded JSON document."""

    state_root = configuration.state_dir.expanduser().resolve()
    composition_options: dict[str, Any] = {}
    if configuration.plugin_deployment_module is not None:
        composition = plugin_deployment_loader(
            configuration.plugin_deployment_module,
            context=PluginCompositionDeploymentContext(state_dir=state_root),
        )
        registry = composition.primary_registry
        composition_options = _control_plane_composition_options(composition)
    else:
        loaded_plugins = _load_plugins(
            configuration,
            entry_point_loader=entry_point_loader,
            module_loader=module_loader,
        )
        registry = registry_factory(require_executable_identity=True)
        for loaded_plugin in loaded_plugins:
            loaded_plugin.register(registry)
    deployment = deployment_loader(
        configuration.deployment_module,
        context=PrivateAnalysisDeploymentContext(state_dir=state_root),
    )
    control_plane = control_plane_factory(
        state_root,
        registry=registry,
        private_analysis_runners=deployment.registrations,
        private_analysis_execution_limits=deployment.execution_limits,
        private_analysis_ceilings=deployment.ceilings,
        **composition_options,
    )
    exit_code = EXIT_SUCCESS
    document = _base_document(configuration)
    try:
        scope = EvidenceScope(
            tenant_id=configuration.tenant_id,
            project_id=configuration.project_id,
            workspace_id=configuration.workspace_id,
        )
        service = control_plane.private_analysis
        operation = configuration.operation
        if operation is PrivateAnalysisCliOperation.RUNNERS:
            document["runners"] = [
                private_analysis_runner_to_wire(item)
                for item in service.list_runners(scope)
            ]
        elif operation is PrivateAnalysisCliOperation.CREATE:
            if (
                configuration.request_path is None
                or configuration.actor_id is None
                or configuration.idempotency_key is None
            ):
                raise PrivateAnalysisCliInputError("create configuration is incomplete")
            spec = parse_private_analysis_request_spec(
                scope,
                _read_request_document(configuration.request_path),
            )
            document["run"] = private_analysis_run_to_wire(
                service.create(
                    spec,
                    actor_id=configuration.actor_id,
                    idempotency_key=configuration.idempotency_key,
                    run_id=configuration.run_id,
                )
            )
        elif operation is PrivateAnalysisCliOperation.GET:
            if configuration.run_id is None:
                raise PrivateAnalysisCliInputError("get configuration is incomplete")
            document["run"] = private_analysis_run_to_wire(
                service.get(scope, configuration.run_id)
            )
        elif operation is PrivateAnalysisCliOperation.LIST:
            document["runs"] = [
                private_analysis_run_to_wire(item)
                for item in service.list(
                    scope,
                    limit=configuration.limit,
                    after_created_at_ns=configuration.after_created_at_ns,
                    after_run_id=configuration.after_run_id,
                )
            ]
        elif operation is PrivateAnalysisCliOperation.EXECUTE:
            if (
                configuration.run_id is None
                or configuration.actor_id is None
                or configuration.expected_version is None
            ):
                raise PrivateAnalysisCliInputError(
                    "execute configuration is incomplete"
                )
            document["run"] = private_analysis_run_to_wire(
                service.execute(
                    scope,
                    configuration.run_id,
                    expected_version=configuration.expected_version,
                    actor_id=configuration.actor_id,
                    execution_id=configuration.execution_id,
                )
            )
        elif operation is PrivateAnalysisCliOperation.CANCEL:
            if (
                configuration.run_id is None
                or configuration.actor_id is None
                or configuration.expected_version is None
            ):
                raise PrivateAnalysisCliInputError("cancel configuration is incomplete")
            document["run"] = private_analysis_run_to_wire(
                service.cancel(
                    scope,
                    configuration.run_id,
                    expected_version=configuration.expected_version,
                    actor_id=configuration.actor_id,
                )
            )
        elif operation is PrivateAnalysisCliOperation.RECOVER_EXPIRED:
            if configuration.actor_id is None:
                raise PrivateAnalysisCliInputError(
                    "expired-run recovery configuration is incomplete"
                )
            document["runs"] = [
                private_analysis_run_to_wire(item)
                for item in service.recover_expired(
                    scope,
                    actor_id=configuration.actor_id,
                    limit=configuration.limit,
                )
            ]
        elif operation is PrivateAnalysisCliOperation.REPORT:
            if configuration.run_id is None:
                raise PrivateAnalysisCliInputError("report configuration is incomplete")
            document["report"] = private_analysis_report_to_wire(
                service.get_report(scope, configuration.run_id)
            )
        elif operation is PrivateAnalysisCliOperation.DECIDE_PROPOSAL:
            if (
                configuration.run_id is None
                or configuration.proposal_id is None
                or configuration.actor_id is None
                or configuration.expected_version is None
                or configuration.idempotency_key is None
                or configuration.request_path is None
            ):
                raise PrivateAnalysisCliInputError(
                    "proposal decision configuration is incomplete"
                )
            review = parse_proposal_review_request(
                _read_request_document(configuration.request_path)
            )
            document["decision"] = proposal_review_decision_to_wire(
                control_plane.private_analysis_reviews.decide(
                    scope,
                    run_id=configuration.run_id,
                    proposal_id=configuration.proposal_id,
                    proposal_digest=review.proposal_digest,
                    result_digest=review.result_digest,
                    expected_run_version=configuration.expected_version,
                    disposition=review.disposition,
                    actor=configuration.actor_id,
                    rationale=review.rationale,
                    idempotency_key=configuration.idempotency_key,
                    target=review.target,
                )
            )
        elif operation is PrivateAnalysisCliOperation.LIST_DECISIONS:
            if configuration.run_id is None:
                raise PrivateAnalysisCliInputError(
                    "decision list configuration is incomplete"
                )
            document["decisions"] = [
                proposal_review_decision_to_wire(item)
                for item in control_plane.private_analysis_reviews.list(
                    scope,
                    run_id=configuration.run_id,
                    limit=configuration.limit,
                    offset=configuration.offset,
                )
            ]
        elif operation is PrivateAnalysisCliOperation.GET_DECISION:
            if configuration.run_id is None or configuration.decision_id is None:
                raise PrivateAnalysisCliInputError(
                    "decision lookup configuration is incomplete"
                )
            decision = control_plane.private_analysis_reviews.get(
                scope,
                configuration.decision_id,
            )
            if decision.run_id != configuration.run_id:
                raise ProposalReviewNotFoundError(configuration.decision_id)
            document["decision"] = proposal_review_decision_to_wire(decision)
        elif operation is PrivateAnalysisCliOperation.RECOVER_DECISION:
            if (
                configuration.run_id is None
                or configuration.decision_id is None
                or configuration.expected_version is None
            ):
                raise PrivateAnalysisCliInputError(
                    "decision recovery configuration is incomplete"
                )
            current = control_plane.private_analysis_reviews.get(
                scope,
                configuration.decision_id,
            )
            if current.run_id != configuration.run_id:
                raise ProposalReviewNotFoundError(configuration.decision_id)
            document["decision"] = proposal_review_decision_to_wire(
                control_plane.private_analysis_reviews.recover(
                    scope,
                    configuration.decision_id,
                    expected_decision_version=configuration.expected_version,
                )
            )
        else:
            if operation is not PrivateAnalysisCliOperation.RUN:
                raise PrivateAnalysisCliInputError("unsupported lifecycle operation")
            if (
                configuration.request_path is None
                or configuration.actor_id is None
                or configuration.idempotency_key is None
            ):
                raise PrivateAnalysisCliInputError("run configuration is incomplete")
            spec = parse_private_analysis_request_spec(
                scope,
                _read_request_document(configuration.request_path),
            )
            admitted = service.create(
                spec,
                actor_id=configuration.actor_id,
                idempotency_key=configuration.idempotency_key,
                run_id=configuration.run_id,
            )
            terminal = service.execute(
                scope,
                admitted.run_id,
                expected_version=admitted.version,
                actor_id=configuration.actor_id,
                execution_id=configuration.execution_id,
            )
            report = service.get_report(scope, terminal.run_id)
            document["report"] = private_analysis_report_to_wire(report)
            if report.outcome.result is None:
                exit_code = EXIT_ADVISORY_ERROR
        document["success"] = exit_code == EXIT_SUCCESS
        document["exit_code"] = exit_code
    finally:
        control_plane.close()
    _write_document(document, configuration=configuration, stdout=stdout)
    return exit_code


def _error_document(
    operation: str | None,
    *,
    code: str,
    message: str,
) -> dict[str, Any]:
    return {
        "schema_version": PRIVATE_ANALYSIS_CLI_RESULT_VERSION,
        "operation": operation,
        "success": False,
        "exit_code": EXIT_FAILURE,
        "error": {"code": code, "message": message},
    }


def main(argv: Sequence[str] | None = None) -> None:
    operation: str | None = None
    try:
        configuration = parse_args(argv)
        operation = configuration.operation.value
        exit_code = run(configuration)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisServiceError as error:
        print(
            _encode_document(
                _error_document(
                    operation,
                    code=error.code.value,
                    message=error.safe_message,
                ),
                pretty=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILURE) from None
    except ProposalReviewError:
        print(
            _encode_document(
                _error_document(
                    operation,
                    code="proposal_review_failed",
                    message="Private-analysis proposal review failed.",
                ),
                pretty=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILURE) from None
    except (
        PrivateAnalysisApplicationWireLimitError,
        PrivateAnalysisApplicationWireRequestError,
        PrivateAnalysisCliInputError,
        ProposalReviewWireError,
        LookupError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        print(
            _encode_document(
                _error_document(
                    operation,
                    code="command_failed",
                    message="Private analysis command failed.",
                ),
                pretty=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILURE) from None
    except BaseException:  # noqa: BLE001 - final hostile deployment boundary.
        print(
            _encode_document(
                _error_document(
                    operation,
                    code="command_failed",
                    message="Private analysis command failed.",
                ),
                pretty=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILURE) from None
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":  # pragma: no cover - console entry point.
    main()


__all__ = [
    "EXIT_ADVISORY_ERROR",
    "EXIT_FAILURE",
    "EXIT_SUCCESS",
    "MAX_PRIVATE_ANALYSIS_REQUEST_DOCUMENT_BYTES",
    "PRIVATE_ANALYSIS_CLI_RESULT_VERSION",
    "PrivateAnalysisCliConfiguration",
    "PrivateAnalysisCliInputError",
    "PrivateAnalysisCliOperation",
    "build_parser",
    "main",
    "parse_args",
    "run",
]

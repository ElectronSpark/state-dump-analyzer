"""Stable consistency-capable parser fixture shared by integration tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from router_dump_analyzer.plugin_api import (
    ConsistencyFinding,
    DiagnosticSeverity,
    FindingResult,
    PluginCapability,
    Provenance,
    Quality,
)
from tests.test_ingestion import ParseOnlyPlugin


class ConsistencyParsePlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.consistency-ingestion",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.CONSISTENCY_CHECK,
            }
        ),
    )

    def check_consistency(self, world: Any):
        states = tuple(world.iter_states(limit=1))
        if not states:
            return ()
        state = states[0]
        return (
            ConsistencyFinding(
                rule_id="tests.interface-is-observable",
                severity=DiagnosticSeverity.ERROR,
                result=FindingResult.FAIL,
                summary="The deterministic test finding was materialized.",
                resources=(state.resource,),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.EXACT,
                basis=world.basis,
                evidence=state.evidence,
                details={"expected": "test-failure", "actual": "test-failure"},
            ),
        )


class ConsistencyAuxiliaryPlugin(ConsistencyParsePlugin):
    """PROCESS-loadable consistency provider that owns no parser role."""

    manifest = replace(
        ConsistencyParsePlugin.manifest,
        plugin_id="tests.consistency-auxiliary",
        capabilities=frozenset({PluginCapability.CONSISTENCY_CHECK}),
    )


__all__ = ["ConsistencyAuxiliaryPlugin", "ConsistencyParsePlugin"]

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PluginAuthoringDocumentationTests(unittest.TestCase):
    def test_quickstart_tracks_executable_novice_contract(self) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "AnalyzerPluginBase",
            "PluginCapability.STATUS_PARSE",
            "InputParserKind.STATUS",
            "SourceRecordEmission",
            "derive_event_uid",
            "ForwardingCandidateConstraint",
            "ForwardingTraversalStateKey",
            "ForwardingPolicyEvaluation",
            "ForwardingTraversalEvaluation",
            "ingress_scopes_complete=True",
            "policy_scopes_complete",
            "router-dump-plugin-validate minimal_router",
            "--artifact examples/minimal_plugin/fixtures/minimal-status.jsonl",
            "examples/minimal_plugin",
        ):
            with self.subTest(required=required):
                self.assertIn(required, quickstart)

    def test_root_readme_links_the_quickstart_and_example(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/plugin-author-quickstart.md", readme)
        self.assertIn("examples/minimal_plugin", readme)

    def test_minimal_example_points_advanced_forwarding_back_to_contract(self) -> None:
        example = (ROOT / "examples" / "minimal_plugin" / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("ForwardingCandidateConstraint", example)
        self.assertIn("ForwardingTraversalStateKey", example)
        self.assertIn("incomplete scope evidence", example)
        self.assertIn("docs/plugin-author-quickstart.md", example)

    def test_forwarding_docs_keep_trace_start_distinct_from_flow_source(self) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        architecture = (ROOT / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )
        api_contract = (ROOT / "docs" / "api-contract.md").read_text(
            encoding="utf-8"
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for document in (quickstart, contract, architecture):
            with self.subTest(document=document[:24]):
                self.assertIn("evaluate_endpoint_reachability_pair()", document)
        for document in (quickstart, contract, architecture, api_contract):
            with self.subTest(path_relation_document=document[:24]):
                self.assertIn("not_comparable", document)
                self.assertIn("partial_active_reachability", document)
        self.assertIn("destination attachment", quickstart)
        self.assertIn("exact source", quickstart)
        self.assertIn("endpoint", quickstart)
        self.assertIn("federation/linker", contract)
        self.assertIn("forward observation/start", api_contract)
        self.assertIn("starting/observation node", readme)

    def test_author_path_depends_on_core_without_demo_runtime(self) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        example_readme = (
            ROOT / "examples" / "minimal_plugin" / "README.md"
        ).read_text(encoding="utf-8")
        example_project = tomllib.loads(
            (
                ROOT / "examples" / "minimal_plugin" / "pyproject.toml"
            ).read_text(encoding="utf-8")
        )

        self.assertIn("router-dump-analyzer-core", quickstart)
        self.assertIn("router-dump-analyzer-core", contract)
        self.assertIn("router-dump-analyzer-core", example_readme)
        dependencies = tuple(example_project["project"]["dependencies"])
        self.assertTrue(
            any(item.startswith("router-dump-analyzer-core") for item in dependencies)
        )
        self.assertFalse(
            any("router-dump-analyzer-demo" in item for item in dependencies)
        )

    def test_validator_command_is_packaged(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            project["project"]["scripts"]["router-dump-plugin-validate"],
            "router_dump_analyzer.plugin_validation:main",
        )

    def test_codex_and_fable_share_one_maintenance_rule(self) -> None:
        memory = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        fable_import = (ROOT / "CLAUDE.md").read_text(encoding="utf-8").strip()
        self.assertIn("applies only to OpenAI Codex and Fable", memory)
        self.assertIn("plug-in-documentation drift check", memory)
        self.assertNotIn("Codex, or Fable explicitly delegates", memory)
        self.assertEqual(fable_import, "@AGENTS.md")


if __name__ == "__main__":
    unittest.main()

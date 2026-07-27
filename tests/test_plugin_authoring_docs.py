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
            "python -m pip install -e demo",
            "router-dump-plugin-validate demo_router",
            "--artifact demo/fixtures/minimal-status.jsonl",
            "demo/rsl_demo_plugin/__init__.py",
            "declarative domain presentation",
        ):
            with self.subTest(required=required):
                self.assertIn(required, quickstart)

    def test_root_readme_links_the_quickstart_and_example(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/plugin-author-quickstart.md", readme)
        self.assertIn("demo/README.md", readme)
        self.assertIn("router-dump-plugin-validate demo_router", readme)
        self.assertNotIn("examples/minimal_plugin", readme)

    def test_demo_example_points_advanced_forwarding_back_to_contract(self) -> None:
        example = (ROOT / "demo" / "README.md").read_text(encoding="utf-8")
        self.assertIn("ForwardingCandidateConstraint", example)
        self.assertIn("ForwardingTraversalStateKey", example)
        self.assertIn("incomplete scope evidence", example)
        self.assertIn("plugin-author-quickstart.md", example)

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

    def test_author_contract_depends_on_core_without_demo_runtime(self) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        example_readme = (ROOT / "demo" / "README.md").read_text(encoding="utf-8")
        demo_project = tomllib.loads(
            (ROOT / "demo" / "pyproject.toml").read_text(encoding="utf-8")
        )
        plugin_source = (
            ROOT
            / "demo"
            / "rsl_demo_plugin"
            / "__init__.py"
        ).read_text(encoding="utf-8")

        self.assertIn("router-dump-analyzer-core", quickstart)
        self.assertIn("router-dump-analyzer-core", contract)
        self.assertIn("router-dump-analyzer-core", example_readme)
        dependencies = tuple(demo_project["project"]["dependencies"])
        self.assertTrue(
            any(item.startswith("router-dump-analyzer-core") for item in dependencies)
        )
        self.assertFalse(
            any("router-dump-analyzer-demo" in item for item in dependencies)
        )
        self.assertNotIn("from router_dump_analyzer_demo", plugin_source)
        self.assertNotIn("import router_dump_analyzer_demo", plugin_source)

    def test_demo_is_the_only_runnable_example_distribution(self) -> None:
        self.assertTrue(
            (
                ROOT
                / "demo"
                / "rsl_demo_plugin"
                / "__init__.py"
            ).is_file()
        )
        self.assertTrue(
            (ROOT / "demo" / "fixtures" / "minimal-status.jsonl").is_file()
        )
        self.assertTrue((ROOT / "demo" / "tests" / "test_plugin.py").is_file())
        self.assertFalse((ROOT / "examples" / "minimal_plugin").exists())
        self.assertFalse(
            (ROOT / "demo" / "router_dump_analyzer_demo_plugins").exists()
        )
        self.assertFalse(
            (ROOT / "demo" / "router_dump_analyzer_demo").exists()
        )
        self.assertTrue(
            (
                ROOT
                / "demo"
                / "rsl_demo_generator"
                / "__init__.py"
            ).is_file()
        )

    def test_demo_publishes_the_documented_plugin_entry_point(self) -> None:
        project = tomllib.loads(
            (ROOT / "demo" / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            project["project"]["entry-points"]["router_dump_analyzer.plugins"][
                "demo_router"
            ],
            "rsl_demo_plugin:plugin",
        )

    def test_frontend_ownership_is_core_and_plugin_presentation_is_declarative(
        self,
    ) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        architecture = (ROOT / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )
        example = (ROOT / "demo" / "README.md").read_text(encoding="utf-8")

        for document in (quickstart, contract, architecture, example):
            with self.subTest(document=document[:24]):
                self.assertIn("core", document.lower())
                self.assertIn("declarative", document.lower())
        self.assertIn("frontend/", architecture)
        self.assertIn("frontend/", example)
        self.assertIn("never ship executable frontend code", contract)

    def test_docs_use_one_demo_provider_identity(self) -> None:
        documents = tuple(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "README.md",
                "demo/README.md",
                "docs/plugin-contract.md",
                "docs/architecture.md",
            )
        )
        for document in documents:
            with self.subTest(document=document[:24]):
                self.assertIn("demo.example-router", document)
                self.assertNotIn("example.router-state-lab", document)

    def test_docs_keep_revision_and_profile_transport_boundaries_explicit(
        self,
    ) -> None:
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        api_contract = (ROOT / "docs" / "api-contract.md").read_text(
            encoding="utf-8"
        )
        architecture = (ROOT / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )

        for document in (quickstart, contract, api_contract, architecture):
            with self.subTest(document=document[:24]):
                self.assertIn("revision_id", document)
                self.assertIn("opaque", document)
                self.assertIn("may contain `/`", document)
        for document in (quickstart, contract, api_contract, architecture):
            with self.subTest(profile_document=document[:24]):
                self.assertIn("TopologyProjectionDescriptor", document)
                self.assertIn("presentation_roles", document)
        self.assertIn("does not expose them directly", api_contract)

    def test_validator_command_is_packaged(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            project["project"]["scripts"]["router-dump-plugin-validate"],
            "router_dump_analyzer.plugin_validation:main",
        )

    def test_docs_make_the_core_the_only_web_entry_point(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        example = (ROOT / "demo" / "README.md").read_text(encoding="utf-8")
        quickstart = (ROOT / "docs" / "plugin-author-quickstart.md").read_text(
            encoding="utf-8"
        )
        contract = (ROOT / "docs" / "plugin-contract.md").read_text(
            encoding="utf-8"
        )
        architecture = (ROOT / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )
        documents = (readme, example, quickstart, contract, architecture)

        for document in documents:
            with self.subTest(document=document[:32]):
                self.assertIn("router-dump-analyzer", document)
                self.assertNotIn("router-dump-demo", document)
                self.assertNotIn("router_dump_analyzer_demo.app", document)
                self.assertNotIn("--fixture-assembly", document)
        for document in (example, quickstart, contract, architecture):
            with self.subTest(runtime_document=document[:32]):
                self.assertIn("plugin.runtime", document)
                self.assertIn("core", document.lower())
        self.assertIn("--plugin-module", readme)
        self.assertIn("PluginRuntimeCapability", quickstart)
        self.assertIn("PluginRuntimeSession", contract)

    def test_codex_and_fable_share_one_maintenance_rule(self) -> None:
        memory = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        fable_import = (ROOT / "CLAUDE.md").read_text(encoding="utf-8").strip()
        self.assertIn("applies only to OpenAI Codex and Fable", memory)
        self.assertIn("plug-in-documentation drift check", memory)
        self.assertNotIn("Codex, or Fable explicitly delegates", memory)
        self.assertEqual(fable_import, "@AGENTS.md")


if __name__ == "__main__":
    unittest.main()

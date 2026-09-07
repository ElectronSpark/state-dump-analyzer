from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (
    ROOT / "src",
    ROOT / "demo",
    ROOT / "state-dump-generator" / "src",
)


class LazyPackageExportTests(unittest.TestCase):
    def run_isolated(self, code: str, *, installed: bool = False) -> dict:
        setup = "import json, sys\n"
        if not installed:
            setup += f"sys.path[:0] = {[str(path) for path in SOURCE_ROOTS]!r}\n"
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                *([] if installed else ["-S"]),
                "-c",
                setup + textwrap.dedent(code),
            ],
            cwd=ROOT.parent,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_bare_facades_do_not_import_their_implementations(self) -> None:
        for package in (
            "router_dump_analyzer",
            "rsl_demo_generator",
            "state_dump_generator",
        ):
            with self.subTest(package=package):
                result = self.run_isolated(f"""
                    import importlib
                    module = importlib.import_module({package!r})
                    before = sorted(sys.modules)
                    assert set(module.__all__) <= set(dir(module))
                    assert before == sorted(sys.modules)
                    print(json.dumps({{"modules": [name for name in sys.modules
                        if name.startswith(({package!r}, 'router_dump_analyzer'))]}}))
                """)
                allowed = {
                    package,
                    "router_dump_analyzer",
                    "router_dump_analyzer._lazy_exports",
                }
                self.assertLessEqual(set(result["modules"]), allowed)

    def test_contract_and_generator_leaf_imports_exclude_replay_and_catalog_loading(
        self,
    ) -> None:
        for statement in (
            "from router_dump_analyzer.plugin_api import ResourceKey",
            "from rsl_demo_plugin import parser_plugin",
            "from rsl_demo_generator.scenario_source import NodeSpec",
            "from rsl_demo_generator import NodeSpec",
            "from state_dump_generator.model import ScenarioDocument",
        ):
            with self.subTest(statement=statement):
                result = self.run_isolated(f"""
                    from pathlib import Path
                    from unittest.mock import patch
                    read_bytes = Path.read_bytes
                    def read(path):
                        if path.name == 'router-state-lab-default.scenario.json':
                            raise AssertionError('leaf import read the default scenario')
                        return read_bytes(path)
                    with patch.object(Path, 'read_bytes', read):
                        {statement}
                    print(json.dumps({{"modules": sorted(sys.modules)}}))
                """)
                for name in result["modules"]:
                    self.assertNotIn(
                        name,
                        {
                            "router_dump_analyzer.ingestion_pipeline",
                            "router_dump_analyzer.multi_node_route",
                            "router_dump_analyzer.multi_node_topology",
                            "router_dump_analyzer.normalized_data",
                            "rsl_demo_plugin.session",
                            "rsl_demo_generator.assembly",
                            "state_dump_generator.archive",
                            "state_dump_generator.simulation",
                        },
                    )
                    self.assertFalse(
                        name.startswith(
                            ("fastapi", "router_dump_analyzer.private_analysis")
                        )
                    )

    def test_compatibility_exports_keep_concrete_identity_and_static_bindings(
        self,
    ) -> None:
        result = self.run_isolated(
            """
            import importlib
            import router_dump_analyzer as core
            import rsl_demo_generator as generator
            import state_dump_generator as standalone
            checked = {}
            for package in (core, generator, standalone):
                for name in package.__all__:
                    value = getattr(package, name)
                    owner = importlib.import_module(package._EXPORT_MODULES[name], package.__name__)
                    assert value is getattr(owner, name), name
                    assert vars(package)[name] is value, name
                checked[package.__name__] = len(package.__all__)
            from router_dump_analyzer import PluginRegistry
            from router_dump_analyzer.plugin_registration import PluginRegistry as implementation
            assert PluginRegistry is implementation
            print(json.dumps(checked))
        """,
            installed=True,
        )
        self.assertEqual(
            result,
            {
                "router_dump_analyzer": 215,
                "rsl_demo_generator": 41,
                "state_dump_generator": 9,
            },
        )

    def test_default_catalog_materializes_once_and_preserves_tuple_identity(
        self,
    ) -> None:
        result = self.run_isolated("""
            from concurrent.futures import ThreadPoolExecutor
            from pathlib import Path
            from unittest.mock import patch
            reads = []
            read_bytes = Path.read_bytes
            def read(path):
                if path.name == 'router-state-lab-default.scenario.json': reads.append(str(path))
                return read_bytes(path)
            with patch.object(Path, 'read_bytes', read):
                import rsl_demo_generator.catalog as catalog
                from rsl_demo_generator import CoverageCaseSpec, NodeSpec
                assert reads == []
                assert 'DEFAULT_SCENARIO_SOURCE' not in vars(catalog)
                assert 'DEFAULT_SCENARIO_SOURCE' in dir(catalog)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    sources = list(pool.map(lambda _: catalog.DEFAULT_SCENARIO_SOURCE, range(16)))
                assert all(source is sources[0] for source in sources)
                assert catalog.DEMO_NODES is sources[0].nodes
                assert catalog.DEMO_LINKS is sources[0].links
                assert catalog.node_by_id(catalog.DEMO_NODES[0].node_id) is catalog.DEMO_NODES[0]
                from rsl_demo_generator.scenario_source import load_default_scenario_source
                assert load_default_scenario_source() is sources[0]
                for node in catalog.DEMO_NODES:
                    assert all(node.node_id in link.participants for link in catalog.links_for_node(node.node_id))
                    catalog.route_inventory_contexts_for_node(node.node_id)
            print(json.dumps({'reads': len(reads), 'nodes': len(catalog.DEMO_NODES),
                              'links': len(catalog.DEMO_LINKS)}))
        """)
        self.assertEqual(result, {"reads": 1, "nodes": 10, "links": 8})

    def test_catalog_helpers_can_be_the_first_source_access(self) -> None:
        result = self.run_isolated("""
            import rsl_demo_generator.catalog as catalog
            assert 'DEFAULT_SCENARIO_SOURCE' not in vars(catalog)
            try: catalog.node_by_id('not-a-node')
            except KeyError: pass
            assert 'DEFAULT_SCENARIO_SOURCE' in vars(catalog)
            print(json.dumps({'nodes': len(catalog.DEMO_NODES)}))
        """)
        self.assertEqual(result["nodes"], 10)

    def test_old_demo_pickle_paths_and_annotations_remain_valid(self) -> None:
        result = self.run_isolated("""
            import pickle, typing
            import rsl_demo_plugin as package
            for name in ('ExampleRouterPlugin', 'ExampleEvidenceAnalysisPlugin',
                         'TopologyProfileSpec', 'GeneratedProjectionMemberSpec',
                         'ExampleRouterGeneratedProjectionPolicy'):
                cls = pickle.loads(f'crsl_demo_plugin\\n{name}\\n.'.encode())
                assert cls is getattr(package, name)
                assert cls.__module__ == 'rsl_demo_plugin'
                typing.get_type_hints(cls)
                assert pickle.loads(pickle.dumps(cls)) is cls
            assert pickle.loads(pickle.dumps(package.parser_plugin)).__class__ is package.ExampleRouterPlugin
            assert 'rsl_demo_plugin.session' not in sys.modules
            print(json.dumps({'ok': True}))
        """)
        self.assertTrue(result["ok"])

    def test_installed_entry_point_loads_runtime_once_without_changing_parser_instance(
        self,
    ) -> None:
        result = self.run_isolated(
            """
            from concurrent.futures import ThreadPoolExecutor
            from importlib.metadata import entry_points
            import rsl_demo_plugin as package
            parser = package.parser_plugin
            assert 'runtime' not in vars(parser)
            assert 'rsl_demo_plugin.session' not in sys.modules
            with ThreadPoolExecutor(max_workers=8) as pool:
                plugins = list(pool.map(lambda _: package.plugin, range(16)))
            assert all(plugin is plugins[0] for plugin in plugins)
            entry, = entry_points(group='router_dump_analyzer.plugins', name='demo_router')
            assert entry.load() is plugins[0]
            assert package.parser_plugin is parser
            assert 'runtime' not in vars(parser)
            assert 'runtime' in vars(plugins[0])
            assert type(parser) is type(plugins[0]) is package.ExampleRouterPlugin
            assert vars(package)['plugin'] is plugins[0]
            print(json.dumps({'entry':entry.value}))
        """,
            installed=True,
        )
        self.assertEqual(result["entry"], "rsl_demo_plugin:plugin")

    def test_installed_module_targets_attest_and_ingest_in_spawned_children(
        self,
    ) -> None:
        for target in ("rsl_demo_plugin:plugin", "rsl_demo_plugin:parser_plugin"):
            with self.subTest(target=target):
                result = self.run_isolated(
                    f"""
                    import tempfile
                    from pathlib import Path
                    from router_dump_analyzer.ingestion_pipeline import (
                        PluginExecutionProcessError, PluginExecutionTimeoutError,
                        PluginRegistry, _ingest_plugin_child, _run_isolated_child,
                    )
                    from router_dump_analyzer.plugin_loading import load_plugin_module_with_coordinates
                    from rsl_demo_plugin import PLATFORM_ID, SOFTWARE_VERSION, render_conformance_status_fixture
                    loaded = load_plugin_module_with_coordinates({target!r})
                    registered = loaded.register(PluginRegistry(require_executable_identity=True))
                    assert registered.process_bootstrap.plugin_target == 'rsl_demo_plugin:ExampleRouterPlugin'
                    assert ('runtime' in vars(loaded.plugin)) == ({target!r} == 'rsl_demo_plugin:plugin')
                    with tempfile.TemporaryDirectory() as directory:
                        fixture = Path(directory) / 'minimal-status.jsonl'
                        fixture.write_bytes(render_conformance_status_fixture())
                        staged = Path(directory) / 'result.json'
                        result = _run_isolated_child(
                            _ingest_plugin_child,
                            (registered.process_bootstrap, registered.process_bootstrap_digest,
                             (), str(fixture), 'node-a',
                             {{'platform':PLATFORM_ID, 'software_version':SOFTWARE_VERSION}}, str(staged)),
                            timeout_seconds=30, stage='ingest', expected_kind='ingest',
                            subject='lazy demo entry point', process_name_prefix='lazy-package-test',
                            timeout_error=PluginExecutionTimeoutError, process_error=PluginExecutionProcessError,
                        )
                        assert staged.is_file()
                    print(json.dumps({{'kind':result['kind'], 'resources':result['resource_count']}}))
                """,
                    installed=True,
                )
                self.assertEqual(result["kind"], "ingest")
                self.assertGreater(result["resources"], 0)


if __name__ == "__main__":
    unittest.main()

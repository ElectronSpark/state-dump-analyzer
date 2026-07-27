from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from generator import assembly


class GeneratorWorkerSchedulingTests(unittest.TestCase):
    def test_worker_cap_tracks_measured_workload_contention(self) -> None:
        full_scale = assembly.AssemblyConfig(
            nodes=assembly.DEMO_NODES[:4],
        )
        developer_scale = assembly.AssemblyConfig(
            nodes=assembly.DEMO_NODES[:4],
            events_per_node=25_000,
            resources_per_node=2_500,
            allow_small=True,
        )
        with mock.patch.object(assembly.os, "cpu_count", return_value=64):
            self.assertEqual(
                assembly._node_build_worker_count(full_scale),
                2,
            )
            self.assertEqual(
                assembly._node_build_worker_count(developer_scale),
                4,
            )

    def test_single_worker_builds_every_selected_node(self) -> None:
        config = assembly.AssemblyConfig(
            nodes=assembly.DEMO_NODES[:2],
            events_per_node=120,
            resources_per_node=120,
            seed=12345,
            allow_small=True,
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(assembly.os, "cpu_count", return_value=1),
        ):
            output, report = assembly._build_demo_fixture_with_report(
                Path(temporary) / "single-worker.tgz",
                config=config,
                deep_validate=False,
            )

            self.assertTrue(output.is_file())
            self.assertEqual(
                report.node_ids,
                tuple(node.node_id for node in config.nodes),
            )


if __name__ == "__main__":
    unittest.main()

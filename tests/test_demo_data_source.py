from __future__ import annotations

import inspect
import unittest

from rsl_demo_plugin import data as demo_data


class DemoDataSourceTests(unittest.TestCase):
    def test_default_revision_is_generated_node_a(self) -> None:
        self.assertEqual(
            demo_data.REVISION_ID,
            "demo/node-a/revision-0001",
        )

    def test_unscoped_load_requires_core_owned_runtime_input(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            r"core.*--input.*plugin\.runtime",
        ):
            demo_data.load_demo_dataset()

    def test_app_style_fixture_configuration_cannot_return(self) -> None:
        source = inspect.getsource(demo_data)
        for forbidden in (
            "ROUTER_DUMP_DEMO_ASSEMBLY",
            "ASSEMBLY_ARCHIVE_ENV",
            "configure_demo_assembly",
            "close_demo_revision_store",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_loads_only_through_the_configured_assembly_store(self) -> None:
        node_dataset = {
            "demo": {
                "node": "node-a",
                "revision_id": demo_data.REVISION_ID,
            }
        }

        class Store:
            default_revision_id = demo_data.REVISION_ID

            def dataset_for_node(self, node_id: str):
                self.requested_node_id = node_id
                return node_dataset

            def dataset_for_revision(self, revision_id: str):
                self.requested_revision_id = revision_id
                return node_dataset

        store = Store()
        with demo_data.revision_store_scope(store):
            self.assertIs(demo_data.current_revision_store(), store)
            self.assertEqual(
                demo_data.load_demo_dataset(node_id="node-a"),
                node_dataset,
            )
            self.assertEqual(
                demo_data.load_demo_dataset(demo_data.REVISION_ID),
                node_dataset,
            )
            self.assertEqual(
                demo_data.load_demo_dataset(),
                node_dataset,
            )

        with self.assertRaisesRegex(RuntimeError, r"--input"):
            demo_data.current_revision_store()
        self.assertEqual(store.requested_node_id, "node-a")
        self.assertEqual(
            store.requested_revision_id,
            demo_data.REVISION_ID,
        )


if __name__ == "__main__":
    unittest.main()

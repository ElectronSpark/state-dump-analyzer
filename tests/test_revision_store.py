from __future__ import annotations

import unittest

from router_dump_analyzer.revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
)


class RevisionStoreContractTests(unittest.TestCase):
    def test_assembly_rejects_ambiguous_member_identity(self) -> None:
        first = RevisionDescriptor(
            node_id="node-a",
            revision_id="revision-a",
            label="Node A",
            event_count=100_000,
            resource_count=7_500,
        )
        with self.assertRaisesRegex(ValueError, "node_id"):
            AssemblyDescriptor(
                assembly_id="fabric",
                revisions=(
                    first,
                    RevisionDescriptor(
                        node_id="node-a",
                        revision_id="revision-b",
                        label="Duplicate A",
                        event_count=100_000,
                        resource_count=7_500,
                    ),
                ),
            )

    def test_protocol_does_not_impose_demo_scale_policy(self) -> None:
        descriptor = RevisionDescriptor(
            node_id="small-production-capture",
            revision_id="revision-1",
            label="Small capture",
            event_count=1,
            resource_count=1,
        )
        assembly = AssemblyDescriptor(
            assembly_id="capture",
            revisions=(descriptor,),
            coverage_case_ids=("basic.ipv4",),
        )
        self.assertEqual(assembly.revisions, (descriptor,))


if __name__ == "__main__":
    unittest.main()

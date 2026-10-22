"""Exact old/new topology probe semantics without a full generated archive."""

from __future__ import annotations

import random
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer import temporal_topology as topology


def _key(row):
    explicit = row.get("relationship_id") or row.get("id")
    return str(explicit) if explicit else "|".join(str(value) for value in (
        row.get("source"), row.get("relation_type", row.get("type", "related_to")),
        row.get("target"), row.get("valid_from_ns"),
    ))


def _active(row, timestamp):
    start, end = row.get("valid_from_ns"), row.get("valid_to_ns")
    return (start is None or timestamp >= int(start)) and (end is None or timestamp < int(end))


def _presence(row):
    if row is None:
        return False
    value = row.get("present", True)
    return value if type(value) is bool else None


def _reference_views(service, projection, node_times, resource_ids,
                     relationship_limit, connectivity_limit, *, requested_relation_types=None):
    """Frozen pre-optimization scan/probe/output algorithm (2026-10-22).

    Deliberately scans all endpoint histories at each probe. Do not share the
    production sampling implementation: this oracle guards loop inversion,
    last-writer precedence, representative selection and complete wire output.
    """
    node = next((item for item in node_times if item["node_id"] == service.default_node
                 and item.get("query_time_ns") is not None), None)
    empty = {"total_count": 0, "returned_count": 0, "truncated": False,
             "connectivity_candidate_count": 0}
    if node is None:
        return [], [], empty
    center, minimum, maximum = (int(node[field]) for field in
                               ("query_time_ns", "resolved_at_min_ns", "resolved_at_max_ns"))
    types = projection.get("relationship_types")
    types = None if types is None else set(types)
    if requested_relation_types is not None:
        types = requested_relation_types if types is None else types & requested_relation_types
    indexed = service.runtime is not None
    intervals = ({_key(row): row for identifier in resource_ids
                  for row in service.runtime.relationships_by_endpoint.get(identifier, [])}.values()
                 if indexed else service.dataset.get("relationship_intervals", []))
    probes = {minimum, center, maximum}
    for row in intervals:
        if types is not None and row.get("relation_type", row.get("type", "related_to")) not in types:
            continue
        if resource_ids and not {row.get("source"), row.get("target")} & resource_ids:
            continue
        for bound in (row.get("valid_from_ns"), row.get("valid_to_ns")):
            if bound is not None and minimum <= int(bound) <= maximum:
                probes.add(int(bound))
                if int(bound) > minimum:
                    probes.add(int(bound) - 1)
    ordered = sorted(probes)
    maps = []
    for timestamp in ordered:
        if indexed:
            active = {}
            for identifier in resource_ids:
                for row in service.runtime.relationships_by_endpoint.get(identifier, []):
                    if _active(row, timestamp):
                        active[_key(row)] = row
            candidates = active.values()
        else:
            candidates = service.relationship_reader(timestamp)
        maps.append({_key(row): row for row in candidates
                     if (types is None or row.get("relation_type", row.get("type")) in types)
                     and _presence(row) is not False
                     and (not resource_ids or {row.get("source"), row.get("target")} & resource_ids)})
    center_map = maps[ordered.index(center)]
    keys = sorted(set().union(*maps))
    relationships, connectivity = [], []
    connectivity_types = set(projection.get("connectivity_relation_types") or [])
    connectivity_count = 0
    for key in keys:
        row = center_map.get(key) or next(mapping[key] for mapping in maps if key in mapping)
        relation = row.get("relation_type", row.get("type", "related_to"))
        is_connectivity = relation in connectivity_types
        connectivity_count += is_connectivity
        need_relationship = len(relationships) < relationship_limit
        need_connectivity = is_connectivity and len(connectivity) < connectivity_limit
        if not need_relationship and not need_connectivity:
            continue
        possibilities = set()
        for mapping in maps:
            presence = _presence(mapping.get(key))
            possibilities.update((False, True) if presence is None else (presence,))
        confirmed = possibilities == {True}
        view = {
            "relationship_id": key, "source": row["source"], "target": row["target"],
            "source_resource_id": row["source"], "target_resource_id": row["target"],
            "relation_type": relation, "present": True if confirmed else None,
            "temporal_resolution": "stable_within_clock_window" if confirmed else "ambiguous",
            "possible_presence": sorted(possibilities), "valid_from_ns": row.get("valid_from_ns"),
            "valid_to_ns": row.get("valid_to_ns"),
            "quality": row.get("quality", "unknown") if confirmed else "ambiguous",
            "provenance": row.get("provenance", "unknown"), "evidence": row.get("evidence", []),
        }
        if need_relationship:
            relationships.append(view)
        if need_connectivity:
            connectivity.append(view)
    return relationships, connectivity, {
        "total_count": len(keys), "returned_count": len(relationships),
        "truncated": len(keys) > len(relationships), "connectivity_candidate_count": connectivity_count,
    }


def _row(identifier="edge", start=0, end=40, **fields):
    return {"relationship_id": identifier, "source": "a", "target": "b", "relation_type": "link",
            "valid_from_ns": None if start is None else str(start),
            "valid_to_ns": None if end is None else str(end), **fields}


def _service(rows, *, indexed=True, by_endpoint=None):
    service = object.__new__(topology.TemporalTopologyService)
    service.default_node = "node"
    service.dataset = {"relationship_intervals": rows}
    service.runtime = SimpleNamespace(relationships_by_endpoint=by_endpoint or {"a": rows}) if indexed else None
    service.relationship_reader = lambda timestamp: [row for row in rows if _active(row, timestamp)]
    return service


def _times(center=20, minimum=10, maximum=30):
    return [{"node_id": "node", "query_time_ns": str(center),
             "resolved_at_min_ns": str(minimum), "resolved_at_max_ns": str(maximum)}]


class TemporalRelationshipProbeTests(unittest.TestCase):
    projection = {"relationship_types": ["link"], "connectivity_relation_types": ["link"]}

    def assert_reference(self, service, *, projection=None, times=None, resource_ids=None,
                         relationship_limit=10, connectivity_limit=10, requested_relation_types=None):
        args = (self.projection if projection is None else projection,
                _times() if times is None else times, {"a"} if resource_ids is None else resource_ids,
                relationship_limit, connectivity_limit)
        options = {"requested_relation_types": requested_relation_types}
        expected = _reference_views(service, *args, **options)
        actual = service._relationship_views(*args, **options)
        self.assertEqual(actual, expected)
        return actual

    def test_seeded_duplicate_overlap_filters_limits_and_wire_output_match_old_scan(self):
        rng = random.Random(20261022)
        bounds = [None, -10, 0, 1, 9, 10, 11, 19, 20, 21, 29, 30, 31, 50]
        for case in range(250):
            rows = []
            for ordinal in range(rng.randrange(1, 32)):
                row = _row(str(rng.randrange(9)), rng.choice(bounds), rng.choice(bounds),
                           source=rng.choice(["a", "b", "outside"]), target=rng.choice(["a", "b", "elsewhere"]),
                           quality=str(ordinal), provenance=f"case-{case}", evidence=[{"ordinal": ordinal}])
                mode = rng.randrange(5)
                if mode == 0:
                    row.pop("relationship_id")
                elif mode == 1:
                    row["id"] = row.pop("relationship_id")
                if rng.randrange(5):
                    row["present"] = rng.choice([True, False, None, 0, "unknown"])
                relation = rng.choice(["link", "owns", "hidden"])
                row["relation_type"] = relation
                if rng.randrange(3) == 0:
                    row["type"] = row.pop("relation_type")
                rows.append(row)
            minimum = rng.randrange(-5, 21)
            center = minimum + rng.randrange(11)
            maximum = center + rng.randrange(11)
            projection = {"relationship_types": rng.choice([None, [], ["link"], ["link", "owns"]]),
                          "connectivity_relation_types": rng.choice([[], ["link"], ["owns", "hidden"]])}
            identifiers = rng.choice([set(), {"a"}, {"b"}, {"a", "b"}])
            by_endpoint = {"a": rows, "b": rows[::2][::-1]}
            for indexed in (False, True):
                with self.subTest(case=case, indexed=indexed):
                    self.assert_reference(_service(rows, indexed=indexed, by_endpoint=by_endpoint),
                                          projection=projection, times=_times(center, minimum, maximum),
                                          resource_ids=identifiers, relationship_limit=rng.randrange(6),
                                          connectivity_limit=rng.randrange(6),
                                          requested_relation_types=rng.choice([None, set(), {"link"}, {"link", "owns"}]))

    def test_runtime_overwrites_before_filter_but_provider_filters_before_overwrite(self):
        for excluded in ({"present": False}, {"relation_type": "hidden"}, {"source": "outside", "target": "elsewhere"}):
            rows = [_row(evidence=["earlier"]), _row(**excluded, evidence=["excluded"])]
            for indexed in (False, True):
                with self.subTest(excluded=excluded, indexed=indexed):
                    result, _, metadata = self.assert_reference(_service(rows, indexed=indexed), times=_times(20, 20, 20))
                    self.assertEqual(metadata["total_count"], 0 if indexed else 1)
                    if result:
                        self.assertEqual(result[0]["evidence"], ["earlier"])

    def test_center_or_first_probe_representative_and_legacy_probe_boundaries(self):
        rows = [_row(start=0, end=11, evidence=["first"]), _row(start=25, end=40, evidence=["later"])]
        result, _, _ = self.assert_reference(_service(rows))
        self.assertEqual(result[0]["evidence"], ["first"])
        self.assertEqual(result[0]["possible_presence"], [False, True])
        result, _, _ = self.assert_reference(_service(rows), times=_times(26))
        self.assertEqual(result[0]["evidence"], ["later"])
        # The old probe generator keeps the last identity's boundaries. Do not
        # silently add the earlier row's hidden 11..12 pulse during optimization.
        hidden = [_row(start=11, end=12), _row(start=50, end=60)]
        self.assertEqual(self.assert_reference(_service(hidden))[2]["total_count"], 0)

    def test_exact_half_open_unbounded_empty_and_unknown_presence(self):
        rows = [_row("start", 20, 21), _row("end", 10, 20), _row("empty", 20, 20),
                _row("inverted", 21, 19), _row("unbounded", None, None),
                _row("unknown", None, None, present=None), _row("invalid-presence", None, None, present=0)]
        result, _, _ = self.assert_reference(_service(rows), times=_times(20, 20, 20))
        self.assertEqual([row["relationship_id"] for row in result], ["invalid-presence", "start", "unbounded", "unknown"])
        self.assertEqual({row["relationship_id"]: row["possible_presence"] for row in result},
                         {"invalid-presence": [False, True], "start": [True], "unbounded": [True], "unknown": [False, True]})

    def test_each_non_null_runtime_bound_is_validated_once_including_excluded_rows(self):
        rows = [_row(str(i), i, i + 5, relation_type="hidden" if i % 3 == 0 else "link") for i in range(100)]
        rows += [_row("outside", 1000, 2000), _row("unbounded", None, None)]
        with patch.object(topology, "_ns", wraps=topology._ns) as parse:
            self.assert_reference(_service(rows), times=_times(50, 0, 100))
        self.assertEqual(parse.call_count, 202)
        for field, invalid in (("valid_from_ns", "invalid"), ("valid_to_ns", "invalid"),
                               ("valid_from_ns", True), ("valid_to_ns", 2**63)):
            bad = _row("duplicate", None, None, relation_type="hidden")
            bad[field] = invalid
            # Last-ID probe dedup hides the malformed row, but the runtime
            # interval scan must still reject it before considering its range.
            service = _service([bad, _row("duplicate", 1000, 2000, relation_type="hidden")])
            with self.subTest(field=field, invalid=invalid), self.assertRaises(topology.TemporalTopologyRequestError):
                service._relationship_views(self.projection, _times(), {"a"}, 10, 10)

    def test_provider_fallback_keeps_ordered_probes_iterator_cleanup_and_error_fence(self):
        service = _service([_row(start=11, end=21)], indexed=False)
        calls, closed = [], []
        def reader(timestamp):
            calls.append(timestamp)
            try:
                yield _row()
            finally:
                closed.append(timestamp)
        service.relationship_reader = reader
        service._relationship_views(self.projection, _times(), {"a"}, 10, 10)
        self.assertEqual(calls, [10, 11, 20, 21, 30])
        self.assertEqual(closed, calls)
        class ProviderAbort(BaseException):
            pass

        for error, expected in ((RuntimeError("ordinary"), RuntimeError),
                                (ProviderAbort("PRIVATE_PROVIDER_DETAIL"), topology.TemporalTopologyRequestError),
                                (KeyboardInterrupt("control"), KeyboardInterrupt)):
            def failing(_timestamp, selected=error):
                raise selected
            service.relationship_reader = failing
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(expected) as caught:
                    service._relationship_views(self.projection, _times(), {"a"}, 10, 10)
                if expected is topology.TemporalTopologyRequestError:
                    self.assertNotIn("PRIVATE_PROVIDER_DETAIL", str(caught.exception))
                else:
                    self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()

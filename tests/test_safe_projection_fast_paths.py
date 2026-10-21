from __future__ import annotations

import json
import random
import unittest
from collections import UserDict
from collections.abc import Mapping
from unittest.mock import patch

from router_dump_analyzer import normalized_data as projection


def _reference_redact(value, *, path_trie, branches=()):
    """Pre-optimization traversal, including generic Mapping dispatch."""
    if isinstance(value, Mapping):
        result = {}
        for key, nested in value.items():
            hidden, following = projection._advance_sensitive_path(
                str(key), path_trie, branches,
            )
            if not hidden:
                result[key] = _reference_redact(
                    nested, path_trie=path_trie, branches=following,
                )
        return result
    if isinstance(value, list):
        return [_reference_redact(v, path_trie=path_trie, branches=branches) for v in value]
    if isinstance(value, tuple):
        return tuple(_reference_redact(v, path_trie=path_trie, branches=branches) for v in value)
    return value


class SafeProjectionFastPathTests(unittest.TestCase):
    def test_event_compiles_effective_paths_once_for_all_payloads(self):
        policy = ({"PORT": frozenset({"secret", "state.credentials.token"})},
                  {"port/1": "PORT"}, frozenset({"secret", "state.credentials.token"}),
                  {"PORT": False})
        payload = {"secret": "private", "visible": [True, 1, "雪\0Straße"],
                   "credentials": {"token": "private", "label": "public"}}
        subject = {"resource_id": "port/1", "state": payload, "attributes": payload}
        event = {"subject": subject, "subjects": [subject],
                 "affected_resources": [subject], "effects": [subject],
                 "relationship_effects": [{"attributes": payload}],
                 "attributes": payload, "properties": payload, "result": payload}
        with patch.object(projection, "_property_path_trie",
                          wraps=projection._property_path_trie) as compile_paths:
            actual = projection.redact_event_for_client(event, {}, policy=policy)
        self.assertEqual(compile_paths.call_count, 1)
        self.assertNotIn("secret", actual["attributes"])
        self.assertEqual(actual["subject"]["state"]["credentials"], {"label": "public"})
        self.assertEqual(actual["subject"]["attributes"]["credentials"]["token"], "private")
        actual["subject"]["state"]["visible"].append("changed")
        self.assertEqual(actual["subjects"][0]["state"]["visible"], [True, 1, "雪\0Straße"])
        self.assertEqual(payload["visible"], [True, 1, "雪\0Straße"])

    def test_event_path_entry_matches_wrapper_reference(self):
        rng = random.Random(20261021)

        def wrapped_payload(result, key, name, value, path_trie):
            result.update(_reference_redact({key: value}, path_trie=path_trie))

        def tree(depth):
            if not depth or rng.randrange(4) == 0:
                return rng.choice([None, True, False, 0, 1, 1.5, "雪\0Straße"])
            names = ("credentials", "token", "credentials.token", "visible")
            values = [tree(depth - 1) for _ in names]
            return rng.choice((dict, UserDict))(zip(names, values))

        for index in range(250):
            sensitive = frozenset(rng.sample([
                "token", "credentials.token", "state.credentials", "attributes.token",
                "result", "state.visible", "properties.credentials.token",
            ], index % 5))
            policy = ({"PORT": sensitive}, {"port/1": "PORT"}, sensitive, {"PORT": False})
            subject = UserDict(resource_id="port/1", state=tree(3),
                               attributes=tree(3), key=tree(3), raw_key=tree(3))
            event = UserDict(subject=subject, subjects=[subject, tree(2)],
                             affected_resources=[subject, "port/1"], effects=[subject],
                             relationship_effects=[{"properties": tree(3)}],
                             attributes=tree(3), properties=tree(3), result=tree(3))
            actual = projection.redact_event_for_client(event, {}, policy=policy)
            with patch.object(projection, "_redact_event_payload", wrapped_payload):
                expected = projection.redact_event_for_client(event, {}, policy=policy)
            self.assertEqual(json.dumps(actual, ensure_ascii=False),
                             json.dumps(expected, ensure_ascii=False))

    def test_event_policy_mutation_and_unknown_resource_remain_conservative(self):
        policy = ({"PORT": frozenset({"port_secret"}),
                   "OTHER": frozenset({"other_secret"})},
                  {"port/1": "PORT"}, frozenset({"port_secret", "other_secret"}),
                  {"PORT": False, "OTHER": True})
        event = {"subject": {"resource_id": "port/1"}, "status": "up",
                 "effects": [{"status": "up", "condition_class": "healthy"}],
                 "attributes": {"port_secret": "private", "other_secret": "private",
                                "visible": [1]}}
        known = projection.redact_event_for_client(event, {}, policy=policy)
        self.assertEqual(known["status"], "up")
        self.assertEqual(known["attributes"], {"other_secret": "private", "visible": [1]})
        for additions in ({"subjects": [{"resource_kind": "UNDECLARED"}]},
                          {"affected_resources": ["missing"]},
                          {"subject": {}},
                          {"subjects": [{"resource_id": "missing"}]}):
            candidate = {**event, **additions}
            conservative = projection.redact_event_for_client(candidate, {}, policy=policy)
            self.assertEqual(conservative["attributes"], {"visible": [1]})
            self.assertEqual(conservative["status"], "unknown")
            self.assertEqual(conservative["effects"][0]["status"], "unknown")
        policy[0]["PORT"] = frozenset({"other_secret"})
        policy[3]["PORT"] = True
        changed = projection.redact_event_for_client(event, {}, policy=policy)
        self.assertEqual(changed["attributes"], {"port_secret": "private", "visible": [1]})
        self.assertEqual(changed["status"], "unknown")
        policy[1]["port/1"] = "OTHER"
        self.assertEqual(projection.redact_event_for_client(event, {}, policy=policy), changed)

    def test_recursive_projection_matches_reference_and_owns_containers(self):
        rng = random.Random(20261020)

        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class TupleSubclass(tuple):
            pass

        scalars = [None, True, False, 0, 1, -42, 1.25, "雪\0Straße", ""]

        def tree(depth):
            if not depth or rng.randrange(3) == 0:
                return rng.choice(scalars)
            values = [tree(depth - 1) for _ in range(4)]
            kind = rng.randrange(7)
            if kind < 3:
                return (dict, DictSubclass, UserDict)[kind](zip(
                    ("secret", "credentials", "credentials.secret", "visible"), values,
                ))
            return (list, tuple, ListSubclass, TupleSubclass)[kind - 3](values)

        for index in range(2000):
            value = tree(4)
            sensitive = ({"secret"}, {"credentials.secret"}, set())[index % 3]
            expected = _reference_redact(
                value, path_trie=projection._property_path_trie(frozenset(sensitive)),
            )
            actual = projection.redact_sensitive_tree(value, sensitive)
            self.assertEqual(actual, expected)
            self.assertEqual(type(actual), type(expected))
            self.assertEqual(json.dumps(actual, ensure_ascii=False), json.dumps(expected, ensure_ascii=False))

        source = {"visible": [{"visible": [1]}]}
        result = projection.redact_sensitive_tree(source, set())
        result["visible"][0]["visible"].append(2)
        self.assertEqual(source, {"visible": [{"visible": [1]}]})
        source["visible"][0]["visible"].append(3)
        self.assertEqual(result, {"visible": [{"visible": [1, 2]}]})

    def test_hostile_metaclass_cannot_impersonate_scalar(self):
        class ScalarImpersonator(type):
            def __eq__(cls, other):
                raise AssertionError("exact scalar guard invoked metaclass equality")

            def __hash__(cls):
                raise AssertionError("exact scalar guard invoked metaclass hashing")

        class Payload(dict, metaclass=ScalarImpersonator):
            pass

        value = Payload(secret="private", visible=Payload(secret="private", visible=1))
        self.assertEqual(projection.redact_sensitive_tree(value, {"secret"}), {"visible": {"visible": 1}})

    def test_scalar_subclass_mapping_keeps_mapping_semantics(self):
        class StringMapping(str, Mapping):
            def __iter__(self):
                return iter(("secret", "visible"))

            def __len__(self):
                return 2

            def __getitem__(self, key):
                return {"secret": "private", "visible": "public"}[key]

        value = StringMapping("private")
        self.assertEqual(projection.redact_sensitive_tree(value, {"secret"}), {"visible": "public"})

    def test_generic_mapping_event_matches_exact_safe_text_and_kind_policy(self):
        dataset = {"kind_descriptors": [
            {"kind": "PORT", "properties": [{"name": "secret", "sensitive": True}]},
            {"kind": "OTHER", "properties": [{"name": "visible", "sensitive": True}]},
        ], "resources": [{"resource_id": "port/1", "kind": "PORT"}]}
        subject = {"resource_id": "port/1", "state": {"secret": "private", "visible": "雪\0Straße"}}
        event = {"event_uid": "e1", "subject": subject, "subjects": [subject],
                 "attributes": {"secret": "private", "visible": [True, 1, 1.5, None]},
                 "unknown_extension": "private"}
        expected = '{"event_uid": "e1", "subject": {"resource_id": "port/1", "state": {"visible": "雪\\u0000Straße"}}, "subjects": [{"resource_id": "port/1", "state": {"visible": "雪\\u0000Straße"}}], "attributes": {"visible": [true, 1, 1.5, null]}}'
        for wrap in (dict, UserDict):
            candidate = wrap({**event, "subject": wrap(subject), "subjects": [wrap(subject)]})
            actual = projection.redact_event_for_client(candidate, dataset)
            self.assertEqual(json.dumps(actual, ensure_ascii=False), expected)
            with patch.object(projection, "_redact_sensitive_tree", _reference_redact):
                reference = projection.redact_event_for_client(candidate, dataset)
            self.assertEqual(json.dumps(actual, ensure_ascii=False), json.dumps(reference, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()

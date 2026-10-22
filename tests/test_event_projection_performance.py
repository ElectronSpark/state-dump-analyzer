from __future__ import annotations

import copy
import random
import unittest
from collections import UserDict
from unittest.mock import patch

from router_dump_analyzer.normalized_data import redact_event_for_client, redact_sensitive_tree


def reference_redact(value, sensitive, prefix=()):
    """Independent segment-path oracle, including rules restarting at each key."""
    if isinstance(value, (dict, UserDict)):
        result = {}
        for key, nested in value.items():
            path = prefix + tuple(str(key).split('.'))
            rules = [tuple(part for part in name.split('.') if part) for name in sensitive]
            if any(path[start:start + len(rule)] == rule
                   for rule in rules if rule for start in range(len(path) - len(rule) + 1)):
                continue
            result[key] = reference_redact(nested, sensitive, path)
        return result
    if isinstance(value, list):
        return [reference_redact(item, sensitive, prefix) for item in value]
    if isinstance(value, tuple):
        return tuple(reference_redact(item, sensitive, prefix) for item in value)
    return value


class EventProjectionPerformanceTests(unittest.TestCase):
    def test_empty_disclosure_policy_skips_irrelevant_resource_resolution(self):
        event = {
            'event_uid': 'e', 'resource_id': 'known', 'resource_kind': 'K',
            'subject': {'resource_id': 'missing', 'kind': 'OTHER', 'key': {'visible': ['雪']}},
            'subjects': [{'resource_id': 'known', 'kind': 'K'}],
            'effects': [{'resource_id': 'missing', 'kind': 'OTHER', 'after': {'value': 'kept'}}],
            'affected_resources': ['missing'], 'result': {'value': 1}, 'private_envelope': 'omit',
        }
        policy = ({'K': frozenset()}, {'known': 'K'}, frozenset(), {'K': False})
        expected = {key: copy.deepcopy(value) for key, value in event.items() if key != 'private_envelope'}
        with patch('router_dump_analyzer.normalized_data._event_resource_kinds',
                   side_effect=AssertionError('no resource association can change an empty policy')):
            for value in (event, UserDict(event)):
                projected = redact_event_for_client(value, {}, policy=policy)
                self.assertEqual(projected, expected)
                projected['subject']['key']['visible'].append('changed')
                self.assertEqual(event['subject']['key']['visible'], ['雪'])

    def test_empty_policy_shortcut_does_not_skip_private_fields_or_conditions(self):
        event = {'resource_id': 'r', 'resource_kind': 'K', 'status': 'private-status',
                 'subject': {'resource_id': 'missing'}, 'result': {'secret': 'private-value', 'visible': 1}}
        policies = [
            ({'K': frozenset({'secret'})}, {'r': 'K'}, frozenset({'secret'}), {'K': False}),
            ({'K': frozenset()}, {'r': 'K'}, frozenset({'secret'}), {'K': False}),
            ({'K': frozenset({'secret'})}, {'r': 'K'}, frozenset(), {'K': False}),
            ({'K': frozenset()}, {'r': 'K'}, frozenset(), {'K': True}),
        ]
        for index, policy in enumerate(policies):
            with self.subTest(index=index):
                projected = redact_event_for_client(event, {}, policy=policy)
                if index < 3:
                    self.assertEqual(projected['result'], {'visible': 1})
                else:
                    self.assertEqual(projected['status'], 'unknown')

    def test_nested_redaction_matches_segment_path_oracle(self):
        rng = random.Random(20261003)
        keys = ('a', 'b', 'private', 'a.b', 'b.private', 'a.b.private', 'visible')
        def payload(depth):
            if depth == 0:
                return rng.choice((None, 7, 'keep'))
            choice = rng.randrange(4)
            if choice == 0:
                return [payload(depth - 1) for _ in range(3)]
            if choice == 1:
                return tuple(payload(depth - 1) for _ in range(2))
            mapping = {rng.choice(keys): payload(depth - 1) for _ in range(4)}
            return UserDict(mapping) if choice == 2 else mapping
        for sensitive in (set(), {'private'}, {'a.b'}, {'a.b.private', 'b.private'}):
            for _ in range(80):
                value = payload(4)
                with self.subTest(sensitive=sensitive, value=value):
                    self.assertEqual(reference_redact(value, sensitive), redact_sensitive_tree(value, sensitive))

    def test_event_nested_payload_is_redacted_once_and_copied(self):
        for sensitive in (frozenset(), frozenset({'credentials.private', 'secret'})):
            payload = {'credentials': [{'private': 'hidden', 'visible': ['keep']}],
                       'credentials.private': 'hidden', 'secret': 'hidden'}
            event = {'event_uid': 'e', 'resource_kind': 'K',
                     'subject': {'resource_kind': 'K', 'key': copy.deepcopy(payload)},
                     'effects': [{'resource_kind': 'K', 'after': copy.deepcopy(payload)}],
                     'result': copy.deepcopy(payload)}
            policy = ({'K': sensitive}, {}, sensitive, {'K': False})
            projected = redact_event_for_client(event, {}, policy=policy)
            expected = reference_redact(payload, sensitive)
            self.assertEqual(expected, projected['subject']['key'])
            self.assertEqual(expected, projected['effects'][0]['after'])
            self.assertEqual(expected, projected['result'])
            projected['subject']['key']['credentials'][0]['visible'].append('changed')
            projected['effects'][0]['after']['credentials'][0]['visible'].append('changed')
            projected['result']['credentials'][0]['visible'].append('changed')
            self.assertEqual(['keep'], event['subject']['key']['credentials'][0]['visible'])
            self.assertEqual(['keep'], event['effects'][0]['after']['credentials'][0]['visible'])
            self.assertEqual(['keep'], event['result']['credentials'][0]['visible'])


if __name__ == '__main__':
    unittest.main()

from __future__ import annotations

import unittest
from unittest.mock import Mock

from router_dump_analyzer._sqlite_transactions import sqlite_transaction


class SqliteTransactionTests(unittest.TestCase):
    def test_successful_phases_are_ordered(self) -> None:
        phases: list[str] = []
        with sqlite_transaction(
            begin=lambda: phases.append("begin"),
            checkpoint=lambda: phases.append("checkpoint"),
            commit=lambda: phases.append("commit"),
            recover=lambda: phases.append("recover"),
        ):
            phases.append("body")
        self.assertEqual(
            phases, ["begin", "checkpoint", "body", "checkpoint", "commit"]
        )

    def test_every_phase_failure_is_recovered_and_preserved(self) -> None:
        phases = ("begin", "after_begin", "body", "before_commit", "commit")
        for failing_phase in phases:
            with self.subTest(phase=failing_phase):
                failure = RuntimeError(failing_phase)
                recover = Mock()
                checkpoint_calls = 0

                def phase(
                    name: str,
                    selected: str = failing_phase,
                    error: RuntimeError = failure,
                ) -> None:
                    if name == selected:
                        raise error

                def checkpoint() -> None:
                    nonlocal checkpoint_calls
                    checkpoint_calls += 1
                    phase(
                        "after_begin" if checkpoint_calls == 1 else "before_commit"
                    )

                with (
                    self.assertRaises(RuntimeError) as raised,
                    sqlite_transaction(
                        begin=lambda: phase("begin"),
                        commit=lambda: phase("commit"),
                        recover=recover,
                        checkpoint=checkpoint,
                    ),
                ):
                    phase("body")
                self.assertIs(raised.exception, failure)
                recover.assert_called_once_with()

    def test_process_control_failure_is_recovered_without_conversion(self) -> None:
        failure = KeyboardInterrupt()
        recover = Mock()
        commit = Mock()
        with (
            self.assertRaises(KeyboardInterrupt) as raised,
            sqlite_transaction(begin=Mock(), commit=commit, recover=recover),
        ):
            raise failure
        self.assertIs(raised.exception, failure)
        recover.assert_called_once_with()
        commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import unittest
from threading import Event, Thread
from unittest.mock import patch

from router_dump_analyzer import _import_scheduling as scheduling
from router_dump_analyzer.history_search_core import (
    HistorySearchCapacityError,
    HistorySearchCorpus,
)
from router_dump_analyzer.ingestion_pipeline import DurableIngestionPipeline


class ImportSchedulingTests(unittest.TestCase):
    def _call_from_other_thread(self, callback) -> None:
        errors = []

        def invoke():
            try:
                callback()
            except BaseException as error:  # noqa: BLE001 - assert cancellation and control exits
                errors.append(error)

        thread = Thread(target=invoke)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]

    def test_idle_and_same_thread_search_never_sleep(self) -> None:
        with patch.object(scheduling, "sleep") as pause:
            scheduling._cooperate_with_durable_import()
            with scheduling._processing_durable_import():
                scheduling._cooperate_with_durable_import()
                with scheduling._processing_durable_import():
                    scheduling._cooperate_with_durable_import()
            pause.assert_not_called()

    def test_nested_scopes_keep_cooperation_until_outer_exit(self) -> None:
        with patch.object(scheduling, "sleep") as pause:
            with scheduling._processing_durable_import():
                with scheduling._processing_durable_import():
                    self._call_from_other_thread(scheduling._cooperate_with_durable_import)
                self._call_from_other_thread(scheduling._cooperate_with_durable_import)
            self._call_from_other_thread(scheduling._cooperate_with_durable_import)
            self.assertEqual(pause.call_count, 2)
            pause.assert_called_with(0.0001)

    def test_concurrent_imports_release_independently(self) -> None:
        ready = [Event(), Event()]
        release = [Event(), Event()]

        def importing(index):
            with scheduling._processing_durable_import():
                ready[index].set()
                release[index].wait(5)

        threads = [Thread(target=importing, args=(index,)) for index in range(2)]
        with patch.object(scheduling, "sleep") as pause:
            try:
                for thread in threads:
                    thread.start()
                self.assertTrue(all(event.wait(5) for event in ready))
                scheduling._cooperate_with_durable_import()
                release[0].set()
                threads[0].join(5)
                self.assertFalse(threads[0].is_alive())
                scheduling._cooperate_with_durable_import()
                release[1].set()
                threads[1].join(5)
                self.assertFalse(threads[1].is_alive())
                scheduling._cooperate_with_durable_import()
                self.assertEqual(pause.call_count, 2)
            finally:
                for event in release:
                    event.set()
                for thread in threads:
                    thread.join(5)

    def test_all_durable_stages_scope_errors_and_cancellation(self) -> None:
        pipeline = object.__new__(DurableIngestionPipeline)
        for state, method in (
            ("admitting", "_run_admission"),
            ("probing", "_run_probe"),
            ("ingesting", "_run_ingestion"),
            ("publishing", "_run_publication"),
        ):
            for failure in (None, ValueError("failed"), asyncio.CancelledError()):
                with self.subTest(state=state, failure=type(failure).__name__):
                    def stage(_row, failure=failure):
                        self._call_from_other_thread(scheduling._cooperate_with_durable_import)
                        if failure is not None:
                            raise failure

                    with (
                        patch.object(pipeline, "_require_composition_policy"),
                        patch.object(pipeline, method, side_effect=stage),
                        patch.object(scheduling, "sleep") as pause,
                    ):
                        try:
                            pipeline._run_claimed_stage({"state": state})
                        except BaseException as error:  # noqa: BLE001 - assert cancellation and control exits
                            self.assertIs(error, failure)
                        else:
                            self.assertIsNone(failure)
                        self._call_from_other_thread(scheduling._cooperate_with_durable_import)
                        pause.assert_called_once_with(0.0001)

    def test_policy_rejection_does_not_leak_an_active_import(self) -> None:
        pipeline = object.__new__(DurableIngestionPipeline)
        with (
            patch.object(pipeline, "_require_composition_policy", side_effect=ValueError("policy")),
            patch.object(pipeline, "_run_ingestion") as ingest,
            patch.object(scheduling, "sleep") as pause,
        ):
            with self.assertRaisesRegex(ValueError, "policy"):
                pipeline._run_claimed_stage({"state": "ingesting"})
            self._call_from_other_thread(scheduling._cooperate_with_durable_import)
            ingest.assert_not_called()
            pause.assert_not_called()

    def test_a_pause_does_not_hold_up_import_scope_cleanup(self) -> None:
        ready, release = Event(), Event()

        def importing():
            with scheduling._processing_durable_import():
                ready.set()
                release.wait(5)

        thread = Thread(target=importing)
        thread.start()
        try:
            self.assertTrue(ready.wait(5))

            def pause(_seconds):
                release.set()
                thread.join(5)
                self.assertFalse(thread.is_alive())

            with patch.object(scheduling, "sleep", side_effect=pause):
                scheduling._cooperate_with_durable_import()
        finally:
            release.set()
            thread.join(5)

    def test_search_keeps_exact_results_and_bounds_during_cooperation(self) -> None:
        with (
            scheduling._processing_durable_import(),
            patch.object(scheduling, "sleep") as pause,
        ):
            def query():
                corpus = HistorySearchCorpus()
                documents = lambda: (f"match-{ordinal}" for ordinal in range(145))
                self.assertEqual(list(corpus.query("match", documents)), list(range(145)))
                self.assertEqual(list(corpus.query("match-144", documents)), [144])

                bounded = HistorySearchCorpus(max_documents=65)
                with self.assertRaises(HistorySearchCapacityError):
                    bounded.query("match", documents)

            self._call_from_other_thread(query)
            self.assertGreater(pause.call_count, 0)
        with patch.object(scheduling, "sleep") as pause:
            self._call_from_other_thread(
                lambda: HistorySearchCorpus().query("match", lambda: ("match" for _ in range(145)))
            )
            pause.assert_not_called()

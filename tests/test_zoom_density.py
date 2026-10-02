"""Lightweight exact density and bounded zoom work checks."""
import random
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from collections import Counter

from router_dump_analyzer.zoom_density import DensityIndex, adaptive_type_counts


class DensityTests(unittest.TestCase):
    def test_sparse_high_cardinality_sweeps_dictionary_once(self):
        class CountingTypes(dict):
            calls = 0
            def items(self):
                self.calls += 1
                return super().items()
        types = CountingTypes({str(i): [i % 128] for i in range(2048)})
        density = DensityIndex(sorted(i % 128 for i in range(2048)), (), types)
        kwargs = dict(start_ns=0, integer_span=128, bin_count=128,
                      bin_start_index=0, bin_end_index=128)
        page = density.page(**kwargs)
        self.assertEqual(types.calls, 1)
        self.assertEqual(sum(p.count for p in page.values()), 2048)
        self.assertTrue(all(len(p.type_counts) == 16 for p in page.values()))
        self.assertEqual(density.page(**kwargs), page)
        self.assertEqual(types.calls, 1)

    def test_concurrent_requests_cancel_without_corrupting_lru(self):
        density = DensityIndex(range(4096), (), {'a': range(4096)}, max_cache_units=24)
        barrier = Barrier(4)
        def run(offset):
            barrier.wait(timeout=5)
            calls = 0
            def checkpoint():
                nonlocal calls
                calls += 1
                if offset == 3 and calls == 12:
                    raise RuntimeError('cancelled')
            return density.page(start_ns=offset * 1024, integer_span=1024,
                                bin_count=16, bin_start_index=0, bin_end_index=16,
                                checkpoint=checkpoint)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(run, offset) for offset in range(4)]
            for future in futures[:3]:
                self.assertEqual(sum(p.count for p in future.result().values()), 1024)
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                futures[3].result()
        with density._lock:
            self.assertEqual(density._cache_units, sum(1 + len(v.type_counts) for v in density._cache.values()))
            self.assertLessEqual(density._cache_units, 24)
            self.assertFalse(any(lo >= 3072 for lo, _ in density._cache))

    def test_successful_hits_refresh_lru(self):
        density = DensityIndex(range(16), (), {'a': range(16)}, max_cache_units=4)
        def query(start):
            density.page(start_ns=start, integer_span=4, bin_count=1,
                         bin_start_index=0, bin_end_index=1)
        query(0)
        query(4)
        query(0)
        query(8)
        self.assertEqual(list(density._cache), [(0, 4), (8, 4)])

    def test_exact_inclusive_partitions_and_types(self):
        random.seed(41)
        by_type = {str(i): sorted(random.randrange(-50, 80) for _ in range(70)) for i in range(8)}
        times = sorted(t for values in by_type.values() for t in values)
        failures = times[::5]
        density = DensityIndex(times, failures, by_type)
        for start, span, bins in [(-50, 130, 17), (-7, 29, 100), (5, 1, 1), (-90, 200, 9)]:
            page = density.page(start_ns=start, integer_span=span, bin_count=bins,
                                bin_start_index=0, bin_end_index=bins)
            adaptive = adaptive_type_counts(by_type, start_ns=start, integer_span=span,
                                            bin_count=bins, bin_start_index=0, bin_end_index=bins)
            for i in range(bins):
                lo, hi = start + span * i // bins, start + span * (i + 1) // bins
                expected = {name: sum(lo <= t < hi for t in values) for name, values in by_type.items()}
                expected = {name: amount for name, amount in expected.items() if amount}
                self.assertEqual(adaptive.get(i, {}), expected)
                if expected:
                    self.assertEqual(page[i].type_counts, expected)
                    self.assertEqual(page[i].count, sum(expected.values()))
                    self.assertEqual(page[i].failure_count, sum(lo <= t < hi for t in failures))
                else:
                    self.assertNotIn(i, page)

    def test_million_dense_points_bounded_operations_and_warm_reuse(self):
        # range is a million timestamps without a million rich event dictionaries.
        times = range(1_000_000)
        density = DensityIndex(times, range(0, 1_000_000, 10), {'dense': times})
        kwargs = dict(start_ns=0, integer_span=1_000_000, bin_count=180,
                      bin_start_index=0, bin_end_index=180)
        page = density.page(**kwargs)
        self.assertEqual(sum(p.count for p in page.values()), 1_000_000)
        self.assertEqual(sum(p.failure_count for p in page.values()), 100_000)
        self.assertLess(density.stats['bisections'], 6000)
        self.assertLess(density.stats['swept_points'], 100)
        before = density.stats['bisections']
        self.assertEqual(density.page(**kwargs), page)
        self.assertEqual(density.stats['bisections'], before)
        class CountedTimes:
            reads = 0
            def __len__(self):
                return 1_000_000
            def __getitem__(self, index):
                self.reads += 1
                return index
        counted = CountedTimes()
        adaptive = adaptive_type_counts({'dense': counted}, **kwargs)
        self.assertEqual(sum(c['dense'] for c in adaptive.values()), 1_000_000)
        self.assertLess(counted.reads, 10000)

    def test_cache_bounds_isolation_and_cancellation(self):
        density = DensityIndex(range(1000), (), {'a': range(1000)}, max_cache_units=8)
        kwargs = dict(start_ns=0, integer_span=1000, bin_count=50,
                      bin_start_index=0, bin_end_index=50)
        density.page(**kwargs)
        self.assertLessEqual(density.cache_units, 8)
        self.assertLessEqual(density.cache_entries, 4)
        other = DensityIndex(range(10), (), {'b': range(10)})
        self.assertEqual(other.cache_entries, 0)
        snapshot = list(density._cache.items())
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            if calls == 10:
                raise RuntimeError('cancelled')
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            density.page(**{**kwargs, 'start_ns': 2000}, checkpoint=cancel)
        self.assertEqual(list(density._cache.items()), snapshot)

    def test_resolution_reuses_aligned_cells_without_truncating_types(self):
        by_type = {str(i): range(i, 1024, 8) for i in range(8)}
        density = DensityIndex(range(1024), (), by_type)
        common = dict(start_ns=0, integer_span=1024, bin_start_index=0)
        density.page(**common, bin_count=4, bin_end_index=4)
        density.page(**common, bin_count=8, bin_end_index=8)
        before = density.stats['bisections']
        page = density.page(**common, bin_count=8, bin_end_index=8)
        self.assertEqual(before, density.stats['bisections'])
        self.assertEqual(len(page[0].type_counts), 8)
        finer = DensityIndex(range(1024), (), by_type)
        finer.page(**common, bin_count=8, bin_end_index=8)
        before = finer.stats['bisections']
        coarse = finer.page(**common, bin_count=4, bin_end_index=4)
        self.assertEqual(before, finer.stats['bisections'])
        self.assertEqual(finer.stats['cells_merged'], 4)
        self.assertEqual(coarse[0].type_counts, {str(i): 32 for i in range(8)})


if __name__ == '__main__':
    unittest.main()

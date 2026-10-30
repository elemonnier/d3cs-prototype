#!/usr/bin/env python3
import csv
import tempfile
import unittest
from pathlib import Path

import reconnection_latency as bench


class ReconnectionLatencyTests(unittest.TestCase):
    def test_nearest_rank_p95(self):
        self.assertEqual(bench.nearest_rank([1.0, 2.0, 3.0, 4.0], 0.95), 4.0)

    def test_write_results_keeps_failures_out_of_statistics(self):
        rows = [bench.base_row(1), bench.base_row(2)]
        rows[0].update(status="success", message_id="reconnection-001-1", delivery_ms="4.0")
        rows[1].update(status="timeout", message_id="reconnection-002-2", error="timeout")
        with tempfile.TemporaryDirectory() as directory:
            paths = bench.write_results(Path(directory), rows)
            with Path(paths[1]).open(newline="", encoding="utf-8") as stream:
                summary = next(csv.DictReader(stream))
            self.assertEqual(summary["n_success"], "1")
            self.assertEqual(summary["n_failures"], "1")
            self.assertEqual(summary["mean_ms"], "4.000000")
            with Path(paths[2]).open(newline="", encoding="utf-8") as stream:
                errors = list(csv.DictReader(stream))
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["status"], "timeout")

    def test_short_defaults(self):
        args = bench.parse_args(["--short"])
        self.assertEqual(args.repetitions, 1)
        self.assertEqual(args.outage_seconds, 1.0)
        self.assertEqual(args.timeout_seconds, 10.0)


if __name__ == "__main__":
    unittest.main()

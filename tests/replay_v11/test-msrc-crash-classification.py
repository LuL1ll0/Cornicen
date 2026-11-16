# script-purpose: Verify moved Microsoft transactions remain crash injection points.
# script-class: harness
# script-trigger: Manual unittest execution after replay classifier changes.
# script-tests: tests/replay_v11/test-msrc-crash-classification.py
"""Read Microsoft replay fixtures; write temporary stores; unittest exits 0/1.

Run PYTHONPATH=src:. python3 tests/replay_v11/test-msrc-crash-classification.py.
"""
import unittest

from tests.replay_v11 import harness as h


class MicrosoftCrashClassificationTests(unittest.TestCase):
    def test_shared_transactions_are_injectable(self):
        baseline = h.run_crash_scenario('csaf')
        index = next(i for i, point in enumerate(baseline.points)
                     if point.startswith('msrc_charge:csaf_directory.py/'))
        replay = h.run_crash_scenario('csaf', index)
        self.assertTrue(replay.crashed)
        self.assertEqual(replay.deliveries, baseline.deliveries)
        for key, snapshot in baseline.result.snapshots.items():
            for field in ('events', 'baseline'):
                self.assertEqual(replay.result.snapshots[key][field], snapshot[field])


if __name__ == '__main__':
    unittest.main()

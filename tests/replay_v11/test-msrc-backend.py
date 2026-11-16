# script-purpose: Run the Microsoft replay backend and crash recovery acceptance tests.
# script-class: harness
# script-trigger: unittest discovery or direct foreground execution.
# script-tests: tests/test_task2_b2.py, tests/replay_v11/test-msrc-backend.py
"""Read Microsoft JSONL scripts and fixtures; write temporary stores and staging files.

Run PYTHONPATH=src:. python3 tests/replay_v11/test-msrc-backend.py; exit 0/1.
"""
import unittest
from tests import test_task2_b2


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(test_task2_b2.Task2B2Tests(method) for method in (
        'test_t15_csaf_scenario', 'test_t16_inventory_scenario',
        'test_t17_bootstrap_scenario', 'test_t20_crash_replays'))


if __name__ == '__main__':
    unittest.main()

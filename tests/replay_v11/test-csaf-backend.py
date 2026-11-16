# script-purpose: Run the source-keyed Cisco replay backend acceptance tests.
# script-class: harness
# script-trigger: Direct foreground execution or unittest.
# script-tests: tests/test_task3_b2.py, tests/replay_v11/test-csaf-backend.py
"""Read invented Cisco scenarios; write temporary stores; unittest exits 0/1.

Run PYTHONPATH=src:. python3 tests/replay_v11/test-csaf-backend.py.
"""
import unittest
from tests.test_task3_b2 import Task3B2Tests


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(Task3B2Tests(method) for method in (
        'test_t15_platform', 'test_t16_inventory', 'test_t17_bad_member_and_projection',
        'test_t18_bootstrap_retry_and_conflict', 'test_t20_factory_and_watch_independence'))


if __name__ == '__main__':
    unittest.main()

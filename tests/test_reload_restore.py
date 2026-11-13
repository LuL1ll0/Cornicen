# script-purpose: Verify a failed watch reload restores the engine report even when cache restoration fails.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_reload_restore.py
"""Reads no files beyond fixtures, writes only an in-memory database, uses no network.

Run with python -m unittest tests.test_reload_restore. Exit 0 means success,
1 means failed tests, and 2 means invalid unittest arguments.
"""

from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch

from tests import test_ssvc as fixtures


class ReloadRestoreTests(unittest.TestCase):
    setUp = fixtures.SsvcTests.setUp

    def test_reload_secondary_cache_failure_restores_report(self):
        previous = self.engine.report
        original = self.engine._cache_watch_identities
        calls = 0

        def cache():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('invented restore-cache failure')
            return original()

        with patch.object(self.engine, '_cache_watch_identities', side_effect=cache), \
                patch.object(self.engine, '_save_watches', side_effect=sqlite3.OperationalError('invented reload failure')):
            with self.assertRaises(MemoryError):
                self.engine.reload_watches((replace(self.watches[0], version='9.8.8'),))
        self.assertIs(self.engine.report, previous)
        self.assertEqual(self.engine.watches, self.watches)
        self.assertFalse(self.store.connection.in_transaction)


if __name__ == '__main__':
    unittest.main()

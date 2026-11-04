"""Correction dedupe and unchanged-fetch recovery boundaries."""
from dataclasses import replace
from datetime import timedelta
import unittest

from cornicen.model import FetchStatus, IngestResult, Origin
from tests import test_goal_found_bugs as helpers


class Batch2Tests(unittest.TestCase):
    setUp = helpers.GoalFoundBugs.setUp
    ingest = helpers.GoalFoundBugs.ingest
    pair = helpers.GoalFoundBugs.pair

    def unchanged(self):
        return IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                            None, None, unchanged=True)

    def test_unknown_then_unaffected_corrects_once_and_rearms(self):
        self.engine.run_cycle([self.ingest(helpers.record())])
        self.now = self.now.replace(hour=8)
        self.engine.run_cycle([])
        self.assertEqual(self.pair()['notified'], 1)
        episode = self.pair()['episode']
        self.engine.run_cycle([self.ingest(helpers.record('unknown'))])
        cleared = self.ingest(helpers.record('unaffected'))
        for _ in range(2):
            self.engine.run_cycle([cleared])
        corrections = self.store.connection.execute(
            "SELECT count(*) FROM events WHERE type='correction'").fetchone()[0]
        self.assertEqual(corrections, 1)
        self.assertEqual(self.pair()['episode'], episode + 1)
        self.assertEqual(self.pair()['notified'], 0)
        report = self.engine.run_cycle([self.ingest(helpers.record())])
        self.assertIn(f'widget|{helpers.CVE}|new match|{episode + 1}', report.events)

    def test_unchanged_fetch_preserves_cursor_and_clears_fetch_retry(self):
        self.engine.run_cycle([replace(self.ingest(), cursor='cve_2026-11-03_0700Z')])
        cursor = tuple(self.store.connection.execute(
            "SELECT * FROM cursors WHERE source='cvelist'").fetchone())
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.FAILED, Origin.DELTA,
                                           None, None, errors=('listing failed',))])
        self.engine.run_cycle([self.unchanged()])
        self.assertEqual(tuple(self.store.connection.execute(
            "SELECT * FROM cursors WHERE source='cvelist'").fetchone()), cursor)
        self.assertIsNone(self.store.connection.execute(
            "SELECT 1 FROM retry_queue WHERE source='cvelist' AND record_id='@fetch'").fetchone())
        self.assertIsNone(self.store.get_meta('last_error:cvelist'))
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'healthy')

    def test_unchanged_fetch_cannot_clear_incomplete_records_or_stale_coverage(self):
        invalid = helpers.record()
        del invalid['containers']['cna']['affected']
        self.engine.run_cycle([self.ingest(invalid)])
        self.engine.run_cycle([self.unchanged()])
        self.assertIsNotNone(self.store.connection.execute(
            "SELECT 1 FROM retry_queue WHERE source='cvelist' AND record_id=?",
            (helpers.CVE,)).fetchone())
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'unhealthy')
        self.engine.run_cycle([self.ingest(helpers.record())])
        self.now += timedelta(hours=4)
        self.engine.run_cycle([self.unchanged()])
        row = self.store.connection.execute(
            "SELECT state,detail FROM health WHERE source='cvelist'").fetchone()
        self.assertEqual(row['state'], 'unhealthy')
        self.assertIn('stale', row['detail'])

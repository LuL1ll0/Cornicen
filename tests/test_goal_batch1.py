"""Boundary checks for the first confirmed-defect batch."""
from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

from cornicen.engine import Engine
from cornicen.identity import AliasMap
from tests import test_goal_found_bugs as helpers


class Batch1Tests(unittest.TestCase):
    setUp = helpers.GoalFoundBugs.setUp
    catalog = helpers.GoalFoundBugs.catalog
    ingest = helpers.GoalFoundBugs.ingest
    pair = helpers.GoalFoundBugs.pair
    watch_notifications = helpers.GoalFoundBugs.watch_notifications

    def test_first_catalog_waits_for_cna_then_alerts_new_match(self):
        self.store.connection.execute("DELETE FROM meta WHERE k IN ('baseline_complete','kev_initialized')")
        self.store.set_meta('cvelist_snapshot_complete', '1')
        self.engine.run_cycle([self.catalog([helpers.kev()])])
        self.assertIsNone(self.pair())
        self.assertIsNone(self.store.get_meta('kev_only:' + helpers.CVE))
        self.assertEqual(self.watch_notifications(), [])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 0)
        self.engine.run_cycle([self.ingest(helpers.record())])
        self.assertEqual([n.reasons for n in self.watch_notifications()], [('new match',)])

    def test_kev_only_later_unknown_cna_does_not_correct(self):
        self.engine.run_cycle([self.catalog([helpers.kev()])])
        report = self.engine.run_cycle([self.ingest(helpers.record('unknown'))])
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertFalse(any('|correction|' in key for key in report.events))
        self.assertEqual(len(self.watch_notifications()), 1)

    def test_kev_only_cna_resolution_retry_queues_affected_correction(self):
        self.engine.run_cycle([self.catalog([helpers.kev()])])
        with patch('cornicen.applicability.resolve', side_effect=ValueError('retry resolution')):
            self.engine.run_cycle([self.ingest(helpers.record())])
        self.assertEqual(self.store.get_meta('kev_only:' + helpers.CVE), '1')
        report = self.engine.run_cycle([])
        self.assertEqual(self.pair()['state'], 'affected')
        self.assertTrue(any('|correction|' in key for key in report.events))
        row = self.store.connection.execute(
            "SELECT body_json FROM outbox WHERE pair_key=? AND sent_at IS NULL",
            ('widget|' + helpers.CVE + '|correction',)).fetchone()
        self.assertIn('"state": "affected"', row[0])
        self.assertIsNone(self.store.get_meta('kev_only:' + helpers.CVE))

    def test_kev_only_pair_survives_restart_and_clears_on_removal(self):
        unrelated = dict(helpers.kev(helpers.OTHER), product='other-widget')
        self.engine.run_cycle([self.catalog([helpers.kev(), unrelated])])
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.pair()['exploited'], 1)
        self.assertEqual(len(self.watch_notifications()), 1)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 0)
        self.engine = Engine(self.store, (self.watch,), AliasMap(), self.config,
                             lambda: self.now, self.notifier)
        self.engine.run_cycle([self.catalog([unrelated])])
        self.assertEqual(self.pair()['exploited'], 0)
        self.assertEqual(len(self.watch_notifications()), 1)
        self.assertIsNone(self.store.connection.execute("SELECT 1 FROM health WHERE source='records'").fetchone())

    def test_kev_only_pair_accepts_later_cna_exclusion(self):
        self.engine.run_cycle([self.catalog([helpers.kev()])])
        self.engine.run_cycle([self.ingest(helpers.record('unaffected'))])
        self.assertEqual(self.pair()['state'], 'not_affected')
        self.assertIsNone(self.store.get_meta('kev_only:' + helpers.CVE))

    def test_regressed_catalog_after_restart_preserves_data_and_fails_health(self):
        accepted = self.catalog([helpers.kev(), helpers.kev(helpers.OTHER)])
        self.engine.run_cycle([accepted])
        before = [tuple(row) for row in self.store.connection.execute('SELECT * FROM kev ORDER BY cve')]
        cursor = tuple(self.store.connection.execute("SELECT * FROM cursors WHERE source='kev'").fetchone())
        self.engine = Engine(self.store, (self.watch,), AliasMap(), self.config,
                             lambda: self.now, self.notifier)
        stale = replace(self.catalog([helpers.kev(helpers.OTHER)]),
                        content_time=self.now - timedelta(days=1), cursor='older')
        for _ in range(2):
            self.engine.run_cycle([stale])
            self.assertEqual([tuple(row) for row in self.store.connection.execute('SELECT * FROM kev ORDER BY cve')], before)
            self.assertEqual(tuple(self.store.connection.execute("SELECT * FROM cursors WHERE source='kev'").fetchone()), cursor)
            self.assertEqual(self.pair()['exploited'], 1)
            self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='kev'").fetchone()[0], 'unhealthy')
            self.assertIsNotNone(self.store.connection.execute("SELECT 1 FROM retry_queue WHERE source='kev' AND record_id='@fetch'").fetchone())
        self.engine.run_cycle([accepted])
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='kev'").fetchone()[0], 'healthy')

    def test_missing_affected_retains_record_and_queues_retry(self):
        self.engine.run_cycle([self.ingest(helpers.record())])
        before = self.engine._record(helpers.CVE)
        bad = helpers.record()
        del bad['containers']['cna']['affected']
        self.engine.run_cycle([self.ingest(bad)])
        self.assertEqual(self.engine._record(helpers.CVE), before)
        self.assertEqual(self.pair()['state'], 'affected')
        self.assertIsNotNone(self.store.connection.execute(
            "SELECT 1 FROM retry_queue WHERE source='cvelist' AND record_id=?", (helpers.CVE,)).fetchone())

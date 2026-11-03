"""Delivery and record evaluation must have independent durable lifecycles."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
import tempfile
import unittest
from unittest.mock import patch

from tests import test_task5_regressions as helpers
from tests import test_watchlist
from tests.source_helpers import expected_projection


class Round3Tests(unittest.TestCase):
    setUp = helpers.Task5Tests.setUp
    start = helpers.Task5Tests.start
    ingest = helpers.Task5Tests.ingest
    count = helpers.Task5Tests.count
    kev = helpers.Task5Tests.kev

    def fixed(self):
        record = deepcopy(self.record)
        record['containers']['cna']['affected'][0]['versions'][0]['status'] = 'unaffected'
        return record

    def state(self):
        return self.store.connection.execute('SELECT state FROM pairs').fetchone()[0]

    def test_flush_preserves_record_retry_due_or_not(self):
        for due in (False, True):
            with self.subTest(due=due):
                self.setUp()
                self.start()
                self.engine.run_cycle([self.ingest([self.record])])
                if due:
                    self.clock.now += timedelta(hours=1)
                with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
                    self.engine.run_cycle([self.ingest([self.fixed()])])
                self.assertEqual(self.count('retry_queue'), 1)
                self.engine.run_cycle([])
                self.assertEqual(self.state(), 'not_affected')
                self.assertEqual(self.count('retry_queue'), 0)

    def test_pruning_keeps_referenced_records(self):
        self.start()
        self.engine.config = replace(self.config, retention_days=30)
        self.engine.run_cycle([self.ingest([self.record]), self.kev()])
        self.clock.now += timedelta(days=31)
        self.engine.run_cycle([])
        self.notifier.delivered.clear()
        self.engine.run_cycle([self.kev()])
        self.assertEqual(self.state(), 'affected')
        self.assertEqual(self.count('records'), 1)
        self.assertEqual([n for n in self.notifier.delivered if n['watch']], [])

    def test_missing_record_keeps_pair_and_reports_records_health(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record]), self.kev()])
        self.store.connection.execute('DELETE FROM records')
        self.engine.reload_watches((replace(self.watches[0], name='Renamed'),))
        self.engine.run_cycle([])
        self.assertEqual(self.state(), 'affected')
        row = self.store.connection.execute("SELECT state FROM health WHERE source='records'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'unhealthy')

    def test_kev_and_watchlist_retries_use_current_record(self):
        for source in ('kev', 'watchlist'):
            with self.subTest(source=source):
                self.setUp()
                self.start()
                self.engine.run_cycle([self.ingest([self.record])])
                self.clock.now += timedelta(hours=1)
                self.engine.run_cycle([])
                with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
                    if source == 'kev':
                        self.engine.run_cycle([self.kev()])
                    else:
                        self.engine.reload_watches((replace(self.watches[0], name='Renamed'),))
                self.notifier.delivered.clear()
                self.engine.run_cycle([self.ingest([self.fixed()])])
                self.assertEqual(self.state(), 'not_affected')
                rows = self.store.connection.execute("SELECT reasons_json FROM outbox WHERE sent_at IS NULL AND pair_key LIKE 'service|%'").fetchall()
                self.assertEqual([json.loads(r[0]) for r in rows], [['correction']])
                self.assertEqual([n for n in self.notifier.delivered if n['watch']], [])

    def dead_letter(self):
        self.start()
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.run_cycle([self.ingest([self.record])])
            for _ in range(4):
                self.engine.run_cycle([])
        self.assertEqual(self.count('dead_letters'), 1)

    def test_dead_letter_success_recovers(self):
        self.dead_letter()
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.count('dead_letters'), 0)
        self.assertEqual(self.state(), 'affected')
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'healthy')

    def test_dead_letter_daily_and_version_retry(self):
        self.dead_letter()
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')) as resolve:
            self.engine.run_cycle([])
            self.assertEqual(resolve.call_count, 0)
            self.clock.now += timedelta(hours=25)
            self.engine.run_cycle([])
            self.assertEqual(resolve.call_count, 1)
            self.engine.run_cycle([])
            self.assertEqual(resolve.call_count, 1)
            with patch('cornicen.__version__', 'next-version'):
                self.engine.run_cycle([])
                self.assertEqual(resolve.call_count, 2)
        self.assertEqual(self.count('dead_letters'), 1)

    def test_delivery_has_no_transaction_or_ingest_retry_effects(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.run_cycle([self.ingest([self.fixed()])])
        self.clock.now += timedelta(hours=1)
        transactions = []
        def send(n):
            transactions.append(self.store.connection.in_transaction)
            raise ValueError('delivery failed')
        before = [tuple(r) for r in self.store.connection.execute('SELECT * FROM retry_queue')]
        with patch.object(self.notifier, 'send', side_effect=send):
            self.engine._flush()
        self.assertEqual(transactions, [False])
        self.assertEqual([tuple(r) for r in self.store.connection.execute('SELECT * FROM retry_queue')], before)
        self.assertEqual(self.count('dead_letters'), 0)
        row = self.store.connection.execute("SELECT attempts,next_attempt_at FROM outbox WHERE pair_key='service|CVE-2025-54831'").fetchone()
        self.assertEqual(row[0], 1)
        self.assertIsNotNone(row[1])

    def test_retry_schema_contains_only_identity_and_schedule(self):
        columns = {r['name'] for r in self.store.connection.execute('PRAGMA table_info(retry_queue)')}
        self.assertEqual(columns, {'source', 'record_id', 'attempts', 'next_attempt_at', 'last_error'})

    def test_uningested_kev_waits_for_record(self):
        self.start()
        self.engine.run_cycle([self.kev()])
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual([n for n in self.notifier.delivered if n['watch']], [])
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual([n['reasons'] for n in self.notifier.delivered if n['watch']], [['new match', 'KEV added']])

    def test_reactivation_discards_pending_correction(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record]), self.kev()])
        self.engine.run_cycle([self.ingest([self.fixed()])])
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM outbox WHERE sent_at IS NULL AND reasons_json='[\"correction\"]'").fetchone()[0], 0)
        self.clock.now += timedelta(days=1)
        self.engine.run_cycle([])
        self.assertEqual([n['reasons'] for n in self.notifier.delivered if n['watch']], [['new match', 'KEV added'], ['new match']])

    def test_retention_protects_each_reference_and_prunes_unreferenced(self):
        db = self.store.connection
        for key in ('pair', 'outbox', 'kev', 'unused'):
            self.store.put_record(key, {}, '2026-01-01T00:00:00+00:00')
        db.execute("INSERT INTO pairs(watch_id,record_id,state,episode,baseline) VALUES ('w','pair','not_affected',1,0)")
        self.store.queue('w|outbox', 'normal', ['correction'], {'record_id': 'outbox'}, self.clock().isoformat())
        db.execute("INSERT INTO kev VALUES ('kev','{}')")
        self.store.prune_records(self.clock(), 30)
        self.assertEqual({r[0] for r in db.execute('SELECT id FROM records')}, {'pair', 'outbox', 'kev'})

    def test_dead_letter_does_not_block_delivery(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.run_cycle([self.ingest([self.fixed()])])
            for _ in range(4):
                self.engine.run_cycle([])
        self.assertEqual(self.count('dead_letters'), 1)
        before = [tuple(r) for r in self.store.connection.execute('SELECT * FROM dead_letters')]
        self.clock.now += timedelta(hours=1)
        self.engine._flush()
        self.assertEqual([n['reasons'] for n in self.notifier.delivered if n['watch']], [['new match']])
        self.assertEqual([tuple(r) for r in self.store.connection.execute('SELECT * FROM dead_letters')], before)

    def test_baseline_kev_waits_for_record_without_kev_added(self):
        self.engine.run_cycle([self.baseline[0], self.kev(), self.baseline[2]])
        self.assertEqual(self.count('pairs'), 0)
        self.notifier.delivered.clear()
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual([n['reasons'] for n in self.notifier.delivered if n['watch']], [['new match']])

    def test_migration_retains_latest_failed_cvelist_revision(self):
        db = self.store.connection
        key = self.record['cveMetadata']['cveId']
        self.store.put_record(key, self.record, self.clock().isoformat())
        db.execute('DROP TABLE retry_queue')
        db.execute("CREATE TABLE retry_queue(id INTEGER PRIMARY KEY, source TEXT, record_id TEXT, json TEXT, detail TEXT)")
        db.execute('INSERT INTO retry_queue VALUES (1,?,?,?,?)',
                   ('cvelist', key, json.dumps(self.fixed()), 'failed evaluation'))
        db.execute('INSERT INTO retry_queue VALUES (2,?,?,?,?)',
                   ('kev', key, json.dumps(self.record), 'stale evaluation'))
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(self.engine._record(key), expected_projection(self.fixed()))
        self.assertEqual(self.count('retry_queue'), 2)


class WatchlistIndependenceTests(unittest.TestCase):
    def test_watchlist_tempdirs_do_not_require_build(self):
        original = tempfile.TemporaryDirectory
        def independent(*args, **kwargs):
            if kwargs.get('dir') == '.build':
                raise FileNotFoundError('fresh checkout has no .build')
            return original(*args, **kwargs)
        with patch('tests.test_watchlist.tempfile.TemporaryDirectory', side_effect=independent):
            result = unittest.TestResult()
            unittest.defaultTestLoader.loadTestsFromModule(test_watchlist).run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])

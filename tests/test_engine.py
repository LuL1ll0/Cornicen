from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import unittest
from unittest.mock import patch

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.render import render
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier, load_timeline, as_ingest
from tests.source_helpers import expected_projection


class EngineTests(unittest.TestCase):
    def setUp(self):
        rows = load_timeline('same_cycle_coalesce')
        self.watches = load_watchlist_text(rows[0]['watchlist'])
        self.clock = FakeClock(datetime(2026, 11, 3, 7, tzinfo=timezone.utc))
        self.notifier = RecordingNotifier(self.clock)
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.config = Config(':memory:', Path('unused'), None, 'https://ntfy.invalid', 'test', None)
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        self.baseline = [as_ingest(r['ingest']) for r in rows[1:5] if 'ingest' in r]
        self.record = deepcopy(next(r['ingest']['records'][0] for r in rows
                                   if r.get('ingest', {}).get('records')))

    def ingest(self, records, status=FetchStatus.COMPLETE, origin=Origin.DELTA):
        return IngestResult('cvelist', status, origin, 'next', self.clock(), tuple(records))

    def start(self):
        self.engine.run_cycle(self.baseline)
        self.notifier.delivered.clear()
        self.clock.now += timedelta(minutes=10)

    def count(self, table):
        return self.store.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]

    def test_per_record_isolation(self):
        self.start()
        bad = deepcopy(self.record)
        bad['cveMetadata'] = []
        bad['containers']['cna']['affected'][0]['versions'][0]['lessThan'] = 7
        report = self.engine.run_cycle([self.ingest([bad, self.record])])
        self.assertIn('service|CVE-2025-54831|new match|1', report.events)
        self.assertEqual(self.count('retry_queue'), 1)
        self.assertNotEqual(self.store.connection.execute(
            "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], 'next')
        self.assertIn(('cvelist', 'unhealthy'), report.health_changes)
        self.assertEqual(self.count('records'), 1)
        self.assertEqual(self.count('invalid_revisions'), 1)
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))

    def test_applicability_exception_keeps_record_and_rolls_back_evaluation(self):
        self.start()
        from cornicen import applicability
        original = applicability.resolve
        bad = deepcopy(self.record)
        bad['cveMetadata']['cveId'] = 'CVE-2026-9999'
        def resolve(record, *args):
            if record['cveMetadata']['cveId'] == 'CVE-2026-9999':
                raise RuntimeError('evaluation failed')
            return original(record, *args)
        with patch('cornicen.applicability.resolve', side_effect=resolve):
            report = self.engine.run_cycle([self.ingest([bad, self.record])])
        self.assertEqual(len(report.events), 2)  # good match and unhealthy transition
        self.assertEqual(self.count('records'), 2)
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))
        self.assertEqual(self.count('retry_queue'), 1)

    def test_render_exception_does_not_leave_event_without_outbox(self):
        self.start()
        with patch('cornicen.engine.render', side_effect=ValueError('bad rendering')):
            self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.count('retry_queue'), 1)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM events WHERE watch_id!=''").fetchone()[0], 0)

    def test_partial_good_records_and_retry_recovery(self):
        self.start()
        report = self.engine.run_cycle([replace(self.ingest([self.record], FetchStatus.PARTIAL),
                                                errors=('missing record',))])
        self.assertIn('service|CVE-2025-54831|new match|1', report.events)
        self.assertGreater(self.count('retry_queue'), 0)
        report = self.engine.run_cycle([self.ingest([self.record])])
        self.assertIn(('cvelist', 'healthy'), report.health_changes)
        self.assertEqual(self.store.connection.execute(
            "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], 'next')
        self.assertEqual(self.count('retry_queue'), 0)

    def test_snapshot_after_bootstrap_is_new(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record], origin=Origin.SNAPSHOT)])
        self.clock.now += timedelta(hours=1)
        self.engine.run_cycle([])
        self.assertEqual(self.notifier.delivered[0]['reasons'], ['new match'])
        self.assertEqual(self.store.connection.execute('SELECT baseline FROM pairs').fetchone()[0], 0)

    def test_delta_before_baseline_completion_is_new(self):
        self.engine.run_cycle([self.baseline[0]])
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.count('events'), 1)
        self.clock.now += timedelta(hours=1)
        self.engine.run_cycle([])
        self.assertEqual(self.notifier.delivered[0]['reasons'], ['new match'])

    def test_staleness_uses_content_time_and_recovers(self):
        self.start()
        self.clock.now += timedelta(hours=4)
        report = self.engine.run_cycle([])
        self.assertIn(('cvelist', 'unhealthy'), report.health_changes)
        self.assertNotIn(('kev', 'unhealthy'), report.health_changes)
        report = self.engine.run_cycle([self.ingest([])])
        self.assertIn(('cvelist', 'healthy'), report.health_changes)

    def test_epss_full_replacement_can_demote_unsent_item(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        self.engine.run_cycle([IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
            'next', self.clock(), epss={'CVE-2026-9999': (0.01, 0.1)}, epss_date=self.clock().date())])
        row = self.store.connection.execute("SELECT * FROM outbox WHERE sent_at IS NULL").fetchone()
        self.assertEqual(row['urgency'], 'normal')
        self.assertIsNone(json.loads(row['body_json'])['epss'])

    def test_revalidate_drops_queued_item_after_clear(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        fixed = deepcopy(self.record)
        fixed['containers']['cna']['affected'][0]['versions'][0]['status'] = 'unaffected'
        self.engine.run_cycle([self.ingest([fixed])])
        self.clock.now += timedelta(hours=1)
        self.engine.run_cycle([])
        self.assertEqual(self.notifier.delivered, [])
        self.assertEqual(self.store.connection.execute('SELECT episode FROM pairs').fetchone()[0], 2)

    def test_reload_clear_is_silent_and_delivery_is_deferred(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        self.engine.reload_watches((replace(self.watches[0], version='4.0.0'),))
        self.assertEqual(self.notifier.delivered, [])
        self.clock.now += timedelta(hours=1)
        self.engine.run_cycle([])
        self.assertEqual(self.notifier.delivered, [])

    def test_restart_preserves_dedupe_and_baseline(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        self.clock.now += timedelta(hours=1)
        self.engine.run_cycle([])
        self.notifier.delivered.clear()
        engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                        self.clock, self.notifier)
        report = engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(report.events, [])
        self.assertEqual(self.notifier.delivered, [])

    def test_digest_is_next_local_time(self):
        self.engine.config = replace(self.config, timezone='America/New_York')
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        row = self.store.connection.execute('SELECT due_at FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertEqual(datetime.fromisoformat(row[0]), datetime(2026, 11, 3, 13, tzinfo=timezone.utc))

    def test_notifier_failure_retains_same_outbox_id(self):
        self.start()
        self.notifier.down = True
        high = replace(self.baseline[2], epss={'CVE-2025-54831': (0.5, 0.99)})
        self.engine.run_cycle([self.ingest([self.record]), high])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertEqual(row['attempts'], 1)
        self.clock.now += timedelta(minutes=2)
        self.notifier.down = False
        report = self.engine.run_cycle([])
        self.assertEqual(report.sent, 1)
        self.assertEqual(self.store.connection.execute('SELECT sent_at FROM outbox WHERE id=?',
                                                     (row['id'],)).fetchone()[0], self.clock().isoformat())

    def test_same_cycle_score_demotion_waits_for_digest(self):
        self.start()
        high = replace(self.baseline[2], epss={'CVE-2025-54831': (0.5, 0.99)})
        self.engine.run_cycle([high])
        self.engine.run_cycle([self.ingest([self.record]), self.baseline[2]])
        self.assertEqual(self.notifier.delivered, [])
        self.clock.now = self.clock.now.replace(hour=8, minute=0)
        report = self.engine.run_cycle([])
        self.assertEqual(report.sent, 1)
        self.assertEqual(self.notifier.delivered[0]['urgency'], 'normal')

    def test_outbox_failure_rolls_back_event_and_keeps_record(self):
        self.start()
        self.store.connection.execute('''CREATE TRIGGER reject_match BEFORE INSERT ON outbox
            WHEN NEW.pair_key='service|CVE-2025-54831'
            BEGIN SELECT RAISE(ABORT, 'outbox unavailable'); END''')
        report = self.engine.run_cycle([self.ingest([self.record])])
        self.assertNotIn('service|CVE-2025-54831|new match|1', report.events)
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.count('records'), 1)
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))
        self.assertEqual(self.count('retry_queue'), 1)
        self.assertNotEqual(self.store.connection.execute(
            "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], 'next')

    def test_cursor_write_failure_rolls_back_whole_ingest(self):
        self.start()
        self.store.connection.execute('''CREATE TRIGGER reject_cursor BEFORE INSERT ON cursors
            BEGIN SELECT RAISE(ABORT, 'cursor unavailable'); END''')
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.count('records'), 0)
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM events WHERE watch_id!=''").fetchone()[0], 0)

    def test_reload_events_are_reported_in_next_cycle(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record], origin=Origin.SNAPSHOT)])
        other = replace(self.watches[0], id='new-watch')
        self.engine.reload_watches((other,))
        self.assertEqual(self.notifier.delivered, [])
        report = self.engine.run_cycle([])
        self.assertIn('new-watch|CVE-2025-54831|new match|1', report.events)

    def test_epss_stale_and_never_ingested_sources(self):
        self.engine.run_cycle([])
        self.assertEqual(self.count('health'), 0)
        self.start()
        self.clock.now += timedelta(days=3)
        report = self.engine.run_cycle([])
        self.assertIn(('epss', 'unhealthy'), report.health_changes)


class RenderTests(unittest.TestCase):
    def test_unknowns_eol_and_priority(self):
        n = Notification('1', 'w', 'CVE-2026-1234', ('new match',), 'urgent',
                         {'name': 'Router', 'version': '1.0', 'eol': True,
                          'state': 'unknown', 'evidence': 'Version unknown'})
        title, body, priority, tags = render(n)
        self.assertIn('Router', title)
        self.assertTrue(body.startswith('EOL: unsupported by the vendor'))
        self.assertIn('EPSS: not yet scored', body)
        self.assertNotIn('Fix:', body)
        self.assertIn('unknown', body)
        self.assertIn('https://www.cve.org/CVERecord?id=CVE-2026-1234', body)
        self.assertEqual(priority, 5)
        self.assertIn('rotating_light', tags)

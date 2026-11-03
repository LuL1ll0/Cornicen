"""Accepted Task 5 regressions; timelines are also exercised by replay fixtures."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from cornicen.applicability import resolve, State
from cornicen.engine import Engine
from cornicen.health import container_healthy
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.render import render
from cornicen.store import Store
from cornicen.versions import Scheme
from tests import test_engine as helpers
from tests import test_config as config_helpers

from tests.test_fix_g import expected_projection


class Task5Tests(unittest.TestCase):
    setUp = helpers.EngineTests.setUp
    start = helpers.EngineTests.start
    ingest = helpers.EngineTests.ingest
    count = helpers.EngineTests.count

    def kev(self):
        entry = dict(cveID='CVE-2025-54831', vendorProject='examplecorp', product='example_service')
        return replace(self.baseline[1], cursor='new-kev', kev={'CVE-2025-54831': entry}, content_time=self.clock())

    def test_kev_seen_only_after_success(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.run_cycle([self.kev()])
        self.assertIsNone(self.store.connection.execute(
            'SELECT 1 FROM kev_seen WHERE cve=?', ('CVE-2025-54831',)).fetchone())
        self.engine.run_cycle([self.kev()])
        self.assertIsNotNone(self.store.connection.execute(
            'SELECT 1 FROM kev_seen WHERE cve=?', ('CVE-2025-54831',)).fetchone())
        self.assertEqual([reason for n in self.notifier.delivered if n['watch'] for reason in n['reasons']].count('KEV added'), 1)

    def test_none_maps_preserve_tables(self):
        self.start()
        for ingest, table, field in ((self.baseline[1], 'kev', 'kev'), (self.baseline[2], 'epss', 'epss')):
            with self.subTest(table=table):
                before = [tuple(r) for r in self.store.connection.execute(f'SELECT * FROM {table}')]
                self.engine.run_cycle([replace(ingest, **{field: None})])
                self.assertEqual([tuple(r) for r in self.store.connection.execute(f'SELECT * FROM {table}')], before)

    def test_empty_complete_and_partial_maps_preserve_tables(self):
        self.start()
        for ingest, table, field in ((self.baseline[1], 'kev', 'kev'), (self.baseline[2], 'epss', 'epss')):
            for status in (FetchStatus.FAILED, FetchStatus.PARTIAL, FetchStatus.COMPLETE):
                with self.subTest(table=table, status=status):
                    before = [tuple(r) for r in self.store.connection.execute(f'SELECT * FROM {table}')]
                    self.engine.run_cycle([replace(ingest, status=status, **{field: {}})])
                    self.assertEqual([tuple(r) for r in self.store.connection.execute(f'SELECT * FROM {table}')], before)
                    self.assertEqual(self.store.connection.execute('SELECT state FROM health WHERE source=?', (table,)).fetchone()[0], 'unhealthy')

    def test_partial_maps_upsert_without_deletion(self):
        self.start()
        self.engine.run_cycle([replace(self.kev(), status=FetchStatus.PARTIAL)])
        self.assertEqual(self.count('kev'), 2)
        self.engine.run_cycle([replace(self.baseline[2], status=FetchStatus.PARTIAL, epss={'CVE-2026-9999': (.2, .9)})])
        self.assertEqual(self.count('epss'), 2)

    def test_urgent_due_enqueue_merge_demotion_and_overdue(self):
        self.start()
        self.notifier.down = True
        high = replace(self.baseline[2], epss={'CVE-2025-54831': (.5, .99)})
        self.engine.run_cycle([self.ingest([self.record]), high])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        due = self.clock().isoformat()
        self.assertEqual(row['due_at'], due)
        self.assertEqual(row['enqueued_at'], due)
        self.clock.now += timedelta(minutes=2)
        self.engine.run_cycle([self.kev()])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone()
        self.assertEqual(row['due_at'], due)
        self.clock.now += timedelta(minutes=59)
        self.assertFalse(container_healthy(self.store, self.clock(), self.config))
        self.engine.run_cycle([self.baseline[1], self.baseline[2]])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone()
        self.assertEqual(row['urgency'], 'normal')
        self.assertEqual(row['due_at'], self.engine._digest())

    def test_flush_kill_third_preserves_first_two_on_disk(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            store = Store(str(Path(directory)/'state.db')); store.migrate()
            self.addCleanup(store.connection.close)
            engine = Engine(store, (), self.engine.aliases, self.config, self.clock, self.notifier)
            for index in range(4):
                store.queue(f'health-{index}', 'health', ['unhealthy'], {'record_id':f'source-{index}'}, self.clock().isoformat())
            original = self.notifier.send
            calls = []
            def send(n):
                calls.append(n.key)
                if len(calls) == 3:
                    original(n)
                    raise KeyboardInterrupt('simulated process kill after delivery')
                return original(n)
            with patch.object(self.notifier, 'send', side_effect=send), self.assertRaises(KeyboardInterrupt):
                engine.run_cycle([])
            reopened = Store(str(Path(directory)/'state.db')); self.addCleanup(reopened.connection.close)
            self.assertEqual(reopened.connection.execute('SELECT count(*) FROM outbox WHERE sent_at IS NOT NULL').fetchone()[0], 2)
            Engine(reopened, (), engine.aliases, self.config, self.clock, self.notifier).run_cycle([])
            self.assertEqual([n['record'] for n in self.notifier.delivered],
                             ['source-0', 'source-1', 'source-2', 'source-2', 'source-3'])

    def test_retry_keys_and_failed_markers(self):
        self.start()
        failed = replace(self.ingest([]), status=FetchStatus.FAILED, cursor=None)
        self.engine.run_cycle([failed, failed])
        self.assertEqual(self.count('retry_queue'), 1)
        self.engine.run_cycle([replace(failed, cursor='failed-cursor')])
        self.engine.run_cycle([self.ingest([])])
        self.assertEqual(self.count('retry_queue'), 0)
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.run_cycle([self.ingest([self.record])])
            revised = deepcopy(self.record); revised['extra'] = 'revision'
            self.engine.run_cycle([replace(self.ingest([revised]), cursor='later')])
        self.assertEqual(self.count('retry_queue'), 1)

    def test_reload_failures_health_and_retry_next_cycle(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        self.engine.reload_watches(())
        with patch('cornicen.applicability.resolve', side_effect=ValueError('broken')):
            self.engine.reload_watches(self.watches)
        row = self.store.connection.execute("SELECT * FROM retry_queue WHERE source='watchlist'").fetchone()
        self.assertEqual(row['record_id'], 'CVE-2025-54831')
        health = self.store.connection.execute("SELECT state FROM health WHERE source='watchlist'").fetchone()
        self.assertIsNotNone(health)
        self.assertEqual(health[0], 'unhealthy')
        self.engine.run_cycle([])
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='watchlist'").fetchone()[0], 'healthy')

    def test_record_dead_letter_after_five_attempts(self):
        self.start()
        with patch('cornicen.applicability.resolve', side_effect=ValueError('permanently broken')):
            self.engine.run_cycle([self.ingest([self.record])])
            for attempt in range(2, 6):
                self.engine.run_cycle([])
                table = 'dead_letters' if attempt == 5 else 'retry_queue'
                row = self.store.connection.execute(f'SELECT * FROM {table}').fetchone()
                self.assertEqual(row['attempts'], attempt)
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertEqual(self.count('dead_letters'), 1)
        # A dead letter is still incomplete; it cannot commit release coverage.
        self.assertNotEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], 'next')
        self.engine.run_cycle([])
        health = self.store.connection.execute("SELECT state,detail FROM health WHERE source='cvelist'").fetchone()
        self.assertEqual(health['state'], 'unhealthy')
        self.assertIn('CVE-2025-54831', health['detail'])

    def test_compressed_records_and_retention_preserve_dedupe(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        row = self.store.connection.execute('SELECT json FROM records').fetchone()
        self.assertIsInstance(row[0], bytes)
        self.assertEqual(json.loads(zlib.decompress(row[0])), expected_projection(self.record))
        self.engine.config = replace(self.config, retention_days=1)
        events = self.count('events'); pairs = self.count('pairs')
        self.clock.now += timedelta(days=2)
        self.engine.run_cycle([])
        self.assertEqual(self.count('records'), 1)
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))
        self.assertGreaterEqual(self.count('events'), events)
        self.assertEqual(self.count('pairs'), pairs)
        self.assertEqual(self.store.get_meta('baseline_complete'), '1')

    def test_removed_delivered_watch_readded_alerts_new_episode(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record]), self.kev()])
        self.engine.reload_watches(())
        self.engine.reload_watches(self.watches)
        self.engine.run_cycle([])
        self.assertEqual([n['reasons'] for n in self.notifier.delivered if n['watch']],
                         [['new match', 'KEV added'], ['new match']])

    def test_removed_watch_discards_unsent_correction_keys(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record]), self.kev()])
        fixed = deepcopy(self.record)
        fixed['containers']['cna']['affected'][0]['versions'][0]['status'] = 'unaffected'
        self.engine.run_cycle([self.ingest([fixed])])
        self.engine.reload_watches(())
        rows = self.store.connection.execute("SELECT type FROM events WHERE watch_id='service'").fetchall()
        self.assertEqual(sorted(row[0] for row in rows), ['KEV added', 'new match'])

    def test_opaque_equality_constraint_is_normalized(self):
        record = deepcopy(self.record)
        entry = record['containers']['cna']['affected'][0]
        entry['versions'][0].update(version='RomePI-1.0.0.G', versionType='custom')
        watch = replace(self.watches[0], scheme=Scheme.OPAQUE, version='=RomePI-1.0.0.g')
        self.assertEqual(resolve(record, None, watch, self.engine.aliases).state, State.AFFECTED)
        entry['versions'][0]['versionType'] = 'opaque'
        self.assertEqual(resolve(record, None, watch, self.engine.aliases).state, State.AFFECTED)

    def test_store_urgent_merge_never_postpones_deadline(self):
        first = self.store.queue('w|c', 'urgent', ['new match'], {}, '2026-11-03T07:00:00+00:00')
        self.store.queue('w|c', 'urgent', ['KEV added'], {}, '2026-11-03T07:10:00+00:00')
        row = self.store.connection.execute('SELECT * FROM outbox WHERE id=?', (first,)).fetchone()
        self.assertEqual(row['due_at'], '2026-11-03T07:00:00+00:00')

    def test_opaque_normalized_equality_and_safe_mismatch(self):
        record = deepcopy(self.record)
        entry = record['containers']['cna']['affected'][0]
        entry['versions'][0].update(version='RomePI 1.0.0.G', versionType='custom')
        watch = replace(self.watches[0], scheme=Scheme.OPAQUE, version='  ＲｏｍｅＰＩ   1.0.0.g ')
        self.assertEqual(resolve(record, None, watch, self.engine.aliases).state, State.AFFECTED)
        entry['versions'][0]['versionType'] = 'opaque'
        self.assertEqual(resolve(record, None, watch, self.engine.aliases).state, State.AFFECTED)
        entry['versions'][0]['versionType'] = 'custom'
        for default in ('unaffected', None, 'affected'):
            if default is None:
                entry.pop('defaultStatus', None)
            else:
                entry['defaultStatus'] = default
            for kev in (None, self.kev().kev['CVE-2025-54831']):
                result = resolve(record, kev, replace(watch, version='unlisted'), self.engine.aliases)
                self.assertEqual(result.state, State.AFFECTED if default == 'affected' else State.UNKNOWN)
                self.assertEqual(result.exploited, kev is not None)


class RenderingRegressions(unittest.TestCase):
    def test_health_title_fixed_message_and_priorities(self):
        for state, title_state, priority in [('unhealthy', 'unhealthy', 5), ('healthy', 'recovered', 3)]:
            n = Notification('1', '', 'cvelist', (state,), 'health', {'detail':'content stale', 'since':'2026-11-03T07:00:00+00:00'})
            title, body, actual, _ = render(n)
            self.assertEqual(title, f'Cornicen: cvelist {title_state}')
            expected = ('cvelist: unhealthy — failed since 2026-11-03T07:00Z'
                        if state == 'unhealthy' else 'cvelist: recovered')
            self.assertEqual(body, expected)
            self.assertNotIn('content stale', body)
            self.assertNotIn('2026-11-03T07:00:00+00:00', body)
            self.assertEqual(actual, priority)

    def test_ordinals_precision_states_fix_eol_ransomware(self):
        for pct, ordinal in [(1,'1st'),(2,'2nd'),(3,'3rd'),(11,'11th'),(12,'12th'),(13,'13th'),(21,'21st'),(22,'22nd'),(83,'83rd')]:
            n = Notification('1','w','CVE-2026-1234',('correction',),'normal',dict(name='Router',version='1', eol=True,state='not_affected',epss=dict(score=.0999,pct=pct/100,date='2026-11-03'),kev=dict(knownRansomwareCampaignUse='Known')))
            _, body, _, _ = render(n)
            self.assertIn(f'{ordinal} pct', body)
            self.assertIn('EPSS 9.99%', body)
            self.assertIn('not affected', body)
            self.assertNotIn('Fix:', body)
            self.assertEqual(body.count('unsupported by the vendor'), 1)
            self.assertIn('ransomware', body.lower())
            _, body, _, _ = render(replace(n, body={**n.body,'fix':'Upgrade to 2'}))
            self.assertIn('Fix: Upgrade to 2', body)


class ConfigIndependenceTests(unittest.TestCase):
    def test_config_tempdirs_do_not_require_build_directory(self):
        original = tempfile.TemporaryDirectory
        def independent(*args, **kwargs):
            if kwargs.get('dir') == '.build':
                raise FileNotFoundError('fresh checkout has no .build')
            # Test runner scratch stays inside the permitted workspace.
            return original(*args, **{**kwargs, 'dir':'.'})
        with patch('tests.test_config.tempfile.TemporaryDirectory', side_effect=independent):
            config = config_helpers.ConfigTests().load()
        self.assertEqual(config.retention_days, 365)


class LegacyMigrationTests(unittest.TestCase):
    def test_legacy_records_retry_keys_and_enqueue_time_migrate(self):
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        db = store.connection
        db.execute('CREATE TABLE records(id TEXT PRIMARY KEY,json TEXT NOT NULL,ingested_at TEXT NOT NULL)')
        db.execute('CREATE TABLE outbox(id INTEGER PRIMARY KEY,pair_key TEXT,urgency TEXT,reasons_json TEXT,body_json TEXT,due_at TEXT,attempts INTEGER DEFAULT 0,next_attempt_at TEXT,sent_at TEXT)')
        db.execute('CREATE TABLE retry_queue(id INTEGER PRIMARY KEY,source TEXT,cursor TEXT,record_id TEXT,json TEXT,detail TEXT,UNIQUE(source,cursor,json))')
        db.execute('CREATE TABLE events(key TEXT PRIMARY KEY,watch_id TEXT,record_id TEXT,type TEXT,episode INTEGER,created_at TEXT)')
        db.execute("INSERT INTO records VALUES ('c','{}','2026-11-03T07:00:00+00:00')")
        db.execute("INSERT INTO events VALUES ('w|c|new match|1','w','c','new match',1,'2026-11-03T07:00:00+00:00')")
        db.execute("INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at) VALUES ('w|c','urgent','[\"new match\"]','{}','2026-11-03T08:00:00+00:00')")
        for cursor in ('one','two'):
            db.execute('INSERT INTO retry_queue(source,cursor,record_id,json,detail) VALUES (?,?,?,?,?)',
                       ('watchlist',cursor,'c','{"cveMetadata":{"cveId":"c"}}','broken'))
        store.migrate()
        store.migrate()
        self.assertEqual(zlib.decompress(db.execute('SELECT json FROM records').fetchone()[0]), b'{}')
        self.assertEqual(db.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 1)
        row = db.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual(row['enqueued_at'], '2026-11-03T07:00:00+00:00')
        self.assertEqual(row['due_at'], row['enqueued_at'])

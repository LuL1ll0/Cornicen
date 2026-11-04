"""Local operator feature contracts; fictional inventory and no network."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cornicen.cli import main
from cornicen.identity import AliasMap
from cornicen.store import Store


CVE = 'CVE-2026-4321'


class GoalFeaturesATests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db = self.root / 'state.db'
        self.watch = self.root / 'watch.toml'
        self.watch.write_text(self.watch_text('one', 'cloudforge:mistbox'))
        self.config = self.root / 'config.toml'
        self.config.write_text(f'db_path="{self.db}"\nwatchlist_path="{self.watch}"\n')

    def watch_text(self, watch_id, identity):
        return (f'[[watch]]\nid="{watch_id}"\nname="Mistbox service"\n'
                f'match=["{identity}"]\nversion="2.4.0"\nscheme="semver"\n')

    def seed(self, callback=lambda store: None):
        store = Store(str(self.db))
        try:
            store.migrate()
            callback(store)
        finally:
            store.connection.close()

    def snapshot(self):
        if not self.db.exists():
            return None
        with contextlib.closing(sqlite3.connect(self.db.resolve().as_uri() + '?mode=ro',
                                               uri=True)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            rows = {name: connection.execute('SELECT * FROM ' + name).fetchall()
                    for (name,) in tables}
        return self.db.read_bytes(), rows

    def invoke(self, *args):
        before = self.snapshot()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch('cornicen.cli.Store', wraps=Store) as constructor, \
                patch('cornicen.cli.Engine', side_effect=AssertionError('Engine constructed')) as engine, \
                patch('cornicen.cli.Http', side_effect=AssertionError('HTTP constructed')) as http, \
                patch('cornicen.cli._notifier', side_effect=AssertionError('notifier constructed')) as notifier, \
                patch.object(Store, 'migrate', side_effect=AssertionError('migration called')) as migrate, \
                patch('socket.create_connection', side_effect=AssertionError('network called')) as network:
            code = main(['--config', str(self.config), *args])
        for forbidden in (engine, http, notifier, migrate, network):
            forbidden.assert_not_called()
        for call in constructor.call_args_list:
            self.assertIs(call.kwargs.get('read_only'), True)
        self.assertEqual(self.snapshot(), before, 'command changed DB bytes or table contents')
        return code, output.getvalue()

    def record(self, status='affected', vendor='cloudforge', versions=True):
        entry = {'vendor': vendor, 'product': 'mistbox'}
        if versions:
            entry['versions'] = [{'version': '2.4.0', 'status': status}]
        return {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'},
                'containers': {'cna': {'affected': [entry]}}}

    def put_record(self, record, kev=False, pair=False):
        def populate(store):
            store.put_record(CVE, record, datetime.now(timezone.utc).isoformat())
            if kev:
                store.connection.execute('INSERT INTO kev VALUES (?,?)', (CVE, json.dumps(
                    {'cveID': CVE, 'vendorProject': 'cloudforge', 'product': 'mistbox'})))
            if pair:
                store.connection.execute('''INSERT INTO pairs(watch_id,record_id,state,
                    episode,baseline,exploited,alias_map_version) VALUES (?,?,?,1,0,0,?)''',
                    ('one', CVE, 'unknown', 'old-map'))
            store.set_meta('fixture', 'unchanged')
            store.connection.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                                     ('fixture', 'one', CVE, 'new match', 1, '2026-11-01'))
            store.queue('one|' + CVE, 'normal', ['new match'],
                        {'watch_id': 'one', 'record_id': CVE}, '2026-11-04T12:00:00+00:00')
        self.seed(populate)

    def test_f01_affected_and_stored_state_are_separate(self):
        self.put_record(self.record(), pair=True)
        code, text = self.invoke('explain', CVE, '--watch', 'one')
        self.assertEqual(code, 0)
        self.assertIn('Current-file evaluation: one ' + CVE, text)
        self.assertIn('version=2.4.0; scheme=semver; alias_map_version=', text)
        self.assertIn('Stored pair state: ', text)
        self.assertIn('"state": "unknown"', text)
        self.assertIn('"alias_map_version": "old-map"', text)
        self.assertIn('applicability=affected; exploited=false; confidence=high', text)
        self.assertIn('Evidence: CNA affected mistbox:', text)

    def test_f01_authoritative_exclusion_despite_kev(self):
        self.put_record(self.record(status='unaffected'), kev=True)
        code, text = self.invoke('explain', CVE, '--watch', 'one')
        self.assertEqual(code, 0)
        self.assertIn('applicability=not_affected; exploited=true; confidence=high', text)

    def test_f01_unknown_is_evaluable(self):
        self.put_record(self.record(versions=False))
        code, text = self.invoke('explain', CVE, '--watch', 'one')
        self.assertEqual(code, 0)
        self.assertIn('applicability=unknown; exploited=false; confidence=medium', text)

    def test_f01_identity_miss_is_distinct_from_absent_record(self):
        self.put_record(self.record(vendor='driftworks'))
        self.assertIn('identity miss', self.invoke('explain', CVE, '--watch', 'one')[1])
        self.assertEqual(self.invoke('explain', CVE, '--watch', 'one')[0], 0)
        code, text = self.invoke('explain', 'CVE-2026-9999', '--watch', 'one')
        self.assertEqual(code, 1)
        self.assertIn('retained record unavailable; applicability unknown', text)
        self.assertNotIn('identity miss', text)

    def test_f01_unknown_watch_and_missing_database(self):
        self.assertEqual(self.invoke('explain', CVE, '--watch', 'one')[0], 1)
        self.seed()
        self.assertEqual(self.invoke('explain', CVE, '--watch', 'missing'),
                         (1, 'unknown watch ID: missing\n'))

    def test_f02_pending_order_effective_times_and_failed_subset(self):
        def populate(store):
            for key, due, retry, attempts, dirty, sent in (
                    ('future', '18:00', None, 0, 0, False),
                    ('retry', '08:00', '20:00', 2, 0, False),
                    ('overdue', '07:00', None, 0, 0, False),
                    ('dirty', '09:00', '06:00', 1, 1, False),
                    ('health', '09:00', None, 0, 0, False),
                    ('baseline', '10:00', None, 0, 0, False),
                    ('sent', '01:00', None, 3, 0, True)):
                stamp = lambda value: '2026-11-04T' + value + ':00+00:00' if value else None
                body = {'record_id': key}
                if key not in ('health', 'baseline'):
                    body['watch_id'] = 'one'
                row_id = store.queue(key, 'urgent' if key == 'health' else 'normal',
                                     ['fixture'], body, stamp(due), stamp('05:00'))
                store.connection.execute('''UPDATE outbox SET attempts=?,next_attempt_at=?,
                    dirty=?,sent_at=? WHERE id=?''',
                    (attempts, stamp(retry), dirty, stamp('02:00') if sent else None, row_id))
        self.seed(populate)
        code, text = self.invoke('outbox', 'list')
        self.assertEqual(code, 0)
        self.assertEqual(text.splitlines()[-1], 'Pending rows: 6')
        rows = [json.loads(line) for line in text.splitlines()[:-1]]
        self.assertEqual([row['id'] for row in rows], [3, 4, 5, 6, 1, 2])
        self.assertEqual([row['eligible_at'] for row in rows],
                         ['2026-11-04T' + time + ':00+00:00'
                          for time in ('07:00', '09:00', '09:00', '10:00', '18:00', '20:00')])
        self.assertEqual(rows[1]['revalidation'], 'awaiting revalidation')
        self.assertEqual(rows[2]['component'], 'health')
        self.assertIsNone(rows[2]['watch_id'])
        self.assertEqual(rows[3]['component'], 'baseline')
        self.assertEqual(rows[0]['reasons'], ['fixture'])
        self.assertEqual(rows[0]['enqueued_at'], '2026-11-04T05:00:00+00:00')
        self.assertEqual(rows[-1]['attempts'], 2)
        self.assertEqual(rows[-1]['next_attempt_at'], '2026-11-04T20:00:00+00:00')
        code, text = self.invoke('outbox', 'list', '--failed')
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(line)['id'] for line in text.splitlines()[:-1]], [4, 2])
        self.assertEqual(text.splitlines()[-1], 'Pending rows: 2')

    def test_f02_empty_queue(self):
        self.seed()
        self.assertEqual(self.invoke('outbox', 'list'), (0, 'Pending rows: 0\n'))
        self.assertEqual(self.invoke('outbox', 'list', '--failed'), (0, 'Pending rows: 0\n'))

    def test_f02_missing_database(self):
        self.assertEqual(self.invoke('outbox', 'list'), (1, 'unhealthy: database unavailable\n'))

    def assert_status_schema(self, result):
        self.assertEqual(set(result), {'schema_version', 'available', 'container_healthy',
                                      'sources', 'baseline_complete', 'reconcile_at'})
        self.assertIs(type(result['schema_version']), int)
        self.assertEqual(result['schema_version'], 1)
        for key in ('available', 'container_healthy', 'baseline_complete'):
            self.assertIs(type(result[key]), bool)
        self.assertIs(type(result['sources']), dict)
        self.assertTrue(result['reconcile_at'] is None or isinstance(result['reconcile_at'], str))
        for source in result['sources'].values():
            self.assertEqual(set(source), {'state', 'detail', 'cursor', 'content_time'})
            for key in ('state', 'detail'):
                self.assertIsInstance(source[key], str)
            for key in ('cursor', 'content_time'):
                self.assertTrue(source[key] is None or isinstance(source[key], str))

    def seed_health(self, age=0, rejected=False):
        def populate(store):
            for source in ('cvelist', 'kev', 'epss'):
                store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                    (source, 'fixture-cursor',
                     (datetime.now(timezone.utc) - timedelta(hours=age)).isoformat()))
            store.set_meta('baseline_complete', '1')
            store.set_meta('reconcile_at', '2026-11-01T00:00:00+00:00')
            if rejected:
                store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                    ('watchlist', 'unhealthy', '2026-11-01', 'Reload rejected; token=fictional-value'))
        self.seed(populate)

    def test_f06_healthy_exact_schema_and_plain_commands(self):
        self.seed_health()
        code, text = self.invoke('status', '--json')
        result = json.loads(text)
        self.assertEqual(code, 0)
        self.assert_status_schema(result)
        self.assertTrue(result['available'])
        self.assertTrue(result['container_healthy'])
        self.assertTrue(result['baseline_complete'])
        self.assertEqual(set(result['sources']), {'cvelist', 'kev', 'epss'})
        self.assertEqual(result['sources']['cvelist']['cursor'], 'fixture-cursor')
        self.assertEqual(result['reconcile_at'], '2026-11-01T00:00:00+00:00')
        self.assertNotIn('mistbox', text.lower())
        self.assertEqual(self.invoke('healthcheck'), (0, 'healthy\n'))
        code, plain = self.invoke('status')
        self.assertEqual(code, 0)
        self.assertIn('container: healthy\nreconcile: 2026-11-01T00:00:00+00:00\n', plain)

    def test_f06_stale_status_still_exits_zero(self):
        self.seed_health(age=72)
        code, text = self.invoke('status', '--json')
        result = json.loads(text)
        self.assert_status_schema(result)
        self.assertEqual(code, 0)
        self.assertFalse(result['container_healthy'])
        self.assertEqual(result['sources']['cvelist']['state'], 'unhealthy')
        self.assertEqual(result['sources']['epss']['detail'], 'Source content is stale')
        self.assertEqual(self.invoke('healthcheck'), (1, 'unhealthy\n'))

    def test_f06_rejected_watchlist_sanitizes_error(self):
        self.seed_health(rejected=True)
        code, text = self.invoke('status', '--json')
        result = json.loads(text)
        self.assert_status_schema(result)
        self.assertEqual(code, 0)
        self.assertFalse(result['container_healthy'])
        self.assertEqual(result['sources']['watchlist']['detail'], 'Reload rejected; token [redacted]')
        self.assertNotIn('fictional-value', text)
        self.assertEqual(self.invoke('status')[0], 0)
        self.assertEqual(self.invoke('healthcheck'), (1, 'unhealthy\n'))

    def test_f06_missing_and_unreadable_database_valid_json(self):
        expected = dict(schema_version=1, available=False, container_healthy=False,
                        sources={}, baseline_complete=False, reconcile_at=None)
        code, text = self.invoke('status', '--json')
        self.assertEqual((code, json.loads(text)), (1, expected))
        self.assert_status_schema(json.loads(text))
        self.assertFalse(self.db.exists())
        self.assertEqual(self.invoke('status'), (1, 'unhealthy: database unavailable\n'))
        self.db.write_bytes(b'not a SQLite database')
        output = io.StringIO()
        before = self.db.read_bytes()
        with contextlib.redirect_stdout(output):
            code = main(['--config', str(self.config), 'status', '--json'])
        self.assertEqual((code, json.loads(output.getvalue())), (1, expected))
        self.assertEqual(self.db.read_bytes(), before)

    def test_f07_draft_alias_collision_strict_and_default(self):
        aliases = self.root / 'aliases.toml'
        aliases.write_text('version="fictional-1"\n[[alias]]\n'
                           'identities=["cloudforge:mistbox", "vaporworks:fogbox"]\n')
        with self.config.open('a') as target:
            target.write(f'aliases_path="{aliases}"\n')
        draft = self.root / 'draft.toml'
        draft.write_text(self.watch.read_text() + self.watch_text('two', 'vaporworks:fogbox'))
        originals = {path: path.read_bytes() for path in (self.watch, draft, aliases, self.config)}
        code, text = self.invoke('watch', 'check', '--file', str(draft))
        self.assertEqual(code, 0)
        self.assertIn('collision: one and two claim', text)
        self.assertEqual(self.invoke('watch', 'check', '--file', str(draft), '--strict')[0], 1)
        self.assertEqual(self.invoke('watch', 'check', '--strict')[0], 0)
        self.assertFalse(self.db.exists())
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_f07_alias_warning_fails_only_in_strict_mode(self):
        aliases = AliasMap()
        aliases.warnings.append('fixture alias warning')
        with patch('cornicen.cli.AliasMap.load', return_value=aliases):
            self.assertEqual(self.invoke('watch', 'check')[0], 0)
            code, text = self.invoke('watch', 'check', '--strict')
        self.assertEqual(code, 1)
        self.assertIn('alias warning: fixture alias warning', text)
        self.assertFalse(self.db.exists())

    def test_f07_unknown_key_is_reported_in_both_modes(self):
        draft = self.root / 'invalid.toml'
        draft.write_text(self.watch.read_text() + 'mystery_key=true\n')
        before = draft.read_bytes()
        for flags in ((), ('--strict',)):
            code, text = self.invoke('watch', 'check', '--file', str(draft), *flags)
            self.assertEqual(code, 1)
            self.assertIn("unknown key 'mystery_key'", text)
        self.assertEqual(draft.read_bytes(), before)
        self.assertFalse(self.db.exists())

    def test_f07_existing_database_unchanged(self):
        self.put_record(self.record())
        self.assertEqual(self.invoke('watch', 'check', '--strict')[0], 0)

    def test_f07_plain_check_keeps_sanitized_validation_errors(self):
        self.watch.write_text(self.watch.read_text() + 'mystery_key=true\n')
        code, text = self.invoke('watch', 'check')
        self.assertEqual(code, 1)
        self.assertIn('WatchlistError: Watchlist validation failed', text)
        self.assertNotIn('mystery_key', text)
        code, text = self.invoke('watch', 'check', '--strict')
        self.assertEqual(code, 1)
        self.assertIn("unknown key 'mystery_key'", text)

    def test_f07_missing_candidate_is_local_error(self):
        code, text = self.invoke('watch', 'check', '--file', str(self.root / 'absent.toml'))
        self.assertEqual(code, 1)
        self.assertIn('Cannot read watch list:', text)
        self.assertFalse(self.db.exists())

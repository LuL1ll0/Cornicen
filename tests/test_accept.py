"""Expiring operator accept entries: T1–T22 from the v0.1.6 plan."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import io
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import cli, watchlist
from cornicen.config import Config, load_config
from cornicen.engine import Engine
from cornicen.health import container_healthy
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.render import render
from cornicen.scheduler import Scheduler, safe_message
from cornicen.store import Store
from tests.replay.harness import FakeClock

WATCH = '''[[watch]]
id = "proxy"
name = "Proxy"
match = ["fictional:proxy"]
version = "1.25.3"
scheme = "semver"
'''
ENTRY = '''\n[[accept]]
cve = "CVE-2026-0001"
watch = "proxy"
reason = "Module not built"
until = 2026-11-04
'''


class CaptureNotifier:
    def __init__(self):
        self.down = False
        self.sent = []

    def send(self, notification):
        if self.down:
            return False
        self.sent.append(notification)
        return True


class AcceptTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.path = self.root / 'watch.toml'
        self.path.write_text(WATCH + ENTRY)
        self.config_path = self.root / 'config.toml'
        self.db_path = self.root / 'state.db'
        self.config_path.write_text(f'db_path = "{self.db_path}"\nwatchlist_path = "{self.path}"\n')
        self.clock = FakeClock(datetime(2026, 11, 4, 7, tzinfo=timezone.utc))
        self.config = Config(str(self.db_path), self.path, None, 'https://ntfy.invalid', 'test', None)
        self.store = Store(str(self.db_path))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.notifier = CaptureNotifier()
        self.aliases = AliasMap.load(False)

    def build(self, text=None):
        watches, accepts = watchlist.load_document_text(WATCH + ENTRY if text is None else text)
        self.engine = Engine(self.store, watches, self.aliases, self.config,
                             self.clock, self.notifier, accepts=accepts)
        return self.engine

    def record(self, cve='CVE-2026-0001'):
        return {'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED'}, 'containers': {'cna': {
            'affected': [{'vendor': 'fictional', 'product': 'proxy', 'versions': [
                {'version': '0', 'lessThan': '2.0.0', 'versionType': 'semver', 'status': 'affected'}]}]}}}

    def ingest(self, records):
        return IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                            'next', self.clock(), tuple(records))

    def fresh_sources(self):
        return [self.ingest([]),
                IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, 'kev', self.clock(), kev={}),
                IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, 'epss', self.clock(),
                             epss={'CVE-2026-9999': (.01, .1)}, epss_date=self.clock().date())]

    def start(self, text=None):
        self.build(text)
        self.engine.run_cycle(self.fresh_sources())
        self.notifier.sent.clear()

    def pending(self):
        return self.store.connection.execute("SELECT * FROM outbox WHERE pair_key='proxy|CVE-2026-0001' AND sent_at IS NULL").fetchone()

    def items(self):
        return [Notification(**item) if isinstance(item, dict) else item
                for n in self.notifier.sent for item in n.body.get('items', [n]) if n.urgency != 'health']

    def digest(self, days=0):
        self.clock.now = (self.clock.now + timedelta(days=days)).replace(hour=8, minute=0)
        self.engine.run_cycle(self.fresh_sources())

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        clock = self.clock

        class CliDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock().astimezone(tz)

        with redirect_stdout(out), redirect_stderr(err), patch.dict('os.environ', {}, clear=True), \
                patch('cornicen.cli.datetime', CliDateTime):
            code = cli.main(['--config', str(self.config_path), *args])
        return code, out.getvalue(), err.getvalue()

    def scheduler(self):
        sources = {name: Mock() for name in Scheduler.intervals}
        for source in sources.values():
            source.poll.return_value = []
        self.lines = []
        return Scheduler(self.engine, sources, self.clock, self.lines.append,
                         monotonic=lambda: self.clock().timestamp())

    def test_loader_accepts_valid_entries(self):  # T1
        from cornicen.accept import state
        text = WATCH + ENTRY.replace('CVE-', 'cve-') + ENTRY.replace('0001', '0002').replace(
            'until = 2026-11-04', 'until_version_change = true\nversion = "1.25.3"')
        watches, accepts = watchlist.load_document_text(text)
        self.assertEqual(accepts[0].cve, 'CVE-2026-0001')
        self.assertEqual(accepts[0].until, date(2026, 11, 4))
        self.assertEqual([a.entry for a in accepts], [1, 2])
        self.assertEqual(watchlist.load_watchlist_text(text), watches)
        self.assertEqual(watchlist.load_document_text(WATCH + ENTRY.replace('2026-11-04', '"2026-11-04"'))[1][0], accepts[0])
        self.assertEqual(state(accepts[0], {'proxy': watches[0]}, self.clock(), 'UTC'), 'active')
        self.clock.now = datetime(2026, 11, 5, 1, tzinfo=timezone.utc)
        self.assertEqual(state(accepts[0], {'proxy': watches[0]}, self.clock(), 'America/New_York'), 'active')

    def test_malformed_entries_rejected_with_named_label(self):  # T2
        self.build()
        scheduler = self.scheduler()
        old = self.engine.accepts
        invalid = [ENTRY + 'typo = true\n', ENTRY.replace('cve = "CVE-2026-0001"', ''),
                   ENTRY.replace('watch = "proxy"', ''), ENTRY.replace('reason = "Module not built"', ''),
                   ENTRY.replace('CVE-2026-0001', 'invalid'), ENTRY.replace('watch = "proxy"', 'watch = "bad id"'),
                   ENTRY.replace('Module not built', 'x' * 201), ENTRY.replace('until = 2026-11-04', ''),
                   ENTRY.replace('until = 2026-11-04', 'until = 123'), ENTRY + 'until_version_change = 1\n',
                   ENTRY + 'version = "1.25.3"\n', ENTRY + 'until_version_change = true\n',
                   ENTRY + ENTRY.replace('CVE-', 'cve-').replace('"proxy"', '"PROXY"'),
                   '\naccept = "wrong"\n', '\naccept = [1]\n']
        for field, value in (('cve', 'CVE-2026-0001'), ('watch', 'proxy'), ('reason', 'Module not built')):
            for bad in ('""', '"  "', 'false'):
                invalid.append(ENTRY.replace(f'{field} = "{value}"', f'{field} = {bad}'))
        invalid.extend([ENTRY.replace('until = 2026-11-04', 'until = "2026-02-30"'),
                        ENTRY.replace('until = 2026-11-04', 'until = 2026-11-04T00:00:00Z'),
                        ENTRY + 'until_version_change = false\nversion = "1.25.3"\n'])
        for entry in invalid:
            with self.subTest(entry=entry):
                text = WATCH + entry if not entry.startswith('\naccept =') else entry + WATCH
                with self.assertRaisesRegex(watchlist.WatchlistError, r'accept entry \d+ \('):
                    watchlist.load_watchlist_text(text)
                self.path.write_text(text)
                code, out, _ = self.invoke('watch', 'check', '--file', str(self.path))
                self.assertEqual(code, 1)
                self.assertIn('watch validation error: accept entry', out)
                self.assertIn('watch validation error: accept entry', self.invoke('watch', 'check')[1])
                scheduler._reload()
                self.assertEqual(self.engine.accepts, old)
                self.assertEqual(self.engine.watches, watchlist.load_watchlist_text(WATCH))

    def test_unknown_watch_warns_not_fails(self):  # T3
        text = WATCH + ENTRY.replace('watch = "proxy"', 'watch = "absent"')
        self.path.write_text(text)
        self.start(text)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.digest()
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.invoke('watch', 'check')[0], 0)
        self.assertIn('unknown watch', self.invoke('watch', 'check')[1])
        self.assertEqual(self.invoke('watch', 'check', '--strict')[0], 1)

    def test_accept_changes_do_not_rematch(self):  # T4
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        before = [tuple(r) for r in self.store.connection.execute('SELECT * FROM pairs')]
        digest_hash = self.store.get_meta('applied_watches_hash')
        count = self.store.connection.execute('SELECT count(*) FROM events').fetchone()[0]
        scheduler = self.scheduler()
        for text in (WATCH + ENTRY, WATCH):
            self.path.write_text(text)
            scheduler._reload()
            self.assertEqual(self.store.get_meta('applied_watches_hash'), digest_hash)
            self.assertEqual([tuple(r) for r in self.store.connection.execute('SELECT * FROM pairs')], before)
            self.assertEqual(self.store.connection.execute('SELECT count(*) FROM events').fetchone()[0], count)

    def test_accept_only_reload_writes_only_outbox(self):
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        scheduler = self.scheduler()
        writes = []

        def authorizer(action, table, *args):
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                writes.append(table)
            return sqlite3.SQLITE_OK

        self.engine.db.set_authorizer(authorizer)
        try:
            with patch.object(self.engine, 'reload_watches', wraps=self.engine.reload_watches) as reload:
                self.path.write_text(WATCH + ENTRY)
                scheduler._reload()
                reload.assert_not_called()
        finally:
            self.engine.db.set_authorizer(None)
        self.assertEqual(set(writes), {'outbox'})
        self.assertEqual(self.pending()['dirty'], 1)

    def test_accept_only_reload_preserves_matching_failures(self):
        for attempts, table in ((1, 'retry_queue'), (5, 'dead_letters')):
            with self.subTest(table=table):
                self.start(WATCH)
                self.engine.run_cycle([self.ingest([self.record()])])
                changed = WATCH.replace('1.25.3', '3.0.0')
                with patch('cornicen.applicability.resolve', side_effect=ValueError('fictional failure')):
                    self.engine.reload_watches(watchlist.load_watchlist_text(changed))
                    for _ in range(attempts - 1):
                        self.engine.run_cycle(self.fresh_sources())
                before = [tuple(r) for r in self.engine.db.execute(
                    f"SELECT * FROM {table} WHERE source='watchlist'")]
                self.assertEqual(len(before), 1)
                scheduler = self.scheduler()
                self.path.write_text(changed + ENTRY)
                scheduler._reload()
                self.assertEqual([tuple(r) for r in self.engine.db.execute(
                    f"SELECT * FROM {table} WHERE source='watchlist'")], before)
                self.assertEqual(self.engine.db.execute(
                    "SELECT state FROM health WHERE source='watchlist'").fetchone()[0], 'unhealthy')
                # Recover the fictional matching failure before the next subtest.
                self.engine.reload_watches(watchlist.load_watchlist_text(WATCH))

    def test_held_retry_cleared_in_both_refresh_modes(self):
        self.config = replace(self.config, overdue_minutes=1)
        self.start(WATCH)
        self.clock.now = self.clock.now.replace(minute=55)
        self.notifier.down = True
        scores = IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, 'scores', self.clock(),
                              epss={'CVE-2026-0001': (.99, .99)}, epss_date=self.clock().date())
        self.engine.run_cycle([self.ingest([self.record()]), scores])
        for minute in (56, 58):
            self.clock.now = self.clock.now.replace(minute=minute)
            self.engine.run_cycle([self.ingest([])])
        self.assertIsNotNone(self.pending()['next_attempt_at'])
        scheduler = self.scheduler()
        self.path.write_text(WATCH + ENTRY)
        scheduler._reload()
        before = tuple(self.pending())
        self.assertIsNone(self.engine._revalidate(self.pending(), persist=False)['next_attempt_at'])
        self.assertEqual(tuple(self.pending()), before)
        self.engine.run_cycle([self.ingest([])])
        self.assertIsNone(self.pending()['next_attempt_at'])
        for hour, minute, second in ((8, 0, 0), (8, 1, 30)):
            self.clock.now = self.clock.now.replace(hour=hour, minute=minute, second=second)
            self.engine.run_cycle([self.ingest([])])
            self.assertTrue(container_healthy(self.store, self.clock(), self.config))
        self.assertEqual(self.items(), [])

    def test_removed_then_restored_lapsed_entry_notifies_once(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record()])])
        entries = self.engine.accepts
        self.engine.accepts = ()
        before = tuple(self.pending())
        events = list(self.engine.db.execute('SELECT * FROM events'))
        self.engine._revalidate(self.pending(), persist=False)
        self.assertEqual(tuple(self.pending()), before)
        self.assertEqual(list(self.engine.db.execute('SELECT * FROM events')), events)
        self.digest()
        self.assertIn('acceptance lapsed', self.items()[0].reasons)
        key = 'proxy|CVE-2026-0001|acceptance lapsed|1'
        self.assertIsNotNone(self.engine.db.execute('SELECT 1 FROM events WHERE key=?', (key,)).fetchone())
        self.engine.accepts = entries
        self.digest(1)
        self.digest(1)
        self.assertEqual(len(self.items()), 1)

    def test_empty_accept_json_shapes(self):
        self.start(WATCH)
        self.path.write_text(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.engine.db.execute('INSERT INTO dead_letters VALUES (?,?,?,?,?,?)',
            ('cvelist', 'CVE-2026-9998', 5, self.clock().isoformat(), 'fictional failure', '0.1.6'))
        self.assertEqual(json.loads(self.invoke('status', '--json')[1])['accepted'], [])
        rows = [json.loads(line) for line in self.invoke('report', '--format', 'jsonl')[1].splitlines()]
        self.assertIsNone(rows[0]['accepted'])
        self.assertNotIn('accepted', rows[1])
        self.path.write_text('invalid = true')
        self.assertNotIn('accepted', json.loads(self.invoke('status', '--json')[1]))
        for line in self.invoke('report', '--format', 'jsonl')[1].splitlines():
            self.assertNotIn('accepted', json.loads(line))

    def test_accept_watch_id_case_insensitive(self):
        text = WATCH + ENTRY.replace('watch = "proxy"', 'watch = "Proxy"')
        self.path.write_text(text)
        self.start(text)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.assertTrue(json.loads(self.pending()['body_json'])['accepted']['held'])
        self.digest()
        self.assertEqual(self.items(), [])
        code, out, _ = self.invoke('watch', 'check', '--strict')
        self.assertEqual(code, 0)
        self.assertNotIn('unknown watch', out)
        entry = json.loads(self.invoke('status', '--json')[1])['accepted'][0]
        self.assertEqual((entry['state'], entry['held']), ('active', 1))
        self.assertEqual(json.loads(self.invoke('report', '--format', 'jsonl')[1])['accepted']['state'], 'active')
        self.digest(1)
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.items()[0].reasons, ('new match', 'acceptance lapsed'))

    def test_cli_reason_sanitised(self):
        reason = 'Module\x1b[31m\n\t  not built ' + 'x' * 170
        text = WATCH + ENTRY.replace('"Module not built"', json.dumps(reason))
        self.path.write_text(text)
        self.start(text)
        expected = ('Module [31m not built ' + 'x' * 170)[:160]
        for args in (('status',), ('watch', 'check')):
            with self.subTest(args=args):
                out = self.invoke(*args)[1]
                line = next(line for line in out.splitlines() if 'CVE-2026-0001' in line)
                self.assertEqual(line.split('; ')[-1], expected)
                self.assertNotIn('\x1b', out)

    def test_status_both_lapse_conditions(self):
        text = WATCH + ENTRY + 'until_version_change = true\nversion = "1.25.3"\n'
        self.path.write_text(text)
        self.start(text)
        self.assertIn('until 2026-11-04 or version change — active', self.invoke('status')[1])

    def test_config_preserves_positional_fields(self):
        config = Config(str(self.db_path), self.path, None, 'https://ntfy.invalid', 'test', None,
                        .25, '09:00', 'UTC', 17, 'fictional-agent', {}, 30, False,
                        'file', self.root / 'notifications.jsonl', {})
        self.assertEqual(config.overdue_minutes, 17)
        self.assertEqual(config.user_agent, 'fictional-agent')
        self.assertEqual(config.download_budgets, {})
        self.assertEqual(config.accept_warn_days, 180)

    def test_kev_breakthrough_still_gets_one_lapse(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record()]), self.kev()])
        self.assertEqual(len(self.items()), 1)
        self.assertFalse(self.items()[0].body['accepted']['held'])
        self.digest(1)
        self.digest(1)
        self.assertEqual(len(self.items()), 2)
        self.assertEqual(self.items()[1].reasons, ('acceptance lapsed',))

    def test_accepted_pair_silent_in_digest(self):  # T5
        self.start()
        self.engine.run_cycle([self.ingest([self.record(), self.record('CVE-2026-0002')])])
        self.digest()
        self.assertEqual([n.record_id for n in self.items()], ['CVE-2026-0002'])
        self.assertTrue(json.loads(self.pending()['body_json'])['accepted']['held'])
        self.assertGreater(self.pending()['due_at'], self.clock().isoformat())
        self.assertEqual(self.store.connection.execute("SELECT notified FROM pairs WHERE record_id='CVE-2026-0001'").fetchone()[0], 0)

    def test_held_row_rolls_forward_and_stays_healthy(self):  # T6
        self.start(WATCH + ENTRY.replace('2026-11-04', '2026-11-10'))
        self.engine.run_cycle([self.ingest([self.record()])])
        for day in range(3):
            self.digest(1)
            self.assertTrue(container_healthy(self.store, self.clock(), self.config))
            self.assertEqual(self.items(), [])
            self.assertGreater(self.pending()['due_at'], self.clock().isoformat())

    def test_high_epss_does_not_break_through(self):  # T7
        self.start()
        self.engine.run_cycle([self.ingest([self.record()]), IngestResult(
            'epss', FetchStatus.COMPLETE, Origin.SCORES, 'scores', self.clock(),
            epss={'CVE-2026-0001': (.9, .99)}, epss_date=self.clock().date())])
        self.assertEqual(self.items(), [])
        self.assertEqual(self.pending()['urgency'], 'normal')
        self.assertTrue(json.loads(self.pending()['body_json'])['accepted']['held'])

    def kev(self):
        return IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, 'next', self.clock(),
                            kev={'CVE-2026-0001': {'cveID': 'CVE-2026-0001', 'vendorProject': 'fictional', 'product': 'proxy'}})

    def test_kev_added_on_accepted_pair_alerts_with_accepted_line(self):  # T8
        self.start()
        self.engine.run_cycle([self.ingest([self.record()])])
        self.engine.run_cycle([self.kev()])
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.items()[0].urgency, 'urgent')
        self.assertIn('Accepted: Module not built (until 2026-11-04) — alerting anyway: KEV listed', render(self.items()[0])[1])

    def test_new_match_already_kev_listed_breaks_through(self):  # T9
        self.start()
        self.engine.run_cycle([self.kev(), self.ingest([self.record()])])
        self.assertEqual(len(self.items()), 1)
        self.assertFalse(self.items()[0].body['accepted']['held'])

    def test_until_lapse_resurfaces_once(self):  # T10
        self.start()
        self.engine.run_cycle([self.ingest([self.record()])])
        self.digest()
        self.assertEqual(self.items(), [])
        self.digest(1)
        self.assertEqual(len(self.items()), 1)
        self.assertIn('Acceptance lapsed (date passed): Module not built', render(self.items()[0])[1])
        self.digest(1)
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.store.connection.execute('SELECT notified FROM pairs').fetchone()[0], 1)

    def test_lapse_after_prior_notification_resurfaces_once(self):  # T11
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.digest()
        self.engine.accepts = watchlist.load_document_text(WATCH + ENTRY)[1]
        self.clock.now += timedelta(days=1)
        self.clock.now = self.clock.now.replace(hour=7)
        self.engine.run_cycle(self.fresh_sources())
        self.digest()
        self.assertEqual(len(self.items()), 2)
        self.assertEqual(self.items()[-1].reasons, ('acceptance lapsed',))
        self.digest(1)
        self.assertEqual(len(self.items()), 2)

    def test_version_change_lapses_until_version_change(self):  # T12
        text = WATCH + ENTRY.replace('until = 2026-11-04', 'until_version_change = true\nversion = "1.25.3"')
        self.start(text)
        self.engine.run_cycle([self.ingest([self.record(), self.record('CVE-2026-0002')])])
        self.engine.accepts += watchlist.load_document_text(WATCH + ENTRY.replace('0001', '0002'))[1]
        self.engine.reload_watches(watchlist.load_watchlist_text(WATCH.replace('1.25.3', '1.25.4')))
        self.digest()
        self.assertEqual([n.record_id for n in self.items()], ['CVE-2026-0001'])
        self.assertEqual(self.items()[0].body['acceptance_lapsed']['why'], 'version changed')

    def test_reload_adds_and_removes_acceptance_without_restart(self):  # T13
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.path.write_text(WATCH)
        scheduler = self.scheduler()
        self.path.write_text(WATCH + ENTRY)
        scheduler.tick()
        self.digest()
        self.assertEqual(self.items(), [])
        self.path.write_text(WATCH)
        scheduler.tick()
        self.digest(1)
        self.assertEqual(len(self.items()), 1)

    def test_replay_keeps_exact_mixed_case_watch_id(self):  # round-2 regression
        text = WATCH.replace('id = "proxy"', 'id = "Proxy"')
        self.path.write_text(text)
        self.start(text)
        self.engine.run_cycle([self.ingest([self.record()])])
        expect = self.root / 'expect.toml'
        expect.write_text('[[expect]]\nwatch_id = "Proxy"\ncve = "CVE-2026-0001"\n')
        self.assertEqual(self.invoke('replay', '--list', str(expect))[:2],
                         (0, 'Proxy CVE-2026-0001: matched\n'))
        # Replay ids stay exact, as before accept entries existed.
        expect.write_text('[[expect]]\nwatch_id = "proxy"\ncve = "CVE-2026-0001"\n')
        self.assertEqual(self.invoke('replay', '--list', str(expect))[0], 1)

    def test_fixed_accept_after_rejected_reload_recovers_health(self):  # T13b
        # Same watches before and after: the reload must still clear the rejection.
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        scheduler = self.scheduler()
        self.path.write_text(WATCH + ENTRY.replace('reason = "Module not built"', ''))
        scheduler.tick()
        state = lambda: self.engine.db.execute(
            "SELECT state FROM health WHERE source='watchlist'").fetchone()[0]
        self.assertEqual(state(), 'unhealthy')
        self.path.write_text(WATCH + ENTRY)
        scheduler.tick()
        self.assertEqual(state(), 'healthy')
        self.assertEqual(len(self.engine.accepts), 1)

    def test_entry_removed_releases_held_row(self):  # T14
        text = WATCH + ENTRY.replace('2026-11-04', '2026-11-10')
        self.start(text)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.engine.accepts = ()
        self.digest()
        self.assertEqual(len(self.items()), 1)
        self.assertEqual(self.items()[0].body['acceptance_lapsed']['why'], 'entry removed')
        self.digest(1)
        self.assertEqual(len(self.items()), 1)
        # Removing a watch drops its held rows like any pending row; re-adding it
        # re-matches, and a still-active entry holds the new row again.
        self.notifier.sent.clear()
        self.engine.accepts = watchlist.load_document_text(text)[1]
        other = self.record('CVE-2026-0003')
        self.engine.accepts += (replace(self.engine.accepts[0], cve='CVE-2026-0003'),)
        self.engine.run_cycle([self.ingest([other])])
        self.engine.reload_watches(())
        self.engine.run_cycle([])
        self.assertEqual(self.items(), [])
        self.engine.reload_watches(watchlist.load_watchlist_text(WATCH))
        self.digest(1)
        released = [n for n in self.items() if n.record_id == 'CVE-2026-0003']
        self.assertEqual(released, [])
        pending = self.engine.db.execute(
            "SELECT body_json FROM outbox WHERE sent_at IS NULL AND pair_key='proxy|CVE-2026-0003'").fetchall()
        self.assertEqual(len(pending), 1)
        self.assertTrue(json.loads(pending[0][0])['accepted']['held'])

    def test_acceptance_changes_no_ingest_state(self):  # T15
        snapshots = []
        for accepted in (False, True):
            store = Store(':memory:')
            store.migrate()
            watches, accepts = watchlist.load_document_text(WATCH + ENTRY)
            notifier = CaptureNotifier()
            engine = Engine(store, watches, self.aliases, self.config, self.clock, notifier,
                            accepts=accepts if accepted else ())
            engine.run_cycle(self.fresh_sources())
            engine.run_cycle([self.ingest([self.record()])])
            self.clock.now = self.clock.now.replace(hour=8)
            engine.run_cycle(self.fresh_sources())
            tables = [r[0] for r in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('outbox','sqlite_sequence')")]
            snapshot = {t: [dict(r) for r in store.connection.execute(f'SELECT * FROM {t}')] for t in tables}
            for row in snapshot['pairs']:
                row.pop('notified')
            snapshots.append(snapshot)
            engine.accepts = ()
            self.clock.now += timedelta(days=1)
            engine.run_cycle(self.fresh_sources())
            self.assertEqual(store.connection.execute('SELECT notified FROM pairs').fetchone()[0], 1)
            store.connection.close()
            self.clock.now = datetime(2026, 11, 4, 7, tzinfo=timezone.utc)
        self.assertEqual(*snapshots)

    def test_crash_and_replay_idempotent_with_acceptances(self):  # T16
        self.start()
        ingest = self.ingest([self.record(), self.record('CVE-2026-0002')])
        self.notifier.down = True
        self.engine.run_cycle([ingest])
        self.digest()
        self.assertEqual(self.items(), [])
        self.build()
        self.clock.now += timedelta(minutes=2)
        self.notifier.down = False
        self.engine.run_cycle([ingest])
        self.engine.run_cycle([ingest])
        self.assertEqual([n.record_id for n in self.items()], ['CVE-2026-0002'])
        self.assertTrue(json.loads(self.pending()['body_json'])['accepted']['held'])

    def test_status_text_and_json_list_acceptances(self):  # T17
        self.start()
        code, out, _ = self.invoke('status')
        self.assertEqual(code, 0)
        self.assertIn('accepted: proxy/CVE-2026-0001 until 2026-11-04', out)
        self.assertIn('held 0; Module not built', out)
        result = json.loads(self.invoke('status', '--json')[1])
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['accepted'][0]['watch_id'], 'proxy')
        self.path.write_text(WATCH)
        plain = json.loads(self.invoke('status', '--json')[1])
        result.pop('accepted')
        plain.pop('accepted', None)
        self.assertEqual(result, plain)
        self.path.write_text('invalid = true')
        self.assertIn('accepted: not checked (watch list unreadable)', self.invoke('status')[1])
        self.assertNotIn('accepted', json.loads(self.invoke('status', '--json')[1]))

    def test_report_counts_accepted_apart(self):  # T18
        self.start()
        self.engine.run_cycle([self.ingest([self.record(), self.record('CVE-2026-0002')])])
        out = self.invoke('report')[1]
        self.assertIn('Open matches: 1', out)
        self.assertIn('Accepted (not alerting): 1', out)
        code, out, err = self.invoke('report', '--format', 'jsonl')
        self.assertEqual(code, 0)
        rows = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['accepted']['state'], 'active')
        self.assertIsNone(rows[1]['accepted'])
        self.assertEqual(rows[0]['schema_version'], 1)
        self.assertEqual(rows[0]['group'], 'open')
        self.engine.run_cycle([self.kev()])
        self.assertIn('Open matches: 2', self.invoke('report')[1])
        self.path.write_text('invalid = true')
        code, out, err = self.invoke('report', '--format', 'jsonl')
        self.assertIn('accepted: not applied (watch list unreadable)', err)
        for line in out.splitlines():
            json.loads(line)

    def test_watch_check_lists_acceptances_and_warnings(self):  # T19
        text = WATCH + ENTRY.replace('2026-11-04', '2020-01-01') + ENTRY.replace('0001', '0002').replace('2026-11-04', '2099-01-01')
        self.path.write_text(text)
        code, out, _ = self.invoke('watch', 'check')
        self.assertEqual(code, 0)
        self.assertIn('lapsed-date', out)
        self.assertIn('accept warning:', out)
        self.assertIn('long', out)
        self.assertIn('matches nothing', out)
        candidate = self.root / 'candidate.toml'
        candidate.write_text(WATCH + ENTRY.replace('2026-11-04', '2099-01-01'))
        self.config_path.write_text(self.config_path.read_text() + 'accept_warn_days = 40000\n')
        self.assertNotIn('long', self.invoke('watch', 'check', '--file', str(candidate))[1])
        self.config_path.write_text(f'db_path = "{self.root / "missing.db"}"\nwatchlist_path = "{candidate}"\n')
        out = self.invoke('watch', 'check')[1]
        self.assertIn('not checked', out)
        self.assertNotIn('matches nothing', out)

    def test_correction_still_sent_for_previously_notified_accepted_pair(self):  # T20
        self.start(WATCH)
        self.engine.run_cycle([self.ingest([self.record()])])
        self.digest()
        self.engine.accepts = watchlist.load_document_text(WATCH + ENTRY)[1]
        fixed = self.record()
        fixed['containers']['cna']['affected'][0]['versions'][0]['status'] = 'unaffected'
        self.engine.run_cycle([self.ingest([fixed])])
        self.digest(1)
        self.assertEqual(len(self.items()), 2)
        self.assertEqual(self.items()[-1].reasons, ('correction',))

    def test_reason_sanitised_in_render(self):  # T21
        self.start()
        self.engine.accepts = (replace(self.engine.accepts[0], reason='private\x00\n  reason ' + 'x' * 180),)
        self.engine.run_cycle([self.ingest([self.record()]), self.kev()])
        line = next(line for line in render(self.items()[0])[1].splitlines() if line.startswith('Accepted:'))
        reason = line.split('Accepted: ')[1].split(' (until')[0]
        self.assertEqual(len(reason), 160)
        self.assertTrue(reason.startswith('private reason '))
        self.assertNotIn('\x00', line)
        scheduler = self.scheduler()
        scheduler.tick()
        self.assertNotIn('private', ''.join(self.lines))
        error = watchlist.WatchlistError(['accept entry 1: private reason'])
        self.assertNotIn('private', safe_message(error))
        health = Notification('', '', 'watchlist', ('unhealthy',), 'health', {'accepted': {'reason': 'private'}})
        self.assertNotIn('private', render(health)[1])

    def test_accept_warn_days_config(self):  # T22
        self.assertEqual(load_config(self.config_path, {}).accept_warn_days, 180)
        self.config_path.write_text('accept_warn_days = 21')
        self.assertEqual(load_config(self.config_path, {}).accept_warn_days, 21)
        for value in ('0', '-1', 'true', '1.5', '"30"'):
            self.config_path.write_text('accept_warn_days = ' + value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'accept_warn_days'):
                load_config(self.config_path, {})

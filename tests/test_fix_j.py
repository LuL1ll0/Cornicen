# script-purpose: Check fix j behavior and private diagnostics.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_fix_j.py
"""Offline regressions for concurrent diagnostics and resilient minute cycles.

Reads local source and fixtures; writes temporary test data and unittest output.
Exit codes: 0 success, 1 failed tests, 2 invalid command arguments.
"""
from contextlib import closing, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import queue
import sqlite3
import stat
import tempfile
import threading
import unicodedata
import unittest
from unittest.mock import Mock, patch

from cornicen import cli
from cornicen.config import Config, SecretToken
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.notify.file import FileNotifier
from cornicen.scheduler import Scheduler
from cornicen.store import Store
from cornicen.watchlist import WatchlistError, load_watchlist
from tests.replay.harness import FakeClock


class CycleStop:
    """Advance fake time at the loop's normal wait boundary."""
    def __init__(self, clock, cycles, after=None):
        self.clock, self.cycles, self.after = clock, cycles, after
        self.count = 0

    def is_set(self):
        return self.count >= self.cycles

    def set(self):
        self.count = self.cycles

    def wait(self, seconds):
        if self.after:
            self.after(self.count)
        self.count += 1
        self.clock.now += timedelta(minutes=1)


class FixJTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        # URI metacharacters must remain part of the filename.
        self.db = self.root / 'state #?.db'
        self.watch = self.root / 'watch.toml'
        self.watch.write_text('''[[watch]]
id = "fixture-watch"
name = "Fixture service"
match = ["fixture:service"]
version = "1.0"
scheme = "dotted"
''')
        self.config_path = self.root / 'config.toml'
        self.config_path.write_text(f'db_path="{self.db}"\nwatchlist_path="{self.watch}"\n')
        self.acceptance = self.root / 'acceptance.toml'
        self.acceptance.write_text('[[expect]]\nwatch_id="fixture-watch"\ncve="CVE-2026-1000"\n')
        self.store = Store(str(self.db))
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.clock = FakeClock(datetime.now(timezone.utc))
        self.config = Config(str(self.db), self.watch, None, 'https://ntfy.invalid',
                             'fixture', SecretToken('fixture-token'), notifier='file',
                             notification_path=self.root / 'notifications.jsonl')
        self.engine = Engine(self.store, load_watchlist(self.watch), AliasMap.load(False),
                             self.config, self.clock, FileNotifier(self.config.notification_path))
        self.sources = {}
        for name, origin in [('cvelist', Origin.DELTA), ('kev', Origin.CATALOG), ('epss', Origin.SCORES)]:
            self.sources[name] = Mock()
            self.sources[name].poll.side_effect = lambda now, name=name, origin=origin: [
                IngestResult(name, FetchStatus.COMPLETE, origin, 'cursor', now)]
        self.lines = []
        self.scheduler = Scheduler(self.engine, self.sources, self.clock, self.lines.append,
                                   monotonic=lambda: self.clock().timestamp())
        self.scheduler.intervals = dict.fromkeys(self.sources, timedelta(minutes=1))

    def invoke(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(['--config', str(self.config_path), *args])
        return code, output.getvalue()

    def run_cycles(self, count, after=None):
        self.scheduler.stop = CycleStop(self.clock, count, after)
        with patch('cornicen.scheduler.signal.signal'):
            self.assertEqual(self.scheduler.run(), 0)
        self.assertEqual(self.scheduler.stop.count, count)

    def health(self, source):
        return self.store.connection.execute('SELECT state FROM health WHERE source=?', (source,)).fetchone()[0]

    def notifications(self):
        return [json.loads(line) for line in self.config.notification_path.read_text().splitlines()]

    def test_loop_with_concurrent_cli_and_long_read_transaction(self):
        cycles = 4
        requests, ready, release, finished = (queue.Queue() for _ in range(4))
        failures, commands = [], []

        def reader():
            try:
                for _ in range(cycles):
                    if requests.get(timeout=10) is None:
                        return
                    db = sqlite3.connect(self.db.resolve().as_uri() + '?mode=ro', uri=True)
                    try:
                        db.execute('BEGIN')
                        db.execute('SELECT * FROM meta').fetchall()
                        for args in [('watch', 'check'), ('status',), ('report',)]:
                            with patch('cornicen.cli.print', create=True) as output:
                                code = cli.main(['--config', str(self.config_path), *args])
                            if code != 0:
                                raise AssertionError((args, code, output.call_args_list))
                            commands.append(args)
                        ready.put(True)
                        # Old rollback journaling times out at five seconds while
                        # this snapshot stays open. WAL must commit before release.
                        release.get(timeout=8)
                    finally:
                        db.close()
                    finished.put(True)
            except Exception as error:
                failures.append(error)
                ready.put(False)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        original_poll = self.sources['cvelist'].poll.side_effect
        original_cycle = self.engine.run_cycle
        completed = []

        def poll(now):
            requests.put(True)
            self.assertTrue(ready.get(timeout=10))
            return original_poll(now)

        def cycle(ingests):
            try:
                result = original_cycle(ingests)
                completed.append(result)
                return result
            finally:
                release.put(True)
                self.assertTrue(finished.get(timeout=10))

        self.sources['cvelist'].poll.side_effect = poll
        try:
            with patch.object(self.engine, 'run_cycle', side_effect=cycle):
                self.run_cycles(cycles)
        finally:
            requests.put(None)
            release.put(True)
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(completed), cycles)
        self.assertEqual(len(commands), cycles * 3)
        self.assertEqual(len(self.lines), cycles)
        self.assertFalse(any('error' in json.loads(line) for line in self.lines))
        self.assertTrue(self.notifications())

    def test_connection_pragmas_and_private_wal_sidecars(self):
        self.assertEqual(self.store.connection.execute('PRAGMA busy_timeout').fetchone()[0], 30000)
        self.assertEqual(self.store.connection.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        original_umask = os.umask(0)
        try:
            self.store.set_meta('fixture', 'value')
            for suffix in ('', '-wal', '-shm'):
                self.assertEqual(stat.S_IMODE(Path(str(self.db) + suffix).stat().st_mode), 0o600)
            reader = Store(str(self.db), read_only=True)
            self.addCleanup(reader.connection.close)
            self.assertEqual(reader.connection.execute('PRAGMA busy_timeout').fetchone()[0], 30000)
            self.assertEqual(reader.connection.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        finally:
            os.umask(original_umask)

    def test_diagnostics_use_read_only_uri_without_migration_or_writes(self):
        connect = sqlite3.connect
        for args in [('status',), ('healthcheck',), ('watch', 'check'), ('report',),
                     ('replay', '--list', str(self.acceptance))]:
            connections = []

            def opened(path, *positional, **kwargs):
                self.assertEqual(path, self.db.resolve().as_uri() + '?mode=ro')
                self.assertTrue(kwargs.get('uri'))
                connection = connect(path, *positional, **kwargs)
                with self.assertRaisesRegex(sqlite3.OperationalError, 'readonly'):
                    connection.execute('CREATE TABLE forbidden(value)')
                connections.append(connection)
                return connection

            with self.subTest(command=args), patch('cornicen.store.sqlite3.connect', side_effect=opened), \
                    patch.object(Store, 'migrate', side_effect=AssertionError('Reader migrated')):
                code, text = self.invoke(*args)
                self.assertEqual(code, 1 if args[0] == 'replay' else 0, text)
                self.assertEqual(len(connections), 1)
                self.assertNotIn('command failed', text)

    def test_reader_does_not_chmod_existing_files(self):
        self.db.chmod(0o640)
        self.assertEqual(self.invoke('status')[0], 0)
        self.assertEqual(stat.S_IMODE(self.db.stat().st_mode), 0o640)

    def test_source_exception_is_persisted_notified_and_recovers(self):
        poll = self.sources['cvelist'].poll.side_effect
        calls = 0

        def flaky(now):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError('source\nfailed\x00\u202e fixture-token ' + 'x' * 400)
            return poll(now)

        self.sources['cvelist'].poll.side_effect = flaky
        self.run_cycles(3, lambda index: self.assertEqual(
            self.health('cvelist'), 'unhealthy' if index == 0 else 'healthy'))
        self.assertEqual(calls, 3)
        errors = [json.loads(line) for line in self.lines if 'error' in json.loads(line)]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['component'], 'cvelist')
        self.assertEqual(errors[0]['error'], 'RuntimeError')
        self.assertEqual(errors[0]['message'], '[redacted]')
        self.assertLessEqual(len(errors[0]['message']), 300)
        self.assertFalse(any(unicodedata.category(c).startswith('C') for c in errors[0]['message']))
        self.assertNotIn('fixture-token', ''.join(self.lines))
        self.assertEqual([(n['record_id'], n['reasons']) for n in self.notifications()
                          if n['record_id'] == 'cvelist'],
                         [('cvelist', ['unhealthy']), ('cvelist', ['healthy'])])

    def test_engine_exception_retries_uncommitted_ingests_and_recovers(self):
        original = self.engine.run_cycle
        calls = 0

        def flaky(ingests):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ValueError('engine failed')
            return original(ingests)

        # Retries must not wait an hour after the failed engine call.
        self.scheduler.intervals = Scheduler.intervals
        with patch.object(self.engine, 'run_cycle', side_effect=flaky):
            self.run_cycles(3, lambda index: self.assertEqual(
                self.health('engine'), 'unhealthy' if index == 0 else 'healthy'))
        self.assertEqual(calls, 3)
        self.assertEqual(self.sources['cvelist'].poll.call_count, 2)
        self.assertEqual(self.store.get_meta('complete:cvelist'), '1')
        errors = [json.loads(line) for line in self.lines if 'error' in json.loads(line)]
        self.assertEqual([(e['component'], e['error'], e['message']) for e in errors],
                         [('engine', 'ValueError', 'engine failed')])
        self.assertEqual([n['reasons'] for n in self.notifications() if n['record_id'] == 'engine'],
                         [['unhealthy'], ['healthy']])

    def test_cycle_record_payload_and_token_never_reach_logs_or_health(self):
        record = {'cveMetadata': {'cveId': 'CVE-2026-1000'},
                  'containers': {'cna': {'title': 'fixture-record-content'}}}
        self.sources['cvelist'].poll.side_effect = [
            RuntimeError(f'poll failed: {record}; fixture-token'), []]
        self.run_cycles(2)
        error = next(json.loads(line) for line in self.lines if 'error' in json.loads(line))
        self.assertEqual(error['error'], 'RuntimeError')
        for text in (''.join(self.lines), self.config.notification_path.read_text(),
                     str(list(map(tuple, self.store.connection.execute('SELECT * FROM health'))))):
            self.assertNotIn('fixture-record-content', text)
            self.assertNotIn('fixture-token', text)
            self.assertNotIn('cveMetadata', text)

    def test_failure_to_persist_health_does_not_kill_loop(self):
        original = self.engine.run_cycle
        health = self.engine._health
        calls = 0

        def flaky(ingests):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError('engine failed')
            return original(ingests)

        def unavailable(source, state, detail, reason=None):
            if source == 'engine' and state == 'unhealthy':
                raise sqlite3.OperationalError('database is locked')
            return health(source, state, detail, reason)

        with patch.object(self.engine, 'run_cycle', side_effect=flaky), \
                patch.object(self.engine, '_health', side_effect=unavailable):
            self.run_cycles(2)
        errors = [json.loads(line) for line in self.lines if 'error' in json.loads(line)]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['health_error'], 'OperationalError')
        self.assertEqual(self.health('cvelist'), 'healthy')

    def test_failed_cycle_rolls_back_abandoned_transaction_before_health(self):
        original = self.engine.run_cycle
        calls = 0

        def interrupted(ingests):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.store.connection.execute('BEGIN')
                self.store.set_meta('uncommitted-fixture', 'discard')
                raise sqlite3.OperationalError('database is locked')
            return original(ingests)

        def checked(index):
            self.assertFalse(self.store.connection.in_transaction)
            with closing(sqlite3.connect(self.db.resolve().as_uri() + '?mode=ro', uri=True)) as reader:
                self.assertEqual(reader.execute("SELECT state FROM health WHERE source='engine'").fetchone()[0],
                                 'unhealthy' if index == 0 else 'healthy')
                self.assertIsNone(reader.execute("SELECT v FROM meta WHERE k='uncommitted-fixture'").fetchone())

        with patch.object(self.engine, 'run_cycle', side_effect=interrupted):
            self.run_cycles(2, checked)
        self.assertEqual([n['reasons'] for n in self.notifications() if n['record_id'] == 'engine'],
                         [['unhealthy'], ['healthy']])

    def test_cli_failure_includes_type_and_sanitised_bounded_message(self):
        with patch('cornicen.cli.load_config', return_value=self.config), \
                patch('cornicen.cli.Store', side_effect=sqlite3.OperationalError(
                    'database\nis locked\x00\u202e fixture-token ' + 'x' * 400)):
            code, text = self.invoke('status')
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith('command failed: OperationalError: [redacted]'))
        self.assertEqual(len(text.splitlines()), 1)
        self.assertNotIn('fixture-token', text)
        self.assertLessEqual(len(text.removeprefix('command failed: OperationalError: ').rstrip('\n')), 300)
        self.assertFalse(any(unicodedata.category(c).startswith('C') for c in text.rstrip('\n')))

    def test_cli_unexpected_exception_is_reported_without_record_payload(self):
        with patch('cornicen.cli.Store', side_effect=RuntimeError(
                'bad record: {"cveMetadata": {"title": "fixture-record-content"}}')):
            code, text = self.invoke('status')
        self.assertEqual(code, 1)
        self.assertIn('RuntimeError', text)
        self.assertNotIn('fixture-record-content', text)

    def test_cli_watchlist_failure_does_not_expose_inventory(self):
        with patch('cornicen.cli.load_watchlist', side_effect=WatchlistError(['fixture-private-inventory'])):
            code, text = self.invoke('watch', 'check')
        self.assertEqual(code, 1)
        self.assertIn('WatchlistError', text)
        self.assertNotIn('fixture-private-inventory', text)

    def test_memory_connections_also_set_busy_timeout(self):
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        self.assertEqual(store.connection.execute('PRAGMA busy_timeout').fetchone()[0], 30000)

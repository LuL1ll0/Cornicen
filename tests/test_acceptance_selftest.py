"""Scheduled and read-only acceptance checks use fictional pinned inventory."""

import contextlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
import json
import os
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import acceptance
from cornicen.cli import main
from cornicen.config import Config, load_config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.scheduler import Scheduler
from cornicen.store import Store
from tests.replay.harness import FakeClock, RecordingNotifier


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.live = self.root / 'live.toml'
        self.live.write_text('')
        self.pinned = self.root / 'pinned.toml'
        self.watch_text = '''[[watch]]
id = "pinned-orbit"
name = "Zyphora Relay"
match = ["zyphora:relay"]
version = "4.2.3"
scheme = "semver"
'''
        self.pinned.write_text(self.watch_text)
        self.list = self.root / 'expect.toml'
        self.list.write_text('[[expect]]\nwatch_id = "pinned-orbit"\ncve = "CVE-2099-0001"\n')
        self.db_path = self.root / 'test.db'
        self.store = Store(str(self.db_path))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.clock = FakeClock(datetime(2099, 5, 1, tzinfo=timezone.utc))
        self.config = Config(str(self.db_path), self.live, None, 'https://ntfy.invalid', 'test', None,
                             acceptance_list_path=self.list, acceptance_watchlist_path=self.pinned)
        self.notifier = RecordingNotifier(self.clock)
        self.engine = Engine(self.store, (), AliasMap.load(False), self.config, self.clock, self.notifier)
        self.store.set_meta('baseline_complete', '1')
        self.record()
        self.lines = []
        self.sources = {name: Mock() for name in Scheduler.intervals}
        for source in self.sources.values():
            source.poll.return_value = []
        self.scheduler = self.new_scheduler()

    def new_scheduler(self):
        return Scheduler(self.engine, self.sources, self.clock, self.lines.append,
                         monotonic=lambda: self.clock().timestamp())

    def record(self, version='4.0.0', cve='CVE-2099-0001', default='unaffected', old=False):
        record = {'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': [{
                      'vendor': 'zyphora', 'product': 'relay', 'defaultStatus': default,
                      'versions': [{'version': version, 'lessThan': '4.5.0',
                                    'versionType': 'semver', 'status': 'affected'}]}]}}}
        self.store.put_record(cve, record, (self.clock() - timedelta(days=800) if old else self.clock()).isoformat())

    def health(self):
        return self.store.connection.execute("SELECT * FROM health WHERE source='acceptance'").fetchone()

    def events(self):
        return [json.loads(row[0]) for row in self.store.connection.execute(
            "SELECT body_json FROM outbox WHERE urgency='health' AND json_extract(body_json,'$.record_id')='acceptance'")]

    def kev(self):
        self.store.connection.execute('INSERT OR REPLACE INTO kev VALUES (?,?)', (
            'CVE-2099-0001', json.dumps({'cveID': 'CVE-2099-0001', 'vendorProject': 'zyphora', 'product': 'relay'})))

    def changed(self):
        self.list.write_text(self.list.read_text() + '\n# changed\n')

    def test_all_pass_healthy_without_event(self):
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'healthy')
        self.assertEqual(self.health()['detail'], '1 of 1 entries match')
        self.assertEqual(self.events(), [])
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_silenced_match_health_outbox_and_same_tick_delivery(self):
        self.record('4.4.0')
        self.scheduler.tick()
        self.assertEqual(self.health()['detail'], '1 of 1 entries no longer match; 0 could not be checked')
        self.assertEqual(self.events()[0]['reason'], 'failed')
        self.assertEqual(self.events()[0]['detail'], 'acceptance self-test failed')
        row = self.store.connection.execute("SELECT sent_at FROM outbox WHERE urgency='health' AND json_extract(body_json,'$.record_id')='acceptance'").fetchone()
        self.assertIsNotNone(row[0])

    def test_unknown_kev_is_regression(self):
        self.scheduler.tick()
        self.record('unorderable', default='unknown')
        self.kev()
        self.changed()
        self.scheduler.tick()
        outcomes = acceptance.evaluate(self.store, acceptance.load_entries(self.list),
                                       acceptance.load_watches(self.pinned, acceptance.load_entries(self.list)),
                                       self.engine.aliases)
        self.assertEqual(outcomes[0].state, 'unknown')
        self.assertEqual(self.events()[0]['reason'], 'failed')

    def test_unknown_without_kev_is_regression(self):
        self.record('unorderable', default='unknown')
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'unhealthy')
        self.assertEqual(self.events()[0]['reason'], 'failed')
        self.assertEqual(self.invoke()[0], 1)
        self.assertIn('regression (unknown)', self.invoke()[1])

    def test_resolve_none_is_regression(self):
        with patch('cornicen.acceptance.resolve', return_value=None):
            self.scheduler.tick()
            self.assertEqual(self.invoke()[0], 1)
            self.assertIn('regression (no_match)', self.invoke()[1])
        self.assertEqual(self.health()['state'], 'unhealthy')
        self.assertEqual(self.events()[0]['reason'], 'failed')

    def test_text_record_passes(self):
        import zlib
        raw = self.store.connection.execute('SELECT json FROM records').fetchone()[0]
        self.store.connection.execute('UPDATE records SET json=?', (zlib.decompress(raw).decode(),))
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'healthy')
        self.assertEqual(self.invoke()[0], 0)

    def test_case_insensitive_duplicate_watch_id_rejected(self):
        self.pinned.write_text(self.watch_text + self.watch_text.replace('pinned-orbit', 'PINNED-ORBIT'))
        self.scheduler.tick()
        self.assertEqual(self.health()['detail'], 'Acceptance list rejected')
        self.assertEqual(self.events()[0]['reason'], 'rejected')
        self.assertEqual(self.invoke()[0], 2)

    def test_unknown_top_level_keys_rejected(self):
        original = self.list.read_text()
        for extra in ('[[exepct]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n',
                      '[other]\nvalue=1\n', 'extra=1\n'):
            with self.subTest(extra=extra):
                # Include a valid entry: otherwise the empty-list check masks the bug.
                self.list.write_text(extra + original)
                self.scheduler.tick()
                self.assertEqual(self.health()['detail'], 'Acceptance list rejected')
                self.assertEqual(self.events()[0]['reason'], 'rejected')
                self.assertEqual(self.invoke()[0], 2)

    def test_missing_record_with_and_without_kev(self):
        self.store.connection.execute('DELETE FROM records')
        for kev in (False, True):
            with self.subTest(kev=kev):
                if kev:
                    self.kev()
                    self.store.set_meta('kev_only:CVE-2099-0001', '1')
                self.changed()
                self.scheduler.tick()
                self.assertEqual(self.health()['detail'], '0 of 1 entries no longer match; 1 could not be checked')
                self.assertEqual(self.events()[0]['reason'], 'missing')

    def test_rejected_files(self):
        for path, text in ((self.list, 'private-inventory = ['), (self.list, ''),
                           (self.list, '[[expect]]\nwatch_id="absent"\ncve="CVE-2099-0001"'),
                           (self.pinned, 'private-inventory = [')):
            with self.subTest(path=path, text=text):
                self.list.write_text('[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0001"')
                self.pinned.write_text(self.watch_text)
                path.write_text(text)
                self.scheduler.tick()
                self.assertEqual(self.health()['detail'], 'Acceptance list rejected')
                self.assertEqual(self.events()[0]['reason'], 'rejected')
                self.assertNotIn('private-inventory', json.dumps(self.events()))

    def test_unreadable_files(self):
        for path in (self.list, self.pinned):
            with self.subTest(path=path):
                old = path.read_text()
                path.unlink()
                self.scheduler.tick()
                self.assertEqual(self.health()['detail'], 'Acceptance list rejected')
                path.write_text(old)

    def test_config_requires_both_paths_and_positive_interval(self):
        path = self.root / 'config.toml'
        for text in ('acceptance_list_path="list"', 'acceptance_watchlist_path="watch"',
                     'acceptance_interval_days=0', 'acceptance_interval_days=true',
                     'acceptance_interval_days=1.5'):
            path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_config(path, {})
        path.write_text('')
        config = load_config(path, {})
        self.assertIsNone(config.acceptance_list_path)
        self.assertEqual(config.acceptance_interval_days, 7)

    def test_recovery_event(self):
        self.record('4.4.0')
        self.scheduler.tick()
        self.record()
        self.changed()
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'healthy')
        self.assertEqual([event['reason'] for event in self.events()], ['failed', 'recovered'])

    def test_schedule_first_interval_restart_and_stamps(self):
        with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 1)
            saved = self.store.get_meta('acceptance_last_run')
            self.clock.now += timedelta(days=7)
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 1)
            self.clock.now += timedelta(seconds=1)
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 2)
            self.assertNotEqual(saved, self.store.get_meta('acceptance_last_run'))
            self.scheduler = self.new_scheduler()
            # Isolate the explicit first-process-tick trigger from stamp changes.
            self.scheduler.acceptance_stamp = self.scheduler._acceptance_stamps()
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 3)
            self.clock.now += timedelta(days=8)
            self.scheduler = self.new_scheduler()
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 4)
            self.changed()
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 5)
            self.pinned.write_text(self.watch_text + '\n# changed\n')
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 6)

    def test_size_only_and_mtime_only_stamp_changes_run(self):
        self.scheduler.tick()
        for path in (self.list, self.pinned):
            for change in ('size', 'mtime'):
                with self.subTest(path=path, change=change):
                    before = path.stat()
                    if change == 'size':
                        path.write_text(path.read_text() + '\n# size change\n')
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                    else:
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                    after = path.stat()
                    self.assertEqual(before.st_ino, after.st_ino)
                    self.assertEqual(before.st_mtime_ns == after.st_mtime_ns, change == 'size')
                    self.assertEqual(before.st_size == after.st_size, change == 'mtime')
                    with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
                        self.scheduler.tick()
                    evaluate.assert_called_once()

    def test_unhealthy_retries_hourly_and_healthy_keeps_interval(self):
        for failure in ('regression', 'missing', 'exception', 'rejected'):
            with self.subTest(failure=failure):
                self.scheduler = self.new_scheduler()
                self.record('4.4.0' if failure == 'regression' else '4.0.0')
                if failure == 'missing':
                    self.store.connection.execute('DELETE FROM records')
                original = self.pinned.read_text()
                if failure == 'rejected':
                    self.pinned.write_text('broken = [')
                with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
                    if failure == 'exception':
                        evaluate.side_effect = RuntimeError('private inventory')
                    self.scheduler.tick()
                    self.assertEqual(self.health()['state'], 'unhealthy')
                    evaluate.side_effect = None
                    self.record()
                    if failure == 'rejected':
                        self.pinned.write_text(original)
                        # Isolate the hourly trigger from the repair's stamp change.
                        self.scheduler.acceptance_stamp = self.scheduler._acceptance_stamps()
                    calls = evaluate.call_count
                    self.clock.now += timedelta(minutes=59)
                    self.scheduler.tick()
                    self.assertEqual(evaluate.call_count, calls)
                    self.clock.now += timedelta(minutes=1)
                    self.scheduler.tick()
                    self.assertEqual(evaluate.call_count, calls + 1)
                    self.assertEqual(self.health()['state'], 'healthy')
                    self.clock.now += timedelta(hours=2)
                    self.scheduler.tick()
                    self.assertEqual(evaluate.call_count, calls + 1)

    def test_invalid_last_run_is_due_then_normal(self):
        self.scheduler.tick()
        for value in ('not-a-date', self.clock().replace(tzinfo=None).isoformat(),
                      (self.clock() + timedelta(days=30)).isoformat()):
            with self.subTest(value=value):
                self.store.set_meta('acceptance_last_run', value)
                with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
                    self.scheduler.tick()
                    evaluate.assert_called_once()
                    self.assertEqual(self.store.get_meta('acceptance_last_run'), self.clock().isoformat())
                    self.clock.now += timedelta(minutes=1)
                    self.scheduler.tick()
                    evaluate.assert_called_once()

    def test_selftest_secondary_failures_never_escape_or_print_inventory(self):
        original_health = self.engine._health
        original_get = self.store.get_meta
        def health(source, *args):
            if source == 'acceptance':
                raise RuntimeError('private Zyphora 4.2.3')
            return original_health(source, *args)
        def get_meta(key):
            if key == 'baseline_complete':
                raise RuntimeError('private Zyphora 4.2.3')
            return original_get(key)
        # Engine uses the same methods: let run_cycle finish before injecting.
        original_cycle = self.engine.run_cycle
        for target, replacement in ((self.engine, ('_health', health)),
                                    (self.engine, ('_flush', Mock(side_effect=RuntimeError('private Zyphora 4.2.3')))),
                                    (self.store, ('get_meta', get_meta))):
            with self.subTest(method=replacement[0]), contextlib.ExitStack() as stack:
                self.scheduler = self.new_scheduler()
                def cycle(ingests):
                    report = original_cycle(ingests)
                    stack.enter_context(patch.object(target, replacement[0], replacement[1]))
                    return report
                stack.enter_context(patch.object(self.engine, 'run_cycle', side_effect=cycle))
                self.scheduler.tick()
                self.assert_private_absent('\n'.join(self.lines))

    def assert_private_absent(self, text):
        for private in ('private', 'pinned-orbit', 'CVE-2099-0001', 'Zyphora',
                        '4.2.3', str(self.root), str(self.list), str(self.pinned)):
            self.assertNotIn(private, text)

    def test_error_guards_keep_all_output_private(self):
        secret = f'private pinned-orbit CVE-2099-0001 Zyphora 4.2.3 {self.list} {self.pinned}'
        output = io.StringIO()
        errors = io.StringIO()
        logs = io.StringIO()
        import logging
        handler = logging.StreamHandler(logs)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        original_health = self.engine._health
        def health(source, *args):
            if source == 'acceptance':
                raise RuntimeError(secret)
            return original_health(source, *args)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            # Refresh guard, evaluation guard, and secondary guard each see
            # an exception containing the entire fictional private inventory.
            with patch('cornicen.acceptance.load_entries', side_effect=RuntimeError(secret)):
                self.scheduler.tick()
            self.changed()
            with patch('cornicen.acceptance.evaluate', side_effect=RuntimeError(secret)):
                self.scheduler.tick()
            self.changed()
            with patch.object(self.engine, '_health', side_effect=health):
                self.scheduler.tick()
        self.assertEqual(len(self.lines), 3)
        self.assert_private_absent('\n'.join(self.lines) + output.getvalue()
                                   + errors.getvalue() + logs.getvalue())

    def test_failed_holds_write_protects_this_tick_and_repairs_next_tick(self):
        self.record(old=True)
        original = self.store.set_meta
        def set_meta(key, value):
            if key == 'acceptance_holds':
                raise sqlite3.OperationalError('fictional write failure')
            return original(key, value)
        with patch.object(self.store, 'set_meta', side_effect=set_meta):
            self.scheduler.tick()
        self.assertIsNone(self.store.get_meta('acceptance_holds'))
        self.assertEqual(self.engine.acceptance_holds, frozenset({'CVE-2099-0001'}))
        self.assertIsNotNone(self.store.connection.execute('SELECT id FROM records').fetchone())
        self.assertEqual(self.health()['state'], 'healthy')
        self.scheduler.tick()
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_corrupt_holds_repaired_with_unchanged_files_before_pruning(self):
        self.scheduler.tick()
        for garbage in ('not-json', '{"x":"CVE-2099-0001"}', '5', '[null]', '[5]'):
            with self.subTest(garbage=garbage):
                self.store.set_meta('acceptance_holds', garbage)
                self.record(old=True)
                self.scheduler.tick()
                self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])
                self.assertIsNotNone(self.store.connection.execute('SELECT id FROM records').fetchone())

    def test_failed_hold_parse_retried_with_unchanged_files(self):
        with patch('cornicen.acceptance.load_entries', side_effect=acceptance.AcceptanceError('rejected')):
            self.scheduler.tick()
        self.assertEqual(self.engine.acceptance_holds, frozenset())
        self.assertIsNone(self.store.get_meta('acceptance_holds'))
        self.record(old=True)
        self.scheduler.tick()
        self.assertEqual(self.engine.acceptance_holds, frozenset({'CVE-2099-0001'}))
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])
        self.assertIsNotNone(self.store.connection.execute('SELECT id FROM records').fetchone())

    def test_garbage_holds_without_memory_do_not_prevent_pruning(self):
        self.assertEqual(self.engine.acceptance_holds, frozenset())
        for garbage in ('not-json', '{"x":"CVE-2099-0001"}', '5', '[null]', '[5]',
                        '["CVE-2099-0001", null]', '["CVE-2099-0001", 5]'):
            with self.subTest(garbage=garbage):
                self.store.set_meta('acceptance_holds', garbage)
                self.record(old=True)
                self.store.prune_records(self.clock(), self.config.retention_days)
                self.assertIsNone(self.store.connection.execute('SELECT id FROM records').fetchone())

    def test_keep_alone_protects_record_without_meta(self):
        self.assertIsNone(self.store.get_meta('acceptance_holds'))
        self.record(old=True)
        self.record(cve='CVE-2099-0002', old=True)
        self.store.prune_records(self.clock(), self.config.retention_days,
                                 keep=frozenset({'CVE-2099-0001'}))
        self.assertEqual([row[0] for row in self.store.connection.execute('SELECT id FROM records')],
                         ['CVE-2099-0001'])

    def test_failed_health_transaction_retries_next_tick_atomically(self):
        self.scheduler.tick()
        saved = self.store.get_meta('acceptance_last_run')
        stamp = self.scheduler.acceptance_stamp
        self.clock.now += timedelta(minutes=1)
        self.record('4.4.0')
        self.changed()
        original = self.engine._health
        def fail_after_health(*args):
            original(*args)
            if args[0] == 'acceptance':
                raise RuntimeError('fictional health failure')
        with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
            with patch.object(self.engine, '_health', side_effect=fail_after_health):
                self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 1)
            self.assertEqual(self.store.get_meta('acceptance_last_run'), saved)
            self.assertEqual(self.scheduler.acceptance_stamp, stamp)
            self.assertEqual(self.health()['state'], 'healthy')
            self.assertEqual(self.events(), [])
            self.clock.now += timedelta(minutes=1)
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 2)
        self.assertEqual(self.store.get_meta('acceptance_last_run'), self.clock().isoformat())
        self.assertEqual(self.health()['state'], 'unhealthy')
        self.assertEqual(len(self.events()), 1)

    def test_corrupt_health_episode_retries_next_tick_privately(self):
        secret = f'private pinned-orbit CVE-2099-0001 Zyphora 4.2.3 {self.pinned}'
        self.store.set_meta('health_episode:acceptance', secret)
        self.record('4.4.0')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
                patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 1)
            self.assertIsNone(self.store.get_meta('acceptance_last_run'))
            self.assertFalse(self.scheduler.acceptance_started)
            self.assertIsNone(self.scheduler.acceptance_stamp)
            self.clock.now += timedelta(minutes=1)
            self.scheduler.tick()
            self.assertEqual(evaluate.call_count, 2)
        self.assertEqual(len(self.lines), 2)
        self.assert_private_absent('\n'.join(self.lines) + output.getvalue())

    def test_sustained_regression_has_one_unhealthy_event(self):
        self.record('4.4.0')
        with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
            for hour in range(5):
                if hour:
                    self.clock.now += timedelta(hours=1)
                self.scheduler.tick()
                self.assertEqual(self.health()['state'], 'unhealthy')
            self.assertEqual(evaluate.call_count, 5)
        self.assertEqual([event['reason'] for event in self.events()], ['failed'])

    def test_not_before_baseline_or_when_disabled(self):
        self.store.connection.execute("DELETE FROM meta WHERE k='baseline_complete'")
        self.scheduler.tick()
        self.assertIsNone(self.health())
        self.assertIsNone(self.store.get_meta('acceptance_last_run'))
        self.store.set_meta('baseline_complete', '1')
        self.engine.config = replace(self.config, acceptance_list_path=None, acceptance_watchlist_path=None)
        self.scheduler.tick()
        self.assertIsNone(self.health())

    def test_exception_is_fixed_health_failure_and_cycle_continues(self):
        with patch('cornicen.acceptance.evaluate', side_effect=RuntimeError('Zyphora 4.2.3')):
            self.scheduler.tick()
        self.assertEqual(self.health()['detail'], 'Acceptance self-test failed')
        self.assertEqual(self.events()[0]['reason'], 'failed')
        self.assertEqual(len(self.lines), 1)

    def test_holds_survive_broken_files_and_preserve_only_held_records(self):
        self.scheduler.tick()
        self.record(old=True)
        self.record(cve='CVE-2099-0002', old=True)
        self.list.write_text('broken = [')
        self.scheduler.tick()
        self.assertEqual([row[0] for row in self.store.connection.execute('SELECT id FROM records')],
                         ['CVE-2099-0001'])
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_new_and_extended_holds_precede_pruning(self):
        self.engine.config = replace(self.config, acceptance_list_path=None, acceptance_watchlist_path=None)
        self.scheduler.tick()
        self.engine.config = self.config
        for cve in ('CVE-2099-0001', 'CVE-2099-0002'):
            with self.subTest(cve=cve):
                self.record(cve=cve, old=True)
                if cve.endswith('0002'):
                    self.list.write_text(self.list.read_text() +
                                         '\n[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n')
                self.scheduler.tick()
                self.assertIsNotNone(self.store.connection.execute('SELECT id FROM records WHERE id=?', (cve,)).fetchone())
                self.assertEqual(self.health()['state'], 'healthy')

    def test_missing_holds_refreshed_even_with_unchanged_stamps(self):
        self.scheduler.tick()
        self.store.connection.execute("DELETE FROM meta WHERE k='acceptance_holds'")
        self.record(old=True)
        self.scheduler.tick()
        self.assertIsNotNone(self.store.connection.execute('SELECT id FROM records').fetchone())
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_corrupt_holds_prune_normally_and_success_rewrites(self):
        self.scheduler.tick()
        for bad in ('not-json', '{}', '5', '[null]', '[5]', '[["CVE-2099-0002"]]',
                    '{"CVE-2099-0002":true}'):
            with self.subTest(bad=bad):
                self.store.set_meta('acceptance_holds', bad)
                self.record(cve='CVE-2099-0002', old=True)
                self.record(cve='5', old=True)
                self.scheduler.tick()
                self.assertEqual([row[0] for row in self.store.connection.execute('SELECT id FROM records')],
                                 ['CVE-2099-0001'])
                # Successful evaluation repairs bad metadata even without file edits.
                self.clock.now += timedelta(days=8)
                self.scheduler.tick()
                self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_valid_meta_array_protects_records_without_memory(self):
        self.store.set_meta('acceptance_holds', '["CVE-2099-0003"]')
        for cve in ('5', 'CVE-2099-0002', 'CVE-2099-0003'):
            self.record(cve=cve, old=True)
        self.store.prune_records(self.clock(), self.config.retention_days)
        self.assertEqual({row[0] for row in self.store.connection.execute('SELECT id FROM records')},
                         {'CVE-2099-0001', 'CVE-2099-0003'})

    def test_holds_saved_even_when_pinned_file_rejected(self):
        self.pinned.write_text('broken = [')
        self.scheduler.tick()
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0001'])

    def test_no_pairs_or_match_notifications_and_suppressions_ignored(self):
        self.pinned.write_text(self.watch_text + '\n[[accept]]\nanything = "ignored"\n')
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'healthy')
        self.assertEqual(self.engine.watches, ())
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM pairs').fetchone()[0], 0)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM outbox WHERE json_extract(body_json,'$.watch_id') IS NOT NULL").fetchone()[0], 0)

    def test_real_heartbeat_details_are_public(self):
        details = ['1 of 1 entries match',
                   '1 of 1 entries no longer match; 0 could not be checked',
                   '0 of 1 entries no longer match; 1 could not be checked',
                   'Acceptance list rejected']
        for index, expected in enumerate(details):
            if index == 1:
                self.record('4.4.0')
            elif index == 2:
                self.store.connection.execute('DELETE FROM records')
            elif index == 3:
                self.pinned.write_text('broken = [')
            self.changed()
            output = io.StringIO()
            self.scheduler.output = print
            with contextlib.redirect_stdout(output):
                self.scheduler.tick()
            line = output.getvalue().strip()
            heartbeat = json.loads(line)
            self.assertEqual(heartbeat['health_details']['acceptance'], expected)
            self.assertEqual(heartbeat['health_details_withheld'], 0)
            for private in ('pinned-orbit', 'CVE-2099-0001', 'Zyphora', '4.2.3'):
                self.assertNotIn(private, line)

    def test_engine_alias_map_is_used(self):
        path = self.root / 'aliases.toml'
        path.write_text('version="fictional"\n[[alias]]\nidentities=["zyphora:relay", "velindra:beacon"]\n')
        self.engine.aliases = AliasMap.load(False, path)
        self.pinned.write_text(self.watch_text.replace('zyphora:relay', 'velindra:beacon'))
        self.scheduler.tick()
        self.assertEqual(self.health()['state'], 'healthy')

    def test_missing_reason_outranks_regression(self):
        self.record('4.4.0')
        self.list.write_text(self.list.read_text() + '\n[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n')
        self.scheduler.tick()
        self.assertEqual(self.health()['detail'], '1 of 2 entries no longer match; 1 could not be checked')
        self.assertEqual(self.events()[0]['reason'], 'missing')

    def test_restart_with_reopened_store_preserves_last_run(self):
        self.scheduler.tick()
        saved = self.store.get_meta('acceptance_last_run')
        reopened = Store(str(self.db_path))
        self.addCleanup(reopened.connection.close)
        self.assertEqual(reopened.get_meta('acceptance_last_run'), saved)
        self.clock.now += timedelta(days=8)
        self.engine = Engine(reopened, (), self.engine.aliases, self.config, self.clock, self.notifier)
        self.scheduler = self.new_scheduler()
        self.scheduler.tick()
        self.assertEqual(reopened.get_meta('acceptance_last_run'), self.clock().isoformat())

    def test_inode_change_with_same_size_and_mtime_runs(self):
        self.scheduler.tick()
        previous = self.pinned.stat()
        replacement = self.root / 'replacement.toml'
        replacement.write_text(self.watch_text)
        os.utime(replacement, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        replacement.replace(self.pinned)
        with patch('cornicen.acceptance.evaluate', wraps=acceptance.evaluate) as evaluate:
            self.scheduler.tick()
        evaluate.assert_called_once()

    def test_holds_are_sorted_distinct_and_released_by_valid_list(self):
        self.list.write_text(self.list.read_text() +
                             '\n[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n' +
                             '\n[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0001"\n')
        self.scheduler.tick()
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')),
                         ['CVE-2099-0001', 'CVE-2099-0002'])
        self.list.write_text('[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n')
        self.scheduler.tick()
        self.assertEqual(json.loads(self.store.get_meta('acceptance_holds')), ['CVE-2099-0002'])

    def invoke(self, configured=True):
        config = self.root / 'cli.toml'
        text = f'db_path="{self.db_path}"\nwatchlist_path="{self.root / "absent-live.toml"}"\n'
        if configured:
            text += f'acceptance_list_path="{self.list}"\nacceptance_watchlist_path="{self.pinned}"\n'
        config.write_text(text)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--config', str(config), 'selftest'])
        return code, output.getvalue()

    def test_cli_exit_codes_output_and_no_writes(self):
        before = list(self.store.connection.iterdump())
        self.assertEqual(self.invoke(), (0, 'pinned-orbit CVE-2099-0001: pass\n1 of 1 entries match\n'))
        self.assertEqual(list(self.store.connection.iterdump()), before)
        self.record('4.4.0')
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn('regression (not_affected)', output)
        self.store.connection.execute('DELETE FROM records')
        self.assertEqual(self.invoke()[0], 3)
        self.assertIn('could not check', self.invoke()[1])
        self.assertEqual(self.invoke(configured=False)[0], 2)
        self.list.write_text('broken = [')
        self.assertEqual(self.invoke()[0], 2)

    def test_cli_database_bytes_mtime_and_read_only_open(self):
        # Include WAL bytes as committed writes may not touch the main DB yet.
        def snapshot():
            return {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in (self.db_path, Path(str(self.db_path) + '-wal')) if path.exists()}
        before = snapshot()
        with patch('cornicen.cli.Store', wraps=Store) as opened:
            self.assertEqual(self.invoke()[0], 0)
        opened.assert_called_once_with(str(self.db_path), read_only=True)
        self.assertEqual(snapshot(), before)
        # Negative control: a writable open and meta write violates both checks.
        def writable(path, **kwargs):
            store = Store(path, read_only=False)
            store.set_meta('fictional_write_probe', '1')
            return store
        with patch('cornicen.cli.Store', side_effect=writable) as opened:
            self.assertEqual(self.invoke()[0], 0)
        self.assertNotEqual(snapshot(), before)

    def test_cli_missing_outranks_regression(self):
        self.record('4.4.0')
        self.list.write_text(self.list.read_text() + '\n[[expect]]\nwatch_id="pinned-orbit"\ncve="CVE-2099-0002"\n')
        code, text = self.invoke()
        self.assertEqual(code, 3)
        self.assertIn('regression (not_affected)', text)
        self.assertIn('could not check', text)

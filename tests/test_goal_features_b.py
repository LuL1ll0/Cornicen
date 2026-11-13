# script-purpose: Verify local features, backup, operator reports and notification context.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_goal_features_b.py
"""Batch B contracts: fictional inventory, local files, and no network.

Reads local fixtures, writes temporary files; run with unittest.
Exit codes: 0 success, 1 failed assertions, 2 invalid arguments.
"""
import contextlib
from dataclasses import asdict
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sqlite3
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cornicen.applicability import Result, State
from cornicen.cli import main
from cornicen.engine import Engine
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier
from cornicen.outbox import Outbox
from cornicen.render import render
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text


CVE = 'CVE-2026-4321'


class LocalFeaturesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / 'state.db'
        self.config = self.root / 'config.toml'
        self.config.write_text(f'db_path="{self.db}"\nwatchlist_path="{self.root / "absent.toml"}"\n')
        self.network = patch('socket.create_connection', side_effect=AssertionError('network'))
        self.network_mock = self.network.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.network_mock.assert_not_called)

    def seed(self):
        store = Store(str(self.db))
        store.migrate()
        self.addCleanup(store.connection.close)
        return store

    def invoke(self, *args, store_type=Store):
        before = self.db.read_bytes() if self.db.exists() else None
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch('cornicen.cli.Store', wraps=store_type) as constructor, \
                patch('cornicen.cli.Engine', side_effect=AssertionError('Engine')) as engine, \
                patch('cornicen.cli._notifier', side_effect=AssertionError('notifier')) as notifier, \
                patch('cornicen.cli.Http', side_effect=AssertionError('HTTP')) as http, \
                patch.object(Store, 'migrate', side_effect=AssertionError('migrate')) as migrate:
            code = main(['--config', str(self.config), *args])
        for forbidden in (engine, notifier, http, migrate):
            forbidden.assert_not_called()
        for call in constructor.call_args_list:
            self.assertIs(call.kwargs.get('read_only'), True)
        self.assertEqual(self.db.read_bytes() if self.db.exists() else None, before)
        return code, output.getvalue()

    def test_f04_live_wal_exact_state_and_private_copy(self):
        store = self.seed()
        store.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        main_before = self.db.read_bytes()
        store.put_record(CVE, {'cveMetadata': {'cveId': CVE}}, '2026-11-04')
        store.connection.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                                 ('key', 'mist', CVE, 'new match', 1, '2026-11-04'))
        store.queue('mist|' + CVE, 'normal', ['new match'],
                    {'watch_id': 'mist', 'record_id': CVE}, '2026-11-04')
        store.set_meta('baseline_complete', '1')
        store.set_meta('record_baseline:' + CVE, '1')
        self.assertEqual(self.db.read_bytes(), main_before, 'fixture must be WAL-resident')
        self.assertGreater(Path(str(self.db) + '-wal').stat().st_size, 0)
        wal_before = Path(str(self.db) + '-wal').read_bytes()
        output = self.root / 'backup.db'
        code, text = self.invoke('db', 'backup', '--output', str(output))
        self.assertEqual(code, 0, text)
        self.assertIn('watch/config/alias files separately', text)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with contextlib.closing(sqlite3.connect(output)) as copied:
            self.assertEqual(copied.execute('PRAGMA quick_check').fetchall(), [('ok',)])
            tables = store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (table,) in tables:
                expected = [tuple(row) for row in store.connection.execute('SELECT * FROM ' + table)]
                self.assertEqual(copied.execute('SELECT * FROM ' + table).fetchall(), expected)
        self.assertEqual(Path(str(self.db) + '-wal').read_bytes(), wal_before)
        self.assertEqual(list(self.root.glob('*.staging')), [])

    def test_f04_refuses_existing_source_symlink_and_hardlink(self):
        self.seed()
        existing = self.root / 'existing'
        existing.write_bytes(b'keep')
        symlink = self.root / 'symlink'
        symlink.symlink_to(self.db.name)
        hardlink = self.root / 'hardlink'
        hardlink.hardlink_to(self.db)
        for path in (existing, self.db, symlink, hardlink):
            code, text = self.invoke('db', 'backup', '--output', str(path))
            self.assertEqual(code, 1)
            self.assertIn('backup destination not writable', text)
        self.assertEqual(existing.read_bytes(), b'keep')
        self.assertEqual(list(self.root.glob('*.staging')), [])

    def test_f04_injected_backup_failure_cleans_only_own_staging(self):
        self.seed()
        leftover = self.root / '.backup.db-old.staging'
        leftover.write_bytes(b'older invocation')
        output = self.root / 'backup.db'
        class FailingSource(Store):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                connection = self.connection
                self.connection = SimpleNamespace(
                    backup=lambda target: (_ for _ in ()).throw(sqlite3.DatabaseError('injected')),
                    close=connection.close)

        code, text = self.invoke('db', 'backup', '--output', str(output), store_type=FailingSource)
        self.assertEqual(code, 1)
        self.assertIn('backup destination not writable', text)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob('*.staging')), [leftover])
        self.assertEqual(leftover.read_bytes(), b'older invocation')

    def test_f04_failed_quick_check_does_not_publish(self):
        self.seed()
        original = sqlite3.connect

        class BadCopy(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql == 'PRAGMA quick_check':
                    return SimpleNamespace(fetchall=lambda: [('corrupt',)])
                return super().execute(sql, *args)

        def connect(*args, **kwargs):
            if args and str(args[0]).endswith('.staging'):
                kwargs['factory'] = BadCopy
            return original(*args, **kwargs)

        output = self.root / 'backup.db'
        with patch('cornicen.maintenance.sqlite3.connect', side_effect=connect):
            code, text = self.invoke('db', 'backup', '--output', str(output))
        self.assertEqual(code, 1)
        self.assertIn('backup destination not writable', text)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob('*.staging')), [])

    def test_f04_destination_race_never_overwrites(self):
        self.seed()
        output = self.root / 'backup.db'
        import os
        original = os.link

        def race(source, destination):
            output.write_bytes(b'concurrent backup')
            return original(source, destination)

        with patch('cornicen.maintenance.os.link', side_effect=race):
            code, text = self.invoke('db', 'backup', '--output', str(output))
        self.assertEqual(code, 1)
        self.assertIn('FileExistsError', text)
        self.assertEqual(output.read_bytes(), b'concurrent backup')
        self.assertEqual(list(self.root.glob('*.staging')), [])

    def test_f04_missing_database(self):
        output = self.root / 'backup.db'
        self.assertEqual(self.invoke('db', 'backup', '--output', str(output)),
                         (1, 'command failed: FileNotFoundError: database file not found\n'))
        self.assertFalse(output.exists())

    def report_fixture(self):
        store = self.seed()
        # Insert deliberately out of display order, including pairs omitted by policy.
        for watch, cve, state, baseline, exploited in (
                ('vapor', 'CVE-2026-1005', 'not_affected', 1, 1),
                ('mist', 'CVE-2026-1004', 'unknown', 0, 1),
                ('vapor', 'CVE-2026-1003', 'affected', 0, 0),
                ('mist', 'CVE-2026-1002', 'unknown', 1, 1),
                ('mist', 'CVE-2026-1001', 'affected', 1, 0),
                ('mist', 'CVE-2026-1006', 'unknown', 0, 0)):
            store.connection.execute('''INSERT INTO pairs(watch_id,record_id,state,episode,
                baseline,exploited,alias_map_version) VALUES (?,?,?,1,?,?,?)''',
                (watch, cve, state, baseline, exploited, 'fictional-1'))
        store.connection.execute('INSERT INTO dead_letters VALUES (?,?,?,?,?,?)',
                                 ('cvelist', 'CVE-2026-1007', 3, '2026-11-04', 'error', 'v1'))

    def expected_report(self):
        labels = ('Baseline: affected', 'Baseline: exploited (unknown version)', 'Open matches',
                  'Not affected (recorded, no alert)', 'Dead letters')
        groups = ('baseline-affected', 'baseline-exploited', 'open', 'open', 'not-affected', 'dead-letters')
        rows = [dict(watch_id=watch, record_id='CVE-2026-' + cve, state=state,
                     alias_map_version='fictional-1') for watch, cve, state in (
            ('mist', '1001', 'affected'), ('mist', '1002', 'unknown'),
            ('mist', '1004', 'unknown'), ('vapor', '1003', 'affected'),
            ('vapor', '1005', 'not_affected'))]
        rows.append(dict(source='cvelist', record_id='CVE-2026-1007', attempts=3))
        return labels, groups, rows

    def test_f05_default_text_exact_compatibility(self):
        self.report_fixture()
        labels, _, rows = self.expected_report()
        expected = 'Summary: ' + '; '.join(f'{label}: {count}' for label, count in
                                          zip(labels, (1, 1, 2, 1, 1))) + '\n'
        for label, items in zip(labels, ([rows[0]], [rows[1]], rows[2:4], [rows[4]], [rows[5]])):
            expected += label + ':\n' + ''.join(json.dumps(row, sort_keys=True) + '\n' for row in items)
        self.assertEqual(self.invoke('report'), (0, expected))

    def test_f05_jsonl_exact_objects_disjoint_and_stable(self):
        self.report_fixture()
        _, groups, rows = self.expected_report()
        expected = [dict(row, schema_version=1, group=group) for row, group in zip(rows, groups)]
        code, text = self.invoke('report', '--format', 'jsonl')
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(line) for line in text.splitlines()], expected)
        self.assertEqual(len({(row['watch_id'], row['record_id']) for row in expected[:-1]}), 5)
        self.assertEqual(self.invoke('report', '--format', 'jsonl'), (0, text))

    def test_f05_repeatable_group_watch_intersections_and_text_counts(self):
        self.report_fixture()
        flags = ('--watch', 'mist', '--watch', 'vapor', '--group', 'open',
                 '--group', 'not-affected', '--group', 'dead-letters')
        code, text = self.invoke('report', *flags, '--format', 'jsonl')
        self.assertEqual(code, 0)
        _, _, rows = self.expected_report()
        expected = [dict(row, schema_version=1, group=group)
                    for row, group in zip(rows[2:5], ('open', 'open', 'not-affected'))]
        self.assertEqual([json.loads(line) for line in text.splitlines()], expected)
        code, text = self.invoke('report', *flags)
        self.assertEqual(code, 0)
        self.assertEqual(text.splitlines()[0],
                         'Summary: Open matches: 2; Not affected (recorded, no alert): 1')
        self.assertNotIn('Dead letters', text)
        code, text = self.invoke('report', '--watch', 'mist', '--group', 'open', '--format', 'jsonl')
        self.assertEqual([json.loads(line) for line in text.splitlines()], expected[:1])

    def test_f05_empty_quoted_watch_and_missing_database(self):
        self.assertEqual(self.invoke('report', '--format', 'jsonl')[0], 1)
        self.report_fixture()
        for watch in ('absent', "mist' OR 1=1 --"):
            self.assertEqual(self.invoke('report', '--watch', watch, '--format', 'jsonl'), (0, ''))
        self.assertEqual(self.invoke('report', '--watch', 'mist', '--group', 'dead-letters',
                                     '--format', 'jsonl'), (0, ''))

    def test_f05_invalid_group_argument(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(['report', '--group', 'invalid'])
        self.assertEqual(raised.exception.code, 2)

    def test_f15_relations_without_config_or_database(self):
        with patch('cornicen.cli.load_config', side_effect=AssertionError('config read')) as config, \
                patch('pathlib.Path.read_text', side_effect=AssertionError('file read')) as read:
            for left, right, scheme, expected, code in (
                    ('3.14.0rc1', '3.14.0', 'python', 'less', 0),
                    ('1.2', '1.2.0', 'dotted', 'unknown', 1),
                    ('2.4-2', '2.4-1', 'debian', 'greater', 0),
                    ('  Mist   Build A ', 'mist build a', 'opaque', 'equal', 0),
                    ('mist-a', 'mist-b', 'opaque', 'unknown', 1),
                    ('2.4.0', '2.4.0+mist', 'semver', 'equal', 0),
                    ('bad', '2.4.0', 'semver', 'unknown', 1)):
                self.assertEqual(self.invoke('version', 'compare', left, right, '--scheme', scheme),
                                 (code, expected + '\n'))
            config.assert_not_called()
            read.assert_not_called()
        self.assertFalse(self.db.exists())

    def test_f15_argument_errors(self):
        for args in (('version', 'compare', '1', '2'),
                     ('version', 'compare', '1', '2', '--scheme', 'invalid')):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(list(args))
            self.assertEqual(raised.exception.code, 2)


class AlertContextTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.watch = load_watchlist_text('[[watch]]\nid="mist"\nname="Mistbox"\n'
            'match=["cloudforge:mistbox"]\nversion="2.4.0"\nscheme="semver"\n')[0]
        # Exercise body construction without running ingestion or changing resolver behavior.
        self.engine = Engine.__new__(Engine)
        self.engine.store = self.store
        self.engine.db = self.store.connection
        self.engine.config = SimpleNamespace(epss_threshold=.1)
        self.result = Result(State.AFFECTED, False, 'CNA affected mistbox', 'high')

    def body(self, title=None, metrics=None, adp=None):
        cna = {'title': title}
        if metrics is not None:
            cna['metrics'] = metrics
        record = {'cveMetadata': {'cveId': CVE}, 'containers': {'cna': cna, 'adp': adp or []}}
        self.store.put_record(CVE, record, '2026-11-04')
        return self.engine._body(self.watch, CVE, self.result)

    def notification(self, body, urgency='normal'):
        return Notification('key', 'mist', CVE, ('new match',), urgency, body)

    def test_f09_cna_only_highest_numeric_score_and_zero_vs_missing(self):
        adp = [{'metrics': [{'cvssV4_0': {'baseScore': 10.0}}]}]
        body = self.body('Mistbox parser issue', [
            {'cvssV3_1': {'baseScore': 4.2}}, {'cvssV4_0': {'baseScore': 8.1}},
            {'cvssV3_0': {'baseScore': '9.9'}}, {'cvssV2_0': {'baseScore': True}}], adp)
        self.assertEqual((body['cve_title'], body['cna_cvss_score'], body['severity']),
                         ('Mistbox parser issue', 8.1, 8.1))
        self.assertIn('CNA CVSS score: 8.1', render(self.notification(body))[1])
        missing = self.body(adp=adp)
        zero = self.body(metrics=[{'cvssV3_1': {'baseScore': 0.0}}], adp=adp)
        self.assertIsNone(missing['cna_cvss_score'])
        self.assertEqual(missing['severity'], 0)
        self.assertEqual(zero['cna_cvss_score'], 0.0)
        self.assertIn('CNA CVSS score: unknown', render(self.notification(missing))[1])
        self.assertIn('CNA CVSS score: 0.0', render(self.notification(zero))[1])

    def test_f09_title_controls_length_and_malformed_values(self):
        body = self.body('Mist\r\nbox\tparser\x00\x1b\u202e\u2028' + 'x' * 200)
        text = render(self.notification(body))[1]
        line = next(line for line in text.splitlines() if line.startswith('CVE title: '))
        title = line.removeprefix('CVE title: ')
        self.assertEqual(len(title), 160)
        self.assertTrue(title.startswith('Mist box parser '))
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\u202e', text)
        for bad in (None, [], {}, 12, ''):
            self.assertIn('CVE title: unknown', render(self.notification(self.body(bad)))[1])

    def test_f09_old_payload_existing_field_order_urgency_and_eol(self):
        old = {'name': 'Mistbox', 'product': 'mistbox', 'version': '2.4.0',
               'state': 'affected', 'eol': True, 'evidence': 'CNA affected mistbox'}
        title, text, priority, tags = render(self.notification(old, 'urgent'))
        self.assertTrue(title.startswith('🚨 Cornicen: '))
        self.assertEqual(priority, 5)
        self.assertEqual(tags, ['rotating_light'])
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith('EOL: unsupported'))
        self.assertEqual(lines[1:], [
            'Why: new match', 'KEV: not listed', 'SSVC: not assessed', 'EPSS: not yet scored',
            'Match: CNA affected mistbox — affected',
            'https://www.cve.org/CVERecord?id=' + CVE,
            'CVE title: unknown', 'CNA CVSS score: unknown'])
        self.assertEqual(render(self.notification(old))[2:], (3, ['information_source']))

    def test_f09_standalone_digest_and_local_file_delivery(self):
        first = Notification('first', 'mist', 'CVE-2099-4321', ('new match',), 'normal',
                             {'name': 'Mistbox', 'product': 'mistbox', 'version': '73.8.91',
                              'cve_title': 'Mistbox issue', 'cna_cvss_score': 7.5})
        second = Notification('second', 'mist', 'CVE-2099-4322', ('new match',), 'urgent',
                              dict(first.body))
        digest = Notification('digest', '', 'digest', (), 'normal',
                              {'items': [asdict(first), asdict(second)]})
        title, text, priority, tags = render(digest)
        self.assertEqual(title, 'Cornicen digest: 2 items')
        self.assertEqual((priority, tags), (3, ['information_source']))
        expected = ('2 items on 1 watches: 2 new matches\n\n'
                    'Mistbox (mistbox 73.8.91): 2 items\n'
                    + '\n'.join(render(item)[0] + '\n' + render(item)[1] for item in (first, second)))
        self.assertEqual(text, expected)
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'notifications.jsonl'
            self.assertTrue(FileNotifier(path).send(digest))
            saved = json.loads(path.read_text())
            self.assertEqual(render(Notification(**saved)), render(digest))

    def test_f09_digest_ranking_and_urgency_stay_unchanged(self):
        clock = lambda: datetime(2026, 11, 4, tzinfo=timezone.utc)
        for index, score, probability in ((1, 2.1, .09), (2, 9.8, .01), (3, None, .05)):
            metrics = [{'cvssV3_1': {'baseScore': score}}] if score is not None else []
            body = self.body('Mistbox issue ' + str(index), metrics)
            body['record_id'] = 'CVE-2026-100' + str(index)
            body['epss'] = {'score': probability, 'pct': .5, 'date': '2026-11-04'}
            self.assertFalse(self.engine._urgent(body, ['new match']))
            self.store.queue(str(index), 'normal', ['new match'], body, clock().isoformat())
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'notifications.jsonl'
            self.assertEqual(Outbox(self.store, FileNotifier(path), clock).flush(), 1)
            delivered = json.loads(path.read_text())
        items = delivered['body']['items']
        self.assertEqual([item['record_id'] for item in items],
                         ['CVE-2026-1002', 'CVE-2026-1001', 'CVE-2026-1003'])
        self.assertEqual([item['body']['cna_cvss_score'] for item in items], [9.8, 2.1, None])
        self.assertEqual(render(Notification(**delivered))[2:], (3, ['information_source']))

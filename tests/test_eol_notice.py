import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen.cli import main
from cornicen.store import Store


NOTICE = ('coverage limited: the vendor issues no advisories for unsupported versions; '
          'absence of alerts is not evidence of safety')


class EolNoticeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db = self.root / 'test.db'
        self.watch = self.root / 'watch.toml'
        self.config = self.root / 'config.toml'
        self.config.write_text(f'db_path = "{self.db}"\nwatchlist_path = "{self.watch}"\n')
        self.write_watches(True)
        store = Store(str(self.db))
        store.migrate()
        store.connection.close()

    def write_watches(self, eol):
        self.watch.write_text(f'''[[watch]]
id = "old-example"
name = "Example Widget"
match = ["example-vendor:example-widget"]
version = "1.2.3"
scheme = "semver"
eol = {str(eol).lower()}
[[watch]]
id = "current-example"
name = "Example Gadget"
match = ["example-vendor:example-gadget"]
version = "4.5.6"
scheme = "semver"
eol = false
''')

    def invoke_streams(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(['--config', str(self.config), *args])
        return code, output.getvalue(), errors.getvalue()

    def invoke(self, *args):
        code, text, _ = self.invoke_streams(*args)
        return code, text

    def assert_notice(self, text):
        self.assertIn('old-example: ' + NOTICE, text.splitlines())
        self.assertNotIn('current-example: ' + NOTICE, text.splitlines())
        self.assertEqual(text.count(NOTICE), 1)

    def test_eol_notice_status(self):
        code, text = self.invoke('status')
        self.assertEqual(code, 0)
        self.assert_notice(text)

    def test_eol_notice_report(self):
        code, text = self.invoke('report')
        self.assertEqual(code, 0)
        self.assert_notice(text)
        self.assertNotIn(NOTICE, self.invoke('report', '--watch', 'current-example')[1])
        self.assert_notice(self.invoke('report', '--watch', 'old-example', '--group', 'open')[1])

    def test_eol_notice_watch_check(self):
        code, text = self.invoke('watch', 'check')
        self.assertEqual(code, 0)
        self.assert_notice(text)

    def test_eol_no_health_change(self):
        for unhealthy in (False, True):
            with self.subTest(unhealthy=unhealthy):
                if unhealthy:
                    store = Store(str(self.db))
                    store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                                             ('watchlist', 'unhealthy', '2026-11-04T00:00:00+00:00',
                                              'Example reload rejected'))
                    store.connection.close()
                self.write_watches(True)
                eol_code, eol_text = self.invoke('status')
                json_code, eol_json = self.invoke('status', '--json')
                health = self.invoke('healthcheck')
                self.write_watches(False)
                plain_code, plain_text = self.invoke('status')
                plain_json_code, plain_json = self.invoke('status', '--json')
                self.assertEqual(eol_code, plain_code)
                self.assertEqual(eol_code, 0)
                self.assertEqual(eol_text.replace('old-example: ' + NOTICE + '\n', ''), plain_text)
                result = json.loads(eol_json)
                self.assertEqual(result.pop('eol_coverage_limited'), ['old-example'])
                self.assertEqual(result, json.loads(plain_json))
                self.assertEqual(json_code, plain_json_code)
                self.assertEqual(self.invoke('healthcheck'), health)
                self.assertEqual(health, (1, 'unhealthy\n') if unhealthy else (0, 'healthy\n'))

    def test_eol_notice_json(self):
        code, text = self.invoke('status', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['eol_coverage_limited'], ['old-example'])
        self.write_watches(False)
        self.assertNotIn('eol_coverage_limited', json.loads(self.invoke('status', '--json')[1]))
        self.assertEqual(self.invoke('report', '--format', 'jsonl'), (0, ''))

    def test_eol_notice_status_without_database(self):
        self.config.write_text(f'db_path = "{self.root / "missing.db"}"\n'
                               f'watchlist_path = "{self.watch}"\n')
        code, text = self.invoke('status')
        self.assertEqual(code, 1)
        self.assert_notice(text)
        code, text = self.invoke('status', '--json')
        self.assertEqual(code, 1)
        result = json.loads(text)
        self.assertEqual(result['eol_coverage_limited'], ['old-example'])
        self.assertFalse(result['available'])
        self.assertFalse(result['container_healthy'])

    def test_jsonl_rows_unchanged_and_notice_on_stderr(self):
        store = Store(str(self.db))
        store.connection.execute(
            'INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited,alias_map_version) '
            'VALUES (?,?,?,?,?,?,?)',
            ('old-example', 'fictional-record', 'affected', 1, 0, 0, 'fixture-map'))
        store.connection.close()
        args = ('report', '--format', 'jsonl', '--watch', 'old-example', '--group', 'open')
        actual = self.invoke_streams(*args)
        self.write_watches(False)
        plain = self.invoke_streams(*args)
        self.assertEqual(actual[:2], plain[:2])
        self.assertEqual(actual[0], 0)
        self.assertEqual(json.loads(actual[1]), dict(
            schema_version=1, group='open', watch_id='old-example',
            record_id='fictional-record', state='affected', alias_map_version='fixture-map', accepted=None))
        self.assertEqual(actual[2], 'old-example: ' + NOTICE + '\n')
        self.assertEqual(plain[2], '')

    def test_jsonl_empty_stdout_and_filtered_stderr(self):
        for filters, notice in (((), True), (('--watch', 'old-example', '--group', 'open'), True),
                                (('--watch', 'current-example'), False)):
            with self.subTest(filters=filters):
                self.assertEqual(self.invoke_streams('report', '--format', 'jsonl', *filters),
                                 (0, '', 'old-example: ' + NOTICE + '\n' if notice else ''))

    def test_unloadable_watch_file_preserves_outputs(self):
        missing = self.root / 'missing.toml'
        invalid = self.root / 'invalid.toml'
        invalid.write_text(self.watch.read_text() + '\n[[watch]]\neol = "invalid"\n')
        for watch in (missing, invalid):
            self.config.write_text(f'db_path = "{self.db}"\nwatchlist_path = "{watch}"\n')
            for args in (('status',), ('status', '--json'), ('report',),
                         ('report', '--format', 'jsonl'), ('watch', 'check')):
                with self.subTest(watch=watch.name, args=args):
                    with patch('cornicen.cli._eol_ids', return_value=[]):
                        baseline = self.invoke_streams(*args)
                    actual = self.invoke_streams(*args)
                    self.assertEqual(actual, baseline)
                    self.assertEqual(actual[0], 1 if args[0] == 'watch' else 0)
                    self.assertNotIn(NOTICE, actual[1] + actual[2])
                    self.assertNotIn('eol_coverage_limited', actual[1])

    def test_watch_check_candidate_coverage(self):
        candidate = self.root / 'candidate.toml'
        for configured_eol, candidate_eol in ((True, False), (False, True), (True, True)):
            self.write_watches(candidate_eol)
            candidate.write_text(self.watch.read_text().replace('old-example', 'candidate-example'))
            self.write_watches(configured_eol)
            with self.subTest(configured=configured_eol, candidate=candidate_eol):
                code, text, errors = self.invoke_streams('watch', 'check', '--file', str(candidate))
                self.assertEqual(code, 0)
                self.assertEqual(errors, '')
                self.assertNotIn('old-example: ' + NOTICE, text)
                self.assertEqual(text.count(NOTICE), int(candidate_eol))
                if candidate_eol:
                    self.assertIn('candidate-example: ' + NOTICE, text.splitlines())

    def test_database_failures_keep_notice_and_exit_one(self):
        missing = self.root / 'missing.db'
        corrupt = self.root / 'corrupt.db'
        corrupt.write_bytes(b'not a sqlite database')
        candidate = self.root / 'candidate.toml'
        candidate.write_text(self.watch.read_text().replace('old-example', 'candidate-example'))
        for db in (missing, corrupt):
            self.config.write_text(f'db_path = "{db}"\nwatchlist_path = "{self.watch}"\n')
            for args in (('status',), ('report',), ('report', '--format', 'jsonl'),
                         ('report', '--watch', 'old-example'),
                         ('report', '--watch', 'current-example'), ('watch', 'check'),
                         ('watch', 'check', '--file', str(candidate))):
                with self.subTest(db=db.name, args=args):
                    code, text, errors = self.invoke_streams(*args)
                    if db == missing and args[0] == 'watch':
                        # watch check runs without a database (exit 0, as before the flag existed).
                        watch_id = 'candidate-example' if '--file' in args else 'old-example'
                        self.assertEqual(code, 0)
                        self.assertIn(watch_id + ': ' + NOTICE + '\n', text)
                        self.assertEqual(errors, '')
                        continue
                    self.assertEqual(code, 1)
                    error = ('unhealthy: database unavailable' if db == missing else
                             'command failed: DatabaseError: file is not a database')
                    filtered = 'current-example' in args
                    watch_id = 'candidate-example' if '--file' in args else 'old-example'
                    notice = '' if filtered else watch_id + ': ' + NOTICE + '\n'
                    self.assertEqual(text, error + '\n' + ('' if 'jsonl' in args else notice))
                    self.assertEqual(errors, notice if 'jsonl' in args else '')

    def test_diagnostics_create_no_events_outbox_or_notifications(self):
        store = Store(str(self.db))
        self.addCleanup(store.connection.close)
        before = list(store.connection.iterdump())
        with patch('cornicen.cli._notifier') as notifier, \
                patch('cornicen.notify.file.FileNotifier.send') as file_send, \
                patch('cornicen.notify.ntfy.NtfyNotifier.send') as ntfy_send:
            for args in (('status',), ('status', '--json'), ('report',),
                         ('report', '--format', 'jsonl'), ('watch', 'check')):
                with self.subTest(args=args):
                    code, text, errors = self.invoke_streams(*args)
                    self.assertEqual(code, 0)
                    self.assertTrue(NOTICE in text + errors or 'eol_coverage_limited' in text)
                    self.assertEqual(list(store.connection.iterdump()), before)
                    for table in ('events', 'outbox'):
                        self.assertEqual(store.connection.execute(
                            f'SELECT count(*) FROM {table}').fetchone()[0], 0)
                    for guard in (notifier, file_send, ntfy_send):
                        guard.assert_not_called()

    def test_notice_printed_once_when_a_query_fails_after_it(self):
        empty = self.root / 'empty.db'
        empty.write_bytes(b'')
        self.config.write_text(f'db_path = "{empty}"\nwatchlist_path = "{self.watch}"\n')
        line = 'old-example: ' + NOTICE + '\n'
        for args in (('report',), ('report', '--format', 'jsonl')):
            with self.subTest(args=args):
                code, text, errors = self.invoke_streams(*args)
                self.assertEqual(code, 1)
                self.assertEqual((text + errors).count(line), 1)

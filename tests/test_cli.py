import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen.cli import main
from cornicen.config import load_config
from cornicen.store import Store


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db = self.root / 'test.db'
        self.watch = self.root / 'watch.toml'
        self.watch.write_text('''[[watch]]
id = "one"
name = "Proxy"
match = ["nginx:nginx"]
version = "1.0.0"
scheme = "semver"
[[watch]]
id = "two"
name = "Proxy two"
match = ["f5:nginx"]
version = "1.0.0"
scheme = "semver"
''')
        self.config = self.root / 'config.toml'
        self.config.write_text(f'db_path = "{self.db}"\nwatchlist_path = "{self.watch}"\n')
        store = Store(str(self.db))
        store.migrate()
        store.connection.close()

    def invoke(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--config', str(self.config), *args])
        return code, output.getvalue()

    def test_cli_watch_check_reports_collision(self):
        code, text = self.invoke('watch', 'check')
        self.assertEqual(code, 0)
        self.assertIn('collision: one and two claim', text)
        self.assertIn('one: matched', text)
        self.assertIn('near misses', text)

    def test_healthcheck_exit_codes(self):
        self.assertEqual(self.invoke('healthcheck')[0], 0)
        store = Store(str(self.db))
        store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                                 ('watchlist', 'unhealthy', datetime.now(timezone.utc).isoformat(),
                                  'Reload rejected'))
        store.connection.close()
        self.assertEqual(self.invoke('healthcheck')[0], 1)

    def test_missing_database_is_unhealthy(self):
        self.config.write_text(f'db_path = "{self.root / "missing.db"}"\n')
        self.assertEqual(self.invoke('healthcheck')[0], 1)
        self.assertFalse((self.root / 'missing.db').exists())

    def test_replay_reports_each_expected_cve(self):
        acceptance = self.root / 'acceptance.toml'
        acceptance.write_text('[[expect]]\nwatch_id = "one"\ncve = "CVE-2026-1234"\n')
        code, text = self.invoke('replay', '--list', str(acceptance))
        self.assertEqual(code, 1)
        self.assertIn('one CVE-2026-1234: not matched', text)

    def test_stored_matches_near_misses_and_positive_replay(self):
        store = Store(str(self.db))
        now = datetime.now(timezone.utc).isoformat()
        for cve, version in [('CVE-2026-1234', '1.0.0'), ('CVE-2026-5678', '2.0.0')]:
            store.put_record(cve, {
                'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED', 'datePublished': now},
                'containers': {'cna': {'affected': [{
                    'vendor': 'nginx', 'product': 'nginx',
                    'defaultStatus': 'unaffected',
                    'versions': [{'version': version, 'status': 'affected'}]
                }]}}
            }, now)
        store.connection.close()
        code, text = self.invoke('watch', 'check')
        self.assertEqual(code, 0)
        self.assertIn('one: matched CVE-2026-1234; near misses CVE-2026-5678', text)
        self.assertIn('two: matched CVE-2026-1234; near misses CVE-2026-5678', text)
        acceptance = self.root / 'acceptance.toml'
        acceptance.write_text('[[expect]]\nwatch_id = "one"\ncve = "CVE-2026-1234"\n')
        self.assertEqual(self.invoke('replay', '--list', str(acceptance)),
                         (0, 'one CVE-2026-1234: matched\n'))

    def test_report_groups_and_counts_without_duplicate_pairs(self):
        store = Store(str(self.db))
        cases = [
            ('baseline-affected', 'affected', 1, 0),
            ('baseline-exploited', 'unknown', 1, 1),
            ('baseline-unaffected', 'not_affected', 1, 1),
            ('baseline-unknown', 'unknown', 1, 0),
            ('open-affected', 'affected', 0, 0),
            ('open-exploited', 'unknown', 0, 1),
            ('unaffected', 'not_affected', 0, 0),
            ('unknown', 'unknown', 0, 0),
        ]
        for record, state, baseline, exploited in cases:
            store.connection.execute(
                'INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited,alias_map_version) '
                'VALUES (?,?,?,?,?,?,?)', ('one', record, state, 1, baseline, exploited, 'fixture-map'))
        store.connection.execute(
            'INSERT INTO dead_letters VALUES (?,?,?,?,?,?)',
            ('cvelist', 'dead-record', 5, '2026-11-04T07:00Z', 'fixture failure', 'fixture-version'))
        store.connection.close()
        code, text = self.invoke('report')
        self.assertEqual(code, 0)
        expected = {
            'Baseline: affected': ['baseline-affected'],
            'Baseline: exploited (unknown version)': ['baseline-exploited'],
            'Open matches': ['open-affected', 'open-exploited'],
            'Not affected (recorded, no alert)': ['baseline-unaffected', 'unaffected'],
            'Dead letters': ['dead-record'],
        }
        lines = text.splitlines()
        self.assertEqual(lines[0], 'Summary: ' + '; '.join(
            f'{label}: {len(records)}' for label, records in expected.items()))
        groups = {}
        for line in lines[1:]:
            if line.endswith(':'):
                label = line[:-1]
                groups[label] = []
            else:
                item = json.loads(line)
                groups[label].append(item['record_id'])
                if label != 'Dead letters':
                    self.assertEqual(item['alias_map_version'], 'fixture-map')
        self.assertEqual(groups, expected)

    def test_file_notifier_config_selection(self):
        path = self.root / 'notifications.jsonl'
        with self.config.open('a') as target:
            target.write(f'notifier = "file"\nnotification_path = "{path}"\n')
        self.assertEqual(self.invoke('notify', 'test'), (0, 'delivered\n'))
        self.assertIn('notification test', path.read_text())

    def test_run_passes_configured_budgets_to_all_sources(self):
        with self.config.open('a') as target:
            for name, max_bytes, seconds in (
                ('cvelist_snapshot', 10000, 100), ('cvelist_delta', 2000, 20),
                ('kev', 3000, 30), ('epss', 4000, 40),
            ):
                target.write(f'[download_budgets.{name}]\n'
                             f'max_bytes = {max_bytes}\ndeadline_seconds = {seconds}\n')
        expected = load_config(self.config, {}).download_budgets
        with patch('cornicen.cli.Scheduler') as scheduler:
            scheduler.return_value.run.return_value = 0
            self.assertEqual(self.invoke('run')[0], 0)
        sources = scheduler.call_args.args[1]
        self.assertEqual(set(sources), {'cvelist', 'kev', 'epss'})
        for source in sources.values():
            self.assertEqual(source.http.download_budgets, expected)

"""Heartbeat schema, private aggregate counts, and stored GitHub metadata."""

from argparse import Namespace
from contextlib import ExitStack, redirect_stdout
from datetime import timedelta
import builtins
import io
import json
import re
from pathlib import Path
import unittest
from unittest.mock import patch

from cornicen import __version__, cli
from cornicen.counts import COUNT_QUERIES, report_counts
from cornicen.github import github_status
from tests.frozen_v018_scheduler import Scheduler as V018Scheduler
from cornicen.watchlist import load_document
from tests import test_scheduler as helpers


class HeartbeatCountsTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp

    def populate(self):
        # A distinctive fictional inventory, including active, lapsed and exploited accepts.
        self.path.write_text(self.text.replace('private-inventory', 'quartz-watch-77391')
                             .replace('Private product name', 'Quartz Fiction Appliance 77391')
                             .replace('examplecorp:example', 'quartzfiction:prism77391') + '''
[[accept]]
watch = "quartz-watch-77391"
cve = "CVE-2098-77391001"
reason = "Fictional module disabled"
until = 2099-01-01
[[accept]]
watch = "quartz-watch-77391"
cve = "CVE-2098-77391002"
reason = "Fictional expired decision"
until = 2020-01-01
[[accept]]
watch = "quartz-watch-77391"
cve = "CVE-2098-77391003"
reason = "Exploitation still alerts"
until = 2099-01-01
[[accept]]
watch = "quartz-watch-77391"
cve = "CVE-2098-77391008"
reason = "Fictional open accept"
until = 2099-01-01
''')
        self.engine.watches, self.engine.accepts = load_document(self.path)
        self.scheduler.watch_stamp = self.scheduler._stamp()
        rows = [('affected', 1, 0), ('affected', 1, 0), ('unknown', 1, 1),
                ('affected', 0, 0), ('unknown', 0, 1), ('not_affected', 0, 0),
                ('affected', 1, 0), ('affected', 0, 0)]
        with self.store.transaction():
            for i, (state, baseline, exploited) in enumerate(rows, 1):
                self.store.connection.execute(
                    'INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited) '
                    'VALUES(?,?,?,1,?,?)',
                    ('quartz-watch-77391', f'CVE-2098-7739100{i}', state, baseline, exploited))
                self.store.connection.execute(
                    'INSERT INTO records(id,json,ingested_at) VALUES(?,?,?)',
                    (f'CVE-2098-7739100{i}', json.dumps({
                        'cveMetadata': {'cveId': f'CVE-2098-7739100{i}', 'state': 'PUBLISHED'},
                        'containers': {'cna': {'affected': []}}}), self.clock().isoformat()))
            self.store.connection.execute(
                'INSERT INTO dead_letters VALUES(?,?,?,?,?,?)',
                ('cvelist', 'CVE-2098-77391999', 5, '2099-01-01T00:00:00+00:00',
                 'fictional error', __version__))

    def heartbeat(self):
        self.clock.now += timedelta(minutes=1)
        self.scheduler.tick()
        return json.loads(self.lines[-1])

    def assert_schema(self, value):
        expected = {
            'time': None,
            'health_details_withheld': None,
            'sources': dict.fromkeys(('cvelist', 'kev', 'epss', 'watchlist')),
            'health_details': dict.fromkeys(('cvelist', 'kev', 'epss', 'watchlist')),
            'ingested': dict.fromkeys(('cvelist', 'kev', 'epss')),
            'events': None, 'sent': None, 'pending': None,
            'report': dict.fromkeys(('affected', 'exploited_unknown', 'open', 'dead_letters', 'accepted')),
            'github': dict.fromkeys(('auth', 'limit', 'remaining', 'reset', 'observed_at')),
        }

        def paths(obj, prefix=''):
            result = set()
            for key, item in obj.items():
                path = prefix + key
                result.add(path)
                if isinstance(item, dict):
                    result.update(paths(item, path + '.'))
            return result

        self.assertEqual(paths(value), paths(expected))
        self.assertIsInstance(value['time'], str)
        for key in ('sources', 'health_details'):
            for item in value[key].values():
                self.assertIsInstance(item, str)
        for key in ('events', 'sent', 'pending', 'health_details_withheld'):
            self.assertIs(type(value[key]), int)
        for item in value['ingested'].values():
            self.assertIs(type(item), int)
        for item in value['report'].values():
            self.assertTrue(item is None or type(item) is int)
        self.assertIn(value['github']['auth'],
                      ('token', 'none', 'token-rejected', 'token-unusable', 'unknown'))
        for key in ('limit', 'remaining', 'reset', 'observed_at'):
            item = value['github'][key]
            self.assertTrue(item is None or type(item) is int)

    def test_h1_exact_recursive_keys_and_types_empty_and_populated(self):
        self.scheduler.tick()
        self.assert_schema(json.loads(self.lines[-1]))
        self.assertEqual(json.loads(self.lines[-1])['report'],
                         dict(affected=0, exploited_unknown=0, open=0, dead_letters=0, accepted=0))
        self.populate()
        self.assert_schema(self.heartbeat())

    def test_h2_counts_equal_unfiltered_text_report(self):
        self.scheduler.tick()
        self.populate()
        # All five totals differ, so exchanging any two fields fails this test.
        extra = [('unknown', 1, 1)] * 2 + [('affected', 0, 0)] * 5
        with self.store.transaction():
            for i, (state, baseline, exploited) in enumerate(extra, 20):
                self.store.connection.execute(
                    'INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited) '
                    'VALUES(?,?,?,1,?,?)',
                    ('quartz-watch-77391', f'CVE-2098-77391{i:03}', state, baseline, exploited))
        for i in range(22, 25):
            with self.path.open('a') as stream:
                stream.write(f'\n[[accept]]\nwatch="quartz-watch-77391"\ncve="CVE-2098-77391{i:03}"'
                             '\nreason="Fictional decision"\nuntil=2099-01-01\n')
        self.engine.watches, self.engine.accepts = load_document(self.path)
        self.scheduler.watch_stamp = self.scheduler._stamp()
        heartbeat = self.heartbeat()
        output = io.StringIO()
        with redirect_stdout(output):
            cli.report(self.store, Namespace(group=None, watch=None, format='text'),
                       config=self.engine.config, now=self.clock())
        summary = output.getvalue().splitlines()[0]
        labels = dict(affected='Baseline: affected',
                      exploited_unknown='Baseline: exploited (unknown version)',
                      open='Open matches', dead_letters='Dead letters',
                      accepted='Accepted (not alerting)')
        parsed = {key: int(re.search(re.escape(label) + r': (\d+)', summary)[1])
                  for key, label in labels.items()}
        self.assertEqual(parsed, dict(affected=2, exploited_unknown=3, open=4,
                                     dead_letters=1, accepted=5))
        self.assertEqual(heartbeat['report'], parsed)

    def scope_states(self):
        yield 'empty'
        self.populate()
        with self.store.transaction():
            self.store.connection.execute('DELETE FROM dead_letters')
        # Include product_only inventory as well as vendor/product identities.
        self.path.write_text(self.path.read_text().replace(
            'match = ["quartzfiction:prism77391"]',
            'match = ["quartzfiction:prism77391"]\nproduct_only = ["fictional-prism-only-77391"]'))
        self.engine.watches, self.engine.accepts = load_document(self.path)
        self.scheduler.watch_stamp = self.scheduler._stamp()
        yield 'accepts'
        with self.store.transaction():
            self.store.connection.execute('INSERT INTO dead_letters VALUES(?,?,?,?,?,?)',
                ('cvelist', 'CVE-2098-77391999', 5, '2099-01-01T00:00:00+00:00',
                 'fictional failure', __version__))
            # Legacy diagnostics include every stored source, including extension sources.
            self.engine._health('fictional-extension', 'unhealthy', 'Fictional extension failure')
        yield 'dead-letter'
        self.path.write_text(self.path.read_text().replace('version = "1.0"', 'version = "2.0"'))
        error = RuntimeError('Cannot evaluate quartz-watch-77391 for Quartz Fiction Appliance 77391')
        with patch.object(self.engine, '_rematch_record', side_effect=error) as rematch:
            yield 'failed-rematch'
            rematch.assert_called()
        self.assertIn('quartz-watch-77391', self.store.get_meta('last_error:watchlist'))
        self.assertIn('Quartz Fiction Appliance 77391', self.store.get_meta('last_error:watchlist'))

    def key_paths(self, value, prefix=''):
        result = []
        if isinstance(value, dict):
            for key, item in value.items():
                path = prefix + key
                result.append(path)
                result.extend(self.key_paths(item, path + '.'))
        elif isinstance(value, list):
            for item in value:
                result.extend(self.key_paths(item, prefix))
        return sorted(result)

    def test_h3_new_blocks_and_all_key_paths_exclude_inventory(self):
        for state in self.scope_states():
            with self.subTest(state=state):
                value = self.heartbeat()
                serialized = json.dumps([value['report'], value['github'],
                                         self.key_paths(value)], ensure_ascii=False).casefold()
                for secret in ('private-inventory', 'Private product name', 'examplecorp', 'example',
                               'quartz-watch-77391', 'Quartz Fiction Appliance 77391',
                               'quartzfiction', 'prism77391', 'fictional-prism-only-77391',
                               'CVE-2098-77391999',
                               *(f'CVE-2098-7739100{i}' for i in range(1, 9))):
                    self.assertNotIn(secret.casefold(), serialized)
                self.assertNotRegex(serialized, r'cve-\d+')

    def test_original_fields_equal_frozen_v018_except_public_health_text(self):
        original_keys = ('time', 'sources', 'health_details', 'ingested', 'events', 'sent', 'pending')
        for state in self.scope_states():
            with self.subTest(state=state):
                lines = []
                reference = V018Scheduler(self.engine, self.sources, self.clock, lines.append,
                                          monotonic=lambda: self.clock().timestamp())
                reference.next_poll = dict(self.scheduler.next_poll)
                self.clock.now += timedelta(minutes=1)
                report = self.scheduler.tick()
                value = json.loads(self.lines[-1])
                # Replay the same poll results/cycle result against the same post-cycle DB.
                # Avoid a second engine cycle or inventory reload changing that state.
                with patch.object(reference, '_reload'), patch.object(
                        self.engine, 'run_cycle', return_value=report):
                    reference.tick()
                expected = json.loads(lines[-1])
                # v0.1.10 changes health text and drops the fictional extension key.
                expected['health_details'] = {
                    'cvelist': ('Dead-letter records: [redacted]'
                                if state in ('dead-letter', 'failed-rematch') else
                                'Complete fetch; content age within source policy'),
                    'epss': 'Complete fetch; content age within source policy',
                    'kev': 'Complete fetch; catalog 0 days old',
                    'watchlist': ('Incomplete ingest; retry pending; last error: RuntimeError: '
                                  'Cannot [redacted] for [redacted] 77391'
                                  if state == 'failed-rematch' else 'No fetch failure'),
                }
                self.assertEqual({key: value[key] for key in original_keys}, expected)
                self.assertEqual(value['health_details_withheld'],
                                 1 if state in ('dead-letter', 'failed-rematch') else 0)

    def test_f4_accept_watch_case_subtracted_in_cli_and_heartbeat(self):
        self.scheduler.tick()
        self.populate()
        self.path.write_text(self.path.read_text().replace('watch = "quartz-watch-77391"',
                                                         'watch = "QUARTZ-WATCH-77391"'))
        self.engine.watches, self.engine.accepts = load_document(self.path)
        self.scheduler.watch_stamp = self.scheduler._stamp()
        with self.store.transaction():
            self.store.connection.execute("UPDATE pairs SET watch_id='QuArTz-WaTcH-77391'")
        value = self.heartbeat()
        output = io.StringIO()
        with redirect_stdout(output):
            cli.report(self.store, Namespace(group=None, watch=None, format='text'),
                       config=self.engine.config, now=self.clock())
        self.assertEqual(value['report'], dict(affected=2, exploited_unknown=1, open=2,
                                             dead_letters=1, accepted=2))
        for label, expected in (('Baseline: affected', 2), ('Open matches', 2),
                                ('Accepted (not alerting)', 2)):
            self.assertEqual(int(re.search(re.escape(label) + r': (\d+)', output.getvalue())[1]), expected)

    def store_rate(self):
        rate = dict(limit=5000, remaining=4321, reset='2026-11-03T01:00:00+00:00',
                    observed_at='2026-11-03T00:00:00+00:00')
        with self.store.transaction():
            self.store.set_meta('github_auth', 'token')
            self.store.set_meta('github_rate_limit', json.dumps(rate))
        return dict(auth='token', limit=5000, remaining=4321,
                    reset=1793667600, observed_at=1793664000)

    def test_h4_second_tick_uses_stored_rate_without_http_or_watch_read(self):
        self.scheduler.tick()
        for source in self.sources.values():
            source.poll.reset_mock()
        expected = self.store_rate()
        targets = ('cornicen.fetch.Http.__init__', 'cornicen.fetch.Http.get',
                   'cornicen.fetch.build_opener', 'urllib.request.build_opener',
                   'urllib.request.OpenerDirector.open', 'urllib.request.urlopen',
                   'http.client.HTTPSConnection.connect', 'cornicen.scheduler.load_document')
        reads = []
        def guard_read(original):
            def guarded(path, *args, **kwargs):
                if isinstance(path, (str, Path)) and Path(path).resolve() == self.path.resolve():
                    reads.append(str(path))
                    raise AssertionError('Heartbeat read the watch list')
                return original(path, *args, **kwargs)
            return guarded
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target)))
                      for target in targets]
            stack.enter_context(patch('builtins.open', guard_read(builtins.open)))
            for name in ('open', 'read_bytes', 'read_text'):
                stack.enter_context(patch.object(Path, name, guard_read(getattr(Path, name))))
            value = self.heartbeat()
        self.assertEqual(reads, [])
        for guard in guards:
            guard.assert_not_called()
        for source in self.sources.values():
            source.poll.assert_not_called()
        self.assertEqual(value['github'], expected)
        self.assert_schema(value)

    def test_h5_absent_or_malformed_rate_keeps_auth_and_null_numbers(self):
        self.scheduler.tick()
        malformed = (None, 'invalid json', '[]', '{}',
                     json.dumps(dict(limit=True, remaining=3, reset='bad', observed_at='bad')),
                     json.dumps(dict(limit=50, remaining=3, reset='2026-11-03T01:00:00',
                                     observed_at='2026-11-03T00:00:00+00:00')))
        for auth in ('none', 'token', 'token rejected', 'token unusable: fictional failure', 'other'):
            for rate in malformed:
                with self.subTest(auth=auth, rate=rate):
                    with self.store.transaction():
                        self.store.set_meta('github_auth', auth)
                        if rate is None:
                            self.store.connection.execute("DELETE FROM meta WHERE k='github_rate_limit'")
                        else:
                            self.store.set_meta('github_rate_limit', rate)
                    value = self.heartbeat()['github']
                    self.assertEqual(value, dict(auth=github_status(self.store)['auth'],
                                                 limit=None, remaining=None, reset=None, observed_at=None))

    def test_h5_each_malformed_field_independently_nulls_all_numbers(self):
        self.scheduler.tick()
        valid = dict(limit=5000, remaining=4321, reset='2026-11-03T01:00:00+00:00',
                     observed_at='2026-11-03T00:00:00+00:00')
        invalid = {key: (True, 3.5, '50') for key in ('limit', 'remaining')}
        invalid.update({key: ('2026-11-03T00:00:00', '2026-11-03T00:00:00+01:00', 'garbage')
                        for key in ('reset', 'observed_at')})
        for key, values in invalid.items():
            for bad in values:
                with self.subTest(field=key, value=bad):
                    with self.store.transaction():
                        self.store.set_meta('github_auth', 'token')
                        self.store.set_meta('github_rate_limit', json.dumps({**valid, key: bad}))
                    self.assertEqual(self.heartbeat()['github'], dict(auth='token', limit=None,
                        remaining=None, reset=None, observed_at=None))

    def test_h6_count_failure_still_prints_all_null_counts(self):
        with patch('cornicen.scheduler.report_counts', side_effect=RuntimeError('fictional failure')):
            value = self.heartbeat()
        self.assertEqual(value['report'], dict(affected=None, exploited_unknown=None,
                                              open=None, dead_letters=None, accepted=None))
        self.assert_schema(value)

    def test_h6_github_failure_still_prints_unknown_and_nulls(self):
        with patch('cornicen.scheduler.github_status', side_effect=RuntimeError('fictional failure')):
            value = self.heartbeat()
        self.assertEqual(value['github'], dict(auth='unknown', limit=None, remaining=None,
                                              reset=None, observed_at=None))
        self.assertEqual(value['report']['affected'], 0)

    def test_h7_count_query_plans_and_executed_tables_exclude_records(self):
        self.scheduler.tick()
        self.populate()
        for group, (_, query) in COUNT_QUERIES.items():
            with self.subTest(group=group):
                plan = self.store.connection.execute('EXPLAIN QUERY PLAN ' + query).fetchall()
                self.assertNotRegex(' '.join(str(tuple(row)) for row in plan), r'\brecords\b')
        tables = set()

        def authorizer(action, table, column, database, trigger):
            import sqlite3
            if action == sqlite3.SQLITE_READ:
                tables.add(table)
            return sqlite3.SQLITE_OK

        self.store.connection.set_authorizer(authorizer)
        try:
            report_counts(self.store.connection, self.engine.watches, self.engine.accepts,
                          self.clock(), self.engine.config.timezone)
        finally:
            self.store.connection.set_authorizer(None)
        self.assertEqual(tables, {'pairs', 'dead_letters'})

    def test_counts_recomputed_each_cycle(self):
        self.scheduler.tick()
        self.populate()
        self.assertEqual(self.heartbeat()['report']['affected'], 2)
        with self.store.transaction():
            self.store.connection.execute("UPDATE pairs SET state='not_affected' WHERE record_id='CVE-2098-77391007'")
        self.assertEqual(self.heartbeat()['report']['affected'], 1)

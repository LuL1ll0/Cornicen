"""Offline hardening regressions, including the final review's boundary probes."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from email.message import Message
from hashlib import sha256
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl
from zipfile import ZipFile, ZIP_STORED

from cornicen import cli
from cornicen.config import load_config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, Notification, Origin
from cornicen.notify.file import FileNotifier
from cornicen.notify.ntfy import post
from cornicen.render import render
from cornicen.store import Store
from tests import test_engine, test_cvelist_source, test_cli
from tests.source_helpers import RAW, archive, release, expected_projection


def zipped(entries):
    data = io.BytesIO()
    with ZipFile(data, 'w', ZIP_STORED) as target:
        for name, value in entries:
            target.writestr(name, json.dumps(value))
    return data.getvalue()


class BoundaryTests(unittest.TestCase):
    setUp = test_cvelist_source.CveListTests.setUp
    source = test_cvelist_source.CveListTests.source
    cursor = test_cvelist_source.CveListTests.cursor

    def delta(self, entries):
        self.cursor(release(3, 1)['tag_name'])
        r = release(3)
        source, _ = self.source([r], **{r['assets'][1]['browser_download_url']: zipped(entries)})
        return source.poll(test_cvelist_source.NOW)[0]

    def test_record_shapes_are_partial_at_boundary(self):
        good = json.loads((RAW / 'CVE-2026-106803.json').read_text())
        for path, value in ((('cveMetadata', 'state'), 'RESERVED'),
                            (('containers', 'cna', 'affected'), {}),
                            (('containers', 'cna', 'affected'), [None]),
                            (('containers', 'cna', 'affected', 0, 'versions'), {}),
                            (('containers', 'cna', 'affected', 0, 'versions'), [{'version': 7}]),
                            (('containers', 'cna', 'affected', 0, 'versions'), [{'changes': {}}])):
            with self.subTest(path=path, value=value):
                self.store.connection.execute('DELETE FROM cursors')
                bad = deepcopy(good)
                part = bad
                for key in path[:-1]:
                    part = part[key]
                part[path[-1]] = value
                self.assertEqual(self.delta([('deltaCves/CVE-2026-106803.json', bad)]).status,
                                 FetchStatus.PARTIAL)

    def test_manifest_requires_all_declared_records(self):
        result = self.delta([('deltaLog.json', {'new': [{'cveId': 'CVE-2026-10001'}],
                                               'updated': [], 'error': []})])
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertIn('CVE-2026-10001', ' '.join(result.errors))

    def test_unexplained_empty_and_unrecognised_layout_are_partial(self):
        for entries in ([], [('unexpected/record.json', {})]):
            with self.subTest(entries=entries):
                self.store.connection.execute('DELETE FROM cursors')
                self.assertEqual(self.delta(entries).status, FetchStatus.PARTIAL)

    def test_zero_manifest_does_not_hide_unknown_record_layout(self):
        result = self.delta([('deltaLog.json', {'new': [], 'updated': [], 'error': []}),
                             ('unexpected/CVE-2026-10001.json', {})])
        self.assertEqual(result.status, FetchStatus.PARTIAL)

    def test_missing_version_and_change_fields_are_invalid(self):
        from cornicen import validate
        good = json.loads((RAW / 'CVE-2026-106803.json').read_text())
        for version in ({}, {'version': '1.0'}, {'version': '1.0', 'status': 'affected', 'changes': [{}]}):
            with self.subTest(version=version):
                bad = deepcopy(good)
                bad['containers']['cna']['affected'][0]['versions'] = [version]
                self.assertTrue(validate.record(bad))

    def test_explicit_empty_delta_is_complete(self):
        self.assertEqual(self.delta([('delta.json', {'new': [], 'updated': [], 'error': []})]).status,
                         FetchStatus.COMPLETE)

    def test_end_of_day_and_unknown_tag_catch_up(self):
        self.cursor(release(1, 1)['tag_name'])
        eod = {'tag_name': 'cve_2026-11-01_at_end_of_day', 'assets': [{
            'name': '2026-11-01_delta_CVEs_at_end_of_day.zip',
            'browser_download_url': 'https://github.com/eod'}]}
        releases = [release(1), eod, release(2), release(3), {'tag_name': 'notes', 'assets': []}]
        routes = {r['assets'][-1]['browser_download_url']: archive() for r in releases if r['assets']}
        source, _ = self.source(releases, **routes)
        with self.assertLogs('cornicen.sources.cvelist', level='WARNING'):
            results = source.poll(test_cvelist_source.NOW)
        self.assertEqual([r.cursor for r in results], [eod['tag_name'], release(2)['tag_name'], release(3)['tag_name']])
        self.assertTrue(all(r.status == FetchStatus.COMPLETE for r in results))

    def test_future_tag_or_publication_never_downloaded(self):
        self.cursor(release(3, 1)['tag_name'])
        for future in (release(5), dict(release(3), published_at='2026-11-05T00:00:00Z')):
            with self.subTest(future=future['tag_name']):
                source, opener = self.source([future], **{
                    a['browser_download_url']: archive(snapshot='all_CVEs' in a['name']) for a in future['assets']})
                result = source.poll(test_cvelist_source.NOW)[0]
                self.assertNotEqual(result.status, FetchStatus.COMPLETE)
                self.assertIn(future['tag_name'], ' '.join(result.errors))
                self.assertEqual(len(opener.requests), 1)

    def test_empty_release_listing_is_failed(self):
        source, _ = self.source([])
        results = source.poll(test_cvelist_source.NOW)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FetchStatus.FAILED)

    def test_real_end_of_day_fixture_is_appended(self):
        listing = json.loads((RAW / 'github_releases_sample.json').read_text())
        self.assertTrue(any(r['tag_name'].endswith('_at_end_of_day') and any(
            a['name'].endswith('_delta_CVEs_at_end_of_day.zip') for a in r['assets']) for r in listing))
        self.assertTrue(any(r['tag_name'].endswith('00Z') for r in listing))


class StateTests(unittest.TestCase):
    setUp = test_engine.EngineTests.setUp
    start = test_engine.EngineTests.start
    ingest = test_engine.EngineTests.ingest
    count = test_engine.EngineTests.count

    def test_partial_manifest_holds_cursor_and_durable_fetch_retry(self):
        self.start()
        previous = self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0]
        self.engine.run_cycle([replace(self.ingest([]), status=FetchStatus.PARTIAL,
            errors=('Declared record missing or invalid: CVE-2026-10001',))])
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        self.engine.run_cycle([])
        self.assertEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], previous)
        self.assertEqual(self.store.connection.execute("SELECT record_id FROM retry_queue WHERE source='cvelist'").fetchone()[0], '@fetch')
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'unhealthy')

    def test_invalid_revision_preserves_accepted_match_and_retry(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        previous = self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0]
        bad = deepcopy(self.record)
        bad['containers']['cna']['affected'] = {}
        self.engine.run_cycle([replace(self.ingest([bad]), cursor='bad-revision')])
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))
        self.assertEqual(self.store.connection.execute('SELECT state FROM pairs').fetchone()[0], 'affected')
        self.assertEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], previous)
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        self.engine.run_cycle([])
        self.assertGreater(self.count('retry_queue'), 0)
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'unhealthy')
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM outbox WHERE pair_key LIKE 'service|%' AND sent_at IS NULL").fetchone()[0], 1)
        self.engine.run_cycle([replace(self.ingest([self.record]), cursor='repaired')])
        self.assertEqual(self.count('retry_queue'), 0)

    def test_invalid_first_revision_is_only_in_retry_storage(self):
        self.start()
        bad = deepcopy(self.record)
        bad['containers']['cna']['affected'] = {}
        self.engine.run_cycle([self.ingest([bad])])
        self.assertEqual(self.count('records'), 0)
        self.assertEqual(self.count('invalid_revisions'), 1)
        self.assertEqual(self.count('retry_queue'), 1)

    def test_standalone_outbox_combines_normal_rows(self):
        from cornicen.outbox import Outbox
        self.start()
        second = deepcopy(self.record)
        second['cveMetadata']['cveId'] = 'CVE-2026-9999'
        self.engine.run_cycle([self.ingest([self.record, second])])
        self.clock.now = self.clock.now.replace(hour=8, minute=0)
        self.assertEqual(Outbox(self.store, self.notifier, self.clock).flush(), 1)
        self.assertEqual(len(self.notifier.delivered), 1)
        self.assertEqual(self.notifier.delivered[0]['record'], 'digest')

    def test_invalid_revision_dead_letter_never_advances_cursor(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        bad = deepcopy(self.record)
        bad['containers']['cna']['affected'] = {}
        for _ in range(6):
            self.engine.run_cycle([replace(self.ingest([bad]), cursor='invalid')])
        self.assertEqual(self.count('dead_letters'), 1)
        self.assertNotEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], 'invalid')
        self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))

    def test_last_error_survives_staleness_and_is_sanitised(self):
        self.start()
        detail = 'Bad archive\x1b\n\t' + 'x' * 300
        self.engine.run_cycle([replace(self.ingest([]), status=FetchStatus.FAILED, errors=(detail,))])
        self.clock.now += timedelta(hours=4)
        self.engine.run_cycle([])
        row = self.store.connection.execute("SELECT detail FROM health WHERE source='cvelist'").fetchone()[0]
        self.assertIn('Bad archive', row)
        self.assertNotIn('\x1b', row)
        self.assertNotIn('\n', row)
        self.assertLessEqual(len(self.store.get_meta('last_error:cvelist')), 200)
        self.assertIn('stale', row)

    def test_startup_reconciles_offline_watch_change_once(self):
        outside = (replace(self.watches[0], version='99.0.0'),)
        self.engine.reload_watches(outside)
        self.engine.run_cycle([self.ingest([self.record], origin=Origin.SNAPSHOT), *self.baseline[1:]])
        self.notifier.delivered.clear()
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        self.engine.run_cycle([])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM events WHERE type='new match'").fetchone()[0], 1)
        saved = self.store.get_meta('applied_watches')
        self.assertEqual(self.store.get_meta('applied_watches_hash'), sha256(saved.encode()).hexdigest())
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        self.engine.run_cycle([])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM events WHERE type='new match'").fetchone()[0], 1)

    def test_digest_combines_sorted_items_and_retries_atomically(self):
        self.start()
        second = deepcopy(self.record)
        second['cveMetadata']['cveId'] = 'CVE-2026-9999'
        scores = replace(self.baseline[2], epss={self.record['cveMetadata']['cveId']: (.01, .2), 'CVE-2026-9999': (.09, .8)})
        self.engine.run_cycle([self.ingest([self.record, second]), scores])
        self.clock.now = self.clock.now.replace(hour=8, minute=0)
        sent = []
        self.engine.notifier.send = lambda n: sent.append(n) or False
        self.engine.run_cycle([])
        self.assertEqual(len(sent), 1)
        title, body, _, _ = render(sent[0])
        self.assertEqual(title, 'Cornicen digest: 2 items')
        self.assertLess(body.index('CVE-2026-9999'), body.index(self.record['cveMetadata']['cveId']))
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM outbox WHERE pair_key LIKE 'service|%' AND sent_at IS NULL").fetchone()[0], 2)
        self.clock.now += timedelta(minutes=2)
        self.engine.notifier.send = lambda n: sent.append(n) or True
        self.engine.run_cycle([])
        self.assertEqual(sent[-1].key, sent[0].key)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM outbox WHERE pair_key LIKE 'service|%' AND sent_at IS NULL").fetchone()[0], 0)
        self.assertEqual(self.store.connection.execute('SELECT sum(notified) FROM pairs').fetchone()[0], 2)

    def test_pair_keeps_alias_version_across_restart(self):
        self.start()
        self.engine.aliases = AliasMap('first')
        self.engine.run_cycle([self.ingest([self.record])])
        self.engine = Engine(self.store, self.watches, AliasMap('second'), self.config, self.clock, self.notifier)
        self.assertEqual(self.store.connection.execute('SELECT alias_map_version FROM pairs').fetchone()[0], 'first')
        self.engine.run_cycle([self.ingest([self.record])])
        self.assertEqual(self.store.connection.execute('SELECT alias_map_version FROM pairs').fetchone()[0], 'second')


class LocalTests(unittest.TestCase):
    setUp = test_cli.CliTests.setUp
    invoke = test_cli.CliTests.invoke

    def test_cli_restart_after_offline_version_edit(self):
        from datetime import datetime, timezone
        from unittest.mock import Mock
        from cornicen.model import IngestResult
        from cornicen.scheduler import Scheduler
        self.watch.write_text('[[watch]]\nid="one"\nname="Proxy"\nmatch=["nginx:nginx"]\nversion="2.0.0"\nscheme="semver"\n')
        record = {'cveMetadata': {'cveId': 'CVE-2026-10000', 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': [{'vendor': 'nginx', 'product': 'nginx',
                      'versions': [{'version': '1.0.0', 'status': 'affected'}], 'defaultStatus': 'unaffected'}]}}}
        stamp = datetime.now(timezone.utc)
        cve = Mock()
        cve.poll.return_value = [IngestResult('cvelist', FetchStatus.COMPLETE, Origin.SNAPSHOT,
                                             'initial', stamp, (record,))]
        kev, epss = Mock(), Mock()
        kev.poll.return_value = [IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, 'initial', stamp, kev={})]
        epss.poll.return_value = [IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, 'initial', stamp, epss={})]
        with patch.object(cli, 'CveListSource', return_value=cve), patch.object(cli, 'KevSource', return_value=kev), \
             patch.object(cli, 'EpssSource', return_value=epss), patch.object(cli, '_notifier', return_value=Mock(send=Mock(return_value=True))), \
             patch.object(Scheduler, 'run', lambda scheduler: (scheduler.tick(), 0)[1]):
            self.assertEqual(self.invoke('run')[0], 0)
            self.watch.write_text(self.watch.read_text().replace('2.0.0', '1.0.0'))
            cve.poll.return_value = kev.poll.return_value = epss.poll.return_value = []
            self.assertEqual(self.invoke('run')[0], 0)
            self.assertEqual(self.invoke('run')[0], 0)
        store = Store(str(self.db))
        self.addCleanup(store.connection.close)
        self.assertEqual(store.connection.execute("SELECT count(*) FROM events WHERE type='new match'").fetchone()[0], 1)
        self.assertEqual(store.connection.execute('SELECT state FROM pairs').fetchone()[0], 'affected')

    def test_watch_check_without_database(self):
        missing = self.root / 'missing.db'
        self.config.write_text(f'db_path="{missing}"\nwatchlist_path="{self.watch}"\n')
        code, output = self.invoke('watch', 'check')
        self.assertEqual(code, 0)
        self.assertIn('collision:', output)
        self.assertIn('no records ingested yet', output)
        self.assertFalse(missing.exists())

    def test_private_files_and_existing_sidecars(self):
        old = os.umask(0o022)
        try:
            db = self.root / 'private.db'
            store = Store(str(db))
            store.migrate()
            store.connection.execute('PRAGMA journal_mode=WAL')
            store.set_meta('inventory', 'fictional')
            self.addCleanup(store.connection.close)
            for path in (db, Path(str(db) + '-wal'), Path(str(db) + '-shm')):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                path.chmod(0o644)
            reopened = Store(str(db))
            self.addCleanup(reopened.connection.close)
            for path in (db, Path(str(db) + '-wal'), Path(str(db) + '-shm')):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            output = self.root / 'notifications.jsonl'
            channel = FileNotifier(output)
            self.assertTrue(channel.send(Notification('1', '', 'test', (), 'normal', {})))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            output.chmod(0o644)
            FileNotifier(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        finally:
            os.umask(old)

    def test_shared_token_requires_explicit_opt_in(self):
        token = self.root / 'fixture-token'
        token.write_text('fixture-only-value')
        token.chmod(0o644)
        env = {'CORNICEN_NTFY_TOKEN_FILE': str(token)}
        with self.assertRaisesRegex(ValueError, 'permissions'):
            load_config(self.config, env)
        with self.config.open('a') as target:
            target.write('allow_shared_token_file=true\n')
        self.assertIsNotNone(load_config(self.config, env).ntfy_token)

    def test_status_shows_sanitised_last_error(self):
        store = Store(str(self.db))
        store.set_meta('last_error:cvelist', 'Malformed archive')
        store.connection.execute("INSERT INTO health VALUES ('cvelist','unhealthy','2026-11-03','Incomplete ingest')")
        store.connection.close()
        self.assertIn('Malformed archive', self.invoke('status')[1])

    def test_report_shows_pair_alias_version(self):
        store = Store(str(self.db))
        store.connection.execute("INSERT INTO pairs(watch_id,record_id,state,episode,baseline) VALUES ('one','CVE-2026-1234','affected',1,1)")
        store.connection.close()
        self.assertIn('alias_map_version', self.invoke('report')[1])


class ContractTests(unittest.TestCase):
    def test_real_opener_blocks_all_redirect_codes(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                requests = []
                class Transport(HTTPSHandler):
                    def https_open(self, request):
                        requests.append(request)
                        headers = Message()
                        headers['Location'] = 'https://elsewhere.invalid/steal'
                        reply = addinfourl(io.BytesIO(b''), headers, request.full_url, code if len(requests) == 1 else 204)
                        reply.msg = 'fixture'
                        return reply
                with patch('cornicen.notify.ntfy.build_opener', side_effect=lambda *handlers: build_opener(*handlers, Transport())):
                    self.assertEqual(post('https://ntfy.invalid/topic', b'test', {'Authorization': 'Bearer fixture-only-value'}), code)
                self.assertEqual(len(requests), 1)
                self.assertFalse(any(r.get_header('Authorization') for r in requests[1:]))

    def test_user_readme_and_approved_spec_contracts(self):
        readme = Path('README.md').read_text()
        spec = Path('docs/spec.md').read_text()
        self.assertIn('(docs/spec.md)', readme)
        self.assertNotIn('## 13. Decisions', readme)
        self.assertIn('allow_shared_token_file', readme)
        self.assertIn('release-assets.githubusercontent.com', readme)
        self.assertIn('completed-source markers', spec)
        self.assertIn('at_end_of_day', spec)
        self.assertIn('one state per source', spec)
        self.assertIn('Cornicen digest: N items', spec)

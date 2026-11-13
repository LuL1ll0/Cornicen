# script-purpose: Check CISA SSVC projection, urgency, display and snapshot recovery.
# script-class: harness
# script-trigger: Run by unittest discovery and make gate.
# script-tests: tests/test_ssvc.py
"""Read invented records; write temporary stores and unittest output only.

Run with python -m unittest tests.test_ssvc. Exit codes: 0 success, 1 failure,
2 invalid command arguments.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.fetch import Response
from cornicen.health import assess
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.render import render
from cornicen.sources.cvelist import CveListSource
from cornicen.store import Store, project_record
from cornicen.watchlist import load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier

NOW = datetime(2099, 4, 5, 6, tzinfo=timezone.utc)
TAG = 'cve_2099-04-05_0600Z'
POINTS = {'Exploitation': 'active', 'Automatable': 'yes', 'Technical Impact': 'total'}


def record(number=1001, points=None):
    return {'cveMetadata': {'cveId': f'CVE-2099-{number}', 'state': 'PUBLISHED',
                            'dateUpdated': NOW.isoformat()},
            'containers': {'cna': {'affected': [{'vendor': 'fable', 'product': 'reed',
                'versions': [{'version': '9.8.7', 'status': 'affected'}]}]},
                'adp': [{'providerMetadata': {'shortName': 'CISA-ADP', 'extra': 'discard'},
                    'metrics': [{'other': {'type': 'ssvc', 'content': {
                        'timestamp': NOW.isoformat(), 'id': 'discard',
                        'options': [{key: value} for key, value in
                                    (POINTS if points is None else points).items()]}}}]}]}}


class SsvcTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.config = Config(':memory:', Path('unused'), None, 'https://notify.invalid', 'test', None)
        self.clock = FakeClock(NOW)
        self.notifier = RecordingNotifier(self.clock)
        self.watches = load_watchlist_text('''[[watch]]
id = "reed"
name = "Fable reed"
match = ["fable:reed"]
version = "9.8.7"
scheme = "semver"
''')
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)

    def ingest(self, value):
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                           None, NOW, (value,))])

    def source(self, records):
        http = Mock(github_token=None)
        source = CveListSource(http, self.store)
        release = {'tag_name': TAG, 'assets': [
            {'name': '2099-04-05_all_CVEs_at_midnight.zip.zip',
             'browser_download_url': 'https://archive.invalid/snapshot'},
            {'name': '2099-04-05_delta_CVEs_at_0600Z.zip',
             'browser_download_url': 'https://archive.invalid/delta'}]}
        source._listing = Mock(return_value=([release], True))
        source._archive = Mock(return_value=IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, TAG, NOW, records))
        self.store.connection.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
                                      ('cvelist', TAG, NOW.isoformat()))
        return source

    def test_ssvc_projection_allowlist_and_cna_unchanged(self):
        value = record()
        cna = value['containers']['cna']
        cna['metrics'] = deepcopy(value['containers']['adp'][0]['metrics'])
        value['containers']['adp'][0]['metrics'][0]['cvssV3_1'] = {'baseScore': 2.3}
        projected = project_record(value)
        adp = projected['containers']['adp'][0]
        self.assertEqual(adp['providerMetadata'], {'shortName': 'CISA-ADP'})
        self.assertEqual(adp['metrics'][0]['other'], {'type': 'ssvc', 'content': {
            'options': [{key: val} for key, val in POINTS.items()], 'timestamp': NOW.isoformat()}})
        self.assertEqual(adp['metrics'][0]['cvssV3_1'], {'baseScore': 2.3})
        self.assertEqual(projected['containers']['cna']['metrics'], [{}])
        self.assertEqual(projected['containers']['cna']['affected'], cna['affected'])
        self.assertEqual(project_record(projected), projected)
        for provider in ('FABLE-ADP', 'CISA-ADP'):
            value['containers']['adp'][0]['providerMetadata']['shortName'] = provider
            value['containers']['adp'][0]['metrics'][0]['other']['type'] = 'unrelated'
            self.assertNotIn('other', project_record(value)['containers']['adp'][0]['metrics'][0])
        value = record(points={'Exploitation': 'surprise', 'Automatable': 'no',
                               'Technical Impact': 'partial', 'Untrusted': 'discard'})
        value['containers']['adp'][0]['metrics'][0]['other']['content']['timestamp'] = 'invalid'
        content = project_record(value)['containers']['adp'][0]['metrics'][0]['other']['content']
        self.assertEqual(content, {'options': [{'Automatable': 'no'}, {'Technical Impact': 'partial'}]})
        value = record()
        value['containers']['adp'][0]['providerMetadata']['shortName'] = 'FABLE-ADP'
        self.assertEqual(project_record(value)['containers']['adp'], [{'metrics': [{}]}])

    def test_ssvc_active_urgency_without_activation_change(self):
        self.store.connection.execute('INSERT INTO epss VALUES (?,?,?,?)',
                                      ('CVE-2099-1001', .001, .01, '2099-04-05'))
        self.ingest(record())
        self.assertEqual(self.notifier.delivered[0]['urgency'], 'urgent')
        body = json.loads(self.store.connection.execute(
            "SELECT body_json FROM outbox WHERE pair_key='reed|CVE-2099-1001'").fetchone()[0])
        self.assertEqual(body['ssvc'], POINTS)
        self.assertEqual(self.store.connection.execute('SELECT exploited FROM pairs').fetchone()[0], 0)
        unknown = record(1002)
        unknown['containers']['cna']['affected'][0]['versions'] = []
        self.ingest(unknown)
        pair = self.store.connection.execute("SELECT state,exploited FROM pairs WHERE record_id='CVE-2099-1002'").fetchone()
        self.assertEqual(tuple(pair), ('unknown', 0))
        self.assertEqual(len(self.notifier.delivered), 1)
        for number, exploitation in ((1003, 'none'), (1004, 'poc')):
            self.ingest(record(number, dict(POINTS, Exploitation=exploitation)))
            row = self.store.connection.execute('SELECT urgency FROM outbox WHERE pair_key=?',
                                                (f'reed|CVE-2099-{number}',)).fetchone()
            self.assertEqual(row[0], 'normal')

    def check_render(self, points, expected):
        body = {'ssvc': points} if points is not None else {}
        text = render(Notification('1', 'reed', 'CVE-2099-1001', ('new match',), 'normal', body))[1]
        self.assertEqual(text.splitlines()[text.splitlines().index('KEV: not listed') + 1], expected)

    def test_ssvc_render_complete(self):
        self.check_render(POINTS, 'SSVC (CISA): exploitation active · automatable yes · technical impact total')

    def test_ssvc_render_partial(self):
        self.check_render({'Exploitation': 'poc'},
            'SSVC (CISA): exploitation poc · automatable unknown · technical impact unknown')

    def test_ssvc_render_unassessed(self):
        self.check_render(None, 'SSVC: not assessed')
        self.check_render({}, 'SSVC: not assessed')

    def test_ssvc_backfill_atomic_no_evaluation_and_second_start_noop(self):
        first, second = record(), record(1002)
        for value in (first, second):
            old = deepcopy(value)
            old['containers'].pop('adp')
            self.store.put_record(value['cveMetadata']['cveId'], old, NOW.isoformat())
        second['cveMetadata']['dateUpdated'] = '2099-04-04T06:00:00+00:00'
        self.store.connection.execute("INSERT INTO pairs VALUES ('reed','CVE-2099-1001','affected',3,1,0,1,'evidence','exact','1')")
        before = [tuple(row) for row in self.store.connection.execute('SELECT * FROM pairs')]
        source = self.source((first, second))
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
        with patch('cornicen.applicability.resolve', side_effect=AssertionError('must not evaluate')):
            source.poll(NOW)
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(first))
        self.assertNotIn('adp', self.engine._record('CVE-2099-1002')['containers'])
        self.assertEqual([tuple(row) for row in self.store.connection.execute('SELECT * FROM pairs')], before)
        for table in ('events', 'outbox'):
            self.assertEqual(self.store.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)
        self.assertEqual(assess('projection', self.store, NOW, self.config)[0], 'healthy')
        self.assertGreaterEqual(int(self.store.get_meta('projection_runtime_seconds')), 0)
        source = self.source((first,))
        self.store.connection.execute("""CREATE TRIGGER projection_once BEFORE INSERT ON meta
            WHEN NEW.k='applied_projection_revision'
            BEGIN SELECT RAISE(ABORT, 'already applied'); END""")
        source.poll(NOW)
        source._archive.assert_not_called()

    def test_ssvc_backfill_interruption_retries_and_delta_continues(self):
        old = record()
        old['containers'].pop('adp')
        self.store.put_record('CVE-2099-1001', old, NOW.isoformat())
        def interrupted():
            yield record()
            raise OSError('interrupted')
        source = self.source(interrupted())
        release = source._listing.return_value[0][0]
        release['tag_name'] = 'cve_2099-04-05_0700Z'
        release['assets'][1]['name'] = '2099-04-05_delta_CVEs_at_0700Z.zip'
        snapshot = source._archive.return_value
        delta = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                             release['tag_name'], NOW, ())
        source._archive.side_effect = [snapshot, delta]
        results = source.poll(NOW)
        self.assertEqual(results, [delta])
        self.assertEqual(source._archive.call_args_list[1].args[1], Origin.DELTA)
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
        self.assertIsNone(self.store.get_meta('applied_projection_revision'))
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(old))
        source = self.source((record(),))
        source._backfill_projection(source._listing.return_value[0], NOW + timedelta(hours=6))
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.assertIn('adp', self.engine._record('CVE-2099-1001')['containers'])

    def test_ssvc_pending_match_promotes_after_backfill(self):
        old = record()
        old['containers'].pop('adp')
        self.ingest(old)
        self.assertEqual(self.notifier.delivered, [])
        self.assertEqual(self.store.connection.execute('SELECT dirty FROM outbox').fetchone()[0], 0)
        self.source((record(),)).poll(NOW)
        self.engine.run_cycle([])
        self.assertEqual(len(self.notifier.delivered), 1)
        self.assertEqual(self.notifier.delivered[0]['urgency'], 'urgent')
        self.assertEqual(self.notifier.delivered[0]['reasons'], ['new match'])

    def test_ssvc_backfill_real_archive_uses_snapshot_budget(self):
        old = record()
        old['containers'].pop('adp')
        self.store.put_record('CVE-2099-1001', old, NOW.isoformat())
        source = self.source(())
        source._archive = CveListSource._archive.__get__(source)
        with tempfile.TemporaryDirectory(dir='.') as directory:
            source.directory = Path(directory)
            inner = io.BytesIO()
            with ZipFile(inner, 'w') as zipped:
                zipped.writestr('cves/2099/1xxx/CVE-2099-1001.json', json.dumps(record()))
            archive = Path(directory) / 'snapshot.zip'
            with ZipFile(archive, 'w') as zipped:
                zipped.writestr('snapshot.zip', inner.getvalue())
            source._get = Mock(return_value=Response(200, {}, b'', archive))
            source.poll(NOW)
            self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
            self.assertEqual(source._get.call_args.kwargs, {'to_file': True, 'budget': 'cvelist_snapshot'})
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(record()))

    def test_ssvc_backfill_marker_failure_rolls_back_and_retries(self):
        old = record()
        old['containers'].pop('adp')
        self.store.put_record('CVE-2099-1001', old, 'original')
        self.store.connection.execute("""CREATE TRIGGER interrupt_projection BEFORE INSERT ON meta
            WHEN NEW.k='applied_projection_revision'
            BEGIN SELECT RAISE(ABORT, 'interrupted'); END""")
        source = self.source((record(),))
        source.poll(NOW)
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(old))
        self.assertIsNone(self.store.get_meta('applied_projection_revision'))
        self.store.connection.execute('DROP TRIGGER interrupt_projection')
        source._backfill_projection(source._listing.return_value[0], NOW + timedelta(hours=6))
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(record()))
        self.assertEqual(self.store.connection.execute('SELECT ingested_at FROM records').fetchone()[0], 'original')

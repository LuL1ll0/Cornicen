"""Regression replays for missing watch metadata and nightly source alarms."""

from datetime import datetime, timedelta, timezone
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource
from cornicen.sources.epss import EpssSource
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier
from tests.source_helpers import Opener, public_resolver

RELEASES_URL = 'https://listing.invalid/releases'
URL = 'https://scores.invalid/epss_scores-current.csv.gz'


def delta_zip(records=(), extra=None):
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w') as zipped:
        for record in records:
            key = record['cveMetadata']['cveId']
            zipped.writestr(f'deltaCves/{key}.json', json.dumps(record))
        if extra:
            zipped.writestr(*extra)
    return buffer.getvalue()


def release(hour):
    tag = f'cve_2099-04-03_{hour:02d}00Z'
    return {'tag_name': tag, 'assets': [{
        'name': f'2099-04-03_delta_CVEs_at_{hour:02d}00Z.zip',
        'browser_download_url': f'https://archives.invalid/fictional/{tag}/delta'}]}


class NightlyFixTests(unittest.TestCase):
    def setUp(self):
        for mocked in (
                patch('cornicen.sources.cvelist.RELEASES_URL', RELEASES_URL),
                patch('cornicen.sources.epss.URL', URL),
                patch.dict('cornicen.fetch.SOURCE_HOSTS', {
                    'cvelist': frozenset({'listing.invalid', 'archives.invalid'}),
                    'epss': frozenset({'scores.invalid'})})):
            mocked.start()
            self.addCleanup(mocked.stop)
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'watch.toml'
        self.path.write_text('''[[watch]]
id = "copper"
name = "Copper relay"
match = ["fictional:copper-relay"]
version = "7.3.91"
scheme = "dotted"
''')
        self.watches = load_watchlist_text(self.path.read_text())
        self.clock = FakeClock(datetime(2099, 4, 3, 13, 11, tzinfo=timezone.utc))
        self.store = Store(str(Path(directory.name) / 'state.db'))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.config = Config(':memory:', self.path, None, 'https://notice.invalid', 'fictional', None)
        self.notifier = RecordingNotifier(self.clock)
        self.engine = self.restart(self.watches)
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('applied_projection_revision', '2')
        self.record = {'cveMetadata': {'cveId': 'CVE-2099-91001', 'state': 'PUBLISHED'},
                       'containers': {'cna': {'affected': [{'vendor': 'fictional',
                           'product': 'copper-relay', 'versions': [
                               {'version': '7.3.91', 'status': 'affected'}]}]}}}

    def restart(self, watches):
        return Engine(self.store, watches, AliasMap.load(False), self.config,
                      self.clock, self.notifier)

    def seed_pairs(self):
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.SNAPSHOT,
                                           'cve_2099-04-03_0000Z', self.clock(), (self.record,))])
        self.store.connection.execute('DELETE FROM events')
        self.store.connection.execute('DELETE FROM outbox')

    def test_missing_applied_watches_removal_and_present_pairs_match_normal_path(self):
        self.seed_pairs()
        original = [tuple(row) for row in self.store.connection.execute('SELECT * FROM pairs')]
        self.assertEqual(len(original), 1)
        self.restart(self.watches)
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_watches'")
        self.restart(self.watches)
        self.assertEqual([tuple(row) for row in self.store.connection.execute('SELECT * FROM pairs')], original)
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_watches'")
        self.restart(())
        for table in ('pairs', 'events', 'outbox'):
            self.assertEqual(self.store.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)
        self.assertEqual(self.store.get_meta('applied_watches'), '[]')

    def test_missing_applied_watches_interrupted_start_retries_removal(self):
        self.seed_pairs()
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_watches'")
        with patch.object(Engine, '_save_watches', side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):
                self.restart(())
        self.assertIsNone(self.store.get_meta('applied_watches'))
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM pairs').fetchone()[0], 1)
        self.restart(())
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM pairs').fetchone()[0], 0)

    def cve_source(self, releases, bodies):
        previous = {'tag_name': 'cve_2099-04-02_at_end_of_day', 'assets': [{
            'name': '2099-04-02_delta_CVEs_at_end_of_day.zip',
            'browser_download_url': 'https://archives.invalid/fictional/previous/delta'}]}
        routes = {RELEASES_URL: json.dumps([*releases, previous]).encode()}
        routes.update({r['assets'][0]['browser_download_url']: body for r, body in zip(releases, bodies)})
        opener = Opener(routes)
        return CveListSource(Http('fictional', {}, opener, resolver=public_resolver), self.store), opener

    def cve_cursor(self):
        self.store.connection.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
            ('cvelist', 'cve_2099-04-02_at_end_of_day', '2099-04-02T23:59:59+00:00'))

    def test_empty_first_delta_replay_0000_then_0100_ingests_once_and_stays_healthy(self):
        self.clock.now = self.clock.now.replace(hour=0, minute=1)
        self.cve_cursor()
        first, second = release(0), release(1)
        source, opener = self.cve_source([first], [delta_zip()])
        results = source.poll(self.clock())
        self.assertEqual(results[0].status, FetchStatus.COMPLETE)
        self.engine.run_cycle(results)
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'healthy')
        self.assertEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], first['tag_name'])
        other = {**self.record, 'cveMetadata': {'cveId': 'CVE-2099-91002', 'state': 'PUBLISHED'}}
        opener.routes[RELEASES_URL] = json.dumps([second, first]).encode()
        opener.routes[second['assets'][0]['browser_download_url']] = delta_zip((self.record, other))
        self.clock.now += timedelta(hours=1)
        report = self.engine.run_cycle(source.poll(self.clock()))
        self.assertEqual(len([event for event in report.events if '|new match|' in event]), 2)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 2)
        self.assertEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], second['tag_name'])
        self.assertEqual(self.engine.run_cycle(source.poll(self.clock())).events, [])

    def test_empty_first_delta_0100_and_later_and_nonempty_without_manifest_rejected(self):
        self.cve_cursor()
        first = release(1)
        source, _ = self.cve_source([first], [delta_zip()])
        result, = source.poll(self.clock())
        self.addCleanup(result.records.close)
        self.assertNotEqual(result.status, FetchStatus.COMPLETE)
        for body in (delta_zip(), delta_zip(extra=('notes.txt', '0 changes'))):
            with self.subTest(body=body):
                source, _ = self.cve_source([release(12), first], [body, delta_zip()])
                self.assertNotEqual(source.poll(self.clock())[0].status, FetchStatus.COMPLETE)
        source, _ = self.cve_source([release(0)], [delta_zip(extra=('notes.txt', '0 changes'))])
        self.assertNotEqual(source.poll(self.clock())[0].status, FetchStatus.COMPLETE)
        # A shortened listing cannot erase evidence in the durable cursor.
        self.store.connection.execute("UPDATE cursors SET value=? WHERE source='cvelist'",
                                      (first['tag_name'],))
        source, _ = self.cve_source([release(12)], [delta_zip()])
        result, = source.poll(self.clock())
        self.assertNotEqual(result.status, FetchStatus.COMPLETE)
        self.engine.run_cycle([result])
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'unhealthy')

    def test_empty_midnight_duplicate_tag_rejected(self):
        self.cve_cursor()
        for ambiguous in (False, True):
            for filtered in (None, 'prerelease', 'draft'):
                with self.subTest(ambiguous=ambiguous, filtered=filtered):
                    duplicate, selected = release(0), release(0)
                    duplicate['assets'][0]['browser_download_url'] += '/duplicate'
                    if ambiguous:
                        duplicate['assets'].append(deepcopy(release(1)['assets'][0]))
                    if filtered:
                        duplicate[filtered] = True
                    source, _ = self.cve_source([duplicate, selected], [delta_zip(), delta_zip()])
                    result, = source.poll(self.clock())
                    if hasattr(result.records, 'close'):
                        self.addCleanup(result.records.close)
                    self.assertNotEqual(result.status, FetchStatus.COMPLETE)
                    self.engine.run_cycle([result])
                    self.assertEqual(self.store.connection.execute(
                        "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0],
                        'cve_2099-04-02_at_end_of_day')

    def test_empty_midnight_extra_asset_or_parse_error_rejected(self):
        self.cve_cursor()
        for kind in ('two-deltas', 'extra-asset', 'invalid-time', 'later-coverage'):
            with self.subTest(kind=kind):
                candidate = release(0)
                if kind == 'two-deltas':
                    candidate['assets'].append(deepcopy(release(1)['assets'][0]))
                elif kind == 'extra-asset':
                    candidate['assets'].append({'name': 'notes.txt',
                        'browser_download_url': 'https://archives.invalid/fictional/notes'})
                else:
                    candidate['assets'][0]['name'] = (
                        '2099-04-03_delta_CVEs_at_0060Z.zip' if kind == 'invalid-time'
                        else '2099-04-03_delta_CVEs_at_0100Z.zip')
                source, _ = self.cve_source([candidate], [delta_zip()])
                result, = source.poll(self.clock())
                if hasattr(result.records, 'close'):
                    self.addCleanup(result.records.close)
                self.assertNotEqual(result.status, FetchStatus.COMPLETE)

    def test_empty_midnight_requires_ascii_tag_and_asset(self):
        # Integration review r3 (lane A): Unicode digits parse as a midnight stamp.
        self.cve_cursor()
        arabic_zeros = '٠٠'
        for kind in ('unicode-tag', 'unicode-asset'):
            with self.subTest(kind=kind):
                candidate = release(0)
                if kind == 'unicode-tag':
                    candidate['tag_name'] = candidate['tag_name'].replace('_0000Z', f'_{arabic_zeros}00Z')
                else:
                    candidate['assets'][0]['name'] = f'2099-04-03_delta_CVEs_at_{arabic_zeros}00Z.zip'
                source, _ = self.cve_source([candidate], [delta_zip()])
                result, = source.poll(self.clock())
                if hasattr(result.records, 'close'):
                    self.addCleanup(result.records.close)
                self.assertNotEqual(result.status, FetchStatus.COMPLETE)
        clean, = self.cve_source([release(0)], [delta_zip()])[0].poll(self.clock())
        if hasattr(clean.records, 'close'):
            self.addCleanup(clean.records.close)
        self.assertEqual(clean.status, FetchStatus.COMPLETE)

    def epss_scheduler(self, stuck=False):
        calls = []
        owner = self
        class Published:
            def open(self, request, timeout=None):
                day = owner.clock().date()
                if stuck or (owner.clock().hour, owner.clock().minute) < (13, 30):
                    day -= timedelta(days=1)
                if stuck:
                    day = datetime(2099, 4, 2).date()
                calls.append(owner.clock())
                body = gzip.compress((f'#model_version:fictional,score_date:{day}T12:00:00Z\n'
                                      'cve,epss,percentile\nCVE-2099-91001,0.01,0.2\n').encode())
                return Opener({URL: body}).open(request, timeout)
        epss = EpssSource(Http('fictional', {}, Published(), resolver=public_resolver), self.store)
        sources = {'epss': epss, 'cvelist': Mock(), 'kev': Mock()}
        sources['cvelist'].poll.return_value = []
        sources['kev'].poll.return_value = []
        scheduler = Scheduler(self.engine, sources, self.clock, lambda line: None,
                              monotonic=lambda: self.clock().timestamp())
        return scheduler, calls

    def test_epss_hourly_until_publication_three_days_never_stale(self):
        scheduler, calls = self.epss_scheduler()
        start = self.clock()
        for minute in range(3 * 24 * 60 + 1):
            self.clock.now = start + timedelta(minutes=minute)
            scheduler.tick()
            self.assertEqual(assess('epss', self.store, self.clock(), self.config)[0], 'healthy')
            if (self.clock().hour, self.clock().minute) == (14, 30):
                self.assertEqual(self.store.connection.execute("SELECT value FROM cursors WHERE source='epss'").fetchone()[0], str(self.clock().date()))
        self.assertGreater(len(calls), 3)

    def test_epss_stuck_date_hourly_retries_still_stale_after_two_days(self):
        scheduler, calls = self.epss_scheduler(stuck=True)
        for hour in range(50):
            scheduler.tick()
            self.clock.now += timedelta(hours=1)
        self.assertEqual(len(calls), 50)
        state, detail = assess('epss', self.store, self.clock(), self.config)
        self.assertEqual((state, detail), ('unhealthy', 'Source content is stale'))

    def test_epss_today_sleeps_until_next_utc_day(self):
        self.clock.now = self.clock.now.replace(hour=14, minute=11)
        scheduler, calls = self.epss_scheduler()
        scheduler.tick()
        self.clock.now = self.clock.now.replace(hour=23, minute=59)
        scheduler.tick()
        self.assertEqual(len(calls), 1)
        self.clock.now += timedelta(minutes=1)
        scheduler.tick()
        self.assertEqual(len(calls), 2)

    def test_truncated_listing_must_not_prove_first(self):
        self.cve_cursor()
        last = release(12)
        source, opener = self.cve_source([last], [delta_zip()])
        next_page = RELEASES_URL + '?page=2'
        opener.routes[RELEASES_URL] = (json.dumps([last]).encode(), 200,
            {'Link': '<' + next_page + '>; rel="next"'})
        opener.routes[next_page] = (b'{"message":"Only the first 1000 results are available."}', 422, {})
        previous = {'tag_name': 'cve_2099-04-02_at_end_of_day', 'assets': [{
            'name': '2099-04-02_delta_CVEs_at_end_of_day.zip',
            'browser_download_url': 'https://archives.invalid/previous/delta'}]}
        opener.routes[RELEASES_URL + '/tags/' + previous['tag_name']] = json.dumps(previous).encode()
        listing, exhausted = source._listing('cve_2099-04-02_at_end_of_day', self.clock())
        self.assertFalse(exhausted)
        result, = source.poll(self.clock())
        self.engine.run_cycle([result])
        cursor = self.store.connection.execute("SELECT value, content_time FROM cursors WHERE source='cvelist'").fetchone()
        print(f'truncated listing: exhausted={exhausted}; empty midday={result.status.value}; cursor={tuple(cursor)}; health={assess("cvelist", self.store, self.clock(), self.config)}')
        self.assertNotEqual(result.status, FetchStatus.COMPLETE, 'Incomplete listing is not evidence that a release is first')
        # Exact midnight coverage is sufficient even without a complete listing;
        # a midnight tag attached to later coverage is not.
        for asset_hour, accepted in ((0, True), (2, False)):
            with self.subTest(asset_hour=asset_hour):
                midnight = release(0)
                midnight['assets'][0]['name'] = f'2099-04-03_delta_CVEs_at_{asset_hour:02d}00Z.zip'
                source, opener = self.cve_source([midnight], [delta_zip()])
                opener.routes[RELEASES_URL] = (json.dumps([midnight]).encode(), 200,
                    {'Link': '<' + next_page + '>; rel="next"'})
                opener.routes[next_page] = (b'{"message":"Only the first 1000 results are available."}', 422, {})
                opener.routes[RELEASES_URL + '/tags/' + previous['tag_name']] = json.dumps(previous).encode()
                result, = source.poll(self.clock())
                self.addCleanup(result.records.close)
                self.assertEqual(result.status == FetchStatus.COMPLETE, accepted)

    def test_crafted_midnight_tag_with_later_asset(self):
        self.cve_cursor()
        self.clock.now = self.clock.now.replace(hour=2, minute=1)
        crafted, earlier = release(0), release(1)
        crafted['assets'][0]['name'] = '2099-04-03_delta_CVEs_at_0200Z.zip'
        crafted['published_at'] = '2099-04-03T02:00:00Z'
        source, _ = self.cve_source([crafted, earlier], [delta_zip(), delta_zip((self.record,))])
        result, = source.poll(self.clock())
        self.engine.run_cycle([result])
        cursor = self.store.connection.execute("SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone()
        count = self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0]
        if result.status == FetchStatus.COMPLETE:
            self.assertEqual(source.poll(self.clock()), [])
            self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 0)
        print(f'crafted 0000 tag / 0200 asset: status={result.status.value}; cursor={tuple(cursor)}; records={count}; earlier 0100 has 1 record')
        self.assertNotEqual(result.status, FetchStatus.COMPLETE, 'Known earlier coverage must defeat the empty exception')
        # The other tag can be later while its asset covers an earlier hour.
        earlier['tag_name'] = 'cve_2099-04-03_0200Z'
        source, _ = self.cve_source([crafted, earlier], [delta_zip(), delta_zip((self.record,))])
        result, = source.poll(self.clock())
        self.addCleanup(result.records.close)
        self.assertNotEqual(result.status, FetchStatus.COMPLETE)

    def test_epss_restart_today_must_wait_until_midnight(self):
        self.clock.now = self.clock.now.replace(hour=14, minute=11)
        scheduler, calls = self.epss_scheduler()
        scheduler.tick()
        self.assertEqual(len(calls), 1)
        self.clock.now += timedelta(minutes=1)
        restarted = Scheduler(self.restart(self.watches), scheduler.sources, self.clock,
                              lambda _: None, monotonic=lambda: self.clock().timestamp())
        restarted.tick()
        print(f'today cursor retained; restart 1 minute later: requests={len(calls)} (expected 1 through midnight)')
        self.assertEqual(len(calls), 1, 'A stored current date must prevent another same-day poll after restart')
        midnight = self.clock().replace(hour=0, minute=0, second=0) + timedelta(days=1)
        self.assertEqual(restarted.next_poll['epss'], midnight.timestamp())
        self.clock.now = midnight - timedelta(seconds=1)
        restarted.tick()
        self.assertEqual(len(calls), 1)
        self.clock.now = midnight
        restarted.tick()
        self.assertEqual(len(calls), 2)

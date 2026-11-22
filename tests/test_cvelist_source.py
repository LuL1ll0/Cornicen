from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat
import tempfile
import tracemalloc
import unittest

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.store import Store
from tests.replay.harness import FakeClock, RecordingNotifier, utc
from tests.source_helpers import public_resolver, Opener, RAW, archive, release

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)
EMPTY_DELTA = b'PK\x05\x06' + b'\x00' * 18
CAP_URL = RELEASES_URL + '?page=2'
CAP_RESPONSE = (b'{"message":"Only the first 1000 results are available"}', 422, {})


def hourly_release(day, hour, published):
    candidate = release(day, hour)
    candidate['published_at'] = f'2026-11-{day:02d}T{published}Z'
    candidate['assets'].append({'name': 'release_notes.md',
                                'browser_download_url': f'https://github.com/{candidate["tag_name"]}/notes'})
    return candidate


def capped_listing(releases):
    return (json.dumps(releases).encode(), 200, {'Link': f'<{CAP_URL}>; rel="next"'})


class CveListTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.store = Store(str(Path(self.directory.name) / 'state.db'))
        self.store.migrate()
        # These archive/cursor tests start after the independent projection pass.
        self.store.set_meta('applied_projection_revision', '2')
        self.addCleanup(self.store.connection.close)

    def source(self, releases, **routes):
        mapping = {RELEASES_URL: json.dumps(releases).encode()}
        mapping.update(routes)
        opener = Opener(mapping)
        return CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store), opener

    def cursor(self, tag):
        self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                      ('cvelist', tag, NOW.isoformat()))

    def rollover_engine(self, hour=23):
        clock = FakeClock(utc('2026-11-20T23:30:00Z'))
        config = Config(':memory:', Path('unused'), None, 'https://ntfy.invalid', 'test', None)
        engine = Engine(self.store, (), AliasMap.load(False), config, clock, RecordingNotifier(clock))
        engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                       release(20, hour)['tag_name'], utc(f'2026-11-20T{hour:02d}:00:00Z'))])
        return engine

    def test_utc_rollover_stays_healthy(self):
        yesterday = hourly_release(20, 23, '23:27:58')
        eod = {'tag_name': 'cve_2026-11-20_at_end_of_day', 'published_at': '2026-11-21T00:37:54Z',
               'assets': [{'name': '2026-11-20_delta_CVEs_at_end_of_day.zip',
                           'browser_download_url': 'https://github.com/20/eod'},
                          {'name': 'release_notes.md', 'browser_download_url': 'https://github.com/20/notes'}]}
        hours = [hourly_release(21, hour, published) for hour, published in enumerate(
            ('00:39:07', '01:29:14', '02:25:48', '03:23:20', '04:33:00'))]
        eod_url = eod['assets'][0]['browser_download_url']
        delta_urls = [candidate['assets'][1]['browser_download_url'] for candidate in hours]
        source, opener = self.source([], **{CAP_URL: CAP_RESPONSE, eod_url: archive(),
            **dict.fromkeys(delta_urls[:3], EMPTY_DELTA), delta_urls[3]: archive(count=2)})
        engine = self.rollover_engine()
        cursor = yesterday['tag_name']
        for at, expected, downloads in (
            ('00:08', [], []),
            ('00:40', [eod, hours[0]], [eod_url, delta_urls[0]]),
            ('01:08', [], []),
            ('02:08', [hours[1]], [delta_urls[1]]),
            ('03:08', [hours[2]], [delta_urls[2]]),
            ('04:08', [hours[3]], [delta_urls[3]]),
        ):
            if expected:
                cursor = expected[-1]['tag_name']
            with self.subTest(poll=at):
                engine.clock.now = utc(f'2026-11-21T{at}:00Z')
                visible = [candidate for candidate in reversed([yesterday, *hours])
                           if utc(candidate['published_at']) <= engine.clock.now]
                opener.routes[RELEASES_URL] = capped_listing(visible)
                if utc(eod['published_at']) <= engine.clock.now:
                    opener.routes[RELEASES_URL + '/tags/' + eod['tag_name']] = json.dumps(eod).encode()
                opener.requests.clear()
                results = source.poll(engine.clock.now)
                for result in results:
                    if hasattr(result.records, 'close'):
                        self.addCleanup(result.records.close)
                report = engine.run_cycle(results)
                state, detail = assess('cvelist', self.store, engine.clock.now, engine.config)
                self.assertEqual(state, 'healthy', detail)
                self.assertEqual(report.health_changes, [])
                self.assertEqual([result.cursor for result in results], [r['tag_name'] for r in expected])
                self.assertEqual([request.full_url for request in opener.requests
                                  if request.full_url in [eod_url, *delta_urls]], downloads)
                self.assertEqual(self.store.connection.execute(
                    "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], cursor)
                if at == '00:40':
                    self.assertIsNotNone(engine._record('CVE-2026-10000'))
        self.assertIsNotNone(engine._record('CVE-2026-10001'))
        self.assertEqual(engine.notifier.delivered, [])

    def test_eod_wait_ingests_yesterdays_final_hour_and_stays_healthy(self):
        yesterday = hourly_release(20, 23, '23:27:58')
        today = hourly_release(21, 0, '00:39:07')
        eod_url = 'https://github.com/20/eod'
        eod = {'tag_name': 'cve_2026-11-20_at_end_of_day', 'published_at': '2026-11-21T00:37:54Z',
               'assets': [{'name': '2026-11-20_delta_CVEs_at_end_of_day.zip',
                           'browser_download_url': eod_url}]}
        eod_tag_url = RELEASES_URL + '/tags/' + eod['tag_name']
        yesterday_url = yesterday['assets'][1]['browser_download_url']
        today_url = today['assets'][1]['browser_download_url']
        source, opener = self.source([], **{
            RELEASES_URL: capped_listing([yesterday]), CAP_URL: CAP_RESPONSE,
            yesterday_url: archive(), eod_url: archive(count=2), today_url: EMPTY_DELTA,
        })
        engine = self.rollover_engine(hour=22)

        for at, expected, downloads in (
            ('00:08', [yesterday], [yesterday_url]),
            ('01:08', [eod, today], [eod_url, today_url]),
        ):
            with self.subTest(poll=at):
                engine.clock.now = utc(f'2026-11-21T{at}:00Z')
                if utc(eod['published_at']) <= engine.clock.now:
                    opener.routes[eod_tag_url] = json.dumps(eod).encode()
                    opener.routes[RELEASES_URL] = capped_listing([today, yesterday])
                opener.requests.clear()
                results = source.poll(engine.clock.now)
                for result in results:
                    self.addCleanup(result.records.close)
                report = engine.run_cycle(results)
                self.assertEqual(report.health_changes, [])
                assessed_at = utc('2026-11-21T01:05:00Z') if at == '00:08' else engine.clock.now
                state, detail = assess('cvelist', self.store, assessed_at, engine.config)
                self.assertEqual(state, 'healthy', detail)
                self.assertIn(eod_tag_url, [request.full_url for request in opener.requests])
                self.assertEqual([result.cursor for result in results], [r['tag_name'] for r in expected])
                self.assertEqual([request.full_url for request in opener.requests
                                  if request.full_url in (yesterday_url, eod_url, today_url)], downloads)
                self.assertEqual(self.store.connection.execute(
                    "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], expected[-1]['tag_name'])
                self.assertIsNone(self.store.get_meta('reconcile_at'))
                self.assertEqual(engine.notifier.delivered, [])

    def test_eod_wait_catches_up_through_yesterdays_latest_hour(self):
        self.cursor(release(18, 22)['tag_name'])
        yesterday, today = release(20), release(21, 0)
        eods = [
            {'tag_name': f'cve_2026-11-{day}_at_end_of_day',
             'assets': [{'name': f'2026-11-{day}_delta_CVEs_at_end_of_day.zip',
                         'browser_download_url': f'https://github.com/{day}/eod'}]}
            for day in (18, 19)
        ]
        expected_urls = [r['assets'][-1]['browser_download_url'] for r in (*eods, yesterday)]
        today_url = today['assets'][1]['browser_download_url']
        source, opener = self.source([], **{
            RELEASES_URL: capped_listing([today, yesterday, release(20, 22)]), CAP_URL: CAP_RESPONSE,
            **{RELEASES_URL + '/tags/' + r['tag_name']: json.dumps(r).encode() for r in eods},
            **dict.fromkeys([*expected_urls, today_url], archive()),
        })
        results = source.poll(utc('2026-11-21T00:10:00Z'))
        for result in results:
            self.addCleanup(result.records.close)
        self.assertEqual([r.cursor for r in results], [r['tag_name'] for r in (*eods, yesterday)])
        self.assertTrue(all(r.status == FetchStatus.COMPLETE and r.origin == Origin.DELTA for r in results))
        requested = [request.full_url for request in opener.requests]
        self.assertIn(RELEASES_URL + '/tags/cve_2026-11-20_at_end_of_day', requested)
        self.assertEqual([url for url in requested if url in [*expected_urls, today_url]], expected_urls)
        self.assertIsNone(self.store.get_meta('reconcile_at'))

    def test_eod_wait_blocks_todays_delta_even_when_listed(self):
        yesterday, today = release(20), hourly_release(21, 0, '00:39:07')
        engine = self.rollover_engine()
        engine.clock.now = utc('2026-11-21T01:59:59Z')
        for capped in (False, True):
            with self.subTest(capped=capped):
                visible = [today, yesterday]
                source, opener = self.source(visible, **{
                    RELEASES_URL: capped_listing(visible) if capped else json.dumps(visible).encode(),
                    CAP_URL: CAP_RESPONSE,
                    today['assets'][0]['browser_download_url']: archive(snapshot=True),
                    today['assets'][1]['browser_download_url']: EMPTY_DELTA,
                })
                results = source.poll(engine.clock.now)
                for result in results:
                    if hasattr(result.records, 'close'):
                        self.addCleanup(result.records.close)
                self.assertEqual(results, [])
                self.assertEqual(opener.requests[-1].full_url,
                                 RELEASES_URL + '/tags/cve_2026-11-20_at_end_of_day')
                self.assertIsNone(self.store.get_meta('reconcile_at'))
                self.assertEqual(engine.run_cycle(results).health_changes, [])
                self.assertEqual(assess('cvelist', self.store, engine.clock.now, engine.config)[0], 'healthy')

    def test_missing_eod_at_grace_expiry_is_unhealthy(self):
        yesterday = release(20)
        source, _ = self.source([], **{RELEASES_URL: capped_listing([yesterday]), CAP_URL: CAP_RESPONSE})
        engine = self.rollover_engine()
        engine.clock.now = utc('2026-11-21T02:00:00Z')
        report = engine.run_cycle(source.poll(engine.clock.now))
        self.assertEqual(report.health_changes, [('cvelist', 'unhealthy')])
        self.assertEqual(self.store.get_meta('last_error:cvelist'),
                         'ValueError: No full snapshot cutoff covers 2026-11-20')

    def test_zero_member_delta_is_complete_with_three_assets(self):
        self.cursor('cve_2026-11-03_0100Z')
        latest = hourly_release(3, 22, '22:25:48')
        source, _ = self.source([latest], **{latest['assets'][1]['browser_download_url']: EMPTY_DELTA})
        result, = source.poll(NOW)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
        self.assertEqual(len(result.records), 0)

    def test_oversized_zero_member_delta_is_partial(self):
        self.cursor('cve_2026-11-03_0100Z')
        latest = hourly_release(3, 22, '22:25:48')
        oversized = bytes(1025 - len(EMPTY_DELTA)) + EMPTY_DELTA
        source, _ = self.source([latest], **{latest['assets'][1]['browser_download_url']: oversized})
        result, = source.poll(NOW)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertIn('Delta has no recognised records or explicit zero-change manifest', result.errors)

    def test_empty_delta_after_committed_same_day_records_is_partial(self):
        earlier, latest = hourly_release(21, 3, '03:23:20'), hourly_release(21, 4, '04:33:00')
        engine = self.rollover_engine()
        engine.clock.now = utc('2026-11-21T03:08:00Z')
        engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                       'cve_2026-11-21_0200Z', utc('2026-11-21T02:00:00Z'))])
        engine.clock.now = utc('2026-11-21T04:08:00Z')
        source, opener = self.source([earlier], **{earlier['assets'][1]['browser_download_url']: archive(),
                                                  latest['assets'][1]['browser_download_url']: EMPTY_DELTA})
        first, = source.poll(engine.clock.now)
        self.addCleanup(first.records.close)
        self.assertEqual(first.status, FetchStatus.COMPLETE, first.errors)
        engine.run_cycle([first])
        self.assertIsNotNone(engine._record('CVE-2026-10000'))

        opener.routes[RELEASES_URL] = json.dumps([latest]).encode()
        engine.clock.now = utc('2026-11-21T05:08:00Z')
        result, = CveListSource(source.http, self.store).poll(engine.clock.now)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertIn('same-day delta had records', ' '.join(result.errors))
        engine.run_cycle([result])
        self.assertEqual(self.store.connection.execute(
            "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], earlier['tag_name'])

    def test_eocd_claiming_members_with_no_central_directory_is_bad_zip(self):
        self.cursor('cve_2026-11-03_0100Z')
        latest = hourly_release(3, 22, '22:25:48')
        bad_zip = EMPTY_DELTA[:8] + b'\x01\x00\x01\x00' + EMPTY_DELTA[12:]
        source, _ = self.source([latest], **{latest['assets'][1]['browser_download_url']: bad_zip})
        result, = source.poll(NOW)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('BadZipFile', ' '.join(result.errors))

    def test_snapshot_streams(self):
        r = release(3)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: archive(
            5000, snapshot=True, padding=16000), r['assets'][1]['browser_download_url']: archive()})
        tracemalloc.start()
        try:
            results = source.poll(NOW)
            self.assertEqual([r.origin for r in results], [Origin.SNAPSHOT, Origin.DELTA])
            self.assertEqual(results[0].status, FetchStatus.COMPLETE)
            self.assertEqual(sum(1 for _ in results[0].records), 5000)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLess(peak, 64 * 1024 * 1024)
        finally:
            tracemalloc.stop()
        self.assertFalse(list(Path(self.directory.name).glob('*.zip')))
        self.assertIsNone(self.store.connection.execute('SELECT * FROM cursors').fetchone())

    def test_catch_up_three_missed_days(self):
        self.cursor(release(1, 1)['tag_name'])
        releases = [release(3, 12), release(2, 23), release(1, 23), release(2, 12)]
        source, opener = self.source(releases, **{
            r['assets'][1]['browser_download_url']: archive() for r in releases})
        results = source.poll(NOW)
        self.assertEqual([r.cursor for r in results], [release(1)['tag_name'], release(2)['tag_name'], release(3,12)['tag_name']])
        self.assertTrue(all(r.origin == Origin.DELTA for r in results))
        self.assertEqual(len(opener.requests), 6)

    def test_delta_error_list_is_partial(self):
        self.cursor(release(3, 1)['tag_name'])
        r = release(3)
        source, _ = self.source([r], **{r['assets'][1]['browser_download_url']: archive(errors=True)})
        result, = source.poll(NOW)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertEqual(len(result.records), 1)
        self.assertIn('CVE-2026-88888', ' '.join(result.errors))

    def test_malformed_records_are_isolated_and_paths_not_extracted(self):
        self.cursor(release(3, 1)['tag_name'])
        r = release(3)
        source, _ = self.source([r], **{r['assets'][1]['browser_download_url']: archive(bad=True)})
        result, = source.poll(NOW)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(len(result.errors), 2)
        files = list(Path(self.directory.name).iterdir())
        self.assertEqual(sorted(p.name for p in files), ['state.db', 'state.db-shm', 'state.db-wal'])
        for path in files:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rate_limited_is_failed_and_deferred(self):
        opener = Opener({RELEASES_URL: (b'', 403, {'X-RateLimit-Remaining': '0',
                                                'X-RateLimit-Reset': str(int((NOW+timedelta(hours=1)).timestamp()))})})
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        self.assertEqual(source.poll(NOW)[0].status, FetchStatus.FAILED)
        # Deferral survives recreation, as a scheduler restart must not hammer GitHub.
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        self.assertEqual(source.poll(NOW+timedelta(minutes=59)), [])
        self.assertEqual(len(opener.requests), 1)
        self.assertIsNone(self.store.connection.execute('SELECT * FROM cursors').fetchone())
        source.poll(NOW+timedelta(hours=1))
        self.assertEqual(len(opener.requests), 2)

    def test_missing_day_reconciles(self):
        self.cursor('cve_2026-10-31_2300Z')
        r = release(3)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: archive(snapshot=True),
                                      r['assets'][1]['browser_download_url']: archive()})
        results = source.poll(NOW)
        self.assertEqual(results[0].origin, Origin.SNAPSHOT)
        self.assertEqual(self.store.get_meta('reconcile_at'), NOW.isoformat())

    def test_saved_release_listing(self):
        releases = json.loads((RAW / 'github_releases_sample.json').read_text())
        latest = max(releases, key=lambda r: r['tag_name'])
        source, _ = self.source(releases, **{
            a['browser_download_url']: archive(snapshot='all_CVEs' in a['name'])
            for a in latest['assets'] if a['name'].endswith('.zip')})
        self.assertEqual(source.poll(NOW)[-1].cursor, latest['tag_name'])

    def test_reconcile_records_are_new_after_baseline(self):
        from cornicen.config import Config
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from cornicen.watchlist import load_watchlist_text
        from tests.replay.harness import FakeClock, RecordingNotifier, load_timeline
        from cornicen.model import IngestResult
        rows = load_timeline('same_cycle_coalesce')
        watches = load_watchlist_text(rows[0]['watchlist'])
        record = next(row['ingest']['records'][0] for row in rows if row.get('ingest', {}).get('records'))
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('reconcile_at', NOW.isoformat())
        clock = FakeClock(NOW)
        config = Config(':memory:', Path('unused'), None, 'https://ntfy.test', 'test', None)
        engine = Engine(self.store, watches, AliasMap.load(False), config, clock, RecordingNotifier(clock))
        report = engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.SNAPSHOT,
                                                release(3)['tag_name'], NOW, (record,))])
        self.assertIn('service|CVE-2025-54831|new match|1', report.events)

    def test_pagination_covers_all_missed_days(self):
        self.cursor(release(1, 1)['tag_name'])
        first, second = release(3), release(2)
        third = release(1)
        next_url = RELEASES_URL + '?page=2'
        opener = Opener({RELEASES_URL: (json.dumps([first, second]).encode(), 200,
                                      {'Link': f'<{next_url}>; rel="next"'}),
                         next_url: json.dumps([third]).encode(),
                         **{r['assets'][1]['browser_download_url']: archive() for r in (first, second, third)}})
        results = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store).poll(NOW)
        self.assertEqual([r.cursor for r in results], [r['tag_name'] for r in (third, second, first)])

    def test_incomplete_day_stops_before_later_days(self):
        self.cursor(release(1, 1)['tag_name'])
        first, second = release(1), release(2)
        source, opener = self.source([second, first], **{
            first['assets'][1]['browser_download_url']: archive(errors=True)})
        results = source.poll(NOW)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, FetchStatus.PARTIAL)
        self.assertEqual(len(opener.requests), 4)

    def test_bootstrap_snapshot_does_not_skip_failed_delta(self):
        r = release(3)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: archive(snapshot=True),
                                      r['assets'][1]['browser_download_url']: (b'', 500, {})})
        snapshot, delta = source.poll(NOW)
        self.assertEqual(snapshot.status, FetchStatus.COMPLETE)
        self.assertEqual(snapshot.cursor, r['tag_name'])
        self.assertEqual(delta.status, FetchStatus.FAILED)

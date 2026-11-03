"""Offline regressions for release tags whose asset clocks differ."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.store import Store
from tests import test_cvelist_source as sources, test_engine as engines
from tests.source_helpers import Opener, RAW, archive, public_resolver, release
from tests.test_fix_f import delta

NOW = datetime(2026, 11, 3, 21, 16, tzinfo=timezone.utc)


def with_delta(hour, asset_time):
    candidate = release(3, hour)
    candidate['assets'][1]['name'] = f'2026-11-03_delta_CVEs_at_{asset_time}.zip'
    return candidate


class AssetSelectionTests(unittest.TestCase):
    setUp = sources.CveListTests.setUp
    source = sources.CveListTests.source
    cursor = sources.CveListTests.cursor

    def test_delta_accepts_two_hour_boundary_and_minutes(self):
        self.cursor(release(3, 17)['tag_name'])
        for asset_time, stamp in (('1800Z', '18:00:00'), ('2200Z', '22:00:00'),
                                  ('2137Z', '21:37:00')):
            with self.subTest(asset_time=asset_time):
                candidate = with_delta(20, asset_time)
                url = candidate['assets'][1]['browser_download_url']
                source, opener = self.source([candidate], **{url: archive()})
                result, = source.poll(sources.NOW)
                self.addCleanup(result.records.close)
                self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
                self.assertEqual(result.cursor, candidate['tag_name'])
                self.assertEqual(result.content_time.isoformat(), f'2026-11-03T{stamp}+00:00')
                self.assertEqual([r.full_url for r in opener.requests], [RELEASES_URL, url])

    def test_suspicious_delta_clock_holds_cursor_without_download(self):
        self.cursor(release(3, 17)['tag_name'])
        for asset_time in ('1759Z', '2201Z', '0000Z', 'end_of_day'):
            with self.subTest(asset_time=asset_time):
                candidate = with_delta(20, asset_time)
                source, opener = self.source([candidate])
                result, = source.poll(sources.NOW)
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertIn('more than 2 hours', '; '.join(result.errors))
                self.assertIsNone(result.cursor)
                self.assertEqual([r.full_url for r in opener.requests], [RELEASES_URL])
                self.assertEqual(self.store.connection.execute(
                    "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0],
                    release(3, 17)['tag_name'])

    def test_delta_requires_one_exact_same_date_match(self):
        self.cursor(release(3, 17)['tag_name'])
        for names in ([], ['2026-11-02_delta_CVEs_at_2000Z.zip'],
                      ['prefix2026-11-03_delta_CVEs_at_2000Z.zip'],
                      ['2026-11-03_delta_CVEs_at_2000Z.zip.bak'],
                      ['2026-11-03_delta_CVEs_at_2000Z.zip\n'],
                      ['2026-11-03_delta_CVEs_at_2000Z.zip'] * 2,
                      ['2026-11-03_delta_CVEs_at_2000Z.zip',
                       '2026-11-03_delta_CVEs_at_2100Z.zip']):
            with self.subTest(names=names):
                candidate = release(3, 20)
                candidate['assets'] = [{'name': name, 'browser_download_url':
                                        f'https://github.com/asset/{index}'}
                                       for index, name in enumerate(names)]
                source, opener = self.source([candidate], **{
                    a['browser_download_url']: archive() for a in candidate['assets']})
                result, = source.poll(sources.NOW)
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertIsNone(result.cursor)
                self.assertTrue(result.errors)
                self.assertEqual(len(opener.requests), 1)

    def test_invalid_delta_clock_is_incomplete(self):
        self.cursor(release(3, 17)['tag_name'])
        for asset_time in ('2400Z', '2060Z', '9999Z'):
            with self.subTest(asset_time=asset_time):
                source, opener = self.source([with_delta(20, asset_time)])
                result, = source.poll(sources.NOW)
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertTrue(result.errors)
                self.assertEqual(len(opener.requests), 1)

    def test_other_date_assets_and_notes_do_not_create_ambiguity(self):
        self.cursor(release(3, 17)['tag_name'])
        candidate = with_delta(20, '2100Z')
        candidate['assets'] += [{'name': name, 'browser_download_url': 'https://github.com/unused'}
                                for name in ('2026-11-02_delta_CVEs_at_2100Z.zip',
                                             'release_notes.md')]
        url = candidate['assets'][1]['browser_download_url']
        source, opener = self.source([candidate], **{url: archive()})
        result, = source.poll(sources.NOW)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
        self.assertEqual(opener.requests[-1].full_url, url)

    def test_daily_cumulative_delta_is_ordered_by_asset_clock(self):
        self.cursor(release(3, 17)['tag_name'])
        newer_asset, newer_tag = with_delta(19, '2100Z'), with_delta(20, '2000Z')
        for listing in ([newer_tag, newer_asset], [newer_asset, newer_tag]):
            with self.subTest(tags=[r['tag_name'] for r in listing]):
                source, opener = self.source(listing, **{
                    r['assets'][1]['browser_download_url']: archive() for r in listing})
                result, = source.poll(sources.NOW)
                self.addCleanup(result.records.close)
                self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
                self.assertEqual(result.cursor, newer_asset['tag_name'])
                self.assertEqual(result.content_time.hour, 21)
                self.assertEqual(opener.requests[-1].full_url,
                                 newer_asset['assets'][1]['browser_download_url'])

    def test_older_incomplete_releases_do_not_block_newer_cumulative_delta(self):
        self.cursor(release(3, 17)['tag_name'])
        older_day, older_hour, latest = release(2, 20), release(3, 18), with_delta(20, '2100Z')
        older_day['assets'] = older_hour['assets'] = []
        url = latest['assets'][1]['browser_download_url']
        source, opener = self.source([latest, older_hour, older_day], **{url: archive()})
        result, = source.poll(sources.NOW)
        self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
        self.addCleanup(result.records.close)
        self.assertEqual(result.cursor, latest['tag_name'])
        self.assertEqual([r.full_url for r in opener.requests], [RELEASES_URL, url])

    def test_end_of_day_asset_sorts_after_2359(self):
        self.cursor(release(3, 20)['tag_name'])
        last_minute, final = with_delta(23, '2359Z'), with_delta(22, 'end_of_day')
        source, opener = self.source([last_minute, final], **{
            r['assets'][1]['browser_download_url']: archive() for r in (last_minute, final)})
        result, = source.poll(sources.NOW)
        self.addCleanup(result.records.close)
        self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
        self.assertEqual(result.cursor, final['tag_name'])
        self.assertEqual(result.content_time.isoformat(), '2026-11-03T23:59:59+00:00')
        self.assertEqual(opener.requests[-1].full_url, final['assets'][1]['browser_download_url'])

    def test_direct_end_of_day_tag_still_orders_by_asset_clock(self):
        self.cursor(release(2, 20)['tag_name'])
        hourly, final, today = release(2, 23), release(2, 23), release(3, 20)
        hourly['assets'][1]['name'] = '2026-11-02_delta_CVEs_at_2359Z.zip'
        final['tag_name'] = 'cve_2026-11-02_at_end_of_day'
        final['assets'][1] = {'name': '2026-11-02_delta_CVEs_at_2300Z.zip',
                              'browser_download_url': 'https://github.com/final/delta'}
        source, opener = self.source([today, hourly], **{
            RELEASES_URL + '/tags/' + final['tag_name']: json.dumps(final).encode(),
            **{r['assets'][1]['browser_download_url']: archive() for r in (hourly, final, today)}})
        results = source.poll(sources.NOW)
        for result in results:
            self.addCleanup(result.records.close)
        self.assertEqual([r.cursor for r in results], [hourly['tag_name'], today['tag_name']])
        self.assertNotIn(final['assets'][1]['browser_download_url'],
                         [r.full_url for r in opener.requests])

    def test_snapshot_requires_one_exact_same_date_match(self):
        for names in ([], ['2026-11-02_all_CVEs_at_midnight.zip.zip'],
                      ['prefix2026-11-03_all_CVEs_at_midnight.zip.zip'],
                      ['2026-11-03_all_CVEs_at_midnight.zip.zip.bak'],
                      ['2026-11-03_all_CVEs_at_midnight.zip.zip\n'],
                      ['2026-11-03_all_CVEs_at_midnight.zip.zip'] * 2):
            with self.subTest(names=names):
                candidate = release(3, 20)
                candidate['assets'] = candidate['assets'][1:] + [
                    {'name': name, 'browser_download_url': f'https://github.com/snapshot/{index}'}
                    for index, name in enumerate(names)]
                source, opener = self.source([candidate], **{
                    a['browser_download_url']: archive(snapshot=True) for a in candidate['assets'][1:]})
                result, = source.poll(sources.NOW)
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertIsNone(result.cursor)
                self.assertEqual(len(opener.requests), 1)

    def test_snapshot_ignores_other_dates_and_keeps_midnight_cutoff(self):
        candidate = with_delta(20, '2100Z')
        decoy = deepcopy(candidate['assets'][0])
        decoy.update(name='2026-11-02_all_CVEs_at_midnight.zip.zip',
                     browser_download_url='https://github.com/unused')
        candidate['assets'].insert(0, decoy)
        source, opener = self.source([candidate], **{
            candidate['assets'][1]['browser_download_url']: archive(snapshot=True),
            candidate['assets'][2]['browser_download_url']: archive()})
        snapshot, delta_result = source.poll(sources.NOW)
        self.addCleanup(snapshot.records.close)
        self.addCleanup(delta_result.records.close)
        self.assertEqual([snapshot.status, delta_result.status], [FetchStatus.COMPLETE] * 2)
        self.assertEqual(snapshot.content_time.isoformat(), '2026-11-03T00:00:00+00:00')
        self.assertEqual(snapshot.cursor, candidate['tag_name'])
        self.assertNotIn(decoy['browser_download_url'], [r.full_url for r in opener.requests])


class RealListingRecoveryTests(unittest.TestCase):
    def setUp(self):
        engines.EngineTests.setUp(self)
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'state.db'
        self.store = Store(str(self.path))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.clock.now = NOW
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config,
                             self.clock, self.notifier)
        cutoff = NOW.replace(hour=0, minute=0)
        cursor_time = NOW.replace(hour=19, minute=0)
        initial = release(3, 19)['tag_name']
        self.engine.run_cycle([
            replace(self.baseline[0], cursor=initial, content_time=cutoff),
            replace(self.baseline[1], content_time=NOW),
            replace(self.baseline[2], content_time=NOW, epss_date=NOW.date(),
                    epss={self.record['cveMetadata']['cveId']: (.5, .99)}),
            IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA, initial, cursor_time)])
        self.notifier.delivered.clear()
        self.listing = json.loads((RAW / 'github_releases_tag_asset_mismatch.json').read_text())
        self.latest = self.listing[0]
        self.url = next(a['browser_download_url'] for a in self.latest['assets']
                        if a['name'] == '2026-11-03_delta_CVEs_at_2100Z.zip')
        self.opener = Opener({RELEASES_URL: json.dumps(self.listing).encode(),
                              self.url: delta([self.record])})

    def poll(self):
        source = CveListSource(Http('test', {}, self.opener, resolver=public_resolver,
                                    data_dir=self.path.parent), self.store)
        results = source.poll(self.clock())
        self.engine.run_cycle(results)
        for result in results:
            if hasattr(result.records, 'close'):
                result.records.close()
        return results

    def assert_recovered_once(self):
        with patch.object(self.store, 'put_record', wraps=self.store.put_record) as put_record:
            result, = self.poll()
            self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors)
            self.assertEqual(result.cursor, 'cve_2026-11-03_2000Z')
            self.assertEqual(result.content_time, NOW.replace(hour=21, minute=0))
            self.clock.now += timedelta(hours=1)
            self.assertEqual(self.poll(), [])
            self.assertEqual([call.args[0] for call in put_record.call_args_list],
                             [self.record['cveMetadata']['cveId']])
        row = self.store.connection.execute(
            "SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone()
        self.assertEqual(tuple(row), ('cve_2026-11-03_2000Z', '2026-11-03T21:00:00+00:00'))
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 1)
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'healthy')
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'healthy')
        self.assertEqual(sum(r.full_url == self.url for r in self.opener.requests), 1)
        self.assertEqual(self.store.get_meta('committed_cve:delta:cve_2026-11-03_2000Z'), '1')
        self.assertEqual([(n['record'], n['reasons']) for n in self.notifier.delivered if n['watch']],
                         [(self.record['cveMetadata']['cveId'], ['new match'])])

    def test_real_2116_listing_ingests_once_and_advances_tag_cursor(self):
        self.assert_recovered_once()

    def test_existing_unhealthy_database_recovers_on_next_poll(self):
        self.engine.run_cycle([IngestResult(
            'cvelist', FetchStatus.FAILED, Origin.DELTA, None, None,
            errors=('ValueError: Required release asset missing',))])
        self.assertEqual(assess('cvelist', self.store, NOW, self.config)[0], 'unhealthy')
        self.assertIn('Required release asset missing', self.store.get_meta('last_error:cvelist'))
        self.store.connection.close()
        self.store = Store(str(self.path))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.engine = Engine(self.store, self.watches, self.engine.aliases, self.config,
                             self.clock, self.notifier)
        self.assert_recovered_once()
        self.assertIsNone(self.store.get_meta('last_error:cvelist'))
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM retry_queue WHERE source='cvelist'").fetchone()[0], 0)
        self.assertEqual([n['reasons'] for n in self.notifier.delivered
                          if n['record'] == 'cvelist'], [['unhealthy'], ['healthy']])

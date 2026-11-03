"""Offline regressions for the Task 6 rejection review."""

from datetime import timedelta
from email.utils import format_datetime
import io
import json
import unittest
import warnings
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_STORED

from cornicen.fetch import Http
from cornicen.health import assess
from cornicen.model import FetchStatus, Origin
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.sources.kev import KevSource, URL as KEV_URL
from tests.source_helpers import public_resolver, Opener, RAW, archive, release
from tests import test_cvelist_source as cve_tests

NOW = cve_tests.NOW
from tests.test_health import CONFIG


def zipped(entries, *, snapshot=False, compression=ZIP_STORED):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with ZipFile(buffer, 'w', compression) as target:
            for name, data in entries:
                target.writestr(name, data)
    if snapshot:
        return zipped([('snapshot.zip', buffer.getvalue())])
    return buffer.getvalue()


def record(number=10000, **extra):
    return json.dumps({'cveMetadata': {'cveId': f'CVE-2026-{number}', 'state': 'PUBLISHED'}, 'containers': {'cna': {}}, **extra})


# Reuse the source setup helpers without inheriting its tests a second time.
class Task6Regressions(unittest.TestCase):
    setUp = cve_tests.CveListTests.setUp
    source = cve_tests.CveListTests.source
    cursor = cve_tests.CveListTests.cursor

    def delta(self, data):
        self.store.connection.execute('DELETE FROM cursors')
        self.cursor(release(3, 1)['tag_name'])
        r = release(3)
        source, _ = self.source([r], **{r['assets'][1]['browser_download_url']: data})
        return source.poll(NOW)[0]

    def test_listing_reads_cursor_day_tail_and_bootstrap_page_one(self):
        for bootstrap in (False, True):
            with self.subTest(bootstrap=bootstrap):
                self.store.connection.execute('DELETE FROM cursors')
                if not bootstrap:
                    self.cursor(release(1, 1)['tag_name'])
                first = [release(2), release(1, 1)]
                tail = [release(1), release(3)]
                next_url = RELEASES_URL + '?page=2'
                routes = {RELEASES_URL: (json.dumps(first).encode(), 200,
                          {'Link': f'<{next_url}>; rel="next"'}),
                          next_url: json.dumps(tail).encode()}
                for r in first + tail:
                    for asset in r['assets']:
                        routes[asset['browser_download_url']] = archive(snapshot='all_CVEs' in asset['name'])
                opener = Opener(routes)
                results = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store).poll(NOW)
                expected = [release(2)['tag_name']] * 2 if bootstrap else [release(n)['tag_name'] for n in (1, 2, 3)]
                self.assertEqual([r.cursor for r in results], expected)
                self.assertEqual(next_url in [r.full_url for r in opener.requests], not bootstrap)

    def test_listing_page_cap_is_failed(self):
        self.cursor(release(1, 1)['tag_name'])
        routes = {}
        for n in range(1, 52):
            url = RELEASES_URL if n == 1 else RELEASES_URL + f'?page={n}'
            routes[url] = (json.dumps([release(3)]).encode(), 200,
                           {'Link': f'<{RELEASES_URL}?page={n+1}>; rel="next"'} if n < 51 else {})
        opener = Opener(routes)
        result, = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store).poll(NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertEqual(len(opener.requests), 50)
        self.assertIn('pagination', ' '.join(result.errors).lower())

    def test_unexpected_record_paths_are_partial(self):
        for snapshot in (False, True):
            root = 'cves' if snapshot else 'deltaCves'
            good = 'cves/2026/10xxx/CVE-2026-10000.json' if snapshot else 'deltaCves/CVE-2026-10000.json'
            for bad in (f'{root}/CVE-2026-10001.txt', f'{root}/subdir/CVE-2026-10001.json',
                        f'{root}/unexpected/', f'{root}/bad.json'):
                with self.subTest(snapshot=snapshot, path=bad):
                    data = zipped([(good, record()), (bad, record(10001)), ('README', 'ignored')], snapshot=snapshot)
                    r = release(3)
                    source, _ = self.source([r], **{r['assets'][int(not snapshot)]['browser_download_url']: data})
                    result = source._archive(r, Origin.SNAPSHOT if snapshot else Origin.DELTA, NOW)
                    self.assertEqual(result.status, FetchStatus.PARTIAL)
                    self.assertEqual(len(result.errors), 1)
                    self.assertEqual(len(result.records), 1)

    def test_duplicate_archive_ids_keep_first_and_report_each_repeat(self):
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot):
                name = ('cves/2026/10xxx/' if snapshot else 'deltaCves/') + 'CVE-2026-10000.json'
                data = zipped([(name, record(revision=n)) for n in (1, 0, 2)], snapshot=snapshot)
                r = release(3)
                source, _ = self.source([r], **{r['assets'][int(not snapshot)]['browser_download_url']: data})
                result = source._archive(r, Origin.SNAPSHOT if snapshot else Origin.DELTA, NOW)
                self.assertEqual(result.status, FetchStatus.PARTIAL)
                self.assertEqual([r['revision'] for r in result.records], [1])
                self.assertEqual(len(result.errors), 2)

    def test_kev_metadata_types_fail_and_preserve_accepted_catalog(self):
        catalog = json.loads((RAW / 'kev_sample.json').read_text())
        catalog['count'] = len(catalog['vulnerabilities'])
        opener = Opener({KEV_URL: json.dumps(catalog).encode()})
        source = KevSource(Http('test', {}, opener, resolver=public_resolver))
        accepted, = source.poll(NOW)
        for field in ('dateReleased', 'catalogVersion', 'count'):
            for value in (None, 0, True, [], {}, '', ' '):
                with self.subTest(field=field, value=value):
                    opener.routes[KEV_URL] = json.dumps({**catalog, field: value}).encode()
                    result, = source.poll(NOW)
                    self.assertEqual(result.status, FetchStatus.FAILED)
                    self.assertIs(source.accepted, accepted)
        opener.routes[KEV_URL] = (b'', 304, {})
        self.assertIs(source.poll(NOW)[0], accepted)

    def test_rate_limit_deadlines_and_plain_403(self):
        cases = [
            (429, {'Retry-After': '7200'}, 7200),
            (429, {'Retry-After': format_datetime(NOW + timedelta(hours=3))}, 10800),
            (403, {'X-RateLimit-Remaining': '0', 'Retry-After': '7200',
                   'X-RateLimit-Reset': str(int((NOW + timedelta(hours=3)).timestamp()))}, 10800),
            (429, {'Retry-After': '10800', 'X-RateLimit-Reset': str(int((NOW + timedelta(hours=2)).timestamp()))}, 10800),
        ]
        for status, headers, seconds in cases:
            with self.subTest(status=status, headers=headers):
                self.store.connection.execute("DELETE FROM meta WHERE k='github_retry_at'")
                opener = Opener({RELEASES_URL: (b'', status, headers)})
                source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
                self.assertEqual(source.poll(NOW)[0].status, FetchStatus.FAILED)
                recreated = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
                self.assertEqual(recreated.poll(NOW + timedelta(seconds=seconds-1)), [])
                self.assertEqual(len(opener.requests), 1)
                recreated.poll(NOW + timedelta(seconds=seconds))
                self.assertEqual(len(opener.requests), 2)
        self.store.connection.execute("DELETE FROM meta WHERE k='github_retry_at'")
        opener = Opener({RELEASES_URL: (b'', 403, {'Retry-After': '7200'})})
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        self.assertEqual(source.poll(NOW)[0].status, FetchStatus.FAILED)
        self.assertIsNone(self.store.get_meta('github_retry_at'))
        source.poll(NOW + timedelta(hours=1))
        self.assertEqual(len(opener.requests), 2)

    def test_record_expansion_limit_and_ratio_are_partial(self):
        oversized = record(padding='x' * (8 * 1024 * 1024))
        for data in (zipped([('deltaCves/CVE-2026-10000.json', oversized)]),
                     zipped([('deltaCves/CVE-2026-10000.json', record(padding='x' * 1000000))], compression=ZIP_DEFLATED)):
            with self.subTest(size=len(data)):
                result = self.delta(data)
                self.assertEqual(result.status, FetchStatus.PARTIAL)
                self.assertEqual(len(result.records), 0)
                self.assertEqual(len(result.errors), 1)

    def test_snapshot_expansion_total_and_container_are_bounded(self):
        # Scale only the 4 GiB budget; fixtures exercise the same boundary logic.
        r = release(3)
        entries = [('cves/2026/10xxx/CVE-2026-10000.json', record()),
                   ('cves/2026/10xxx/CVE-2026-10001.json', record(10001))]
        data = zipped(entries, snapshot=True)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: data})
        with patch('cornicen.sources.cvelist.MAX_SNAPSHOT_BYTES', len(record().encode()) + 1, create=True):
            result = source._archive(r, Origin.SNAPSHOT, NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('limit', ' '.join(result.errors).lower())
        # A compressed container can be small while its entries exceed the budget.
        data = zipped(entries, snapshot=True)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: data})
        with patch('cornicen.sources.cvelist.MAX_SNAPSHOT_BYTES', 1000, create=True):
            result = source._archive(r, Origin.SNAPSHOT, NOW)
        self.assertEqual(result.status, FetchStatus.COMPLETE)

    def test_kev_health_shows_catalog_age_without_stale_alarm(self):
        for days in (3, 100):
            with self.subTest(days=days):
                self.store.connection.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
                    ('kev', 'version', (NOW - timedelta(days=days)).isoformat()))
                state, detail = assess('kev', self.store, NOW, CONFIG)
                self.assertEqual(state, 'healthy')
                self.assertIn(f'catalog {days} days old', detail)

    def test_http_body_reads_are_bounded(self):
        from tests.source_helpers import Reply
        class BoundedOpener:
            def open(self, request, timeout=None):
                class BoundedReply(Reply):
                    def read(self, size=-1):
                        if size < 0:
                            raise AssertionError('Unbounded HTTP read')
                        return super().read(size)
                return BoundedReply(b'{}')
        response = Http('test', {}, BoundedOpener(), resolver=public_resolver).get(RELEASES_URL, source='cvelist')
        self.assertEqual(response.body, b'{}')
        with patch('cornicen.fetch.MAX_BODY_BYTES', 10, create=True):
            with self.assertRaises(ValueError):
                Http('test', {}, Opener({RELEASES_URL: b'x' * 11}), resolver=public_resolver).get(
                    RELEASES_URL, source='cvelist')

    def test_inner_snapshot_total_expansion_is_partial(self):
        r = release(3)
        entries = [(f'cves/2026/10xxx/CVE-2026-{n}.json', record(n, padding='x' * 1000)) for n in (10000, 10001)]
        inner = zipped(entries, compression=ZIP_DEFLATED)
        data = zipped([('snapshot.zip', inner)])
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: data})
        self.assertLess(len(inner), 1500)
        with patch('cornicen.sources.cvelist.MAX_SNAPSHOT_BYTES', 1500, create=True):
            result = source._archive(r, Origin.SNAPSHOT, NOW)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertEqual(len(result.records), 1)
        self.assertIn('limit', ' '.join(result.errors).lower())

    def test_snapshot_container_ratio_is_failed(self):
        r = release(3)
        data = zipped([('snapshot.zip', b'x' * 1000000)], compression=ZIP_DEFLATED)
        source, _ = self.source([r], **{r['assets'][0]['browser_download_url']: data})
        result = source._archive(r, Origin.SNAPSHOT, NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('ratio', ' '.join(result.errors).lower())

    def test_epss_expanded_lines_are_bounded(self):
        import gzip
        from cornicen.sources.epss import EpssSource, URL
        prefix = '#model_version:v1,score_date:2026-11-03\ncve,epss,percentile\n'
        inputs = [prefix.replace('v1', 'x' * (1024 * 1024)) + 'CVE-2026-10000,0.1,0.2\n',
                  prefix + 'CVE-2026-10000,' + '0' * (1024 * 1024) + '.1,0.2\n']
        for text in inputs:
            with self.subTest(size=len(text)):
                opener = Opener({URL: gzip.compress(text.encode())})
                result, = EpssSource(Http('test', {}, opener, resolver=public_resolver), self.store).poll(NOW)
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertIn('limit', ' '.join(result.errors).lower())

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat
import tempfile
import tracemalloc
import unittest

from cornicen.fetch import Http
from cornicen.model import FetchStatus, Origin
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.store import Store
from tests.source_helpers import public_resolver, Opener, RAW, archive, release

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)


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

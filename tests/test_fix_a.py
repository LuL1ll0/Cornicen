"""Offline regressions for fix round A."""
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import Mock, patch

from cornicen import validate
from cornicen.cli import watch_check
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess, container_healthy
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, Origin
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from tests import test_cvelist_source as sources, test_engine as engines
from tests.source_helpers import public_resolver, Opener, archive, release, expected_projection


def eod(day):
    result = release(day)
    result['tag_name'] = f'cve_2026-11-{day:02}_at_end_of_day'
    result['assets'] = [{'name': f'2026-11-{day:02}_delta_CVEs_at_end_of_day.zip',
                         'browser_download_url': f'https://github.com/eod/{day}'}]
    return result


class SourceFixTests(unittest.TestCase):
    setUp = sources.CveListTests.setUp
    source = sources.CveListTests.source
    cursor = sources.CveListTests.cursor

    def test_f4_bootstrap_reads_page_one_only(self):
        r = release(3)
        source, opener = self.source([r], **{a['browser_download_url']: archive(snapshot=i == 0)
                                           for i, a in enumerate(r['assets'])})
        opener.routes[RELEASES_URL] = (json.dumps([r]).encode(), 200,
                                     {'Link': f'<{RELEASES_URL}?page=2>; rel="next"'})
        result = source.poll(sources.NOW)
        self.assertEqual([r.status for r in result], [FetchStatus.COMPLETE] * 2)
        self.assertNotIn(RELEASES_URL + '?page=2', [r.full_url for r in opener.requests])

    def test_f4_page_eleven_422_ends_listing(self):
        source, opener = self.source([])
        for page in range(1, 11):
            url = RELEASES_URL if page == 1 else RELEASES_URL + f'?page={page}'
            opener.routes[url] = (json.dumps([release(3)] * 100).encode(), 200,
                {'Link': f'<{RELEASES_URL}?page={page+1}>; rel="next"'})
        opener.routes[RELEASES_URL + '?page=11'] = (
            b'{"message":"Only the first 1000 results are available."}', 422, {})
        releases, exhausted = source._listing('cve_2026-10-01_0000Z', sources.NOW)
        self.assertEqual(len(releases), 1000)
        self.assertFalse(exhausted)
        self.assertEqual(len(opener.requests), 11)

    def test_f4_direct_tag_catchup(self):
        self.cursor(release(1, 1)['tag_name'])
        releases = [eod(1), eod(2), release(3)]
        source, opener = self.source([releases[-1]], **{
            **{RELEASES_URL + '/tags/' + r['tag_name']: json.dumps(r).encode() for r in releases[:2]},
            **{r['assets'][-1]['browser_download_url']: archive() for r in releases}})
        result = source.poll(sources.NOW)
        self.assertEqual([r.cursor for r in result], [r['tag_name'] for r in releases])
        self.assertTrue(all(r.origin == Origin.DELTA for r in result))

    def test_f4_45_day_outage_reconciles_and_reports(self):
        self.cursor('cve_2026-09-19_2300Z')
        r = release(3)
        source, opener = self.source([r], **{a['browser_download_url']: archive(snapshot=i == 0)
                                           for i, a in enumerate(r['assets'])})
        opener.routes[RELEASES_URL + '/tags/cve_2026-09-19_at_end_of_day'] = (b'{}', 404, {})
        result = source.poll(sources.NOW)
        self.assertEqual(result[0].origin, Origin.SNAPSHOT)
        self.assertEqual(self.store.get_meta('reconcile_at'), sources.NOW.isoformat())
        from tests.test_health import CONFIG
        self.assertIn('reconcil', assess('cvelist', self.store, sources.NOW, CONFIG)[1].lower())

    def test_w1_1_resume_snapshot_cutoff_includes_its_day(self):
        self.store.set_meta('cvelist_snapshot_cutoff', '2026-11-01T00:00:00+00:00')
        self.store.set_meta('cvelist_snapshot_complete', '1')
        releases = [eod(1), eod(2), release(3)]
        source, _ = self.source(releases, **{
            **{RELEASES_URL + '/tags/' + r['tag_name']: json.dumps(r).encode() for r in releases[:2]},
            **{r['assets'][-1]['browser_download_url']: archive() for r in releases}})
        result = source.poll(sources.NOW)
        self.assertEqual([r.origin for r in result], [Origin.DELTA] * 3)
        self.assertEqual([r.cursor for r in result], [r['tag_name'] for r in releases])

    def test_w1_2_unknown_only_fails_bootstrap(self):
        source, _ = self.source([{'tag_name': 'unsupported', 'assets': []}])
        result, = source.poll(sources.NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('No CVE releases', ' '.join(result.errors))


class EngineFixTests(unittest.TestCase):
    setUp = engines.EngineTests.setUp
    ingest = engines.EngineTests.ingest
    start = engines.EngineTests.start
    count = engines.EngineTests.count

    def test_w1_1_snapshot_phase_and_cutoff_atomic(self):
        snapshot = replace(self.ingest([self.record], origin=Origin.SNAPSHOT), cursor=None)
        self.store.connection.execute('''CREATE TRIGGER fail_phase BEFORE INSERT ON meta
            WHEN NEW.k='cvelist_snapshot_complete' BEGIN SELECT RAISE(ABORT, 'crash'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            self.engine.run_cycle([snapshot])
        self.assertEqual(self.count('records'), 0)
        self.assertIsNone(self.store.get_meta('cvelist_snapshot_cutoff'))
        self.store.connection.execute('DROP TRIGGER fail_phase')
        self.engine.run_cycle([snapshot])
        self.assertEqual(self.store.get_meta('cvelist_snapshot_cutoff'), self.clock().isoformat())
        self.assertEqual(self.store.get_meta('cvelist_snapshot_complete'), '1')

    def test_w1_1_later_snapshot_records_new_before_other_feeds(self):
        self.engine.run_cycle([replace(self.baseline[0], cursor=None)])
        self.clock.now += timedelta(days=1)
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        report = self.engine.run_cycle([self.ingest([self.record], origin=Origin.SNAPSHOT)])
        self.assertIn('service|CVE-2025-54831|new match|1', report.events)
        self.assertEqual(self.store.connection.execute('SELECT baseline FROM pairs').fetchone()[0], 0)

    def test_w1_2_no_completed_fetch_grace_survives_restart(self):
        self.engine.run_cycle([])
        self.clock.now += timedelta(hours=2)
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'healthy')
        self.clock.now += timedelta(seconds=1)
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        report = self.engine.run_cycle([])
        self.assertIn(('cvelist', 'unhealthy'), report.health_changes)
        self.assertFalse(container_healthy(self.store, self.clock(), self.config))
        self.assertTrue(any(n['record'] == 'cvelist' for n in self.notifier.delivered))

    def test_w1_3_monotonic_polling_after_utc_rewind(self):
        elapsed = [0.0]
        feeds = {name: Mock() for name in Scheduler.intervals}
        for feed in feeds.values():
            feed.poll.return_value = []
        scheduler = Scheduler(self.engine, feeds, self.clock, lambda _: None,
                              monotonic=lambda: elapsed[0])
        scheduler.tick()
        self.clock.now -= timedelta(days=2)
        for hour in range(1, 25):
            elapsed[0] = hour * 3600
            self.clock.now += timedelta(hours=1)
            scheduler.tick()
        self.assertEqual([feed.poll.call_count for feed in feeds.values()], [25, 5, 2])

    def test_w1_3_future_persisted_content_unhealthy_and_notified(self):
        self.start()
        self.clock.now -= timedelta(days=2)
        for source in ('cvelist', 'kev', 'epss'):
            self.assertEqual(assess(source, self.store, self.clock(), self.config)[0], 'unhealthy')
        report = self.engine.run_cycle([])
        self.assertEqual(set(report.health_changes), {(s, 'unhealthy') for s in ('cvelist', 'kev', 'epss')})
        self.assertEqual(len(self.notifier.delivered), 3)

    def test_w1_4_startup_clears_reload_rejection(self):
        self.start()
        with self.store.transaction():
            self.engine._health('watchlist', 'unhealthy', 'Watchlist reload rejected')
        self.engine.run_cycle([])
        self.notifier.delivered.clear()
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        self.engine.run_cycle([])
        self.assertEqual(assess('watchlist', self.store, self.clock(), self.config)[0], 'healthy')
        self.assertEqual([n['reasons'] for n in self.notifier.delivered], [['healthy']])

    def test_w3_2_old_release_cannot_apply_revision(self):
        self.start()
        newest = replace(self.ingest([self.record]), cursor='cve_2026-11-03_0700Z')
        self.engine.run_cycle([newest])
        rejected = deepcopy(self.record)
        rejected['cveMetadata']['state'] = 'REJECTED'
        for tag in ('cve_2026-11-03_0700Z', 'cve_2026-11-03_0600Z'):
            self.engine.run_cycle([replace(newest, cursor=tag, records=(rejected,))])
            self.assertEqual(self.engine._record(self.record['cveMetadata']['cveId']), expected_projection(self.record))

    def test_w3_3_metadata_dates_rejected_at_ingestion(self):
        for field in ('datePublished', 'dateUpdated'):
            for value in (7, None, [], 'not-a-date', '2026-11-03'):
                with self.subTest(field=field, value=value):
                    record = deepcopy(self.record)
                    record['cveMetadata'][field] = value
                    self.assertIn('cveMetadata.' + field, '; '.join(validate.record(record)))
        record = deepcopy(self.record)
        record['cveMetadata']['datePublished'] = 7
        self.engine.run_cycle([self.ingest([record])])
        self.assertEqual(self.count('invalid_revisions'), 1)
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'unhealthy')

    def test_w3_3_watch_check_falls_back_for_legacy_metadata(self):
        for value in (7, [], 'not-a-date'):
            record = deepcopy(self.record)
            record['cveMetadata']['datePublished'] = value
            self.store.put_record(record['cveMetadata']['cveId'], record, self.clock().isoformat())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(watch_check(self.store, self.watches, AliasMap.load(False), 90, self.clock()), 0)
            self.assertIn('matched CVE-2025-54831', output.getvalue())

    def test_w3_4_spec_promises_rejection_only(self):
        spec = Path('docs/spec.md').read_text().split('## 6.')[0]
        self.assertIn('Rejected records are **not affected**', spec)
        self.assertNotIn('Rejected or withdrawn records', spec)


class AdditionalFixTests(unittest.TestCase):
    setUp = engines.EngineTests.setUp
    ingest = engines.EngineTests.ingest
    start = engines.EngineTests.start
    count = engines.EngineTests.count

    def test_release_identity_rolls_back_with_records(self):
        self.start()
        tag = 'cve_2026-11-03_0700Z'
        self.store.connection.execute('''CREATE TRIGGER fail_identity BEFORE INSERT ON meta
            WHEN NEW.k='committed_cve:delta:cve_2026-11-03_0700Z'
            BEGIN SELECT RAISE(ABORT, 'crash'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            self.engine.run_cycle([replace(self.ingest([self.record]), cursor=tag)])
        self.assertEqual(self.count('records'), 0)
        self.assertEqual(self.count('pairs'), 0)
        self.assertIsNone(self.store.get_meta('committed_cve:delta:' + tag))

    def test_incomplete_release_retries_after_restart(self):
        self.start()
        tag = 'cve_2026-11-03_0700Z'
        ingest = replace(self.ingest([self.record]), cursor=tag)
        with patch('cornicen.applicability.resolve', side_effect=ValueError('temporary')):
            self.engine.run_cycle([ingest])
        self.assertIsNone(self.store.get_meta('committed_cve:delta:' + tag))
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        self.engine.run_cycle([ingest])
        self.assertEqual(self.store.get_meta('committed_cve:delta:' + tag), '1')
        self.assertEqual(self.count('retry_queue'), 0)

    def test_startup_preserves_real_rematch_failure(self):
        self.start()
        with self.store.transaction():
            self.engine._health('watchlist', 'unhealthy', 'Re-match failed; retry pending')
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)
        self.assertEqual(assess('watchlist', self.store, self.clock(), self.config)[0], 'unhealthy')

    def test_future_cursor_even_when_content_time_is_sane(self):
        self.start()
        self.store.connection.execute("UPDATE cursors SET value='cve_2026-11-05_0700Z' WHERE source='cvelist'")
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'unhealthy')
        report = self.engine.run_cycle([])
        self.assertIn(('cvelist', 'unhealthy'), report.health_changes)

    def test_unknown_listing_is_unhealthy_and_notified_during_bootstrap(self):
        opener = Opener({RELEASES_URL: b'[{"tag_name":"new-format","assets":[]}]'})
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        self.engine.run_cycle(source.poll(self.clock()))
        self.assertFalse(container_healthy(self.store, self.clock(), self.config))
        self.assertEqual([n['reasons'] for n in self.notifier.delivered], [['unhealthy']])


class AdditionalSourceFixTests(unittest.TestCase):
    setUp = sources.CveListTests.setUp
    source = sources.CveListTests.source
    cursor = sources.CveListTests.cursor

    def test_listing_finishes_after_cursor_day_tail(self):
        source, opener = self.source([release(3)])
        opener.routes[RELEASES_URL] = (json.dumps([release(3)]).encode(), 200,
                                     {'Link': f'<{RELEASES_URL}?page=2>; rel="next"'})
        opener.routes[RELEASES_URL + '?page=2'] = (json.dumps([release(2), release(1)]).encode(), 200,
                                     {'Link': f'<{RELEASES_URL}?page=3>; rel="next"'})
        opener.routes[RELEASES_URL + '?page=3'] = json.dumps([release(2, 22)]).encode()
        result, exhausted = source._listing(release(2, 1)['tag_name'], sources.NOW)
        self.assertEqual([r['tag_name'] for r in result],
                         [release(n)['tag_name'] for n in (3, 2, 1)] + [release(2, 22)['tag_name']])
        self.assertTrue(exhausted)
        self.assertEqual(len(opener.requests), 3)

    def test_direct_tag_404_falls_back_to_latest_hourly(self):
        self.cursor(release(2, 1)['tag_name'])
        releases = [release(3), release(2, 12), release(2, 23)]
        source, opener = self.source(releases, **{
            r['assets'][-1]['browser_download_url']: archive() for r in releases})
        result = source.poll(sources.NOW)
        self.assertEqual([r.cursor for r in result], [release(2, 23)['tag_name'], release(3)['tag_name']])
        self.assertIn(RELEASES_URL + '/tags/cve_2026-11-02_at_end_of_day', [r.full_url for r in opener.requests])

    def test_other_422_is_failure(self):
        source, opener = self.source([])
        opener.routes[RELEASES_URL] = (b'{"message":"Validation Failed"}', 422, {})
        result, = source.poll(sources.NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('Validation Failed', ' '.join(result.errors))

    def test_partial_snapshot_resume_uses_pinned_release(self):
        pinned, latest = release(1), release(3)
        self.store.set_meta('cvelist_snapshot_cutoff', '2026-11-01T00:00:00+00:00')
        self.store.set_meta('cvelist_snapshot_release', pinned['tag_name'])
        source, opener = self.source([latest], **{
            RELEASES_URL + '/tags/' + pinned['tag_name']: json.dumps(pinned).encode(),
            pinned['assets'][0]['browser_download_url']: archive(snapshot=True)})
        result, = source.poll(sources.NOW)
        self.assertEqual(result.status, FetchStatus.COMPLETE)
        self.assertEqual(result.cursor, pinned['tag_name'])
        self.assertNotIn(latest['assets'][0]['browser_download_url'], [r.full_url for r in opener.requests])

    def test_malformed_metadata_date_makes_archive_partial(self):
        from zipfile import ZipFile
        from tests.source_helpers import RAW
        record = json.loads((RAW / 'CVE-2026-106803.json').read_text())
        record['cveMetadata']['dateUpdated'] = 7
        buffer = io.BytesIO()
        with ZipFile(buffer, 'w') as zipped:
            zipped.writestr('deltaCves/CVE-2026-106803.json', json.dumps(record))
        r = release(3)
        self.cursor(release(3, 1)['tag_name'])
        source, _ = self.source([r], **{r['assets'][1]['browser_download_url']: buffer.getvalue()})
        result, = source.poll(sources.NOW)
        self.assertEqual(result.status, FetchStatus.PARTIAL)
        self.assertIn('dateUpdated', ' '.join(result.errors))

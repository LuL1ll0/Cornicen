"""Offline release-list completeness and response-boundary regressions."""

from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from cornicen.fetch import Http
from cornicen.health import assess, container_healthy
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from tests import test_engine as engines
from tests.replay.harness import load_expected, run_scenario
from tests.source_helpers import Opener, public_resolver, release


def delta(records=()):
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w') as zipped:
        for record in records:
            record_id = record['cveMetadata']['cveId']
            zipped.writestr(f'deltaCves/{record_id}.json', json.dumps(record))
        zipped.writestr('delta.json', json.dumps({'new': [], 'updated': [], 'error': []}))
    return buffer.getvalue()


def snapshot(records):
    inner, outer = io.BytesIO(), io.BytesIO()
    with ZipFile(inner, 'w') as zipped:
        for record in records:
            record_id = record['cveMetadata']['cveId']
            zipped.writestr(f'cves/2025/54xxx/{record_id}.json', json.dumps(record))
    with ZipFile(outer, 'w') as zipped:
        zipped.writestr('cves.zip', inner.getvalue())
    return outer.getvalue()


class ReleaseCoverageTests(unittest.TestCase):
    def setUp(self):
        engines.EngineTests.setUp(self)
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.clock.now = self.clock().replace(hour=8)
        cutoff = self.clock().replace(day=2, hour=0)
        initial = release(2, 0)['tag_name']
        baseline = [replace(self.baseline[0], cursor=initial, content_time=cutoff),
                    replace(self.baseline[1], content_time=cutoff),
                    replace(self.baseline[2], content_time=cutoff,
                            epss={self.record['cveMetadata']['cveId']: (.5, .99)},
                            epss_date=cutoff.date()),
                    IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                 initial, cutoff)]
        self.engine.run_cycle(baseline)
        self.notifier.delivered.clear()
        self.first, self.early, self.older, self.late = (
            release(3, 8), release(2, 1), release(1, 23), release(2, 23))
        # No snapshot can hide the omitted hourly record in this fixture.
        for candidate in (self.first, self.early, self.older, self.late):
            candidate['assets'] = candidate['assets'][1:]
        self.next_url = RELEASES_URL + '?page=2'
        self.opener = Opener({
            RELEASES_URL: (json.dumps([self.first, self.early, self.older]).encode(), 200,
                           {'Link': f'<{self.next_url}>; rel="next"'}),
            self.next_url: json.dumps([self.late]).encode(),
            **{r['assets'][0]['browser_download_url']: delta()
               for r in (self.first, self.early, self.older)},
            self.late['assets'][0]['browser_download_url']: delta([self.record]),
        })
        http = Http('test', {}, self.opener, resolver=public_resolver, data_dir=self.directory)
        self.source = CveListSource(http, self.store)
        sources = {'cvelist': self.source, 'kev': Mock(), 'epss': Mock()}
        for name in ('kev', 'epss'):
            sources[name].poll.return_value = []
        self.lines = []
        self.scheduler = Scheduler(self.engine, sources, self.clock, self.lines.append,
                                   monotonic=lambda: self.clock().timestamp())

    def coverage(self):
        return tuple(self.store.connection.execute(
            "SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone())

    def assert_unhealthy(self):
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='cvelist'").fetchone()[0], 'unhealthy')
        self.assertEqual(assess('cvelist', self.store, self.clock(), self.config)[0], 'unhealthy')
        self.assertFalse(container_healthy(self.store, self.clock(), self.config))
        self.assertEqual(json.loads(self.lines[-1])['sources']['cvelist'], 'unhealthy')

    def assert_ingested_once(self, put_record):
        self.assertEqual([call.args[0] for call in put_record.call_args_list],
                         [self.record['cveMetadata']['cveId']])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 1)
        self.assertEqual([(n['record'], n['reasons']) for n in self.notifier.delivered if n['watch']],
                         [(self.record['cveMetadata']['cveId'], ['new match'])])

    def test_out_of_order_two_poll_listing_does_not_lose_final_hour(self):
        with patch.object(self.store, 'put_record', wraps=self.store.put_record) as put_record:
            self.scheduler.tick()
            self.assertIn(self.next_url, [request.full_url for request in self.opener.requests])
            self.assert_ingested_once(put_record)
            self.assertEqual(self.coverage()[0], self.first['tag_name'])
            # The next poll puts the late hourly release on page one, as in the review.
            self.opener.routes[RELEASES_URL] = json.dumps([self.first, self.late, self.early]).encode()
            self.clock.now += timedelta(hours=1)
            self.scheduler.tick()
            self.assert_ingested_once(put_record)
        self.assertEqual(len(self.lines), 2)

    def interrupted_listing_recovers(self, *, page_limit=False):
        before = self.coverage()
        if not page_limit:
            self.opener.routes[self.next_url] = (
                b'{"message":"Only the first 1000 results are available."}', 422, {})
        with patch.object(self.store, 'put_record', wraps=self.store.put_record) as put_record:
            if page_limit:
                with patch('cornicen.sources.cvelist.MAX_RELEASE_PAGES', 1):
                    self.scheduler.tick()
            else:
                self.scheduler.tick()
            self.assertEqual(self.coverage(), before)
            self.assert_unhealthy()
            self.assertEqual(put_record.call_count, 0)
            self.opener.routes[self.next_url] = json.dumps([self.late]).encode()
            self.clock.now += timedelta(hours=1)
            self.scheduler.tick()
            self.assert_ingested_once(put_record)
            self.assertEqual(self.coverage()[0], self.first['tag_name'])
        self.assertEqual(len(self.lines), 2)

    def test_1000_result_limit_never_certifies_hourly_fallback(self):
        self.interrupted_listing_recovers()

    def test_page_limit_never_certifies_hourly_fallback(self):
        self.interrupted_listing_recovers(page_limit=True)

    def test_partial_listing_reconciles_from_covering_snapshot(self):
        candidate = release(3, 8)
        self.opener.routes[RELEASES_URL] = (json.dumps([candidate, self.early, self.older]).encode(),
            200, {'Link': f'<{self.next_url}>; rel="next"'})
        self.opener.routes[self.next_url] = (
            b'{"message":"Only the first 1000 results are available."}', 422, {})
        self.opener.routes[candidate['assets'][0]['browser_download_url']] = snapshot([self.record])
        self.scheduler.tick()
        self.assertEqual(self.store.get_meta('reconcile_at'), self.clock().isoformat())
        self.assertEqual(self.coverage()[0], candidate['tag_name'])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 1)
        self.assertEqual(json.loads(self.lines[-1])['sources']['cvelist'], 'healthy')

    def test_partial_listing_rejects_snapshot_before_day_end(self):
        before = self.coverage()
        candidate = release(2, 1)
        self.opener.routes[RELEASES_URL] = (json.dumps([self.first, candidate, self.older]).encode(),
            200, {'Link': f'<{self.next_url}>; rel="next"'})
        self.opener.routes[self.next_url] = (
            b'{"message":"Only the first 1000 results are available."}', 422, {})
        self.opener.routes[candidate['assets'][0]['browser_download_url']] = snapshot([self.record])
        self.opener.routes[candidate['assets'][1]['browser_download_url']] = delta()
        self.scheduler.tick()
        self.assertEqual(self.coverage(), before)
        self.assert_unhealthy()
        self.assertNotIn(candidate['assets'][0]['browser_download_url'],
                         [request.full_url for request in self.opener.requests])


class ReleaseResponseTests(unittest.TestCase):
    setUp = ReleaseCoverageTests.setUp
    coverage = ReleaseCoverageTests.coverage
    assert_unhealthy = ReleaseCoverageTests.assert_unhealthy

    def assert_failed_polls_keep_running(self):
        self.scheduler.next_poll.clear()
        row = self.store.connection.execute(
            "SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone()
        before = tuple(row) if row else None
        polls = []
        poll = self.source.poll

        def capture(now):
            results = poll(now)
            polls.append(results)
            return results

        with patch.object(self.source, 'poll', side_effect=capture):
            for _ in range(2):
                self.scheduler.tick()
                result, = polls[-1]
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertTrue(result.errors[0].startswith('ValueError:'), result.errors)
                row = self.store.connection.execute(
                    "SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone()
                self.assertEqual(tuple(row) if row else None, before)
                self.assert_unhealthy()
                self.clock.now += timedelta(hours=1)
        self.assertEqual(len(polls), 2)
        self.assertEqual(len(self.lines), 2)

    def test_422_array_is_failed_through_scheduler(self):
        self.opener.routes[RELEASES_URL] = (b'[]', 422, {})
        self.assert_failed_polls_keep_running()

    def test_422_message_requires_string(self):
        for message in (None, 7, False, [], {}, ['Only the first 1000 results are available.']):
            with self.subTest(message=message):
                self.opener.routes[RELEASES_URL] = (json.dumps({'message': message}).encode(), 422, {})
                self.lines.clear()
                self.assert_failed_polls_keep_running()

    def pinned_response(self, body):
        pinned = release(2, 1)
        self.store.connection.execute("DELETE FROM cursors WHERE source='cvelist'")
        self.store.connection.execute("DELETE FROM meta WHERE k='cvelist_snapshot_complete'")
        self.store.set_meta('cvelist_snapshot_release', pinned['tag_name'])
        self.opener.routes[RELEASES_URL] = json.dumps([self.first]).encode()
        self.opener.routes[RELEASES_URL + '/tags/' + pinned['tag_name']] = json.dumps(body).encode()

    def test_pinned_direct_tag_array_is_failed_through_scheduler(self):
        self.pinned_response([])
        self.assert_failed_polls_keep_running()

    def test_pinned_direct_tag_identity_and_assets_are_validated(self):
        for candidate in (release(1), {'tag_name': release(2, 1)['tag_name'], 'assets': [7]},
                          {'tag_name': release(2, 1)['tag_name'], 'assets': None}):
            with self.subTest(candidate=candidate):
                self.pinned_response(candidate)
                self.lines.clear()
                self.assert_failed_polls_keep_running()

    def test_listing_body_requires_list(self):
        self.opener.routes[RELEASES_URL] = b'{}'
        self.assert_failed_polls_keep_running()

    def test_listing_members_require_objects(self):
        self.opener.routes[RELEASES_URL] = b'[[]]'
        self.assert_failed_polls_keep_running()

    def test_end_of_day_direct_tag_requires_object(self):
        self.opener.routes[RELEASES_URL + '/tags/cve_2026-11-02_at_end_of_day'] = b'[]'
        self.assert_failed_polls_keep_running()


class ReleaseReplayTests(unittest.TestCase):
    def test_uncertified_day_recovers_once(self):
        # This scenario is registered here alongside its source-level regressions.
        name = 'fix_f/uncertified_day_recovers'
        self.assertEqual(run_scenario(name), load_expected(name))

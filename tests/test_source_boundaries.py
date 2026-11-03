"""Untrusted release identity, ZIP metadata, and repeated rate limits."""
from datetime import timedelta
import io
import json
import unittest
from zipfile import ZipFile, BadZipFile

from cornicen.fetch import Http
from cornicen.model import FetchStatus
from cornicen.sources.cvelist import CveListSource, _SnapshotZip, RELEASES_URL
from tests import test_cvelist_source as helpers
from tests.test_fix_a import eod
from tests.source_helpers import Opener, public_resolver, release, archive


class ArchiveMetadataTests(unittest.TestCase):
    def test_bad_central_directory_signature_is_rejected(self):
        data = io.BytesIO()
        with ZipFile(data, 'w') as zipped:
            zipped.writestr('record.json', '{}')
        corrupt = data.getvalue().replace(b'PK\x01\x02', b'BAD!', 1)
        with self.assertRaises(BadZipFile):
            with _SnapshotZip(io.BytesIO(corrupt)) as zipped:
                list(zipped.infolist())


class SourceBoundaryTests(unittest.TestCase):
    setUp = helpers.CveListTests.setUp
    source = helpers.CveListTests.source
    cursor = helpers.CveListTests.cursor

    def test_listed_end_of_day_release_avoids_redundant_tag_lookup(self):
        self.cursor(release(2, 1)['tag_name'])
        releases = [eod(2), release(3)]
        source, opener = self.source(releases, **{
            candidate['assets'][-1]['browser_download_url']: archive() for candidate in releases})
        results = source.poll(helpers.NOW)
        for result in results:
            if hasattr(result.records, 'close'):
                self.addCleanup(result.records.close)
        self.assertEqual([result.cursor for result in results],
                         [candidate['tag_name'] for candidate in releases])
        self.assertEqual([request.full_url for request in opener.requests],
                         [RELEASES_URL] + [candidate['assets'][-1]['browser_download_url']
                                           for candidate in releases])

    def test_new_rate_limit_renews_expired_durable_deadline(self):
        now = helpers.NOW
        self.store.set_meta('github_retry_at', (now - timedelta(seconds=1)).isoformat())
        opener = Opener({RELEASES_URL: (b'', 429, {'Retry-After': '3600'})})
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        self.assertEqual(source.poll(now)[0].status, FetchStatus.FAILED)
        self.assertEqual(self.store.get_meta('github_retry_at'),
                         (now + timedelta(hours=1)).isoformat())
        self.assertEqual(source.poll(now + timedelta(minutes=1)), [])
        self.assertEqual(len(opener.requests), 1)

    def test_pinned_release_response_must_match_requested_tag(self):
        pinned, newer = release(1), release(3)
        self.store.set_meta('cvelist_snapshot_release', pinned['tag_name'])
        self.store.set_meta('cvelist_snapshot_cutoff', '2026-11-01T00:00:00+00:00')
        source, opener = self.source([newer], **{
            RELEASES_URL + '/tags/' + pinned['tag_name']: json.dumps(newer).encode(),
            newer['assets'][0]['browser_download_url']: archive(snapshot=True)})
        results = source.poll(helpers.NOW)
        for result in results:
            if hasattr(result.records, 'close'):
                self.addCleanup(result.records.close)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('Unexpected pinned', ' '.join(result.errors))
        self.assertNotIn(newer['assets'][0]['browser_download_url'],
                         [request.full_url for request in opener.requests])

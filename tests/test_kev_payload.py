"""A complete catalog must retain identities and all enrichment fields."""
from datetime import datetime, timezone
import json
import unittest
from cornicen.fetch import Http
from cornicen.model import FetchStatus
from cornicen.sources.kev import KevSource, URL
from tests.source_helpers import public_resolver, Opener, RAW


class KevPayloadTests(unittest.TestCase):
    def test_saved_catalog_is_the_exact_input_map(self):
        catalog = json.loads((RAW / 'kev_sample.json').read_text())
        catalog['count'] = len(catalog['vulnerabilities'])
        source = KevSource(Http('test', {}, Opener({URL: json.dumps(catalog).encode()}), resolver=public_resolver))
        ingest, = source.poll(datetime(2026, 11, 3, 23, tzinfo=timezone.utc))
        self.assertEqual(ingest.status, FetchStatus.COMPLETE)
        self.assertEqual(ingest.kev, {row['cveID']: row for row in catalog['vulnerabilities']})

    def test_naive_release_dates_assume_utc_and_offsets_keep_their_instant(self):
        catalog = json.loads((RAW / 'kev_sample.json').read_text())
        catalog['count'] = len(catalog['vulnerabilities'])
        for value in ('2026-11-03T18:00:00', '2026-11-03T23:00:00+05:00'):
            with self.subTest(value=value):
                catalog['dateReleased'] = value
                source = KevSource(Http('test', {}, Opener({URL: json.dumps(catalog).encode()}), resolver=public_resolver))
                ingest, = source.poll(datetime(2026, 11, 3, 23, tzinfo=timezone.utc))
                self.assertEqual(ingest.status, FetchStatus.COMPLETE)
                self.assertEqual(ingest.content_time,
                                 datetime(2026, 11, 3, 18, tzinfo=timezone.utc))

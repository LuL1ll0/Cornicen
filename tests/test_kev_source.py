from datetime import datetime, timezone
import json
import unittest

from cornicen.fetch import Http
from cornicen.model import FetchStatus
from cornicen.sources.kev import KevSource, URL
from tests.source_helpers import public_resolver, Opener, RAW

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


class KevTests(unittest.TestCase):
    def poll(self, data):
        return KevSource(Http('test', {}, Opener({URL: data}), resolver=public_resolver)).poll(NOW)[0]

    def test_kev_empty_200_failed(self):
        for data in (b'', b'{}', b'{"vulnerabilities": [], "count": 0}'):
            with self.subTest(data=data):
                self.assertEqual(self.poll(data).status, FetchStatus.FAILED)

    def test_kev_count_mismatch_failed(self):
        data = json.loads((RAW / 'kev_sample.json').read_text())
        data['count'] = len(data['vulnerabilities']) + 1
        self.assertEqual(self.poll(json.dumps(data).encode()).status, FetchStatus.FAILED)

    def test_saved_catalog(self):
        data = json.loads((RAW / 'kev_sample.json').read_text())
        # Keep the expected count tied to the fixture's actual membership.
        data['count'] = len(data['vulnerabilities'])
        result = self.poll(json.dumps(data).encode())
        self.assertEqual(result.status, FetchStatus.COMPLETE)
        self.assertEqual(len(result.kev), 25)
        self.assertEqual(result.cursor, data['catalogVersion'])

    def test_304_preserves_catalog(self):
        data = json.loads((RAW / 'kev_sample.json').read_text())
        data['count'] = len(data['vulnerabilities'])
        opener = Opener({URL: (json.dumps(data).encode(), 200, {'ETag': 'v1'})})
        source = KevSource(Http('test', {}, opener, resolver=public_resolver))
        initial, = source.poll(NOW)
        opener.routes[URL] = (b'', 304, {})
        unchanged, = source.poll(NOW)
        self.assertEqual(unchanged.status, FetchStatus.COMPLETE)
        self.assertEqual(unchanged.kev, initial.kev)
        self.assertEqual(opener.requests[-1].get_header('If-none-match'), 'v1')

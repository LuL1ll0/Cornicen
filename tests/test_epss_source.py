from datetime import datetime, timezone
import gzip
from pathlib import Path
import stat
import tempfile
import unittest

from cornicen.fetch import Http
from cornicen.model import FetchStatus
from cornicen.sources.epss import EpssSource, URL
from cornicen.store import Store
from tests.source_helpers import public_resolver, Opener, RAW

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)


class EpssTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.store = Store(str(Path(self.directory.name) / 'state.db'))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.body = gzip.compress((RAW / 'epss_head.csv').read_bytes())

    def source(self, body):
        return EpssSource(Http('test', {}, Opener({URL: body}), resolver=public_resolver), self.store)

    def test_epss_redirect_followed(self):
        dated = 'https://epss.empiricalsecurity.com/epss_scores-2026-11-03.csv.gz'
        opener = Opener({URL: (b'', 302, {'Location': dated}), dated: self.body})
        result, = EpssSource(Http('test', {}, opener, resolver=public_resolver), self.store).poll(NOW)
        self.assertEqual(result.status, FetchStatus.COMPLETE)
        self.assertEqual(result.epss_date.isoformat(), '2026-11-03')
        self.assertEqual(result.epss['CVE-1999-0001'], (0.04753, 0.91894))
        self.assertEqual([r.full_url for r in opener.requests], [URL, dated])
        files = list(Path(self.directory.name).iterdir())
        self.assertEqual(sorted(p.name for p in files), ['state.db', 'state.db-shm', 'state.db-wal'])
        for path in files:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_epss_row_collapse_failed(self):
        self.store.set_meta('last_epss_rows', 100)
        self.assertEqual(self.source(self.body).poll(NOW)[0].status, FetchStatus.FAILED)
        self.assertEqual(self.store.get_meta('last_epss_rows'), '100')

    def test_engine_row_count_key_used(self):
        self.store.set_meta('last_epss_row_count', 100)
        self.assertEqual(self.source(self.body).poll(NOW)[0].status, FetchStatus.FAILED)

    def test_twenty_percent_drop_is_accepted(self):
        body = gzip.compress(b'#model_version:v1,score_date:2026-11-03\ncve,epss,percentile\n' +
                             b''.join(f'CVE-2026-{1000+n},0.1,0.2\n'.encode() for n in range(8)))
        self.store.set_meta('last_epss_rows', 10)
        self.assertEqual(self.source(body).poll(NOW)[0].status, FetchStatus.COMPLETE)

    def test_epss_truncated_gzip_failed(self):
        self.assertEqual(self.source(self.body[:-5]).poll(NOW)[0].status, FetchStatus.FAILED)

    def test_invalid_headers_numbers_and_regressing_date(self):
        self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                      ('epss', '2026-11-04', NOW.isoformat()))
        for body in (b'#model_version:v1,score_date:2026-11-03\ncve,epss,percentile\nCVE-2026-1234,0.1,0.2\n',
                     b'#model_version:v1,score_date:2026-11-04\nwrong,epss,percentile\n',
                     b'#model_version:v1,score_date:2026-11-04\ncve,epss,percentile\nCVE-2026-1234,nan,0.2\n'):
            with self.subTest(body=body):
                self.assertEqual(self.source(gzip.compress(body)).poll(NOW)[0].status, FetchStatus.FAILED)

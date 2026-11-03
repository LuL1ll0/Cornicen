"""Source adapters must retain the HTTP policy and configured transfer budgets."""

from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from cornicen.fetch import Http
from cornicen.model import FetchStatus, Origin
from cornicen.sources.cvelist import CveListSource
from cornicen.sources.epss import EpssSource, URL as EPSS_URL
from cornicen.sources.kev import KevSource, URL as KEV_URL
from cornicen.store import Store
from tests.source_helpers import Opener, RAW, archive, public_resolver, release

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)


class SourceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = Store(str(self.root / 'state.db'))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)

    def test_cvelist_selects_snapshot_and_delta_budgets(self):
        for snapshot in (False, True):
            body = archive(snapshot=snapshot)
            budget = 'cvelist_snapshot' if snapshot else 'cvelist_delta'
            other = 'cvelist_delta' if snapshot else 'cvelist_snapshot'
            candidate = release(3)
            url = candidate['assets'][int(not snapshot)]['browser_download_url']
            for limit in (len(body), len(body) - 1):
                with self.subTest(snapshot=snapshot, limit=limit):
                    http = Http('test', {}, Opener({url: body}), resolver=public_resolver,
                                download_budgets={budget: {'max_bytes': limit},
                                                  other: {'max_bytes': 1}})
                    source = CveListSource(http, self.store)
                    result = source._archive(candidate, Origin.SNAPSHOT if snapshot else Origin.DELTA, NOW)
                    self.addCleanup(result.records.close)
                    self.assertEqual(result.status, FetchStatus.COMPLETE if limit == len(body)
                                     else FetchStatus.FAILED)
                    if limit < len(body):
                        self.assertIn('size limit', ' '.join(result.errors))
                    self.assertEqual(list(self.root.glob('*.download')), [])

    def test_kev_and_epss_enforce_configured_download_budgets(self):
        catalog = json.loads((RAW / 'kev_sample.json').read_text())
        catalog['count'] = len(catalog['vulnerabilities'])
        bodies = {'kev': (KEV_URL, json.dumps(catalog).encode()),
                  'epss': (EPSS_URL, gzip.compress((RAW / 'epss_head.csv').read_bytes()))}
        for name, (url, body) in bodies.items():
            for limit in (len(body), len(body) - 1):
                with self.subTest(source=name, limit=limit):
                    http = Http('test', {}, Opener({url: body}), resolver=public_resolver,
                                data_dir=self.root, download_budgets={name: {'max_bytes': limit}})
                    source = KevSource(http) if name == 'kev' else EpssSource(http, self.store)
                    result, = source.poll(NOW)
                    self.assertEqual(result.status, FetchStatus.COMPLETE if limit == len(body)
                                     else FetchStatus.FAILED)
                    if limit < len(body):
                        self.assertIn('size limit', ' '.join(result.errors))
                    self.assertEqual(list(self.root.glob('*.download')), [])

    def test_github_release_redirects_accept_both_asset_hosts(self):
        candidate = release(3)
        initial = candidate['assets'][1]['browser_download_url']
        for host in ('release-assets.githubusercontent.com', 'objects.githubusercontent.com'):
            with self.subTest(host=host):
                destination = f'https://{host}/asset.zip'
                opener = Opener({initial: (b'', 302, {'Location': destination}),
                                 destination: archive()})
                http = Http('test', {}, opener, resolver=public_resolver)
                result = CveListSource(http, self.store)._archive(candidate, Origin.DELTA, NOW)
                self.addCleanup(result.records.close)
                self.assertEqual(result.status, FetchStatus.COMPLETE)
                self.assertEqual([request.full_url for request in opener.requests], [initial, destination])

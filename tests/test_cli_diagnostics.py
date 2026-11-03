"""Exercise near misses, exploitation, and timestamps through operator commands."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import unittest

from cornicen.cli import watch_check, replay
from cornicen.identity import AliasMap
from cornicen.store import Store
from cornicen.watchlist import Watch
from cornicen.versions import Scheme
import tempfile

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)
CVE = 'CVE-2026-1000'


def record(vendor, product, published=None):
    metadata = {'cveId': CVE, 'state': 'PUBLISHED'}
    if published is not None:
        metadata['datePublished'] = published
    return {'cveMetadata': metadata, 'containers': {'cna': {'affected': [
        {'vendor': vendor, 'product': product}]}}}


class CliDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.aliases = AliasMap.load(False)
        self.watch = Watch('w', 'Service', (('acme', 'server'),), (),
                           '1.0', Scheme.DOTTED, False)

    def output(self, rec):
        self.store.put_record(CVE, rec, NOW.isoformat())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = watch_check(self.store, (self.watch,), self.aliases, 90, NOW)
        self.assertEqual(status, 0)
        return output.getvalue()

    def test_near_miss_requires_vendor_or_product_overlap(self):
        for vendor, product, expected in (
                ('other', 'different', 'w: matched none; near misses none\n'),
                ('acme', 'different', 'w: matched none; near misses CVE-2026-1000\n'),
                ('other', 'server', 'w: matched none; near misses CVE-2026-1000\n')):
            with self.subTest(vendor=vendor, product=product):
                self.assertEqual(self.output(record(vendor, product)), expected)

    def test_equivalent_utc_and_offset_dates_share_90_day_cutoff(self):
        # Boundary is Nov 3 23:00Z minus 90 days. The positive offset must
        # not turn a record one hour outside the window into a recent record.
        published = NOW - timedelta(days=90, hours=1)
        for value in (published.isoformat(),
                      published.astimezone(timezone(timedelta(hours=5))).isoformat()):
            with self.subTest(value=value):
                self.assertEqual(self.output(record('acme', 'different', value)),
                                 'w: matched none; near misses none\n')

    def test_acceptance_replay_includes_unknown_exploited(self):
        import json
        self.store.connection.execute('INSERT INTO kev VALUES (?,?)',
            (CVE, json.dumps({'cveID': CVE, 'vendorProject': 'acme', 'product': 'server'})))
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'acceptance.toml'
            path.write_text('[[expect]]\nwatch_id="w"\ncve="CVE-2026-1000"\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = replay(self.store, (self.watch,), self.aliases, path)
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), 'w CVE-2026-1000: matched\n')

"""Offline CVE List regressions against the November 3 real archive layouts."""

import io
import json
from pathlib import Path
import unittest
from zipfile import ZipFile, ZIP_DEFLATED

from cornicen import validate
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.health import assess, container_healthy
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, Origin
from cornicen.sources.cvelist import RELEASES_URL
from cornicen.watchlist import load_watchlist_text
from tests import test_cvelist_source as helpers
from tests.replay.harness import FakeClock, RecordingNotifier, as_ingest, load_timeline
from tests.source_helpers import RAW, release

NOW = helpers.NOW
MANIFESTS = ('cves/delta.json', 'cves/deltaLog.json')


def snapshot_entries():
    with ZipFile(RAW / 'real_snapshot_trimmed.zip.zip') as outer:
        assert outer.namelist() == ['cves.zip']
        with ZipFile(io.BytesIO(outer.read('cves.zip'))) as inner:
            return [(entry, inner.read(entry)) for entry in inner.infolist()]


def zipped(entries, *, snapshot=False, reverse_directory=False):
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w', ZIP_DEFLATED) as target:
        for entry, body in entries:
            target.writestr(entry, body)
        if reverse_directory:
            # Change only central-directory order, leaving local headers intact.
            target.filelist.reverse()
    if snapshot:
        return zipped([('cves.zip', buffer.getvalue())])
    return buffer.getvalue()


class RealCveListTests(unittest.TestCase):
    setUp = helpers.CveListTests.setUp
    source = helpers.CveListTests.source
    cursor = helpers.CveListTests.cursor

    def snapshot(self, body):
        candidate = release(3)
        source, _ = self.source([candidate], **{
            candidate['assets'][0]['browser_download_url']: body})
        result = source._archive(candidate, Origin.SNAPSHOT, NOW)
        self.addCleanup(result.records.close)
        return result

    def assert_complete(self, result, count):
        self.assertEqual(result.status, FetchStatus.COMPLETE, result.errors[:5])
        self.assertEqual(result.errors, ())
        self.assertEqual(len(result.records), count)

    def test_real_snapshot_directories_are_silent(self):
        entries = snapshot_entries()
        directories = [entry.filename for entry, _ in entries if entry.is_dir()]
        self.assertEqual(len(directories), 229)
        self.assertIn('cves/', directories)
        self.assertIn('cves/2007/', directories)
        self.assertIn('cves/2007/20xxx/', directories)
        result = self.snapshot(zipped([(entry, body) for entry, body in entries
                                       if entry.filename not in MANIFESTS], snapshot=True))
        self.assert_complete(result, 200)

    def test_real_snapshot_manifests_do_not_describe_snapshot_coverage(self):
        entries = snapshot_entries()
        documents = {entry.filename: json.loads(body) for entry, body in entries
                     if not entry.is_dir()}
        ids = {value['cveMetadata']['cveId'] for name, value in documents.items()
               if name not in MANIFESTS}
        self.assertIsInstance(documents['cves/deltaLog.json'], list)
        self.assertEqual(len(documents['cves/deltaLog.json']), 3)
        self.assertEqual(documents['cves/delta.json']['numberOfChanges'], 7)
        self.assertTrue(validate.delta(documents['cves/delta.json'], ids))
        # Spec §6.3 requires delta completeness, not agreement between a full
        # snapshot and its last-delta metadata/history. Neither manifest is a
        # snapshot inventory; ignore their contents when ingesting a snapshot.
        result = self.snapshot(zipped([(entry, body) for entry, body in entries
                                       if not entry.is_dir()], snapshot=True))
        self.assert_complete(result, 200)

    def test_real_snapshot_bootstrap_through_source_and_engine(self):
        candidate = release(3)
        first, body = next((entry, body) for entry, body in snapshot_entries()
                           if '/CVE-' in entry.filename)
        # A same-day delta repeating an unchanged snapshot record adds no IDs.
        delta = zipped([('deltaCves/' + first.filename.rsplit('/', 1)[1], body)])
        source, _ = self.source([candidate], **{
            candidate['assets'][0]['browser_download_url']:
                (RAW / 'real_snapshot_trimmed.zip.zip').read_bytes(),
            candidate['assets'][1]['browser_download_url']: delta})
        results = source.poll(NOW)
        for result in results:
            self.addCleanup(result.records.close)
        self.assertEqual([result.origin for result in results], [Origin.SNAPSHOT, Origin.DELTA])
        self.assert_complete(results[0], 200)
        self.assert_complete(results[1], 1)

        rows = load_timeline('same_cycle_coalesce')
        watches = load_watchlist_text(rows[0]['watchlist'])
        clock = FakeClock(NOW)
        notifier = RecordingNotifier(clock)
        config = Config(str(Path(self.directory.name) / 'state.db'), Path('unused'),
                        None, 'https://ntfy.invalid', 'test', None)
        engine = Engine(self.store, watches, AliasMap.load(False), config, clock, notifier)
        other_feeds = [as_ingest(row['ingest']) for row in rows if
                       row.get('ingest', {}).get('source') in ('kev', 'epss')]
        report = engine.run_cycle(results + other_feeds)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 200)
        self.assertEqual(self.store.get_meta('cvelist_snapshot_complete'), '1')
        self.assertEqual(self.store.get_meta('baseline_complete'), '1')
        self.assertEqual(self.store.connection.execute(
            "SELECT value FROM cursors WHERE source='cvelist'").fetchone()[0], candidate['tag_name'])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 0)
        self.assertEqual(assess('cvelist', self.store, NOW, config)[0], 'healthy')
        self.assertTrue(container_healthy(self.store, NOW, config))
        self.assertEqual([item['reasons'] for item in notifier.delivered], [['baseline']])
        self.assertEqual(report.sent, 1)

    def test_real_end_of_day_catch_up_without_manifest_or_directories(self):
        self.cursor(release(2, 1)['tag_name'])
        hourly = release(2)
        eod = {'tag_name': 'cve_2026-11-02_at_end_of_day', 'assets': [{
            'name': '2026-11-02_delta_CVEs_at_end_of_day.zip',
            'browser_download_url': 'https://github.com/real/end-of-day'}]}
        with ZipFile(RAW / 'real_delta_end_of_day.zip') as fixture:
            names = fixture.namelist()
            self.assertEqual(len(names), 1194)
            self.assertTrue(all(name.startswith('deltaCves/CVE-') and name.endswith('.json')
                                for name in names))
        source, opener = self.source([hourly], **{
            RELEASES_URL + '/tags/' + eod['tag_name']: json.dumps(eod).encode(),
            eod['assets'][0]['browser_download_url']: (RAW / 'real_delta_end_of_day.zip').read_bytes()})
        result, = source.poll(NOW)
        self.addCleanup(result.records.close)
        self.assert_complete(result, 1194)
        self.assertEqual(result.origin, Origin.DELTA)
        self.assertEqual(result.cursor, eod['tag_name'])
        self.assertEqual(result.content_time.isoformat(), '2026-11-02T23:59:59+00:00')
        self.assertEqual([request.full_url for request in opener.requests], [
            RELEASES_URL, RELEASES_URL + '/tags/' + eod['tag_name'],
            eod['assets'][0]['browser_download_url']])
        self.assertEqual({record['cveMetadata']['cveId'] for record in result.records},
                         {name.rsplit('/', 1)[1][:-5] for name in names})

    def test_real_snapshot_counts_records_and_replays_archive_order(self):
        entries = snapshot_entries()
        self.assertEqual(len(entries), 431)
        expected = [json.loads(body) for entry, body in entries if '/CVE-' in entry.filename]
        for reverse in (False, True):
            with self.subTest(reverse_directory=reverse):
                result = self.snapshot(zipped(entries, snapshot=True, reverse_directory=reverse))
                self.assert_complete(result, 200)
                ordered = list(reversed(expected)) if reverse else expected
                self.assertEqual(list(result.records), ordered)
                self.assertEqual(list(result.records), ordered)

    def test_unexpected_directories_remain_partial_with_real_records(self):
        for snapshot in (False, True):
            for bad in ('cves/unexpected/', 'deltaCves/unexpected/', 'unexpected/',
                        'cves/2026/10xxx/nested/', 'cves/2026/nope/', 'cves/delta.json/'):
                with self.subTest(snapshot=snapshot, path=bad):
                    if snapshot:
                        entries = snapshot_entries()
                    else:
                        with ZipFile(RAW / 'real_delta_end_of_day.zip') as fixture:
                            entries = [(entry, fixture.read(entry)) for entry in fixture.infolist()]
                    data = zipped(entries + [(bad, b'')], snapshot=snapshot)
                    candidate = release(3)
                    source, _ = self.source([candidate], **{
                        candidate['assets'][int(not snapshot)]['browser_download_url']: data})
                    result = source._archive(candidate, Origin.SNAPSHOT if snapshot else Origin.DELTA, NOW)
                    self.addCleanup(result.records.close)
                    self.assertEqual(result.status, FetchStatus.PARTIAL)
                    self.assertEqual(result.errors, (bad + ': ValueError: Unexpected record path',))
                    self.assertEqual(len(result.records), 200 if snapshot else 1194)

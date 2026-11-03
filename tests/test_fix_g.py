"""Offline manifest and stored-projection regressions on public real CVEs."""

from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zlib

from cornicen import applicability, cli, validate
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.render import render
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch
from tests import test_fix_e as archive_helpers
from tests.test_fix_e import MANIFESTS, snapshot_entries, zipped
from tests.source_helpers import RAW, release, expected_projection
from tests.test_cvelist_source import NOW
from tests.replay.harness import FakeClock


def real_records():
    individual = [json.loads(path.read_text()) for path in sorted(RAW.glob('CVE-*.json'))]
    snapshot = [json.loads(body) for entry, body in snapshot_entries() if '/CVE-' in entry.filename]
    return individual, snapshot



class SnapshotManifestTests(unittest.TestCase):
    setUp = archive_helpers.RealCveListTests.setUp
    source = archive_helpers.RealCveListTests.source

    def test_12_mib_manifests_bootstrap_without_opening_them(self):
        for manifest in MANIFESTS:
            with self.subTest(manifest=manifest):
                self.store = Store(str(Path(self.directory.name) / (Path(manifest).name + '.db')))
                self.store.migrate()
                self.addCleanup(self.store.connection.close)
                # Retain the real layout and records; replace just one manifest.
                body = b'[' + b' ' * (12 * 1024 * 1024 - 2) + b']'
                archive = zipped([(entry, body if entry.filename == manifest else payload)
                                  for entry, payload in snapshot_entries()], snapshot=True)
                candidate = release(3)
                source, _ = self.source([candidate], **{
                    candidate['assets'][0]['browser_download_url']: archive,
                    candidate['assets'][1]['browser_download_url']:
                        zipped([('delta.json', b'{"numberOfChanges":0,"new":[],"updated":[]}')])})
                opened = []
                from cornicen.sources.cvelist import _SnapshotZip
                original = _SnapshotZip.open

                def tracked(zipped_file, entry, *args, **kwargs):
                    name = getattr(entry, 'filename', entry)
                    opened.append(name)
                    if name in MANIFESTS:
                        raise AssertionError('Snapshot manifest must never be opened')
                    return original(zipped_file, entry, *args, **kwargs)

                with patch.object(_SnapshotZip, 'open', tracked):
                    results = source.poll(NOW)
                for result in results:
                    self.addCleanup(result.records.close)
                self.assertEqual([r.status for r in results], [FetchStatus.COMPLETE] * 2,
                                 [r.errors for r in results])
                self.assertEqual(len(results[0].records), 200)
                self.assertTrue(set(MANIFESTS).isdisjoint(opened))
                clock = FakeClock(NOW)
                engine = Engine(self.store, (), AliasMap.load(False),
                                Config(':memory:', Path('unused'), None, 'https://ntfy.invalid', 'test', None),
                                clock, CaptureNotifier())
                engine.run_cycle(results)
                self.assertEqual(self.store.get_meta('cvelist_snapshot_complete'), '1')
                self.assertEqual(self.store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 200)


class CaptureNotifier:
    def __init__(self):
        self.items = []

    def send(self, notification):
        self.items.append((notification, render(notification)))
        return True


class ProjectionTests(unittest.TestCase):
    def store(self, path=':memory:'):
        store = Store(path)
        self.addCleanup(store.connection.close)
        store.migrate()
        return store

    def test_exact_projection_for_all_real_records(self):
        store = self.store()
        groups = real_records()
        self.assertEqual([len(group) for group in groups], [12, 200])
        for record in groups[0] + groups[1]:
            with self.subTest(cve=record['cveMetadata']['cveId']):
                before = deepcopy(record)
                key = record['cveMetadata']['cveId']
                store.put_record(key, record, NOW.isoformat())
                row = store.connection.execute('SELECT json FROM records WHERE id=?', (key,)).fetchone()
                projected = json.loads(zlib.decompress(row[0]))
                self.assertEqual(projected, expected_projection(record))
                self.assertEqual(validate.record(projected), [])
                self.assertEqual(record, before)

    def test_migration_batches_text_and_compressed_records_and_resumes(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = str(Path(directory) / 'legacy.db')
            store = Store(path)
            self.addCleanup(store.connection.close)
            db = store.connection
            db.execute('CREATE TABLE records(id TEXT PRIMARY KEY,json BLOB NOT NULL,ingested_at TEXT NOT NULL)')
            records = real_records()[1]
            for index, record in enumerate(records):
                raw = json.dumps(record)
                db.execute('INSERT INTO records VALUES (?,?,?)',
                           (record['cveMetadata']['cveId'], raw if index % 2 else zlib.compress(raw.encode()), 'original'))
            keys = sorted(record['cveMetadata']['cveId'] for record in records)
            # A failure beyond the first batch must not roll back earlier batches.
            db.execute(f'''CREATE TRIGGER interrupt_projection BEFORE UPDATE OF json ON records
                WHEN NEW.id='{keys[150]}' BEGIN SELECT RAISE(ABORT, 'interrupted'); END''')
            with self.assertRaises(sqlite3.IntegrityError):
                store.migrate()
            row = db.execute('SELECT json FROM records WHERE id=?', (keys[0],)).fetchone()
            original = next(r for r in records if r['cveMetadata']['cveId'] == keys[0])
            self.assertEqual(json.loads(zlib.decompress(row[0])), expected_projection(original))
            self.assertIsNone(store.get_meta('record_projection_version'))
            self.assertEqual(store.get_meta('record_projection_cursor'), keys[127])
            db.execute('DROP TRIGGER interrupt_projection')
            db.close()
            store = self.store(path)
            self.assertEqual(store.get_meta('record_projection_version'), '1')
            for record in records:
                row = store.connection.execute('SELECT json,ingested_at FROM records WHERE id=?',
                                               (record['cveMetadata']['cveId'],)).fetchone()
                self.assertEqual(json.loads(zlib.decompress(row[0])), expected_projection(record))
                self.assertEqual(row['ingested_at'], 'original')
            before = list(map(tuple, store.connection.execute('SELECT * FROM records ORDER BY id')))
            store.migrate()
            self.assertEqual(list(map(tuple, store.connection.execute('SELECT * FROM records ORDER BY id'))), before)

    def test_invalid_payloads_keep_validation_and_retry_identity(self):
        store = self.store()
        base = real_records()[0][0]
        for record in ({'bad': 'record'}, dict(base, cveMetadata=[]),
                       dict(base, containers={'cna': {'affected': 'invalid'}})):
            key = Engine._retry_identity(record)[1]
            store.put_record(key, record, NOW.isoformat())
            raw = store.connection.execute('SELECT json FROM records WHERE id=?', (key,)).fetchone()[0]
            self.assertEqual(json.loads(zlib.decompress(raw)), record)
            self.assertTrue(validate.record(record))

    def test_real_snapshot_compressed_size_is_less_than_half(self):
        store = self.store()
        records = real_records()[1]
        full = sum(len(zlib.compress(json.dumps(record).encode())) for record in records)
        for record in records:
            store.put_record(record['cveMetadata']['cveId'], record, NOW.isoformat())
        projected = store.connection.execute('SELECT sum(length(json)) FROM records').fetchone()[0]
        self.assertLess(projected, full / 2)

    def exercise_readers(self, records, directory, full):
        store = self.store(str(directory / 'state.db'))
        if full:
            # The control preserves the old storage format, using the same readers.
            def put_full(key, record, stamp):
                store.connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',
                                         (key, zlib.compress(json.dumps(record).encode()), stamp))
                store.dirty_record(key)
            store.put_record = put_full
        watches = []
        for index, record in enumerate(records):
            entries = record.get('containers', {}).get('cna', {}).get('affected', [])
            entry = next((e for e in entries if e.get('vendor') and e.get('product')), {})
            versions = entry.get('versions') or [{}]
            version = versions[0].get('version', '1')
            if not version or ',' in version or version.startswith(('=', '>', '<')):
                version = '1'
            scheme = Scheme.OPAQUE
            if versions[0].get('versionType') in ('semver', 'dotted', 'debian'):
                scheme = Scheme(versions[0]['versionType'])
            watch = Watch(f'w{index}', 'Fixture watch', ((entry.get('vendor', 'absent'),
                          entry.get('product', 'absent')),), (), version, scheme, index % 2 == 0)
            watches.extend((watch, replace(watch, id=f'loose{index}', match=(),
                                           product_only=(watch.match[0][1].lower(),))))
        watches = tuple(watches)
        aliases = AliasMap.load(False)
        clock = FakeClock(NOW)
        notifier = CaptureNotifier()
        config = Config(str(directory / 'state.db'), Path('unused'), None, 'https://ntfy.invalid', 'test', None)
        engine = Engine(store, watches, aliases, config, clock, notifier)
        store.set_meta('baseline_complete', '1')
        ingest = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA, None, NOW, tuple(records))
        with patch.object(engine, '_apply_record', side_effect=RuntimeError('retry fixture')):
            engine.run_cycle([ingest])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM retry_queue').fetchone()[0], len(records))
        engine.run_cycle([])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 0,
                         list(map(tuple, store.connection.execute('SELECT * FROM retry_queue'))))
        # Resolve every real record against scoped and loose watches, both with
        # and without KEV; _body also exercises stored CNA CVSS and render inputs.
        results = []
        bodies = []
        kev = {}
        for index, record in enumerate(records):
            key = record['cveMetadata']['cveId']
            watch = watches[index * 2]
            kev[key] = {'cveID': key, 'vendorProject': watch.match[0][0], 'product': watch.match[0][1]}
            stored = engine._record(key)
            for w in watches[index * 2:index * 2 + 2]:
                for evidence in (None, kev[key]):
                    result = applicability.resolve(stored, evidence, w, aliases)
                    results.append(result)
                    if result:
                        bodies.append(engine._body(w, key, result))
        self.assertTrue(any(result is not None for result in results))
        self.assertTrue(bodies)
        engine.run_cycle([IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, 'fixture', NOW, kev=kev),
                          IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, 'fixture', NOW,
                                       epss={key: (.5, .9) for key in kev}, epss_date=NOW.date())])
        # All three retry dispatch branches and the dead-letter retry reader.
        for source in ('cvelist', 'kev', 'watchlist'):
            for key in kev:
                engine._retry(source, key, 'retry fixture')
        key = next(iter(kev))
        for _ in range(4):
            engine._retry('watchlist', key, 'dead-letter fixture')
        self.assertEqual(store.connection.execute('SELECT count(*) FROM dead_letters').fetchone()[0], 1)
        clock.now += timedelta(days=1)
        engine.run_cycle([])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 0,
                         list(map(tuple, store.connection.execute('SELECT * FROM retry_queue'))))
        self.assertEqual(store.connection.execute('SELECT count(*) FROM dead_letters').fetchone()[0], 0)
        engine.reload_watches(tuple(replace(w, name='Reloaded watch') for w in watches))
        engine.run_cycle([])
        # Startup re-match, including changed watches and revalidation of outbox.
        engine = Engine(store, tuple(replace(w, name='Startup watch') for w in watches),
                        aliases, config, clock, notifier)
        engine.run_cycle([])
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.watch_check(store, watches, aliases, 100000, NOW), 0)
            acceptance = directory / 'acceptance.toml'
            acceptance.write_text('\n'.join(f'[[expect]]\nwatch_id="w{i}"\ncve="{r["cveMetadata"]["cveId"]}"'
                                             for i, r in enumerate(records)))
            replay_code = cli.replay(store, watches, aliases, acceptance)
            with patch('cornicen.cli.load_config', return_value=config):
                self.assertEqual(cli.main(['report']), 0)
        # Rejection/correction and reactivation also rebuild notification bodies
        # from the stored projection, including after delivery/revalidation.
        rejected = deepcopy(records)
        for record in rejected:
            record['cveMetadata']['state'] = 'REJECTED'
        engine.run_cycle([replace(ingest, records=tuple(rejected), content_time=clock())])
        clock.now += timedelta(days=1)
        engine.run_cycle([])
        engine.run_cycle([replace(ingest, content_time=clock())])
        tables = {table: list(map(tuple, store.connection.execute(f'SELECT * FROM {table} ORDER BY 1,2')))
                  for table in ('pairs', 'events', 'outbox', 'retry_queue', 'dead_letters')}
        self.assertTrue(tables['pairs'])
        self.assertTrue(notifier.items)
        return results, bodies, output.getvalue(), replay_code, tables, notifier.items

    def test_every_stored_record_reader_matches_full_records(self):
        for records in real_records():
            with self.subTest(records=len(records)), tempfile.TemporaryDirectory(dir='.') as directory:
                root = Path(directory)
                (root / 'full').mkdir()
                (root / 'projected').mkdir()
                self.assertEqual(self.exercise_readers(records, root / 'projected', False),
                                 self.exercise_readers(records, root / 'full', True))

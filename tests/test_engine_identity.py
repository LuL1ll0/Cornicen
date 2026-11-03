"""Behavioral probes for durable and compiled identities."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen.identity import AliasMap
from cornicen.engine import Engine
from cornicen.model import Origin
from tests import test_engine as helpers
from tests.source_helpers import expected_projection


class EngineIdentityTests(unittest.TestCase):
    setUp = helpers.EngineTests.setUp
    start = helpers.EngineTests.start
    ingest = helpers.EngineTests.ingest

    def test_untagged_snapshot_replay_cannot_replace_committed_record(self):
        self.start()
        original = replace(self.ingest([self.record]), origin=Origin.SNAPSHOT, cursor=None)
        self.engine.run_cycle([original])
        record_id = self.record['cveMetadata']['cveId']
        self.assertEqual(self.engine._record(record_id), expected_projection(self.record))
        revision = deepcopy(self.record)
        revision['cveMetadata']['state'] = 'REJECTED'
        self.engine.run_cycle([replace(original, records=(revision,))])
        self.assertEqual(self.engine._record(record_id), expected_projection(self.record))

    def test_reconcile_preserves_first_snapshot_cutoff(self):
        self.start()
        cutoff = self.store.get_meta('cvelist_snapshot_cutoff')
        self.assertIsNotNone(cutoff)
        self.clock.now += timedelta(days=1)
        self.engine.run_cycle([replace(self.ingest([]), origin=Origin.SNAPSHOT,
                                       cursor='cve_2026-11-04_0700Z')])
        self.assertEqual(self.store.get_meta('cvelist_snapshot_cutoff'), cutoff)

    def test_startup_rejection_recovery_preserves_pending_watchlist_retry(self):
        self.start()
        self.engine._health('watchlist', 'unhealthy', 'Watchlist reload rejected')
        self.store.connection.execute('INSERT INTO retry_queue VALUES (?,?,?,?,?)',
            ('watchlist', 'CVE-2026-22222', 1, self.clock().isoformat(), 'rematch pending'))
        Engine(self.store, self.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='watchlist'").fetchone()[0], 'unhealthy')

    def test_completing_older_work_never_rewinds_release_position(self):
        newest = '2026-11-03T07:00:00+00:00'
        self.store.set_meta('cvelist_release_position', newest)
        with self.store.transaction():
            self.engine._complete_cursor('cvelist', {
                'cursor': 'cve_2026-11-03_0600Z',
                'content_time': '2026-11-03T06:00:00+00:00',
                'release_identity': 'delta:cve_2026-11-03_0600Z',
                'release_position': '2026-11-03T06:00:00+00:00'})
        self.assertEqual(self.store.get_meta('cvelist_release_position'), newest)

    def test_delivery_rechecks_retry_deadline_between_sends(self):
        self.start()
        other = deepcopy(self.record)
        other['cveMetadata']['cveId'] = 'CVE-2026-22222'
        self.engine.run_cycle([self.ingest([self.record, other])])
        retry = (self.clock() + timedelta(minutes=30)).isoformat()
        calls = []
        def send(notification):
            calls.append(notification)
            self.store.connection.execute('UPDATE outbox SET next_attempt_at=? WHERE sent_at IS NULL',
                                          (retry,))
            return True
        scores = {record['cveMetadata']['cveId']: (.5, .99) for record in (self.record, other)}
        with patch.object(self.notifier, 'send', side_effect=send):
            report = self.engine.run_cycle([replace(self.baseline[2], epss=scores)])
        self.assertEqual(len(calls), 1)
        self.assertEqual(report.sent, 1)
        pending = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchall()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]['next_attempt_at'], retry)
        self.assertEqual(pending[0]['attempts'], 0)

    def test_alias_only_reload_rematches_stored_record(self):
        self.start()
        record = deepcopy(self.record)
        entry = record['containers']['cna']['affected'][0]
        entry.update(vendor='renamed-vendor', product='renamed-product')
        self.engine.run_cycle([self.ingest([record])])
        self.assertIsNone(self.store.connection.execute('SELECT * FROM pairs').fetchone())
        identity = ':'.join(self.watches[0].match[0])
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'aliases.toml'
            path.write_text('version = "new-aliases"\n[[alias]]\nidentities = ['
                            + json.dumps(identity) + ', "renamed-vendor:renamed-product"]\n')
            self.engine.aliases = AliasMap.load(False, extra=path)
            self.engine.reload_watches(self.watches)
        pair = self.store.connection.execute('SELECT * FROM pairs').fetchone()
        self.assertIsNotNone(pair)
        self.assertEqual(pair['state'], 'affected')
        self.assertEqual(pair['alias_map_version'], self.engine.aliases.version)

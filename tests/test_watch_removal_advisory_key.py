# script-purpose: Verify that removing a watch keeps delivered keys and drops queued keys.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_watch_removal_advisory_key.py
"""Read invented advisory and feed fixtures; write only in-memory SQLite state.

Run with unittest, which exits 0 on success and 1 on failure.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.feedvalidate import validate_advisory
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch
from tests.replay.harness import FakeClock, RecordingNotifier


CVE = 'CVE-2099-98301'
PAIR = f'turbine|{CVE}'
CORRECTION = f'{PAIR}|correction'


class WatchRemovalAdvisoryKeyTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.db = self.store.connection
        self.clock = FakeClock(datetime(2099, 1, 1, 7, tzinfo=timezone.utc))
        self.notifier = RecordingNotifier(self.clock)
        self.watch = Watch(*('turbine', 'Cloud Turbine', (('cloudforge', 'cloud-turbine'),), (),
                             '1.0.0', Scheme.SEMVER, False))
        config = Config(':memory:', Path('unused'), None, 'https://cloudforge.invalid', 'test', None)
        self.engine = Engine(self.store, (self.watch,), AliasMap(), config, self.clock, self.notifier)
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('kev_initialized', '1')

    def revise_advisory(self, status):
        now = self.clock().isoformat()
        raw = dict(id='FIX-2099-98301', title='Cloud Turbine advisory',
                   url='https://cloudforge.invalid/advisories/98301', published='2099-01-01T07:00:00Z',
                   updated=now, cves=[CVE], products=[dict(id='p', name='cloudforge:cloud-turbine')],
                   evidence=[dict(product_id='p', scheme='semver', status=status,
                                  range=dict(introduced='1.0.0', limit='2.0.0'))])
        self.engine.commit_advisory(validate_advisory(raw, source='fixture_a', observed_at=now).data)

    def deliver_digest(self):
        self.clock.now += timedelta(days=1)
        self.engine.run_cycle([])

    def close_advisory_episode(self):
        self.revise_advisory('known_affected')
        self.deliver_digest()
        self.revise_advisory('known_not_affected')

    def correction_rows(self):
        return self.db.execute('SELECT id, sent_at FROM outbox WHERE pair_key=? ORDER BY id',
                               (CORRECTION,)).fetchall()

    def keys(self, *, corrections_only=False):
        rows = self.db.execute('SELECT key, type FROM events WHERE watch_id=? AND record_id=?',
                               (self.watch.id, CVE))
        return {row['key'] for row in rows if not corrections_only or row['type'] == 'correction'}

    def queue_second_advisory_correction(self):
        self.close_advisory_episode()
        self.deliver_digest()
        self.close_advisory_episode()

    def test_removal_keeps_delivered_advisory_key_and_drops_queued_key(self):
        self.queue_second_advisory_correction()
        delivered, queued = self.correction_rows()
        self.assertIsNotNone(delivered['sent_at'])
        self.assertIsNone(queued['sent_at'])
        self.assertEqual(self.keys(corrections_only=True), {f'{CORRECTION}|1', f'{CORRECTION}|2'})

        self.engine.reload_watches(())

        self.assertEqual(self.correction_rows(), [delivered])
        self.assertEqual(self.keys(corrections_only=True), {f'{CORRECTION}|1'})

    def test_readding_watch_does_not_send_the_delivered_correction_again(self):
        self.queue_second_advisory_correction()
        corrections = lambda: [notice for notice in self.notifier.delivered
                               if notice['watch'] == self.watch.id and notice['record'] == CVE
                               and notice['reasons'] == ['correction']]
        before = corrections()
        self.assertEqual(len(before), 1)

        self.engine.reload_watches(())
        sent = {f'{PAIR}|new match|1', f'{PAIR}|new match|2', f'{CORRECTION}|1'}
        self.assertEqual(self.keys(), sent)
        self.engine.reload_watches((self.watch,))
        self.revise_advisory('known_not_affected')
        self.deliver_digest()

        self.assertEqual(corrections(), before)
        self.assertEqual(self.keys(), sent)

        self.close_advisory_episode()
        self.deliver_digest()

        self.assertEqual(len(corrections()), 2)
        self.assertEqual(corrections()[:1], before)
        self.assertEqual(self.keys(), sent | {f'{PAIR}|new match|3', f'{CORRECTION}|3'})

    def test_removal_preserves_plain_cve_list_and_kev_behavior(self):
        def ingest(status):
            entry = dict(vendor='cloudforge', product='cloud-turbine', defaultStatus='unaffected',
                         versions=[dict(version='1.0.0', status=status)])
            record = dict(cveMetadata=dict(cveId=CVE, state='PUBLISHED'),
                          containers=dict(cna=dict(affected=[entry])))
            return IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                None, self.clock(), records=[record])

        kev = dict(cveID=CVE, vendorProject='cloudforge', product='cloud-turbine',
                   dateAdded='2099-01-01', dueDate='2099-01-22')
        self.engine.run_cycle([ingest('affected'), IngestResult('kev', FetchStatus.COMPLETE,
                              Origin.CATALOG, 'catalog', self.clock(), kev={CVE: kev})])
        self.engine.run_cycle([ingest('unaffected')])
        self.assertEqual([notice['reasons'] for notice in self.notifier.delivered
                          if notice['watch'] == self.watch.id], [['new match', 'KEV added']])
        queued, = self.correction_rows()
        self.assertIsNone(queued['sent_at'])
        sent = {f'{PAIR}|new match|1', f'{PAIR}|KEV added|1'}
        self.assertEqual(self.keys(), sent | {f'{CORRECTION}|1'})

        self.engine.reload_watches(())

        self.assertEqual(self.correction_rows(), [])
        self.assertEqual(self.keys(), sent)

    def test_removal_keeps_advisory_key_when_only_correction_was_delivered(self):
        self.close_advisory_episode()
        self.deliver_digest()
        delivered, = self.correction_rows()
        self.assertIsNotNone(delivered['sent_at'])

        self.engine.reload_watches(())

        self.assertEqual(self.correction_rows(), [delivered])
        self.assertEqual(self.keys(corrections_only=True), {f'{CORRECTION}|1'})

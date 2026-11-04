"""Alias group changes use ordinary transactional startup re-matching."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import health
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch


CVE = 'CVE-2026-99001'


class AliasRematchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / 'aliases.toml'
        self.db_path = str(self.directory / 'state.sqlite')
        self.now = datetime(2026, 11, 3, 7, tzinfo=timezone.utc)
        self.watch = Watch('widget', 'Acme widget', (('acme', 'widget'),), (),
                           '1.0.0', Scheme.SEMVER, False)
        self.config = Config(self.db_path, Path('unused'), None,
                             'https://ntfy.invalid', 'test', None)
        self.sent = []
        self.notifier = Mock()
        self.notifier.send.side_effect = lambda n: self.sent.append(n) or True
        self.aliases = self.load_aliases()
        self.restart()
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('kev_initialized', '1')
        for source in ('cvelist', 'kev', 'epss'):
            self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                         (source, None, self.now.isoformat()))
        record = {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': [{'vendor': 'acme-labs',
                      'product': 'widget-next', 'defaultStatus': 'unaffected',
                      'versions': [{'version': '1.0.0', 'status': 'affected'}]}]}}}
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.DELTA, None, self.now, records=(record,))])
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.sent, [])

    def load_aliases(self, linked=False, version='same'):
        text = f'version="{version}"\n'
        if linked:
            text += '[[alias]]\nidentities=["acme:widget","acme-labs:widget-next"]\n'
        self.path.write_text(text)
        return AliasMap.load(False, self.path)

    def restart(self, aliases=None, watches=None):
        if hasattr(self, 'store'):
            self.store.connection.close()
        self.store = Store(self.db_path)
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.engine = Engine(self.store, (self.watch,) if watches is None else watches,
                             self.aliases if aliases is None else aliases,
                             self.config, lambda: self.now, self.notifier)

    def count(self, table):
        return self.store.connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]

    def deliver_digest(self):
        self.now += timedelta(hours=1)
        self.engine.run_cycle([])

    def reset_bootstrap(self):
        record = self.engine._record(CVE)
        self.store.connection.execute('DELETE FROM records')
        self.store.connection.execute('DELETE FROM cursors')
        for key in ('baseline_complete', 'kev_initialized', 'complete:cvelist',
                    'complete:kev', 'complete:epss'):
            self.store.connection.execute('DELETE FROM meta WHERE k=?', (key,))
        return record

    def finish_bootstrap(self, ids):
        self.engine.run_cycle([
            IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, None, self.now, kev={}),
            IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, None, self.now,
                         epss={cve: (.8, .99) for cve in ids}, epss_date=self.now.date())])
        self.assertEqual(self.store.get_meta('baseline_complete'), '1')

    def assert_snapshot_silent(self, ids):
        self.assertEqual([row['record_id'] for row in self.store.connection.execute(
            "SELECT record_id FROM events WHERE watch_id='widget'")
            if row['record_id'] in ids], [])
        self.assertEqual([row['pair_key'] for row in self.store.connection.execute(
            'SELECT pair_key FROM outbox') if row['pair_key'] in
            {'widget|' + cve for cve in ids}], [])
        self.assertEqual([n for n in self.sent if n.record_id in ids], [])
        self.assertEqual([item for n in self.sent for item in n.body.get('items', [])
                          if item['record_id'] in ids], [])

    def bootstrap_rematch(self, watch_edit=False):
        record = self.reset_bootstrap()
        ids = [f'CVE-2026-{200000 + i}' for i in range(50)]
        snapshots = []
        for cve in ids:
            value = json.loads(json.dumps(record))
            value['cveMetadata']['cveId'] = cve
            snapshots.append(value)
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, None, self.now, records=tuple(snapshots))])
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.DELTA, None, self.now, records=(record,))])
        self.assertIsNone(self.store.get_meta('baseline_complete'))
        self.assertEqual(self.count('pairs'), 0)
        self.assertTrue(all(self.store.get_meta('record_baseline:' + cve) == '1' for cve in ids))
        if watch_edit:
            self.engine.reload_watches((replace(self.watch, match=(('acme-labs', 'widget-next'),)),))
        else:
            self.restart(self.load_aliases(linked=True))
        self.assertEqual(self.count('pairs'), 51)
        self.assert_snapshot_silent(ids)
        self.assertEqual(self.store.connection.execute(
            'SELECT count(*) FROM pairs WHERE baseline=1').fetchone()[0], 50)
        self.finish_bootstrap(ids + [CVE])
        self.assert_snapshot_silent(ids)
        delta_alerts = [n for n in self.sent if n.record_id == CVE]
        self.assertEqual(len(delta_alerts), 1)
        self.assertEqual(delta_alerts[0].urgency, 'urgent')
        self.assertEqual(delta_alerts[0].reasons, ('new match',))
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM events WHERE watch_id='widget'").fetchone()[0], 1)
        summary = [n for n in self.sent if n.record_id == 'baseline']
        self.assertEqual(len(summary), 1)
        self.assertIn('50 historical matches, 0 exploited', summary[0].body['detail'])

    def test_bootstrap_alias_rematch_keeps_50_snapshot_matches_historical(self):
        self.bootstrap_rematch()

    def test_bootstrap_watch_edit_keeps_50_snapshot_matches_historical(self):
        self.bootstrap_rematch(watch_edit=True)

    def test_bootstrap_existing_baseline_pair_alias_activation_is_silent(self):
        record = self.reset_bootstrap()
        entry = json.loads(json.dumps(record['containers']['cna']['affected'][0]))
        entry.update(vendor='acme', product='widget')
        entry['versions'][0]['version'] = '2.0.0'
        record['containers']['cna']['affected'].append(entry)
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, None, self.now, records=(record,))])
        pair = self.store.connection.execute('SELECT state,baseline FROM pairs').fetchone()
        self.assertEqual(tuple(pair), ('not_affected', 1))
        self.restart(self.load_aliases(linked=True))
        self.assert_snapshot_silent([CVE])
        self.finish_bootstrap([CVE])
        self.assert_snapshot_silent([CVE])
        pair = self.store.connection.execute('SELECT state,baseline FROM pairs').fetchone()
        self.assertEqual(tuple(pair), ('affected', 1))
        summary = next(n for n in self.sent if n.record_id == 'baseline')
        self.assertIn('1 historical matches', summary.body['detail'])

    def test_completed_bootstrap_alias_match_of_snapshot_alerts_normally(self):
        record = self.reset_bootstrap()
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, None, self.now, records=(record,))])
        self.finish_bootstrap([CVE])
        self.assertEqual(self.store.get_meta('record_baseline:' + CVE), '1')
        self.assertEqual(self.count('pairs'), 0)
        self.restart(self.load_aliases(linked=True))
        self.engine.run_cycle([])
        alerts = [n for n in self.sent if n.record_id == CVE]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].urgency, 'urgent')
        self.assertEqual(alerts[0].reasons, ('new match',))
        self.assertEqual(self.store.connection.execute('SELECT baseline FROM pairs').fetchone()[0], 0)
        self.engine.run_cycle([])
        self.assertEqual(len([n for n in self.sent if n.record_id == CVE]), 1)

    def test_bootstrap_watchlist_retry_preserves_snapshot_baseline(self):
        record = self.reset_bootstrap()
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, None, self.now, records=(record,))])
        with patch('cornicen.applicability.resolve', side_effect=ValueError('retry matching')):
            self.restart(self.load_aliases(linked=True))
        retry = self.store.connection.execute('SELECT source,record_id FROM retry_queue').fetchone()
        self.assertEqual(tuple(retry), ('watchlist', CVE))
        self.assertEqual(self.count('pairs'), 0)
        self.engine.run_cycle([])
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertEqual(self.count('dead_letters'), 0)
        self.assertEqual(self.count('pairs'), 1)
        self.assert_snapshot_silent([CVE])
        self.assertEqual(self.store.connection.execute('SELECT baseline FROM pairs').fetchone()[0], 1)
        self.finish_bootstrap([CVE])
        self.assert_snapshot_silent([CVE])
        summary = next(n for n in self.sent if n.record_id == 'baseline')
        self.assertIn('1 historical matches', summary.body['detail'])

    def test_bootstrap_alias_rematch_of_first_kev_delta_alerts_as_new_match(self):
        record = self.reset_bootstrap()
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.DELTA, None, self.now, records=(record,))])
        entry = {'cveID': CVE, 'vendorProject': 'acme-labs', 'product': 'widget-next',
                 'dateAdded': '2026-11-03', 'dueDate': '2026-11-24'}
        self.engine.run_cycle([IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
            None, self.now, kev={CVE: entry})])
        self.assertFalse(self.store.get_meta('record_baseline:' + CVE))
        self.assertEqual(self.store.get_meta('kev_baseline:' + CVE), '1')
        self.assertIsNone(self.store.get_meta('baseline_complete'))
        self.assertEqual(self.count('pairs'), 0)
        self.restart(self.load_aliases(linked=True))
        self.engine.run_cycle([IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
            None, self.now, epss={CVE: (.8, .99)}, epss_date=self.now.date())])
        self.assertEqual(self.store.get_meta('baseline_complete'), '1')
        # A delta CVE is new even when the first KEV catalog listed it.
        self.assertEqual(self.store.connection.execute('SELECT baseline FROM pairs').fetchone()[0], 0)
        alerts = [n for n in self.sent if n.record_id == CVE]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].urgency, 'urgent')
        self.assertEqual(alerts[0].reasons, ('new match',))
        summary = next(n for n in self.sent if n.record_id == 'baseline')
        self.assertIn('0 historical matches, 0 exploited', summary.body['detail'])

    def test_local_groups_edited_with_same_version_rematch_into_digest(self):
        aliases = self.load_aliases(linked=True)
        # load() embeds the file checksum in version; force the exact same version
        # too, so this test cannot pass by comparing version strings alone.
        aliases.version = self.aliases.version
        self.restart(aliases)
        self.assertEqual(self.count('pairs'), 1)
        self.assertEqual(self.count('events'), 1)
        self.assertEqual(self.sent, [])
        queued = self.store.connection.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual(queued['urgency'], 'normal')
        self.assertEqual(json.loads(queued['reasons_json']), ['new match'])
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0].body['items'][0]['record_id'], CVE)

    def test_version_only_change_does_not_rematch(self):
        with patch.object(Engine, 'reload_watches', autospec=True) as reload:
            self.restart(self.load_aliases(version='second'))
        reload.assert_not_called()
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.count('events'), 0)
        self.deliver_digest()
        self.assertEqual(self.sent, [])

    def test_unchanged_map_does_not_rematch_or_notify_again(self):
        aliases = self.load_aliases(linked=True)
        self.restart(aliases)
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)
        with patch.object(Engine, 'reload_watches', autospec=True) as reload:
            self.restart(aliases)
        reload.assert_not_called()
        self.engine.run_cycle([])
        self.assertEqual(self.count('pairs'), 1)
        self.assertEqual(self.count('events'), 1)
        self.assertEqual(len(self.sent), 1)

    def test_upgrade_without_fingerprint_rematches_changed_groups_once(self):
        # Review probe 14: unchanged watches must not hide unknown alias coverage.
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_aliases_hash'")
        aliases = self.load_aliases(linked=True)
        self.restart(aliases)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        self.assertEqual(self.count('pairs'), 1)
        self.assertEqual(self.count('events'), 1)
        queued = self.store.connection.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual(queued['urgency'], 'normal')
        self.assertEqual(json.loads(queued['reasons_json']), ['new match'])
        self.assertEqual(self.sent, [])
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0].body['items'][0]['record_id'], CVE)
        self.restart(aliases)
        self.engine.run_cycle([])
        self.assertEqual(self.count('pairs'), 1)
        self.assertEqual(self.count('events'), 1)
        self.assertEqual(len(self.sent), 1)

    def test_upgrade_without_fingerprint_preserves_delivered_event_keys(self):
        aliases = self.load_aliases(linked=True)
        self.restart(aliases)
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)
        keys = [row[0] for row in self.store.connection.execute('SELECT key FROM events')]
        self.assertEqual(len(keys), 1)
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_aliases_hash'")
        with patch.object(Engine, 'reload_watches', autospec=True,
                          side_effect=Engine.reload_watches) as reload:
            self.restart(aliases)
        self.assertEqual(reload.call_count, 1)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        self.deliver_digest()
        self.assertEqual([row[0] for row in self.store.connection.execute('SELECT key FROM events')], keys)
        self.assertEqual(self.count('outbox'), 1)
        self.assertEqual(len(self.sent), 1)

    def test_aborted_rematch_rolls_back_hash_and_retries_without_duplicates(self):
        old_hash = self.store.get_meta('applied_aliases_hash')
        aliases = self.load_aliases(linked=True)
        save_watches = Engine._save_watches

        def abort(engine):
            save_watches(engine)
            self.assertEqual(self.count('pairs'), 1)
            self.assertEqual(self.count('events'), 1)
            raise RuntimeError('simulated crash before commit')

        with patch.object(Engine, '_save_watches', abort):
            with self.assertRaisesRegex(RuntimeError, 'simulated crash'):
                self.restart(aliases)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), old_hash)
        for table in ('pairs', 'events', 'outbox'):
            self.assertEqual(self.count(table), 0)
        self.assertEqual(self.sent, [])
        self.restart(aliases)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)
        # Replay after a committed delivery, as if the fingerprint write was lost.
        self.store.set_meta('applied_aliases_hash', old_hash)
        self.restart(aliases)
        self.engine.run_cycle([])
        for table in ('pairs', 'events', 'outbox'):
            self.assertEqual(self.count(table), 1)
        self.assertEqual(len(self.sent), 1)

    def test_new_alias_match_with_kev_is_urgent(self):
        entry = {'cveID': CVE, 'vendorProject': 'acme-labs', 'product': 'widget-next',
                 'dateAdded': '2026-11-03', 'dueDate': '2026-11-24'}
        self.engine.run_cycle([IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
            'catalog', self.now, kev={CVE: entry})])
        self.assertEqual(self.count('pairs'), 0)
        self.restart(self.load_aliases(linked=True))
        self.engine.run_cycle([])
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0].urgency, 'urgent')
        self.assertEqual(self.sent[0].reasons, ('new match',))
        self.assertEqual(self.sent[0].record_id, CVE)

    def test_alias_and_watch_change_rematch_once(self):
        reload_watches = Engine.reload_watches
        with patch.object(Engine, 'reload_watches', autospec=True,
                          side_effect=reload_watches) as reload:
            self.restart(self.load_aliases(linked=True),
                         (replace(self.watch, name='Acme renamed widget'),))
        self.assertEqual(reload.call_count, 1)
        self.assertEqual(self.count('pairs'), 1)
        self.assertEqual(self.count('events'), 1)
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)

    def test_malformed_stored_fingerprint_rematches(self):
        aliases = self.load_aliases(linked=True)
        for bad in ('garbage', b'not-a-string'):
            with self.subTest(fingerprint=bad):
                self.store.connection.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                                             ('applied_aliases_hash', bad))
                with patch.object(Engine, 'reload_watches', autospec=True,
                                  side_effect=Engine.reload_watches) as reload:
                    self.restart(aliases)
                self.assertEqual(reload.call_count, 1)
                self.assertEqual(self.count('pairs'), 1)
                self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        self.deliver_digest()
        self.assertEqual(len(self.sent), 1)

    def test_incomplete_bootstrap_rematches_snapshot_and_delta_at_startup(self):
        # Review probe 01: complete CVE snapshot, but no first KEV/EPSS completion.
        record = self.engine._record(CVE)
        second = 'CVE-2026-99002'
        delta = json.loads(json.dumps(record))
        delta['cveMetadata']['cveId'] = second
        self.store.connection.execute('DELETE FROM records')
        self.store.connection.execute('DELETE FROM cursors')
        for key in ('baseline_complete', 'kev_initialized', 'complete:cvelist',
                    'complete:kev', 'complete:epss'):
            self.store.connection.execute('DELETE FROM meta WHERE k=?', (key,))
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.SNAPSHOT, None, self.now, records=(record,))])
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
            Origin.DELTA, None, self.now, records=(delta,))])
        self.assertEqual(self.store.get_meta('complete:cvelist'), '1')
        self.assertIsNone(self.store.get_meta('baseline_complete'))
        aliases = self.load_aliases(linked=True)
        self.restart(aliases)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        self.assertEqual(self.count('records'), 2)
        self.assertEqual(self.count('pairs'), 2)
        self.assertEqual(self.sent, [])
        kev_id = 'CVE-2026-99999'
        kev = {kev_id: {'cveID': kev_id, 'vendorProject': 'unrelated', 'product': 'other',
                        'dateAdded': '2026-11-03', 'dueDate': '2026-11-24'}}
        self.engine.run_cycle([
            IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, None, self.now, kev=kev),
            IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES, None, self.now,
                         epss={CVE: (.8, .99), second: (.8, .99)}, epss_date=self.now.date())])
        self.assertEqual(self.store.get_meta('baseline_complete'), '1')
        self.assertEqual(self.count('pairs'), 2)
        delta_alerts = [n for n in self.sent if n.record_id == second]
        self.assert_snapshot_silent([CVE])
        self.assertEqual(self.store.connection.execute(
            'SELECT baseline FROM pairs WHERE record_id=?', (CVE,)).fetchone()[0], 1)
        summaries = [n for n in self.sent if n.record_id == 'baseline']
        self.assertEqual(len(summaries), 1)
        self.assertIn('1 historical matches', summaries[0].body['detail'])
        self.assertEqual(len(delta_alerts), 1)
        self.assertEqual(delta_alerts[0].urgency, 'urgent')
        self.assertEqual(delta_alerts[0].reasons, ('new match',))
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM events WHERE watch_id='widget' AND record_id=?",
            (second,)).fetchone()[0], 1)
        delivered = len(self.sent)
        self.restart(aliases)
        self.engine.run_cycle([])
        self.assertEqual(self.count('pairs'), 2)
        self.assertEqual(len(self.sent), delivered)
        self.assertEqual(self.count('retry_queue') + self.count('dead_letters'), 0)
        self.assertTrue(health.container_healthy(self.store, self.now, self.config))

    def test_fifth_rematch_failure_stays_unhealthy_in_dead_letters(self):
        # Review probe 09: moving the last retry to dead letters is not recovery.
        self.store.connection.execute('INSERT INTO retry_queue VALUES (?,?,?,?,?)',
            ('watchlist', CVE, 4, self.now.isoformat(), 'prior matching failures'))
        self.engine._health('watchlist', 'unhealthy', 'Re-match failed; retry pending')
        self.store.connection.execute('UPDATE outbox SET sent_at=?', (self.now.isoformat(),))
        aliases = self.load_aliases(linked=True)
        with patch('cornicen.applicability.resolve', side_effect=ValueError('still failing')):
            self.restart(aliases)
        dead = self.store.connection.execute(
            "SELECT * FROM dead_letters WHERE source='watchlist'").fetchone()
        self.assertEqual(dead['attempts'], 5)
        self.assertIn('still failing', dead['last_error'])
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertEqual(self.count('pairs'), 0)
        self.assertEqual(self.store.get_meta('applied_aliases_hash'), aliases.fingerprint())
        startup_health = self.store.connection.execute(
            "SELECT state,detail FROM health WHERE source='watchlist'").fetchone()
        self.assertEqual(startup_health['state'], 'unhealthy')
        self.assertEqual(startup_health['detail'], 'Re-match failed; retry pending')
        self.assertFalse(health.container_healthy(self.store, self.now, self.config))
        self.assertEqual(self.store.connection.execute(
            'SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0], 0)
        self.engine.run_cycle([])
        self.assertEqual(self.count('dead_letters'), 1)
        self.assertFalse(health.container_healthy(self.store, self.now, self.config))
        self.assertEqual([n for n in self.sent if n.record_id == 'watchlist'], [])

    def test_fingerprint_uses_effective_groups_only(self):
        aliases = self.load_aliases(linked=True)
        self.path.write_text('version="other"\n[[alias]]\n'
            'identities=[" ACME-LABS:WIDGET-NEXT ","acme:widget"]\n'
            '[[alias]]\nidentities=["acme:widget","acme:widget"]\n')
        self.assertEqual(aliases.fingerprint(), AliasMap.load(False, self.path).fingerprint())
        self.assertNotEqual(aliases.fingerprint(), self.aliases.fingerprint())

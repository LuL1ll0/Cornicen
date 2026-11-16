# script-purpose: Verify the budgeted Microsoft CSAF adapter and offline replay contracts.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task2_b2.py
"""Read invented scripts and fixtures; write temporary SQLite and member files.

Run with unittest; exit 0 on success, 1 on failure. Scale requires CORNICEN_SCALE=1.
"""
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import random
import resource
import tempfile
import time
import unittest
from unittest.mock import patch

from cornicen.adapterstore import AdapterStore, canonical, digest, instant, stamp
from cornicen.store import Store
from cornicen.sources import msrc_csaf as m

ROOT = Path(__file__).resolve().parents[1]
T = '2099-01-01T00:00:00Z'
BASE = 'https://msrc.microsoft.com/csaf/advisories/'
META = 'https://msrc.microsoft.com/csaf/provider-metadata.json'
RAW = json.loads((ROOT/'tests/fixtures/msrc/advisory_sample.json').read_text())
METADATA = {'distributions': [{'directory_url': BASE}, {'directory_url': 'https://msrc.microsoft.com/csaf/vex/'}]}


def raw(n=1):
    value = deepcopy(RAW)
    value['document']['tracking']['id'] = f'msrc_CVE-2099-{71000+n}'
    value['vulnerabilities'][0]['cve'] = f'CVE-2099-{71000+n}'
    return value


class Task2B2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name)/'db'); self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.state = m.MsrcState(self.store, rng=random.Random(1))
        self.p = AdapterStore(self.store, self.tmp.name)
        self.now = instant(T)
        self.action = 0

    def adapter(self):
        from tests.replay_v11.msrc_backend import ScriptedMsrc
        self.server = ScriptedMsrc(data_dir=self.tmp.name)
        return m.MsrcCsaf(self.server.http(), self.state, lambda: self.now)

    def scripts(self, listing, records=None, *, metadata=False, listing_status=200, listing_headers=None):
        self.action += 1; self.server.reset(self.action)
        if metadata:
            self.server.add(self.action, 'metadata', '', body=METADATA)
        body = listing if isinstance(listing, str) else ''.join(f'{p},{t}\n' for p, ts in listing.items() for t in ts)
        self.server.add(self.action, 'listing', '', body=body, status=listing_status, headers=listing_headers)
        for path, result in (records or {}).items():
            options = result if isinstance(result, dict) and ('status' in result or 'error' in result) else dict(body=result)
            self.server.add(self.action, 'record', path, **options)

    def poll(self, adapter):
        return adapter.poll()[0]

    def process(self, outcome):
        result = self.p.process('msrc', [outcome], stamp(self.now), required_resources=('msrc/advisories',))
        self.p.finish_cycle('msrc', stamp(self.now))
        return result

    def members(self, outcome):
        return [json.loads(line) for line in Path(outcome['members_file']).read_text().splitlines()]

    def incremental(self):
        self.state._put('bootstrap', [])
        self.p.process('msrc', [dict(path='msrc/advisories', status=200, body='[]')], T, required_resources=('msrc/advisories',))

    def test_t14_admission_and_budgets(self):
        adapter = self.adapter()
        listing = {f'2099/{n:04}.json': [T] for n in range(600)}
        self.scripts(listing, {p: raw(n+1) for n,p in enumerate(list(listing)[:197])}, metadata=True)
        self.assertEqual(self.poll(adapter)['reason'], 'bootstrap backlog')
        self.assertEqual(len(self.server.requests), 199)
        self.now += timedelta(minutes=1)
        self.scripts(listing, {p: raw(n+198) for n,p in enumerate(list(listing)[197:395])})
        self.assertEqual(self.poll(adapter)['reason'], 'bootstrap backlog')
        self.assertEqual(len(self.server.requests), 398)
        self.now += timedelta(minutes=1)
        self.scripts(listing)
        self.assertEqual(self.poll(adapter)['reason'], 'bootstrap backlog')
        self.assertEqual(len(self.server.requests), 399)
        self.now += timedelta(hours=1)
        self.scripts(listing, {p: raw(n+396) for n,p in enumerate(list(listing)[395:593])})
        self.poll(adapter)
        self.assertEqual([r['path'] for r in self.server.requests if r['operation']=='record'], list(listing)[:593])

    def test_t14_failures_backoff_and_audit(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json':[T], '2099/b.json':[T], '2099/c.json':[T]}
        self.scripts(listing, {'2099/a.json': raw(), '2099/b.json':dict(status=429, headers={'retry-after':'120'})}, metadata=True)
        outcome = self.poll(adapter)
        self.assertEqual(outcome['subrequest_http_errors'], 1)
        self.assertEqual(len(self.members(outcome)), 1)
        self.assertEqual(self.process(outcome), 'FAILED')
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')
        self.assertEqual(len(self.server.requests), 4)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 1)
        self.now += timedelta(seconds=30)
        outcome = self.poll(adapter)
        self.assertEqual(self.process(outcome), 'FAILED')
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')
        self.assertEqual(len(self.server.requests), 4)
        self.assertEqual(self.state.meta('rate_hold_until'), '2099-01-01T00:02:00Z')
        self.now += timedelta(seconds=91)
        self.scripts(listing, {'2099/b.json':dict(error=OSError('invented outage')), '2099/c.json':raw(3)})
        outcome = self.poll(adapter)
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 2)

    def test_t14_never_successful_audit(self):
        adapter = self.adapter()
        self.now += timedelta(days=8)
        # Seed an accepted container at the current tick, independently of the
        # historical path cache. Its manifest cannot cause the audit failure.
        self.state._put('bootstrap', [])
        self.assertEqual(self.process(dict(path=m.RESOURCE, status=200, body='[]')), 'COMPLETE')
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.state.observe_listing(listing, 0, T)
        self.state.record_success('2099/a.json', [T],
            m.normalise(raw(), path='2099/a.json', directory_url=BASE), stamp(self.now), raw_digest=digest(raw()))
        self.scripts(listing, {'2099/b.json': dict(error=OSError('invented outage'))}, metadata=True)
        outcome = self.poll(adapter)
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertIsNone(self.state.path('2099/b.json')['last_success'])
        manifest = self.db.execute("SELECT audited_at, fetched_at FROM manifests WHERE source='msrc'").fetchone()
        self.assertLess((self.now-instant(manifest['audited_at'] or manifest['fetched_at'])).total_seconds(), 7*86400)
        self.assertEqual(self.db.execute("SELECT state,detail FROM source_health WHERE dimension='audit'").fetchone()[:],
                         ('unhealthy', '["record_audit_oldest"]'))
        self.now += timedelta(hours=1)
        self.scripts(listing, {'2099/b.json': dict(body='malformed JSON')})
        self.assertEqual(self.process(self.poll(adapter)), 'PARTIAL')
        self.assertEqual(self.state.path('2099/b.json')['audit_anchor'], stamp(self.now))
        self.assertEqual(self.store.get_meta('record_audit_oldest:msrc'), stamp(self.now-timedelta(hours=1)))
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='audit'").fetchone()[0], 'healthy')

    def test_t14_timestamp_changes_refresh_and_order(self):
        adapter = self.adapter(); self.incremental()
        paths = [f'2099/{c}.json' for c in 'abcdef']
        listing = dict.fromkeys(paths, [T])
        self.state.observe_listing(listing, 0, T)
        for n,p in enumerate(paths):
            self.state.record_success(p,[T], m.normalise(raw(n+1),path=p,directory_url=BASE),T,raw_digest=digest(raw(n+1)))
        self.state.record_failure(paths[3],T)
        self.state.record_failure(paths[4],T)
        self.now += timedelta(seconds=30)
        changed = dict(listing); changed[paths[0]]=[T, '2099-01-01T00:01:00Z']; changed[paths[1]]=['2098-12-31T00:00:00Z']
        self.scripts(changed,{paths[0]:raw(),paths[1]:raw(2)},metadata=True)
        self.process(self.poll(adapter))
        self.assertEqual([r['path'] for r in self.server.requests if r['operation']=='record'], paths[:2])
        self.now += timedelta(days=6, seconds=1)
        changed[paths[0]] = [stamp(self.now)]
        changed[paths[1]] = [T, stamp(self.now)]
        # R-M18: retry deadlines, changed listing order, oldest refresh first.
        for path, updates in (
            (paths[3], {'next_attempt': '2099-01-01T00:02:00Z'}),
            (paths[4], {'next_attempt': '2099-01-01T00:01:00Z'}),
            (paths[2], {'last_success': '2098-12-31T23:00:00Z'}),
            (paths[5], {'last_success': '2098-12-31T22:00:00Z'}),
        ):
            row = self.state.path(path); row.update(updates)
            with self.store.transaction(): self.state._put('path:'+path, row)
        self.scripts(changed,{p:raw(n+1) for n,p in enumerate(paths)},metadata=True)
        self.process(self.poll(adapter))
        self.assertEqual([r['path'] for r in self.server.requests
                          if r['action']==self.action and r['operation']=='record'],
                         ['2099/e.json', '2099/d.json', '2099/a.json',
                          '2099/b.json', '2099/f.json', '2099/c.json'])
        # An exact-second deadline precedes a fractional deadline at that second.
        for path, fraction in ((paths[3],0),(paths[4],.5)):
            self.state.record_failure(path,stamp(self.now))
            row=self.state.path(path)
            row['next_attempt']=stamp(self.now+timedelta(seconds=60+fraction))
            with self.store.transaction(): self.state._put('path:'+path,row)
        self.now+=timedelta(seconds=61)
        self.scripts(changed,{paths[3]:raw(4),paths[4]:raw(5)})
        self.poll(adapter)
        self.assertEqual([r['path'] for r in self.server.requests if r['action']==self.action and r['operation']=='record'], paths[3:5])

    def test_t14_stale_timestamps_hold_cursor(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.scripts(listing, {'2099/a.json': raw(), '2099/b.json': raw(2)}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        cursor = self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='msrc'").fetchone()[0]
        self.now += timedelta(hours=1)
        changed = dict.fromkeys(listing, [stamp(self.now)])
        self.scripts(changed, {'2099/a.json': raw()})
        # Listing + one changed record + the required spare request.
        with patch.object(m, 'CYCLE_LIMIT', 3):
            outcome = self.poll(adapter)
        self.assertEqual(self.state.path('2099/b.json')['failure'], None)
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='msrc'").fetchone()[0], cursor)
        self.assertFalse(outcome['coverage_complete'])
        self.assertEqual([r['path'] for r in self.server.requests
                          if r['action']==self.action and r['operation']=='record'], ['2099/a.json'])

    def test_t14_record_403_stops_fetching(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json': [T], '2099/b.json': [T], '2099/c.json': [T]}
        self.scripts(listing, {'2099/a.json': raw(),
                              '2099/b.json': dict(status=403, headers={'retry-after': '120'})}, metadata=True)
        outcome = self.poll(adapter)
        self.assertEqual([r['path'] for r in self.server.requests if r['operation']=='record'],
                         ['2099/a.json', '2099/b.json'])
        self.assertEqual(len(self.members(outcome)), 1)
        self.assertEqual(self.process(outcome), 'FAILED')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')
        self.assertEqual(self.state.meta('rate_hold_until'), '2099-01-01T00:02:00Z')
        self.now += timedelta(seconds=30)
        self.assertEqual(self.process(self.poll(adapter)), 'FAILED')
        self.assertEqual(len(self.server.requests), 4)
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')

    def test_t14_invalid_200_preserves_cache(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json': [T]}
        self.scripts(listing, {'2099/a.json': raw()}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        prior = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        identity = raw()['document']['tracking']['id']
        for body in ('malformed JSON', {'unrelated': 'document'}):
            with self.subTest(body=body):
                self.now += timedelta(hours=1)
                listing['2099/a.json'] = [stamp(self.now)]
                self.scripts(listing, {'2099/a.json': dict(body=body)})
                outcome = self.poll(adapter)
                row = self.state.path('2099/a.json')
                self.assertEqual(self.members(outcome), [dict(id=identity, mapping_error='invalid CSAF document')])
                self.assertEqual(row['timestamps'], listing['2099/a.json'])
                self.assertEqual(row['audit_anchor'], stamp(self.now))
                self.assertIsNone(row['failure'])
                self.assertEqual(outcome['subrequest_failures'], 0)
                self.assertEqual(outcome['subrequest_http_errors'], 0)
                self.assertEqual(self.process(outcome), 'PARTIAL')
                self.assertEqual(self.db.execute('SELECT source_id FROM quarantine').fetchone()[0], identity)
                self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'healthy')
                self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], prior)
                self.now += timedelta(hours=1); self.scripts(listing)
                self.assertEqual(self.process(self.poll(adapter)), 'PARTIAL')
                self.assertEqual([r for r in self.server.requests if r['action']==self.action and r['operation']=='record'], [])
        print('R4 cached probe: PARTIAL fetch=healthy quarantine=1 prior_evidence=kept unchanged_listing_fetches=0')
        self.now += timedelta(days=6)
        self.scripts(listing, {'2099/a.json': raw()}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 0)

    def test_t14_invalid_200_without_cache_quarantines(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.scripts(listing, {'2099/a.json': dict(body='malformed JSON'),
                              '2099/b.json': dict(body={'unrelated': 'document'})}, metadata=True)
        outcome = self.poll(adapter)
        self.assertEqual(len(self.members(outcome)), 2)
        self.assertTrue(all(member['id'] is None for member in self.members(outcome)))
        self.assertEqual(outcome['subrequest_failures'], 0)
        self.assertEqual(self.process(outcome), 'PARTIAL')
        rows = self.db.execute('SELECT source_id FROM quarantine').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertTrue(all(row[0].startswith('@invalid:') for row in rows))
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'healthy')
        for path in listing:
            self.assertEqual(self.state.path(path)['audit_anchor'], T)
            self.assertEqual(self.state.path(path)['timestamps'], [T])
        print('R4 uncached probe: PARTIAL fetch=healthy quarantine=1 (@invalid)')

    def test_t14_bootstrap_429_and_backoff(self):
        adapter = self.adapter()
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.scripts(listing, {'2099/a.json': dict(status=429, headers={'retry-after':'120'})}, metadata=True)
        for seconds in (0, 30):
            self.now += timedelta(seconds=seconds)
            outcome = self.poll(adapter)
            self.assertEqual(outcome['subrequest_failures'], 1)
            self.assertEqual(outcome['subrequest_http_errors'], 1)
            self.assertEqual(outcome['record_audit_oldest'], T)
            self.assertEqual(self.process(outcome), 'FAILED')
            self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'unhealthy')
        self.assertEqual(len(self.server.requests), 3)
        print('R1 probe: bootstrap=FAILED backoff=FAILED fetch=unhealthy requests=3')

    def test_t14_listing_and_metadata_failure_keep_record_audit(self):
        adapter = self.adapter(); self.incremental()
        self.now += timedelta(days=8)
        self.assertEqual(self.process(dict(path=m.RESOURCE, status=200, body='[]')), 'COMPLETE')
        self.state.observe_listing({'2099/a.json':[T]}, 0, T)
        self.state.set_metadata(METADATA, stamp(self.now))
        for operation in ('listing', 'metadata'):
            if operation == 'metadata':
                self.now += timedelta(days=1)
            self.action += 1; self.server.reset(self.action)
            self.server.add(self.action, operation, '', status=503)
            outcome = self.poll(adapter)
            self.assertEqual(outcome['record_audit_oldest'], T)
            self.assertEqual(self.process(outcome), 'FAILED')
            self.assertEqual(self.store.get_meta('record_audit_oldest:msrc'), T)
            self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='audit'").fetchone()[0], 'unhealthy')
        self.state.observe_listing({'2099/b.json':[stamp(self.now)]}, 0, stamp(self.now))
        self.state.set_hold(stamp(self.now + timedelta(minutes=2)))
        self.assertEqual(self.poll(adapter)['record_audit_oldest'], stamp(self.now))
        self.state.observe_listing({}, 0, stamp(self.now))
        self.assertNotIn('record_audit_oldest', self.poll(adapter))
        print('R2 probe: listing=503 metadata=503 audit=unhealthy oldest=2099-01-01T00:00:00Z; departed anchor excluded')

    def bootstrap_retry(self):
        adapter = self.adapter()
        listing = {'2099/a.json':[T], '2099/b.json':[T]}
        self.scripts(listing, {'2099/a.json':raw(), '2099/b.json':dict(status=503)}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'FAILED')
        self.now += timedelta(hours=1)
        self.scripts(listing, {'2099/b.json':raw(2)})
        return adapter, self.poll(adapter)

    def test_t17_staging_failure_keeps_baseline_hold(self):
        adapter, outcome = self.bootstrap_retry()
        with patch.object(self.p, 'stage_members', side_effect=OSError('invented staging failure')):
            self.assertEqual(self.process(outcome), 'FAILED')
        identity = raw(2)['document']['tracking']['id']
        for table in ('advisories', 'quarantine'):
            self.assertIsNone(self.db.execute('SELECT 1 FROM '+table+' WHERE source_id=?', (identity,)).fetchone())
        self.assertEqual(self.p.summaries(), [])
        self.assertIsNotNone(self.store.get_meta('baseline_hold:msrc'))
        self.now += timedelta(hours=1)
        self.scripts({'2099/a.json':[T], '2099/b.json':[T]})
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        self.assertEqual(len(self.p.summaries()), 1)
        print('R3 staging probe: FAILED late_id_absent=True summaries=0 hold=retained; retry summaries=1')

    def test_t17_same_id_staging_failure_keeps_baseline_hold(self):
        adapter = self.adapter()
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.scripts(listing, {'2099/a.json': raw(),
                              '2099/b.json': dict(status=503)}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'FAILED')
        self.now += timedelta(hours=1)
        changed = raw()
        changed['document']['title'] = 'Changed document with the accepted ID'
        self.scripts(listing, {'2099/b.json': changed})
        outcome = self.poll(adapter)
        self.assertEqual(self.members(outcome), [dict(id=raw()['document']['tracking']['id'],
                                                     mapping_error='path conflict')])
        with patch.object(self.p, 'stage_members', side_effect=OSError('staging unavailable')):
            result = self.process(outcome)
        row = m.MsrcState(self.store).path('2099/b.json')
        self.assertEqual(result, 'FAILED')
        self.assertIsNone(row['staged_generation'])
        self.assertIsNone(row['committed_generation'])
        self.assertIsNotNone(self.store.get_meta('baseline_hold:msrc'))
        self.assertEqual(self.p.summaries(), [])
        print('R2 item 1 probe: FAILED summaries=0 hold=retained last_path_committed=False')
        self.now += timedelta(hours=1)
        self.scripts(listing)
        self.assertEqual(self.process(self.poll(adapter)), 'PARTIAL')
        self.assertEqual(len(self.p.summaries()), 1)
        for path in listing:
            row = self.state.path(path)
            self.assertEqual(row['committed_generation'], row['container_generation'])
        print('R2 item 1 retry: PARTIAL conflict_quarantined=True both_paths_committed=True summaries=1')

    def test_t17_duplicate_copies_resolve_every_path(self):
        adapter = self.adapter()
        listing = {'2099/a.json': [T], '2099/b.json': [T]}
        self.scripts(listing, dict.fromkeys(listing, raw()), metadata=True)
        outcome = self.poll(adapter)
        self.assertEqual(len(self.members(outcome)), 1)
        self.assertEqual(self.process(outcome), 'COMPLETE')
        self.assertEqual(len(self.p.summaries()), 1)
        for path in listing:
            row = self.state.path(path)
            self.assertEqual(row['staged_generation'], row['container_generation'])
            self.assertEqual(row['committed_generation'], row['container_generation'])

    def test_t17_invalid_tracking_id_resolves_quarantined_path(self):
        adapter = self.adapter()
        listing = {'2099/a.json': [T]}
        document = raw()
        document['document']['tracking']['id'] = 'bad|id'
        self.scripts(listing, {'2099/a.json': document}, metadata=True)
        outcome = self.poll(adapter)
        key = self.p._key(self.members(outcome)[0], False)[0]
        self.assertTrue(key.startswith('@invalid:'))
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT source_id FROM quarantine').fetchone()[0], key)
        self.assertIsNone(self.store.get_meta('baseline_hold:msrc'))
        self.assertEqual(len(self.p.summaries()), 1)
        self.now += timedelta(hours=1)
        self.scripts(listing)
        self.assertEqual(self.process(self.poll(adapter)), 'PARTIAL')
        self.assertEqual(len(self.p.summaries()), 1)
        print('R2 item 2 probe: PARTIAL quarantine=@invalid:<digest> hold=released summaries=1; unchanged PARTIAL summaries=1')

    def test_t14_mapping_failure_prefers_incoming_tracking_id(self):
        adapter = self.adapter()
        listing = {'2099/a.json': [T]}
        self.scripts(listing, {'2099/a.json': raw()}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        old_id = raw()['document']['tracking']['id']
        before = [tuple(row) for row in self.db.execute('SELECT * FROM advisory_evidence')]
        accepted = tuple(self.db.execute('SELECT * FROM advisories WHERE source_id=?', (old_id,)).fetchone())
        self.now += timedelta(hours=1)
        listing['2099/a.json'] = [stamp(self.now)]
        document = raw(2)
        document['vulnerabilities'][0]['product_status']['known_affected'] = ['missing-product']
        self.scripts(listing, {'2099/a.json': document})
        outcome = self.poll(adapter)
        new_id = document['document']['tracking']['id']
        self.assertEqual(self.members(outcome), [dict(id=new_id, mapping_error='invalid CSAF document')])
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT source_id FROM quarantine').fetchone()[0], new_id)
        self.assertEqual(tuple(self.db.execute('SELECT * FROM advisories WHERE source_id=?', (old_id,)).fetchone()), accepted)
        self.assertEqual([tuple(row) for row in self.db.execute('SELECT * FROM advisory_evidence')], before)
        self.assertEqual(self.db.execute("SELECT state FROM source_health WHERE dimension='fetch'").fetchone()[0], 'healthy')
        print('R2 item 3 probe: PARTIAL emitted=msrc_CVE-2099-71002 quarantined=msrc_CVE-2099-71002 prior_evidence=kept prior_id_quarantined=False fetch=healthy')

    def test_t17_crash_before_process_keeps_baseline_hold(self):
        adapter, outcome = self.bootstrap_retry()
        Path(outcome['members_file']).unlink()  # Crash after poll, before process.
        adapter = self.adapter()
        self.p.finish_cycle('msrc', stamp(self.now))
        self.assertEqual(self.p.summaries(), [])
        self.assertIsNotNone(self.store.get_meta('baseline_hold:msrc'))
        self.now += timedelta(hours=1)
        self.scripts({'2099/a.json':[T], '2099/b.json':[T]})
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        self.assertEqual(len(self.p.summaries()), 1)
        print('R3 crash probe: before_process summaries=0 hold=retained; recovery summaries=1')

    def test_members_file_cleanup_on_write_and_poll_failure(self):
        adapter = self.adapter(); self.incremental()
        listing = {'2099/a.json': [T]}
        self.scripts(listing, {'2099/a.json': raw()}, metadata=True)
        self.assertEqual(self.process(self.poll(adapter)), 'COMPLETE')
        self.now += timedelta(hours=1)
        self.scripts(listing)
        create_stream = m.tempfile.NamedTemporaryFile
        def broken_stream(**options):
            stream = create_stream(**options)
            def broken_write(value):
                stream.file.write(value[:1])
                raise OSError('invented write failure')
            stream.write = broken_write
            return stream
        with patch.object(m.tempfile, 'NamedTemporaryFile', broken_stream):
            with self.assertRaisesRegex(OSError, 'invented write failure'):
                self.poll(adapter)
        self.assertEqual(list(Path(self.tmp.name).glob('msrc-members-*')), [])
        original = adapter._container
        def broken_return(invalid):
            original(invalid)
            raise RuntimeError('invented poll failure')
        self.now += timedelta(hours=1)
        self.scripts(listing)
        with patch.object(adapter, '_container', broken_return):
            with self.assertRaisesRegex(RuntimeError, 'invented poll failure'):
                self.poll(adapter)
        self.assertEqual(list(Path(self.tmp.name).glob('msrc-members-*')), [])

    def test_t18_duplicate_and_conflicting_paths(self):
        document = raw(); document['document'].pop('references',None)
        for listing in ({'2099/b.json':[T],'2099/a.json':[T]}, {'2099/a.json':[T],'2099/b.json':[T]}):
            with self.subTest(order=list(listing)):
                fresh = Task2B2Tests()
                fresh.setUp()
                try:
                    adapter = fresh.adapter(); fresh.incremental()
                    fresh.scripts(listing, {p:document for p in listing}, metadata=True)
                    outcome = fresh.poll(adapter)
                    self.assertEqual(len(fresh.members(outcome)),1)
                    self.assertEqual(fresh.process(outcome),'COMPLETE')
                    self.assertEqual(sum(r['operation']=='record' for r in fresh.server.requests), 2)
                    fresh.now += timedelta(hours=1)
                    changed = deepcopy(document); changed['document']['notes']=[{'text':'invented ignored difference'}]
                    listing['2099/b.json']=[stamp(fresh.now)]
                    fresh.scripts(listing, {'2099/b.json':changed})
                    outcome=fresh.poll(adapter)
                    self.assertEqual(fresh.members(outcome),[{'id':document['document']['tracking']['id'],'mapping_error':'path conflict'}])
                    self.assertEqual(fresh.process(outcome),'PARTIAL')
                    self.assertEqual(fresh.db.execute('SELECT count(*) FROM advisories').fetchone()[0],1)
                    print(f'R6 probe: order={list(listing)} initial_record_fetches=2 duplicate=COMPLETE conflict=PARTIAL')
                finally:
                    fresh.doCleanups()

    def test_t19_metadata_and_redirects(self):
        adapter=self.adapter(); self.incremental()
        listing={'2099/a.json':[T]}
        self.scripts(listing,{'2099/a.json':raw()},metadata=True)
        self.assertEqual(self.process(self.poll(adapter)),'COMPLETE')
        self.now += timedelta(hours=23)
        self.scripts(listing)
        self.process(self.poll(adapter))
        self.assertEqual(sum(r['operation']=='metadata' for r in self.server.requests),1)
        self.now += timedelta(hours=1)
        self.scripts(listing,metadata=True)
        self.process(self.poll(adapter))
        self.assertEqual(sum(r['operation']=='metadata' for r in self.server.requests),2)
        for hop in ('https://msrc.microsoft.com/csaf/vex/a.json',BASE+'other',BASE+'2099/a.json?q=1',BASE+'2099/a.json#x','https://examplecorp.invalid/csaf/advisories/changes.csv'):
            self.now += timedelta(hours=1)
            self.action += 1; self.server.reset(self.action)
            self.server.add(self.action,'listing','',status=302,headers={'location':hop})
            self.assertEqual(self.process(self.poll(adapter)),'FAILED')
        self.now += timedelta(days=1)
        self.action += 1; self.server.reset(self.action)
        self.server.add(self.action,'metadata','',body={'distributions':[METADATA['distributions'][1]]})
        self.assertEqual(self.process(self.poll(adapter)),'FAILED')
        self.assertFalse(any('/vex/' in r['url'] for r in self.server.requests))

    def test_t23_watch_independent_requests(self):
        from cornicen import __version__
        self.assertEqual(__version__, '0.5.0')
        from tests.replay_v11 import harness as h
        from tests.replay_v11.msrc_backend import MsrcBackend
        rows=h.load_timeline('csaf')
        traces=[]
        for version in ('9.4.1200.7','9.4.1200.8'):
            backend=MsrcBackend(h.fixture_registry())
            try:
                for row in rows:
                    row=deepcopy(row)
                    if 'watchlist' in row: row['watchlist']=row['watchlist'].replace('9.4.1200.7',version)
                    backend.action(row)
                self.assertEqual(len(backend.server.requests),6)
                traces.append(canonical(backend.server.requests))
            finally: backend.close()
        self.assertEqual(traces[0],traces[1])

    def test_t24_unchanged_cache(self):
        adapter=self.adapter(); self.incremental()
        listing={'2099/a.json':[T]}
        self.scripts(listing,{'2099/a.json':raw()},metadata=True)
        self.assertEqual(self.process(self.poll(adapter)),'COMPLETE')
        before={table:[tuple(r) for r in self.db.execute('SELECT * FROM '+table)] for table in ('advisories','events')}
        self.now+=timedelta(hours=1); self.scripts(listing)
        self.assertEqual(self.process(self.poll(adapter)),'COMPLETE')
        for table,rows in before.items(): self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM '+table)],rows)
        self.assertEqual(len(self.server.requests),4)

    def test_t15_csaf_scenario(self): self.scenario('csaf')
    def test_t16_inventory_scenario(self): self.scenario('csaf_inventory')
    def test_t17_bootstrap_scenario(self): self.scenario('msrc_bootstrap')

    def scenario(self,name):
        from tests.replay_v11 import harness as h
        result=h.run_scenario(name); expected=h.load_expected(name)
        h.assert_notifications(result,expected)
        for row in expected: h.assert_line(result,row,expected)

    def test_t20_crash_replays(self):
        from tests.replay_v11 import harness as h
        for name in ('csaf','msrc_bootstrap'):
            baseline=h.run_crash_scenario(name)
            from collections import Counter
            totals = {
                'csaf': {'msrc_charge':12,'msrc_set_metadata':4,'msrc_observe_listing':4,
                         'msrc_record_success':4,'msrc_stage_members':4,'record':12,
                         'msrc__container':4,'msrc_commit_generation':4,
                         'alias':4,'enqueue':2,'msrc__accept_batch':4,'ack':1},
                'msrc_bootstrap': {'msrc_charge':30,'msrc_set_metadata':4,
                         'msrc_observe_listing':12,'msrc_record_success':12,
                         'msrc_record_failure':2,'enqueue':12,'ack':6,
                         'msrc_stage_members':10,'record':42,'alias':10,'msrc__accept_batch':2,
                         'msrc__container':10,'msrc_commit_generation':10}}
            self.assertEqual(dict(Counter(p.split(':',1)[0] for p in baseline.points)),totals[name])
            for n in range(len(baseline.points)):
                replay=h.run_crash_scenario(name,n)
                self.assertTrue(replay.crashed)
                self.assertEqual(sorted(canonical({k:v for k,v in note.items() if k!='t'}) for note in replay.result.notifications if note['watch']),
                                 sorted(canonical({k:v for k,v in note.items() if k!='t'}) for note in baseline.result.notifications if note['watch']),(name,n))
                self.assertEqual(replay.deliveries,baseline.deliveries,(name,n))
                for case in {key[0] for key in baseline.result.snapshots}:
                    key=max(key for key in baseline.result.snapshots if key[0]==case)
                    for field in ('events','baseline'):
                        self.assertEqual(replay.result.snapshots[key][field],
                                         baseline.result.snapshots[key][field],(name,n,field))

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE')=='1','opt-in scale')
    def test_t21_scale(self):
        from dataclasses import replace
        from cornicen.adapters import REGISTRY
        adapter=self.adapter()
        def dispatch():
            return self.p.dispatch({'msrc':replace(REGISTRY['msrc'],gate='met')},
                                   {'msrc':True},{'msrc':lambda:adapter},stamp(self.now))['msrc']
        listing={f'2099/{n:05}.json':[T] for n in range(20000)}
        start=time.perf_counter(); self.state.observe_listing(listing,0,T)
        for n,p in enumerate(listing):
            document=raw(n+1)
            self.state.record_success(p,[T],m.normalise(document,path=p,directory_url=BASE),T,raw_digest=digest(document))
        self.scripts(listing,metadata=True)
        start=time.perf_counter()
        self.assertEqual(dispatch(),'COMPLETE')
        bootstrap=time.perf_counter()-start
        bootstrap_rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if os.uname().sysname!='Darwin': bootstrap_rss*=1024
        self.now+=timedelta(hours=1)
        changed=dict(listing)
        # Metadata is cached: one listing plus 198 records exhausts the cycle.
        for p in list(listing)[:200]: changed[p]=[stamp(self.now)]
        self.scripts(changed,{p:raw(n+1) for n,p in enumerate(list(listing)[:198])})
        start=time.perf_counter()
        self.assertEqual(dispatch(),'PARTIAL')
        self.now+=timedelta(minutes=1)
        self.scripts(changed,{p:raw(n+199) for n,p in enumerate(list(listing)[198:200])})
        self.assertEqual(dispatch(),'COMPLETE')
        steady=time.perf_counter()-start
        self.assertEqual(sum(r['operation']=='record' for r in self.server.requests),200)
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if os.uname().sysname!='Darwin': rss*=1024
        print(f'T21 bootstrap={bootstrap:.3f}s steady={steady:.3f}s bootstrap_peak_RSS={bootstrap_rss/1024**2:.2f}MB steady_peak_RSS={rss/1024**2:.2f}MB',flush=True)
        self.assertLess(bootstrap,900); self.assertLess(steady,60); self.assertLess(rss,256*1024**2)

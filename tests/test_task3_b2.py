# script-purpose: Verify Cisco factory wiring and offline replay acceptance contracts.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task3_b2.py
"""Read invented Cisco JSONL and CSAF fixtures; write temporary SQLite/member files.

Unittest exits 0 on success, 1 on failure. T21 requires CORNICEN_SCALE=1.
"""
from collections import Counter
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import resource
import time
import unittest
from unittest.mock import patch

from cornicen.adapterstore import canonical, digest, stamp
from tests.replay_v11 import harness as h


class Task3B2Tests(unittest.TestCase):
    def backend(self):
        from tests.replay_v11.msrc_backend import CiscoBackend
        backend = CiscoBackend(h.fixture_registry())
        self.addCleanup(backend.close)
        return backend

    def scenario(self, name):
        result = h.run_scenario(name)
        expected = h.load_expected(name)
        for row in expected:
            h.assert_line(result, row, expected)
        h.assert_notifications(result, expected)
        return result

    def test_t15_platform(self):
        result = self.scenario('cisco_platform')
        for case in ('main', 'unlisted', 'gateway', 'different', 'omitted'):
            snapshot = next(v for k, v in result.snapshots.items() if k[0] == case)
            rows = snapshot['evidence_rows']['cisco|cisco-sa-sample-relay-2099a']
            self.assertEqual(len(rows), 23)
            self.assertEqual({r['identity'] for r in rows}, {'CVE-2099-72001'})
            self.assertTrue(all(r['platform'] is None for r in rows))
            self.assertEqual(any('relationship' in r['provenance']['evidence'] for r in rows),
                             case in ('gateway', 'different', 'omitted'))

    def test_t16_inventory(self):
        result = self.scenario('cisco_inventory')
        for case in ('429', '404', 'spa', 'transport', 'invalid', 'rolling'):
            snaps = [v for k, v in sorted(result.snapshots.items()) if k[0] == case]
            self.assertEqual(snaps[0]['cursor'], snaps[1]['cursor'])
            self.assertEqual(snaps[0]['evidence_rows'], snaps[1]['evidence_rows'])
            if case != 'rolling':
                self.assertEqual(snaps[0]['conformance'], snaps[1]['conformance'])
        matched_union = next(v for k,v in result.snapshots.items() if k[0]=='main')
        mismatch = next(v for k,v in result.snapshots.items() if k[0]=='mismatch')
        self.assertEqual(matched_union['dimensions'], mismatch['dimensions'])
        self.assertEqual(matched_union['cursor']['cisco']['digest'], mismatch['cursor']['cisco']['digest'])
        self.assertEqual(matched_union['evidence_rows'], mismatch['evidence_rows'])
        self.assertNotEqual(matched_union['conformance']['changes_only'], mismatch['conformance']['changes_only'])
        self.assertNotIn('cisco_inventory', h.scenario_names())

    def test_t17_bad_member_and_projection(self):
        result = self.scenario('cisco_bad_member')
        key = 'cisco|cisco-sa-sample-relay-2099a'
        before = result.snapshots['main', '2026-11-03T00:00:00Z', 'after_restart']
        after = result.snapshots['main', '2026-11-03T01:00:00Z']
        self.assertEqual(before['evidence_rows'][key], after['evidence_rows'][key])
        # Exercise the observer itself, rather than comparing modified dictionaries.
        from tests.replay_v11.msrc_backend import evidence_projection
        backend = self.backend()
        for row in h.load_timeline('cisco_bad_member')[:2]: backend.action(row)
        db = backend.store.connection
        original = evidence_projection(db)
        columns = {r[1] for r in db.execute('PRAGMA table_info(advisory_evidence)')}
        self.assertEqual(set(original[key][0]), columns)
        db.execute("UPDATE advisory_evidence SET release='invented-release'")
        self.assertNotEqual(evidence_projection(db), original)
        db.execute('UPDATE advisory_evidence SET release=NULL')
        db.execute("UPDATE advisory_evidence SET provenance=json_set(provenance,'$.evidence.binding','changed')")
        self.assertNotEqual(evidence_projection(db), original)
        db.execute("UPDATE advisory_evidence SET provenance=json_set(provenance,'$.evidence.binding','watch')")
        self.assertEqual(evidence_projection(db), original)
        db.execute('INSERT INTO advisory_evidence SELECT * FROM advisory_evidence')
        self.assertEqual(evidence_projection(db)[key], original[key]*2)

    def setup_rows(self, backend, *, baseline=True):
        rows = h.load_timeline('cisco_inventory')
        backend.action(rows[0])
        backend.action(dict(t=rows[0]['t'], seed=dict(v1_baseline_complete=True,
                            **({'cisco_completed_baseline':True} if baseline else {}))))
        return deepcopy(rows[2]['cisco'])

    def test_t18_bootstrap_retry_and_conflict(self):
        backend = self.backend()
        scripts = self.setup_rows(backend, baseline=False)
        scripts[4] = dict(operation='record', path='2099/b.json', status=500)
        backend.action(dict(t='2026-11-03T01:00:00Z', cisco=scripts))
        backend.action(dict(t='2026-11-03T01:00:00Z', cycle=True))
        first = backend.snapshot()
        self.assertEqual(first['classification'], {'cisco':'FAILED'})
        self.assertEqual(first['baseline']['cisco']['summaries'], 0)
        self.assertEqual(first['events'], [])
        retry = [deepcopy(scripts[1]), deepcopy(scripts[2]),
                 deepcopy(h.load_timeline('cisco_inventory')[2]['cisco'][4])]
        backend.action(dict(t='2026-11-03T02:00:00Z', cisco=retry))
        backend.action(dict(t='2026-11-03T02:00:00Z', cycle=True))
        final = backend.snapshot()
        self.assertEqual(final['classification'], {'cisco':'COMPLETE'})
        self.assertEqual(final['baseline']['cisco']['summaries'], 1)
        self.assertEqual(final['events'], [])
        self.assertEqual(sum(n['record']=='baseline:cisco' for n in backend.notifications()), 1)
        self.assertEqual(first['request_paths'], ['2099/a.json','2099/b.json','2099/c.json'])
        self.assertEqual(final['request_paths'], first['request_paths']+['2099/b.json'])
        # Same tracking ID, different raw documents: withheld together as one member.
        conflict = self.backend()
        scripts = self.setup_rows(conflict)
        scripts = scripts[:3] + scripts[3:5]
        scripts[1]['body'] = '2099/a.json,2026-11-03T00:00:00Z\n2099/b.json,2026-11-03T00:00:00Z\n'
        scripts[2]['body'] = '2099/a.json\n2099/b.json\n'
        scripts[4]['body'] = deepcopy(scripts[3]['body'])
        scripts[4]['body']['document']['title'] = 'Invented conflicting copy'
        conflict.action(dict(t='2026-11-03T01:00:00Z', cisco=scripts))
        from cornicen.sources.cisco_csaf import CiscoCsaf
        original = CiscoCsaf._container
        emitted = []
        def capture(adapter, invalid):
            outcome = original(adapter, invalid)
            if 'members_file' in outcome:
                emitted.extend(json.loads(line) for line in Path(outcome['members_file']).read_text().splitlines())
            return outcome
        with patch.object(CiscoCsaf, '_container', capture):
            conflict.action(dict(t='2026-11-03T01:00:00Z', cycle=True))
        self.assertEqual(conflict.snapshot()['classification'], {'cisco':'PARTIAL'})
        self.assertEqual(conflict.store.connection.execute('SELECT count(*) FROM quarantine').fetchone()[0],1)
        member = json.loads(conflict.store.get_meta('cisco:path:2099/a.json'))['member']
        self.assertEqual(conflict.persistence._key(member,False)[0], 'cisco-sa-synthetic-2')
        self.assertEqual(emitted, [dict(id='cisco-sa-synthetic-2', mapping_error='path conflict')])

    def test_t19_crash_replays(self):
        totals = CRASH_COUNTS
        for name, counts in totals.items():
            baseline = h.run_crash_scenario(name)
            actual = dict(Counter(p.split(':',1)[0] for p in baseline.points))
            self.assertEqual(actual, counts, name)
            self.assertTrue(all(n > 0 for n in actual.values()))
            for index in range(len(baseline.points)):
                replay = h.run_crash_scenario(name, index)
                self.assertTrue(replay.crashed, (name,index))
                self.assertEqual(replay.deliveries, baseline.deliveries, (name,index))
                self.assertEqual(sorted(canonical({k:v for k,v in n.items() if k!='t'})
                                        for n in replay.result.notifications if n['watch']),
                                 sorted(canonical({k:v for k,v in n.items() if k!='t'})
                                        for n in baseline.result.notifications if n['watch']))
                for case in {k[0] for k in baseline.result.snapshots}:
                    key = max(k for k in baseline.result.snapshots if k[0]==case)
                    for field in ('events','baseline','evidence_rows'):
                        self.assertEqual(replay.result.snapshots[key][field],
                                         baseline.result.snapshots[key][field], (name,index,field))

    def test_t20_factory_and_watch_independence(self):
        from cornicen.adapterfactories import production_factories
        from cornicen.adapters import REGISTRY
        from cornicen import __version__
        self.assertEqual(__version__, '0.10.2')
        self.assertEqual(REGISTRY['cisco'].gate, 'not met')
        expected = [dict(method='GET', url='https://www.cisco.com/.well-known/csaf/'+path,
                         headers={'User-agent':'Cornicen/test'})
                    for path in ('provider-metadata.json','changes.csv','index.txt','2099/a.json')]
        for platform in (False, True):
            backend = self.backend()
            rows = deepcopy(h.load_timeline('cisco_platform')[:4])
            if platform:
                rows[0]['watchlist'] += 'platform = {vendor="cisco", product="contoso sample relay gateway"}\n'
                rows[0]['watchlist'] = rows[0]['watchlist'].replace('93.0.0-392','93.0.0-391')
            for row in rows: backend.action(row)
            self.assertEqual([{k:r[k] for k in ('method','url','headers')} for r in backend.server.requests], expected)
            factory = unittest.mock.Mock(side_effect=AssertionError('transport before gate'))
            factories = production_factories(backend.engine, http_factory=factory)
            self.assertIn('cisco', factories)
            factory.assert_not_called()
            backend.engine.dispatch_adapters(registry={'cisco':REGISTRY['cisco']}, factories=factories)
            factory.assert_not_called()

        from tests.replay_v11.msrc_backend import validate_rows
        rows = deepcopy(h.load_timeline('cisco_platform')[:4])
        rows[0]['watchlist'] += 'platform = { vendor = "cisco", product = "contoso sample relay gateway" }\n'
        self.assertEqual(validate_rows(rows, 'cisco'), rows)
        for before, after in (
                ('cisco:contoso sample relay', 'cisco:other product'),
                ('93.0.0-392', '94.0.0-392'),
                ('www.cisco.com', 'foreign.invalid'),
                ('sec.cloudapps.cisco.com', 'foreign.invalid')):
            bad = json.loads(json.dumps(rows).replace(before, after))
            with self.assertRaises(ValueError): validate_rows(bad, 'cisco')
        redirect = self.backend()
        rows = deepcopy(h.load_timeline('cisco_platform')[:4])
        scripts = rows[2]['cisco']
        index_body = scripts[2]['body']
        scripts[2] = dict(operation='index', status=302,
                          headers={'location':'https://www.cisco.com/.well-known/csaf/2099/inventory.json'})
        scripts.append(dict(operation='record',path='2099/inventory.json',body=index_body))
        for row in rows: redirect.action(row)
        self.assertEqual(redirect.snapshot()['classification'], {'cisco':'COMPLETE'})
        self.assertEqual(len(redirect.server.requests), 5)

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE')=='1','opt-in scale')
    def test_t21_scale(self):
        from cornicen.csaf import normalise, CISCO
        from cornicen.sources.cisco_csaf import CiscoState, DIRECTORY
        backend = self.backend()
        scripts = self.setup_rows(backend, baseline=False)
        state = CiscoState(backend.store)
        tick = '2026-11-03T00:00:00Z'
        paths = [f'2099/{n:05}.json' for n in range(20000)]
        listing = {p:([tick] if n<18000 else []) for n,p in enumerate(paths)}
        state.observe_listing(listing,0,tick)
        document = scripts[3]['body']
        for n,path in enumerate(paths):
            doc = deepcopy(document)
            doc['document']['tracking']['id'] = f'cisco-sa-scale-{n}'
            doc['vulnerabilities'][0]['cve'] = f'CVE-2099-{80000+n}'
            state.record_success(path,listing[path],normalise(doc,path=path,directory_url=DIRECTORY,policy=CISCO),tick,raw_digest=digest(doc))
        listing_body = ''.join(p+','+tick+'\n' for p in paths[:18000])
        index_body = '\n'.join(paths)+'\n'
        def dispatch(t, responses):
            backend.action(dict(t=t,cisco=responses))
            backend.action(dict(t=t,cycle=True))
            return backend.observed['classification']['cisco']
        responses=[scripts[0],dict(operation='listing',body=listing_body),dict(operation='index',body=index_body)]
        start=time.perf_counter()
        self.assertEqual(dispatch('2026-11-03T01:00:00Z',responses),'COMPLETE')
        bootstrap=time.perf_counter()-start
        bootstrap_rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        changed_tick = '2026-11-03T02:00:00Z'
        changed_listing = ''.join(p+','+(changed_tick if n<200 else tick)+'\n'
                                  for n,p in enumerate(paths[:18000]))
        changes = [dict(operation='listing',body=changed_listing), dict(operation='index',body=index_body)]
        records = []
        for n,path in enumerate(paths[:200]):
            doc = deepcopy(document)
            doc['document']['tracking']['id'] = f'cisco-sa-scale-{n}'
            doc['vulnerabilities'][0]['cve'] = f'CVE-2099-{80000+n}'
            records.append(dict(operation='record',path=path,body=doc))
        start=time.perf_counter()
        # Two listings leave room for 197 records, reserving one request.
        self.assertEqual(dispatch(changed_tick,changes+records[:197]),'PARTIAL')
        self.assertEqual(dispatch('2026-11-03T02:01:00Z',changes+records[197:]),'COMPLETE')
        steady=time.perf_counter()-start
        self.assertEqual(sum(r['operation']=='record' for r in backend.server.requests),200)
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        factor=1 if os.uname().sysname=='Darwin' else 1024
        print(f'Cisco T21 bootstrap={bootstrap:.3f}s steady={steady:.3f}s bootstrap_peak_RSS={bootstrap_rss*factor/1024**2:.2f}MB steady_peak_RSS={rss*factor/1024**2:.2f}MB machine={os.uname()}',flush=True)
        self.assertLess(bootstrap,900);self.assertLess(steady,60);self.assertLess(rss*factor,256*1024**2)
        self.assertEqual(backend.store.connection.execute(
            "SELECT count(*) FROM events WHERE type='baseline' AND record_id='baseline:cisco'").fetchone()[0], 1)
        self.assertEqual(backend.store.connection.execute('SELECT count(*) FROM advisories').fetchone()[0],20000)


CRASH_COUNTS = {'cisco_platform': {'cisco_charge': 48, 'cisco_set_metadata': 12, 'cisco_observe_listing': 12, 'cisco_record_success': 12, 'cisco__container': 12, 'cisco_stage_members': 12, 'record': 32, 'alias': 10, 'enqueue': 6, 'cisco_commit_generation': 12, 'cisco__accept_batch': 10, 'ack': 3}, 'cisco_bad_member': {'cisco_charge': 16, 'cisco_set_metadata': 2, 'cisco_observe_listing': 4, 'cisco_record_success': 6, 'cisco__container': 4, 'cisco_stage_members': 4, 'record': 14, 'alias': 4, 'enqueue': 4, 'cisco_commit_generation': 4, 'ack': 2, 'cisco__accept_batch': 2}, 'cisco_inventory': {'cisco_charge': 120, 'cisco_set_metadata': 16, 'cisco_observe_listing': 20, 'cisco_record_success': 48, 'cisco__container': 20, 'cisco_stage_members': 20, 'record': 124, 'alias': 48, 'cisco_commit_generation': 20, 'cisco__accept_batch': 16, 'cisco_set_hold': 2, 'enqueue': 12, 'ack': 6}}

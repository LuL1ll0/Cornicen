# script-purpose: Verify Debian factory, replay contracts, crash recovery and export scale.
# script-class: harness
# script-trigger: unittest discovery, make gate and opt-in scale measurement.
# script-tests: tests/test_task4_b2.py
"""Read invented JSONL/OSV fixtures; write temporary SQLite and archive files.

Unittest exits 0/1. --scale-day DIRECTORY DAY reads a prepared fixture.zip,
writes DIRECTORY/data and emits JSON metrics; exits 0 success, 1 failure.
CORNICEN_SCALE=1 enables T22 (100000 members; CORNICEN_SCALE_MEMBERS overrides
for a smaller rehearsal). Each measured day runs in a fresh foreground process.
"""
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen.adapterstore import canonical
from tests.replay_v11 import harness as h

NAMES = tuple('debian_'+n for n in ('bounds','exports','split','aggregate','boundary'))

CRASH_COUNTS = {'debian_aggregate': {'record': 22, 'debian_restore_health': 10, 'debian_ensure': 30, 'debian_reconcile_required': 10, 'debian_dimension': 80, 'debian_attempt': 10, 'debian__pass': 10, 'debian_poll': 10, 'debian_dispatch': 20, 'debian__process_resources': 10, 'debian__audit_observation': 10, 'debian_stage_members': 10, 'debian_commit_staged': 30, 'alias': 12, 'enqueue': 8, 'debian__accept_batch': 10, 'debian__defaults': 10, 'debian_process': 10, 'debian_finish_cycle': 20, 'ack': 4}, 'debian_boundary': {'ack': 4, 'debian__audit_observation': 8, 'debian__defaults': 8, 'debian__pass': 2, 'debian__process_resources': 8, 'debian_attempt': 8, 'debian_dimension': 56, 'debian_dispatch': 16, 'debian_ensure': 16, 'debian_finish_cycle': 16, 'debian_process': 8, 'debian_reconcile_required': 8, 'debian_restore_health': 8, 'debian_retry': 8, 'enqueue': 8}, 'debian_bounds': {'ack': 3, 'alias': 8, 'debian__accept_batch': 8, 'debian__audit_observation': 8, 'debian__defaults': 8, 'debian__pass': 8, 'debian__process_resources': 8, 'debian_attempt': 8, 'debian_commit_staged': 16, 'debian_dimension': 62, 'debian_dispatch': 16, 'debian_ensure': 24, 'debian_finish_cycle': 16, 'debian_poll': 8, 'debian_process': 8, 'debian_reconcile_required': 8, 'debian_restore_health': 8, 'debian_stage_members': 8, 'enqueue': 6, 'record': 8}, 'debian_exports': {'ack': 12, 'alias': 12, 'debian__accept_batch': 16, 'debian__audit_observation': 24, 'debian__clear_reappeared': 2, 'debian__defaults': 24, 'debian__pass': 26, 'debian__process_resources': 24, 'debian_attempt': 24, 'debian_commit_staged': 38, 'debian_dimension': 184, 'debian_dispatch': 48, 'debian_ensure': 70, 'debian_finish_cycle': 48, 'debian_poll': 22, 'debian_process': 24, 'debian_quarantine': 2, 'debian_reconcile_required': 24, 'debian_restore_health': 24, 'debian_retry': 10, 'debian_stage_members': 22, 'enqueue': 24, 'record': 12}, 'debian_split': {'ack': 2, 'alias': 4, 'debian__accept_batch': 4, 'debian__audit_observation': 4, 'debian__defaults': 4, 'debian__pass': 4, 'debian__process_resources': 4, 'debian_attempt': 4, 'debian_commit_staged': 12, 'debian_dimension': 32, 'debian_dispatch': 8, 'debian_ensure': 12, 'debian_finish_cycle': 8, 'debian_poll': 4, 'debian_process': 4, 'debian_reconcile_required': 4, 'debian_restore_health': 4, 'debian_stage_members': 4, 'enqueue': 4, 'record': 6}}


class Task4B2Tests(unittest.TestCase):
    def scenario(self, name):
        result = h.run_scenario(name)
        expected = h.load_expected(name)
        for row in expected: h.assert_line(result, row, expected)
        h.assert_notifications(result, expected)
        self.assertNotIn(name, h.scenario_names())
        return result

    def test_t16_bounds(self):
        result = self.scenario('debian_bounds')
        snaps = list(result.snapshots.values())[:3]
        self.assertEqual([s['pairs'][0]['state'] for s in snaps], ['affected','unaffected','affected'])
        self.assertEqual([s['notification_count']['advisory'] for s in snaps], [1,0,1])
        self.assertEqual([s['fix'] for s in snaps], [{'CVE-2099-80213':'93.0.11-1~deb12u2'},
                                                   {'CVE-2099-80213':None}, {'CVE-2099-80091':None}])
        self.assertTrue(all(s['dimensions']['debian']['freshness']=='healthy' for s in snaps))
        browser = h.load_timeline('debian_bounds')[12]['debian'][1]['members'][0]
        self.assertRegex(browser['modified'], r'\.\d{9}Z$')

    def test_t17_exports(self):
        result = self.scenario('debian_exports')
        main = [s for k,s in result.snapshots.items() if k[0]=='main']
        self.assertEqual([s['classification']['debian'] for s in main], ['COMPLETE','PARTIAL','COMPLETE'])
        self.assertEqual(main[0]['cursor'], main[1]['cursor'])
        self.assertEqual(main[0]['evidence_rows'], main[1]['evidence_rows'])
        self.assertEqual(main[0]['events'], main[2]['events'])
        self.assertEqual(main[2]['requests']-main[1]['requests'], 6)
        # Inspect the request trace, not just the count, for both complete passes.
        for key in ('lost_copy','missing_member','truncated'):
            snaps=[v for k,v in result.snapshots.items() if k[0]==key]
            self.assertEqual(snaps[0]['evidence_rows'],snaps[1]['evidence_rows'])
            self.assertEqual(snaps[0]['cursor'],snaps[1]['cursor'])
        truncated=[v for k,v in result.snapshots.items() if k[0]=='truncated']
        self.assertEqual(truncated[-1]['requests'], truncated[-2]['requests'])
        self.assertEqual(truncated[1]['staged'],[])
        backend=self.backend()
        for row in h.load_timeline('debian_exports')[:8]: backend.action(row)
        trace=[r['operation'] for r in backend.server.requests]
        self.assertEqual(trace, ['discovery','archive:Debian:12','archive:Debian:13']*4)

    def test_t18_split(self):
        result = self.scenario('debian_split')
        first,second = result.snapshots.values()
        self.assertEqual([p['state'] for p in first['pairs']], ['unknown','unknown','affected'])
        self.assertEqual(first['body']['label'], 'advisory — which listed CVE affects you is not stated')
        self.assertEqual([p['state'] for p in second['pairs']], ['affected','unknown','affected'])
        self.assertEqual(len(result.notifications),2)

    def test_t19_aggregate(self):
        result = self.scenario('debian_aggregate')
        # Observe execution, including the first request, rather than action order.
        pending = Counter()
        case = 'main'
        for row in h.load_timeline('debian_aggregate'):
            if 'case' in row: case = row['case']
            if 'ingest' in row: pending[case, row['t']] += 1
        for (case, tick), count in pending.items():
            events = [event for t, event in result.snapshots[case, tick]['call_order'] if t == tick]
            self.assertEqual(events, ['ingest'] * count + ['request'], (case, tick))
        unscoped = result.snapshots['unscoped_cna', '2026-11-14T01:00:00Z']
        self.assertEqual(unscoped['pairs'][0]['state'], 'affected')
        main = [s for k,s in result.snapshots.items() if k[0]=='main']
        self.assertEqual([s['pairs'][0]['state'] for s in main], ['affected','unknown','unaffected'])
        self.assertEqual(main[-1]['pairs'][0]['episode'],2)
        backend=self.backend()
        for row in h.load_timeline('debian_aggregate'):
            if 'case' in row: break
            backend.action(row)
        record=backend.engine._record('CVE-2099-80213')
        self.assertEqual(record['containers']['cna']['affected'][0]['defaultStatus'],'unaffected')
        from cornicen import advisory
        from cornicen.identity import AliasMap
        verdicts=advisory.cnascope.scoped_verdicts(record,backend.watches[0],AliasMap.load(False))
        self.assertTrue(any(v.authoritative and v.state.value=='not_affected' for v in verdicts))
        explanation=advisory.resolve(backend.store.connection,'CVE-2099-80213',backend.watches[0],AliasMap.load(False),record=record)
        self.assertIn(verdicts[0].evidence,explanation.evidence)
        unscoped_backend = self.backend()
        rows = h.load_timeline('debian_aggregate')
        start = next(i for i, row in enumerate(rows) if row.get('case') == 'unscoped_cna')
        for row in rows[start+1:]: unscoped_backend.action(row)
        record = unscoped_backend.engine._record('CVE-2099-80213')
        self.assertNotIn('release', record['containers']['cna']['affected'][0])
        verdicts = advisory.cnascope.scoped_verdicts(record, unscoped_backend.watches[0], AliasMap.load(False))
        self.assertTrue(any(v.authoritative and v.state.value == 'not_affected' for v in verdicts))

    def test_t19_scratch_mutations_detected(self):
        from cornicen import advisory
        from tests.replay_v11 import osv_backend
        # Compile scratch copies in memory so production and harness files stay intact.
        source = Path(osv_backend.__file__).read_text()
        ingest = """            for ingest in self.ingests:
                with self.store.transaction(): self.engine._ingest(ingest)
                self.server.call_order.append((row['t'], 'ingest'))
"""
        self.assertEqual(source.count(ingest), 1)
        source = source.replace(ingest, '').replace('            self.engine._flush()', ingest + '            self.engine._flush()')
        scratch = dict(vars(osv_backend))
        exec(compile(source, '<scratch ingest-after-dispatch>', 'exec'), scratch)
        with patch.object(osv_backend, 'DebianBackend', scratch['DebianBackend']):
            result = unittest.TestResult()
            Task4B2Tests('test_t19_aggregate').run(result)
        self.assertFalse(result.errors, result.errors)
        self.assertEqual(len(result.failures), 1)
        self.assertIn("'request', 'ingest'", result.failures[0][1])

        source = Path(advisory.__file__).read_text()
        original = '    if osv_row(row):\n        return False'
        self.assertEqual(source.count(original), 1)
        source = source.replace(original, '    if osv_row(row):\n        return True')
        scratch = dict(vars(advisory))
        exec(compile(source, '<scratch OSV same_scope True>', 'exec'), scratch)
        with patch.object(advisory, 'same_scope', scratch['same_scope']):
            result = unittest.TestResult()
            Task4B2Tests('test_t19_aggregate').run(result)
        self.assertFalse(result.errors, result.errors)
        self.assertEqual(len(result.failures), 1)
        self.assertIn('unscoped_cna', result.failures[0][1])

    def test_debian_zero_retry_attempts_rejected(self):
        original = h.dump_database
        mutations = []
        def corrupt(connection):
            dump = original(connection)
            retries = dump['tables']['adapter_retries']
            for row in retries['rows']:
                row[retries['columns'].index('attempts')] = 0
                mutations.append(True)
            return dump
        with patch.object(h, 'dump_database', corrupt):
            with self.assertRaisesRegex(AssertionError, 'retry attempts must be positive'):
                h.run_crash_scenario('debian_boundary')
        self.assertTrue(mutations, 'control must mutate a retry row')

    def test_t20_boundary(self):
        result = self.scenario('debian_boundary')
        for (case,t),snapshot in result.snapshots.items():
            self.assertEqual(snapshot['classification']['debian'], 'PARTIAL' if case=='truncated' else 'FAILED')
            self.assertEqual(snapshot['events'],[])
            self.assertEqual(snapshot['cursor']['debian']['digest'], '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945')
            self.assertEqual(snapshot['retries'],[dict(source='debian',resource='debian/advisories')])
            self.assertEqual(snapshot['evidence_rows'],{})
        self.assertEqual(len(result.notifications),4)
        self.assertTrue(all(n['reasons']==['unhealthy'] for n in result.notifications))

    def test_t21_crash_replays(self):
        counts={}
        for name in NAMES:
            baseline=h.run_crash_scenario(name)
            counts[name]=dict(Counter(p.split(':',1)[0] for p in baseline.points))
            self.assertEqual(counts[name],CRASH_COUNTS[name],name)
            self.assertTrue(all(n>0 for n in counts[name].values()))
            for index in range(len(baseline.points)):
                try:
                    replay=h.run_crash_scenario(name,index)
                except BaseException as error:
                    error.add_note(f'{name} index={index} {baseline.points[index]}')
                    raise
                self.assertTrue(replay.crashed,(name,index))
                self.assertEqual(replay.deliveries,baseline.deliveries,(name,index))
                for case in {k[0] for k in baseline.result.snapshots}:
                    key=max(k for k in baseline.result.snapshots if k[0]==case)
                    for field in ('events','baseline','evidence_rows','pairs','cursor'):
                        self.assertEqual(replay.result.snapshots[key][field],baseline.result.snapshots[key][field],(name,index,field))
        required={'debian_attempt','debian_poll','debian__pass','debian__audit_observation',
                  'debian_stage_members','debian_commit_staged','debian_retry','debian_quarantine','debian__accept_batch'}
        self.assertLessEqual(required,set().union(*(set(v) for v in counts.values())))
        print('Debian T21 boundary counts: '+json.dumps(counts,sort_keys=True),flush=True)

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE')=='1','opt-in scale')
    def test_t22_scale(self):
        from cornicen.adapterfactories import production_factories
        self.assertIn('debian', production_factories(Mock()))
        count=int(os.environ.get('CORNICEN_SCALE_MEMBERS','100000'))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            directory=Path(tmp)
            prepare_scale(directory,count)
            metrics=[]
            for day in (0,1):
                result=subprocess.run([sys.executable,'-m','tests.test_task4_b2','--scale-day',tmp,str(day)],
                                      check=True,capture_output=True,text=True)
                metrics.append(json.loads(result.stdout))
            self.assertEqual(metrics[0]['members'],count)
            self.assertEqual(metrics[1]['members'],count)
            self.assertEqual([m['summaries'] for m in metrics],[1,1])
            self.assertLess(metrics[0]['seconds'],600)
            self.assertLess(metrics[1]['seconds'],300)
            self.assertTrue(all(m['rss_bytes']<256*1024**2 for m in metrics))
            print('Debian T22 '+json.dumps(dict(members=count,days=metrics),sort_keys=True),flush=True)

    def test_t23_factory_watch_independence(self):
        from cornicen.adapterfactories import production_factories
        from cornicen.adapters import REGISTRY
        from cornicen import __version__
        self.assertEqual(__version__,'0.10.1')
        self.assertEqual(REGISTRY['debian'].gate,'not met')
        self.assertFalse(REGISTRY['debian'].last_modified_validated)
        expected=[dict(method='GET',url=url,headers={'User-agent':'Cornicen/test'}) for url in (
            'https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt',
            'https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip')]
        self.assertTrue(expected)
        for selectors in (True,False):
            backend=self.backend()
            rows=deepcopy(h.load_timeline('debian_bounds')[:4])
            if not selectors: rows[0]['watchlist']='\n'.join(l for l in rows[0]['watchlist'].splitlines() if not l.startswith('osv=' )).replace('93.0.11-1~deb12u1','1:90.0-1')
            for row in rows: backend.action(row)
            self.assertEqual([{k:r[k] for k in ('method','url','headers')} for r in backend.server.requests],expected)
            factory=Mock(side_effect=AssertionError('transport before gate'))
            factories=production_factories(backend.engine,http_factory=factory)
            self.assertIn('debian',factories)
            backend.engine.dispatch_adapters(registry={'debian':REGISTRY['debian']},factories=factories)
            factory.assert_not_called()

    def test_backend_contracts(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('test_osv_backend', Path(__file__).parent/'replay_v11/test-osv-backend.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromModule(module).run(result)
        self.assertTrue(result.wasSuccessful(),result.failures+result.errors)

    def backend(self):
        from tests.replay_v11.osv_backend import DebianBackend
        backend=DebianBackend(h.fixture_registry())
        self.addCleanup(backend.close)
        return backend


def prepare_scale(directory,count):
    """Write the entire fixture before starting either measured child process."""
    import zipfile
    fixture=json.loads(Path('tests/fixtures/debian/osv_query_sample.json').read_text())['vulns']
    with zipfile.ZipFile(directory/'fixture.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for n in range(count):
            record=deepcopy(fixture[n%len(fixture)])
            record['id']=f'DEBIAN-CVE-2099-{900000+n}'
            record['upstream']=[f'CVE-2099-{900000+n}']
            record['affected']=[deepcopy(record['affected'][i%len(record['affected'])]) for i in range(3)]
            for i,affected in enumerate(record['affected']): affected['package']['ecosystem']=f'Debian:{12+i}'
            archive.writestr(record['id']+'.json',canonical(record))


def scale_day(directory,day):
    """Measure real Http/zip/dispatch/store in a new process using file-backed input."""
    import resource
    import socket
    import threading
    import time
    from io import BytesIO
    from cornicen.adapterfactories import production_factories
    from cornicen.adapters import REGISTRY
    from cornicen.config import Config
    from cornicen.engine import Engine
    from cornicen.fetch import Http
    from cornicen.identity import AliasMap
    from cornicen.store import Store
    from dataclasses import replace
    from tests.replay.harness import FakeClock, RecordingNotifier, utc
    data=directory/'data'; data.mkdir(exist_ok=True)
    tick=f'2026-11-{3+day:02}T01:00:00Z'
    clock=FakeClock(utc(tick))
    store=Store(data/'state.db');store.migrate()
    store.set_meta('baseline_complete','1')
    config=Config(data/'state.db',data/'unused',None,'https://examplecorp.invalid','test',None,retention_days=365)
    engine=Engine(store,(),AliasMap.load(False),config,clock,RecordingNotifier(clock))
    engine._digest=lambda:tick
    config.adapters['debian']=True
    class Opener:
        def open(self,request,timeout):
            assert request.get_method()=='GET'
            if request.full_url.endswith('/ecosystems.txt'): response=BytesIO(b'Debian\n')
            else:
                assert request.full_url=='https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip'
                response=(directory/'fixture.zip').open('rb')
            response.status=200
            response.headers={'last-modified':f'{"Tue" if day==0 else "Wed"}, {3+day:02} Nov 2026 00:00:00 GMT'}
            return response
    def resolver(host,port,**kwargs):
        assert host=='osv-vulnerabilities.storage.googleapis.com'
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',port))]
    def factory(): return Http('Cornicen/test',{},opener=Opener(),resolver=resolver,data_dir=data)
    def disk(): return sum(p.stat().st_size for p in data.rglob('*') if p.is_file())
    initial=disk(); peak=[initial];stop=threading.Event()
    def sample():
        while not stop.wait(.01):
            try: peak[0]=max(peak[0],disk())
            except FileNotFoundError: pass
    thread=threading.Thread(target=sample);thread.start()
    start=time.perf_counter()
    try:
        result=engine.dispatch_adapters(registry={'debian':replace(REGISTRY['debian'],gate='met',last_modified_validated=True)},factories=production_factories(engine,http_factory=factory))
        engine._flush()
        assert result=={'debian':'COMPLETE'},result
    finally:
        elapsed=time.perf_counter()-start;stop.set();thread.join()
    assert not list(data.glob('debian-*'))
    assert not list(data.glob('fetch-*'))
    assert not store.connection.execute('SELECT 1 FROM staged_containers').fetchone()
    assert not [p for p in data.rglob('*') if p.is_file() and not p.name.startswith('state.db')]
    members=store.connection.execute('SELECT count(*) FROM advisories').fetchone()[0]
    summaries=store.connection.execute("SELECT count(*) FROM events WHERE type='baseline' AND record_id='baseline:debian'").fetchone()[0]
    store.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    growth=disk()-initial; peak[0]=max(peak[0],disk())
    from tests.source_helpers import peak_rss_bytes
    rss=peak_rss_bytes()
    store.connection.close();store._finalizer.detach()
    print(json.dumps(dict(day=day,seconds=elapsed,rss_bytes=rss,db_growth_bytes=growth,peak_disk_bytes=peak[0],members=members,summaries=summaries)))


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--scale-day': scale_day(Path(sys.argv[2]),int(sys.argv[3]))
    else: unittest.main()

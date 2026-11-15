# script-purpose: Verify durable adapter staging, commits, baselines and retries.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f2a.py
"""Read invented records; write isolated databases and staged files.

Run python3 -m unittest tests.test_f2a; exit 0 on success, 1 on failure.
"""
from datetime import datetime, timedelta, timezone
import json
import hashlib
import os
import resource
import subprocess
import sys
from pathlib import Path
import random
import tempfile
import tracemalloc
import unittest
from unittest.mock import Mock

from cornicen import adapters, feedvalidate as v
from cornicen.store import Store
from tests.test_f1 import member

T = '2099-01-01T00:00:00Z'
T2 = '2099-01-01T01:00:00Z'
S = 'fixture_a'

def m(n, **kw):
    return member() | {'id': f'FIX-2099-{n:04}'} | kw

def complete_memory_probe(count):
    """Read generated members, write temporary state, print RSS and digests."""
    from cornicen.adapterstore import AdapterStore
    def rss():
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value if sys.platform == 'darwin' else value * 1024
    baseline = rss()
    # Independent reference: encode raw records and membership without production
    # canonical/digest helpers, reading the generator in lexical identity order.
    reference = hashlib.sha256(b'[')
    for n in range(count):
        i = n
        raw = m(n, id=f'FIX-2099-{n:07}', title='x'*1024)
        md = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        entry = json.dumps({'digest': md, 'source_id': raw['id']}, sort_keys=True, separators=(',', ':')).encode()
        reference.update((b',' if i else b'') + entry)
    reference.update(b']')
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        store = Store(Path(directory)/'state.db')
        store.migrate()
        p = AdapterStore(store, directory)
        p.stage_members(S, 'listing.json', (m(n, id=f'FIX-2099-{n:07}', title='x'*1024) for n in range(count)), T)
        candidates = []
        state = p.commit_staged(S, 'listing.json', T, deferred=candidates)
        p._accept_batch(S, T, candidates)
        for _, _, index_path in candidates:
            index_path.unlink(missing_ok=True)
        db = store.connection
        result = dict(count=count, classification=state, baseline=baseline, peak=rss(),
                      reference=reference.hexdigest(),
                      cursor=db.execute('SELECT cursor_digest FROM adapter_state').fetchone()[0],
                      manifest=db.execute('SELECT digest FROM manifests').fetchone()[0],
                      committed=db.execute('SELECT count(*) FROM advisories').fetchone()[0])
        db.close()
    print(json.dumps(result), flush=True)

class F2aTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.db'
        self.open()

    def open(self):
        from cornicen.adapterstore import AdapterStore
        self.store = Store(self.path)
        self.store.migrate()
        self.p = AdapterStore(self.store, Path(self.tmp.name), rng=random.Random(7))
        self.db = self.store.connection
        self.addCleanup(self.db.close)

    def commit(self, members, tick=T, **kw):
        self.p.stage_members(S, 'listing.json', iter(members), tick)
        return self.p.commit_staged(S, 'listing.json', tick, **kw)

    def rows(self, table):
        return [tuple(r) for r in self.db.execute('SELECT * FROM ' + table)]

    def test_record_commit_survives_sibling_failure(self):
        self.assertEqual(self.commit([m(10), m(11, url='bad')]), 'PARTIAL')
        row=self.db.execute('SELECT source_id,digest FROM advisories').fetchone()
        self.assertEqual(tuple(row),(m(10)['id'],v.validate_advisory(m(10),source=S,observed_at=T).data['digest']))
        self.assertEqual(self.db.execute('SELECT source_id FROM quarantine').fetchone()[0], m(11)['id'])
        self.assertIsNone(self.db.execute('SELECT cursor_tick FROM adapter_state').fetchone()[0])

    def test_quarantine_keeps_prior_evidence(self):
        self.commit([m(11,products=[dict(id='p',name='examplecorp:widget')],evidence=[dict(product_id='p',scheme='semver',status='known_affected')])])
        self.db.execute("INSERT INTO advisory_evidence(source,source_id,provenance) VALUES (?,?,?)", (S,m(11)['id'],'prior'))
        before = self.rows('advisories'), self.rows('advisory_evidence')
        self.commit([m(11, url='bad')], T2)
        self.assertEqual(before, (self.rows('advisories'), self.rows('advisory_evidence')))
        self.assertEqual(tuple(self.db.execute('SELECT source_id,last_at FROM quarantine').fetchone()),(m(11)['id'],T2))
        self.commit([m(12, id='bad|id')], T2)
        row = self.db.execute("SELECT source_id,reason FROM quarantine WHERE reason='invalid id'").fetchone()
        self.assertIsNotNone(row)
        v.source_id(row[0])
        self.assertTrue(row[0].startswith('@invalid:'))

    def test_same_id_conflict_withheld_together(self):
        self.assertEqual(self.commit([m(12)] + [m(n) for n in range(100,1098)] + [m(12,title='changed')]), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0],998)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories WHERE source_id=?',(m(12)['id'],)).fetchone()[0],0)

    def check_complete_memory(self, count, bound_mb):
        result = subprocess.run([sys.executable, '-c',
            f'from tests.test_f2a import complete_memory_probe; complete_memory_probe({count})'],
            capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        print('COMPLETE_MEMORY ' + json.dumps(data), flush=True)
        self.assertEqual(data['classification'], 'COMPLETE')
        self.assertEqual(data['committed'], count)
        self.assertEqual(data['manifest'], data['reference'])
        self.assertEqual(data['cursor'], data['reference'])
        self.assertLess(data['peak'] - data['baseline'], bound_mb * 1024**2)

    def test_complete_path_bounded_default(self):
        self.check_complete_memory(50000, 200 * 50000 / 600000)

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE_TESTS') == '1', 'opt-in scale test')
    def test_complete_path_bounded(self):
        self.check_complete_memory(600000, 200)

    def test_commit_path_bounded(self):
        self.check_commit_path_bounded(50000)

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE_TESTS') == '1', 'opt-in scale test')
    def test_commit_path_bounded_scale(self):
        self.check_commit_path_bounded(200000)

    def check_commit_path_bounded(self, count):
        def members():
            for n in range(count):
                yield m(n, title='x'*1024)
            yield m(0,title='conflict')
            yield m(1,title='x'*1024)
        self.p.stage_members(S,'listing.json',members(),T)
        tracemalloc.start()
        try:
            self.assertEqual(self.p.commit_staged(S,'listing.json',T),'PARTIAL')
            self.assertLess(tracemalloc.get_traced_memory()[1],32*1024**2)
        finally:
            tracemalloc.stop()
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0],count-1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories WHERE source_id=?',(m(0)['id'],)).fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories WHERE source_id=?',(m(1)['id'],)).fetchone()[0],1)
        self.assertEqual(self.db.execute('SELECT revision FROM advisories WHERE source_id=?',(m(1)['id'],)).fetchone()[0],'1')
        self.assertEqual(list(Path(self.tmp.name).rglob('*.index*')),[])

    def test_resumed_partial_gets_backoff(self):
        self.p.stage_members(S, 'listing.json', iter([m(10, url='bad')]), T)
        self.p.resume(T)
        row = self.db.execute('SELECT attempts,next_attempt_at FROM adapter_retries').fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row['attempts'], 1)
        self.assertGreater(row['next_attempt_at'], T)
        self.p.resume(T)
        self.assertEqual(self.db.execute('SELECT attempts FROM adapter_retries').fetchone()[0], 1)

    def test_invalid_id_does_not_pin_baseline(self):
        self.assertEqual(self.commit([m(10), m(11, id='bad|id')]), 'PARTIAL')
        self.assertEqual(self.commit([m(10)], T2), 'COMPLETE')
        self.assertTrue(self.db.execute('SELECT baseline_complete FROM adapter_state').fetchone()[0])
        # Legacy impossible pins are cleared by the rebaseline command.
        self.db.execute("UPDATE adapter_state SET baseline_members=?,baseline_complete=0", (json.dumps(["@invalid:old"]),))
        self.db.execute('INSERT INTO baseline_members VALUES (?,?)',(S,'@invalid:old'))
        self.p.rebaseline(S, T2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM baseline_members WHERE source_id GLOB '@invalid:*'").fetchone()[0],0)
        self.assertNotIn('@invalid:', self.db.execute('SELECT baseline_members FROM adapter_state').fetchone()[0])
        self.assertTrue(self.db.execute('SELECT baseline_complete FROM adapter_state').fetchone()[0])

    def test_interrupted_container_resumes(self):
        def crash(point):
            if point == 'after_index': raise RuntimeError('crash')
        with self.assertRaises(RuntimeError): self.commit([m(10),m(10)], checkpoint=crash)
        self.assertEqual(self.rows('advisories'),[])
        self.db.close(); self.open()
        self.p.resume(T)
        self.assertEqual(len(self.rows('advisories')),1)
        self.assertEqual(self.rows('staged_containers'),[])
        from cornicen.adapterstore import AdapterStore
        reference_dir=Path(self.tmp.name)/'reference'
        reference_dir.mkdir()
        reference=Store(reference_dir/'state.db')
        try:
            reference.migrate()
            persistence=AdapterStore(reference,reference_dir)
            persistence.stage_members(S,'listing.json',iter([m(10),m(10)]),T)
            persistence.commit_staged(S,'listing.json',T)
            for table in ('advisories','manifests','manifest_members','baseline_members','adapter_state','events','outbox'):
                self.assertEqual(self.rows(table),[tuple(row) for row in reference.connection.execute('SELECT * FROM '+table)])
        finally:
            reference.connection.close()

    def test_cursor_held_on_partial_and_failed(self):
        self.commit([m(10)])
        cursor = tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state').fetchone())
        self.assertEqual(cursor,(T,'cacb2be686e4adb42235c275a42cff95c2c610770b6b7c840145d39e8076a074'))
        self.commit([m(10,title='revision'),m(11,url='bad')],T2)
        self.p.process(S,[dict(path='bad.json',status=500,body='')],T2)
        self.assertEqual(cursor,tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state').fetchone()))
        self.assertEqual(self.db.execute('SELECT revision FROM advisories').fetchone()[0],'2')

    def test_manifest_and_cursor_atomic(self):
        self.commit([m(10)])
        before=self.rows('manifests'),self.rows('manifest_members'),self.rows('adapter_state')
        def crash(point):
            if point=='after_manifest': raise RuntimeError('crash')
        with self.assertRaises(RuntimeError): self.commit([m(10,title='edit')],T2,checkpoint=crash)
        self.assertEqual(before,(self.rows('manifests'),self.rows('manifest_members'),self.rows('adapter_state')))

    def test_cache_body_validators_headers(self):
        r=dict(path='listing.json',status=200,body=json.dumps([m(10)]),headers={'ETag':'e','Last-Modified':'d','Link':'l'})
        self.p.process(S,[r],T)
        row=self.db.execute('SELECT * FROM resource_cache').fetchone()
        self.assertEqual((row['body'],row['etag'],row['last_modified'],row['link_header']),(r['body'],'e','d','l'))
        self.db.close();self.open()
        self.assertEqual(self.p.process(S,[dict(path='listing.json',status=304)],T2),'COMPLETE')
        self.assertEqual(tuple(self.db.execute('SELECT body,etag,last_modified,link_header FROM resource_cache').fetchone()),(r['body'],'e','d','l'))
        self.assertEqual(self.p.process(S,[dict(path='absent',status=304)],T2),'FAILED')
        self.assertIn('304 without cached body',self.db.execute("SELECT last_error FROM adapter_retries WHERE resource='absent'").fetchone()[0])

    def test_304_keeps_pending_work(self):
        self.p.process(S,[dict(path='listing.json',status=200,body=json.dumps([m(10)]))],T)
        self.p.stage_members(S,'member.json',iter([m(11)]),T2,integrity='pending')
        self.p.retry(S,'member.json',T2,'pending')
        before=self.rows('staged_containers'),self.rows('adapter_retries'),self.rows('adapter_state')
        self.assertEqual(self.p.process(S,[dict(path='listing.json',status=304)],T2),'PARTIAL')
        self.assertEqual(before,(self.rows('staged_containers'),self.rows('adapter_retries'),self.rows('adapter_state')))

    def test_cutoff_persists(self):
        self.commit([m(10)])
        self.assertEqual(self.db.execute('SELECT cutoff FROM adapter_state').fetchone()[0],T)
        self.db.close();self.open()
        seen=[]
        adapter=Mock();adapter.poll.return_value=[]
        self.p.dispatch({S: adapters.Adapter(S,'F','met')},{S:True},{S:lambda:adapter},T2)
        self.assertEqual(adapter.poll.call_args.kwargs['cutoff'],T)
        self.assertEqual(self.db.execute('SELECT cutoff FROM adapter_state').fetchone()[0],T)

    def test_baseline_pins_first_intact_enumeration(self):
        self.p.process(S,[dict(path='listing.json',status=200,body=json.dumps([m(20)]),transfer_complete=False)],T)
        self.assertIsNone(self.db.execute('SELECT baseline_members FROM adapter_state').fetchone()[0])
        seen=[]
        self.commit([m(20),m(21),m(22,url='bad')],T2)
        self.assertEqual([r[0] for r in self.db.execute('SELECT source_id FROM baseline_members ORDER BY source_id')],[m(i)['id'] for i in (20,21,22)])
        self.commit([m(20),m(21),m(22,url='bad'),m(23)],'2099-01-01T02:00:00Z',on_record=lambda data,baseline:seen.append((data['source_id'],baseline)))
        self.assertIn((m(23)['id'],False),seen)
        self.assertFalse(self.db.execute('SELECT baseline_complete FROM adapter_state').fetchone()[0])
        self.commit([m(i) for i in (20,21,22,23)],'2099-01-01T03:00:00Z',on_record=lambda data,baseline:seen.append((data['source_id'],baseline)))
        self.assertIn((m(22)['id'],True),seen)
        self.assertTrue(self.db.execute('SELECT baseline_complete FROM adapter_state').fetchone()[0])
        self.assertEqual(len(self.p.summaries()),1)

    def test_one_summary_after_baseline(self):
        self.commit([]);self.commit([],T2)
        self.assertEqual(len(self.p.summaries()),1)
        self.db.close();self.open();self.commit([],T2)
        self.assertEqual(len(self.p.summaries()),1)

    def test_rebaseline_preserves_history_and_gap(self):
        self.commit([m(10)])
        self.p.gap(S,T2,'retention gap')
        with self.store.transaction():
            self.store.queue('w|CVE-2099-0010','normal',['new match'],{'record_id':'CVE-2099-0010'},T2)
            for reason in ('new match','KEV added'):
                self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',('w|CVE-2099-0010|'+reason+'|1','w','CVE-2099-0010',reason,1,T))
        before=self.rows('events'),self.rows('outbox')
        gap_count=len(self.rows('gap_ledger'))
        self.p.rebaseline(S,T2)
        self.assertEqual(len(self.rows('gap_ledger')),gap_count)
        self.assertEqual(before,(self.rows('events'),self.rows('outbox')))
        self.assertEqual(self.db.execute('SELECT acknowledged_at FROM gap_ledger').fetchone()[0],T2)
        self.assertEqual(self.p.historical(S),'unhealthy (permanent gap)')
        self.assertEqual(self.db.execute('SELECT cursor_tick FROM adapter_state').fetchone()[0],T2)

    def test_retry_schedule(self):
        expected=random.Random(7)
        now=datetime.fromisoformat(T)
        for n in range(1,11):
            wait=self.p.retry(S,'r',T,'bad')
            self.assertAlmostEqual(wait,min(60*2**(n-1),21600)*expected.uniform(.8,1.2))
        self.assertEqual(self.db.execute('SELECT attempts FROM adapter_retries').fetchone()[0],10)
        self.assertEqual(self.rows('dead_letters'),[])
        self.p.retry(S,'header',T,'bad')
        self.assertEqual(self.p.retry(S,'header',T,'bad',retry_after=900),900)
        self.assertEqual(self.p.retry(S,'reset',T,'bad',rate_reset=now+timedelta(hours=2)),7200)
        before=self.rows('adapter_retries');self.db.close();self.open()
        self.assertEqual(before,self.rows('adapter_retries'))
        self.assertEqual(self.rows('retry_queue'),[])

    def test_retry_does_not_block_valid_alerts(self):
        self.p.retry(S,'bad.json',T,'bad')
        self.p.process(S,[dict(path='other.json',status=200,body=json.dumps([m(31)]))],T)
        self.p.process(S,[dict(path='other.json',status=200,body=json.dumps([m(31,title='revision')]))],T2)
        self.assertEqual(self.db.execute('SELECT revision FROM advisories').fetchone()[0],'2')
        self.assertEqual(len(self.rows('adapter_retries')),1)

    def test_disable_after_unhealthy(self):
        self.commit([])
        self.db.execute('INSERT INTO source_health VALUES (?,?,?,?,?)',(S,'completeness','unhealthy',T,'gap'))
        self.db.execute('INSERT INTO health VALUES (?,?,?,?)',(S,'unhealthy',T,'gap'))
        self.p.retry(S,'r',T,'bad')
        self.p.gap(S,T,'retention gap')
        kept=('source_health','adapter_retries','outbox','adapter_state','gap_ledger','advisory_evidence')
        before=tuple(self.rows(table) for table in kept)
        self.p.dispatch({S:adapters.Adapter(S,'F','met')},{S:False},{S:Mock()},T2)
        self.assertEqual(self.rows('health'),[])
        from types import SimpleNamespace
        from cornicen.health import container_healthy
        self.assertTrue(container_healthy(self.store,datetime.fromisoformat(T2),SimpleNamespace(deadman_url=None,overdue_minutes=60)))
        self.assertEqual(before,tuple(self.rows(table) for table in kept))
        adapter=Mock();adapter.poll.return_value=[];adapter.retry.return_value=[]
        self.p.dispatch({S:adapters.Adapter(S,'F','met')},{S:True},{S:lambda:adapter},T2)
        self.assertEqual(self.db.execute('SELECT state FROM health').fetchone()[0],'unhealthy')
        self.assertEqual(before,tuple(self.rows(table) for table in kept))

    def test_dispatch_exceptions_do_not_stop_cycle_or_outbox(self):
        from dataclasses import replace
        from cornicen.config import Config
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from tests.replay.harness import FakeClock, RecordingNotifier
        from unittest.mock import patch
        clock=FakeClock(datetime.fromisoformat(T))
        notifier=RecordingNotifier(clock)
        config=replace(Config(self.path, Path('unused'), None, 'https://examplecorp.invalid', 'test', None), adapters={S:True,'fixture_b':True})
        engine=Engine(self.store, (), AliasMap.load(False), config, clock, notifier)
        registry={name:adapters.Adapter(name,'F','met') for name in (S,'fixture_b')}
        for attempt,phase in enumerate(('factory','poll','process'),1):
            with self.subTest(phase=phase):
                bad=Mock();bad.poll.return_value=[]
                good=Mock();good.poll.return_value=[]
                factory=Mock(return_value=bad)
                if phase=='factory': factory.side_effect=RuntimeError('factory broke')
                elif phase=='poll': bad.poll.side_effect=RuntimeError('poll broke')
                else:
                    # A lazy resource stream can raise inside process.
                    def broken():
                        raise RuntimeError('process broke')
                        yield
                    bad.poll.return_value=broken()
                factories={S:factory,'fixture_b':lambda:good}
                with self.store.transaction():
                    self.store.queue('|baseline:'+phase,'normal',['baseline'],{'record_id':'baseline:'+phase},clock().isoformat())
                delivered_before=len(notifier.delivered)
                dispatch=engine.dispatch_adapters
                with patch.object(engine,'dispatch_adapters',side_effect=lambda:dispatch(registry=registry,factories=factories)):
                    engine.run_cycle([],release_checks=False)
                self.assertEqual(len(notifier.delivered),delivered_before+1+(attempt==1))
                self.assertIsNotNone(self.db.execute('SELECT sent_at FROM outbox WHERE pair_key=?',('|baseline:'+phase,)).fetchone()[0])
                good.poll.assert_called_once()
                self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0],'unhealthy')
                retry=self.db.execute("SELECT attempts,last_error FROM adapter_retries WHERE source=? AND resource='@dispatch'",(S,)).fetchone()
                self.assertIsNotNone(retry)
                self.assertEqual(retry['attempts'],attempt)
                self.assertIn(phase+' broke',retry['last_error'])
                self.assertEqual(self.rows('retry_queue'),[])

    def test_dispatch_gate(self):
        for gate,on,calls in [('met',True,1),('met',False,0),('not met',True,0)]:
            adapter=Mock();adapter.poll.return_value=[]
            factory=Mock(return_value=adapter)
            entry=adapters.Adapter(S,'F',gate)
            self.assertEqual(entry.effective(on),bool(calls))
            from types import SimpleNamespace
            from cornicen.engine import Engine
            engine=object.__new__(Engine)
            engine.store=self.store
            engine.config=SimpleNamespace(db_path=self.path,adapters={S:on})
            engine.clock=lambda:datetime.fromisoformat(T)
            engine.dispatch_adapters(registry={S:entry},factories={S:factory})
            self.assertEqual(factory.call_count,calls)
            self.assertEqual(adapter.poll.call_count,calls)
            if not calls:
                adapter.retry.assert_not_called();adapter.audit.assert_not_called()

    def test_integrity_precedes_publication(self):
        path=self.p.stage_members(S,'listing.json',iter([m(10)]),T)
        with path.open('a') as output: output.write(json.dumps(m(11))+'\n')
        self.assertEqual(self.p.commit_staged(S,'listing.json',T),'FAILED')
        self.assertEqual(self.rows('advisories'),[])
        self.assertIsNone(self.db.execute('SELECT baseline_members FROM adapter_state').fetchone()[0])

    def test_cursor_streams_union_across_resources(self):
        from cornicen.adapterstore import digest
        resources=[dict(path='a.json',status=200,body=json.dumps([m(10),m(11)])),
                   dict(path='b.json',status=200,body=json.dumps([m(11),m(12)]))]
        self.assertEqual(self.p.process(S,resources,T),'COMPLETE')
        expected=digest([dict(source_id=m(n)['id'],digest=digest(m(n))) for n in (10,11,12)])
        self.assertEqual(self.db.execute('SELECT cursor_digest FROM adapter_state').fetchone()[0],expected)
        self.assertEqual(len(self.rows('manifest_members')),4)

    def test_legacy_memberships_migrate_to_rows(self):
        self.commit([m(10),m(11)])
        before=self.rows('manifests'),self.rows('adapter_state')
        entries=[dict(r) for r in self.db.execute('SELECT source_id,digest FROM manifest_members ORDER BY source_id')]
        self.db.execute('DELETE FROM manifest_members')
        self.db.execute('DELETE FROM baseline_members')
        self.db.execute('UPDATE manifests SET members=?',(json.dumps(entries),))
        self.db.execute('UPDATE adapter_state SET baseline_members=?',(json.dumps([m(10)['id'],m(11)['id'],'@invalid:old']),))
        self.db.close();self.open()
        self.assertEqual(before,(self.rows('manifests'),self.rows('adapter_state')))
        self.assertEqual(entries,[dict(r) for r in self.db.execute('SELECT source_id,digest FROM manifest_members ORDER BY source_id')])
        self.assertEqual(self.rows('baseline_members'),[(S,m(n)['id']) for n in (10,11)])
        self.store.migrate()
        self.assertEqual(len(self.rows('manifest_members')),2)

    def test_multi_resource_cursor_is_atomic(self):
        self.commit([m(10)])
        accepted=lambda: [tuple(r) for r in self.db.execute("SELECT source,resource,digest,members,fetched_at FROM manifests WHERE digest!='' ORDER BY resource")]
        before=accepted(),tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state').fetchone())
        self.assertEqual(self.p.process(S,[dict(path='listing.json',status=200,body=json.dumps([m(10,title='new')])),dict(path='other.json',status=500,body='')],T2),'FAILED')
        self.assertEqual(before,(accepted(),tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state').fetchone())))
        self.assertEqual(self.db.execute('SELECT revision FROM advisories').fetchone()[0],'2')

    def test_engine_commits_one_shot_stream(self):
        from cornicen.engine import Engine
        engine=object.__new__(Engine);engine.store=self.store
        result=v.validate_members(iter([m(10),m(11)]),source=S,observed_at=T)
        engine.validate_adapter_result(result,source=S,tick=T,data_dir=self.tmp.name)
        self.assertEqual(len(self.rows('advisories')),2)
        self.assertEqual(list(result.records),[])
        before=self.rows('advisories')
        with self.assertRaises(TypeError):
            engine.validate_adapter_result(v.AdapterResult(iter([v.validate_advisory(m(12),source=S,observed_at=T),m(13)])),source=S,tick=T,data_dir=self.tmp.name)
        self.assertEqual(before,self.rows('advisories'))

    def test_headers_drive_retry_dispatch(self):
        self.p.process(S,[dict(path='r',status=429,body='',headers={'Retry-After':'900'})],T)
        self.assertEqual(self.db.execute('SELECT next_attempt_at FROM adapter_retries').fetchone()[0],'2099-01-01T00:15:00Z')
        adapter=Mock();adapter.poll.return_value=[];adapter.retry.return_value=[dict(path='r',status=500,body='')]
        self.p.dispatch({S:adapters.Adapter(S,'F','met')},{S:True},{S:lambda:adapter},'2099-01-01T00:14:59Z')
        adapter.retry.assert_not_called()
        self.p.dispatch({S:adapters.Adapter(S,'F','met')},{S:True},{S:lambda:adapter},'2099-01-01T00:15:00Z')
        adapter.retry.assert_called_once_with('r')
        self.assertEqual(self.db.execute('SELECT attempts FROM adapter_retries').fetchone()[0],2)

    def test_cli_rebaseline(self):
        from contextlib import redirect_stdout
        import io
        from cornicen.cli import main
        # A production registry name can be rebaselined without constructing a
        # production adapter. All inputs remain invented and entirely offline.
        source='synology'
        self.p.stage_members(source,'listing.json',iter([m(10)]),T)
        self.p.commit_staged(source,'listing.json',T)
        self.p.gap(source,T2,'retention gap')
        config=Path(self.tmp.name)/'config.toml'
        config.write_text('db_path = '+json.dumps(str(self.path))+'\nwatchlist_path = '+json.dumps(str(Path(self.tmp.name)/'watch.toml'))+'\n')
        with redirect_stdout(io.StringIO()):
            result=main(['--config',str(config),'adapter','rebaseline',source])
        self.assertEqual(result,0)
        self.assertIsNotNone(self.db.execute('SELECT acknowledged_at FROM gap_ledger').fetchone()[0])

    def test_rebaseline_reconciles_missing_inventory(self):
        self.commit([m(10),m(11)])
        self.assertEqual(self.commit([m(10)],T2),'PARTIAL')
        self.p.gap(S,T2,'retention gap')
        self.p.rebaseline(S,T2)
        self.assertEqual(self.db.execute('SELECT source_id FROM manifest_members').fetchone()[0],m(10)['id'])
        self.assertEqual(len(self.rows('manifest_members')),1)
        self.assertEqual(len(self.rows('advisories')),2)
        self.assertIsNotNone(self.db.execute('SELECT acknowledged_at FROM gap_ledger').fetchone()[0])

    def test_failed_rebaseline_keeps_gap_unacknowledged(self):
        self.commit([m(10)])
        self.p.gap(S,T2,'retention gap')
        self.commit([m(10,url='bad')],T2)
        with self.assertRaises(ValueError): self.p.rebaseline(S,T2)
        self.assertIsNone(self.db.execute('SELECT acknowledged_at FROM gap_ledger').fetchone()[0])
        self.assertEqual(self.db.execute('SELECT cursor_tick FROM adapter_state').fetchone()[0],T)

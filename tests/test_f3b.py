# script-purpose: Verify permanent facets and acknowledged identity coverage offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f3b.py
"""Read invented records; write temporary SQLite databases. Exit 0/1 via unittest."""
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from cornicen import advisory as api
from cornicen.adapterstore import AdapterStore
from cornicen.model import IngestResult, FetchStatus, Origin
from tests import test_f3a as helpers
from tests.test_f3a import advisory, T, P

A = 'CVE-2099-0001'


class F3bTests(unittest.TestCase):
    setUp = helpers.F3aTests.setUp
    put = helpers.F3aTests.put
    pair = helpers.F3aTests.pair
    ack = helpers.F3aTests.ack

    def process(self, raw):
        self.p.ensure('fixture_a', T)
        self.db.execute("UPDATE adapter_state SET baseline_members='[]',baseline_complete=1")
        p = AdapterStore(self.store, self.tmp.name, on_record=self.engine.commit_advisory)
        return p.process('fixture_a', [dict(path='a.json', status=200, body=json.dumps([raw]))], T)

    def facets(self):
        row = self.db.execute('SELECT json FROM advisories').fetchone()
        return json.loads(row[0])['facets']

    def test_facet_numbers_permanent(self):
        for key in ('cve', 'ids', 'fallback'):
            with self.subTest(key=key):
                self.db.execute('DELETE FROM advisories')
                facets = [dict(title='Widget issue', products=[dict(name='examplecorp:widget', version='1.0.0')]),
                          dict(title='Gadget issue', products=[dict(name='examplecorp:gadget', version='1.0.0')])]
                if key == 'cve':
                    for n, f in enumerate(facets): f['cve'] = f'CVE-2099-00{n+10:02}'
                if key == 'ids':
                    for n, f in enumerate(facets): f['ids'] = [dict(system_name='fixture', text=f'FIX-2099-00{n+10:02}')]
                raw = advisory(cves=tuple(f['cve'] for f in facets) if key == 'cve' else ()) | dict(facets=facets)
                raw['products'].append(dict(id='q', name='examplecorp:gadget'))
                self.assertEqual(self.process(raw), 'COMPLETE')
                before = {f['title']: f['number'] for f in self.facets()}
                raw['facets'].reverse()
                for f in raw['facets']: f['products'][0]['version'] = '2.0.0'
                self.assertEqual(self.process(raw), 'COMPLETE')
                self.assertEqual({f['title']: f['number'] for f in self.facets()}, before)

    def test_facet_ambiguity_quarantines(self):
        base = dict(title='Widget', products=[dict(name='examplecorp:widget')], ids=[dict(system_name='fixture', text='FIX-2099-0010')])
        for changed in ([base, base], [dict(base, ids=[])], [dict(base, title='Gadget', products=[dict(name='examplecorp:gadget')]), dict(title='Widget', products=base['products'])]):
            with self.subTest(changed=changed):
                self.assertEqual(self.process(advisory(cves=()) | dict(facets=[base])), 'COMPLETE')
                evidence = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
                cursor = tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state WHERE source="fixture_a"').fetchone())
                self.assertEqual(self.process(advisory(cves=()) | dict(facets=changed)), 'PARTIAL')
                self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], evidence)
                self.assertEqual(tuple(self.db.execute('SELECT cursor_tick,cursor_digest FROM adapter_state WHERE source="fixture_a"').fetchone()), cursor)

    def test_related_and_references_are_not_links(self):
        self.put(advisory(cves=(A, 'CVE-2099-0002')) | dict(related=[A], references=[dict(url='https://examplecorp.invalid/'+A)]))
        self.assertFalse(self.db.execute('SELECT 1 FROM identity_redirects').fetchone())
        self.assertEqual(self.db.execute('SELECT count(*) FROM pairs').fetchone()[0], 3)

    def seed_link(self, closed=False):
        self.put(advisory(cves=()))
        self.db.execute('UPDATE pairs SET episode=2,notified=1')
        self.db.execute('UPDATE outbox SET sent_at=?,body_json=json_set(body_json,\'$.episode\',?)', (T, 1 if closed else 2))
        self.put(advisory(cves=(A,)), source='fixture_b')
        self.db.execute('UPDATE pairs SET episode=4,notified=0 WHERE record_id=?', (A,))
        self.db.execute("UPDATE outbox SET body_json=json_set(body_json,'$.episode',4),reasons_json=?,urgency='urgent',attempts=3,next_attempt_at=? WHERE sent_at IS NULL", (json.dumps(['new match','KEV added']), T))

    def test_link_merges(self):
        self.seed_link()
        keys = [tuple(r) for r in self.db.execute('SELECT * FROM events')]
        self.put(advisory(cves=(A,)))
        self.assertEqual(self.pair(A)['episode'], 4)
        self.assertEqual(self.pair(A)['notified'], 1)
        self.assertTrue(api.logical_latch(self.db, self.pair(A), implicit=False))
        rows = self.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['reasons_json']), ['KEV added'])
        self.assertEqual(rows[0]['pair_key'], 'w|'+A)
        self.assertEqual(rows[0]['attempts'], 3)
        self.assertIn(P, json.loads(rows[0]['body_json'])['also_known_as'])
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM events')], keys)
        for table in ('pairs','events','outbox','affected_latches','identity_redirects','delivery_coverage','advisories','advisory_evidence','advisory_support'):
            self.db.execute('DELETE FROM '+table)
        self.seed_link(closed=True)
        self.put(advisory(cves=(A,)))
        row = self.db.execute('SELECT reasons_json FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertIn('new match', json.loads(row[0]))

    def test_redirect_coverage_permanent(self):
        self.seed_link()
        self.put(advisory(cves=(A,)))
        self.store.connection.commit()
        self.store.connection.close()
        from cornicen.store import Store
        reopened = Store(self.store.path) if hasattr(self.store, 'path') else Store(self.engine.config.db_path)
        self.addCleanup(reopened.connection.close)
        self.assertTrue(api.covered(reopened.connection, 'w', A, 'new match', 4))
        from cornicen.engine import Engine
        self.engine = Engine(reopened, self.engine.watches, self.engine.aliases, self.engine.config, self.clock, self.engine.notifier)
        self.store = reopened
        self.db = reopened.connection
        before = self.db.execute('SELECT count(*) FROM events').fetchone()[0]
        self.engine._event('w', P, 'new match', 4, dict(record_id=P))
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0], before)
        self.put(advisory('known_not_affected', cves=(A,)), source='fixture_b')
        self.put(advisory('known_not_affected', cves=(A,)))
        self.assertEqual(self.pair(A)['episode'], 5)
        self.put(advisory(cves=(A,)))
        self.assertTrue(self.db.execute('SELECT 1 FROM events WHERE key=?', ('w|'+A+'|new match|5',)).fetchone())

    def test_redirect_chain_and_cycle(self):
        b = 'advisory:fixture_b:FIX-2099-0001:main'
        self.db.execute('INSERT INTO identity_redirects VALUES (?,?,?)', (P,b,T))
        api.link(self.engine, b, A, T)
        self.assertEqual(dict(self.db.execute('SELECT old_id,new_id FROM identity_redirects')), {P:A,b:A})
        cycle_target = 'CVE-2099-0002'
        self.db.execute('INSERT INTO identity_redirects VALUES (?,?,?)', (cycle_target,A,T))
        with self.assertRaisesRegex(ValueError, 'identity link cycle'):
            api.link(self.engine, A, cycle_target, T)
        self.db.execute('DELETE FROM identity_redirects WHERE old_id=?', (cycle_target,))
        self.assertEqual(dict(self.db.execute('SELECT old_id,new_id FROM identity_redirects')), {P:A,b:A})

    def test_kev_reason_survives_link(self):
        self.put(advisory(cves=())); self.ack()
        self.put(advisory(cves=(A,)))
        self.store.set_meta('kev_initialized', '1')
        self.store.set_meta('baseline_complete', '1')
        self.engine._health_verdicts = {}
        self.engine._ingest(IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG, 'K1', None, kev={A:dict(cveID=A)}))
        self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='KEV added'")], ['w|'+A+'|KEV added|1'])

    def test_split_inheritance(self):
        a,b = 'CVE-2099-0002','CVE-2099-0003'
        raw = advisory(cves=(a,b)) | dict(id='FIX-2099-0002')
        raw['products'].append(dict(id='q',name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0],product_id='q'))
        self.put(raw); self.ack()
        raw['associations'] = [dict(cve=a,product_id='p'),dict(cve=b,product_id='q')]
        self.put(raw)
        self.assertEqual([r[0] for r in self.db.execute('SELECT child_id FROM coverage_inheritance')], [a])
        self.assertFalse(self.db.execute('SELECT 1 FROM identity_redirects').fetchone())
        self.assertEqual(self.pair('advisory:fixture_a:FIX-2099-0002:main')['state'], 'affected')
        self.assertFalse(self.db.execute('SELECT 1 FROM events WHERE record_id IN (?,?)', (a,b)).fetchone())

    def test_cycle_order(self):
        calls=[]
        ingests=[IngestResult(s,FetchStatus.COMPLETE,Origin.CATALOG,None,None) for s in ('epss','kev','cvelist')]
        with patch.object(self.engine,'_ingest',side_effect=lambda i:calls.append(i.source)), patch.object(self.engine,'dispatch_adapters',side_effect=lambda:calls.extend(['fixture_a','fixture_b'])), patch.object(self.engine,'_flush',side_effect=lambda:calls.append('release')):
            self.engine.run_cycle(ingests,release_checks=False)
        self.assertEqual(calls,['cvelist','fixture_a','fixture_b','kev','epss','release'])

    def test_recordless_retries_recover(self):
        self.put(advisory(cves=()))
        with patch.object(self.engine,'_evaluate_advisory',side_effect=RuntimeError('transient')):
            self.engine.reload_watches((replace(self.watch,version='1.1.0'),))
        self.assertEqual(self.db.execute('SELECT record_id FROM retry_queue').fetchone()[0], P)
        self.engine._attempted_records=set(); self.engine._health_verdicts={}
        self.engine._retry_records()
        self.assertFalse(self.db.execute('SELECT 1 FROM retry_queue').fetchone())
        self.assertEqual(self.engine._health_verdicts['watchlist'][0], 'healthy')
        self.assertFalse(self.db.execute("SELECT 1 FROM health WHERE source='records' AND state='unhealthy'").fetchone())
        self.put(advisory('under_investigation', cves=(A,)), source='fixture_b')
        self.engine._health_verdicts={}
        self.store.set_meta('kev_initialized', '1')
        self.store.set_meta('baseline_complete', '1')
        with patch.object(self.engine,'_evaluate_advisory',side_effect=RuntimeError('transient')):
            self.engine._ingest(IngestResult('kev',FetchStatus.COMPLETE,Origin.CATALOG,'K1',None,kev={A:dict(cveID=A)}))
        self.assertEqual(self.db.execute('SELECT record_id FROM retry_queue').fetchone()[0], A)
        self.assertFalse(self.db.execute('SELECT 1 FROM events WHERE record_id=?', (A,)).fetchone())
        self.engine._attempted_records=set()
        self.engine._retry_records()
        self.assertFalse(self.db.execute('SELECT 1 FROM retry_queue').fetchone())
        self.assertEqual(self.engine._health_verdicts['kev'][0], 'healthy')
        self.assertTrue(self.db.execute('SELECT 1 FROM events WHERE key=?', ('w|'+A+'|KEV added|1',)).fetchone())
        self.assertTrue(self.db.execute('SELECT 1 FROM events WHERE key=?', ('w|'+A+'|new match|1',)).fetchone())
        self.assertFalse(self.db.execute("SELECT 1 FROM health WHERE source='records' AND state='unhealthy'").fetchone())

    def test_evaluate_callers_have_isolation_boundaries(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path('src/cornicen/engine.py').read_text())
        engine_class = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Engine')
        methods = {n.name:n for n in engine_class.body if isinstance(n,ast.FunctionDef)}
        def calls(node, name):
            return [n for n in ast.walk(node) if isinstance(n,ast.Call)
                    and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name)
                    and n.func.value.id=='self' and n.func.attr==name]
        callers = {name for name,node in methods.items() if calls(node,'_evaluate')}
        self.assertEqual(callers, {'commit_advisory','_apply_record','_evaluate_kev','_rematch_record','_ingest'})
        commit_call = calls(methods['commit_advisory'],'_evaluate')[0]
        self.assertTrue(any(k.arg=='advisory_only' and isinstance(k.value,ast.Constant) and k.value.value is True for k in commit_call.keywords))
        for name in ('_apply_record','_evaluate_kev','_rematch_record','_evaluate'):
            for owner,node in methods.items():
                if name=='_evaluate' and owner!='_ingest': continue
                if owner=='_retry_records': continue  # The local apply dispatcher is enclosed below.
                for call in calls(node,name):
                    if name=='_evaluate' or owner not in callers:
                        self.assertTrue(any(call in list(ast.walk(boundary)) for boundary in calls(node,'_isolated')), (owner,name))
        self.assertTrue(calls(methods['_retry_records'],'_isolated'))

    def test_split_requires_acknowledged_scope_coverage(self):
        a,b='CVE-2099-0002','CVE-2099-0003'
        raw=advisory(cves=(a,b)) | dict(id='FIX-2099-0002')
        self.put(raw)
        self.db.execute('UPDATE pairs SET notified=1')
        raw['associations']=[dict(cve=a,product_id='p')]
        self.put(raw)
        self.assertFalse(self.db.execute('SELECT 1 FROM coverage_inheritance').fetchone())

    def test_link_pending_policy_and_correction_separation(self):
        self.seed_link(closed=True)
        old_body=dict(watch_id='w',record_id=P,episode=2,state='affected')
        self.db.execute("UPDATE outbox SET urgency='normal' WHERE sent_at IS NULL")
        self.store.queue('w|'+P,'urgent',['acceptance lapsed'],old_body,'2099-01-01T00:00:00Z',T)
        self.db.execute('UPDATE outbox SET attempts=5,next_attempt_at=? WHERE pair_key=? AND sent_at IS NULL',('2099-12-01T00:00:00Z','w|'+P))
        self.store.queue('w|'+P+'|correction','normal',['correction'],old_body,T,T)
        self.store.queue('w|'+A+'|correction','urgent',['correction'],dict(old_body,record_id=A),T,T)
        self.put(advisory(cves=(A,)))
        rows=self.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL ORDER BY pair_key').fetchall()
        self.assertEqual(len(rows),2)
        self.assertEqual(json.loads(rows[0]['reasons_json']),['KEV added','acceptance lapsed','new match'])
        self.assertEqual(rows[0]['urgency'],'urgent')
        self.assertEqual(rows[0]['due_at'],'2099-01-01T00:00:00Z')
        self.assertEqual(rows[0]['attempts'],5)
        self.assertEqual(rows[0]['next_attempt_at'],'2099-12-01T00:00:00Z')
        self.assertEqual(json.loads(rows[1]['reasons_json']),['correction'])
        self.assertEqual(rows[1]['pair_key'], 'w|'+A+'|correction')
        self.assertEqual(json.loads(rows[1]['body_json'])['record_id'], A)
        self.assertIn(P, json.loads(rows[1]['body_json'])['also_known_as'])

    def test_facets_have_distinct_permanent_evidence_identities(self):
        raw=advisory(cves=())
        raw['products'].append(dict(id='q',name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0],product_id='q'))
        raw['facets']=[dict(title='Widget',products=['examplecorp:widget']),dict(title='Gadget',products=['examplecorp:gadget'])]
        self.assertEqual(self.process(raw),'COMPLETE')
        before=[tuple(r) for r in self.db.execute('SELECT facet,identity,package FROM advisory_evidence ORDER BY facet')]
        self.assertEqual(before,[('1',P.removesuffix('main')+'1','examplecorp:widget'),('2',P.removesuffix('main')+'2','examplecorp:gadget')])
        raw['facets'].reverse()
        self.assertEqual(self.process(raw),'COMPLETE')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT facet,identity,package FROM advisory_evidence ORDER BY facet')],before)

    def test_cycle_commits_links_before_release(self):
        from tests.replay_v11.harness import fixture_registry
        self.assertLess(fixture_registry()['fixture_a'].position,fixture_registry()['fixture_b'].position)
        def dispatch():
            self.put(advisory(cves=(A,)),source='fixture_a')
            self.put(advisory(cves=(A,)),source='fixture_b')
        def release():
            self.assertEqual(dict(self.db.execute('SELECT old_id,new_id FROM identity_redirects')),
                             {P:A,'advisory:fixture_b:FIX-2099-0001:main':A})
            self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='new match'")],['w|'+A+'|new match|1'])
        with patch.object(self.engine,'dispatch_adapters',side_effect=dispatch), patch.object(self.engine,'_flush',side_effect=release):
            self.engine.run_cycle([],release_checks=False)

    def test_cycle_is_quarantined_atomically(self):
        cycle_target = 'CVE-2099-0002'
        self.db.execute('INSERT INTO identity_redirects VALUES (?,?,?)', (cycle_target,A,T))
        before=dict(self.db.execute('SELECT old_id,new_id FROM identity_redirects'))
        def callback(data,baseline):
            api.link(self.engine,A,cycle_target,T)
        p=AdapterStore(self.store,self.tmp.name,on_record=callback)
        self.assertEqual(p.process('fixture_a',[dict(path='a.json',status=200,body=json.dumps([advisory(cves=())]))],T),'PARTIAL')
        self.assertEqual(dict(self.db.execute('SELECT old_id,new_id FROM identity_redirects')),before)
        self.assertFalse(self.db.execute('SELECT 1 FROM advisories').fetchone())
        self.assertEqual(self.db.execute('SELECT source_id FROM quarantine').fetchone()[0],'FIX-2099-0001')

    def assert_withdrawal_retracts(self, retained):
        self.assertEqual(self.process(advisory(cves=(A,))), 'COMPLETE')
        episode = self.pair(A)['episode']
        self.ack()
        self.assertEqual(self.process(advisory(cves=retained) | dict(withdrawn=T)), 'COMPLETE')
        self.assertEqual(self.pair(A)['state'], 'not_affected')
        self.assertEqual(self.pair(A)['episode'], episode + 1)
        self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='correction'")],
                         ['w|' + A + '|correction|' + str(episode)])
        self.assertTrue(self.db.execute("SELECT 1 FROM outbox WHERE pair_key=? AND sent_at IS NULL", ('w|' + A + '|correction',)).fetchone())
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_evidence').fetchone())

    def test_withdrawal_without_cves_retracts(self):
        self.assert_withdrawal_retracts(())

    def test_withdrawal_with_cve_retracts(self):
        self.assert_withdrawal_retracts((A,))

    def assert_facet_withdrawal_retracts(self, facet, cves, identity):
        raw = advisory(cves=cves) | dict(facets=[dict(facet, products=['examplecorp:widget'])])
        self.assertEqual(self.process(raw), 'COMPLETE')
        self.assertEqual(self.pair(identity)['state'], 'affected')
        self.assertEqual(self.pair(identity)['episode'], 1)
        self.ack()
        redirects = [tuple(r) for r in self.db.execute('SELECT * FROM identity_redirects')]
        self.assertEqual(self.process(advisory(cves=()) | dict(withdrawn=T)), 'COMPLETE')
        self.assertEqual(self.pair(identity)['state'], 'not_affected')
        self.assertEqual(self.pair(identity)['episode'], 2)
        self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='correction'")],
                         ['w|' + identity + '|correction|1'])
        self.assertTrue(self.db.execute('SELECT 1 FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                                       ('w|' + identity + '|correction',)).fetchone())
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_evidence').fetchone())
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM identity_redirects')], redirects)
        if cves:
            self.assertEqual([(r[0], r[1]) for r in redirects], [(P.removesuffix('main') + '1', A)])

    def test_withdrawal_without_facets_retracts_facet_cve(self):
        self.assert_facet_withdrawal_retracts(dict(cve=A), (A,), A)

    def test_withdrawal_without_facets_retracts_facet_ids(self):
        self.assert_facet_withdrawal_retracts(
            dict(ids=[dict(system_name='fixture', text='FIX-2099-0010')]),
            (), P.removesuffix('main') + '1')

    def test_active_revision_without_facets_quarantines(self):
        facet = dict(ids=[dict(system_name='fixture', text='FIX-2099-0010')],
                     products=['examplecorp:widget'])
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[facet])), 'COMPLETE')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.assertEqual(self.process(advisory(cves=())), 'PARTIAL')
        self.assertEqual(self.pair(P.removesuffix('main') + '1')['state'], 'affected')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)
        self.assertIn('facet identifier removed', self.db.execute('SELECT reason FROM quarantine').fetchone()[0])

    def test_active_revision_without_cves_quarantines(self):
        self.assertEqual(self.process(advisory(cves=(A,))), 'COMPLETE')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.assertEqual(self.process(advisory(cves=())), 'PARTIAL')
        self.assertEqual(self.pair(A)['state'], 'affected')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)
        self.assertIn('identifier removed or reassigned', self.db.execute('SELECT reason FROM quarantine').fetchone()[0])

    def test_split_parent_withdraws_on_its_own_record(self):
        self.test_split_inheritance()
        row=self.db.execute("SELECT json FROM advisories WHERE source_id='FIX-2099-0002'").fetchone()
        data=json.loads(row[0]); data['withdrawn']=T
        self.engine.commit_advisory(data)
        self.assertEqual(self.pair('advisory:fixture_a:FIX-2099-0002:main')['state'],'not_affected')
        self.assertEqual(self.pair('advisory:fixture_a:FIX-2099-0002:main')['episode'],2)

    def rejected_facet(self, facet, error):
        raw = advisory(cves=(A,)) | dict(facets=[facet])
        before = [tuple(r) for r in self.db.execute('SELECT * FROM identity_redirects')]
        self.assertEqual(self.process(raw), 'PARTIAL')
        self.assertIn(error, self.db.execute('SELECT reason FROM quarantine').fetchone()[0])
        self.assertFalse(self.db.execute("SELECT 1 FROM advisories WHERE source='fixture_a'").fetchone())
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM identity_redirects')], before)

    def test_facet_outside_cve(self):
        self.rejected_facet(dict(cve='CVE-2099-7777'), 'facet CVE')

    def test_facet_malformed_cve(self):
        self.rejected_facet(dict(cve='NOT-A-CVE; DROP'), 'facet CVE')

    def test_facet_string_cves(self):
        self.assertEqual(self.process(advisory(cves=(A,)) | dict(facets=[dict(cves=A, products=['examplecorp:widget'])])), 'COMPLETE')
        self.assertEqual({r[0] for r in self.db.execute('SELECT record_id FROM pairs')}, {A})

    def test_facet_other_source_cve(self):
        self.put(advisory(cves=('CVE-2099-7777',)), source='fixture_b')
        self.rejected_facet(dict(cve='CVE-2099-7777'), 'facet CVE')

    def test_facet_unknown_scheme(self):
        self.rejected_facet(dict(cve=A, products=['examplecorp:widget'], evidence=[dict(advisory()['evidence'][0], scheme='nope')]), 'unknown version scheme')

    def test_facet_outside_association(self):
        self.rejected_facet(dict(cve=A, associations=[dict(cve='CVE-2099-7777',product_id='p')]), 'association')

    def test_facet_boundary_shapes(self):
        from cornicen.feedvalidate import validate_advisory
        bad = [dict(title=3), dict(ids=['x']), dict(ids=[dict(text=3)]),
               dict(products=['examplecorp:missing']), dict(cves=[3]),
               dict(evidence=[dict(advisory()['evidence'][0], status='bad')]),
               dict(evidence=[dict(advisory()['evidence'][0], range=dict(limit=3))]),
               dict(evidence=[dict(advisory()['evidence'][0], product_id='missing')])]
        bad += [dict(evidence=[dict(advisory()['evidence'][0], **{k:3})]) for k in ('release','platform','fix','first_fixed')]
        for facets in (None, {}, [3], *([f] for f in bad)):
            with self.subTest(facets=facets), self.assertRaisesRegex(ValueError, 'facet'):
                validate_advisory(advisory(cves=(A,)) | dict(facets=facets), source='fixture_a', observed_at=T)

    def test_identifier_reassignment_quarantines(self):
        self.assertEqual(self.process(advisory(cves=('CVE-2099-0002',))), 'COMPLETE')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.assertEqual(self.process(advisory(cves=(A,))), 'PARTIAL')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)

    def test_split_trim_quarantines(self):
        self.assertEqual(self.process(advisory(cves=(A,'CVE-2099-0002'))), 'COMPLETE')
        self.assertEqual(self.process(advisory(cves=(A,))), 'PARTIAL')
        self.assertFalse(self.db.execute('SELECT 1 FROM identity_redirects WHERE old_id=?',(P,)).fetchone())

    def test_split_parent_cannot_link(self):
        self.put(advisory(cves=(A,'CVE-2099-0002')))
        with self.assertRaisesRegex(ValueError, 'split parent'):
            api.link(self.engine, P, A, T)

    def test_v1_exploited_unknown_latch(self):
        pair = dict(watch_id='w',record_id=A,episode=1,state='unknown',exploited=1,notified=0)
        self.assertTrue(api.logical_latch(self.db, pair))
        self.assertFalse(self.db.execute('SELECT 1 FROM affected_latches').fetchone())

    def test_link_enqueued_at_preserved(self):
        self.seed_link(closed=True)
        early='2099-01-01T00:00:00Z'
        self.db.execute('UPDATE outbox SET enqueued_at=? WHERE sent_at IS NULL', (early,))
        self.store.queue('w|'+P, 'normal', ['acceptance lapsed'], dict(watch_id='w',record_id=P,episode=2), T, '2099-02-01T00:00:00Z')
        api.link(self.engine, P, A, '2099-12-01T00:00:00Z')
        self.assertEqual(self.db.execute('SELECT enqueued_at FROM outbox WHERE sent_at IS NULL').fetchone()[0],early)

    def test_link_target_must_be_cve(self):
        from cornicen.advisoryidentity import _link
        for fn in (api.link, _link):
            for target in ('NOT-A-CVE; DROP', 'advisory:fixture_b:FIX-2099-0001:main'):
                with self.subTest(fn=fn.__name__,target=target), self.assertRaisesRegex(ValueError, 'CVE'):
                    fn(self.engine,P,target,T)

    def test_distinct_cves_never_merge(self):
        with self.assertRaisesRegex(ValueError, 'distinct CVEs'):
            api.link(self.engine, A, 'CVE-2099-0002', T)
        self.assertFalse(self.db.execute('SELECT 1 FROM identity_redirects').fetchone())

    def test_link_latch_only_from_merged_row(self):
        self.seed_link(closed=True)
        self.db.execute("UPDATE pairs SET state='unknown',notified=0,exploited=0")
        self.db.execute('DELETE FROM affected_latches')
        self.db.execute('INSERT INTO affected_latches VALUES (?,?,?,1)', ('w',P,2))
        api.link(self.engine, P, A, T)
        self.assertTrue(api.logical_latch(self.db, self.pair(A)))
        self.assertTrue(api.logical_latch(self.db, self.pair(A), implicit=False))

    def test_split_gadget_inherits_no_widget_scope(self):
        a,b = 'CVE-2099-0002','CVE-2099-0003'
        gadget = replace(self.watch, id='g', match=(('examplecorp','gadget'),))
        self.engine.watches = (self.watch, gadget)
        self.engine._cache_watch_identities()
        raw = advisory(cves=(a,b)) | dict(id='FIX-2099-0002')
        raw['products'].append(dict(id='q',name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0],product_id='q'))
        self.put(raw); self.ack()
        independent = advisory(cves=(a,))
        independent['products'][0]['name'] = 'examplecorp:gadget'
        self.put(independent, source='fixture_b')
        raw['associations'] = [dict(cve=a,product_id='p')]
        self.put(raw)
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT child_id,watch_id FROM coverage_inheritance')], [(a,'w')])

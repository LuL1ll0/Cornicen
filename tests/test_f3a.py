# script-purpose: Verify scoped evidence and advisory delivery without network.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f3a.py
"""Read invented advisories; write temporary SQLite. Exit 0 on success, 1 on failure."""
from contextlib import redirect_stdout
from dataclasses import replace
from itertools import combinations, permutations
import io
import json
from pathlib import Path
import tempfile
import unittest

from cornicen.adapterstore import AdapterStore, instant
from cornicen.applicability import State
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.feedvalidate import validate_advisory
from cornicen.identity import AliasMap
from cornicen.store import Store
from cornicen.watchlist import Watch
from cornicen.versions import Scheme
from tests.test_f1 import member, T
from tests.replay.harness import RecordingNotifier, FakeClock

A='CVE-2099-0040'
P='advisory:fixture_a:FIX-2099-0001:main'


def advisory(status='known_affected', cves=(A,), **evidence):
    return member() | dict(cves=list(cves), products=[dict(id='p',name='examplecorp:widget')],
        evidence=[dict(product_id='p',scheme='semver',status=status,
                       range=dict(introduced='1.0.0',limit='2.0.0')) | evidence])


class F3aTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'db')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db=self.store.connection
        self.watch=Watch('w','Widget',(('examplecorp','widget'),),(),'1.0.0',Scheme.SEMVER,False)
        self.clock=FakeClock(instant(T))
        config=Config(Path(self.tmp.name)/'db',Path('unused'),None,'https://examplecorp.invalid','test',None)
        self.engine=Engine(self.store,(self.watch,),AliasMap.load(False),config,self.clock,RecordingNotifier(self.clock))
        self.p=AdapterStore(self.store,self.tmp.name)

    def put(self, raw=None, source='fixture_a', baseline=False):
        data=validate_advisory(raw or advisory(),source=source,observed_at=T).data
        self.engine.commit_advisory(data,baseline)
        return data

    def result(self, identity=A, scope=None):
        return self.engine.advisory_result(self.watch,identity,scope=scope)

    def pair(self, identity=A):
        return self.db.execute('SELECT * FROM pairs WHERE record_id=?',(identity,)).fetchone()

    def ack(self):
        self.db.execute('UPDATE pairs SET notified=1')
        self.db.execute("UPDATE outbox SET sent_at=?",(T,))

    def cna(self,status,release=None):
        entry=dict(vendor='examplecorp',product='widget',defaultStatus='unknown',versions=[dict(version='0.0.0', versionType='semver', lessThan='2.0.0', status=status)])
        if release: entry['release']=release
        record=dict(cveMetadata=dict(cveId=A,state='PUBLISHED'),containers=dict(cna=dict(affected=[entry])))
        # Resolve CNA directly through the public aggregate boundary.
        return record

    def store_gadget_cna(self):
        record = self.cna('affected')
        record['containers']['cna']['affected'][0]['product'] = 'gadget'
        self.db.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',
                        (A, json.dumps(record), T))
        return record

    def test_cna_only_watch_after_advisory(self):
        gadget = replace(self.watch, id='g', match=(('examplecorp', 'gadget'),))
        self.engine.watches = (self.watch, gadget)
        self.engine._cache_watch_identities()
        self.put()
        record = self.store_gadget_cna()
        self.engine._evaluate(record, A)
        pair = self.db.execute("SELECT * FROM pairs WHERE watch_id='g'").fetchone()
        self.assertIsNotNone(pair)
        self.assertEqual(pair['state'], 'affected')
        self.assertEqual(sorted(r[0] for r in self.db.execute('SELECT key FROM events')),
                         ['g|' + A + '|new match|1', 'w|' + A + '|new match|1'])

    def test_cna_only_watch_after_quarantined_shell(self):
        data = validate_advisory(advisory(), source='fixture_a', observed_at=T).data
        self.engine.observe_unknown_advisory(data)
        self.engine.watches = (replace(self.watch, id='g', match=(('examplecorp', 'gadget'),)),)
        self.engine._cache_watch_identities()
        record = self.store_gadget_cna()
        self.engine._evaluate(record, A)
        pair = self.db.execute("SELECT * FROM pairs WHERE watch_id='g'").fetchone()
        self.assertIsNotNone(pair)
        self.assertEqual(pair['state'], 'affected')
        self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')],
                         ['g|' + A + '|new match|1'])

    def test_cna_only_watch_matches_v1_with_unrelated_advisory(self):
        self.engine.watches = (replace(self.watch, match=(('examplecorp', 'gadget'),)),)
        self.engine._cache_watch_identities()
        record = self.store_gadget_cna()
        self.engine._evaluate(record, A)
        expected = tuple(self.pair()[k] for k in ('state', 'episode', 'exploited', 'notified'))
        keys = [r[0] for r in self.db.execute('SELECT key FROM events')]
        for table in ('pairs', 'events', 'outbox', 'affected_latches'):
            self.db.execute('DELETE FROM ' + table)
        self.put()
        self.engine._evaluate(record, A)
        self.assertIsNotNone(self.pair())
        self.assertEqual(tuple(self.pair()[k] for k in ('state', 'episode', 'exploited', 'notified')), expected)
        self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')], keys)

    def test_shell_marker_removed_on_acceptance(self):
        data = validate_advisory(advisory(), source='fixture_a', observed_at=T).data
        self.engine.observe_unknown_advisory(data)
        self.put()
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_shells').fetchone())

    def test_shell_marker_removed_when_quarantine_clears(self):
        p = AdapterStore(self.store, self.tmp.name, on_record=self.engine.commit_advisory,
                         on_unknown=self.engine.observe_unknown_advisory)
        self.put()
        data = validate_advisory(advisory(), source='fixture_a', observed_at=T).data
        self.engine.observe_unknown_advisory(data)
        p.quarantine('fixture_a', data['source_id'], 'invalid evidence', T)
        self.assertEqual(p.process('fixture_a', [dict(path='a.json', status=200,
                         body=json.dumps([advisory()]))], T), 'COMPLETE')
        self.assertFalse(self.db.execute('SELECT 1 FROM quarantine').fetchone())
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_shells').fetchone())

    def test_removed_identity_loses_support_marker(self):
        from cornicen.advisory import has_identity
        self.put(advisory(cves=('CVE-2099-0041',)))
        # Seed an obsolete marker: identifier reassignment now quarantines at
        # the commit boundary, so it cannot be used to arrange cleanup state.
        self.db.execute('INSERT OR IGNORE INTO advisory_support VALUES (?,?,?)',
                        ('fixture_a', 'FIX-2099-0001', A))
        self.put(advisory(cves=('CVE-2099-0041',)))
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_support WHERE identity=?', (A,)).fetchone())
        self.assertFalse(has_identity(self.db, A))
        self.put(advisory(cves=('CVE-2099-0041',)) | {'withdrawn': T})
        self.assertFalse(has_identity(self.db, A))

    def test_withdrawn_and_active_scope_mismatch_is_unknown(self):
        self.put()
        self.put(advisory(release='example-13'), source='fixture_b')
        self.ack()
        self.put(advisory() | {'withdrawn': T})
        self.assertEqual(self.result().state, State.UNKNOWN)
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.pair()['episode'], 1)
        self.assertFalse(self.db.execute("SELECT 1 FROM events WHERE type='correction'").fetchone())

    def test_kev_sibling_pair_is_report_only(self):
        sibling = 'CVE-2099-0041'
        self.db.execute('INSERT INTO kev VALUES (?,?)', (sibling, json.dumps({'cveID': sibling})))
        raw = advisory(cves=(A, sibling))
        raw['products'].append(dict(id='q', name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0], product_id='q'))
        raw['associations'] = [dict(cve=A, product_id='p'), dict(cve=sibling, product_id='q')]
        self.put(raw)
        self.engine._evaluate_advisory(sibling, kev_added=True)
        self.assertEqual(self.pair(sibling)['state'], 'unknown')
        self.assertFalse(self.db.execute('SELECT 1 FROM events WHERE record_id=?', (sibling,)).fetchone())
        self.assertFalse(self.db.execute('SELECT 1 FROM outbox WHERE pair_key=?', ('w|' + sibling,)).fetchone())

    def test_first_kev_load_suppresses_advisory_kev_added(self):
        from cornicen.model import IngestResult, FetchStatus, Origin
        self.put()
        self.ack()
        self.engine._health_verdicts = {}
        self.engine._ingest(IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
                            'K1', None, kev={A: {'cveID': A}}))
        self.assertEqual(self.pair()['exploited'], 1)
        self.assertFalse(self.db.execute("SELECT 1 FROM events WHERE type='KEV added'").fetchone())

    def test_backport_scope_not_overridden(self):
        self.put(advisory('known_not_affected',release='example-12'))
        record=self.cna('affected')
        self.assertEqual(self.engine.advisory_result(self.watch,A,record=record,scope={'release':'example-12'}).state,State.NOT_AFFECTED)
        self.engine.scope_equivalences={(None,'example-12')}
        self.assertEqual(self.engine.advisory_result(self.watch,A,record=record,scope={'release':'example-12'}).state,State.AFFECTED)

    def test_same_scope_cna_decides(self):
        for adapter,cna,expected in [('known_not_affected','affected',State.AFFECTED),('known_affected','unaffected',State.NOT_AFFECTED)]:
            self.put(advisory(adapter,release='example-12'))
            self.assertEqual(self.engine.advisory_result(self.watch,A,record=self.cna(cna,'example-12'),scope={'release':'example-12'}).state,expected)

    def test_aggregate_table(self):
        from cornicen.advisory import aggregate
        states=[State.AFFECTED,State.UNKNOWN,State.NOT_AFFECTED]
        for n in range(1,4):
            for subset in combinations(states,n):
                for order in permutations(subset):
                    expected=next(s for s in states if s in subset)
                    self.assertEqual(aggregate(order),expected)

    def test_withdrawal_removes_only_own_evidence(self):
        self.put(); self.put(source='fixture_b'); self.ack()
        self.put(advisory() | {'withdrawn':T})
        self.assertEqual(self.result().state,State.AFFECTED)
        self.assertEqual([r[0] for r in self.db.execute('SELECT DISTINCT source FROM advisory_evidence')],['fixture_b'])
        self.assertFalse(self.db.execute("SELECT 1 FROM events WHERE type='correction'").fetchone())

    def test_all_retracted(self):
        for delivered in (False,True):
            self.db.execute('DELETE FROM pairs'); self.db.execute('DELETE FROM events')
            self.db.execute('DELETE FROM affected_latches'); self.db.execute('DELETE FROM outbox')
            self.put()
            if delivered: self.ack()
            self.put(advisory() | {'withdrawn':T})
            self.assertEqual(self.pair()['episode'],2)
            self.assertEqual(self.result().state,State.NOT_AFFECTED)
            self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='correction'")], ['w|'+A+'|correction|1'] if delivered else [])

    def test_retraction_with_other_active_support(self):
        self.put(); self.put(source='fixture_b'); self.ack()
        self.put(advisory() | {'withdrawn':T})
        self.assertEqual(self.result().state,State.AFFECTED)
        self.assertEqual(self.pair()['episode'],1)
        self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='correction'")],[])

    def test_disappearance_is_not_withdrawal(self):
        self.p.ensure('fixture_a',T)
        self.db.execute("UPDATE adapter_state SET baseline_members='[]',baseline_complete=1")
        raw=advisory()
        self.p.process('fixture_a',[dict(path='a.json',status=200,body=json.dumps([raw]))],T)
        before=list(self.db.execute('SELECT * FROM advisory_evidence'))
        self.assertTrue(before)
        self.assertEqual(self.p.process('fixture_a',[dict(path='a.json',status=200,body='[]')],T),'PARTIAL')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')],[tuple(r) for r in before])

    def test_latch(self):
        for delivered in (False,True):
            for table in ('pairs','events','affected_latches','outbox'):
                self.db.execute('DELETE FROM '+table)
            self.put()
            if delivered: self.ack()
            self.put(advisory('under_investigation'))
            self.assertEqual(self.pair()['episode'],1)
            self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')], ['w|'+A+'|new match|1'])
            self.put(advisory('known_not_affected'))
            self.assertEqual(self.pair()['episode'],2)
            self.put(advisory('known_not_affected'))
            self.assertEqual(self.pair()['episode'],2)
            self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM events WHERE type='correction'")], ['w|'+A+'|correction|1'] if delivered else [])
            self.put()
            self.assertTrue(self.db.execute("SELECT 1 FROM events WHERE key=?",('w|'+A+'|new match|2',)).fetchone())

    def test_partition_single_identity(self):
        self.put(advisory() | {'id':'FIX-2099-0040'})
        self.assertEqual(self.pair()['state'],'affected')
        self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')], ['w|'+A+'|new match|1'])

    def test_partition_multi_cve(self):
        self.put(advisory(cves=(A,'CVE-2099-0041')))
        self.assertEqual(self.result().state,State.UNKNOWN)
        self.assertEqual(self.result('CVE-2099-0041').state,State.UNKNOWN)
        self.assertEqual(self.engine._body(self.watch,P,self.result(P))['label'], 'advisory — which listed CVE affects you is not stated')
        self.assertEqual(self.result(P).state,State.AFFECTED)
        self.assertEqual([r[0] for r in self.db.execute('SELECT record_id FROM events')],[P])
        self.assertTrue(all(r[0] is None for r in self.db.execute('SELECT "range" FROM advisory_evidence WHERE identity=?',(A,))))

    def test_same_advisory_sibling_pair_is_unknown(self):
        sibling = 'CVE-2099-0041'
        gadget = replace(self.watch, id='g', match=(('examplecorp', 'gadget'),))
        self.engine.watches = (self.watch, gadget)
        raw = advisory(cves=(A, sibling), fix='2.0.0')
        raw['products'].append(dict(id='q', name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0], product_id='q'))
        raw['associations'] = [dict(cve=A, product_id='p'),
                               dict(cve=sibling, product_id='q')]
        self.put(raw)
        pairs = {(r['watch_id'], r['record_id']): r for r in
                 self.db.execute('SELECT * FROM pairs')}
        self.assertEqual({key: r['state'] for key, r in pairs.items()},
                         {('w', A): 'affected', ('w', sibling): 'unknown',
                          ('g', A): 'unknown', ('g', sibling): 'affected'})
        for watch, identity in ((self.watch, sibling), (gadget, A)):
            self.assertEqual(pairs[(watch.id, identity)]['notified'], 0)
            self.assertIsNone(self.engine.advisory_fix(watch, identity))
            self.assertIsNone(self.db.execute(
                'SELECT 1 FROM affected_latches WHERE watch_id=? AND record_id=?',
                (watch.id, identity)).fetchone())
        self.assertEqual(sorted(r[0] for r in self.db.execute('SELECT key FROM events')),
                         ['g|' + sibling + '|new match|1', 'w|' + A + '|new match|1'])

    def test_never_copy_parent_ranges(self):
        self.put(advisory(cves=(A,'CVE-2099-0041')))
        self.put(advisory() | {'id':'FIX-2099-0040'})
        other=advisory(cves=('CVE-2099-0041',)) | {'id':'FIX-2099-0041','products':[dict(id='p',name='examplecorp:gadget')]}
        self.put(other)
        self.assertEqual(self.result().state,State.AFFECTED)
        self.assertEqual(self.result('CVE-2099-0041').state,State.UNKNOWN)

    def test_fix_scope(self):
        self.put(advisory(fix='2.0.0',release='example-12'))
        self.assertEqual(self.engine.advisory_fix(self.watch,A,scope={'release':'example-12'}),'2.0.0')
        self.assertIsNone(self.engine.advisory_fix(self.watch,A,scope={'release':'example-13'}))
        self.put(advisory())
        before=[r[0] for r in self.db.execute('SELECT key FROM events')]
        for category,expected in [('vendor_fix','available'),('workaround',None),('date',None),('update',None)]:
            raw=advisory() | {'remediations':[dict(category=category,product_ids=['p'])]}
            self.put(raw)
            self.assertEqual(self.engine.advisory_fix(self.watch,A),expected)
            self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')], before)
            if expected == 'available':
                self.assertEqual(self.engine._body(self.watch,A,self.result())['fix'],
                                 'available; version not stated')

    def test_delivery_paths(self):
        from cornicen.cli import explain
        self.put(advisory(cves=()))
        self.assertFalse(self.db.execute('SELECT 1 FROM records').fetchone())
        body=self.engine._body(self.watch,P,self.result(P))
        self.assertEqual(body['cve_title'],'Widget')
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(explain(self.store,(self.watch,),self.engine.aliases,P,'w'),0)
        self.assertIn('Current decision: applicability=affected;',output.getvalue())
        self.assertIn('Evidence: fixture_a: affected\n',output.getvalue())
        self.put(advisory(),source='fixture_d')
        self.put(advisory('known_not_affected'),source='fixture_b')
        self.put(advisory('under_investigation'),source='fixture_c')
        with redirect_stdout(io.StringIO()) as output:
            explain(self.store,(self.watch,),self.engine.aliases,A,'w')
        self.assertIn('Evidence: fixture_d: affected; fixture_b: not_affected; fixture_c: unknown\n',output.getvalue())
        self.db.execute("DELETE FROM advisory_evidence WHERE source IN ('fixture_b','fixture_c','fixture_d')")
        self.engine.reload_watches((replace(self.watch,version='3.0.0'),))
        self.assertEqual(self.pair(P)['state'],'not_affected')
        self.engine.reload_watches((self.watch,))
        row=self.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL AND pair_key=?',('w|'+P,)).fetchone()
        from cornicen.advisory import write_evidence
        write_evidence(self.db,validate_advisory(advisory('under_investigation',cves=()),source='fixture_a',observed_at=T).data)
        self.assertIsNone(self.engine._revalidate(row))

    def test_incremental_cna_after_adapter_baseline(self):
        self.put(baseline=True)
        self.assertFalse(self.db.execute('SELECT 1 FROM events').fetchone())
        self.engine._evaluate(self.cna('affected'), A)
        self.assertTrue(self.db.execute("SELECT 1 FROM events WHERE type='new match'").fetchone())

    def test_unknown_before_delivery_can_resume_same_episode(self):
        self.put()
        self.put(advisory('under_investigation'))
        pending = self.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertIsNone(self.engine._revalidate(pending))
        self.put()
        self.assertEqual(self.pair()['episode'], 1)
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM outbox WHERE sent_at IS NULL').fetchone())

    def test_adapter_product_only_and_range_watch(self):
        self.put()
        self.watch = replace(self.watch, match=(), product_only=('widget',))
        self.assertEqual(self.result().state, State.UNKNOWN)
        self.watch = replace(self.watch, match=(('examplecorp', 'widget'),), product_only=(),
                             version='>=1.0.0,<3.0.0')
        self.assertEqual(self.result().state, State.AFFECTED)
        self.watch = replace(self.watch, version='>=2.0.0,<3.0.0')
        self.assertEqual(self.result().state, State.NOT_AFFECTED)

    def test_exact_product_version_and_platform_fix_scope(self):
        raw = advisory(platform='example-platform', fix='2.0.0')
        raw['evidence'][0].pop('range')
        raw['products'][0]['version'] = '1.0.0'
        self.put(raw)
        scope = {'platform': 'example-platform'}
        self.assertEqual(self.result(scope=scope).state, State.AFFECTED)
        self.assertIsNone(self.engine.advisory_fix(self.watch, A, scope={'platform':'other-platform'}))
        self.watch = replace(self.watch, version='3.0.0')
        self.assertEqual(self.result(scope=scope).state, State.UNKNOWN)

    def test_quarantine_retains_unknown_without_accepting_evidence(self):
        from tests.replay_v11.fixture_adapter import ValidationBackend
        from tests.replay_v11.harness import fixture_registry, WATCHLIST
        backend = ValidationBackend(fixture_registry())
        try:
            backend.action(dict(t=T, watchlist=WATCHLIST))
            raw = advisory() | {'remediations':[dict(category='vendor_fix',group_ids=['missing'])]}
            backend.action(dict(t=T, adapter='fixture_a', result={'resources':[
                dict(path='listing.json',status=200,body=json.dumps([raw]))]}))
            backend.action(dict(t=T, cycle=True))
            db = backend.store.connection
            self.assertEqual(db.execute('SELECT state FROM pairs').fetchone()[0], 'unknown')
            self.assertFalse(db.execute('SELECT 1 FROM advisory_evidence').fetchone())
            self.assertFalse(db.execute('SELECT 1 FROM advisories').fetchone())
        finally:
            backend.close()

    def test_initialized_engine_matches_typed_stream(self):
        from cornicen.feedvalidate import validate_members
        self.p.ensure('fixture_a', T)
        self.db.execute("UPDATE adapter_state SET baseline_members='[]',baseline_complete=1")
        result = validate_members(iter([advisory()]), source='fixture_a', observed_at=T)
        self.engine.validate_adapter_result(result, source='fixture_a', tick=T, data_dir=self.tmp.name)
        self.assertEqual(self.pair()['state'], 'affected')
        self.assertTrue(self.db.execute("SELECT 1 FROM events WHERE type='new match'").fetchone())

    def test_unrelated_watch_with_kev(self):
        gadget=replace(self.watch,id='g',match=(('examplecorp','gadget'),))
        self.engine.watches=(self.watch,gadget)
        self.db.execute('INSERT INTO kev VALUES (?,?)',(A,json.dumps({'cveID':A})))
        self.put()
        self.assertIsNone(self.db.execute("SELECT 1 FROM pairs WHERE watch_id='g'").fetchone())
        self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')],['w|'+A+'|new match|1'])
        self.put(advisory() | {'withdrawn':T})
        self.assertIsNone(self.db.execute("SELECT 1 FROM pairs WHERE watch_id='g'").fetchone())

    def test_kev_ingest_advisory(self):
        from cornicen.model import IngestResult, FetchStatus, Origin
        self.put(); self.ack()
        self.store.set_meta('kev_initialized','1')
        self.engine._health_verdicts={}
        self.engine._ingest(IngestResult('kev',FetchStatus.COMPLETE,Origin.CATALOG,'K1',None,kev={A:{'cveID':A}}))
        self.assertEqual(self.pair()['exploited'],1)
        self.assertTrue(self.db.execute('SELECT 1 FROM kev_seen WHERE cve=?',(A,)).fetchone())

    def test_quarantine_shell_reload_explain_revalidate(self):
        from cornicen.cli import explain
        p=AdapterStore(self.store,self.tmp.name,on_record=self.engine.commit_advisory,on_unknown=self.engine.observe_unknown_advisory)
        raw=advisory(); raw['evidence'][0]['product_id']='missing'
        self.assertEqual(p.process('fixture_a',[dict(path='a.json',status=200,body=json.dumps([raw]))],T),'PARTIAL')
        self.assertEqual(self.pair()['state'],'unknown')
        # Simulate a shell created before its additive marker table existed.
        self.db.execute('DELETE FROM advisory_shells')
        self.store.migrate()
        self.engine.reload_watches((replace(self.watch,version='1.1.0'),))
        self.assertFalse(self.db.execute("SELECT 1 FROM health WHERE state='unhealthy'").fetchone())
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(explain(self.store,(self.watch,),self.engine.aliases,A,'w'),0)
        self.assertIn('applicability=unknown;',output.getvalue())
        body=dict(watch_id='w',record_id=A,episode=1)
        self.store.queue('w|'+A,'normal',['new match'],body,T,T)
        self.assertIsNone(self.engine._revalidate(self.db.execute('SELECT * FROM outbox').fetchone()))
        self.assertFalse(self.db.execute("SELECT 1 FROM health WHERE state='unhealthy'").fetchone())

    def test_identifier_only_withdrawal_keeps_cna_path(self):
        from cornicen import advisory as api
        identity='CVE-2099-0050'
        self.put(advisory(cves=()))
        raw=advisory(cves=()) | dict(identifiers=[dict(type='CVE',value=identity)],withdrawn=T)
        self.put(raw)
        self.db.execute('DELETE FROM events')
        self.assertFalse(api.has_identity(self.db,identity))
        record=self.cna('affected'); record['cveMetadata']['cveId']=identity
        self.engine._evaluate(record,identity)
        self.assertEqual(self.pair(identity)['state'],'affected')
        self.assertEqual([r[0] for r in self.db.execute('SELECT key FROM events')],['w|'+identity+'|new match|1'])

    def test_strict_remediation_sibling(self):
        bad=advisory() | dict(remediations=[dict(category='vendor_fix',product_ids=5)])
        with self.assertRaises(ValueError):
            validate_advisory(bad,source='fixture_a',observed_at=T)
        good=advisory() | dict(id='FIX-2099-0051')
        state=self.p.process('fixture_a',[dict(path='a.json',status=200,body=json.dumps([bad,good]))],T)
        self.assertEqual(state,'PARTIAL')
        self.assertEqual([r[0] for r in self.db.execute('SELECT source_id FROM quarantine')],['FIX-2099-0001'])
        self.assertEqual([r[0] for r in self.db.execute('SELECT source_id FROM advisories')],['FIX-2099-0051'])

    def test_strict_evidence_fields(self):
        for field in ('release','platform','fix','first_fixed'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_advisory(advisory(**{field:5}),source='fixture_a',observed_at=T)
        with self.assertRaises(ValueError):
            validate_advisory(advisory(range={'limit':5}),source='fixture_a',observed_at=T)
        for refs in ({'product_ids':[5]}, {'group_ids':5}, {'group_ids':['missing']}):
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                validate_advisory(advisory() | dict(remediations=[dict(category='vendor_fix',**refs)]),source='fixture_a',observed_at=T)

    def test_callback_exception_isolates_record(self):
        from cornicen.advisory import write_evidence
        def callback(data,baseline):
            write_evidence(self.db,data,baseline)
            if data['source_id']=='FIX-2099-0001':
                raise RuntimeError('injected callback failure')
        p=AdapterStore(self.store,self.tmp.name,on_record=callback)
        good=advisory() | dict(id='FIX-2099-0051')
        self.assertEqual(p.process('fixture_a',[dict(path='a.json',status=200,body=json.dumps([advisory(),good]))],T),'PARTIAL')
        self.assertEqual([r[0] for r in self.db.execute('SELECT source_id FROM advisories')],['FIX-2099-0051'])
        self.assertEqual([r[0] for r in self.db.execute('SELECT DISTINCT source_id FROM advisory_evidence')],['FIX-2099-0051'])
        self.assertEqual([r[0] for r in self.db.execute('SELECT source_id FROM quarantine')],['FIX-2099-0001'])

    def test_advisory_render_url(self):
        from cornicen.model import Notification
        from cornicen.render import render
        self.put(advisory(cves=()))
        body=self.engine._body(self.watch,P,self.result(P))
        text=render(Notification('k','w',P,('new match',),'normal',body))[1]
        self.assertIn('\nhttps://examplecorp.invalid/a\n',text)
        self.assertNotIn('CVERecord?id=advisory:',text)

    def test_fix_version_precedence(self):
        self.put(advisory(fix='10.0.0'))
        self.put(advisory(fix='2.0.0'),source='fixture_b')
        self.assertEqual(self.engine.advisory_fix(self.watch,A),'2.0.0')

    def test_removed_watch_clears_latches(self):
        self.put()
        self.engine.reload_watches(())
        self.assertFalse(self.db.execute('SELECT 1 FROM affected_latches').fetchone())

    def test_readme_delivery_capability_current(self):
        text=Path('tests/replay_v11/README.md').read_text()
        self.assertNotIn('all F3a/F3b oracle lines remain pending',text)
        self.assertNotIn('`advisory_delivery_available` is false until F3a',text)

    def test_cna_helper_has_plan_range(self):
        from cornicen.applicability import resolve
        result=resolve(self.cna('affected'),None,replace(self.watch,version='2.0.0'),self.engine.aliases)
        self.assertEqual(result.state,State.NOT_AFFECTED)

    def test_support_history_migration_and_withdrawal(self):
        from cornicen import advisory as api
        self.put()
        self.db.execute('DROP TABLE advisory_support')
        self.store.migrate()
        self.put(advisory() | {'withdrawn':T})
        self.store.migrate()
        self.assertTrue(api.has_identity(self.db,A))
        self.assertEqual(self.result().state,State.NOT_AFFECTED)
        self.assertFalse(self.db.execute('SELECT 1 FROM advisory_evidence').fetchone())

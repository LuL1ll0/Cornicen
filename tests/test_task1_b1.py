# script-purpose: Verify B-1 selector, transport and independent store contracts offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task1_b1.py
"""Read invented members and frozen source; write temporary SQLite and staging.

Run PYTHONPATH=src python3 -m unittest tests.test_task1_b1 -v; exit 0/1.
"""
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from io import BytesIO

from cornicen import advisory, adapters, feedvalidate as v, watchlist
from cornicen.adapterstore import AdapterStore, canonical, digest, instant, stamp
from cornicen.applicability import State
from cornicen.config import DOWNLOAD_BUDGETS, SecretToken
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.identity import AliasMap
from cornicen.store import Store, TransactionAborted
from cornicen.versions import Scheme
from tests.test_f1 import member, T
from tests import test_f3a as f3a

ROOT = Path(__file__).resolve().parents[1]
REPO = 'examplecorp/widget-engine'
PACKAGE = 'examplecorp/widget-engine'
G = 'GHSA-2345-6789-cfgh'
A = 'CVE-2099-0040'
BASE = dict(id='w', name='Widget Engine', match=['examplecorp:widget'], version='1.5', scheme='dotted')
SEL = dict(repository=REPO, ecosystem='other', package=PACKAGE)


def watch(**kw):
    return watchlist._watch(BASE | dict(github=[SEL]) | kw)


def raw(identity=G, **kw):
    return member() | dict(id=identity, products=[dict(id='p', name=f'github-selector:{REPO}#other#{PACKAGE}')],
        evidence=[dict(product_id='p', scheme='opaque', status='known_affected', range={'github': '>= 1.0, < 2.0'})]) | kw


def resource(path, members=(), **kw):
    return dict(path=path, status=200, body=json.dumps(list(members))) | kw


class B1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.p = AdapterStore(self.store, self.tmp.name)
        self.aliases = AliasMap.load(False)

    def process(self, resources, tick=T, required=('a', 'b')):
        return self.p.process('github', resources, tick, required_resources=required)

    def dimension(self, name):
        return tuple(self.db.execute('SELECT state,detail FROM source_health WHERE source=? AND dimension=?', ('github', name)).fetchone())

    def row(self, range_text, **kw):
        data = v.validate_advisory(raw(**kw), source='github', observed_at=T).data
        data['evidence'][0]['range']['github'] = range_text
        advisory.write_evidence(self.db, data)
        return self.db.execute('SELECT * FROM advisory_evidence WHERE identity=?', (advisory.parent_id(data),)).fetchone()

    def test_watch_github_entries(self):
        w = watch(github=[SEL | dict(repository='ExampleCorp/Widget-Engine')])
        self.assertEqual(w.github[0].repository, REPO)
        self.assertEqual(w.github[0].package, PACKAGE)
        for values, message in [([SEL | dict(repository='../bad')], 'github repository is invalid'),
                ([SEL | dict(ecosystem='unknown')], 'github ecosystem is invalid'),
                *[([SEL | dict(package=p)], 'github package is invalid') for p in ('', 'x'*201, 'x\u202e')],
                ([SEL]*21, 'github must be an array of at most 20 selectors'),
                ([SEL, SEL], 'duplicate github selector')]:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, '^'+message+'$'):
                watch(github=values)
        self.assertEqual(watchlist._watch(BASE | dict(latest_release='github:ExampleCorp/Widget-Engine')).github, ())
        text = '[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.5"\nscheme="dotted"\ngithub=[{repository="examplecorp/widget-engine",ecosystem="other",package="Widget Engine"}]'
        self.assertEqual(watchlist.load_watchlist_text(text)[0].github[0].package, 'Widget Engine')
        with self.assertRaisesRegex(ValueError, '^match or product_only must declare at least one identity$'):
            watchlist._watch(BASE | dict(match=[], github=[SEL]))
        self.assertFalse(any(e.effective(True) for e in adapters.REGISTRY.values()))

    def test_watch_canonical_unchanged(self):
        old = watchlist._watch(BASE)
        # Generated once from the pinned v0.2.0 tree's _canonical_watches;
        # committed bytes keep this assertion active in a clean checkout.
        expected = json.loads((ROOT / 'tests/fixtures/github/v0200_canonical_watches.json').read_text())['base']
        self.assertEqual(Engine._canonical_watches((old,)), expected)
        w = watch(github=[SEL | dict(package='Widget Engine'), SEL])
        encoded = Engine._canonical_watches((w,))
        self.assertNotEqual(encoded, expected)
        self.assertEqual(json.loads(encoded)[0]['github'], sorted([SEL, SEL | dict(package='Widget Engine')], key=lambda s:(s['repository'],s['ecosystem'],s['package'])))
        self.assertEqual(Engine._canonical_watches((replace(w, github=()),)), expected)
        fixture = f3a.F3aTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        engine = fixture.engine
        config = engine.config
        # An unchanged startup does not reload, including a stored legacy watch.
        with patch.object(Engine, 'reload_watches', wraps=engine.reload_watches) as reload:
            Engine(fixture.store, (fixture.watch,), fixture.engine.aliases, config, fixture.clock, engine.notifier)
            reload.assert_not_called()
        data = v.validate_advisory(raw(cves=[A]), source='github', observed_at=T).data
        initial = replace(fixture.watch, version='1.5', scheme=Scheme.DOTTED)
        engine.reload_watches((initial,))
        engine.commit_advisory(data, False)
        self.assertEqual(fixture.db.execute('SELECT count(*) FROM pairs').fetchone()[0], 0)
        selected = replace(initial, github=watch().github)
        with patch('cornicen.fetch.Http.get', side_effect=AssertionError('refetch')):
            engine.reload_watches((selected,))
            self.assertEqual(engine.advisory_result(selected, A).state, State.AFFECTED)
            self.assertEqual(fixture.db.execute('SELECT count(*) FROM pairs').fetchone()[0], 1)
            self.assertEqual([r[0] for r in fixture.db.execute("SELECT key FROM events WHERE type='new match'")],
                             ['w|' + A + '|new match|1'])
            original_reload = Engine.reload_watches
            observed = []
            def inspect(instance, watches, **kw):
                observed.extend(instance.watches[0].github)
                return original_reload(instance, watches, **kw)
            with patch.object(Engine, 'reload_watches', inspect):
                Engine(fixture.store, (fixture.watch,), engine.aliases, config, fixture.clock, engine.notifier)
            self.assertIsInstance(observed[0], watchlist.GitHubSelector)

    def test_selector_added_while_stopped(self):
        fixture = f3a.F3aTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        engine = fixture.engine
        data = raw(cves=[A])
        data['evidence'][0]['range']['github'] = '>= 1.0.0, < 2.0.0'
        engine.commit_advisory(v.validate_advisory(data, source='github', observed_at=T).data, False)
        self.assertEqual(fixture.db.execute('SELECT count(*) FROM pairs').fetchone()[0], 0)
        selected = replace(fixture.watch, github=watch().github)
        with patch('cornicen.fetch.Http.get', side_effect=AssertionError('refetch')):
            restarted = Engine(fixture.store, (selected,), engine.aliases, engine.config, fixture.clock, engine.notifier)
        self.assertEqual(restarted.advisory_result(selected, A).state, State.AFFECTED)
        self.assertEqual(fixture.db.execute('SELECT count(*) FROM pairs').fetchone()[0], 1)
        self.assertEqual([r[0] for r in fixture.db.execute("SELECT key FROM events WHERE type='new match'")],
                         ['w|' + A + '|new match|1'])

    def test_version_range_grammar(self):
        cases = [('<= 2099.7.1', '2099.7.1', True), ('<= 2099.7.1', '2099.7.2', False),
            ('>= 1.0, < 2.0', '1.0', True), ('>= 1.0, < 2.0', '2.0', False),
            ('< 1.0 || >= 3.0, < 3.4', '0.9', True), ('< 1.0 || >= 3.0, < 3.4', '2.0', False),
            ('< 1.0 || >= 3.0, < 3.4', '3.0', True), ('< 1.0 || >= 3.0, < 3.4', '3.4', False),
            ('= 2.0', '2.0', True), ('= 2.0', '2.1', False),
            ('> 1.0', '1.0', False), ('> 1.0', '1.1', True), ('>= 1.0', '1.0', True),
            ('>= 1.0', '0.9', False), ('>= 1.0, < 2.0', '>= 1.5, < 1.7', True), ('< 1.0', '>= 1.5, < 1.7', False)]
        for text, version, affected in cases:
            with self.subTest(text=text, version=version):
                self.assertEqual(advisory.evaluate_row(self.row(text), watch(version=version), self.aliases), State.AFFECTED if affected else State.NOT_AFFECTED)
        for text in ('', 'garbage', '!= 1.0', '< 2.0, < 3.0', '= 1.0, < 2.0', '>= 1.0 ||', '>= nope', '> 1.0, >= 2.0'):
            self.assertEqual(advisory.evaluate_row(self.row(text), watch(), self.aliases), State.UNKNOWN)
        for scheme, version, text in [('semver','0.0.0-alpha','>= 0.0.0, < 1.0.0'), ('python','0.0.0a1','>= 0.0.0, < 1.0.0'), ('debian','0~rc1','>= 0, < 1')]:
            w = (watchlist.Watch('w', 'Widget Engine', (('examplecorp', 'widget'),), (),
                                version, Scheme.DEBIAN, False, github=watch().github)
                 if scheme == 'debian' else watch(scheme=scheme, version=version))
            self.assertEqual(advisory.evaluate_row(self.row(text), w, self.aliases), State.NOT_AFFECTED)
        w = watch(scheme='opaque', version='RomePI 1.0.0.G')
        for text, state in [('< 2.0', State.UNKNOWN), ('= RomePI 1.0.0.G', State.AFFECTED), ('= RomePI 1.0.0.H', State.UNKNOWN)]:
            self.assertEqual(advisory.evaluate_row(self.row(text), w, self.aliases), state)
        for fix, expected in [('2099.8','2099.8'), ('1.2, 1.3',None), (None,None), ('invalid',None)]:
            data = raw()
            if fix: data['evidence'][0]['fix'] = fix
            self.row('>= 1.0', **data)
            self.assertEqual(advisory.fix_for(self.db, f'advisory:github:{G}:main', watch(), self.aliases), expected)

    def test_selector_scope(self):
        row = self.row('>= 1.0, < 2.0')
        self.assertIsNone(advisory.evaluate_row(dict(row) | dict(source='fixture_a'), watch(), self.aliases))
        for status in ('under_investigation', 'known_not_affected', 'fixed', 'unexpected'):
            self.assertEqual(advisory.evaluate_row(dict(row) | dict(status=status), watch(), self.aliases), State.UNKNOWN)
        self.assertIsNone(advisory.evaluate_row(row, watch(github=[SEL | dict(package='Widget Core')]), self.aliases))
        self.assertIsNone(advisory.evaluate_row(row, watch(github=[SEL | dict(repository='examplecorp/other')]), self.aliases))
        self.assertIsNone(advisory.evaluate_row(row, watch(github=[], product_only=[row['package']]), self.aliases))
        for scheme, version in [('dotted','1.5'), ('python','1.5.0'), ('debian','1.5'), ('semver','1.5.0')]:
            self.assertEqual(advisory.evaluate_row(row, watch(scheme=scheme, version=version), self.aliases), State.AFFECTED if scheme in ('dotted','debian') else State.UNKNOWN)
        self.row('>= 1.0', cves=[A, 'CVE-2099-0041'])
        for cve in (A, 'CVE-2099-0041'):
            self.assertEqual(advisory.resolve(self.db, cve, watch(), self.aliases).state, State.UNKNOWN)
            self.assertIsNone(advisory.fix_for(self.db, cve, watch(), self.aliases))
        data = raw(cves=[A]); data['evidence'][0]['fix']='2.0'
        data['products'].append(dict(id='q',name=f'github-selector:{REPO}#other#Widget Core'))
        data['evidence'].append(dict(product_id='q',scheme='opaque',status='known_affected',range={'github':'>= 1.0'}))
        advisory.write_evidence(self.db,v.validate_advisory(data,source='github',observed_at=T).data)
        self.assertIsNone(advisory.fix_for(self.db,A,watch(github=[SEL | dict(package='Widget Core')]),self.aliases))

    def test_transport_headers_and_hops(self):
        self.assertEqual(DOWNLOAD_BUDGETS['github_advisories'], dict(max_bytes=8*1024**2, deadline_seconds=60))
        requests=[]; hops=[]
        class Reply(BytesIO):
            status=200
            headers={}
        def opener(req, **kw):
            requests.append(req)
            reply=Reply(b'[]')
            if len(requests)==1:
                reply.status=302; reply.headers={'Location':'https://api.github.com/repos/examplecorp/foreign/security-advisories'}
            return reply
        def validate(url):
            hops.append(url)
            if '/foreign/' in url: raise ValueError('foreign')
        http=Http('test',{},opener=opener,resolver=lambda *a,**k:[(2,1,6,'',('8.8.8.8',443))],github_token=SecretToken('invented-token'))
        with self.assertRaisesRegex(ValueError,'foreign'):
            http.get(f'https://api.github.com/repos/{REPO}/security-advisories',source='github_advisories',validate_hop=validate)
        self.assertEqual(len(requests),1); self.assertEqual(len(hops),2)
        headers={k.lower():val for k,val in requests[0].header_items()}
        self.assertEqual(headers['accept'],'application/vnd.github+json')
        self.assertEqual(headers['x-github-api-version'],'2022-11-28')
        self.assertNotIn('authorization',headers)
        self.assertNotIn('invented-token',str(headers))
        # Both accepted hops are charged, in order, and the fixed headers repeat.
        requests.clear(); accepted=[]
        http.get(f'https://api.github.com/repos/{REPO}/security-advisories',source='github_advisories',validate_hop=accepted.append)
        self.assertEqual(accepted,[r.full_url for r in requests])
        self.assertEqual(len(accepted),2)
        for req in requests:
            self.assertEqual(req.get_header('Accept'),'application/vnd.github+json')
        # Destination rejection runs before the adapter hook or opener.
        requests.clear(); accepted.clear()
        with self.assertRaises(ValueError):
            http.get('https://foreign.invalid/repos/examplecorp/widget-engine',source='github_advisories',validate_hop=accepted.append)
        self.assertEqual(requests,[]); self.assertEqual(accepted,[])

    def test_retraction_and_mapping_boundary(self):
        self.assertTrue(advisory.retracted({'retraction':'administrative'}))
        self.assertTrue(advisory.retracted({'withdrawn':T}))
        self.assertFalse(advisory.retracted({}))
        for mapping in ('invalid GHSA','untrusted token\x07'):
            with self.assertRaisesRegex(ValueError,'advisory mapping failed'):
                v.validate_advisory(raw(mapping_error=mapping),source='github',observed_at=T)
        with self.assertRaisesRegex(ValueError,'invalid advisory retraction'):
            v.validate_advisory(raw(retraction='other'),source='github',observed_at=T)
        data=v.validate_advisory(raw(retraction='administrative'),source='github',observed_at=T).data
        self.assertIsNone(data['withdrawn']); self.assertTrue(advisory.retracted(data))
        advisory.write_evidence(self.db,data)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisory_evidence').fetchone()[0],0)
        result=v.validate_members([raw()],source='github',observed_at=T)
        with patch.object(v,'validate_advisory',side_effect=ValueError('arbitrary secret\x07')):
            list(result.records)
        self.assertEqual(result.quarantine_reasons[G],'ValueError: adapter error')
        typed=v.validate_members([raw()],source='github',observed_at=T)
        engine=Engine.__new__(Engine); engine.store=self.store
        with patch.object(v,'validate_advisory',side_effect=ValueError('arbitrary secret\x07')):
            engine.validate_adapter_result(typed,source='github',resource='typed',tick=T,data_dir=self.tmp.name)
        self.assertEqual(self.db.execute('SELECT reason FROM quarantine WHERE source_id=?',(G,)).fetchone()[0],'ValueError: adapter error')
        # The typed boundary's own quarantine path uses that sanitised reason.
        from cornicen.diagnostics import FixedDiagnostic
        fixed=v.validate_members([raw()],source='github',observed_at=T)
        with patch.object(v,'validate_advisory',side_effect=ValueError(FixedDiagnostic('invalid advisory retraction'))):
            list(fixed.records)
        self.assertEqual(fixed.quarantine_reasons[G],'ValueError: invalid advisory retraction')
        self.process([resource('a',[raw(cves=[A])])],required=('a',))
        self.assertEqual(self.process([resource('a',[raw(cves=[A],mapping_error='untrusted')])],required=('a',)),'PARTIAL')
        self.assertGreater(self.db.execute('SELECT count(*) FROM advisory_evidence').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT reason FROM quarantine WHERE source_id=?',(G,)).fetchone()[0],'ValueError: advisory mapping failed')
        # Administrative retraction may remove identifiers without fabricating a date.
        self.assertEqual(self.process([resource('a',[raw(retraction='administrative')])],required=('a',)),'COMPLETE')
        self.assertEqual(self.db.execute('SELECT state FROM advisories').fetchone()[0],'withdrawn')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisory_evidence').fetchone()[0],0)

    def test_independent_store(self):
        self.assertTrue(adapters.REGISTRY['github'].independent)
        self.process([],required=('a','b'))
        self.p.retry('github','b',T,'PARTIAL')
        self.assertEqual(self.process([resource('a',[raw()])]),'COMPLETE')
        self.assertEqual(self.db.execute("SELECT digest FROM manifests WHERE resource='a'").fetchone()[0] != '',True)
        self.assertIsNone(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0])
        self.p.finish_cycle('github',T)
        self.assertEqual(self.dimension('completeness'),('unhealthy','retry pending'))
        # An observation placeholder must not count as an accepted enumeration.
        self.db.execute("DELETE FROM adapter_retries WHERE resource='b'")
        self.p._audit_observation('github',resource('b',status=500),T)
        self.process([resource('a',[raw()])])
        self.assertIsNone(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0])
        self.process([resource('b')])
        self.assertEqual(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0],T)
        accepted_members=[dict(source_id=r[0],digest=r[1]) for r in self.db.execute('SELECT DISTINCT source_id,digest FROM manifest_members ORDER BY source_id,digest')]
        self.assertEqual(self.db.execute("SELECT cursor_digest FROM adapter_state WHERE source='github'").fetchone()[0],digest(accepted_members))
        self.assertEqual(len(self.p.summaries()),1)
        # A later failed outcome cannot let A advance using B's older manifest.
        next_tick=stamp(instant(T)+timedelta(hours=1))
        self.assertEqual(self.process([resource('a',[raw(title='Updated Widget')]),resource('b',status=500)],next_tick),'FAILED')
        self.assertEqual(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0],T)
        self.assertEqual(self.db.execute("SELECT fetched_at FROM manifests WHERE resource='a'").fetchone()[0],next_tick)
        self.process([resource('b')],next_tick)
        self.assertEqual(self.p.known_members('github','a'),{G})
        # Active disappearance blocks; accepted administrative retraction resolves it.
        self.assertEqual(self.process([resource('a')]),'PARTIAL')
        self.assertEqual(self.process([resource('a',[raw(retraction='administrative')])]),'COMPLETE')
        self.assertEqual(self.process([resource('a')]),'COMPLETE')
        self.assertEqual(self.p.known_members('github','a'),set())
        self.assertEqual(self.db.execute("SELECT state FROM advisories").fetchone()[0],'withdrawn')
        # Dropped resources retain history but no longer route or affect health.
        self.process([resource('b',[raw('GHSA-3456-789c-fghj')])])
        self.p.stage_members('github','b',[],T)
        self.p.retry('github','b',T,'FAILED')
        self.process([],required=('a',))
        self.assertEqual(json.loads(self.store.get_meta('required_since:github')),{'a':T})
        self.assertIsNone(self.db.execute("SELECT 1 FROM adapter_retries WHERE resource='b'").fetchone())
        self.assertIsNone(self.db.execute("SELECT 1 FROM staged_containers WHERE resource='b'").fetchone())
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM manifests WHERE resource='b'").fetchone())
        self.assertEqual(set(json.loads(self.dimension('fetch')[1])),{'a'})
        self.assertNotIn('b',self.p.audits_due('github',stamp(instant(T)+timedelta(days=8))))
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM advisories WHERE source_id=?',('GHSA-3456-789c-fghj',)).fetchone())
        self.process([resource('a')],required=('a',))
        self.assertEqual(self.db.execute("SELECT cursor_digest FROM adapter_state WHERE source='github'").fetchone()[0],digest([]))
        self.p.finish_cycle('github',stamp(instant(T)+timedelta(days=8)))
        self.assertEqual(self.dimension('audit')[1],canonical(['a']))
        # A dropped retry/stage never reaches resume, audit or retry routing.
        adapter=Mock(); adapter.required_resources.return_value={'a'}
        adapter.poll.return_value=[]; adapter.audit.return_value=[]; adapter.retry.return_value=[]
        self.p.dispatch({'github':replace(adapters.REGISTRY['github'],gate='met')},{'github':True},{'github':lambda:adapter},T)
        self.assertNotIn('b',[c.args[0] for c in adapter.audit.call_args_list+adapter.retry.call_args_list])

    def test_independent_backlog_and_dispatch(self):
        self.process([],required=('a',))
        self.assertEqual(json.loads(self.store.get_meta('required_since:github')), {'a': T})
        for seconds, state in ((86399,'healthy'),(86400,'unhealthy')):
            self.p.finish_cycle('github',stamp(instant(T)+timedelta(seconds=seconds)))
            self.assertEqual(self.dimension('completeness')[0],state)
        self.assertEqual(self.dimension('completeness')[1],'rate budget backlog')
        self.process([resource('a')],required=('a',))
        for seconds, state in ((86399,'healthy'),(86400,'unhealthy')):
            self.p.finish_cycle('github',stamp(instant(T)+timedelta(seconds=seconds)))
            self.assertEqual(self.dimension('completeness')[0],state)
        self.assertEqual(self.dimension('completeness'),('unhealthy','rate budget backlog'))
        adapter=Mock()
        adapter.required_resources.return_value={'a'}
        adapter.poll.side_effect=RuntimeError('secret')
        registry={'github':replace(adapters.REGISTRY['github'],gate='met')}
        self.p.dispatch(registry,{'github':True},{'github':lambda:adapter},T)
        self.assertEqual(self.dimension('completeness'),('unhealthy','RuntimeError: adapter error'))
        adapter.poll.side_effect=None; adapter.poll.return_value=[resource('a')]
        adapter.audit.return_value=[]; adapter.retry.return_value=[]
        self.p.dispatch(registry,{'github':True},{'github':lambda:adapter},T)
        self.assertEqual(self.dimension('completeness'),('healthy',''))
        self.assertNotIn('@dispatch',[c.args[0] for c in adapter.retry.call_args_list])
        self.assertEqual(self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0],T)

    def test_shared_resume_before_raising_factory(self):
        self.p.stage_members('fixture_a', 'a', [member()], T)
        def factory():
            self.assertIsNotNone(self.db.execute("SELECT 1 FROM manifests WHERE source='fixture_a' AND digest!=''").fetchone())
            raise RuntimeError('factory failed')
        entry = adapters.Adapter('fixture_a', 'fixture', gate='met')
        self.assertEqual(self.p.dispatch({'fixture_a': entry}, {'fixture_a': True},
                                        {'fixture_a': factory}, T), {'fixture_a': 'FAILED'})
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM advisories WHERE source='fixture_a'").fetchone())
        self.assertIsNone(self.db.execute("SELECT 1 FROM staged_containers WHERE source='fixture_a'").fetchone())

    def test_empty_baseline_resources_no_summary(self):
        self.process([], required=())
        self.p.finish_cycle('github', T)
        self.assertEqual(self.p.summaries(), [])
        self.process([resource('a', [raw()])], required=('a',))
        self.assertEqual(self.p.summaries(), [])

    def test_unenumerated_and_baseline_resources(self):
        self.assertEqual(self.process([resource('a',unenumerated=True)]),'PARTIAL')
        for table in ('staged_containers','resource_cache','baseline_members','manifests','advisories'):
            self.assertEqual(self.db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
        self.assertEqual(self.dimension('fetch')[0],'healthy')
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0],'unenumerated')
        seen=[]
        self.p.on_record=lambda data,baseline:seen.append((data['source_id'],baseline))
        self.process([resource('a',[raw(),raw('GHSA-3456-789c-fghj',title='')])])
        self.assertEqual(json.loads(self.store.get_meta('baseline_resources:github')),['a','b'])
        self.assertIsNotNone(self.store.get_meta('baseline_pinned:github:a'))
        self.assertEqual(seen,[(G,True)])
        self.assertEqual(self.p.known_members('github','a'),{G})
        self.assertEqual(len(self.p.summaries()),0)
        # Recreate store wrapper to witness durable pin after a partial enumeration.
        self.p=AdapterStore(self.store,self.tmp.name,on_record=lambda d,b:seen.append((d['source_id'],b)))
        self.process([resource('a',[raw(),raw('GHSA-3456-789c-fghj')])])
        self.assertIn(('GHSA-3456-789c-fghj',True),seen)
        self.process([resource('c',[raw('GHSA-4567-89cf-ghjm')])],required=('a','c'))
        self.assertIn(('GHSA-4567-89cf-ghjm',False),seen)
        self.assertEqual(len(self.p.summaries()),1)
        self.assertIsNone(self.store.get_meta('baseline_pinned:github:c'))
        # No callback can happen before its resource pin is durable.
        def inspect(data,baseline):
            self.assertIsNotNone(self.store.get_meta('baseline_pinned:github:a'))
        self.p.on_record=inspect
        self.process([resource('a',[raw(title='changed'),raw('GHSA-3456-789c-fghj')])],required=('a',))
        self.assertEqual(len(self.p.summaries()),1)

        # A real connection restart after pin and before the first record commit.
        path=Path(self.tmp.name)/'recovery'
        other=Store(path); other.migrate()
        persistence=AdapterStore(other,self.tmp.name,on_record=lambda d,b:(_ for _ in ()).throw(TransactionAborted('crash')))
        persistence.reconcile_required('github',('a','b'),T)
        persistence.stage_members('github','a',[raw()],T)
        with self.assertRaises(TransactionAborted):
            persistence.commit_staged('github','a',T)
        pin=other.get_meta('baseline_pinned:github:a')
        self.assertEqual(json.loads(pin),[G])
        self.assertIsNone(other.connection.execute('SELECT 1 FROM manifests').fetchone())
        other.connection.close()
        other=Store(path); self.addCleanup(other.connection.close)
        seen=[]
        persistence=AdapterStore(other,self.tmp.name,on_record=lambda d,b:seen.append((d['source_id'],b)))
        persistence.process('github',[resource('a',[raw(),raw('GHSA-5678-9cfg-hjmp')])],T,required_resources=('a','b'))
        self.assertEqual(other.get_meta('baseline_pinned:github:a'),pin)
        self.assertEqual(seen,[(G,True),('GHSA-5678-9cfg-hjmp',False)])
        persistence.on_record=lambda d,b:(_ for _ in ()).throw(TransactionAborted('crash'))
        persistence.stage_members('github','b',[raw('GHSA-6789-cfgh-jmpq')],T)
        with self.assertRaises(TransactionAborted):
            persistence.commit_staged('github','b',T)
        self.assertEqual(len(persistence.summaries()),0)
        # Dropping an unsettled pinned baseline resource must release the summary.
        persistence.process('github',[],T,required_resources=('a',))
        self.assertEqual(len(persistence.summaries()),1)

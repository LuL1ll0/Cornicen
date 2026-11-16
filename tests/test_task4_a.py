# script-purpose: Verify OSV mapping, selectors, ranges and source dates offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task4_a.py
"""Read invented OSV fixtures; write temporary local databases and JSONL members.

Run PYTHONPATH=src python3 -m unittest tests.test_task4_a -v; exit 0/1.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from cornicen import advisory, feedvalidate, public_text, watchlist
try:
    from cornicen import osv
except ImportError:
    osv = None
from cornicen.adapterstore import AdapterStore
from cornicen.applicability import State
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.store import Store
from tests.test_f1 import T
from tests import test_f3a as f3a
from tests import test_task3_a as task3
from tests import test_task3_b1 as task3b

ROOT = Path(__file__).resolve().parents[1]
A = 'CVE-2099-80213'
SELECTOR = dict(ecosystem='Debian:12', package='examplessl')
TEXT = '[[watch]]\nid="w"\nname="Sample"\nmatch=["examplecorp:widget"]\nversion="VERSION"\nscheme="debian"\nosv=[{ecosystem="Debian:12",package="examplessl"}]\n'
PLATFORM_CANONICAL = '[{"eol":false,"id":"w","match":[["examplecorp","widget"]],"name":"Widget","platform":{"product":"host","vendor":"examplecorp"},"product_only":[],"scheme":"opaque","version":"1"}]'


def fixture(identity='DSA-9001-1'):
    return deepcopy(next(r for r in json.loads((ROOT / 'tests/fixtures/debian/osv_query_sample.json').read_text())['vulns'] if r['id'] == identity))


def watch(version='1', **kw):
    return watchlist._watch(dict(id='w', name='Sample', match=['examplecorp:widget'],
        version=version, scheme='debian', osv=[SELECTOR]) | kw)


def synthetic(events=None, *, ranges=None, versions=None):
    r = dict(id='DSA-9001-1', modified=T, published=T, upstream=[A],
        affected=[dict(package=dict(ecosystem='Debian:12', name='examplessl'))])
    entry = r['affected'][0]
    if ranges is not None:
        entry['ranges'] = ranges
    elif events is not None:
        entry['ranges'] = [dict(type='ECOSYSTEM', events=events)]
    if versions is not None:
        entry['versions'] = versions
    return r


def events(*values):
    return [dict([pair]) for pair in zip(values[::2], values[1::2])]


class Task4ATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.persistence = AdapterStore(self.store, self.tmp.name)
        self.aliases = AliasMap.load(False)
        self.members = {}

    def mapped(self, record):
        self.assertIsNotNone(osv, 'OSV mapper must exist')
        return osv.normalise(record)

    def put(self, record, source='debian', expected='COMPLETE'):
        raw = self.mapped(record)
        path = Path(self.tmp.name) / 'members.jsonl'
        self.members.setdefault(source, {})[raw['id']] = raw
        path.write_text(''.join(json.dumps(m)+'\n' for m in self.members[source].values()))
        self.persistence.reconcile_required(source, ['debian/advisories'], T)
        self.assertEqual(self.persistence.process(source, [dict(path='debian/advisories', status=200,
            members_file=str(path))], T), expected)
        return advisory.rows_for(self.db, A)

    def result(self, w, identity=A, **kw):
        return advisory.resolve(self.db, identity, w, self.aliases, **kw).state

    def fix(self, w):
        return advisory.fix_for(self.db, A, w, self.aliases)

    def test_t1_mapping_details_and_storage(self):
        r = fixture()
        raw = self.mapped(r)
        self.assertEqual(raw['cves'], [A])
        self.assertEqual(raw['title'], 'examplessl security update')
        self.assertEqual(raw['url'], r['affected'][0]['database_specific']['source'])
        self.assertEqual(raw['products'], [dict(id='aff-0', name='osv-selector:Debian:12#examplessl', purl=r['affected'][0]['package']['purl'])])
        e = raw['evidence'][0]
        self.assertEqual(e['status'], 'known_affected')
        self.assertEqual(e['scheme'], 'debian')
        self.assertFalse({'release', 'platform', 'fix'} & e.keys())
        self.assertEqual(json.loads(e['range']['osv']), {k:r['affected'][0][k] for k in ('ranges', 'versions')})
        r = fixture('DEBIAN-CVE-2099-80091')
        raw = self.mapped(r)
        self.assertEqual(raw['updated'], r['modified'])
        self.assertRegex(raw['updated'], r'\.\d{9}Z$')
        # Supply the explicit contract at the producer boundary; the store must supply it too.
        data = feedvalidate.validate_advisory(raw, source='debian', observed_at=T,
            date_fields={'updated': (True, 'rfc3339')}).data
        self.assertEqual(data['details'], r['details'])
        self.put(r)
        stored = json.loads(self.db.execute('SELECT json FROM advisories').fetchone()[0])
        self.assertEqual(stored['details'], r['details'])
        microsoft = task3.normalise(task3.synthetic(), microsoft=True)
        self.assertNotIn('details', feedvalidate.validate_advisory(microsoft, source='msrc', observed_at=T).data)

    def test_t2_identity_and_partition(self):
        r = fixture('DSA-9003-1')
        self.assertEqual(self.mapped(r)['cves'], ['CVE-2099-80232', 'CVE-2099-80233'])
        r2 = synthetic(versions=['1'])
        r2.update(id='CVE-2099-80999', upstream=['DEBIAN-CVE-2099-80999', None, 'other'], aliases=['CVE-2099-80998', 3, 'CVE-2099-80999'])
        self.assertEqual(self.mapped(r2)['cves'], ['CVE-2099-80999', 'CVE-2099-80998'])
        self.put(r)
        parent = 'advisory:debian:DSA-9003-1:main'
        self.assertTrue(advisory.rows_for(self.db, parent))
        self.assertEqual(self.result(watch('93.0.10-1'), parent), State.AFFECTED)
        for identity in ['CVE-2099-80232', 'CVE-2099-80233']:
            self.assertEqual(self.result(watch('93.0.10-1'), identity), State.UNKNOWN)
            self.assertTrue(all(row['status'] == 'under_investigation' for row in advisory.rows_for(self.db, identity)))
        rows = self.put(fixture())
        self.assertTrue(rows)
        self.assertEqual({r['identity'] for r in rows}, {A})

    def test_t2_debian_cve_upstream_collapse(self):
        r = synthetic(versions=['1'])
        r.update(id='DSA-9777-1', upstream=['DEBIAN-CVE-2099-80777'])
        self.assertEqual(self.mapped(r)['cves'], ['CVE-2099-80777'])

    def test_t2_cve_order_upstream_before_aliases(self):
        r = synthetic(versions=['1'])
        r.update(id='DSA-9778-1', upstream=['CVE-2099-80701'], aliases=['CVE-2099-80702'])
        self.assertEqual(self.mapped(r)['cves'], ['CVE-2099-80701', 'CVE-2099-80702'])

    def test_t3_malformed_shapes(self):
        base = synthetic(events('introduced', '0', 'fixed', '2'))
        mutations = []
        def add(change, message):
            r = deepcopy(base); change(r); mutations.append((r, message))
        add(lambda r:r.update(affected={}), 'invalid OSV affected')
        for key in ('ecosystem', 'name'):
            add(lambda r,k=key:r['affected'][0]['package'].pop(k), 'invalid OSV package')
            add(lambda r,k=key:r['affected'][0]['package'].update({k:'bad#part'}), 'invalid OSV package')
        add(lambda r:r['affected'][0].update(ranges={}), 'invalid OSV ranges or versions')
        for event in [{'introduced':'0','fixed':'2'}, {'other':'1'}, {'introduced':''}, None]:
            add(lambda r,e=event:r['affected'][0]['ranges'][0].update(events=[e]), 'invalid OSV ranges or versions')
        for value in [None, [''], [1]]:
            add(lambda r,v=value:r['affected'][0].update(versions=v), 'invalid OSV ranges or versions')
        add(lambda r:r['affected'][0].pop('ranges'), 'invalid OSV ranges or versions')
        add(lambda r:r.pop('modified'), 'invalid OSV date')
        add(lambda r:r.update(published='bad'), 'invalid OSV date')
        for value in [3, 'x'*65537, 'a\0b']:
            add(lambda r,v=value:r.update(details=v), 'invalid OSV details')
        for r, message in mutations:
            with self.subTest(message=message, r=r):
                raw = self.mapped(r)
                self.assertEqual(raw, dict(id=base['id'], mapping_error=message))
                with self.assertRaisesRegex(ValueError, 'mapping failed'):
                    feedvalidate.validate_advisory(raw, source='debian', observed_at=T)
        for identity in ['bad:id', '.bad']:
            r = dict(base, id=identity); raw = self.mapped(r)
            self.assertEqual(raw, dict(id=None, mapping_error='invalid OSV id', osv_digest=hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode()).hexdigest()))

    def test_t3_fixture_enumerations_tombstone_and_urls(self):
        for r in json.loads((ROOT / 'tests/fixtures/debian/osv_query_sample.json').read_text())['vulns']:
            self.assertNotIn('mapping_error', self.mapped(r), r['id'])
        r = synthetic(versions=['1'])
        self.assertEqual(self.mapped(r)['url'], 'https://osv.dev/vulnerability/DSA-9001-1')
        r['references'] = [dict(type='WEB',url='https://wrong.invalid/'),dict(type='ADVISORY',url='bad'),dict(type='ADVISORY',url='https://example.invalid/advisory')]
        self.assertEqual(self.mapped(r)['url'], 'https://example.invalid/advisory')
        self.put(r)
        self.assertTrue(advisory.rows_for(self.db, A))
        r.pop('affected'); r['withdrawn'] = T
        self.put(r)
        self.assertEqual(advisory.rows_for(self.db, A), [])
        self.assertEqual(self.result(watch()), State.NOT_AFFECTED)

    def test_t4_fixture_bounds_and_release(self):
        rows = self.put(fixture())
        self.assertTrue(all(r['release'] is None and r['platform'] is None for r in rows))
        for version, expected in [('93.0.11-1~deb12u1', State.AFFECTED), ('93.0.11-1~deb12u2', State.NOT_AFFECTED), ('93.0.10-1~deb12u1', State.AFFECTED), ('1:90.0-1', State.NOT_AFFECTED)]:
            with self.subTest(version=version):
                w = watchlist.load_watchlist_text(TEXT.replace('VERSION',version))[0]
                self.assertEqual(self.result(w), expected)
        self.assertIsNone(advisory.evaluate_row(rows[0], watch(osv=[dict(SELECTOR,ecosystem='Debian:13')]), self.aliases))
        self.assertEqual(self.result(watch('1.0.0',scheme='semver')), State.UNKNOWN)
        self.put(fixture('DEBIAN-CVE-2099-80091'))
        self.assertEqual(self.result(watch('133.1-1',osv=[dict(SELECTOR,package='example-browser')]), 'CVE-2099-80091'), State.AFFECTED)

    def test_t5_listed_order_intervals(self):
        cases = [
            (events('introduced','2','fixed','2'), '2', State.NOT_AFFECTED),
            (events('introduced','2','fixed','2'), '3', State.NOT_AFFECTED),
            (events('introduced','0','fixed','2','introduced','2','fixed','3'), '2', State.AFFECTED),
            (events('introduced','0','fixed','2','introduced','2','fixed','3'), '3', State.NOT_AFFECTED),
            (events('fixed','2','introduced','0'), '1', State.UNKNOWN),
            (events('introduced','0','introduced','1','fixed','2'), '1', State.UNKNOWN),
            (events('introduced','3','fixed','2'), '1', State.UNKNOWN),
            (events('introduced','0','last_affected','2'), '2', State.AFFECTED),
            (events('introduced','0','limit','2'), '2', State.NOT_AFFECTED),
            (events('introduced','2'), '3', State.AFFECTED),
            (events('introduced','5','fixed','8','introduced','1','fixed','3'), '2', State.AFFECTED)]
        for ev, version, expected in cases:
            with self.subTest(ev=ev,version=version):
                rows = self.put(synthetic(ev))
                self.assertEqual(self.result(watch(version)), expected)
                self.assertEqual(len(rows), 1)

    def test_t5_union_enumeration_unsupported(self):
        for versions, v, expected in [(['2'],'2',State.AFFECTED), (['2'],'3',State.NOT_AFFECTED), (['x y'],'3',State.UNKNOWN), (['x y','3'],'3',State.AFFECTED)]:
            self.put(synthetic(versions=versions)); self.assertEqual(self.result(watch(v)),expected)
        supported = dict(type='ECOSYSTEM',events=events('introduced','1','fixed','3'))
        for other in [dict(type='GIT',events=events('introduced','0')),dict(type='ECOSYSTEM',events=events('introduced','x y')),dict(type='SEMVER',events=events('introduced','0','fixed','5.0.0'))]:
            for v, expected in [('2-1',State.AFFECTED),('4-1',State.UNKNOWN)]:
                self.put(synthetic(ranges=[supported,other])); self.assertEqual(self.result(watch(v)),expected)
        self.put(synthetic(ranges=[supported,dict(type='ECOSYSTEM',events=events('introduced','5','fixed','7'))]))
        self.assertEqual(self.result(watch('6')),State.AFFECTED)
        self.assertEqual(self.result(watch('9')),State.NOT_AFFECTED)
        # Invalid serialized shape and constraint watches cannot supply negative evidence.
        row = dict(advisory.rows_for(self.db,A)[0]); row['range'] = '{"osv":"{}"}'
        self.assertEqual(advisory.evaluate_row(row,watch(),self.aliases),State.UNKNOWN)
        self.assertEqual(self.result(replace(watch(),version='>=1')),State.UNKNOWN)
        for ecosystem in ['Debian-like','Other:12']:
            r=synthetic(versions=['1']); r['affected'][0]['package']['ecosystem']=ecosystem
            self.put(r)
            self.assertEqual(self.result(watch(osv=[dict(SELECTOR,ecosystem=ecosystem)])),State.UNKNOWN)

    def test_t5_open_semver_range_with_unparseable_watch(self):
        rows = self.put(synthetic(ranges=[dict(type='SEMVER', events=events('introduced', '0'))]))
        w = watch('2-1')
        self.assertEqual(advisory.evaluate_row(rows[0], w, self.aliases), State.UNKNOWN)
        self.assertEqual(self.result(w), State.UNKNOWN)

    def test_t6_scoped_fixes_and_vetoes(self):
        self.put(fixture()); self.assertEqual(self.fix(watch('93.0.11-1~deb12u1')), '93.0.11-1~deb12u2')
        def range_(ev, kind='ECOSYSTEM'): return dict(type=kind,events=ev)
        cases = [
            ([range_(events('introduced','0','fixed','5')),range_(events('introduced','6','fixed','9'))], [], '7', '9'),
            ([range_(events('introduced','0','fixed','2','introduced','2','fixed','3'))], [], '1', '3'),
            ([range_(events('introduced','0','fixed','2')),range_(events('introduced','0'))], [], '1', None),
            ([range_(events('introduced','0','fixed','2'))], ['2'], '1', None),
            ([range_(events('introduced','0','last_affected','2'))], [], '1', None),
            ([range_(events('introduced','0','limit','2'))], [], '1', None),
            ([range_(events('introduced','0','fixed','2'))], [], '3', None),
            ([range_(events('introduced','0','fixed','2.0.0'),'SEMVER')], [], '1.0.0', 'available')]
        for ranges, versions, v, expected in cases:
            with self.subTest(ranges=ranges,v=v):
                self.put(synthetic(ranges=ranges,versions=versions)); self.assertEqual(self.fix(watch(v)),expected)
        r = synthetic(events('introduced','0','fixed','9'))
        other = deepcopy(r['affected'][0]); other['package']['ecosystem']='Debian:13'; other['ranges'][0]['events'][-1]={'fixed':'2'}
        r['affected'].append(other); self.put(r); self.assertEqual(self.fix(watch()), '9')
        self.put(synthetic(versions=['1'])); self.assertIsNone(self.fix(watch()))
        self.put(fixture('DEBIAN-CVE-2099-80091'))
        self.assertIsNone(advisory.fix_for(self.db,'CVE-2099-80091',watch('133.1-1',osv=[dict(SELECTOR,package='example-browser')]),self.aliases))
        # A malicious generic fix on an unaffected OSV row must never leak.
        self.put(synthetic(events('introduced','0','fixed','2')))
        self.db.execute("UPDATE advisory_evidence SET fix='8'")
        self.assertIsNone(self.fix(watch('3')))

    def test_t6_whole_record_union_vetoes_fix(self):
        r = synthetic(events('introduced', '5'))
        # Keep the open entry first so retaining only the final entry loses its veto.
        r['affected'].append(synthetic(events('introduced', '0', 'fixed', '5'))['affected'][0])
        rows = self.put(r)
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.result(watch('4')), State.AFFECTED)
        self.assertIsNone(self.fix(watch('4')))

    def test_t6_many_endpoints(self):
        self.put(synthetic(ranges=[dict(type='ECOSYSTEM',events=events('introduced','0','fixed',str(i))) for i in range(2,602)]))
        start = time.monotonic(); self.assertEqual(self.fix(watch()),'601')
        self.assertLess(time.monotonic()-start,1.0)

    def test_t7_cna_scope_and_withdrawal(self):
        helper = f3a.F3aTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        record = helper.cna('unaffected')
        record['containers']['cna']['affected'][0].update(defaultStatus='unaffected',versions=[])
        w = replace(watch('93.0.11-1~deb12u1'),match=helper.watch.match)
        rows = self.put(fixture())
        verdict = advisory.cnascope.scoped_verdicts(record,w,self.aliases)[0]
        self.assertTrue(verdict.authoritative)
        self.assertFalse(advisory.same_scope(rows[0],verdict,self.aliases,(),scheme=w.scheme))
        self.assertEqual(self.result(w,record=record),State.AFFECTED)
        r = fixture(); r.pop('affected'); r['withdrawn']=T; self.put(r)
        r = synthetic(events('introduced','0','fixed','2')); r['id']='DEBIAN-CVE-2099-80213'; self.put(r)
        self.assertEqual(self.result(w,record=record),State.NOT_AFFECTED)

    def test_t7_same_scope_rejects_matching_osv_package(self):
        row = dict(self.put(synthetic(versions=['1']))[0])
        verdict = advisory.cnascope.ScopedVerdict(
            None, 'osv-selector:debian:12#examplessl', None, 'debian',
            State.NOT_AFFECTED, True, 'test', 'high')
        self.assertIsNone(row['release'])
        self.assertIsNone(row['platform'])
        self.assertFalse(advisory.same_scope(row, verdict, self.aliases, ()))
        self.assertTrue(advisory.same_scope(dict(row, source='fixture'), verdict, self.aliases, ()))

    def test_t8_selectors_validation_and_redaction(self):
        self.assertEqual(watch().osv[0].ecosystem,'Debian:12')
        cases = [(SELECTOR,'osv must be an array of at most 20 selectors'),([SELECTOR]*21,'osv must be an array of at most 20 selectors'),(['secretvalue'],'osv selector requires ecosystem and package'),([dict(ecosystem='secretvalue')],'osv selector requires ecosystem and package'),([dict(SELECTOR,extra='secretvalue')],'osv selector requires ecosystem and package'),([SELECTOR,SELECTOR],'duplicate osv selector')]
        for value in ['', 'x'*101, '1secretvalue', 'Debian#secretvalue', 'Debian:']:
            cases.append(([dict(SELECTOR,ecosystem=value)],'osv ecosystem is invalid'))
        for value in ['', 'x'*201, 'secret#value', 'secret value','secret\u200bvalue']:
            cases.append(([dict(SELECTOR,package=value)],'osv package is invalid'))
        for selectors,message in cases:
            with self.subTest(selectors=selectors), self.assertRaises(ValueError) as caught:
                watch(osv=selectors)
            self.assertEqual(str(caught.exception),message)
            self.assertNotIn('secretvalue',str(caught.exception))
        for selector in [dict(ecosystem='directory',package='gateway'),dict(ecosystem='gateway',package='directory')]:
            self.assertEqual(public_text.public_text('directory',[watch(osv=[selector])]),public_text.MARKER)
        self.assertEqual(watchlist.load_watchlist_text(TEXT.replace('VERSION','93.0.11-1~deb12u1'))[0].version,'93.0.11-1~deb12u1')
        with self.assertRaises(ValueError): watch('93.0.11-1~deb12u1',osv=[])

    def test_t8_dotted_osv_watch_rejects_tilde_constraint(self):
        text = TEXT.replace('VERSION', '1.0~rc1').replace('scheme="debian"', 'scheme="dotted"')
        with self.assertRaisesRegex(watchlist.WatchlistError, 'version constraint is invalid'):
            watchlist.load_watchlist_text(text)

    def test_t8_reload_restore_and_startup_selection(self):
        helper = f3a.F3aTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        e = helper.engine
        first = replace(helper.watch,osv=watch().osv); second = replace(helper.watch,id='second')
        e.reload_watches((first,second))
        helper.put()
        edited = replace(first,osv=watch(osv=[dict(SELECTOR,ecosystem='Debian:13')]).osv)
        with patch.object(e,'_rematch_record') as rematch: e.reload_watches((edited,second))
        self.assertTrue(rematch.called)
        self.assertTrue(all(c.kwargs['watches']==(edited,) for c in rematch.call_args_list))
        with patch.object(Engine,'reload_watches') as reload:
            Engine(helper.store,(edited,second),e.aliases,e.config,helper.clock,e.notifier)
            reload.assert_not_called()
        observed=[]; original=Engine.reload_watches
        def inspect(instance,watches,**kw):
            observed.append({w.id:w.osv for w in instance.watches})
            return original(instance,watches,**kw)
        with patch.object(Engine,'reload_watches',inspect),patch.object(Engine,'_rematch_record') as rematch:
            Engine(helper.store,(edited,replace(second,name='Edited')),e.aliases,e.config,helper.clock,e.notifier)
        self.assertEqual(observed,[{edited.id:edited.osv,second.id:()}])
        selected=[tuple(w.id for w in c.kwargs['watches']) for c in rematch.call_args_list]
        bare=(replace(edited,osv=()),second)
        helper.store.set_meta('applied_watches',Engine._canonical_watches(bare))
        with patch.object(Engine,'_rematch_record') as rematch:
            Engine(helper.store,(bare[0],replace(second,name='Edited')),e.aliases,e.config,helper.clock,e.notifier)
        self.assertTrue(selected)
        self.assertEqual(selected,[tuple(w.id for w in c.kwargs['watches']) for c in rematch.call_args_list])

    def test_t9_canonical_received_literals_guard(self):
        watches=watchlist.load_watchlist_text((ROOT/'tests/fixtures/watchlist_example.toml').read_text())
        self.assertEqual(Engine._canonical_watches(watches),task3.EXAMPLE_CANONICAL)
        selected=watchlist._watch(dict(id='w',name='Widget',match=['examplecorp:widget'],version='1',scheme='opaque',github=[dict(repository='examplecorp/widget',ecosystem='other',package='Widget')]))
        self.assertEqual(Engine._canonical_watches([selected]),task3.GITHUB_CANONICAL)
        self.assertEqual(Engine._canonical_watches([replace(selected,github=(),platform=('examplecorp','host'))]),PLATFORM_CANONICAL)

    def test_t9_osv_canonical_and_source_predicate(self):
        encoded=json.loads(Engine._canonical_watches([watch(osv=[dict(SELECTOR,ecosystem='Debian:13'),SELECTOR])]))
        self.assertEqual(encoded[0]['osv'],[SELECTOR,dict(SELECTOR,ecosystem='Debian:13')])
        row=dict(release=None,platform=None,source='fixture',package='osv-selector:Debian#pkg',status='known_affected',range=None,scheme='debian',provenance='{}')
        ordinary=watchlist._watch(dict(id='w',name='Ordinary',match=['osv-selector:Debian#pkg'],version='1',scheme='debian'))
        verdict=advisory.cnascope.ScopedVerdict(None,'osv-selector:debian#pkg',None,'debian',State.NOT_AFFECTED,True,'test','high')
        self.assertTrue(advisory.same_scope(row,verdict,self.aliases,()))
        self.assertFalse(advisory.osv_row(row))
        self.assertEqual(advisory.evaluate_row(row,ordinary,self.aliases),State.AFFECTED)
        row['source']='debian'; self.assertTrue(advisory.osv_row(row))
        self.assertIsNone(advisory.evaluate_row(row,ordinary,self.aliases))

    def test_t9_debian_source_ordinary_package_uses_ordinary_range(self):
        row = dict(release=None, platform=None, source='debian', package='examplecorp:widget',
            status='known_affected', range=json.dumps(dict(introduced='1', limit='3')),
            scheme='debian', provenance='{}')
        ordinary = watch('2', osv=[])
        self.assertEqual(advisory.evaluate_row(row, ordinary, self.aliases), State.AFFECTED)
        self.assertEqual(advisory.evaluate_row(dict(row, source='fixture'), ordinary, self.aliases), State.AFFECTED)

    def test_t9_existing_guards(self):
        for method in ['test_t9_ordinary_github_microsoft_frozen_guards','test_t7_cna_override_scope_and_microsoft_guard','test_t7_fix_scope_partition_and_relationship_remediation']:
            case=task3.Task3ATests(method); result=unittest.TestResult(); case.run(result)
            self.assertEqual(result.errors+result.failures,[])

    def test_t12_date_map_process_resume_rebaseline(self):
        r=synthetic(versions=['1']); r.pop('published')
        self.put(r)
        self.assertIsNone(json.loads(self.db.execute('SELECT json FROM advisories').fetchone()[0])['published'])
        # A staged container survives a crash before pass two; resume validates afresh.
        r['id']='DEBIAN-CVE-2099-80999'
        self.persistence.stage_members('debian','debian/advisories',[self.mapped(r)],T)
        restored=AdapterStore(self.store,self.tmp.name)
        restored.resume(T,source='debian')
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM advisories WHERE source_id=?",(r['id'],)).fetchone())
        r['id']='DEBIAN-CVE-2099-80998'
        restored.stage_members('debian','debian/advisories',[self.mapped(r)],T)
        restored.rebaseline('debian',T)
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM advisories WHERE source_id=?',(r['id'],)).fetchone())
        shells=[]
        malformed=self.mapped(dict(r,id='DEBIAN-CVE-2099-80997'))
        malformed['evidence'][0]['status']='invalid'
        observing=AdapterStore(self.store,self.tmp.name,on_unknown=shells.append)
        body=json.dumps({'advisories':[malformed]})
        self.assertEqual(observing.process('debian',[dict(path='debian/advisories',status=200,body=body)],T),'PARTIAL')
        self.assertEqual([s['source_id'] for s in shells],['DEBIAN-CVE-2099-80997'])
        self.assertIsNone(shells[0]['published'])
        for source in ['msrc','cisco','github','fixture']:
            self.put(r,source=source,expected='PARTIAL')
            self.assertIsNone(self.db.execute('SELECT 1 FROM advisories WHERE source=?',(source,)).fetchone())
        case=task3.Task3ATests('test_t9_ordinary_github_microsoft_frozen_guards'); result=unittest.TestResult(); case.run(result)
        self.assertEqual(result.errors+result.failures,[])
        case=task3b.Task3B1Tests('test_t12_microsoft_literals'); result=unittest.TestResult(); case.run(result)
        self.assertEqual(result.errors+result.failures,[])


if __name__ == '__main__':
    unittest.main()

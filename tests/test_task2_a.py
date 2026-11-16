# script-purpose: Verify pure CSAF normalization and watch scheme evaluation offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task2_a.py
"""Read invented CSAF and frozen replay fixtures; write temporary SQLite databases.

Run PYTHONPATH=src python3 -m unittest tests.test_task2_a -v; exit 0/1.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from cornicen import advisory, feedvalidate, watchlist
from cornicen.adapterstore import AdapterStore
from cornicen.applicability import State
from cornicen.identity import AliasMap
from cornicen.store import Store
from tests.test_f1 import T, member
from tests import test_f3a as f3a

ROOT = Path(__file__).resolve().parents[1]
A = 'CVE-2099-71001'
B = 'CVE-2099-71002'
PACKAGE = 'microsoft:contoso sample agent for windows'


def fixture():
    return json.loads((ROOT / 'tests/fixtures/msrc/advisory_sample.json').read_text())


def normalise(document):
    from cornicen.csaf import normalise
    return normalise(document, path='2099/msrc_cve-2099-71001.json',
                     directory_url='https://msrc.microsoft.com/csaf/advisories')


def watch(version='9.4.1200.7', scheme='dotted', **kw):
    return watchlist._watch(dict(id='w', name='Contoso Sample Agent', match=[PACKAGE],
                                 version=version, scheme=scheme) | kw)


def leaf(document, text, category='product_version_range'):
    branch = document['product_tree']['branches'][0]['branches'][0]['branches'][0]
    branch['name'] = text
    branch['category'] = category


class Task2ATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.persistence = AdapterStore(self.store, self.tmp.name)
        self.aliases = AliasMap.load(False)

    def put(self, document=None):
        raw = normalise(document if document is not None else fixture())
        validated = feedvalidate.validate_advisory(raw, source='msrc', observed_at=T)
        self.persistence.reconcile_required('msrc', ['sample'], T)
        self.assertEqual(self.persistence.process('msrc', [dict(path='sample', status=200,
            body=json.dumps({'advisories': [raw]}))], T), 'COMPLETE')
        return validated.data

    def result(self, version='9.4.1200.7', scheme='dotted', identity=A, **kw):
        return advisory.resolve(self.db, identity, watch(version, scheme), self.aliases, **kw)

    def test_t1_fixture_normalisation(self):
        from cornicen.csaf import index_products
        raw = normalise(fixture())
        self.assertEqual(raw['id'], 'msrc_CVE-2099-71001')
        self.assertEqual(set(index_products(fixture())), {'1', '12013'})
        self.assertEqual([(p['id'], p['name']) for p in raw['products']],
            [('1', 'Microsoft:Contoso Sample Agent for Windows'), ('12013', 'Microsoft:Contoso Sample Agent for Windows')])
        self.assertEqual(raw['products'][1]['version'], '9.4.1200.8')
        facet = raw['facets'][0]
        self.assertEqual(facet['cve'], A)
        self.assertNotIn('number', facet)
        self.assertEqual(facet['evidence'][0]['fix'], 'available')
        self.assertEqual(facet['evidence'][0]['range'], {'csaf': '<9.4.1200.8'})
        self.assertTrue(all(e['scheme'] == 'opaque' and e['binding'] == 'watch' for e in facet['evidence']))
        data = self.put()
        self.assertEqual(data['published'], '2026-10-13T07:00:00.000Z')
        self.assertEqual(data['updated'], '2026-11-02T08:00:00.000Z')
        self.assertEqual(data['observed_at'], T)
        self.assertNotIn('observed_at', raw)
        self.assertEqual(raw['url'], 'https://msrc.microsoft.com/update-guide/vulnerability/' + A)
        doc = fixture(); doc['document']['references'] = []
        self.assertEqual(normalise(doc)['url'], 'https://msrc.microsoft.com/csaf/advisories/2099/msrc_cve-2099-71001.json')
        doc['document']['references'] = [dict(category='self', url='https://examplecorp.invalid/sample.json')]
        self.assertEqual(normalise(doc)['url'], 'https://examplecorp.invalid/sample.json')

    def test_t2_watch_binding(self):
        self.put()
        for version, state in [('9.4.1200.7', State.AFFECTED), ('9.4.1200.8', State.NOT_AFFECTED), ('9.4.1200.9', State.UNKNOWN)]:
            self.assertEqual(self.result(version).state, state)
        self.assertEqual(advisory.fix_for(self.db, A, watch(), self.aliases), '9.4.1200.8')
        self.assertEqual(self.result(scheme='opaque').state, State.UNKNOWN)
        doc = fixture(); doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['1']}
        self.put(doc)
        self.assertEqual(self.result('9.4.1200.9').state, State.UNKNOWN)
        self.assertNotIn('msrc:', self.result('9.4.1200.9').evidence)
        self.assertEqual(advisory.route(self.db, A, watch('9.4.1200.9'), self.aliases), 'advisory')
        for scheme, bound, version in [('semver', '<1.2.3', '1.2.2'), ('python', '<2.0.0', '1.9.0')]:
            leaf(doc, bound); self.put(doc)
            self.assertEqual(self.result(version, scheme).state, State.AFFECTED)
        leaf(doc, '1.2', 'product_version')
        doc['vulnerabilities'][0]['product_status']['known_not_affected'] = ['12013']
        doc['product_tree']['branches'][0]['branches'][0]['branches'][1]['name'] = '1.2.0'
        self.put(doc)
        self.assertEqual(self.result('1.2.0').state, State.UNKNOWN)
        self.assertIn('msrc: unknown', self.result('1.2.0').evidence)
        self.assertEqual(self.result('1.2').state, State.AFFECTED)
        self.assertEqual(self.result('1.2', 'opaque').state, State.AFFECTED)
        self.assertEqual(advisory.resolve(self.db, A, watch(match=['examplecorp:other']), self.aliases).state, State.UNKNOWN)

    def test_t3_range_grammar(self):
        doc = fixture(); doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['1']}
        for text, version, expected in [('<2', '1', State.AFFECTED), ('<= 2', '2', State.AFFECTED),
                ('>=1 <2', '1', State.AFFECTED), ('>= 1  <= 2', '2', State.AFFECTED),
                ('>=1 <2', '0', State.UNKNOWN), ('<2', '2', State.UNKNOWN),
                *[(t, '1', State.UNKNOWN) for t in ('vers:generic/<1', '<1 || >2', '>1', '= 1', '<nope', '>=2 <1', '>=1 <1', '>=1 <=nope')]]:
            with self.subTest(text=text, version=version):
                leaf(doc, text); self.put(doc)
                self.assertEqual(self.result(version).state, expected)
                row = next(r for r in advisory.rows_for(self.db, A) if json.loads(r['provenance'])['product_id'] == '1')
                vote = advisory.evaluate_row(row, watch(version), self.aliases)
                if text == '>=1 <2' and version == '0' or text == '<2' and version == '2':
                    self.assertIs(vote, advisory.ABSTAIN)
                else:
                    self.assertEqual(vote, expected)
        leaf(doc, '<2'); self.put(doc)
        self.assertEqual(self.result('>=1, <2').state, State.UNKNOWN)
        self.assertEqual(advisory.resolve(self.db, A, watch('1', product_only=['contoso sample agent for windows'], match=[]), self.aliases).state, State.UNKNOWN)

    def test_watch_binding_requires_csaf_source(self):
        self.put()
        row = dict(advisory.rows_for(self.db, A)[0])
        row.update(range=None, status='known_affected')
        provenance = json.loads(row['provenance'])
        provenance['product_version'] = None
        row['provenance'] = json.dumps(provenance)
        for source in ('msrc', 'cisco'):
            with self.subTest(source=source):
                row['source'] = source
                self.assertTrue(advisory._watch_bound(row))
                self.assertEqual(advisory.evaluate_row(row, watch(), self.aliases), State.AFFECTED)
        row['source'] = 'fixture_a'
        ordinary = dict(row)
        provenance['evidence'].pop('binding')
        ordinary['provenance'] = json.dumps(provenance)
        self.assertFalse(advisory._watch_bound(row))
        for scheme, expected in [('dotted', State.UNKNOWN), ('opaque', State.AFFECTED)]:
            with self.subTest(scheme=scheme):
                w = watch(scheme=scheme)
                self.assertEqual(advisory.evaluate_row(ordinary, w, self.aliases), expected)
                self.assertEqual(advisory.evaluate_row(row, w, self.aliases), expected)

    def test_watch_binding_non_dict_evidence(self):
        for evidence in (None, [], ['watch'], 'watch', 1, True):
            with self.subTest(evidence=evidence):
                row = dict(source='msrc', provenance=json.dumps(dict(evidence=evidence)))
                self.assertFalse(advisory._watch_bound(row))

    def test_product_level_range_watch_guard(self):
        doc = fixture()
        leaf(doc, 'edition', 'service_pack')
        doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['1']}
        self.put(doc)
        row = advisory.rows_for(self.db, A)[0]
        self.assertIsNone(row['range'])
        self.assertIsNone(json.loads(row['provenance'])['product_version'])
        self.assertEqual(self.result('1').state, State.AFFECTED)
        self.assertEqual(advisory.evaluate_row(row, watch('<2'), self.aliases), State.UNKNOWN)
        self.assertEqual(self.result('<2').state, State.UNKNOWN)

    def test_t4_status_map(self):
        for status, expected in [('known_affected', 'known_affected'), ('known_not_affected', 'known_not_affected'),
                ('fixed', 'first_fixed'), ('first_fixed', 'first_fixed'), ('under_investigation', 'under_investigation'),
                ('recommended', None), ('last_affected', None)]:
            with self.subTest(status=status):
                doc = fixture(); doc['vulnerabilities'][0]['remediations'] = []
                doc['vulnerabilities'][0]['product_status'] = {status: ['12013']}
                raw = normalise(doc); evidence = raw['facets'][0]['evidence']
                self.assertEqual([e['status'] for e in evidence], [expected] if expected else [])
                if status in ('fixed', 'first_fixed'):
                    self.assertEqual(evidence[0]['fix'], '9.4.1200.8')
                self.put(doc)
        doc['vulnerabilities'][0]['product_status'] = dict(known_affected=['12013'], fixed=['12013'])
        e = normalise(doc)['facets'][0]['evidence'][0]
        self.assertEqual((e['status'], e['diagnostic']), ('known_affected', 'contradictory status'))
        # A leaf of another category asserts the entire product.
        leaf(doc, 'edition', 'service_pack'); doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['1']}
        self.put(doc)
        self.assertEqual(self.result().state, State.AFFECTED)

    def test_t5_scoped_group_fix(self):
        doc = fixture()
        doc['product_tree']['product_groups'] = [dict(group_id='g', product_ids=['1'])]
        doc['vulnerabilities'][0]['remediations'] = [dict(category='vendor_fix', group_ids=['g'], details='Never parse 99.0')]
        second = deepcopy(doc['vulnerabilities'][0]); second['cve'] = B; second['remediations'] = []
        second['product_status'] = {'known_affected': ['1']}
        doc['vulnerabilities'].append(second)
        raw = normalise(doc)
        self.assertNotIn('remediations', raw)
        self.assertEqual(raw['facets'][0]['evidence'][0]['fix'], 'available')
        self.assertNotIn('fix', raw['facets'][1]['evidence'][0])
        self.put(doc)
        self.assertIsNone(advisory.fix_for(self.db, B, watch(), self.aliases))
        self.assertEqual(advisory.fix_for(self.db, A, watch(), self.aliases), '9.4.1200.8')

    def test_t6_mapping_errors_quarantine(self):
        mutations = []
        doc = fixture(); doc['vulnerabilities'][0]['product_status']['known_affected'] = ['missing']; mutations.append(doc)
        doc = fixture(); doc['vulnerabilities'][0]['remediations'][0]['group_ids'] = ['missing']; mutations.append(doc)
        doc = fixture(); doc['vulnerabilities'][0]['remediations'][0]['product_ids'] = ['missing']; mutations.append(doc)
        doc = fixture(); doc['product_tree']['product_groups'] = [dict(group_id='g', product_ids=['missing'])]; mutations.append(doc)
        relation = dict(category='installed_on', product_reference='1', relates_to_product_reference='missing', full_product_name=dict(product_id='r', name='combined'))
        doc = fixture(); doc['product_tree']['relationships'] = [relation]; mutations.append(doc)
        doc = fixture(); doc['product_tree']['relationships'] = [relation | dict(product_reference='r', relates_to_product_reference='1')]; mutations.append(doc)
        doc = fixture(); doc['document']['tracking']['status'] = 'draft'; mutations.append(doc)
        for key in ('initial_release_date', 'current_release_date'):
            doc = fixture(); doc['document']['tracking'][key] = '2026-11-02T08:00:00'; mutations.append(doc)
        doc = fixture(); doc['product_tree']['branches'][0]['name'] = 'Microsoft:Other'; mutations.append(doc)
        for doc in mutations:
            with self.subTest(document=doc):
                raw = normalise(doc)
                self.assertIn('mapping_error', raw)
                self.persistence.reconcile_required('msrc', ['sample'], T)
                self.assertEqual(self.persistence.process('msrc', [dict(path='sample', status=200,
                    body=json.dumps({'advisories': [raw]}))], T), 'PARTIAL')
                self.assertGreater(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 0)
        for malformed in (None, [], {}, {'document': []}, {'product_tree': None}):
            self.assertIn('mapping_error', normalise(malformed))

    def test_t7_unresolved_products(self):
        doc = fixture()
        doc['product_tree']['full_product_names'] = [dict(product_id='p', name='Invented Bundle')]
        doc['product_tree']['relationships'] = [dict(category='installed_on', product_reference='p', relates_to_product_reference='1', full_product_name=dict(product_id='r', name='Invented Combined')),
            dict(category='installed_on', product_reference='r', relates_to_product_reference='12013', full_product_name=dict(product_id='nested', name='Invented Nested'))]
        doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['p', 'r', 'nested']}
        doc['vulnerabilities'][0]['remediations'] = []
        self.put(doc)
        for package in (PACKAGE, 'csaf-unresolved:p', 'csaf-unresolved:r', 'csaf-unresolved:nested'):
            w = watch(match=[package])
            self.assertEqual(advisory.resolve(self.db, A, w, self.aliases).state, State.UNKNOWN)
            self.assertEqual(advisory.matching_rows(self.db, A, w, self.aliases), [])
            self.assertIsNone(advisory.fix_for(self.db, A, w, self.aliases))
        self.assertEqual({p['name'] for p in normalise(doc)['products'] if p['id'] in ('p', 'r', 'nested')}, {'csaf-unresolved:p', 'csaf-unresolved:r', 'csaf-unresolved:nested'})

    def test_t8_facet_reordering(self):
        doc = fixture(); second = deepcopy(doc['vulnerabilities'][0]); second['cve'] = B
        doc['vulnerabilities'].append(second); self.put(doc)
        def numbers():
            return {r['identity']: r['facet'] for r in self.db.execute('SELECT * FROM advisory_evidence')}
        before = numbers(); self.assertEqual(set(before), {A, B})
        doc['vulnerabilities'].reverse(); self.put(doc)
        self.assertEqual(numbers(), before)

    def test_t9_ordinary_and_github_guards(self):
        raw = member() | dict(products=[dict(id='p', name='csaf-unresolved:p')], cves=[A],
            evidence=[dict(product_id='p', scheme='dotted', status='known_affected')])
        data = feedvalidate.validate_advisory(raw, source='fixture_a', observed_at=T).data
        advisory.write_evidence(self.db, data)
        self.assertEqual(advisory.resolve(self.db, A, watch(match=['csaf-unresolved:p']), self.aliases).state, State.AFFECTED)
        from tests.test_f4 import F4Tests
        F4Tests('test_v1_replays_unchanged').test_v1_replays_unchanged()
        from tests.test_task1_b1 import B1Tests
        case = B1Tests('test_selector_scope'); case.setUp()
        try:
            case.test_selector_scope()
        finally:
            case.doCleanups()

    def test_t22_fix_selection_and_cna_scope(self):
        doc = fixture()
        branches = doc['product_tree']['branches'][0]['branches'][0]['branches']
        for pid, version in [('old', '9.4.1200.2'), ('bad', 'malformed')]:
            branches.append(dict(category='product_version', name=version, product=dict(product_id=pid, name='Invented fixed version')))
        doc['vulnerabilities'][0]['product_status']['fixed'] += ['old', 'bad']
        self.put(doc)
        self.assertEqual(advisory.fix_for(self.db, A, watch(), self.aliases), '9.4.1200.8')
        self.assertIsNone(advisory.fix_for(self.db, A, watch('9.4.1200.8'), self.aliases))
        # Use the existing CNA record builder, adapting its invented identity and range.
        record = f3a.F3aTests().cna('unaffected')
        record['cveMetadata']['cveId'] = A
        entry = record['containers']['cna']['affected'][0]
        entry.update(vendor='Microsoft', product='Contoso Sample Agent for Windows')
        entry['versions'] = [dict(version='9.4.1200.7', versionType='dotted', status='unaffected')]
        self.assertEqual(self.result(record=record).state, State.NOT_AFFECTED)
        self.assertIn('msrc: affected', self.result(record=record).evidence)

    def test_t22_mutually_indeterminate_eligible_fixes(self):
        doc = fixture(); leaf(doc, '<2')
        branches = doc['product_tree']['branches'][0]['branches'][0]['branches']
        branches[1]['name'] = '1.1'
        for pid, version in [('second', '1.2'), ('third', '1.2.0')]:
            branches.append(dict(category='product_version', name=version,
                product=dict(product_id=pid, name='Invented fixed version')))
        doc['vulnerabilities'][0]['product_status']['fixed'] += ['second', 'third']
        self.put(doc)
        self.assertIsNone(advisory.compare('1.2', '1.2.0', watch().scheme))
        self.assertEqual(advisory.fix_for(self.db, A, watch('1.0'), self.aliases), 'available')
        print('R5 probe: watch=1.0 fixes=1.1,1.2,1.2.0 compare=None fix=available')

    def test_bound_fix_skips_nonmatching_product(self):
        doc = fixture()
        product_branch = doc['product_tree']['branches'][0]['branches'][0]
        other = deepcopy(product_branch)
        other['name'] = 'Contoso Other Agent for Windows'
        other['branches'] = [dict(category='product_version', name='9.4.1200.7',
            product=dict(product_id='other', name='Invented other fixed version'))]
        doc['product_tree']['branches'][0]['branches'].append(other)
        doc['vulnerabilities'][0]['product_status']['fixed'].append('other')
        self.put(doc)
        rows = advisory.rows_for(self.db, A)
        affected = next(r for r in rows if r['status'] == 'known_affected')
        fix = next(r for r in rows if r['fix'] == '9.4.1200.7')
        self.assertEqual((fix['source'], fix['source_id'], fix['facet']),
                         (affected['source'], affected['source_id'], affected['facet']))
        w = watch('9.4.1200.6')
        self.assertEqual(advisory.evaluate_row(affected, w, self.aliases), State.AFFECTED)
        self.assertIsNone(advisory.evaluate_row(fix, w, self.aliases))
        self.assertEqual(advisory.fix_for(self.db, A, w, self.aliases), '9.4.1200.8')

# script-purpose: Verify Cisco CSAF policies, relationship scope and watch platforms offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task3_a.py
"""Read invented CSAF fixtures; write temporary SQLite databases under the repository.

Run PYTHONPATH=src python3 -m unittest tests.test_task3_a -v; exit 0/1.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen import advisory, csaf, feedvalidate, public_text, watchlist
from cornicen.adapterstore import AdapterStore
from cornicen.applicability import State
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.store import Store
from tests.test_f1 import T
from tests import test_f3a as f3a
from tests import test_task2_a as task2

ROOT = Path(__file__).resolve().parents[1]
A = 'CVE-2099-72001'
COMPONENT = 'CSAFPID-286755'
GATEWAY = 'CSAFPID-277395'
PLATFORM = dict(vendor='cisco', product='contoso sample relay gateway')
EXAMPLE_CANONICAL = '[{"eol":false,"id":"nas","match":[["examplecorp","examplenas_os"]],"name":"File server","product_only":["examplenas os"],"scheme":"opaque","version":"4.0.0-example"},{"eol":false,"id":"proxy","match":[["f5","nginx"],["nginx","nginx"]],"name":"Reverse proxy","product_only":[],"scheme":"semver","version":"1.25.3"},{"eol":true,"id":"router","match":[["openwrt","openwrt"]],"name":"Edge router","product_only":[],"scheme":"dotted","version":"21.02.7"}]'
GITHUB_CANONICAL = '[{"eol":false,"github":[{"ecosystem":"other","package":"Widget","repository":"examplecorp/widget"}],"id":"w","match":[["examplecorp","widget"]],"name":"Widget","product_only":[],"scheme":"opaque","version":"1"}]'


def fixture(repaired=True):
    document = json.loads((ROOT / 'tests/fixtures/cisco/advisory_sample.json').read_text())
    if repaired:
        vulnerability = document['vulnerabilities'][0]
        vulnerability['product_status']['known_affected'].remove('CSAFPID-189790')
        for remediation in vulnerability['remediations']:
            if 'CSAFPID-189790' in remediation.get('product_ids', []):
                remediation['product_ids'].remove('CSAFPID-189790')
    return document


def normalise(document, microsoft=False):
    # Fall back on the received API to expose semantic failures in pristine runs.
    policy = {} if microsoft or not hasattr(csaf, 'CISCO') else dict(policy=csaf.CISCO)
    return csaf.normalise(document, path='2099/sample.json',
                          directory_url='https://examplecorp.invalid/csaf/', **policy)


def watch(version='93.0.0-392', **kw):
    return watchlist._watch(dict(id='w', name='Sample relay', match=['cisco:contoso sample relay'],
                                 version=version, scheme='opaque') | kw)


def relationship(pid, component=COMPONENT, platform=GATEWAY, category='installed_on'):
    return dict(category=category, product_reference=component, relates_to_product_reference=platform,
                full_product_name=dict(product_id=pid, name='Invented combined product'))


def branch(pid, name, category='product_name', children=None):
    return dict(category=category, name=name, product=dict(product_id=pid, name='Invented product'),
                branches=children or [])


def synthetic():
    document = fixture()
    document['product_tree'] = dict(branches=[dict(category='vendor', name='Cisco', branches=[
        dict(category='product_family', name='Contoso Sample Relay', branches=[
            branch(COMPONENT, '1', 'product_version'), branch('fixed', '2', 'product_version'),
            branch('plain', 'Contoso Sample Relay')]),
        branch(GATEWAY, 'Contoso Sample Relay Gateway'), branch('other', 'Other Gateway')])],
        relationships=[relationship('r')])
    document['vulnerabilities'][0]['product_status'] = dict(known_affected=['r'])
    document['vulnerabilities'][0]['remediations'] = []
    return document


class Task3ATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.persistence = AdapterStore(self.store, self.tmp.name)
        self.aliases = AliasMap.load(False)

    def put(self, document, expected='COMPLETE'):
        raw = normalise(document)
        if expected == 'COMPLETE':
            feedvalidate.validate_advisory(raw, source='cisco', observed_at=T)
        self.persistence.reconcile_required('cisco', ['sample'], T)
        self.assertEqual(self.persistence.process('cisco', [dict(path='sample', status=200,
            body=json.dumps({'advisories': [raw]}))], T), expected)
        return advisory.rows_for(self.db, A)

    def result(self, w, **kw):
        return advisory.resolve(self.db, A, w, self.aliases, **kw).state

    def fix(self, w):
        return advisory.fix_for(self.db, A, w, self.aliases)

    def run_guard(self, name):
        case = task2.Task2ATests(name)
        with redirect_stdout(io.StringIO()):
            case.setUp()
            try:
                getattr(case, name)()
            finally:
                case.doCleanups()

    def test_t1_fixture_and_dangling_quarantine(self):
        self.assertEqual(normalise(fixture(False)), dict(id='cisco-sa-sample-relay-2099a',
                                                       mapping_error='dangling product reference'))
        self.put(fixture(False), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 1)
        raw = normalise(fixture())
        products = {p['id']: p for p in raw['products']}
        self.assertEqual(products[COMPONENT], dict(id=COMPONENT, name='Cisco:Contoso Sample Relay', version='93.0.0-392'))
        self.assertEqual(products[GATEWAY], dict(id=GATEWAY, name='Cisco:Contoso Sample Relay Gateway'))
        self.assertEqual(len(raw['facets']), 1)
        facet = raw['facets'][0]
        self.assertEqual(facet['cve'], A)
        self.assertEqual(len(facet['evidence']), 23)
        self.assertTrue(all(e['status'] == 'known_affected' and e['fix'] == 'available'
                            and 'relationship' not in e for e in facet['evidence']))
        self.assertTrue(raw['url'].startswith('https://sec.cloudapps.cisco.com/'))
        self.assertEqual(len(self.put(fixture())), 23)

    def test_t2_policy_switches(self):
        self.assertEqual(csaf.MICROSOFT, csaf.NormalisationPolicy())
        with self.assertRaises(AttributeError):
            csaf.CISCO.family_names = False
        document = synthetic()
        family = document['product_tree']['branches'][0]['branches'][0]
        family['branches'] = [dict(category='product_name', name='Preferred component', branches=[
            branch(COMPONENT, '1.0', 'service_pack')])]
        document['product_tree']['relationships'] = []
        document['vulnerabilities'][0]['product_status'] = dict(known_affected=[COMPONENT])
        products = csaf.index_products(document, policy=csaf.CISCO)
        self.assertEqual(products[COMPONENT]['name'], 'Cisco:Preferred component')
        self.assertEqual(products[COMPONENT]['version'], '1.0')
        family['branches'] = [dict(category='product_version', name='intermediate', branches=[
            branch(COMPONENT, 'leaf', 'product_name')])]
        self.assertNotIn('version', csaf.index_products(document, policy=csaf.CISCO)[COMPONENT])
        # Each switch is independent, and relationship metadata never leaks into products.
        document = synthetic()
        family_only = csaf.NormalisationPolicy(family_names=True)
        products = csaf.index_products(document, policy=family_only)
        self.assertEqual(products[COMPONENT]['name'], 'Cisco:Contoso Sample Relay')
        self.assertEqual(products['r']['name'], 'csaf-unresolved:r')
        self.assertTrue(all('relationship' not in p for p in normalise(document)['products']))

    def test_t2_default_normalisation_digest_guards(self):
        for document, expected in [
            (json.loads((ROOT / 'tests/fixtures/msrc/advisory_sample.json').read_text()),
             'ec6e14bc94a2801d05ad67127df844116caebee908f674df55e925e8fb4c10fb'),
            (fixture(), '8f8b5683c6d664741a83dc7d5273b63f9a0d10994579588d9833b2162ca1044b')]:
            encoded = json.dumps(normalise(document, microsoft=True), sort_keys=True, separators=(',', ':')).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected)
        self.run_guard('test_product_level_range_watch_guard')
        self.run_guard('test_t4_status_map')

    def test_t3_direct_rows_ignore_platform(self):
        rows = self.put(fixture())
        self.assertEqual(len(rows), 23)
        self.assertTrue(all(r['platform'] is None for r in rows))
        for version, expected in [('93.0.0-392', State.AFFECTED), ('93.0.5-007', State.AFFECTED),
                                  ('93.0.0-391', State.UNKNOWN)]:
            for platform in ({}, dict(platform=PLATFORM), dict(platform=PLATFORM | dict(product='other'))):
                with self.subTest(version=version, platform=platform):
                    w = watch(version, **platform)
                    self.assertEqual(self.result(w), expected)
                    self.assertEqual(self.fix(w), 'available' if expected == State.AFFECTED else None)

    def test_t4_relationship_only_votes(self):
        document = fixture()
        relations = document['product_tree']['relationships']
        document['vulnerabilities'][0]['product_status'] = dict(known_affected=[r['full_product_name']['product_id'] for r in relations])
        rows = self.put(document)
        self.assertEqual(len(rows), 23)
        self.assertTrue(all(r['platform'] is None and r['fix'] is None for r in rows))
        equal = watch(platform=PLATFORM)
        omitted = watch()
        different = watch(platform=PLATFORM | dict(product='other'))
        self.assertEqual(self.result(equal), State.AFFECTED)
        self.assertIsNone(self.fix(equal))
        self.assertEqual(self.result(omitted), State.UNKNOWN)
        self.assertEqual(self.result(different), State.UNKNOWN)
        row = next(r for r in rows if json.loads(r['provenance'])['product_version'] == equal.version)
        self.assertIs(advisory.evaluate_row(row, different, self.aliases), advisory.ABSTAIN)
        self.assertEqual(advisory.evaluate_row(row, omitted, self.aliases), State.UNKNOWN)
        self.assertEqual(self.result(watch('93.0.0-391', platform=PLATFORM)), State.UNKNOWN)
        self.assertEqual(advisory.route(self.db, A, different, self.aliases), 'advisory')
        document['vulnerabilities'][0]['product_status']['known_not_affected'] = [COMPONENT]
        self.put(document)
        self.assertEqual(self.result(different), State.NOT_AFFECTED)
        self.assertEqual(self.result(omitted), State.UNKNOWN)
        self.assertEqual(self.result(equal), State.AFFECTED)

    def test_t5_recursive_and_unsupported_scopes(self):
        document = synthetic()
        vendor = document['product_tree']['branches'][0]
        vendor['branches'].append(branch('equivalent', '  CONTOSO Sample Relay Gateway  '))
        document['product_tree']['relationships'].append(relationship('nested', component='r', platform='equivalent'))
        document['vulnerabilities'][0]['product_status'] = dict(known_affected=['nested'])
        rows = self.put(document)
        relation = json.loads(rows[0]['provenance'])['evidence']['relationship']
        self.assertEqual(relation, dict(category='installed_on', platform='Cisco:Contoso Sample Relay Gateway'))
        self.assertEqual(self.result(watch('1', platform=PLATFORM)), State.AFFECTED)
        mutations = []
        d = deepcopy(document); d['product_tree']['relationships'][1]['relates_to_product_reference'] = 'other'; mutations.append(('distinct', d, 'installed_on', False))
        d = deepcopy(document); d['product_tree']['relationships'][0]['category'] = 'optional_component_of'; mutations.append(('category', d, 'optional_component_of', False))
        d = deepcopy(document); d['product_tree']['relationships'][0]['product_reference'] = 'plain'; mutations.append(('versionless', d, 'installed_on', True))
        for label, d, category, versionless in mutations:
            with self.subTest(case=label):
                rows = self.put(d)
                self.assertEqual(len(rows), 1)
                self.assertEqual(json.loads(rows[0]['provenance'])['evidence']['relationship'], dict(category=category))
                self.assertEqual(self.result(watch('1', platform=PLATFORM)), State.UNKNOWN)
                expected = State.UNKNOWN if versionless else advisory.ABSTAIN
                self.assertIs(advisory.evaluate_row(rows[0], watch('2', scheme='dotted', platform=PLATFORM), self.aliases), expected)
                self.assertEqual(self.result(watch('2', scheme='dotted', platform=PLATFORM)), State.UNKNOWN)
        d = synthetic(); d['product_tree']['full_product_names'] = [dict(product_id='full', name='Invented component')]
        d['product_tree']['relationships'][0]['product_reference'] = 'full'
        rows = self.put(d)
        self.assertEqual(rows[0]['package'], 'csaf-unresolved:r')
        self.assertIsNone(advisory.evaluate_row(rows[0], watch('1', match=['csaf-unresolved:r']), self.aliases))
        for mutation, reason in [('r', 'relationship cycle'), ('missing', 'dangling product reference')]:
            d = synthetic(); d['product_tree']['relationships'][0]['product_reference'] = mutation
            self.assertEqual(normalise(d)['mapping_error'], reason)
            self.put(d, 'PARTIAL')

    def test_t5_platform_qualification_conditions(self):
        for label in ('versioned', 'range', 'nested-only'):
            with self.subTest(platform=label):
                document = synthetic()
                tree = document['product_tree']
                vendor = tree['branches'][0]
                if label == 'nested-only':
                    # A standalone full product has no branch ancestry, version or range.
                    vendor['branches'] = [b for b in vendor['branches']
                                          if b.get('product', {}).get('product_id') != GATEWAY]
                    tree['full_product_names'] = [dict(product_id=GATEWAY,
                        name='Cisco:Contoso Sample Relay Gateway')]
                else:
                    category = 'product_version' if label == 'versioned' else 'product_version_range'
                    name = '1' if label == 'versioned' else '>=1 <3'
                    vendor['branches'][1] = dict(category='product_name',
                        name='Contoso Sample Relay Gateway', branches=[branch(GATEWAY, name, category)])
                self.assertEqual(len(tree['relationships']), 1)
                rows = self.put(document)
                self.assertEqual(len(rows), 1)
                self.assertEqual(json.loads(rows[0]['provenance'])['evidence']['relationship'],
                                 dict(category='installed_on'))
                covered = watch('1', platform=PLATFORM)
                self.assertEqual(advisory.evaluate_row(rows[0], covered, self.aliases), State.UNKNOWN)
                self.assertEqual(self.result(covered), State.UNKNOWN)

                # Replace only the platform definition with a qualifying branch product.
                if label == 'nested-only':
                    del tree['full_product_names']
                    vendor['branches'].append(branch(GATEWAY, 'Contoso Sample Relay Gateway'))
                else:
                    vendor['branches'][1] = branch(GATEWAY, 'Contoso Sample Relay Gateway')
                rows = self.put(document)
                self.assertEqual(len(rows), 1)
                self.assertEqual(json.loads(rows[0]['provenance'])['evidence']['relationship'],
                                 dict(category='installed_on', platform='Cisco:Contoso Sample Relay Gateway'))
                self.assertEqual(advisory.evaluate_row(rows[0], covered, self.aliases), State.AFFECTED)
                self.assertEqual(self.result(covered), State.AFFECTED)

    def test_t5_relationship_range_and_vote_order(self):
        d = synthetic()
        b = d['product_tree']['branches'][0]['branches'][0]['branches'][0]
        b.update(category='product_version_range', name='>=1 <3')
        rows = self.put(d)
        self.assertEqual(self.result(watch('2', scheme='dotted', platform=PLATFORM)), State.AFFECTED)
        self.assertEqual(self.result(watch('2', scheme='dotted')), State.UNKNOWN)
        self.assertIs(advisory.evaluate_row(rows[0], watch('3', scheme='dotted', platform=PLATFORM), self.aliases), advisory.ABSTAIN)
        self.assertEqual(self.result(watch('>=1, <3', scheme='dotted', platform=PLATFORM)), State.UNKNOWN)
        self.assertIs(advisory.evaluate_row(rows[0], watch('>=1, <3', scheme='dotted', platform=PLATFORM | dict(product='other')), self.aliases), advisory.ABSTAIN)
        self.assertEqual(self.result(watch('2', scheme='dotted', match=[], product_only=['contoso sample relay'], platform=PLATFORM)), State.UNKNOWN)
        # Alias equivalence cannot turn a mismatched platform into a match.
        key = ('cisco', 'contoso sample relay gateway')
        other = ('cisco', 'other')
        self.aliases._links = {key: {other}, other: {key}}
        self.assertIs(advisory.evaluate_row(rows[0], watch('2', scheme='dotted', platform=PLATFORM | dict(product='other')), self.aliases), advisory.ABSTAIN)
        d['product_tree']['relationships'][0]['category'] = 'optional_component_of'
        rows = self.put(d)
        self.assertEqual(self.result(watch('2', scheme='dotted', platform=PLATFORM)), State.UNKNOWN)
        self.assertIs(advisory.evaluate_row(rows[0], watch('3', scheme='dotted', platform=PLATFORM), self.aliases), advisory.ABSTAIN)

        self.assertIsNone(advisory.evaluate_row(rows[0], watch('2', match=['cisco:other'], platform=PLATFORM), self.aliases))

    def test_t6_relationship_validation(self):
        raw = normalise(synthetic())
        for relationship_value in [dict(category='installed_on', platform='Cisco:Gateway'),
                                   dict(category='other'), dict(category='c'*64, platform='v:'+'p'*198)]:
            d = deepcopy(raw); d['facets'][0]['evidence'][0]['relationship'] = relationship_value
            feedvalidate.validate_advisory(d, source='cisco', observed_at=T)
        invalid = [None, [], 'installed_on', {}, dict(category=1), dict(category=''), dict(category=' '*2),
                   dict(category='c'*65), dict(category='x', extra=True),
                   *[dict(category='x', platform=p) for p in (None, 1, '', 'gateway', ':p', 'v:', 'v:p:q', 'v:'+'p'*199)]]
        for relationship_value in invalid:
            with self.subTest(relationship=relationship_value):
                d = deepcopy(raw); d['facets'][0]['evidence'][0]['relationship'] = relationship_value
                with self.assertRaises(ValueError):
                    feedvalidate.validate_advisory(d, source='cisco', observed_at=T)
                self.assertEqual(self.persistence.process('cisco', [dict(path='sample', status=200,
                    body=json.dumps({'advisories': [d]}))], T, required_resources=['sample']), 'PARTIAL')
        raw['facets'][0]['evidence'][0].pop('relationship', None)
        feedvalidate.validate_advisory(raw, source='cisco', observed_at=T)

    def test_t7_fix_scope_partition_and_relationship_remediation(self):
        d = synthetic()
        d['product_tree']['relationships'].append(relationship('rf', component='fixed', platform='other'))
        d['vulnerabilities'][0]['product_status']['first_fixed'] = ['rf']
        rows = self.put(d)
        w = watch('1', scheme='dotted', platform=PLATFORM)
        self.assertEqual(self.result(w), State.AFFECTED)
        self.assertEqual(len(rows), 2)
        self.assertIsNone(self.fix(w))
        # A direct investigation row has no relationship scope and cannot donate.
        d['vulnerabilities'][0]['product_status'] = dict(known_affected=['r'], under_investigation=[COMPONENT])
        d['vulnerabilities'][0]['remediations'] = [dict(category='vendor_fix', product_ids=[COMPONENT])]
        self.put(d)
        self.assertIsNone(self.fix(w))
        # Equivalent platform spellings share a scope at evaluation time.
        d['product_tree']['branches'].append(dict(category='vendor', name='cisco', branches=[
            branch('lower', 'contoso sample relay gateway')]))
        d['product_tree']['relationships'][1]['relates_to_product_reference'] = 'lower'
        d['vulnerabilities'][0]['product_status'] = dict(known_affected=['r'], first_fixed=['rf'])
        rows = self.put(d)
        self.assertEqual(self.fix(w), '2')
        self.assertEqual(advisory._relationship_scope(rows[0]), advisory._relationship_scope(rows[1]))
        d['vulnerabilities'][0]['product_status'] = dict(known_affected=['r'])
        d['vulnerabilities'][0]['remediations'] = [dict(category='vendor_fix', product_ids=['r'])]
        rows = self.put(d)
        self.assertEqual(rows[0]['fix'], 'available')
        self.assertEqual(self.fix(w), 'available')

    def test_t7_cna_override_scope_and_microsoft_guard(self):
        record = f3a.F3aTests().cna('unaffected')
        record['cveMetadata']['cveId'] = A
        entry = record['containers']['cna']['affected'][0]
        entry.update(vendor='Cisco', product='Contoso Sample Relay')
        entry['versions'] = [dict(version='1', versionType='dotted', status='unaffected')]
        w = watch('1', scheme='dotted', platform=PLATFORM)
        d = synthetic(); d['vulnerabilities'][0]['product_status'] = dict(known_affected=[COMPONENT])
        self.put(d)
        self.assertEqual(self.result(w, record=record), State.NOT_AFFECTED)
        for category in ('installed_on', 'optional_component_of'):
            d['product_tree']['relationships'][0]['category'] = category
            d['vulnerabilities'][0]['product_status'] = dict(known_affected=['r'])
            rows = self.put(d)
            expected = State.AFFECTED if category == 'installed_on' else State.UNKNOWN
            self.assertEqual(self.result(w, record=record), expected)
            verdict = advisory.cnascope.scoped_verdicts(record, w, self.aliases)[0]
            self.assertFalse(advisory.same_scope(rows[0], verdict, self.aliases, (), scheme=w.scheme))
        self.run_guard('test_t22_fix_selection_and_cna_scope')
        self.run_guard('test_t22_mutually_indeterminate_eligible_fixes')

    def test_t8_watch_platform_validation_and_redaction(self):
        text = '[[watch]]\nid="w"\nname="Sample"\nmatch=["cisco:relay"]\nversion="1"\nscheme="opaque"\n'
        accepted = watchlist.load_watchlist_text(text+'platform={vendor=" CISCO ",product=" Contoso  Gateway "}')[0]
        self.assertEqual(accepted.platform, ('cisco', 'contoso gateway'))
        different = replace(accepted, id='other', platform=('other', 'gateway'))
        self.assertTrue(watchlist.collisions([accepted, different], self.aliases))
        for value in ['{vendor="secretvalue"}', '{vendor="secretvalue",product="p",extra="leak"}',
                      '{vendor="secretvalue",product=""}', '{vendor="secretvalue",product="unknown"}',
                      '{vendor="unknown",product="secretvalue"}', '{vendor="secretvalue",product=3}',
                      '{vendor="secretvalue:bad",product="p"}', '"secretvalue"', '[]']:
            with self.subTest(value=value), self.assertRaises(watchlist.WatchlistError) as caught:
                watchlist.load_watchlist_text(text+'platform='+value)
            self.assertEqual(caught.exception.problems, ['watch entry 1 (w): platform requires non-placeholder vendor and product strings'])
            self.assertNotIn('secretvalue', str(caught.exception))
        from cornicen.vocabulary import WORDS
        self.assertIn('directory', WORDS)
        self.assertEqual(public_text.public_text('directory', [watch(platform=dict(vendor='directory', product='gateway'))]), public_text.MARKER)
        self.assertEqual(public_text.public_text('directory', [watch(platform=dict(vendor='gateway', product='directory'))]), public_text.MARKER)

    def test_t8_reload_restart_alias_and_rejection(self):
        helper = f3a.F3aTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        e = helper.engine
        first = replace(helper.watch, platform=('cisco', 'gateway'))
        second = replace(helper.watch, id='second')
        e.reload_watches((first, second))
        e.commit_advisory(feedvalidate.validate_advisory(normalise(synthetic()), source='cisco', observed_at=T).data, False)
        edited = replace(first, platform=('cisco', 'other gateway'))
        with patch.object(e, '_rematch_record') as rematch:
            e.reload_watches((edited, second))
        self.assertTrue(rematch.called)
        self.assertTrue(all(call.kwargs['watches'] == (edited,) for call in rematch.call_args_list))
        with patch.object(Engine, 'reload_watches') as reload:
            Engine(helper.store, (edited, second), e.aliases, e.config, helper.clock, e.notifier)
            reload.assert_not_called()
        # Compare restart selection to the same saved lists without platforms.
        observed = []
        original = Engine.reload_watches
        def inspect(instance, watches, **kw):
            observed.append({w.id: w.platform for w in instance.watches})
            return original(instance, watches, **kw)
        with patch.object(Engine, 'reload_watches', inspect), patch.object(Engine, '_rematch_record') as rematch:
            restarted = Engine(helper.store, (edited, replace(second, name='Edited')), e.aliases, e.config, helper.clock, e.notifier)
        self.assertEqual(observed[0], {edited.id: edited.platform, second.id: None})
        platform_ids = [tuple(w.id for w in c.kwargs['watches']) for c in rematch.call_args_list]
        bare = (replace(edited, platform=None), second)
        helper.store.set_meta('applied_watches', Engine._canonical_watches(bare))
        with patch.object(Engine, '_rematch_record') as rematch:
            Engine(helper.store, (bare[0], replace(second, name='Edited')), e.aliases, e.config, helper.clock, e.notifier)
        self.assertEqual(platform_ids, [tuple(w.id for w in c.kwargs['watches']) for c in rematch.call_args_list])
        self.assertTrue(platform_ids)
        restarted.aliases = AliasMap.load(False)
        with patch.object(restarted, '_rematch_record') as rematch:
            restarted.reload_watches(restarted.watches)
        self.assertTrue(rematch.called)
        self.assertEqual(restarted.watches[0].platform, edited.platform)
        before = restarted.watches
        with self.assertRaises(watchlist.WatchlistError):
            watchlist.load_watchlist_text('[[watch]]\nid="bad"\nplatform="rejected"')
        self.assertEqual(restarted.watches, before)
        with patch.object(restarted, '_save_watches', side_effect=RuntimeError('rejected')):
            with self.assertRaises(RuntimeError):
                restarted.reload_watches((replace(edited, platform=('cisco', 'rejected')), second))
        self.assertEqual(restarted.watches[0].platform, edited.platform)

    def test_t9_canonical_literals_guard(self):
        watches = watchlist.load_document_text((ROOT / 'tests/fixtures/watchlist_example.toml').read_text())[0]
        self.assertEqual(Engine._canonical_watches(watches), EXAMPLE_CANONICAL)
        selected = watchlist._watch(dict(id='w', name='Widget', match=['examplecorp:widget'], version='1', scheme='opaque',
            github=[dict(repository='examplecorp/widget', ecosystem='other', package='Widget')]))
        self.assertEqual(Engine._canonical_watches([selected]), GITHUB_CANONICAL)

    def test_t9_canonical_platform_object(self):
        encoded = Engine._canonical_watches([watch('1', platform=PLATFORM)])
        self.assertEqual(encoded, '[{"eol":false,"id":"w","match":[["cisco","contoso sample relay"]],"name":"Sample relay","platform":{"product":"contoso sample relay gateway","vendor":"cisco"},"product_only":[],"scheme":"opaque","version":"1"}]')

    def test_t9_ordinary_github_microsoft_frozen_guards(self):
        self.run_guard('test_t9_ordinary_and_github_guards')
        self.run_guard('test_t2_watch_binding')


if __name__ == '__main__':
    unittest.main()

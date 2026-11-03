import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from cornicen.applicability import Result, State, rejected, resolve
from cornicen.identity import AliasMap
from cornicen.versions import Scheme
from cornicen.watchlist import Watch


RAW = Path(__file__).parent / 'fixtures' / 'raw'


def raw(name):
    return json.loads((RAW / (name + '.json')).read_text())


def record(*entries, state='PUBLISHED'):
    return {'cveMetadata': {'state': state, 'cveId': 'CVE-2026-1000'},
            'containers': {'cna': {'affected': list(entries)}}}


def entry(versions=(), default='unknown', vendor='examplecorp', product='service'):
    return {'vendor': vendor, 'product': product, 'versions': list(versions),
            'defaultStatus': default}


def row(version='1.0', status='affected', **extra):
    return dict(version=version, status=status, **extra)


class ApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.aliases = AliasMap.load()
        self.watch = Watch('service', 'Service', (('examplecorp', 'service'),),
                           (), '1.6', Scheme.DOTTED, False)

    def check(self, rec, expected, kev=None, watch=None):
        result = resolve(rec, kev, watch or self.watch, self.aliases)
        self.assertIsInstance(result, Result)
        self.assertEqual(result.state, expected)
        self.assertTrue(result.evidence)
        self.assertIn(result.confidence, ('high', 'medium', 'low'))
        return result

    def fixture_watch(self, rec, version, scheme=Scheme.DOTTED):
        e = rec['containers']['cna']['affected'][0]
        return replace(self.watch, match=((e['vendor'], e['product']),),
                       version=version, scheme=scheme)

    def changes(self):
        # Raw Płatnik records have an unorderable change; this numeric case
        # exercises the schema's transition rule independently of that defect.
        return record(entry([row(lessThan='2.0', changes=[
            {'at': '1.5', 'status': 'unaffected'}])], 'unaffected'))

    def test_changes_excludes_1_6(self):
        self.check(self.changes(), State.NOT_AFFECTED)

    def test_changes_boundary_and_before(self):
        for version, expected in [('1.4', State.AFFECTED), ('1.5', State.NOT_AFFECTED)]:
            self.check(self.changes(), expected, watch=replace(self.watch, version=version))

    def test_changes_unsorted_and_return_to_affected(self):
        rec = record(entry([row(lessThan='2.0', changes=[
            {'at': '1.7', 'status': 'affected'}, {'at': '1.5', 'status': 'unaffected'}])]))
        self.check(rec, State.AFFECTED, watch=replace(self.watch, version='1.8'))

    def test_less_than_or_equal_includes_endpoint(self):
        rec = raw('CVE-2013-20009')
        self.check(rec, State.AFFECTED, watch=self.fixture_watch(rec, '1.01.06'))

    def test_less_than_or_equal_outside(self):
        rec = raw('CVE-2013-20009')
        self.check(rec, State.NOT_AFFECTED, watch=self.fixture_watch(rec, '1.01.07'))

    def test_less_than_excludes_endpoint(self):
        rec = raw('CVE-2015-20129')
        self.check(rec, State.NOT_AFFECTED, watch=self.fixture_watch(rec, '7.3.0'))
        self.check(rec, State.AFFECTED, watch=self.fixture_watch(rec, '7.2.9'))

    def test_lower_endpoint_included(self):
        self.check(record(entry([row(lessThan='2.0')])), State.AFFECTED,
                   watch=replace(self.watch, version='1.0'))

    def test_equality(self):
        rec = raw('CVE-2025-54831')
        for version, expected in [('3.0.3', State.AFFECTED), ('3.0.4', State.NOT_AFFECTED)]:
            self.check(rec, expected, watch=self.fixture_watch(rec, version, Scheme.SEMVER))

    def test_default_status_affected_unlisted_version(self):
        rec = raw('CVE-2026-103399')
        self.check(rec, State.AFFECTED, watch=self.fixture_watch(rec, '10.0'))
        self.check(record(entry([row(status='unaffected')], 'affected')), State.AFFECTED)

    def test_opaque_unlisted_version_takes_default_status(self):
        # Opaque is equality-only, and equality is decidable: an unlisted version gets defaultStatus.
        rec = raw('CVE-2023-20577')
        self.check(rec, State.AFFECTED,
                   watch=self.fixture_watch(rec, 'RomePI 1.0.0.I', Scheme.OPAQUE))

    def test_unaffected_equality(self):
        rec = raw('CVE-2023-20577')
        self.check(rec, State.NOT_AFFECTED,
                   watch=self.fixture_watch(rec, 'RomePI 1.0.0.H', Scheme.OPAQUE))

    def test_opaque_changes_fuzz_minimal(self):
        # Base seed 202002894, point-oracle seed 12425537217522917773, case 9291.
        rec = {'containers': {'cna': {'affected': [{
            'product': 'test-service', 'vendor': 'example corp',
            'versions': [{'version': '0', 'status': 'affected',
                          'changes': [{'at': '0', 'status': 'unaffected'}]}],
        }]}}}
        watch = replace(self.watch, match=(('example corp', 'test-service'),),
                        version='0', scheme=Scheme.OPAQUE)
        self.check(rec, State.UNKNOWN, watch=watch)

    def test_opaque_changes_cannot_decide_even_at_equal_boundary(self):
        watch = replace(self.watch, version='0', scheme=Scheme.OPAQUE)
        for status in ('affected', 'unaffected', 'unknown'):
            for default in ('affected', 'unaffected', 'unknown'):
                for lower in ('0', '*'):
                    with self.subTest(status=status, default=default, lower=lower):
                        rec = record(entry([row(lower, changes=[
                            {'at': '0', 'status': status}])], default))
                        self.check(rec, State.UNKNOWN, watch=watch)
                        self.check(rec, State.UNKNOWN, watch=replace(watch, version='=0'))

    def test_opaque_unlisted_default_only_decides_affected(self):
        watch = replace(self.watch, version='build-b', scheme=Scheme.OPAQUE)
        for default, expected in [('affected', State.AFFECTED),
                                  ('unaffected', State.UNKNOWN), ('unknown', State.UNKNOWN)]:
            with self.subTest(default=default):
                self.check(record(entry([row('build-a', 'unaffected')], default)),
                           expected, watch=watch)

    def test_explicit_unknown_honoured(self):
        self.check(record(entry([row('1.6', 'unknown')], 'affected')), State.UNKNOWN)

    def test_kev_does_not_override_cna_not_affected(self):
        result = self.check(record(entry([row('1.6', 'unaffected')])),
                            State.NOT_AFFECTED, {'cveID': 'CVE-2026-1000',
                                                 'vendorProject': 'examplecorp', 'product': 'service'})
        self.assertTrue(result.exploited)
        self.assertEqual(result.confidence, 'high')

    def test_kev_only_is_unknown_exploited(self):
        kev = raw('kev_sample')['vulnerabilities'][0]
        watch = replace(self.watch, match=((kev['vendorProject'], kev['product']),))
        result = self.check({'cveMetadata': {'cveId': kev['cveID']}}, State.UNKNOWN, kev, watch)
        self.assertTrue(result.exploited)
        self.assertEqual(result.confidence, 'medium')

    def test_kev_marks_cna_match_exploited_even_if_identity_differs(self):
        result = self.check(record(entry([row('1.6')])), State.AFFECTED,
                            {'cveID': 'CVE-2026-1000', 'vendorProject': 'different', 'product': 'name'})
        self.assertTrue(result.exploited)

    def test_kev_mismatched_id_does_not_mark_cna_exploited(self):
        kev = {'cveID': 'CVE-2026-2000', 'vendorProject': 'examplecorp', 'product': 'service'}
        result = self.check(record(entry([row('1.6')])), State.AFFECTED, kev)
        self.assertFalse(result.exploited)

    def test_kev_requires_matching_nonempty_ids_for_identity(self):
        for record_id, kev_id in [('CVE-2026-1000', 'CVE-2026-2000'),
                                  (None, 'CVE-2026-1000'), ('CVE-2026-1000', None),
                                  ('', ''), (' ', ' ')]:
            with self.subTest(record_id=record_id, kev_id=kev_id):
                rec = {'cveMetadata': {'cveId': record_id}}
                kev = {'cveID': kev_id, 'vendorProject': 'examplecorp', 'product': 'service'}
                self.assertIsNone(resolve(rec, kev, self.watch, self.aliases))

    def test_kev_ids_match_case_insensitively(self):
        kev = {'cveID': 'cve-2026-1000', 'vendorProject': 'examplecorp', 'product': 'service'}
        self.assertTrue(self.check(record(), State.UNKNOWN, kev).exploited)

    def test_no_identity_match_returns_none(self):
        self.assertIsNone(resolve(record(entry(vendor='other')), None, self.watch, self.aliases))
        self.assertIsNone(resolve(record(), {'cveID': 'CVE-2026-1000',
                                            'vendorProject': 'other', 'product': 'service'},
                                  self.watch, self.aliases))

    def test_identity_normalisation(self):
        self.check(record(entry([row('1.6')], vendor=' ExampleCorp ', product=' SERVICE ')),
                   State.AFFECTED)

    def test_alias_expansion(self):
        rec = record(entry([row('1.6')], vendor='F5', product='nginx'))
        self.check(rec, State.AFFECTED, watch=replace(self.watch, match=(('nginx', 'nginx'),)))
        kev = {'cveID': 'CVE-2026-1000', 'vendorProject': 'f5', 'product': 'nginx'}
        self.assertTrue(self.check(record(), State.UNKNOWN, kev,
                                 replace(self.watch, match=(('nginx', 'nginx'),))).exploited)

    def test_placeholder_vendor_ignored(self):
        rec = raw('CVE-2016-0012')
        watch = replace(self.watch, product_only=('n/a',), match=())
        self.assertIsNone(resolve(rec, None, watch, self.aliases))
        for value in ('n/a', 'NA', 'unknown', '', '-'):
            for vendor, product in [(value, 'service'), ('examplecorp', value)]:
                rec = record(entry([row('1.6')], vendor=vendor, product=product))
                watch = replace(self.watch, product_only=(product,), match=((vendor, product),))
                self.assertIsNone(resolve(rec, None, watch, self.aliases))
                self.assertIsNone(resolve(record(), {'cveID': 'CVE-2026-1000',
                                                    'vendorProject': vendor, 'product': product},
                                          watch, self.aliases))

    def test_missing_vendor_ignored_with_product_only(self):
        e = entry([row('1.6')])
        del e['vendor']
        self.assertIsNone(resolve(record(e), None, replace(self.watch, product_only=('service',)),
                                  self.aliases))

    def test_product_only_caps_at_unknown(self):
        for status in ('affected', 'unaffected'):
            result = self.check(record(entry([row('1.6', status)], vendor='other')),
                                State.UNKNOWN, watch=replace(self.watch, product_only=('service',)))
            self.assertEqual(result.confidence, 'low')

    def test_loose_entry_cannot_override_exact(self):
        rec = record(entry([row('1.6', 'unaffected')]),
                     entry([row('1.6')], vendor='other'))
        self.check(rec, State.NOT_AFFECTED, watch=replace(self.watch, product_only=('service',)))

    def test_rejected_matching_identity_is_not_affected(self):
        for state in ('REJECTED', 'WITHDRAWN'):
            self.check(record(entry([row('1.6')]), state=state), State.NOT_AFFECTED)

    def test_rejected_unrelated_watch_returns_none(self):
        for rec in (record(state='REJECTED'),
                    record(entry(vendor='other'), state='REJECTED')):
            self.assertIsNone(resolve(rec, None, self.watch, self.aliases))

    def test_rejected_record_signal_without_identity(self):
        self.assertTrue(rejected(record(state='REJECTED')))
        self.assertTrue(rejected(record(state='rejected')))
        for rec in ({}, record(), record(state='WITHDRAWN')):
            self.assertFalse(rejected(rec))

    def test_rejected_overrides_product_only_and_kev(self):
        self.check(record(entry(vendor='other'), state='REJECTED'), State.NOT_AFFECTED,
                   {'cveID': 'CVE-2026-1000', 'vendorProject': 'other', 'product': 'service'},
                   replace(self.watch, product_only=('service',)))

    def test_multiple_entries_affected_wins(self):
        for states, expected in [(('unaffected', 'affected', 'unknown'), State.AFFECTED),
                                 (('unknown', 'unaffected'), State.NOT_AFFECTED),
                                 (('unknown', 'unknown'), State.UNKNOWN)]:
            self.check(record(*(entry([row('1.6', s)]) for s in states)), expected)

    def test_version_type_conflict_unknown(self):
        for version_type in ('semver', 'rpm', 'git'):
            self.check(record(entry([row('1.6', versionType=version_type)], 'affected')),
                       State.UNKNOWN)

    def test_matching_version_type(self):
        result = self.check(record(entry([row('1.6', versionType='dotted')])), State.AFFECTED)
        self.assertIn('versionType dotted', result.evidence)

    def test_undecidable_comparisons_are_unknown(self):
        for version in ('1.6-bad', '1.6.0'):
            self.check(record(entry([row(version)], 'unaffected')), State.UNKNOWN)
        self.check(record(entry([row('1.0', lessThan='bad')], 'affected')), State.UNKNOWN)
        self.check(record(entry([row('1.0', lessThan='2.0')], 'affected')), State.UNKNOWN,
                   watch=replace(self.watch, scheme=Scheme.OPAQUE))

    def test_unorderable_real_changes_unknown(self):
        rec = raw('CVE-2026-110970')
        self.check(rec, State.UNKNOWN, watch=self.fixture_watch(rec, '10.02.002'))

    def test_range_watch_any_affected(self):
        self.check(self.changes(), State.AFFECTED,
                   watch=replace(self.watch, version='>=1.4, <1.7'))

    def test_range_watch_all_excluded(self):
        self.check(self.changes(), State.NOT_AFFECTED,
                   watch=replace(self.watch, version='>=1.5, <2.0'))

    def test_range_watch_partial_unknown(self):
        self.check(record(entry([row('1.0', 'unaffected', lessThan='2.0')])), State.UNKNOWN,
                   watch=replace(self.watch, version='>=1.5, <2.5'))

    def test_range_watch_equality_and_open_boundaries(self):
        rec = record(entry([row('1.6')], 'unaffected'))
        for constraint, expected in [('=1.6', State.AFFECTED), ('>1.6, <1.8', State.NOT_AFFECTED),
                                     ('>=1.5, <=1.6', State.AFFECTED)]:
            self.check(rec, expected, watch=replace(self.watch, version=constraint))

    def test_range_watch_unbounded(self):
        self.check(self.changes(), State.AFFECTED, watch=replace(self.watch, version='<1.5'))
        self.check(self.changes(), State.NOT_AFFECTED, watch=replace(self.watch, version='>=2.0'))

    def test_range_watch_unknown_ordering(self):
        for constraint in ('>=1.0, <bad', '>=1.0, <1.0.0'):
            self.check(self.changes(), State.UNKNOWN, watch=replace(self.watch, version=constraint))

    def test_range_watch_opaque_unknown(self):
        self.check(record(entry([row('1.6')], 'unaffected')), State.UNKNOWN,
                   watch=replace(self.watch, version='>=1.6', scheme=Scheme.OPAQUE))

    def test_range_watch_coverage_across_rows(self):
        rec = record(entry([row('1.0', 'unaffected', lessThan='1.5'),
                            row('1.5', 'unaffected', lessThan='2.0')]))
        self.check(rec, State.NOT_AFFECTED, watch=replace(self.watch, version='>=1.0, <2.0'))

    def test_range_watch_affected_point_inside_excluded_range(self):
        rec = record(entry([row('1.6')], 'unaffected'))
        self.check(rec, State.AFFECTED, watch=replace(self.watch, version='>1.5, <1.7'))

    def test_range_watch_unknown_point_prevents_full_exclusion(self):
        rec = record(entry([row('1.6', 'unknown')], 'unaffected'))
        self.check(rec, State.UNKNOWN, watch=replace(self.watch, version='>=1.5, <1.7'))

    def test_range_watch_semver_adjacent_values_have_no_interior(self):
        rec = record(entry([row('1.0.0-rc.1', 'unaffected'),
                            row('1.0.0-rc.1.0', 'unaffected')], 'affected'))
        self.check(rec, State.NOT_AFFECTED, watch=replace(
            self.watch, scheme=Scheme.SEMVER, version='>=1.0.0-rc.1, <=1.0.0-rc.1.0'))

    def test_range_watch_semver_large_patch_never_raises(self):
        # Base seed 202002894, never-raises seed 6804494246565159983, case 0.
        # 4,300 nines parse as int, but incrementing adds a digit and printing fails.
        for digits in (4300, 10000):
            huge = '1.0.' + '9' * digits
            with self.subTest(digits=digits):
                rec = {'containers': {'cna': {'affected': [{
                    'vendor': 'example corp', 'product': 'test-service',
                    'versions': [{'version': huge}],
                }]}}}
                self.check(rec, State.UNKNOWN, watch=replace(
                    self.watch, match=(('example corp', 'test-service'),),
                    scheme=Scheme.SEMVER, version='<2.0.0'))

    def test_range_watch_semver_successor_carry_and_adjacency(self):
        for patch in ('0', '8', '9', '129', '9' * 10000):
            next_patch = {'0': '1', '8': '9', '9': '10', '129': '130'}.get(
                patch, '1' + '0' * len(patch))
            lower, upper = '1.0.' + patch, '1.0.' + next_patch + '-0'
            with self.subTest(digits=len(patch), suffix=patch[-3:]):
                rec = record(entry([row(lower, 'unaffected'), row(upper, 'unaffected')],
                                   'affected'))
                self.check(rec, State.NOT_AFFECTED, watch=replace(
                    self.watch, scheme=Scheme.SEMVER, version=f'>={lower}, <={upper}'))

    def test_range_watch_semver_interior_affected(self):
        rec = record(entry([row('1.0.0', 'unaffected'), row('1.0.1', 'unaffected')],
                           'affected'))
        self.check(rec, State.AFFECTED, watch=replace(
            self.watch, scheme=Scheme.SEMVER, version='>=1.0.0, <=1.0.1'))

    def test_range_watch_debian(self):
        rec = record(entry([row('1:1.0', lessThan='1:2.0', versionType='debian')],
                           'unaffected'))
        self.check(rec, State.AFFECTED, watch=replace(
            self.watch, scheme=Scheme.DEBIAN, version='>=1:1.5, <1:3.0'))

    def test_range_watch_leading_v(self):
        self.check(self.changes(), State.AFFECTED,
                   watch=replace(self.watch, version='>=v1.4, <V1.7'))

    def test_zero_and_wildcard_range_starts_are_unbounded(self):
        for scheme, below in [(Scheme.SEMVER, '0.0.0-rc.1'),
                              (Scheme.DOTTED, '0.0'), (Scheme.DEBIAN, '0~rc1')]:
            for start in ('0', '0.0', '0.0.0', '*'):
                for upper in ('lessThan', 'lessThanOrEqual'):
                    for version in (below, '1.6.0', '<1.0.0'):
                        with self.subTest(scheme=scheme, start=start, upper=upper,
                                          version=version):
                            rec = record(entry([row(start, **{upper: '2.0.0'})], 'unaffected'))
                            self.check(rec, State.AFFECTED, watch=replace(
                                self.watch, scheme=scheme, version=version))

    def test_bare_zero_is_equality(self):
        for scheme, version, expected in [(Scheme.SEMVER, '1.0.0', State.UNKNOWN),
                                           (Scheme.DOTTED, '1.0', State.NOT_AFFECTED),
                                           (Scheme.DEBIAN, '0~rc1', State.NOT_AFFECTED),
                                           (Scheme.OPAQUE, '0', State.AFFECTED)]:
            with self.subTest(scheme=scheme):
                self.check(record(entry([row('0')], 'unaffected')), expected,
                           watch=replace(self.watch, scheme=scheme, version=version))

    def test_wildcard_unbounded_upper(self):
        self.check(record(entry([row('1.0', lessThan='*')])), State.AFFECTED)

    def test_absent_version_data_is_unknown(self):
        self.check(record(entry()), State.UNKNOWN)

    def test_evidence_and_confidence(self):
        result = self.check(record(entry([row(lessThan='2.0')])), State.AFFECTED)
        self.assertIn('CNA', result.evidence)
        self.assertIn('service', result.evidence)
        self.assertIn('2.0', result.evidence)
        self.assertEqual(result.confidence, 'high')
        self.assertFalse(result.exploited)

    def test_malformed_records_never_raise(self):
        cases = [(None, None), ([], None), ({'cveMetadata': []}, None),
                 ({'containers': None}, None), ({'containers': []}, None),
                 ({'containers': {'cna': None}}, None),
                 ({'containers': {'cna': []}}, None),
                 ({'containers': {'cna': {'affected': {}}}}, None),
                 ({'containers': {'cna': {'affected': None}}}, None),
                 ({'containers': {'cna': {'affected': 'service'}}}, None),
                 (record(None, 1, []), None)]
        for field in ('vendor', 'product'):
            for value in (None, 7, [], {}):
                malformed = entry([row('1.6')])
                malformed[field] = value
                cases.append((record(malformed), None))
        for field, values in [('versions', (None, '1.0', {}, [None], [1], [[]])),
                              ('defaultStatus', (None, 7, [], {}))]:
            for value in values:
                malformed = entry([row('1.6')])
                malformed[field] = value
                cases.append((record(malformed), State.UNKNOWN))
        for field in ('version', 'lessThan', 'lessThanOrEqual', 'status', 'versionType'):
            for value in (None, 7, [], {}):
                malformed = row('1.6')
                malformed[field] = value
                cases.append((record(entry([malformed])), State.UNKNOWN))
        for value in (None, {}, 'changes', [1], [None], [[]],
                      [{'at': None, 'status': 'affected'}],
                      [{'at': [], 'status': 'affected'}],
                      [{'at': '1.5', 'status': []}],
                      [{'at': '1.5', 'status': None}]):
            cases.append((record(entry([row('1.0', lessThan='2.0', changes=value)])),
                          State.UNKNOWN))
        for value in (None, [], 7):
            rec = record(entry([row('1.6')]))
            rec['cveMetadata'] = value
            cases.append((rec, State.UNKNOWN))
        for value in (None, [], 7):
            cases.append((record(entry([row('1.6')]), state=value), State.UNKNOWN))
        self.assertGreaterEqual(len(cases), 15)
        for index, (rec, expected) in enumerate(cases):
            for version in ('1.6', '>=1.5, <1.7'):
                with self.subTest(case=index, version=version):
                    result = resolve(rec, None, replace(self.watch, version=version), self.aliases)
                    if expected is None:
                        self.assertIsNone(result)
                    else:
                        self.assertIsInstance(result, Result)
                        self.assertEqual(result.state, expected)
                    self.assertFalse(rejected(rec))

    def test_malformed_kev_entries_are_ignored(self):
        cases = [None, [], 7, 'kev']
        for field in ('cveID', 'vendorProject', 'product'):
            for value in (None, 7, [], {}):
                kev = {'cveID': 'CVE-2026-1000',
                       'vendorProject': 'examplecorp', 'product': 'service'}
                kev[field] = value
                cases.append(kev)
        for index, kev in enumerate(cases):
            with self.subTest(case=index):
                result = self.check(record(entry([row('1.6')])), State.AFFECTED, kev)
                self.assertFalse(result.exploited)
                self.assertIsNone(resolve(record(), kev, self.watch, self.aliases))

    def test_inputs_unchanged(self):
        rec = self.changes()
        before = copy.deepcopy(rec)
        self.check(rec, State.NOT_AFFECTED)
        self.assertEqual(rec, before)


if __name__ == '__main__':
    unittest.main()

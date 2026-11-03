"""Regression cases copied unchanged from the 2026-11-03 public corpus.

Synthetic variants are deep copies, labelled in each test; fixtures retain all
stored metadata and CNA affected rows without editing their original defaults.
"""
import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from cornicen.applicability import State, resolve
from cornicen.identity import AliasMap
from cornicen.versions import Scheme, compare
from cornicen.watchlist import Watch


FIXTURES = Path(__file__).parent / 'fixtures' / 'real_matches'


def fixture(cve):
    return json.loads((FIXTURES / (cve + '.json')).read_text())


def watch_for(rec, version, scheme):
    entry = rec['containers']['cna']['affected'][0]
    return Watch('fictional', 'Fictional watch', ((entry['vendor'], entry['product']),),
                 (), version, Scheme(scheme), False)


class RealMatchTests(unittest.TestCase):
    def resolve(self, rec, version, scheme):
        return resolve(rec, None, watch_for(rec, version, scheme), AliasMap.load())

    def test_junos_undecidable_covering_entry(self):
        for cve in ('CVE-2019-0062', 'CVE-2020-1606'):
            rec = fixture(cve)
            # Reuse the harness's fictional inside watch, plus a made-up build.
            for version in ('14.1X53', '14.1X53-0fictional'):
                with self.subTest(cve=cve, version=version):
                    result = self.resolve(rec, version, 'debian')
                    self.assertEqual(result.state, State.UNKNOWN)
                    self.assertIn('CNA unknown junos os:', result.evidence)
                    rec['containers']['cna']['affected'].reverse()
                    self.assertEqual(self.resolve(rec, version, 'debian').state, State.UNKNOWN)

    def test_semver_label_uses_dsm_watch_scheme(self):
        rec = fixture('CVE-2026-40537')
        for version, state in [('7.2.2-72806-6', State.AFFECTED),
                               ('7.2.2-72806-7', State.UNKNOWN),
                               ('7.2.2-72806-11', State.UNKNOWN),
                               ('7.4.1-90081', State.UNKNOWN)]:
            with self.subTest(version=version):
                self.assertEqual(self.resolve(rec, version, 'debian').state, state)

        # Synthetic unaffected default: the same endpoints still hold.
        variant = copy.deepcopy(rec)
        variant['containers']['cna']['affected'][0]['defaultStatus'] = 'unaffected'
        self.assertEqual(self.resolve(variant, '7.2.2-72806-6', 'debian').state, State.AFFECTED)
        self.assertEqual(self.resolve(variant, '7.2.2-72806-7', 'debian').state,
                         State.NOT_AFFECTED)
        self.assertEqual(self.resolve(variant, '7.2.2-72806-11', 'debian').state,
                         State.NOT_AFFECTED)

    def test_dsm_outside_ranges_with_affected_default(self):
        rec = fixture('CVE-2026-40537')
        for version, expected in [('7.4.3-90500', State.UNKNOWN),
                                  ('7.2.2-72806-9', State.UNKNOWN),
                                  ('7.2.2-72806-6', State.AFFECTED),
                                  ('6.2.3-25426', State.UNKNOWN)]:
            with self.subTest(version=version):
                result = self.resolve(rec, version, 'debian')
                self.assertEqual(result.state, expected)
        # Public record has an explicit unknown older range. This synthetic
        # variant isolates the affected default for an unlisted older version.
        variant = copy.deepcopy(rec)
        entry = variant['containers']['cna']['affected'][0]
        entry['versions'] = [row for row in entry['versions'] if row['status'] == 'affected']
        self.assertEqual(self.resolve(variant, '6.2.3-25426', 'debian').state, State.UNKNOWN)

    def test_python_label_uses_watch_scheme(self):
        rec = fixture('CVE-2026-103995')
        for scheme in ('semver', 'dotted'):
            self.assertEqual(self.resolve(rec, '3.14.11', scheme).state, State.AFFECTED)
            self.assertEqual(self.resolve(rec, '3.16.0', scheme).state, State.NOT_AFFECTED)

    def test_pep440_bounds_stay_unknown_under_existing_schemes(self):
        rec = fixture('CVE-2026-82049')
        for scheme in ('semver', 'dotted'):
            result = self.resolve(rec, '3.14.11', scheme)
            self.assertEqual(result.state, State.UNKNOWN)
            self.assertIn('version comparison unknown', result.evidence)
            self.assertIsNone(compare('3.14.0a1', '3.14.0b1', Scheme(scheme)))

    def test_python_scheme_orders_real_cpython_prereleases(self):
        rec = fixture('CVE-2026-82049')
        for version, expected in [('3.14.0a1', State.AFFECTED),
                                  ('3.14.0a2', State.AFFECTED),
                                  ('3.14.0b1', State.NOT_AFFECTED),
                                  ('3.14.11', State.NOT_AFFECTED),
                                  ('>=3.14.0a1, <3.14.0b1', State.AFFECTED),
                                  ('>=3.14.0b1, <3.15.0', State.NOT_AFFECTED)]:
            with self.subTest(version=version):
                self.assertEqual(self.resolve(rec, version, 'python').state, expected)

    def test_python_range_cells_respect_adjacent_versions(self):
        rec = fixture('CVE-2026-82049')
        entry = rec['containers']['cna']['affected'][0]
        # Affected default must not create a phantom affected open cell.
        entry['defaultStatus'] = 'affected'
        for left, right in [('3.14.0a1', '3.14.0a2'), ('3.14.0b1', '3.14.0b2'),
                            ('3.14.0rc1', '3.14.0rc2'), ('3.14.0', '3.14.1a0')]:
            entry['versions'] = [{'version': left, 'status': 'unaffected'},
                                 {'version': right, 'status': 'unaffected'}]
            with self.subTest(left=left, right=right):
                self.assertEqual(self.resolve(rec, f'>={left}, <={right}', 'python').state,
                                 State.NOT_AFFECTED)
        entry['versions'] = [{'version': '0.0.0a0', 'status': 'unaffected'}]
        self.assertEqual(self.resolve(rec, '<=0.0.0a0', 'python').state, State.NOT_AFFECTED)

    def test_php_label_is_hint_but_wildcard_bound_is_unknown(self):
        rec = fixture('CVE-2026-92842')
        result = self.resolve(rec, '8.2.36', 'dotted')
        self.assertEqual(result.state, State.UNKNOWN)
        self.assertIn('version comparison unknown', result.evidence)

    def test_other_named_types_still_conflict(self):
        rec = fixture('CVE-2026-103995')
        for kind in ('git', 'rpm', 'maven', 'original_commit_for_fix'):
            variant = copy.deepcopy(rec)
            for row in variant['containers']['cna']['affected'][0]['versions']:
                row['versionType'] = kind
            result = self.resolve(variant, '3.14.11', 'semver')
            self.assertEqual(result.state, State.UNKNOWN)
            self.assertIn('conflicts', result.evidence)

    def test_dsm_debian_sequence(self):
        versions = ['7.2.2', '7.2.2-72806', '7.2.2-72806-7',
                    '7.2.2-72806-11', '7.3', '7.4-90075', '7.4.1-90081']
        for index, a in enumerate(versions):
            for j, b in enumerate(versions):
                self.assertEqual(compare(a, b, Scheme.DEBIAN), (index > j) - (index < j))

    def test_dsm_unspecified_lower_bound_is_unknown(self):
        rec = fixture('CVE-2021-43929')
        result = self.resolve(rec, '7.2.2-72806-11', 'debian')
        self.assertEqual(result.state, State.UNKNOWN)
        self.assertIn('version comparison unknown', result.evidence)

    def test_radarr_placeholder_vendor_product_only(self):
        rec = fixture('CVE-2025-13130')
        watch = Watch('radarr', 'Fictional Radarr', (('radarr', 'radarr'),),
                      ('radarr',), '6.4.5', Scheme.SEMVER, False)
        aliases = AliasMap.load()
        for version in ('6.4.5', '5.28.0.10274'):
            result = resolve(rec, None, replace(watch, version=version), aliases)
            self.assertIsNotNone(result)
            self.assertEqual(result.state, State.UNKNOWN)
            self.assertEqual(result.confidence, 'low')
            self.assertIn('Product-only', result.evidence)
        self.assertIsNone(resolve(rec, None, replace(watch, product_only=()), aliases))

    def test_placeholder_products_never_match_even_with_loose_opt_in(self):
        rec = fixture('CVE-2025-13130')
        for placeholder in ('n/a', 'NA', 'unknown', '', '-', 'not available'):
            variant = copy.deepcopy(rec)
            variant['containers']['cna']['affected'][0]['product'] = placeholder
            watch = Watch('bad', 'Invalid identity', (('n/a', placeholder),),
                          (placeholder,), '6.4.5', Scheme.SEMVER, False)
            self.assertIsNone(resolve(variant, None, watch, AliasMap.load()))

    def test_placeholder_vendor_kev_and_cached_identity(self):
        rec = fixture('CVE-2025-13130')
        kev = {'cveID': 'CVE-2025-13130', 'vendorProject': 'n/a', 'product': 'Radarr'}
        aliases = AliasMap.load()
        identities = {}
        watch = Watch('radarr', 'Fictional Radarr', (), ('radarr',), '6.4.5',
                      Scheme.SEMVER, False)
        for _ in range(2):
            result = resolve(rec, kev, watch, aliases, identities=identities)
            self.assertIsNotNone(result)
            self.assertEqual(result.state, State.UNKNOWN)
            self.assertTrue(result.exploited)
            self.assertEqual(result.confidence, 'low')

    def test_plex_history_excludes_later_release(self):
        rec = fixture('CVE-2026-96652')
        # Original corpus record explicitly says unknown; omitted is a variant.
        for omitted in (False, True):
            variant = copy.deepcopy(rec)
            if omitted:
                del variant['containers']['cna']['affected'][0]['defaultStatus']
            for version, expected in [('1.43.3.10860', State.AFFECTED),
                                      ('1.43.3.10861', State.NOT_AFFECTED),
                                      ('1.43.5.11031', State.NOT_AFFECTED),
                                      ('>=1.43.4, <1.44', State.NOT_AFFECTED),
                                      ('>=1.43.3.10860, <1.44', State.AFFECTED)]:
                with self.subTest(omitted=omitted, version=version):
                    result = self.resolve(variant, version, 'dotted')
                    self.assertEqual(result.state, expected)
                    if version == '1.43.5.11031':
                        self.assertIn('outside every affected range the CNA listed', result.evidence)

    def test_history_exclusion_requires_complete_decidable_rows(self):
        rec = fixture('CVE-2026-96652')
        entry = rec['containers']['cna']['affected'][0]
        del entry['defaultStatus']
        # Synthetic bounded start: no history exclusion remains.
        bounded = copy.deepcopy(rec)
        bounded['containers']['cna']['affected'][0]['versions'][0]['version'] = '1.0'
        self.assertEqual(self.resolve(bounded, '1.43.5.11031', 'dotted').state,
                         State.UNKNOWN)
        for start in ('0', '*', '0.0', '0.0.0'):
            variant = copy.deepcopy(rec)
            variant['containers']['cna']['affected'][0]['versions'][0]['version'] = start
            self.assertEqual(self.resolve(variant, '1.43.5.11031', 'dotted').state,
                             State.NOT_AFFECTED)
        variants = []
        for field, value in [('version', 'unspecified'),
                             ('lessThan', 'unorderable'), ('versionType', 'git'),
                             ('changes', [{'at': 'unorderable', 'status': 'unaffected'}])]:
            variant = copy.deepcopy(rec)
            variant['containers']['cna']['affected'][0]['versions'][0][field] = value
            variants.append(variant)
        variant = copy.deepcopy(rec)
        variant['containers']['cna']['affected'][0]['versions'].append(
            {'version': 'unorderable', 'status': 'unaffected'})
        variants.append(variant)
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertEqual(self.resolve(variant, '1.43.5.11031', 'dotted').state,
                                 State.UNKNOWN)
        self.assertEqual(self.resolve(rec, '1.43.5.11031', 'opaque').state, State.UNKNOWN)

    def test_outside_ranges_respects_default_and_preserves_kev(self):
        rec = fixture('CVE-2026-96652')
        for default, state in [('affected', State.UNKNOWN), ('unaffected', State.NOT_AFFECTED)]:
            variant = copy.deepcopy(rec)
            variant['containers']['cna']['affected'][0]['defaultStatus'] = default
            self.assertEqual(self.resolve(variant, '1.43.5.11031', 'dotted').state, state)
        kev = {'cveID': 'CVE-2026-96652', 'vendorProject': 'Plex', 'product': 'Media Server'}
        result = resolve(rec, kev, watch_for(rec, '1.43.5.11031', 'dotted'), AliasMap.load())
        self.assertEqual(result.state, State.NOT_AFFECTED)
        self.assertTrue(result.exploited)

    def test_history_upper_only_comparator_and_mixed_entries(self):
        rec = fixture('CVE-2026-96652')
        entry = rec['containers']['cna']['affected'][0]
        del entry['defaultStatus']
        entry['versions'][0] = {'version': '<1.43.3.10861', 'status': 'affected'}
        self.assertEqual(self.resolve(rec, '1.43.5.11031', 'dotted').state, State.NOT_AFFECTED)
        # A second entry with a positive result must still win aggregation.
        other = copy.deepcopy(entry)
        other['versions'] = [{'version': '1.43.5.11031', 'status': 'affected'}]
        rec['containers']['cna']['affected'].append(other)
        self.assertEqual(self.resolve(rec, '1.43.5.11031', 'dotted').state, State.AFFECTED)

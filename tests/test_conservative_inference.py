"""Independent review regressions; fictional versions, controller UNKNOWN policy."""
import unittest
import json
from pathlib import Path
from cornicen.applicability import resolve, State
from cornicen.identity import AliasMap
from cornicen.versions import Scheme
from cornicen.watchlist import Watch


def row(lo, hi=None, status='affected', kind='semver', inclusive=False):
    r = dict(version=lo, status=status, versionType=kind)
    if hi is not None:
        r['lessThanOrEqual' if inclusive else 'lessThan'] = hi
    return r


def entry(rows, default=None, vendor='Fictional', product='Widget'):
    e = dict(vendor=vendor, product=product, versions=rows)
    if default is not None:
        e['defaultStatus'] = default
    return e


def check(entries, version, scheme='semver', loose=False):
    rec = dict(cveMetadata=dict(cveId='CVE-2099-999999', state='PUBLISHED'),
               containers=dict(cna=dict(affected=entries)))
    watch = Watch('review', 'Fictional', () if loose else (('fictional', 'widget'),),
                  ('widget',) if loose else (), version, Scheme(scheme), False)
    return resolve(rec, None, watch, AliasMap())


class ConservativeInferenceTests(unittest.TestCase):
    def test_outside_ranges_ignores_prefixes(self):
        for lower, fix, version, scheme in (
                ('7.2.2', '7.2.2-72806-8', '7.2.2-72806-9', 'debian'),
                ('7.2.2', '7.2.2-72806-8', '7.2.20-72806-9', 'debian'),
                ('11.0', '11.0.3', '11.0.5', 'dotted'),
                ('11.0', '11.0.3', '11.01.5', 'dotted'),
                ('1', '1.4', '1.31.4', 'dotted'),
                ('7.2', '7.2.9', '7.20.1', 'dotted')):
            with self.subTest(lower=lower, version=version):
                result = check([entry([row(lower, fix)], 'affected')], version, scheme)
                self.assertEqual(result.state, State.UNKNOWN)
                self.assertIn("outside every range the CNA listed; the CNA's default says affected",
                              result.evidence)

    def test_outside_range_cells_and_affected_overlap(self):
        e = entry([row('11.0', '11.0.3')], 'affected')
        for version, expected in (('>=11.0.4, <=11.0.5', State.UNKNOWN),
                                  ('>=11.0.4, <12.0', State.UNKNOWN),
                                  ('>=11.0.4', State.UNKNOWN),
                                  ('>=11.0.2, <=11.0.5', State.AFFECTED)):
            with self.subTest(version=version):
                self.assertEqual(check([e], version, 'dotted').state, expected)

    def test_debian_unlisted_interval_is_unknown(self):
        e = entry([row('11.0', '11.0-8')], 'affected')
        self.assertEqual(check([e], '>=11.0-9, <=11.0.5', 'debian').state, State.UNKNOWN)

    def test_unbounded_start_equality_watch_does_not_crash(self):
        self.check_unbounded_start('=2.5.6', State.UNKNOWN)

    def test_unbounded_start_outside_range_watch_does_not_crash(self):
        self.check_unbounded_start('>=2.5.6, <=2.5.7', State.UNKNOWN)

    def test_unbounded_start_overlapping_range_watch_does_not_crash(self):
        self.check_unbounded_start('>=0.5.0, <=2.5.6', State.AFFECTED)

    def check_unbounded_start(self, version, expected):
        for lower in ('0', '*', '0.0', '0.0.0'):
            with self.subTest(lower=lower, version=version):
                e = entry([row(lower, '1.0.0')], 'affected')
                self.assertEqual(check([e], version).state, expected)

    def test_unbounded_start_point_and_explicit_exclusion(self):
        for lower in ('0', '*'):
            e = entry([row(lower, '1.0.0')], 'affected')
            self.assertEqual(check([e], '2.5.6').state, State.UNKNOWN)
            excluded = entry([row('2.5.6', status='unaffected')])
            for entries in ([e, excluded], [excluded, e]):
                self.assertEqual(check(entries, '2.5.6').state, State.NOT_AFFECTED)

    def test_history_weakness_keeps_explicit_exclusion_precedence(self):
        history = entry([row('0', '1.0.0')])
        wildcard = entry([row('2.0.0', '2.*', inclusive=True)])
        for exclusion in (entry([], 'unaffected'), entry([row('2.5.6', status='unaffected')])):
            self.assertEqual(check([history, wildcard, exclusion], '2.5.6').state,
                             State.NOT_AFFECTED)

    def test_reviewer_handchecks(self):
        cases = json.loads((Path(__file__).parent / 'fixtures' / 'review_handchecks.json').read_text())
        self.assertEqual(len(cases), 31)
        for case in cases:
            with self.subTest(cve=case['cve'], version=case['version']):
                identity = case['identity']
                product = case['affected'][0]['product']
                watch = Watch('review', 'Fictional watch', (tuple(identity),) if identity else (),
                              () if identity else (product,), case['version'],
                              Scheme(case['scheme']), False)
                rec = dict(cveMetadata=dict(cveId=case['cve'], state='PUBLISHED'),
                           containers=dict(cna=dict(affected=case['affected'])))
                result = resolve(rec, None, watch, AliasMap())
                self.assertEqual(result.state.value, case['expected'])

    def test_outside_ranges_with_affected_default(self):
        e = entry([row('11.0.0', '11.2.0'), row('9.0.0', '9.4.0')], 'affected')
        self.assertEqual(check([e], '12.3.4').state, State.UNKNOWN)

    def test_outside_range_watch_with_affected_default(self):
        e = entry([row('11.0.0', '11.2.0')], 'affected')
        self.assertEqual(check([e], '>=12.3.4, <=12.3.5').state, State.UNKNOWN)

    def test_history_cannot_hide_wildcard_affected_entry(self):
        entries = [entry([row('0', '1.0.0')]),
                   entry([row('2.0.0', '2.*', inclusive=True)])]
        self.assertEqual(check(entries, '2.5.6').state, State.UNKNOWN)

    def test_history_cannot_hide_wildcard_range(self):
        entries = [entry([row('0', '1.0.0')]),
                   entry([row('2.0.0', '2.*', inclusive=True)])]
        self.assertEqual(check(entries, '>=2.5.6, <=2.5.7').state, State.UNKNOWN)

    def test_history_entry_order_does_not_prove_safety(self):
        entries = [entry([row('2.0.0', '2.*', inclusive=True)]),
                   entry([row('0', '1.0.0')])]
        self.assertEqual(check(entries, '2.5.6').state, State.UNKNOWN)

    def test_same_history_case_dotted_preserves_unknown(self):
        entries = [entry([row('0', '1.0.0')]),
                   entry([row('2.0.0', '2.*', inclusive=True)])]
        self.assertEqual(check(entries, '2.5.6', 'dotted').state, State.UNKNOWN)

    def test_out_of_order_rows(self):
        e = entry([row('11.0.0', '11.2.0'), row('9.0.0', '9.4.0')], 'affected')
        self.assertEqual(check([e], '11.1.3').state, State.AFFECTED)
        e['versions'].reverse()
        self.assertEqual(check([e], '11.1.3').state, State.AFFECTED)

    def test_overlapping_ranges(self):
        e = entry([row('11.0.0', '11.2.0'), row('9.0.0', '13.0.0')])
        self.assertEqual(check([e], '11.3.7').state, State.AFFECTED)

    def test_tied_lower_bounds(self):
        e = entry([row('11.0.0', '11.2.0'), row('11.0.0', '11.4.0')])
        self.assertEqual(check([e], '11.3.7').state, State.AFFECTED)

    def test_inclusive_endpoint(self):
        e = entry([row('11.0.0', '11.2.7', inclusive=True)])
        self.assertEqual(check([e], '11.2.7').state, State.AFFECTED)

    def test_wildcard_alone(self):
        e = entry([row('2.0.0', '2.*', inclusive=True)])
        self.assertEqual(check([e], '2.5.6').state, State.UNKNOWN)

    def test_mixed_hints(self):
        e = entry([row('9.0.0', '9.4.0'), row('11.0.0', '11.4.0', kind='python')])
        self.assertEqual(check([e], '11.3.7', 'dotted').state, State.AFFECTED)

    def test_mixed_incompatible_types(self):
        e = entry([row('9.0.0', '9.4.0'), row('11.0.0', '11.4.0', kind='git')])
        self.assertEqual(check([e], '11.3.7').state, State.UNKNOWN)

    def test_multiple_entries_affected_wins(self):
        entries = [entry([row('9.0.0', '9.4.0')]), entry([row('11.0.0', '11.4.0')])]
        self.assertEqual(check(entries, '11.3.7').state, State.AFFECTED)

    def test_history_does_not_hide_decidable_affected(self):
        entries = [entry([row('0', '1.0.0')]), entry([row('2.0.0', '3.0.0')])]
        self.assertEqual(check(entries, '2.5.6').state, State.AFFECTED)

    def test_python_fixed_release(self):
        e = entry([row('11.0.0a1', '11.0.0rc2', kind='python')], 'unaffected')
        self.assertEqual(check([e], '11.0.0rc7', 'python').state, State.NOT_AFFECTED)

    def test_python_prerelease_affected(self):
        e = entry([row('11.0.0a1', '11.0.0rc2', kind='python')], 'unaffected')
        self.assertEqual(check([e], '11.0.0b7', 'python').state, State.AFFECTED)

    def test_placeholder_vendor_cap(self):
        e = entry([row('2.0.0', '3.0.0')], vendor='n/a')
        self.assertEqual(check([e], '2.5.6', loose=True).state, State.UNKNOWN)

    def test_other_product_does_not_exclude(self):
        entries = [entry([row('0', '3.0.0')], product='Other'),
                   entry([row('2.0.0', '3.0.0')])]
        self.assertEqual(check(entries, '2.5.6').state, State.AFFECTED)

    def test_opaque_range_stays_unknown(self):
        self.assertEqual(check([entry([row('0', '1.0.0')])], '2.5.6', 'opaque').state,
                         State.UNKNOWN)


if __name__ == '__main__':
    unittest.main()

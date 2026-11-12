"""Regression coverage for bounded numeric wildcard CNA range starts."""

from dataclasses import replace
import unittest

from cornicen.applicability import State, resolve
from cornicen.cli import _active
from cornicen.identity import AliasMap
from cornicen.versions import Scheme, compare
from cornicen.watchlist import Watch, load_watchlist_text
from tests.test_applicability import entry, record, row


ORDERED = (Scheme.SEMVER, Scheme.DOTTED, Scheme.DEBIAN, Scheme.PYTHON)


class WildcardStartTests(unittest.TestCase):
    def setUp(self):
        self.aliases = AliasMap.load()
        self.watch = Watch('widget', 'Widget', (('acme', 'widget'),),
                           (), '4.7.11', Scheme.SEMVER, False)

    def check(self, rows, version, expected, scheme=Scheme.SEMVER, kev=None,
              default='unaffected', loaded=False):
        affected = entry(rows, default, vendor='acme', product='widget')
        if default is None:
            del affected['defaultStatus']
        rec = record(affected)
        watch = replace(self.watch, version=version, scheme=scheme)
        if loaded:
            watch, = load_watchlist_text(f'''[[watch]]
id = "widget"
name = "Widget"
match = ["acme:widget"]
version = "{version}"
scheme = "{scheme.value}"
''')
        result = resolve(rec, kev, watch, self.aliases)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, expected)
        return result

    def test_loader_aliases_and_literal_controls_below_start(self):
        cases = [
            (Scheme.SEMVER, '4.7.0-rc1',
             ('v4.7.0-rc1', 'V4.7.0-rc1', 'v4.7.0-rc1+BUILD')),
            (Scheme.PYTHON, '4.7.0a1', ('v4.7.0a1', '04.7.0a1')),
            (Scheme.PYTHON, '4.7.0rc1',
             ('V4.7.0RC1', '4.07.0rc1', '004.007.000RC01')),
            (Scheme.DEBIAN, '4.7-1',
             ('0:4.7-1', '00:4.7-1', '04.7-1', '4.07-1', '0:04.07-1')),
            (Scheme.DEBIAN, '4.7', ('04.7',)),
            (Scheme.DEBIAN, '4.7+1', ('004.007+1',)),
        ]
        for field in ('lessThan', 'lessThanOrEqual'):
            wildcard = row('4.7.*', **{field: '4.7.12'})
            for default in ('unaffected', None, 'unknown'):
                rows = [wildcard] if default == 'unaffected' else [
                    row('0', lessThan='4.6.0'), wildcard]
                for scheme, literal, aliases in cases:
                    for version in (literal, *aliases):
                        with self.subTest(field=field, default=default,
                                          scheme=scheme, version=version):
                            self.assertEqual(compare(version, literal, scheme), 0)
                            self.check(rows, version, State.UNKNOWN, scheme,
                                       default=default, loaded=True)

    def test_loader_earlier_lines_and_debian_epoch_control(self):
        for field in ('lessThan', 'lessThanOrEqual'):
            rows = [row('4.7.*', **{field: '4.7.12'})]
            for scheme, versions in [
                    (Scheme.SEMVER, ('4.6.9', 'v4.6.9')),
                    (Scheme.PYTHON, ('4.6.9', 'v4.6.9')),
                    (Scheme.DEBIAN, ('0:4.6-1', '1:4.7-1'))]:
                for version in versions:
                    with self.subTest(field=field, scheme=scheme, version=version):
                        self.check(rows, version, State.NOT_AFFECTED, scheme, loaded=True)

    def test_loader_real_world_adjacent_lines(self):
        rows = [row('6.4.*', lessThan='6.4.20'),
                row('6.5.*', lessThan='6.5.17'),
                row('6.6.*', lessThan='6.6.9')]
        for scheme in (Scheme.DOTTED, Scheme.SEMVER):
            for version, expected in [('6.5.17', State.NOT_AFFECTED),
                                      ('6.5.16', State.AFFECTED)]:
                with self.subTest(scheme=scheme, version=version):
                    self.check(rows, version, expected, scheme, loaded=True)

    def test_line_floor_ordering_and_lowest_prereleases(self):
        for scheme, floor, members, earlier in [
                (Scheme.SEMVER, '4.7.0-0',
                 ('v4.7.0-0', '4.7.0-0.0', '4.7.0-rc1', '4.7.0'), 'v4.6.9'),
                (Scheme.PYTHON, '4.7.0a0',
                 ('V04.007.000A00', '4.7.0a1', '4.7.0b0', '4.7.0'), 'v4.6.9'),
                (Scheme.DEBIAN, '4.7~',
                 ('04.7', '0:4.7-1', '00:4.7+1', '4.7.0', '1:4.7-1'), '0:4.6-1'),
                (Scheme.DOTTED, '4.7', ('04.7', '4.7.1'), 'v4.6.9')]:
            with self.subTest(scheme=scheme):
                self.assertEqual(compare(floor, floor, scheme), 0)
                self.assertLess(compare(earlier, floor, scheme), 0)
                for member in members:
                    self.assertGreaterEqual(compare(member, floor, scheme), 0)
        self.assertIsNone(compare('04.7.0', '4.7', Scheme.DOTTED))
        for scheme, version in [(Scheme.SEMVER, 'v4.7.0-0'),
                                (Scheme.PYTHON, 'V04.007.000A00')]:
            with self.subTest(scheme=scheme):
                self.check([row('4.7.*', lessThan='4.7.12')],
                           version, State.UNKNOWN, scheme, loaded=True)

    def test_two_lines_and_exclusive_endpoints(self):
        rows = [row('4.7.*', lessThan='4.7.12', versionType='semver'),
                row('4.8.*', lessThan='4.8.3', versionType='custom')]
        for scheme in ORDERED:
            for version, expected in [('4.7.11', State.AFFECTED),
                                      ('4.7.12', State.NOT_AFFECTED),
                                      ('4.7.0', State.AFFECTED),
                                      ('4.6.9', State.NOT_AFFECTED),
                                      ('4.8.0', State.AFFECTED),
                                      ('4.8.2', State.AFFECTED),
                                      ('4.8.3', State.NOT_AFFECTED)]:
                with self.subTest(scheme=scheme, version=version):
                    self.check(rows, version, expected, scheme)
            # Outside the first line alone, before the second row is considered.
            self.check(rows[:1], '4.8.0', State.NOT_AFFECTED, scheme)

    def test_inclusive_endpoint(self):
        for scheme in ORDERED:
            for version, expected in [('4.7.12', State.AFFECTED),
                                      ('4.7.13', State.NOT_AFFECTED)]:
                with self.subTest(scheme=scheme, version=version):
                    self.check([row('4.7.*', lessThanOrEqual='4.7.12')],
                               version, expected, scheme)

    def test_range_watches_keep_raw_wildcard_boundaries(self):
        for scheme in ORDERED:
            for version, expected in [('>=4.7.0, <4.7.12', State.UNKNOWN),
                                      ('>=4.7.12, <4.8.0', State.UNKNOWN),
                                      ('=4.7.0', State.UNKNOWN)]:
                with self.subTest(scheme=scheme, version=version):
                    self.check([row('4.7.*', lessThan='4.7.12')],
                               version, expected, scheme)

    def test_below_floor_review_reproducers(self):
        cases = [(Scheme.DEBIAN, '4.7'),
                 (Scheme.DEBIAN, '4.7-1234'),
                 (Scheme.DEBIAN, '4.7+1234'),
                 (Scheme.DEBIAN, '4.7+1'),
                 (Scheme.SEMVER, '4.7.0-rc1'),
                 (Scheme.PYTHON, '4.7.0a1'),
                 (Scheme.PYTHON, '4.7.0rc1')]
        for field in ('lessThan', 'lessThanOrEqual'):
            for default in (None, 'unknown', 'unaffected', 'affected'):
                for scheme, watch in cases:
                    for version in (watch, '=' + watch, f'>={watch}, <4.7.0'):
                        with self.subTest(field=field, default=default,
                                          scheme=scheme, version=version):
                            self.check([row('4.7.*', **{field: '4.7.12'})],
                                       version, State.UNKNOWN, scheme, default=default)
                with self.subTest(field=field, default=default, shortened=True):
                    self.check([row('7.2.*', **{field: '7.2.1-69057'})],
                               '7.2-64570', State.UNKNOWN, Scheme.DEBIAN, default=default)

    def test_bare_and_revised_prefix_lengths_one_to_five(self):
        for prefix, upper in [('4', '4.7.12'), ('4.7', '4.7.12'),
                              ('1.04.1', '1.04.1.12'),
                              ('1.04.1.592', '1.04.1.592.12'),
                              ('1.04.1.592.3', '1.04.1.592.3.12')]:
            for field in ('lessThan', 'lessThanOrEqual'):
                for watch in (prefix, prefix + '-1234', prefix + '+1234'):
                    with self.subTest(prefix=prefix, field=field, watch=watch):
                        self.check([row(prefix + '.*', **{field: upper})],
                                   watch, State.UNKNOWN, Scheme.DEBIAN)
                with self.subTest(prefix=prefix, field=field, scheme='dotted'):
                    self.check([row(prefix + '.*', **{field: upper})],
                               prefix, State.UNKNOWN, Scheme.DOTTED)

    def test_below_floor_history_and_overlapping_rows(self):
        cases = [(Scheme.SEMVER, '4.7.0-rc1'),
                 (Scheme.PYTHON, '4.7.0a1'), (Scheme.DEBIAN, '4.7-1234')]
        for field in ('lessThan', 'lessThanOrEqual'):
            history = [row('0', lessThan='4.6.0'),
                       row('4.7.*', **{field: '4.7.12'})]
            overlapping = [row('4.7.*', **{field: '4.7.10'}),
                           row('4.7.*', **{field: '4.7.12'}),
                           row('4.*', lessThan='4.6.0')]
            for rows in (history, overlapping):
                for ordered in (rows, list(reversed(rows))):
                    for default in (None, 'unknown', 'unaffected', 'affected'):
                        for scheme, watch in cases:
                            for version in (watch, f'>={watch}, <4.7.0'):
                                with self.subTest(rows=ordered, default=default,
                                                  scheme=scheme, version=version):
                                    self.check(ordered, version, State.UNKNOWN,
                                               scheme, default=default)

    def test_cross_line_upper_bounds_remain_unknown(self):
        for scheme in Scheme:
            for field in ('lessThan', 'lessThanOrEqual'):
                for status in ('affected', 'unaffected'):
                    for default in (None, 'unknown', 'unaffected', 'affected'):
                        for watch in ('4.8.0', '=4.8.0', '>=4.8.0, <4.8.1'):
                            with self.subTest(scheme=scheme, field=field, status=status,
                                              default=default, watch=watch):
                                self.check([row('4.7.*', status, **{field: '4.9.0'})],
                                           watch, State.UNKNOWN, scheme, default=default)

    def test_upper_bound_must_have_prefix_dot(self):
        for upper in ('4.70.1', '4.7', '4.7-1'):
            for scheme in ORDERED:
                with self.subTest(upper=upper, scheme=scheme):
                    self.check([row('4.7.*', lessThan=upper)],
                               '4.6.9', State.UNKNOWN, scheme)

    def test_short_and_long_numeric_prefixes(self):
        for scheme in ORDERED:
            with self.subTest(scheme=scheme):
                self.check([row('4.*', lessThan='4.7.12')],
                           '4.0.0', State.AFFECTED, scheme)
        for scheme in (Scheme.DOTTED, Scheme.DEBIAN):
            with self.subTest(scheme=scheme):
                self.check([row('4.7.1.*', lessThan='4.7.1.12')],
                           '4.7.1.0', State.AFFECTED, scheme)

    def test_unsupported_starts_remain_unknown(self):
        for scheme in Scheme:
            for version_row in [row('4.7.*'), row('x.*', lessThan='4.7.12'),
                                row('4.7.*suffix', lessThan='4.7.12'),
                                row('4.7', lessThan='4.7.12')]:
                # An ordinary short start still follows its comparator's rules.
                if version_row['version'] == '4.7' and scheme in (
                        Scheme.DOTTED, Scheme.DEBIAN):
                    continue
                with self.subTest(scheme=scheme, row=version_row):
                    self.check([version_row], '4.7.12', State.UNKNOWN, scheme)

    def test_invalid_conversion_or_upper_cannot_prove_safety(self):
        for scheme in (Scheme.SEMVER, Scheme.PYTHON):
            with self.subTest(scheme=scheme):
                self.check([row('4.7.1.*', lessThan='4.7.12')],
                           '4.8.0', State.UNKNOWN, scheme)
        self.check([row('04.7.*', lessThan='4.7.12')],
                   '4.8.0', State.UNKNOWN)
        for scheme in Scheme:
            for upper in ('*', '4.7.*', 'invalid'):
                with self.subTest(scheme=scheme, upper=upper):
                    self.check([row('4.7.*', lessThan=upper)],
                               '4.8.0', State.UNKNOWN, scheme)
        self.check([row('4.7.*', lessThan='4.7.12')],
                   '4.7.11', State.UNKNOWN, Scheme.OPAQUE)

    def test_existing_star_upper_bound_is_unchanged(self):
        for scheme in ORDERED:
            with self.subTest(scheme=scheme):
                self.check([row('4.7.0', lessThan='*')],
                           '4.8.0', State.AFFECTED, scheme)

    def test_kev_unknown_alerts_but_fixed_version_is_inactive(self):
        kev = {'cveID': 'CVE-2026-1000', 'vendorProject': 'acme', 'product': 'widget'}
        unknown = self.check([row('4.7.*')], '4.7.12', State.UNKNOWN, kev=kev)
        self.assertTrue(unknown.exploited)
        self.assertTrue(_active(unknown))
        fixed = self.check([row('4.7.*', lessThan='4.7.12')],
                           '4.7.12', State.NOT_AFFECTED, kev=kev)
        self.assertTrue(fixed.exploited)
        self.assertFalse(_active(fixed))

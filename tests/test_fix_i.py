"""Real CNA spellings and comparator strings (Fix I)."""

import copy
import json
from pathlib import Path
import unittest

from cornicen.applicability import Result, State, resolve
from cornicen.identity import AliasMap
from cornicen.versions import Scheme
from cornicen.watchlist import Watch, load_watchlist


FIXTURES = Path(__file__).parent / 'fixtures' / 'real_matches'
ROOT = Path(__file__).resolve().parents[1]


def fixture(cve):
    return json.loads((FIXTURES / (cve + '.json')).read_text())


def watch(identity, version, scheme=Scheme.SEMVER):
    return Watch('service', 'Service', (tuple(identity.split(':')),), (), version, scheme, False)


def record(*rows, **extra):
    return {'containers': {'cna': {'affected': [dict(
        vendor='example', product='service', versions=list(rows), **extra)]}}}


class FixITests(unittest.TestCase):
    def setUp(self):
        self.aliases = AliasMap.load()

    def check(self, rec, watched, expected):
        before = copy.deepcopy(rec)
        result = resolve(rec, None, watched, self.aliases)
        self.assertIsInstance(result, Result)
        self.assertEqual(result.state, expected)
        self.assertEqual(rec, before)
        return result

    def test_jellyfin_real_constraints(self):
        for cve, version, expected in [
                ('CVE-2026-49246', '10.8.0', State.AFFECTED),
                ('CVE-2023-48702', '10.8.0', State.AFFECTED),
                ('CVE-2026-49246', '10.11.10', State.NOT_AFFECTED)]:
            with self.subTest(cve=cve, version=version):
                self.check(fixture(cve), watch('jellyfin:jellyfin', version), expected)

    def test_openwrt_real_constraint(self):
        for version, expected in [('21.02.7', State.AFFECTED),
                                  ('24.10.6', State.NOT_AFFECTED)]:
            with self.subTest(version=version):
                self.check(fixture('CVE-2026-30874'),
                           watch('openwrt:openwrt', version, Scheme.DOTTED), expected)

    def test_nginx_ui_real_conjunction(self):
        for version, expected in [('2.3.0', State.AFFECTED),
                                  ('1.9.9', State.NOT_AFFECTED),
                                  ('2.3.8', State.NOT_AFFECTED)]:
            with self.subTest(version=version):
                self.check(fixture('CVE-2026-42221'), watch('0xJacky:nginx-ui', version), expected)

    def test_nginx_alias_selects_open_source_and_custom_uses_watch_scheme(self):
        rec = fixture('CVE-2026-56434')
        watched = watch('nginx:nginx', '1.31.2')
        # NGINX Open Source lists 1.31.2 <= v < 1.31.3 with versionType custom: custom has no
        # ordering of its own, so the watch's semver scheme decides it.
        result = self.check(rec, watched, State.AFFECTED)
        self.assertIn('nginx open source', result.evidence)
        # Both the fix and later patch lie outside every listed affected range.
        self.check(rec, watch('nginx:nginx', '1.31.3'), State.UNKNOWN)
        self.check(rec, watch('nginx:nginx', '1.31.303'), State.UNKNOWN)
        # A named, different ordering (rpm, git) is still a conflict and stays unknown.
        for row in rec['containers']['cna']['affected'][1]['versions']:
            row['versionType'] = 'rpm'
        self.check(rec, watched, State.UNKNOWN)
        # Plus is a separate product: removing Open Source leaves no identity match.
        rec['containers']['cna']['affected'].pop()
        self.assertIsNone(resolve(rec, None, watched, self.aliases))

    def test_nginx_alias_is_bidirectional_and_excludes_plus(self):
        identities = {('f5', 'nginx open source'), ('nginx', 'nginx'), ('f5', 'nginx')}
        for identity in identities:
            self.assertEqual(self.aliases.expand(identity), identities)
        self.assertEqual(self.aliases.expand(('f5', 'nginx plus')), {('f5', 'nginx plus')})

    def test_openwrt_asu_git_boundary_is_unknown(self):
        for scheme, version in [(Scheme.SEMVER, '1.0.0'), (Scheme.DOTTED, '24.10.6'),
                                (Scheme.OPAQUE, '920c8a1'), (Scheme.OPAQUE, 'other')]:
            with self.subTest(scheme=scheme):
                self.check(fixture('CVE-2024-54143'), watch('openwrt:asu', version, scheme),
                           State.UNKNOWN)

    def test_comparator_shapes_and_whitespace(self):
        for text, yes, no in [('< 2.0.0', '1.0.0', '2.0.0'),
                              ('<2.0.0', '1.0.0', '2.0.0'),
                              ('<= 2.0.0', '2.0.0', '2.0.1'),
                              ('= 2.0.0', '2.0.0', '1.0.0'),
                              ('>= 2.0.0', '2.0.0', '1.0.0'),
                              ('>2.0.0', '2.0.1', '2.0.0'),
                              ('>= 1.0.0, < 2.0.0', '1.0.0', '2.0.0'),
                              ('>=1.0.0, <2.0.0', '1.0.0', '2.0.0'),
                              (' \t>= 1.0.0 ,\n <= 2.0.0\t', '2.0.0', '2.0.1')]:
            rec = record({'version': text, 'status': 'affected'})
            for version, expected in [(yes, State.AFFECTED), (no, State.NOT_AFFECTED)]:
                with self.subTest(text=text, version=version):
                    self.check(rec, watch('example:service', version), expected)

    def test_range_watches_use_constraint_endpoints(self):
        rec = record({'version': '>= 2.0.0, < 3.0.0', 'status': 'affected'})
        for version, expected in [('>=1.0.0, <2.0.0', State.NOT_AFFECTED),
                                  ('>=1.0.0, <4.0.0', State.AFFECTED),
                                  ('=3.0.0', State.NOT_AFFECTED),
                                  ('>2.0.0, <3.0.0', State.AFFECTED)]:
            with self.subTest(version=version):
                self.check(rec, watch('example:service', version), expected)

    def test_explicit_defaults_statuses_and_history_exclusion(self):
        for status, default, version, expected in [
                ('affected', 'unknown', '3.0.0', State.NOT_AFFECTED),
                ('unaffected', 'affected', '1.0.0', State.NOT_AFFECTED),
                ('unaffected', 'affected', '3.0.0', State.AFFECTED),
                ('unknown', 'unaffected', '1.0.0', State.UNKNOWN),
                ('unknown', 'unaffected', '3.0.0', State.NOT_AFFECTED)]:
            with self.subTest(status=status, default=default, version=version):
                self.check(record({'version': '<2.0.0', 'status': status}, defaultStatus=default),
                           watch('example:service', version), expected)
        self.check(record({'version': '>=1.0.0, <2.0.0', 'status': 'affected'},
                          defaultStatus='unknown'),
                   watch('example:service', '3.0.0'), State.UNKNOWN)

    def test_constraint_status_changes(self):
        rec = record({'version': '>=1.0.0, <3.0.0', 'status': 'affected',
                      'changes': [{'at': '2.0.0', 'status': 'unaffected'}]})
        for version, expected in [('1.5.0', State.AFFECTED), ('2.0.0', State.NOT_AFFECTED),
                                  ('>=2.0.0, <4.0.0', State.NOT_AFFECTED)]:
            self.check(rec, watch('example:service', version), expected)

    def test_plain_versions_and_explicit_bounds_keep_existing_semantics(self):
        for row, version, scheme, expected in [
                ({'version': '1.0.0'}, '2.0.0', Scheme.SEMVER, State.UNKNOWN),
                ({'version': '< 2.0.0', 'lessThan': '3.0.0'}, '1.0.0',
                 Scheme.SEMVER, State.UNKNOWN),
                ({'version': '< 2.0.0', 'lessThanOrEqual': '3.0.0'}, '1.0.0',
                 Scheme.SEMVER, State.UNKNOWN),
                ({'version': 'RomePI 1.0.G'}, 'RomePI 1.0.G', Scheme.OPAQUE, State.AFFECTED),
                ({'version': '1.0.0 - 2.0.0'}, '1.0.0', Scheme.SEMVER, State.UNKNOWN)]:
            self.check(record(dict(row, status='affected')),
                       watch('example:service', version, scheme), expected)

    def test_undecidable_constraint_does_not_prove_exclusion(self):
        for scheme, version, constraint in [
                (Scheme.SEMVER, '1.0.0', '>=2.0.0, <920c8a1'),
                (Scheme.DOTTED, '1.2', '<=1.2.0'),
                (Scheme.OPAQUE, 'build-a', '<build-b')]:
            self.check(record({'version': constraint, 'status': 'affected'}),
                       watch('example:service', version, scheme), State.UNKNOWN)

    def test_example_watches_match_real_identities(self):
        watches = load_watchlist(ROOT / 'examples' / 'watchlist.example.toml')
        self.assertEqual(len(watches), 4)
        records = [fixture(cve) for cve in ('CVE-2026-49246', 'CVE-2026-30874',
                                           'CVE-2026-42221', 'CVE-2026-56434')]
        for watched in watches:
            with self.subTest(watch=watched.id):
                self.assertTrue(any(resolve(rec, None, watched, self.aliases) is not None
                                    for rec in records))

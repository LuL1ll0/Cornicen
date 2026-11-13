# script-purpose: Check watchlist behavior and private diagnostics.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_watchlist.py
"""Watch parsing and conservative identity validation.

Reads local source and fixtures; writes temporary test data and unittest output.
Exit codes: 0 success, 1 failed tests, 2 invalid command arguments.
"""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hashlib import sha256

from cornicen.identity import AliasMap, is_placeholder, normalise
from cornicen.versions import Scheme
from cornicen.watchlist import (
    WatchlistError, collisions, load_watchlist, load_watchlist_text,
)


WATCH = '''[[watch]]
id = "proxy"
name = "Reverse proxy"
match = [" F5 : Nginx "]
version = "v1.25.3"
scheme = "semver"
'''


class WatchlistTests(unittest.TestCase):
    def test_unknown_top_level_keys(self):
        with self.assertRaises(WatchlistError) as caught:
            load_watchlist_text('[[watches]]\nid = "oops"\n[[watchs]]\nid = "oops"\n')
        self.assertEqual(len(caught.exception.problems), 2)
        for key, problem in zip(("watches", "watchs"), caught.exception.problems):
            self.assertEqual(problem, "watch list: unknown table; expected watch or accept")
        self.assertEqual(load_watchlist_text(""), ())

    def test_unknown_entry_keys(self):
        for key in ("versions", "matches", "typo"):
            with self.subTest(key=key), self.assertRaisesRegex(WatchlistError, "watch entry 1.*unknown key"):
                load_watchlist_text(WATCH + f'{key} = "oops"\n')

    def test_version_matches_scheme(self):
        for scheme, invalid in (
                ("semver", ("~1.0", ">1 <2", "latest", "1.x", "*", ">=abc", "1.0", ">=1.0.0, <abc")),
                ("dotted", ("latest", "1.x", ">=abc", "1 .0")),
                ("debian", ("latest", ">=abc")),
                ("python", ("3.14", "3.14.0.dev1", "3.14.0+local", ">=abc")),
                ("opaque", (">1", ">=1", "<2", "<=2", "~1", "^1", ">1 <2"))):
            for version in invalid:
                with self.subTest(scheme=scheme, version=version), self.assertRaises(WatchlistError):
                    load_watchlist_text(WATCH.replace("semver", scheme).replace("v1.25.3", version))
        for scheme, version in (("semver", ">=1.0.0, <2.0.0"), ("dotted", ">=1.0, <2.0"),
                                ("python", "3.14.11"), ("python", ">=3.14.0a1, <3.14.0b1"),
                                ("debian", "1:2.0-1"), ("opaque", "release-a"), ("opaque", "=release-a"),
                                ("opaque", "RomePI 1.0.0.G")):
            self.assertEqual(load_watchlist_text(WATCH.replace("semver", scheme).replace(
                "v1.25.3", version))[0].version, version)

    def test_nfkc_casefold_normalisation(self):
        self.assertEqual(normalise("  ＦＯＯ\tStraße  "), "foo strasse")
        self.assertEqual(normalise("Cafe\u0301"), normalise("Café"))
        self.assertEqual(normalise("ＦＯＯ－ＢＡＲ"), "foo-bar")

    def test_semver_large_numeric_identifiers_are_valid(self):
        for digits in (4300, 4301, 10000):
            huge = '9' * digits
            for template in ('{}.0.0', '1.{}.0', '1.0.{}', '1.0.0-{}'):
                for constraint in ('{}', '>={}'):
                    with self.subTest(digits=digits, template=template, constraint=constraint):
                        version = constraint.format(template.format(huge))
                        watches = load_watchlist_text(WATCH.replace('v1.25.3', version))
                        self.assertEqual(len(watches), 1)
                        self.assertEqual(watches[0].version, version)

    def test_alias_expanded_collisions(self):
        watches = load_watchlist_text(WATCH + WATCH.replace('"proxy"', '"other"').replace(
            ' F5 : Nginx ', 'nginx:nginx'))
        self.assertEqual(collisions(watches), [])
        self.assertEqual(len(collisions(watches, AliasMap.load())), 1)

    def test_watch_ids_are_safe_and_case_insensitively_unique(self):
        for value in ("bad id", "../path", "x" * 65, "é"):
            with self.subTest(value=value), self.assertRaisesRegex(WatchlistError, "id"):
                load_watchlist_text(WATCH.replace('"proxy"', f'"{value}"'))
        with self.assertRaisesRegex(WatchlistError, "duplicate"):
            load_watchlist_text(WATCH + WATCH.replace('"proxy"', '" PROXY "'))
        self.assertEqual(load_watchlist_text(WATCH.replace('"proxy"', '" A._-09 "'))[0].id, "A._-09")

    def test_recursive_watch_toml_is_rejected(self):
        with patch("cornicen.watchlist.tomllib.loads", side_effect=RecursionError):
            with self.assertRaises(WatchlistError):
                load_watchlist_text("")

    def test_required_id_names_entry(self):
        with self.assertRaises(WatchlistError) as caught:
            load_watchlist_text(WATCH.replace('id = "proxy"\n', ''))
        self.assertIn("watch entry 1", str(caught.exception))
        self.assertNotIn("Reverse proxy", str(caught.exception))
        self.assertIn("id", str(caught.exception))
        self.assertIsInstance(caught.exception.problems, list)

    def test_duplicate_id_rejected(self):
        with self.assertRaisesRegex(WatchlistError, "proxy"):
            load_watchlist_text(WATCH + WATCH)

    def test_unknown_scheme_rejected(self):
        with self.assertRaisesRegex(WatchlistError, "scheme"):
            load_watchlist_text(WATCH.replace('"semver"', '"imaginary"'))

    def test_match_requires_vendor_product(self):
        for identity in ("nginx", "f5:nginx:extra", ":nginx", "f5:"):
            with self.subTest(identity=identity), self.assertRaises(WatchlistError):
                load_watchlist_text(WATCH.replace(' F5 : Nginx ', identity))

    def test_na_identity_never_matches(self):
        self.assertTrue(is_placeholder("N/A "))
        aliases = AliasMap.load()
        for placeholder in ("N/A ", "na", "unknown", "", "-", "none", "null", "tbd",
                            "unspecified", "not applicable", "not available", "n / a", "n.a.",
                            "n/a.", "--", "–", "—", "?", "n/a\u200b"):
            for identity in ((placeholder, "nginx"), ("f5", placeholder)):
                with self.subTest(identity=identity):
                    self.assertEqual(aliases.expand(identity), frozenset())
                    with self.assertRaises(WatchlistError):
                        load_watchlist_text(WATCH.replace(' F5 : Nginx ', ':'.join(identity)))
            with self.assertRaises(WatchlistError):
                load_watchlist_text(WATCH + f'product_only = ["{placeholder}"]\n')

    def test_normalisation_keeps_punctuation(self):
        self.assertEqual(normalise("  Example\t CORP \n"), "example corp")
        self.assertNotEqual(normalise("foo-bar"), normalise("foobar"))

    def test_valid_watch_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watch.toml"
            path.write_text(WATCH + 'product_only = [" Nginx  Server "]\neol = true\n')
            watches = load_watchlist(path)
        self.assertEqual(len(watches), 1)
        watch = watches[0]
        self.assertEqual(watch.match, (("f5", "nginx"),))
        self.assertEqual(watch.product_only, ("nginx server",))
        self.assertEqual(watch.scheme, Scheme.SEMVER)
        self.assertEqual(watch.version, "v1.25.3")
        self.assertTrue(watch.eol)

    def test_collisions_reported_not_rejected(self):
        watches = load_watchlist_text(WATCH + WATCH.replace('"proxy"', '"other"'))
        reports = collisions(watches)
        self.assertEqual(len(reports), 1)
        for text in ("proxy", "other", "nginx"):
            self.assertIn(text, reports[0])
        self.assertEqual(collisions(watches[:1]), [])

    def test_product_only_collision(self):
        watches = load_watchlist_text(WATCH + WATCH.replace('"proxy"', '"other"').replace(
            'match = [" F5 : Nginx "]', 'product_only = ["nginx"]'))
        self.assertEqual(len(collisions(watches)), 1)

    def test_whole_list_validation(self):
        with self.assertRaises(WatchlistError) as caught:
            load_watchlist_text(WATCH + WATCH.replace('"proxy"', '"other"').replace(
                'scheme = "semver"', 'scheme = "invalid"'))
        self.assertIn("other", str(caught.exception))
        self.assertEqual(load_watchlist_text(""), ())

    def test_bad_shapes_and_toml(self):
        for text in ('[[watch]', 'watch = "bad"', WATCH.replace(
                'match = [" F5 : Nginx "]', 'match = "f5:nginx"'),
                WATCH.replace('version = "v1.25.3"', 'version = 123'),
                WATCH + 'eol = "yes"\n', WATCH.replace(
                    'match = [" F5 : Nginx "]\n', '')):
            with self.subTest(text=text), self.assertRaises(WatchlistError):
                load_watchlist_text(text)

    def test_range_syntax(self):
        self.assertEqual(load_watchlist_text(WATCH.replace('v1.25.3', '>=1.0.0, <2.0.0'))[0].version,
                         '>=1.0.0, <2.0.0')
        with self.assertRaises(WatchlistError):
            load_watchlist_text(WATCH.replace('v1.25.3', '=>1'))


class AliasTests(unittest.TestCase):
    def test_builtin_symmetric_and_versioned(self):
        aliases = AliasMap.load()
        self.assertTrue(aliases.version)
        expected = frozenset({("f5", "nginx"), ("nginx", "nginx"),
                              ("f5", "nginx open source")})
        self.assertEqual(aliases.expand((" F5 ", "NGINX")), expected)
        self.assertEqual(aliases.expand(("nginx", "nginx")), expected)

    def test_no_builtin_is_exact(self):
        aliases = AliasMap.load(builtin=False)
        self.assertEqual(aliases.expand((" F5 ", "NGINX")), frozenset({("f5", "nginx")}))

    def test_extra_extends_transitively_and_changes_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.toml"
            path.write_text('version = "local-1"\n[[alias]]\nidentities = '
                            '["nginx:nginx", "examplecorp:proxy"]\n')
            aliases = AliasMap.load(extra=path)
        expanded = aliases.expand(("examplecorp", "proxy"))
        self.assertIn(("f5", "nginx"), expanded)
        self.assertEqual(aliases.expand(("f5", "nginx")), expanded)
        self.assertIn("local-1", aliases.version)
        self.assertNotEqual(aliases.version, AliasMap.load().version)

    def test_extra_rejects_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.toml"
            path.write_text('version = "local-1"\n[[alias]]\nidentities = ["n/a:nginx", "f5:nginx"]\n')
            with self.assertRaises(ValueError):
                AliasMap.load(extra=path)

    def test_alias_source_hashes_and_merge_warnings(self):
        builtin_text = Path("src/cornicen/data/aliases.toml").read_text(encoding="utf-8")
        self.assertIn(sha256(builtin_text.encode()).hexdigest()[:8], AliasMap.load().version)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.toml"
            text = ('version = "local"\n[[alias]]\nidentities = '
                    '["nginx:nginx", "example:bridge"]\n[[alias]]\nidentities = '
                    '["example:bridge", "microsoft:windows"]\n')
            path.write_text(text)
            aliases = AliasMap.load(extra=path)
            self.assertIn(sha256(text.encode()).hexdigest()[:8], aliases.version)
            self.assertEqual(len(aliases.warnings), 1)
            self.assertIn("2", aliases.warnings[0])
            self.assertIn("aliases_path", aliases.warnings[0])
            self.assertNotIn(str(path), aliases.warnings[0])
            self.assertIn(("microsoft", "windows"), aliases.expand(("f5", "nginx")))
            path.write_text(text + "# changed\n")
            self.assertNotEqual(aliases.version, AliasMap.load(extra=path).version)
            self.assertEqual(AliasMap.load(builtin=False, extra=path).warnings, [])

    def test_expand_requires_pair_of_strings(self):
        for identity in ("ab", ["f5", "nginx"], ("f5",), ("a", "b", "c"), (1, "b"), None):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                AliasMap().expand(identity)

    def test_recursive_alias_toml_is_rejected(self):
        with patch("cornicen.identity.tomllib.loads", side_effect=RecursionError):
            with self.assertRaises(ValueError):
                AliasMap.load()

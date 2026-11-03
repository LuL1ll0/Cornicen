import unittest

from cornicen.versions import Scheme, compare, parse_constraint, satisfies


class VersionTests(unittest.TestCase):
    def assert_order(self, a, b, scheme, expected):
        self.assertEqual(compare(a, b, scheme), expected)
        self.assertEqual(compare(b, a, scheme), -expected)

    def test_scheme_values(self):
        self.assertEqual([s.value for s in Scheme],
                         ["semver", "dotted", "debian", "opaque"])

    def test_semver_release_after_prerelease(self):
        self.assert_order("1.0.0-rc.1", "1.0.0", Scheme.SEMVER, -1)

    def test_semver_build_metadata_ignored(self):
        self.assert_order("1.0.0+build.1", "1.0.0+other", Scheme.SEMVER, 0)

    def test_leading_v_accepted(self):
        for scheme, version in ((Scheme.SEMVER, "1.25.3"),
                                (Scheme.DOTTED, "1.25.3")):
            for prefix in ("v", "V"):
                with self.subTest(scheme=scheme, prefix=prefix):
                    self.assert_order(prefix + version, version, scheme, 0)
            self.assertIsNone(compare("vv" + version, version, scheme))

    def test_semver_precedence_sequence(self):
        versions = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
                    "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                    "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"]
        for a, b in zip(versions, versions[1:]):
            with self.subTest(a=a, b=b):
                self.assert_order(a, b, Scheme.SEMVER, -1)

    def test_semver_invalid_is_unknown_even_if_identical(self):
        for version in ("", "1", "1.0", "01.0.0", "1.01.0", "1.0.01",
                        "1.0.0-01", "1.0.0-", "1.0.0+", "1.0.0-a..b",
                        "1.0.0+a..b", "1.0.0_a", " 1.0.0", "1.0.0\n",
                        "١.0.0"):
            with self.subTest(version=version):
                self.assertIsNone(compare(version, version, Scheme.SEMVER))
                self.assertIsNone(compare("1.0.0", version, Scheme.SEMVER))

    def test_semver_numeric_build_leading_zero_allowed(self):
        self.assert_order("1.0.0+001", "1.0.0", Scheme.SEMVER, 0)
        self.assert_order("1.0.0-01a", "1.0.0-1a", Scheme.SEMVER, -1)

    def test_semver_large_numeric_identifiers(self):
        for digits in (4300, 4301, 10000):
            huge = '9' * digits
            larger = '1' + '0' * digits
            for template in ('{}.0.0', '1.{}.0', '1.0.{}', '1.0.0-{}'):
                with self.subTest(digits=digits, template=template):
                    version = template.format(huge)
                    self.assert_order(version, version, Scheme.SEMVER, 0)
                    self.assert_order(version, template.format(larger), Scheme.SEMVER, -1)
                    self.assert_order(version, template.format('8' + '9' * (digits - 1)),
                                      Scheme.SEMVER, 1)
                    self.assertIs(satisfies(version, parse_constraint('>=' + version),
                                            Scheme.SEMVER), True)

    def test_dotted_numeric_order(self):
        self.assert_order("7.2.2", "7.2.10", Scheme.DOTTED, -1)
        self.assert_order("1.43.5.11029", "1.43.5.11030", Scheme.DOTTED, -1)
        self.assert_order("21.02.7", "21.2.7", Scheme.DOTTED, 0)
        self.assert_order("7.1", "7.2.3", Scheme.DOTTED, -1)

    def test_dotted_nonnumeric_is_unknown(self):
        for version in ("7.2.2-72806", "", "1..2", ".1", "1.", "1.a",
                        "1.0+build", " 1.0", "1.0\n", "١.0"):
            with self.subTest(version=version):
                self.assertIsNone(compare(version, version, Scheme.DOTTED))

    def test_dotted_missing_segment_is_zero(self):
        self.assertIsNone(compare("1.2", "1.2.0", Scheme.DOTTED))
        self.assertIsNone(compare("1.2.0", "1.2", Scheme.DOTTED))
        self.assert_order("1.2", "1.2.1", Scheme.DOTTED, -1)
        self.assert_order("21.02.7", "23.05", Scheme.DOTTED, -1)

    def test_dotted_range_with_missing_segments(self):
        self.assertIs(satisfies("1.5", parse_constraint(">=1, <2"),
                                Scheme.DOTTED), True)

    def test_debian_epoch(self):
        self.assert_order("1:1.0", "2.0", Scheme.DEBIAN, 1)
        self.assert_order("0:1.0", "1.0", Scheme.DEBIAN, 0)
        self.assert_order("10:1.0", "2:9.0", Scheme.DEBIAN, 1)

    def test_debian_revision(self):
        self.assert_order("1.2-0ubuntu1", "1.2-1", Scheme.DEBIAN, -1)
        self.assert_order("1.0", "1.0-0", Scheme.DEBIAN, 0)
        self.assert_order("1.0-9", "1.0-10", Scheme.DEBIAN, -1)
        self.assert_order("1.0-a-1", "1.0-a-2", Scheme.DEBIAN, -1)

    def test_debian_tilde(self):
        self.assert_order("1.0~rc1", "1.0", Scheme.DEBIAN, -1)
        self.assert_order("1.0~~", "1.0~", Scheme.DEBIAN, -1)
        self.assert_order("1.0-1~bpo1", "1.0-1", Scheme.DEBIAN, -1)

    def test_debian_character_and_digit_order(self):
        for a, b, expected in (("1.0a", "1.0+", -1),
                               ("1.0A", "1.0a", -1),
                               ("1.0", "1.0a", -1),
                               ("1.09", "1.9", 0),
                               ("1.0a9", "1.0a10", -1),
                               ("1.0+git9", "1.0+git10", -1),
                               ("1:1.0:2", "1:1.0:3", -1)):
            with self.subTest(a=a, b=b):
                self.assert_order(a, b, Scheme.DEBIAN, expected)

    def test_debian_invalid_is_unknown(self):
        for version in ("", "v1.0", "a1.0", "-1", "1.0-", ":1.0",
                        "x:1.0", "1:", "1.0-1:2", "1.0_1", "1.0\n",
                        "1.0-α", "١:1.0"):
            with self.subTest(version=version):
                self.assertIsNone(compare(version, version, Scheme.DEBIAN))

    def test_debian_digit_before_letter(self):
        self.assert_order("1a1", "1aa", Scheme.DEBIAN, -1)
        self.assertIs(satisfies("1a1", parse_constraint("<1aa"),
                                Scheme.DEBIAN), True)

    def test_opaque_equality_only(self):
        self.assertEqual(compare("7.2.2-72806", "7.2.2-72806", Scheme.OPAQUE), 0)
        self.assertIsNone(compare("1", "2", Scheme.OPAQUE))
        self.assertIsNone(compare("v1", "1", Scheme.OPAQUE))

    def test_parse_constraint(self):
        self.assertEqual(parse_constraint(" >=7.0, <7.2.3 "),
                         ((">=", "7.0"), ("<", "7.2.3")))
        self.assertEqual(parse_constraint("=1, > 0, <=2"),
                         (("=", "1"), (">", "0"), ("<=", "2")))
        self.assertEqual(parse_constraint("=1:1.0-0ubuntu1"),
                         (("=", "1:1.0-0ubuntu1"),))
        self.assertEqual(parse_constraint(">=1.0~rc1"), ((">=", "1.0~rc1"),))

    def test_parse_constraint_rejects_bad_syntax(self):
        for text in ("=>1", "", " ", "1", ">=", "==1", "!=1", "~=1",
                     ">>1", "=<1", ">=1,", ",<2", ">1,,<2", ">=1 <2",
                     ">=1 || <2", "=a b", "=1\n2"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_constraint(text)

    def test_satisfies_range(self):
        constraint = parse_constraint(">=7.0, <7.2.3")
        for version, expected in (("7.0", True), ("7.1", True),
                                  ("7.2.3", False), ("6.9", False)):
            with self.subTest(version=version):
                self.assertIs(satisfies(version, constraint, Scheme.DOTTED), expected)

    def test_satisfies_all_operators(self):
        for op, expected in (("=", True), (">=", True), (">", False),
                             ("<=", True), ("<", False)):
            with self.subTest(op=op):
                self.assertIs(satisfies("1.0.0", parse_constraint(op + "1.0.0"),
                                        Scheme.SEMVER), expected)

    def test_satisfies_undecidable(self):
        self.assertIsNone(satisfies("7.2.2-72806", parse_constraint(">=7.0"),
                                   Scheme.DOTTED))
        self.assertIsNone(satisfies("1", parse_constraint("=2"), Scheme.OPAQUE))
        for op in (">=", ">", "<=", "<"):
            with self.subTest(op=op):
                self.assertIsNone(satisfies("1", parse_constraint(op + "1"),
                                           Scheme.OPAQUE))
        self.assertIs(satisfies("1", parse_constraint("=1"), Scheme.OPAQUE), True)

    def test_satisfies_false_conjunct_decides(self):
        for text in ("=1.2.0, >2", ">2, =1.2.0"):
            self.assertIs(satisfies("1.2", parse_constraint(text), Scheme.DOTTED), False)

    def test_satisfies_empty_constraint(self):
        self.assertIs(satisfies("1", (), Scheme.DOTTED), True)


if __name__ == "__main__":
    unittest.main()

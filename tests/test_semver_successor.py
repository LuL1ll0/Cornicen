"""SemVer successor regressions from mutation sweep 2; entirely offline."""
import unittest

from cornicen.applicability import _semver_successor


class SuccessorTests(unittest.TestCase):
    def test_patch_carry_produces_next_release_prerelease_floor(self):
        # Carries affect whether an open interval contains a valid SemVer.
        for patch, successor in [('9', '10'), ('19', '20'), ('99', '100'),
                                 ('1099', '1100'), ('9' * 5000, '1' + '0' * 5000)]:
            with self.subTest(digits=len(patch), suffix=patch[-4:]):
                self.assertEqual(_semver_successor('1.0.' + patch),
                                 '1.0.' + successor + '-0')

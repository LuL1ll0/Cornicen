"""script-purpose: Check that structured audit output leaves the generic wordlist frozen.
script-class: harness
script-trigger: Manual verification of vocabulary generation.
script-tests: tests/test_unknown_digest_outputs.py, tests/test_cvelist_gap.py

Read the generated vocabulary and exercise the diagnostic boundary using local fixtures.
Writes only transient offline test data. Exit 0 on success or 1 on test failure.
Run with PYTHONPATH=src:. python3 tools/test-gen-vocabulary.py.
"""

import unittest


if __name__ == '__main__':
    names = [
        'tests.test_unknown_digest_outputs.UnknownPrivacyTests.test_T12_vocabulary_and_redaction_are_unchanged',
        'tests.test_cvelist_gap.GapTests.test_t18_privacy_never_uses_free_text_detail',
    ]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())

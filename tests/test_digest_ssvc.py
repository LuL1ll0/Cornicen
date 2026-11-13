# script-purpose: Verify SSVC data survives digest grouping in full and compact rows.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_digest_ssvc.py
"""Seam between the 0.1.14 digest-grouping and SSVC lanes. No files, no network.

Run with python -m unittest tests.test_digest_ssvc. Exit 0 means success,
1 means failed tests, and 2 means invalid unittest arguments.
"""

import unittest

from cornicen.render import render
from tests.test_digest_grouping import digest, full, item

ACTIVE = {'Exploitation': 'active', 'Automatable': 'yes', 'Technical Impact': 'total'}


class DigestSsvcTests(unittest.TestCase):
    def test_ssvc_active_top_item_renders_full_with_ssvc_line(self):
        values = [item(1, score=.09, ssvc=ACTIVE)] + [item(n, score=n / 1000) for n in range(2, 7)]
        text = render(digest(values))[1]
        self.assertTrue(text.startswith('6 items on 1 watches: 6 new matches'))
        self.assertIn(full(values[0]), text)
        self.assertIn('SSVC (CISA): exploitation active · automatable yes · technical impact total', text)
        self.assertEqual(text.count('SSVC: not assessed'), 2)  # the other two full rows

    def test_ssvc_active_compact_row_says_so(self):
        values = [item(n, score=(10 - n) / 100) for n in range(1, 6)]
        values[4] = item(5, score=.001, state='unknown', ssvc=ACTIVE)
        text = render(digest(values))[1]
        self.assertIn('CVE-2099-0005 — EPSS 0.10% · unknown · KEV not listed · SSVC exploitation active', text)
        self.assertIn('CVE-2099-0004 — EPSS 6.0% · affected · KEV not listed\n', text + '\n')
        poc = item(6, score=.0005, ssvc=dict(ACTIVE, Exploitation='poc'))
        text = render(digest(values + [poc]))[1]
        line = next(l for l in text.splitlines() if l.startswith('CVE-2099-0006 — '))
        self.assertNotIn('SSVC', line)


if __name__ == '__main__':
    unittest.main()

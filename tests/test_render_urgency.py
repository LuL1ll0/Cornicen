"""Urgent and normal titles must not reverse the visual urgency cue."""
import unittest
from cornicen.model import Notification
from cornicen.render import render


class RenderUrgencyTests(unittest.TestCase):
    def test_title_marks_only_urgent_notifications(self):
        for urgency, prefix in [('urgent', '🚨 '), ('normal', '')]:
            with self.subTest(urgency=urgency):
                notification = Notification('42', 'w', 'CVE-2026-1000',
                    ('new match',), urgency, {'name': 'Server', 'product': 'server',
                                             'version': '1.0', 'state': 'affected'})
                title, _, _, _ = render(notification)
                self.assertEqual(title, prefix + 'Cornicen: CVE-2026-1000 — Server (server 1.0)')

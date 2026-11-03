"""A representation preference: readable UTF-8, not a data-integrity guarantee."""
from pathlib import Path
import tempfile
import unittest
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier


class FileEncodingTests(unittest.TestCase):
    def test_unicode_is_readable_in_dry_run_output(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'notifications.jsonl'
            notification = Notification('42', 'w', 'CVE-2026-1000', (), 'normal',
                                        {'name': 'Café'})
            self.assertTrue(FileNotifier(path).send(notification))
            self.assertIn('Café', path.read_text(encoding='utf-8'))

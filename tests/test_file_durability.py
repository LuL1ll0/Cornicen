"""A file-channel acknowledgement requires a successful durability barrier."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier


class FileDurabilityTests(unittest.TestCase):
    def test_fsync_failure_is_not_acknowledged(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            channel = FileNotifier(Path(directory) / 'notifications.jsonl')
            notification = Notification('42', 'w', 'CVE-2026-1000',
                                        ('new match',), 'urgent', {})
            with patch('cornicen.notify.file.os.fsync', side_effect=OSError('disk failure')):
                self.assertFalse(channel.send(notification))

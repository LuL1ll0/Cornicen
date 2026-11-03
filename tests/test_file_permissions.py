"""Files must start private even if setting final permissions fails."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier


class FilePermissionsTests(unittest.TestCase):
    def test_new_file_is_private_when_fchmod_fails(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'notifications.jsonl'
            channel = FileNotifier(path)
            notification = Notification('42', '', 'test', (), 'normal', {})
            original = os.umask(0)
            try:
                with patch('cornicen.notify.file.os.fchmod', side_effect=OSError('disk failure')):
                    self.assertFalse(channel.send(notification))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                os.umask(original)

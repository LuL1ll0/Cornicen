"""Bulk files follow the configured database volume, including memory stores."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from cornicen.sources import data_directory
from cornicen.store import Store


class SourceDirectoryTests(unittest.TestCase):
    def test_file_store_and_memory_store_use_the_right_volume(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            volume = Path(directory).resolve()
            store = Store(str(volume / 'state.db'))
            self.addCleanup(store.connection.close)
            http = SimpleNamespace(data_dir=volume / 'other')
            result = data_directory(http, store)
            self.assertEqual(result, volume)
            self.assertIs(result, http.data_dir)
            with tempfile.TemporaryFile(dir=result) as target:
                target.write(b'bulk archive')
            memory = Store(':memory:')
            self.addCleanup(memory.connection.close)
            original = volume / 'memory'
            http.data_dir = original
            self.assertIs(data_directory(http, memory), original)
            self.assertIs(http.data_dir, original)

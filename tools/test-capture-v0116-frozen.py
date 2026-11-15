# script-purpose: Verify frozen capture coverage and deterministic regeneration.
# script-class: harness
# script-trigger: Run manually after tools/capture_v0116_frozen.py.
# script-tests: tools/test-capture-v0116-frozen.py
"""Read frozen captures and replay inputs; write a temporary workspace capture.

Usage: PYTHONPATH=src python3 tools/test-capture-v0116-frozen.py
Exit 0 on successful checks, 1 on unittest failure.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('capture', ROOT / 'tools/capture_v0116_frozen.py')
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def test_every_replay_and_status_captured(self):
        frozen = ROOT / 'tests/fixtures/v0116_frozen'
        expected = {str(p.relative_to(ROOT / 'tests/replay')).removesuffix('.input.jsonl')
                    for p in (ROOT / 'tests/replay').rglob('*.input.jsonl')}
        actual = {str(p.relative_to(frozen / 'replays')).removesuffix('.json')
                  for p in (frozen / 'replays').rglob('*.json')}
        self.assertEqual(actual, expected)
        for state in ('missing', 'empty', 'populated'):
            self.assertTrue((frozen / 'status' / (state + '.txt')).read_text())
            json.loads((frozen / 'status' / (state + '.json')).read_text())
        store = capture.Store(':memory:')
        try:
            store.migrate()
            self.assertEqual(capture.dump(store), json.loads((frozen / 'status/empty.database.json').read_text()))
        finally:
            store.connection.close()

    def test_regeneration_is_byte_identical(self):
        frozen = ROOT / 'tests/fixtures/v0116_frozen'
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            regenerated = Path(temp)
            capture.capture(regenerated)
            originals = {str(p.relative_to(frozen)) for p in frozen.rglob('*') if p.is_file()}
            copies = {str(p.relative_to(regenerated)) for p in regenerated.rglob('*') if p.is_file()}
            self.assertEqual(originals, copies)
            for name in sorted(originals):
                with self.subTest(file=name):
                    self.assertEqual((frozen / name).read_bytes(), (regenerated / name).read_bytes())


if __name__ == '__main__':
    unittest.main()

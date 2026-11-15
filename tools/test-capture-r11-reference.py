# script-purpose: Verify independent R11 reference provenance and byte-identical capture.
# script-class: harness
# script-trigger: unittest discovery through tests/test_r11_differential.py.
# script-tests: tools/test-capture-r11-reference.py
"""Read frozen R11 references; write a temporary regenerated copy under tempfile.gettempdir().

Usage: PYTHONPATH=src python3 tools/test-capture-r11-reference.py
Exit 0 on success, 1 on unittest failure. No network or runtime oracle imports.
"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReferenceCaptureTests(unittest.TestCase):
    def test_reference_size_limit(self):
        frozen = ROOT / 'tests/fixtures/r11_reference'
        oversized = [str(p.relative_to(frozen)) for p in frozen.rglob('*')
                     if p.is_file() and p.stat().st_size > 5_000_000]
        self.assertEqual(oversized, [])

    def test_regeneration_is_byte_identical(self):
        if not (ROOT / '.build/v11/v0116/src/cornicen/engine.py').is_file():
            self.skipTest('pinned v0.1.16 tree absent: could not check regeneration')
        frozen = ROOT / 'tests/fixtures/r11_reference'
        with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as directory:
            output = Path(directory)
            process = subprocess.run([sys.executable, str(ROOT / 'tools/capture_r11_reference.py'),
                '--output', str(output)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            originals = {str(p.relative_to(frozen)) for p in frozen.rglob('*') if p.is_file()}
            copies = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
            self.assertEqual(originals, copies)
            for name in sorted(originals):
                with self.subTest(file=name):
                    if name == 'capture.json':
                        # These are historical generator hashes, not oracle
                        # values. Source and input hashes remain byte-pinned.
                        old = json.loads((frozen / name).read_text())
                        new = json.loads((output / name).read_text())
                        for key in ('tests/replay_r11/harness.py', 'tools/capture_r11_reference.py'):
                            self.assertEqual(len(new['sha256'].pop(key)), 64)
                            old['sha256'].pop(key)
                        self.assertEqual(old, new)
                    else:
                        self.assertEqual((frozen / name).read_bytes(), (output / name).read_bytes())

    def test_absent_tree_exits_three_before_import(self):
        import importlib.util
        from unittest.mock import patch
        import contextlib
        import io
        spec = importlib.util.spec_from_file_location('r11_capture_absent', ROOT / 'tools/capture_r11_reference.py')
        module = importlib.util.module_from_spec(spec)
        # Loading this script changes sys.path; restore it for the current suite.
        with patch.object(sys, 'path', list(sys.path)):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as directory:
            output = Path(directory) / 'output'
            message = io.StringIO()
            with patch.object(module, 'PINNED', Path(directory) / 'absent'), contextlib.redirect_stderr(message):
                self.assertEqual(module.capture(output), 3)
            self.assertEqual(message.getvalue().strip(), module.ABSENT)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()

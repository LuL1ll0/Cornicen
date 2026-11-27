# script-purpose: Verify release-version checks preserve every other dead-letter cell.
# script-class: harness
# script-trigger: tests/test_f4.py and manual unittest execution.
# script-tests: tests/replay_v11/test-cycle-capture.py
"""Read cycle references, frozen capture metadata and synthetic rows; write no files.

Run PYTHONPATH=src:. python3 tests/replay_v11/test-cycle-capture.py.
Exit 0 on success, 1 on assertion failure.
"""
from copy import deepcopy
import json
import unittest

from cornicen import __version__
from tests.replay_v11.cycle_capture import (
    REFERENCE, ROOT, current_projection, cycle_meta_keys, digest, frozen_projection,
)


class WriterVersionTests(unittest.TestCase):
    def test_reference_uses_compact_meta_key_hashes(self):
        raw = REFERENCE.read_text()
        reference = json.loads(raw)
        self.assertEqual(set(reference), {'cycles'})
        self.assertLess(len(raw.encode()), 1_000_000)
        self.assertEqual(raw, json.dumps(reference, sort_keys=True, separators=(',', ':')) + '\n')
        for name, cycles in reference['cycles'].items():
            for index, cycle in enumerate(cycles):
                with self.subTest(scenario=name, cycle=index):
                    self.assertRegex(cycle['meta_keys'], r'^[0-9a-f]{64}$')

    def setUp(self):
        self.version = json.loads(
            (ROOT / 'tests/fixtures/v0116_frozen/capture.json').read_text())['version']
        self.frozen = {'tables': {'dead_letters': {
            'columns': ['id', 'version', 'detail'],
            'rows': [['FIX-2099-0001', self.version, 'invalid input']]}}, 'meta_keys': []}
        self.current = deepcopy(self.frozen)
        self.current['tables']['dead_letters']['rows'][0][1] = __version__

    def test_writer_versions_checked_independently(self):
        self.assertEqual(current_projection(self.current, self.frozen, 'synthetic'),
                         frozen_projection(self.frozen, 'synthetic'))
        for database, project in ((self.current, lambda db: current_projection(db, self.frozen, 'synthetic')),
                                  (self.frozen, lambda db: frozen_projection(db, 'synthetic'))):
            with self.subTest(project=project):
                database['tables']['dead_letters']['rows'][0][1] = 'invalid-writer'
                with self.assertRaisesRegex(AssertionError, r'synthetic: dead_letters.version'):
                    project(database)

    def test_every_other_column_remains_in_comparison_and_hash(self):
        expected = frozen_projection(self.frozen, 'synthetic')
        for index in (0, 2):
            with self.subTest(column=self.current['tables']['dead_letters']['columns'][index]):
                changed = deepcopy(self.current)
                changed['tables']['dead_letters']['rows'][0][index] = 'changed'
                projected = current_projection(changed, self.frozen, 'synthetic')
                self.assertNotEqual(projected, expected)
                self.assertNotEqual(digest(projected), digest(expected))
        self.assertEqual(self.frozen['tables']['dead_letters']['columns'], ['id', 'version', 'detail'])

    def test_unrelated_meta_key_changes_cycle_hash(self):
        keys = ['adapter_schema_version', 'outbox_event_keys_version', 'schema_version']
        expected = digest(['schema_version'])
        self.assertEqual(digest(cycle_meta_keys({'meta_keys': keys})), expected)
        keys.insert(2, 'outbox_event_keys_version_unapproved')
        with self.assertRaises(AssertionError):
            self.assertEqual(digest(cycle_meta_keys({'meta_keys': keys})), expected)


if __name__ == '__main__':
    unittest.main()

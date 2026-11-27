# script-purpose: Check foundation replay infrastructure and frozen provenance.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_replay_v11.py
"""Read v1.1 fixtures and frozen baselines; write no persistent data.

Run with python3 -m unittest tests.test_replay_v11. Exit 0 on success, 1 on failure.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from tests.replay_v11 import harness as h

ROOT = Path(__file__).resolve().parents[1]


class FoundationTests(unittest.TestCase):
    def test_fixture_schema(self):
        self.assertEqual(h.FOUNDATION_TASK, 'F4')
        self.assertEqual(set(h.scenario_names()), h.ORACLES)
        for name in h.scenario_names():
            with self.subTest(oracle=name):
                timeline = h.load_timeline(name)
                expected = h.load_expected(name, timeline)
                self.assertTrue(expected)
                self.assertTrue(all(row['lifted_by'] in h.TASKS for row in expected))
                h.validate_identities(timeline + expected)
                self.assertTrue(h.run_scenario(name).snapshots)
                members = {}
                for action in timeline:
                    if 'adapter' in action:
                        for resource in action['result']['resources']:
                            try:
                                body = json.loads(resource['body'])
                            except ValueError:
                                continue
                            records = body if isinstance(body, list) else body['advisories']
                            for record in records:
                                encoded = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                                members[hashlib.sha256(encoded).hexdigest()] = record['id']
                for assertion in expected:
                    state = assertion.get('state', {})
                    for source, manifest in state.get('manifests', {}).items():
                        for member in manifest:
                            self.assertEqual(members[member['digest']], member['source_id'])
                        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                        self.assertEqual(state['cursor'][source]['digest'], hashlib.sha256(encoded).hexdigest())
        with self.assertRaises(ValueError):
            h.validate_timeline([{'t': '2099-11-03T01:00:00Z', 'watchlist': h.WATCHLIST},
                                 {'t': '2099-11-03T00:00:00Z', 'cycle': True}])

    @patch.object(h, 'FOUNDATION_TASK', 'F3b')
    def test_pending_mechanics(self):
        def wrong():
            self.assertEqual(1, 2)
        def passes():
            self.assertEqual(1, 1)
        def broken():
            raise ValueError('infrastructure error')
        for assertion, failures, errors, pending in [(wrong, 0, 0, 1), (passes, 1, 0, 0), (broken, 0, 1, 0)]:
            result = unittest.TestResult()
            h.AssertionCase('mechanics', lambda: None, lambda _: assertion(), 'F4').run(result)
            self.assertEqual((len(result.failures), len(result.errors), len(result.expectedFailures)),
                             (failures, errors, pending))
        result = unittest.TestResult()
        h.AssertionCase('execution error', broken, lambda _: wrong(), 'F2a').run(result)
        self.assertEqual(len(result.errors), 1)
        result = unittest.TestResult()
        h.AssertionCase('active failure', lambda: None, lambda _: wrong(), 'F0').run(result)
        self.assertEqual(len(result.failures), 1)

    def test_frozen_capture_commit_first(self):
        from cornicen.store import Store
        frozen = ROOT / 'tests/fixtures/v0116_frozen'
        provenance = json.loads((frozen / 'capture.json').read_text())
        for name, digest in provenance['sha256'].items():
            if not name.startswith('status/') and (not name.startswith('src/') or h.FOUNDATION_TASK == 'F0'):
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)
        names = {str(p.relative_to(ROOT / 'tests/replay')).removesuffix('.input.jsonl')
                 for p in (ROOT / 'tests/replay').rglob('*.input.jsonl')}
        self.assertEqual(names, {str(p.relative_to(frozen / 'replays')).removesuffix('.json')
                                for p in (frozen / 'replays').rglob('*.json')})
        for name in ('missing', 'empty', 'populated'):
            self.assertTrue((frozen / 'status' / (name + '.txt')).read_text())
            json.loads((frozen / 'status' / (name + '.json')).read_text())
        store = Store(':memory:')
        try:
            store.migrate()
            expected = json.loads((frozen / 'status/empty.database.json').read_text())
            actual = h.dump_database(store.connection)
            self.assertEqual(h.project_frozen(actual, expected), expected)
            h.assert_additions(actual, expected, foundation=h.FOUNDATION_TASK != 'F0')
            # Projection cannot hide illicit additions or changed old cells.
            changed = json.loads(json.dumps(actual))
            changed['tables']['unapproved'] = {'columns': [], 'rows': []}
            with self.assertRaisesRegex(AssertionError, 'unexpected added tables: .*unapproved'):
                h.assert_additions(changed, expected, foundation=h.FOUNDATION_TASK != 'F0')
            with self.assertRaises(AssertionError):
                h.assert_additions(actual, expected, foundation=h.FOUNDATION_TASK == 'F0')
        finally:
            store.connection.close()


def load_tests(loader, tests, pattern):
    for path in (ROOT / 'tests/replay_v11/test-harness.py', ROOT / 'tools/test-build-f0-oracles.py'):
        spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tests.addTests(loader.loadTestsFromModule(module))
    tests.addTests(h.oracle_suite())
    return tests

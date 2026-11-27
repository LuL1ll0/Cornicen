# script-purpose: Exercise replay parsing, backend isolation and pending assertions.
# script-class: harness
# script-trigger: tests/test_replay_v11.py and manual unittest execution.
# script-tests: tests/replay_v11/test-harness.py
"""Read in-memory test inputs and adjacent fixtures; write no files.

Usage: PYTHONPATH=src python3 tests/replay_v11/test-harness.py
Exit 0 on success, 1 on unittest failure.
"""
from copy import deepcopy
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.replay_v11 import harness as h


class HarnessTests(unittest.TestCase):
    def test_all_v1_replays_match_frozen_projection_and_notifications(self):
        import importlib.util
        import json
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('frozen_capture', root / 'tools/capture_v0116_frozen.py')
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        for path in sorted((root / 'tests/replay').glob('*.input.jsonl')):
            name = path.name.removesuffix('.input.jsonl')
            with self.subTest(scenario=name):
                frozen = json.loads((root / 'tests/fixtures/v0116_frozen/replays' / (name + '.json')).read_text())
                store, notifications = capture.replay_capture(name)
                try:
                    actual = h.dump_database(store.connection)
                    from tests.replay_v11.cycle_capture import current_projection, frozen_projection
                    self.assertEqual(current_projection(actual, frozen['database'], name),
                                     frozen_projection(frozen['database'], name))
                    h.assert_additions(actual, frozen['database'])
                    self.assertEqual(notifications, frozen['notifications'])
                finally:
                    store.connection.close()

    def test_registry_and_backend_lifecycle(self):
        instances = []
        class Backend:
            def __init__(self, registry):
                self.rows = []
                self.closed = False
                self.registry = registry
                instances.append(self)
            def action(self, row):
                self.rows.append(row)
            def snapshot(self):
                return {'classification': {'fixture_a': 'engine-test-observation'}}
            def notifications(self):
                return []
            def close(self):
                self.closed = True
        previous = h.register_backend(Backend)
        try:
            result = h.run_scenario('late_identity')
        finally:
            h.register_backend(previous)
        self.assertEqual(len(instances), 2)
        self.assertTrue(all(b.closed for b in instances))
        self.assertIsNot(instances[0].registry, instances[1].registry)
        self.assertEqual([a.position for a in instances[0].registry.values()], [1, 6, 2])
        self.assertTrue(instances[0].registry['fixture_export'].export)
        self.assertTrue(all(a.gate == 'met' for a in instances[0].registry.values()))
        raw = [r for r in instances[0].rows if 'adapter' in r]
        self.assertTrue(raw)
        self.assertIn('body', raw[0]['result']['resources'][0])
        self.assertEqual(result.unavailable, set())
        # A hook's observation is used verbatim, not replaced by expected data.
        row = h.load_expected('late_identity')[1]
        with self.assertRaises(AssertionError):
            h.assert_line(result, row, [row])

    def test_restart_preserves_both_snapshots(self):
        class Backend:
            def __init__(self, registry):
                self.restarted = False
            def action(self, row):
                if 'restart' in row:
                    self.restarted = True
            def snapshot(self):
                return {'retries': [] if self.restarted else [
                    {'source': 'fixture_a', 'resource': 'listing.json'}]}
            def notifications(self):
                return []
            def close(self):
                pass
        previous = h.register_backend(Backend)
        try:
            result = h.run_scenario('boundary')
        finally:
            h.register_backend(previous)
        retry = next(row for row in h.load_expected('boundary')
                     if set(row.get('state', {})) == {'retries'})
        self.assertEqual(retry['snapshot'], 'after_restart')
        h.assert_line(result, {k: v for k, v in retry.items() if k != 'snapshot'}, [retry])
        with self.assertRaises(AssertionError):
            h.assert_line(result, retry, [retry])
        for name in ('alias_episode', 'late_identity'):
            previous = h.register_backend(Backend)
            try:
                observed = h.run_scenario(name)
            finally:
                h.register_backend(previous)
            restart = next(row for row in h.load_timeline(name) if 'restart' in row)
            key = ('main', restart['t'])
            self.assertTrue(observed.snapshots[key]['retries'])
            self.assertEqual(observed.snapshots[key + ('after_restart',)]['retries'], [])

    def test_restart_selector_requires_matching_restart(self):
        rows = h.load_expected('boundary')
        retry = next(row for row in rows if row.get('snapshot') == 'after_restart')
        result = h.ReplayResult(snapshots={('main', retry['t']): {'retries': retry['state']['retries']}},
                                unavailable={('main', retry['t'], 'after_restart')})
        with self.assertRaisesRegex(AssertionError, 'hook not implemented'):
            h.assert_line(result, retry, [retry])
        # Removing restart actions must make the expected selector a schema error.
        timeline = [row for row in h.load_timeline('boundary') if 'restart' not in row]
        with self.assertRaises(ValueError):
            h.load_expected('boundary', timeline)

    def test_additions_checks_survive_optimization(self):
        result = subprocess.run([sys.executable, '-O', str(Path(__file__).resolve()),
                                 'HarnessTests.test_projection_preserves_old_cells_and_checks_additions'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @patch.object(h, 'FOUNDATION_TASK', 'F3b')
    def test_pending_notification_multiplicity_and_active_exactness(self):
        row = {'t': '2099-11-03T01:00:00Z', 'watch': 'w', 'record': 'CVE-2099-0001',
               'reasons': ['new match'], 'urgency': 'normal', 'lifted_by': 'F3a'}
        result = h.ReplayResult(notifications=[h.notification(row)])
        with self.assertRaises(AssertionError):
            h.assert_notifications(result, [row | {'lifted_by': 'F4'}])
        h.assert_line(result, row, [row])
        with self.assertRaises(AssertionError):
            h.assert_line(result, row, [row, row])
        result.notifications.append(h.notification(row))
        h.assert_line(result, row, [row, row])

    def test_counts_require_advisory_delivery_capability(self):
        tick='2099-11-03T01:00:00Z'
        row=dict(t=tick,state={'notification_count':{'advisory':0,'total':0}},lifted_by='F2b')
        snapshot={'notification_count':{'advisory':0,'total':0},'advisory_delivery_available':False}
        result=h.ReplayResult(snapshots={('main',tick):snapshot})
        h.assert_line(result,row,[row])
        with self.assertRaisesRegex(AssertionError,'F3 delivery hook'):
            h.assert_line(result,row | {'lifted_by':'F3a'},[row])
        snapshot['advisory_delivery_available']=True
        h.assert_line(result,row | {'lifted_by':'F3a'},[row])

    def test_reject_preclassified_or_malformed_actions(self):
        prefix = {'t': '2099-11-03T00:00:00Z', 'watchlist': h.WATCHLIST}
        invalid = [
            {'adapter': 'fixture_a', 'result': {'classification': 'COMPLETE'}},
            {'adapter': 'unregistered', 'result': {'resources': []}},
            {'command': ['adapter', 'rebaseline', 'unregistered']},
            {'restart': True, 'cycle': True},
        ]
        for action in invalid:
            with self.subTest(action=action), self.assertRaises(ValueError):
                h.validate_timeline([prefix, dict(t=prefix['t'], **action), {'t': prefix['t'], 'cycle': True}])
        for text in ['CVE-2026-0001', 'FIX-2026-0001', 'https://other.invalid/a']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                h.validate_identities([{'value': text}])

    def test_projection_preserves_old_cells_and_checks_additions(self):
        frozen = {'tables': {'meta': {'columns': ['k', 'v'], 'rows': [['schema_version', '1']]},
                             'pairs': {'columns': ['id'], 'rows': [['CVE-2099-0001']]}},
                  'meta_keys': ['schema_version']}
        actual = deepcopy(frozen)
        actual['tables'].update({name: {'columns': ['test_column'], 'rows': []} for name in h.NEW_TABLES})
        actual['tables']['outbox_event_keys'] = {
            'columns': ['outbox_id', 'reason', 'key', 'legacy'], 'rows': [[1, 'new match', '', 1]]}
        actual['tables']['meta']['rows'].append(['adapter_schema_version', '1'])
        actual['tables']['meta']['rows'].append(['outbox_event_keys_version', '1'])
        actual['meta_keys'].insert(0, 'adapter_schema_version')
        actual['meta_keys'].insert(1, 'outbox_event_keys_version')
        self.assertEqual(h.project_frozen(actual, frozen), frozen)
        h.assert_additions(actual, frozen)
        with self.assertRaisesRegex(AssertionError, 'unexpected added tables: .*outbox_event_keys_unapproved'):
            changed = dict(actual, tables=dict(actual['tables'], outbox_event_keys_unapproved={}))
            h.assert_additions(changed, frozen)
        with self.assertRaisesRegex(AssertionError, 'unexpected meta keys'):
            changed = dict(actual, meta_keys=sorted(
                [*actual['meta_keys'], 'outbox_event_keys_version_unapproved']))
            h.assert_additions(changed, frozen)
        actual['tables']['meta']['rows'][-1][1] = '2'
        with self.assertRaisesRegex(AssertionError, 'outbox_event_keys_version must be 1'):
            h.assert_additions(actual, frozen)
        actual['tables']['meta']['rows'][-1][1] = '1'
        actual['tables']['affected_latches']['rows'].append(['w', 'CVE-2099-0001', 1, 1])
        with self.assertRaises(AssertionError):
            h.assert_additions(actual, frozen)
        actual['tables']['affected_latches']['rows'].clear()
        actual['tables']['pairs']['columns'].append('affected_latch')
        actual['tables']['pairs']['rows'][0].append(0)
        with self.assertRaises(AssertionError):
            h.assert_additions(actual, frozen)
        actual['tables']['pairs']['columns'].pop()
        actual['tables']['pairs']['rows'][0].pop()
        actual['tables']['pairs']['rows'][0][0] = 'CVE-2099-0002'
        self.assertNotEqual(h.project_frozen(actual, frozen), frozen)


if __name__ == '__main__':
    unittest.main()

# script-purpose: Verify crash recovery, disabled adapter invariance and release contracts.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f4.py
"""Read replay fixtures and frozen captures; write temporary offline databases.

Run PYTHONPATH=src python3 -m unittest tests.test_f4; exit 0 success, 1 failure.
"""
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from cornicen import __version__, adapters, cli
from cornicen.adapterstore import AdapterStore, instant, stamp
from cornicen.engine import Engine
from tests.replay_v11 import harness as h

ROOT = Path(__file__).resolve().parents[1]
# Literal base migration minus frozen v0.1.16, including the separate latch table.
ADDITIONS = {
    'adapter_retries', 'adapter_state', 'advisories', 'advisory_evidence',
    'advisory_shells', 'advisory_support', 'affected_latches', 'baseline_members',
    'coverage_inheritance', 'delivery_coverage', 'gap_ledger', 'identity_redirects',
    'manifest_members', 'manifests', 'quarantine', 'resource_cache',
    'source_health', 'staged_containers',
}


def capture_module():
    spec = importlib.util.spec_from_file_location('f4_capture', ROOT / 'tools/capture_v0116_frozen.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class F4Tests(unittest.TestCase):
    def test_crash_at_every_transaction(self):
        counts = {}
        for name in h.scenario_names():
            expected = h.load_expected(name)
            uninterrupted = h.run_crash_scenario(name)
            h.assert_notifications(uninterrupted.result, expected)
            for row in expected:
                h.assert_line(uninterrupted.result, row, expected)
            for index, point in enumerate(uninterrupted.points):
                with self.subTest(oracle=name, index=index, point=point):
                    recovered = h.run_crash_scenario(name, crash_index=index)
                    self.assertTrue(recovered.crashed)
                    self.assertEqual(recovered.durable, uninterrupted.durable)
                    h.assert_notifications(recovered.result, expected)
                counts[point] = counts.get(point, 0) + 1
        totals = {}
        for point, count in counts.items():
            kind = point.split(':', 1)[0]
            totals[kind] = totals.get(kind, 0) + count
        self.assertEqual(totals, {'record': 278, 'alias': 36, 'enqueue': 64, 'ack': 32})

    def test_v1_replays_unchanged(self):
        self.assertEqual(h.NEW_TABLES, ADDITIONS)
        self.assertEqual(len(ADDITIONS), 18)
        capture = capture_module()
        from tests.replay import harness as v1
        for path in sorted(v1.SCENARIOS.rglob('*.input.jsonl')):
            name = str(path.relative_to(v1.SCENARIOS)).removesuffix('.input.jsonl')
            with self.subTest(scenario=name):
                frozen = json.loads((ROOT / 'tests/fixtures/v0116_frozen/replays' / (name + '.json')).read_text())
                store, notifications = capture.replay_capture(name)
                try:
                    actual = h.dump_database(store.connection)
                    self.assertEqual(set(actual['tables']) - set(frozen['database']['tables']), ADDITIONS)
                    from tests.replay_v11.cycle_capture import current_projection, frozen_projection
                    self.assertEqual(current_projection(actual, frozen['database'], name),
                                     frozen_projection(frozen['database'], name))
                    h.assert_additions(actual, frozen['database'])
                    self.assertFalse(any(k.startswith('advisory_history:') for k in actual['meta_keys']))
                    self.assertEqual(notifications, frozen['notifications'])
                finally:
                    store.connection.close()

    def test_cycle_identical_when_not_effective(self):
        from tests.replay_v11.cycle_capture import compare_cycles
        for mode in ('absent', 'false', 'true'):
            with self.subTest(config=mode):
                compare_cycles(self, mode)

    def test_no_adapter_activity(self):
        from tests.replay_v11.cycle_capture import compare_cycles
        factory, poll, audit, retry, transport = (Mock() for _ in range(5))
        instance = Mock(poll=poll, audit=audit, retry=retry)
        factory.return_value = instance
        dispatch = Engine.dispatch_adapters
        def guarded(engine):
            return dispatch(engine, factories=dict.fromkeys(adapters.REGISTRY, factory))
        with patch.object(Engine, 'dispatch_adapters', guarded), \
                patch('cornicen.fetch.Http.get', transport), \
                patch('socket.socket.connect', side_effect=AssertionError('network in replay')):
            for mode in ('absent', 'false', 'true'):
                compare_cycles(self, mode)
        for spy in (factory, poll, audit, retry, transport):
            spy.assert_not_called()
        self.assertTrue(all(entry.gate == 'not met' for entry in adapters.REGISTRY.values()))
        self.assertTrue(all(not hasattr(entry, 'factory') for entry in adapters.REGISTRY.values()))

    def test_release_version_pinned(self):
        self.assertEqual(__version__, '0.4.0')

    def test_cli_status_lists_six_and_pins_f06_adapters(self):
        from tests.test_goal_features_a import GoalFeaturesATests
        fixture = GoalFeaturesATests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.seed_health()
        code, text = fixture.invoke('status', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['adapters'], {
            'synology': dict(setting=False, gate='not met', gate_name='S', effective=False),
            'debian': dict(setting=False, gate='not met', gate_name='D', effective=False),
            'ubuntu': dict(setting=False, gate='not met', gate_name='U', effective=False),
            'msrc': dict(setting=False, gate='not met', gate_name='M', effective=False),
            'cisco': dict(setting=False, gate='not met', gate_name='C', effective=False),
            'github': dict(setting=True, gate='not met', gate_name='G', effective=False),
        })
        code, text = fixture.invoke('status')
        self.assertEqual(code, 0)
        lines = [line for line in text.splitlines() if line.split(':')[0] in adapters.REGISTRY]
        self.assertEqual(len(lines), 6)
        self.assertIn('github: authentication unknown; rate limit not seen yet; advisory adapter: disabled: gate G not met (setting on)', lines)
        self.assertEqual([line for line in lines if not line.startswith('github:')], [
            'synology: disabled: gate S not met (setting off)',
            'debian: disabled: gate D not met (setting off)',
            'ubuntu: disabled: gate U not met (setting off)',
            'msrc: disabled: gate M not met (setting off)',
            'cisco: disabled: gate C not met (setting off)',
        ])

    def test_audit_exact_boundary(self):
        from tests.test_f2b import F2bTests, T, S, resource
        fixture = F2bTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.p.process(S, [resource()], T)
        for offset, due, health in ((-1, [], 'healthy'), (0, ['listing.json'], 'healthy'),
                                    (1, ['listing.json'], 'unhealthy')):
            tick = stamp(instant(T) + timedelta(days=7, seconds=offset))
            fixture.finish(tick)
            self.assertEqual(fixture.p.audits_due(S, tick), due)
            self.assertEqual(fixture.dimensions()['audit'], health)


def load_tests(loader, tests, pattern):
    for name in ('test-cycle-capture', 'test-crash-replay'):
        path = ROOT / 'tests/replay_v11' / (name + '.py')
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tests.addTests(loader.loadTestsFromModule(module))
    return tests

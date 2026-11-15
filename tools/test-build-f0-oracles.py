# script-purpose: Verify authored oracle generation is deterministic and complete.
# script-class: harness
# script-trigger: unittest discovery through tests/test_replay_v11.py or manual execution.
# script-tests: tools/test-build-f0-oracles.py
"""Read the oracle generator and committed JSONL; write files under the system temporary directory.

Usage: PYTHONPATH=src python3 tools/test-build-f0-oracles.py
Exit 0 on success, 1 on unittest failure.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('oracle_builder', ROOT / 'tools/build_f0_oracles.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class OracleGeneratorTests(unittest.TestCase):
    def test_regeneration(self):
        original = ROOT / 'tests/replay_v11'
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            builder.build(output)
            # Hand-authored scenarios (task 1's GitHub oracles) sit beside these
            # but are not generator outputs; every generated file must match.
            names = {p.name for p in output.glob('*.jsonl')}
            self.assertEqual(len(names), 26)
            self.assertTrue(names <= {p.name for p in original.glob('*.jsonl')})
            for name in sorted(names):
                with self.subTest(file=name):
                    self.assertEqual((original / name).read_bytes(), (output / name).read_bytes())

    def test_f3a_retags_change_ownership_only(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            original = Path(temp) / 'original'
            with patch.object(builder, 'F3A_RETAGS', {}):
                builder.build(original)
            for name, numbers in builder.F3A_RETAGS.items():
                before = [json.loads(line) for line in
                          (original / f'{name}.expected.jsonl').read_text().splitlines()]
                after = [json.loads(line) for line in
                         (ROOT / 'tests/replay_v11' / f'{name}.expected.jsonl').read_text().splitlines()]
                self.assertEqual(len(before), len(after))
                for number, (old, new) in enumerate(zip(before, after), 1):
                    self.assertEqual(new, old | {'lifted_by': 'F3a'} if number in numbers else old)

    def test_f1_has_no_persistence_dependency(self):
        root = ROOT / 'tests/replay_v11'
        for path in root.glob('*.input.jsonl'):
            inputs = [json.loads(line) for line in path.read_text().splitlines()]
            expected = [json.loads(line) for line in path.with_name(
                path.name.replace('.input.', '.expected.')).read_text().splitlines()]
            self.check_f1_inputs(inputs, expected)

    def check_f1_inputs(self, inputs, expected):
        """Independently reject persistence-dependent F1 observations from raw inputs."""
        case, seed, prior, pending, ticks = 'main', {}, {}, {}, {}
        for row in inputs:
            if 'case' in row:
                case, seed, prior, pending = row['case'], {}, {}, {}
            if 'seed' in row:
                seed.update(row['seed'])
                for source, adapter in seed.get('adapters', {}).items():
                    prior.setdefault(source, set()).update(adapter.get('baseline_members') or [])
                    prior[source].update(m['source_id'] for m in adapter.get('manifest', []))
            if 'adapter' in row:
                pending[row['adapter']] = row['result']['resources']
            if 'cycle' not in row:
                continue
            dependencies = set()
            for source, resources in pending.items():
                if any(g['source'] == source for g in seed.get('gaps', [])):
                    dependencies.add('seeded gap ledger')
                for resource in resources:
                    if resource['status'] == 304:
                        dependencies.add('cached body')
                        continue
                    try:
                        body = json.loads(resource['body'])
                    except ValueError:
                        continue  # Invalid raw content can be classified without storage.
                    if isinstance(body, dict) and ('coverage_start' in body or 'retention_hours' in body):
                        dependencies.add('stored retention cursor')
                    members = body if isinstance(body, list) else body['advisories']
                    ids = {member['id'] for member in members}
                    if prior.get(source, set()) - ids:
                        dependencies.add('earlier manifest membership')
                    prior.setdefault(source, set()).update(ids)
            ticks[case, row['t']] = (dependencies, bool(pending))
            pending = {}
        for row in expected:
            if row.get('lifted_by') != 'F1':
                continue
            with self.subTest(case=row.get('case', 'main'), t=row['t'], state=row.get('state')):
                dependencies, has_raw = ticks[row.get('case', 'main'), row['t']]
                self.assertTrue(has_raw, 'F1 requires current raw adapter input')
                self.assertFalse(dependencies, f'F1 requires persistence: {dependencies}')
                state = row['state']
                self.assertTrue(set(state) <= {'classification', 'quarantine'})
                if 'quarantine' in state:
                    self.assertTrue(state['quarantine'], 'empty stored quarantine requires persistence')

    def test_f1_guard_rejects_persistence_mutations(self):
        root = ROOT / 'tests/replay_v11'
        for name, case, suffix in [('audits', 'main', '01:00:00Z'),
                                   ('audits', 'permanent_gap', '01:00:00Z'),
                                   ('empty_enumeration', 'disappearance', '02:00:00Z'),
                                   ('rebaseline_gap', 'main', '03:00:00Z'),
                                   ('bad_member', 'main', '02:00:00Z')]:
            inputs = [json.loads(line) for line in (root / f'{name}.input.jsonl').read_text().splitlines()]
            expected = [json.loads(line) for line in (root / f'{name}.expected.jsonl').read_text().splitlines()]
            target = next(row for row in expected if row.get('case') == case
                          and row.get('t', '').endswith(suffix)
                          and ('quarantine' if name == 'bad_member' else 'classification') in row.get('state', {}))
            target['lifted_by'] = 'F1'
            # Use a separate result because subTest failures do not raise to callers.
            probe = OracleGeneratorTests()
            result = unittest.TestResult()
            unittest.FunctionTestCase(lambda: probe.check_f1_inputs(inputs, [target])).run(result)
            self.assertTrue(result.failures, name)

    def test_reviewed_contract(self):
        root = ROOT / 'tests/replay_v11'
        def rows(name, kind='expected'):
            return [row for line in (root / f'{name}.{kind}.jsonl').read_text().splitlines()
                    if '#' not in (row := json.loads(line))]
        with tempfile.TemporaryDirectory() as temp:
            builder.build(Path(temp))
            generated = sorted(Path(temp).glob('*.expected.jsonl'))
        for path in generated:
            for row in rows(path.name.removesuffix('.expected.jsonl')):
                state = row.get('state', {})
                for key in ('classification', 'quarantine'):
                    if key in state:
                        self.assertIn(row['lifted_by'], ('F1', 'F2a'))
                        self.assertEqual(set(state), {key})
                if 'cursor' in state or 'manifests' in state:
                    self.assertEqual(row['lifted_by'], 'F2a')
                    self.assertNotIn('dimensions', state)
                if set(state) == {'gaps', 'historical_completeness'}:
                    self.assertEqual(row['lifted_by'], 'F2a')
                if row.get('reasons') == ['baseline']:
                    self.assertEqual(row['lifted_by'], 'F2a')
        notifications = [r for r in rows('baseline_is_local') if 'record' in r and r['case'] == 'main']
        self.assertEqual([r['record'] for r in notifications], [builder.A, 'baseline:fixture_a'])
        final_tick = max(r['t'] for r in rows('rebaseline_gap'))
        self.assertTrue(all('total' not in r.get('state', {}).get('notification_count', {})
                            for r in rows('rebaseline_gap') if r['t'] == final_tick))
        bad_pairs = [r['state']['pairs'] for r in rows('bad_member')
                     if 'pairs' in r.get('state', {}) and r['t'].endswith('01:00:00Z')]
        self.assertEqual(bad_pairs, [[builder.pair(builder.A), builder.pair(
            'advisory:fixture_a:FIX-2099-0003:main', 'unknown', latch=False, notified=False)]])
        audit_pairs = [r for r in rows('audits') if r['case'] == 'main' and 'pairs' in r.get('state', {})]
        self.assertEqual(len(audit_pairs), 3)
        self.assertTrue(all(r['lifted_by'] == 'F3a' and r['state']['pairs'][0]['state'] == 'unknown'
                            for r in audit_pairs))
        boundary = rows('boundary', 'input')
        restarts = [i for i, r in enumerate(boundary) if 'restart' in r]
        self.assertEqual(len(restarts), 4)
        for i in restarts:
            self.assertTrue(boundary[i - 1].get('cycle'))
        retry_rows = [r for r in rows('boundary') if 'retries' in r.get('state', {})]
        self.assertEqual(len(retry_rows), 8)
        self.assertEqual(sum(r.get('snapshot') == 'after_restart' for r in retry_rows), 4)
        disappearance = [r for r in rows('empty_enumeration') if r['case'] == 'disappearance']
        partial = [r for r in disappearance if r.get('state', {}).get('classification') == {'fixture_a': 'PARTIAL'}]
        self.assertEqual(len(partial), 2)
        cursors = [r['state']['cursor'] for r in disappearance if 'cursor' in r.get('state', {})]
        self.assertEqual(cursors, [cursors[0]] * 3)


if __name__ == '__main__':
    unittest.main()

# script-purpose: Compare all CNA timelines against independent frozen v1 observables.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_r11_differential.py
"""Read replay fixtures and r11_reference; write only temporary test databases.

Run PYTHONPATH=src python3 -m unittest tests.test_r11_differential.
Exit 0 on success, 1 on regression/error. Every acceptance comparison is active.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.replay_r11 import harness as h


def compare_all(variant=None):
    mismatches = {}
    explanations = json.loads((h.REFERENCE / 'explain.json').read_text())
    audits = []
    for name, path in h.scenarios().items():
        reference = h.load_reference(name)
        actual = h.run(path, variant, explain=True)
        audits.append(actual['audit'])
        differences = h.differences(actual, reference)
        if actual['explain'] != explanations[name]:
            differences.append('cli.explain differs from pinned v0.1.16 text/exit codes')
        if differences:
            mismatches[name] = differences
    routes = [r for audit in audits for r in audit['routes']]
    for site in ('_evaluate', '_revalidate', '_body', 'reload_watches', 'explain'):
        if not any(r['watch'] != h.EXTRA and site in r['sites'] for r in routes) and not (variant is None and site in ('_evaluate', 'reload_watches')):
            mismatches['route coverage ' + site] = ['public cohort route observation never fired']
    if variant == 'mixed':
        extra_routes = [r for r in routes if r['watch'] == h.EXTRA]
        if not extra_routes or any(r['route'] != 'advisory' for r in extra_routes):
            mismatches['mixed positive control route'] = ['extra watch must be observed routed advisory']
        for field in ('extra_affected', 'extra_events', 'extra_outbox', 'extra_digest'):
            if not any(audit[field] for audit in audits):
                mismatches['mixed positive control ' + field] = ['expected advisory output never observed']
        bodies = [body for audit in audits for body in audit['extra_bodies']]
        if not any(body.get('state') == 'affected' and body.get('advisory_title') == 'Injected adapter title' for body in bodies):
            mismatches['mixed positive control body'] = ['affected adapter notification absent']
        if not any(any(count) for audit in audits for count in audit['baseline_contributions']):
            mismatches['mixed positive control baseline'] = ['extra baseline contribution never observed']
    if variant in ('late', 'mixed_late') and not any(audit['live'] for audit in audits):
        mismatches['live commit'] = ['mid-timeline adapter commit never fired']
    return mismatches


def assert_equal(mismatches):
    if mismatches:
        # All ticks and fields are compared, but report one example per field
        # per fixture so a long quiet replay cannot conceal another regression.
        lines = []
        for name, differences in mismatches.items():
            samples = {}
            for difference in differences:
                field = next((f for f in ('route', 'pairs', 'events', 'outbox',
                    'notifications', 'rendered') if f' {f}' in difference), 'other')
                samples.setdefault(field, difference)
            lines.append(name + ': ' + '\n  '.join(samples.values()))
        raise AssertionError(f'{len(mismatches)} timelines diverged\n' + '\n'.join(lines))


class DifferentialInfrastructureTests(unittest.TestCase):
    def test_fixture_cohort_and_frozen_coverage(self):
        manifest = json.loads((h.REFERENCE / 'capture.json').read_text())
        self.assertEqual(manifest['commit'], '1c97d0d')
        captured = {str(p.relative_to(h.REFERENCE)).removesuffix('.gz').removesuffix('.json')
                    for directory in ('replay', 'replay_r11')
                    for p in (h.REFERENCE / directory).glob('*.json*')}
        self.assertEqual(captured, set(h.scenarios()))
        for name, path in h.scenarios().items():
            rows, cohort, identities = h.definition(path)
            reference = h.load_reference(name)
            self.assertTrue(cohort)
            self.assertEqual(cohort, reference['cohort'])
            self.assertEqual(identities, reference['identities'])
            self.assertEqual(len(rows), len(reference['snapshots']))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                             manifest['sha256'][str(path.relative_to(h.ROOT))])
            if path.parent.name == 'replay_r11':
                self.assertTrue(all(identity.startswith('CVE-2099-') for identity in identities))

    def test_reference_contains_required_observations(self):
        def frozen(name):
            return json.loads((h.REFERENCE / f'replay_r11/{name}.json').read_text())['snapshots']
        def items(name):
            return [n for n in frozen(name)[-1]['notifications'] if n['watch_id']]
        self.assertEqual(items('accept_active_hold'), [])
        self.assertIn('KEV added', items('accept_kev_override')[-1]['reasons'])
        self.assertIn('acceptance lapsed', items('accept_lapse')[-1]['reasons'])
        self.assertIn('acceptance lapsed', items('accept_removal')[-1]['reasons'])
        self.assertEqual(items('correction_never_delivered'), [])
        self.assertTrue(any('correction' in n['reasons'] for n in
                            items('correction_delivered_rejected_no_affected')))
        self.assertTrue(any('correction' in n['reasons'] for n in
                            items('correction_affected_unknown_unaffected')))
        for name in ('reload_revision_correction', 'reload_retry'):
            self.assertTrue(any('correction' in n['reasons'] for n in items(name)), name)
        self.assertFalse(any('correction' in n['reasons'] for n in
                             items('reload_ordinary_suppression')))
        keys = [e['key'] for e in frozen('epss_crossing_rearm')[-1]['events']
                if e['type'] == 'epss_crossed']
        self.assertEqual(len(keys), 2)
        self.assertTrue(any(key.endswith('|1|2') for key in keys))
        self.assertFalse(any('epss_crossed' in n['reasons'] for n in
                             items('epss_delivery_suppression')))
        kev = frozen('kev_no_cna_initial_later_resolution')
        self.assertFalse(any(e['watch_id'] for e in kev[4]['events']))
        self.assertTrue(any('resolution' in e['key'] for e in kev[-1]['events']))
        for name, state, confidence in (
            ('multi_exact_unaffected_product_only', 'not_affected', 'high'),
            ('multi_unaffected_malformed', 'unknown', 'medium'),
            ('multi_differing_states', 'affected', 'high'),
            ('multi_differing_evidence_confidence', 'affected', 'high')):
            pair = frozen(name)[-1]['pairs'][0]
            self.assertEqual((pair['state'], pair['confidence']), (state, confidence), name)

    def test_comparison_detects_each_observable_and_misrouting(self):
        path = h.scenarios()['replay_r11/multi_differing_states']
        value = json.loads((h.REFERENCE / 'replay_r11/multi_differing_states.json').read_text())
        for field in ('pairs', 'events', 'outbox', 'notifications', 'rendered',
                      'affected_latches', 'epss_crossings', 'meta', 'health'):
            mutated = json.loads(json.dumps(value))
            mutated['snapshots'][-1][field] = ['mutation']
            self.assertTrue(h.differences(mutated, value), field)
        mutated = json.loads(json.dumps(value))
        mutated['snapshots'][-1]['routes'] = [dict(watch='w',identity='CVE-2099-1100',route='advisory')]
        self.assertTrue(any('expected v1' in d for d in h.differences(mutated, value)))
        self.assertEqual(h.definition(path)[1], ['w'])

    def test_mixed_advisory_positive_control(self):
        actual = h.run(h.scenarios()['replay_r11/correction_delivered_rejected_no_affected'], 'mixed')
        audit = actual['audit']
        extra = [route for route in audit['routes'] if route['watch'] == h.EXTRA]
        self.assertTrue(extra, 'public route observation must fire for the extra watch')
        self.assertEqual({route['route'] for route in extra}, {'advisory'})
        for field in ('extra_affected', 'extra_events', 'extra_outbox', 'extra_digest'):
            self.assertTrue(audit[field], field)
        self.assertTrue(any(body['state'] == 'affected' and
                            body.get('advisory_title') == 'Injected adapter title'
                            for body in audit['extra_bodies']))
        self.assertIn((1, 1), audit['baseline_contributions'])
        reference = json.loads((h.REFERENCE / 'replay_r11/correction_delivered_rejected_no_affected.json').read_text())
        self.assertEqual(h.differences(actual, reference), [])

    def test_mixed_late_commit_preserves_seeded_cohort(self):
        actual = h.run(h.scenarios()['replay_r11/correction_pending_reactivation'], 'mixed_late')
        self.assertTrue(actual['audit']['live'])
        self.assertTrue(actual['audit']['commit_probes'])
        for probe in actual['audit']['commit_probes']:
            self.assertEqual(probe['after'], probe['before'])
            self.assertTrue(probe['before']['outbox'])
            self.assertTrue(probe['before']['epss_crossings'])
            self.assertTrue(any(r['k'].startswith('matching_revision_retry:') for r in probe['before']['meta']))
        self.assertTrue(actual['audit']['extra_affected'])

    def test_commit_path_mutants_are_killed(self):
        import inspect
        import textwrap
        from cornicen.engine import Engine
        original = textwrap.dedent(inspect.getsource(Engine._evaluate))
        inside = "    if advisory_only:\n        # Adapter evidence changes"
        early = "    if advisory_only:\n        selected ="
        mutations = {
            'dirty_all': (inside, "self.db.execute('UPDATE outbox SET dirty=1 WHERE sent_at IS NULL')"),
            'epss_rearm': (inside, "self.db.execute('UPDATE epss_crossings SET fired=0')"),
            'retry_clear': (inside, "self.db.execute('DELETE FROM meta WHERE k=?', ('matching_revision_retry:' + record_id,))"),
            'dirty_record': (inside, "self.store.dirty_record(record_id)"),
            'early_dirty_all': (early, "self.db.execute('UPDATE outbox SET dirty=1 WHERE sent_at IS NULL')"),
            'early_retry_clear': (early, "self.db.execute('DELETE FROM meta WHERE k=?', ('matching_revision_retry:' + record_id,))"),
        }
        path = h.scenarios()['replay_r11/correction_pending_reactivation']
        for name, (anchor, statement) in mutations.items():
            with self.subTest(mutant=name):
                self.assertIn(anchor, original)
                first, rest = anchor.split('\n', 1)
                mutated = original.replace(anchor, first + '\n        ' + statement + '\n' + rest)
                namespace = {}
                exec(compile(mutated, '<r11-mutant-' + name + '>', 'exec'), Engine._evaluate.__globals__, namespace)
                with patch.object(Engine, '_evaluate', namespace['_evaluate']):
                    actual = h.run(path, 'mixed_late')
                probes = actual['audit']['commit_probes']
                self.assertTrue(probes)
                self.assertTrue(any(p['before'] != p['after'] for p in probes), name + ' survived')

    def test_invented_replay_versions(self):
        for path in (h.ROOT / 'tests/replay_r11').glob('*.input.jsonl'):
            for copied in ('3.0.3', '1.01.06', '1.01.07'):
                self.assertNotIn(copied, path.read_text(), str(path))

    def test_migration_notes_are_in_harness_docs(self):
        public = (h.ROOT / 'README.md').read_text()
        self.assertNotIn('Unreleased R11 advisory evidence migration', public)
        self.assertNotIn('advisory_history:', public)
        self.assertIn('advisory_shells', (h.ROOT / 'tests/replay_r11/README.md').read_text())

    def test_plain_rejected_record_correction_canary(self):
        actual = h.run(h.scenarios()['replay_r11/correction_delivered_rejected_no_affected'])
        self.assertIn('service|CVE-2099-1001|correction|1',
                      [event['key'] for snapshot in actual['snapshots'] for event in snapshot['events']])

    def test_pending_semantics(self):
        def fail(_):
            raise AssertionError('observable mismatch')
        def broken():
            raise ValueError('execution error')
        def assertion_crash(_):
            raise TypeError('bad assertion')
        with patch.dict(os.environ, {'CORNICEN_R11_PENDING': '1'}):
            for execute, assertion, expected in (
                (lambda: None, fail, (0, 0, 1)),
                (lambda: None, lambda _: None, (1, 0, 0)),
                (broken, fail, (0, 1, 0)),
                (lambda: None, assertion_crash, (0, 1, 0))):
                result = unittest.TestResult()
                h.PendingCase('mechanics', execute, assertion).run(result)
                self.assertEqual((len(result.failures),len(result.errors),len(result.expectedFailures)),expected)
        with patch.dict(os.environ, {'CORNICEN_R11_PENDING': '0'}):
            result = unittest.TestResult()
            h.PendingCase('active', lambda: None, fail).run(result)
            self.assertEqual(len(result.failures), 1)


def load_tests(loader, tests, pattern):
    tests.addTest(h.PendingCase('r11.plain.all_timelines', compare_all, assert_equal, pending=False))
    for variant in h.VARIANTS:
        tests.addTest(h.PendingCase(f'r11.injected.{variant}.all_timelines',
            lambda variant=variant: compare_all(variant), assert_equal, pending=False))
    path = h.ROOT / 'tools/test-capture-r11-reference.py'
    spec = importlib.util.spec_from_file_location('test_capture_r11', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tests.addTests(loader.loadTestsFromModule(module))
    return tests

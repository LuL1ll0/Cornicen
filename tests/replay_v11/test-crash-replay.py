# script-purpose: Verify crash projections detect persisted adapter corruption.
# script-class: harness
# script-trigger: tests/test_f4.py and manual unittest execution.
# script-tests: tests/replay_v11/test-crash-replay.py
"""Read invented replay fixtures; write temporary stores; unittest exits 0/1.

Run PYTHONPATH=src:. python3 tests/replay_v11/test-crash-replay.py.
"""
import json
import unittest
from unittest.mock import patch
from tests.replay_v11 import harness as h


class CrashProjectionTests(unittest.TestCase):
    def test_withdrawal_reissue_preserves_durable_history(self):
        run = h.run_crash_scenario('withdrawal_reissue')
        def advisory(case):
            table = run.durable[case]['advisories']
            return json.loads(table['rows'][0][table['columns'].index('json')])
        withdrawn, reissued = advisory(0), advisory(1)
        self.assertEqual(withdrawn['identity_history']['cves'], ['CVE-2099-0001'])
        self.assertEqual(withdrawn['identity_history']['facets'], reissued['facets'])
        self.assertEqual(withdrawn['facet_next'], reissued['facet_next'])
        self.assertNotIn('identity_history', reissued)

    def test_crash_projection_covers_adapter_tables(self):
        run = h.run_crash_scenario('late_identity')
        for dump in run.durable.values():
            self.assertTrue(h.NEW_TABLES <= set(dump), h.NEW_TABLES - set(dump))

    def assert_mutation_detected(self, name, index, sql, parameters=()):
        import sys
        original = h.dump_database
        mutations = []

        def corrupt(connection):
            caller = sys._getframe(1)
            run_frame = caller
            while run_frame is not None and run_frame.f_code.co_name != 'run':
                run_frame = run_frame.f_back
            if (caller.f_code.co_name == 'close' and run_frame is not None
                    and run_frame.f_locals.get('crashed') is True):
                changed = connection.execute(sql, parameters).rowcount
                if changed:
                    mutations.append(changed)
            return original(connection)

        clean = h.run_crash_scenario(name)
        with self.assertRaises(AssertionError):
            with patch.object(h, 'dump_database', corrupt):
                recovered = h.run_crash_scenario(name, crash_index=index)
            self.assertEqual(clean.durable, recovered.durable)
        self.assertTrue(mutations, 'control must mutate persisted state')

    def test_recovered_retry_deadline_mutation_is_detected(self):
        self.assert_mutation_detected(
            'boundary', 11, 'UPDATE adapter_retries SET next_attempt_at=?',
            ('9999-01-01T00:00:00Z',))

    def test_recovered_missing_staged_path_is_detected(self):
        self.assert_mutation_detected(
            'boundary', 11, 'UPDATE staged_containers SET path=?',
            ('/nonexistent/recovery-lost.jsonl',))

    def test_recovered_null_fired_crossing_mutation_is_detected(self):
        self.assert_mutation_detected(
            'late_identity', 38,
            'UPDATE epss_crossings SET crossing=999999 WHERE fired IS NULL')

    def test_recovered_advisory_json_mutation_is_detected(self):
        import sys
        original = h.dump_database
        mutations = []
        def corrupt(connection):
            if sys._getframe(1).f_code.co_name == 'close':
                row = connection.execute('SELECT source,source_id,json FROM advisories LIMIT 1').fetchone()
                if row:
                    data = json.loads(row['json'])
                    data['identity_history'] = {'cves': ['CVE-2099-9999'], 'facets': []}
                    connection.execute('UPDATE advisories SET json=? WHERE source=? AND source_id=?',
                                       (json.dumps(data), row['source'], row['source_id']))
                    mutations.append(True)
            return original(connection)
        clean = h.run_crash_scenario('late_identity')
        with patch.object(h, 'dump_database', corrupt):
            recovered = h.run_crash_scenario('late_identity', crash_index=38)
        self.assertTrue(recovered.crashed)
        self.assertTrue(mutations)
        with self.assertRaises(AssertionError):
            self.assertEqual(clean.durable, recovered.durable)


if __name__ == '__main__':
    unittest.main()

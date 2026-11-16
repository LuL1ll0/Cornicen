# script-purpose: Verify Debian replay validation, script isolation and evidence observations.
# script-class: harness
# script-trigger: Manual unittest and Build B-2 acceptance tests.
# script-tests: tests/replay_v11/test-osv-backend.py, tests/test_task4_b2.py
"""Read invented Debian replay fixtures; write temporary stores. unittest exits 0/1."""
from copy import deepcopy
import unittest
from unittest.mock import Mock

from cornicen.adapterfactories import production_factories
from tests.replay_v11 import harness as h
from tests.replay_v11.osv_backend import DebianBackend, validate_rows


class OsvBackendTests(unittest.TestCase):
    def setUp(self):
        self.assertIn('debian',production_factories(Mock()))

    def test_validation_is_debian_only(self):
        rows=h.load_timeline('debian_bounds')[:4]
        self.assertEqual(validate_rows(rows),rows)
        for before,after in (('examplessl','real-package'),('Debian:12','Ubuntu:12'),
                             ('osv-vulnerabilities.storage.googleapis.com','foreign.invalid'),
                             ('security-tracker.example.invalid','foreign.invalid')):
            bad=deepcopy(rows)
            import json
            bad=json.loads(json.dumps(bad).replace(before,after))
            if bad==rows: continue
            with self.assertRaises(ValueError):validate_rows(bad)
        # Debian-only snapshot additions remain rejected on legacy scenarios.
        from unittest.mock import patch
        original=h._rows
        def altered(path):
            result=original(path)
            if path.name=='boundary.expected.jsonl':
                result[0]['state']={'evidence_rows':{}}
            return result
        with patch.object(h,'_rows',altered):
            with self.assertRaises(ValueError):h.load_expected('boundary')

    def test_projection_keeps_columns_provenance_and_duplicates(self):
        backend=DebianBackend(h.fixture_registry());self.addCleanup(backend.close)
        for row in h.load_timeline('debian_bounds')[:4]:backend.action(row)
        identity='CVE-2099-80213'
        before=backend.snapshot()['evidence_rows'][identity]
        columns={r[1] for r in backend.store.connection.execute('PRAGMA table_info(advisory_evidence)')}
        self.assertEqual(set(before[0]),columns)
        backend.store.connection.execute("UPDATE advisory_evidence SET release='invented-release'")
        self.assertNotEqual(backend.snapshot()['evidence_rows'][identity],before)
        backend.store.connection.execute('UPDATE advisory_evidence SET release=NULL')
        backend.store.connection.execute("UPDATE advisory_evidence SET provenance=json_set(provenance,'$.synthetic','changed')")
        self.assertNotEqual(backend.snapshot()['evidence_rows'][identity],before)
        backend.store.connection.execute("UPDATE advisory_evidence SET provenance=json_remove(provenance,'$.synthetic')")
        backend.store.connection.execute('INSERT INTO advisory_evidence SELECT * FROM advisory_evidence')
        self.assertEqual(backend.snapshot()['evidence_rows'][identity],before*2)

    def test_destroyed_directory_and_action_keys(self):
        backend=DebianBackend(h.fixture_registry());self.addCleanup(backend.close)
        rows=deepcopy(h.load_timeline('debian_bounds')[:4])
        rows[2]['debian'][1].pop('members')
        rows[2]['debian'][1]['broken']='central_directory'
        for row in rows:backend.action(row)
        self.assertEqual(backend.snapshot()['classification'],{'debian':'FAILED'})
        self.assertEqual(backend.snapshot()['events'],[])
        self.assertEqual(set(backend.server.scripts),{(2,'discovery',1),(2,'archive:Debian',1)})
        with self.assertRaises(AssertionError):backend.server.add(2,'discovery')


if __name__=='__main__':unittest.main()

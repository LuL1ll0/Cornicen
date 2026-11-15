# script-purpose: Verify withdrawal identity history and facet reconciliation offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_sw.py
"""Read invented advisories; write temporary SQLite databases. Exit 0/1 via unittest."""
import json
import unittest

from cornicen.feedvalidate import validate_advisory
from tests import test_f3a as helpers, test_f3b as facet_helpers
from tests.test_f3a import advisory, T, P

A = 'CVE-2099-0001'
B = 'CVE-2099-0002'


class WithdrawalTests(unittest.TestCase):
    setUp = helpers.F3aTests.setUp
    pair = helpers.F3aTests.pair
    ack = helpers.F3aTests.ack
    process = facet_helpers.F3bTests.process

    def facet(self, identifier='FIX-2099-0010', title='Widget'):
        return dict(title=title, products=['examplecorp:widget'],
                    ids=[dict(system_name='fixture', text=identifier)])

    def stored(self):
        return json.loads(self.db.execute('SELECT json FROM advisories').fetchone()[0])

    def rows(self, table):
        return [tuple(r) for r in self.db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]

    def snapshot(self):
        return {table: self.rows(table) for table in
                ('advisories', 'advisory_evidence', 'advisory_support', 'pairs',
                 'events', 'outbox', 'identity_redirects')}

    def assert_unique_numbers(self):
        for row in self.db.execute('SELECT json FROM advisories'):
            numbers = [f['number'] for f in json.loads(row[0]).get('facets', [])]
            self.assertEqual(len(numbers), len(set(numbers)))

    def reject(self, raw, reason):
        before = self.snapshot()
        result = self.process(raw)
        # Check persisted numbers even if the status assertion will fail.
        self.assert_unique_numbers()
        self.assertEqual(result, 'PARTIAL')
        self.assertIn(reason, self.db.execute('SELECT reason FROM quarantine').fetchone()[0])
        self.assertEqual(self.snapshot(), before)

    def withdraw(self):
        self.assertEqual(self.process(advisory(cves=()) | dict(withdrawn=T)), 'COMPLETE')
        self.assertFalse(self.rows('advisory_evidence'))
        self.assertEqual(self.stored()['cves'], [])
        self.assertEqual(self.stored()['facets'], [])

    def test_faceted_withdrawal_ambiguous(self):
        facets = [self.facet(), self.facet('FIX-2099-0011')]
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=facets)), 'COMPLETE')
        ambiguous = dict(title='Widget', products=['examplecorp:widget'])
        self.reject(advisory(cves=()) | dict(withdrawn=T, facets=[ambiguous]),
                    'ambiguous facet reconciliation')

    def test_faceted_withdrawal_reassigned(self):
        facet = self.facet()
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[facet])), 'COMPLETE')
        for changed in ([dict(facet, ids=[])],
                        [dict(facet, title='Changed Widget'),
                         dict(title='Widget', products=['examplecorp:widget'])]):
            with self.subTest(changed=changed):
                self.reject(advisory(cves=()) | dict(withdrawn=T, facets=changed),
                            'facet identifier removed or reassigned' if len(changed) == 1
                            else 'facet identifier reassigned')

    def test_faceted_withdrawal_partial(self):
        facets = [self.facet(), self.facet('FIX-2099-0011', 'Other Widget')]
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=facets)), 'COMPLETE')
        self.reject(advisory(cves=()) | dict(withdrawn=T, facets=facets[:1]),
                    'facet identifier removed')

    def assert_duplicate_numbers_rejected(self, withdrawn):
        # One revision per test: a shared database would let an earlier
        # quarantine row satisfy the reason and status assertions.
        facet = self.facet()
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[facet])), 'COMPLETE')
        self.assertFalse(self.rows('quarantine'))
        raw = advisory(cves=()) | dict(facets=[facet, facet])
        if withdrawn:
            raw['withdrawn'] = withdrawn
        self.reject(raw, 'ambiguous facet reconciliation')
        # The adapter path reconciles twice (store, then engine commit), so the
        # second pass can mask a missing check. Pin the check itself.
        from cornicen.advisoryidentity import reconcile_facets
        stored = self.stored()
        twin = {k: v for k, v in stored['facets'][0].items() if k != 'number'}
        data = dict(stored, cves=[], facets=[twin, dict(twin)])
        if withdrawn:
            data['withdrawn'] = withdrawn
        with self.assertRaisesRegex(ValueError, 'ambiguous facet reconciliation'):
            reconcile_facets(self.db, data)

    def test_duplicate_numbers_active(self):
        self.assert_duplicate_numbers_rejected(None)

    def test_duplicate_numbers_withdrawn(self):
        self.assert_duplicate_numbers_rejected(T)

    def test_withdraw_reissue_other_cve(self):
        self.assertEqual(self.process(advisory(cves=(A,))), 'COMPLETE')
        self.ack()
        self.withdraw()
        self.assertEqual(self.pair(A)['state'], 'not_affected')
        self.reject(advisory(cves=(B,)), 'identifier removed or reassigned')
        self.assertEqual(self.stored()['identity_history']['cves'], [A])

    def test_withdraw_reissue_other_facet_identifier(self):
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[self.facet()])), 'COMPLETE')
        self.ack()
        self.withdraw()
        self.assertEqual(self.pair(P.removesuffix('main') + '1')['state'], 'not_affected')
        self.reject(advisory(cves=()) | dict(facets=[self.facet('FIX-2099-0011')]),
                    'facet identifier removed or reassigned')

    def test_withdraw_twice_reissue_other_cve(self):
        self.assertEqual(self.process(advisory(cves=(A,))), 'COMPLETE')
        self.withdraw()
        self.withdraw()
        self.reject(advisory(cves=(B,)), 'identifier removed or reassigned')
        self.assertEqual(self.stored()['identity_history']['cves'], [A])

    def test_withdraw_reissue_same_facets(self):
        anonymous = dict(title='Retired Widget', products=['examplecorp:widget'])
        facet = self.facet()
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[anonymous, facet])), 'COMPLETE')
        self.assertEqual(self.process(advisory(cves=()) | dict(facets=[facet])), 'COMPLETE')
        before = self.stored()
        self.withdraw()
        self.assertEqual(self.stored()['facet_next'], before['facet_next'])
        self.assertEqual(self.process(advisory(cves=()) | dict(
            facets=[self.facet('FIX-2099-0011', 'New Widget'), facet])), 'COMPLETE')
        after = self.stored()
        self.assertEqual(after['facets'][1]['number'], before['facets'][0]['number'])
        self.assertGreaterEqual(after['facets'][0]['number'], before['facet_next'])
        self.assertNotIn('identity_history', after)
        self.assert_unique_numbers()

    def assert_cve_withdrawal_rejected(self, prior, incoming):
        raw = advisory(cves=prior)
        self.assertEqual(self.process(raw), 'COMPLETE')
        self.reject(raw | dict(cves=list(incoming), withdrawn=T),
                    'identifier removed or reassigned')

    def test_withdrawal_different_cve_set(self):
        self.assert_cve_withdrawal_rejected((A,), (B,))

    def test_withdrawal_smaller_cve_set(self):
        self.assert_cve_withdrawal_rejected((A, B), (A,))

    def test_engine_reissue_raises_and_rolls_back(self):
        self.assertEqual(self.process(advisory(cves=(A,))), 'COMPLETE')
        self.withdraw()
        data = validate_advisory(advisory(cves=(B,)), source='fixture_a', observed_at=T).data
        before = list(self.db.iterdump())
        with self.assertRaisesRegex(ValueError, 'identifier removed or reassigned'):
            self.engine.commit_advisory(data)
        self.assertEqual(list(self.db.iterdump()), before)

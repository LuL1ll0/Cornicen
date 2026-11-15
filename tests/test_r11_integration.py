# script-purpose: Verify R11 scoped CNA aggregation and advisory lifecycle policies.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_r11_integration.py
"""Read invented fixtures; write temporary SQLite databases in the workspace.

Run PYTHONPATH=src python3 -m unittest tests.test_r11_integration.
Exit 0 on success, 1 on failure. No network or fixture writes.
"""
from dataclasses import replace
from datetime import date
import json
import unittest
from unittest.mock import patch

from cornicen import applicability, cnascope
from cornicen.accept import Accept
from cornicen.model import FetchStatus, IngestResult, Origin
from tests import test_f3a as fixtures


class R11IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.F3aTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_scoped_multi_entry_uses_resolver_state_evidence_confidence(self):
        f = self.f
        for status in ('affected', 'unaffected', 'unknown'):
            record = f.cna(status)
            entry = record['containers']['cna']['affected'][0]
            record['containers']['cna']['affected'].append(dict(entry, versions=[], version='malformed'))
            expected = applicability.resolve(record, None, f.watch, f.engine.aliases)
            verdict, = cnascope.scoped_verdicts(record, f.watch, f.engine.aliases)
            self.assertEqual((verdict.state, verdict.evidence, verdict.confidence),
                             (expected.state, expected.evidence, expected.confidence))
            self.assertEqual(verdict.authoritative, expected.confidence == 'high')

    def test_rejected_and_withdrawn_cna_retract_without_adapter_veto(self):
        f = self.f
        f.put()
        for state in ('REJECTED', 'WITHDRAWN'):
            record = f.cna('unaffected')
            record['cveMetadata']['state'] = state
            self.assertEqual(cnascope.scoped_verdicts(record, f.watch, f.engine.aliases), ())
            self.assertEqual(f.engine.advisory_result(f.watch, fixtures.A, record=record).state,
                             applicability.State.AFFECTED)

    def test_cna_authority_does_not_cross_package_scope(self):
        f = self.f
        watch = replace(f.watch, match=(('examplecorp', 'widget'), ('examplecorp', 'gadget')))
        raw = fixtures.advisory()
        raw['products'][0]['name'] = 'examplecorp:gadget'
        f.put(raw)
        result = f.engine.advisory_result(watch, fixtures.A, record=f.cna('unaffected'))
        self.assertEqual(result.state, applicability.State.AFFECTED)
        self.assertIn('fixture_a: affected', result.evidence)
        self.assertIn('CNA unaffected widget', result.evidence)

    def test_withdrawal_route_is_sticky_and_closes_only_once(self):
        f = self.f
        f.put()
        f.ack()
        f.put(fixtures.advisory('under_investigation'))
        f.put(fixtures.advisory() | {'withdrawn': fixtures.T})
        self.assertEqual(f.engine.route(fixtures.A, f.watch), 'advisory')
        self.assertEqual(f.pair()['episode'], 2)
        f.engine._evaluate(None, fixtures.A)
        self.assertEqual(f.pair()['episode'], 2)
        self.assertEqual([r[0] for r in f.db.execute("SELECT key FROM events WHERE type='correction'")],
                         ['w|' + fixtures.A + '|correction|1'])

    def test_delivery_revalidation_applies_acceptance_and_kev_override(self):
        f = self.f
        f.put()
        f.engine.accepts = (Accept(fixtures.A, 'w', 'reviewed', date(2100, 1, 1), False, None, 1),)
        row = f.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        held = f.engine._revalidate(row)
        self.assertTrue(json.loads(held['body_json'])['accepted']['held'])
        f.db.execute('INSERT INTO kev VALUES (?,?)', (fixtures.A, json.dumps({'cveID': fixtures.A})))
        released = f.engine._revalidate(held)
        self.assertFalse(json.loads(released['body_json'])['accepted']['held'])
        self.assertEqual(released['urgency'], 'urgent')

    def test_delivery_revalidation_sibling_is_report_only(self):
        f = self.f
        sibling = 'CVE-2099-0041'
        raw = fixtures.advisory(cves=(fixtures.A, sibling))
        raw['products'].append(dict(id='q', name='examplecorp:gadget'))
        raw['evidence'].append(dict(raw['evidence'][0], product_id='q'))
        raw['associations'] = [dict(cve=fixtures.A, product_id='p'), dict(cve=sibling, product_id='q')]
        f.put(raw)
        f.db.execute('INSERT INTO kev VALUES (?,?)', (sibling, json.dumps({'cveID': sibling})))
        body = dict(watch_id='w', record_id=sibling, episode=1)
        f.store.queue('w|' + sibling, 'urgent', ['KEV added'], body, fixtures.T, fixtures.T)
        row = f.db.execute('SELECT * FROM outbox WHERE pair_key=?', ('w|' + sibling,)).fetchone()
        self.assertIsNone(f.engine._revalidate(row))

    def test_malformed_scope_preserves_cna_only_pair_and_event(self):
        f = self.f
        gadget = replace(f.watch, id='g', match=(('examplecorp', 'gadget'),))
        f.engine.watches = (f.watch, gadget)
        f.engine._cache_watch_identities()
        record = f.cna('affected')
        entry = record['containers']['cna']['affected'][0]
        record['containers']['cna']['affected'].append(dict(entry, product='gadget'))
        entry['release'] = ['x']
        f.engine._evaluate(record, fixtures.A, watches=(gadget,))
        expected_pair = tuple(f.db.execute("SELECT * FROM pairs WHERE watch_id='g'").fetchone())
        expected_event = tuple(f.db.execute("SELECT * FROM events WHERE watch_id='g'").fetchone())
        f.db.execute("DELETE FROM pairs WHERE watch_id='g'")
        f.db.execute("DELETE FROM events WHERE watch_id='g'")
        f.put()
        with f.store.transaction():
            f.engine._isolated('cvelist', record, lambda: f.engine._evaluate(record, fixtures.A))
        self.assertEqual(tuple(f.db.execute("SELECT * FROM pairs WHERE watch_id='g'").fetchone() or ()), expected_pair)
        self.assertEqual(tuple(f.db.execute("SELECT * FROM events WHERE watch_id='g'").fetchone() or ()), expected_event)
        self.assertEqual(f.db.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 0)
        for bad in (['x'], {'x': 1}, 42):
            entry['release'] = entry['platform'] = bad
            verdict, = cnascope.scoped_verdicts(record, f.watch, f.engine.aliases)
            self.assertIsNone(verdict.release)
            self.assertIsNone(verdict.platform)

    def test_advisory_exception_cannot_rollback_v1(self):
        f = self.f
        gadget = replace(f.watch, id='g', match=(('examplecorp', 'gadget'),))
        f.engine.watches = (f.watch, gadget)
        f.engine._cache_watch_identities()
        f.put()
        record = f.store_gadget_cna()
        with f.store.transaction(), patch.object(f.engine, 'advisory_result', side_effect=RuntimeError('injected')):
            f.engine._isolated('cvelist', record, lambda: f.engine._evaluate(record, fixtures.A))
        self.assertIsNotNone(f.db.execute("SELECT * FROM pairs WHERE watch_id='g'").fetchone())
        self.assertIsNotNone(f.db.execute("SELECT * FROM events WHERE watch_id='g'").fetchone())

    def test_reload_missing_record_held_by_unchanged_watch(self):
        f = self.f
        other = replace(f.watch, id='g', match=(('examplecorp', 'gadget'),))
        f.engine.watches = (f.watch, other)
        f.engine._cache_watch_identities()
        f.engine._evaluate(f.cna('affected'), fixtures.A)
        f.engine.reload_watches((f.watch, replace(other, version='7.77.0')))
        health = f.db.execute("SELECT * FROM health WHERE source='records'").fetchone()
        self.assertIsNotNone(health)
        self.assertEqual(health['state'], 'unhealthy')

    def test_empty_adapter_routing_has_constant_query_count(self):
        f = self.f
        for count in (1, 30):
            watches = tuple(replace(f.watch, id=f'w{i}') for i in range(count))
            queries = []
            f.db.set_trace_callback(queries.append)
            try:
                with patch.object(f.engine, '_evaluate_pairs'):
                    f.engine._evaluate(f.cna('affected'), fixtures.A, watches=watches)
            finally:
                f.db.set_trace_callback(None)
            routing = [q for q in queries if 'advisory_' in q]
            self.assertLessEqual(len(routing), 1, routing)

    def test_support_text_is_not_advisory_history(self):
        f = self.f
        f.engine._evaluate(f.cna('affected'), fixtures.A)
        f.db.execute("UPDATE pairs SET evidence='fixture_a: coincidental CNA text'")
        f.db.execute('INSERT INTO advisory_support VALUES (?,?,?)', ('fixture_a', 'FIX-2099-7777', fixtures.A))
        self.assertEqual(f.engine.route(fixtures.A, f.watch), 'v1')

    def test_identity_indexes(self):
        f = self.f
        for table in ('advisory_evidence', 'advisory_shells'):
            indexes = [r[1] for r in f.db.execute(f'PRAGMA index_list({table})')]
            self.assertTrue(any([r[2] for r in f.db.execute(f'PRAGMA index_info({name})')] == ['identity'] for name in indexes), table)

    def _advisory_retry_case(self, source):
        f = self.f
        gadget = replace(f.watch, id='g', match=(('examplecorp', 'gadget'),))
        f.engine.watches = (f.watch, gadget)
        f.engine._cache_watch_identities()
        f.put()
        f.ack()
        record = f.store_gadget_cna()
        f.store.set_meta('baseline_complete', '1')
        f.store.set_meta('kev_initialized', '1')
        marker = 'matching_revision_retry:' + fixtures.A
        f.store.set_meta(marker, '1')
        edited = (replace(f.watch, version='7.77.0'), gadget)
        with patch.object(f.engine, '_flush'):
            with patch.object(f.engine, 'advisory_result', side_effect=RuntimeError('injected')):
                if source == 'watchlist':
                    f.engine.reload_watches(edited, force_all=True)
                else:
                    f.engine.watches = edited
                    f.engine._cache_watch_identities()
                    ingest = IngestResult(source, FetchStatus.COMPLETE,
                        Origin.DELTA if source == 'cvelist' else Origin.CATALOG,
                        'retry-cursor', f.clock(), records=(record,) if source == 'cvelist' else (),
                        kev={fixtures.A: {'cveID': fixtures.A}} if source == 'kev' else None)
                    f.engine.run_cycle((ingest,), release_checks=False)
                self.assertEqual(f.store.get_meta(marker), '1')
                retry = f.db.execute('SELECT * FROM retry_queue WHERE source=? AND record_id=?',
                                     (source, fixtures.A)).fetchone()
                self.assertIsNotNone(retry)
                self.assertEqual(retry['attempts'], 1)
                self.assertEqual(f.db.execute('SELECT state FROM health WHERE source=?',
                                             (source,)).fetchone()[0], 'unhealthy')
                self.assertEqual(f.db.execute("SELECT state FROM pairs WHERE watch_id='g'").fetchone()[0],
                                 'affected')
                events = [tuple(row) for row in f.db.execute("SELECT * FROM events WHERE watch_id='g' ORDER BY key")]
                self.assertTrue(events)
                if source != 'watchlist':
                    self.assertIsNone(f.db.execute('SELECT 1 FROM cursors WHERE source=?', (source,)).fetchone())
                # A second failed attempt must retain the row, marker and v1 events.
                f.engine.run_cycle((), release_checks=False)
                self.assertEqual(f.db.execute('SELECT attempts FROM retry_queue WHERE source=?',
                                             (source,)).fetchone()[0], 2)
                self.assertEqual(f.store.get_meta(marker), '1')
            recovered = f.engine.run_cycle((), release_checks=False)
            self.assertIsNone(f.store.get_meta(marker))
            self.assertFalse(f.db.execute('SELECT 1 FROM retry_queue WHERE source=?', (source,)).fetchone())
            self.assertEqual(f.db.execute('SELECT state FROM health WHERE source=?',
                                         (source,)).fetchone()[0], 'healthy')
            self.assertEqual(f.db.execute("SELECT state FROM pairs WHERE watch_id='w'").fetchone()[0],
                             'not_affected')
            correction = 'w|' + fixtures.A + '|correction|1'
            self.assertIn(correction, recovered.events)
            self.assertEqual([tuple(row) for row in f.db.execute("SELECT * FROM events WHERE watch_id='g' ORDER BY key")], events)
            self.assertFalse(any(key.startswith('g|') for key in recovered.events))
            if source != 'watchlist':
                self.assertEqual(f.db.execute('SELECT value FROM cursors WHERE source=?',
                                             (source,)).fetchone()[0], 'retry-cursor')
            f.engine.run_cycle((), release_checks=False)
            self.assertEqual(f.db.execute('SELECT count(*) FROM events WHERE key=?', (correction,)).fetchone()[0], 1)

    def test_advisory_failure_retries_matching_revision_rematch(self):
        self._advisory_retry_case('watchlist')

    def test_advisory_failure_retries_cvelist_ingest(self):
        self._advisory_retry_case('cvelist')

    def test_advisory_failure_retries_kev_ingest(self):
        self._advisory_retry_case('kev')

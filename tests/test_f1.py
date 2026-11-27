# script-purpose: Verify the F1 adapter foundation without network or persistence.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f1.py
"""Read invented inputs and frozen dumps; write temporary databases only.

Run python3 -m unittest tests.test_f1; exit 0 on success, 1 on failure.
"""
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import Mock

from cornicen import adapters, feeddates as dates, feedvalidate as v
from cornicen.config import Config, load_config
from cornicen.cli import status_json
from cornicen.engine import Engine
from cornicen.store import Store
from tests.replay_v11 import harness as h
from tests.replay_v11.fixture_adapter import observe_pairs

T = '2099-01-01T00:00:00Z'
ROOT = Path(__file__).parent / 'fixtures/v0116_frozen/status'

def member():
    return dict(id='FIX-2099-0001', title='Widget', url='https://examplecorp.invalid/a',
                published=T, updated=T, products=[], evidence=[], cves=[])

def resource(body='[]', **kw):
    return dict(path='a.json', status=200, body=body, **kw)

class F1Tests(unittest.TestCase):
    def config(self, text=''):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text(text)
            return load_config(path, {})

    def test_default_settings(self):
        config = self.config()
        self.assertEqual(config.adapters, dict.fromkeys(adapters.REGISTRY, False) | {'github': True})
        self.assertFalse(any(s['effective'] for s in adapters.status(config.adapters).values()))
        self.assertTrue(all(not hasattr(a, 'factory') for a in adapters.REGISTRY.values()))
        for name, entry in adapters.REGISTRY.items():
            with self.subTest(name=name):
                self.assertIs(entry.last_modified_validated, False)
                self.assertIs(entry.export, name in ('debian', 'ubuntu'))

    def test_unmet_gate_wins(self):
        config = self.config('[adapters.msrc]\nenabled=true')
        self.assertIn('msrc: disabled: gate M not met (setting on)', adapters.status_lines(config.adapters))
        factory = Mock()
        for name, entry in adapters.REGISTRY.items():
            if entry.effective(config.adapters[name]):
                factory().poll()
        factory.assert_not_called()

    def test_setting_off(self):
        config = self.config('[adapters.github]\nenabled=false')
        self.assertIn('github: disabled: gate G not met (setting off)', adapters.status_lines(config.adapters))
        self.assertFalse(replace(adapters.REGISTRY['github'], gate='met').effective(False))

    def test_adapters_config_rejected(self):
        for text in ['[adapters.other]\nenabled=true', '[adapters.msrc]\nother=true',
                     'adapters=1', '[adapters.msrc]\nenabled=1', '[adapters.msrc]\nenabled="true"',
                     'adapters=[]', '[adapters]\nmsrc=true']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.config(text)

    def test_status_lists_six(self):
        lines = adapters.status_lines(self.config().adapters)
        self.assertEqual([line.split(':')[0] for line in lines], list(adapters.REGISTRY))
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[-1].endswith('(setting on)'))
        self.assertTrue(all(line.endswith('(setting off)') for line in lines[:-1]))

    def restore(self, name):
        frozen = json.loads((ROOT / (name + '.database.json')).read_text())
        store = Store(':memory:')
        store.migrate()
        # R-SK5: restore pre-migration state without the new side table.
        for table in h.NEW_TABLES | {'outbox_event_keys'}:
            store.connection.execute(f'DROP TABLE "{table}"')
        for table, data in frozen['tables'].items():
            store.connection.execute(f'DELETE FROM "{table}"')
            for row in data['rows']:
                cells = [bytes.fromhex(c['$blob']) if isinstance(c, dict) else c for c in row]
                store.connection.execute(f'INSERT INTO "{table}" VALUES ({",".join("?" for _ in cells)})', cells)
        return store, frozen

    def test_status_json_frozen(self):
        capture = json.loads((ROOT.parent / 'capture.json').read_text())
        inputs = Path(__file__).parent / 'replay' / (capture['populated_scenario'] + '.input.jsonl')
        watchlist = next(row['watchlist'] for row in map(json.loads, inputs.read_text().splitlines())
                         if 'watchlist' in row)
        with tempfile.TemporaryDirectory() as directory:
            watch = Path(directory) / 'watch.toml'
            watch.write_text(watchlist)
            config = Config(':memory:', watch, None, 'https://example.invalid', 'fixture', None)
            for name in ('missing', 'empty', 'populated'):
                with self.subTest(state=name):
                    store = None
                    if name != 'missing':
                        store, _ = self.restore(name)
                        store.migrate()
                    try:
                        out = io.StringIO()
                        with redirect_stdout(out):
                            status_json(store, datetime.fromisoformat(capture['status_at']), config)
                        actual = json.loads(out.getvalue())
                        self.assertEqual(actual.pop('adapters'), adapters.status(config.adapters))
                        self.assertEqual(actual, json.loads((ROOT / (name + '.json')).read_text()))
                    finally:
                        if store:
                            store.connection.close()

    def test_migration_additive(self):
        store, frozen = self.restore('populated')
        try:
            store.migrate()
            actual = h.dump_database(store.connection)
            self.assertEqual(h.project_frozen(actual, frozen), frozen)
            h.assert_additions(actual, frozen)
            with self.assertRaisesRegex(AssertionError, 'unexpected meta keys'):
                h.assert_additions(dict(actual, meta_keys=sorted(
                    [*actual['meta_keys'], 'outbox_event_keys_version_unapproved'])), frozen)
            self.assertEqual(len(h.NEW_TABLES), 18)
            self.assertEqual(actual['tables']['pairs']['columns'], frozen['tables']['pairs']['columns'])
            self.assertEqual(actual['tables']['affected_latches']['rows'], [])
            self.assertEqual(store.get_meta('schema_version'), '1')
            store.migrate()
            self.assertEqual(h.dump_database(store.connection), actual)
            # Also cover durable work absent from the captured status example.
            # Keep the frozen files intact and take an in-memory pre-migration dump.
            # R-SK5: model the old schema without the side table or its marker.
            for table in h.NEW_TABLES | {'outbox_event_keys'}:
                store.connection.execute(f'DROP TABLE "{table}"')
            store.connection.execute("DELETE FROM meta WHERE k IN ('adapter_schema_version','outbox_event_keys_version')")
            for identity, attempts in [('CVE-2099-0001', 0), ('CVE-2099-0002', 5)]:
                store.connection.execute('''INSERT INTO outbox
                    (pair_key,urgency,reasons_json,body_json,due_at,attempts,enqueued_at,dirty)
                    VALUES (?,'normal','["new match"]',?,?,?, ?,0)''',
                    ('w|' + identity, json.dumps({'record_id': identity}), T, attempts, T))
            store.connection.execute('INSERT INTO retry_queue VALUES (?,?,?,?,?)',
                                     ('cvelist', 'CVE-2099-0003', 2, T, 'invalid record'))
            store.connection.execute('INSERT INTO dead_letters VALUES (?,?,?,?,?,?)',
                                     ('cvelist', 'CVE-2099-0004', 5, T, 'invalid record', 'fixture'))
            before = h.dump_database(store.connection)
            store.migrate()
            after = h.dump_database(store.connection)
            self.assertEqual(h.project_frozen(after, before), before)
            h.assert_additions(after, before)
            store.migrate()
            self.assertEqual(h.dump_database(store.connection), after)
        finally:
            store.connection.close()

    def classify(self, r, **kw):
        result = v.validate_resource(r, source='fixture_a', observed_at=T, **kw)
        list(result.records)
        return result

    def test_pair_latch_observation(self):
        store, _ = self.restore('populated')
        try:
            store.migrate()
            self.assertTrue(observe_pairs(store.connection))
            self.assertTrue(all(not row['affected_latch'] for row in observe_pairs(store.connection)))
            pair = observe_pairs(store.connection)[0]
            store.connection.execute('INSERT INTO affected_latches VALUES (?,?,?,1)',
                                     (pair['watch'], pair['id'], pair['episode'] + 1))
            self.assertFalse(observe_pairs(store.connection)[0]['affected_latch'])
            store.connection.execute('INSERT INTO affected_latches VALUES (?,?,?,1)',
                                     (pair['watch'], pair['id'], pair['episode']))
            self.assertTrue(observe_pairs(store.connection)[0]['affected_latch'])
        finally:
            store.connection.close()

    def test_classification_table(self):
        for r, expected in [(resource(), 'COMPLETE'),
                (resource(json.dumps([member(), {}])), 'PARTIAL'),
                (resource('{', transfer_complete=False), 'PARTIAL'),
                (resource('[]', integrity='failed'), 'FAILED'),
                *[(resource(json.dumps({'advisories': [], key: value})), 'PARTIAL') for key, value in
                  [('pagination_stable', False),
                   ('expected_count', 1), ('coverage_complete', False)]],
                (resource(json.dumps([member() | {'evidence': [{'product_id': 'missing', 'scheme': 'semver', 'status': 'known_affected'}]}])), 'PARTIAL'),
                (dict(resource(), status=500), 'FAILED'),
                *[(resource(body), 'FAILED') for body in ['', '<html>x</html>', '{"error":"x"}', '{}', '1', '{']]]:
            with self.subTest(r=r):
                self.assertEqual(self.classify(r).classification, expected)

        from cornicen.adapterstore import AdapterStore
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'state.db')
            try:
                store.migrate()
                persistence = AdapterStore(store, directory)
                self.assertEqual(persistence.process('fixture_a', [resource(json.dumps([member()]))], T), 'COMPLETE')
                self.assertEqual(persistence.process('fixture_a', [resource('[]')], T), 'PARTIAL')
            finally:
                store.connection.close()

    def test_membership_collapse(self):
        for count, prior, expected in [(79, 100, 'PARTIAL'), (80, 100, 'COMPLETE'), (0, 0, 'COMPLETE')]:
            self.assertEqual(self.classify(resource(json.dumps([member()] * count)), prior_count=prior).classification, expected)

    def test_ids_and_urls(self):
        for value in ['', '  ', 'a|b', 'a\x00b']:
            with self.assertRaises(ValueError): v.source_id(value)
        for value in ['javascript:x', 'file:///x', '/x', 'https://', 'http//x']:
            with self.assertRaises(ValueError): v.display_url(value)
        for value in ['http://examplecorp.invalid/x', 'https://examplecorp.invalid/x']:
            self.assertEqual(v.display_url(value), value)

    def test_safe_paths(self):
        for value in ['/a', '../a', 'a/../b', 'a\\b', 'a\x00', 'a//b', '%2e%2e/a']:
            with self.assertRaises(ValueError): v.safe_path(value)
        self.assertEqual(v.safe_path('a/b.json'), 'a/b.json')

    def test_xml_entities_rejected(self):
        for value in ['<!DOCTYPE x><x/>', '<!ENTITY x "y"><x/>']:
            with self.assertRaises(ValueError): v.reject_xml_entities(value)
        v.reject_xml_entities('<x/>')

    def test_members_streamed(self):
        def members():
            for n in range(200000):
                yield member() | {'id': f'FIX-2099-{n:06}', 'title': 'x' * 300, 'padding': 'x' * 724}
        tracemalloc.start()
        try:
            result = v.validate_members(members(), source='fixture_a', observed_at=T)
            self.assertEqual(sum(1 for _ in result.records), 200000)
            self.assertEqual(result.classification, 'COMPLETE')
            self.assertLess(tracemalloc.get_traced_memory()[1], 32 * 1024**2)
        finally:
            tracemalloc.stop()

    def test_unvalidated_record_rejected(self):
        store = Store(':memory:')
        try:
            store.migrate()
            before = h.dump_database(store.connection)
            engine = object.__new__(Engine)
            engine.store = store
            with self.assertRaises(TypeError):
                engine.validate_adapter_result(v.AdapterResult(iter([member()])))
            self.assertEqual(h.dump_database(store.connection), before)
            with self.assertRaises(TypeError):
                v.ValidatedAdvisory(member())
        finally:
            store.connection.close()

    def test_rfc822(self):
        for value in ['Thu, 29 Oct 2099 13:12:54 +0000', 'Thu, 29 Oct 2099 15:12:54 +0200']:
            self.assertEqual(dates.rfc822(value).utc(), '2099-10-29T13:12:54Z')
        with self.assertRaises(ValueError): dates.rfc822('Thu, 29 Oct 2099 13:12:54')

    def test_rfc3339_fractions(self):
        for fraction in ['', '.1', '.123', '.123456', '.123456789', '.123456789123']:
            value = '2099-01-01T00:00:00' + fraction + 'Z'
            self.assertEqual(dates.rfc3339(value).raw, value)
        self.assertGreater(dates.rfc3339('2099-01-01T00:00:00.1Z'), dates.rfc3339(T))
        self.assertLess(dates.rfc3339('2099-01-01T01:00:00+02:00'), dates.rfc3339('2099-01-01T00:30:00Z'))
        equal = [dates.rfc3339(x) for x in ['2099-01-01T00:00:00.5Z', '2099-01-01T00:00:00.500000000Z', '2099-01-01T02:00:00.5+02:00']]
        self.assertEqual(equal[0], equal[1]); self.assertEqual(equal[1], equal[2])
        self.assertNotEqual(dates.rfc3339('2099-01-01T00:00:00.0000001Z'), dates.rfc3339('2099-01-01T00:00:00.0000002Z'))
        self.assertEqual(dates.rfc3339('2099-01-01T02:00:00+02:00').utc(), T)

    def test_strict_decoding(self):
        for body in [b'\xff', '[]'.encode('utf-16'), '{"a":1,"a":2}', '[]x', '[NaN]', '[Infinity]', '[-Infinity]']:
            with self.assertRaises(ValueError): v.decode_json(body)
        bad = member() | {'evidence': [{'scheme': 'invented', 'product_id': 'p'}]}
        with self.assertRaisesRegex(ValueError, 'unknown version scheme'):
            v.validate_advisory(bad, source='fixture_a', observed_at=T)

    def test_required_optional_dates(self):
        for change in [{k: value} for k in ['published', 'updated'] for value in [None, 'bad']]:
            result = self.classify(resource(json.dumps([member() | change])))
            self.assertEqual(result.classification, 'PARTIAL')
            self.assertEqual(result.quarantine, ['FIX-2099-0001'])
        for field in ['published', 'updated']:
            raw = member(); del raw[field]
            self.assertEqual(self.classify(resource(json.dumps([raw]))).classification, 'PARTIAL')
        result = self.classify(resource(json.dumps([member() | {'withdrawn': 'bad'}])))
        self.assertEqual(result.classification, 'PARTIAL')
        raw = v.validate_advisory(member(), source='fixture_a', observed_at=T)
        self.assertIsNone(raw.data['withdrawn'])

    def test_harness_smoke(self):
        result = h.run_scenario('empty_enumeration')
        self.assertEqual([n for n in result.notifications if n['watch']], [])
        self.assertEqual([n['record'] for n in result.notifications if n['case']=='main'], ['baseline:fixture_a'])
        for tick in ['2099-11-03T01:00:00Z', '2099-11-03T02:00:00Z']:
            self.assertEqual(result.snapshots[('main', tick)]['classification']['fixture_a'], 'COMPLETE')
        with self.assertRaises(ValueError):
            h.validate_timeline([{'t': '2099-01-02T00:00:00Z', 'watchlist': h.WATCHLIST}, {'t': T, 'cycle': True}])

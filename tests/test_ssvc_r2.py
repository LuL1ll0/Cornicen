# script-purpose: Check malformed ADP projection, transaction failures and projection recovery policy.
# script-class: harness
# script-trigger: Run by unittest discovery and make gate.
# script-tests: tests/test_ssvc_r2.py
"""Read invented fixtures and source modules; write temporary SQLite state and test output.

Run with python -m unittest tests.test_ssvc_r2. Exit codes: 0 success, 1 failure,
2 invalid command arguments. No network is used.
"""
from copy import deepcopy
from datetime import timedelta
from itertools import permutations, product
import json
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from cornicen import validate
from cornicen.health import assess
from cornicen.fetch import Response
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.store import Store, project_record, record_ssvc
from cornicen.sources.cvelist import CveListSource
from tests import test_ssvc as fixtures

NOW = fixtures.NOW


class ReleaseFault:
    def __init__(self, connection, persistent=False):
        self.connection = connection
        self.failed = False
        self.persistent = persistent

    def execute(self, sql, *args):
        if sql.startswith('RELEASE') and (self.persistent or not self.failed):
            self.failed = True
            raise sqlite3.OperationalError('injected release failure')
        return self.connection.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class StoreCommitTests(unittest.TestCase):
    def test_store_release_failure_rolls_back_and_connection_reusable(self):
        store = Store(':memory:')
        store.migrate()
        connection = store.connection
        self.addCleanup(connection.close)
        store.connection = ReleaseFault(connection)
        with self.assertRaises(sqlite3.OperationalError):
            with store.transaction():
                store.set_meta('failed', '1')
        self.assertFalse(connection.in_transaction)
        self.assertIsNone(store.get_meta('failed'))
        with store.transaction():
            store.set_meta('durable', '1')
        connection.rollback()
        self.assertEqual(store.get_meta('durable'), '1')

    def test_store_nested_release_failure_isolates_inner_work(self):
        store = Store(':memory:')
        store.migrate()
        connection = store.connection
        self.addCleanup(connection.close)
        with store.transaction():
            store.set_meta('outer', '1')
            store.connection = ReleaseFault(connection)
            with self.assertRaises(sqlite3.OperationalError):
                with store.transaction():
                    store.set_meta('inner', '1')
            self.assertIsNone(store.get_meta('inner'))
            self.assertEqual(store.get_meta('outer'), '1')
        self.assertFalse(connection.in_transaction)
        self.assertEqual(store.get_meta('outer'), '1')

    def test_store_release_cleanup_failure_rolls_back_entire_transaction(self):
        store = Store(':memory:')
        store.migrate()
        connection = store.connection
        self.addCleanup(connection.close)
        with self.assertRaises(Exception) as caught:
            with store.transaction():
                store.set_meta('outer', '1')
                store.connection = ReleaseFault(connection, persistent=True)
                with store.transaction():
                    store.set_meta('inner', '1')
        self.assertEqual(type(caught.exception).__name__, 'TransactionAborted')
        self.assertFalse(connection.in_transaction)
        self.assertIsNone(store.get_meta('outer'))
        self.assertIsNone(store.get_meta('inner'))

    def test_r3_aborted_scope_refuses_new_savepoints_until_outer_exit(self):
        store = Store(':memory:')
        store.migrate()
        raw = store.connection
        self.addCleanup(raw.close)
        with self.assertRaises(Exception) as outer:
            with store.transaction():
                store.set_meta('outer', '1')
                store.connection = ReleaseFault(raw, persistent=True)
                with self.assertRaises(Exception) as inner:
                    with store.transaction():
                        store.set_meta('inner', '1')
                self.assertEqual(type(inner.exception).__name__, 'TransactionAborted')
                self.assertIsInstance(inner.exception.__cause__, sqlite3.OperationalError)
                self.assertFalse(raw.in_transaction)
                self.assertIsNone(store.get_meta('outer'))
                with self.assertRaises(Exception) as refused:
                    with store.transaction():
                        self.fail('aborted scope accepted new work')
                self.assertEqual(type(refused.exception).__name__, 'TransactionAborted')
        self.assertEqual(type(outer.exception).__name__, 'TransactionAborted')
        store.connection = raw
        with store.transaction():
            store.set_meta('recovered', '1')
        raw.rollback()
        self.assertEqual(store.get_meta('recovered'), '1')


class SsvcRound2Tests(unittest.TestCase):
    setUp = fixtures.SsvcTests.setUp
    source = fixtures.SsvcTests.source
    ingest = fixtures.SsvcTests.ingest

    def test_r3_engine_cleanup_failure_stops_cycle_before_later_records(self):
        raw = self.store.connection
        original = self.engine._apply_record
        for mode in ('ordinary', 'rollback-to', 'release-cleanup', 'lost-transaction'):
            with self.subTest(mode=mode):
                target = f'tx_{self.store._savepoint + 3}'
                class Fault:
                    def execute(self, sql, *args):
                        if sql == (f'ROLLBACK TO {target}' if mode == 'rollback-to'
                                   else f'RELEASE {target}') and mode in ('rollback-to', 'release-cleanup'):
                            raise sqlite3.OperationalError('injected cleanup failure')
                        return raw.execute(sql, *args)
                    def __getattr__(self, name):
                        return getattr(raw, name)
                self.store.connection = Fault()
                visited = []
                def apply(record, baseline=False):
                    number = record['cveMetadata']['cveId']
                    visited.append(number)
                    if number == 'CVE-2099-5102':
                        if mode == 'lost-transaction':
                            raw.rollback()
                        raise ValueError('invented evaluation failure')
                    return original(record, baseline)
                result = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                    None, NOW, tuple(fixtures.record(n) for n in (5101, 5102, 5103)))
                with patch.object(self.engine, '_apply_record', side_effect=apply):
                    if mode == 'ordinary':
                        self.engine.run_cycle([result])
                        self.assertEqual(raw.execute('SELECT count(*) FROM records').fetchone()[0], 3)
                        self.assertEqual(raw.execute('SELECT count(*) FROM pairs').fetchone()[0], 2)
                        self.assertEqual(raw.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 1)
                    else:
                        with self.assertRaises(Exception) as caught:
                            self.engine.run_cycle([result])
                        self.assertEqual(type(caught.exception).__name__, 'TransactionAborted')
                        self.assertNotIn('CVE-2099-5103', visited)
                        raw.rollback()
                        for table in ('records', 'pairs', 'events', 'outbox', 'retry_queue', 'cursors'):
                            self.assertEqual(raw.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)
                self.assertFalse(raw.in_transaction)
                for table in ('records', 'pairs', 'events', 'outbox', 'retry_queue', 'cursors'):
                    raw.execute(f'DELETE FROM {table}')
                self.store.connection = raw

    def test_r3_real_nested_snapshot_skips_validation_errors_only(self):
        good, bad = fixtures.record(5201), fixtures.record(5202)
        bad['containers']['cna']['affected'] = 'invalid'
        for extra in (None, 'invalid-json', 'bad-layout', 'expansion', 'corrupt'):
            with self.subTest(extra=extra):
                self.store.connection.execute("DELETE FROM meta WHERE k IN ('applied_projection_revision','projection_skipped_records','projection_next_attempt_at')")
                for number in (5201, 5202):
                    self.store.put_record(f'CVE-2099-{number}', fixtures.record(number, {}), 'original')
                before = self.store.connection.execute("SELECT json FROM records WHERE id='CVE-2099-5202'").fetchone()[0]
                source = self.source(())
                source.directory = Path('.build')
                source._archive = CveListSource._archive.__get__(source)
                inner = io.BytesIO()
                with ZipFile(inner, 'w') as zipped:
                    for value in (good, bad):
                        zipped.writestr(f"cves/2099/5xxx/{value['cveMetadata']['cveId']}.json", json.dumps(value))
                    if extra == 'invalid-json':
                        zipped.writestr('cves/2099/5xxx/CVE-2099-5203.json', '{')
                    if extra == 'bad-layout':
                        zipped.writestr('cves/unexpected.json', '{}')
                with tempfile.TemporaryDirectory(dir='.build') as directory:
                    path = Path(directory) / 'snapshot.zip'
                    with ZipFile(path, 'w') as zipped:
                        zipped.writestr('invented.zip', b'invalid' if extra == 'corrupt' else inner.getvalue())
                    source._get = Mock(return_value=Response(200, {}, None, path))
                    release = source._listing.return_value[0][0]
                    # Keep the container readable and fail one record's budget.
                    check = source._check_entry
                    def entry_check(entry, limit):
                        check(entry, limit)
                        if extra == 'expansion' and entry.filename.endswith('5201.json'):
                            raise ValueError('Uncompressed size limit exceeded')
                    with patch.object(source, '_check_entry', side_effect=entry_check):
                        source._backfill_projection([release], NOW)
                    self.assertFalse(path.exists())
                self.assertEqual(self.store.connection.execute("SELECT json FROM records WHERE id='CVE-2099-5202'").fetchone()[0], before)
                if extra is None:
                    self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
                    self.assertEqual(self.store.get_meta('projection_skipped_records'), '1')
                    self.assertEqual(record_ssvc(self.engine._record('CVE-2099-5201')), fixtures.POINTS)
                    self.assertEqual(assess('projection', self.store, NOW, self.config), ('healthy', 'complete; 1 records skipped'))
                    self.assertEqual(self.store.connection.execute("SELECT detail FROM health WHERE source='projection'").fetchone()[0], 'complete; 1 records skipped')
                else:
                    self.assertIsNone(self.store.get_meta('applied_projection_revision'))
                    self.assertEqual(record_ssvc(self.engine._record('CVE-2099-5201')), {})
                    self.assertEqual(self.store.get_meta('projection_next_attempt_at'), (NOW + timedelta(hours=6)).isoformat())

    def test_ssvc_malformed_adp_containers_never_escape_allowlist(self):
        entry = fixtures.record()['containers']['adp'][0]
        malformed = [entry, [list([entry])], [dict(entry, metrics=entry)],
                     [None, 'discard', 3, [entry]],
                     [dict(entry, metrics=[None, 'discard', [entry], {}])],
                     None, 'discard']
        for adp in malformed:
            with self.subTest(adp=adp):
                value = fixtures.record()
                value['containers']['adp'] = deepcopy(adp)
                self.assertEqual(validate.record(value), [])
                projected = project_record(value)
                self.assertNotIn('discard', json.dumps(projected))
                self.assertEqual(validate.record(projected), [])
                self.assertEqual(projected['containers']['cna'], value['containers']['cna'])
                self.assertEqual(project_record(projected), projected)
                self.ingest(value)
                self.assertEqual(self.engine._record('CVE-2099-1001'), projected)
                self.assertEqual(self.store.connection.execute('SELECT count(*) FROM invalid_revisions').fetchone()[0], 0)
                self.assertEqual(self.store.connection.execute('SELECT count(*) FROM retry_queue').fetchone()[0], 0)

    def test_ssvc_malformed_top_container_on_rejected_record_is_dropped(self):
        for containers in ([{'untrusted': 'discard'}], 'discard'):
            value = fixtures.record()
            value['cveMetadata']['state'] = 'REJECTED'
            value['containers'] = containers
            self.assertEqual(validate.record(value), [])
            self.assertEqual(project_record(value), {'cveMetadata': value['cveMetadata']})
            self.ingest(value)
            self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(value))

    def test_ssvc_urgency_direct_state_exploitation_kev_reason_matrix(self):
        for state, exploitation, kev, reasons in product(
                ('unknown', 'not_affected', 'affected'), ('active', 'poc', 'none', None),
                (False, True), ([], ['new match'], ['KEV added'], ['correction'],
                                ['acceptance lapsed'], ['new match', 'correction'])):
            with self.subTest(state=state, exploitation=exploitation, kev=kev, reasons=reasons):
                body = {'state': state, 'kev': {'listed': True} if kev else None,
                        'epss': {'score': .001}}
                if exploitation is not None:
                    body['ssvc'] = {'Exploitation': exploitation}
                expected = bool(set(reasons) & {'new match', 'KEV added'}) and (
                    kev or (state == 'affected' and exploitation == 'active'))
                self.assertEqual(self.engine._urgent(body, reasons), expected)

    def test_ssvc_conflicting_points_use_severity_in_every_order(self):
        options = [{'Exploitation': 'active', 'Automatable': 'yes', 'Technical Impact': 'total'},
                   {'Exploitation': 'none', 'Automatable': 'no', 'Technical Impact': 'partial'},
                   {'Exploitation': 'poc', 'Automatable': 'invalid', 'Technical Impact': []}]
        for ordered in permutations(options):
            value = fixtures.record()
            content = value['containers']['adp'][0]['metrics'][0]['other']['content']
            content['options'] = list(ordered)
            projected = project_record(value)
            self.assertEqual(record_ssvc(value), fixtures.POINTS)
            self.assertEqual(record_ssvc(projected), fixtures.POINTS)
            points = projected['containers']['adp'][0]['metrics'][0]['other']['content']['options']
            self.assertEqual({k: v for option in points for k, v in option.items()}, fixtures.POINTS)
            self.assertEqual(project_record(projected), projected)

    def test_ssvc_invalid_snapshot_records_skipped_counted_and_untouched(self):
        old = fixtures.record(1002, {})
        self.store.put_record('CVE-2099-1002', old, 'original')
        invalid = fixtures.record(1002)
        invalid['containers']['cna']['affected'] = 'invalid'
        source = self.source((fixtures.record(), invalid, {}, None))
        source.poll(NOW)
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.assertEqual(int(self.store.get_meta('projection_skipped_records')), 3)
        self.assertEqual(self.engine._record('CVE-2099-1002'), project_record(old))
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('healthy', 'complete; 3 records skipped'))
        source._archive.reset_mock()
        source.poll(NOW)
        source._archive.assert_not_called()

    def test_ssvc_projection_commit_failure_rolls_back_and_retries_after_backoff(self):
        old = fixtures.record(1001, {})
        self.store.put_record('CVE-2099-1001', old, 'original')
        source = self.source((fixtures.record(),))
        original = self.store.connection
        self.store.connection = ReleaseFault(original)
        source.poll(NOW)
        self.assertFalse(original.in_transaction)
        self.assertIsNone(self.store.get_meta('applied_projection_revision'))
        self.assertIsNone(self.store.get_meta('projection_skipped_records'))
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(old))
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
        source._archive.reset_mock()
        source.poll(NOW + timedelta(hours=5))
        source._archive.assert_not_called()
        self.ingest(fixtures.record(1003))
        self.assertFalse(original.in_transaction)
        original.rollback()
        self.assertIsNotNone(self.engine._record('CVE-2099-1003'))
        source._backfill_projection(source._listing.return_value[0], NOW + timedelta(hours=6))
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.assertIsNone(self.store.get_meta('projection_next_attempt_at'))

    def test_ssvc_projection_runtime_write_failure_rolls_back_pass(self):
        old = fixtures.record(1001, {})
        self.store.put_record('CVE-2099-1001', old, 'original')
        self.store.connection.execute("""CREATE TRIGGER fail_runtime BEFORE INSERT ON meta
            WHEN NEW.k='projection_runtime_seconds'
            BEGIN SELECT RAISE(ABORT, 'injected'); END""")
        source = self.source((fixtures.record(),))
        source.poll(NOW)
        self.assertFalse(self.store.connection.in_transaction)
        self.assertIsNone(self.store.get_meta('applied_projection_revision'))
        self.assertIsNone(self.store.get_meta('projection_skipped_records'))
        self.assertEqual(self.engine._record('CVE-2099-1001'), project_record(old))
        self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
        self.assertEqual(self.store.get_meta('projection_next_attempt_at'),
                         (NOW + timedelta(hours=6)).isoformat())
        self.store.connection.execute('DROP TRIGGER fail_runtime')
        source._backfill_projection(source._listing.return_value[0], NOW + timedelta(hours=6))
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')

    def test_ssvc_projection_failure_backoff_persists_across_source_restart(self):
        for failure in ('download', 'failed', 'partial', 'iterator'):
            with self.subTest(failure=failure):
                self.store.connection.execute("DELETE FROM meta WHERE k IN ('projection_next_attempt_at','applied_projection_revision')")
                source = self.source(())
                if failure == 'download':
                    source._archive.side_effect = OSError('injected')
                elif failure == 'iterator':
                    def interrupted():
                        yield fixtures.record()
                        raise OSError('injected')
                    source._archive.return_value = IngestResult('cvelist', FetchStatus.COMPLETE,
                        Origin.SNAPSHOT, fixtures.TAG, NOW, interrupted())
                else:
                    source._archive.return_value = IngestResult('cvelist',
                        FetchStatus.FAILED if failure == 'failed' else FetchStatus.PARTIAL,
                        Origin.SNAPSHOT, None, NOW, ())
                source.poll(NOW)
                self.assertEqual(self.store.get_meta('projection_next_attempt_at'),
                                 (NOW + timedelta(hours=6)).isoformat())
                self.assertIsNone(self.store.get_meta('applied_projection_revision'))
                restarted = self.source((fixtures.record(),))
                restarted.poll(NOW)
                restarted._archive.assert_not_called()
                self.assertEqual(assess('projection', self.store, NOW, self.config), ('unhealthy', 'incomplete'))
                restarted._backfill_projection(restarted._listing.return_value[0], NOW + timedelta(hours=6))
                self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
                self.assertIsNone(self.store.get_meta('projection_next_attempt_at'))

    def test_ssvc_projection_retry_meta_malformed_and_future_cap(self):
        for stamp in ('invalid', '2099-04-05T12:00:00', '', '99999-01-01T00:00:00Z'):
            with self.subTest(stamp=stamp):
                self.store.connection.execute("DELETE FROM meta WHERE k='applied_projection_revision'")
                self.store.set_meta('projection_next_attempt_at', stamp)
                self.source(()).poll(NOW)
                self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')
        self.store.connection.execute("DELETE FROM meta WHERE k='applied_projection_revision'")
        self.store.set_meta('projection_next_attempt_at', '9999-01-01T00:00:00+00:00')
        source = self.source(())
        source.poll(NOW)
        source._archive.assert_not_called()
        deadline = (NOW + timedelta(hours=6)).isoformat()
        self.assertEqual(self.store.get_meta('projection_next_attempt_at'), deadline)
        source.poll(NOW + timedelta(hours=1))
        self.assertEqual(self.store.get_meta('projection_next_attempt_at'), deadline)
        source._backfill_projection(source._listing.return_value[0], NOW + timedelta(hours=6))
        self.assertEqual(self.store.get_meta('applied_projection_revision'), '2')

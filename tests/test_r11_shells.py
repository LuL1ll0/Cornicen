# script-purpose: Pin R11 owned quarantine shell migration and clearing behavior.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_r11_shells.py
"""Read invented records; write temporary SQLite and staged fixture containers.

Run PYTHONPATH=src python3 -m unittest tests.test_r11_shells.
Exit 0 on success, 1 on failure. All seven owned-shell assertions are active.
"""
import json
from pathlib import Path
import tempfile
import unittest

from cornicen.adapterstore import AdapterStore
from cornicen.advisory import write_evidence
from cornicen.feedvalidate import validate_advisory
from cornicen.store import Store
from tests.replay_r11.harness import PendingCase, raw_advisory
from tests.replay_v11.fixture_adapter import ValidationBackend
from tests.replay_v11.harness import fixture_registry

T = '2099-11-03T00:00:00Z'
A = 'CVE-2099-1200'
B = 'CVE-2099-1201'
WATCH = '[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.0.0"\nscheme="semver"\n'


def columns(db):
    return [r[1] for r in db.execute('PRAGMA table_info(advisory_shells)')]


def migration():
    with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as directory:
        path = Path(directory) / 'state.db'
        store = Store(path)
        try:
            store.migrate()
            db = store.connection
            db.execute('DROP TABLE advisory_shells')
            db.execute('CREATE TABLE advisory_shells(identity TEXT PRIMARY KEY)')
            db.execute('INSERT INTO advisory_shells VALUES (?)', (A,))
            store.migrate()
            observed = dict(columns=columns(db), reset=[tuple(r) for r in db.execute('SELECT * FROM advisory_shells')])
            if observed['columns'] == ['source', 'source_id', 'identity']:
                db.executemany('INSERT INTO advisory_shells VALUES (?,?,?)',
                    [('fixture_a','FIX-2099-0001',A), ('fixture_a','FIX-2099-0002',A)])
                store.connection.close()
                store = Store(path)
                store.migrate()
                observed['restarted'] = [tuple(r) for r in store.connection.execute(
                    'SELECT * FROM advisory_shells ORDER BY source,source_id,identity')]
                observed['primary_key'] = [r[5] for r in store.connection.execute('PRAGMA table_info(advisory_shells)')]
            return observed
        finally:
            store.connection.close()


def assert_migration(observed):
    expected = dict(columns=['source','source_id','identity'],reset=[],
        restarted=[('fixture_a','FIX-2099-0001',A),('fixture_a','FIX-2099-0002',A)],
        primary_key=[1,2,3])
    if observed != expected:
        raise AssertionError(f'one-column reset/persistence: observed {observed!r}; expected {expected!r}')


def clear_case(site, case):
    from unittest.mock import patch
    with patch.object(Path, 'cwd', return_value=Path(tempfile.gettempdir())):
        backend = ValidationBackend(fixture_registry())
    try:
        backend.action(dict(t=T,watchlist=WATCH))
        db = backend.store.connection
        persistence = AdapterStore(backend.store, backend.tmp.name,
            on_unknown=backend.engine.observe_unknown_advisory)
        raw = raw_advisory(A)
        raw['products'][0]['name'] = 'examplecorp:widget'
        def quarantine(record):
            invalid = json.loads(json.dumps(record))
            invalid['evidence'][0]['product_id'] = 'missing'
            status = persistence.process('fixture_a', [dict(path=record['id']+'.json',status=200,
                body=json.dumps([invalid]))], T)
            if status != 'PARTIAL':
                raise RuntimeError(f'quarantine setup unexpectedly {status}')
        quarantine(raw)
        if not db.execute('SELECT 1 FROM advisory_shells WHERE identity=?',(A,)).fetchone():
            raise RuntimeError('quarantine setup did not create a shell')
        if case == 'shared':
            quarantine(dict(raw,id='FIX-2099-0002'))
        accepted = json.loads(json.dumps(raw))
        if case == 'omitted':
            accepted['cves'] = [B]
        elif case == 'withdrawn':
            accepted['withdrawn'] = T
        if site == 'write_evidence':
            data = validate_advisory(accepted,source='fixture_a',observed_at=T).data
            with backend.store.transaction():
                write_evidence(db,data)
        elif site == 'commit_staged':
            # Deliberately bypass write_evidence: this acceptance path must clear
            # its own shells even with a callback which publishes no evidence.
            persistence.on_record = lambda data, baseline: None
            persistence.stage_members('fixture_a','accepted.json',iter([accepted]),T)
            status = persistence.commit_staged('fixture_a','accepted.json',T)
            if status != 'COMPLETE':
                raise RuntimeError(f'acceptance setup unexpectedly {status}')
        else:
            raise ValueError(site)
        return dict(marker_present=bool(db.execute(
            'SELECT 1 FROM advisory_shells WHERE identity=?',(A,)).fetchone()),
            markers=[dict(r) for r in db.execute('SELECT * FROM advisory_shells')],
            quarantine=[r[0] for r in db.execute('SELECT source_id FROM quarantine ORDER BY source_id')], site=site)
    finally:
        backend.close()


def assert_clear(observed, case):
    expected = case != 'omitted'
    if observed['marker_present'] != expected:
        explanation = dict(shared='accepting one record must keep the other owner\'s marker',
            omitted='acceptance must clear its own omitted identities',
            withdrawn='withdrawal must keep quarantine markers')[case]
        raise AssertionError(f'{explanation}: observed marker_present={observed["marker_present"]}; '
                             f'expected {expected}; rows={observed["markers"]!r}')
    if case == 'withdrawn':
        # write_evidence is only evidence publication; commit_staged owns the
        # quarantine acceptance row and removes it even on withdrawal.
        expected_quarantine = ['FIX-2099-0001'] if observed['site'] == 'write_evidence' else []
        if observed['quarantine'] != expected_quarantine:
            raise AssertionError(f"withdrawn quarantine: {observed['quarantine']!r}, expected {expected_quarantine!r}")
        expected_marker = [dict(source='fixture_a', source_id='FIX-2099-0001', identity=A)]
        if observed['markers'] != expected_marker:
            raise AssertionError(f"withdrawn ownership: {observed['markers']!r}")
    # Ownership is asserted in addition to visible identity membership.
    if case == 'shared':
        expected_rows = [dict(source='fixture_a',source_id='FIX-2099-0002',identity=A)]
        if observed['markers'] != expected_rows:
            raise AssertionError(f'owner isolation: observed {observed["markers"]!r}; expected {expected_rows!r}')


def load_tests(loader, tests, pattern):
    tests.addTest(PendingCase('r11.shell.migration_restart', migration, assert_migration, pending=False))
    for site in ('write_evidence','commit_staged'):
        for case in ('shared','omitted','withdrawn'):
            tests.addTest(PendingCase(f'r11.shell.{site}.{case}',
                lambda site=site,case=case: clear_case(site,case),
                lambda observed,case=case: assert_clear(observed,case), pending=False))
    return tests

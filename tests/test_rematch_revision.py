# script-purpose: Check matching revision startup, rollback, retry and notification behavior.
# script-class: harness
# script-trigger: Run by unittest discovery and make gate.
# script-tests: tests/test_rematch_revision.py
"""Read local sources; write temporary stores under the working directory and unittest output.

Run with python -m unittest tests.test_rematch_revision. Exit codes: 0 success,
1 failed tests, 2 invalid command arguments.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import applicability
from cornicen.applicability import Result, State
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.health import assess, container_healthy
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text


# SHA-256 of concatenated repo-relative UTF-8 file name + NUL + complete raw
# file bytes, in sorted file-name order. Nothing (including revision) is omitted.
SOURCES = ('src/cornicen/applicability.py', 'src/cornicen/identity.py',
           'src/cornicen/versions.py')
# Privacy diagnostics changed identity.py without changing matching behavior.
PINS = {1: '7b96e28f8dca2d28c29dc62c7b46a73aed55f27ba72cf31e0139eb7a0f926673'}
CVE = 'CVE-2099-10001'
CLEAR = Result(State.NOT_AFFECTED, False, 'CNA not affected', 'high')


class MatchingRevisionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.watches = load_watchlist_text('''[[watch]]
id="widget"
name="Example widget"
match=["examplevendor:examplewidget"]
version="3.4.1"
scheme="semver"
''')
        self.aliases = AliasMap.load(False)
        self.config = Config(':memory:', Path('unused'), None, '', 'test', None)
        self.clock = lambda: datetime(2099, 1, 1, tzinfo=timezone.utc)
        self.notifier = Mock()
        self.record = {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'},
                       'containers': {'cna': {'affected': []}}}

    def restart(self, watches=None):
        return Engine(self.store, self.watches if watches is None else watches,
                      self.aliases, self.config, self.clock, self.notifier)

    def seed(self, notified=True, watches=None):
        if watches:
            self.watches = watches
        with patch.object(applicability, 'MATCHING_REVISION', 1, create=True):
            self.restart()
        self.store.put_record(CVE, self.record, self.clock().isoformat())
        for watch in self.watches:
            self.db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                            (watch.id, CVE, 'unknown', 1, 0, 1, int(notified),
                             'Version unknown', 'high', self.aliases.version))
        self.store.set_meta('applied_matching_revision', '1')

    def bump(self, watches=None):
        with patch.object(applicability, 'MATCHING_REVISION', 2, create=True), \
                patch.object(applicability, 'resolve', return_value=CLEAR):
            return self.restart(watches)

    def count(self, table):
        return self.db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]

    def assert_revision(self, revision=2):
        self.assertEqual(self.store.get_meta('applied_matching_revision'), str(revision))

    def test_matching_revision_pin(self):
        message = 'matching sources changed: bump MATCHING_REVISION and add a new pin'
        self.assertEqual(max(PINS), applicability.MATCHING_REVISION, message)
        root = Path(__file__).resolve().parents[1]
        digest = sha256(b''.join(name.encode('utf-8') + b'\0' + (root / name).read_bytes()
                                 for name in sorted(SOURCES))).hexdigest()
        self.assertEqual(digest, PINS[applicability.MATCHING_REVISION], message)

    def test_rematch_on_revision_change(self):
        self.seed()
        self.bump()
        self.assertEqual(self.db.execute('SELECT state FROM pairs').fetchone()[0], 'not_affected')
        self.assert_revision()
        self.assertEqual(self.count('events'), 1)
        before = [tuple(row) for row in self.db.execute('SELECT * FROM pairs')]
        with patch.object(Engine, 'reload_watches') as reload:
            self.bump()
        reload.assert_not_called()
        self.assertEqual(before, [tuple(row) for row in self.db.execute('SELECT * FROM pairs')])
        self.assertEqual(self.count('outbox'), 1)

    def test_revision_rematch_notified_pair_sends_one_correction(self):
        self.seed()
        self.bump()
        self.assertEqual(self.count('events'), 1)
        row = self.db.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual(json.loads(row['reasons_json']), ['correction'])
        self.assertEqual(self.db.execute('SELECT key FROM events').fetchone()[0],
                         f'widget|{CVE}|correction|1')
        for _ in range(2):
            engine = self.bump()
            with patch.object(applicability, 'resolve', return_value=CLEAR):
                engine._rematch_record(self.record, CVE)
        self.assertEqual(self.count('events'), 1)
        self.assertEqual(self.count('outbox'), 1)

    def test_revision_rematch_unnotified_pair_clears_quietly(self):
        self.seed(notified=False)
        self.bump()
        self.assertEqual(self.db.execute('SELECT state FROM pairs').fetchone()[0], 'not_affected')
        self.assertEqual(self.count('events'), 0)
        self.assertEqual(self.count('outbox'), 0)

    def test_watch_edit_reload_clear_stays_silent(self):
        self.seed()
        with patch.object(applicability, 'MATCHING_REVISION', 1, create=True), \
                patch.object(applicability, 'resolve', return_value=CLEAR):
            self.restart((replace(self.watches[0], version='9.0.2'),))
        self.assertEqual(self.db.execute('SELECT state FROM pairs').fetchone()[0], 'not_affected')
        self.assertEqual(self.count('events'), 0)
        self.assertEqual(self.count('outbox'), 0)
        # Fresh stores must record the revision even before any watches change.
        self.db.execute('DELETE FROM pairs')
        self.db.execute('DELETE FROM records')
        self.db.execute("DELETE FROM meta WHERE k IN ('applied_watches','applied_matching_revision')")
        with patch.object(applicability, 'MATCHING_REVISION', 1, create=True):
            self.restart()
        self.assert_revision(1)

    def test_first_upgrade_missing_meta(self):
        self.seed()
        self.db.execute("DELETE FROM meta WHERE k='applied_matching_revision'")
        with patch.object(Engine, '_rematch_record', autospec=True,
                          side_effect=Engine._rematch_record) as rematch:
            self.bump()
            self.assertEqual(rematch.call_count, 1)
            self.bump()
            self.assertEqual(rematch.call_count, 1)
        self.assert_revision()

    def test_fresh_db_no_rematch(self):
        with patch.object(Engine, 'reload_watches') as reload:
            self.bump()
        reload.assert_not_called()
        self.assert_revision()

    def test_rematch_interrupted_retries(self):
        class Interrupted(BaseException):
            pass
        self.seed()
        self.db.execute("DELETE FROM meta WHERE k='applied_matching_revision'")
        original = Engine._rematch_record
        def interrupt(engine, *args, **kwargs):
            original(engine, *args, **kwargs)
            raise Interrupted()
        with patch.object(Engine, '_rematch_record', interrupt):
            with self.assertRaises(Interrupted):
                self.bump()
        self.assertIsNone(self.store.get_meta('applied_matching_revision'))
        self.assertEqual(self.count('events'), 0)
        self.assertEqual(self.db.execute('SELECT state FROM pairs').fetchone()[0], 'unknown')
        self.bump()
        self.assert_revision()
        self.assertEqual(self.count('events'), 1)

    def test_rematch_record_failure_retries_all_watches(self):
        self.seed(watches=(self.watches[0], replace(self.watches[0], id='second')))
        with patch.object(applicability, 'MATCHING_REVISION', 2, create=True), \
                patch.object(applicability, 'resolve', side_effect=ValueError('matching failed')):
            self.restart()
        self.assertEqual(self.count('retry_queue'), 1)
        self.assertEqual(self.db.execute('SELECT source FROM retry_queue').fetchone()[0], 'watchlist')
        self.assert_revision()
        # Retry on a new engine to prove the notification policy is durable.
        with patch.object(applicability, 'MATCHING_REVISION', 2, create=True):
            engine = self.restart()
        with patch.object(applicability, 'resolve', return_value=CLEAR) as resolve:
            engine.run_cycle([])
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM events WHERE type='correction'").fetchone()[0], 2)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM outbox WHERE pair_key LIKE '%|correction'").fetchone()[0], 2)
        # A subsequent watchlist retry must preserve the queued corrections.
        with patch.object(applicability, 'resolve', return_value=CLEAR):
            engine._rematch_record(self.record, CVE)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM outbox WHERE pair_key LIKE '%|correction'").fetchone()[0], 2)

    def test_single_rematch_when_watch_and_revision_change(self):
        self.seed()
        with patch.object(Engine, '_rematch_record', autospec=True,
                          side_effect=Engine._rematch_record) as rematch:
            self.bump((replace(self.watches[0], version='9.0.2'),))
        self.assertEqual(rematch.call_count, 1)
        self.assertEqual(self.count('events'), 1)
        self.assert_revision()

    def test_force_all_rematches_unchanged_watches(self):
        self.seed(watches=(self.watches[0], replace(self.watches[0], id='second')))
        with patch.object(applicability, 'MATCHING_REVISION', 2, create=True), \
                patch.object(applicability, 'resolve', return_value=CLEAR) as resolve:
            engine = self.restart()
            self.assertEqual(resolve.call_count, 2)
            # force_all must also work with an initialized identity cache.
            resolve.reset_mock()
            engine.reload_watches(self.watches, force_all=True)
            self.assertEqual(resolve.call_count, 2)

    def test_force_all_passes_all_watches_to_rematch(self):
        self.seed(watches=(self.watches[0], replace(self.watches[0], id='second')))
        with patch.object(applicability, 'MATCHING_REVISION', 1):
            engine = self.restart()
        # Check the explicit selection before the durable retry policy overrides it.
        with patch.object(engine, '_rematch_record', wraps=engine._rematch_record) as rematch:
            engine.reload_watches(self.watches, force_all=True)
        rematch.assert_called_once_with(self.record, CVE, watches=self.watches,
                                        revision_corrections=True)

    def revision_fixture(self, dead=False):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / 'state.db')
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.connection.close())
        self.store.migrate()
        self.db = self.store.connection
        self.now = datetime(2099, 1, 1, tzinfo=timezone.utc)
        self.clock = lambda: self.now
        self.config = replace(self.config, db_path=self.path)
        self.record['containers']['cna']['affected'] = [{
            'vendor': 'examplevendor', 'product': 'examplewidget',
            'defaultStatus': 'unaffected',
            'versions': [{'version': '3.4.1', 'status': 'affected'}]}]
        self.seed(watches=(self.watches[0], replace(self.watches[0], id='second')))
        self.db.execute("UPDATE pairs SET state='affected',exploited=0")
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('kev_initialized', '1')
        for source in ('cvelist', 'kev', 'epss'):
            self.db.execute('INSERT INTO cursors VALUES (?,?,?)',
                            (source, None, self.now.isoformat()))
        self.sent = []
        self.notifier.send.side_effect = lambda item: self.sent.append(item) or True
        with patch.object(applicability, 'MATCHING_REVISION', 2), \
                patch.object(applicability, 'resolve', side_effect=ValueError('fixture failure')):
            self.engine = self.restart()
            if dead:
                for _ in range(4):
                    self.engine.run_cycle([])
        self.assertEqual(self.store.get_meta('matching_revision_retry:' + CVE), '1')
        if dead:
            self.assertEqual(self.count('dead_letters'), 1)
            self.assertEqual(self.db.execute('SELECT attempts FROM dead_letters').fetchone()[0], 5)

    def reopen_revision_fixture(self):
        self.store.connection.close()
        self.store = Store(self.path)
        self.store.migrate()
        self.db = self.store.connection
        with patch.object(applicability, 'MATCHING_REVISION', 2):
            self.engine = self.restart()

    def ingest_revision_fixture(self):
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                           None, self.now, records=(self.record,))])

    def check_ingest_completion_health_recovery(self, dead=False):
        self.revision_fixture(dead=dead)
        table = 'dead_letters' if dead else 'retry_queue'
        if not dead:
            # Keep the queued retry scheduled beyond the successful ingest cycle.
            self.db.execute('UPDATE retry_queue SET next_attempt_at=? WHERE source=? AND record_id=?',
                            ((self.now + timedelta(minutes=1)).isoformat(), 'watchlist', CVE))
        pending = tuple(self.db.execute(
            f'SELECT * FROM {table} WHERE source=? AND record_id=?', ('watchlist', CVE)).fetchone())
        due = self.db.execute(
            f'SELECT next_attempt_at FROM {table} WHERE source=? AND record_id=?',
            ('watchlist', CVE)).fetchone()[0]
        self.assertEqual(assess('watchlist', self.store, self.now, self.config)[0], 'unhealthy')
        self.ingest_revision_fixture()
        self.assertIsNone(self.store.get_meta('matching_revision_retry:' + CVE))
        kept = self.db.execute(
            f'SELECT * FROM {table} WHERE source=? AND record_id=?', ('watchlist', CVE)).fetchone()
        self.assertIsNotNone(kept, 'successful ingestion must retain scheduled watchlist work')
        self.assertEqual(tuple(kept), pending)
        if dead:
            self.reopen_revision_fixture()
        with patch.object(self.engine, '_rematch_record', wraps=self.engine._rematch_record) as rematch:
            self.engine.run_cycle([])
        rematch.assert_not_called()
        self.assertEqual(assess('watchlist', self.store, self.now, self.config)[0], 'unhealthy')
        self.assertFalse(container_healthy(self.store, self.now, self.config))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM events WHERE record_id='watchlist' AND type='healthy'").fetchone()[0], 0)
        self.now = datetime.fromisoformat(due) + timedelta(seconds=1)
        # Keep source coverage fresh while advancing to the dead letter's next day.
        self.db.execute('UPDATE cursors SET content_time=?', (self.now.isoformat(),))
        events_before = [tuple(row) for row in self.db.execute(
            'SELECT * FROM events WHERE record_id=?', (CVE,))]
        outbox_before = [tuple(row) for row in self.db.execute(
            "SELECT * FROM outbox WHERE urgency!='health'")]
        self.sent.clear()
        with patch.object(self.engine, '_rematch_record', wraps=self.engine._rematch_record) as rematch:
            self.engine.run_cycle([])
        rematch.assert_called_once()
        self.assertEqual(self.count(table), 0)
        self.assertEqual(assess('watchlist', self.store, self.now, self.config)[0], 'healthy')
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM events WHERE record_id='watchlist' AND type='healthy'").fetchone()[0], 1)
        self.assertTrue(container_healthy(self.store, self.now, self.config))
        self.assertEqual([tuple(row) for row in self.db.execute(
            'SELECT * FROM events WHERE record_id=?', (CVE,))], events_before)
        self.assertEqual([tuple(row) for row in self.db.execute(
            "SELECT * FROM outbox WHERE urgency!='health'")], outbox_before)
        self.assertFalse([item for notification in self.sent
                          for item in notification.body.get('items', [])])

    def test_ingest_completion_keeps_watchlist_retry_so_health_recovers(self):
        self.check_ingest_completion_health_recovery()

    def test_ingest_completion_keeps_dead_letter_so_health_recovers(self):
        self.check_ingest_completion_health_recovery(dead=True)

    def test_meta_write_failure_rolls_back_entire_revision(self):
        self.seed(watches=(self.watches[0], replace(self.watches[0], id='second')))
        before = {table: [tuple(row) for row in self.db.execute(f'SELECT * FROM {table}')]
                  for table in ('meta', 'pairs', 'events', 'outbox', 'retry_queue', 'dead_letters')}
        original = self.store.set_meta
        def fail_meta(key, value):
            if key == 'applied_matching_revision':
                raise RuntimeError('fixture metadata write failure')
            return original(key, value)
        with patch.object(self.store, 'set_meta', side_effect=fail_meta):
            with self.assertRaisesRegex(RuntimeError, 'metadata write failure'):
                self.bump()
        for table, rows in before.items():
            self.assertEqual([tuple(row) for row in self.db.execute(f'SELECT * FROM {table}')], rows,
                             table)

    def test_pending_revision_partial_reload_still_covers_all_watches(self):
        self.revision_fixture()
        edited = (replace(self.watches[0], name='Edited example widget'), self.watches[1])
        with patch.object(applicability, 'resolve', return_value=CLEAR) as resolve:
            self.engine.reload_watches(edited)
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type='correction'").fetchone()[0], 2)
        self.assertIsNone(self.store.get_meta('matching_revision_retry:' + CVE))
        self.assertEqual(self.count('retry_queue'), 0)

    def test_dead_letter_retains_policy_until_actual_retry(self):
        self.revision_fixture(dead=True)
        self.reopen_revision_fixture()
        with patch.object(applicability, 'resolve') as resolve:
            self.engine.run_cycle([])
        resolve.assert_not_called()
        self.assertEqual(self.store.get_meta('matching_revision_retry:' + CVE), '1')
        self.assertEqual(self.count('dead_letters'), 1)
        self.now += timedelta(days=1, seconds=1)
        with patch.object(applicability, 'resolve', return_value=CLEAR) as resolve:
            self.engine.run_cycle([])
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type='correction'").fetchone()[0], 2)
        self.assertIsNone(self.store.get_meta('matching_revision_retry:' + CVE))
        self.assertEqual(self.count('dead_letters'), 0)

    def test_cvelist_success_retires_revision_marker(self):
        self.revision_fixture(dead=True)
        # A failed ingest must leave the policy durable too.
        with patch.object(applicability, 'resolve', side_effect=[CLEAR, ValueError('fixture failure')]):
            self.ingest_revision_fixture()
        self.assertEqual(self.store.get_meta('matching_revision_retry:' + CVE), '1')
        self.assertEqual(self.db.execute("SELECT count(*) FROM pairs WHERE state='affected'").fetchone()[0], 2)
        self.ingest_revision_fixture()
        self.assertIsNone(self.store.get_meta('matching_revision_retry:' + CVE))
        self.assertEqual(self.count('dead_letters'), 1)
        self.assertEqual(self.count('retry_queue'), 0)

    def test_cvelist_then_partial_edit_does_not_force_unchanged_watch(self):
        self.revision_fixture(dead=True)
        self.ingest_revision_fixture()
        edited = (replace(self.watches[0], name='Edited example widget'), self.watches[1])
        with patch.object(applicability, 'resolve', wraps=applicability.resolve) as resolve:
            self.engine.reload_watches(edited)
        self.assertEqual(resolve.call_count, 1)

    def test_cvelist_then_watch_edit_clear_stays_silent(self):
        self.revision_fixture(dead=True)
        self.ingest_revision_fixture()
        self.reopen_revision_fixture()
        edited = (replace(self.watches[0], version='9.0.2'), self.watches[1])
        self.engine.reload_watches(edited)
        self.now += timedelta(days=1, minutes=1)
        self.engine.run_cycle([])
        items = [item for notification in self.sent for item in notification.body.get('items', [])]
        self.assertEqual(sum(tuple(item['reasons']) == ('correction',) for item in items), 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type='correction'").fetchone()[0], 0)

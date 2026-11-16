# script-purpose: Interrupt replay transaction boundaries and reopen durable stores.
# script-class: harness
# script-trigger: tests/test_f4.py through the foundation harness.
# script-tests: tests/test_f4.py, tests/replay_v11/test-crash-replay.py, tests/replay_v11/test-msrc-crash-classification.py, tests/test_task1_a.py, tests/test_task1_b2.py, tests/test_task2_b2.py, tests/test_task3_b2.py, tests/test_task4_b2.py
"""Read foundation timelines; write temporary SQLite stores and staging files.

Library helper for unittest (exit 0 success, 1 failure). No production hooks.
Injection before/after savepoints rolls back open work; acknowledgements inject
only after commit, excluding the external send-before-ack at-least-once window.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import json
import sys
from unittest.mock import patch

from cornicen.store import Store
from cornicen.adapterstore import AdapterStore, instant, stamp
from tests.replay_v11.fixture_adapter import ValidationBackend


class Crash(BaseException):
    """Process loss must escape ordinary record/transport exception handling."""


@dataclass
class CrashRun:
    result: object
    durable: dict
    points: list
    crashed: bool
    accounting: dict = None
    interrupted_accounting: list = None
    deliveries: list = None


def run(name, crash_index=None):
    from tests.replay_v11 import harness as h
    from tests.replay_v11.github_backend import GitHubBackend, is_github
    from cornicen.sources.github_advisories import GitHubState
    from tests.replay_v11.msrc_backend import backend_for, is_msrc, is_cisco
    from tests.replay_v11.osv_backend import DebianBackend
    debian = name.startswith('debian_')
    reference = run(name) if debian and crash_index is not None else None
    cisco = is_cisco(name)
    CsafBackend = backend_for(name)
    msrc = is_msrc(name)
    github = is_github(name)
    points, durable = [], {}
    accounting, journal, accounting_writes, interrupted_accounting = {}, [], [], []
    deliveries = []
    active = False
    crashed = False
    transaction, queue = Store.transaction, Store.queue
    retry = AdapterStore.retry
    failures = {}
    witnessed = {}

    def record_retry(adapter, source, resource, tick, error, **kwargs):
        # Use the production backoff (including its actual jitter and headers),
        # recording the failure clock before any final-dump mutation can occur.
        old = adapter.db.execute(
            'SELECT attempts FROM adapter_retries WHERE source=? AND resource=?',
            (source, resource)).fetchone()
        attempts = (old[0] if old else 0) + 1
        wait = retry(adapter, source, resource, tick, error, **kwargs)
        key = source, resource
        if not debian:
            witnessed[key] = witnessed.get(key, 0) + 1
            failures[adapter.directory, source, resource] = (
                attempts, stamp(instant(tick) + timedelta(seconds=wait)), tick)
        return wait

    def hit(kind, site, side):
        nonlocal crashed
        if not active or kind == 'state':
            return
        point = f'{kind}:{site}:{side}'
        index = len(points)
        points.append(point)
        if index == crash_index and not crashed:
            crashed = True
            raise Crash(point)

    @contextmanager
    def boundary(store):
        frame = sys._getframe(2)  # contextlib.__enter__ -> transaction caller
        file, function, line = Path(frame.f_code.co_filename).name, frame.f_code.co_name, frame.f_lineno
        site = f'{file}/{function}/{line}'
        kind = ('ack' if file == 'outbox.py' and function == 'deliver' else
                'alias' if file == 'advisoryidentity.py' else
                'record' if function in ('commit_advisory', 'commit_staged', '_isolated', 'observe_unknown_advisory')
                else (('cisco_' if cisco else 'msrc_') + function if (msrc or cisco) and (file in ('msrc_csaf.py', 'cisco_csaf.py', 'csaf_directory.py') or function in ('stage_members','_accept_batch','_finish_index','rebaseline','_acknowledge_rebaseline')) else 'github_' + function if github and file == 'github_advisories.py' and function != 'set_hold' else 'state'))
        if debian and (file == 'osv_debian.py' or file == 'adapterstore.py'):
            kind = 'debian_' + function
        if kind != 'ack':
            hit(kind, site, 'before')
        with transaction(store) as db:
            yield db
        if debian and file == 'adapterstore.py' and function == 'retry':
            values = frame.f_locals
            adapter, source, resource = values['self'], values['source'], values['resource']
            row = adapter.db.execute('SELECT attempts,next_attempt_at FROM adapter_retries WHERE source=? AND resource=?', (source, resource)).fetchone()
            key = source, resource
            witnessed[key] = witnessed.get(key, 0) + 1
            failures[adapter.directory, source, resource] = (row['attempts'], row['next_attempt_at'], values['tick'])
        if github and file == 'github_advisories.py':
            values = frame.f_locals
            if function == 'charge':
                tick = values['tick']
                journal[:] = [t for t in journal if (instant(tick)-instant(t)).total_seconds() < 3600]
                journal.append(tick)
                if values['first']:
                    accounting_writes.append((values['repository'], 'first', tick))
            elif function == 'check_detail':
                accounting_writes.append((values['repository'], 'detail', (values['identity'], values['tick'])))
            elif function == 'set_pages':
                accounting_writes.append((values['repository'], 'pages', values['expected_pages']))
        hit(kind, site, 'after')

    def enqueue(store, *args, **kwargs):
        frame = sys._getframe(1)
        site = f'{Path(frame.f_code.co_filename).name}/{frame.f_code.co_name}/{frame.f_lineno}'
        hit('enqueue', site, 'before')
        result = queue(store, *args, **kwargs)
        hit('enqueue', site, 'after')
        return result

    class Backend(DebianBackend if debian else CsafBackend if (msrc or cisco) else GitHubBackend if github else ValidationBackend):
        def __init__(self, registry):
            super().__init__(registry)
            if github:
                journal.clear()
            self.interrupted_retries = {}
            self.inert_crossings = set()
            self.closed = False

        def start_engine(self):
            super().start_engine()
            self.remember_inert_crossings()

        def remember_inert_crossings(self):
            # Remember the pair episode at initialization: identity linking can
            # subsequently retire that pair while leaving its inert row behind.
            for row in self.store.connection.execute(
                    'SELECT * FROM epss_crossings WHERE fired IS NULL AND crossing=0'):
                pair = self.store.connection.execute(
                    'SELECT episode FROM pairs WHERE watch_id=? AND record_id=?',
                    (row['watch_id'], row['record_id'])).fetchone()
                score = self.store.connection.execute(
                    'SELECT score FROM epss_crossing_scores WHERE cve=?',
                    (row['record_id'],)).fetchone()
                if (pair is not None and row['episode'] == pair['episode']
                        and (score is None or score['score'] is None)
                        and row['threshold'] == self.engine.config.epss_threshold
                        and row['rearm_ratio'] == self.engine.config.epss_rearm_ratio):
                    self.inert_crossings.add(tuple(row))

        def retry_counts(self):
            return {(r['source'], r['resource']): r['attempts'] for r in
                    self.store.connection.execute('SELECT * FROM adapter_retries')}

        def action(self, row):
            nonlocal active
            active = 'cycle' in row or 'command' in row
            pending, ingests = deepcopy(self.pending), list(self.ingests)
            before = self.retry_counts()
            accounting_before = len(accounting_writes)
            witnessed.clear()
            try:
                super().action(row)
            except Crash:
                active = False
                interrupted_accounting.extend(accounting_writes[accounting_before:])
                # Only retry increments that survived the interrupted action's
                # rollback can explain a higher count after replaying that action.
                for key, count in self.retry_counts().items():
                    extra = count - before.get(key, 0)
                    assert 0 <= extra <= witnessed.get(key, 0), 'unwitnessed retry increment'
                    self.interrupted_retries[key] = self.interrupted_retries.get(key, 0) + extra
                # Exception unwinding rolls back every open savepoint. Reopen the
                # same file, recreate the engine, then retry interrupted inputs.
                self.store.connection.close()
                self.store = Store(self.path)
                self.store.migrate()
                self.start_engine()
                self.pending, self.ingests = pending, ingests
                super().action(row)
            finally:
                active = False
                if self.engine is not None:
                    self.remember_inert_crossings()

        def close(self):
            if self.closed:
                return
            self.closed = True
            try:
                self.remember_inert_crossings()
                self.compare_dump(h.dump_database(self.store.connection)['tables'])
            finally:
                super().close()

        def compare_dump(self, dump):
            # Compare all durable tables, including future adapter additions.
            for row in dump['staged_containers']['rows']:
                columns = dump['staged_containers']['columns']
                path = Path(row[columns.index('path')])
                assert path.is_file(), f'missing staged file: {path}'
                # The digest stays in the projection, so equality checks the
                # actual bytes against the uninterrupted corresponding resource.
                checksum = sha256(path.read_bytes()).hexdigest()
                assert checksum == row[columns.index('digest')], 'staged content digest'
                row[columns.index('path')] = checksum
            if github:
                state = GitHubState(self.store)
                assert state.meta('requests', []) == journal, 'unwitnessed GitHub charge'
                schedule = state.meta('schedule', {})
                for repository, checks in state.meta('detail_checks', {}).items():
                    schedule[repository]['detail_checks'] = checks
                accounting[len(accounting)] = schedule
                meta = dump['meta']
                column = meta['columns'].index('k')
                meta['rows'] = [r for r in meta['rows'] if r[column] not in ('github:requests', 'github:schedule', 'github:detail_checks')]
            retries = dump['adapter_retries']
            for row in retries['rows']:
                values = dict(zip(retries['columns'], row))
                key = values['source'], values['resource']
                assert values['attempts'] > 0, 'retry attempts must be positive'
                attempts, deadline, tick = failures[self.persistence.directory, *key]
                assert type(values['attempts']) is int and values['attempts'] == attempts
                assert values['next_attempt_at'] == deadline, 'retry backoff deadline'
                assert instant(tick) <= self.clock(), 'failure beyond harness clock'
                count = attempts - self.interrupted_retries.get(key, 0)
                if debian and reference is not None:
                    expected = reference.durable[len(durable)]['adapter_retries']
                    expected_counts = {(r[expected['columns'].index('source')],
                                        r[expected['columns'].index('resource')]):
                                       r[expected['columns'].index('attempts')] for r in expected['rows']}
                    # Same-tick resume can retain only the committed failure; require its exact uninterrupted count.
                    if count == 0:
                        count = attempts
                    assert count == expected_counts[key], 'retry count differs from uninterrupted run'
                assert count > 0, 'retry count must be positive'
                row[retries['columns'].index('attempts')] = count
                row[retries['columns'].index('next_attempt_at')] = tick
            # Only the complete unevaluated initialization shape is inert.
            crossings = dump['epss_crossings']
            crossings['rows'] = [row for row in crossings['rows']
                                 if tuple(row) not in self.inert_crossings]
            durable[len(durable)] = dump

    from tests.replay.harness import RecordingNotifier
    send = RecordingNotifier.send
    def record_send(notifier, notification):
        accepted = send(notifier, notification)
        if accepted and notification.watch_id:
            deliveries.append((notification.watch_id, notification.record_id,
                               tuple(notification.reasons), notification.body.get('episode', 1)))
        return accepted

    # A killed process does not execute Python cleanup handlers. In particular,
    # stage_members must not unlink an already durable stage while the injected
    # BaseException unwinds; resume needs precisely those committed bytes.
    unlink = Path.unlink
    def process_unlink(path, *args, **kwargs):
        if debian and active and isinstance(sys.exc_info()[1], Crash):
            return None
        return unlink(path, *args, **kwargs)

    previous = h.register_backend(Backend)
    try:
        with patch.object(Path, 'unlink', process_unlink), patch.object(Store, 'transaction', boundary), patch.object(Store, 'queue', enqueue), \
                patch.object(AdapterStore, 'retry', record_retry), \
                patch.object(RecordingNotifier, 'send', record_send):
            result = h.run_scenario(name)
    finally:
        h.register_backend(previous)
    return CrashRun(result, durable, points, crashed, accounting, interrupted_accounting, deliveries)

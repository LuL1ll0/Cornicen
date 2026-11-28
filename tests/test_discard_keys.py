# script-purpose: Verify that discarded release notices release only their own event keys.
# script-class: harness
# script-trigger: Unittest discovery and make gate.
# script-tests: tests/test_discard_keys.py
"""Read invented release responses and feed records, with no network access.

Write temporary watch files and in-memory SQLite. Unittest exits 0 if all
contracts hold and 1 on test failure.
"""
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from cornicen.accept import Accept
from cornicen.config import Config, SecretToken
from cornicen.engine import Engine
from cornicen.feedvalidate import validate_advisory
from cornicen.fetch import Http
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.outbox import deliver
from cornicen.releases import ReleaseChecker
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier
from tests.source_helpers import Opener, public_resolver
from tests.test_f3a import advisory
from tests.test_latest_releases import WATCH
from tests.test_stored_event_keys import version_one


REPO = 'github:example-org/widget'
OTHER_REPO = 'github:example-org/widget-b'
TAG, NEWER = 'v4.3.0', 'v4.4.0'
CVE = 'CVE-2099-99701'
RELEASE, MATCH, LAPSE, CROSSING, CORRECTION = (
    'release_behind', 'new match', 'acceptance lapsed', 'epss_crossed', 'correction')


def url(repo):
    return 'https://api.github.com/repos/' + repo.split(':', 1)[1] + '/releases/latest'


def reply(tag):
    return json.dumps(dict(tag_name=tag, draft=False, prerelease=False)).encode()


def release_id(repository, tag):
    return 'release:' + sha256((repository.lower() + '\0' + tag).encode()).hexdigest()


class Capture(RecordingNotifier):
    def __init__(self, clock):
        super().__init__(clock)
        self.items = []
        self.reject_releases = False

    def send(self, notification):
        if self.reject_releases and RELEASE in notification.reasons:
            return False
        if not super().send(notification):
            return False
        self.items.extend(notification.body.get('items', []))
        return True


class EmptySource:
    def poll(self, now):
        return []


class DiscardKeysTests(unittest.TestCase):
    def setUp(self):
        self.init_rig()

    def init_rig(self):
        directory = TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.path = root / 'watch.toml'
        self.store = Store(':memory:')
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.store.migrate()
        self.clock = FakeClock(datetime(2099, 6, 7, 7, tzinfo=timezone.utc))
        self.notifier = Capture(self.clock)
        self.opener = Opener({url(REPO): reply(TAG), url(OTHER_REPO): reply(TAG)})
        self.http = Http('fixture', {}, self.opener, resolver=public_resolver,
                         data_dir=root, github_token=SecretToken('invented-token'))
        self.checker = ReleaseChecker(CveListSource(self.http, self.store))
        self.config = Config(':memory:', self.path, None, 'https://notify.example.invalid', 'fixture', None)
        self.watch = self.write_watch()[0]
        self.engine = Engine(self.store, (self.watch,), AliasMap(), self.config, self.clock,
                             self.notifier, release_checker=self.checker)
        self.store.set_meta('baseline_complete', '1')
        # Keep an unrelated, genuinely delivered key in every ledger.
        self.engine._health('records', 'unhealthy', 'Invented historical event')
        self.engine._flush()

    def write_watch(self, repo=REPO, version='4.2.0'):
        text = WATCH.replace('version = "4.2.0"', f'version = "{version}"')
        if repo:
            text += f'latest_release = "{repo}"\nrelease_tag_prefix = "v"\n'
        self.path.write_text(text)
        return load_watchlist_text(text)

    def ledger(self):
        return {row[0]: tuple(row) for row in self.db.execute('SELECT * FROM events')}

    def snapshot(self):
        return (self.ledger(), tuple(map(tuple, self.db.execute('SELECT * FROM outbox ORDER BY id'))),
                tuple(map(tuple, self.db.execute(
                    'SELECT * FROM outbox_event_keys ORDER BY outbox_id,reason,key,legacy'))))

    def pending(self, record=CVE, *, watch=None, correction=False):
        pair = f'{watch or self.watch.id}|{record}' + ('|correction' if correction else '')
        return self.db.execute('SELECT * FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                               (pair,)).fetchone()

    def release_row(self, tag=TAG, *, watch=None):
        return self.pending(release_id(REPO, tag), watch=watch)

    def queue_release(self):
        self.checker.check(self.engine)
        row = self.release_row()
        self.assertIsNotNone(row)
        self.assertEqual(list(map(tuple, self.store.event_ownership(row['id']))),
                         [(RELEASE, self.key(RELEASE, record=release_id(REPO, TAG)), 0)])
        return row

    def key(self, kind, episode=1, *, record=CVE):
        return f'{self.watch.id}|{record}|{kind}|{episode}'

    def own(self, row):
        return row['pair_key'] + f'|{RELEASE}|1'

    def assert_discard(self, before, own, after):
        self.assertIn(own, before)
        self.assertEqual({k: v for k, v in after.items() if k != own},
                         {k: v for k, v in before.items() if k != own})
        self.assertNotIn(own, after)

    def assert_gone(self, row):
        self.assertIsNone(self.db.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone())
        self.assertEqual(self.store.event_ownership(row['id']), [])

    def refresh(self, row):
        with self.store.transaction():
            return self.engine._refresh_pending(row['id'])

    def flush_at_due(self, row, tick=None):
        self.assertIsNotNone(row, 'No pending notice to deliver')
        self.clock.now = max(self.clock(), datetime.fromisoformat(row['due_at']))
        (tick or self.engine._flush)()

    def release_sends(self):
        return [(item['watch_id'], item['body']['tag']) for item in self.notifier.items
                if RELEASE in item['reasons']]

    def record_sends(self, record=CVE):
        return [n['reasons'] for n in self.notifier.delivered if n['record'] == record]

    def rearm_release(self):
        self.engine.reload_watches((self.watch,))
        self.checker.check(self.engine)
        self.flush_at_due(self.release_row())
        self.checker.check(self.engine)
        self.engine._flush()
        self.assertIsNone(self.release_row())

    def exercise_settings(self, **changes):
        row = self.queue_release()
        own = self.own(row)
        before = self.ledger()
        self.engine.reload_watches((replace(self.watch, **changes),))
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.release_sends(), [])
        with self.subTest(phase='discard'):
            self.assert_discard(before, own, self.ledger())
        self.rearm_release()
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(set(self.ledger()), set(before))

    def test_01_caught_up_then_behind(self):
        self.exercise_settings(version='4.3.0')

    def test_02_release_settings_restored(self):
        for change in (dict(latest_release=None), dict(latest_release=OTHER_REPO),
                       dict(scheme=Scheme.OPAQUE)):
            with self.subTest(change=change):
                self.init_rig()
                self.exercise_settings(**change)

    def scheduler(self):
        sources = {name: EmptySource() for name in ('cvelist', 'kev', 'epss')}
        return Scheduler(self.engine, sources, self.clock, lambda line: None,
                         monotonic=lambda: self.clock().timestamp())

    def complete_worker(self, scheduler):
        worker = scheduler.release_worker
        self.assertIsNotNone(worker)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(scheduler.release_outcome, [True])

    def start_scheduler(self, *, version='4.2.0'):
        self.engine.reload_watches(self.write_watch(version=version))
        scheduler = self.scheduler()
        scheduler.tick()
        self.complete_worker(scheduler)
        scheduler.tick()
        return scheduler

    def swap_during_fetch(self, scheduler):
        entered, proceed = Event(), Event()
        opener = self.opener

        def block(request, timeout=None):
            if request.full_url == url(OTHER_REPO):
                entered.set()
                if not proceed.wait(5):
                    raise TimeoutError('Invented worker never released')
            return opener.open(request, timeout=timeout)

        def unblock():
            proceed.set()
            if scheduler.release_worker is not None:
                scheduler.release_worker.join(3)

        self.addCleanup(unblock)
        self.http.opener = block
        row = self.release_row()
        self.assertIsNotNone(row)
        before = self.ledger()
        self.write_watch(OTHER_REPO)
        scheduler.tick()
        self.assertTrue(entered.wait(2))
        self.assert_gone(row)
        with self.subTest(phase='discard'):
            self.assert_discard(before, self.own(row), self.ledger())
        self.write_watch()
        scheduler.tick()
        self.assertTrue(scheduler.release_worker.is_alive())
        self.assertIsNone(self.release_row())
        self.assertEqual(self.release_sends(), [])
        return proceed

    def requests(self):
        return [r.full_url for r in self.opener.requests]

    def test_02_scheduler_uses_fresh_cache_after_obsolete_fetch(self):
        scheduler = self.start_scheduler()
        signature = self.checker.applied
        proceed = self.swap_during_fetch(scheduler)
        self.assertEqual(self.checker.signature(self.engine), signature)
        proceed.set()
        self.complete_worker(scheduler)
        scheduler.tick()
        self.assertIsNone(scheduler.release_worker)
        self.assertEqual(self.requests(), [url(REPO), url(OTHER_REPO)])
        row = self.release_row()
        self.assertIsNotNone(row)
        self.assertIn(self.own(row), self.ledger())
        self.assertEqual(self.release_sends(), [])
        digest = self.clock().replace(hour=8)
        self.assertEqual(row['due_at'], digest.isoformat())
        self.clock.now = digest
        scheduler.tick()
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        scheduler.tick()
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(self.requests(), [url(REPO), url(OTHER_REPO)])

    def test_02_scheduler_cache_expires_during_obsolete_fetch(self):
        for refreshed in (TAG, NEWER):
            with self.subTest(refreshed=refreshed):
                self.init_rig()
                scheduler = self.start_scheduler(version='4.3.0')
                expires = self.clock() + timedelta(days=1)
                self.clock.now = expires - timedelta(seconds=3)
                self.write_watch()
                scheduler.tick()
                self.clock.now += timedelta(seconds=1)
                proceed = self.swap_during_fetch(scheduler)
                self.assertLess(self.clock(), expires)
                self.clock.now = expires
                scheduler.tick()
                self.assertTrue(scheduler.release_worker.is_alive())
                self.assertIsNone(self.release_row())
                self.opener.routes[url(REPO)] = reply(refreshed)
                proceed.set()
                self.complete_worker(scheduler)
                scheduler.tick()
                self.complete_worker(scheduler)
                scheduler.tick()
                if refreshed == NEWER:
                    self.assertIsNone(self.release_row(TAG))
                self.assertEqual(self.requests(), [url(REPO), url(OTHER_REPO), url(REPO)])
                row = self.release_row(refreshed)
                self.assertIsNotNone(row)
                self.assertIn(self.own(row), self.ledger())
                self.assertEqual(self.release_sends(), [])
                digest = expires.replace(hour=8)
                self.assertEqual(row['due_at'], digest.isoformat())
                self.clock.now = digest
                scheduler.tick()
                self.assertEqual(self.release_sends(), [(self.watch.id, refreshed)])
                scheduler.tick()
                self.assertEqual(self.release_sends(), [(self.watch.id, refreshed)])
                self.assertEqual(self.requests(), [url(REPO), url(OTHER_REPO), url(REPO)])

    def test_02_scheduler_cached_failure_flaps_health_without_fetch(self):
        scheduler = self.start_scheduler()
        self.notifier.reject_releases = True
        self.clock.now += timedelta(days=1)
        self.opener.routes[url(REPO)] = TimeoutError('Invented release fetch failure')
        scheduler.tick()
        self.complete_worker(scheduler)
        scheduler.tick()
        self.assertEqual(self.record_sends('releases'), [])
        proceed = self.swap_during_fetch(scheduler)
        self.assertEqual(self.record_sends('releases'), [['unhealthy']])
        proceed.set()
        self.complete_worker(scheduler)
        scheduler.tick()
        scheduler.tick()
        self.assertEqual(self.record_sends('releases'), [['unhealthy'], ['healthy'], ['unhealthy']])
        self.assertEqual(self.release_sends(), [])
        self.assertEqual(self.requests(), [url(REPO), url(REPO), url(OTHER_REPO)])

    def test_02a_advisory_release_flag_is_not_ownership(self):
        self.queue_release()
        self.advisory()
        row = self.pending()
        self.assertEqual(list(map(tuple, self.store.event_ownership(row['id']))),
                         [(MATCH, self.key(MATCH), 0)])
        self.edit_body(row, release_behind=True, repository=OTHER_REPO, tag=TAG)
        before, signature = self.ledger(), self.checker.applied
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.ledger(), before)
        self.assertEqual(self.checker.applied, signature)
        self.advisory()
        self.assertIsNone(self.pending())
        self.flush_at_due(self.release_row())
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(self.record_sends(), [])
        self.assertEqual(self.ledger(), before)

    def test_03_remove_and_readd_watch(self):
        row = self.queue_release()
        before = self.ledger()
        self.engine.reload_watches(())
        self.assert_gone(row)
        self.assert_discard(before, self.own(row), self.ledger())
        self.rearm_release()
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])

    def test_04_stale_release_dry_pass_changes_nothing(self):
        self.start_scheduler()
        row = self.release_row()
        self.assertIsNotNone(row)
        self.assertEqual(list(map(tuple, self.store.event_ownership(row['id']))),
                         [(RELEASE, self.key(RELEASE, record=release_id(REPO, TAG)), 0)])
        self.engine.reload_watches((replace(self.watch, version='4.3.0'),))
        before, signature = self.snapshot(), self.checker.applied
        self.assertIsNotNone(signature)
        self.assertIsNone(self.engine._revalidate(row, persist=False))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.checker.applied, signature)
        self.assertEqual(self.release_sends(), [])
        self.engine.reload_watches((self.watch,))
        self.flush_at_due(self.release_row())
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(self.ledger(), before[0])

    def test_05_key_deleted_first_and_both_deletes_roll_back(self):
        row = self.queue_release()
        self.engine.reload_watches((replace(self.watch, version='4.3.0'),))
        before = self.snapshot()
        seen = []
        self.db.create_function('observe_deletion', 1, seen.append)
        self.db.execute('''CREATE TEMP TRIGGER fail_discard BEFORE DELETE ON outbox
            WHEN OLD.id = %d BEGIN
                SELECT observe_deletion(count(*)) FROM events
                    WHERE key = OLD.pair_key || '|release_behind|1';
                SELECT RAISE(ABORT, 'invented outbox delete failure');
            END''' % row['id'])
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'invented outbox delete failure'):
                self.refresh(row)
        finally:
            self.db.execute('DROP TRIGGER fail_discard')
            self.db.create_function('observe_deletion', 1, None)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.release_sends(), [])
        self.engine.reload_watches((self.watch,))
        self.flush_at_due(self.release_row())
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(self.ledger(), before[0])
        self.assertEqual(seen, [0], 'The key must already be gone at the outbox delete')

    def edit_body(self, row, **changes):
        body = json.loads(row['body_json']) | changes
        self.db.execute('UPDATE outbox SET body_json=? WHERE id=?', (json.dumps(body), row['id']))

    def migrate_legacy_release(self):
        version_one(self.store)
        record = release_id(REPO, TAG)
        pair = f'{self.watch.id}|{record}'
        body = dict(watch_id=self.watch.id, record_id=record, release_behind=True,
                    repository=REPO, tag=TAG, version=self.watch.version)
        stamp = self.clock().isoformat()
        # The two v0.10.1 writes, before ownership was recorded at queue time.
        with self.store.transaction():
            self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                            (self.key(RELEASE, record=record), self.watch.id, record, RELEASE, 1, stamp))
            self.db.execute('INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at,enqueued_at) '
                            'VALUES (?,?,?,?,?,?)',
                            (pair, 'normal', json.dumps([RELEASE]), json.dumps(body),
                             self.engine._digest(), stamp))
        self.store.migrate()
        row = self.release_row()
        self.assertEqual(list(map(tuple, self.store.event_ownership(row['id']))), [(RELEASE, '', 1)])
        return row

    def test_06_legacy_rebuild_accepts_repository_case_change(self):
        for repository in (REPO, REPO.upper()):
            with self.subTest(repository=repository):
                self.init_rig()
                row = self.migrate_legacy_release()
                self.edit_body(row, repository=repository)
                before = self.ledger()
                self.engine.reload_watches((replace(self.watch, latest_release=REPO.title(), version='4.3.0'),))
                self.assertIsNone(self.refresh(row))
                self.assert_gone(row)
                with self.subTest(phase='discard'):
                    self.assert_discard(before, self.own(row), self.ledger())
                self.assertEqual(self.release_sends(), [])
                self.rearm_release()
                self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])

    def test_06_legacy_rebuild_rejects_inconsistent_fields(self):
        for field, changed in (('tag', NEWER), ('record_id', release_id(REPO, NEWER)),
                               ('reasons', [RELEASE, MATCH]), ('repository', ''),
                               ('ownership', (MATCH, '', 1))):
            with self.subTest(field=field):
                self.init_rig()
                row = self.migrate_legacy_release()
                if field == 'reasons':
                    self.db.execute('UPDATE outbox SET reasons_json=? WHERE id=?',
                                    (json.dumps(changed), row['id']))
                elif field == 'ownership':
                    self.store.union(row['id'], [changed])
                else:
                    self.edit_body(row, **{field: changed})
                self.engine.reload_watches((replace(self.watch, latest_release=None),))
                before = self.ledger()
                self.assertIsNone(self.refresh(row))
                self.assert_gone(row)
                self.assertEqual(self.ledger(), before)
                self.engine.reload_watches((self.watch,))
                self.checker.check(self.engine)
                self.assertIsNone(self.release_row())
                self.assertEqual(self.release_sends(), [])
                self.opener.routes[url(REPO)] = reply(NEWER)
                self.clock.now += timedelta(days=1)
                self.checker.check(self.engine)
                self.flush_at_due(self.release_row(NEWER))
                self.assertEqual(self.release_sends(), [(self.watch.id, NEWER)])

    def test_06_legacy_body_cannot_claim_second_watchs_key(self):
        for delivered in (False, True):
            with self.subTest(already_delivered=delivered):
                self.init_rig()
                row = self.migrate_legacy_release()
                other = replace(self.watch, id='widget-two')
                self.engine.reload_watches((self.watch, other))
                self.queue_other_release(other)
                other_row = self.release_row(watch=other.id)
                self.assertIsNotNone(other_row)
                if delivered:
                    # Keep the legacy row pending while the second notice is sent.
                    self.db.execute('UPDATE outbox SET due_at=? WHERE id=?',
                                    ((self.clock() + timedelta(hours=3)).isoformat(), row['id']))
                    self.flush_at_due(other_row)
                self.edit_body(row, watch_id=other.id)
                self.engine.reload_watches((self.watch, replace(other, latest_release=None)))
                before = self.ledger()
                self.assertIn(self.own(other_row), before)
                self.assertIsNone(self.refresh(row))
                self.assert_gone(row)
                with self.subTest(phase='discard'):
                    self.assertEqual(self.ledger(), before)
                self.engine.reload_watches((self.watch, other))
                self.checker.check(self.engine)
                if not delivered:
                    self.flush_at_due(self.release_row(watch=other.id))
                self.assertEqual(self.release_sends(), [(other.id, TAG)])
                self.assertIsNone(self.release_row())
                self.assertIsNone(self.release_row(watch=other.id))

    def queue_other_release(self, other):
        self.checker.check(self.engine)
        other_row = self.release_row(watch=other.id)
        self.assertIsNotNone(other_row)
        self.assertEqual(list(map(tuple, self.store.event_ownership(other_row['id']))),
                         [(RELEASE, self.own(other_row), 0)])

    def test_07_unrelated_keys_unchanged_own_key_gone(self):
        row = self.queue_release()
        other = replace(self.watch, id='widget-two')
        self.engine.reload_watches((self.watch, other))
        self.queue_other_release(other)
        self.engine.reload_watches((replace(self.watch, latest_release=None), other))
        before, own = self.ledger(), self.own(row)
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        after = self.ledger()
        self.flush_at_due(self.release_row(watch=other.id))
        self.assertEqual(self.release_sends(), [(other.id, TAG)])
        self.assertEqual(after, self.ledger())
        with self.subTest(phase='unrelated-key guard'):
            self.assertEqual({k: v for k, v in before.items() if k != own},
                             {k: v for k, v in after.items() if k != own})
        with self.subTest(phase='own key'):
            self.assertNotIn(own, after)

    def advisory(self, status='known_affected'):
        raw = advisory(status, cves=(CVE,))
        raw['evidence'][0]['range'] = dict(introduced='4.0.0', limit='5.0.0')
        result = validate_advisory(raw, source='fixture_a', observed_at=self.clock().isoformat())
        self.assertIsNotNone(result.data)
        self.engine.commit_advisory(result.data)

    def cna(self, state='affected'):
        record = dict(cveMetadata=dict(cveId=CVE, state='PUBLISHED'), containers=dict(cna=dict(
            affected=[dict(vendor='examplecorp', product='widget',
                           versions=[dict(version='4.2.0', status=state)])])))
        with self.store.transaction():
            self.store.put_record(CVE, record, self.clock().isoformat())
            self.engine._evaluate(record, CVE)

    def cycle(self, *ingests):
        self.engine.run_cycle(ingests, release_checks=False)

    def scores(self, value):
        self.cycle(IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
                               self.clock().date().isoformat(), self.clock(), epss={CVE: (value, .91)},
                               epss_date=self.clock().date()))

    def test_08_notified_advisory_lapse_stays_suppressed(self):
        self.advisory()
        self.flush_at_due(self.pending())
        self.engine.accepts = (Accept(CVE, self.watch.id, 'Invented decision',
                                      date(2099, 6, 6), False, None, 1),)
        self.cycle()
        row = self.pending()
        before = self.ledger()
        self.assertIn(self.key(LAPSE), before)
        self.advisory('under_investigation')
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.ledger(), before)
        self.advisory()
        self.clock.now += timedelta(days=1)
        self.cycle()
        self.assertEqual(self.ledger(), before)
        self.assertIsNone(self.pending())
        self.assertEqual(self.record_sends(), [[MATCH]])

    def test_08_epss_drop_and_strip_keep_crossing_history(self):
        for strip in (False, True):
            with self.subTest(strip=strip):
                self.init_rig()
                self.scores(.02)
                self.cna()
                self.flush_at_due(self.pending())
                self.notifier.down = True
                self.scores(.2)
                if strip:
                    with self.store.transaction():
                        self.engine._event(self.watch.id, CVE, LAPSE, 1,
                                           dict(watch_id=self.watch.id, record_id=CVE, episode=1))
                row = self.pending()
                before = self.ledger()
                first_crossing = self.key(CROSSING) + '|1'
                self.assertIn(first_crossing, before)
                self.engine.config = replace(self.config, epss_crossing=False)
                kept = self.refresh(row)
                self.assertEqual(self.ledger(), before)
                if strip:
                    self.assertEqual(json.loads(kept['reasons_json']), [LAPSE])
                    self.assertEqual(list(map(tuple, self.store.event_ownership(row['id']))),
                                     [(LAPSE, self.key(LAPSE), 0)])
                else:
                    self.assertIsNone(kept)
                    self.assert_gone(row)
                self.engine.config = self.config
                self.notifier.down = False
                if strip:
                    # Honour the failed urgent send's backoff as well as the digest due time.
                    self.clock.now = datetime.fromisoformat(kept['next_attempt_at'])
                    self.flush_at_due(kept)
                self.scores(.2)
                expected = [[MATCH], [LAPSE]] if strip else [[MATCH]]
                self.assertEqual(self.record_sends(), expected)
                self.scores(.01)
                self.scores(.2)
                second = self.key(CROSSING) + '|2'
                self.assertEqual(self.ledger(), before | {
                    second: (second, self.watch.id, CVE, CROSSING, 1, self.clock().isoformat())})
                self.assertEqual(self.record_sends(), expected + [[CROSSING]])

    def test_08_invalid_v1_correction_preserves_key(self):
        self.cna()
        self.flush_at_due(self.pending())
        self.cna('unaffected')
        row = self.pending(correction=True)
        pair = self.db.execute('SELECT * FROM pairs WHERE record_id=?', (CVE,)).fetchone()
        before = self.ledger()
        self.assertIn(self.key(CORRECTION), before)
        self.db.execute('DELETE FROM pairs WHERE record_id=?', (CVE,))
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.ledger(), before)
        self.db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)', tuple(pair))
        self.cna()
        self.flush_at_due(self.pending())
        self.cna('unaffected')
        self.flush_at_due(self.pending(correction=True))
        self.assertEqual(self.record_sends(), [[MATCH], [MATCH], [CORRECTION]])
        self.assertEqual(set(self.ledger()) - set(before), {self.key(MATCH, 2), self.key(CORRECTION, 2)})

    def test_08_health_drop_keeps_key_and_later_transition_delivers(self):
        self.engine._health('releases', 'unhealthy', 'Invented failure')
        row = self.db.execute("SELECT * FROM outbox WHERE pair_key='|releases|health|1'").fetchone()
        self.db.execute('UPDATE outbox SET pair_key=? WHERE id=?', ('invalid-health', row['id']))
        self.edit_body(row, record_id=CVE)
        before = self.ledger()
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.ledger(), before)
        self.engine._health('releases', 'unhealthy', 'Same episode')
        self.engine._flush()
        self.assertEqual(self.record_sends('releases'), [])
        self.engine._health('releases', 'healthy', 'Invented recovery')
        self.engine._flush()
        self.assertEqual(self.record_sends('releases'), [['healthy']])
        self.assertEqual(self.ledger(), before | {
            '|releases|healthy|2': ('|releases|healthy|2', '', 'releases', 'healthy',
                                    2, self.clock().isoformat())})

    def test_08_invalid_advisory_correction_still_cancels_unnotified_match(self):
        self.advisory()
        self.flush_at_due(self.pending())
        self.advisory('known_not_affected')
        correction = self.pending(correction=True)
        self.advisory()
        active = self.pending()
        before = self.ledger()
        self.assertIn(self.key(CORRECTION), before)
        self.assertIsNone(self.refresh(correction))
        self.assert_gone(correction)
        self.assert_gone(active)
        self.assert_discard(before, self.key(MATCH, 2), self.ledger())
        self.cycle()
        self.assertIsNone(self.pending())
        self.advisory()
        self.flush_at_due(self.pending())
        self.advisory('known_not_affected')
        self.flush_at_due(self.pending(correction=True))
        self.assertEqual(self.record_sends(), [[MATCH], [MATCH], [CORRECTION]])

    def test_08_closing_advisory_correction_still_lost_after_investigation(self):
        self.advisory()
        self.flush_at_due(self.pending())
        self.advisory('known_not_affected')
        row = self.pending(correction=True)
        self.advisory('under_investigation')
        before = self.ledger()
        self.assertIn(self.key(CORRECTION), before)
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        self.assertEqual(self.ledger(), before)
        self.advisory('known_not_affected')
        self.engine._flush()
        self.assertIsNone(self.pending(correction=True))
        self.assertEqual(self.record_sends(), [[MATCH]])
        self.assertEqual(self.ledger(), before)

    def test_09_accepted_send_with_unrecorded_commit_can_repeat_once(self):
        row = self.queue_release()
        self.clock.now = datetime.fromisoformat(row['due_at'])
        before_ack = self.snapshot()
        self.db.set_authorizer(lambda action, verb, *_:
                               sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_SAVEPOINT and verb == 'RELEASE'
                               else sqlite3.SQLITE_OK)
        try:
            with self.assertRaisesRegex(sqlite3.DatabaseError, 'not authorized'):
                deliver(self.store, self.notifier, self.clock, [row],
                        revalidate=self.engine._delivery_rows)
        finally:
            self.db.set_authorizer(None)
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)])
        self.assertEqual(self.snapshot(), before_ack)
        self.engine.reload_watches((replace(self.watch, latest_release=None),))
        self.assertIsNone(self.refresh(row))
        self.assert_gone(row)
        with self.subTest(phase='discard'):
            self.assert_discard(before_ack[0], self.own(row), self.ledger())
        self.rearm_release()
        self.assertEqual(self.release_sends(), [(self.watch.id, TAG)] * 2)

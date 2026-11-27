# script-purpose: Verify pending event ownership and schema migration with invented alerts.
# script-class: harness
# script-trigger: Unittest discovery and make gate.
# script-tests: tests/test_stored_event_keys.py
"""Read invented feed and advisory data; write memory or temporary SQLite databases.

Unittest exits 0 on success and 1 on failure.
"""
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cornicen import advisoryidentity
from cornicen.adapters import Adapter, REGISTRY
from cornicen.adapterstore import AdapterStore
from cornicen.cli import main, outbox_list
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.outbox import deliver
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch
from tests.replay.harness import FakeClock, RecordingNotifier


CVE = 'CVE-2099-97001'
PROVISIONAL = 'advisory:fixture_a:FIX-2099-97001:main'
WATCH = Watch(*('spindle', 'Quartz Spindle', (('velvetforge', 'quartz-spindle'),), (),
                '1.0.0', Scheme.SEMVER, False))
T = '2099-06-01T07:00:00+00:00'
CROSSING = 'epss_crossed'
MATCH = 'new match'
LAPSE = 'acceptance lapsed'
CORRECTION = 'correction'


def key(reason, episode, identity=CVE, suffix=''):
    return f'{WATCH.id}|{identity}|{reason}|{episode}{suffix}'


def version_one(store):
    """Build the v0.10.1 schema from the common columns, before seeding any rows."""
    db = store.connection
    db.execute('DROP TABLE IF EXISTS outbox_event_keys')
    db.execute("DELETE FROM meta WHERE k='outbox_event_keys_version'")


class StoredEventKeysTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.store.migrate()
        self.clock = FakeClock(datetime.fromisoformat(T))
        self.notifier = RecordingNotifier(self.clock)
        config = Config(':memory:', Path('unused'), None, 'https://velvetforge.invalid',
                        'fixture', None)
        self.engine = Engine(self.store, (WATCH,), AliasMap(), config, self.clock, self.notifier)
        self.store.set_meta('baseline_complete', '1')
        self.store.set_meta('kev_initialized', '1')

    def pair(self, identity=CVE, episode=1, notified=0, state='affected'):
        self.db.execute('INSERT OR REPLACE INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (WATCH.id, identity, state, episode, 0, 0, notified,
                         'invented match', 'high', self.engine.aliases.version))

    def record(self):
        return dict(cveMetadata=dict(cveId=CVE, state='PUBLISHED'),
                    containers=dict(cna=dict(affected=[dict(vendor='velvetforge',
                        product='quartz-spindle', versions=[dict(version='1.0.0', status='affected')])])))

    def event(self, reason, episode, identity=CVE, *, body_episode=None, sent=False, **options):
        with self.store.transaction():
            self.engine._event(WATCH.id, identity, reason, episode,
                dict(watch_id=WATCH.id, record_id=identity, state='affected',
                     episode=episode if body_episode is None else body_episode), **options)
        if sent:
            row = self.pending(identity, correction=reason == CORRECTION)
            self.assertEqual(deliver(self.store, self.notifier, self.clock, [row]), 1)

    def pending(self, identity=CVE, *, correction=False):
        pair_key = f'{WATCH.id}|{identity}' + ('|correction' if correction else '')
        return self.db.execute('SELECT * FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                               (pair_key,)).fetchone()

    def ownership(self, row):
        return self.db.execute('SELECT reason,key,legacy FROM outbox_event_keys WHERE outbox_id=?',
                               (row['id'],)).fetchall()

    def assert_ownership(self, ownership, *entries):
        self.assertEqual({(reason, key) for reason, key, legacy in ownership if not legacy}, set(entries))

    def assert_legacy(self, ownership, *reasons):
        self.assertEqual({reason for reason, _, legacy in ownership if legacy}, set(reasons))

    def ledger(self):
        return {row['key'] for row in self.db.execute('SELECT key FROM events')}

    def link(self):
        advisoryidentity.link(self.engine, PROVISIONAL, CVE, T)

    def readd_and_deliver(self, ledger, episode):
        self.assertEqual(self.ledger(), ledger)
        self.store.put_record(CVE, self.record(), T)
        self.engine.reload_watches((WATCH,))
        before = len(self.notifier.delivered)
        self.clock.now += timedelta(days=1)
        self.engine._flush()
        self.assertEqual([(n['watch'], n['record'], n['reasons'])
                          for n in self.notifier.delivered[before:]], [(WATCH.id, CVE, [MATCH])])
        self.assertEqual(self.ledger(), ledger | {key(MATCH, episode)})

    def test_provisional_correction_keeps_two_delivered_corrections(self):
        self.event(CORRECTION, 1, sent=True)
        self.event(CORRECTION, 2, sent=True)
        self.pair(PROVISIONAL, 3)
        self.pair(episode=3)
        self.event(CORRECTION, 2, PROVISIONAL)
        sent = {key(CORRECTION, 1), key(CORRECTION, 2)}
        queued = key(CORRECTION, 2, PROVISIONAL)
        self.link()
        self.assertEqual(self.ledger(), sent | {queued})
        self.engine.reload_watches(())
        self.readd_and_deliver(sent, 3)

    def test_body_episode_overlap_does_not_delete_delivered_key(self):
        self.event(MATCH, 4, sent=True)
        self.pair(episode=4, notified=1)
        self.event(MATCH, 3, body_episode=4)
        self.assertEqual(self.ledger(), {key(MATCH, 3), key(MATCH, 4)})
        self.engine.reload_watches(())
        self.readd_and_deliver({key(MATCH, 4)}, 5)

    def test_coalesced_epss_crossings_are_both_deleted(self):
        with patch.object(self.engine, '_finish_health'):
            self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                                None, self.clock(), records=[self.record()])])
            self.clock.now += timedelta(hours=2)
            self.engine._flush()
            self.assertEqual([n['reasons'] for n in self.notifier.delivered], [[MATCH]])
            self.notifier.down = True
            for score in (.02, .2, .01, .2):
                self.engine.run_cycle([IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
                    None, self.clock(), epss={CVE: (score, .91)}, epss_date=self.clock().date())])
        first, second = (key(CROSSING, 1, suffix=f'|{occurrence}') for occurrence in (1, 2))
        history = {key(MATCH, 1)}
        self.assertEqual(self.ledger(), history | {first, second})
        row = self.pending()
        self.assertEqual(json.loads(row['reasons_json']), [CROSSING])
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), history)
        self.assert_ownership(ownership, (CROSSING, first), (CROSSING, second))
        self.notifier.down = False
        self.readd_and_deliver(history, 2)
        self.assertEqual(self.db.execute('SELECT * FROM outbox_event_keys').fetchall(), [])

    def test_link_detaches_queued_epss_when_other_reason_survives(self):
        self.event(CROSSING, 1, occurrence=1, sent=True)
        self.pair()
        self.pair(PROVISIONAL)
        self.event(CROSSING, 1, PROVISIONAL, occurrence=2)
        self.event('KEV added', 1, PROVISIONAL)
        history = {key(CROSSING, 1, suffix='|1'), key(CROSSING, 1, PROVISIONAL, '|2')}
        transferred = key('KEV added', 1, PROVISIONAL)
        self.link()
        row = self.pending()
        self.assertEqual(json.loads(row['reasons_json']), ['KEV added'])
        self.assertEqual(self.ledger(), history | {transferred})
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), history)
        self.assert_ownership(ownership, ('KEV added', transferred))
        self.readd_and_deliver(history, 2)

    def revalidate_without_crossings(self):
        self.store.put_record(CVE, self.record(), T)
        self.pair()
        self.event(MATCH, 1)
        self.event(CROSSING, 1, occurrence=1)
        crossing = key(CROSSING, 1, suffix='|1')
        row = self.pending()
        self.assertEqual(json.loads(row['reasons_json']), [MATCH, CROSSING])
        self.assert_ownership(self.ownership(row), (MATCH, key(MATCH, 1)), (CROSSING, crossing))
        self.engine.config = replace(self.engine.config, epss_crossing=False)
        with self.store.transaction():
            row = self.engine._revalidate(row)
        self.assertEqual(json.loads(row['reasons_json']), [MATCH])
        self.assertEqual(self.ledger(), {key(MATCH, 1), crossing})
        return crossing, self.ownership(row)

    def test_revalidation_detaches_crossing_before_watch_removal(self):
        crossing, ownership = self.revalidate_without_crossings()
        self.engine.reload_watches(())
        self.readd_and_deliver({crossing}, 2)
        self.assert_ownership(ownership, (MATCH, key(MATCH, 1)))

    def test_revalidation_detaches_crossing_before_link_and_watch_removal(self):
        crossing, ownership = self.revalidate_without_crossings()
        self.pair(PROVISIONAL)
        self.link()
        self.assert_ownership(self.ownership(self.pending()), (MATCH, key(MATCH, 1)))
        self.engine.reload_watches(())
        self.readd_and_deliver({crossing}, 2)
        self.assert_ownership(ownership, (MATCH, key(MATCH, 1)))

    def test_revalidation_detaches_crossing_before_activation_cancellation(self):
        crossing, ownership = self.revalidate_without_crossings()
        with self.store.transaction():
            self.engine._drop_activation(WATCH.id, CVE)
        self.assertIsNone(self.pending())
        self.assertEqual(self.ledger(), {crossing})
        self.assert_ownership(ownership, (MATCH, key(MATCH, 1)))

    def test_resolution_key_is_deleted_exactly(self):
        self.event(CORRECTION, 1, sent=True)
        self.pair(episode=2)
        self.event(CORRECTION, 2, resolution=True)
        row = self.pending(correction=True)
        history = {key(CORRECTION, 1)}
        resolution = key(CORRECTION, 2, suffix='|resolution')
        self.assertEqual(self.ledger(), history | {resolution})
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), history)
        self.assert_ownership(ownership, (CORRECTION, resolution))
        self.readd_and_deliver(history, 2)

    def test_link_unions_correction_keys_without_touching_sent_history(self):
        self.event(CORRECTION, 1, sent=True)
        self.pair(episode=3)
        self.pair(PROVISIONAL, 4)
        self.event(CORRECTION, 2)
        self.event(CORRECTION, 3, PROVISIONAL)
        history = {key(CORRECTION, 1)}
        queued = {key(CORRECTION, 2), key(CORRECTION, 3, PROVISIONAL)}
        self.link()
        row = self.pending(correction=True)
        self.assertEqual(json.loads(row['reasons_json']), [CORRECTION])
        self.assertEqual(self.ledger(), history | queued)
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), history)
        self.assert_ownership(ownership, *((CORRECTION, value) for value in queued))
        self.readd_and_deliver(history, 2)

    def test_link_leaves_covered_key_as_history(self):
        self.event(MATCH, 2, sent=True)
        self.pair(episode=2, notified=1)
        self.pair(PROVISIONAL)
        self.event(MATCH, 1, PROVISIONAL)
        self.event('KEV added', 1)
        self.event('KEV added', 1, PROVISIONAL)
        history = {key(MATCH, 2), key(MATCH, 1, PROVISIONAL)}
        surviving = {key('KEV added', 1), key('KEV added', 1, PROVISIONAL)}
        self.link()
        row = self.pending()
        self.assertEqual(json.loads(row['reasons_json']), ['KEV added'])
        self.assertEqual(self.ledger(), history | surviving)
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), history)
        self.assert_ownership(ownership, *(('KEV added', value) for value in surviving))
        self.readd_and_deliver(history, 3)

    def test_activation_cancellation_only_deletes_owned_keys(self):
        self.event(MATCH, 4, sent=True)
        self.pair(episode=4, notified=1)
        self.event(MATCH, 3, body_episode=4)
        self.event(CROSSING, 3, occurrence=2, body_episode=4)
        self.event(CORRECTION, 2)
        self.assertEqual(self.ledger(), {key(MATCH, 4), key(MATCH, 3),
                                        key(CROSSING, 3, suffix='|2'), key(CORRECTION, 2)})
        with self.store.transaction():
            self.engine._drop_activation(WATCH.id, CVE)
        self.assertEqual(self.engine.watches, (WATCH,))
        self.assertIsNone(self.pending())
        self.assertIsNotNone(self.pending(correction=True))
        history = {key(MATCH, 4)}
        self.assertEqual(self.ledger(), history | {key(CORRECTION, 2)})
        self.engine.reload_watches(())
        self.readd_and_deliver(history, 5)

    def lapse_row(self, existing):
        self.store.put_record(CVE, self.record(), T)
        self.pair()
        if existing:
            self.event(LAPSE, 1, sent=True)
        self.event(MATCH, 1)
        held = json.dumps(dict(held=True, reason='scheduled replacement',
                               until='2099-06-02', version='1.0.0'))
        self.db.execute("UPDATE outbox SET body_json=json_set(body_json,'$.accepted',json(?)) "
                        'WHERE id=?', (held, self.pending()['id']))
        with self.store.transaction():
            return self.engine._revalidate(self.pending())

    def test_lapse_revalidation_attaches_new_key(self):
        row = self.lapse_row(existing=False)
        self.assertEqual(self.ledger(), {key(MATCH, 1), key(LAPSE, 1)})
        # An identity link can change the episode in the body after revalidation.
        self.db.execute("UPDATE outbox SET body_json=json_set(body_json,'$.episode',2) WHERE id=?",
                        (row['id'],))
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), set())
        self.assert_ownership(ownership, (MATCH, key(MATCH, 1)), (LAPSE, key(LAPSE, 1)))
        self.readd_and_deliver(set(), 1)

    def test_lapse_revalidation_does_not_claim_delivered_key(self):
        row = self.lapse_row(existing=True)
        self.assertEqual(self.ledger(), {key(MATCH, 1), key(LAPSE, 1)})
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), {key(LAPSE, 1)})
        self.assert_ownership(ownership, (MATCH, key(MATCH, 1)))
        self.readd_and_deliver({key(LAPSE, 1)}, 2)

    def test_event_ignore_does_not_claim_delivered_key(self):
        self.event(MATCH, 1, sent=True)
        self.event('KEV added', 1)
        self.event(MATCH, 1)
        row = self.pending()
        history = {key(MATCH, 1)}
        self.assertEqual(self.ledger(), history | {key('KEV added', 1)})
        self.assertEqual(json.loads(row['reasons_json']), ['KEV added'])
        self.engine.reload_watches(())
        self.readd_and_deliver(history, 2)

    def legacy_row(self, identity=CVE, reason=CORRECTION):
        version_one(self.store)
        episode = 2 if reason == CORRECTION else 1
        self.pair(identity, episode)
        # The two relevant v0.10.1 inserts, with no inferred ownership.
        self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                        (key(reason, 1, identity), WATCH.id, identity, reason, 1, T))
        body = dict(watch_id=WATCH.id, record_id=identity, episode=episode)
        pair_key = f'{WATCH.id}|{identity}' + ('|correction' if reason == CORRECTION else '')
        self.db.execute('INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at,enqueued_at) '
                        'VALUES (?,?,?,?,?,?)', (pair_key, 'normal', json.dumps([reason]), json.dumps(body), T, T))
        self.store.migrate()

    def test_legacy_only_keeps_version_one_cleanup_behavior(self):
        self.legacy_row()
        self.assertEqual(self.ledger(), {key(CORRECTION, 1)})
        self.engine.reload_watches(())
        self.readd_and_deliver(set(), 1)

    def merge_legacy(self, identity):
        self.legacy_row(identity, MATCH)
        self.event(MATCH, 2, identity, body_episode=1)
        self.event('KEV added', 2, identity, body_episode=1)
        old = key(MATCH, 1, identity)
        exact = {key(MATCH, 2, identity), key('KEV added', 2, identity)}
        self.assertEqual(self.ledger(), {old} | exact)
        return old, exact, self.pending(identity)

    def test_legacy_merge_same_and_different_reason(self):
        _, _, row = self.merge_legacy(CVE)
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        self.assertEqual(self.ledger(), set())
        self.assert_legacy(ownership, MATCH)
        self.assert_ownership(ownership, (MATCH, key(MATCH, 2)), ('KEV added', key('KEV added', 2)))
        self.readd_and_deliver(set(), 1)

    def test_legacy_merge_same_and_different_reason_then_link(self):
        old, exact, before = self.merge_legacy(PROVISIONAL)
        prior_ownership = self.ownership(before)
        self.link()
        row = self.pending()
        self.assertEqual(self.ledger(), {old} | exact)
        ownership = self.ownership(row)
        self.engine.reload_watches(())
        # V1 would reconstruct a canonical episode-1 key from the linked body.
        # That guess has no match, so the original provisional legacy key stays.
        self.assertEqual(self.ledger(), {old})
        self.assert_legacy(prior_ownership, MATCH)
        self.assert_legacy(ownership, MATCH)
        self.assert_ownership(ownership, (MATCH, key(MATCH, 2, PROVISIONAL)),
                              ('KEV added', key('KEV added', 2, PROVISIONAL)))
        self.readd_and_deliver({old}, 1)

    def test_migration_preserves_pairs_and_events_and_repeats_as_noop(self):
        version_one(self.store)
        self.pair()
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)', (key(MATCH, 1), WATCH.id, CVE, MATCH, 1, T))
        body = json.dumps(dict(watch_id=WATCH.id, record_id=CVE, episode=1))
        self.db.execute('INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at,enqueued_at) '
                        'VALUES (?,?,?,?,?,?)', (f'{WATCH.id}|{CVE}', 'normal', json.dumps([MATCH]), body, T, T))
        promoted_at = (self.clock() + timedelta(hours=2)).isoformat()
        crossing = key(CROSSING, 1, suffix='|1')
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                        (crossing, WATCH.id, CVE, CROSSING, 1, promoted_at))
        self.db.execute("UPDATE outbox SET urgency='urgent',reasons_json=?,due_at=?,dirty=1 WHERE id=?",
                        (json.dumps([MATCH, CROSSING]), promoted_at, self.pending()['id']))
        self.assertEqual((self.pending()['enqueued_at'], self.pending()['due_at']), (T, promoted_at))

        control_store = Store(':memory:')
        control = control_store.connection
        self.addCleanup(control.close)
        self.db.backup(control)
        # The v0.10.1 data updates relevant to this already-upgraded schema and fixture.
        control.execute("""UPDATE outbox SET enqueued_at=coalesce(
            (SELECT min(created_at) FROM events WHERE watch_id || '|' || record_id=outbox.pair_key),
            due_at) WHERE enqueued_at IS NULL""")
        control.execute("UPDATE outbox SET due_at=min(due_at,enqueued_at) WHERE urgency='urgent'")

        self.store.migrate()
        self.assertEqual(self.store.get_meta('schema_version'), '1')
        self.assertEqual(self.store.get_meta('outbox_event_keys_version'), '1')
        row = self.pending()
        self.assertEqual(row['due_at'], T)
        self.assertEqual({tuple(entry) for entry in self.db.execute('SELECT * FROM outbox_event_keys')},
                         {(row['id'], MATCH, '', 1), (row['id'], CROSSING, '', 1)})
        lines = list(self.db.iterdump())
        marker = "INSERT INTO \"meta\" VALUES('outbox_event_keys_version','1');"
        self.assertEqual([line for line in lines if line != marker and not line.startswith(
            ('CREATE TABLE outbox_event_keys(', 'INSERT INTO "outbox_event_keys"'))], list(control.iterdump()))
        dump = '\n'.join(lines).encode()
        self.store.migrate()
        self.assertEqual('\n'.join(self.db.iterdump()).encode(), dump)
        self.engine.reload_watches(())
        self.readd_and_deliver({crossing}, 2)

    def test_standalone_rebaseline_migrates_before_writing_watchless_event(self):
        source = 'fixture_a'
        with TemporaryDirectory(dir='.') as directory:
            folder = Path(directory).resolve()
            path = folder / 'fixture.db'
            config = folder / 'config.toml'
            config.write_text(f'db_path = {json.dumps(str(path))}\n'
                              f'watchlist_path = {json.dumps(str(folder / "watch.toml"))}\n')
            store = Store(str(path))
            self.addCleanup(store.connection.close)
            store.migrate()
            version_one(store)
            db = store.connection
            db.execute('INSERT INTO adapter_state(source) VALUES (?)', (source,))
            db.execute('INSERT INTO manifests(source,resource,digest) VALUES (?,?,?)', (source, 'fixture', 'accepted'))
            with patch.dict(REGISTRY, {source: Adapter(source, 'F')}), \
                    patch('cornicen.cli.datetime', wraps=datetime) as date, redirect_stdout(StringIO()) as output:
                date.now.return_value = self.clock()
                result = main(['--config', str(config), 'adapter', 'rebaseline', source])
            self.assertEqual(result, 0, output.getvalue())
            baseline = f'|baseline:{source}|baseline|1'
            self.assertEqual({row['key'] for row in db.execute('SELECT key FROM events')}, {baseline})
            self.assertEqual(store.get_meta('schema_version'), '1')
            self.assertEqual(store.get_meta('outbox_event_keys_version'), '1')
            processor = AdapterStore(store, folder)
            processor.dimension(source, 'fetch', 'unhealthy', T, 'invented failure')
            processor.finish_cycle(source, T)
            watchless = {baseline, f'|{source}|unhealthy|1'}
            self.assertEqual({row['key'] for row in db.execute('SELECT key FROM events')}, watchless)
            self.assertEqual(db.execute('SELECT * FROM outbox_event_keys').fetchall(), [])
            with redirect_stdout(StringIO()) as lines:
                self.assertEqual(outbox_list(store, False), 0)
            items = [json.loads(line) for line in lines.getvalue().splitlines()[:-1]]
            self.assertEqual(len(items), 2)
            for item in items:
                self.assertNotIn('event_keys', item)
                self.assertNotIn('legacy_reasons', item)

            engine = Engine(store, (WATCH,), AliasMap(), self.engine.config, self.clock, self.notifier)
            engine.reload_watches(())
            self.assertEqual({row['key'] for row in db.execute('SELECT key FROM events')}, watchless)
            store.put_record(CVE, self.record(), T)
            engine.reload_watches((WATCH,))
            self.clock.now += timedelta(days=1)
            engine._flush()
            self.assertEqual([(n['record'], n['reasons']) for n in self.notifier.delivered
                              if n['watch'] == WATCH.id], [(CVE, [MATCH])])
            self.assertEqual({row['key'] for row in db.execute('SELECT key FROM events')},
                             watchless | {key(MATCH, 1)})

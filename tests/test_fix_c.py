"""Scale regressions use operation counts rather than host-dependent timings."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_STORED

from cornicen import applicability
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.identity import AliasMap
from cornicen.model import Origin
from cornicen.outbox import deliver
from cornicen.sources.cvelist import CveListSource
from cornicen.store import Store
from tests import test_engine as helpers
from tests.source_helpers import public_resolver, release


def synthetic_record(number):
    entry = {'vendor': f'vendor-{number % 2000}', 'product': 'service',
             'versions': [{'version': '1.0.0', 'status': 'affected', 'versionType': 'semver'}]}
    if number % 5 == 0:
        entry['versions'][0].update(version='0', lessThan='2.0.0')
    if number % 20 == 0:
        entry['versions'][0]['changes'] = [{'at': '1.5.0', 'status': 'unaffected'}]
    return {'cveMetadata': {'cveId': f'CVE-2026-{10000 + number}', 'state': 'PUBLISHED'},
            'containers': {'cna': {'affected': [entry], 'descriptions': [
                {'lang': 'en', 'value': 'Synthetic vulnerability. ' * 16}]}}}


def snapshot_archive(directory, count):
    """Generate on disk, outside the measured consumer's allocation window."""
    inner, outer = Path(directory) / 'inner.zip', Path(directory) / 'snapshot.zip'
    with ZipFile(inner, 'w', ZIP_STORED) as zipped:
        for number in range(count):
            record = synthetic_record(number)
            record_id = record['cveMetadata']['cveId']
            zipped.writestr(f'cves/2026/10xxx/{record_id}.json', json.dumps(record))
    with ZipFile(outer, 'w', ZIP_STORED) as zipped:
        zipped.write(inner, 'snapshot.zip')
    return outer


class FileOpener:
    """Injected HTTP response backed by a fixture file; never opens a socket."""

    def __init__(self, routes):
        self.routes = routes

    def open(self, request, timeout=None):
        result = Path(self.routes[request.full_url]).open('rb')
        result.status, result.headers = 200, {}
        return result


class ScaleTests(unittest.TestCase):
    setUp = helpers.EngineTests.setUp
    start = helpers.EngineTests.start
    ingest = helpers.EngineTests.ingest
    count = helpers.EngineTests.count

    def test_1_prune_indexes_and_all_protections(self):
        db = self.store.connection
        old = (self.clock() - timedelta(days=400)).isoformat()
        for key in ('pair', 'pending', 'kev', 'retry', 'dead', 'expired', 'sent', 'fresh'):
            self.store.put_record(key, {}, self.clock().isoformat() if key == 'fresh' else old)
        db.execute("INSERT INTO pairs(watch_id,record_id,state,episode,baseline) VALUES ('w','pair','affected',1,0)")
        self.store.queue('w|pending', 'normal', [], {'record_id': 'pending'}, old)
        self.store.queue('w|sent', 'normal', [], {'record_id': 'sent'}, old)
        db.execute("UPDATE outbox SET sent_at=? WHERE pair_key='w|sent'", (old,))
        db.execute("INSERT INTO kev VALUES ('kev','{}')")
        db.execute("INSERT INTO retry_queue VALUES ('cvelist','retry',1,?,'error')", (old,))
        db.execute("INSERT INTO dead_letters VALUES ('cvelist','dead',5,?,'error','1')", (old,))
        queries = []
        db.set_trace_callback(queries.append)
        self.store.prune_records(self.clock(), 365)
        db.set_trace_callback(None)
        self.assertEqual({r[0] for r in db.execute('SELECT id FROM records')},
                         {'pair', 'pending', 'kev', 'retry', 'dead', 'fresh'})
        sql = next(q for q in queries if q.startswith('DELETE FROM records'))
        plan = '\n'.join(r['detail'] for r in db.execute('EXPLAIN QUERY PLAN ' + sql))
        for table in ('records', 'pairs', 'outbox', 'retry_queue', 'dead_letters'):
            self.assertNotIn('SCAN ' + table, plan, plan)
            self.assertIn('SEARCH ' + table, plan, plan)
        db.executemany('INSERT INTO records VALUES (?,X\'00\',?)',
                       ((f'fresh-{n}', self.clock().isoformat()) for n in range(10000)))
        steps = 0
        def progress():
            nonlocal steps
            steps += 1
        db.set_progress_handler(progress, 1)
        self.store.prune_records(self.clock(), 1)
        db.set_progress_handler(None, 0)
        self.assertLess(steps, 500)

    def future_rows(self, count=3000):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        row = self.store.connection.execute("SELECT * FROM outbox WHERE pair_key LIKE 'service|%'").fetchone()
        with self.store.transaction():
            for number in range(1, count):
                self.store.queue(f'copy-{number}', 'normal', json.loads(row['reasons_json']),
                                 json.loads(row['body_json']), row['due_at'])
        self.engine._flush()

    def test_2_unchanged_future_flush_has_constant_queries(self):
        self.future_rows()
        self.engine._flush()  # Settle any initial dirty rows.
        queries = []
        self.store.connection.set_trace_callback(queries.append)
        self.engine._flush()
        self.store.connection.set_trace_callback(None)
        self.assertLessEqual(len(queries), 5, f'{len(queries)} SQL statements for zero due rows')
        self.assertFalse(any(q.startswith('UPDATE') for q in queries))
        plan = '\n'.join(row['detail'] for row in self.store.connection.execute(
            'EXPLAIN QUERY PLAN ' + queries[0]))
        self.assertIn('USING INDEX outbox_ready', plan)
        self.assertIn('USING INDEX outbox_dirty', plan)
        self.assertEqual(self.count('outbox'), 3001)  # Includes the sent bootstrap summary.

    def test_2_dirty_promotion_and_bounded_transactions(self):
        self.future_rows(601)
        queries, transactions = [], []
        self.store.connection.set_trace_callback(queries.append)
        def send(notification):
            transactions.append(self.store.connection.in_transaction)
            return True
        with patch.object(self.notifier, 'send', side_effect=send):
            self.engine.run_cycle([replace(self.baseline[2], epss={self.record['cveMetadata']['cveId']: (.5, .99)})])
        self.store.connection.set_trace_callback(None)
        self.assertEqual(transactions, [False] * 601)
        # Batches of at most 256 revalidations, plus one acknowledgement per send.
        saves = sum(q.startswith('SAVEPOINT') for q in queries)
        self.assertLessEqual(saves, 601 + 12)
        stack, batches = [], []
        for query in queries:
            if query.startswith('SAVEPOINT'):
                stack.append(0)
            elif query.startswith('UPDATE outbox SET dirty=0'):
                stack[-1] += 1
            elif query.startswith('RELEASE'):
                count = stack.pop()
                if count:
                    batches.append(count)
        self.assertEqual(batches, [256, 256, 89])
        self.assertEqual(self.count('outbox'), 602)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0], 0)

    def test_2_retry_deadline_blocks_promoted_future_row(self):
        self.future_rows(1)
        retry = (self.clock() + timedelta(minutes=30)).isoformat()
        self.store.connection.execute('UPDATE outbox SET next_attempt_at=? WHERE sent_at IS NULL', (retry,))
        self.engine.run_cycle([replace(self.baseline[2], epss={self.record['cveMetadata']['cveId']: (.5, .99)})])
        self.assertEqual(self.notifier.delivered, [])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertEqual(row['urgency'], 'urgent')
        self.assertEqual(row['next_attempt_at'], retry)
        self.clock.now += timedelta(minutes=30)
        self.engine._flush()
        self.assertEqual(len(self.notifier.delivered), 1)

    def test_2_evidence_removal_demotes_pending_urgent(self):
        self.future_rows(1)
        self.notifier.down = True
        high = replace(self.baseline[2], epss={self.record['cveMetadata']['cveId']: (.5, .99)})
        self.engine.run_cycle([high])
        self.engine.run_cycle([self.baseline[2]])
        row = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertEqual(row['urgency'], 'normal')
        self.assertEqual(row['due_at'], self.engine._digest())

    def test_2_revalidates_between_sends_outside_transactions(self):
        self.future_rows(2)
        high = replace(self.baseline[2], epss={self.record['cveMetadata']['cveId']: (.5, .99)})
        calls = []
        def send(notification):
            calls.append(notification)
            self.assertFalse(self.store.connection.in_transaction)
            # The second delivery must see this change after the first send.
            self.store.connection.execute("UPDATE pairs SET state='not_affected'")
            return True
        with patch.object(self.notifier, 'send', side_effect=send):
            self.engine.run_cycle([high])
        self.assertEqual(len(calls), 1)

    def test_2_unchanged_evidence_does_not_dirty_future_queue(self):
        self.future_rows(10)
        with patch.object(self.engine, '_revalidate', wraps=self.engine._revalidate) as revalidate:
            self.engine.run_cycle([self.baseline[2]])
        self.assertEqual(revalidate.call_count, 0)

    def test_3_watch_expansion_once_and_pairs_once_per_record(self):
        watches = tuple(replace(self.watches[0], id=f'w-{n}', match=((f'watch-{n}', 'service'),))
                        for n in range(20))
        aliases = AliasMap()
        with patch.object(aliases, 'expand', wraps=aliases.expand) as expand:
            engine = Engine(self.store, watches, aliases, self.config, self.clock, self.notifier)
            queries = []
            self.store.connection.set_trace_callback(queries.append)
            for number in range(10):
                record = synthetic_record(number)
                engine._evaluate(record, record['cveMetadata']['cveId'], baseline=True)
            self.store.connection.set_trace_callback(None)
            for watch in watches:
                self.assertEqual(sum(call.args[0] == watch.match[0] for call in expand.call_args_list), 1)
            self.assertEqual(sum('FROM pairs WHERE' in q for q in queries), 10)
            for number in range(10):
                identity = (f'vendor-{number}', 'service')
                self.assertEqual(sum(call.args[0] == identity for call in expand.call_args_list), 1)
            engine.reload_watches(watches)
            aliases.version = 'changed'
            engine._evaluate(synthetic_record(0), 'CVE-2026-10000', baseline=True)
            for watch in watches:
                self.assertEqual(sum(call.args[0] == watch.match[0] for call in expand.call_args_list), 3)

    def test_3_disappearing_identity_still_clears_old_pair(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        record = deepcopy(self.record)
        record['containers']['cna']['affected'] = []
        self.engine.run_cycle([self.ingest([record])])
        self.assertEqual(self.store.connection.execute('SELECT state FROM pairs').fetchone()[0], 'not_affected')

    def test_4_episode_lookup_uses_covering_index(self):
        plan = '\n'.join(r['detail'] for r in self.store.connection.execute(
            'EXPLAIN QUERY PLAN SELECT coalesce(max(episode),0) FROM events WHERE watch_id=? AND record_id=?',
            ('missing-watch', 'missing-record')))
        self.assertIn('USING COVERING INDEX', plan)
        self.assertIn('watch_id=? AND record_id=?', plan)

    def test_5_seen_migration_is_idempotent_and_keyed(self):
        self.store.set_meta('kev_seen', json.dumps(['CVE-2026-1234', 'CVE-2026-1235', 'CVE-2026-1234']))
        self.store.migrate()
        self.store.migrate()
        self.assertEqual({r[0] for r in self.store.connection.execute('SELECT cve FROM kev_seen')},
                         {'CVE-2026-1234', 'CVE-2026-1235'})
        self.assertIsNone(self.store.get_meta('kev_seen'))

    def test_5_seen_updates_do_not_serialize_history(self):
        self.start()
        self.engine.run_cycle([self.ingest([self.record])])
        entry = {'cveID': self.record['cveMetadata']['cveId'], 'vendorProject': 'examplecorp', 'product': 'example_service'}
        queries = []
        self.store.connection.set_trace_callback(queries.append)
        self.engine.run_cycle([replace(self.baseline[1], kev={entry['cveID']: entry})])
        self.store.connection.set_trace_callback(None)
        self.assertFalse(any("meta WHERE k='kev_seen'" in q or "meta VALUES ('kev_seen'" in q for q in queries))
        self.assertTrue(any('INSERT OR IGNORE INTO kev_seen' in q for q in queries))

    def test_6_digest_partition_has_linear_equality_work(self):
        class Row(dict):
            comparisons = 0
            def __eq__(self, other):
                Row.comparisons += 1
                return super().__eq__(other)
        ready = [Row(id=n, urgency='normal', body_json=json.dumps({'watch_id': 'w', 'record_id': str(n)}),
                     reasons_json='[]', attempts=0) for n in range(1000)]
        self.notifier.down = True
        self.assertEqual(deliver(self.store, self.notifier, self.clock, ready), 0)
        self.assertLessEqual(Row.comparisons, 1000)

    def test_7_bootstrap_50000_memory_bound(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            archive = snapshot_archive(directory, 50000)
            store = Store(str(Path(directory) / 'state.db'))
            self.addCleanup(store.connection.close)
            store.migrate()
            r = release(3)
            url = r['assets'][0]['browser_download_url']
            source = CveListSource(Http('test', {}, FileOpener({url: archive}), resolver=public_resolver), store)
            engine = Engine(store, (), AliasMap(), self.config, self.clock, self.notifier)
            tracemalloc.start()
            try:
                result = source._archive(r, Origin.SNAPSHOT, self.clock())
                self.assertEqual(result.errors, ())
                engine.run_cycle([result])
                _, peak = tracemalloc.get_traced_memory()
                # 8 MiB fixed + 256 bytes/CVE projects to <82 MiB Python heap
                # at 300k, leaving >174 MiB for SQLite, interpreter and native ZIP/zlib.
                self.assertLessEqual(peak, 8 * 1024 * 1024 + 256 * 50000)
                self.assertEqual(store.connection.execute('SELECT count(*) FROM records').fetchone()[0], 50000)
                result.records.close()
            finally:
                tracemalloc.stop()

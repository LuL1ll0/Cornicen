# script-purpose: Verify release workers never stall scheduler cycles offline.
# script-class: harness
# script-trigger: Run unittest or make gate.
# script-tests: tests/test_release_worker.py
"""Read invented fixtures; write temporary watch files and databases.

Run python3 -m unittest tests.test_release_worker. Exit 0 passes; exit 1 fails.
No network is used. Only test cleanup waits for workers.
"""
from datetime import timedelta
import threading
import time
import unittest
from unittest.mock import patch

from cornicen.scheduler import Scheduler
from tests import test_latest_releases as fixtures


class ReleaseWorkerTests(unittest.TestCase):
    setUp = fixtures.LatestReleaseTests.setUp
    response = fixtures.LatestReleaseTests.response
    enabled = fixtures.LatestReleaseTests.enabled
    events = fixtures.LatestReleaseTests.events
    retained_cve = fixtures.LatestReleaseTests.retained_cve
    def scheduler(self):
        class Empty:
            def poll(self, now):
                return []
        self.lines = []
        return Scheduler(self.engine, {s: Empty() for s in ('cvelist', 'kev', 'epss')},
                         self.clock, self.lines.append, monotonic=lambda: self.clock().timestamp())

    def blocking(self, scheduler):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def resolver(*args, **kwargs):
            from tests.source_helpers import public_resolver
            calls.append(threading.get_ident())
            entered.set()
            release.wait()  # No timeout: production cannot make this return.
            return public_resolver(*args, **kwargs)
        self.http.resolver = resolver
        def cleanup():
            release.set()
            worker = getattr(scheduler, 'release_worker', None)
            if worker:
                worker.join(2)
        self.addCleanup(cleanup)
        return entered, release, calls

    def test_latest_release_r3_blocked_dns_cve_delivery_ticks_single_worker(self):
        self.enabled()
        scheduler = self.scheduler()
        entered, release, calls = self.blocking(scheduler)
        # Finite escape solely prevents the old synchronous code hanging the red run.
        escape = threading.Timer(1, release.set)
        escape.start()
        self.addCleanup(escape.cancel)
        started = time.monotonic()
        scheduler.tick()
        self.assertLess(time.monotonic() - started, .5)
        escape.cancel()
        self.assertTrue(entered.wait(1))
        self.store.connection.execute('INSERT INTO epss VALUES (?,?,?,?)', ('CVE-2099-1000', .9, .9, '2099-06-07'))
        scheduler.sources['cvelist'].poll = lambda now: [self.retained_cve()]
        for minutes in (1, 60, 1440):
            self.clock.now += timedelta(minutes=minutes)
            started = time.monotonic()
            scheduler.tick()
            self.assertLess(time.monotonic() - started, .5)
        self.assertTrue(any(n['record'] == 'CVE-2099-1000' and n['urgency'] == 'urgent'
                            for n in self.notifier.delivered))
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.lines), 4)
        health = self.engine.db.execute("SELECT state,detail FROM health WHERE source='releases'").fetchone()
        self.assertEqual(tuple(health), ('unhealthy', 'Release checks failed'))
        self.assertIsNone(self.store.get_meta('release_check:github:example-org/widget'))

    def test_latest_release_r3_success_later_tick_once_scheduler_transaction(self):
        self.enabled()
        scheduler = self.scheduler()
        entered, release, calls = self.blocking(scheduler)
        escape = threading.Timer(1, release.set)
        escape.start()
        self.addCleanup(escape.cancel)
        scheduler.tick()
        self.assertEqual(self.events(), [])
        escape.cancel()
        self.assertTrue(entered.wait(1))
        release.set()
        scheduler.release_worker.join(2)
        self.assertEqual(self.events(), [])
        self.assertIsNone(self.store.get_meta('release_check:github:example-org/widget'))
        observed = []
        original = self.checker._record
        def record(*args):
            observed.append((threading.get_ident(), self.engine.db.in_transaction))
            return original(*args)
        with patch.object(self.checker, '_record', side_effect=record):
            scheduler.tick()
            scheduler.tick()
        self.assertEqual(observed, [(threading.get_ident(), True)])
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(len(calls), 1)

    def test_latest_release_r3_restart_inflight_retries_without_durable_loss(self):
        from cornicen.engine import Engine
        from cornicen.store import Store
        from cornicen.sources.cvelist import CveListSource
        from cornicen.releases import ReleaseChecker
        from tests.source_helpers import public_resolver
        self.enabled()
        path = self.root / 'restart.sqlite'
        durable = Store(path)
        self.addCleanup(durable.connection.close)
        self.store.connection.backup(durable.connection)
        self.store = durable
        self.client.store = durable
        self.engine = Engine(durable, self.engine.watches, self.engine.aliases,
                             self.config, self.clock, self.notifier)
        self.engine.run_cycle([self.retained_cve()])
        self.engine.release_checker = self.checker
        scheduler = self.scheduler()
        entered, release, calls = self.blocking(scheduler)
        escape = threading.Timer(1, release.set)
        escape.start()
        self.addCleanup(escape.cancel)
        scheduler.tick()
        self.assertIsNone(durable.get_meta('release_check:github:example-org/widget'))
        escape.cancel()
        self.assertTrue(entered.wait(1))
        before = {table: [tuple(r) for r in durable.connection.execute('SELECT * FROM ' + table)]
                  for table in ('records', 'pairs', 'events', 'outbox')}
        durable.connection.close()  # Old worker remains blocked across database close.
        self.store = Store(path)
        self.addCleanup(self.store.connection.close)
        self.http.resolver = public_resolver
        client = CveListSource(self.http, self.store)
        checker = ReleaseChecker(client)
        self.engine = Engine(self.store, self.engine.watches, self.engine.aliases,
                             self.config, self.clock, self.notifier, release_checker=checker)
        for table, rows in before.items():
            self.assertEqual([tuple(r) for r in self.store.connection.execute('SELECT * FROM ' + table)], rows)
        restarted = self.scheduler()
        restarted.tick()
        restarted.release_worker.join(2)
        restarted.tick()
        self.assertEqual(len(self.events()), 1)
        self.assertIsNotNone(self.store.get_meta('release_check:github:example-org/widget'))
        # The abandoned worker can finish after its original database is closed;
        # it has only plain Python state and cannot damage the restarted store.
        release.set()
        scheduler.release_worker.join(2)
        self.assertTrue(scheduler.release_outcome[0])
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(len(calls), 1)

    def test_latest_release_r3_record_rollback_retry_and_newer_shared_metadata(self):
        self.enabled()
        from tests.test_latest_releases import URL
        body = self.opener.routes[URL]
        self.opener.routes[URL] = (body, 200, {'ETag': 'invented-etag'})
        scheduler = self.scheduler()
        scheduler.tick()
        scheduler.release_worker.join(2)
        job = scheduler.release_job
        job.state.set_meta('github_auth', 'token rejected')
        job.state.set_meta('github_rate_limit', 'invented stale metadata')
        self.store.set_meta('github_rate_limit', 'invented newer metadata')
        original = self.checker._record
        def broken(*args):
            original(*args)
            raise RuntimeError('invented record failure')
        with patch.object(self.checker, '_record', side_effect=broken):
            with self.assertRaises(RuntimeError):
                scheduler.tick()
        self.assertEqual(self.events(), [])
        self.assertEqual(self.store.get_meta('github_auth'), 'token')
        self.assertIsNone(self.store.get_meta('release_check:github:example-org/widget'))
        self.assertFalse(self.engine.db.in_transaction)
        self.assertIs(scheduler.release_job, job)
        scheduler.tick()
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.store.get_meta('github_auth'), 'token rejected')
        self.assertEqual(self.store.get_meta('github_rate_limit'), 'invented newer metadata')
        self.assertIsNotNone(self.engine.db.execute('SELECT * FROM http_cache').fetchone())

    def test_latest_release_r3_disable_inflight_no_stale_notice(self):
        from dataclasses import replace
        self.enabled()
        scheduler = self.scheduler()
        entered, release, calls = self.blocking(scheduler)
        escape = threading.Timer(1, release.set)
        escape.start()
        self.addCleanup(escape.cancel)
        scheduler.tick()
        self.assertTrue(entered.wait(1))
        # Red code already recorded the result before returning.
        self.assertEqual(self.events(), [])
        escape.cancel()
        self.clock.now += timedelta(minutes=1)
        scheduler.tick()
        self.assertIsNotNone(self.engine.db.execute("SELECT * FROM health WHERE source='releases'").fetchone())
        self.engine.reload_watches((replace(self.engine.watches[0], latest_release=None),))
        scheduler.tick()
        self.assertIsNone(self.engine.db.execute("SELECT * FROM health WHERE source='releases'").fetchone())
        release.set()
        scheduler.release_worker.join(2)
        scheduler.tick()
        self.assertEqual(self.events(), [])
        self.assertIsNone(self.engine.db.execute("SELECT * FROM health WHERE source='releases'").fetchone())

    def test_integration_reenable_while_worker_stuck_reports_unhealthy(self):
        # Integration (lane D r3 residual): disable then re-enable during a stuck worker.
        from dataclasses import replace
        self.enabled()
        scheduler = self.scheduler()
        entered, release, calls = self.blocking(scheduler)
        scheduler.tick()
        self.assertTrue(entered.wait(1))
        self.clock.now += timedelta(minutes=1)
        scheduler.tick()
        health = "SELECT state FROM health WHERE source='releases'"
        self.assertEqual(self.engine.db.execute(health).fetchone()[0], 'unhealthy')
        enabled_watch = self.engine.watches[0]
        self.engine.reload_watches((replace(enabled_watch, latest_release=None),))
        scheduler.tick()
        self.assertIsNone(self.engine.db.execute(health).fetchone())
        self.engine.reload_watches((enabled_watch,))
        self.clock.now += timedelta(minutes=1)
        scheduler.tick()
        self.assertTrue(scheduler.release_worker.is_alive())
        self.assertEqual(self.engine.db.execute(health).fetchone()[0], 'unhealthy')
        self.assertEqual(len(calls), 1)

    def test_latest_release_r3_worker_etag_rate_budget_and_daily_dedup(self):
        from dataclasses import replace
        from tests.test_latest_releases import URL
        self.enabled()
        self.opener.routes[URL] = (self.opener.routes[URL], 200, {'ETag': 'invented-etag'})
        scheduler = self.scheduler()
        scheduler.tick()
        self.assertEqual(self.events(), [])
        scheduler.release_worker.join(2)
        scheduler.tick()
        self.assertEqual(len(self.events()), 1)
        self.clock.now += timedelta(days=1)
        reset = int((self.clock() + timedelta(hours=1)).timestamp())
        self.opener.routes[URL] = (b'', 304, {'x-ratelimit-remaining': '0',
                                          'x-ratelimit-limit': '10', 'x-ratelimit-reset': str(reset)})
        watch = self.engine.watches[0]
        self.engine.reload_watches((watch, replace(watch, id='widget-two', latest_release='github:example-org/widget-two')))
        scheduler.tick()
        scheduler.release_worker.join(2)
        scheduler.tick()
        self.assertEqual(len(self.opener.requests), 2)
        self.assertEqual(self.opener.requests[-1].get_header('If-none-match'), 'invented-etag')
        self.assertEqual(len(self.events()), 1)
        self.assertIn('"remaining": 0', self.store.get_meta('github_rate_limit'))
        self.assertEqual(self.engine.db.execute("SELECT state FROM health WHERE source='releases'").fetchone()[0], 'unhealthy')

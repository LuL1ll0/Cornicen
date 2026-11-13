# script-purpose: Verify opt-in release checks and delivery offline.
# script-class: harness
# script-trigger: Run unittest or make gate.
# script-tests: tests/test_latest_releases.py
"""Read invented fixtures and source; write temporary databases and watch files.

Run with python3 -m unittest tests.test_latest_releases. Exit 0 passes;
exit 1 reports a failed offline release, delivery, privacy or upgrade contract.
"""
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cornicen.cli import status_json
from cornicen.config import Config, SecretToken
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.identity import AliasMap
from cornicen.model import Notification
from cornicen.render import render
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource
from cornicen.store import Store
from cornicen.watchlist import WatchlistError, load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier
from tests.source_helpers import Opener, public_resolver
from tests.source_helpers import Reply
from cornicen.model import IngestResult, FetchStatus, Origin

WATCH = '''[[watch]]
id = "widget"
name = "Example widget"
match = ["examplecorp:widget"]
version = "4.2.0"
scheme = "semver"
'''
URL = 'https://api.github.com/repos/example-org/widget/releases/latest'


class LatestReleaseTests(unittest.TestCase):
    def setUp(self):
        # A missing feature module is an individual red result on the original tree.
        from cornicen.releases import ReleaseChecker
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.watchpath = self.root / 'watch.toml'
        self.watchpath.write_text(WATCH)
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.clock = FakeClock(datetime(2099, 6, 7, 7, tzinfo=timezone.utc))
        self.notifier = RecordingNotifier(self.clock)
        self.config = Config(':memory:', self.watchpath, None, 'https://notify.example.invalid', 'example', None)
        self.opener = Opener({})
        self.http = Http('example', {}, self.opener, resolver=public_resolver,
                         data_dir=self.root, github_token=SecretToken('invented-token'))
        self.client = CveListSource(self.http, self.store)
        self.checker = ReleaseChecker(self.client)
        self.engine = Engine(self.store, load_watchlist_text(WATCH), AliasMap.load(False),
                             self.config, self.clock, self.notifier, release_checker=self.checker)
        self.response()

    def response(self, tag='v4.3.0', **fields):
        self.opener.routes[URL] = json.dumps(dict(tag_name=tag, draft=False, prerelease=False, **fields)).encode()

    def enabled(self, extra=''):
        text = WATCH + 'latest_release = "github:example-org/widget"\nrelease_tag_prefix = "v"\n' + extra
        self.watchpath.write_text(text)
        self.engine.reload_watches(load_watchlist_text(text))

    def cycle(self, days=0):
        self.clock.now += timedelta(days=days)
        return self.engine.run_cycle([])

    def events(self):
        return self.store.connection.execute("SELECT * FROM events WHERE type='release_behind'").fetchall()

    def pending(self):
        return [r for r in self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL')
                if json.loads(r['body_json']).get('release_behind')]

    def test_latest_release_no_field_no_request(self):
        self.cycle()
        self.assertEqual(self.opener.requests, [])
        self.assertEqual(self.events(), [])
        self.assertIsNone(self.store.connection.execute("SELECT * FROM health WHERE source='releases'").fetchone())

    def test_latest_release_behind_once_same_tag_then_newer(self):
        self.enabled()
        self.cycle()
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.pending()[0]['urgency'], 'normal')
        self.assertEqual(self.opener.requests[0].get_header('Authorization'), 'Bearer invented-token')
        self.cycle()
        self.assertEqual(len(self.opener.requests), 1)
        self.cycle(1)
        self.assertEqual(len(self.events()), 1)
        self.response('v4.4.0')
        self.cycle(1)
        self.assertEqual(len(self.events()), 2)
        self.assertEqual(len(self.opener.requests), 3)
        # The notices actually join the durable digest, then stay deduped after delivery.
        self.clock.now += timedelta(hours=12)
        self.cycle()
        self.assertEqual(self.pending(), [])
        self.assertTrue(any(n['urgency'] == 'normal' and n['record'].startswith('release:')
                            for n in self.notifier.delivered))
        self.cycle(1)
        self.assertEqual(len(self.events()), 2)

    def test_latest_release_watch_updated_clears_quietly(self):
        self.enabled()
        self.cycle()
        self.engine.reload_watches(tuple(replace(w, version='4.3.0') for w in self.engine.watches))
        before = len(self.events())
        self.cycle()
        self.assertEqual(self.pending(), [])
        self.assertEqual(len(self.events()), before)
        self.assertFalse(any('release_behind' in n['reasons'] for n in self.notifier.delivered))

    def test_latest_release_unparseable_draft_prerelease(self):
        self.enabled()
        for tag, field in [('untrusted-tag', None), ('v4.3.0', 'draft'), ('v4.3.0', 'prerelease')]:
            value = dict(tag_name=tag, draft=False, prerelease=False)
            if field:
                value[field] = True
            self.opener.routes[URL] = json.dumps(value).encode()
            self.cycle(1)
            self.assertEqual(self.events(), [])
            row = self.store.connection.execute("SELECT * FROM health WHERE source='releases'").fetchone()
            self.assertEqual(row['state'], 'healthy')
            self.assertIn('could not compare: 1', row['detail'])

    def test_latest_release_304_etag_no_event(self):
        self.enabled()
        body = self.opener.routes[URL]
        self.opener.routes[URL] = (body, 200, {'ETag': '"example-etag"'})
        self.cycle()
        self.opener.routes[URL] = (b'', 304, {})
        self.cycle(1)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.opener.requests[-1].get_header('If-none-match'), '"example-etag"')

    def test_latest_release_404_not_failure(self):
        self.enabled()
        self.opener.routes[URL] = (b'{}', 404, {})
        self.cycle()
        self.assertEqual(self.events(), [])
        row = self.store.connection.execute("SELECT * FROM health WHERE source='releases'").fetchone()
        self.assertEqual(row['state'], 'healthy')
        self.assertIn('could not compare: 1', row['detail'])

    def test_latest_release_failure_health_isolated(self):
        self.enabled()
        prior = [tuple(r) for r in self.store.connection.execute("SELECT * FROM health WHERE source!='releases'")]
        self.opener.routes[URL] = RuntimeError('untrusted-tag')
        self.cycle()
        after = [tuple(r) for r in self.store.connection.execute("SELECT * FROM health WHERE source!='releases'")]
        self.assertEqual(prior, after)
        row = self.store.connection.execute("SELECT * FROM health WHERE source='releases'").fetchone()
        self.assertEqual(row['state'], 'unhealthy')
        self.assertNotIn('untrusted-tag', row['detail'])
        self.assertEqual(self.events(), [])
        self.response()
        self.cycle(1)
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='releases'").fetchone()[0], 'healthy')

    def test_latest_release_two_watches_one_repository(self):
        self.enabled()
        watch = self.engine.watches[0]
        self.engine.reload_watches((watch, replace(watch, id='widget-two', latest_release='github:Example-Org/Widget')))
        self.cycle()
        detail = self.store.connection.execute("SELECT detail FROM health WHERE source='releases'").fetchone()[0]
        self.assertEqual(detail, 'Release checks: 1; failed: 0; compared: 2; could not compare: 0')
        self.assertEqual(len(self.opener.requests), 1)
        self.assertEqual(len(self.events()), 2)
        self.assertEqual(self.opener.requests[0].full_url, URL)
        self.assertNotIn('4.2.0', self.opener.requests[0].full_url)

    def retained_cve(self):
        self.store.set_meta('baseline_complete', '1')
        record = {'cveMetadata': {'cveId': 'CVE-2099-1000', 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': [{'vendor': 'examplecorp', 'product': 'widget',
                      'versions': [{'version': '4.2.0', 'status': 'affected'}]}]}}}
        return IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA, None, self.clock(), (record,))

    def test_latest_release_r2_flush_before_io_outside_transaction(self):
        self.enabled()
        self.store.connection.execute('INSERT INTO epss VALUES (?,?,?,?)', ('CVE-2099-1000', .9, .9, '2099-06-07'))
        observed = []
        def opener(request, timeout=None):
            observed.append((bool(self.notifier.delivered), self.store.connection.in_transaction))
            raise TimeoutError('invented stalled transfer')
        self.http.opener = opener
        self.engine.run_cycle([self.retained_cve()])
        self.assertEqual(observed, [(True, False)])
        self.assertTrue(any(n['record'] == 'CVE-2099-1000' and n['urgency'] == 'urgent'
                            for n in self.notifier.delivered))

    def test_latest_release_r2_total_budget_including_auth_retry(self):
        self.enabled()
        watch = self.engine.watches[0]
        self.engine.reload_watches((watch, replace(watch, id='widget-two', latest_release='github:example-org/widget-two')))
        elapsed = [0]
        self.http.clock = lambda: elapsed[0]
        timeouts = []
        def opener(request, timeout=None):
            timeouts.append(timeout)
            elapsed[0] += 4 if len(timeouts) == 1 else timeout
            return Reply(b'{}', status=401)
        self.http.opener = opener
        self.cycle()
        self.assertEqual(timeouts, [10, 6])
        self.assertEqual(elapsed[0], 10)
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='releases'").fetchone()[0], 'unhealthy')

    def test_latest_release_r2_settings_only_no_cve_rematch(self):
        self.engine.run_cycle([self.retained_cve()])
        for fields in (dict(latest_release='github:example-org/widget'),
                       dict(release_tag_prefix='v'), dict(release_tag_prefix='release-'),
                       dict(latest_release='github:example-org/widget-two'),
                       dict(release_tag_prefix=None), dict(latest_release=None)):
            with self.subTest(fields=fields):
                sql = []
                self.store.connection.set_trace_callback(sql.append)
                with patch.object(self.engine, '_rematch_record', wraps=self.engine._rematch_record) as rematch:
                    self.engine.reload_watches((replace(self.engine.watches[0], **fields),))
                self.store.connection.set_trace_callback(None)
                self.assertEqual(rematch.call_count, 0)
                self.assertFalse(any(s.lstrip().upper().startswith(('INSERT INTO PAIRS', 'UPDATE PAIRS', 'DELETE FROM PAIRS')) for s in sql))

    def test_latest_release_tag_body_only_status_stdout_health(self):
        self.enabled()
        self.response('v4.3.0+secret-tag')
        class Empty:
            def poll(self, now):
                return []
        output = []
        scheduler = Scheduler(self.engine, {s: Empty() for s in ('cvelist', 'kev', 'epss')},
                              clock=self.clock, output=output.append, monotonic=lambda: 0)
        scheduler.tick()
        worker = getattr(scheduler, 'release_worker', None)
        if worker is not None:
            worker.join(2)  # Test synchronization only; production never waits.
            self.assertFalse(worker.is_alive())
            scheduler.tick()
        capture = io.StringIO()
        with redirect_stdout(capture):
            status_json(self.store, self.clock(), self.config)
        self.assertEqual(json.loads(capture.getvalue())['release_checks'], 1)
        # A rejected/unapplied file does not misreport the daemon's active checks.
        from cornicen.cli import release_check_count
        self.watchpath.write_text('invalid watch document')
        self.assertEqual(release_check_count(self.config, self.store), 1)
        public = capture.getvalue() + str(output) + str([tuple(r) for r in self.store.connection.execute('SELECT * FROM health')])
        self.assertNotIn('secret-tag', public)
        self.assertNotIn('example-org', public)
        row = self.pending()[0]
        body = json.loads(row['body_json'])
        n = Notification('example', 'widget', body['record_id'], ('release_behind',), 'normal', body)
        self.assertIn('v4.3.0+secret-tag', render(n)[1])
        # Release text remains in its watch block even after the three full CVE items.
        others = [dict(key=str(i), watch_id='widget', record_id=f'CVE-2099-{1000+i}',
                       reasons=['new match'], urgency='normal', body=dict(name='Example widget',
                       product='widget', version='4.2.0', epss={'score': .5, 'pct': .5})) for i in range(4)]
        from dataclasses import asdict
        digest = Notification('digest', '', '', (), 'normal', {'items': others + [asdict(n)]})
        self.assertIn('you are behind', render(digest)[1])
        self.assertEqual(render(digest)[2], 3)
        from cornicen.public_text import public_text
        watch = replace(self.engine.watches[0], release_tag_prefix='failed')
        self.assertEqual(public_text('failed', (watch,)), '[redacted]')

    def test_latest_release_invalid_field_no_echo(self):
        for value in ['https://example.invalid/private', 'github:example-org/widget/extra',
                      'other:example-org/widget', 'github:-bad/widget', 'github:example-org/..', '', 7]:
            with self.subTest(value=value):
                with self.assertRaises(WatchlistError) as caught:
                    load_watchlist_text(WATCH + 'latest_release = ' + json.dumps(value))
                self.assertIn('latest_release is invalid', str(caught.exception))
                if value not in ('', 7):
                    self.assertNotIn(value, str(caught.exception))
        for value in ['', 7, 'bad\ntext']:
            with self.assertRaises(WatchlistError):
                load_watchlist_text(WATCH + 'latest_release = "github:example-org/widget"\nrelease_tag_prefix = ' + json.dumps(value))

    def test_latest_release_daily_state_survives_restart(self):
        self.enabled()
        self.cycle()
        self.engine = Engine(self.store, self.engine.watches, self.engine.aliases, self.config,
                             self.clock, self.notifier, release_checker=self.checker)
        self.cycle()
        self.assertEqual(len(self.opener.requests), 1)
        self.assertEqual(len(self.events()), 1)

    def test_latest_release_shared_rate_budget(self):
        self.enabled()
        self.store.set_meta('github_rate_limit', json.dumps(dict(remaining=0, limit=60,
            reset=(self.clock()+timedelta(hours=1)).isoformat(), observed_at=self.clock().isoformat())))
        self.cycle()
        self.assertEqual(self.opener.requests, [])
        self.assertEqual(self.events(), [])
        self.assertEqual(self.store.connection.execute("SELECT state FROM health WHERE source='releases'").fetchone()[0], 'unhealthy')

    def test_latest_release_own_scheme_and_prefix(self):
        self.enabled()
        watch = self.engine.watches[0]
        from cornicen.versions import Scheme
        self.engine.reload_watches((replace(watch, version='4.2.0-7', scheme=Scheme.DEBIAN,
                                           release_tag_prefix='widget-'),))
        self.response('widget-4.2.0-8')
        self.cycle()
        self.assertEqual(len(self.events()), 1)
        self.engine.reload_watches((replace(watch, scheme=Scheme.OPAQUE),))
        self.cycle(1)
        self.assertEqual(len(self.events()), 1)

    def test_latest_release_upgrade_original_database_no_rematch(self):
        db = self.root / 'original.db'
        # Pinned from v0.1.14 (release-0.1.14 src) for WATCH; that release stored exactly this string.
        v0114_applied = ('[{"eol":false,"id":"widget","match":[["examplecorp","widget"]],'
                         '"name":"Example widget","product_only":[],"scheme":"semver","version":"4.2.0"}]')
        v0114_hash = '67eaa62ec3a3080ee8eef433556b6ad45ca36e9082f40b90043f843ccce09155'
        self.assertEqual(Engine._canonical_watches(load_watchlist_text(WATCH)), v0114_applied)
        seed = Store(str(db)); seed.migrate()
        config = replace(self.config, db_path=str(db))
        writer = Engine(seed, load_watchlist_text(WATCH), self.engine.aliases, config, self.clock, self.notifier)
        record = {'cveMetadata': {'cveId': 'CVE-2099-1000', 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': [{'vendor': 'examplecorp', 'product': 'widget',
                      'versions': [{'version': '4.2.0', 'status': 'affected'}]}]}}}
        writer.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.SNAPSHOT, 'example',
                                       datetime(2099, 6, 7, tzinfo=timezone.utc), (record,))])
        with seed.transaction():
            seed.set_meta('applied_watches', v0114_applied)
            seed.set_meta('applied_watches_hash', v0114_hash)
        seed.connection.close()
        store = Store(str(db)); store.migrate()
        self.addCleanup(store.connection.close)
        pairs = [tuple(r) for r in store.connection.execute('SELECT * FROM pairs')]
        self.assertEqual(len(pairs), 1)
        with patch.object(Engine, 'reload_watches', side_effect=AssertionError('unexpected re-match')):
            statements = []
            store.connection.set_trace_callback(statements.append)
            engine = Engine(store, load_watchlist_text(WATCH), self.engine.aliases, self.config,
                            self.clock, self.notifier)
            store.connection.set_trace_callback(None)
        pair_writes = [sql for sql in statements if sql.lstrip().upper().startswith(('UPDATE PAIRS', 'INSERT INTO PAIRS', 'DELETE FROM PAIRS', 'INSERT OR REPLACE INTO PAIRS'))]
        self.assertEqual(pair_writes, [])
        self.assertEqual([tuple(r) for r in store.connection.execute('SELECT * FROM pairs')], pairs)
        self.assertEqual(engine._pending_report.events, [])
        self.assertNotIn('latest_release', store.get_meta('applied_watches'))
        # Loading older saved JSON during an actual watch edit uses field defaults.
        engine.reload_watches((replace(engine.watches[0], name='Example changed'),))
        Engine(store, load_watchlist_text(WATCH), engine.aliases, self.config, self.clock, self.notifier)

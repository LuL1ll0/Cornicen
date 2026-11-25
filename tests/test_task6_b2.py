"""Exercise offline Synology replay, gated construction, cadence and scale.

Read invented fixtures and write temporary stores. Unittest exits 0/1.
--scale-day DIRECTORY DAY reads DIRECTORY/feed.xml, writes DIRECTORY/state.db
and emits JSON metrics (0 success, 1 failure). Enable the parent scale test
with CORNICEN_SCALE=1. Each measured day runs in a fresh process.
"""

from collections import Counter
from contextlib import contextmanager
from datetime import timedelta
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

from cornicen.adapterfactories import production_factories
from cornicen.adapters import REGISTRY
from cornicen.adapterstore import instant, stamp
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.sources.synology_rss import SynologyRss, SynologyState
from cornicen.store import Store
from tests.replay_v11 import harness as h
from tests.replay_v11.rss_backend import SynologyBackend, rss_body
from tests.source_helpers import peak_rss_bytes


T1, T2, T3, REBASELINE, T4 = ('2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z',
                              '2099-01-04T01:00:00Z', '2099-01-04T02:00:00Z',
                              '2099-01-05T02:00:00Z')
FIRST, THIRD = 'Synology_SA_99_01', 'Synology_SA_99_03'
KEV_ID = 'CVE-2099-81011'
FIXTURE = Path(__file__).parent / 'fixtures/synology/feed_sample.xml'
WATCH = ('[[watch]]\nid="w"\nname="Invented DSM watch"\n'
         'match=["synology:diskstation manager (dsm)"]\nversion="7.9.0-99999"\nscheme="debian"\n')
TRACE = [{'method': 'GET', 'url': 'https://www.synology.com/api/rssfeed/security/en-us',
          'headers': {'User-agent': 'Cornicen/test'}}]
SCALE_N = 5000
REPLAY_TARGETS = {'synology_t1t2': T2, 'synology_t3t4': T4, 'synology_guid_variant': T1}


def item(number):
    members = ET.parse(FIXTURE).findall('channel/item')
    return {el.tag: el.text for el in members[number-1] if el.tag != 'author'}


class Task6B2Tests(unittest.TestCase):
    def backend(self, watch=WATCH):
        backend = SynologyBackend(h.fixture_registry())
        self.addCleanup(backend.close)
        backend.action({'t': T1, 'watchlist': watch})
        return backend

    def replay(self, name):
        result = h.run_scenario(name)
        expected = h.load_expected(name)
        for row in expected:
            h.assert_line(result, row, expected)
        h.assert_notifications(result, expected)
        self.assertNotIn(name, h.scenario_names())
        return result

    def test_t14_first_and_edited_feed(self):
        replay = self.replay('synology_t1t2')
        first, second = (replay.snapshots['main', tick] for tick in (T1, T2))
        self.assertEqual(instant(T2)-instant(T1), timedelta(hours=24))
        eight_cves = [f'CVE-2099-810{n:02d}' for n in (2, 3, 4, 6, 8, 9, 10, 12)]
        identities = {'CVE-2099-81001', *eight_cves, f'advisory:synology:{THIRD}:main'}
        for snap in (first, second):
            self.assertEqual(set(snap['advisory_rows']), {FIRST, THIRD})
            self.assertEqual(snap['event_keys'], ['|baseline:synology|baseline|1'])
            self.assertEqual({row['id'] for row in snap['pairs']}, identities)
            self.assertEqual(len(snap['pairs']), 10)
            self.assertTrue(all(row['state'] == 'unknown' for row in snap['pairs']))
            self.assertEqual(snap['fix'], dict.fromkeys(identities))
            evidence = snap['evidence_rows']
            self.assertEqual({row['identity'] for row in evidence}, identities)
            self.assertEqual(len(evidence), 10)
            self.assertTrue(all(row['range'] is None and row['status'] == 'under_investigation'
                                for row in evidence))
        self.assertNotEqual(first['advisory_rows'][FIRST]['digest'], second['advisory_rows'][FIRST]['digest'])
        self.assertEqual(first['advisory_rows'][THIRD], second['advisory_rows'][THIRD])

    def test_t15_gap_and_rebaseline(self):
        replay = self.replay('synology_t3t4')
        rows = h.load_timeline('synology_t3t4')
        self.assertIn('seed', rows[1])
        self.assertEqual(instant(T3)-instant(T2), timedelta(hours=49))
        self.assertEqual(instant(REBASELINE)-instant(T3), timedelta(hours=1))
        self.assertEqual(instant(T4)-instant(REBASELINE), timedelta(hours=24))
        before, gap, reset, after = (replay.snapshots['main', t] for t in (T2, T3, REBASELINE, T4))
        self.assertEqual(before['retention_summary']['boundary'], [THIRD])
        t3_items = next(row['rss']['items'] for row in rows if row['t'] == T3 and 'rss' in row)
        self.assertLessEqual(set(before['retention_summary']['ids']),
                             {item['guid'].rsplit('/', 1)[1] for item in t3_items})
        self.assertEqual(gap['retention_summary']['observed_at'], T2)
        self.assertEqual(gap['retention_summary']['newest'], '2026-10-29T13:12:54Z')
        self.assertEqual(reset['retention_summary']['observed_at'], T3)
        self.assertEqual(reset['retention_summary']['newest'], '2026-10-31T01:00:00Z')
        pending, = after['outbox']
        self.assertGreater(instant(pending['due_at']), max(instant(row['t']) for row in rows))
        self.assertEqual(len(before['events']), 2)

    def test_t16_conflicting_guid(self):
        replay = self.replay('synology_guid_variant')
        rows = h.load_timeline('synology_guid_variant')
        first, second = rows[1]['rss']['items']
        self.assertEqual({k for k in first if first[k] != second[k]}, {'guid'})
        self.assertEqual(list(first), list(second))
        self.assertEqual(replay.snapshots['main', T1]['requests'], 1)

    def test_t17_boundary_bodies(self):
        for broken in ('html', 'empty', 'malformed'):
            with self.subTest(body=broken):
                name = 'synology_boundary_'+broken
                self.assertEqual(h.load_timeline(name)[1]['rss'], {'broken': broken})
                result = self.replay(name)
                before_restart = result.snapshots['main', T1]
                after_restart = result.snapshots['main', T1, 'after_restart']
                retry, = after_restart['retry_detail']
                self.assertEqual(before_restart['retry_detail'], [retry])
                self.assertEqual(retry['attempts'], 1)
                self.assertGreater(instant(retry['next_attempt_at']), instant(T1))

    def test_t18_kev_interplay(self):
        for listed, bootstrapping in ((True, False), (False, False), (True, True)):
            with self.subTest(listed=listed, bootstrapping=bootstrapping):
                backend = self.backend()
                store = backend.store
                if not bootstrapping:
                    backend.action({'t': T1, 'seed': {'v1_baseline_complete': True}})
                    self.poll(backend, T1, [item(1)])
                    self.assertEqual(backend.observed['classification'], {'synology': 'COMPLETE'})
                    self.assertTrue(backend.snapshot()['baseline']['synology']['complete'])
                self.assertIsNone(store.get_meta('kev_initialized'))
                payload = {KEV_ID: {'cveID': KEV_ID}} if listed else {}
                backend.engine._health_verdicts = {}
                with store.transaction():
                    backend.engine._ingest(IngestResult('kev', FetchStatus.COMPLETE, Origin.SNAPSHOT, None, instant(T1), kev=payload))
                self.assertEqual(store.get_meta('kev_initialized'), '1')
                self.assertEqual(bool(store.connection.execute('SELECT 1 FROM kev WHERE cve=?', (KEV_ID,)).fetchone()), listed)
                self.assertEqual(bool(store.get_meta('baseline_complete')), not bootstrapping)
                self.assertEqual(bool(backend.snapshot()['baseline'].get('synology', {}).get('complete')), not bootstrapping)
                self.assertFalse(store.connection.execute('SELECT 1 FROM pairs WHERE record_id=?', (KEV_ID,)).fetchone())
                self.assertEqual([n for n in backend.sent if n['watch']], [])
                self.poll(backend, T2, [item(1), item(11)])
                self.assertEqual(backend.observed['classification'], {'synology': 'COMPLETE'})
                pair = store.connection.execute(
                    'SELECT state,exploited FROM pairs WHERE watch_id=? AND record_id=?', ('w', KEV_ID)).fetchone()
                self.assertEqual(tuple(pair), ('unknown', int(listed)))
                deliveries = [n for n in backend.sent if n['watch']]
                if listed and not bootstrapping:
                    self.assertEqual([(n['watch'], n['record'], n['urgency']) for n in deliveries],
                                     [('w', KEV_ID, 'urgent')])
                else:
                    self.assertEqual(deliveries, [])

    def test_t19_crash_replay(self):
        def logical_deliveries(result):
            return Counter((n['watch'], n['record'], tuple(n['reasons']), n['urgency'])
                           for n in result.result.notifications)

        def logical_events(snapshot):
            # Process loss can omit a health transition and shift the subsequent
            # health episode. Compare logical health events without renumbering watch keys.
            return Counter(key.rsplit('|', 1)[0]
                           if key.startswith(('|synology|healthy|', '|synology|unhealthy|'))
                           else key for key in snapshot['event_keys'])

        counts = {}
        for name, last_target in REPLAY_TARGETS.items():
            baseline = h.run_crash_scenario(name)
            checkpoints = [row['t'] for row in h.load_timeline(name) if 'cycle' in row]
            selected = [(i, p, tick) for i, (p, tick) in enumerate(zip(baseline.points, baseline.point_ticks))
                        if tick <= last_target]
            kinds = {(p.split(':')[0], p.rsplit(':', 1)[1]) for _, p, _ in selected}
            counts[name] = len(selected)
            staged_crashes = 0
            uninterrupted_deliveries = logical_deliveries(baseline)
            final_key = ('main', checkpoints[-1])
            uninterrupted_events = logical_events(baseline.result.snapshots[final_key])
            for index, point, tick in selected:
                with self.subTest(scenario=name, index=index, point=point):
                    replay = h.run_crash_scenario(name, index)
                    self.assertTrue(replay.crashed)
                    if point.startswith('synology_stage_members:') and point.endswith(':after'):
                        self.assertGreater(replay.survived_stages, 0)
                        staged_crashes += 1
                    # Task 4's T21 compares watch deliveries and non-health events.
                    self.assertEqual(replay.deliveries, baseline.deliveries)
                    self.assertFalse(logical_deliveries(replay) - uninterrupted_deliveries)
                    self.assertFalse(logical_events(replay.result.snapshots[final_key]) - uninterrupted_events)
                    for key, snapshot in replay.result.snapshots.items():
                        expected = baseline.result.snapshots[key]
                        self.assertEqual(snapshot['events'], expected['events'])
                        new_keys = set(snapshot['event_keys']) - set(expected['event_keys'])
                        self.assertFalse({k for k in new_keys if '|baseline|' in k})
                    next_poll = next(t for t in checkpoints if t > tick)
                    expected = baseline.result.snapshots['main', next_poll]
                    actual = replay.result.snapshots['main', next_poll]
                    for field in ('advisory_rows', 'evidence_rows', 'manifests', 'cursor',
                                  'manifest_rows', 'retention_summary', 'dimensions'):
                        self.assertEqual(actual[field], expected[field], field)
            self.assertGreater(staged_crashes, 0, name)
            required = {'stage_members', 'observe_build', 'commit_staged'}
            if name == 'synology_t1t2':
                required.add('_accept_batch')
            elif name == 'synology_t3t4':
                required.update(('_accept_batch', 'gap', 'retry'))
            else:
                required.update(('quarantine', 'retry'))
            expected = {('synology_'+kind, side) for kind in required for side in ('before', 'after')}
            self.assertFalse(expected - kinds, (name, expected - kinds))
        print('Synology crash boundaries:', counts)

    @unittest.skipUnless(os.environ.get('CORNICEN_SCALE') == '1', 'opt-in scale')
    def test_t20_scale(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            directory = Path(temporary)
            prepare_scale(directory)
            metrics = []
            for day in (1, 2):
                child = subprocess.run([sys.executable, '-m', 'tests.test_task6_b2',
                                        '--scale-day', temporary, str(day)], capture_output=True, text=True)
                self.assertEqual(child.returncode, 0, child.stderr)
                metrics.append(json.loads(child.stdout))
        print('Synology T20:', json.dumps(metrics, sort_keys=True), flush=True)
        for result in metrics:
            self.assertEqual(result['classification'], {'synology': 'COMPLETE'})
            self.assertEqual(result['accepted'], SCALE_N)
            self.assertEqual(result['members'], SCALE_N)
            self.assertEqual(result['evidence'], 2*SCALE_N)
            self.assertLessEqual(result['rss_bytes'], 256*1024**2)
        self.assertLessEqual(metrics[0]['transactions'], 3*SCALE_N+100)
        self.assertLessEqual(metrics[1]['transactions'], SCALE_N+100)

    def test_t21_factory_request_watch_independence(self):
        for watch in (WATCH, h.WATCHLIST.replace('1.0.0', '7.9.0-99999').replace('semver', 'debian')):
            with self.subTest(watch=watch):
                backend = self.backend(watch)
                factory = Mock(wraps=backend.server.http)
                factories = production_factories(backend.engine, http_factory=factory)
                self.assertEqual(REGISTRY['synology'].gate, 'not met')
                self.assertIn('synology', factories)
                factory.assert_not_called()
                closure = Mock(wraps=factories['synology'])
                outcomes = backend.engine.dispatch_adapters(registry={'synology': REGISTRY['synology']},
                                                            factories={'synology': closure})
                closure.assert_not_called()
                factory.assert_not_called()
                self.assertEqual(outcomes, {})

                adapter = factories['synology']()
                factory.assert_called_once_with()
                self.assertIsInstance(adapter, SynologyRss)
                self.assertIsInstance(adapter.state, SynologyState)
                self.assertIs(adapter.state.store, backend.store)
                self.assertEqual(adapter.clock, backend.engine._now)
                self.assertIsNone(adapter.retention_hours)
                self.assertEqual(adapter.interval, timedelta(hours=24))
                backend.server.add(0, {'items': [item(1)]})
                self.assertEqual(adapter.poll()[0]['status'], 200)
                trace = [{key: req[key] for key in ('method', 'url', 'headers')}
                         for req in backend.server.requests]
                self.assertEqual(trace, TRACE)

    def test_hourly_dispatch_cadence(self):
        backend = self.backend()
        start = instant(T1)
        ticks = []
        hourly = timedelta(hours=1)
        feed = [item(1)]
        for hour in range(4*24):
            tick = stamp(start + hour*hourly)
            before = len(backend.server.requests)
            self.poll(backend, tick, feed)
            self.assertEqual(backend.observed['classification'], {'synology': 'COMPLETE'})
            if len(backend.server.requests) > before:
                ticks.append(hour)
        self.assertEqual(len(ticks), 4, ticks)
        self.assertEqual(ticks[0], 0)
        self.assertTrue(all(b-a == 24 for a, b in zip(ticks, ticks[1:])), ticks)
        self.assertEqual(backend.snapshot()['gaps'], [])
        self.assertEqual(backend.snapshot()['cursor']['synology']['tick'], stamp(start + ticks[-1]*hourly))

    def test_replay_harness_contracts(self):
        path = Path(__file__).parent / 'replay_v11/test-rss-backend.py'
        spec = importlib.util.spec_from_file_location('test_rss_backend', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromModule(module).run(result)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)

    @staticmethod
    def poll(backend, tick, items):
        backend.action({'t': tick, 'rss': {'items': items}})
        backend.action({'t': tick, 'cycle': True})


def prepare_scale(directory):
    items = []
    for n in range(SCALE_N):
        identity = f'Synology_SA_99_{n:02d}'
        link = f'https://www.synology.com/en-us/support/security/{identity}'
        description = (f'CVE-2099-{900000+n} allows a user to read data via a susceptible version of '
                       'DSM and Photo Station. Invented padding follows. ')
        description += 'x' * (1024 - len(description))
        items.append(dict(guid=link, link=link, title=f'Invented notice {identity}',
                          description=description, pubDate='Thu, 29 Oct 2026 21:12:54 +0800'))
    (directory / 'feed.xml').write_bytes(rss_body(items))


def scale_day(directory, day):
    from dataclasses import replace
    from cornicen.config import Config
    from cornicen.engine import Engine
    from cornicen.fetch import Http
    from cornicen.identity import AliasMap
    from tests.replay.harness import FakeClock, RecordingNotifier
    from tests.source_helpers import public_resolver

    path = directory / 'state.db'
    prior_size = path.stat().st_size if path.exists() else 0
    store = Store(path)
    store.migrate()
    tick = instant(T1) + timedelta(days=day-1)
    clock = FakeClock(tick)
    config = Config(path, directory / 'unused', None, 'https://examplecorp.invalid', 'test', None)
    config.adapters['synology'] = True
    engine = Engine(store, (), AliasMap.load(False), config, clock, RecordingNotifier(clock))
    registry = {'synology': replace(REGISTRY['synology'], gate='met')}

    def open_feed(request, timeout):
        assert request.get_method() == 'GET' and request.full_url == TRACE[0]['url']
        response = (directory / 'feed.xml').open('rb')
        response.status, response.headers = 200, {'content-type': 'text/xml'}
        return response

    def factory():
        return SynologyRss(Http('Cornicen/test', {}, opener=open_feed, resolver=public_resolver,
                               data_dir=directory), SynologyState(store), engine._now, retention_hours=48)

    entries = 0
    transaction = Store.transaction

    @contextmanager
    def count_transaction(instance):
        nonlocal entries
        with transaction(instance) as db:
            entries += 1
            yield db

    with patch.object(Store, 'transaction', count_transaction):
        classification = engine.dispatch_adapters(registry=registry, factories={'synology': factory})
    assert store.connection.execute("SELECT cursor_tick FROM adapter_state WHERE source='synology'").fetchone()[0] == stamp(tick)
    metrics = dict(classification=classification, transactions=entries, rss_bytes=peak_rss_bytes(),
                   accepted=store.connection.execute('SELECT count(*) FROM manifest_members').fetchone()[0],
                   members=store.connection.execute('SELECT count(*) FROM advisories').fetchone()[0],
                   evidence=store.connection.execute('SELECT count(*) FROM advisory_evidence').fetchone()[0])
    store.connection.close()
    return metrics | dict(db_growth_bytes=path.stat().st_size-prior_size)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--scale-day' and sys.argv[3] in ('1', '2'):
        print(json.dumps(scale_day(Path(sys.argv[2]), int(sys.argv[3]))))
    else:
        unittest.main()

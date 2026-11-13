# script-purpose: Check persistent EPSS crossings with invented offline fixtures.
# script-class: harness
# script-trigger: Run python3 -m unittest tests.test_epss_crossing.
# script-tests: tests/test_epss_crossing.py
"""Read application code; write temporary SQLite fixtures under .build.
Unittest exits 0 on success and 1 on failure. No network is used.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone, date
from pathlib import Path
import tempfile
import unittest

from cornicen.accept import Accept
from cornicen.config import Config, load_config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.render import render
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text
from tests.replay.harness import FakeClock, RecordingNotifier


CVE = 'CVE-2099-81001'


class EpssCrossingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.build')
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / 'crossing.db')
        self.clock = FakeClock(datetime(2099, 6, 1, 7, tzinfo=timezone.utc))
        self.notifier = RecordingNotifier(self.clock)
        self.config = Config(self.path, Path('unused'), None, 'https://alerts.invalid', 'fiction', None)
        self.watches = load_watchlist_text('''[[watch]]
id = "widget"
name = "Fictional widget"
match = ["fictional:widget"]
version = "81.82.83"
scheme = "semver"
''')
        self.record = {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'},
                       'containers': {'cna': {'affected': [{'vendor': 'fictional', 'product': 'widget',
                           'versions': [{'version': '81.82.83', 'status': 'affected'}]}]}}}
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.connection.close())
        self.store.migrate()
        self.store.set_meta('baseline_complete', '1')
        self.restart()

    def restart(self):
        self.engine = Engine(self.store, self.watches, AliasMap.load(False), self.config,
                             self.clock, self.notifier)

    def record_cycle(self):
        self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                               None, self.clock(), (deepcopy(self.record),))])

    def scores(self, score):
        self.engine.run_cycle([IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
            self.clock().date().isoformat(), self.clock(), epss={CVE: (score, .91)},
            epss_date=self.clock().date())])

    def delivered_low(self):
        self.scores(.02)
        self.record_cycle()
        self.clock.now += timedelta(hours=2)
        self.engine.run_cycle([])
        self.assertEqual(self.store.connection.execute('SELECT notified FROM pairs').fetchone()[0], 1)
        self.notifier.delivered.clear()

    def crossings(self):
        return [n for n in self.notifier.delivered if 'epss_crossed' in n['reasons']]

    def assert_state(self, fired):
        row = self.store.connection.execute('SELECT fired FROM epss_crossings').fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], fired)

    def event_count(self):
        return self.store.connection.execute(
            "SELECT count(*) FROM events WHERE type='epss_crossed'").fetchone()[0]

    def test_epss_crossing_r2_incomplete_neither_fires_nor_rearms(self):
        self.delivered_low()
        for status, errors in ((FetchStatus.PARTIAL, ()),
                               (FetchStatus.COMPLETE, ('Incomplete invented file',))):
            with self.subTest(status=status, errors=errors):
                self.engine.run_cycle([IngestResult('epss', status, Origin.SCORES,
                    None, self.clock(), epss={CVE: (.2, .91)}, errors=errors)])
                self.assertEqual(self.event_count(), 0)
                self.assert_state(0)
        self.scores(.2)
        for status, errors in ((FetchStatus.PARTIAL, ()),
                               (FetchStatus.COMPLETE, ('Incomplete invented file',))):
            self.engine.run_cycle([IngestResult('epss', status, Origin.SCORES,
                None, self.clock(), epss={CVE: (.01, .91)}, errors=errors)])
            self.restart()
            self.assert_state(1)
        self.scores(.2)
        self.assertEqual(self.event_count(), 1)

    def test_epss_crossing_r2_partial_cannot_seed_initialization(self):
        self.engine.run_cycle([IngestResult('epss', FetchStatus.PARTIAL, Origin.SCORES,
            None, self.clock(), epss={CVE: (.2, .91)})])
        self.restart()
        self.record_cycle()
        self.assert_state(None)
        self.scores(.02)
        self.assert_state(0)
        self.clock.now += timedelta(hours=2)
        self.engine.run_cycle([])
        self.scores(.2)
        self.assertEqual(self.event_count(), 1)

    def config_change_cases(self, threshold, ratio, cases):
        self.delivered_low()
        for initial, score, expected in cases:
            with self.subTest(initial=initial, score=score):
                self.engine.config = self.config
                self.scores(.01)
                if initial:
                    self.scores(.2)
                self.scores(score)
                before = self.event_count()
                self.config = replace(self.config, epss_threshold=threshold, epss_rearm_ratio=ratio)
                self.engine.config = self.config
                self.restart()
                self.assertEqual(self.event_count(), before)
                self.assert_state(expected)
                self.scores(score)
                self.assertEqual(self.event_count(), before)
                self.assert_state(expected)
                self.restart()
                row = self.store.connection.execute('SELECT threshold,rearm_ratio FROM epss_crossings').fetchone()
                self.assertEqual(tuple(row), (threshold, ratio))
                self.scores(.001)
                self.scores(threshold)
                self.assertEqual(self.event_count(), before + 1)
                self.config = replace(self.config, epss_threshold=.1, epss_rearm_ratio=.8)

    def test_epss_crossing_r2_raise_threshold_both_sides(self):
        self.config_change_cases(.5, .8, ((1, .2, 0), (1, .45, 1), (0, .6, 1)))

    def test_epss_crossing_r2_lower_threshold_both_sides(self):
        self.config_change_cases(.08, .8, ((0, .09, 1), (1, .06, 0), (0, .07, 0), (1, .085, 1)))

    def test_epss_crossing_r2_change_ratio_both_sides(self):
        self.config_change_cases(.1, .9, ((1, .085, 0), (1, .09, 1), (0, .095, 0), (1, .12, 1)))
        self.config_change_cases(.1, .7, ((1, .09, 1), (0, .075, 0), (1, .06, 0), (1, .12, 1)))

    def test_epss_crossing_r2_unknown_never_creates_event(self):
        self.delivered_low()
        self.store.connection.execute("UPDATE pairs SET state='unknown'")
        self.scores(.2)
        self.assertEqual(self.event_count(), 0)
        self.assertEqual(self.crossings(), [])

    def test_epss_crossing_hysteresis_once_and_rearm(self):
        self.delivered_low()
        for score, count, fired in ((.10, 1, 1), (.15, 1, 1), (.09, 1, 1),
                                    (.08, 1, 1), (.079, 1, 0), (.10, 2, 1)):
            self.scores(score)
            self.assertEqual(len(self.crossings()), count)
            self.assert_state(fired)
        n = self.crossings()[0]
        self.assertEqual(n['urgency'], 'urgent')
        from cornicen.model import Notification
        import json
        row = self.store.connection.execute("SELECT * FROM outbox WHERE reasons_json LIKE '%epss_crossed%' ORDER BY id LIMIT 1").fetchone()
        text = render(Notification(str(row['id']), n['watch'], n['record'], tuple(n['reasons']),
                                   n['urgency'], json.loads(row['body_json'])))[1]
        self.assertIn('EPSS threshold crossed: ' + CVE, text)
        self.assertIn('Match:', text)

    def test_epss_crossing_same_file_and_restart(self):
        self.delivered_low()
        self.scores(.12)
        self.store.connection.close()
        self.store = Store(self.path)
        self.store.migrate()
        self.restart()
        self.scores(.12)
        self.assertEqual(len(self.crossings()), 1)
        self.assert_state(1)

    def test_epss_crossing_upgrade_high_silent(self):
        self.delivered_low()
        self.store.connection.execute('UPDATE epss SET score=.2')
        self.store.connection.execute('DROP TABLE IF EXISTS epss_crossings')
        self.store.migrate()
        self.restart()
        self.scores(.2)
        self.assertEqual(self.crossings(), [])
        self.assert_state(1)
        self.scores(.01)
        self.scores(.2)
        self.assertEqual(len(self.crossings()), 1)

    def test_epss_crossing_excluded_pairs(self):
        self.delivered_low()
        for excluded in ('unknown', 'suppressed', 'accepted', 'kev', 'ssvc', 'undelivered'):
            with self.subTest(excluded=excluded):
                self.scores(.01)
                self.store.connection.execute("UPDATE pairs SET state='affected', notified=1")
                self.engine.accepts = ()
                self.store.connection.execute('DELETE FROM kev')
                record = deepcopy(self.record)
                if excluded in ('unknown', 'suppressed'):
                    self.store.connection.execute('UPDATE pairs SET state=?',
                        ('unknown' if excluded == 'unknown' else 'not_affected',))
                elif excluded == 'accepted':
                    self.engine.accepts = (Accept(CVE, 'widget', 'fictional decision', date(2099, 7, 1), False, None, 1),)
                elif excluded == 'kev':
                    self.store.connection.execute('INSERT INTO kev VALUES (?,?)', (CVE, '{}'))
                elif excluded == 'undelivered':
                    self.store.connection.execute('UPDATE pairs SET notified=0')
                else:
                    record['containers']['adp'] = [{'providerMetadata': {'shortName': 'CISA-ADP'},
                        'metrics': [{'other': {'type': 'ssvc', 'content': {'options': [{'Exploitation': 'active'}]}}}]}]
                self.store.put_record(CVE, record, self.clock().isoformat())
                self.scores(.2)
                self.assertEqual(self.crossings(), [])
                self.assert_state(1)

    def test_epss_crossing_disabled(self):
        self.delivered_low()
        self.engine.config = replace(self.config, epss_crossing=False)
        self.scores(.2)
        self.assertEqual(self.crossings(), [])
        self.assert_state(1)

    def test_epss_crossing_high_initial_delivery(self):
        self.scores(.2)
        self.record_cycle()
        self.assert_state(1)
        self.scores(.21)
        self.assertEqual(self.crossings(), [])
        self.scores(.01)
        self.scores(.2)
        self.assertEqual(len(self.crossings()), 1)

    def test_epss_crossing_clear_reopen(self):
        self.delivered_low()
        self.scores(.2)
        self.record['containers']['cna']['affected'][0]['versions'][0]['status'] = 'unaffected'
        self.record_cycle()
        self.scores(.01)
        self.record['containers']['cna']['affected'][0]['versions'][0]['status'] = 'affected'
        self.record_cycle()
        self.clock.now += timedelta(days=1)
        self.engine.run_cycle([])
        self.scores(.2)
        self.assertEqual(len(self.crossings()), 2)

    def test_epss_crossing_retry_coalesces_and_disable_drops_pending(self):
        self.delivered_low()
        self.notifier.down = True
        self.scores(.2)
        self.assert_state(1)
        self.scores(.01)
        self.scores(.2)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM outbox WHERE sent_at IS NULL AND pair_key='widget|' || ?", (CVE,)).fetchone()[0], 1)
        self.clock.now += timedelta(hours=2)
        self.notifier.down = False
        self.engine.run_cycle([])
        self.assertEqual(len(self.crossings()), 1)
        self.notifier.down = True
        self.scores(.01)
        self.scores(.2)
        self.engine.config = replace(self.config, epss_crossing=False)
        self.notifier.down = False
        self.clock.now += timedelta(hours=2)
        self.engine.run_cycle([])
        self.assertEqual(len(self.crossings()), 1)

    def test_epss_crossing_actual_file_repeated(self):
        import gzip
        from types import SimpleNamespace
        from cornicen.sources.epss import EpssSource
        self.delivered_low()
        root = Path(self.directory.name)
        body = gzip.compress(('#model_version:fiction,score_date:2099-06-01\n'
                              'cve,epss,percentile\n' + CVE + ',0.2,0.91\n').encode())
        class Transport:
            data_dir = root
            def get(inner, *args, **kwargs):
                path = root / 'scores.gz'
                path.write_bytes(body)
                return SimpleNamespace(status=200, path=path)
        source = EpssSource(Transport(), self.store)
        for _ in range(2):
            ingests = source.poll(self.clock())
            self.assertEqual(ingests[0].status, FetchStatus.COMPLETE)
            self.engine.run_cycle(ingests)
        self.assertEqual(len(self.crossings()), 1)

    def test_epss_crossing_first_observed_score_silent(self):
        self.record_cycle()
        self.clock.now += timedelta(hours=2)
        self.engine.run_cycle([])
        self.notifier.delivered.clear()
        self.scores(.2)
        self.assertEqual(self.crossings(), [])
        self.assert_state(1)
        self.scores(.01)
        self.scores(.2)
        self.assertEqual(len(self.crossings()), 1)

    def test_epss_crossing_acceptance_added_before_retry(self):
        self.delivered_low()
        self.notifier.down = True
        self.scores(.2)
        self.assert_state(1)
        self.engine.accepts = (Accept(CVE, 'widget', 'fictional decision', date(2099, 7, 1), False, None, 1),)
        self.notifier.down = False
        self.clock.now += timedelta(hours=2)
        self.engine.run_cycle([])
        self.assertEqual(self.crossings(), [])
        self.assertEqual(self.store.connection.execute(
            'SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0], 0)

    def test_epss_crossing_config_ratio_validation(self):
        path = Path(self.directory.name) / 'config.toml'
        path.write_text('epss_rearm_ratio = 0.75\nepss_crossing = false\n')
        config = load_config(path, {})
        self.assertEqual(config.epss_rearm_ratio, .75)
        self.assertFalse(config.epss_crossing)
        path.write_text('')
        config = load_config(path, {})
        self.assertEqual(config.epss_rearm_ratio, .8)
        self.assertTrue(config.epss_crossing)
        for value in ('0', '1', '-0.5', '"private-canary"', 'true', 'nan', 'inf'):
            path.write_text('epss_rearm_ratio = ' + value)
            with self.assertRaises(ValueError) as caught:
                load_config(path, {})
            self.assertEqual(str(caught.exception), 'epss_rearm_ratio must be greater than 0 and less than 1')
        path.write_text('epss_crossing = "private-canary"')
        with self.assertRaisesRegex(ValueError, '^epss_crossing must be a boolean$'):
            load_config(path, {})

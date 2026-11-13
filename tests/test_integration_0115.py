# script-purpose: Verify the seams between the v0.1.15 lanes (EPSS polling x crossings, upgrade start x release fields, webhook secrets x command errors).
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_integration_0115.py
"""Seams between the 0.1.15 lanes.

Reads local fixtures, writes temporary files under .build, and uses no network.
Run with python -m unittest tests.test_integration_0115. Exit 0 means success,
1 means failed tests, and 2 means invalid unittest arguments.
"""

from dataclasses import replace
from datetime import timedelta
import gzip
import unittest
from unittest.mock import Mock, patch

from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.scheduler import Scheduler
from cornicen.sources.epss import EpssSource
from cornicen.watchlist import load_watchlist_text
from tests import test_cli_private_errors as cli_fixtures
from tests import test_epss_crossing as crossing_fixtures
from tests import test_latest_releases as release_fixtures
from tests.source_helpers import Opener, public_resolver

EPSS_URL = 'https://scores.invalid/epss_scores-current.csv.gz'


class EpssPollingMeetsCrossings(unittest.TestCase):
    """Lane A polls hourly while the score date is behind; lane B must fire once."""
    setUp = crossing_fixtures.EpssCrossingTests.setUp
    restart = crossing_fixtures.EpssCrossingTests.restart
    record_cycle = crossing_fixtures.EpssCrossingTests.record_cycle
    scores = crossing_fixtures.EpssCrossingTests.scores
    delivered_low = crossing_fixtures.EpssCrossingTests.delivered_low
    crossings = crossing_fixtures.EpssCrossingTests.crossings

    def test_hourly_repolls_of_one_file_fire_one_crossing(self):
        for mocked in (patch('cornicen.sources.epss.URL', EPSS_URL),
                       patch.dict('cornicen.fetch.SOURCE_HOSTS', {'epss': frozenset({'scores.invalid'})})):
            mocked.start()
            self.addCleanup(mocked.stop)
        self.delivered_low()
        stored = self.clock().date()
        owner, calls = self, []

        class Published:
            def open(self, request, timeout=None):
                now = owner.clock()
                day = now.date() if (now.hour, now.minute) >= (13, 30) else now.date() - timedelta(days=1)
                day = max(day, stored)
                calls.append(now)
                body = gzip.compress((f'#model_version:fictional,score_date:{day}T12:00:00Z\n'
                                      f'cve,epss,percentile\n{crossing_fixtures.CVE},0.5,0.99\n').encode())
                return Opener({EPSS_URL: body}).open(request, timeout)

        epss = EpssSource(Http('fictional', {}, Published(), resolver=public_resolver), self.store)
        sources = {'epss': epss, 'cvelist': Mock(), 'kev': Mock()}
        sources['cvelist'].poll.return_value = []
        sources['kev'].poll.return_value = []
        scheduler = Scheduler(self.engine, sources, self.clock, lambda line: None,
                              monotonic=lambda: self.clock().timestamp())
        self.clock.now = self.clock.now.replace(hour=0, minute=0) + timedelta(days=1)
        for _ in range(48):
            scheduler.tick()
            self.clock.now += timedelta(hours=1)
        self.assertGreater(len(calls), 3)  # hourly re-polls of the same file did happen
        self.assertEqual(len(self.crossings()), 1)


class UpgradeStartMeetsReleaseFields(unittest.TestCase):
    """Lane A's missing-meta path and lane D's new watch fields on one start."""
    setUp = release_fixtures.LatestReleaseTests.setUp
    enabled = release_fixtures.LatestReleaseTests.enabled
    response = release_fixtures.LatestReleaseTests.response
    retained_cve = release_fixtures.LatestReleaseTests.retained_cve

    def test_missing_applied_watches_keeps_pairs_of_watch_with_release_field(self):
        self.enabled()
        self.engine.run_cycle([self.retained_cve()])
        before = [tuple(r) for r in self.store.connection.execute('SELECT watch_id, record_id, state FROM pairs')]
        self.assertTrue(before)
        with self.store.transaction():
            self.store.connection.execute("DELETE FROM meta WHERE k IN ('applied_watches','applied_watches_hash')")
        events_before = self.store.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        engine = Engine(self.store, self.engine.watches, self.engine.aliases, self.config, self.clock, self.notifier)
        after = [tuple(r) for r in self.store.connection.execute('SELECT watch_id, record_id, state FROM pairs')]
        self.assertEqual(after, before)
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0], events_before)
        self.assertIn('latest_release', self.store.get_meta('applied_watches'))
        # A second start with the same file is not a watch edit.
        with patch.object(Engine, 'reload_watches', side_effect=AssertionError('unexpected re-match')):
            Engine(self.store, engine.watches, engine.aliases, self.config, self.clock, self.notifier)

    def test_release_only_edit_after_upgrade_does_not_rematch(self):
        self.enabled()
        watch = self.engine.watches[0]
        self.engine.run_cycle([self.retained_cve()])
        # _rematch_record runs inside _isolated, which would swallow a raise; count calls instead.
        with patch.object(Engine, '_rematch_record', autospec=True) as rematch:
            self.engine.reload_watches((replace(watch, latest_release=None),))
            self.engine.reload_watches((watch,))
        self.assertEqual(rematch.call_count, 0)


WEBHOOK_URL = 'https://hookseam.invalid/vaultroute2099/complete?k=webhookquery2099'
WEBHOOK_SECRET = 'invented-seam-secret'
DEADMAN_URL = 'https://pingseam.invalid/deadroute2099/complete?k=deadquery2099'
PARTS = ('hookseam.invalid', 'vaultroute2099', 'webhookquery2099', WEBHOOK_URL, WEBHOOK_SECRET,
         'pingseam.invalid', 'deadroute2099', 'deadquery2099', DEADMAN_URL)
ENV = {'CORNICEN_WEBHOOK_URL': WEBHOOK_URL, 'CORNICEN_WEBHOOK_SECRET': WEBHOOK_SECRET,
       'CORNICEN_DEADMAN_URL': DEADMAN_URL}


class WebhookSecretsMeetCommandErrors(unittest.TestCase):
    """Lane C's two secrets and 0.1.14's dead-man URL never print on an error path."""
    setUp = cli_fixtures.PrivateCommandErrors.setUp
    invoke = cli_fixtures.PrivateCommandErrors.invoke

    def assert_private(self, output):
        for part in PARTS:
            self.assertNotIn(part, output)

    def test_config_error_with_all_secrets_set(self):
        self.config.write_text(self.settings + 'notifier = "webhook"\nnot_a_key = 1\n')
        code, output = self.invoke(('healthcheck',), ENV)
        self.assertEqual(code, 1)
        self.assert_private(output)

    def test_store_error_quoting_every_secret(self):
        message = ' '.join(PARTS)
        self.config.write_text(self.settings + 'notifier = "webhook"\n')
        for command in (('healthcheck',), ('status',), ('report',)):
            with self.subTest(command=command):
                with patch('cornicen.cli.Store', side_effect=RuntimeError('Cannot reach ' + message)):
                    code, output = self.invoke(command, ENV)
                self.assertEqual(code, 1)
                self.assertIn('command failed', output)
                self.assert_private(output)

    def test_alias_error_with_webhook_notifier(self):
        self.alias.write_text('version = \n')
        self.config.write_text(self.settings + f'notifier = "webhook"\naliases_path="{self.alias}"\n')
        code, output = self.invoke(('run',), ENV)
        self.assertEqual(code, 1)
        self.assert_private(output)


if __name__ == '__main__':
    unittest.main()

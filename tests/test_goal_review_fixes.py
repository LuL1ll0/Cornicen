"""Regression tests for the five final-review findings."""
from dataclasses import replace
from datetime import timedelta
from http.client import HTTPResponse
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from cornicen.engine import Engine
from cornicen.fetch import Http, _Deadline
from cornicen.model import FetchStatus
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource
from cornicen.sources.kev import KevSource
from tests import test_goal_found_bugs as helpers
from tests.test_goal_found_bugs import record, kev, CVE, OTHER


def copy_body(body, declared):
    stream = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                        str(declared).encode() + b'\r\n\r\n' + body)
    with HTTPResponse(Mock(makefile=Mock(return_value=stream))) as response:
        response.begin()
        target = io.BytesIO()
        Http._copy(response, target, 1000, _Deadline(5, lambda: 0))
        return target.getvalue()


class ReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.h = helpers.GoalFoundBugs()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        blocker = patch('socket.create_connection', side_effect=AssertionError('network'))
        mocked = blocker.start()
        self.addCleanup(blocker.stop)
        self.addCleanup(mocked.assert_not_called)

    def test_review1_real_exclusion_after_kev_only_resolution_must_correct(self):
        for delivered in (False, True):
            with self.subTest(resolution_delivered=delivered):
                h = helpers.GoalFoundBugs()
                h.setUp()
                self.addCleanup(h.doCleanups)
                h.engine.run_cycle([h.catalog([kev()])])
                h.engine.run_cycle([h.ingest(record())])
                if delivered:
                    h.now = h.now.replace(hour=8)
                    h.engine.run_cycle([])
                h.engine.run_cycle([h.ingest(record('unaffected'))])
                h.now = h.now + timedelta(days=1)
                h.engine.run_cycle([])
                states = [item['body']['state'] for notification in h.sent
                          for item in notification.body.get('items', [])]
                self.assertEqual(h.pair()['state'], 'not_affected')
                self.assertEqual(states, ['affected', 'not_affected'] if delivered else ['not_affected'],
                                 'A later exclusion must replace or follow the affected correction')

    def test_review2_repeated_initial_catalog_must_not_hide_later_delta(self):
        h = self.h
        h.store.connection.execute("DELETE FROM meta WHERE k IN ('baseline_complete','kev_initialized')")
        h.store.set_meta('cvelist_snapshot_complete', '1')
        h.engine.run_cycle([h.catalog([kev()])])
        self.assertIsNone(h.pair())
        h.store.set_meta('baseline_complete', '1')
        h.engine = Engine(h.store, (h.watch,), h.engine.aliases, h.config,
                          lambda: h.now, h.notifier)
        h.engine.run_cycle([h.catalog([kev()])])
        self.assertIsNone(h.pair())
        self.assertEqual(h.store.get_meta('kev_baseline:' + CVE), '1')
        h.engine.run_cycle([h.ingest(record())])
        h.now = h.now.replace(hour=8)
        h.engine.run_cycle([])
        self.assertEqual([n.reasons for n in h.watch_notifications()], [('new match',)],
                         'Repeating the first catalog must preserve its later-delta behavior')

    def test_review3_truncated_kev_must_not_abort_other_source_ingests(self):
        h = self.h
        http = Mock(data_dir=h.directory)
        http.get.side_effect = lambda *a, **k: copy_body(b'{}', 100)
        cvelist, epss = Mock(), Mock()
        cvelist.poll.return_value = [h.ingest(record())]
        epss.poll.return_value = []
        scheduler = Scheduler(h.engine,
            dict(cvelist=cvelist, kev=KevSource(http), epss=epss),
            clock=lambda: h.now, output=lambda _: None)
        try:
            scheduler.tick()
        except EOFError as error:
            scheduler._failed_cycle(error)
        observed = (epss.poll.call_count,
                    h.store.connection.execute('SELECT count(*) FROM records').fetchone()[0],
                    h.store.connection.execute(
                        "SELECT count(*) FROM retry_queue WHERE source='kev' AND record_id='@fetch'").fetchone()[0])
        self.assertEqual(observed, (1, 1, 1),
                         'A failed KEV transfer must return a failed ingest and durable retry')
        self.assertEqual(h.store.connection.execute(
            "SELECT state FROM health WHERE source='kev'").fetchone()[0], 'unhealthy')
        scheduler.next_poll['kev'] = 0
        scheduler.tick()
        self.assertEqual(h.store.connection.execute(
            "SELECT attempts FROM retry_queue WHERE source='kev' AND record_id='@fetch'").fetchone()[0], 2)
        # The release-listing boundary must classify the same transfer failure.
        result = CveListSource(http, h.store).poll(h.now)
        self.assertEqual(result[-1].status, FetchStatus.FAILED)
        self.assertIn('EOFError', result[-1].errors[0])

    def test_review4_pending_newer_catalog_must_reject_older_replacement(self):
        h = self.h
        # This shape was accepted by main; the new affected-field check rejects it.
        legacy = record()
        del legacy['containers']['cna']['affected']
        h.store.put_record(CVE, legacy, h.now.isoformat())
        h.now += timedelta(minutes=1)
        h.engine.run_cycle([replace(h.catalog([kev(), kev(OTHER)]), cursor='new')])
        pending_before = h.store.get_meta('pending_ingest:kev')
        self.assertEqual(json.loads(pending_before)['cursor'], 'new')
        h.engine.run_cycle([replace(h.catalog([kev()]), cursor='old',
                                   content_time=h.now - timedelta(seconds=30))])
        ids = [r[0] for r in h.store.connection.execute('SELECT cve FROM kev ORDER BY cve')]
        self.assertEqual(ids, [CVE, OTHER], 'A pending record retry must not disable date regression protection')
        self.assertEqual(h.store.get_meta('pending_ingest:kev'), pending_before)

    def test_review5_docker_permission_test_must_reject_unreadable_copy(self):
        from tests.test_goal_dockerfile import DockerfileTests
        original = Path('Dockerfile').read_text()
        for mode in ('000', '0700', '0600', '0750', '0640', '0004', '0644', '0666', '0744',
                     'a+rX', '0755', '0777'):
            with self.subTest(mode=mode):
                mutated = original.replace('--chmod=a+rX', '--chmod=' + mode)
                with patch.object(Path, 'read_text', return_value=mutated):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(DockerfileTests).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.wasSuccessful(), mode in ('a+rX', '0755', '0777'),
                                 'Source permissions must allow other users to read and traverse')

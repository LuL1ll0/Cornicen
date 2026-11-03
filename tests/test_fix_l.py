"""Health categories are structured metadata, including across delivery retries."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.render import health_body, render
from cornicen.store import Store


class FixLTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 3, 7, tzinfo=timezone.utc)
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.notifier = Mock()
        self.notifier.send.return_value = True
        config = Config(':memory:', Path('unused'), None, 'https://ntfy.invalid', 'test', None)
        self.engine = Engine(self.store, (), AliasMap.load(False), config,
                             lambda: self.now, self.notifier)

    def test_each_category_renders_without_private_fields(self):
        for reason in ('failed', 'incomplete', 'stale', 'future-dated', 'rejected', 'missing', 'recovered'):
            with self.subTest(reason=reason):
                state = 'healthy' if reason == 'recovered' else 'unhealthy'
                body = {'reason': reason, 'since': '2026-11-03T09:00:59+02:00',
                        'detail': '/private/fixture https://fixture.invalid feed content',
                        'error': 'PrivateException', 'url': 'https://fixture.invalid'}
                notification = Notification('1', '', 'cvelist', (state,), 'health', body)
                _, text, _, _ = render(notification)
                self.assertEqual(text, 'cvelist: recovered' if state == 'healthy' else
                                 f'cvelist: unhealthy — {reason} since 2026-11-03T07:00Z')
                safe = health_body('cvelist', state, reason=reason, since=body['since'])
                self.assertEqual(safe['reason'], reason)
                self.assertEqual(safe['since'], '2026-11-03T07:00Z')

    def test_invalid_metadata_cannot_leak(self):
        for reason in ('/private/fixture', 'https://fixture.invalid', 'feed content', ['stale']):
            for since in ('private timestamp', '2026-99-99T07:00Z',
                          '2026-11-03T07:00Z /private/fixture', {}):
                with self.subTest(reason=reason, since=since):
                    body = health_body('cvelist', 'unhealthy', reason=reason, since=since)
                    self.assertEqual(body['reason'], 'failed')
                    self.assertNotIn('since', body)

    def test_ingest_paths_choose_categories_without_using_diagnostics(self):
        for status, reason in ((FetchStatus.FAILED, 'failed'), (FetchStatus.PARTIAL, 'incomplete')):
            with self.subTest(status=status):
                self.engine.run_cycle([IngestResult('cvelist', status, Origin.DELTA, None,
                    self.now, errors=('stale future-dated /private/fixture feed content',))])
                notification = self.notifier.send.call_args.args[0]
                self.assertEqual(notification.body['reason'], reason)
                self.assertEqual(notification.body['since'], '2026-11-03T07:00Z')
                self.assertNotIn('/private/fixture', json.dumps(notification.body))
                with self.store.transaction():
                    self.engine._health('cvelist', 'healthy', 'complete')

    def test_coverage_paths_and_recovery(self):
        for stamp, cursor, reason in (
            (self.now - timedelta(hours=4), None, 'stale'),
            (self.now + timedelta(hours=3), None, 'future-dated'),
            (self.now, 'cve_2026-11-03_1100Z', 'future-dated'),
            (None, None, 'incomplete'),
            ('invalid', None, 'incomplete'),
        ):
            with self.subTest(reason=reason, stamp=stamp):
                self.store.set_meta('baseline_complete', '1')
                self.store.connection.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
                    ('cvelist', cursor, stamp.isoformat() if isinstance(stamp, datetime) else stamp))
                self.engine.run_cycle([])
                notification = next(call.args[0] for call in reversed(self.notifier.send.call_args_list)
                                    if call.args[0].record_id == 'cvelist')
                self.assertEqual(notification.body['reason'], reason)
                self.assertEqual(render(notification)[1],
                                 f'cvelist: unhealthy — {reason} since 2026-11-03T07:00Z')
                # Repair stored coverage before testing recovery; cursors never rewind.
                self.store.connection.execute(
                    'UPDATE cursors SET value=NULL,content_time=? WHERE source=?',
                    (self.now.isoformat(), 'cvelist'))
                self.engine.run_cycle([IngestResult('cvelist', FetchStatus.COMPLETE,
                                                  Origin.DELTA, None, self.now)])
                recovered = self.notifier.send.call_args.args[0]
                self.assertEqual(recovered.body['reason'], 'recovered')
                self.assertEqual(render(recovered)[1], 'cvelist: recovered')

    def test_watchlist_and_missing_record_defaults_and_delayed_delivery(self):
        self.notifier.send.return_value = False
        with self.store.transaction():
            self.engine._health('watchlist', 'unhealthy', 'stale /private/fixture')
            self.engine._health('records', 'unhealthy', 'failed https://fixture.invalid')
        self.engine._flush()
        self.now += timedelta(hours=1)
        self.notifier.send.return_value = True
        self.engine._flush()
        for notification, reason in [(call.args[0], {'watchlist': 'rejected', 'records': 'missing'}[
                call.args[0].record_id]) for call in self.notifier.send.call_args_list]:
            self.assertEqual(notification.body['reason'], reason)
            self.assertEqual(notification.body['since'], '2026-11-03T07:00Z')

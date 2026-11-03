from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from cornicen.config import Config
from cornicen.health import container_healthy
from cornicen.outbox import Outbox
from cornicen.store import Store
from tests.replay.harness import FakeClock, RecordingNotifier


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.clock = FakeClock(datetime(2026, 11, 3, tzinfo=timezone.utc))
        self.notifier = RecordingNotifier(self.clock)
        self.notifier.down = True
        self.outbox = Outbox(self.store, self.notifier, self.clock)
        self.config = Config(':memory:', Path('unused'), None, 'https://ntfy.invalid', 'test', None)

    def queue(self, pair='proxy|CVE-2026-1234'):
        with self.store.transaction():
            self.store.queue(pair, 'urgent', ['new match'],
                             {'watch_id': 'proxy', 'record_id': pair.split('|')[1]},
                             self.clock().isoformat())

    def test_backoff_schedule(self):
        self.queue()
        for seconds in (60, 120, 240, 480, 960, 1920, 3600, 3600):
            self.assertEqual(self.outbox.flush(), 0)
            row = self.store.connection.execute('SELECT * FROM outbox').fetchone()
            due = datetime.fromisoformat(row['next_attempt_at'])
            self.assertEqual((due - self.clock()).total_seconds(), seconds)
            self.assertEqual(self.outbox.flush(), 0)
            self.assertEqual(self.store.connection.execute(
                'SELECT attempts FROM outbox').fetchone()[0], row['attempts'])
            self.clock.now = due

    def test_long_outage_recovers_once(self):
        for minute in range(3 * 24 * 60):
            self.queue()
            self.queue('proxy|CVE-2026-5678')
            self.assertEqual(self.outbox.flush(), 0)
            self.clock.now += timedelta(minutes=1)
            if minute >= 60:
                self.assertFalse(container_healthy(self.store, self.clock(), self.config))
        self.assertEqual(self.store.connection.execute(
            'SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0], 2)
        self.notifier.down = False
        self.clock.now += timedelta(hours=1)
        self.assertEqual(self.outbox.flush(), 2)
        self.assertEqual(self.outbox.flush(), 0)
        self.assertEqual(len(self.notifier.delivered), 2)
        self.assertTrue(container_healthy(self.store, self.clock(), self.config))

    def test_future_due_is_not_sent(self):
        self.queue()
        self.store.connection.execute('UPDATE outbox SET due_at=?',
                                      ((self.clock() + timedelta(days=1)).isoformat(),))
        self.notifier.down = False
        self.assertEqual(self.outbox.flush(), 0)

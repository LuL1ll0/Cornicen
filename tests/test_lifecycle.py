"""Scheduler resource and timing contracts; outbox flush accounting."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cornicen.outbox import Outbox, deliver
from tests import test_scheduler as helpers
from tests import test_outbox as outbox_helpers


class SchedulerLifecycleTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp

    def test_record_spools_close_after_success_and_cycle_failure(self):
        class Records(list):
            pass
        for fail in (False, True):
            with self.subTest(fail=fail):
                self.scheduler.next_poll.clear()
                records = Records()
                records.close = Mock()
                previous = self.sources['cvelist'].poll.return_value[0]
                self.sources['cvelist'].poll.return_value = [replace(previous, records=records)]
                if fail:
                    with patch.object(self.engine, 'run_cycle', side_effect=RuntimeError('cycle failed')):
                        with self.assertRaisesRegex(RuntimeError, 'cycle failed'):
                            self.scheduler.tick()
                else:
                    self.scheduler.tick()
                records.close.assert_called_once_with()

    def test_wait_subtracts_elapsed_cycle_time(self):
        self.scheduler.monotonic = Mock(side_effect=[100, 107])
        self.scheduler.stop = Mock()
        self.scheduler.stop.is_set.side_effect = [False, True]
        with patch('cornicen.scheduler.signal.signal'), patch.object(self.scheduler, 'tick'):
            self.assertEqual(self.scheduler.run(), 0)
        self.scheduler.stop.wait.assert_called_once_with(53)


class FlushAccountingTests(unittest.TestCase):
    def test_engine_flush_returns_only_new_deliveries(self):
        engine = Mock(report=SimpleNamespace(sent=3))
        engine._flush.side_effect = lambda: setattr(engine.report, 'sent', 5)
        self.assertEqual(Outbox(Mock(), Mock(), Mock(), engine=engine).flush(), 2)


class DeliverMembershipTests(unittest.TestCase):
    setUp = outbox_helpers.OutboxTests.setUp

    def test_digest_acknowledges_only_revalidated_members(self):
        for number in (1234, 5678):
            record_id = f'CVE-2026-{number}'
            self.store.queue(f'service|{record_id}', 'normal', ['new match'],
                             {'watch_id': 'service', 'record_id': record_id},
                             self.clock().isoformat())
        ready = self.store.connection.execute('SELECT * FROM outbox ORDER BY id').fetchall()
        notifier = Mock()
        notifier.send.return_value = True
        self.assertEqual(deliver(self.store, notifier, self.clock, ready,
                                  revalidate=lambda rows: rows[:1]), 1)
        items = notifier.send.call_args.args[0].body['items']
        self.assertEqual([item['record_id'] for item in items], ['CVE-2026-1234'])
        rows = self.store.connection.execute('SELECT sent_at,attempts FROM outbox ORDER BY id').fetchall()
        self.assertIsNotNone(rows[0]['sent_at'])
        self.assertIsNone(rows[1]['sent_at'])
        self.assertEqual(rows[1]['attempts'], 0)

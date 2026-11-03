"""Immutable ingest and delivery envelopes keep accepted cycle data stable."""
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import unittest

from cornicen.model import FetchStatus, IngestResult, Notification, Origin


class ModelContractsTests(unittest.TestCase):
    def test_ingest_envelope_is_frozen(self):
        ingest = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                              'cursor', datetime(2026, 11, 3, tzinfo=timezone.utc))
        with self.assertRaises(FrozenInstanceError):
            ingest.cursor = 'skipped-release'
        self.assertEqual(ingest.cursor, 'cursor')
        self.assertEqual(ingest.errors, ())

    def test_notification_envelope_is_frozen(self):
        notification = Notification('durable-id', 'w', 'CVE-2026-1000',
                                    ('new match',), 'urgent', {})
        with self.assertRaises(FrozenInstanceError):
            notification.key = 'different-id'
        self.assertEqual(notification.key, 'durable-id')

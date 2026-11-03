"""Pending-payload cache invalidation contracts."""
import json
from copy import deepcopy
import unittest

from tests import test_engine as helpers


class StoreInvalidationTests(unittest.TestCase):
    setUp = helpers.EngineTests.setUp
    start = helpers.EngineTests.start
    ingest = helpers.EngineTests.ingest

    def pending_revision(self):
        self.start()
        record = deepcopy(self.record)
        record['containers']['cna']['metrics'] = [{'cvssV3_1': {'baseScore': 2.1}}]
        self.engine.run_cycle([self.ingest([record])])
        pending = self.store.connection.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchone()
        self.assertEqual(json.loads(pending['body_json'])['severity'], 2.1)
        revision = deepcopy(record)
        revision['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'] = 9.8
        self.store.put_record(record['cveMetadata']['cveId'], revision, self.clock().isoformat())
        return pending

    def test_record_write_refreshes_future_notification_evidence(self):
        pending = self.pending_revision()
        self.engine._flush()
        row = self.store.connection.execute('SELECT * FROM outbox WHERE id=?', (pending['id'],)).fetchone()
        self.assertEqual(json.loads(row['body_json'])['severity'], 9.8)
        self.assertIsNone(row['sent_at'])

    def test_queue_merge_preserves_earlier_record_invalidation(self):
        pending = self.pending_revision()
        # A coalescing update based on the old payload must still see the new record.
        self.store.queue(pending['pair_key'], 'normal', json.loads(pending['reasons_json']),
                         json.loads(pending['body_json']), pending['due_at'])
        self.engine._flush()
        row = self.store.connection.execute('SELECT * FROM outbox WHERE id=?', (pending['id'],)).fetchone()
        self.assertEqual(json.loads(row['body_json'])['severity'], 9.8)
        self.assertIsNone(row['sent_at'])

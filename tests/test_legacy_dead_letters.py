"""Migration must choose a failed revision by its age, not merely membership."""
from datetime import datetime, timezone
import json
import unittest
import zlib
from cornicen.store import Store


class LegacyDeadLetterTests(unittest.TestCase):
    def test_latest_failed_cve_revision_is_restored_and_old_failure_is_ignored(self):
        for failed_at, expected in [('2026-11-02T00:00:00+00:00', 'accepted'),
                                    ('2026-11-04T00:00:00+00:00', 'failed')]:
            with self.subTest(failed_at=failed_at):
                store = Store(':memory:')
                self.addCleanup(store.connection.close)
                store.migrate()
                cve = 'CVE-2026-1000'
                accepted = {'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED'}, 'revision': 'accepted'}
                failed = {**accepted, 'revision': 'failed'}
                store.put_record(cve, accepted, '2026-11-03T00:00:00+00:00')
                db = store.connection
                db.execute('DROP TABLE dead_letters')
                db.execute('CREATE TABLE dead_letters(id INTEGER PRIMARY KEY, source TEXT, '
                           'record_id TEXT, json TEXT, detail TEXT, failed_at TEXT)')
                db.execute('INSERT INTO dead_letters VALUES (?,?,?,?,?,?)',
                           (1, 'cvelist', cve, json.dumps(failed), 'evaluation failed', failed_at))
                store.migrate()
                store.migrate()
                row = db.execute('SELECT json FROM records WHERE id=?', (cve,)).fetchone()
                self.assertEqual(json.loads(zlib.decompress(row[0]))['revision'], expected)
                retry = db.execute('SELECT source,record_id,attempts FROM dead_letters').fetchone()
                self.assertEqual(tuple(retry), ('cvelist', cve, 1))

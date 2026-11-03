"""Migration must distinguish source fetch failures from invalid CVE records."""
import json
import unittest
import zlib
from cornicen.store import Store


class LegacyRetryTests(unittest.TestCase):
    def test_fetch_errors_keep_fetch_identity_and_invalid_record_keeps_payload(self):
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        store.migrate()
        db = store.connection
        db.execute('DROP TABLE retry_queue')
        db.execute('CREATE TABLE retry_queue(id INTEGER PRIMARY KEY, source TEXT, '
                   'record_id TEXT, json TEXT, detail TEXT)')
        db.execute('INSERT INTO retry_queue VALUES (1,?,?,?,?)',
                   ('cvelist', None, json.dumps({'errors': ['HTTP 503']}), 'fetch failure'))
        db.execute('INSERT INTO retry_queue VALUES (2,?,?,?,?)',
                   ('cvelist', None, json.dumps({'bad': 'record'}), 'record failure'))
        store.migrate()
        store.migrate()
        retries = db.execute('SELECT record_id,last_error FROM retry_queue ORDER BY record_id').fetchall()
        self.assertEqual(len(retries), 2)
        fetch = db.execute('SELECT last_error FROM retry_queue WHERE record_id=?', ('@fetch',)).fetchone()
        self.assertIsNotNone(fetch)
        self.assertEqual(fetch[0], 'fetch failure')
        invalid = next(row for row in retries if row['record_id'] != '@fetch')
        self.assertTrue(invalid['record_id'].startswith('@invalid:'))
        self.assertEqual(invalid['last_error'], 'record failure')
        records = db.execute('SELECT id,json FROM records').fetchall()
        self.assertEqual([row['id'] for row in records], [invalid['record_id']])
        self.assertEqual(json.loads(zlib.decompress(records[0]['json'])), {'bad': 'record'})

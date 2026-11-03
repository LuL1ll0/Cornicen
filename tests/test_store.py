import json
import sqlite3
import unittest

from cornicen.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)

    def test_migration_is_repeatable(self):
        self.store.migrate()
        tables = {r[0] for r in self.store.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({'records', 'kev', 'epss', 'pairs', 'events', 'outbox',
                         'cursors', 'health', 'meta', 'retry_queue'} <= tables)
        self.assertEqual(self.store.get_meta('schema_version'), '1')

    def test_nested_transaction_rolls_back_only_failed_record(self):
        with self.store.transaction():
            self.store.set_meta('good', 'yes')
            with self.assertRaises(ValueError):
                with self.store.transaction():
                    self.store.set_meta('bad', 'no')
                    raise ValueError('bad record')
        self.assertEqual(self.store.get_meta('good'), 'yes')
        self.assertIsNone(self.store.get_meta('bad'))

    def test_outer_rollback_includes_event_and_outbox(self):
        with self.assertRaises(ValueError):
            with self.store.transaction():
                self.store.connection.execute(
                    "INSERT INTO events VALUES ('w|c|new match|1','w','c','new match',1,'now')")
                self.store.queue('w|c', 'normal', ['new match'], {}, 'later')
                raise ValueError('abort')
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 0)
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM outbox').fetchone()[0], 0)

    def test_merge_keeps_id_due_and_one_unsent_row(self):
        with self.store.transaction():
            first = self.store.queue('w|c', 'normal', ['new match'], {'v': 1}, 'later')
            second = self.store.queue('w|c', 'urgent', ['KEV added'], {'v': 2}, 'now')
        row = self.store.connection.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual(first, second)
        self.assertEqual(json.loads(row['reasons_json']), ['new match', 'KEV added'])
        self.assertEqual(row['urgency'], 'urgent')
        self.assertEqual(row['due_at'], 'now')
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at) VALUES ('w|c','normal','[]','{}','now')")
        self.store.connection.execute("UPDATE outbox SET sent_at='now'")
        with self.store.transaction():
            self.assertNotEqual(first, self.store.queue('w|c', 'normal', ['correction'], {}, 'later'))

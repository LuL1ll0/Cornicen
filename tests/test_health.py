from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from cornicen.config import Config
from cornicen.health import assess, container_healthy
from cornicen.store import Store

NOW = datetime(2026, 11, 3, 23, tzinfo=timezone.utc)
CONFIG = Config(':memory:', Path('watch.toml'), None, 'https://ntfy.test', 'test', None)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)

    def test_quiet_install_container_healthy(self):
        self.assertTrue(container_healthy(self.store, NOW, CONFIG))
        self.store.set_meta('baseline_complete', '1')
        for source in ('cvelist', 'epss', 'kev'):
            self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                          (source, 'unchanged', NOW.isoformat()))
        self.assertTrue(container_healthy(self.store, NOW, CONFIG))

    def test_cvelist_stale_after_3h(self):
        self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                      ('cvelist', 'ignored', NOW.isoformat()))
        self.assertEqual(assess('cvelist', self.store, NOW+timedelta(hours=3), CONFIG)[0], 'healthy')
        self.assertEqual(assess('cvelist', self.store, NOW+timedelta(hours=3, seconds=1), CONFIG)[0], 'unhealthy')

    def test_epss_stale_kev_fetch_only_and_explicit_failure(self):
        for source in ('epss', 'kev'):
            self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                          (source, 'ignored', (NOW-timedelta(days=3)).isoformat()))
        self.assertEqual(assess('epss', self.store, NOW, CONFIG)[0], 'unhealthy')
        self.assertEqual(assess('kev', self.store, NOW, CONFIG)[0], 'healthy')
        self.store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                                      ('watchlist', 'unhealthy', NOW.isoformat(), 'invalid'))
        self.assertFalse(container_healthy(self.store, NOW, CONFIG))

    def test_overdue_pending_only(self):
        self.store.queue('test', 'urgent', [], {}, (NOW-timedelta(minutes=61)).isoformat())
        self.assertFalse(container_healthy(self.store, NOW, CONFIG))
        self.store.connection.execute('UPDATE outbox SET sent_at=?', (NOW.isoformat(),))
        self.assertTrue(container_healthy(self.store, NOW, CONFIG))

    def test_recovered_watchlist_needs_no_feed_cursor(self):
        self.store.set_meta('baseline_complete', '1')
        for source in ('cvelist', 'epss', 'kev'):
            self.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                          (source, 'unchanged', NOW.isoformat()))
        self.store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                                      ('watchlist', 'healthy', NOW.isoformat(), 'Reload succeeded'))
        self.assertTrue(container_healthy(self.store, NOW, CONFIG))

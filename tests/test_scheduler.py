from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import IngestResult, FetchStatus, Origin
from cornicen.scheduler import Scheduler
from cornicen.store import Store
from cornicen.watchlist import load_watchlist
from tests.replay.harness import FakeClock, RecordingNotifier


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'watch.toml'
        self.text = '''[[watch]]
id = "private-inventory"
name = "Private product name"
match = ["examplecorp:example"]
version = "1.0"
scheme = "dotted"
'''
        self.path.write_text(self.text)
        self.clock = FakeClock(datetime(2026, 11, 3, tzinfo=timezone.utc))
        self.store = Store(':memory:')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        config = Config(':memory:', self.path, None, 'https://ntfy.invalid', 'test', None)
        self.engine = Engine(self.store, load_watchlist(self.path), AliasMap.load(False),
                             config, self.clock, RecordingNotifier(self.clock))
        self.sources = {}
        for name, origin in [('cvelist', Origin.DELTA), ('kev', Origin.CATALOG), ('epss', Origin.SCORES)]:
            self.sources[name] = Mock()
            self.sources[name].poll.return_value = [
                IngestResult(name, FetchStatus.COMPLETE, origin, 'cursor', self.clock())]
        self.lines = []
        self.scheduler = Scheduler(self.engine, self.sources, self.clock, self.lines.append,
                                   monotonic=lambda: self.clock().timestamp())

    def test_poll_intervals_order_and_private_logs(self):
        order = []
        for name, source in self.sources.items():
            result = source.poll.return_value
            source.poll.side_effect = lambda now, name=name, result=result: (order.append(name) or result)
        self.scheduler.tick()
        self.assertEqual(order, ['cvelist', 'kev', 'epss'])
        for minute in range(1, 24 * 60 + 1):
            self.clock.now += timedelta(minutes=1)
            self.scheduler.tick()
        self.assertEqual([s.poll.call_count for s in self.sources.values()], [25, 5, 2])
        self.assertEqual(len(self.lines), 1441)
        for line in self.lines:
            self.assertNotIn('Private product name', line)
            self.assertNotIn('private-inventory', line)
            self.assertNotIn('examplecorp', line)
            self.assertEqual(set(json.loads(line)['sources']), {'cvelist', 'kev', 'epss', 'watchlist'})

    def test_invalid_reload_keeps_previous_then_recovers(self):
        old = self.engine.watches
        self.path.write_text(self.text + '\nunknown = true\n')
        self.scheduler.tick()
        self.assertEqual(self.engine.watches, old)
        row = self.store.connection.execute("SELECT state,detail FROM health WHERE source='watchlist'").fetchone()
        self.assertEqual(row['state'], 'unhealthy')
        self.assertEqual(row['detail'], 'Watchlist reload rejected')
        self.path.write_text(self.text.replace('1.0', '2.0'))
        self.clock.now += timedelta(minutes=1)
        self.scheduler.tick()
        self.assertEqual(self.engine.watches[0].version, '2.0')
        self.assertEqual(self.store.connection.execute(
            "SELECT state FROM health WHERE source='watchlist'").fetchone()[0], 'healthy')

    def test_sigterm_finishes_current_cycle(self):
        handlers = {}
        def register(sig, handler):
            handlers[sig] = handler
            return signal.SIG_DFL
        def poll(now):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return []
        self.sources['cvelist'].poll.side_effect = poll
        with patch('cornicen.scheduler.signal.signal', side_effect=register):
            self.assertEqual(self.scheduler.run(), 0)
        self.sources['kev'].poll.assert_called_once()
        self.sources['epss'].poll.assert_called_once()
        self.assertEqual(len(self.lines), 1)

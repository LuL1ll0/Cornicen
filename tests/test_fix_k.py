"""Health diagnostics stay local; notifier payloads use closed messages."""

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unicodedata
import unittest
from unittest.mock import Mock, patch

from cornicen import cli
from cornicen.config import Config, SecretToken
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.notify.file import FileNotifier
from cornicen.notify.ntfy import NtfyNotifier
from cornicen.render import render
from cornicen.scheduler import Scheduler, safe_message
from cornicen.store import Store


class FixKTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.clock = lambda: datetime(2026, 11, 3, 7, tzinfo=timezone.utc)
        self.db = self.root / 'state.db'
        self.config = Config(str(self.db), self.root / 'watch.toml', None,
                             'https://ntfy.invalid', 'fixture', SecretToken('configured-secret'))
        self.store = Store(str(self.db))
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.path = self.root / 'notifications.jsonl'
        self.engine = Engine(self.store, (), AliasMap.load(False), self.config,
                             self.clock, FileNotifier(self.path))
        self.logs = []
        self.scheduler = Scheduler(self.engine, {}, self.clock, self.logs.append)

    def notifications(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def status(self):
        output = io.StringIO()
        with patch('cornicen.cli.load_config', return_value=self.config), redirect_stdout(output):
            self.assertEqual(cli.main(['status']), 0)
        return output.getvalue()

    def test_secret_forms_are_masked(self):
        for prefix in ('access_token=', 'X-Api-Key: ', 'Authorization: Bearer ', '?token=',
                       '_secret=', 'password=', 'api_key=', 'authorization=', 'secret='):
            with self.subTest(prefix=prefix):
                text = safe_message(RuntimeError('failed ' + prefix + 'fake-credential'))
                self.assertNotIn('fake-credential', text)
                self.assertIn('[redacted]', text)
        self.assertEqual(safe_message(RuntimeError('mytoken=ordinary')), 'mytoken=ordinary')

    def test_exception_detail_is_local_for_file_and_ntfy(self):
        message = ('read\nfailed\x00\u202e /private/fixture/records.json; '
                   'CVE description: fixture remote execution; '
                   'https://fixture.invalid/feed?token=fake-query-secret')
        self.scheduler.component = 'cvelist'
        self.scheduler._failed_cycle(RuntimeError(message))
        notification = self.notifications()[0]
        self.assertEqual(notification['body']['detail'], 'CVE List ingest failed')
        self.assertEqual(notification['body']['error'], 'RuntimeError')
        payloads = []
        notifier = NtfyNotifier(lambda url, body, headers: payloads.append(body.decode()) or 200,
                                'https://ntfy.invalid', 'fixture', None)
        self.assertTrue(notifier.send(Notification(**notification)))
        for text in (self.path.read_text(), *payloads):
            for private in ('/private/fixture', 'https://fixture.invalid',
                            'fixture remote execution', 'fake-query-secret'):
                self.assertNotIn(private, text)
        detail = self.store.connection.execute(
            "SELECT detail FROM health WHERE source='cvelist'").fetchone()[0]
        for local in (detail, self.status(), json.loads(self.logs[0])['message']):
            self.assertIn('/private/fixture/records.json', local)
            self.assertIn('fixture remote execution', local)
            self.assertIn('https://fixture.invalid/feed?token', local)
            self.assertIn('[redacted]', local)
            self.assertNotIn('fake-query-secret', local)
        self.assertLessEqual(len(detail), 300)
        self.assertFalse(any(unicodedata.category(c).startswith('C') for c in detail))

    def test_validation_diagnostics_stay_local_and_masked(self):
        ingests = [IngestResult('kev', FetchStatus.FAILED, Origin.CATALOG,
            None, None, errors=('fixture feed text /fixture/private access_token=fake-secret',))]
        self.scheduler.sources = {name: Mock() for name in self.scheduler.intervals}
        for name, source in self.scheduler.sources.items():
            source.poll.return_value = ingests if name == 'kev' else []
        with self.store.transaction():
            self.engine._health('records', 'unhealthy', 'Missing stored record: fixture-record')
        self.scheduler.tick()
        notification = next(n for n in self.notifications() if n['record_id'] == 'kev')
        self.assertEqual(notification['body']['detail'], 'KEV fetch failed')
        self.assertNotIn('fixture feed text', json.dumps(notification))
        self.assertIn('fixture feed text', self.status())
        self.assertNotIn('fake-secret', self.status())
        detail = self.store.connection.execute("SELECT detail FROM health WHERE source='kev'").fetchone()[0]
        self.assertNotIn('fake-secret', detail)
        logged = json.loads(self.logs[0])['health_details']['kev']
        self.assertIn('fixture feed text', logged)
        self.assertIn('[redacted]', logged)
        self.assertNotIn('fake-secret', logged)
        self.assertEqual(json.loads(self.logs[0])['health_details']['records'],
                         'Missing stored record: fixture-record')

    def test_all_components_and_recovery_use_fixed_messages(self):
        messages = {'cvelist': 'CVE List ingest failed', 'kev': 'KEV fetch failed',
                    'epss': 'EPSS fetch failed', 'engine': 'processing cycle failed',
                    'scheduler': 'scheduler cycle failed', 'watchlist': 'watch list reload rejected',
                    'records': 'stored record missing', 'source-0': 'component health failed'}
        for component, message in messages.items():
            for state in ('unhealthy', 'healthy'):
                with self.subTest(component=component, state=state):
                    with self.store.transaction():
                        self.engine._health(component, state, 'fixture private diagnostic')
                    self.engine._flush()
                    n = self.notifications()[-1]
                    self.assertEqual(n['record_id'], component)
                    self.assertNotIn('fixture private diagnostic', json.dumps(n))
                    self.assertEqual(n['body']['detail'], message if state == 'unhealthy'
                                     else 'component recovered')

    def test_render_ignores_legacy_free_form_health_detail(self):
        n = Notification('1', '', 'kev', ('unhealthy',), 'health',
                         {'detail': 'fixture private diagnostic', 'since': 'private timestamp'})
        title, body, priority, _ = render(n)
        self.assertEqual(body, 'kev: unhealthy — failed')
        self.assertEqual(priority, 5)
        self.assertIn('kev', title)

    def test_pending_legacy_health_is_safe_for_any_notifier(self):
        with self.store.transaction():
            self.engine._event('', 'kev', 'unhealthy', 1,
                {'record_id': 'kev', 'detail': 'fixture legacy private diagnostic'}, True)
        self.engine._flush()
        self.assertNotIn('fixture legacy private diagnostic', self.path.read_text())

    def test_local_detail_is_bounded_and_status_masks_legacy_rows(self):
        self.scheduler.component = 'engine'
        self.scheduler._failed_cycle(ValueError('configured-secret\n' + 'x' * 500))
        detail = self.store.connection.execute("SELECT detail FROM health WHERE source='engine'").fetchone()[0]
        self.assertLessEqual(len(detail), 300)
        self.assertNotIn('configured-secret', detail)
        with self.store.transaction():
            self.store.set_meta('last_error:kev', 'access_token=legacy-secret')
            self.store.connection.execute('INSERT INTO health VALUES (?,?,?,?)',
                ('kev', 'unhealthy', self.clock().isoformat(), 'legacy\n detail'))
        status = self.status()
        self.assertNotIn('legacy-secret', status)
        self.assertIn('[redacted]', status)


if __name__ == '__main__':
    unittest.main()

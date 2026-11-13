# script-purpose: Check webhook literal text, credential boundaries and total delivery deadlines offline.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_webhook_r2.py
"""Read invented fixtures; write temporary config files and unittest results.

Exit codes: 0 success, 1 failed tests, 2 invalid unittest arguments.
"""
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cornicen.config import SecretToken, load_config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import Notification
from cornicen.scheduler import redact_tokens
from cornicen.store import Store

NOW = datetime(2099, 1, 1, tzinfo=timezone.utc)
URL = 'https://hook.example.invalid/quartz-route?key=opal%2Fprivate'
SECRET = 'review-signing-quartz'


def fixture(title):
    return Notification('42', 'quartz', 'CVE-2099-1001', ('new match',), 'urgent',
                        {'watch_id': 'quartz', 'record_id': 'CVE-2099-1001', 'state': 'affected', 'name': 'Quartz', 'product': 'fiction:quartz', 'version': '99.88',
                         'cve_title': title, 'description': '<!channel> @room @everyone'})


class WebhookR2Tests(unittest.TestCase):
    def test_r2_service_literal_text(self):
        from cornicen.notify.webhook import payload
        samples = {'slack': '<!channel> <!here> <@U2099> <https://phish.invalid/|Trusted Quartz> &',
                   'discord': '@everyone @here <@&2099> [Trusted Quartz](https://phish.invalid/)',
                   'matrix': '@room [Trusted Quartz](https://phish.invalid/)',
                   'gotify': '**Quartz** [Trusted Quartz](https://phish.invalid/)'}
        for shape, title in samples.items():
            with self.subTest(shape=shape):
                data = payload(fixture(title), shape)
                if shape == 'slack':
                    self.assertIn('&lt;!channel&gt;', data['text'])
                    self.assertIn('&amp;', data['text'])
                    self.assertNotIn('<', data['text'])
                elif shape == 'discord':
                    self.assertEqual(data['allowed_mentions'], {'parse': []})
                    self.assertIn(r'\[Trusted Quartz\]', data['content'])
                elif shape == 'matrix':
                    self.assertEqual(data['m.mentions'], {})
                    self.assertNotIn('formatted_body', data)
                    self.assertIn(title, data['body'])
                else:
                    self.assertEqual(data['extras'], {'client::display': {'contentType': 'text/plain'}})
                self.assertNotIn('description', data)
                self.assertNotIn('<!channel> @room @everyone', str(data))

    def test_r2_derived_url_health_and_status(self):
        from cornicen import cli
        for url, text in [('https://qünartz.invalid/quartz-route', 'xn--qnartz-3ya.invalid'),
                          ('https://xn--qnartz-3ya.invalid/quartz-route', 'qünartz.invalid'),
                          (URL, 'quartz-route opal%2fprivate opal%2Fprivate opal/private')]:
            with self.subTest(url=url), tempfile.TemporaryDirectory(dir='.') as directory:
                path = Path(directory) / 'config.toml'
                path.write_text('notifier = "webhook"\n')
                config = load_config(path, {'CORNICEN_WEBHOOK_URL': url, 'CORNICEN_WEBHOOK_SECRET': SECRET})
                store = Store(':memory:')
                store.migrate()
                try:
                    engine = Engine(store, (), AliasMap.load(False), config, lambda: NOW, Mock())
                    engine._health('cvelist', 'unhealthy', RuntimeError('Cannot read ' + text))
                    detail = store.connection.execute("SELECT detail FROM health WHERE source='cvelist'").fetchone()[0]
                    output = io.StringIO()
                    with redirect_stdout(output):
                        cli.status_json(store, NOW, config)
                    for part in text.split():
                        self.assertNotIn(part, detail + output.getvalue())
                finally:
                    store.connection.close()

    def test_r2_short_components_preserve_diagnostics(self):
        original = 'processing cycle failed: 12, 20. api v2 hooks x1 CVE-2099-1001'
        token = SecretToken('https://hook.example.invalid/x1/api/v2/hooks/1/./?a=2&b=:')
        self.assertEqual(redact_tokens(original, token), original)
        self.assertEqual(redact_tokens(token.reveal(), token), '[redacted]')
        for segment in ('fail', 'cycle', '1', '.', '%31'):
            self.assertEqual(redact_tokens(original, SecretToken('https://hook.example.invalid/' + segment)), original)

    def test_r2_slow_drip_deadline_and_pending(self):
        from cornicen.notify.ntfy import post
        from cornicen.notify.webhook import WebhookNotifier
        from cornicen.outbox import Outbox
        class Raw(io.RawIOBase):
            def readable(self):
                return True
            def readinto(self, buffer):
                delay = min(59, sock.timeout)
                sock.elapsed += delay
                if delay < 59:
                    raise TimeoutError('invented timeout')
                buffer[:1] = sock.response.read(1)
                return 1
        class Socket:
            elapsed = 0
            timeout = 60
            response = io.BytesIO(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
            def makefile(self, *args, **kwargs):
                return io.BufferedReader(Raw())
            def settimeout(self, value):
                self.timeout = value
            def sendall(self, value):
                pass
            def close(self):
                pass
        sock = Socket()
        def connect(connection):
            connection.sock = sock
            sock.timeout = connection.timeout
        store = Store(':memory:')
        store.migrate()
        try:
            with store.transaction():
                store.queue('quartz|CVE-2099-1001', 'urgent', ['new match'], fixture('Quartz').body, NOW.isoformat())
            with patch('http.client.HTTPSConnection.connect', connect), patch.dict(os.environ, {'no_proxy': '*'}), \
                 patch('time.monotonic', side_effect=lambda: float(sock.elapsed)):
                channel = WebhookNotifier(post, SecretToken(URL), SecretToken(SECRET))
                self.assertEqual(Outbox(store, channel, lambda: NOW).flush(), 0)
            self.assertLessEqual(sock.elapsed, 60)
            row = store.connection.execute('SELECT sent_at, attempts FROM outbox').fetchone()
            self.assertEqual(tuple(row), (None, 1))
        finally:
            store.connection.close()

    def test_r2_whole_request_deadline_even_before_socket(self):
        from cornicen.notify.ntfy import post
        release = threading.Event()
        def stalled(*args, **kwargs):
            release.wait(2)
            raise TimeoutError('invented resolver stall')
        start = time.monotonic()
        try:
            with patch('cornicen.notify.ntfy.REQUEST_TIMEOUT', 0.05, create=True), \
                 patch('cornicen.notify.ntfy.build_opener', side_effect=stalled):
                with self.assertRaises(TimeoutError):
                    post(URL, b'{}', {})
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            release.set()


if __name__ == '__main__':
    unittest.main()

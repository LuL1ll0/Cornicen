# script-purpose: Verify signed webhook delivery and private diagnostics offline.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_webhook.py
"""Reads fixtures and install documentation; writes temporary files and test output.

Exit codes: 0 success, 1 failed tests, 2 invalid unittest arguments.
"""
from contextlib import redirect_stdout
from datetime import datetime, timezone
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote, quote, quote_plus
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

from cornicen import cli
from cornicen.config import SecretToken, load_config
from cornicen.model import Notification
from cornicen.outbox import Outbox
from cornicen.scheduler import Scheduler, redact_tokens
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.store import Store

URL = 'https://hook.example.invalid/x1/health%20failed?key=processing'
SECRET = 'within'
ENV = {'CORNICEN_WEBHOOK_URL': URL, 'CORNICEN_WEBHOOK_SECRET': SECRET}


class WebhookTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'config.toml'
        self.path.write_text('notifier = "webhook"\n')

    def load(self, env=None):
        return load_config(self.path, ENV if env is None else env)

    def channel(self, transport, shape='json'):
        from cornicen.notify.webhook import WebhookNotifier
        return WebhookNotifier(transport, SecretToken(URL), SecretToken(SECRET), shape,
                               clock=lambda: 4102444800)

    def notification(self):
        return Notification('42', 'quartz', 'CVE-2099-1001', ('new match',), 'urgent',
                            {'name': 'Quartz', 'product': 'fiction:quartz', 'version': '99.88'})

    def test_webhook_https_required_and_missing_variables(self):
        self.assertEqual(self.load().notifier, 'webhook')
        for url in ('http://hook.example.invalid/x1', 'https:///x1', 'file:///x1',
                    'https://hook.example.invalid:bad/x1', 'https://user@hook.example.invalid/x1'):
            with self.subTest(url=url), self.assertRaises(ValueError) as caught:
                self.load({**ENV, 'CORNICEN_WEBHOOK_URL': url})
            self.assertIn('CORNICEN_WEBHOOK_URL', str(caught.exception))
            self.assertNotIn(url, str(caught.exception))
        for variable in ENV:
            with self.subTest(variable=variable), self.assertRaises(ValueError) as caught:
                self.load({k: v for k, v in ENV.items() if k != variable})
            self.assertIn(variable, str(caught.exception))
            self.assertNotIn(URL, str(caught.exception))
            output = io.StringIO()
            with patch('cornicen.cli.os.environ', {k: v for k, v in ENV.items() if k != variable}), redirect_stdout(output):
                self.assertEqual(cli.main(['--config', str(self.path), 'healthcheck']), 1)
            self.assertIn(variable, output.getvalue())
            self.assertNotIn(URL, output.getvalue())

    def test_webhook_toml_secrets_rejected(self):
        for key in ('webhook_url', 'webhook_url_file', 'webhook_secret', 'webhook_secret_file'):
            self.path.write_text(key + ' = "private-fixture"')
            with self.subTest(key=key), self.assertRaises(ValueError) as caught:
                self.load()
            self.assertIn('Secrets are forbidden', str(caught.exception))
            self.assertNotIn('private-fixture', str(caught.exception))

    def test_webhook_files_permissions_precedence_and_format(self):
        env = {}
        for variable, value in ENV.items():
            path = self.root / variable
            path.write_text(value + '\n')
            path.chmod(0o600)
            env[variable + '_FILE'] = str(path)
        config = self.load(env)
        self.assertEqual(config.webhook_url.reveal(), URL)
        self.assertEqual(config.webhook_secret.reveal(), SECRET)
        self.assertNotIn(URL, repr(config))
        self.assertNotIn(SECRET, repr(config))
        for variable in ENV:
            path = Path(env[variable + '_FILE'])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.load(env)
            self.assertEqual(self.load({**env, **ENV}).webhook_url.reveal(), URL)
            path.chmod(0o600)
            path.write_text('')
            with self.assertRaises(ValueError):
                self.load(env)
            path.write_text(ENV[variable])
        self.path.write_text('notifier = "webhook"\nwebhook_format = "unknown"')
        with self.assertRaises(ValueError):
            self.load()

    def test_webhook_signature_documented_recipe_and_tampering(self):
        calls = []
        self.assertTrue(self.channel(lambda *args: calls.append(args) or 204).send(self.notification()))
        _, body, headers = calls[0]
        recipe = Path('docs/install.md').read_text().split('```python\n', 1)[1].split('```', 1)[0]
        scope = {}
        exec(recipe, scope)
        verify = scope['verify_webhook']
        timestamp = headers['X-Cornicen-Timestamp']
        signature = headers['X-Cornicen-Signature']
        self.assertEqual(timestamp, '4102444800')
        self.assertRegex(signature, r'^sha256=[0-9a-f]{64}$')
        self.assertTrue(verify(SECRET.encode(), body, timestamp, signature, now=4102444800))
        self.assertFalse(verify(SECRET.encode(), body + b' ', timestamp, signature, now=4102444800))
        self.assertFalse(verify(SECRET.encode(), body, str(int(timestamp)+1), signature, now=4102444800))
        self.assertFalse(verify(SECRET.encode(), body, timestamp, signature, now=4102445101))
        self.assertFalse(verify(SECRET.encode(), body, timestamp, signature, now=4102444499))
        self.assertFalse(verify(SECRET.encode(), body, 'invalid', signature, now=4102444800))

    def test_webhook_shapes_truncation_and_digest_ids(self):
        from cornicen.notify.webhook import MARKER
        expected = {'json': {'title', 'body', 'priority', 'cve_ids'},
                    'discord': {'content', 'allowed_mentions'}, 'slack': {'text'},
                    'matrix': {'msgtype', 'body', 'm.mentions'}, 'gotify': {'title', 'message', 'priority', 'extras'},
                    'homeassistant': {'title', 'body', 'priority', 'cve_ids'}}
        for shape, keys in expected.items():
            calls = []
            channel = self.channel(lambda *args: calls.append(args) or 200, shape)
            self.assertTrue(channel.send(self.notification()))
            payload = json.loads(calls[-1][1])
            self.assertEqual(set(payload), keys)
            self.assertIn('CVE-2099-1001', str(payload))
            self.assertIn('X-Cornicen-Signature', calls[-1][2])
            if shape == 'matrix':
                self.assertEqual(payload['msgtype'], 'm.text')
            if shape in ('json', 'gotify', 'homeassistant'):
                self.assertEqual(payload['priority'], 5)
            with patch('cornicen.notify.webhook.render', return_value=('Quartz', '🪨' * 100000, 3, [])):
                self.assertTrue(channel.send(self.notification()))
            payload = json.loads(calls[-1][1])
            text = payload.get('content', payload.get('text', payload.get('message', payload.get('body'))))
            self.assertTrue(text.endswith(MARKER))
            if shape == 'discord':
                self.assertLessEqual(len(text.encode('utf-16-le')) // 2, 2000)
            if shape == 'slack':
                self.assertLessEqual(len(text), 4000)
            self.assertLessEqual(len(calls[-1][1]), 64000)
        from dataclasses import asdict
        item = asdict(self.notification())
        digest = Notification('digest', '', 'digest', ('digest',), 'normal', {'items': [item, item]})
        calls = []
        self.channel(lambda *args: calls.append(args) or 200).send(digest)
        self.assertEqual(json.loads(calls[0][1])['cve_ids'], ['CVE-2099-1001'])

    def test_webhook_outbox_ack_retry_and_cli_selection(self):
        config = self.load()
        from cornicen.notify.webhook import WebhookNotifier
        self.assertIsInstance(cli._notifier(config), WebhookNotifier)
        for result in (200, 204, 299, 302, 500, TimeoutError(URL + SECRET)):
            with self.subTest(result=type(result).__name__):
                store = Store(':memory:')
                store.migrate()
                try:
                    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
                    with store.transaction():
                        store.queue('quartz|CVE-2099-1001', 'urgent', ['new match'],
                                    {'watch_id': 'quartz', 'record_id': 'CVE-2099-1001'}, now.isoformat())
                    transport = Mock(side_effect=result) if isinstance(result, Exception) else Mock(return_value=result)
                    box = Outbox(store, self.channel(transport), lambda: now)
                    success = isinstance(result, int) and 200 <= result < 300
                    self.assertEqual(box.flush(), int(success))
                    row = store.connection.execute('SELECT * FROM outbox').fetchone()
                    self.assertEqual(row['sent_at'] is not None, success)
                    self.assertEqual(row['attempts'], 1)
                    if not success:
                        self.assertEqual((datetime.fromisoformat(row['next_attempt_at'])-now).total_seconds(), 60)
                        self.assertEqual(box.flush(), 0)
                        self.assertEqual(transport.call_count, 1)
                finally:
                    store.connection.close()

    def test_webhook_real_transport_no_redirect_and_timeout(self):
        from cornicen.notify.webhook import post
        requests = []
        class Transport(HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                headers = Message()
                headers['Location'] = 'https://other.example.invalid/target'
                response = addinfourl(io.BytesIO(b''), headers, request.full_url, 302)
                response.msg = 'fixture'
                return response
        with patch('cornicen.notify.ntfy.build_opener',
                   side_effect=lambda *handlers: build_opener(*handlers, Transport())):
            self.assertEqual(post(URL, b'{}', {}), 302)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].timeout, 60)
        self.assertEqual(requests[0].get_method(), 'POST')

    def test_webhook_private_health_status_heartbeat_and_command_failures(self):
        config = self.load()
        store = Store(':memory:')
        store.migrate()
        self.addCleanup(store.connection.close)
        now = lambda: datetime(2099, 1, 1, tzinfo=timezone.utc)
        engine = Engine(store, [], AliasMap.load(False), config, now, self.channel(Mock(return_value=500)))
        parts = [URL, unquote(URL), quote(URL, safe=''), quote_plus(URL),
                 'health failed', 'health%20failed', 'processing', SECRET]
        error = 'Cannot read ' + ' '.join(parts)
        for part in parts:
            self.assertEqual(redact_tokens(part, config.webhook_url, config.webhook_secret), '[redacted]')
        engine._health('scheduler', 'unhealthy', error)
        details = store.connection.execute('SELECT detail FROM health').fetchall()
        lines = []
        sources = {name: Mock() for name in ('cvelist', 'kev', 'epss')}
        for source in sources.values():
            source.poll.return_value = []
        scheduler = Scheduler(engine, sources, now, lines.append)
        scheduler._failed_cycle(RuntimeError(error))
        scheduler.tick()
        output = io.StringIO()
        with redirect_stdout(output):
            cli.status_json(store, now(), config)
        proxy = Mock(wraps=store)
        proxy.connection = Mock(wraps=store.connection)
        proxy.connection.close.return_value = None
        with patch('cornicen.cli.load_config', return_value=config), patch('cornicen.cli.Store', return_value=proxy), \
             patch('cornicen.cli.Path.is_file', return_value=True), redirect_stdout(output):
            self.assertEqual(cli.main(['status']), 0)
        with patch('cornicen.cli.load_config', return_value=config), \
             patch('cornicen.cli.Store', side_effect=RuntimeError(error)), \
             patch('cornicen.cli.Path.is_file', return_value=True), redirect_stdout(output):
            self.assertEqual(cli.main(['healthcheck']), 1)
        text = str([tuple(row) for row in details]) + '\n'.join(lines) + output.getvalue()
        for part in parts:
            self.assertNotIn(part, text)
        self.assertIn('command failed', text)

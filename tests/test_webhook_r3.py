# script-purpose: Check final webhook redaction and interrupted transport cleanup offline.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_webhook_r3.py
"""Read invented notification fixtures; write only unittest results.

Exit codes: 0 success, 1 failed tests, 2 invalid unittest arguments.
"""
import hashlib
import hmac
import json
from dataclasses import replace
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from cornicen.config import SecretToken
from cornicen.notify import ntfy, webhook
from tests.test_webhook_r2 import fixture, NOW


class WebhookR3Tests(unittest.TestCase):
    def test_r3_real_channels_preserve_identity_and_urgency(self):
        from cornicen.applicability import Result, State
        from cornicen.config import Config
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from cornicen.render import render
        from cornicen.store import Store
        from cornicen.watchlist import load_watchlist_text
        watches = load_watchlist_text('[[watch]]\nid="quartz"\nname="Quartz"\nmatch=["fiction:quartz"]\nversion="99.88"\nscheme="dotted"\n')
        for channel in ('ntfy', 'webhook'):
            for route in ('unrelated-route', 'quartz', 'affected', 'active'):
                with self.subTest(channel=channel, route=route):
                    store = Store(':memory:')
                    store.migrate()
                    self.addCleanup(store.connection.close)
                    config = Config(':memory:', Path('unused'), None, 'https://notify.example.invalid', 'quartz', None)
                    url = SecretToken('https://hook.example.invalid/' + route)
                    secret = SecretToken('invented-signing-secret')
                    config = replace(config, notifier=channel, deadman_url=url if channel == 'ntfy' else None,
                                     webhook_url=url if channel == 'webhook' else None,
                                     webhook_secret=secret if channel == 'webhook' else None)
                    calls = []
                    def post(*args):
                        calls.append(args)
                        return 204
                    notifier = (ntfy.NtfyNotifier(post, config.ntfy_url, 'quartz', None) if channel == 'ntfy'
                                else webhook.WebhookNotifier(post, url, secret))
                    engine = Engine(store, watches, AliasMap.load(False), config, lambda: NOW, notifier)
                    cve = 'CVE-2099-1001'
                    record = {'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED'},
                              'containers': {'cna': {'affected': [], 'title': 'Invented issue'},
                                             'adp': [{'providerMetadata': {'shortName': 'CISA-ADP'},
                                                      'metrics': [{'other': {'type': 'ssvc', 'content': {
                                                          'options': [{'Exploitation': 'active'}]}}}]}]}}
                    with store.transaction():
                        store.put_record(cve, record, NOW.isoformat())
                        store.connection.execute('INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited,evidence,confidence) VALUES (?,?,?,1,0,0,?,?)',
                                                 ('quartz', cve, 'affected', 'invented range', 'exact'))
                        body = engine._body(watches[0], cve, Result(State.AFFECTED, False, 'invented range', 'exact'))
                        self.assertEqual((body['watch_id'], body['state'], body['ssvc']['Exploitation']),
                                         ('quartz', 'affected', 'active'))
                        engine._event('quartz', cve, 'new match', 1, body)
                    row = store.connection.execute('SELECT * FROM outbox').fetchone()
                    self.assertEqual(json.loads(row['body_json']), body)
                    self.assertEqual(row['urgency'], 'urgent')
                    engine._flush()
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(store.connection.execute('SELECT notified FROM pairs').fetchone()[0], 1)
                    if channel == 'ntfy':
                        self.assertEqual(calls[0][2]['Priority'], '5')
                        sent = fixture('Invented issue')
                        sent = replace(sent, body=body)
                        self.assertEqual(calls[0][1], render(sent)[1].encode())
                    else:
                        self.assertEqual(json.loads(calls[0][1])['priority'], 5)

    def test_integration_signed_bytes_are_the_serialized_payload(self):
        # Integration (lane C r3 residual): no rewriting between serialization and signing.
        secret = SecretToken('invented-serial-secret')
        url = SecretToken('https://hook.example.invalid/quartz')
        title = 'Invented [redacted] title quartz'
        for shape in sorted(webhook.FORMATS):
            with self.subTest(shape=shape):
                calls = []
                notification = fixture(title)
                self.assertTrue(webhook.WebhookNotifier(
                    lambda *args: calls.append(args) or 204, url, secret,
                    shape, clock=lambda: 42).send(notification))
                body = calls[0][1]
                expected_body = json.dumps(webhook.payload(notification, shape), ensure_ascii=False,
                                           separators=(',', ':')).encode('utf-8')
                self.assertEqual(body, expected_body)
                json.loads(body)
                expected = hmac.new(secret.reveal().encode(), b'42.' + body, hashlib.sha256).hexdigest()
                self.assertEqual(calls[0][2]['X-Cornicen-Signature'], 'sha256=' + expected)

    def test_r3_setup_baseexceptions_release_slots(self):
        for stage in ('_Deadline', 'Event', 'Thread'):
            for error in (KeyboardInterrupt, SystemExit, RuntimeError):
                with self.subTest(stage=stage, error=error.__name__):
                    slots = threading.BoundedSemaphore(4)
                    target = ntfy if stage == '_Deadline' else ntfy.threading
                    with patch.object(ntfy, '_REQUEST_SLOTS', slots), patch.object(target, stage, side_effect=error):
                        for _ in range(4):
                            with self.assertRaises(error):
                                ntfy.post('https://hook.example.invalid/quartz', b'{}', {})
                    self.assertEqual(slots._value, 4)


if __name__ == '__main__':
    unittest.main()

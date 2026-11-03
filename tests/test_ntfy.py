import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from cornicen.config import SecretToken
from cornicen.model import Notification
from cornicen.notify.ntfy import NtfyNotifier, post, _NoRedirect
from cornicen.notify.file import FileNotifier


class NtfyTests(unittest.TestCase):
    def notification(self, urgency='urgent'):
        return Notification('42', 'proxy', 'CVE-2026-1234', ('new match',), urgency,
                            {'name': 'Proxy', 'product': 'nginx', 'version': '1.0',
                             'state': 'affected'})

    def test_ntfy_headers_and_priority(self):
        send = Mock(return_value=204)
        token = Mock(spec=SecretToken)
        token.reveal.return_value = 'private-test-value'
        notifier = NtfyNotifier(send, 'https://ntfy.invalid/', 'topic', token)
        token.reveal.assert_not_called()
        self.assertTrue(notifier.send(self.notification()))
        url, body, headers = send.call_args.args
        self.assertEqual(url, 'https://ntfy.invalid/topic')
        self.assertEqual(headers['Priority'], '5')
        self.assertEqual(headers['Tags'], 'rotating_light')
        self.assertEqual(headers['X-Cornicen-Event'], '42')
        self.assertEqual(headers['Authorization'], 'Bearer private-test-value')
        self.assertIn('CVE-2026-1234', headers['Title'])
        self.assertIn(b'Why: new match', body)
        token.reveal.assert_called_once_with()
        notifier = NtfyNotifier(send, 'https://ntfy.invalid', 'topic', None)
        self.assertTrue(notifier.send(self.notification('normal')))
        self.assertEqual(send.call_args.args[2]['Priority'], '3')
        self.assertNotIn('Authorization', send.call_args.args[2])
        for status in (199, 300, 302, 401, 500):
            send.return_value = status
            self.assertFalse(notifier.send(self.notification()))

    def test_redirect_is_not_followed(self):
        from urllib.error import HTTPError
        from unittest.mock import patch
        opener = Mock()
        opener.open.side_effect = HTTPError('https://ntfy.invalid', 302, 'redirect',
                                           {'Location': 'https://elsewhere.invalid'}, None)
        with patch('cornicen.notify.ntfy.build_opener', return_value=opener):
            self.assertEqual(post('https://ntfy.invalid/topic', b'test',
                                  {'Authorization': 'Bearer private-test-value'}), 302)
        self.assertEqual(opener.open.call_count, 1)
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, 'redirect',
                                                        {}, 'https://elsewhere.invalid'))

    def test_token_never_logged(self):
        secret = 'private-test-value'
        send = Mock(side_effect=RuntimeError(secret))
        notifier = NtfyNotifier(send, 'https://ntfy.invalid', 'topic', SecretToken(secret))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertFalse(notifier.send(self.notification()))
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(secret, repr(notifier))
        self.assertNotIn(secret, repr(vars(notifier)))

    def test_file_notifier_json_lines(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'notifications.jsonl'
            notifier = FileNotifier(path)
            self.assertTrue(notifier.send(self.notification()))
            self.assertTrue(notifier.send(self.notification('normal')))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([row['key'] for row in rows], ['42', '42'])
            self.assertEqual(rows[0]['record_id'], 'CVE-2026-1234')

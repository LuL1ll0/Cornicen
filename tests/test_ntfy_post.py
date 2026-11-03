"""Use urllib's real request/opener stack with an offline HTTPS transport."""
from email.header import decode_header, make_header
from email.message import Message
import io
import unittest
from unittest.mock import patch
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

from cornicen.notify.ntfy import post


class NtfyPostTests(unittest.TestCase):
    def test_success_status_and_encoded_sanitised_title(self):
        requests = []
        class Transport(HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                response = addinfourl(io.BytesIO(b''), Message(), request.full_url, 204)
                response.msg = 'fixture'
                return response
        with patch('cornicen.notify.ntfy.build_opener',
                   side_effect=lambda *handlers: build_opener(*handlers, Transport())):
            status = post('https://ntfy.invalid/topic', b'payload',
                          {'Title': 'Cornicen: Café 🚨\r\nInjected: header'})
        self.assertEqual(status, 204)
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(request.data, b'payload')
        title = request.get_header('Title')
        self.assertNotIn('\r', title)
        self.assertNotIn('\n', title)
        self.assertTrue(title.isascii())
        self.assertEqual(str(make_header(decode_header(title))),
                         'Cornicen: Café 🚨 Injected: header')

    def test_channel_escapes_topic_and_declares_plain_text(self):
        from cornicen.model import Notification
        from cornicen.notify.ntfy import NtfyNotifier
        calls = []
        def transport(url, body, headers):
            calls.append((url, body, headers))
            return 204
        channel = NtfyNotifier(transport, 'https://ntfy.invalid/', 'team/alerts ?', None)
        self.assertTrue(channel.send(Notification('42', 'w', 'CVE-2026-1000',
            ('new match',), 'normal', {'name': 'Server', 'version': '1.0', 'state': 'affected'})))
        self.assertEqual(calls[0][0], 'https://ntfy.invalid/team%2Falerts%20%3F')
        self.assertEqual(calls[0][2]['Content-Type'], 'text/plain; charset=utf-8')
        self.assertIn(b'Why: new match', calls[0][1])

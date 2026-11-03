"""Offline transport boundary and deadline regressions."""
import io
from email.message import Message
from http.client import HTTPResponse
import os
import socket
import unittest
from unittest.mock import Mock, call, patch
from urllib.request import Request, HTTPSHandler, ProxyHandler
from urllib.response import addinfourl

from cornicen.fetch import Http, _connect_public, _Deadline, _HTTPSConnection, _HTTPSHandler
from tests.source_helpers import public_resolver, Opener, Reply


class DeadlineTests(unittest.TestCase):
    def test_trickling_body_yields_to_deadline_between_underlying_reads(self):
        elapsed = [0]
        class Trickling(io.RawIOBase):
            def __init__(self):
                self.header = b'HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n'
                self.body_reads = 0
            def readable(self):
                return True
            def readinto(self, buffer):
                if self.header:
                    data, self.header = self.header[:len(buffer)], self.header[len(buffer):]
                    buffer[:len(data)] = data
                    return len(data)
                if self.body_reads == 64:
                    return 0
                self.body_reads += 1
                elapsed[0] += 1
                buffer[0] = ord('x')
                return 1
        raw = Trickling()
        stream = io.BufferedReader(raw)
        self.addCleanup(stream.close)
        response = HTTPResponse(Mock(makefile=Mock(return_value=stream)))
        response.begin()
        target = io.BytesIO()
        with self.assertRaises(TimeoutError):
            Http._copy(response, target, 64, _Deadline(2, lambda: elapsed[0]))
        self.assertEqual(raw.body_reads, 2)
        self.assertEqual(target.getvalue(), b'x')

    def test_remaining_is_duration_with_nonzero_monotonic_origin(self):
        now = [100.0]
        deadline = _Deadline(10, lambda: now[0])
        now[0] += 3
        self.assertEqual(deadline.remaining(), 7)

    def test_exact_deadline_is_expired(self):
        now = [100.0]
        deadline = _Deadline(10, lambda: now[0])
        now[0] += 10
        with self.assertRaises(TimeoutError):
            deadline.check()

    def test_stalled_transfer_timer_is_started(self):
        with patch('cornicen.fetch.threading.Timer') as timer:
            with _Deadline(10, lambda: 100):
                timer.return_value.start.assert_called_once_with()
            timer.return_value.cancel.assert_called_once_with()


class PolicyBoundaryTests(unittest.TestCase):
    def test_budget_must_belong_to_source_before_transport(self):
        url = 'https://epss.empiricalsecurity.com/scores'
        opener = Opener({url: b''})
        with self.assertRaisesRegex(ValueError, 'belong to source'):
            Http('test', {}, opener, resolver=public_resolver).get(
                url, source='epss', budget='cvelist_snapshot')
        self.assertEqual(opener.requests, [])

    def test_invalid_per_call_budgets_fail_before_transport(self):
        url = 'https://api.github.com/'
        for setting in ('max_bytes', 'deadline_seconds'):
            with self.subTest(setting=setting):
                opener = Opener({url: b''})
                with self.assertRaisesRegex(ValueError, 'positive integer'):
                    Http('test', {}, opener, resolver=public_resolver).get(
                        url, source='cvelist', **{setting: 0})
                self.assertEqual(opener.requests, [])

    def test_control_characters_rejected_before_transport(self):
        for character in ('\t', '\n', '\x00', '\x7f', ' '):
            with self.subTest(character=repr(character)):
                opener = Mock()
                opener.open.return_value = Reply(b'')
                with self.assertRaises(ValueError):
                    Http('test', {}, opener, resolver=public_resolver).get(
                        'https://api.github.com/path' + character, source='cvelist')
                opener.open.assert_not_called()

    def test_injected_opener_requires_explicit_resolver(self):
        url = 'https://api.github.com/'
        opener = Opener({url: b''})
        with patch('cornicen.fetch.socket.getaddrinfo', side_effect=public_resolver) as resolver:
            client = Http('test', {}, opener)
            with self.assertRaisesRegex(ValueError, 'explicit resolver'):
                client.get(url, source='cvelist')
        self.assertEqual(opener.requests, [])
        resolver.assert_not_called()

    def test_three_allowed_redirect_hops_keep_each_destination_policy(self):
        urls = ['https://api.github.com/start', 'https://github.com/download',
                'https://objects.githubusercontent.com/object',
                'https://release-assets.githubusercontent.com/final']
        routes = {url: (b'', 302, {'Location': target}) for url, target in zip(urls, urls[1:])}
        routes[urls[-1]] = b'payload'
        opener = Opener(routes)
        self.assertEqual(Http('test', {}, opener, resolver=public_resolver).get(
            urls[0], source='cvelist').body, b'payload')
        self.assertEqual([request.full_url for request in opener.requests], urls)


class NativeTransportTests(unittest.TestCase):
    def test_native_redirect_returns_to_source_policy_before_dispatch(self):
        requests = []
        class Transport(HTTPSHandler):
            def https_open(self, request):
                requests.append(request.full_url)
                headers = Message()
                headers['Location'] = 'https://www.cisa.gov/disallowed-for-cvelist'
                reply = addinfourl(io.BytesIO(b''), headers, request.full_url,
                                   302 if len(requests) == 1 else 200)
                reply.msg = 'offline fixture'
                return reply
        with patch('cornicen.fetch._HTTPSHandler', return_value=Transport()):
            with self.assertRaisesRegex(ValueError, 'allowed HTTPS host'):
                Http('test', {}, resolver=public_resolver).get('https://api.github.com/',
                                                              source='cvelist')
        self.assertEqual(requests, ['https://api.github.com/'])

    def test_environment_proxy_is_disabled_in_native_opener(self):
        fake = Opener({'https://api.github.com/': b'[]'})
        with patch.dict(os.environ, {'https_proxy': 'http://proxy.invalid:8080'}, clear=True), \
                patch('cornicen.fetch.build_opener', return_value=fake) as build:
            self.assertEqual(Http('test', {}, resolver=public_resolver).get(
                'https://api.github.com/', source='cvelist').body, b'[]')
        proxy = next(handler for handler in build.call_args.args if isinstance(handler, ProxyHandler))
        self.assertEqual(proxy.proxies, {})

    def test_connect_and_tls_share_deadline_and_original_hostname(self):
        raw, tls, context, deadline = Mock(), Mock(), Mock(), Mock()
        deadline.remaining.return_value = 7
        context.wrap_socket.return_value = tls
        host = 'epss.empiricalsecurity.com'
        with patch('cornicen.fetch.socket.socket', return_value=raw):
            connection = _HTTPSConnection(host, timeout=60, context=context,
                                          resolver=public_resolver, deadline=deadline)
            connection.connect()
        self.addCleanup(connection.close)
        raw.settimeout.assert_called_once_with(7)
        raw.connect.assert_called_once_with(('93.184.216.34', 443))
        self.assertEqual(deadline.watch.call_args_list, [call(raw), call(tls)])
        context.wrap_socket.assert_called_once_with(raw, server_hostname=host,
                                                    do_handshake_on_connect=False)
        tls.do_handshake.assert_called_once_with()

    def test_failed_address_socket_is_closed_before_fallback(self):
        first, second = Mock(), Mock()
        first.connect.side_effect = OSError('unreachable')
        addresses = public_resolver('github.com', 443) * 2
        with patch('cornicen.fetch.socket.socket', side_effect=[first, second]):
            self.assertIs(_connect_public(('github.com', 443), 10,
                                          resolver=lambda *a, **kw: addresses), second)
        first.close.assert_called_once_with()
        second.close.assert_not_called()

    def test_native_connection_rejects_tunnels_before_socket_creation(self):
        connection = _HTTPSConnection('github.com', context=Mock(), resolver=public_resolver,
                                      deadline=Mock())
        self.addCleanup(connection.close)
        connection.set_tunnel('www.cisa.gov')
        with patch.object(connection, '_create_connection') as connect:
            with self.assertRaisesRegex(ValueError, 'proxies'):
                connection.connect()
        connect.assert_not_called()

    def test_handler_forwards_explicit_tls_context(self):
        handler = _HTTPSHandler(public_resolver, Mock())
        handler._context = context = Mock()
        request = Request('https://github.com/')
        with patch.object(handler, 'do_open') as open_request:
            self.assertIs(handler.https_open(request), open_request.return_value)
        open_request.assert_called_once_with(handler.connection, request, context=context)

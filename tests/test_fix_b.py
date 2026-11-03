"""Offline regressions for public-source egress and resource budgets."""

from datetime import datetime, timezone
import gzip
import io
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen.config import load_config
from cornicen.fetch import Http
from cornicen.model import FetchStatus, Origin
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.sources.epss import EpssSource, URL
from cornicen.store import Store
from tests.source_helpers import Opener, Reply, release


def public_resolver(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
             ('93.184.216.34', port))]


class EgressTests(unittest.TestCase):
    def client(self, routes, resolver=public_resolver):
        opener = Opener(routes)
        return Http('test', {}, opener, resolver=resolver), opener

    def test_unsafe_urls_rejected_before_transport(self):
        for url in ('http://api.github.com/', 'https://127.0.0.1/',
                    'https://169.254.169.254/', 'https://[::1]/',
                    'https://api.github.com:444/', 'https://user@api.github.com/',
                    'https://www.cisa.gov/', 'https://api.github.com.evil.test/'):
            with self.subTest(url=url):
                http, opener = self.client({url: b''})
                with self.assertRaises(ValueError):
                    http.get(url, source='cvelist')
                self.assertEqual(opener.requests, [])

    def test_all_resolved_addresses_must_be_public(self):
        for address in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1',
                        'fe80::1', 'fd00::1', '224.0.0.1', 'ff02::1',
                        '::ffff:127.0.0.1'):
            with self.subTest(address=address):
                def resolver(host, port, **kwargs):
                    return public_resolver(host, port) + [
                        (socket.AF_INET6 if ':' in address else socket.AF_INET,
                         socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (address, port))]
                http, opener = self.client({RELEASES_URL: b'[]'}, resolver)
                with self.assertRaises(ValueError):
                    http.get(RELEASES_URL, source='cvelist')
                self.assertEqual(opener.requests, [])

    def test_redirect_hops_cannot_change_source_or_downgrade(self):
        for destination in ('http://api.github.com/private', 'https://private.test/',
                            'https://www.cisa.gov/', 'https://[::1]/'):
            with self.subTest(destination=destination):
                http, opener = self.client({RELEASES_URL: (b'', 302, {'Location': destination})})
                with self.assertRaises(ValueError):
                    http.get(RELEASES_URL, source='cvelist')
                self.assertEqual([r.full_url for r in opener.requests], [RELEASES_URL])

    def test_allowed_redirect_name_resolving_private_is_rejected(self):
        def resolver(host, port, **kwargs):
            if host == 'github.com':
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                         ('10.0.0.1', port))]
            return public_resolver(host, port)
        http, opener = self.client({RELEASES_URL: (b'', 302, {'Location': 'https://github.com/asset'})}, resolver)
        with self.assertRaises(ValueError):
            http.get(RELEASES_URL, source='cvelist')
        self.assertEqual(len(opener.requests), 1)

    def test_unknown_or_missing_source_is_error(self):
        http, opener = self.client({RELEASES_URL: b'[]'})
        for kwargs in ({}, {'source': 'unknown'}, {'source': 'ntfy'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                http.get(RELEASES_URL, **kwargs)
        self.assertEqual(opener.requests, [])

    def test_pagination_destination_is_checked(self):
        import json
        opener = Opener({RELEASES_URL: (json.dumps([release(3)]).encode(), 200, {
            'Link': '<https://www.cisa.gov/page>; rel="next"'})})
        source = self.cvelist(opener)
        with self.assertRaisesRegex(ValueError, 'allowed HTTPS host'):
            source._listing('cve_2026-11-03_0100Z', datetime(2026, 11, 3, 23, tzinfo=timezone.utc))
        self.assertEqual(len(opener.requests), 1)

    def cvelist(self, opener):
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        http = Http('test', {}, opener, resolver=public_resolver)
        return CveListSource(http, store)

    def test_asset_url_is_checked_before_transport(self):
        for destination in ('http://127.0.0.1:8080/admin',
                            'http://169.254.169.254/latest/meta-data/',
                            'https://[::1]/', 'https://www.cisa.gov/asset'):
            with self.subTest(destination=destination):
                opener = Opener({})
                source = self.cvelist(opener)
                candidate = release(3)
                candidate['assets'][1]['browser_download_url'] = destination
                result = source._archive(candidate, Origin.DELTA,
                                         datetime(2026, 11, 3, tzinfo=timezone.utc))
                self.assertEqual(result.status, FetchStatus.FAILED)
                self.assertIn('allowed HTTPS host', ' '.join(result.errors))
                self.assertEqual(opener.requests, [])

    def test_native_transport_preserves_tls_hostname_and_pins_socket_address(self):
        resolver = Mock(side_effect=public_resolver)
        raw, tls, context = Mock(), Mock(), Mock()
        tls.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]')
        context.wrap_socket.return_value = tls
        with patch('cornicen.fetch.socket.socket', return_value=raw), \
                patch('http.client.ssl._create_default_https_context', return_value=context):
            response = Http('test', {}, resolver=resolver).get(RELEASES_URL, source='cvelist')
        self.assertEqual(response.body, b'[]')
        resolver.assert_called_once_with('api.github.com', 443, type=socket.SOCK_STREAM)
        raw.connect.assert_called_once_with(('93.184.216.34', 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname='api.github.com',
                                                    do_handshake_on_connect=False)
        tls.do_handshake.assert_called_once_with()

    def test_source_allowlists_accept_only_their_hosts(self):
        from cornicen.fetch import SOURCE_HOSTS
        for source, hosts in SOURCE_HOSTS.items():
            for host in hosts:
                with self.subTest(source=source, host=host):
                    url = f'https://{host}:443/feed'
                    http, opener = self.client({url: b'ok'})
                    self.assertEqual(http.get(url, source=source).body, b'ok')
                    self.assertEqual(len(opener.requests), 1)

    def test_connect_uses_validated_address_without_second_dns_lookup(self):
        from cornicen.fetch import _connect_public
        resolver = Mock(side_effect=[public_resolver('api.github.com', 443),
                                    [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]])
        connection = Mock()
        with patch('cornicen.fetch.socket.socket', return_value=connection):
            self.assertIs(_connect_public(('api.github.com', 443), 10, resolver=resolver), connection)
        connection.connect.assert_called_once_with(('93.184.216.34', 443))
        self.assertEqual(resolver.call_count, 1)

    def test_private_connect_address_rejected_before_socket(self):
        from cornicen.fetch import _connect_public
        resolver = lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 443))]
        with patch('cornicen.fetch.socket.socket') as transport:
            with self.assertRaises(ValueError):
                _connect_public(('api.github.com', 443), 10, resolver=resolver)
        transport.assert_not_called()


class DownloadTests(unittest.TestCase):
    def test_each_source_budget_applies_to_files_and_memory(self):
        cases = [('cvelist', 'cvelist_snapshot', RELEASES_URL),
                 ('cvelist', 'cvelist_delta', RELEASES_URL),
                 ('kev', 'kev', 'https://www.cisa.gov/feed'), ('epss', 'epss', URL)]
        for source, budget, url in cases:
            for to_file in (False, True):
                with self.subTest(source=source, budget=budget, to_file=to_file), \
                        tempfile.TemporaryDirectory(dir='.') as directory:
                    http = Http('test', {}, Opener({url: b'123456'}), data_dir=Path(directory),
                                resolver=public_resolver, download_budgets={budget: {'max_bytes': 5}})
                    with patch('cornicen.fetch.CHUNK_BYTES', 2), \
                            self.assertRaisesRegex(ValueError, 'size limit'):
                        http.get(url, source=source, budget=budget, to_file=to_file)
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_counted_download_and_partial_cleanup(self):
        for body, fails in ((b'1234', False), (b'12345', True)):
            with self.subTest(body=body), tempfile.TemporaryDirectory(dir='.') as directory:
                http = Http('test', {}, Opener({URL: body}), data_dir=Path(directory),
                            resolver=public_resolver)
                if fails:
                    with self.assertRaisesRegex(ValueError, 'size limit'):
                        http.get(URL, source='epss', to_file=True, max_bytes=4)
                    self.assertEqual(list(Path(directory).iterdir()), [])
                else:
                    response = http.get(URL, source='epss', to_file=True, max_bytes=4)
                    self.assertEqual(response.path.read_bytes(), body)
                    response.path.unlink()

    def test_deadline_includes_transfer_and_removes_partial(self):
        elapsed = [0]
        class SlowReply(Reply):
            def read(self, size=-1):
                elapsed[0] += 2
                return super().read(min(size, 1))
        opener = Mock()
        opener.open.return_value = SlowReply(b'123456')
        with tempfile.TemporaryDirectory(dir='.') as directory:
            http = Http('test', {}, opener, data_dir=Path(directory),
                        resolver=public_resolver, clock=lambda: elapsed[0])
            with self.assertRaisesRegex(TimeoutError, 'deadline'):
                http.get(URL, source='epss', to_file=True, deadline_seconds=3)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_defaults_and_config_overrides(self):
        from cornicen.config import DOWNLOAD_BUDGETS
        self.assertEqual(DOWNLOAD_BUDGETS, {
            'cvelist_snapshot': {'max_bytes': 2 * 1024**3, 'deadline_seconds': 2700},
            'cvelist_delta': {'max_bytes': 200 * 1024**2, 'deadline_seconds': 300},
            'kev': {'max_bytes': 20 * 1024**2, 'deadline_seconds': 300},
            'epss': {'max_bytes': 64 * 1024**2, 'deadline_seconds': 300}})
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('[download_budgets.epss]\nmax_bytes = 4\ndeadline_seconds = 2\n')
            config = load_config(path, {})
            self.assertEqual(config.download_budgets['epss']['max_bytes'], 4)
            http = Http('test', {}, Opener({URL: b'12345'}), data_dir=Path(directory),
                        resolver=public_resolver, download_budgets=config.download_budgets)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                http.get(URL, source='epss', to_file=True)
            self.assertEqual(list(Path(directory).glob('*.download')), [])

    def test_invalid_budget_config(self):
        for value in ('0', '-1', 'true', '1.5', '"1"'):
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir='.') as directory:
                path = Path(directory) / 'config.toml'
                path.write_text(f'[download_budgets.epss]\nmax_bytes = {value}\n')
                with self.assertRaisesRegex(ValueError, 'positive integer'):
                    load_config(path, {})

    def test_total_deadline_spans_redirects(self):
        elapsed = [0]
        class Redirects:
            def open(self, request, timeout=None):
                elapsed[0] += 2
                return Reply(b'', 302, {'Location': RELEASES_URL + '?next'})
        http = Http('test', {}, Redirects(), resolver=public_resolver, clock=lambda: elapsed[0])
        with self.assertRaisesRegex(TimeoutError, 'deadline'):
            http.get(RELEASES_URL, source='cvelist', deadline_seconds=3)

    def test_deadline_interrupts_watched_socket(self):
        from cornicen.fetch import _Deadline
        connection = Mock()
        with _Deadline(300, lambda: 0) as deadline:
            deadline.watch(connection)
            deadline._expire()
            connection.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        self.assertTrue(deadline.timer.finished.is_set())

    def test_interrupted_download_is_removed(self):
        class BrokenReply(Reply):
            def read(self, size=-1):
                raise OSError('interrupted')
        opener = Mock()
        opener.open.return_value = BrokenReply()
        with tempfile.TemporaryDirectory(dir='.') as directory:
            http = Http('test', {}, opener, data_dir=Path(directory), resolver=public_resolver)
            with self.assertRaisesRegex(OSError, 'interrupted'):
                http.get(URL, source='epss', to_file=True)
            self.assertEqual(list(Path(directory).iterdir()), [])


class EpssBudgetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.store = Store(str(Path(self.directory.name) / 'state.db'))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.store.connection.execute('INSERT INTO epss VALUES (?,?,?,?)',
                                      ('CVE-2026-1234', .4, .5, '2026-11-02'))
        self.store.connection.commit()

    def poll(self, rows):
        path = Path(self.directory.name) / 'scores.gz'
        path.write_bytes(gzip.compress(('#model_version:v1,score_date:2026-11-03\n'
                                      'cve,epss,percentile\n' + rows).encode()))
        http = Mock(data_dir=Path(self.directory.name))
        http.get.return_value = Mock(status=200, path=path)
        result, = EpssSource(http, self.store).poll(datetime(2026, 11, 3, tzinfo=timezone.utc))
        self.assertFalse(path.exists())
        self.assertEqual(tuple(self.store.connection.execute('SELECT * FROM epss').fetchone()),
                         ('CVE-2026-1234', .4, .5, '2026-11-02'))
        return result

    def test_identifier_limits(self):
        for identifier in ('CVE-2026-' + '1' * 20, 'CVE-2026-' + '1' * 100000,
                           'CVE-2026-123', 'CVE-26-1234'):
            with self.subTest(length=len(identifier)):
                self.assertEqual(self.poll(identifier + ',0.1,0.2\n').status, FetchStatus.FAILED)

    def test_longest_valid_identifier_accepted(self):
        identifier = 'CVE-2026-' + '1' * 19
        result = self.poll(identifier + ',0.1,0.2\n')
        self.assertEqual(result.status, FetchStatus.COMPLETE)
        self.assertEqual(result.epss, {identifier: (.1, .2)})

    def test_row_limit_preserves_accepted_scores(self):
        with patch('cornicen.sources.epss.MAX_ROWS', 1, create=True):
            result = self.poll('CVE-2026-1234,0.1,0.2\nCVE-2026-1235,0.2,0.3\n')
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('row', ' '.join(result.errors))

    def test_expanded_byte_limit_preserves_accepted_scores(self):
        with patch('cornicen.sources.epss.MAX_EXPANDED_BYTES', 64, create=True):
            result = self.poll('CVE-2026-1234,0.1,0.2\n')
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('expanded', ' '.join(result.errors))


class ContainerTests(unittest.TestCase):
    def test_base_image_has_immutable_digest(self):
        lines = [line for line in Path('Dockerfile').read_text().splitlines()
                 if line.startswith('FROM ')]
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r'^FROM python:3\.13-slim@sha256:[0-9a-f]{64}$')
        self.assertTrue(lines[0].endswith('ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1'))

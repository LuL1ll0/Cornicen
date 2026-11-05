"""Bounded public-feed HTTP, with source policy enforced at every request hop."""

from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from http.client import HTTPResponse, HTTPSConnection
from io import BytesIO
import ipaddress
from pathlib import Path
import socket
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from cornicen.config import SecretToken, download_budgets as _download_budgets


MAX_BODY_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
SOURCE_HOSTS = {
    'cvelist': frozenset({'api.github.com', 'github.com', 'objects.githubusercontent.com',
                         'release-assets.githubusercontent.com'}),
    'kev': frozenset({'www.cisa.gov'}),
    'epss': frozenset({'epss.empiricalsecurity.com'}),
}


def _authorization(source, host, token):
    if source == 'cvelist' and host == 'api.github.com' and token is not None:
        return 'Bearer ' + token.reveal()
    return None


def _destination(url, source):
    if source not in SOURCE_HOSTS:
        raise ValueError('Unknown public source')
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        valid = (parsed.scheme == 'https' and (parsed.port is None or parsed.port == 443)
                 and host in SOURCE_HOSTS[source] and parsed.username is None
                 and parsed.password is None and not any(c.isspace() or ord(c) < 32 or ord(c) == 127
                                                        for c in url))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('Public source URL must use an allowed HTTPS host on port 443 without userinfo')
    # The allowlist contains DNS names only; literals cannot enter resolution.
    return host


def _public_addresses(host, port, resolver):
    addresses = resolver(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('Public source host has no addresses')
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        mapped = getattr(ip, 'ipv4_mapped', None)
        if not ip.is_global or ip.is_multicast or (mapped is not None and not mapped.is_global):
            raise ValueError('Public source resolved to a non-public address')
    return addresses


def _connect_public(address, timeout, source_address=None, *, resolver=socket.getaddrinfo,
                    deadline=None):
    """Resolve at connect time, then connect numerically without a second DNS lookup."""
    host, port = address
    addresses = _public_addresses(host, port, resolver)
    error = None
    for family, kind, protocol, _, sockaddr in addresses:
        if deadline is not None:
            deadline.check()
        connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(min(timeout, deadline.remaining()) if deadline else timeout)
            if deadline is not None:
                deadline.watch(connection)
            if source_address:
                connection.bind(source_address)
            connection.connect(sockaddr)
            return connection
        except OSError as failure:
            connection.close()
            error = failure
    if error is not None:
        raise error
    raise ValueError('Public source host has no usable addresses')


class _Deadline:
    """Interrupt stalled TLS/header/body reads as well as checking between chunks."""

    def __init__(self, seconds, clock):
        self.clock = clock
        self.end = clock() + seconds
        self.sockets = []
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True

    def _expire(self):
        for connection in tuple(self.sockets):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def remaining(self):
        self.check()
        return self.end - self.clock()

    def check(self):
        if self.clock() >= self.end:
            raise TimeoutError('HTTP transfer deadline exceeded')

    def watch(self, connection):
        self.sockets.append(connection)
        self.check()

    def __enter__(self):
        self.timer.start()
        return self

    def __exit__(self, *args):
        self.timer.cancel()
        self.check()


class _HTTPSConnection(HTTPSConnection):
    def __init__(self, *args, resolver, deadline, **kwargs):
        super().__init__(*args, **kwargs)
        self._deadline = deadline
        self._create_connection = partial(_connect_public, resolver=resolver, deadline=deadline)

    def connect(self):
        # Keep the original hostname for certificate verification and SNI.
        if self._tunnel_host:
            raise ValueError('Public source proxies are not supported')
        self.sock = self._create_connection((self.host, self.port), self.timeout,
                                            self.source_address)
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host,
                                                  do_handshake_on_connect=False)
            self._deadline.watch(self.sock)
            self.sock.do_handshake()
        except BaseException:
            self.close()
            raise


class _HTTPSHandler(HTTPSHandler):
    def __init__(self, resolver, deadline):
        super().__init__()
        self.connection = partial(_HTTPSConnection, resolver=resolver, deadline=deadline)

    def https_open(self, request):
        return self.do_open(self.connection, request, context=self._context)


class _Redirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Http.get validates redirects and chooses each destination's User-Agent.
        return None


@dataclass
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes | None
    path: Path | None
    url: str | None = None


class Http:
    def __init__(self, user_agent: str, overrides: Mapping[str, str], opener=None,
                 *, data_dir: Path | None = None, resolver=None, clock=time.monotonic,
                 download_budgets=None, github_token: SecretToken | None = None):
        self.github_token = github_token
        self.user_agent = user_agent
        self.overrides = overrides
        self.opener = opener
        self.resolver = resolver if resolver is not None else socket.getaddrinfo
        self.injected_resolver = resolver is not None
        self.clock = clock
        self.download_budgets = _download_budgets(download_budgets or {})
        self.data_dir = Path(data_dir) if data_dir is not None else Path('.')

    def get(self, url: str, etag: str | None = None,
            last_modified: str | None = None, to_file: bool = False, *,
            source: str | None = None, budget: str | None = None,
            max_bytes: int | None = None, deadline_seconds: int | None = None,
            on_response=None) -> Response:
        _destination(url, source)
        budget = budget or ('cvelist_delta' if source == 'cvelist' else source)
        permitted = {'cvelist_snapshot', 'cvelist_delta'} if source == 'cvelist' else {source}
        if budget not in permitted:
            raise ValueError('Download budget does not belong to source')
        limits = self.download_budgets[budget]
        max_bytes = limits['max_bytes'] if max_bytes is None else max_bytes
        deadline_seconds = limits['deadline_seconds'] if deadline_seconds is None else deadline_seconds
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError('max_bytes must be a positive integer')
        if type(deadline_seconds) is not int or deadline_seconds <= 0:
            raise ValueError('deadline_seconds must be a positive integer')
        result = None
        try:
            with _Deadline(deadline_seconds, self.clock) as deadline:
                # Ignore environment proxies: they would resolve/connect on our behalf.
                opener = self.opener if self.opener is not None else build_opener(
                    ProxyHandler({}), _Redirects(), _HTTPSHandler(self.resolver, deadline))
                result = self._get(url, etag, last_modified, to_file, source, max_bytes, deadline, opener, on_response)
            return result
        except BaseException:
            if result is not None and result.path is not None:
                result.path.unlink(missing_ok=True)
            raise

    def _get(self, url, etag, last_modified, to_file, source, max_bytes, deadline, opener, on_response):
        for _ in range(11):
            host = _destination(url, source)
            if self.opener is not None:
                if not self.injected_resolver:
                    raise ValueError('Injected source transport requires an explicit resolver')
                # Fake transports cannot establish a socket; validate before dispatch.
                _public_addresses(host, 443, self.resolver)
            headers = {'User-Agent': self.overrides.get(host, self.user_agent)}
            authorization = _authorization(source, host, self.github_token)
            if authorization:
                headers['Authorization'] = authorization
            if etag:
                headers['If-None-Match'] = etag
            if last_modified:
                headers['If-Modified-Since'] = last_modified
            request = Request(url, headers=headers)
            try:
                opened = (opener.open if hasattr(opener, 'open') else opener)(
                    request, timeout=min(60, deadline.remaining()))
            except HTTPError as error:
                opened = error
            with opened as response:
                deadline.check()
                status = response.status if response.status is not None else response.code
                received = {key.lower(): value for key, value in response.headers.items()}
                if on_response is not None:
                    on_response(host, status, received)
                if status in (301, 302, 303, 307, 308):
                    if not received.get('location'):
                        raise ValueError('Redirect has no Location')
                    url = urljoin(url, received['location'])
                    if source == 'cvelist':
                        # Validators belong to the requested URL; KEV keeps v0.1.6 behaviour.
                        etag = None
                    continue
                if status == 401 and authorization:
                    return Response(status, received, b'', None, url)
                limit = max_bytes if to_file and status == 200 else min(MAX_BODY_BYTES, max_bytes)
                path = None
                try:
                    if to_file and status == 200:
                        target = tempfile.NamedTemporaryFile(dir=self.data_dir, prefix='cornicen-',
                                                             suffix='.download', delete=False)
                        path = Path(target.name)
                        with target:
                            self._copy(response, target, limit, deadline)
                        return Response(status, received, None, path, url)
                    target = BytesIO()
                    self._copy(response, target, limit, deadline)
                    return Response(status, received, target.getvalue(), None, url)
                except BaseException:
                    if path is not None:
                        path.unlink(missing_ok=True)
                    raise
        raise ValueError('Too many redirects')

    @staticmethod
    def _copy(response, target, limit, deadline):
        total = 0
        # HTTPResponse.read1 performs at most one underlying read, so trickling
        # bodies return control for the elapsed-time check between reads.
        read = response.read1 if isinstance(response, HTTPResponse) else response.read
        while True:
            deadline.check()
            chunk = read(min(CHUNK_BYTES, limit - total + 1))
            deadline.check()
            if not chunk:
                if isinstance(response, HTTPResponse) and response.length:
                    raise EOFError('Truncated HTTP response body')
                return
            total += len(chunk)
            if total > limit:
                raise ValueError('HTTP response body size limit exceeded')
            target.write(chunk)

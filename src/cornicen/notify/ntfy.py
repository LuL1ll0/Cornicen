"""ntfy delivery with no redirect forwarding or diagnostic secret output."""

from email.header import Header
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
import io
import threading
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from cornicen.render import render


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


# Bound both elapsed request time and the number of abandoned resolver workers.
REQUEST_TIMEOUT = 60
_REQUEST_SLOTS = threading.BoundedSemaphore(4)


class _Deadline:
    def __init__(self):
        self.end = time.monotonic() + REQUEST_TIMEOUT
        self.cancelled = threading.Event()

    def remaining(self):
        remaining = self.end - time.monotonic()
        if self.cancelled.is_set() or remaining <= 0:
            raise TimeoutError('Notification request timed out')
        return min(REQUEST_TIMEOUT, remaining)


class _DeadlineReader(io.RawIOBase):
    def __init__(self, reader, sock, deadline):
        self.reader, self.sock, self.deadline = reader, sock, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        # read1 performs at most one underlying read. A buffered readline could
        # otherwise perform arbitrarily many successful reads of one byte each.
        self.sock.settimeout(self.deadline.remaining())
        data = self.reader.read1(len(buffer))
        self.deadline.remaining()
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        try:
            self.reader.close()
        finally:
            super().close()


class _DeadlineConnection:
    def __init__(self, *args, deadline, **kwargs):
        self.deadline = deadline
        super().__init__(*args, **kwargs)
        def response(sock, **options):
            result = HTTPResponse(sock, **options)
            result.fp = io.BufferedReader(_DeadlineReader(result.fp, sock, deadline))
            return result
        self.response_class = response

    def connect(self):
        self.timeout = self.deadline.remaining()
        super().connect()
        try:
            self.sock.settimeout(self.deadline.remaining())
        except BaseException:
            self.close()
            raise

    def send(self, data):
        self.deadline.remaining()
        if self.sock is not None:
            self.sock.settimeout(self.deadline.remaining())
        super().send(data)
        self.deadline.remaining()


class _HTTPConnection(_DeadlineConnection, HTTPConnection):
    pass


class _HTTPSConnection(_DeadlineConnection, HTTPSConnection):
    pass


class _HTTPHandler(HTTPHandler):
    handler_order = 501

    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def http_open(self, request):
        return self.do_open(lambda *args, **kwargs: _HTTPConnection(
            *args, deadline=self.deadline, **kwargs), request)


class _HTTPSHandler(HTTPSHandler):
    handler_order = 501

    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def https_open(self, request):
        return self.do_open(lambda *args, **kwargs: _HTTPSConnection(
            *args, deadline=self.deadline, **kwargs), request,
            context=self._context)


def post(url, body, headers):
    """POST with a total deadline, including DNS, connect, write and headers.

    A daemon isolates resolver calls that cannot be cancelled by Python. Timed
    out workers retain a bounded slot until exit and cannot acknowledge an alert.
    """
    if not _REQUEST_SLOTS.acquire(blocking=False):
        raise TimeoutError('Notification request timed out')
    deadline = worker = None
    try:
        deadline = _Deadline()
        done = threading.Event()
        outcome = []

        def run():
            try:
                outcome.append((_post(url, body, headers, deadline), None))
            except BaseException as error:
                outcome.append((None, error))
            finally:
                try:
                    _REQUEST_SLOTS.release()
                finally:
                    done.set()

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        if not done.wait(max(0, deadline.end - time.monotonic())):
            raise TimeoutError('Notification request timed out')
        status, error = outcome[0]
        if error is not None:
            raise error
        return status
    finally:
        try:
            if deadline is not None:
                deadline.cancelled.set()
        finally:
            # A started worker owns its slot until its own finally block runs.
            if worker is None or worker.ident is None:
                _REQUEST_SLOTS.release()


def _post(url, body, headers, deadline):
    # urllib's default redirect handler can forward Authorization. Disable all
    # redirects, including same-host redirects, for this authenticated channel.
    headers = dict(headers)
    if 'Title' in headers:
        title = ' '.join(headers['Title'].splitlines())
        headers['Title'] = Header(title, 'utf-8', maxlinelen=1000000).encode()
    request = Request(url, data=body, headers=headers, method='POST')
    try:
        with build_opener(_NoRedirect(), _HTTPHandler(deadline), _HTTPSHandler(deadline)).open(request, timeout=REQUEST_TIMEOUT) as response:
            deadline.remaining()
            return response.status
    except HTTPError as error:
        status = error.code
        error.close()
        return status


class NtfyNotifier:
    def __init__(self, http_post, url, topic, token):
        self.http_post = http_post
        self.url = url.rstrip('/') + '/' + quote(topic, safe='')
        self.token = token

    def send(self, n):
        try:
            title, text, priority, tags = render(n)
            headers = {'Title': title, 'Priority': str(priority), 'Tags': ','.join(tags),
                       'X-Cornicen-Event': n.key,
                       'Content-Type': 'text/plain; charset=utf-8'}
            if self.token is not None:
                headers['Authorization'] = 'Bearer ' + self.token.reveal()
            status = self.http_post(self.url, text.encode('utf-8'), headers)
            return 200 <= status < 300
        except Exception:
            # Even an HTTP implementation's exception can contain credentials.
            return False

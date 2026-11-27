"""A release-listing page cut short is requested again, within one small wait budget."""
from http.client import HTTPResponse, IncompleteRead
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest

from cornicen.fetch import Http
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.store import Store
from tests.source_helpers import Reply, public_resolver, release
from tests.test_cvelist_source import NOW

PAGE_TWO = 'https://api.github.com/repositories/1/releases?page=2'
# Real http.client responses built from raw bytes, cut off before the body ends.
FIXED_CUT = b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n[{"tag'
CHUNKED_CUT = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n[{"t'
RATE_CUT = (b'HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3600\r\nContent-Length: 100\r\n\r\n{"mess')


class _Socket:
    def __init__(self, raw):
        self.raw = raw

    def makefile(self, mode):
        return io.BytesIO(self.raw)


def response(raw):
    reply = HTTPResponse(_Socket(raw))
    reply.begin()
    return reply


class SequenceOpener:
    """Each URL serves its outcomes in order; the last one repeats."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request.full_url)
        outcomes = self.routes[request.full_url]
        outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, bytes):
            return response(outcome)
        body, status, headers = outcome
        return Reply(body, status, headers)


def page(releases, next_url=None):
    headers = {'Link': f'<{next_url}>; rel="next"'} if next_url else {}
    return (json.dumps(releases).encode(), 200, headers)


class ListingRetryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        self.store = Store(str(Path(directory.name) / 'state.db'))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.sleeps = []

    def source(self, routes):
        opener = SequenceOpener(routes)
        source = CveListSource(Http('test', {}, opener, resolver=public_resolver), self.store)
        source._retry_sleep = self.sleeps.append
        return source, opener

    def test_errors_keep_their_type_and_text(self):
        source, _ = self.source({RELEASES_URL: [FIXED_CUT]})
        with self.assertRaises(EOFError) as raised:
            source._get(RELEASES_URL, NOW)
        self.assertIs(type(raised.exception), EOFError)
        self.assertEqual(str(raised.exception), 'Truncated HTTP response body')
        self.assertEqual(raised.exception.truncated_body, 200)
        source, _ = self.source({RELEASES_URL: [CHUNKED_CUT]})
        with self.assertRaises(IncompleteRead) as raised:
            source._get(RELEASES_URL, NOW)
        self.assertIs(type(raised.exception), IncompleteRead)
        self.assertEqual(raised.exception.truncated_body, 200)

    def test_one_cut_page_is_requested_again(self):
        for cut in (FIXED_CUT, CHUNKED_CUT):
            with self.subTest(cut=cut[:40]):
                self.sleeps.clear()
                source, opener = self.source({RELEASES_URL: [cut, page([release(2)])]})
                releases, _ = source._listing('cve_2026-11-02_2300Z', NOW)
                self.assertEqual([r['tag_name'] for r in releases], ['cve_2026-11-02_2300Z'])
                self.assertEqual(opener.requests, [RELEASES_URL, RELEASES_URL])
                self.assertEqual(self.sleeps, [1])

    def test_a_cut_second_page_is_requested_again(self):
        source, opener = self.source({
            RELEASES_URL: [page([release(2)], PAGE_TWO)],
            PAGE_TWO: [FIXED_CUT, CHUNKED_CUT, page([release(1)])]})
        releases, _ = source._listing('cve_2026-11-01_2300Z', NOW)
        self.assertEqual(len(releases), 2)
        self.assertEqual(opener.requests, [RELEASES_URL, PAGE_TWO, PAGE_TWO, PAGE_TWO])
        self.assertEqual(self.sleeps, [1, 2])

    def test_three_cut_attempts_fail_with_the_usual_error(self):
        source, opener = self.source({RELEASES_URL: [FIXED_CUT]})
        with self.assertRaisesRegex(EOFError, '^Truncated HTTP response body$'):
            source._listing('cve_2026-11-02_2300Z', NOW)
        self.assertEqual(opener.requests, [RELEASES_URL] * 3)
        self.assertEqual(self.sleeps, [1, 2])

    def test_the_wait_budget_is_shared_across_pages(self):
        # Page one uses 1 s of the 3 s budget; page two's second wait (2 s) would pass it.
        source, opener = self.source({
            RELEASES_URL: [FIXED_CUT, page([release(2)], PAGE_TWO)],
            PAGE_TWO: [FIXED_CUT, FIXED_CUT, FIXED_CUT]})
        with self.assertRaisesRegex(EOFError, '^Truncated HTTP response body$'):
            source._listing('cve_2026-11-01_2300Z', NOW)
        self.assertEqual(self.sleeps, [1, 1])
        self.assertEqual(opener.requests, [RELEASES_URL, RELEASES_URL, PAGE_TWO, PAGE_TWO])

    def test_a_failed_poll_reads_exactly_as_before(self):
        for cut, text in ((FIXED_CUT, 'EOFError: Truncated HTTP response body'),
                          (CHUNKED_CUT, 'IncompleteRead: IncompleteRead(0 bytes read)')):
            with self.subTest(cut=cut[:40]):
                self.store.connection.execute('DELETE FROM cursors')
                source, _ = self.source({RELEASES_URL: [cut]})
                source.store.connection.execute('INSERT INTO cursors VALUES (?,?,?)',
                                                ('cvelist', 'cve_2026-11-02_2300Z', NOW.isoformat()))
                self.assertEqual(source.poll(NOW)[-1].errors, (text,))

    def test_a_cut_error_response_is_not_requested_again(self):
        source, opener = self.source({RELEASES_URL: [RATE_CUT]})
        with self.assertRaises(EOFError):
            source._listing('cve_2026-11-02_2300Z', NOW)
        self.assertEqual(opener.requests, [RELEASES_URL])
        self.assertEqual(self.sleeps, [])
        self.assertIsNotNone(self.store.get_meta('github_retry_at'))

    def test_a_deferral_after_a_wait_is_dated_from_the_retry(self):
        rate_cut = RATE_CUT.replace(b'Retry-After: 3600', b'Retry-After: 60')
        source, _ = self.source({RELEASES_URL: [FIXED_CUT, rate_cut]})
        with self.assertRaises(EOFError):
            source._listing('cve_2026-11-02_2300Z', NOW)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(self.store.get_meta('github_retry_at'),
                         (NOW + timedelta(seconds=61)).isoformat())

    def test_other_failures_are_not_requested_again(self):
        for outcome in (ConnectionResetError('reset'), (b'{}', 500, {}), (b'{}', 429, {}),
                        EOFError('Truncated HTTP response body'), IncompleteRead(b'', 4)):
            with self.subTest(outcome=outcome):
                self.sleeps.clear()
                source, opener = self.source({RELEASES_URL: [outcome]})
                with self.assertRaises(Exception):
                    source._listing('cve_2026-11-02_2300Z', NOW)
                self.assertEqual(opener.requests, [RELEASES_URL])
                self.assertEqual(self.sleeps, [])


if __name__ == '__main__':
    unittest.main()

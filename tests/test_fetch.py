import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from cornicen.fetch import Http
from tests.source_helpers import public_resolver, Opener


class FetchTests(unittest.TestCase):
    def test_headers_and_streaming(self):
        opener = Opener({'https://github.com/bulk': b'a' * 2000000})
        with tempfile.TemporaryDirectory(dir='.') as directory:
            http = Http('default', {'github.com': 'override'}, opener, data_dir=Path(directory), resolver=public_resolver)
            response = http.get('https://github.com/bulk', 'tag', 'yesterday', to_file=True,
                                source='cvelist')
            self.assertEqual(response.status, 200)
            self.assertIsNone(response.body)
            self.assertEqual(response.path.parent, Path(directory))
            self.assertEqual(response.path.stat().st_size, 2000000)
            response.path.unlink()
        request = opener.requests[0]
        self.assertEqual(request.get_header('User-agent'), 'override')
        self.assertEqual(request.get_header('If-none-match'), 'tag')
        self.assertEqual(request.get_header('If-modified-since'), 'yesterday')

    def test_http_errors_are_responses(self):
        error = HTTPError('https://github.com/', 304, 'unchanged', {}, None)
        response = Http('test', {}, Opener({'https://github.com/': error}), resolver=public_resolver).get(
            'https://github.com/', source='cvelist')
        self.assertEqual(response.status, 304)

    def test_interrupted_download_is_removed(self):
        class Broken(Opener):
            def open(self, request, timeout=None):
                from tests.source_helpers import Reply
                reply = Reply()
                def read(size=-1):
                    raise OSError('interrupted')
                reply.read = read
                return reply
        with tempfile.TemporaryDirectory(dir='.') as directory:
            with self.assertRaises(OSError):
                Http('test', {}, Broken({}), data_dir=Path(directory), resolver=public_resolver).get(
                    'https://github.com/', to_file=True, source='cvelist')
            self.assertEqual(list(Path(directory).iterdir()), [])

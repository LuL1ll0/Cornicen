"""Optional GitHub credentials, conditional requests, and public status contracts."""

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
import io
from http.client import HTTPResponse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import zlib

from cornicen.cli import main, status_json
from cornicen.config import load_config, SecretToken
from cornicen.fetch import Http
from cornicen.health import container_healthy
from cornicen.model import FetchStatus
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.store import Store
from tests.source_helpers import Opener, Reply, archive, public_resolver, release
from tests.test_cvelist_source import NOW

TOKEN = 'test-token-not-real-0001'


def headers(request):
    return {name.lower(): value for name, value in request.header_items()}


class GitHubTokenTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config_path = self.root / 'config.toml'
        self.db_path = self.root / 'state.db'
        self.config_path.write_text(f'db_path = "{self.db_path}"\nwatchlist_path = "{self.root / "watch.toml"}"\n')
        (self.root / 'watch.toml').write_text('')
        self.token_path = self.root / 'token'
        self.token_path.write_text(TOKEN + '\n')
        self.token_path.chmod(0o600)
        self.store = Store(str(self.db_path))
        self.store.migrate()
        self.addCleanup(self.store.connection.close)

    def config(self, env=None):
        return load_config(self.config_path, env or {})

    def source(self, routes=None, token=True):
        r = release(3)
        mapping = {RELEASES_URL: json.dumps([r]).encode(),
                   r['assets'][0]['browser_download_url']: archive(snapshot=True),
                   r['assets'][1]['browser_download_url']: archive()}
        mapping.update(routes or {})
        opener = Opener(mapping)
        http = Http('test', {}, opener, resolver=public_resolver, data_dir=self.root,
                    github_token=SecretToken(TOKEN) if token else None)
        return CveListSource(http, self.store), opener

    def cursor(self):
        self.store.connection.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
                                      ('cvelist', release(3, 1)['tag_name'], NOW.isoformat()))

    def cache(self, url=RELEASES_URL, used_at=NOW):
        self.store.connection.execute('INSERT OR REPLACE INTO http_cache VALUES (?,?,?,?,?)',
                                      (url, '"cached"', None, zlib.compress(b'[]'), used_at.isoformat()))

    def rows(self):
        return [tuple(row) for row in self.store.connection.execute('SELECT * FROM http_cache ORDER BY url')]

    def json_status(self, config=None):
        output = io.StringIO()
        with redirect_stdout(output):
            status_json(self.store, NOW, config or self.config())
        return json.loads(output.getvalue())

    def test_token_file_loaded(self):  # T1
        config = self.config({'CORNICEN_GITHUB_TOKEN_FILE': str(self.token_path)})
        self.assertEqual(config.github_token.reveal(), TOKEN)
        self.assertIsNone(config.github_token_problem)
        self.assertNotIn(TOKEN, repr(config))

    def test_token_absent_is_none(self):  # T2
        for env in ({}, {'CORNICEN_GITHUB_TOKEN_FILE': ''}, {'CORNICEN_GITHUB_TOKEN': TOKEN}):
            config = self.config(env)
            self.assertIsNone(config.github_token)
            self.assertIsNone(config.github_token_problem)

    def test_token_file_problems_do_not_raise(self):  # T3
        cases = [('missing', None, 0o600, 'unreadable'), ('empty', '', 0o600, 'empty'),
                 ('shared', TOKEN, 0o644, 'permissions'),
                 ('space', 'bad value', 0o600, 'invalid characters'),
                 ('control', 'bad\x00value', 0o600, 'invalid characters'),
                 ('encoding', b'\xff', 0o600, 'unreadable')]
        for name, value, mode, problem in cases:
            with self.subTest(name=name):
                path = self.root / name
                if value is not None:
                    path.write_bytes(value if isinstance(value, bytes) else value.encode())
                    path.chmod(mode)
                config = self.config({'CORNICEN_GITHUB_TOKEN_FILE': str(path)})
                self.assertIsNone(config.github_token)
                self.assertEqual(config.github_token_problem, problem)
                self.assertNotIn(str(path), config.github_token_problem)
        with self.config_path.open('a') as target:
            target.write('allow_shared_token_file = true\n')
        self.assertEqual(self.config({'CORNICEN_GITHUB_TOKEN_FILE': str(self.root / 'shared')}).github_token.reveal(), TOKEN)

    def test_bearer_sent_to_api_github_only(self):  # T4
        r = release(3)
        asset = 'https://release-assets.githubusercontent.com/example/snapshot'
        objects = 'https://objects.githubusercontent.com/example/delta'
        source, opener = self.source({r['assets'][1]['browser_download_url']: (b'', 302, {'Location': objects}),
                                      objects: archive(), r['assets'][0]['browser_download_url']: (b'', 302, {'Location': asset}),
                                      asset: archive(snapshot=True)})
        self.assertTrue(all(result.status == FetchStatus.COMPLETE for result in source.poll(NOW)))
        for kind, url in [('kev', 'https://www.cisa.gov/example'),
                          ('epss', 'https://epss.empiricalsecurity.com/example')]:
            opener.routes[url] = b'{}'
            source.http.get(url, source=kind)
        for request in opener.requests:
            expected = 'Bearer ' + TOKEN if urlsplit(request.full_url).hostname == 'api.github.com' else None
            self.assertEqual(headers(request).get('authorization'), expected)
        self.assertTrue(any(request.full_url == asset for request in opener.requests))
        self.assertTrue(any(request.full_url == objects for request in opener.requests))

    def test_redirect_off_api_drops_bearer(self):  # T5
        target = 'https://github.com/example'
        source, opener = self.source({RELEASES_URL: (b'', 302, {'Location': target}), target: b'[]'})
        source._get(RELEASES_URL, NOW)
        self.assertEqual(headers(opener.requests[0]).get('authorization'), 'Bearer ' + TOKEN)
        self.assertNotIn('authorization', headers(opener.requests[1]))

    def test_no_token_requests_unchanged(self):  # T6
        self.cursor()
        source, opener = self.source(token=False)
        self.assertEqual(source.poll(NOW)[0].status, FetchStatus.COMPLETE)
        expected = [(RELEASES_URL, {'user-agent': 'test'}),
                    (release(3)['assets'][1]['browser_download_url'], {'user-agent': 'test'})]
        self.assertEqual([(r.full_url, headers(r)) for r in opener.requests], expected)
        self.assertEqual(self.rows(), [])

    def test_etag_stored_and_sent(self):  # T7
        self.cursor()
        body = json.dumps([release(3)]).encode()
        source, opener = self.source({RELEASES_URL: (body, 200, {'ETag': 'W/"example"'})})
        source.poll(NOW)
        row = self.rows()[0]
        self.assertEqual(row[1], 'W/"example"')
        self.assertEqual(zlib.decompress(row[3]), body)
        source.poll(NOW + timedelta(minutes=1))
        self.assertEqual(headers(opener.requests[2]).get('if-none-match'), 'W/"example"')
        tag_url = RELEASES_URL + '/tags/' + release(3)['tag_name']
        opener.routes[tag_url] = (json.dumps(release(3)).encode(), 200, {'ETag': '"tag"'})
        source._get(tag_url, NOW)
        opener.routes[tag_url] = (b'', 304, {})
        self.assertEqual(json.loads(source._get(tag_url, NOW).body), release(3))
        self.assertEqual(headers(opener.requests[-1]).get('if-none-match'), '"tag"')
        self.store.connection.execute('DELETE FROM http_cache WHERE url=?', (tag_url,))
        for etag in ('', 'x' * 257, 'bad\nvalue', 'nonascii\u00e9'):
            opener.routes[RELEASES_URL] = (body, 200, {'ETag': etag})
            source.poll(NOW)
            self.assertEqual(self.rows(), [])

    def test_304_reuses_body_and_link(self):  # T8
        self.cursor()
        page2 = RELEASES_URL + '?page=2'
        source, opener = self.source({RELEASES_URL: (json.dumps([release(3)]).encode(), 200,
                                                        {'ETag': '"page1"', 'Link': f'<{page2}>; rel="next"'}),
                                      page2: b'[]'})
        first = source.poll(NOW)
        opener.routes[RELEASES_URL] = (b'', 304, {})
        opener.requests.clear()
        second = source.poll(NOW + timedelta(minutes=1))
        self.assertEqual([(r.cursor, list(r.records)) for r in second],
                         [(r.cursor, list(r.records)) for r in first])
        self.assertIn(page2, [r.full_url for r in opener.requests])
        self.assertEqual(self.rows()[0][4], (NOW + timedelta(minutes=1)).isoformat())

    def test_304_without_cache_fails(self):  # T9
        source, _ = self.source({RELEASES_URL: (b'', 304, {})})
        result, = source.poll(NOW)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertIn('HTTP 304 without cached body', ' '.join(result.errors))

    def test_no_conditional_without_token(self):  # T10
        self.cache(used_at=NOW - timedelta(days=8))
        before = self.rows()
        source, opener = self.source(token=False)
        source.poll(NOW)
        self.assertTrue(all('if-none-match' not in headers(r) for r in opener.requests))
        self.assertEqual(self.rows(), before)

    def test_cache_survives_restart(self):  # T11
        source, _ = self.source({RELEASES_URL: (json.dumps([release(3)]).encode(), 200, {'ETag': '"persisted"'})})
        source.poll(NOW)
        other = Store(str(self.db_path))
        self.addCleanup(other.connection.close)
        source, opener = self.source({RELEASES_URL: (b'', 304, {})})
        source = CveListSource(source.http, other)
        self.assertEqual(source.poll(NOW)[0].status, FetchStatus.COMPLETE)
        self.assertEqual(headers(opener.requests[0]).get('if-none-match'), '"persisted"')

    def test_cache_404_and_prune(self):  # T12
        tag = RELEASES_URL + '/tags/cve_2026-11-02_at_end_of_day'
        self.cache(tag)
        self.cache(RELEASES_URL + '?old', NOW - timedelta(days=8))
        self.cache(RELEASES_URL + '?keep', NOW - timedelta(days=7))
        source, _ = self.source()
        self.assertEqual(source._get(tag, NOW, allowed=(404,)).status, 404)
        source.poll(NOW)
        self.assertEqual([r[0] for r in self.rows()], [RELEASES_URL + '?keep'])

    def test_401_falls_back_once(self):  # T13
        self.cache()
        source, opener = self.source()
        original = opener.open
        def reject_first(request, timeout=None):
            if not opener.requests:
                opener.requests.append(request)
                return Reply(b'', 401)
            return original(request, timeout)
        opener.open = reject_first
        with self.assertLogs('cornicen.sources.cvelist', level='WARNING') as logs:
            results = source.poll(NOW)
        self.assertTrue(all(r.status == FetchStatus.COMPLETE for r in results))
        self.assertEqual(opener.requests[0].full_url, opener.requests[1].full_url)
        self.assertEqual(self.store.get_meta('github_auth'), 'token rejected')
        source.poll(NOW)
        for request in opener.requests[1:]:
            self.assertNotIn('authorization', headers(request))
            self.assertNotIn('if-none-match', headers(request))
        self.assertEqual(len(logs.output), 1)
        self.assertNotIn(TOKEN, ''.join(logs.output))
        source, _ = self.source({RELEASES_URL: (b'', 401, {})}, token=False)
        self.assertIn('HTTP 401', ' '.join(source.poll(NOW)[0].errors))
        source, opener = self.source({RELEASES_URL: (b'', 401, {})})
        with self.assertLogs('cornicen.sources.cvelist', level='WARNING'):
            result, = source.poll(NOW)
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(result.status, FetchStatus.FAILED)
        self.assertNotIn('authorization', headers(opener.requests[1]))


    def test_rate_limit_recorded(self):  # T14
        reset = NOW + timedelta(hours=1)
        values = {'X-RateLimit-Limit': '5000', 'X-RateLimit-Remaining': '4987',
                  'X-RateLimit-Reset': str(int(reset.timestamp()))}
        for status in (200, 304, 403, 429):
            with self.subTest(status=status):
                source, opener = self.source({RELEASES_URL: (b'[]', status, values)})
                source.poll(NOW)
                state = json.loads(self.store.get_meta('github_rate_limit'))
                self.assertEqual(state, dict(limit=5000, remaining=4987, reset=reset.isoformat(), observed_at=NOW.isoformat()))
                for bad in ({'X-RateLimit-Limit': '3'}, *({**values, key: 'invalid'} for key in values)):
                    opener.routes[RELEASES_URL] = (b'[]', 200, bad)
                    source._get(RELEASES_URL, NOW)
                    self.assertEqual(json.loads(self.store.get_meta('github_rate_limit')), state)

    def test_status_line_authenticated(self):  # T15
        self.store.set_meta('github_auth', 'token')
        self.store.set_meta('github_rate_limit', json.dumps(dict(limit=5000, remaining=4987,
                            reset='2026-11-03T11:49:00+00:00', observed_at='2026-11-03T10:51:00+00:00')))
        output = io.StringIO()
        with patch.dict('os.environ', {'CORNICEN_GITHUB_TOKEN_FILE': str(self.token_path)}), redirect_stdout(output):
            with patch('cornicen.config.Path.open', autospec=True, side_effect=Path.open) as opened:
                self.assertEqual(main(['--config', str(self.config_path), 'status']), 0)
                self.assertFalse(any(call.args[0] == self.token_path for call in opened.call_args_list))
        text = output.getvalue()
        self.assertIn('github: authenticated; rate limit 4987/5000, resets 11:49 UTC (seen 10:51 UTC)', text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(str(self.token_path), text)

    def test_status_json_github_object(self):  # T16
        self.assertEqual(self.json_status()['github'], dict(auth='unknown', problem=None, rate_limit=None))
        source, _ = self.source(token=False)
        CveListSource(source.http, self.store, github_token_problem='unreadable')
        self.assertEqual(self.store.get_meta('github_auth'), 'token unusable: unreadable')
        for stored, auth, problem in [('token', 'token', None), ('none', 'none', None),
                                     ('token unusable: unreadable', 'token-unusable', 'unreadable'),
                                     ('token rejected', 'token-rejected', None)]:
            self.store.set_meta('github_auth', stored)
            result = self.json_status()
            self.assertEqual(result['schema_version'], 1)
            self.assertEqual(result['github'], dict(auth=auth, problem=problem, rate_limit=None))

    def test_container_health_unchanged_by_token_problem(self):  # T17
        config = self.config()
        expected = container_healthy(self.store, NOW, config)
        for auth in ('token unusable: unreadable', 'token rejected'):
            self.store.set_meta('github_auth', auth)
            self.assertEqual(container_healthy(self.store, NOW, config), expected)
        self.store.set_meta('baseline_complete', '1')
        self.assertFalse(container_healthy(self.store, NOW, config))

    def test_deferral_ignored_across_modes(self):  # T18
        for mode in (None, 'none', 'token'):
            self.store.connection.execute("DELETE FROM meta WHERE k IN ('github_retry_at','github_retry_mode')")
            self.store.set_meta('github_retry_at', (NOW + timedelta(hours=1)).isoformat())
            if mode:
                self.store.set_meta('github_retry_mode', mode)
            source, opener = self.source()
            results = source.poll(NOW)
            if mode == 'token':
                self.assertEqual(results, [])
                self.assertEqual(opener.requests, [])
            else:
                self.assertEqual(results[0].status, FetchStatus.COMPLETE)
                self.assertIsNone(self.store.get_meta('github_retry_at'))
                self.assertIsNone(self.store.get_meta('github_retry_mode'))
        self.store.connection.execute("DELETE FROM meta WHERE k IN ('github_retry_at','github_retry_mode')")
        source, _ = self.source({RELEASES_URL: (b'', 429, {})})
        source.poll(NOW)
        self.assertEqual(self.store.get_meta('github_retry_mode'), 'token')

    def test_token_redacted_everywhere(self):  # T19
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from cornicen.scheduler import Scheduler, safe_message
        from tests.replay.harness import FakeClock, RecordingNotifier
        config = replace(self.config(), github_token=SecretToken(TOKEN), ntfy_token=None)
        clock = FakeClock(NOW)
        class CapturingNotifier(RecordingNotifier):
            def __init__(self, clock):
                super().__init__(clock)
                self.notifications = []

            def send(self, notification):
                self.notifications.append(notification)
                return super().send(notification)

        notifier = CapturingNotifier(clock)
        engine = Engine(self.store, [], AliasMap.load(False), config, clock, notifier)
        source, _ = self.source({RELEASES_URL: ValueError('failure ' + TOKEN)})
        output = io.StringIO()
        scheduler = Scheduler(engine, {'cvelist': source}, clock=clock, output=lambda s: output.write(s))
        class Empty:
            def poll(self, now):
                return []
        scheduler.sources.update(kev=Empty(), epss=Empty())
        with patch('logging.Logger.handle') as log:
            scheduler.tick()
            scheduler._failed_cycle(ValueError('failure ' + TOKEN))
            with redirect_stdout(output), patch('cornicen.cli.load_config', return_value=config):
                main(['--config', str(self.config_path), 'status'])
                main(['--config', str(self.config_path), 'status', '--json'])
            captured = repr(log.call_args_list)
        self.assertTrue(notifier.notifications)
        dump = '\n'.join(self.store.connection.iterdump())
        self.assertNotIn(TOKEN, dump + output.getvalue() + captured + repr(notifier.__dict__))
        self.assertNotIn(TOKEN, safe_message(ValueError('failure ' + TOKEN), SecretToken(TOKEN)))

    def test_docs_describe_token(self):  # T20
        install = Path('docs/install.md').read_text()
        for phrase in ('CORNICEN_GITHUB_TOKEN_FILE', 'fine-grained', 'read-only'):
            self.assertIn(phrase, install)
        self.assertRegex(Path('docs/privacy.md').read_text(), r'(?s)token goes only to `api\.github\.com`')

    def test_non_ascii_token_is_invalid(self):  # T21
        for char in ('\ufeff', '\u200b', '\u20ac', '\u00e9', '\x7f'):
            with self.subTest(char=repr(char)):
                self.token_path.write_text(TOKEN[:5] + char + TOKEN[5:], encoding='utf-8')
                config = self.config({'CORNICEN_GITHUB_TOKEN_FILE': str(self.token_path)})
                self.assertIsNone(config.github_token)
                self.assertEqual(config.github_token_problem, 'invalid characters')

    def test_redirect_does_not_forward_validator_or_cache(self):  # T22
        target = RELEASES_URL + '?page=2'
        self.cache()
        before = self.rows()
        for status in (200, 304, 404):
            with self.subTest(status=status):
                self.cache()
                source, opener = self.source({RELEASES_URL: (b'', 302, {'Location': target}),
                                              target: (b'[{}]', status, {'ETag': '"other"'})})
                if status == 304:
                    with self.assertRaisesRegex(ValueError, 'HTTP 304'):
                        source._get(RELEASES_URL, NOW)
                else:
                    response = source._get(RELEASES_URL, NOW, allowed=(404,))
                    self.assertEqual(response.status, status)
                    self.assertEqual(response.body, b'[{}]')
                self.assertEqual(headers(opener.requests[0]).get('if-none-match'), '"cached"')
                self.assertNotIn('if-none-match', headers(opener.requests[1]))
                self.assertEqual(self.rows(), before)

    def test_truncated_401_body_still_falls_back(self):  # T23
        source, opener = self.source()
        class MemorySocket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 9\r\nX-RateLimit-Limit: 5000\r\nX-RateLimit-Remaining: 4999\r\nX-RateLimit-Reset: 1793707200\r\n\r\nbad')
        original = opener.open
        def rejected(request, timeout=None):
            if not opener.requests:
                opener.requests.append(request)
                response = HTTPResponse(MemorySocket())
                response.begin()
                return response
            return original(request, timeout)
        opener.open = rejected
        results = source.poll(NOW)
        self.assertEqual([result.status for result in results], [FetchStatus.COMPLETE] * 2)
        self.assertEqual(self.store.get_meta('github_auth'), 'token rejected')
        self.assertEqual(len(opener.requests), 4)
        self.assertNotIn('authorization', headers(opener.requests[1]))
        self.assertEqual(json.loads(self.store.get_meta('github_rate_limit'))['remaining'], 4999)

    def test_non_api_deferral_blocks_both_modes(self):  # T24
        for status in (403, 429):
            for host in ('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'):
                for token in (False, True):
                    with self.subTest(status=status, host=host, token=token):
                        self.store.connection.execute("DELETE FROM meta WHERE k IN ('github_retry_at','github_retry_mode')")
                        url = 'https://' + host + '/example'
                        source, _ = self.source({url: (b'', status, {'Retry-After': '3600', 'X-RateLimit-Remaining': '0'})}, token=token)
                        with self.assertRaisesRegex(ValueError, 'HTTP ' + str(status)):
                            source._get(url, NOW)
                        self.assertEqual(self.store.get_meta('github_retry_mode'), 'any')
                        for next_token in (False, True):
                            next_source, opener = self.source(token=next_token)
                            self.assertEqual(next_source.poll(NOW + timedelta(minutes=5)), [])
                            self.assertEqual(opener.requests, [])
                            self.assertEqual(self.store.get_meta('github_retry_mode'), 'any')
                            self.assertEqual(self.store.get_meta('github_retry_at'), (NOW + timedelta(hours=1)).isoformat())

    def test_control_chars_cannot_rebuild_token(self):  # T25
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from cornicen.model import IngestResult, Origin
        from cornicen.scheduler import redact_tokens, safe_message
        from tests.replay.harness import FakeClock, RecordingNotifier
        config = replace(self.config(), github_token=SecretToken(TOKEN), ntfy_token=SecretToken(TOKEN))
        clock = FakeClock(NOW)
        engine = Engine(self.store, [], AliasMap.load(False), config, clock, RecordingNotifier(clock))
        record = {'cveMetadata': {'cveId': 'CVE-2026-10000', 'state': 'REJECTED'}}
        for char in ('\x00', '\u200b'):
            with self.subTest(char=repr(char)):
                message = 'transport ' + TOKEN[:5] + char + TOKEN[5:]
                ingest = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                      release(3)['tag_name'], NOW, records=(record,))
                with patch.object(engine, '_apply_record', side_effect=RuntimeError(message)):
                    engine.run_cycle([ingest])
                self.assertNotIn(TOKEN, '\n'.join(self.store.connection.iterdump()))
                self.assertEqual(redact_tokens(message, SecretToken(TOKEN)), 'transport [redacted]')
                self.assertNotIn(TOKEN, safe_message(RuntimeError(message), SecretToken(TOKEN)))

    def test_release_tag_warning_redacted(self):  # T26
        for rejected, ntfy_only in ((False, False), (True, False), (False, True)):
            with self.subTest(rejected=rejected, ntfy_only=ntfy_only):
                body = json.dumps([{'tag_name': TOKEN}, release(3)]).encode()
                source, opener = self.source({RELEASES_URL: (b'', 401, {}) if rejected else body}, token=not ntfy_only)
                if ntfy_only:
                    source = CveListSource(source.http, self.store, ntfy_token=SecretToken(TOKEN))
                original = opener.open
                def respond(request, timeout=None):
                    response = original(request, timeout)
                    opener.routes[RELEASES_URL] = body
                    return response
                opener.open = respond
                with self.assertLogs('cornicen.sources.cvelist', level='WARNING') as logs:
                    source.poll(NOW)
                self.assertNotIn(TOKEN, '\n'.join(logs.output))
                self.assertIn('Skipping unrecognised release tag', '\n'.join(logs.output))

    def test_malformed_rate_limit_meta_tolerated(self):  # T27
        valid = dict(limit=5000, remaining=4987, reset=NOW.isoformat(), observed_at=NOW.isoformat())
        cases = ['not json', 'null', '[]', '1', '"text"', '{}', '[' * 1100 + ']' * 1100]
        for key in valid:
            cases.append(json.dumps({k: v for k, v in valid.items() if k != key}))
            for value in (None, True, [], 'invalid'):
                cases.append(json.dumps({**valid, key: value}))
        cases.append(json.dumps({**valid, 'reset': '2026-11-03T12:00:00'}))
        for value in cases:
            with self.subTest(value=value):
                self.store.set_meta('github_rate_limit', value)
                self.store.connection.commit()
                for args in ([], ['--json']):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = main(['--config', str(self.config_path), 'status', *args])
                    self.assertEqual(code, 0)
                    if args:
                        result = json.loads(output.getvalue())
                        self.assertTrue(result['available'])
                        self.assertIsNone(result['github']['rate_limit'])
                    else:
                        self.assertIn('rate limit not seen yet', output.getvalue())

    def test_redaction_before_truncation(self):  # T28
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from cornicen.model import IngestResult, Origin
        from tests.replay.harness import FakeClock, RecordingNotifier
        config = replace(self.config(), github_token=SecretToken(TOKEN))
        clock = FakeClock(NOW)
        engine = Engine(self.store, [], AliasMap.load(False), config, clock, RecordingNotifier(clock))
        for offset in (170, 177, 190):
            with self.subTest(offset=offset):
                engine.run_cycle([IngestResult('cvelist', FetchStatus.FAILED, Origin.DELTA, None, None,
                                               errors=('x' * offset + TOKEN,))])
                self.assertNotIn(TOKEN[:8], '\n'.join(self.store.connection.iterdump()))
        body = json.dumps({'message': 'y' * 177 + TOKEN}).encode()
        source, _ = self.source({RELEASES_URL: (body, 422, {})})
        errors = ' '.join(error for result in source.poll(NOW) for error in result.errors)
        self.assertIn('HTTP 422', errors)
        self.assertNotIn(TOKEN[:8], errors)

    def test_kev_redirect_keeps_validator(self):  # T29
        kev = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        moved = 'https://www.cisa.gov/feeds/kev.json'
        opener = Opener({kev: (b'', 302, {'Location': moved}), moved: (b'', 304, {})})
        http = Http('Cornicen/test', {}, opener, resolver=public_resolver, github_token=SecretToken(TOKEN))
        http.get(kev, '"kev-tag"', source='kev')
        self.assertEqual([headers(request).get('if-none-match') for request in opener.requests],
                         ['"kev-tag"', '"kev-tag"'])
        self.assertTrue(all('authorization' not in headers(request) for request in opener.requests))

    def test_spec_names_both_secrets(self):  # T30
        text = (Path(__file__).parents[1] / 'docs' / 'spec.md').read_text()
        self.assertNotIn('Secrets (ntfy token)', text)
        self.assertIn('GitHub token from a file only', text)

    def listing_routes(self):
        pages = [RELEASES_URL] + [RELEASES_URL + f'?page={n}' for n in range(2, 6)]
        entries = [[release(3, 3), release(3, 4)], [release(3, 5), release(3)]]
        routes = {url: (json.dumps(entries[min(n, 1)]).encode(), 200,
                        {'Link': f'<{pages[n + 1]}>; rel="next"'})
                  for n, url in enumerate(pages[:-1])}
        routes[pages[-1]] = (b'{"message":"Only the first 1000 results are available"}', 422, {})
        return routes, pages

    def test_authenticated_listing_stops_at_result_cap(self):  # T31
        self.cursor()
        routes, pages = self.listing_routes()
        source, opener = self.source(routes)
        with patch('cornicen.sources.cvelist.LISTING_RESULT_CAP', 3, create=True):
            result, = source.poll(NOW)
        self.assertEqual(result.status, FetchStatus.COMPLETE)
        self.assertEqual(result.cursor, release(3)['tag_name'])
        self.assertEqual(len(result.records), 1)
        self.assertEqual([r.full_url for r in opener.requests],
                         pages[:2] + [release(3)['assets'][1]['browser_download_url']])
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                if terminal:
                    body, status, _ = routes[pages[1]]
                    routes[pages[1]] = (body, status, {})
                source, _ = self.source(routes)
                with patch('cornicen.sources.cvelist.LISTING_RESULT_CAP', 3, create=True):
                    releases, exhausted = source._listing(release(3, 1)['tag_name'], NOW)
                self.assertEqual(releases, [release(3, hour) for hour in (3, 4, 5, 23)])
                self.assertFalse(exhausted)

    def test_anonymous_listing_still_ends_on_422(self):  # T32
        self.cursor()
        routes, pages = self.listing_routes()
        for rejected in (False, True):
            with self.subTest(rejected=rejected):
                source, opener = self.source(routes, token=rejected)
                if rejected:
                    original = opener.open
                    def reject_second_page(request, timeout=None):
                        if request.full_url == pages[1] and len(opener.requests) == 1:
                            opener.requests.append(request)
                            return Reply(b'', 401)
                        return original(request, timeout)
                    opener.open = reject_second_page
                with patch('cornicen.sources.cvelist.LISTING_RESULT_CAP', 3, create=True):
                    if rejected:
                        with self.assertLogs('cornicen.sources.cvelist', level='WARNING'):
                            result, = source.poll(NOW)
                    else:
                        result, = source.poll(NOW)
                self.assertEqual(result.status, FetchStatus.COMPLETE)
                self.assertEqual(result.cursor, release(3)['tag_name'])
                expected = pages[:2] + pages[1:] if rejected else pages
                self.assertEqual([r.full_url for r in opener.requests],
                                 expected + [release(3)['assets'][1]['browser_download_url']])
                for request in opener.requests[2:] if rejected else opener.requests:
                    self.assertEqual(headers(request), {'user-agent': 'test'})
                self.assertIsNone(source.http.github_token)
                self.assertEqual(self.rows(), [])

    def test_listing_cap_counts_skipped_entries(self):  # T33
        routes, pages = self.listing_routes()
        entries = [dict(release(3), draft=True), dict(release(3), prerelease=True),
                   {'tag_name': 'unrecognised'}]
        _, status, links = routes[RELEASES_URL]
        routes[RELEASES_URL] = (json.dumps(entries).encode(), status, links)
        source, opener = self.source(routes)
        with patch('cornicen.sources.cvelist.LISTING_RESULT_CAP', 4, create=True):
            with self.assertLogs('cornicen.sources.cvelist', level='WARNING'):
                releases, exhausted = source._listing(release(3, 1)['tag_name'], NOW)
        self.assertEqual([r.full_url for r in opener.requests], pages[:2])
        self.assertEqual(releases, [release(3, 5), release(3)])
        self.assertFalse(exhausted)

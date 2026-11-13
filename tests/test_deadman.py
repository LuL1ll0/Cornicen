"""Opt-in dead-man pings, delivery silence, and secret boundaries."""

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, Mock

from cornicen import cli
from cornicen.config import load_config, SecretToken
from tests import test_scheduler as helpers


URL = 'https://ping.example.invalid/abc123?check=fixture'


class DeadmanConfigTests(unittest.TestCase):
    def load(self, text='', env=None):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'config.toml'
            path.write_text(text)
            return load_config(path, env or {})

    def test_deadman_defaults_and_environment_secret(self):
        config = self.load()
        self.assertIsNone(config.deadman_url)
        self.assertEqual(config.deadman_interval_minutes, 5)
        config = self.load('deadman_interval_minutes = 2', {'CORNICEN_DEADMAN_URL': URL})
        self.assertEqual(config.deadman_url.reveal(), URL)
        self.assertEqual(config.deadman_interval_minutes, 2)
        self.assertNotIn(URL, repr(config))

    def test_deadman_file_secret_and_precedence(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'secret'
            path.write_text(URL + '\n')
            path.chmod(0o600)
            env = {'CORNICEN_DEADMAN_URL_FILE': str(path)}
            self.assertEqual(self.load(env=env).deadman_url.reveal(), URL)
            env['CORNICEN_DEADMAN_URL'] = 'http://ping.example.invalid/other'
            self.assertEqual(self.load(env=env).deadman_url.reveal(), env['CORNICEN_DEADMAN_URL'])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.load(env={'CORNICEN_DEADMAN_URL_FILE': str(path)})

    def test_deadman_invalid_scheme_unreadable_file_and_toml_are_private(self):
        for env in ({'CORNICEN_DEADMAN_URL': 'ftp://ping.example.invalid/abc123'},
                    {'CORNICEN_DEADMAN_URL': 'https://'},
                    {'CORNICEN_DEADMAN_URL_FILE': 'missing-fixture-secret-file'}):
            with self.subTest(env=env):
                with self.assertRaises(ValueError) as caught:
                    self.load(env=env)
                self.assertNotIn('abc123', str(caught.exception))
                self.assertNotIn('missing-fixture-secret-file', str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            self.load('deadman_url = "' + URL + '"')
        self.assertNotIn(URL, str(caught.exception))
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('')
            for env in ({'CORNICEN_DEADMAN_URL': 'ftp://ping.example.invalid/abc123'},
                        {'CORNICEN_DEADMAN_URL_FILE': 'missing-fixture-secret-file'}):
                output = io.StringIO()
                with patch.dict('os.environ', env, clear=True), redirect_stdout(output):
                    self.assertEqual(cli.main(['--config', str(path), 'status']), 1)
                self.assertIn('command failed', output.getvalue())
                self.assertNotIn('abc123', output.getvalue())
                self.assertNotIn('missing-fixture-secret-file', output.getvalue())

    def test_deadman_interval_validation(self):
        # Valid input also proves the setting passes the TOML secret-name rule.
        self.assertEqual(self.load('deadman_interval_minutes = 1').deadman_interval_minutes, 1)
        for value in ('0', '-1', 'true', '1.5', '"5"'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load('deadman_interval_minutes = ' + value)


class DeadmanSchedulerTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp

    def completed_tick(self):
        report = self.scheduler.tick()
        worker = getattr(self.scheduler, 'deadman_worker', None)
        if worker:
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.scheduler._collect_deadman()
        return report

    def enable(self):
        self.engine.config = replace(self.engine.config, deadman_url=SecretToken(URL))

    def test_deadman_off_no_request(self):
        with patch('urllib.request.OpenerDirector.open') as request:
            self.completed_tick()
        request.assert_not_called()
        self.assertEqual(json.loads(self.lines[-1])['deadman'], 'off')

    def test_deadman_get_after_heartbeat_interval_monotonic_restart(self):
        self.enable()
        elapsed = [0]
        self.scheduler.monotonic = lambda: elapsed[0]
        observed = []
        started_after = []
        start_thread = threading.Thread.start
        def start(worker):
            started_after.append((len(self.lines), self.engine.db.in_transaction))
            start_thread(worker)
        def sent(request, *args, **kwargs):
            observed.append((request, kwargs, len(self.lines), threading.get_ident()))
            return Mock(__enter__=Mock(return_value=Mock()), __exit__=Mock(return_value=False))
        with patch('urllib.request.OpenerDirector.open', side_effect=sent) as request, \
             patch('threading.Thread.start', side_effect=start, autospec=True):
            self.completed_tick()
            self.clock.now += timedelta(days=1)
            elapsed[0] = 299
            self.completed_tick()
            self.assertEqual(request.call_count, 1)
            elapsed[0] = 300
            self.completed_tick()
            self.assertEqual(request.call_count, 2)
            from cornicen.scheduler import Scheduler
            restarted = Scheduler(self.engine, self.sources, self.clock, self.lines.append,
                                  monotonic=lambda: 301)
            restarted.tick()
            worker = getattr(restarted, 'deadman_worker', None)
            if worker:
                worker.join(2)
            self.assertEqual(request.call_count, 3)
        req, kwargs, lines, worker_id = observed[0]
        self.assertNotEqual(worker_id, threading.get_ident())
        self.assertEqual(started_after[0], (1, False))
        self.assertEqual(lines, 1)
        self.assertEqual(kwargs, {'timeout': 10})
        self.assertEqual(req.get_method(), 'GET')
        self.assertEqual(req.full_url, URL)
        self.assertIsNone(req.data)
        self.assertEqual(dict(req.header_items()), {'User-agent': 'Cornicen'})

    def test_deadman_failed_tick_never_pings(self):
        self.enable()
        with patch('urllib.request.OpenerDirector.open') as request:
            with patch.object(self.engine, 'run_cycle', side_effect=RuntimeError('failed')):
                with self.assertRaises(RuntimeError) as caught:
                    self.completed_tick()
            self.scheduler._failed_cycle(caught.exception)
        request.assert_not_called()
        self.assertNotIn('deadman', json.loads(self.lines[-1]))

    def test_deadman_unhealthy_cvelist_still_pings(self):
        self.enable()
        with self.store.transaction():
            self.engine._health('cvelist', 'unhealthy', 'Incomplete fetch')
        self.sources['cvelist'].poll.return_value = []
        with patch('urllib.request.OpenerDirector.open') as request:
            self.completed_tick()
        request.assert_called_once()
        self.assertEqual(json.loads(self.lines[-1])['sources']['cvelist'], 'unhealthy')

    def test_deadman_failed_due_delivery_skips_until_sent(self):
        self.enable()
        self.engine.notifier.send = Mock(return_value=False)
        with self.store.transaction():
            self.engine._health('cvelist', 'unhealthy', 'Incomplete fetch')
        self.sources['cvelist'].poll.return_value = []
        with patch('urllib.request.OpenerDirector.open') as request:
            self.completed_tick()
            self.assertEqual(json.loads(self.lines[-1])['deadman'], 'skipped')
            self.completed_tick()  # Retry backoff does not make delivery healthy.
            request.assert_not_called()
            self.engine.notifier.send.return_value = True
            self.clock.now += timedelta(minutes=1)
            self.completed_tick()
            request.assert_called_once()

    def test_deadman_timeout_health_rate_limit_recovery_and_privacy(self):
        self.enable()
        with patch('urllib.request.OpenerDirector.open', side_effect=TimeoutError(URL)) as request:
            self.completed_tick()
            before = {r['source']: tuple(r) for r in self.engine.db.execute('SELECT * FROM health')
                      if r['source'] != 'deadman'}
            row = self.engine.db.execute("SELECT state,detail FROM health WHERE source='deadman'").fetchone()
            self.assertEqual(tuple(row), ('unhealthy', 'Ping failed'))
            body = json.loads(self.engine.db.execute(
                "SELECT body_json FROM outbox WHERE pair_key LIKE '%deadman%' ").fetchone()[0])
            self.assertEqual(body['reason'], 'failed')
            self.completed_tick()
            self.assertEqual(request.call_count, 1)
            self.assertEqual(json.loads(self.lines[-1])['deadman'], 'failed')
            self.clock.now += timedelta(minutes=5)
            self.completed_tick()
            self.assertEqual(request.call_count, 2)
            self.assertEqual(self.engine.db.execute(
                "SELECT count(*) FROM events WHERE record_id='deadman'").fetchone()[0], 1)
            after = {r['source']: tuple(r) for r in self.engine.db.execute('SELECT * FROM health')
                     if r['source'] != 'deadman'}
            self.assertEqual(before, after)
        with patch('urllib.request.OpenerDirector.open'):
            self.clock.now += timedelta(minutes=5)
            self.completed_tick()
        self.assertEqual(self.engine.db.execute(
            "SELECT state FROM health WHERE source='deadman'").fetchone()[0], 'healthy')
        self.assertNotIn(URL, '\n'.join(self.lines))
        self.assertNotIn(URL, '\n'.join(row[0] for row in self.engine.db.execute('SELECT detail FROM health')))

    def test_deadman_redaction_status_command_failed_and_health(self):
        self.enable()
        config = self.engine.config
        with self.store.transaction():
            self.engine._health('scheduler', 'unhealthy', 'Cannot read ' + URL)
        self.assertNotIn(URL, self.engine.db.execute(
            "SELECT detail FROM health WHERE source='scheduler'").fetchone()[0])
        # Exercise both status forms against a proxy that leaves the fixture open.
        proxy = Mock(wraps=self.store)
        proxy.connection = Mock(wraps=self.store.connection)
        proxy.connection.close.return_value = None
        for args in (['status'], ['status', '--json']):
            output = io.StringIO()
            with patch('cornicen.cli.load_config', return_value=config), \
                 patch('cornicen.cli.Store', return_value=proxy), \
                 patch('cornicen.cli.Path.is_file', return_value=True), redirect_stdout(output):
                self.assertEqual(cli.main(args), 0)
            self.assertNotIn(URL, output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output):
            cli.status_json(self.store, self.clock(), config)
        self.assertNotIn(URL, output.getvalue())
        output = io.StringIO()
        with patch('cornicen.cli.load_config', return_value=config), \
             patch('cornicen.cli.Store', side_effect=RuntimeError(URL)), \
             patch('cornicen.cli.Path.is_file', return_value=True), redirect_stdout(output):
            self.assertEqual(cli.main(['healthcheck']), 1)
        self.assertNotIn(URL, output.getvalue())
        self.assertIn('command failed', output.getvalue())
        self.scheduler._failed_cycle(RuntimeError(URL))
        self.assertNotIn(URL, '\n'.join(self.lines))

    def test_deadman_request_error_and_future_outbox_do_not_block(self):
        self.enable()
        with self.store.transaction():
            self.store.queue('fixture-future', 'normal', ['unhealthy'],
                             {'record_id': 'fixture', 'detail': 'failed'},
                             (self.clock() + timedelta(days=1)).isoformat())
            self.engine.db.execute("UPDATE outbox SET attempts=1 WHERE pair_key='fixture-future'")
        with patch('urllib.request.OpenerDirector.open', side_effect=OSError(URL)) as request:
            self.completed_tick()
            request.assert_called_once()
        self.assertEqual(self.engine.db.execute(
            "SELECT state FROM health WHERE source='deadman'").fetchone()[0], 'unhealthy')
        self.assertNotIn(URL, '\n'.join(self.lines))

    def test_deadman_cvelist_warning_redacts_url(self):
        self.enable()
        from cornicen.sources.cvelist import CveListSource
        http = Mock()
        http.github_token = None
        http.data_dir = self.path.parent
        source = CveListSource(http, self.store, deadman_url=self.engine.config.deadman_url)
        response = Mock(status=200, headers={}, body=json.dumps([{'tag_name': URL}]).encode())
        with patch.object(source, '_get', return_value=response), \
             self.assertLogs('cornicen.sources.cvelist', level='WARNING') as logs, \
             self.assertRaisesRegex(ValueError, 'No CVE releases'):
            source._listing(None, self.clock())
        self.assertNotIn(URL, '\n'.join(logs.output))
        self.assertIn('[redacted]', '\n'.join(logs.output))

    def test_deadman_redirect_policy(self):
        self.enable()
        from cornicen.deadman import SameHostRedirect
        from urllib.request import Request
        handler = SameHostRedirect()
        request = Request(URL)
        self.assertIsNone(handler.redirect_request(request, None, 302, 'Found', {},
                                                 'https://other.example.invalid/path'))
        self.assertIsNone(handler.redirect_request(request, None, 302, 'Found', {},
                                                 'file:///fixture'))
        self.assertIsNotNone(handler.redirect_request(request, None, 302, 'Found', {},
                                                    'https://ping.example.invalid/next'))


class DeadmanRoundTwoTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp
    enable = DeadmanSchedulerTests.enable
    completed_tick = DeadmanSchedulerTests.completed_tick
    # Reuse the fixture without inheriting the round-one cases a second time.
    def test_r2_worker_deadline_single_flight_and_shutdown(self):
        self.enable()
        entered, release = threading.Event(), threading.Event()
        threads = []
        def blocked(url):
            threads.append(threading.get_ident())
            entered.set()
            release.wait(5)
        health_threads = []
        original = self.engine._health
        def health(*args, **kwargs):
            health_threads.append(threading.get_ident())
            return original(*args, **kwargs)
        with patch('cornicen.scheduler.ping', side_effect=blocked) as ping, \
             patch.object(self.engine, '_health', side_effect=health):
            try:
                started = time.monotonic()
                self.scheduler.tick()
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(entered.wait(1))
                worker = self.scheduler.deadman_worker
                self.assertTrue(worker.daemon)
                self.assertIsNone(self.engine.db.execute("SELECT state FROM health WHERE source='deadman'").fetchone())
                self.clock.now += timedelta(seconds=30)
                self.scheduler.tick()
                self.assertEqual(json.loads(self.lines[-1])['deadman'], 'failed')
                self.clock.now += timedelta(minutes=10)
                self.scheduler.tick()
                self.assertEqual(ping.call_count, 1)
                import signal
                handlers = {}
                def register(sig, handler):
                    handlers[sig] = handler
                    return signal.SIG_DFL
                def terminate(_):
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
                with patch('cornicen.scheduler.signal.signal', side_effect=register), \
                     patch.object(self.scheduler.stop, 'wait', side_effect=terminate):
                    started = time.monotonic()
                    self.scheduler.run()
                    self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(all(t == threading.get_ident() for t in health_threads))
                self.assertNotEqual(threads, [threading.get_ident()])
            finally:
                release.set()
                worker = getattr(self.scheduler, 'deadman_worker', None)
                if worker:
                    worker.join(2)
        # Late success cannot recover a timed-out request.
        self.scheduler._collect_deadman()
        self.assertEqual(self.scheduler.deadman_result, 'failed')

    def test_r2_delivery_completion_clock(self):
        self.enable()
        with self.store.transaction():
            self.store.queue('future', 'normal', ['unhealthy'], {'record_id': 'fixture'},
                             (self.clock() + timedelta(seconds=10)).isoformat())
        self.engine.notifier.send = Mock(return_value=False)
        original = self.engine.run_cycle
        def slow(ingests):
            self.clock.now += timedelta(seconds=70)
            return original(ingests)
        with patch.object(self.engine, 'run_cycle', side_effect=slow), patch('cornicen.scheduler.ping') as ping:
            self.scheduler.tick()
            ping.assert_not_called()
        self.assertEqual(json.loads(self.lines[-1])['deadman'], 'skipped')

    def test_r2_optional_monitor_failure_preserves_container(self):
        from cornicen.health import container_healthy
        from cornicen.scheduler import Scheduler
        self.enable()
        with patch('cornicen.scheduler.ping', side_effect=OSError(URL)):
            self.completed_tick()
        self.assertTrue(container_healthy(self.store, self.clock(), self.engine.config))

    def test_r2_disabled_ignores_stored_failure_without_recovery(self):
        from cornicen.scheduler import Scheduler
        self.enable()
        with patch('cornicen.scheduler.ping', side_effect=OSError(URL)):
            self.completed_tick()
        events = self.engine.db.execute("SELECT count(*) FROM events WHERE record_id='deadman'").fetchone()[0]
        self.engine.config = replace(self.engine.config, deadman_url=None)
        self.scheduler = Scheduler(self.engine, self.sources, self.clock, self.lines.append)
        self.scheduler.tick()
        output = io.StringIO()
        with redirect_stdout(output):
            cli.status_json(self.store, self.clock(), self.engine.config)
        self.assertNotIn('deadman', json.loads(output.getvalue())['sources'])
        self.assertNotIn('deadman', json.loads(self.lines[-1])['health_details'])
        self.assertEqual(events, self.engine.db.execute("SELECT count(*) FROM events WHERE record_id='deadman'").fetchone()[0])

    def test_r2_derived_secrets_all_boundaries(self):
        from urllib.parse import quote, unquote
        from cornicen.scheduler import safe_message, redact_tokens
        url = 'https://user2099:pass2099@watcher.example.invalid/complete/%76ault2099/RuntimeError?q=%71uery2099#frag2099'
        self.engine.config = replace(self.engine.config, deadman_url=SecretToken(url))
        parts = [url, url.split('#')[0], unquote(url), quote(url, safe=''),
                 'user2099:pass2099', '/complete/%76ault2099/RuntimeError', 'complete', 'RuntimeError',
                 'vault2099', 'query2099', '%71uery2099', 'q=%71uery2099',
                 quote(url), 'watcher.example.invalid']
        for special in ('HTTPS://watcher.example.invalid/complete',
                        'https://%5Bwatcher.example.invalid/complete'):
            self.assertEqual(redact_tokens(unquote(special), SecretToken(special)), '[redacted]')
        for part in parts:
            with self.subTest(part=part):
                error = RuntimeError('Cannot read ' + part)
                self.assertNotIn(part, safe_message(error, self.engine.config.deadman_url))
                self.assertEqual(redact_tokens(part, self.engine.config.deadman_url), '[redacted]')
                with self.store.transaction():
                    self.engine._health('scheduler', 'unhealthy', error)
                self.assertNotIn(part, self.engine.db.execute("SELECT detail FROM health WHERE source='scheduler'").fetchone()[0])
                self.scheduler._failed_cycle(error)
                self.assertNotIn(part, self.lines[-1])
                output = io.StringIO()
                with patch('cornicen.cli.load_config', return_value=self.engine.config), \
                     patch('cornicen.cli.Store', side_effect=error), \
                     patch('cornicen.cli.Path.is_file', return_value=True), redirect_stdout(output):
                    self.assertEqual(cli.main(['healthcheck']), 1)
                self.assertNotIn(part, output.getvalue())

    def test_r2_json_escaped_unicode_component_is_private(self):
        from cornicen.scheduler import safe_message
        url = 'https://watcher.invalid/mön2099?x=opaque2099'
        self.engine.config = replace(self.engine.config, deadman_url=SecretToken(url))
        component = 'mön2099'
        escaped = json.dumps(component)[1:-1]
        for text in (component, escaped):
            with self.subTest(text=text):
                error = RuntimeError('Cannot read ' + text)
                self.assertNotIn(escaped, safe_message(error, self.engine.config.deadman_url))
                with self.store.transaction():
                    self.engine._health('scheduler', 'unhealthy', error)
                detail = self.engine.db.execute("SELECT detail FROM health WHERE source='scheduler'").fetchone()[0]
                self.assertNotIn(component, detail)
                self.assertNotIn(escaped, detail)
                self.scheduler._failed_cycle(error)
                self.assertNotIn(escaped, self.lines[-1])
                self.assertNotIn(component, self.lines[-1])


    def test_r2_completed_result_written_on_scheduler_next_tick(self):
        self.enable()
        with patch('cornicen.scheduler.ping', side_effect=OSError(URL)):
            self.scheduler.tick()
            worker = getattr(self.scheduler, 'deadman_worker', None)
            if worker:
                worker.join(2)
            self.assertIsNone(self.engine.db.execute("SELECT state FROM health WHERE source='deadman'").fetchone())
            self.scheduler.tick()
        self.assertEqual(json.loads(self.lines[-1])['deadman'], 'failed')
        self.assertEqual(self.engine.db.execute("SELECT state FROM health WHERE source='deadman'").fetchone()[0], 'unhealthy')

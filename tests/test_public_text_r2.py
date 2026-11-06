"""Round-two regressions with fictional record and watch data."""

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
import io
import json
import unittest
from unittest.mock import patch

from cornicen import cli
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.public_text import prepare_inventory, public_text, public_token
from cornicen.watchlist import load_document_text
from tests import test_public_text as boundary
from tests import test_scheduler as helpers
from tests.test_public_text_r1 import RECORD_ID_PREFIXES


class RuleTests(unittest.TestCase):
    def test_record_roles_withhold_the_entire_remainder(self):
        for prefix in RECORD_ID_PREFIXES:
            for ids in ('x; api.github.com', 'x; Unavailable; python',
                        'x, api.github.com', '403, 2026-11-05',
                        'x; ' + prefix + ' api.github.com'):
                with self.subTest(prefix=prefix, ids=ids):
                    self.assertEqual(public_text('HTTP ' + prefix + ' ' + ids),
                                     'HTTP ' + prefix + ' [redacted]')
        # Prefix declaration order must not pick a later span over an earlier one.
        for first in RECORD_ID_PREFIXES:
            for second in RECORD_ID_PREFIXES:
                self.assertEqual(public_text(first + ' x; ' + second + ' api.github.com'),
                                 first + ' [redacted]')

    def test_punctuation_is_judged_before_peeling(self):
        for token in ('....', '(....)', '(.-.)', '---___---', '(-),', '-_+~', '(-)', '--', '/=', '...'):
            self.assertEqual(public_text('HTTP ' + token), 'HTTP [redacted]')
            self.assertIsNone(public_token(token))
        for token in (':', '-', '/', '='):
            self.assertEqual(public_text(token), token)
            self.assertEqual(public_token(token), token)

    def test_punctuation_shape_is_independent_of_inventory(self):
        for field in ({'id': '--..'}, {'name': '--..'}, {'version': '--..'},
                      {'match': (('--..', 'fiction'),)}, {'product_only': ('--..',)}):
            inventory = (replace(boundary.INVENTORY[0], **field),)
            for token in ('--', '..', '--.'):
                with self.subTest(field=field, token=token):
                    self.assertEqual(public_text('HTTP ' + token, inventory), 'HTTP [redacted]')
                    self.assertIsNone(public_token(token, inventory))
        inventory = (replace(boundary.INVENTORY[0], name='fiction--..'),)
        self.assertEqual(public_text('--', inventory), '[redacted]')
        for token in ('-', '.', ':'):
            inventory = (replace(boundary.INVENTORY[0], name=token),)
            self.assertEqual(public_text(token, inventory), token)
            self.assertEqual(public_token(token, inventory), token)

    def test_empty_inventory_values_are_dropped(self):
        inventory = (replace(boundary.INVENTORY[0], name='\u200b', version='',
                             product_only=('\x00',)),)
        self.assertNotIn('', prepare_inventory(inventory))
        self.assertEqual(public_text('HTTP : (HTTP)', inventory), 'HTTP : (HTTP)')
        self.assertEqual(public_token(':', inventory), ':')


class LogTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp
    heartbeat = boundary.LogBoundaryTests.heartbeat

    def test_semicolon_ids_and_comma_list_through_real_dead_letters(self):
        ids = ('x; api.github.com', 'x; Unavailable; python', 'api.github.com')
        records = [{'cveMetadata': {'cveId': rid, 'state': 'PUBLISHED'},
                    'containers': {'cna': {'affected': []}}} for rid in ids]
        self.scheduler.tick()
        for _ in range(5):
            self.sources['cvelist'].poll.return_value = [IngestResult(
                'cvelist', FetchStatus.COMPLETE, Origin.DELTA, 'cursor',
                self.clock(), records=records)]
            self.scheduler.next_poll.clear()
            self.scheduler.tick()
            self.clock.now += timedelta(minutes=1)
        self.assertEqual(dict(self.store.connection.execute(
            'SELECT record_id,attempts FROM dead_letters')), dict.fromkeys(ids, 5))
        self.sources['cvelist'].poll.return_value = [IngestResult(
            'cvelist', FetchStatus.FAILED, Origin.DELTA, None,
            self.clock(), errors=['HTTP 403'])]
        self.scheduler.next_poll.clear()
        self.scheduler.tick()
        self.assertEqual(json.loads(self.lines[-1])['health_details']['cvelist'],
                         'Dead-letter records: [redacted]')
        stored = self.store.connection.execute(
            "SELECT detail FROM health WHERE source='cvelist'").fetchone()[0]
        for rid in ids:
            self.assertIn(rid, stored)
        self.assertIn(', ', stored)
        self.assertIn('last error: HTTP 403', stored)

    def test_punctuation_wrappers_and_cut_on_every_log_path(self):
        cases = [
            ('....', text, '[redacted]')
            for text in ('HTTP....', '....HTTP', '(HTTP)....', '403....',
                         '2026-11-05....', '(....)', '(.-.)')
        ]
        cases.extend((
            ('-- --', 'HTTP -- --', 'HTTP [redacted]'),
            ('..........', 'x' * 291 + ' HTTP..........', '[redacted]'),
            ('....', 'HTTP 403;', 'HTTP 403;'),
            ('....', 'error:', 'error:'),
            ('....', '(HTTP)', '(HTTP)'),
        ))
        for secret, text, expected in (*cases, ('....', 'HTTP (....)', 'HTTP [redacted]'),
                                       ('.-.', 'HTTP (.-.)', 'HTTP [redacted]'),
                                       ('---___---___', 'x' * 290 + ' ---___---___', '[redacted]')):
            with self.subTest(secret=secret):
                self.engine.watches = load_document_text(
                    '[[watch]]\nid=' + json.dumps('qzzfiction' if secret == '-- --' else secret)
                    + '\nname=' + json.dumps('-- --' if secret == '-- --' else 'Qzzfiction') + '\n'
                    'match=["qzzfiction:wzzfiction"]\nversion="7.8.9"\nscheme="opaque"\n')[0]
                direct = public_text(text, self.engine.watches)
                self.assertEqual(direct, expected)
                token = public_token(text, self.engine.watches)
                self.assertEqual(token, text if expected == text and len(text.split()) == 1 else None)
                self.assertEqual(self.heartbeat(text), expected)
                with patch.object(self.engine, '_flush', side_effect=RuntimeError(text)):
                    self.scheduler._failed_cycle(RuntimeError(text))
                entry = json.loads(self.lines[-1])
                self.assertEqual(entry['message'], expected)
                self.assertEqual(entry['health_message'], expected)
                out = io.StringIO()
                # A separate store prevents startup's close from consuming the fixture.
                from cornicen.store import Store
                store = Store(':memory:')
                with (patch('cornicen.cli.load_config', return_value=self.engine.config),
                      patch('cornicen.cli.Store', return_value=store),
                      patch('cornicen.cli.load_document', return_value=(self.engine.watches, ())),
                      patch('cornicen.cli.AliasMap.load', side_effect=RuntimeError(text)),
                      redirect_stdout(out)):
                    self.assertEqual(cli.main(['run']), 1)
                self.assertEqual(out.getvalue(), 'command failed: RuntimeError: ' + expected + '\n')

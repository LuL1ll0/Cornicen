"""Round-one regressions; all inventory and record identifiers are fictional."""

import ast
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import timedelta
import io
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from cornicen import cli
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.public_text import PUNCTUATION, public_text, public_token
from tests import test_public_text as boundary
from tests import test_scheduler as helpers


RECORD_ID_PREFIXES = ('Dead-letter records:', 'Missing stored record:',
                      'Declared record missing or invalid:')


class RoleAndCoreTests(unittest.TestCase):
    def test_record_id_roles(self):
        for prefix in RECORD_ID_PREFIXES:
            for ids in ('api.github.com', 'HTTP 403 python', '[redacted]', '---___---___'):
                with self.subTest(prefix=prefix, ids=ids):
                    self.assertEqual(public_text(prefix + ' ' + ids + '; HTTP 403'),
                                     prefix + ' [redacted]')
                    self.assertEqual(public_text(prefix + ' ' + ids), prefix + ' [redacted]')

    def test_record_literal_list_covers_source(self):
        # Inspect literal text, including f-string pieces, rather than filter output.
        from cornicen import public_text as module
        self.assertEqual(getattr(module, 'RECORD_ID_PREFIXES', ()), RECORD_ID_PREFIXES)
        found = set()
        for path in Path('src/cornicen').rglob('*.py'):
            if path.name == 'vocabulary.py':
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    found.update(re.findall(r'[^;\n]*\brecords?\b[^;:\n]*:', node.value, re.I))
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == '_health' and len(node.args) >= 3):
                    for detail in ast.walk(node.args[2]):
                        if (isinstance(detail, ast.Constant) and isinstance(detail.value, str)
                                and re.search(r'\brecords?\b', detail.value, re.I)):
                            self.assertIn(detail.value.strip(), RECORD_ID_PREFIXES, str(path))
        self.assertEqual(found, set(RECORD_ID_PREFIXES))

    def test_punctuation_inventory_core_and_whole_token(self):
        for secret, token in (('---___---___', '---___---___'),
                              ('---___---___', '(---___---___),'),
                              ('()', '()')):
            inventory = (replace(boundary.INVENTORY[0], id=secret),)
            self.assertEqual(public_text('HTTP ' + token, inventory), 'HTTP [redacted]')
            self.assertIsNone(public_token(token, inventory))
        self.assertEqual(public_text('HTTP : (-),'), 'HTTP : [redacted]')

    def test_substring_floor_and_normalization(self):
        inventory = (replace(boundary.INVENTORY[0], id='xxＨＴＴＰyy',
                             name='xxfull-\u200bsnapshotyy'),)
        self.assertEqual(public_text('HTTP full-snapshot', inventory), '[redacted]')
        short = (replace(boundary.INVENTORY[0], id='xxhasxx', name='xxhttpxx'),)
        self.assertEqual(public_text('has HTTP', short), 'has [redacted]')
        self.assertEqual(public_text('has', (replace(short[0], id='has'),)), '[redacted]')

    def test_peel_set_and_exact_marker(self):
        self.assertEqual(PUNCTUATION, '.,;:!?()[]{}<>"\'')
        self.assertEqual(public_text('-HTTP- /HTTP/ _HTTP_'), '[redacted]')
        inventory = (replace(boundary.INVENTORY[0], id='redacted'),)
        self.assertEqual(public_text('redacted', inventory), '[redacted]')
        self.assertIsNone(public_token('redacted', inventory))
        self.assertEqual(public_text('[redacted]', inventory), '[redacted]')
        self.assertEqual(public_token('[redacted]', inventory), '[redacted]')


class LogRegressionTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp
    heartbeat = boundary.LogBoundaryTests.heartbeat

    def test_record_dead_letter_then_fetch_failure(self):
        self.scheduler.tick()
        record = {'cveMetadata': {'cveId': 'api.github.com', 'state': 'PUBLISHED'},
                  'containers': {'cna': {'affected': []}}}
        for _ in range(5):
            self.sources['cvelist'].poll.return_value = [IngestResult(
                'cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                'cursor', self.clock(), records=[record])]
            self.scheduler.next_poll.clear()
            self.scheduler.tick()
            self.clock.now += timedelta(minutes=1)
        row = self.store.connection.execute('SELECT record_id,attempts FROM dead_letters').fetchone()
        self.assertEqual(tuple(row), ('api.github.com', 5))
        self.sources['cvelist'].poll.return_value = [IngestResult(
            'cvelist', FetchStatus.FAILED, Origin.DELTA, None, self.clock(), errors=['HTTP 403'])]
        self.scheduler.next_poll.clear()
        self.scheduler.tick()
        self.assertEqual(json.loads(self.lines[-1])['health_details']['cvelist'],
                         'Dead-letter records: [redacted]')
        stored = self.store.connection.execute("SELECT detail FROM health WHERE source='cvelist'").fetchone()[0]
        self.assertIn('api.github.com', stored)

    def test_truncated_composite_and_plain_vocabulary_prefix(self):
        for secret, offset in (('full-snapshot-77391', 286), ('Unavailablefiction', 288)):
            self.engine.watches = (replace(boundary.INVENTORY[0], id=secret),)
            text = 'x' * offset + ' ' + secret
            self.assertEqual(self.heartbeat(text), '[redacted]')
            with patch.object(self.engine, '_flush', side_effect=RuntimeError(text)):
                self.scheduler._failed_cycle(RuntimeError(text))
            entry = json.loads(self.lines[-1])
            self.assertEqual(entry['message'], '[redacted]')
            self.assertEqual(entry['health_message'], '[redacted]')

    def test_each_failed_cycle_field_uses_inventory(self):
        self.engine.watches = (replace(boundary.INVENTORY[0], id='RuntimeError'),)
        with patch.object(self.engine, '_flush', side_effect=RuntimeError('RuntimeError')):
            self.scheduler._failed_cycle(RuntimeError('RuntimeError'))
        entry = json.loads(self.lines[-1])
        self.assertEqual({key: entry[key] for key in ('error', 'message', 'health_error', 'health_message')},
                         {'error': 'Exception', 'message': '[redacted]',
                          'health_error': 'Exception', 'health_message': '[redacted]'})

    def test_startup_uses_loaded_inventory_only(self):
        watches = (replace(boundary.INVENTORY[0], id='RuntimeError'),)
        for loaded in (False, True):
            out = io.StringIO()
            with (patch('cornicen.cli.load_config', return_value=self.engine.config),
                  patch('cornicen.cli.Store', return_value=self.store),
                  patch('cornicen.cli.load_document', return_value=(watches, ())) as load,
                  patch('cornicen.cli.AliasMap.load', side_effect=RuntimeError('RuntimeError')),
                  redirect_stdout(out)):
                if not loaded:
                    load.side_effect = RuntimeError('RuntimeError')
                self.assertEqual(cli.main(['run']), 1)
            self.assertEqual(out.getvalue(), 'command failed: Exception: [redacted]\n' if loaded
                             else 'command failed: RuntimeError: RuntimeError\n')
            # cli.main closes its store on both paths; create a fresh one next time.
            if not loaded:
                from cornicen.store import Store
                self.store = Store(':memory:')
                self.store.migrate()
                self.addCleanup(self.store.connection.close)

    def test_heartbeat_builds_inventory_once(self):
        from cornicen import public_text as module
        original = module._inventory
        builds = []
        def count(watches):
            if not hasattr(module, '_Inventory') or not isinstance(watches, module._Inventory):
                builds.append(watches)
            return original(watches)
        with patch('cornicen.public_text._inventory', side_effect=count):
            self.scheduler.tick()
        self.assertEqual(len(builds), 1)


class ParserRegressionTests(unittest.TestCase):
    def test_real_run_parser_fixed_stderr(self):
        for args in (['run', 'quartz-watch-77391', 'CVE-2098-77391001'],
                     ['--config', 'fiction.toml', 'run', '--private-77391'],
                     ['run', '--config', 'fiction.toml']):
            with self.subTest(args=args):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                    cli.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(out.getvalue(), '')
                self.assertEqual(err.getvalue(), 'usage: cornicen [--config CONFIG] run\n')

    def test_other_commands_keep_argparse_diagnostics(self):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            cli.main(['healthcheck', 'fiction-77391'])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('error: unrecognized arguments: fiction-77391', err.getvalue())

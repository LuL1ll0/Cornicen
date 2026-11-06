"""Container-log word rule, using only fictional inventory."""

from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import random
import re
import sqlite3
import string
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from unittest.mock import patch

from cornicen import cli
from cornicen.public_text import public_text, public_token, BUILTIN_EXCEPTIONS
from cornicen.scheduler import safe_message
from cornicen.vocabulary import WORDS
from cornicen.watchlist import Watch
from cornicen.versions import Scheme
from tests import test_scheduler as helpers
from tools.gen_vocabulary import generate


INVENTORY = (Watch('quartz-watch-77391', 'docker Straße İgranite Ｑuartz',
                   (('quartzfiction', 'prism77391'), ('watch', 'cve')),
                   ('Zephyr Gizmo 9000', 'error'), '1.2.3', Scheme.DOTTED, False),)
PINNED = (
    'Complete fetch; content age within source policy',
    'Complete fetch; catalog 0 days old', 'Complete fetch; catalog 1 day old',
    'No fetch failure', 'Watchlist re-match complete',
    'Complete fetch; content age within source policy; full-snapshot reconcile: 2026-11-06T00:20:16.169361+00:00',
    'Incomplete ingest; retry pending; last error: Delta has no recognised records or explicit zero-change manifest',
    'Incomplete ingest; retry pending; last error: ValueError: GitHub pagination page limit exceeded',
    'Incomplete ingest; retry pending; last error: ValueError: HTTP 403',
    'Incomplete ingest; retry pending; last error: ValueError: No full snapshot cutoff covers 2026-11-05',
    'Source content is stale; last error: ValueError: No full snapshot cutoff covers 2026-11-05',
    'Baseline pending', 'Cycle completed', 'Watchlist reload rejected',
)


class PublicTextTests(unittest.TestCase):
    def boundary_call(self, function, *args):
        try:
            return function(*args)
        except Exception as error:
            self.fail(f'Boundary raised {type(error).__name__}')

    def test_boundary_fails_soft_on_inventory_and_filter_errors(self):
        class BrokenInventory:
            def __iter__(self):
                raise sqlite3.OperationalError('database is locked')

        class BrokenWatch:
            @property
            def id(self):
                raise sqlite3.OperationalError('database is locked')

        for inventory in (BrokenInventory(), (BrokenWatch(),)):
            with self.subTest(inventory=type(inventory).__name__):
                self.assertEqual(self.boundary_call(public_text, 'HTTP', inventory), '[redacted]')
                self.assertIsNone(self.boundary_call(public_token, 'HTTP', inventory))
        for stage in ('_strip', '_allowed'):
            with patch('cornicen.public_text.' + stage,
                       side_effect=sqlite3.OperationalError('database is locked')):
                self.assertEqual(self.boundary_call(public_text, 'HTTP'), '[redacted]')
                self.assertIsNone(self.boundary_call(public_token, 'HTTP'))

    def test_ascii_punctuation_only_cores(self):
        for text in string.punctuation:
            with self.subTest(text=text):
                self.assertEqual(public_text(text), text)
                self.assertEqual(public_token(text), text)
        for text in ('--', '/=', '-_+', '(-)', '(HTTP),', '-quartzfiction-', '/77391quartz/', '=é=', '—', '！'):
            with self.subTest(text=text):
                self.assertEqual(public_text(text), '[redacted]')
                self.assertIsNone(public_token(text))

    def test_inventory_controls_stripped_before_normalization(self):
        fields = (
            {'id': 'watch\u200blist'}, {'name': 'watch\u200blist'},
            {'match': (('watch\u200blist', 'fiction'),)},
            {'product_only': ('watch\u200blist',)}, {'version': 'watch\u200blist'},
            {'name': 'ｗａｔｃｈ\x00ｌｉｓｔ'},
        )
        for field in fields:
            with self.subTest(field=field):
                inventory = (replace(INVENTORY[0], **field),)
                for text in ('watchlist', 'watch\u200blist'):
                    self.assertEqual(public_text(text, inventory), '[redacted]')
                    self.assertIsNone(public_token(text, inventory))

    def test_allowed_shapes_fuzz(self):
        rng = random.Random(77391)
        # Independent grammar and inventory construction for the output oracle.
        blocked = {'docker', 'strasse', 'i̇granite', 'quartz', 'quartzfiction',
                   'prism77391', 'watch', 'cve', 'zephyr', 'gizmo', 'error'}
        date = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?\Z')
        atoms = sorted(WORDS) + ['quartz-watch-77391', 'CVE-2026-12345', '1.2.3',
            'docker', 'watch', 'ＣＶＥ', 'ſource', 'Falſe', 'K', '2026-11-05evil',
            '2026-11-05T12:03:04.123456Z', '2026-11-05', '403', '\x00', '\u200b',
            'quartz-\u200bwatch-77391', '[redacted]', '١٢٣', '２０２６-１１-０５']
        for _ in range(int(os.environ.get('CORNICEN_FUZZ_CASES', '2000'))):
            text = ' '.join(rng.choices(atoms, k=rng.randrange(1, 15)))
            result = public_text(text, INVENTORY)
            for token in result.split():
                if token == '[redacted]':
                    continue
                core = token.strip('.,;:!?()[]{}<>"\'')
                self.assertTrue(not core or re.fullmatch('[0-9]+', core) or date.fullmatch(core)
                    or (core.isascii() and core.casefold() in WORDS | BUILTIN_EXCEPTIONS
                        and core.casefold() not in blocked), (text, result, core))
            self.assertFalse(any(unicodedata.category(c).startswith('C') for c in result))

    def test_whole_cores_ascii_and_full_iso(self):
        for text in ('CVE-2026-12345', 'watch-77391', 'watch.77391', '1.2.3',
                     '2026-11-05quartz', '2026-11-05T12:00Zquartz', 'Falſe', 'K', '١٢٣'):
            with self.subTest(text=text):
                self.assertEqual(public_text(text), '[redacted]')
                self.assertIsNone(public_token(text))
        for text in ('403', '2026-11-05', '2026-11-05T12:34',
                     '2026-11-05T12:34:56.123456+00:00', '(HTTP)', ':'):
            self.assertEqual(public_text(text), text)
        self.assertEqual(public_text('bad\u200bquartz \x00HTTP'), '[redacted] HTTP')
        self.assertIsNone(public_token('HTTP error'))

    def test_inventory_all_fields_and_normalization(self):
        watch = Watch('HTTP-id', 'Ｆａｉｌｅｄ Name', (('Source', 'catalog'),),
                      ('complete fetch',), 'pending', Scheme.OPAQUE, False)
        for token in ('HTTP-id', 'HTTP', 'failed', 'name', 'source', 'catalog',
                      'complete', 'fetch', 'pending'):
            self.assertEqual(public_text(token, (watch,)), '[redacted]', token)
        numeric = replace(watch, id='403', version='2026-11-05')
        self.assertEqual(public_text('403 2026-11-05', (numeric,)), '403 2026-11-05')

    def test_marker_is_stable_and_collapses(self):
        inventory = (replace(INVENTORY[0], name='redacted', id='redacted'),)
        self.assertEqual(public_text('[redacted]', inventory), '[redacted]')
        self.assertEqual(public_token('[redacted]', inventory), '[redacted]')
        self.assertEqual(public_text('quartz [redacted] prism\t[redacted]', inventory), '[redacted]')
        self.assertEqual(public_text('[redacted] HTTP [redacted]'), '[redacted] HTTP [redacted]')

    def test_vocabulary_current_and_independent_of_generated_file(self):
        path = Path('src/cornicen/vocabulary.py')
        self.assertEqual(path.read_text(), generate())
        self.assertFalse(any(re.search(r'CVE-\d|GHSA-', w, re.I) for w in WORDS))
        with tempfile.TemporaryDirectory(dir='.') as directory:
            root = Path(directory)
            source = root / 'src/cornicen'
            source.mkdir(parents=True)
            (source / 'vocabulary.py').write_text('not valid python -- secretword')
            (source / 'sample.py').write_text('"""moduleprivate"""\nclass FictionError:\n """classprivate"""\n def f(self):\n  """functionprivate"""\n  return f"Literal {3} tail CVE-2098-77391 GHSA-abcd cve-2098-1 ghsa-efgh café"\n')
            generated = generate(root)
            self.assertIn("'literal'", generated)
            self.assertIn("'fictionerror'", generated)
            for forbidden in ('moduleprivate', 'classprivate', 'functionprivate', 'secretword', 'cve-2098', 'ghsa-abcd', 'ghsa-efgh', 'café'):
                self.assertNotIn(forbidden, generated)
        result = subprocess.run([sys.executable, 'tools/gen_vocabulary.py', '--check'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class LogBoundaryTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp

    def heartbeat(self, text):
        with self.store.transaction():
            self.engine._health('watchlist', 'unhealthy', text)
        stored = self.engine.db.execute("SELECT detail FROM health WHERE source='watchlist'").fetchone()[0]
        self.scheduler.tick()
        self.assertEqual(self.engine.db.execute("SELECT detail FROM health WHERE source='watchlist'").fetchone()[0], stored)
        return json.loads(self.lines[-1])['health_details']['watchlist']

    def startup(self, error, command='run'):
        output = io.StringIO()
        with patch('cornicen.cli.load_config', side_effect=error), redirect_stdout(output):
            self.assertEqual(cli.main([command]), 1)
        return output.getvalue()

    def test_heartbeat_inventory_failure_withholds_keys(self):
        class BrokenInventory:
            def __iter__(self):
                raise sqlite3.OperationalError('database is locked')

        self.scheduler.tick()
        expected = len(json.loads(self.lines[-1])['health_details'])
        # Keep the inventory fault inside the log boundary, after engine work.
        run_cycle = self.engine.run_cycle
        def cycle(ingests):
            report = run_cycle(ingests)
            self.engine.watches = BrokenInventory()
            return report

        with patch.object(self.engine, 'run_cycle', side_effect=cycle):
            try:
                self.scheduler.tick()
            except Exception as error:
                self.fail(f'Heartbeat raised {type(error).__name__}')
        entry = json.loads(self.lines[-1])
        self.assertEqual(entry['health_details'], {})
        self.assertEqual(entry['health_details_withheld'], expected)
        row = self.engine.db.execute("SELECT state FROM health WHERE source='scheduler'").fetchone()
        self.assertTrue(row is None or row[0] == 'healthy')

    def test_heartbeat_value_failure_still_prints_markers(self):
        class BrokenWatch:
            @property
            def id(self):
                raise sqlite3.OperationalError('database is locked')

        self.scheduler.tick()
        # Key checks succeed; only value filtering sees the inaccessible watch.
        with patch('cornicen.scheduler.public_text',
                   side_effect=lambda text, watches: public_text(text, (BrokenWatch(),))):
            try:
                self.scheduler.tick()
            except Exception as error:
                self.fail(f'Heartbeat raised {type(error).__name__}')
        entry = json.loads(self.lines[-1])
        self.assertGreater(len(entry['health_details']), 0)
        self.assertEqual(set(entry['health_details'].values()), {'[redacted]'})
        self.assertEqual(entry['health_details_withheld'], 0)
        row = self.engine.db.execute("SELECT state FROM health WHERE source='scheduler'").fetchone()
        self.assertTrue(row is None or row[0] == 'healthy')

    def test_failed_cycle_and_startup_filter_errors_still_print(self):
        with patch('cornicen.public_text._allowed',
                   side_effect=sqlite3.OperationalError('database is locked')):
            try:
                with patch.object(self.engine, '_flush', side_effect=RuntimeError('HTTP')):
                    self.scheduler._failed_cycle(RuntimeError('HTTP'))
                startup = self.startup(RuntimeError('HTTP'))
            except Exception as error:
                self.fail(f'Log boundary raised {type(error).__name__}')
        entry = json.loads(self.lines[-1])
        self.assertEqual(entry['error'], 'Exception')
        self.assertEqual(entry['health_error'], 'Exception')
        self.assertEqual(entry['message'], '[redacted]')
        self.assertEqual(entry['health_message'], '[redacted]')
        self.assertEqual(startup, 'command failed: Exception: [redacted]\n')

    def test_absence_on_all_log_paths(self):
        self.engine.watches = INVENTORY + (replace(INVENTORY[0], id='CVE'),)
        secrets = ('CVE-2026-12345', '1.2.3', 'quartz-watch-77391',
                   'Straße-fiction', 'İgranite-fiction', 'Ｑuartz-fiction', 'quartz-\u200bwatch-77391', 'docker')
        text = 'Cannot evaluate ' + ' '.join(secrets)
        primary = type('quartz-watch-77391', (RuntimeError,), {})(text)
        secondary = type('CVE-2026-12345', (RuntimeError,), {})(text)
        self.heartbeat(text)
        heartbeat = self.lines[-1]
        with patch.object(self.engine, '_flush', side_effect=secondary):
            self.scheduler._failed_cycle(primary)
        failed = self.lines[-1]
        entry = json.loads(failed)
        self.assertEqual(entry['error'], 'Exception')
        self.assertEqual(entry['health_error'], 'Exception')
        startup = self.startup(primary)
        self.assertTrue(startup.startswith('command failed: Exception: '))
        for line in (heartbeat, failed, startup):
            for secret in (*secrets, '77391', 'quartz', '12345', 'strasse-fiction'):
                self.assertNotIn(secret.casefold(), line.casefold())
        # Vocabulary collisions require loaded inventory, unavailable at startup.
        self.assertEqual(self.heartbeat('docker CVE'), '[redacted]')
        self.scheduler._failed_cycle(RuntimeError('docker CVE'))
        self.assertEqual(json.loads(self.lines[-1])['message'], '[redacted]')
        self.assertIn('quartz-watch-77391', self.startup(primary, 'healthcheck'))

    def test_readability_pins_through_heartbeat(self):
        for text in PINNED:
            with self.subTest(text=text):
                self.assertEqual(self.heartbeat(text), text)
        self.assertEqual(self.heartbeat('Missing stored record: CVE-2026-12345'),
                         'Missing stored record: [redacted]')

    def test_keys_and_fixed_old_fields(self):
        self.scheduler.tick()
        self.scheduler.tick()
        normal = json.loads(self.lines[-1])
        self.assertEqual(normal['health_details_withheld'], 0)
        self.assertIs(type(normal['health_details_withheld']), int)
        old_keys = ['events', 'github', 'health_details', 'ingested', 'pending', 'report', 'sent', 'sources', 'time']
        self.assertEqual([key for key in normal if key != 'health_details_withheld'], old_keys)
        self.assertEqual(list(normal['sources']), ['cvelist', 'epss', 'kev', 'watchlist'])
        self.assertEqual(list(normal['ingested']), ['cvelist', 'epss', 'kev'])
        self.engine.watches = INVENTORY
        with self.store.transaction():
            self.engine._health('quartz-watch-77391', 'healthy', 'No fetch failure')
            self.engine._health('error', 'healthy', 'No fetch failure')
        self.scheduler.tick()
        entry = json.loads(self.lines[-1])
        self.assertNotIn('quartz-watch-77391', entry['health_details'])
        self.assertNotIn('error', entry['health_details'])
        self.assertEqual(entry['health_details_withheld'], 2)
        self.assertEqual({key: entry[key] for key in old_keys if key != 'health_details'},
                         {key: normal[key] for key in old_keys if key != 'health_details'})

    def test_truncation_is_before_boundary(self):
        self.engine.watches = INVENTORY
        text = 'No ' * 98 + 'quartz-watch-77391'
        # This is the safe_message cut, independent of Engine._health's stored cut.
        with patch('cornicen.scheduler.assess', return_value=('unhealthy', text)):
            self.scheduler.tick()
        self.assertEqual(json.loads(self.lines[-1])['health_details']['watchlist'], 'No ' * 98 + '[redacted]')
        self.assertEqual(self.heartbeat(text), 'No ' * 98 + '[redacted]')
        self.scheduler._failed_cycle(RuntimeError(text))
        self.assertEqual(json.loads(self.lines[-1])['message'], 'No ' * 98 + '[redacted]')
        self.assertEqual(self.startup(RuntimeError(text)), 'command failed: RuntimeError: ' + 'No ' * 98 + '[redacted]\n')

    def test_ported_item9_leak_inputs(self):
        # Each group names the original probe file. Calls target this base's tick.
        groups = {
            'codex-r1-probes.py': [
                'Cannot evaluate watch quartz-watch-77391 for Quartz Fiction Appliance 77391 quartzfiction:prism77391 CVE-2098-77391001',
                'quartz-watch-77391', 'prefixCVE-2098-77391001'],
            'codex-r1-archive_privacy.py': [
                'deltaCves/quartz-watch-77391prefixCVE-2098-77391001.json: ValueError: Unexpected record path'],
            's-head-exp_priv.py': ['cve-2098-77391001', 'XCVE-2098-77391002',
                'x_CVE-2098-77391003', 'Cve-2098-77391004', 'CVE‑2098-77391005',
                'CVE-２098-77391006', 'private-inventory', 'Private product name', ' CVE-2098-77391007'],
            's-head-exp_priv2.py': ['cve-2098-77391001'],
            's-head-exp_priv3.py': ['failed matching private-inventory product Private product name'],
            'codex-r2-probes.py': ['Cannot evaluate STRASSE-FICTION-77391',
                'Cannot evaluate Mößquarz:prism77391', 'Cannot evaluate i\u0307granitefiction-77391',
                'Cannot evaluate quartz-only-77391', 'Cannot evaluate [redacted]',
                'Missing stored record: redacted', 'Missing stored record: STRASSE-OPAQUE-77391',
                'x' * 290 + ' quartz-\u200bwatch-77391',
                'x' * 292 + ' CVE-\u200b2098-77391042', 'x' * 290 + ' quartz-watch-77391',
                'Failure quartz-\u200bwatch-77391 CVE-\u200b2098-77391042',
                'Failure Acme.[x]+(quartz)?|^$\\fiction',
                'Failure abcdefghijklmnopqrstuvwxyz', 'Failure CVE-2098-77391042'],
            'sonnet-r2-e1.py': ['bad STRASSE:PRISM77391 here', 'bad Straße product',
                'x Ｑuartz  Fiction (v1.0)* [x] y', 'x Quartz Fiction (v1.0)* [x] y',
                'x Straße Ｑuartz Fiction (v1.0)* [x] y', 'x Straße Ｑuartz  Fiction (v1.0)* [x] y',
                'x quartz-watch\u200b-77391 y', 'x quartz\u00ad-watch-77391 y', 'x STRASSE y',
                'xxquartz-watch-77391yy', '[redacted] quartz-watch-77391',
                'abcdefgh', 'xxabcdefghxx', 'cdefgh abcdef',
                'quartz redacted [redacted] x', '[red[redacted]']
                + ['x' * offset + ' quartz\u200b-watch-77391 CVE\u200b-2098-77391042'
                   for offset in range(270, 300)],
            'sonnet-r2-e2.py': ['Cannot evaluate zephyr gizmo 9000 against 1.0',
                'Cannot evaluate oldwatch-55512 for Old Prod',
                'Dead-letter records: ' + ', '.join(f'CVE-2098-7739{i:04}' for i in range(40))],
            'sonnet-r2-e3.py': ['failed matching oldwatch-55512 product Old Prod'],
            'sonnet-r2-e4.py': ['Dead-letter records: ' + ', '.join(f'CVE-2098-{7739100+i}'
                for i in range(n)) + '; failed after 5 attempts' for n in range(1, 40)],
            'sonnet-r2-e5.py': ['Dead-letter records: ' + ', '.join(f'CVE-2098-{7000000+i}'
                for i in range(30)) + '; last error: ValueError: ' + 'x' * 150],
            'sonnet-r2-e6.py': ['database is locked'],
        }
        self.engine.watches = INVENTORY + (
            Watch('CVE', 'Private product name Quartz Fiction Appliance Straße Ｑuartz Fiction (v1.0)* [x]',
                  (('Mößquarz', 'prism77391'), ('klmnopqrstuvwxyz', 'cdefgh')),
                  ('quartz-only-77391', 'Old Prod', 'redacted'), '1.0', Scheme.DOTTED, False),
            replace(INVENTORY[0], id='abcdef', name='abcdefghijklmnop'),
        )
        forbidden = ('quartz', '-77391', 'strasse', 'straße', 'mößquarz', 'granitefiction',
                     'cve-', '2098-', 'qrstuvwxyz', 'cdefgh', 'abcdef', 'oldwatch',
                     'old prod', 'zephyr', 'gizmo', 'private-inventory', 'private product',
                     'prism77391', 'acme', 'v1.0', '1.0', 'fullwidth')
        for filename, inputs in groups.items():
            for text in inputs:
                with self.subTest(probe=filename, text=text):
                    detail = self.heartbeat(text)
                    for fragment in forbidden:
                        self.assertNotIn(fragment, detail.casefold())
                    self.assertNotIn('[[redacted]]', detail)
        # The round-1 key probe uses a data-derived source, not a value.
        with self.store.transaction():
            self.engine._health('quartz-watch-77391', 'healthy', 'No fetch failure')
        self.scheduler.tick()
        entry = json.loads(self.lines[-1])
        self.assertNotIn('quartz-watch-77391', entry['health_details'])
        self.assertEqual(entry['health_details_withheld'], 1)

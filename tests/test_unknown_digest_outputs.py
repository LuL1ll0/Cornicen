"""Report, exact transport boundaries and public-diagnostic guards."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
import hashlib
import io
import json
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

from cornicen import cli, engine
from cornicen.config import SecretToken
from cornicen.model import Notification
from cornicen.notify import ntfy, webhook
from cornicen.public_text import public_text
from cornicen.vocabulary import WORDS

from tests.test_unknown_digest import (
    ACCEPTS, ACCEPT_TEXT, Install, MEDIA, NOW, ROOT, WATCH_TEXT, Opener, entry, record,
)


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz)


class UnknownReportTests(unittest.TestCase):
    def setUp(self):
        self.install = Install(self, accepts=ACCEPTS).selection()
        self.install.config.watchlist_path.write_text(WATCH_TEXT + ACCEPT_TEXT)
        self.enterContext(patch.object(cli, 'load_config', return_value=self.install.config))
        self.enterContext(patch.object(cli, 'datetime', Clock))

    def report(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cli.main(['report', *args]), 0)
        return stdout.getvalue(), stderr.getvalue()

    def test_T10_unknown_text_and_jsonl(self):
        rows = [
            dict(watch_id='Fictional-Media', record_id='CVE-2099-80009', state='unknown',
                 alias_map_version='fixture', accepted=None, reason='version compare unknown'),
            dict(watch_id='fictional-media', record_id='CVE-2099-80001', state='unknown',
                 alias_map_version='fixture', accepted=None, reason='version compare unknown'),
            dict(watch_id='fictional-media', record_id='CVE-2099-80002', state='unknown',
                 alias_map_version='fixture', accepted=None, reason='default says affected'),
            dict(watch_id='fictional-media', record_id='CVE-2099-80006', state='unknown',
                 alias_map_version='fixture', reason='version compare unknown',
                 accepted=dict(reason='fixture accept', until='2026-12-31', version=None, state='active')),
            dict(watch_id='fictional-media', record_id='CVE-2099-80007', state='unknown',
                 alias_map_version='fixture', reason='version compare unknown',
                 accepted=dict(reason='fixture accept', until='2026-11-01', version=None, state='lapsed-date')),
        ]
        text, warning = self.report('--group', 'unknown')
        self.assertEqual(warning, '')
        summary, heading, *text_rows = text.splitlines()
        self.assertEqual(summary, 'Summary: Unknown (not alerting): 4; Accepted (not alerting): 1')
        self.assertEqual(heading, 'Unknown applicability (not alerting):')
        self.assertEqual([json.loads(line) for line in text_rows], rows)
        jsonl, warning = self.report('--group', 'unknown', '--format', 'jsonl')
        self.assertEqual(warning, '')
        self.assertEqual([json.loads(line) for line in jsonl.splitlines()],
                         [dict(row, schema_version=1, group='unknown') for row in rows])
        self.assertEqual(self.report('--group', 'unknown', '--watch', 'FICTIONAL-MEDIA'), (text, ''))
        self.install.config.watchlist_path.unlink()
        text, warning = self.report('--group', 'unknown')
        self.assertEqual(text, 'Summary: Unknown (not alerting): 0\nUnknown applicability (not alerting):\n')
        self.assertEqual(warning, 'accepted: not applied (watch list unreadable)\n')

    def test_T10_legacy_report_bytes(self):
        # The headings, counts and ordered row bytes from the supplied v0.7.0 tree.
        groups = [
            ('baseline-affected', 'Baseline: affected', 0, ''),
            ('baseline-exploited', 'Baseline: exploited (unknown version)', 0, ''),
            ('open', 'Open matches', 2,
             '{"accepted": null, "alias_map_version": "fixture", "record_id": "CVE-2099-80003", '
             '"state": "unknown", "watch_id": "fictional-media"}\n'
             '{"accepted": null, "alias_map_version": "fixture", "record_id": "CVE-2099-80004", '
             '"state": "affected", "watch_id": "fictional-media"}\n'),
            ('not-affected', 'Not affected (recorded, no alert)', 1,
             '{"accepted": null, "alias_map_version": "fixture", "record_id": "CVE-2099-80005", '
             '"state": "not_affected", "watch_id": "fictional-media"}\n'),
            ('dead-letters', 'Dead letters', 0, ''),
        ]
        for selection in (groups, *([group] for group in groups)):
            with self.subTest(selection=[group[0] for group in selection]):
                args = () if selection is groups else ('--group', selection[0][0])
                summary = '; '.join(f'{label}: {count}' for _, label, count, _ in selection)
                body = ''.join(f'{label}:\n{rows}' for _, label, _, rows in selection)
                self.assertEqual(self.report(*args), (f'Summary: {summary}; Accepted (not alerting): 0\n{body}', ''))


def section_fixture(names, product):
    blocks = [dict(name=name, product=product, version=MEDIA.version, count=1,
                   why=[['version compare unknown', 1]], ids=[f'CVE-2099-8000{i}'], more=0)
              for i, name in enumerate(names, 1)]
    n = len(blocks)
    return dict(total=n, watches=n, why=[['version compare unknown', n]], list=blocks, more=0)


def expected_sections(names, product):
    n = len(names)
    heading = f'Unknown applicability (not alerting): {n} pairs on {n} watches\nWhy: {n} version compare unknown'
    blocks = [f'{name} ({product} 8.2.90): 1 — 1 version compare unknown\n  CVE-2099-8000{i}'
              for i, name in enumerate(names, 1)]
    return [heading + ''.join('\n' + block for block in blocks[:k]) +
            (f'\nand {n - k} more watches: cornicen report --group unknown' if k != n else '')
            for k in range(n, -1, -1)]


def base_text(length):
    # Multiple lines and a multibyte character make an exact byte check useful.
    prefix = 'Fictional Media\nCVE-2099-80090 é\n'
    return prefix + 'x' * (length - len(prefix.encode('utf-8')))


class UnknownTransportTests(unittest.TestCase):
    def send(self, shape, base, section, title='Cornicen digest: 1 items'):
        notification = Notification('digest-fixture', '', 'digest', ('digest',),
                                    'normal', dict(applicability=section, items=[]))
        opener = Opener()
        with patch.object(ntfy, 'build_opener', return_value=opener):
            if shape == 'ntfy':
                notifier = ntfy.NtfyNotifier(ntfy.post, 'https://example.invalid', 'fixture', None)
                module = ntfy
            else:
                notifier = webhook.WebhookNotifier(ntfy.post, SecretToken('https://example.invalid'),
                                                   SecretToken('fixture'), shape=shape)
                module = webhook
            with patch.object(module, 'render', return_value=(title, base, 3, ['information_source'])):
                self.assertTrue(notifier.send(notification))
        request, = opener.requests
        return request.data

    def test_T11_ntfy_first_fit_and_byte_boundary(self):
        names, product = ('é' * 160, 'ö' * 160), 'é' * 160
        data = section_fixture(names, product)
        first, shorter, shortest = expected_sections(names, product)
        self.assertGreater(len(first.encode('utf-8')), 1400)
        self.assertLess(len(first.encode('utf-8')), 1600)
        self.assertGreater(3000 + 2 + len(first.encode('utf-8')), 4096)
        exact = 4096 - len(('\n\n' + shortest).encode('utf-8'))
        for length, suffix in ((4090, ''), (3000, shorter), (exact, shortest),
                               (exact + 1, ''), (5000, first)):
            with self.subTest(length=length):
                base = base_text(length)
                wire = self.send('ntfy', base, data)
                expected = base + ('\n\n' + suffix if suffix else '')
                self.assertEqual(wire, expected.encode('utf-8'))
                if length <= 4096:
                    self.assertLessEqual(len(wire), 4096)
                if length == exact:
                    self.assertEqual(len(wire), 4096)

        one_watch = section_fixture(names[:1], product)
        one_full, _ = expected_sections(names[:1], product)
        base = base_text(3000)
        self.assertEqual(self.send('ntfy', base, one_watch), (base + '\n\n' + one_full).encode('utf-8'))

    def test_T11_json_and_matrix_pre_title_budget(self):
        names, product = ('é' * 160,), 'é' * 160
        data = section_fixture(names, product)
        first, _ = expected_sections(names, product)
        for shape, length, include, title in (
                ('json', 7999, False, 'Cornicen digest'),
                ('json', 6000, True, 'Cornicen digest'),
                ('matrix', 7000, True, 'Cornicen digest'),
                ('matrix', 7000, True, 'x' * 256)):
            with self.subTest(shape=shape, length=length, title_length=len(title)):
                base = base_text(length)
                expected = base + ('\n\n' + first if include else '')
                if shape == 'matrix':
                    expected = title + '\n' + expected
                actual = json.loads(self.send(shape, base, data, title))['body']
                self.assertEqual(actual, expected)
                self.assertNotIn('[truncated]', actual)
                if shape == 'json':
                    self.assertLessEqual(len(actual.encode('utf-8')), 8000)

    def test_T11_escaped_discord_and_slack_choose_shorter(self):
        names, product = ('<>&' * 40,), 'fictional player'
        data = section_fixture(names, product)
        first, shorter = expected_sections(names, product)
        title = 'Cornicen digest (fixture)'
        for shape, field, encoding, escape in (
                ('discord', 'content', 'utf-16-le', lambda s: re.sub(r'([()<>])', r'\\\1', s)),
                ('slack', 'text', 'utf-8', lambda s: s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))):
            with self.subTest(shape=shape):
                # The unescaped field fits just below the limit. The longest
                # candidate fails only once the actual escaping is applied.
                limit = 2000 if shape == 'discord' else 4000
                unit = len if shape == 'discord' else lambda text: len(text.encode('utf-8'))
                base = base_text(3980 if shape == 'slack' else 1980)
                combined = title + '\n' + base + '\n\n' + first
                base = base[:-(unit(combined) - limit + 20)]
                prefix = title + '\n' + base + '\n\n'
                self.assertLessEqual(len((prefix + first).encode(encoding)), 4000)
                self.assertGreater(len(escape(prefix + first).encode(encoding)), 4000)
                expected = escape(prefix + shorter)
                result = json.loads(self.send(shape, base, data, title))[field]
                self.assertEqual(result, expected)
                self.assertLessEqual(len(result.encode(encoding)), 4000)
                self.assertNotIn('[truncated]', result)


    def test_T11_discord_and_slack_count_title_in_fit(self):
        names, product = ('Fictional Media Watch',), 'fictional player'
        data = section_fixture(names, product)
        first, shorter = expected_sections(names, product)
        title = 'Cornicen digest'
        # Discord escapes the watch line's parentheses. Slack leaves this fixture unchanged.
        for shape, field, encoding, escape in (
                ('discord', 'content', 'utf-16-le', lambda s: s.replace('(', r'\(').replace(')', r'\)')),
                ('slack', 'text', 'utf-8', lambda s: s)):
            with self.subTest(shape=shape):
                def size(text):
                    return len(escape(text).encode(encoding))

                start = base_text(1000) + '\n\n'
                byte_per_x = len('x'.encode(encoding))
                base = base_text(1000 + (4000 - size(start + first)) // byte_per_x)
                body = base + '\n\n'
                prefix = title + '\n' + body
                self.assertEqual(size(body + first), 4000)
                self.assertGreater(size(prefix + first), 4000)
                self.assertLessEqual(size(prefix + shorter), 4000)
                result = json.loads(self.send(shape, base, data, title))[field]
                self.assertEqual(result, escape(prefix + shorter))


class UnknownPrivacyTests(unittest.TestCase):
    def test_T12_full_cycle_is_private(self):
        def cycle(control):
            install = Install(self)
            opener = install.ntfy(self)
            install.due(90)
            deliver = engine.deliver

            def without_section(*args, **kwargs):
                kwargs.pop('unknown_section', None)
                return deliver(*args, **kwargs)

            notifications = []
            send = install.engine.notifier.send

            def capture(notification):
                notifications.append(notification)
                return send(notification)

            stdout, stderr = io.StringIO(), io.StringIO()
            with (patch.object(engine, 'deliver', without_section if control else deliver),
                  patch.object(install.engine.notifier, 'send', capture),
                  redirect_stdout(stdout), redirect_stderr(stderr)):
                install.ingest(record(1, entry(defaultStatus='unknown')))
            return opener.texts, notifications, stdout.getvalue(), stderr.getvalue()

        sent, envelopes, out, err = cycle(False)
        control, _, control_out, control_err = cycle(True)
        self.assertEqual((out, err), (control_out, control_err))
        base, = control
        posted, = sent
        self.assertTrue(posted.startswith(base + '\n\nUnknown applicability (not alerting):'))
        envelope, = envelopes
        block = envelope.body['applicability']
        self.assertEqual(block['why'], [['no version data', 1]])
        for text in (envelope.body.keys(), block.keys(), block['list'][0].keys(),
                     posted[len(base):].splitlines()[2:4],
                     ('Unknown applicability: not available', 'Unknown (not alerting)',
                      'and more watches: cornicen report --group unknown',
                      'version compare unknown', 'scheme mismatch', 'malformed record',
                      'default says affected', 'no version data', 'CNA says unknown',
                      'product only', 'vendor advisory', 'other')):
            tokens = re.findall(r'[A-Za-z_-]+', ' '.join(text).lower())
            # The two fixed text lines are kept separate from watch inventory.
            self.assertLessEqual(set(tokens), WORDS)

    def test_T12_vocabulary_and_redaction_are_unchanged(self):
        vocabulary = ROOT / 'src/cornicen/vocabulary.py'
        self.assertEqual(hashlib.sha256(vocabulary.read_bytes()).hexdigest(),
                         'e7213282052ff938273165d07797b5e053624021c8e80eac483d066f764d6391')
        checked = subprocess.run([sys.executable, str(ROOT / 'tools/gen_vocabulary.py'), '--check'],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        # Pin the outputs against the supplied v0.7.0 snapshot.
        for probe, expected in (
                ('applicability unknown' + '_applicability more' + '_watches', 'applicability [redacted]'),
                ('alerted comparable', '[redacted]'), ('zl zp', '[redacted]')):
            self.assertEqual(public_text(probe, (MEDIA,)), expected)

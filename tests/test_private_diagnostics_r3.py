# script-purpose: Verify acceptance and nested validation diagnostic provenance.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_private_diagnostics_r3.py
"""Read local fixtures, write temporary files under .build, and use no network.

Run with python -m unittest tests.test_private_diagnostics_r3. Exit 0 means
success, 1 means failed tests, and 2 means invalid unittest arguments.
"""

import unittest
from unittest.mock import patch

from cornicen import acceptance, cli, diagnostics, watchlist
from tests import test_cli_private_errors as fixtures


class PrivateDiagnosticsR3(unittest.TestCase):
    setUp = fixtures.PrivateCommandErrors.setUp
    invoke = fixtures.PrivateCommandErrors.invoke

    def test_external_acceptance_public_message_requires_fixed_provenance(self):
        secret = 'r3quindlesecret'
        token = self.root / 'token'
        token.write_text(secret)
        token.chmod(0o600)
        self.config.write_text(self.settings +
                               f'acceptance_list_path="{self.alias}"\n'
                               f'acceptance_watchlist_path="{self.watch}"\n')
        for message in (f'acceptance list entry 1: {fixtures.MARKER} {secret}',
                        diagnostics.FixedDiagnostic('acceptance list rejected')):
            with self.subTest(fixed=isinstance(message, diagnostics.FixedDiagnostic)):
                error = acceptance.AcceptanceError(message)
                with patch.object(acceptance, 'load_entries', side_effect=error):
                    code, output = self.invoke(('selftest',),
                                              {'CORNICEN_NTFY_TOKEN_FILE': str(token)})
                self.assertEqual(code, 2)
                self.assertNotIn(fixtures.MARKER, output)
                self.assertNotIn(secret, output)
                self.assertIn('acceptance list', output)
        self.alias.write_text('[[expect]]\nwatch_id=7\n')
        with self.assertRaises(acceptance.AcceptanceError) as caught:
            acceptance.load_entries(self.alias)
        self.assertIsInstance(caught.exception.public_message, diagnostics.FixedDiagnostic)

    def test_nested_watch_and_accept_errors_require_fixed_provenance(self):
        secret = 'r3quindlesecret'
        token = self.root / 'token'
        token.write_text(secret)
        token.chmod(0o600)
        for lane in ('watch', 'accept'):
            for attribute in (False, True):
                with self.subTest(lane=lane, forged_attribute=attribute):
                    error = ValueError(f'{fixtures.MARKER} {secret}')
                    if attribute:
                        error.public_message = str(error)
                    if lane == 'watch':
                        self.watch.write_text(fixtures.WATCH)
                        hook = patch.object(watchlist, '_parse_identity', side_effect=error)
                    else:
                        self.watch.write_text('[[accept]]\nwatch="sentinel"\n')
                        hook = patch.object(watchlist, '_string', side_effect=error)
                    with hook:
                        code, output = self.invoke(('run',),
                                                  {'CORNICEN_NTFY_TOKEN_FILE': str(token)})
                        self.assertEqual(code, 1)
                        self.assertEqual(output, f'command failed: WatchlistError: {lane} entry 1: invalid value\n')
                        code, output = self.invoke(('watch', 'check', '--strict'),
                                                  {'CORNICEN_NTFY_TOKEN_FILE': str(token)})
                    self.assertEqual(code, 1)
                    self.assertEqual(output, f'watch validation error: {lane} entry 1 (sentinel): invalid value\n')

    def test_problem_lists_do_not_acquire_fixed_provenance(self):
        error = watchlist._validation_error([fixtures.MARKER])
        self.assertNotIsInstance(error.public_problems[0], diagnostics.FixedDiagnostic)

    def test_parser_position_attributes_must_be_integers(self):
        error = ValueError('invalid document')
        error.lineno = fixtures.MARKER
        error.colno = fixtures.MARKER
        self.assertEqual(diagnostics.toml_error('config', error),
                         'config file is not valid TOML')

    def test_each_position_coordinate_checked_independently(self):
        class Formatted(int):
            def __str__(self):
                return fixtures.MARKER
            __format__ = lambda self, spec: fixtures.MARKER
        for line, column in ((fixtures.MARKER, 7), (3, fixtures.MARKER), (True, 7), (3, False),
                             (Formatted(3), 7), (3, Formatted(7))):
            with self.subTest(line=repr(line), column=repr(column)):
                error = ValueError('invalid document')
                error.lineno, error.colno = line, column
                text = diagnostics.toml_error('config', error)
                self.assertNotIn(fixtures.MARKER, text)
                self.assertNotIn('True', text)
                self.assertNotIn('False', text)

    def test_forged_class_never_acquires_fixed_provenance(self):
        class Forged(str):
            @property
            def __class__(self):
                return diagnostics.FixedDiagnostic
        forged = Forged(f'{fixtures.MARKER} private')
        self.assertIsInstance(forged, diagnostics.FixedDiagnostic)  # the trap the check must avoid
        for lane in ('watch', 'accept'):
            with self.subTest(lane=lane):
                error = ValueError(forged)
                if lane == 'watch':
                    self.watch.write_text(fixtures.WATCH)
                    hook = patch.object(watchlist, '_parse_identity', side_effect=error)
                else:
                    self.watch.write_text('[[accept]]\nwatch="sentinel"\n')
                    hook = patch.object(watchlist, '_string', side_effect=error)
                with hook:
                    code, output = self.invoke(('run',), {})
                self.assertEqual(code, 1)
                self.assertNotIn(fixtures.MARKER, output)
                self.assertEqual(output, f'command failed: WatchlistError: {lane} entry 1: invalid value\n')
        self.config.write_text(self.settings +
                               f'acceptance_list_path="{self.alias}"\n'
                               f'acceptance_watchlist_path="{self.watch}"\n')
        error = acceptance.AcceptanceError(diagnostics.FixedDiagnostic('acceptance list rejected'))
        error.public_message = forged
        with patch.object(acceptance, 'load_entries', side_effect=error):
            code, output = self.invoke(('selftest',), {})
        self.assertEqual(code, 2)
        self.assertNotIn(fixtures.MARKER, output)


if __name__ == '__main__':
    unittest.main()

# script-purpose: Verify fixed diagnostics preserve roles while withholding private input.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_private_diagnostics_r2.py
"""Read local fixtures and write temporary files under .build; no network.

Run with python -m unittest tests.test_private_diagnostics_r2. Exit 0 means
success; exit 1 means a failed assertion, and exit 2 means invalid arguments.
"""

from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from cornicen import cli, config, diagnostics, acceptance, watchlist
from tests import test_cli_private_errors as fixtures

WATCH = fixtures.WATCH


class PrivateDiagnosticsR2(unittest.TestCase):
    setUp = fixtures.PrivateCommandErrors.setUp
    invoke = fixtures.PrivateCommandErrors.invoke

    def test_unknown_keys_never_echo_even_public_words_or_numbers(self):
        for key in ('you', 'read', 'config', '12345', 'PRIVATE-Zyphora-4.2.3'):
            with self.subTest(key=key):
                self.config.write_text(f'"{key}"=1')
                code, output = self.invoke(('healthcheck',))
                self.assertEqual(code, 1)
                self.assertEqual(output, 'command failed: ValueError: 1 unknown configuration keys '
                                 '(names not shown; compare with docs/cli.md)\n')

    def test_watch_accept_labels_omit_file_content(self):
        self.watch.write_text(WATCH + '\n[[accept]]\ncve="CVE-2099-2000"\nwatch="sentinel"\nreason="you"\n')
        for extra in ((), ('--strict',), ('--file', str(self.watch))):
            with self.subTest(extra=extra):
                code, output = self.invoke(('watch', 'check', *extra))
                self.assertEqual(code, 1)
                self.assertEqual(output, 'watch validation error: accept entry 1 (sentinel): no lapse condition\n')

    def test_every_validation_line_redacts_both_known_secrets(self):
        self.watch.write_text(WATCH.replace('sentinel', 'you') + 'mystery=1\n' +
                              WATCH.replace('sentinel', 'read') + 'mystery=1\n')
        from cornicen.config import SecretToken
        from dataclasses import replace
        loaded = config.load_config(self.config, {})
        loaded = replace(loaded, ntfy_token=SecretToken('you'), github_token=SecretToken('read'))
        for extra in (('--strict',), ('--file', str(self.watch))):
            with self.subTest(extra=extra), patch.object(cli, 'load_config', return_value=loaded):
                code, output = self.invoke(('watch', 'check', *extra))
                self.assertEqual(code, 1)
                self.assertEqual(output, ''.join(f'watch validation error: watch entry {i} ([redacted]): unknown key\n' for i in (1, 2)))

    def test_fixed_role_reason_and_position_survive_inventory_collisions(self):
        for word in ('aliases_path', 'config', 'file', 'valid', 'not', 'line', 'column'):
            with self.subTest(word=word):
                self.watch.write_text(WATCH.replace('sentinel', word))
                self.alias.write_text('a=1\na=2')
                self.config.write_text(self.settings + f'aliases_path="{self.alias}"\n')
                code, output = self.invoke(('explain', 'CVE-2099-1000', '--watch', word))
                self.assertEqual(code, 1)
                self.assertEqual(output, 'command failed: ValueError: aliases_path file is not valid TOML (line 2, column 4)\n')
        # Entry and reason words must survive too, without the private id.
        self.config.write_text(self.settings)
        self.watch.write_text(WATCH.replace('sentinel', 'entry') + '\n' + WATCH.replace('sentinel', 'entry'))
        code, output = self.invoke(('run',))
        self.assertEqual(code, 1)
        self.assertEqual(output, 'command failed: WatchlistError: watch entry 2: duplicate id\n')

    def test_token_permissions_are_fixed_and_actionable(self):
        token = self.root / 'you'
        token.write_text('private-quindle-token')
        token.chmod(0o644)
        code, output = self.invoke(('healthcheck',), {'CORNICEN_NTFY_TOKEN_FILE': str(token)})
        self.assertEqual(code, 1)
        self.assertEqual(output, 'command failed: ValueError: CORNICEN_NTFY_TOKEN_FILE requires owner-only permissions (mode 0600); shared access requires allow_shared_token_file\n')
        self.assertNotIn(str(token), output)
        self.assertNotIn('private-quindle-token', output)

        # GitHub retains the unauthenticated fallback and reports its fixed role
        # from persisted status without diagnostic processes opening the token.
        loaded = config.load_config(self.config, {'CORNICEN_GITHUB_TOKEN_FILE': str(token)})
        self.assertIsNone(loaded.github_token)
        self.assertEqual(loaded.github_token_problem, 'permissions')
        store = Mock()
        store.get_meta.side_effect = lambda key: 'token unusable: permissions' if key == 'github_auth' else None
        self.assertEqual(cli.github_status_line(store),
                         'github: CORNICEN_GITHUB_TOKEN_FILE requires owner-only permissions (mode 0600); '
                         'shared access requires allow_shared_token_file; using unauthenticated access; rate limit not seen yet')

    def test_backup_source_and_destination_roles(self):
        for name in ('you', 'read', 'config', '12345'):
            with self.subTest(name=name):
                dest = self.root / name / name
                code, output = self.invoke(('db', 'backup', '--output', str(dest)))
                self.assertEqual(code, 1)
                self.assertEqual(output, 'command failed: FileNotFoundError: backup destination not found\n')
        with patch.object(cli, 'Store', side_effect=PermissionError('you')):
            code, output = self.invoke(('db', 'backup', '--output', str(self.root / 'read')))
            self.assertEqual(code, 1)
            self.assertEqual(output, 'command failed: ValueError: database file not readable\n')
        with patch('cornicen.maintenance.tempfile.mkstemp', side_effect=PermissionError('read')):
            code, output = self.invoke(('db', 'backup', '--output', str(self.root / 'read')))
            self.assertEqual(code, 1)
            self.assertEqual(output, 'command failed: PermissionError: backup destination not writable\n')
        self.db.unlink()
        code, output = self.invoke(('db', 'backup', '--output', str(self.root / 'you')))
        self.assertEqual(code, 1)
        self.assertEqual(output, 'command failed: FileNotFoundError: database file not found\n')

    def test_file_role_helpers_never_include_any_input_path(self):
        # Exact helper output catches paths whose words pass public_text, including
        # the review mutation that appends the path to config's open error.
        self.assertEqual(diagnostics.file_error('backup destination', FileNotFoundError('you')),
                         'backup destination not found')
        for name in ('you', 'read', 'config', '12345'):
            path = self.root / name / name
            for role, loader, error_type in (
                    ('config', lambda: config.load_config(path, {}), ValueError),
                    ('watch list', lambda: watchlist.load_document(path), watchlist.WatchlistError),
                    ('aliases_path', lambda: diagnostics.read_text(path, 'aliases_path'), ValueError),
                    ('acceptance list', lambda: acceptance.load_entries(path), acceptance.AcceptanceError),
                    ('acceptance watch list', lambda: acceptance.load_watches(path, ()), acceptance.AcceptanceError)):
                with self.subTest(name=name, role=role):
                    with self.assertRaises(error_type) as caught:
                        loader()
                    error = caught.exception
                    message = getattr(error, 'public_message', str(error))
                    self.assertEqual(message, f'{role} file not found')
                    self.assertNotIn(str(path), message)
                    self.assertNotIn(name + '/', message)
            for role in ('config', 'watch list', 'aliases_path', 'acceptance list',
                         'acceptance watch list', 'CORNICEN_NTFY_TOKEN_FILE', 'CORNICEN_GITHUB_TOKEN_FILE'):
                for error in (FileNotFoundError(str(path)), PermissionError(str(path)), IsADirectoryError(str(path))):
                    with self.subTest(name=name, role=role, error=type(error)):
                        expected = 'not found' if isinstance(error, FileNotFoundError) else 'not readable'
                        self.assertEqual(diagnostics.file_error(role, error), f'{role} file {expected}')

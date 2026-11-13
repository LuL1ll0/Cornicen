# script-purpose: Verify privacy and actionable positions in command failures.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_cli_private_errors.py
"""Private command failures: run with unittest; reads fixtures, writes temp files.

Exit status is zero on success and nonzero on a failed privacy assertion.
"""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen import cli
from cornicen.store import Store
from cornicen.public_text import public_token

MARKER = 'PRIVATE-Zyphora-4.2.3'
WATCH = '''[[watch]]
id = "sentinel"
name = "Zyphora"
match = ["zyphora:quindle"]
version = "4.2.3"
scheme = "semver"
'''
COMMANDS = (('run',), ('healthcheck',), ('status',), ('status', '--json'),
            ('report',), ('explain', 'CVE-2099-1000', '--watch', MARKER),
            ('outbox', 'list'), ('db', 'backup', '--output', MARKER),
            ('watch', 'check'), ('selftest',), ('replay', '--list', MARKER),
            ('notify', 'test'))


class PrivateCommandErrors(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.toml'
        self.watch = self.root / 'watch.toml'
        self.alias = self.root / MARKER
        self.db = self.root / 'state.db'
        store = Store(self.db)
        store.migrate()
        store.connection.close()
        self.watch.write_text(WATCH)
        self.settings = f'db_path="{self.db}"\nwatchlist_path="{self.watch}"\n'
        self.config.write_text(self.settings)

    def invoke(self, command, env=None):
        output = io.StringIO()
        with patch.dict(os.environ, env or {}, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = cli.main(['--config', str(self.config), *command])
        return code, output.getvalue()

    def private(self, command, pin, env=None):
        code, output = self.invoke(command, env)
        self.assertNotIn(MARKER, output)
        self.assertEqual(code, 2 if command[0] == 'selftest' else 1)
        if command != ('status', '--json'):
            self.assertIn(pin, output)
        return output

    def test_private_config_paths_keys_and_toml_all_commands(self):
        for command in COMMANDS:
            for text, pin in ((f'"{MARKER}"=1', '1 unknown configuration keys (names not shown; compare with docs/cli.md)'),
                              (f'a=1\na=2 # {MARKER}', 'config file is not valid TOML (line 2, column 4)')):
                with self.subTest(command=command, pin=pin):
                    self.config.write_text(text)
                    self.private(command, pin)
            saved = self.config
            self.config = self.root / MARKER
            with self.subTest(command=command, path=True):
                self.private(command, 'config file not found')
            self.config = saved

    def test_private_alias_and_watch_errors_reachable_commands(self):
        for command in (('run',), ('watch', 'check'), ('explain', 'CVE-2099-1000', '--watch', 'sentinel'), ('replay', '--list', MARKER)):
            for content, pin in (('a=1\na=2', 'aliases_path file is not valid TOML (line 2, column 4)'), (None, 'aliases_path file not found')):
                with self.subTest(command=command, alias=content):
                    self.watch.write_text(WATCH)
                    self.config.write_text(self.settings + f'aliases_path="{self.alias}"\n')
                    if content is None:
                        self.alias.unlink(missing_ok=True)
                    else:
                        self.alias.write_text(content)
                    self.private(command, pin)
            self.config.write_text(self.settings)
            for text, pin in ((WATCH.replace('sentinel', MARKER) + '\n' + WATCH.replace('sentinel', MARKER), 'watch entry 2: duplicate id'),
                              (WATCH + f'"{MARKER}"=1', 'watch entry 1: unknown key'),
                              ('a=1\na=2', 'watch list file is not valid TOML (line 2, column 4)')):
                with self.subTest(command=command, watch=pin):
                    self.watch.write_text(text)
                    self.private(command, pin)

    def test_private_file_roles_and_unreadable_errors(self):
        for role, target, command in (('config', self.config, ('healthcheck',)),
                                     ('watch list', self.watch, ('run',)),
                                     ('aliases_path', self.alias, ('watch', 'check'))):
            self.config.write_text(self.settings + (f'aliases_path="{self.alias}"\n' if role == 'aliases_path' else ''))
            for error, suffix in ((FileNotFoundError(MARKER), 'not found'), (PermissionError(MARKER), 'not readable'), (IsADirectoryError(MARKER), 'not readable')):
                original = Path.open
                def opening(path, *args, **kwargs):
                    if path == target:
                        raise error
                    return original(path, *args, **kwargs)
                with self.subTest(role=role, error=type(error)), patch.object(Path, 'open', opening):
                    self.private(command, f'{role} file {suffix}')

    def test_private_token_file_paths_all_config_commands(self):
        for command in COMMANDS:
            with self.subTest(command=command):
                self.private(command, 'CORNICEN_NTFY_TOKEN_FILE file not found', {'CORNICEN_NTFY_TOKEN_FILE': str(self.alias)})

    def test_private_acceptance_files_selftest_and_replay(self):
        command = ('selftest',)
        self.config.write_text(self.settings + f'acceptance_list_path="{self.alias}"\nacceptance_watchlist_path="{self.watch}"\n')
        self.private(command, 'acceptance list file not found')
        self.alias.write_text(f'a=1\na=2 # {MARKER}')
        self.private(command, 'acceptance list file is not valid TOML (line 2, column 4)')
        self.alias.write_text(f'[[expect]]\nwatch_id="{MARKER}"\n')
        self.private(command, 'acceptance list entry 1: invalid entry')
        self.alias.write_text('[[expect]]\nwatch_id="sentinel"\ncve="CVE-2099-1000"\n')
        self.watch.write_text('a=1\na=2')
        self.private(command, 'acceptance watch list file is not valid TOML (line 2, column 4)')
        self.config.write_text(self.settings)
        self.watch.write_text(WATCH)
        self.alias.write_text('a=1\na=2')
        self.private(('replay', '--list', str(self.alias)), 'acceptance list file is not valid TOML (line 2, column 4)')

    def test_private_final_boundary_inventory_and_positive_control(self):
        # The same injected failure demonstrates that the marker grep is live.
        for command in (('healthcheck',), ('report',), ('explain', 'CVE-2099-1000', '--watch', 'sentinel')):
            target = {'healthcheck': 'container_healthy', 'report': 'report', 'explain': 'explain'}[command[0]]
            with self.subTest(command=command), patch.object(cli, target, side_effect=ValueError('command ' + MARKER)):
                self.private(command, 'command [redacted]')
                with patch.object(cli, 'public_text', side_effect=lambda text, inventory=(): text):
                    self.assertIn(MARKER, self.invoke(command)[1])
        with patch.object(cli, 'container_healthy', side_effect=ValueError('command sentinel')):
            self.assertNotIn('sentinel', self.invoke(('healthcheck',))[1])
        with patch.object(cli, 'explain', side_effect=ValueError('command sentinel')):
            self.assertNotIn('sentinel', self.invoke(('explain', 'CVE-2099-1000', '--watch', 'sentinel'))[1])

    def test_private_typo_policy_and_watch_validation_lane(self):
        self.config.write_text('epss_threshhold=1')
        output = self.private(('healthcheck',), '1 unknown configuration keys (names not shown; compare with docs/cli.md)')
        self.assertNotIn('epss_threshhold', output)
        self.config.write_text(self.settings)
        self.watch.write_text(WATCH.replace('sentinel', MARKER) + f'"{MARKER}"=1')
        code, output = self.invoke(('watch', 'check', '--file', str(self.watch)))
        self.assertEqual(code, 1)
        self.assertIn(f'watch entry 1 ({MARKER})', output)
        self.assertNotIn(f"unknown key '{MARKER}'", output)

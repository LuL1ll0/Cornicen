# script-purpose: Verify the dead-man URL never prints through command, config, alias or watch-check errors.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_integration_0114.py
"""Seams between the 0.1.14 lanes: dead-man redaction meets the command-error rules.

Reads local fixtures, writes temporary files under .build, and uses no network.
Run with python -m unittest tests.test_integration_0114. Exit 0 means success,
1 means failed tests, and 2 means invalid unittest arguments.
"""

import unittest
from unittest.mock import patch

import json

from cornicen import acceptance, cli, diagnostics, watchlist
from tests import test_cli_private_errors as fixtures

# 'complete' is a vocabulary word, so only the dead-man redaction (not public_text) can hide it.
URL = 'https://quindleping.invalid/vaultsegment2099/complete?k=opaquequery2099'
PARTS = ('quindleping.invalid', 'vaultsegment2099', 'opaquequery2099', 'complete', URL)


class DeadmanMeetsCommandErrors(unittest.TestCase):
    setUp = fixtures.PrivateCommandErrors.setUp
    invoke = fixtures.PrivateCommandErrors.invoke

    def assert_private(self, output):
        for part in PARTS:
            self.assertNotIn(part, output)

    def test_config_error_with_deadman_url_set(self):
        self.config.write_text(self.settings + 'not_a_key = 1\n')
        code, output = self.invoke(('healthcheck',), {'CORNICEN_DEADMAN_URL': URL})
        self.assertEqual(code, 1)
        self.assertIn('unknown configuration key', output)
        self.assert_private(output)

    def test_alias_error_with_deadman_url_set(self):
        self.alias.write_text('version = \n')
        self.config.write_text(self.settings + f'aliases_path="{self.alias}"\n')
        code, output = self.invoke(('run',), {'CORNICEN_DEADMAN_URL': URL})
        self.assertEqual(code, 1)
        self.assertIn('aliases_path', output)
        self.assert_private(output)

    def test_store_error_quoting_the_url(self):
        for command in (('healthcheck',), ('status',), ('report',)):
            with self.subTest(command=command):
                with patch('cornicen.cli.Store', side_effect=RuntimeError('Cannot reach ' + URL + ' complete')):
                    code, output = self.invoke(command, {'CORNICEN_DEADMAN_URL': URL})
                self.assertEqual(code, 1)
                self.assertIn('command failed', output)
                self.assert_private(output)

    def test_watch_check_lane_redacts_deadman_parts(self):
        self.watch.write_text(fixtures.WATCH.replace('id = "sentinel"', 'id = "vaultsegment2099"') + 'bogus = 1\n')
        code, output = self.invoke(('watch', 'check', '--strict'), {'CORNICEN_DEADMAN_URL': URL})
        self.assertEqual(code, 1)
        self.assertIn('watch validation error', output)
        self.assert_private(output)

    def test_untrusted_acceptance_message_redacts_deadman_forms(self):
        url = 'https://watcher.invalid/m%C3%B6n2099/complete?k=opaque2099'
        self.config.write_text(self.settings + f'acceptance_list_path="{self.alias}"\n'
                               f'acceptance_watchlist_path="{self.watch}"\n')
        for form in ('complete', 'm\u00f6n2099', json.dumps('m\u00f6n2099')[1:-1], 'opaque2099'):
            with self.subTest(form=form):
                error = acceptance.AcceptanceError('Cannot read ' + form)
                with patch.object(acceptance, 'load_entries', side_effect=error):
                    code, output = self.invoke(('selftest',), {'CORNICEN_DEADMAN_URL': url})
                self.assertEqual(code, 2)
                self.assertNotIn(form, output)


class Forged(str):
    @property
    def __class__(self):
        return diagnostics.FixedDiagnostic


class ForgedProvenance(unittest.TestCase):
    setUp = fixtures.PrivateCommandErrors.setUp
    invoke = fixtures.PrivateCommandErrors.invoke

    def test_forged_exception_arg_cannot_bypass_filters(self):
        with patch.object(cli, 'Store', side_effect=ValueError(Forged('PRIVATE-quindle2099'))):
            code, output = self.invoke(('healthcheck',))
        self.assertEqual(code, 1)
        self.assertNotIn('PRIVATE-quindle2099', output)

    def test_forged_public_problem_cannot_bypass_filters(self):
        error = watchlist.WatchlistError(['PRIVATE-quindle2099'], [Forged('PRIVATE-quindle2099')])
        with patch.object(cli, 'load_document', side_effect=error):
            code, output = self.invoke(('run',))
        self.assertEqual(code, 1)
        self.assertNotIn('PRIVATE-quindle2099', output)


if __name__ == '__main__':
    unittest.main()

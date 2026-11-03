"""The installed module entrypoint must execute the CLI and propagate its status."""
import runpy
import unittest
from unittest.mock import patch


class EntrypointTests(unittest.TestCase):
    def test_module_runs_cli_and_propagates_status(self):
        with patch('cornicen.cli.main', return_value=23) as main:
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module('cornicen', run_name='__main__')
        main.assert_called_once_with()
        self.assertEqual(stopped.exception.code, 23)

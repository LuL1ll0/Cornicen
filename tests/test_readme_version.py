"""The README's status line must name the version pyproject.toml ships."""
from pathlib import Path
import re
import tomllib
import unittest

from cornicen import __version__


class ReadmeVersionTests(unittest.TestCase):
    def test_readme_status_version_matches_pyproject_and_package(self):
        shipped = tomllib.loads(Path('pyproject.toml').read_text())['project']['version']
        match = re.search(r'^\*\*Status:\*\* version (\S+?),', Path('README.md').read_text(), re.M)
        self.assertIsNotNone(match, 'README status line not found')
        self.assertEqual(match.group(1), shipped)
        self.assertEqual(__version__, shipped)


if __name__ == '__main__':
    unittest.main()

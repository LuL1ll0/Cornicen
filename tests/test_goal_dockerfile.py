"""Source copies must remain readable under a restrictive build-context umask."""
import json
from pathlib import Path
import shlex
import unittest


class DockerfileTests(unittest.TestCase):
    def test_source_copies_set_permissions(self):
        dockerfile = Path(__file__).resolve().parents[1] / 'Dockerfile'
        copies = []
        for line in dockerfile.read_text().replace('\\\n', ' ').splitlines():
            instruction, _, arguments = line.strip().partition(' ')
            if instruction.upper() != 'COPY':
                continue
            flags = []
            while arguments.startswith('--'):
                flag, _, arguments = arguments.partition(' ')
                flags.append(flag)
                arguments = arguments.lstrip()
            paths = json.loads(arguments) if arguments.startswith('[') else shlex.split(arguments)
            if any(path.removeprefix('./').rstrip('/') == 'src'
                   or Path(path).name.startswith('pyproject') for path in paths[:-1]):
                copies.append(paths)
                self.assertTrue(any(flag.startswith('--chmod=') for flag in flags), line)
                mode = next(flag.split('=', 1)[1] for flag in flags if flag.startswith('--chmod='))
                # The runtime user is neither owner nor group: it needs other-read on files
                # and other-read plus traverse on directories.
                directory = any(path.removeprefix('./').rstrip('/') == 'src' for path in paths[:-1])
                need = 0o005 if directory else 0o004
                readable = (mode == 'a+rX' or
                            (mode.isdigit() and all(digit in '01234567' for digit in mode)
                             and int(mode, 8) & need == need))
                self.assertTrue(readable, line)
        self.assertTrue(copies, 'Expected at least one source/package COPY')

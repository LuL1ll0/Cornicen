# script-purpose: Compare unmigrated diagnostics with the pinned v0.1.16 commands.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_upgrade_readonly.py
"""Read pinned sources; create temporary databases; exit 0 on success, 1 on failure."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PINNED = ROOT / '.build/v11/v0116/src'


class UpgradeReadonlyTests(unittest.TestCase):
    def test_unmigrated_commands_equal_pinned(self):
        if not (PINNED / 'cornicen/store.py').is_file():
            # The pinned tree is gitignored (recreate: git archive 1c97d0d src tests tools
            # | tar -x -C .build/v11/v0116), so a fresh checkout or CI skips this check.
            self.skipTest('pinned v0.1.16 tree absent: could not compare unmigrated commands')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'state.db'
            watch = root / 'watch.toml'
            watch.write_text('[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.0.0"\nscheme="semver"\n')
            expected = root / 'expect.toml'
            expected.write_text('[[expect]]\nwatch_id="w"\ncve="CVE-2099-0001"\n')
            config = root / 'config.toml'
            config.write_text(f'db_path="{db}"\nwatchlist_path="{watch}"\nacceptance_list_path="{expected}"\nacceptance_watchlist_path="{watch}"\n')
            def execute(source, code, *args):
                return subprocess.run([sys.executable, '-c', code, *map(str, args)],
                    env=dict(os.environ, PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE='1'),
                    capture_output=True, text=True)
            seed = '''from cornicen.store import Store
import sys
s=Store(sys.argv[1]); s.migrate()
s.put_record('CVE-2099-0001', {'cveMetadata': {'cveId':'CVE-2099-0001','state':'PUBLISHED'}, 'containers': {'cna': {'affected':[{'vendor':'examplecorp','product':'widget','versions':[{'version':'1.0.0','status':'affected'}]}]}}}, '2099-11-03T00:00:00+00:00')
s.connection.close()
'''
            result = execute(PINNED, seed, db)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = hashlib.sha256(db.read_bytes()).digest()
            commands = [('explain','CVE-2099-0001','--watch','w'), ('status',), ('status','--json'),
                        ('replay','--list',expected), ('watch','check'), ('selftest',),
                        ('healthcheck',), ('outbox','list'), ('outbox','list','--failed'),
                        ('report',), ('report','--format','jsonl'), ('db','backup','--output',root/'backup.db')]
            call = 'from cornicen.cli import main; import sys; sys.exit(main(sys.argv[1:]))'
            for command in commands:
                with self.subTest(command=command):
                    old = execute(PINNED, call, '--config', config, *command)
                    (root / 'backup.db').unlink(missing_ok=True)
                    new = execute(ROOT/'src', call, '--config', config, *command)
                    self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
                    self.assertEqual((new.returncode,new.stdout,new.stderr), (old.returncode,old.stdout,old.stderr))
            self.assertEqual(hashlib.sha256(db.read_bytes()).digest(), before)

# script-purpose: Capture deterministic v0.1.16 database and notification baselines.
# script-class: generator
# script-trigger: Run manually before foundation implementation.
# script-tests: tools/test-capture-v0116-frozen.py
"""Read src/ and tests/replay; write tests/fixtures/v0116_frozen.

Usage: PYTHONPATH=src python3 tools/capture_v0116_frozen.py [--output DIR]
Exit 0 on successful capture, nonzero on capture or filesystem failure.
Existing identities in the public v1 inputs are intentionally preserved exactly.
"""
import argparse
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.replay import harness
from cornicen.store import Store
from cornicen.config import Config
from cornicen import cli


def dump(store):
    """All SQLite tables, columns and rows; BLOBs use lossless hexadecimal."""
    def cell(value):
        return {'$blob': value.hex()} if isinstance(value, bytes) else value
    tables = {}
    for (name,) in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        quoted = '"' + name.replace('"', '""') + '"'
        columns = [row[1] for row in store.connection.execute(f'PRAGMA table_info({quoted})')]
        rows = [[cell(value) for value in row] for row in store.connection.execute(f'SELECT * FROM {quoted}')]
        rows.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(',', ':')))
        tables[name] = {'columns': columns, 'rows': rows}
    return {'tables': tables, 'meta_keys': sorted(row[0] for row in store.connection.execute('SELECT k FROM meta'))}


def replay_capture(name):
    stores = []
    def factory(*args, **kwargs):
        store = Store(*args, **kwargs)
        stores.append(store)
        return store
    with patch('cornicen.store.Store', side_effect=factory):
        notifications = harness.run_scenario(name)
    return stores[-1], notifications


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def capture(output):
    output.mkdir(parents=True, exist_ok=True)
    source_files = sorted((ROOT / 'src').rglob('*.py')) + sorted((ROOT / 'tests/replay').rglob('*.jsonl'))
    source_files += [ROOT / 'tests/replay/harness.py']
    provenance = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    for path in sorted(harness.SCENARIOS.rglob('*.input.jsonl')):
        name = str(path.relative_to(harness.SCENARIOS)).removesuffix('.input.jsonl')
        store, notifications = replay_capture(name)
        write_json(output / 'replays' / (name + '.json'), {'database': dump(store), 'notifications': notifications})
        store.connection.close()
    with tempfile.TemporaryDirectory(dir=output) as temp:
        directory = Path(temp)
        watch = directory / 'watch.toml'
        watch.write_text('[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.0.0"\nscheme="semver"\n')
        config = Config(str(directory / 'state.db'), watch, None, 'https://example.invalid', 'fixture', None)
        empty = Store(':memory:')
        empty.migrate()
        populated, _ = replay_capture('baseline_summary')
        for name, store in [('missing', None), ('empty', empty), ('populated', populated)]:
            db = Path(config.db_path)
            if db.exists():
                db.unlink()
            if store:
                import sqlite3
                with sqlite3.connect(db) as target:
                    store.connection.backup(target)
                write_json(output / 'status' / (name + '.database.json'), dump(store))
            now = datetime(2026, 11, 3, 8, tzinfo=timezone.utc)
            class FixedDateTime(datetime):
                @classmethod
                def now(cls, tz=None):
                    return now
            for json_mode in (False, True):
                stream = io.StringIO()
                with patch.object(cli, 'load_config', return_value=config), patch.object(cli, 'datetime', FixedDateTime), redirect_stdout(stream):
                    code = cli.main(['status'] + (['--json'] if json_mode else []))
                suffix = '.json' if json_mode else '.txt'
                destination = output / 'status' / (name + suffix)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(stream.getvalue())
                provenance[f'status/{name}{suffix}:exit'] = code
        empty.connection.close()
        populated.connection.close()
    write_json(output / 'capture.json', {'version': '0.1.16', 'status_at': '2026-11-03T08:00:00Z', 'populated_scenario': 'baseline_summary', 'sha256': provenance})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/fixtures/v0116_frozen')
    capture(parser.parse_args().output)

# script-purpose: Capture independent v0.1.16 timelines for the R11 differential.
# script-class: generator
# script-trigger: Manual review and tools/test-capture-r11-reference.py.
# script-tests: tools/test-capture-r11-reference.py
"""Read .build/v11/v0116/src and replay inputs; write tests/fixtures/r11_reference.

Usage: python3 tools/capture_r11_reference.py [--output DIR]
Exit 0 on success; 3 if the pinned tree is absent; 1 on capture failure.
Recreate: git archive 1c97d0d src tests tools | tar -x -C .build/v11/v0116
Never imports the implementation under test. Existing frozen files are read only.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PINNED = ROOT / '.build/v11/v0116'
ABSENT = 'pinned v0.1.16 tree absent: could not check regeneration'
# Must precede even a caller-supplied PYTHONPATH=src.
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PINNED / 'src'))


def capture(output, *, explain_only=False):
    if not (PINNED / 'src/cornicen/engine.py').is_file():
        print(ABSENT, file=sys.stderr)
        return 3
    from tests.replay_r11 import harness as h
    import cornicen.engine
    from tools.capture_v0116_frozen import dump
    from cornicen.store import Store
    from tests.replay.harness import run_scenario
    from unittest.mock import patch
    if not Path(cornicen.engine.__file__).resolve().is_relative_to(PINNED):
        raise RuntimeError('reference import escaped pinned tree')
    old = json.loads((ROOT / 'tests/fixtures/v0116_frozen/capture.json').read_text())
    hashes = {}
    for name, digest in old['sha256'].items():
        if name.startswith('src/'):
            actual = hashlib.sha256((PINNED / name).read_bytes()).hexdigest()
            if actual != digest:
                raise RuntimeError(f'unmodified v0.1.16 source mismatch: {name}')
            hashes[name] = actual
    for relative in ('tests/replay_r11/harness.py', 'tools/capture_r11_reference.py'):
        hashes[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    explanations = {}
    for name, path in h.scenarios().items():
        observation = h.run(path, reference=True, explain=True)
        explanations[name] = observation.pop('explain')
        if explain_only:
            continue
        if name.startswith('replay/'):
            # Existing frozen final databases and notifier lists remain the
            # independent anchor, in addition to the new per-action capture.
            stores = []
            def factory(*a, **kw):
                store = Store(*a, **kw)
                stores.append(store)
                return store
            with patch('cornicen.store.Store', side_effect=factory):
                notifications = run_scenario(path.name.removesuffix('.input.jsonl'))
            frozen = json.loads((ROOT / 'tests/fixtures/v0116_frozen/replays' /
                                 (path.name.removesuffix('.input.jsonl') + '.json')).read_text())
            try:
                if dict(database=dump(stores[-1]), notifications=notifications) != frozen:
                    raise RuntimeError(f'legacy frozen anchor differs: {name}')
            finally:
                stores[-1].connection.close()
        destination = output / (name + '.json')
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = (json.dumps(observation, sort_keys=True, indent=2) + '\n').encode()
        if len(content) > 5_000_000:
            destination.with_suffix('.json.gz').write_bytes(gzip.compress(content, compresslevel=9, mtime=0))
        else:
            destination.write_bytes(content)
        hashes[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    (output / 'explain.json').write_text(json.dumps(explanations, sort_keys=True, indent=2) + '\n')
    if explain_only:
        return 0
    (output / 'capture.json').write_text(json.dumps(dict(version='0.1.16', commit='1c97d0d',
        sha256=hashes), sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/fixtures/r11_reference')
    parser.add_argument('--explain-only', action='store_true', help='write only the new pinned explain.json reference')
    args = parser.parse_args()
    sys.exit(capture(args.output, explain_only=args.explain_only))

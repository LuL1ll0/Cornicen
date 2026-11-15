# script-purpose: Compare every disabled-adapter cycle with authenticated frozen v1 hashes.
# script-class: harness
# script-trigger: tests/test_f4.py; manual frozen-reference capture.
# script-tests: tests/replay_v11/test-cycle-capture.py, tests/test_f4.py
"""Read v1 timelines and frozen captures; write no files during comparison.

With --capture, print compact reference JSON using the pinned v0.1.16 source tree
selected through PYTHONPATH=.build/v11/v0116/src:.; write no files.
Exit 0 on success, 1 on comparison failure. Never updates frozen v1 captures.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(__file__).with_name('v1_cycle_hashes.json')


def without_writer_version(database, expected_version, scenario):
    """Validate the writer version before excluding only that release-specific cell."""
    from copy import deepcopy
    projected = deepcopy(database)
    table = projected['tables']['dead_letters']
    index = table['columns'].index('version')
    for row in table['rows']:
        if row[index] != expected_version:
            raise AssertionError(
                f'{scenario}: dead_letters.version: {row[index]!r} != {expected_version!r}')
        del row[index]
    del table['columns'][index]
    table['rows'].sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(',', ':')))
    return projected


def frozen_projection(database, scenario):
    version = json.loads((ROOT / 'tests/fixtures/v0116_frozen/capture.json').read_text())['version']
    return without_writer_version(database, version, scenario)


def current_projection(actual, schema, scenario):
    from cornicen import __version__
    from tests.replay_v11 import harness as h
    return without_writer_version(h.project_frozen(actual, schema), __version__, scenario)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def capture_cycles(mode='absent', check=None):
    from cornicen.engine import Engine
    from tests.replay import harness as v1
    from tests.replay_v11 import harness as h
    original = Engine.run_cycle
    initialize = Engine.__init__
    captures = {}
    def configured(engine, *args, **kwargs):
        initialize(engine, *args, **kwargs)
        if mode != 'absent':
            from cornicen import adapters
            engine.config = replace(engine.config, adapters=dict.fromkeys(adapters.REGISTRY, mode == 'true'))
    for path in sorted(v1.SCENARIOS.rglob('*.input.jsonl')):
        name = str(path.relative_to(v1.SCENARIOS)).removesuffix('.input.jsonl')
        frozen = json.loads((ROOT / 'tests/fixtures/v0116_frozen/replays' / (name + '.json')).read_text())
        frozen_projection(frozen['database'], name)
        cycles = []
        def cycle(engine, *args, **kwargs):
            report = original(engine, *args, **kwargs)
            actual = h.dump_database(engine.store.connection)
            keys = [k for k in actual['meta_keys'] if k != 'adapter_schema_version']
            schema = dict(frozen['database'], meta_keys=keys)
            projected = current_projection(actual, schema, name)
            observed = dict(meta_keys=digest(keys), database=digest(projected),
                            notifications=digest(engine.notifier.delivered))
            if check:
                check(name, len(cycles), observed, actual, schema)
            cycles.append(observed)
            return report
        with patch.object(Engine, 'run_cycle', cycle), patch.object(Engine, '__init__', configured):
            notifications = v1.run_scenario(name)
        if notifications != frozen['notifications']:
            raise AssertionError(f'{name}: final notifications differ from frozen capture')
        captures[name] = cycles
    return captures


def compare_cycles(test, mode):
    from tests.replay_v11 import harness as h
    reference = json.loads(REFERENCE.read_text())['cycles']
    def check(name, index, observed, actual, schema):
        with test.subTest(config=mode, scenario=name, cycle=index):
            test.assertEqual(observed, reference[name][index])
            # Equality above authenticates the entire tick's meta-key set against
            # its frozen hash before using those keys for the additions check.
            h.assert_additions(actual, schema)
            test.assertFalse(any(k.startswith('advisory_history:') for k in actual['meta_keys']))
    actual = capture_cycles(mode, check)
    test.assertEqual({n: len(c) for n, c in actual.items()}, {n: len(c) for n, c in reference.items()})


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps({'cycles': capture_cycles()}, separators=(',', ':'), sort_keys=True))

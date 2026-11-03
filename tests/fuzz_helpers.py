"""Seeded stdlib generators and a runner that finishes even after a failure.

Run with PYTHONPATH=src python3 -m unittest tests.test_fuzz -v.
CORNICEN_FUZZ_CASES changes the default 10,000 cases *per scheme/property*;
CORNICEN_FUZZ_SEED changes the reproducible base seed (decimal or 0x-prefixed).
"""

from dataclasses import dataclass
import hashlib
from itertools import chain
import json
import os
from pathlib import Path
import random


CASES = int(os.environ.get('CORNICEN_FUZZ_CASES', '10000'))
SEED = int(os.environ.get('CORNICEN_FUZZ_SEED', '0xC0A51CE'), 0)
if CASES < 1:
    raise ValueError('CORNICEN_FUZZ_CASES must be positive')
RUNS = []
ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Violation(Exception):
    actual: object
    expected: object
    spec: str
    reason: str


def equal(actual, expected, spec, reason):
    if actual != expected:
        raise Violation(actual, expected, spec, reason)


def unicode_text(rng, maximum=64):
    """Include all Unicode code points, lone surrogates, controls and edge text."""
    edges = ['', '\x00', '\n', '\ud800', '\U0010ffff', '١.０.0', '1\u200b.0',
             '0' * 5000, '1.' + '9' * 5000, '1.0.' + '9' * 5000]
    if rng.randrange(8) == 0:
        return rng.choice(edges)
    alphabet = '0123456789.vV-+~: abcXYZ\t\n\x00éΩ١０\u200b'
    return ''.join(rng.choice(alphabet) if rng.randrange(3) else chr(rng.randrange(0x110000))
                   for _ in range(rng.randrange(maximum + 1)))


def decorated(rng, text):
    """Identity variations: ASCII case and whitespace only, preserving punctuation."""
    words = [ ''.join(c.upper() if rng.randrange(2) else c.lower() for c in word)
             for word in text.split() ]
    return rng.choice(['', ' ', '\t']) + rng.choice([' ', '  ', '\t\n']).join(words) + rng.choice(['', ' ', '\n'])


def malformed(rng):
    return rng.choice([None, True, False, 0, 7, 1.5, [], {}, [None], {'bad': []}])


def _size(value):
    return len(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _reductions(value):
    """Deletion and scalar simplification; no production parser in the shrinker."""
    if isinstance(value, dict):
        for key in value:
            yield {k: v for k, v in value.items() if k != key}
        for key, item in value.items():
            for smaller in _reductions(item):
                yield dict(value, **{key: smaller})
    elif isinstance(value, list):
        width = max(1, len(value))
        while width:
            for start in range(0, len(value), width):
                yield value[:start] + value[start + width:]
            width //= 2
        for index, item in enumerate(value):
            for smaller in _reductions(item):
                yield value[:index] + [smaller] + value[index + 1:]
    elif isinstance(value, str):
        canonical = ' '.join(value.lower().split())
        if canonical != value and len(canonical) <= len(value):
            yield canonical
        for smaller in ('', '0', '1', 'a'):
            if (len(smaller), smaller) < (len(value), value):
                yield smaller
        width = max(1, len(value))
        while width:
            for start in range(0, len(value), width):
                yield value[:start] + value[start + width:]
            width //= 2
    elif value is not None:
        yield None
        if value not in (0, False):
            yield 0


def _shared_reductions(value):
    """Simplify repeated boundary strings together, preserving equality ties."""
    counts = {}

    def collect(item):
        if isinstance(item, dict):
            for child in item.values():
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, str):
            counts[item] = counts.get(item, 0) + 1

    def substitute(item, old, new):
        if isinstance(item, dict):
            return {key: substitute(child, old, new) for key, child in item.items()}
        if isinstance(item, list):
            return [substitute(child, old, new) for child in item]
        return new if isinstance(item, str) and item == old else item

    collect(value)
    for text, count in counts.items():
        if count > 1:
            for smaller in ('', '0', '1', 'a'):
                if (len(smaller), smaller) < (len(text), text):
                    yield substitute(value, text, smaller)


def _observation(check, case, spec):
    try:
        checked = check(case)
        return None, checked is not False
    except Violation as failure:
        return failure, True
    except Exception as error:
        return Violation(f'{type(error).__name__}: {error}', 'no exception', spec,
                         'unexpected exception'), True


def _signature(failure):
    actual = failure.actual
    if failure.reason == 'unexpected exception':
        # Message details (e.g. decimal digit counts) change during shrinking.
        actual = actual.split(':', 1)[0]
    return json.dumps([actual, failure.expected, failure.spec, failure.reason],
                      ensure_ascii=True, sort_keys=True)


def minimise(case, check, failure, spec):
    """Reach a fixed point: 1-minimal under _reductions, keeping the same failure.

    A smaller candidate must still satisfy the property's input domain. This is
    local minimality, not a claim of the globally shortest possible reproducer.
    """
    signature = _signature(failure)
    while True:
        for candidate in chain(_shared_reductions(case), _reductions(case)):
            if _size(candidate) > _size(case):
                continue
            observed, _ = _observation(check, candidate, spec)
            if observed is not None and _signature(observed) == signature:
                case = candidate
                break
        else:
            return case


def run_property(test, name, generate, check, spec):
    digest = hashlib.sha256(f'{SEED}:{name}'.encode()).digest()
    seed = int.from_bytes(digest[:8], 'big')
    rng = random.Random(seed)
    failures = {}
    checked = 0
    failed = 0
    # Identical original inputs share their shrink result, but every failed case
    # is retained by index in the report, including repeats.
    cache = {}
    for index in range(CASES):
        case = generate(rng, index)
        failure, did_check = _observation(check, case, spec)
        checked += did_check
        if failure is None:
            continue
        failed += 1
        original_key = json.dumps(case, ensure_ascii=True, sort_keys=True)
        if original_key not in cache:
            cache[original_key] = minimise(case, check, failure, spec)
        minimal = cache[original_key]
        failure, _ = _observation(check, minimal, spec)
        key = _signature(failure) + json.dumps(minimal, ensure_ascii=True, sort_keys=True)
        if key not in failures:
            failures[key] = {'input': minimal, 'actual': failure.actual,
                             'expected': failure.expected, 'spec': failure.spec,
                             'reason': failure.reason, 'indices': []}
        failures[key]['indices'].append(index)
    result = {'name': name, 'seed': seed, 'cases': CASES, 'checked': checked,
              'failed': failed, 'failures': list(failures.values()), 'spec': spec}
    RUNS.append(result)
    write_report()
    if failed:
        first = result['failures'][0]
        preview = json.dumps(first['input'], ensure_ascii=True)
        if len(preview) > 500:
            preview = preview[:500] + '... (full input in report)'
        test.fail(f'{name}: {failed}/{CASES} failed; base seed={SEED}, '
                  f'property seed={seed}, case={first["indices"][0]}; '
                  f'input={preview}; '
                  f'actual={first["actual"]!r}; expected={first["expected"]!r}; '
                  f'{first["spec"]}. All cases ran; see .build/fuzz.out.md')


def write_report():
    total = sum(r['cases'] for r in RUNS)
    failed = sum(r['failed'] for r in RUNS)
    lines = [f'# Fuzz results: {"FAIL" if failed else "PASS"}', '',
             f'{len(RUNS)} property/scheme runs; {total:,} generated cases; '
             f'{failed:,} failing cases.', '',
             f'Command: `PYTHONPATH=src CORNICEN_FUZZ_CASES={CASES} '
             'python3 -m unittest tests.test_fuzz -v`.',
             f'Base seed: `{SEED}` (`{SEED:#x}`). Override with `CORNICEN_FUZZ_SEED`.', '',
             '| Property | Cases | Checked | Failures | Result | Property seed |',
             '|---|---:|---:|---:|---|---:|']
    for run in RUNS:
        lines.append(f'| {run["name"]} | {run["cases"]} | {run["checked"]} | '
                     f'{run["failed"]} | {"FAIL" if run["failed"] else "PASS"} | {run["seed"]} |')
    lines += ['', 'Checked counts generated cases accepted by the check; it excludes explicit '
              'domain rejections and oracle abstentions. Shrink attempts are additional and '
              'are not counted. Generated cases always reach the requested count. '
              'Properties with zero checked '
              'cases are not evidence of correctness.', '',
              'Failure indices are zero-based. Every failing case is listed in a group below. '
              'Groups share the same locally minimal reproducer and actual/expected result. '
              'Shrinking preserves the failure and valid watch domain, reaches a fixed point '
              'under field/item/chunk deletion, scalar simplification and shared-boundary '
              'simplification, and does not claim '
              'global minimality. Reproduce a group directly with its JSON input and the '
              'named check in tests/test_fuzz.py; reproduce the full stream using its seed.', '',
              'Under docs/spec.md §4, unlisted opaque versions are affected only '
              'when defaultStatus is affected; otherwise they are unknown. '
              'Opaque ordering, ranges and status changes are unknown.', '',
              'The §5 oracle uses independent version parsers and Debian Policy §5.6.12 '
              'ordering, point evaluation, uniform affected-default uncertainty, and interval union/coverage for a restricted '
              'decidable range domain. It abstains on malformed or ambiguous schema '
              'semantics; malformed data is still covered by never-raises. Random ASCII '
              'case/whitespace variations apply to identities, not case-sensitive SemVer '
              'identifiers or schema enum values. No external tools, packages or network.', '']
    for run in RUNS:
        for number, failure in enumerate(run['failures'], 1):
            lines += [f'## {run["name"]} — failure {number}', '',
                      f'Rule: {failure["spec"]}. {failure["reason"]}.', '',
                      f'Property seed: `{run["seed"]}`. Case indices: '
                      f'`{", ".join(map(str, failure["indices"]))}`.', '',
                      f'Actual: `{json.dumps(failure["actual"], ensure_ascii=True)}`. '
                      f'Expected: `{json.dumps(failure["expected"], ensure_ascii=True)}`.', '',
                      'Minimal reproducing input:', '', '```json',
                      json.dumps(failure['input'], ensure_ascii=True, sort_keys=True, indent=2),
                      '```', '']
    path = ROOT / '.build' / 'fuzz.out.md'
    path.parent.mkdir(exist_ok=True)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

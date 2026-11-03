"""Reproducible properties for spec §§4–5; no production code is an oracle.

Each test runs 10,000 cases by default (for version properties, per scheme).
Failures deliberately fail unittest, after completing the entire random stream.
"""

from itertools import zip_longest
import math
import re
import unittest

from cornicen.applicability import resolve
from cornicen.identity import AliasMap
from cornicen.versions import Scheme, compare, parse_constraint, satisfies
from cornicen.watchlist import Watch
from tests.fuzz_helpers import (
    decorated, equal, malformed, run_property, unicode_text,
)


SEMVER = 'docs/spec.md:96 (SemVer 2.0 precedence)'
DOTTED = 'docs/spec.md:97 (numeric segments; padding cannot prove equality)'
DEBIAN = 'docs/spec.md:98 (Debian Policy §5.6.12 ordering)'
OPAQUE = 'docs/spec.md:99 (opaque equality/defaultStatus; no ordering or changes)'
UNKNOWN = 'docs/spec.md:101 (undecidable comparisons yield unknown)'
AGGREGATION = 'docs/spec.md §5 (affected > unaffected > unknown across entries)'
RULES = {'semver': SEMVER, 'dotted': DOTTED, 'debian': DEBIAN, 'opaque': OPAQUE}
OPS = ('=', '>=', '>', '<=', '<')
STATUSES = ('affected', 'unaffected', 'unknown')
PLACEHOLDERS = ('', 'n/a', 'NA', 'unknown', '-', 'none', 'not available')
ALIASES = AliasMap()  # This generated identity domain has no spelling aliases.
ABSTAIN = object()


def sign(a, b):
    return (a > b) - (a < b)


def natural(text):
    # Independent reference arithmetic also accepts >4,300-digit valid inputs.
    result = 0
    for char in text:
        result = result * 10 + ord(char) - ord('0')
    return result


def semver_parts(text):
    text = text[1:] if text.startswith(('v', 'V')) else text
    main, plus, build = text.partition('+')
    if plus and (not build or any(not p or any(c not in
            '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-' for c in p)
            for p in build.split('.'))):
        return None
    core, dash, pre = main.partition('-')
    parts = core.split('.')
    if len(parts) != 3 or any(not p or any(c not in '0123456789' for c in p)
                             or len(p) > 1 and p[0] == '0' for p in parts):
        return None
    prerelease = pre.split('.') if dash else []
    for part in prerelease:
        if not part or any(c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-'
                           for c in part):
            return None
        if all(c in '0123456789' for c in part) and len(part) > 1 and part[0] == '0':
            return None
    return tuple(map(natural, parts)), prerelease


def debian_parts(text):
    """Policy: [epoch:]upstream[-revision], splitting at the last hyphen."""
    epoch = '0'
    if ':' in text:
        epoch, _, text = text.partition(':')
        if not epoch or any(c not in '0123456789' for c in epoch):
            return None
    upstream, hyphen, revision = text.rpartition('-')
    if not hyphen:
        upstream, revision = text, '0'
    elif not revision or any(c not in
            '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+.~' for c in revision):
        return None
    if not upstream or upstream[0] not in '0123456789' or any(c not in
            '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+:~-' for c in upstream):
        return None
    return natural(epoch), upstream, revision


def debian_reference(a, b):
    """Straightforward Policy §5.6.12: alternate lexical and numeric runs.

    Tilde precedes even end-of-part; letters precede punctuation. Numeric runs
    compare as integers (leading zeroes ignored). An absent revision is zero.
    This uses substring consumption and arbitrary-precision reference integers,
    rather than the production index/decimal-string implementation.
    """
    def rank(char):
        if char == '~':
            return -1
        if char == '':
            return 0
        if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
            return ord(char)
        return 256 + ord(char)

    def part(left, right):
        while left or right:
            lx = re.match(r'[^0-9]*', left).group()
            rx = re.match(r'[^0-9]*', right).group()
            for x, y in zip_longest(lx, rx, fillvalue=''):
                result = sign(rank(x), rank(y))
                if result:
                    return result
            left, right = left[len(lx):], right[len(rx):]
            lx = re.match(r'[0-9]*', left).group()
            rx = re.match(r'[0-9]*', right).group()
            result = sign(natural(lx), natural(rx))
            if result:
                return result
            left, right = left[len(lx):], right[len(rx):]
        return 0

    left, right = debian_parts(a), debian_parts(b)
    if left is None or right is None:
        return None
    return sign(left[0], right[0]) or part(left[1], right[1]) or part(left[2], right[2])


def reference_compare(a, b, scheme):
    if scheme == 'opaque':
        return 0 if a == b else None
    if scheme == 'debian':
        return debian_reference(a, b)
    if scheme == 'semver':
        ap, bp = semver_parts(a), semver_parts(b)
        if ap is None or bp is None:
            return None
        result = sign(ap[0], bp[0])
        if result:
            return result
        if not ap[1] or not bp[1]:
            return sign(not ap[1], not bp[1])
        for x, y in zip(ap[1], bp[1]):
            numeric_x, numeric_y = x.isascii() and x.isdigit(), y.isascii() and y.isdigit()
            if numeric_x and numeric_y:
                result = sign(natural(x), natural(y))
            elif numeric_x != numeric_y:
                result = -1 if numeric_x else 1
            else:
                result = sign(x, y)
            if result:
                return result
        return sign(len(ap[1]), len(bp[1]))
    a = a[1:] if a.startswith(('v', 'V')) else a
    b = b[1:] if b.startswith(('v', 'V')) else b
    ap, bp = a.split('.'), b.split('.')
    if any(not p or any(c not in '0123456789' for c in p) for p in ap + bp):
        return None
    result = sign(tuple(map(natural, ap)) + (0,) * max(0, len(bp) - len(ap)),
                  tuple(map(natural, bp)) + (0,) * max(0, len(ap) - len(bp)))
    return result if result or len(ap) == len(bp) else None


def version(rng, scheme):
    if scheme == 'semver':
        result = '.'.join(str(rng.randrange(20)) for _ in range(3))
        if rng.randrange(2):
            result += '-' + rng.choice(['alpha', 'rc', '0', 'beta.2', 'rc.10', 'x-y.0'])
        if rng.randrange(3) == 0:
            result += '+' + rng.choice(['build.001', 'abc', '0'])
    elif scheme == 'dotted':
        result = '.'.join('0' * rng.randrange(3) + str(rng.randrange(30))
                          for _ in range(rng.randrange(1, 6)))
    elif scheme == 'debian':
        result = str(rng.randrange(8)) + rng.choice(['', '.0', '.01', '~rc1', 'a1', '+git9', '-a'])
        if rng.randrange(2):
            result += '-' + rng.choice(['0', '1', '02', '1~bpo1', '0ubuntu1', 'a', '+'])
        if rng.randrange(3) == 0:
            result = str(rng.randrange(5)) + ':' + result
    else:
        return rng.choice(['build-a', 'build-b', '0', 'RomePI 1.0.G', 'Ω', 'release-x'])
    if scheme in ('semver', 'dotted') and rng.randrange(4) == 0:
        result = rng.choice('vV') + result
    return result


def lattice_version(number, scheme):
    return f'{number}.0.0' if scheme == 'semver' else str(number)


def version_case(rng, scheme, count=2, arbitrary=False):
    values = [unicode_text(rng) if arbitrary and rng.randrange(3) == 0 else version(rng, scheme)
              for _ in range(count)]
    if rng.randrange(4) == 0 or scheme == 'opaque' and count == 3:
        values = [values[0]] * count
    return dict(scheme=scheme, **dict(zip(('a', 'b', 'c'), values)))


def version_domain(case, count=2):
    return (isinstance(case, dict) and case.get('scheme') in RULES
            and all(isinstance(case.get(key), str) for key in ('a', 'b', 'c')[:count]))


def watch_for(case):
    return Watch('fuzz', 'Fuzz service', (('example corp', 'test-service'),),
                 ('test-service',) if case.get('loose') else (),
                 case['version'], Scheme(case['scheme']), False)


def application_domain(case):
    if not isinstance(case, dict) or case.get('scheme') not in RULES:
        return False
    text = case.get('version')
    if not isinstance(text, str) or not text.strip() or 'record' not in case:
        return False
    text = text.strip()
    if text.startswith(('=', '>', '<')) or ',' in text:
        for item in text.split(','):
            match = re.fullmatch(r'\s*(>=|<=|=|>|<)\s*([^\s,=<>!|]+)\s*', item)
            if not match or reference_compare(match[2], match[2], case['scheme']) != 0:
                return False
    elif reference_compare(text, text, case['scheme']) != 0:
        return False
    return True


def record(entries, state='PUBLISHED'):
    return {'cveMetadata': {'cveId': 'CVE-2026-1000', 'state': state},
            'containers': {'cna': {'affected': entries}}}


def entry(rows, default='unknown', vendor='example corp', product='test-service'):
    return {'vendor': vendor, 'product': product, 'versions': rows, 'defaultStatus': default}


def kev(rng, matching=True):
    return {'cveID': rng.choice(['CVE-2026-1000', 'cve-2026-1000']) if matching else 'CVE-2026-2000',
            'vendorProject': decorated(rng, 'example corp'),
            'product': decorated(rng, 'test-service')}


def generated_application(rng, index, corrupt=False, ranges=False):
    scheme = tuple(RULES)[index % 4]
    watched = lattice_version(rng.randrange(1, 7), scheme)
    if scheme == 'opaque':
        watched = version(rng, scheme)
    if ranges:
        scheme = ('semver', 'dotted', 'debian')[index % 3]
        low, high = sorted(rng.sample(range(1, 9), 2))
        watched = (rng.choice(['>', '>=']) + lattice_version(low, scheme) + ', '
                   + rng.choice(['<', '<=']) + lattice_version(high, scheme))
    entries = []
    for _ in range(rng.randrange(1, 4)):
        rows = []
        for _ in range(rng.randrange(4)):
            low, high = sorted(rng.sample(range(1, 10), 2))
            lower = lattice_version(low, scheme) if scheme != 'opaque' else version(rng, scheme)
            row = {'version': lower, 'status': rng.choice(STATUSES)}
            if rng.randrange(3) != 0:
                row[rng.choice(['lessThan', 'lessThanOrEqual'])] = (
                    lattice_version(high, scheme) if scheme != 'opaque' else version(rng, scheme))
                if rng.randrange(2):
                    changes = [{'at': lattice_version(n, scheme) if scheme != 'opaque'
                                else rng.choice([lower, watched, version(rng, scheme)]),
                                'status': rng.choice(STATUSES)}
                               for n in rng.sample(range(low, high), rng.randrange(min(3, high - low) + 1))]
                    rng.shuffle(changes)
                    row['changes'] = changes
            elif scheme == 'opaque' and rng.randrange(4) == 0:
                row['changes'] = [{'at': lower, 'status': rng.choice(STATUSES)}]
            if rng.randrange(2) == 0:
                space = rng.choice(['', ' ', '\t', '\n'])
                upper = row.pop('lessThan', None)
                inclusive = row.pop('lessThanOrEqual', None)
                if upper is not None or inclusive is not None:
                    row['version'] = (rng.choice(['>', '>=']) + space + lower + ',' + space
                                      + ('<' if upper is not None else '<=') + space
                                      + (upper if upper is not None else inclusive))
                else:
                    row['version'] = rng.choice(OPS) + space + lower
            if rng.randrange(3) != 0:
                row['versionType'] = rng.choice([scheme, 'custom', 'rpm', 'git'])
            rows.append(row)
        vendor = rng.choice(['example corp'] * 6 + ['other corp'] + list(PLACEHOLDERS))
        product = rng.choice(['test-service'] * 8 + ['testservice'] + list(PLACEHOLDERS))
        item = entry(rows, rng.choice(STATUSES), decorated(rng, vendor), decorated(rng, product))
        if rng.randrange(2) == 0:
            item.pop('defaultStatus')
        if corrupt and rng.randrange(2) == 0:
            target = rng.choice(['vendor', 'product', 'versions', 'defaultStatus', 'row', 'change'])
            if target == 'row' and rows:
                rows[0][rng.choice(['version', 'status', 'lessThan', 'lessThanOrEqual', 'versionType'])] = malformed(rng)
            elif target == 'change' and rows:
                rows[0]['changes'] = rng.choice([malformed(rng), [{'at': malformed(rng), 'status': malformed(rng)}]])
            elif target not in ('row', 'change'):
                item[target] = malformed(rng)
        entries.append(item)
    rec = record(entries, rng.choice(['PUBLISHED'] * 8 + ['REJECTED', 'WITHDRAWN', 'rejected']))
    kev_entry = kev(rng, rng.randrange(4) != 0) if rng.randrange(3) == 0 else None
    if corrupt:
        if rng.randrange(4) == 0:
            # Include malformed containers, whole affected entries and metadata.
            location = rng.randrange(7)
            if location == 0:
                rec = malformed(rng)
            elif location == 1:
                rec['containers'] = malformed(rng)
            elif location == 2:
                rec['containers']['cna'] = malformed(rng)
            elif location == 3:
                rec['containers']['cna']['affected'] = malformed(rng)
            elif location == 4:
                entries.append(malformed(rng))
            elif location == 5:
                rec['cveMetadata'] = malformed(rng)
            else:
                rec['cveMetadata']['state'] = malformed(rng)
        if rng.randrange(4) == 0:
            kev_entry = malformed(rng)
        elif isinstance(kev_entry, dict) and rng.randrange(3) == 0:
            kev_entry[rng.choice(['cveID', 'vendorProject', 'product'])] = malformed(rng)
    return {'scheme': scheme, 'version': watched, 'record': rec, 'kev': kev_entry,
            'loose': bool(rng.randrange(2))}


def state_name(status):
    return {'affected': 'affected', 'unaffected': 'not_affected'}.get(status, 'unknown')


def generated_constraint_application(rng, index, ranges=False):
    """Decidable comparator domain with guaranteed matching CNA identities."""
    scheme = ('semver', 'dotted', 'debian')[index % 3]
    rows = []
    affected_only = index % 2 == 0
    for _ in range(rng.randrange(1, 5)):
        low, high = sorted(rng.sample(range(1, 10), 2))
        space = rng.choice(['', ' ', '\t', '\n'])
        text = rng.choice(OPS) + space + lattice_version(low, scheme)
        if rng.randrange(2):
            text = (rng.choice(['>', '>=']) + space + lattice_version(low, scheme)
                    + ',' + space + rng.choice(['<', '<=']) + space
                    + lattice_version(high, scheme))
        rows.append({'version': space + text + space,
                     'status': 'affected' if affected_only else rng.choice(STATUSES)})
    item = entry(rows)
    if rng.randrange(2):
        item['defaultStatus'] = rng.choice(STATUSES)
    else:
        item.pop('defaultStatus')
    watched = lattice_version(rng.randrange(1, 10), scheme)
    if ranges:
        low, high = sorted(rng.sample(range(1, 10), 2))
        watched = (rng.choice(['>', '>=']) + lattice_version(low, scheme) + ', '
                   + rng.choice(['<', '<=']) + lattice_version(high, scheme))
    return {'scheme': scheme, 'version': watched, 'record': record([item])}


def combine(states):
    return next((s for s in ('affected', 'not_affected') if s in states), 'unknown')


def comparator_terms(row):
    """Independent grammar; explicit CNA range fields always take precedence."""
    if 'lessThan' in row or 'lessThanOrEqual' in row:
        return None
    text = row.get('version')
    if not isinstance(text, str):
        return None
    terms = []
    for part in text.split(','):
        match = re.fullmatch(r'\s*(>=|<=|=|>|<)\s*([^\s,=<>!|]+)\s*', part)
        if match is None:
            return None
        terms.append(match.groups())
    return terms


def default_status(item):
    if 'defaultStatus' in item:
        return item['defaultStatus']
    rows = item.get('versions', [])
    affected_constraints = [r for r in rows if r.get('status') == 'affected'
                            and comparator_terms(r) is not None]
    return 'unaffected' if rows and len(affected_constraints) == len(rows) else 'unknown'


def entry_oracle(item, watched, scheme):
    """Literal §5 point rules, abstaining on undefined malformed schema shapes."""
    rows = item.get('versions', [])
    if not isinstance(rows, list) or item.get('defaultStatus', 'unknown') not in STATUSES:
        return ABSTAIN
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('version'), str):
            return ABSTAIN
        if row.get('versionType') not in (None, 'custom', scheme):
            return 'unknown'
        if row.get('status') not in STATUSES:
            return ABSTAIN
        if 'lessThan' in row and 'lessThanOrEqual' in row:
            return ABSTAIN
        if not isinstance(row.get('changes', []), list):
            return ABSTAIN
    states = []
    for row in rows:
        lower = row['version']
        upper = row.get('lessThan', row.get('lessThanOrEqual'))
        terms = comparator_terms(row)
        if terms is not None:
            if scheme == 'opaque':
                if any(op != '=' for op, _ in terms):
                    return 'unknown'
                inside = all(watched == bound for _, bound in terms)
            else:
                relations = [(op, reference_compare(watched, bound, scheme))
                             for op, bound in terms]
                if any(value is None for _, value in relations):
                    return 'unknown'
                inside = all({'=': value == 0, '>': value > 0, '>=': value >= 0,
                              '<': value < 0, '<=': value <= 0}[op]
                             for op, value in relations)
        elif upper is None:
            if lower == '*':
                inside = True
            elif scheme == 'opaque':
                inside = watched == lower
            else:
                relation = reference_compare(watched, lower, scheme)
                if relation is None:
                    return 'unknown'
                inside = relation == 0
        else:
            if not isinstance(upper, str):
                return ABSTAIN
            if scheme == 'opaque':
                return 'unknown'
            low = 1 if lower in ('0', '0.0', '0.0.0', '*') else reference_compare(watched, lower, scheme)
            high = -1 if upper == '*' else reference_compare(watched, upper, scheme)
            if low is None or high is None:
                return 'unknown'
            inside = low >= 0 and (high < 0 or high == 0 and 'lessThanOrEqual' in row)
        if not inside:
            continue
        status = row.get('status')
        changes = row.get('changes', [])
        if changes and scheme == 'opaque':
            return 'unknown'
        applicable = []
        for change in changes:
            if (not isinstance(change, dict) or not isinstance(change.get('at'), str)
                    or change.get('status') not in STATUSES):
                return ABSTAIN
            relation = reference_compare(watched, change['at'], scheme)
            if relation is None:
                return 'unknown'
            if relation >= 0:
                applicable.append(change)
        if applicable:
            # Max by independent pairwise ordering; duplicate conflicting
            # transition timestamps have no stated tie rule, so abstain.
            latest = applicable[0]
            for change in applicable[1:]:
                relation = reference_compare(change['at'], latest['at'], scheme)
                if relation is None:
                    return 'unknown'
                if relation == 0 and change['status'] != latest['status']:
                    return ABSTAIN
                if relation > 0:
                    latest = change
            status = latest['status']
        states.append(state_name(status))
    if states:
        return combine(states)
    default = state_name(default_status(item))
    if scheme == 'opaque' and default != 'affected':
        return 'unknown'
    return default


# An interval is (lower, lower_included, upper, upper_included). All generated
# range endpoints are integer releases >=1, so every intervening open interval
# contains versions in each ordered scheme. Coverage is proved by subtraction,
# not by sampling versions or copying the production boundary-cell evaluator.
def intersection(a, b):
    lo, hi = max(a[0], b[0]), min(a[2], b[2])
    lc = (a[1] if a[0] == lo else True) and (b[1] if b[0] == lo else True)
    hc = (a[3] if a[2] == hi else True) and (b[3] if b[2] == hi else True)
    return (lo, lc, hi, hc) if lo < hi or lo == hi and lc and hc else None


def subtract_all(intervals, cuts):
    for cut in cuts:
        remaining = []
        for item in intervals:
            overlap = intersection(item, cut)
            if overlap is None:
                remaining.append(item)
                continue
            left = (item[0], item[1], overlap[0], not overlap[1])
            right = (overlap[2], not overlap[3], item[2], item[3])
            remaining.extend(p for p in (left, right) if intersection(p, p) is not None)
        intervals = remaining
    return intervals


def numeric_endpoint(text, scheme):
    pattern = r'([1-9][0-9]*)\.0\.0' if scheme == 'semver' else r'([1-9][0-9]*)'
    match = re.fullmatch(pattern, text) if isinstance(text, str) else None
    return natural(match[1]) if match else None


def constraint_interval(terms, scheme):
    lo, lc, hi, hc = -math.inf, False, math.inf, False
    for op, bound in terms:
        if reference_compare(bound, bound, scheme) is None:
            return 'unknown'
        bound = numeric_endpoint(bound, scheme)
        if bound is None:
            return ABSTAIN
        interval = {'>': (bound, False, math.inf, False), '>=': (bound, True, math.inf, False),
                    '<': (-math.inf, False, bound, False), '<=': (-math.inf, False, bound, True),
                    '=': (bound, True, bound, True)}[op]
        clipped = intersection((lo, lc, hi, hc), interval)
        if clipped is None:
            return ABSTAIN  # Empty constraints are outside this oracle domain.
        lo, lc, hi, hc = clipped
    return lo, lc, hi, hc


def range_entry_oracle(item, watched, scheme):
    if scheme == 'opaque':
        return 'unknown'
    terms = comparator_terms({'version': watched})
    if terms is None:
        return ABSTAIN
    watch_interval = constraint_interval(terms, scheme)
    if watch_interval is ABSTAIN or watch_interval == 'unknown':
        return watch_interval
    listed, positive, negative = [], [], []
    rows = item.get('versions', [])
    if not isinstance(rows, list):
        return ABSTAIN
    for row in rows:
        if not isinstance(row, dict):
            return ABSTAIN
        if row.get('status') not in STATUSES:
            return ABSTAIN
        if row.get('versionType') not in (None, 'custom', scheme):
            return 'unknown'
    for row in rows:
        terms = comparator_terms(row)
        if terms is not None:
            whole = constraint_interval(terms, scheme)
            if whole is ABSTAIN or whole == 'unknown':
                return whole
            low, _, high, closed = whole
        else:
            whole = None
        for field in ('version', 'lessThan', 'lessThanOrEqual'):
            if terms is not None and field == 'version':
                continue
            if field in row:
                text = row[field]
                if not isinstance(text, str):
                    return ABSTAIN
                if reference_compare(text, text, scheme) is None:
                    return 'unknown'
        if whole is None:
            low = numeric_endpoint(row.get('version'), scheme)
            upper = row.get('lessThan', row.get('lessThanOrEqual'))
            high = numeric_endpoint(upper, scheme) if upper is not None else low
            if low is None or high is None or low > high:
                return ABSTAIN
            closed = upper is None or 'lessThanOrEqual' in row
            whole = (low, True, high, closed)
        if intersection(whole, whole) is None:
            return ABSTAIN
        listed.append(whole)
        transitions = [(low, row.get('status', 'unknown'))]
        changes = row.get('changes', [])
        if not isinstance(changes, list):
            return ABSTAIN
        for change in changes:
            if not isinstance(change, dict):
                return ABSTAIN
            if not isinstance(change.get('at'), str):
                return ABSTAIN
            if reference_compare(change['at'], change['at'], scheme) is None:
                return 'unknown'
            at = numeric_endpoint(change.get('at'), scheme)
            if at is None or not low <= at < high:
                return ABSTAIN
            transitions.append((at, change.get('status', 'unknown')))
        # A transition at the lower endpoint replaces the initial status.
        statuses = dict(transitions)
        times = sorted(statuses)
        for index, at in enumerate(times):
            end = times[index + 1] if index + 1 < len(times) else high
            piece = (at, whole[1] if index == 0 else True,
                     end, closed if index + 1 == len(times) else False)
            status = statuses[at]
            if status not in STATUSES:
                return ABSTAIN
            if status == 'affected':
                positive.append(piece)
            elif status == 'unaffected':
                negative.append(piece)
    if any(intersection(watch_interval, p) is not None for p in positive):
        return 'affected'
    unlisted = subtract_all([watch_interval], listed)
    default = default_status(item)
    if default == 'affected' and unlisted:
        return 'affected'
    excluded = negative + (unlisted if default == 'unaffected' else [])
    return 'not_affected' if not subtract_all([watch_interval], excluded) else 'unknown'


def identity_kind(vendor, product, loose):
    if not isinstance(vendor, str) or not isinstance(product, str):
        return None
    vendor, product = ' '.join(vendor.lower().split()), ' '.join(product.lower().split())
    placeholders = {'', 'na', 'unknown', 'none', 'null', 'tbd', 'unspecified',
                    'notapplicable', 'notavailable'}
    if any(re.sub(r'[\W_]+', '', text) in placeholders for text in (vendor, product)):
        return None
    if (vendor, product) == ('example corp', 'test-service'):
        return 'exact'
    return 'loose' if loose and product == 'test-service' else None


def oracle(case, range_watch=False):
    rec = case['record']
    if not isinstance(rec, dict):
        return ABSTAIN
    metadata = rec.get('cveMetadata', {})
    containers = rec.get('containers', {})
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        return ABSTAIN
    cna = containers.get('cna', {})
    if not isinstance(cna, dict) or not isinstance(cna.get('affected', []), list):
        return ABSTAIN
    matches = []
    for item in cna.get('affected', []):
        if not isinstance(item, dict):
            continue
        kind = identity_kind(item.get('vendor'), item.get('product'), case.get('loose'))
        if kind:
            matches.append((item, kind))
    kev_entry = case.get('kev')
    kev_match = False
    if isinstance(kev_entry, dict):
        cid, kid = metadata.get('cveId'), kev_entry.get('cveID')
        if isinstance(cid, str) and isinstance(kid, str) and cid and cid.lower() == kid.lower():
            kev_match = bool(identity_kind(kev_entry.get('vendorProject'), kev_entry.get('product'),
                                           case.get('loose')))
    if not matches and not kev_match:
        return None
    state = metadata.get('state', '')
    if not isinstance(state, str):
        return 'unknown'
    if state.upper() in ('REJECTED', 'WITHDRAWN'):
        return 'not_affected'
    exact = [item for item, kind in matches if kind == 'exact']
    if not exact:
        return 'unknown'
    evaluate = range_entry_oracle if range_watch else entry_oracle
    states = [evaluate(item, case['version'].strip(), case['scheme']) for item in exact]
    if ABSTAIN in states:
        return ABSTAIN
    return combine(states)


def resolved_state(case):
    result = resolve(case['record'], case.get('kev'), watch_for(case), ALIASES)
    return None if result is None else result.state.value


def check_oracle(case, range_watch=False):
    if not application_domain(case):
        return False
    if range_watch and not case['version'].strip().startswith(('=', '>', '<')):
        return False
    expected = oracle(case, range_watch)
    if expected is ABSTAIN:
        return False
    spec = ('docs/spec.md:101,115-121,125-128 (range and evidence rules)' if range_watch
            else 'docs/spec.md:115-121,125-128 (point and evidence rules)')
    if case['scheme'] == 'opaque':
        spec = OPAQUE + ('; docs/spec.md:118 (defaultStatus)' if expected == 'not_affected' else '')
    equal(resolved_state(case), expected, spec,
          'independent §5 oracle disagrees')


class VersionFuzzTests(unittest.TestCase):
    def schemes(self, name, generate, check):
        for scheme in RULES:
            with self.subTest(scheme=scheme):
                run_property(self, f'versions.{name}.{scheme}',
                             lambda rng, index, s=scheme: generate(rng, index, s),
                             check, RULES[scheme])

    def test_compare_antisymmetric(self):
        def check(case):
            if not version_domain(case):
                return False
            scheme, a, b = case['scheme'], case['a'], case['b']
            ab, ba = compare(a, b, Scheme(scheme)), compare(b, a, Scheme(scheme))
            equal(ab is None, ba is None, RULES[scheme], 'decidability must be symmetric')
            if ab is not None:
                equal(ab, -ba, RULES[scheme], 'comparison must be antisymmetric')
        self.schemes('antisymmetric', lambda r, i, s: version_case(r, s, arbitrary=True), check)

    def test_compare_reflexive(self):
        def check(case):
            if not version_domain(case, 1) or reference_compare(case['a'], case['a'], case['scheme']) != 0:
                return False
            equal(compare(case['a'], case['a'], Scheme(case['scheme'])), 0,
                  RULES[case['scheme']], 'valid version must compare equal to itself')
        self.schemes('reflexive', lambda r, i, s: {'scheme': s, 'a': version(r, s)}, check)

    def test_compare_transitive(self):
        def check(case):
            if not version_domain(case, 3):
                return False
            s = Scheme(case['scheme'])
            ab, bc, ac = (compare(case[a], case[b], s) for a, b in [('a', 'b'), ('b', 'c'), ('a', 'c')])
            if ab is not None and bc is not None:
                if ab <= 0 and bc <= 0:
                    equal(ac is not None and ac <= 0, True, RULES[s.value], 'nondecreasing triple must be transitive')
                if ab >= 0 and bc >= 0:
                    equal(ac is not None and ac >= 0, True, RULES[s.value], 'nonincreasing triple must be transitive')
        self.schemes('transitive', lambda r, i, s: version_case(r, s, 3), check)

    def test_compare_never_raises_unicode(self):
        def check(case):
            if not version_domain(case):
                return False
            result = compare(case['a'], case['b'], Scheme(case['scheme']))
            equal(result in (None, -1, 0, 1), True, UNKNOWN, 'comparison result must be three-valued precedence')
        self.schemes('unicode_never_raises', lambda r, i, s: {
            'scheme': s, 'a': unicode_text(r), 'b': unicode_text(r)}, check)

    def test_unparseable_is_unknown(self):
        def generate(rng, index, scheme):
            bad = rng.choice(['', ' ', '*', 'latest', '1..0', 'α', '1_0', unicode_text(rng)])
            if reference_compare(bad, bad, scheme) == 0:
                bad += '\x00'
            if scheme == 'opaque':
                # Every string is an opaque version. Only unequal ordering is
                # undecidable; there is no fabricated invalid opaque grammar.
                bad = version(rng, scheme) + '-other'
            return {'scheme': scheme, 'a': bad, 'b': version(rng, scheme)}

        def check(case):
            if not version_domain(case):
                return False
            scheme, a, b = case['scheme'], case['a'], case['b']
            if scheme == 'opaque':
                if a == b:
                    return False
            elif reference_compare(a, a, scheme) is not None:
                return False
            for left, right in [(a, b), (b, a)] + ([] if scheme == 'opaque' else [(a, a)]):
                equal(compare(left, right, Scheme(scheme)), None, RULES[scheme], 'unparseable/undecidable ordering must not be guessed')
        self.schemes('unparseable_unknown', generate, check)

    def test_dotted_padding_never_proves_equality(self):
        def generate(rng, index):
            segments = [str(rng.randrange(10)) for _ in range(rng.randrange(1, 6))]
            a = '.'.join(segments)
            b = a + '.' + '.'.join('0' if index % 2 else str(rng.randrange(10))
                                    for _ in range(rng.randrange(1, 5)))
            return {'scheme': 'dotted', 'a': a, 'b': b}

        def check(case):
            if not version_domain(case) or case['scheme'] != 'dotted':
                return False
            a, b = case['a'], case['b']
            if any(reference_compare(v, v, 'dotted') != 0 for v in (a, b)) or len(a.split('.')) == len(b.split('.')):
                return False
            expected = reference_compare(a, b, 'dotted')
            equal(compare(a, b, Scheme.DOTTED), expected, DOTTED, 'unequal segment counts must not compare equal through padding')
        run_property(self, 'versions.dotted_padding', generate, check, DOTTED)

    def test_debian_matches_policy_reference(self):
        def generate(rng, index):
            # Shared upstream/epoch forces revision and non-digit-run coverage.
            a = version(rng, 'debian')
            if index % 3 == 0:
                b = a + rng.choice(['~', '~rc1', 'a', '+', '.1', '0', '-1'])
            else:
                b = version(rng, 'debian')
            return {'scheme': 'debian', 'a': a, 'b': b}

        def check(case):
            if not version_domain(case) or case['scheme'] != 'debian':
                return False
            equal(compare(case['a'], case['b'], Scheme.DEBIAN), debian_reference(case['a'], case['b']),
                  DEBIAN, 'Debian order differs from independent Policy algorithm')
        run_property(self, 'versions.debian_policy', generate, check, DEBIAN)

    def test_satisfies_single_comparator_agrees(self):
        def generate(rng, index, scheme):
            return dict(version_case(rng, scheme, arbitrary=True), op=rng.choice(OPS))

        def check(case):
            if not version_domain(case) or case.get('op') not in OPS:
                return False
            scheme, op = case['scheme'], case['op']
            relation = compare(case['a'], case['b'], Scheme(scheme))
            expected = None
            if relation is not None and not (scheme == 'opaque' and op != '='):
                expected = {'=': relation == 0, '>=': relation >= 0, '>': relation > 0,
                            '<=': relation <= 0, '<': relation < 0}[op]
            equal(satisfies(case['a'], ((op, case['b']),), Scheme(scheme)), expected,
                  UNKNOWN, 'single comparator disagrees with compare')
        self.schemes('satisfies_single', generate, check)

    def test_parse_constraint_round_trip(self):
        def generate(rng, index):
            scheme = tuple(RULES)[index % 4]
            terms = [[rng.choice(OPS), version(rng, scheme).replace(' ', '-')]
                     for _ in range(rng.randrange(1, 6))]
            return {'terms': terms, 'space': rng.choice(['', ' ', '\t', '\n'])}

        def check(case):
            if not isinstance(case, dict) or not isinstance(case.get('terms'), list) or not case['terms']:
                return False
            if not all(isinstance(t, list) and len(t) == 2 and t[0] in OPS and isinstance(t[1], str)
                       and re.fullmatch(r'[^\s,=<>!|]+', t[1]) for t in case['terms']):
                return False
            space = case.get('space', '')
            if not isinstance(space, str) or space.strip():
                return False
            terms = tuple(tuple(t) for t in case['terms'])
            text = space + (',' + space).join(op + space + bound for op, bound in terms) + space
            parsed = parse_constraint(text)
            equal(parsed, terms, 'docs/spec.md:101 (comma-separated explicit comparators)', 'parse must preserve every operator and bound')
            equal(parse_constraint(', '.join(op + bound for op, bound in parsed)), terms,
                  'docs/spec.md:101', 'canonical serialisation must round-trip')
        run_property(self, 'versions.constraint_round_trip', generate, check, 'docs/spec.md:101')


class ApplicabilityFuzzTests(unittest.TestCase):
    def test_resolve_never_raises(self):
        def generate(rng, index):
            if index == 0:
                # Valid SemVer can exceed Python's decimal-string int limit.
                # It is CNA data, not an invalid watch or a malformed range.
                huge = '1.0.' + '9' * 5000
                return {'scheme': 'semver', 'version': '>=1.0.0, <2.0.0',
                        'record': record([entry([{'version': huge, 'status': 'unaffected'}])])}
            return generated_application(rng, index, corrupt=True, ranges=index % 5 == 0)

        def check(case):
            if not application_domain(case):
                return False
            state = resolved_state(case)
            equal(state in (None, 'affected', 'not_affected', 'unknown'), True, UNKNOWN,
                  'malformed CNA/KEV data must resolve conservatively')
        run_property(self, 'applicability.never_raises', generate, check, UNKNOWN)

    def test_needed_undecidable_comparison(self):
        def generate(rng, index):
            scheme = tuple(RULES)[index % 4]
            watched = lattice_version(3, scheme) if scheme != 'opaque' else 'build-a'
            range_watch = (index // 4) % 2 == 0 and scheme != 'opaque'
            if range_watch:
                watched = '>= ' + lattice_version(2, scheme) + ', < ' + lattice_version(4, scheme)
            lower = lattice_version(1, scheme) if scheme != 'opaque' else 'build-a'
            upper = lattice_version(5, scheme) if scheme != 'opaque' else 'build-z'
            bad = rng.choice(['invalid', '١', '?', '1..2'])
            if scheme != 'opaque' and reference_compare(bad, bad, scheme) is not None:
                # Repeated dots are legal Debian upstream text, so they do not
                # exercise an undecidable Debian comparison.
                bad = '?'
            row = {'version': lower, 'lessThan': upper, 'status': rng.choice(STATUSES)}
            location = index % 5
            if location == 0:
                row['version'] = bad
            elif location == 1:
                row['lessThan'] = bad
            elif location == 2:
                row['changes'] = [{'at': bad, 'status': rng.choice(STATUSES)}]
            elif location == 3:
                row['versionType'] = 'rpm'
            elif scheme == 'dotted' and not range_watch:
                row = {'version': '3.0', 'status': 'affected'}
            elif scheme == 'opaque':
                row['changes'] = [{'at': 'build-z', 'status': 'affected'}]
            else:
                row['version'] = bad
            items = [entry([row], rng.choice(STATUSES))]
            second = rng.choice([None, 'affected', 'unaffected', 'unknown'])
            if second is not None:
                certain = {'version': watched, 'status': second}
                if range_watch:
                    certain = {'version': lower, 'lessThan': upper, 'status': second}
                items.append(entry([certain]))
            rng.shuffle(items)
            return {'scheme': scheme, 'version': watched, 'record': record(items),
                    'kev': kev(rng) if rng.randrange(2) else None}

        def check(case):
            if not application_domain(case):
                return False
            expected = oracle(case, range_watch=case['version'].strip().startswith(('=', '>', '<')))
            if expected is ABSTAIN or expected is None:
                return False
            equal(resolved_state(case), expected, UNKNOWN + '; ' + AGGREGATION,
                  'needed undecidable comparison must stay unknown unless another entry decides')
        run_property(self, 'applicability.needed_undecidable', generate, check, UNKNOWN)

    def test_spec_oracle_points(self):
        run_property(self, 'applicability.spec_oracle_points', generated_application,
                     check_oracle, 'docs/spec.md:99,101,115-128')

    def test_spec_oracle_ranges(self):
        run_property(self, 'applicability.spec_oracle_ranges',
                     lambda rng, index: generated_application(rng, index, ranges=True),
                     lambda case: check_oracle(case, range_watch=True),
                     'docs/spec.md:101,115-128')

    def test_constraint_string_oracle_points(self):
        run_property(self, 'applicability.constraint_string_points', generated_constraint_application,
                     check_oracle, 'docs/spec.md §5 (CNA comparator strings)')

    def test_constraint_string_oracle_ranges(self):
        run_property(self, 'applicability.constraint_string_ranges',
                     lambda rng, index: generated_constraint_application(rng, index, ranges=True),
                     lambda case: check_oracle(case, range_watch=True),
                     'docs/spec.md §5 (CNA comparator strings)')

    def test_kev_never_overrides_cna_not_affected(self):
        def generate(rng, index):
            scheme = tuple(RULES)[index % 4]
            watched = version(rng, scheme)
            item = entry([{'version': watched, 'status': 'unaffected', 'versionType': scheme}],
                         rng.choice(STATUSES), decorated(rng, 'example corp'), decorated(rng, 'test-service'))
            return {'scheme': scheme, 'version': watched, 'record': record([item]), 'kev': kev(rng)}

        def check(case):
            if not application_domain(case) or oracle(case) != 'not_affected':
                return False
            baseline = resolved_state(dict(case, kev=None))
            enriched = resolved_state(case)
            equal([baseline, enriched], ['not_affected', 'not_affected'], 'docs/spec.md:125-126',
                  'KEV cannot flip an authoritative CNA not-affected result')
        run_property(self, 'applicability.kev_cna_not_affected', generate, check, 'docs/spec.md:125-126')

    def test_rejected_nonmatching_identity_returns_none(self):
        def generate(rng, index):
            case = generated_application(rng, index)
            case['record']['cveMetadata']['state'] = rng.choice(['REJECTED', 'WITHDRAWN', 'rejected'])
            for item in case['record']['containers']['cna']['affected']:
                item['vendor'] = decorated(rng, 'unrelated vendor')
                item['product'] = decorated(rng, 'unrelated-product')
            case['kev'] = None
            if rng.randrange(2):
                case['kev'] = {'cveID': 'CVE-2026-1000', 'vendorProject': 'unrelated vendor',
                               'product': 'unrelated-product'}
            return case

        def check(case):
            if not application_domain(case):
                return False
            rec = case['record']
            if (not isinstance(rec, dict) or not isinstance(rec.get('cveMetadata'), dict)
                    or rec['cveMetadata'].get('state', '').upper() not in ('REJECTED', 'WITHDRAWN')
                    or oracle(case) is not None):
                return False
            equal(resolved_state(case), None, 'docs/spec.md:85-86,128 (identity-scoped rejection)',
                  'rejection must not create an unrelated identity match')
        run_property(self, 'applicability.rejected_nonmatching', generate, check, 'docs/spec.md:85-86,128')

    def test_opaque_mismatches_never_not_affected(self):
        def generate(rng, index):
            watched = version(rng, 'opaque')
            rows = [{'version': watched + '-other-' + str(n), 'status': rng.choice(STATUSES)}
                    for n in range(rng.randrange(1, 5))]
            return {'scheme': 'opaque', 'version': watched,
                    'record': record([entry(rows, rng.choice(STATUSES))]),
                    'kev': kev(rng) if rng.randrange(2) else None}

        def check(case):
            if not application_domain(case) or case['scheme'] != 'opaque':
                return False
            rec = case['record']
            if not isinstance(rec, dict) or not isinstance(rec.get('containers'), dict):
                return False
            cna = rec['containers'].get('cna')
            if not isinstance(cna, dict) or not isinstance(cna.get('affected'), list):
                return False
            items = cna['affected']
            if (not items or oracle(dict(case, version=case['version'])) is None
                    or any(not isinstance(item, dict) or not isinstance(item.get('versions'), list)
                           for item in items)):
                return False
            for item in items:
                for row in item['versions']:
                    if (not isinstance(row, dict) or not isinstance(row.get('version'), str)
                            or row['version'] == case['version'].strip() or row['version'] == '*'):
                        return False
            equal(resolved_state(case) == 'not_affected', False,
                  OPAQUE,
                  'opaque mismatch alone cannot prove safety')
        run_property(self, 'applicability.opaque_mismatch_safety', generate, check, OPAQUE)


if __name__ == '__main__':
    unittest.main()

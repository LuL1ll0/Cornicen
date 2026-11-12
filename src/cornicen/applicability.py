"""Local CNA version applicability with conservative, three-valued results."""

from dataclasses import dataclass
from enum import Enum
from functools import cmp_to_key
import re

from cornicen.identity import AliasMap, is_placeholder, normalise
from cornicen.versions import Scheme, compare, parse_constraint, python_successor
from cornicen.watchlist import Watch


# Bump by hand whenever applicability, version comparison or identity matching changes.
MATCHING_REVISION = 1


class State(str, Enum):
    AFFECTED = 'affected'
    NOT_AFFECTED = 'not_affected'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class Result:
    state: State
    exploited: bool
    evidence: str
    confidence: str


class _Undecidable(Exception):
    pass


def _compare(a, b, scheme):
    if scheme == Scheme.OPAQUE:
        a, b = normalise(a), normalise(b)
    result = compare(a, b, scheme)
    if result is None:
        raise _Undecidable('version comparison unknown')
    return result


def _state(status):
    return {'affected': State.AFFECTED, 'unaffected': State.NOT_AFFECTED}.get(
        status, State.UNKNOWN)


def _combine(states):
    for state in (State.AFFECTED, State.NOT_AFFECTED):
        if state in states:
            return state
    return State.UNKNOWN


def watch_identities(watch, aliases):
    """Compile invariant watch identities once per watch/alias revision."""
    expanded = frozenset(identity for candidate in watch.match for identity in aliases.expand(candidate))
    return expanded, frozenset(map(normalise, watch.product_only))


def _identity_match(vendor, product, watch, aliases, prepared=None, identities=None):
    if not isinstance(vendor, str) or not isinstance(product, str):
        return None
    key = vendor, product
    cached = identities.get(key) if identities is not None else None
    if cached is None:
        if is_placeholder(product):
            return None
        identity = normalise(vendor), normalise(product)
        # Placeholder vendors expand to no scoped identities; a real product
        # can still match the explicitly opted-in loose names below.
        expanded = aliases.expand(identity)
        if identities is not None:
            identities[key] = identity, expanded
    else:
        identity, expanded = cached
    exact, products = prepared if prepared is not None else watch_identities(watch, aliases)
    if expanded & exact:
        return 'exact'
    if identity[1] in products:
        return 'product_only'
    return None


def _check_types(entry, scheme):
    if 'defaultStatus' in entry and not isinstance(entry['defaultStatus'], str):
        raise _Undecidable('invalid defaultStatus')
    versions = entry.get('versions', [])
    if not isinstance(versions, list):
        raise _Undecidable('invalid versions')
    for version in versions:
        if not isinstance(version, dict):
            raise _Undecidable('invalid version entry')
        for field in ('version', 'lessThan', 'lessThanOrEqual', 'status', 'versionType'):
            if field in version and not isinstance(version[field], str):
                raise _Undecidable(f'invalid {field}')
        if 'version' not in version:
            raise _Undecidable('missing version')
        changes = version.get('changes', [])
        if not isinstance(changes, list):
            raise _Undecidable('invalid changes')
        for change in changes:
            if not isinstance(change, dict):
                raise _Undecidable('invalid change entry')
            if not isinstance(change.get('at'), str):
                raise _Undecidable('invalid change boundary')
            if not isinstance(change.get('status'), str):
                raise _Undecidable('invalid change status')
        version_type = version.get('versionType')
        # CNAs also use semver/python loosely. The watch chooses the comparator;
        # accepting a label never makes an unorderable boundary decidable.
        if version_type not in (None, 'custom', 'semver', 'python', scheme.value):
            raise _Undecidable(f'versionType {version_type} conflicts with {scheme.value}')


def _constraints(version):
    if 'lessThan' in version or 'lessThanOrEqual' in version:
        return None
    try:
        return parse_constraint(version['version'])
    except ValueError:
        return None


def _default_state(entry):
    versions = entry.get('versions', [])
    # CNA comparator-only affected lists describe their complete affected set.
    # Other lists require explicit history evidence before inferring exclusion.
    if ('defaultStatus' not in entry and versions
            and all(row.get('status') == 'affected' and _constraints(row)
                    for row in versions)):
        return State.NOT_AFFECTED
    if _history_exclusion(entry):
        return State.NOT_AFFECTED
    return _state(entry.get('defaultStatus'))


def _unbounded_start(version):
    return (('lessThan' in version or 'lessThanOrEqual' in version)
            and version.get('version') in ('0', '0.0', '0.0.0', '*'))


def _range_start(version):
    lower = version['version']
    upper = version.get('lessThan', version.get('lessThanOrEqual'))
    if (upper is not None and '*' not in upper
            and re.fullmatch(r'\d+(\.\d+)*\.\*', lower)
            and upper.startswith(lower[:-2] + '.')):
        # Explicit zero avoids dotted's undecidable padded equality. Semver
        # and Python need three components; unsupported forms still fail in
        # the comparator, including numeric prefixes that are too long.
        parts = lower[:-2].split('.') + ['0']
        lower = '.'.join(parts + ['0'] * max(0, 3 - len(parts)))
    return lower


def _line_floor(lower, scheme):
    prefix = lower[:-2]
    if scheme in (Scheme.SEMVER, Scheme.PYTHON):
        parts = prefix.split('.')
        base = '.'.join(parts + ['0'] * max(0, 3 - len(parts)))
        return base + ('-0' if scheme == Scheme.SEMVER else 'a0')
    if scheme == Scheme.DEBIAN:
        return prefix + '~'
    if scheme == Scheme.DOTTED:
        return prefix
    raise _Undecidable('wildcard line comparison unknown')


def _history_exclusion(entry):
    if entry.get('defaultStatus', 'unknown') != 'unknown':
        return False
    for row in entry.get('versions', []):
        if row.get('status') != 'affected':
            continue
        if _unbounded_start(row):
            return True
        terms = _constraints(row)
        if (terms and any(op in ('<', '<=') for op, _ in terms)
                and all(op in ('<', '<=') or (
                    op == '>=' and bound in ('0', '0.0', '0.0.0'))
                        for op, bound in terms)):
            return True
    return False


def _at(entry, relation, scheme, inferred=None):
    """Evaluate a point, or a whole open cell with no CNA boundary inside it."""
    states = []
    for version in entry.get('versions', []):
        lower = version.get('version')
        if not isinstance(lower, str):
            raise _Undecidable('missing version')
        upper = version.get('lessThan', version.get('lessThanOrEqual'))
        constraints = _constraints(version)
        if constraints is not None:
            if scheme == Scheme.OPAQUE and any(op != '=' for op, _ in constraints):
                raise _Undecidable('opaque range comparison unknown')
            try:
                # Evaluate every bound: an invalid bound must not prove safety.
                relations = [(op, relation(bound)) for op, bound in constraints]
                inside = all({'=': value == 0, '>': value > 0, '>=': value >= 0,
                              '<': value < 0, '<=': value <= 0}[op]
                             for op, value in relations)
            except _Undecidable:
                if scheme != Scheme.OPAQUE:
                    raise
                inside = False
        elif upper is None:
            if scheme == Scheme.OPAQUE:
                # A mismatch cannot prove an opaque version safe.
                try:
                    inside = lower == '*' or relation(lower) == 0
                except _Undecidable:
                    inside = False
            else:
                inside = lower == '*' or relation(lower) == 0
        else:
            if scheme == Scheme.OPAQUE:
                raise _Undecidable('opaque range comparison unknown')
            start = _range_start(version)
            low = 1 if _unbounded_start(version) else relation(start)
            if low < 0 and start != lower:
                # Only a comparator-proven earlier line can be excluded by
                # the manufactured start. Unknown floor comparisons raise
                # before defaults or history can infer exclusion.
                if relation(_line_floor(lower, scheme)) >= 0:
                    raise _Undecidable('wildcard line below its first release')
            high = -1 if upper == '*' else relation(upper)
            inside = low >= 0 and (high < 0 or (
                high == 0 and 'lessThanOrEqual' in version))
        if not inside:
            continue
        if scheme == Scheme.OPAQUE and version.get('changes'):
            raise _Undecidable('opaque status changes require ordering')
        status = version.get('status')
        # Find the latest applicable transition, independently of array order.
        latest = None
        for change in version.get('changes', []):
            at = change.get('at')
            if not isinstance(at, str):
                raise _Undecidable('missing change boundary')
            if relation(at) >= 0:
                if latest is None or _compare(at, latest['at'], scheme) >= 0:
                    latest = change
        if latest is not None:
            status = latest.get('status')
        states.append(_state(status))
    if states:
        return _combine(states)
    if (scheme != Scheme.OPAQUE and entry.get('defaultStatus') == 'affected'
            and any(row.get('status') == 'affected' and (
                'lessThan' in row or 'lessThanOrEqual' in row
                or any(op != '=' for op, _ in (_constraints(row) or [])))
                    for row in entry.get('versions', []))):
        # All rows missed. Transitions outside the watch must also be decidable.
        for row in entry.get('versions', []):
            for change in row.get('changes', []):
                relation(change['at'])
        if inferred is not None:
            inferred.setdefault('outside', set()).add(
                "outside every range the CNA listed; the CNA's default says affected")
        return State.UNKNOWN
    if scheme != Scheme.OPAQUE and _history_exclusion(entry):
        # Exclusion needs every row decidable, including transitions in rows
        # outside the watch. An invalid transition must not prove safety.
        for row in entry.get('versions', []):
            if row.get('status') not in ('affected', 'unaffected', 'unknown'):
                raise _Undecidable('invalid status')
            for change in row.get('changes', []):
                relation(change['at'])
                if change['status'] not in ('affected', 'unaffected', 'unknown'):
                    raise _Undecidable('invalid change status')
        if inferred is not None:
            inferred.setdefault('history', set()).add('outside every affected range the CNA listed')
    default = _default_state(entry)
    if scheme == Scheme.OPAQUE and default != State.AFFECTED:
        return State.UNKNOWN
    return default


def _boundaries(entry):
    for version in entry.get('versions', []):
        constraints = _constraints(version)
        if constraints is not None:
            yield from (bound for _, bound in constraints)
        else:
            for key in ('version', 'lessThan', 'lessThanOrEqual'):
                if key == 'version' and _unbounded_start(version):
                    continue
                if key in version and version[key] != '*':
                    # Raw wildcard boundaries keep comparator watches unknown.
                    yield version[key]
        for change in version.get('changes', []):
            yield change.get('at')


def _semver_successor(version):
    """SemVer has adjacent values: rc.1 and rc.1.0 have no value between."""
    version = version.removeprefix('v').removeprefix('V').split('+', 1)[0]
    if '-' in version:
        return version + '.0'
    major, minor, patch = version.split('.')
    # Increment decimal text directly: valid patches can exceed int's digit limit.
    prefix = patch.rstrip('9')
    successor = (prefix[:-1] + chr(ord(prefix[-1]) + 1) if prefix else '1')
    successor += '0' * (len(patch) - len(prefix))
    return f'{major}.{minor}.{successor}-0'


def _cell_exists(position, bounds, scheme):
    if position % 2 == 0:
        return True
    index = (position + 1) // 2
    if scheme == Scheme.SEMVER:
        if index == 0:
            return _compare('0.0.0-0', bounds[0], scheme) < 0
        if index == len(bounds):
            return True
        return _compare(_semver_successor(bounds[index - 1]), bounds[index], scheme) < 0
    if scheme == Scheme.PYTHON:
        if index == 0:
            return _compare('0.0.0a0', bounds[0], scheme) < 0
        if index == len(bounds):
            return True
        successor = python_successor(bounds[index - 1])
        if successor is None:
            raise _Undecidable('version comparison unknown')
        return _compare(successor, bounds[index], scheme) < 0
    if scheme == Scheme.DOTTED and index == 0:
        # Numeric dotted versions have no negative versions.
        return _compare('0', bounds[0], scheme) < 0
    return True


def _range(entry, constraints, scheme, inferred=None):
    if scheme == Scheme.OPAQUE:
        if any(op != '=' for op, _ in constraints):
            raise _Undecidable('opaque range comparison unknown')
        # Equality constraints still permit exact opaque versions.
        first = constraints[0][1]
        for _, bound in constraints:
            _compare(first, bound, scheme)
        return _at(entry, lambda b: _compare(first, b, scheme), scheme, inferred)

    bounds = set(_boundaries(entry)) | {b for _, b in constraints}
    if any(not isinstance(bound, str) for bound in bounds):
        raise _Undecidable('invalid boundary')
    # Check every pair: dotted equality via zero padding is deliberately unknown.
    ranks = {}
    ordered = sorted(bounds, key=cmp_to_key(lambda a, b: _compare(a, b, scheme)))
    unique = []
    for index, bound in enumerate(ordered):
        for other in ordered[index:]:
            _compare(bound, other, scheme)
        if not unique or _compare(unique[-1], bound, scheme) != 0:
            unique.append(bound)
        ranks[bound] = 2 * (len(unique) - 1)

    states = []
    # Even positions are endpoints; odd positions are the intervening open cells.
    # Status is constant in each cell, so this proves coverage without sampling.
    for position in range(-1, 2 * len(unique)):
        allowed = True
        for op, bound in constraints:
            relation = (position > ranks[bound]) - (position < ranks[bound])
            allowed &= {'=': relation == 0, '>': relation > 0, '>=': relation >= 0,
                        '<': relation < 0, '<=': relation <= 0}[op]
        if allowed and _cell_exists(position, unique, scheme):
            states.append(_at(entry, lambda b: (position > ranks[b]) - (position < ranks[b]),
                              scheme, inferred))
    if State.AFFECTED in states:
        return State.AFFECTED
    if states and all(state == State.NOT_AFFECTED for state in states):
        return State.NOT_AFFECTED
    return State.UNKNOWN


def _evaluate(entry, watch):
    try:
        _check_types(entry, watch.scheme)
        version = watch.version.strip()
        inferred = {}
        if version.startswith(('=', '>', '<')) or ',' in version:
            state = _range(entry, parse_constraint(version), watch.scheme, inferred)
        else:
            state = _at(entry, lambda b: _compare(version, b, watch.scheme), watch.scheme,
                        inferred)
        descriptions = []
        for row in entry.get('versions', []):
            text = row.get('version', '?')
            if 'lessThan' in row:
                text += ' <= version < ' + row['lessThan']
            elif 'lessThanOrEqual' in row:
                text += ' <= version <= ' + row['lessThanOrEqual']
            if row.get('changes'):
                text += ' (status changes)'
            descriptions.append(text)
        detail = '; '.join(descriptions) or 'defaultStatus ' + entry.get('defaultStatus', 'unknown')
        if inferred and (state == State.NOT_AFFECTED or 'outside' in inferred):
            detail = '; '.join(sorted(set().union(*inferred.values()))) + '; ' + detail
        types = sorted({row['versionType'] for row in entry.get('versions', [])
                        if row.get('versionType')})
        if types:
            detail += '; versionType ' + ', '.join(types)
        if len(detail) > 180:
            detail = detail[:177] + '...'
        # An inferred exclusion cannot settle another entry's uncertainty. An
        # explicit unaffected default still excludes these unlisted versions.
        weak = ('history' in inferred
                and entry.get('defaultStatus') != 'unaffected')
        return state, detail, weak
    except _Undecidable as error:
        return State.UNKNOWN, str(error), False


def rejected(record: dict) -> bool:
    """Signal rejection independently of identity for the engine's stored pairs."""
    metadata = record.get('cveMetadata') if isinstance(record, dict) else None
    state = metadata.get('state') if isinstance(metadata, dict) else None
    return isinstance(state, str) and state.upper() == 'REJECTED'


def resolve(record: dict, kev_entry: dict | None, watch: Watch,
            aliases: AliasMap, prepared=None, identities=None) -> Result | None:
    if not isinstance(record, dict):
        return None
    metadata = record.get('cveMetadata', {})
    valid_metadata = (isinstance(metadata, dict)
                      and isinstance(metadata.get('state', ''), str))
    record_id = metadata.get('cveId') if isinstance(metadata, dict) else None
    kev_id = kev_entry.get('cveID') if isinstance(kev_entry, dict) else None
    if not (isinstance(record_id, str) and record_id.strip()
            and isinstance(kev_id, str) and kev_id.strip()
            and record_id.casefold() == kev_id.casefold()
            and all(isinstance(kev_entry.get(field, ''), str)
                    for field in ('vendorProject', 'product'))):
        kev_entry = None
    containers = record.get('containers', {})
    cna = containers.get('cna', {}) if isinstance(containers, dict) else None
    entries = cna.get('affected', []) if isinstance(cna, dict) else None
    if not isinstance(entries, list):
        entries = []
    matches = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = _identity_match(entry.get('vendor', ''), entry.get('product', ''), watch, aliases,
                               prepared, identities)
        if kind:
            matches.append((entry, kind))
    kev_kind = None
    if kev_entry is not None:
        kev_kind = _identity_match(kev_entry.get('vendorProject', ''),
                                   kev_entry.get('product', ''), watch, aliases, prepared, identities)

    if not matches and not kev_kind:
        return None

    if not valid_metadata:
        return Result(State.UNKNOWN, kev_entry is not None, 'Invalid CNA record metadata', 'medium')
    if rejected(record) or metadata.get('state', '').upper() == 'WITHDRAWN':
        return Result(State.NOT_AFFECTED, kev_entry is not None, 'CNA record rejected or withdrawn',
                      'high')
    exact = [entry for entry, kind in matches if kind == 'exact']
    if exact:
        evaluated = [(entry, *_evaluate(entry, watch)) for entry in exact]
        # Keep explicit exclusions' existing precedence, but let uncertainty
        # win over another entry's history inference.
        decisive = [item for item in evaluated
                    if item[1] != State.NOT_AFFECTED or not item[3]]
        state = _combine([item[1] for item in decisive]) if decisive else State.NOT_AFFECTED
        entry, _, detail, _ = next(item for item in (decisive or evaluated) if item[1] == state)
        label = 'unaffected' if state == State.NOT_AFFECTED else state.value
        evidence = f'CNA {label} {normalise(entry["product"])}: {detail}'
        return Result(state, kev_entry is not None, evidence,
                      'medium' if state == State.UNKNOWN else 'high')
    if matches or kev_kind == 'product_only':
        return Result(State.UNKNOWN, kev_entry is not None,
                      'Product-only identity match; version applicability unknown', 'low')
    return Result(State.UNKNOWN, True, 'KEV identity match; CNA version applicability unknown',
                  'medium')

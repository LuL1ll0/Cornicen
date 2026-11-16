# script-purpose: Store and aggregate scoped advisory applicability and fix evidence.
# script-class: pipeline-tool
# script-trigger: Adapter commits and engine evaluation.
# script-tests: tests/test_f3a.py, tests/test_f3b.py, tests/test_r11_differential.py, tests/test_r11_shells.py, tests/test_r11_integration.py, tests/test_task1_b1.py, tests/test_task2_a.py
"""Read validated advisories and SQLite evidence; write scoped evidence rows.

Library API, no command entry point or exit codes. No network access.
"""
import json
import re

from cornicen.versions import compare

from cornicen import applicability, cnascope
from cornicen.applicability import State, Result


def retracted(data):
    """An explicit withdrawal or administrative retraction retires evidence."""
    return bool(data.get('withdrawn') or data.get('retraction') == 'administrative')


def aggregate(states):
    states = tuple(states)
    if State.AFFECTED in states:
        return State.AFFECTED
    if State.UNKNOWN in states or not states:
        return State.UNKNOWN
    return State.NOT_AFFECTED


def parent_id(data):
    return f"advisory:{data['source']}:{data['source_id']}:{data.get('_facet', 'main')}"


def facet_records(data):
    """Expand normalized facets without borrowing a sibling's evidence."""
    if not data.get('facets'):
        return [data]
    records = []
    for facet in data['facets']:
        names = {p['name'] if isinstance(p, dict) else p for p in facet.get('products', [])}
        products = [p for p in data['products'] if p['name'] in names]
        product_ids = {p['id'] for p in products}
        cves = facet.get('cves', [facet['cve']] if facet.get('cve') else [])
        records.append(dict(data, facets=[], _facet=str(facet['number']),
            title=facet.get('title') or data['title'], products=products,
            cves=[dict(value=c, field_path='facets.cve') for c in cves],
            evidence=facet.get('evidence', [e for e in data['evidence'] if e['product_id'] in product_ids]),
            associations=facet.get('associations', [])))
    return records


def identities(data):
    if data.get('facets'):
        return sorted({i for f in facet_records(data) for i in identities(f)})
    cves = [c['value'] for c in data['cves']]
    associated = {a['cve'] for a in data.get('associations', [])}
    if len(cves) == 1:
        return cves
    return cves + ([] if cves and associated == set(cves) else [parent_id(data)])


def write_evidence(db, data, baseline=False, *, append=False):
    """Replace only this source record's rows, atomically with its revision."""
    had_parent = False
    if not append:
        db.execute('INSERT OR IGNORE INTO advisory_support SELECT DISTINCT source,source_id,identity FROM advisory_evidence WHERE source=? AND source_id=?',
                   (data['source'], data['source_id']))
        had_parent = db.execute('SELECT 1 FROM advisory_evidence WHERE source=? AND source_id=? AND identity=?',
                                (data['source'], data['source_id'], parent_id(data))).fetchone()
        db.execute('DELETE FROM advisory_evidence WHERE source=? AND source_id=?',
                   (data['source'], data['source_id']))
        current = set(identities(data))
        if had_parent and len(data['cves']) > 1:
            current.add(parent_id(data))
        # Withdrawal retains prior identities as explicit retraction history.
        for row in db.execute('SELECT identity FROM advisory_support WHERE source=? AND source_id=?',
                              (data['source'], data['source_id'])).fetchall():
            if not retracted(data) and row[0] not in current:
                db.execute('DELETE FROM advisory_support WHERE source=? AND source_id=? AND identity=?',
                           (data['source'], data['source_id'], row[0]))
        clear_shells(db, data)
    if retracted(data):
        return
    if data.get('facets'):
        for facet in facet_records(data):
            write_evidence(db, facet, baseline, append=True)
        return
    cves = [c['value'] for c in data['cves']]
    products = {p['id']: p for p in data['products']}
    groups = {g['id']: g['product_ids'] for g in data.get('product_groups', [])}
    associated = data.get('associations', [])
    for evidence in data['evidence']:
        product = products[evidence['product_id']]
        targets = ([cves[0]] if len(cves) == 1 else
                   [a['cve'] for a in associated if a['product_id'] == product['id']])
        if not targets:
            targets = [parent_id(data)]
        elif had_parent and len(cves) > 1:
            targets.append(parent_id(data))
        fix = evidence.get('fix') or evidence.get('first_fixed')
        for remediation in data.get('remediations', []):
            refs = remediation.get('product_ids', []) + [
                p for g in remediation.get('group_ids', []) for p in groups[g]]
            if remediation.get('category') == 'vendor_fix' and product['id'] in refs:
                fix = remediation.get('version') or 'available'
        provenance = dict(data['provenance'], product_id=product['id'],
                          baseline=bool(baseline), product_version=product.get('version'), evidence=evidence)
        for target in targets:
            db.execute('INSERT INTO advisory_evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       (data['source'], data['source_id'], data.get('_facet', 'main'), target,
                        evidence.get('release'), product['name'], evidence.get('platform'),
                        evidence['scheme'], json.dumps(evidence.get('range')) if 'range' in evidence else None,
                        evidence['status'], fix, json.dumps(provenance)))
    # Membership supplies unknown facets, never inherited parent ranges or fixes.
    represented = {r[0] for r in db.execute(
        'SELECT identity FROM advisory_evidence WHERE source=? AND source_id=?',
        (data['source'], data['source_id']))}
    for cve in cves:
        if cve not in represented:
            for product in products.values():
                db.execute('INSERT INTO advisory_evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (data['source'], data['source_id'], data.get('_facet', 'main'), cve, None,
                            product['name'], None, 'semver', None, 'under_investigation',
                            None, json.dumps(dict(data['provenance'], baseline=bool(baseline)))))

    db.execute('INSERT OR IGNORE INTO advisory_support SELECT DISTINCT source,source_id,identity FROM advisory_evidence WHERE source=? AND source_id=?',
               (data['source'], data['source_id']))



def clear_shells(db, data):
    """Retire provisional routing markers when a validated advisory is accepted."""
    if not retracted(data):
        db.execute('DELETE FROM advisory_shells WHERE source=? AND source_id=?',
                   (data['source'], data['source_id']))


def has_identity(db, identity):
    if db.execute('SELECT 1 FROM advisory_evidence WHERE identity=? LIMIT 1', (identity,)).fetchone():
        return True
    return bool(db.execute('SELECT 1 FROM advisory_support WHERE identity=? LIMIT 1',
                           (identity,)).fetchone() or
                db.execute('SELECT 1 FROM advisory_shells WHERE identity=?', (identity,)).fetchone())


def rows_for(db, identity):
    return db.execute('SELECT * FROM advisory_evidence WHERE identity=?', (identity,)).fetchall()


def scope_matches(row, scope, equivalents=()):
    for key in ('release', 'platform'):
        value, wanted = row[key], scope.get(key)
        if value != wanted and (value, wanted) not in equivalents and (wanted, value) not in equivalents:
            return False
    return True


def entry_for(row):
    vendor, _, product = row['package'].partition(':')
    entry = dict(vendor=vendor, product=product, defaultStatus='unknown', versions=[])
    status = dict(known_affected='affected', known_not_affected='unaffected',
                  under_investigation='unknown', first_fixed='unaffected')[row['status']]
    bounds = json.loads(row['range']) if row['range'] else None
    if bounds:
        version = dict(version=bounds.get('introduced', '0.0.0'),
                       versionType=row['scheme'], status=status)
        if 'limit' in bounds:
            version['lessThan'] = bounds['limit']
        if 'last_affected' in bounds:
            version['lessThanOrEqual'] = bounds['last_affected']
        entry['versions'] = [version]
        if status == 'affected':
            entry['defaultStatus'] = 'unaffected'
    else:
        version = json.loads(row['provenance']).get('product_version')
        if version is not None:
            entry['versions'] = [dict(version=version, versionType=row['scheme'], status=status)]
        else:
            entry['defaultStatus'] = status
    return entry


def _selector_matches(row, watch):
    name = row['package'].removeprefix('github-selector:')
    return any(name == f'{s.repository}#{s.ecosystem}#{s.package}' for s in watch.github)


def _github_entry(row, watch):
    bounds = json.loads(row['range']) if row['range'] else {}
    text = bounds.get('github') if isinstance(bounds, dict) else None
    if not isinstance(text, str) or not text:
        return None
    versions = []
    for alternative in text.split('||'):
        terms = []
        for term in alternative.split(','):
            match = re.fullmatch(r'\s*(<=|>=|<|>|=)\s*([^,|]+?)\s*', term)
            if not match:
                return None
            op, bound = match.groups()
            if (not bound or (op != '=' and any(c.isspace() for c in bound))
                    or compare(bound, bound, watch.scheme) is None):
                return None
            terms.append((op, bound))
        ops = [op for op, _ in terms]
        if (len(terms) > 2 or ('=' in ops and len(terms) != 1)
                or sum(op in ('>', '>=') for op in ops) > 1
                or sum(op in ('<', '<=') for op in ops) > 1):
            return None
        if watch.scheme.value == 'opaque' and ops != ['=']:
            return None
        version = terms[0][1] if ops == ['='] else ', '.join(f'{op} {b}' for op, b in terms)
        versions.append(dict(version=version, status='affected', versionType=watch.scheme.value))
    return dict(defaultStatus='unaffected', versions=versions)


ABSTAIN = object()
CSAF_SOURCES = frozenset({'msrc', 'cisco'})


def _watch_bound(row):
    if row['source'] not in CSAF_SOURCES:
        return False
    evidence = json.loads(row['provenance']).get('evidence')
    return isinstance(evidence, dict) and evidence.get('binding') == 'watch'


def _watch_bound_vote(row, watch, aliases):
    if row['package'].startswith('csaf-unresolved:'):
        return None
    vendor, _, product = row['package'].partition(':')
    kind = applicability._identity_match(vendor, product, watch, aliases)
    if not kind:
        return None
    version = watch.version.strip()
    if kind == 'product_only' or version.startswith(('=', '>', '<')) or ',' in version:
        return State.UNKNOWN
    status = dict(known_affected=State.AFFECTED, known_not_affected=State.NOT_AFFECTED,
                  first_fixed=State.NOT_AFFECTED, under_investigation=State.UNKNOWN)[row['status']]
    bounds = json.loads(row['range']) if row['range'] else None
    if bounds is None:
        exact = json.loads(row['provenance']).get('product_version')
        if exact is None:
            return status
        order = compare(version, exact, watch.scheme)
        return State.UNKNOWN if order is None else status if order == 0 else ABSTAIN
    text = bounds.get('csaf')
    if not isinstance(text, str) or watch.scheme.value == 'opaque':
        return State.UNKNOWN
    match = re.fullmatch(r'(?:>=\s*([^\s<>=!,|]+)\s+)?(<=|<)\s*([^\s<>=!,|]+)', text)
    if not match:
        return State.UNKNOWN
    lower, op, upper = match.groups()
    high = compare(version, upper, watch.scheme)
    low = compare(version, lower, watch.scheme) if lower is not None else 0
    span = compare(lower, upper, watch.scheme) if lower is not None else -1
    if high is None or low is None or span is None or span > 0 or (span == 0 and op == '<'):
        return State.UNKNOWN
    return status if low >= 0 and (high < 0 or high == 0 and op == '<=') else ABSTAIN


def evaluate_row(row, watch, aliases):
    if _watch_bound(row):
        return _watch_bound_vote(row, watch, aliases)
    if row['package'].startswith('github-selector:'):
        if row['source'] != 'github' or not _selector_matches(row, watch):
            return None
        if row['status'] != 'known_affected':
            return State.UNKNOWN
        entry = _github_entry(row, watch)
        if entry is None:
            return State.UNKNOWN
        return applicability._evaluate(entry, watch)[0]
    entry = entry_for(row)
    kind = applicability._identity_match(entry['vendor'], entry['product'], watch, aliases)
    if not kind:
        return None
    if kind == 'product_only' or row['scheme'] != watch.scheme.value:
        return State.UNKNOWN
    return applicability._evaluate(entry, watch)[0]


def resolve(db, identity, watch, aliases, *, record=None, kev=None, scope=None, equivalents=()):
    scope = scope or {}
    applicable = []
    for row in rows_for(db, identity):
        if scope_matches(row, scope, equivalents):
            state = evaluate_row(row, watch, aliases)
            if state is not None and state is not ABSTAIN:
                applicable.append((row['source'], state))
    cna = [v for v in cnascope.scoped_verdicts(record, watch, aliases)
           if scope_matches(dict(release=v.release, platform=v.platform), scope, equivalents)]
    # Each authoritative CNA verdict replaces adapter votes only in its own
    # scope. Preserve every vote in the explanation, including conflicts.
    states = []
    for row in rows_for(db, identity):
        if not scope_matches(row, scope, equivalents):
            continue
        state = evaluate_row(row, watch, aliases)
        if state is None or state is ABSTAIN:
            continue
        decisive = [v.state for v in cna if v.authoritative
                    and same_scope(row, v, aliases, equivalents, scheme=watch.scheme)]
        states.append(aggregate(decisive) if decisive else state)
    states.extend(v.state for v in cna)
    state = aggregate(states)
    if not states:
        support = db.execute('''SELECT a.state FROM advisory_support s JOIN advisories a
            ON a.source=s.source AND a.source_id=s.source_id WHERE s.identity=?''', (identity,)).fetchall()
        if support and all(row['state'] == 'withdrawn' for row in support):
            state = State.NOT_AFFECTED
    detail = '; '.join([f'{source}: {s.value}' for source, s in applicable]
                       + [v.evidence for v in cna]) or (
        'All supporting sources explicitly retracted' if state == State.NOT_AFFECTED
        else 'No matching scoped evidence; applicability unknown')
    confidence = ('low' if cna and all(v.confidence == 'low' for v in cna) and not applicable
                  else 'medium' if state == State.UNKNOWN else 'high')
    return Result(state, bool(kev), detail, confidence)


def same_scope(row, verdict, aliases, equivalents, *, scheme=None):
    vendor, _, product = row['package'].partition(':')
    from cornicen.identity import normalise_identity
    identity = normalise_identity(vendor), normalise_identity(product)
    expanded = aliases.expand(identity)
    package = ':'.join(min(expanded) if expanded else identity)
    effective = scheme if scheme is not None and _watch_bound(row) else row['scheme']
    return (package == verdict.package and effective == verdict.scheme
            and scope_matches(row, dict(release=verdict.release, platform=verdict.platform), equivalents))


def matching_rows(db, identity, watch, aliases, scope=None, equivalents=()):
    """Same-record membership grants eligibility, never sibling applicability."""
    rows = db.execute('''SELECT sibling.* FROM advisory_evidence sibling
        WHERE EXISTS (SELECT 1 FROM advisory_evidence member
            WHERE member.identity=? AND member.source=sibling.source
            AND member.source_id=sibling.source_id)''', (identity,)).fetchall()
    return [row for row in rows if scope_matches(row, scope or {}, equivalents)
            and evaluate_row(row, watch, aliases) is not None]


def history_key(identity, watch):
    return 'advisory_history:' + json.dumps([watch.id, identity], separators=(',', ':'))


def remember(db, identity, watch, owners):
    """Retain per-pair owners separately from current identity membership."""
    key = history_key(identity, watch)
    prior = db.execute('SELECT v FROM meta WHERE k=?', (key,)).fetchone()
    history = {tuple(owner) for owner in json.loads(prior[0])} if prior else set()
    history.update(owners)
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(sorted(history))))


def has_routing_data(db, identity):
    """One indexed emptiness probe per record; no cache to invalidate on writes."""
    return bool(db.execute("""SELECT
        EXISTS(SELECT 1 FROM advisory_evidence WHERE identity=?) OR
        EXISTS(SELECT 1 FROM advisory_support WHERE identity=?) OR
        EXISTS(SELECT 1 FROM advisory_shells WHERE identity=?) OR
        EXISTS(SELECT 1 FROM meta WHERE k GLOB 'advisory_history:*'
               AND json_extract(substr(k,18), '$[1]')=?)""",
        (identity, identity, identity, identity)).fetchone()[0])


def route(db, identity, watch, aliases, scope=None, equivalents=()):
    if matching_rows(db, identity, watch, aliases, scope, equivalents):
        return 'advisory'
    history = db.execute('SELECT 1 FROM meta WHERE k=?', (history_key(identity, watch),)).fetchone()
    if not history:
        return 'v1'
    # Shell ownership is recorded by observe_unknown_advisory via remember().
    pair = db.execute('SELECT 1 FROM pairs WHERE watch_id=? AND record_id=?',
                      (watch.id, identity)).fetchone()
    if pair:
        return 'advisory'
    return 'v1'


def fix_for(db, identity, watch, aliases, scope=None, equivalents=()):
    rows = rows_for(db, identity)
    affected = {(row['source'], row['source_id'], row['facet']) for row in rows
                if _watch_bound(row) and scope_matches(row, scope or {}, equivalents)
                and evaluate_row(row, watch, aliases) == State.AFFECTED}
    bound_fixes = set()
    for row in rows:
        if (not _watch_bound(row) or not row['fix']
                or (row['source'], row['source_id'], row['facet']) not in affected
                or not scope_matches(row, scope or {}, equivalents)
                or evaluate_row(row, watch, aliases) is None):
            continue
        if row['fix'] == 'available':
            bound_fixes.add('available')
        else:
            order = compare(row['fix'], watch.version, watch.scheme)
            if order is not None and order > 0:
                bound_fixes.add(row['fix'])
    bound_versions = sorted(bound_fixes - {'available'})
    if any(compare(left, right, watch.scheme) is None
           for i, left in enumerate(bound_versions) for right in bound_versions[i+1:]):
        return 'available'
    fixes = bound_fixes | {row['fix'] for row in rows
             if not _watch_bound(row)
             and row['fix'] and (
                 (row['package'].startswith('github-selector:')
                  and not any(c.isspace() or c in ',|' for c in row['fix'])
                  and compare(row['fix'], row['fix'], watch.scheme) is not None)
                 or (not row['package'].startswith('github-selector:')
                     and row['scheme'] == watch.scheme.value))
             and scope_matches(row, scope or {}, equivalents)
             and evaluate_row(row, watch, aliases) is not None}
    versions = sorted(fixes - {'available'})
    if versions:
        # Only return a minimum when precedence is decidable in the watch scheme.
        for candidate in versions:
            orders = [compare(candidate, other, watch.scheme) for other in versions]
            if all(order is not None and order <= 0 for order in orders):
                return candidate
        return 'available'
    return 'available' if 'available' in fixes else None


def metadata(db, identity, watch=None, aliases=None, scope=None, equivalents=()):
    owners = None
    if watch is not None:
        matching = matching_rows(db, identity, watch, aliases, scope, equivalents)
        owners = {(r['source'], r['source_id']) for r in matching}
        if not owners:
            history = db.execute('SELECT v FROM meta WHERE k=?', (history_key(identity, watch),)).fetchone()
            owners = {tuple(owner) for owner in json.loads(history[0])} if history else set()
    for row in db.execute('SELECT json FROM advisories ORDER BY source,source_id'):
        data = json.loads(row[0])
        if (identity in identities(data) or (identity == parent_id(data) and has_identity(db, identity))) and (owners is None or (data['source'], data['source_id']) in owners):
            return data
    return None


from cornicen.advisoryidentity import (canonical_id, covered, delivered_reasons, link, reconcile_facets)


def logical_latch(db, pair, *, implicit=True):
    """The stored episode latch or the engine's implicit affected/delivered latch."""
    if pair is None:
        return False
    row = db.execute('SELECT latched FROM affected_latches WHERE watch_id=? AND record_id=? AND episode=?',
                     (pair['watch_id'], pair['record_id'], pair['episode'])).fetchone()
    from cornicen.engine import Engine
    return bool((row and row[0]) or (implicit and (Engine._active(pair['state'], pair['exploited']) or pair['notified'])))



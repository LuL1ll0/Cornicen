# script-purpose: Reconcile permanent advisory facets and merge explicit identity links.
# script-class: pipeline-tool
# script-trigger: Validated advisory commits.
# script-tests: tests/test_f3b.py, tests/test_replay_v11.py, tests/test_task1_b1.py
"""Read SQLite histories and normalized facets; write atomic identity mappings.

Library functions have no process exit codes. Invalid identity changes raise ValueError.
"""
import json
import re
from datetime import datetime
from types import SimpleNamespace

from cornicen.diagnostics import FixedDiagnostic


def canonical_id(db, identity):
    row = db.execute('SELECT new_id FROM identity_redirects WHERE old_id=?', (identity,)).fetchone()
    return row[0] if row else identity


def delivered_reasons(db, watch, identity, episode):
    result = {}
    for row in db.execute('''SELECT reasons_json,body_json,sent_at FROM outbox
            WHERE sent_at IS NOT NULL AND json_extract(body_json,'$.watch_id')=?
            AND json_extract(body_json,'$.record_id')=?
            AND json_extract(body_json,'$.episode')=?''', (watch, identity, episode)):
        for reason in json.loads(row['reasons_json']):
            result[reason] = row['sent_at']
    for row in db.execute('SELECT reason,delivered_at FROM delivery_coverage WHERE watch_id=? AND canonical_id=? AND episode=?',
                          (watch, identity, episode)):
        result[row['reason']] = row['delivered_at']
    return result


def covered(db, watch, identity, reason, episode):
    identity = canonical_id(db, identity)
    # Old deliveries enter the new episode only via the persisted mapping;
    # equality of two independent episode numbers is never sufficient.
    return reason in delivered_reasons(db, watch, identity, episode) or bool(db.execute(
        '''SELECT 1 FROM delivery_coverage WHERE watch_id=? AND reason=? AND episode=?
           AND (canonical_id=? OR canonical_id IN
               (SELECT old_id FROM identity_redirects WHERE new_id=?))''',
        (watch, reason, episode, identity, identity)).fetchone())


def reconcile_facets(db, data):
    facets = data.get('facets', [])
    if not isinstance(facets, list) or any(not isinstance(f, dict) for f in facets):
        raise ValueError(FixedDiagnostic('invalid facets'))
    prior = db.execute('SELECT json FROM advisories WHERE source=? AND source_id=?',
                       (data['source'], data['source_id'])).fetchone()
    prior_data = json.loads(prior[0]) if prior else {}
    history = prior_data.get('identity_history', {
        'cves': [c['value'] for c in prior_data.get('cves', [])],
        'facets': prior_data.get('facets', []),
    })
    from cornicen.advisory import retracted
    relaxed_withdrawal = bool(retracted(data) and not data['cves'] and not facets)
    if not relaxed_withdrawal and not set(history['cves']) <= {c['value'] for c in data['cves']}:
        raise ValueError(FixedDiagnostic('advisory identifier removed or reassigned'))
    old = history['facets']
    def keys(f):
        cves = frozenset([f['cve']] if f.get('cve') else f.get('cves', []))
        ids = frozenset(tuple(sorted(i.items())) for i in f.get('ids', []))
        products = frozenset(json.dumps({k:v for k,v in p.items() if k not in ('version','versions','id')}, sort_keys=True)
                             if isinstance(p, dict) else p for p in f.get('products', []))
        return cves, ids, (f.get('title'), products)
    previous = [keys(f) for f in old]
    current = [keys(f) for f in facets]
    used, output = set(), []
    next_number = max(max((f.get('number', n+1) for n,f in enumerate(old)), default=0)+1,
                      prior_data.get('facet_next', 1))
    for f, key in zip(facets, current):
        candidates = []
        for level in range(3):
            if level < 2 and not key[level]:
                continue
            candidates = [n for n,k in enumerate(previous) if k[level] == key[level]]
            if candidates:
                break
        if len(candidates)>1:
            raise ValueError(FixedDiagnostic('ambiguous facet reconciliation'))
        if candidates and candidates[0] in used:
            raise ValueError(FixedDiagnostic('ambiguous facet reconciliation'))
        if candidates:
            n = candidates[0]
            if not previous[n][0] <= key[0] or not previous[n][1] <= key[1]:
                raise ValueError(FixedDiagnostic('facet identifier removed or reassigned'))
            # An identifier cannot migrate while its former title/product
            # identity is still represented by a different incoming facet.
            if previous[n][2] != key[2] and any(k[2] == previous[n][2] for k in current):
                raise ValueError(FixedDiagnostic('facet identifier reassigned'))
            used.add(n)
            number = old[n].get('number', n+1)
        else:
            number = next_number
            next_number += 1
        output.append(dict(f, number=number))
    if not relaxed_withdrawal and any((k[0] or k[1]) and n not in used for n,k in enumerate(previous)):
        raise ValueError(FixedDiagnostic('facet identifier removed'))
    # Keep retired anonymous numbers reserved so they cannot be reused.
    if old:
        data = dict(data, facet_next=max(next_number, prior_data.get('facet_next', 1)))
    else:
        data = dict(data, facet_next=next_number)
    if relaxed_withdrawal:
        data['identity_history'] = history
    else:
        data.pop('identity_history', None)
        data['facets'] = output
    return data


def _cve_target(identity):
    if not isinstance(identity, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', identity):
        raise ValueError(FixedDiagnostic('identity link target must be a well-formed CVE'))


def link(engine, old_id, new_id, tick):
    """Commit a complete link atomically, including callers outside ingestion."""
    _cve_target(new_id)
    with engine.store.transaction():
        _link(engine, old_id, new_id, tick)


def _link(engine, old_id, new_id, tick):
    """Merge an explicit link in the caller's record transaction; preserve events."""
    from cornicen import advisory
    _cve_target(new_id)
    db = engine.db
    target = canonical_id(db, new_id)
    _cve_target(target)
    source, _, local = old_id.removeprefix('advisory:').partition(':')
    source_id, _, _facet = local.rpartition(':')
    for row in db.execute('SELECT json FROM advisories WHERE source=? AND source_id=?', (source, source_id)):
        data = json.loads(row[0])
        if any(advisory.parent_id(f) == old_id and len(f['cves']) > 1 for f in advisory.facet_records(data)):
            raise ValueError(FixedDiagnostic('split parent cannot redirect'))
    old_target = canonical_id(db, old_id)
    if old_id == new_id:
        raise ValueError(FixedDiagnostic('identity link cycle'))
    if target == old_id:
        raise ValueError(FixedDiagnostic('identity link cycle'))
    if old_target == target:
        return
    if old_target != old_id:
        raise ValueError(FixedDiagnostic('identity identifier reassigned'))
    if old_id.partition('-')[0] == target.partition('-')[0] == 'CVE':
        raise ValueError(FixedDiagnostic('distinct CVEs cannot merge'))
    aliases = [old_id] + [r[0] for r in db.execute('SELECT old_id FROM identity_redirects WHERE new_id=?', (old_id,))]
    pairs = db.execute('SELECT * FROM pairs WHERE record_id IN (?,?) ORDER BY watch_id', (old_id,target)).fetchall()
    watches = {p['watch_id'] for p in pairs if p['record_id'] == old_id}
    for watch in watches:
        group = [p for p in pairs if p['watch_id']==watch]
        episode = max(p['episode'] for p in group)
        for p in group:
            for reason, stamp in delivered_reasons(db, watch, p['record_id'], p['episode']).items():
                db.execute('INSERT OR IGNORE INTO delivery_coverage VALUES (?,?,?,?,?,?)',
                           (watch,target,reason,episode,p['record_id'],stamp))
        base = next((p for p in group if p['record_id']==target), group[0])
        values = dict(base, record_id=target, episode=episode,
                      notified=int(any(p['notified'] for p in group)))
        if any(advisory.logical_latch(db,p) for p in group):
            db.execute('INSERT OR REPLACE INTO affected_latches VALUES (?,?,?,1)', (watch,target,episode))
        db.execute('DELETE FROM pairs WHERE watch_id=? AND record_id IN (?,?)', (watch,old_id,target))
        db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)', tuple(values[k] for k in base.keys()))
        history = db.execute('SELECT v FROM meta WHERE k=?', (advisory.history_key(old_id, SimpleNamespace(id=watch)),)).fetchone()
        if history:
            advisory.remember(db,target,SimpleNamespace(id=watch),[tuple(owner) for owner in json.loads(history[0])])
        for suffix in ('', '|correction'):
            pending = db.execute('SELECT * FROM outbox WHERE sent_at IS NULL AND pair_key IN (?,?)',
                                 (watch+'|'+old_id+suffix,watch+'|'+target+suffix)).fetchall()
            if not pending:
                continue
            reasons = sorted({r for row in pending for r in json.loads(row['reasons_json'])})
            if not suffix:
                reasons = [r for r in reasons if not covered(db,watch,target,r,episode)]
            chosen = max(pending, key=lambda r:(r['attempts'],r['id']))
            body = json.loads(chosen['body_json'])
            body.update(record_id=target, also_known_as=sorted(set(aliases + body.get('also_known_as', []))))
            if not suffix:
                body['episode'] = episode
            db.executemany('DELETE FROM outbox WHERE id=?', [(r['id'],) for r in pending])
            if reasons:
                urgency = max((r['urgency'] for r in pending),key=lambda u:{'normal':0,'urgent':1,'health':2}[u])
                engine.store.queue(watch+'|'+target+suffix,urgency,reasons,body,min((r['due_at'] for r in pending), key=datetime.fromisoformat),min((r['enqueued_at'] for r in pending), key=datetime.fromisoformat))
                db.execute('UPDATE outbox SET attempts=?,next_attempt_at=? WHERE pair_key=? AND sent_at IS NULL',
                           (chosen['attempts'],chosen['next_attempt_at'],watch+'|'+target+suffix))
    # Defensive chain collapse: production links go from advisory IDs to CVEs,
    # so production paths can no longer create a chain's first hop.
    db.execute('UPDATE identity_redirects SET new_id=? WHERE new_id=?', (target,old_id))
    db.execute('INSERT INTO identity_redirects VALUES (?,?,?)', (old_id,target,tick))
    db.execute('UPDATE advisory_evidence SET identity=? WHERE identity=?', (target,old_id))
    db.execute('INSERT OR IGNORE INTO advisory_support SELECT source,source_id,? FROM advisory_support WHERE identity=?', (target,old_id))
    db.execute('DELETE FROM advisory_support WHERE identity=?', (old_id,))
    db.execute('DELETE FROM affected_latches WHERE record_id=?', (old_id,))

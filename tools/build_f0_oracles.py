# script-purpose: Write invented foundation oracle inputs and independent expectations.
# script-class: generator
# script-trigger: Run manually when reviewing the F0 oracle contract.
# script-tests: tools/test-build-f0-oracles.py
"""Read no captures; write tests/replay_v11/*.jsonl from authored §8 oracles.

Usage: PYTHONPATH=src python3 tools/build_f0_oracles.py [--output DIR]
Exit 0 on success; nonzero on filesystem or contract construction errors.
Digests use the canonical JSON recipe documented in tests/replay_v11/README.md.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WATCH = '[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.0.0"\nscheme="semver"\n'
T0 = '2099-11-03T00:00:00Z'
A = 'CVE-2099-0001'
B = 'CVE-2099-0002'
C = 'CVE-2099-0003'
G = 'advisory:fixture_a:FIX-2099-0001:main'
P = 'advisory:fixture_a:FIX-2099-0002:main'

# Controller ruling: F3a owns later-tagged assertions it legitimately satisfies.
# These are physical expected-file line numbers after chronological sorting.
# Only ownership changes; every expected value remains the reviewed F0 value.
F3A_RETAGS = {
    'alias_episode': (3, 7, 9, 13, 15),
    'late_identity': (2, 3, 4, 8, 10, 15, 19, 21),
    'split': (9,),
    'synthetic_identifier': (2, 4),
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def manifest(records):
    return sorted([{'source_id': r['id'], 'digest': digest(r)} for r in records], key=lambda r: (r['source_id'], r['digest']))


def cursor(t, records):
    return {'tick': t, 'digest': digest(manifest(records))}


C0 = cursor(T0, [])


def evidence(status='known_affected', product='p', **extra):
    return dict(product_id=product, status=status, scheme='semver', range={'introduced': '1.0.0', 'limit': '2.0.0'}, **extra)


def record(id='FIX-2099-0001', cves=None, status='known_affected', **extra):
    return dict(id=id, title='Widget advisory', url='https://examplecorp.invalid/advisories/' + id,
                published=T0, updated=T0, products=[{'id': 'p', 'name': 'examplecorp:widget'}],
                cves=cves or [], evidence=[evidence(status)], **extra)


def pair(id, state='affected', episode=1, latch=True, notified=True):
    return {'watch': 'w', 'id': id, 'state': state, 'episode': episode,
            'affected_latch': latch, 'notified': notified}


def event(id, reason='new match', episode=1):
    # These reasons have no optional occurrence or resolution suffix in v1.
    return f'w|{id}|{reason}|{episode}'


def cna(id=A, status='unknown', release=None):
    scope = {'vendor': 'examplecorp', 'product': 'widget', 'defaultStatus': status,
             'versions': [{'version': '1.0.0', 'lessThan': '2.0.0', 'versionType': 'semver', 'status': status}]}
    if release:
        scope['release'] = release
    return {'dataType': 'CVE_RECORD', 'dataVersion': '5.1',
            'cveMetadata': {'cveId': id, 'state': 'PUBLISHED', 'assignerOrgId': 'fixture'},
            'containers': {'cna': {'providerMetadata': {'orgId': 'fixture'},
                                   'descriptions': [{'lang': 'en', 'value': 'Widget advisory'}], 'affected': [scope]}}}


class Oracle:
    def __init__(self, name, rowspec, owner='F3a'):
        self.name, self.owner = name, owner
        self.inputs = [{'#': f'Spec §8 {rowspec}; invented mutation, never a capture.'}]
        self.expected = [{'#': f'Spec §8 {rowspec}; exact remapped oracle; invented mutation.'}]
        self.pending_resources = {}
        self.accepted_cycles = []
        self.case = 'main'
        self.base = datetime(2099, 11, 3, tzinfo=timezone.utc)
        self.t = T0
        self.add(watchlist=WATCH)
        self.seed()

    def add(self, **action):
        self.inputs.append(dict(t=self.t, **action))

    def seed(self, **overrides):
        initial = {'v1_baseline_complete': True, 'adapters': {'fixture_a': {
            'baseline_complete': True, 'baseline_members': [], 'cursor': C0,
            'cutoff': T0, 'dimensions': {'fetch': 'healthy', 'completeness': 'healthy',
                                      'freshness': 'n/a', 'audit': 'healthy'}}},
                   'pairs': [], 'events': [], 'outbox': []}
        for source in ('fixture_b', 'fixture_export'):
            initial['adapters'][source] = deepcopy(initial['adapters']['fixture_a'])
            if source == 'fixture_export':
                initial['adapters'][source]['dimensions']['freshness'] = 'healthy'
        initial.update(overrides)
        self.add(seed=initial)

    def variant(self, name, **seed):
        self.base += timedelta(days=10)
        self.t = self.base.isoformat().replace('+00:00', 'Z')
        self.case = name
        self.pending_resources = {}
        self.add(case=name)
        self.add(watchlist=WATCH)
        self.seed(**seed)

    def tick(self, hour):
        self.t = (self.base + timedelta(hours=hour)).isoformat().replace('+00:00', 'Z')

    def raw(self, records=None, source='fixture_a', body=None, status=200, **outcome):
        resource = dict(path='listing.json', status=status,
                        body=canonical(records if records is not None else []) if body is None else body,
                        headers={}, transfer_complete=True, integrity='intact')
        resource.update(outcome)
        self.inputs.append({'t': self.t, 'adapter': source, 'result': {'resources': [resource]}})
        self.pending_resources[source] = resource

    def ingest(self, *records):
        self.add(ingest={'source': 'cvelist', 'status': 'complete', 'origin': 'delta',
                         'cursor': self.t, 'content_time': self.t, 'records': list(records)})

    def cycle(self, accepted=True):
        self.add(cycle=True)
        if accepted:
            self.accepted_cycles.append((self.case, self.t, deepcopy(self.pending_resources)))
        self.pending_resources = {}

    def state(self, task=None, validation_task='F1', snapshot=None, **fields):
        if 'events' in fields:
            fields['events'] = sorted(fields['events'])
        for field, keys in [('pairs', ('watch', 'id')), ('redirects', ('old_id', 'new_id')),
                            ('outbox', ('watch', 'record')), ('gaps', ('source', 'opened_at')),
                            ('retries', ('source', 'resource'))]:
            if field in fields:
                fields[field] = sorted(fields[field], key=lambda row: tuple(row[k] for k in keys))
        start = len(self.expected)
        # Keep raw validation independently liftable; callers mark classification
        # or quarantine observations that also require persistence as F2a.
        for field in ('classification', 'quarantine'):
            if field in fields:
                self.expected.append({'t': self.t, 'case': self.case,
                                      'state': {field: fields.pop(field)}, 'lifted_by': validation_task})
        for owner, names in [('F2a', ('cursor', 'manifests')),
                             ('F2b', ('dimensions',))]:
            selected = {name: fields.pop(name) for name in names if name in fields}
            if selected:
                self.expected.append({'t': self.t, 'case': self.case,
                                      'state': selected, 'lifted_by': owner})
        if fields:
            self.expected.append({'t': self.t, 'case': self.case, 'state': fields, 'lifted_by': 'F2a' if set(fields) == {'gaps', 'historical_completeness'} else task or self.owner})

        if snapshot is not None:
            for row in self.expected[start:]:
                row['snapshot'] = snapshot

    def notify(self, id, reason='new match', task=None, watch='w', urgency='normal'):
        self.expected.append({'t': self.t, 'case': self.case, 'watch': watch, 'record': id,
                              'reasons': [reason], 'urgency': urgency, 'lifted_by': 'F2a' if reason == 'baseline' else task or self.owner})

    def complete(self, records, source='fixture_a', task='F2a'):
        self.state(task=task, classification={source: 'COMPLETE'},
                   cursor={source: cursor(self.t, records)}, manifests={source: manifest(records)})

    def counts(self, advisory, total=None, task=None):
        values = {'advisory': advisory}
        if total is not None:
            values['total'] = total
        self.state(task=task, notification_count=values)

    def write(self, output):
        # Acceptance is authored at each cycle call, never inferred by running
        # implementation code. Expand its literal manifest/cursor contract.
        for case, tick, resources in self.accepted_cycles:
            for source, resource in resources.items():
                body = json.loads(resource['body'])
                members = body if isinstance(body, list) else body['advisories']
                at_tick = [r for r in self.expected if r.get('case') == case and r.get('t') == tick and 'state' in r]
                if not any(source in r['state'].get('cursor', {}) for r in at_tick):
                    self.expected.append({'t': tick, 'case': case, 'state': {
                        'classification': {source: 'COMPLETE'}}, 'lifted_by': 'F1'})
                    self.expected.append({'t': tick, 'case': case, 'state': {
                        'cursor': {source: cursor(tick, members)},
                        'manifests': {source: manifest(members)}}, 'lifted_by': 'F2a'})
                self.expected.append({'t': tick, 'case': case, 'state': {'dimensions': {source: {
                    'fetch': 'healthy', 'completeness': 'healthy', 'audit': 'healthy',
                    'freshness': 'stale' if source == 'fixture_export' else 'n/a'}}}, 'lifted_by': 'F2b'})
        case_order = {'main': 0}
        for row in self.inputs:
            if 'case' in row:
                case_order[row['case']] = len(case_order)
        self.expected[1:] = sorted(self.expected[1:], key=lambda row: (case_order[row['case']], row['t']))
        for number in F3A_RETAGS.get(self.name, ()):
            row = self.expected[number - 1]
            if row['lifted_by'] != 'F3b':
                raise ValueError(f'{self.name}:{number}: re-tag must replace F3b ownership')
            row['lifted_by'] = 'F3a'
        for kind, rows in [('input', self.inputs), ('expected', self.expected)]:
            (output / f'{self.name}.{kind}.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows))


def build(output):
    output.mkdir(parents=True, exist_ok=True)
    files = []
    o = Oracle('late_identity', 'late_identity', 'F3b'); files.append(o)
    r = record()
    o.tick(1); o.raw([r]); o.cycle(); o.notify(G); o.state(pairs=[pair(G)]); o.counts(1, 1)
    o.tick(2); o.ingest(cna(status='affected')); o.raw([r]); o.cycle(); o.notify(A); o.state(pairs=[pair(A), pair(G)]); o.counts(2, 2)
    linked = record(cves=[A])
    o.tick(3); o.raw([linked]); o.cycle(); o.state(redirects=[{'old_id': G, 'new_id': A}], pairs=[pair(A)], events=[event(G), event(A)]); o.counts(2, 2)
    o.add(restart=True)
    o.variant('same_cycle')
    o.tick(1); o.ingest(cna(status='affected')); o.raw([linked]); o.cycle(); o.notify(A)
    o.state(redirects=[{'old_id': G, 'new_id': A}], events=[event(A)]); o.counts(1, 1)

    o = Oracle('alias_episode', 'alias_episode', 'F3b'); files.append(o)
    o.add(seed={'pairs': [pair(G, episode=2), pair(A, episode=4)],
                'events': [event(G, episode=2), event(A, episode=4)],
                'delivered': [{'id': G, 'reason': 'new match', 'episode': 2}, {'id': A, 'reason': 'new match', 'episode': 4}]})
    o.tick(1); o.raw([linked]); o.ingest(cna(status='affected')); o.cycle()
    o.state(pairs=[pair(A, episode=4)], redirects=[{'old_id': G, 'new_id': A}]); o.counts(0, 0)
    o.tick(2); o.raw([record(cves=[A], status='known_not_affected')]); o.ingest(cna(status='unaffected')); o.cycle(); o.notify(A, 'correction')
    o.state(pairs=[pair(A, 'unaffected', 5, False, False)]); o.counts(1, 1)
    o.add(restart=True)
    o.tick(3); o.raw([linked]); o.ingest(cna(status='affected')); o.cycle(); o.notify(A)
    o.state(pairs=[pair(A, episode=5)], redirects=[{'old_id': G, 'new_id': A}],
            events=[event(G, episode=2), event(A, episode=4), event(A, 'correction', 4), event(A, episode=5)])
    o.counts(2, 2)

    o = Oracle('split', 'split'); files.append(o)
    parent = record('FIX-2099-0002', cves=[B, C])
    parent['products'].append({'id': 'q', 'name': 'examplecorp:gadget'})
    parent['evidence'].append(evidence(product='q'))
    o.tick(1); o.raw([parent]); o.cycle(); o.notify(P)
    o.state(pairs=[pair(P), pair(B, 'unknown', latch=False, notified=False), pair(C, 'unknown', latch=False, notified=False)],
            evidence={'parent': parent['evidence'], 'cve_ranges': {B: [], C: []}},
            body={'record': P, 'label': 'advisory — which listed CVE affects you is not stated'})
    o.counts(1, 1)
    o.tick(2)
    associated = deepcopy(parent)
    associated['associations'] = [{'cve': B, 'product_id': 'p'}, {'cve': C, 'product_id': 'q'}]
    o.raw([associated]); o.cycle()
    o.state(task='F3b', coverage=[{'child_id': B, 'parent_id': P, 'watch': 'w', 'reason': 'new match', 'episode': 1}],
            redirects=[], pairs=[pair(P), pair(B), pair(C, 'unknown', latch=False, notified=False)])
    o.counts(1, 1, task='F3b')
    o.variant('explicit_associations')
    o.tick(1); o.raw([associated]); o.cycle(); o.notify(B)
    o.state(pairs=[pair(B), pair(C, 'unknown', latch=False, notified=False)], evidence={'cve_products': {B: ['p'], C: ['q']}}); o.counts(1, 1)

    o = Oracle('aggregate', 'aggregate'); files.append(o)
    affected = record(cves=[A]); unaffected = record(cves=[A], status='known_not_affected')
    for r in (affected, unaffected):
        r['evidence'][0]['release'] = 'example-12'
    o.add(watchlist=WATCH + 'release="example-12"\n')
    o.tick(1); o.raw([affected]); o.raw([unaffected], source='fixture_b'); o.ingest(cna(release='example-12')); o.cycle(); o.notify(A)
    o.state(pairs=[pair(A)]); o.counts(1, 1)
    withdrawn = deepcopy(affected); withdrawn['withdrawn'] = o.t
    o.tick(2); o.raw([withdrawn]); o.raw([unaffected], source='fixture_b'); o.ingest(cna(release='example-12')); o.cycle()
    o.state(pairs=[pair(A, 'unknown')], evidence={'active_sources': ['cvelist', 'fixture_b']}); o.counts(1, 1)
    o.tick(3); o.ingest(cna(status='unaffected', release='example-12')); o.cycle(); o.notify(A, 'correction')
    o.state(pairs=[pair(A, 'unaffected', 2, False, False)]); o.counts(2, 2)
    o.variant('different_release_cna'); o.add(watchlist=WATCH + 'release="example-12"\n')
    o.tick(1); o.raw([affected]); o.ingest(cna(status='unaffected', release='example-13')); o.cycle(); o.notify(A)
    o.state(pairs=[pair(A)]); o.counts(1, 1)

    o = Oracle('baseline_is_local', 'baseline_is_local'); files.append(o)
    baseline = {'fixture_a': {'baseline_complete': False, 'baseline_members': None, 'cursor': C0, 'cutoff': T0}}
    o.add(seed={'adapters': baseline})
    o.tick(1); o.raw([linked]); o.ingest(cna(status='affected')); o.cycle()
    o.notify(A); o.notify('baseline:fixture_a', 'baseline', watch='')
    o.state(task='F2a', baseline={'fixture_a': {'members': ['FIX-2099-0001'], 'complete': True, 'summaries': 1}})
    o.state(pairs=[pair(A)]); o.counts(1, 2)
    o.variant('baseline_alone', adapters=baseline)
    o.tick(1); o.raw([linked]); o.cycle(); o.notify('baseline:fixture_a', 'baseline', watch='')
    o.counts(0, 1)
    o.tick(2); o.raw([linked]); o.cycle(); o.counts(0, 1)

    o = Oracle('bad_member', 'bad_member'); files.append(o)
    good = linked; bad = record('FIX-2099-0003'); bad['evidence'][0]['product_id'] = 'missing'
    o.tick(1); o.raw([good, bad]); o.cycle(False); o.notify(A)
    o.state(pairs=[pair(A), pair('advisory:fixture_a:FIX-2099-0003:main', 'unknown', latch=False, notified=False)])
    o.state(task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': C0},
            quarantine=['FIX-2099-0003'], advisories={'FIX-2099-0001': {'digest': digest(good)}, 'FIX-2099-0003': None},
            retries=[{'source': 'fixture_a', 'resource': 'listing.json'}])
    o.state(task='F2b', dimensions={'fixture_a': {'fetch': 'healthy', 'completeness': 'unhealthy', 'freshness': 'n/a', 'audit': 'healthy'}})
    o.notify('fixture_a', 'unhealthy', task='F2b', watch='', urgency='health'); o.counts(1, 2)
    corrected = record('FIX-2099-0003', status='under_investigation')
    o.tick(2); o.raw([good, corrected]); o.cycle(); o.complete([good, corrected])
    o.state(task='F2a', validation_task='F2a', quarantine=[], advisories={'FIX-2099-0001': {'digest': digest(good)}, 'FIX-2099-0003': {'digest': digest(corrected)}})
    o.notify('fixture_a', 'healthy', task='F2b', watch='', urgency='health'); o.counts(1, 3)

    o = Oracle('boundary', 'boundary'); files.append(o)
    for index, (name, body, status, truncated, classification) in enumerate([
        ('html', '<html>error</html>', 200, False, 'FAILED'), ('blank', '', 200, False, 'FAILED'),
        ('malformed_root', '{', 200, False, 'FAILED'), ('truncated', '[{"id":', 200, True, 'PARTIAL')]):
        if index:
            o.variant(name)
        o.tick(1); o.raw(body=body, status=status, transfer_complete=not truncated); o.cycle(False)
        o.state(task='F2a', classification={'fixture_a': classification}, cursor={'fixture_a': C0},
                retries=[{'source': 'fixture_a', 'resource': 'listing.json'}], advisories={})
        o.add(restart=True)
        o.state(task='F2a', snapshot='after_restart', retries=[{'source': 'fixture_a', 'resource': 'listing.json'}])
        o.state(task='F2b', dimensions={'fixture_a': {'fetch': 'unhealthy' if truncated else 'healthy', 'completeness': 'unhealthy', 'freshness': 'n/a', 'audit': 'healthy'}})
        o.notify('fixture_a', 'unhealthy', task='F2b', watch='', urgency='health'); o.counts(0, 1)

    o = Oracle('audits', 'audits', 'F2b'); files.append(o)
    # T2 - 7 days - 1 second, so T1 is still within seven days.
    audit_at = '2099-10-27T01:59:59Z'
    staged = {'source': 'fixture_a', 'resource': 'listing.json', 'path': 'staged/fixture_a.json', 'digest': digest([bad]), 'integrity': 'pending'}
    o.add(seed={'audits': [{'source': 'fixture_a', 'resource': 'listing.json', 'audited_at': audit_at}],
                'cache': [{'source': 'fixture_a', 'resource': 'listing.json', 'body': canonical([bad]), 'etag': '"revision-1"'}],
                'staged': [staged]})
    for hour in (1, 2):
        o.tick(hour); o.raw(body='', status=304); o.cycle(False)
        o.state(validation_task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': C0}, staged=[staged],
                dimensions={'fixture_a': {'fetch': 'healthy', 'completeness': 'unhealthy', 'freshness': 'n/a', 'audit': 'healthy' if hour == 1 else 'unhealthy'}})
        if hour == 1:
            o.notify('fixture_a', 'unhealthy', watch='', urgency='health')
        o.state(task='F3a', pairs=[pair('advisory:fixture_a:FIX-2099-0003:main', 'unknown', latch=False, notified=False)])
        o.counts(0, 1)
    repaired = record('FIX-2099-0003', status='under_investigation')
    o.tick(3); o.raw([repaired], headers={}); o.cycle(); o.complete([repaired], task='F2b')
    o.state(dimensions={'fixture_a': {'fetch': 'healthy', 'completeness': 'healthy', 'freshness': 'n/a', 'audit': 'healthy'}}, staged=[])
    o.state(task='F3a', pairs=[pair('advisory:fixture_a:FIX-2099-0003:main', 'unknown', latch=False, notified=False)])
    o.notify('fixture_a', 'healthy', watch='', urgency='health'); o.counts(0, 2)
    o.variant('permanent_gap')
    gap = {'source': 'fixture_a', 'opened_at': o.t, 'reason': 'retention gap', 'acknowledged_at': None}
    o.add(seed={'gaps': [gap], 'audits': [{'source': 'fixture_a', 'resource': 'listing.json', 'audited_at': audit_at}]})
    for hour in (1, 2, 3):
        o.tick(hour); o.raw([repaired]); o.cycle(False)
        o.state(validation_task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': C0}, gaps=[gap], historical_completeness={'fixture_a': 'unhealthy (permanent gap)'},
                dimensions={'fixture_a': {'fetch': 'healthy', 'completeness': 'unhealthy', 'freshness': 'n/a', 'audit': 'healthy'}})
        if hour == 1:
            o.notify('fixture_a', 'unhealthy', watch='', urgency='health')
        o.counts(0, 1)
    o.variant('stale_export')
    generated = (o.base - timedelta(hours=49)).isoformat().replace('+00:00', 'Z')
    o.tick(1)
    o.raw(body=canonical({'generation': generated, 'advisories': []}), source='fixture_export', headers={'Date': o.t})
    o.cycle(); o.state(dimensions={'fixture_export': {'fetch': 'healthy', 'completeness': 'healthy', 'freshness': 'stale', 'audit': 'healthy'}})
    o.notify('fixture_export', 'unhealthy', watch='', urgency='health'); o.counts(0, 1)

    o = Oracle('empty_enumeration', 'github_empty (generic part)'); files.append(o)
    o.add(seed={'adapters': baseline})
    for hour in (1, 2):
        o.tick(hour); o.raw([]); o.cycle(); o.complete([])
        o.state(task='F2a', baseline={'fixture_a': {'members': [], 'complete': True, 'summaries': 1}})
        if hour == 1:
            o.notify('baseline:fixture_a', 'baseline', watch='')
        o.counts(0, 1)
    o.variant('disappearance')
    known = record(status='under_investigation')
    o.tick(1); o.raw([known]); o.cycle(); o.complete([known]); accepted = cursor(o.t, [known])
    o.counts(0, 0)
    for hour in (2, 3):
        o.tick(hour); o.raw([]); o.cycle(False)
        o.state(task='F2a', validation_task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': accepted}, advisories={'FIX-2099-0001': {'digest': digest(known)}},
                retries=[{'source': 'fixture_a', 'resource': 'listing.json'}])
        if hour == 2:
            o.notify('fixture_a', 'unhealthy', task='F2b', watch='', urgency='health')
        o.counts(0, 1)

    o = Oracle('rebaseline_gap', 'synology T3–T4 (generic part)'); files.append(o)
    history = [event(A), event(A, 'KEV added')]
    pending = {'watch': 'w', 'record': B, 'reasons': ['new match'], 'episode': 1, 'due_at': '2099-11-10T08:00:00Z', 'attempts': 2, 'next_attempt_at': '2099-11-10T08:01:00Z'}
    o.add(seed={'events': history, 'delivered': [{'id': A, 'reason': 'new match', 'episode': 1}, {'id': A, 'reason': 'KEV added', 'episode': 1}],
                'outbox': [pending], 'pairs': [pair(A), pair(B, notified=False)]})
    retained = record(status='under_investigation')
    for hour in (1, 2):
        o.tick(hour); o.raw([retained]); o.cycle(); o.complete([retained])
    c2 = cursor(o.t, [retained])
    o.tick(51)
    gap = {'source': 'fixture_a', 'opened_at': o.t, 'reason': 'retention gap', 'acknowledged_at': None}
    o.raw(body=canonical({'advisories': [retained], 'retention_hours': 48, 'coverage_start': '2099-11-03T03:00:00Z'})); o.cycle(False)
    o.state(task='F2a', validation_task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': c2}, gaps=[gap], events=history, outbox=[pending], historical_completeness={'fixture_a': 'unhealthy (permanent gap)'})
    o.notify('fixture_a', 'unhealthy', task='F2b', watch='', urgency='health'); o.counts(0, 1)
    o.tick(52); o.add(command=['adapter', 'rebaseline', 'fixture_a'])
    acknowledged = dict(gap, acknowledged_at=o.t)
    o.state(task='F2a', cursor={'fixture_a': cursor(o.t, [retained])}, gaps=[acknowledged], events=history, outbox=[pending],
            historical_completeness={'fixture_a': 'unhealthy (permanent gap)'})
    o.counts(0)

    o = Oracle('synthetic_optional', 'synthetic_osv_optional and synthetic_csaf_optional (evidence level)'); files.append(o)
    o.add(watchlist=WATCH.replace('1.0.0', '2.0.0'))
    inclusive = record(cves=[A]); inclusive['evidence'][0]['range'] = {'introduced': '1.0.0', 'last_affected': '2.0.0'}
    o.tick(1); o.raw([inclusive]); o.cycle(); o.notify(A); o.state(pairs=[pair(A)], fix={A: None}); o.counts(1, 1)
    o.tick(2); withdrawn = deepcopy(inclusive); withdrawn['withdrawn'] = o.t
    o.raw([withdrawn]); o.cycle(); o.notify(A, 'correction'); o.state(pairs=[pair(A, 'unaffected', 2, False, False)]); o.counts(2, 2)
    o.variant('limit'); o.add(watchlist=WATCH.replace('1.0.0', '2.0.0'))
    exclusive = record(cves=[A])
    o.tick(1); o.raw([exclusive]); o.cycle(); o.state(pairs=[pair(A, 'unaffected', latch=False, notified=False)], fix={A: None}); o.counts(0, 0)
    for status, applicability, fix in [('known_not_affected', 'unaffected', None), ('under_investigation', 'unknown', None), ('first_fixed', 'unaffected', '2.0.0'), ('known_affected', 'affected', 'available'), ('missing_group', 'unknown', None)]:
        o.variant(status); o.add(watchlist=WATCH.replace('1.0.0', '2.0.0'))
        grouped = record(cves=[A], status='known_affected' if status == 'missing_group' else status)
        grouped['products'][0]['version'] = '2.0.0'
        grouped['product_groups'] = [{'id': 'g', 'product_ids': ['p']}]
        grouped['evidence'][0].pop('range')
        if status == 'first_fixed':
            grouped['evidence'][0]['first_fixed'] = '2.0.0'
        if status in ('known_affected', 'missing_group'):
            grouped['remediations'] = [{'category': 'vendor_fix', 'group_ids': ['missing' if status == 'missing_group' else 'g']}]
        o.tick(1); o.raw([grouped]); o.cycle(status != 'missing_group')
        o.state(pairs=[pair(A, applicability, latch=applicability == 'affected', notified=applicability == 'affected')], fix={A: fix})
        if applicability == 'affected':
            o.notify(A)
        if status == 'missing_group':
            o.state(task='F2a', classification={'fixture_a': 'PARTIAL'}, cursor={'fixture_a': C0}, quarantine=['FIX-2099-0001'])
            o.notify('fixture_a', 'unhealthy', task='F2b', watch='', urgency='health')
        o.counts(int(applicability == 'affected'), 1 if status in ('known_affected', 'missing_group') else 0)

    o = Oracle('synthetic_identifier', 'synthetic_github_identifier', 'F3b'); files.append(o)
    identified = record(identifiers=[{'type': 'CVE', 'value': A}])
    identified['evidence'][0]['fix'] = '2.0.0'
    o.tick(1); o.raw([identified]); o.cycle(); o.notify(A)
    o.state(redirects=[{'old_id': G, 'new_id': A}], pairs=[pair(A)], fix={A: '2.0.0'}, events=[event(A)]); o.counts(1, 1)
    o = Oracle('withdrawal_reissue', 'S-W withdrawal and same-identity reissue', 'F4')
    files.append(o)
    for reissue in (False, True):
        if reissue:
            o.variant('reissued')
        original = record(cves=[A], facets=[dict(title='Gadget',
            products=[dict(name='examplecorp:gadget')],
            ids=[dict(system_name='fixture', text='FIX-2099-0010')])])
        original['products'][0]['name'] = 'examplecorp:gadget'
        for hour in range(1, 4 if reissue else 3):
            o.tick(hour)
            revision = deepcopy(original)
            revision['updated'] = o.t
            if hour == 2:
                revision.update(withdrawn=o.t, cves=[], facets=[], evidence=[])
            o.raw([revision]); o.cycle()
            o.counts(0, 0)

    for oracle in files:
        oracle.write(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/replay_v11')
    build(parser.parse_args().output)

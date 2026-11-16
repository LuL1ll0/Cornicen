# script-purpose: Verify shared CSAF state, directory listings and transport offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task3_b1.py
"""Read invented responses; write temporary SQLite and member files. unittest exits 0/1."""
from datetime import timedelta
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch
import uuid

from cornicen.adapterstore import AdapterStore, canonical, instant, stamp
from cornicen.store import Store
from tests import test_task2_b2 as legacy

ROOT = Path(__file__).resolve().parents[1]
T = legacy.T


def microsoft_snapshot():
    case = legacy.Task2B2Tests()
    case.setUp()
    result = []
    original_stage = case.p.stage_members
    stages = []
    def stage(*args, **kwargs):
        value = original_stage(*args, **kwargs)
        stages.append(case.store.get_meta('staged_flags:msrc:msrc/advisories'))
        return value
    try:
        with patch.object(uuid, 'uuid4', side_effect=(uuid.UUID(int=n) for n in range(1, 1000))), patch.object(case.p, 'stage_members', stage):
            case.p.rng = random.Random(1)
            adapter = case.adapter()
            for n, (listing, records) in enumerate((
                ({'2099/a.json':[T], '2099/b.json':[T]}, {'2099/a.json':legacy.raw(), '2099/b.json':dict(status=503)}),
                ({'2099/a.json':[T], '2099/b.json':[T]}, {'2099/b.json':legacy.raw(2)}),
                ({'2099/a.json':[T]}, {}),
            )):
                case.scripts(listing, records, metadata=n == 0)
                outcome = case.poll(adapter)
                members = Path(outcome['members_file']).read_bytes().decode() if 'members_file' in outcome else None
                recorded = dict(outcome)
                if 'members_file' in recorded:
                    recorded['members_file'] = '<msrc-members-file>'
                classification = case.process(outcome)
                result.append(dict(outcome=recorded, members=members, classification=classification,
                    meta=[tuple(r) for r in case.db.execute('SELECT k,v FROM meta ORDER BY k')],
                    gaps=[tuple(r) for r in case.db.execute('SELECT * FROM gap_ledger')]))
                case.now += timedelta(hours=1)
            return dict(cycles=result, stages=stages, requests=case.server.requests)
    finally:
        case.doCleanups()


class Task3B1Tests(unittest.TestCase):
    def test_t12_microsoft_literals(self):
        self.assertEqual(microsoft_snapshot(), MICROSOFT_LITERALS)

    def test_t10_index(self):
        from cornicen.sources.cisco_csaf import parse_index
        paths = {'2099/a.json', '2099/A.json', '2099/a..b.json'}
        for newline in ('\n', '\r\n'):
            self.assertEqual(parse_index(newline.join(['', *sorted(paths), '2099/a.json', ''])), (dict.fromkeys(sorted(paths), []), 0))
        bad = [' 2099/a.json', '2099/a.json ', '2099/a#b.json', '2099/a?b.json', '2099/a%b.json', '2099/../a.json', '2099/a.txt', '999/a.json']
        for line in bad:
            self.assertEqual(parse_index('2099/a.json\n'+line)[1], 1)
        for body in ('', ' \n', '<html>', b'\xff', 'garbage\n'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_index(body)

    def test_t13_source_flags(self):
        from cornicen.sources.csaf_directory import state_for
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            store = Store(Path(directory)/'db'); store.migrate()
            self.addCleanup(store.connection.close)
            for source in ('msrc', 'cisco'):
                self.assertEqual(state_for(store, source).profile.source, source)
            self.assertIsNone(state_for(store, 'github'))
        generation = 'a'*32
        self.assertEqual(AdapterStore._outcome_flags({'cisco_generation':generation}, 'cisco'), {'cisco_generation':generation})
        for source, flags in (('msrc', {'cisco_generation':generation}), ('github', {'cisco_generation':generation}), ('cisco', {'msrc_generation':generation}), *[('cisco', {'cisco_generation':v}) for v in ('A'*32, '', 3, None)]):
            with self.subTest(source=source, flags=flags), self.assertRaises(ValueError):
                AdapterStore._outcome_flags(flags, source)

    def environment(self, source='cisco'):
        from cornicen.sources.csaf_directory import state_for
        from cornicen.sources.cisco_csaf import CiscoCsaf
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(directory.cleanup)
        store = Store(Path(directory.name)/'db'); store.migrate()
        self.addCleanup(store.connection.close)
        state = state_for(store, source)
        state.rng = random.Random(1)
        processor = AdapterStore(store, directory.name, rng=random.Random(1))
        processor.reconcile_required(source, (state.profile.resource,), T)
        server = DirectoryHttp(directory.name)
        adapter = CiscoCsaf(server, state, lambda: server.now)
        return store, state, processor, server, adapter

    def cycle(self, env, changes, index, *, records=(), failures=None, inspect=None):
        store, state, processor, http, adapter = env
        http.bodies = {adapter.profile.metadata_url: {'distributions':[{'directory_url':adapter.profile.directory_url}]},
            adapter.profile.directory_url+'changes.csv': changes,
            adapter.profile.directory_url+'index.txt': index,
            **{adapter.profile.directory_url+p: legacy.raw(ord(Path(p).stem[0])-ord('a')+1) for p in records}}
        http.failures = failures or {}
        outcome = adapter.poll()[0]
        if inspect is not None:
            inspect(outcome)
        result = processor.process('cisco', [outcome], stamp(http.now), required_resources=('cisco/advisories',))
        processor.finish_cycle('cisco', stamp(http.now))
        http.now += timedelta(hours=1)
        return result

    def test_cisco_members_after_bootstrap(self):
        env = self.environment(); store, state, processor, http, adapter = env
        a, b = '2099/a.json', '2099/b.json'
        self.assertEqual(self.cycle(env, a+','+T, a, records=(a,)), 'COMPLETE')
        self.assertIsNone(store.get_meta('baseline_hold:cisco'))
        self.assertIsNotNone(store.get_meta('baseline_pinned:cisco:cisco/advisories'))
        def inspect(outcome):
            file = Path(outcome['members_file'])
            self.assertTrue(file.name.startswith('cisco-members-'), file.name)
            members = [json.loads(line) for line in file.read_text().splitlines()]
            self.assertEqual({m['id'] for m in members},
                             {state.path(a)['member']['id'], state.path(b)['member']['id']})
            self.assertEqual(len(members), 2)
        self.assertEqual(self.cycle(env, a+','+T+'\n'+b+','+T, a+'\n'+b,
                                   records=(b,), inspect=inspect), 'COMPLETE')

    def test_cisco_bootstrap_hold_and_late_pin(self):
        store, state, processor, http, adapter = self.environment()
        a, b = '2099/a.json', '2099/b.json'
        state.observe_listing({a:[T], b:[T]}, 0, T)
        for key in ('baseline_hold:', 'baseline_hold_used:'):
            self.assertEqual(store.get_meta(key+'cisco'), T)
            self.assertIsNone(store.get_meta(key+'msrc'))
        # The second bootstrap identity arrives after an unsuccessful attempt.
        state.record_success(a, [T], {'id':'cisco-first'}, T)
        state.record_failure(b, T)
        later = stamp(instant(T)+timedelta(hours=1))
        state.record_success(b, [T], {'id':'cisco-late'}, later)
        self.assertEqual([tuple(row) for row in store.connection.execute(
            'SELECT source,source_id FROM baseline_members ORDER BY source_id')],
            [('cisco', 'cisco-first'), ('cisco', 'cisco-late')])

    def test_cisco_budget_limited_first_poll(self):
        for observed in (False, True):
            with self.subTest(observed=observed):
                store, state, processor, http, adapter = self.environment()
                if observed:
                    state.observe_listing({'2099/a.json':[T]}, 0, T)
                with store.transaction():
                    state._put('requests', [T]*200)
                outcome = adapter.poll()[0]
                self.assertTrue(outcome.get('unenumerated'), outcome)
                self.assertEqual(outcome['path'], 'cisco/advisories')
                self.assertEqual(http.requests, [])

    def test_cisco_invalid_rows_preserve_conformance(self):
        a, b = '2099/a.json', '2099/b.json'
        for listing in ('changes', 'index'):
            for seeded in (False, True):
                with self.subTest(listing=listing, seeded=seeded):
                    env = self.environment(); store, state, processor, http, adapter = env
                    if seeded:
                        self.cycle(env, a+','+T, a, records=(a,))
                    before = state.meta('conformance')
                    if not seeded:
                        self.assertIsNone(before)
                    changes = a+','+T + ('\ngarbage' if listing == 'changes' else '')
                    index = a+'\n'+b + ('\ngarbage' if listing == 'index' else '')
                    self.cycle(env, changes, index, records=(a,b))
                    self.assertEqual(state.meta('conformance'), before)

    def test_cisco_request_ceilings(self):
        for ceiling in ('cycle', 'hour'):
            with self.subTest(ceiling=ceiling):
                store, state, processor, http, adapter = self.environment()
                adapter.now = http.now; adapter.tick = T
                adapter.spent = 199 if ceiling == 'cycle' else 0
                if ceiling == 'hour':
                    earlier = stamp(http.now-timedelta(seconds=1))
                    with store.transaction():
                        state._put('requests', [earlier]*399)
                url = adapter.profile.directory_url+'index.txt'
                http.bodies[url] = '2099/a.json'
                adapter._get(url)
                with self.assertRaisesRegex(ValueError, 'rate budget'):
                    adapter._get(url)
                self.assertEqual(http.requests, [url])

    def test_cisco_metadata_directory_match(self):
        store, state, processor, http, adapter = self.environment()
        directory = adapter.profile.directory_url
        for url in (directory, directory.rstrip('/')):
            document = {'distributions':[{'directory_url':url}]}
            self.assertEqual(adapter._metadata(canonical(document)), document)
        for urls in ((directory+'other/',),
                     ('https://www.cisco.com/.well-known/csaf-other/',),
                     ('https://example.invalid/.well-known/csaf/',),
                     (directory, directory.rstrip('/'))):
            with self.subTest(urls=urls), self.assertRaises(ValueError):
                adapter._metadata(canonical({'distributions':[{'directory_url':url} for url in urls]}))

    def test_t11_union(self):
        env = self.environment(); store, state, processor, http, adapter = env
        a, b = '2099/a.json', '2099/b.json'
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b, records=(a,b)), 'COMPLETE')
        self.assertEqual(state.path(b)['timestamps'], [])
        self.assertEqual(state.meta('conformance'), dict(tick=T, changes_only=0, index_only=1))
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b), 'COMPLETE')
        self.assertEqual(http.requests.count(adapter.profile.directory_url+b), 1)
        self.assertEqual(self.cycle(env, a+','+T+'\n'+b+','+T, a+'\n'+b, records=(b,)), 'COMPLETE')
        self.assertEqual(http.requests.count(adapter.profile.directory_url+b), 2)
        # Leaving the index alone does not remove a changes-listed path.
        self.cycle(env, a+','+T+'\n'+b+','+T, a)
        self.assertTrue(state.path(b)['listed'])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM gap_ledger').fetchone()[0], 0)
        for changes, index in ((a+','+T+'\ngarbage', a), (a+','+T, a+'\ngarbage')):
            self.cycle(env, changes, index)
            self.assertTrue(state.path(b)['listed'])
        self.cycle(env, a+','+T, a)
        self.assertFalse(state.path(b)['listed'])
        self.assertEqual(store.connection.execute('SELECT count(*) FROM gap_ledger').fetchone()[0], 1)

    def test_t11_index_only_backoff_and_audit(self):
        env = self.environment(); store, state, processor, http, adapter = env
        a, b = '2099/a.json', '2099/b.json'
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b, records=(a,b)), 'COMPLETE')
        http.now = instant(T) + timedelta(days=6)
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b, records=(a,b)), 'COMPLETE')
        self.assertEqual(http.requests.count(adapter.profile.directory_url+b), 2)
        state.record_failure(b, stamp(http.now))
        retry = instant(state.path(b)['next_attempt'])
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b), 'PARTIAL')
        self.assertEqual(http.requests.count(adapter.profile.directory_url+b), 2)
        http.now = retry
        self.assertEqual(self.cycle(env, a+','+T, a+'\n'+b, records=(b,)), 'COMPLETE')
        self.assertEqual(http.requests.count(adapter.profile.directory_url+b), 3)

    def test_t11_listing_failures_are_atomic(self):
        for listing in ('changes.csv', 'index.txt'):
            for failure in (503, OSError('invented transfer failure'), ValueError('refused hop'), b'<html>', b'garbage'):
                with self.subTest(listing=listing, failure=failure):
                    env = self.environment(); store, state, processor, http, adapter = env
                    self.cycle(env, '2099/a.json,'+T, '2099/a.json', records=('2099/a.json',))
                    before = list(state.iter_paths(listed=False)); conformance = state.meta('conformance')
                    bodies = {'changes.csv': '2099/b.json,'+T, 'index.txt':'2099/b.json'}
                    failures = {}
                    if isinstance(failure, bytes): bodies[listing] = failure
                    else: failures[adapter.profile.directory_url+listing] = failure
                    self.assertEqual(self.cycle(env, bodies['changes.csv'], bodies['index.txt'], failures=failures), 'FAILED')
                    self.assertEqual(list(state.iter_paths(listed=False)), before)
                    self.assertEqual(state.meta('conformance'), conformance)

    def test_t11_mismatch_has_no_health_effect(self):
        env = self.environment(); store, state, processor, http, adapter = env
        changes = '2099/a.json,'+T+'\n2099/b.json,'+T
        self.assertEqual(self.cycle(env, changes, '2099/a.json\n2099/b.json', records=('2099/a.json','2099/b.json')), 'COMPLETE')
        observations = []
        for index in ('2099/a.json\n2099/b.json', '2099/a.json'):
            self.assertEqual(self.cycle(env, changes, index), 'COMPLETE')
            observations.append((store.connection.execute("SELECT cursor_digest FROM adapter_state WHERE source='cisco'").fetchone()[0],
                [tuple(r) for r in store.connection.execute("SELECT dimension,state FROM source_health WHERE source='cisco' ORDER BY dimension")]))
        self.assertEqual(observations[0], observations[1])
        self.assertEqual(state.meta('conformance')['changes_only'], 1)

    def test_t13_shared_state_and_resume(self):
        for source in ('msrc','cisco'):
            with self.subTest(source=source):
                store, state, processor, http, adapter = self.environment(source)
                resource = state.profile.resource; generation = 'a'*32
                path = '2099/a.json'
                state.observe_listing({path:[T]}, 0, T)
                member = legacy.m.normalise(legacy.raw(), path=path, directory_url=legacy.BASE)
                state.record_success(path, [T], member, T, raw_digest='invented')
                with store.transaction():
                    row = state.path(path)
                    row.update(container_generation=generation, resolution_key=member['id'])
                    state._put('path:'+path, row)
                file = Path(http.data_dir)/'members.jsonl'; file.write_text(canonical(member)+'\n')
                outcome = dict(path=resource, status=200, members_file=file, coverage_complete=False,
                               **{state.profile.generation_key:generation})
                with patch.object(processor, 'commit_staged', side_effect=RuntimeError('crash')):
                    with self.assertRaisesRegex(RuntimeError, 'crash'):
                        processor.process(source, [outcome], T, required_resources=(resource,))
                self.assertEqual(state.path(path)['staged_generation'], generation)
                self.assertIsNone(state.path(path).get('committed_generation'))
                self.assertEqual(json.loads(store.get_meta('staged_flags:'+source+':'+resource)),
                                 {'coverage_complete':False, state.profile.generation_key:generation})
                processor = AdapterStore(store, http.data_dir)
                processor.resume(T, source=source)
                self.assertEqual(state.path(path)['committed_generation'], generation)
                self.assertIsNone(store.connection.execute('SELECT cursor_tick FROM adapter_state WHERE source=?',(source,)).fetchone()[0])
                self.assertEqual(store.connection.execute('SELECT last_error FROM adapter_retries WHERE source=?',(source,)).fetchone()[0], 'PARTIAL')
                with self.assertRaises(ValueError): processor.rebaseline(source, T)
                processor.finish_cycle(source, T)
                self.assertIsNone(store.get_meta('baseline_hold:'+source))
                # Backoff and inventory gaps remain independent by source.
                state.record_failure(path, T, http_error=True)
                self.assertEqual(state.path(path)['failure'], 'http')
                state.observe_listing({}, 0, T)
                self.assertEqual(store.connection.execute('SELECT source FROM gap_ledger').fetchone()[0], source)

    def test_t13_invalid_flags_stage_nothing(self):
        for source in ('msrc','cisco','github'):
            for key, value in (('cisco_generation','A'*32), ('msrc_generation','g'*32),
                               ('cisco_generation','a'*32) if source != 'cisco' else ('msrc_generation','a'*32)):
                store, state, processor, http, adapter = self.environment()
                resource = source+'/advisories'
                processor.reconcile_required(source, (resource,), T)
                result = processor.process(source, [dict(path=resource,status=200,body='[]', **{key:value})], T, required_resources=(resource,))
                self.assertEqual(result, 'FAILED')
                self.assertEqual(store.connection.execute('SELECT count(*) FROM staged_containers').fetchone()[0], 0)
                self.assertEqual(store.connection.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)

    def test_t14_transport(self):
        from cornicen.sources.cisco_csaf import PROFILE
        from cornicen.config import DOWNLOAD_BUDGETS
        from cornicen.fetch import SOURCE_HOSTS
        from cornicen.adapters import REGISTRY
        self.assertEqual(SOURCE_HOSTS['cisco_csaf'], {'www.cisco.com'})
        self.assertEqual(DOWNLOAD_BUDGETS['cisco_csaf'], {'max_bytes':16*1024**2, 'deadline_seconds':60})
        self.assertTrue(REGISTRY['cisco'].independent)
        self.assertFalse(REGISTRY['cisco'].effective(True))
        store, state, processor, http, adapter = self.environment()
        adapter.now = instant(T); adapter.tick = T; adapter.spent = 0
        for path in ('provider-metadata.json','changes.csv','index.txt','2099/a..b.json'):
            http.bodies[PROFILE.directory_url+path] = 'invented'
            adapter._get(PROFILE.directory_url+path)
        invalid = [PROFILE.directory_url+p for p in ('2099/../a.json','index.txt/x','2099/a.json?q=1','2099/a.json#x')]
        invalid.append('https://examplecorp.invalid/.well-known/csaf/index.txt')
        for url in invalid:
            with self.assertRaises(ValueError): adapter._get(url)
            http.redirect = url
            with self.assertRaises(ValueError): adapter._get(PROFILE.directory_url+'changes.csv')
        http.redirect = None
        from cornicen.fetch import Http
        from io import BytesIO
        import socket
        requests = []
        class Opener:
            def open(self, request, timeout):
                requests.append(dict(request.header_items()))
                response = BytesIO(b'invented'); response.status=200; response.headers={}
                return response
        transport = Http('Cornicen/invented', {}, opener=Opener(), data_dir=http.data_dir,
            resolver=lambda host,port,**kwargs:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',port))])
        adapter.http = transport
        adapter._get(PROFILE.directory_url+'index.txt')
        self.assertEqual(requests, [{'User-agent':'Cornicen/invented'}])
        factories = {'cisco':lambda: self.fail('ineffective factory constructed')}
        self.assertEqual(processor.dispatch({'cisco':REGISTRY['cisco']}, {'cisco':True}, factories, T), {})


class DirectoryHttp:
    """Invented synchronous responses; reads maps, records URLs, performs no network."""
    def __init__(self, directory):
        self.data_dir = directory
        self.now = instant(T)
        self.requests, self.bodies, self.failures = [], {}, {}
        self.redirect = None

    def get(self, url, *, source, validate_hop):
        from types import SimpleNamespace
        validate_hop(url)
        self.requests.append(url)
        if self.redirect is not None:
            validate_hop(self.redirect)
        failure = self.failures.get(url)
        if isinstance(failure, BaseException): raise failure
        body = self.bodies.get(url, '')
        if isinstance(body, dict): body = canonical(body)
        return SimpleNamespace(status=failure or 200, headers={}, body=body)


# Recorded before refactoring, sequential UUIDs from 1 and RNG seed=1.
MICROSOFT_LITERALS = {'cycles': [{'outcome': {'path': 'msrc/advisories', 'status': 200, 'members_file': '<msrc-members-file>', 'coverage_complete': False, 'msrc_generation': '00000000000000000000000000000001', 'subrequest_failures': 1, 'subrequest_http_errors': 1, 'record_audit_oldest': '2099-01-01T00:00:00Z'}, 'members': '{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"}\n', 'classification': 'FAILED', 'meta': [('adapter_schema_version', '1'), ('baseline_hold:msrc', '2099-01-01T00:00:00Z'), ('baseline_hold_used:msrc', '2099-01-01T00:00:00Z'), ('baseline_pinned:msrc:msrc/advisories', '["msrc_CVE-2099-71001"]'), ('baseline_resources:msrc', '["msrc/advisories"]'), ('health_episode:msrc', '1'), ('msrc:bootstrap', '["2099/a.json","2099/b.json"]'), ('msrc:metadata', '{"document":{"distributions":[{"directory_url":"https://msrc.microsoft.com/csaf/advisories/"},{"directory_url":"https://msrc.microsoft.com/csaf/vex/"}]},"fetched_at":"2099-01-01T00:00:00Z"}'), ('msrc:path:2099/a.json', '{"attempted":true,"attempts":0,"audit_anchor":"2099-01-01T00:00:00Z","committed_generation":"00000000000000000000000000000001","container_generation":"00000000000000000000000000000001","episode":0,"failure":null,"first_seen":"2099-01-01T00:00:00Z","last_success":"2099-01-01T00:00:00Z","listed":true,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"},"next_attempt":null,"path":"2099/a.json","raw_digest":"fa67766ebe788ea83d80988ded42d1aa78368e5d8a637e11415ec59dbcec4fc6","resolution_key":"msrc_CVE-2099-71001","staged_generation":"00000000000000000000000000000001","timestamps":["2099-01-01T00:00:00Z"],"vanished":false}'), ('msrc:path:2099/b.json', '{"attempted":true,"attempts":1,"audit_anchor":"2099-01-01T00:00:00Z","episode":0,"failure":"http","first_seen":"2099-01-01T00:00:00Z","last_success":null,"listed":true,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":null,"next_attempt":"2099-01-01T00:00:51.224742Z","path":"2099/b.json","raw_digest":null,"timestamps":[],"vanished":false}'), ('msrc:requests', '["2099-01-01T00:00:00Z","2099-01-01T00:00:00Z","2099-01-01T00:00:00Z","2099-01-01T00:00:00Z"]'), ('record_audit_oldest:msrc', '2099-01-01T00:00:00Z'), ('record_projection_version', '1'), ('required_since:msrc', '{"msrc/advisories":"2099-01-01T00:00:00Z"}'), ('schema_version', '1'), ('staged_flags:msrc:msrc/advisories', '{"coverage_complete":false,"msrc_generation":"00000000000000000000000000000001","record_audit_oldest":"2099-01-01T00:00:00Z","subrequest_failures":1,"subrequest_http_errors":1}')], 'gaps': []}, {'outcome': {'path': 'msrc/advisories', 'status': 200, 'members_file': '<msrc-members-file>', 'coverage_complete': True, 'msrc_generation': '00000000000000000000000000000003', 'subrequest_failures': 0, 'subrequest_http_errors': 0, 'record_audit_oldest': '2099-01-01T00:00:00Z'}, 'members': '{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"}\n{"cves":["CVE-2099-71002"],"evidence":[],"facets":[{"cve":"CVE-2099-71002","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71002","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"}\n', 'classification': 'COMPLETE', 'meta': [('adapter_schema_version', '1'), ('baseline_hold_used:msrc', '2099-01-01T00:00:00Z'), ('baseline_pinned:msrc:msrc/advisories', '["msrc_CVE-2099-71001"]'), ('baseline_resources:msrc', '["msrc/advisories"]'), ('health_episode:msrc', '2'), ('msrc:bootstrap', '["2099/a.json","2099/b.json"]'), ('msrc:metadata', '{"document":{"distributions":[{"directory_url":"https://msrc.microsoft.com/csaf/advisories/"},{"directory_url":"https://msrc.microsoft.com/csaf/vex/"}]},"fetched_at":"2099-01-01T00:00:00Z"}'), ('msrc:path:2099/a.json', '{"attempted":true,"attempts":0,"audit_anchor":"2099-01-01T00:00:00Z","committed_generation":"00000000000000000000000000000003","container_generation":"00000000000000000000000000000003","episode":0,"failure":null,"first_seen":"2099-01-01T00:00:00Z","last_success":"2099-01-01T00:00:00Z","listed":true,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"},"next_attempt":null,"path":"2099/a.json","raw_digest":"fa67766ebe788ea83d80988ded42d1aa78368e5d8a637e11415ec59dbcec4fc6","resolution_key":"msrc_CVE-2099-71001","staged_generation":"00000000000000000000000000000003","timestamps":["2099-01-01T00:00:00Z"],"vanished":false}'), ('msrc:path:2099/b.json', '{"attempted":true,"attempts":0,"audit_anchor":"2099-01-01T01:00:00Z","committed_generation":"00000000000000000000000000000003","container_generation":"00000000000000000000000000000003","episode":0,"failure":null,"first_seen":"2099-01-01T00:00:00Z","last_success":"2099-01-01T01:00:00Z","listed":true,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":{"cves":["CVE-2099-71002"],"evidence":[],"facets":[{"cve":"CVE-2099-71002","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71002","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"},"next_attempt":null,"path":"2099/b.json","raw_digest":"bc726c669da6441be0a7cf7d6f16280f2c9d9db1419baf2b830c7b2ae44220f2","resolution_key":"msrc_CVE-2099-71002","staged_generation":"00000000000000000000000000000003","timestamps":["2099-01-01T00:00:00Z"],"vanished":false}'), ('msrc:requests', '["2099-01-01T01:00:00Z","2099-01-01T01:00:00Z"]'), ('record_audit_oldest:msrc', '2099-01-01T00:00:00Z'), ('record_projection_version', '1'), ('required_since:msrc', '{"msrc/advisories":"2099-01-01T00:00:00Z"}'), ('schema_version', '1')], 'gaps': []}, {'outcome': {'path': 'msrc/advisories', 'status': 200, 'members_file': '<msrc-members-file>', 'coverage_complete': True, 'msrc_generation': '00000000000000000000000000000006', 'subrequest_failures': 0, 'subrequest_http_errors': 0, 'record_audit_oldest': '2099-01-01T00:00:00Z'}, 'members': '{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"}\n', 'classification': 'PARTIAL', 'meta': [('adapter_schema_version', '1'), ('baseline_hold_used:msrc', '2099-01-01T00:00:00Z'), ('baseline_pinned:msrc:msrc/advisories', '["msrc_CVE-2099-71001"]'), ('baseline_resources:msrc', '["msrc/advisories"]'), ('health_episode:msrc', '3'), ('msrc:bootstrap', '["2099/a.json","2099/b.json"]'), ('msrc:metadata', '{"document":{"distributions":[{"directory_url":"https://msrc.microsoft.com/csaf/advisories/"},{"directory_url":"https://msrc.microsoft.com/csaf/vex/"}]},"fetched_at":"2099-01-01T00:00:00Z"}'), ('msrc:path:2099/a.json', '{"attempted":true,"attempts":0,"audit_anchor":"2099-01-01T00:00:00Z","committed_generation":"00000000000000000000000000000006","container_generation":"00000000000000000000000000000006","episode":0,"failure":null,"first_seen":"2099-01-01T00:00:00Z","last_success":"2099-01-01T00:00:00Z","listed":true,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":{"cves":["CVE-2099-71001"],"evidence":[],"facets":[{"cve":"CVE-2099-71001","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71001","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"},"next_attempt":null,"path":"2099/a.json","raw_digest":"fa67766ebe788ea83d80988ded42d1aa78368e5d8a637e11415ec59dbcec4fc6","resolution_key":"msrc_CVE-2099-71001","staged_generation":"00000000000000000000000000000006","timestamps":["2099-01-01T00:00:00Z"],"vanished":false}'), ('msrc:path:2099/b.json', '{"attempted":true,"attempts":0,"audit_anchor":"2099-01-01T01:00:00Z","committed_generation":"00000000000000000000000000000003","container_generation":"00000000000000000000000000000003","episode":1,"failure":null,"first_seen":"2099-01-01T00:00:00Z","last_success":"2099-01-01T01:00:00Z","listed":false,"listed_timestamps":["2099-01-01T00:00:00Z"],"member":{"cves":["CVE-2099-71002"],"evidence":[],"facets":[{"cve":"CVE-2099-71002","evidence":[{"binding":"watch","fix":"available","product_id":"1","range":{"csaf":"<9.4.1200.8"},"scheme":"opaque","status":"known_affected"},{"binding":"watch","fix":"9.4.1200.8","product_id":"12013","scheme":"opaque","status":"first_fixed"}],"ids":[],"products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows"}],"title":"Contoso Sample Agent Information Disclosure Vulnerability"}],"id":"msrc_CVE-2099-71002","products":[{"id":"1","name":"Microsoft:Contoso Sample Agent for Windows"},{"id":"12013","name":"Microsoft:Contoso Sample Agent for Windows","version":"9.4.1200.8"}],"published":"2026-10-13T07:00:00.000Z","title":"Contoso Sample Agent Information Disclosure Vulnerability","updated":"2026-11-02T08:00:00.000Z","url":"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2099-71001"},"next_attempt":null,"path":"2099/b.json","raw_digest":"bc726c669da6441be0a7cf7d6f16280f2c9d9db1419baf2b830c7b2ae44220f2","resolution_key":"msrc_CVE-2099-71002","staged_generation":"00000000000000000000000000000003","timestamps":["2099-01-01T00:00:00Z"],"vanished":true}'), ('msrc:requests', '["2099-01-01T02:00:00Z"]'), ('record_audit_oldest:msrc', '2099-01-01T00:00:00Z'), ('record_projection_version', '1'), ('required_since:msrc', '{"msrc/advisories":"2099-01-01T00:00:00Z"}'), ('schema_version', '1'), ('staged_flags:msrc:msrc/advisories', '{"coverage_complete":true,"msrc_generation":"00000000000000000000000000000006","record_audit_oldest":"2099-01-01T00:00:00Z","subrequest_failures":0,"subrequest_http_errors":0}')], 'gaps': [('msrc', '2099-01-01T02:00:00Z', 'inventory removal #1cb5d832c791 e1', None)]}], 'stages': ['{"coverage_complete":false,"msrc_generation":"00000000000000000000000000000001","record_audit_oldest":"2099-01-01T00:00:00Z","subrequest_failures":1,"subrequest_http_errors":1}', '{"coverage_complete":true,"msrc_generation":"00000000000000000000000000000003","record_audit_oldest":"2099-01-01T00:00:00Z","subrequest_failures":0,"subrequest_http_errors":0}', '{"coverage_complete":true,"msrc_generation":"00000000000000000000000000000006","record_audit_oldest":"2099-01-01T00:00:00Z","subrequest_failures":0,"subrequest_http_errors":0}'], 'requests': [{'action': 1, 'operation': 'metadata', 'path': '', 'url': 'https://msrc.microsoft.com/csaf/provider-metadata.json', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 1, 'operation': 'listing', 'path': '', 'url': 'https://msrc.microsoft.com/csaf/advisories/changes.csv', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 1, 'operation': 'record', 'path': '2099/a.json', 'url': 'https://msrc.microsoft.com/csaf/advisories/2099/a.json', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 1, 'operation': 'record', 'path': '2099/b.json', 'url': 'https://msrc.microsoft.com/csaf/advisories/2099/b.json', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 2, 'operation': 'listing', 'path': '', 'url': 'https://msrc.microsoft.com/csaf/advisories/changes.csv', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 2, 'operation': 'record', 'path': '2099/b.json', 'url': 'https://msrc.microsoft.com/csaf/advisories/2099/b.json', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}, {'action': 3, 'operation': 'listing', 'path': '', 'url': 'https://msrc.microsoft.com/csaf/advisories/changes.csv', 'method': 'GET', 'headers': {'User-agent': 'Cornicen/test'}}]}

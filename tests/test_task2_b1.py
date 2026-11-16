# script-purpose: Verify Microsoft listing, durable state and streamed store contracts offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task2_b1.py
"""Read invented listings and records; write temporary SQLite and JSONL files.

Run PYTHONPATH=src python3 -m unittest tests.test_task2_b1 -v; exit 0/1.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import Mock, patch

from cornicen import adapters
from cornicen.adapterstore import AdapterStore, canonical
from cornicen.config import DOWNLOAD_BUDGETS, SecretToken
from cornicen.fetch import Http, _destination
from cornicen.store import Store
from tests.test_f1 import member, T

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'msrc/advisories'
LATER = '2099-01-02T00:00:00Z'


class Task2B1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.p = AdapterStore(self.store, self.tmp.name)

    def members(self):
        return [member() | dict(id=f'FIX-2099-000{n}', products=[dict(id='p', name='examplecorp:widget')],
                evidence=[dict(product_id='p', scheme='dotted', version='1.0', status='known_affected')]) for n in range(1, 4)]

    def outcome(self, members=None, **flags):
        path = Path(self.tmp.name) / 'members.jsonl'
        path.write_text(''.join(canonical(m)+'\n' for m in (self.members() if members is None else members)))
        return dict(path=RESOURCE, status=200, members_file=path) | flags

    def process(self, outcome, tick=T):
        return self.p.process('msrc', [outcome], tick, required_resources=(RESOURCE,))

    def cursor(self):
        return tuple(self.db.execute("SELECT cursor_tick,cursor_digest FROM adapter_state WHERE source='msrc'").fetchone())

    def health(self, dimension):
        return self.db.execute('SELECT state FROM source_health WHERE source=? AND dimension=?', ('msrc', dimension)).fetchone()[0]

    def test_t10_listing(self):
        from cornicen.sources.msrc_csaf import parse_listing
        a = '2099/a.json'
        body = f'"{a}","2099-01-01T01:00:00+01:00"\n{a},{T}\n{a},2099-01-02T00:00:00Z\n2099/A.json,{T}\n'
        listing, invalid = parse_listing(body.encode())
        self.assertEqual(invalid, 0)
        self.assertEqual(listing, {a: [T, LATER], '2099/A.json': [T]})
        for path in ('../a.json', '2099/a#x.json', '2099/a?x.json', '2099/a%20x.json', '2099/../a.json'):
            with self.subTest(path=path):
                self.assertEqual(parse_listing(f'{a},{T}\n{path},{T}')[1], 1)
        self.assertEqual(parse_listing(f'{a},2099-01-01T00:00:00'), ({}, 1))
        self.assertEqual(parse_listing(f'{a},{T},extra'), ({}, 1))
        for row in (f'{a},{T},extra', f'{a},2099-01-01T00:00:00', 'one field'):
            self.assertEqual(parse_listing(f'{a},{T}\n{row}')[1], 1)
        for body in ('', '\n ', '<html>SPA</html>', 'not csv', '"unterminated'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_listing(body)
        listing, invalid = parse_listing((ROOT/'tests/fixtures/msrc/changes_sample.csv').read_bytes())
        self.assertEqual((len(listing), invalid), (50, 0))

    def test_t11_stream_matches_body(self):
        records = self.members()
        self.assertEqual(self.process(dict(path=RESOURCE, status=200, body=canonical(records))), 'COMPLETE')
        expected = {table: [tuple(r) for r in self.db.execute('SELECT * FROM '+table)]
                    for table in ('manifests', 'manifest_members', 'events', 'advisory_evidence')}
        self.store.connection.close()
        self.store = Store(Path(self.tmp.name)/'stream-db'); self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection; self.p = AdapterStore(self.store, self.tmp.name)
        outcome = self.outcome(records)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole file read')):
            self.assertEqual(self.process(outcome), 'COMPLETE')
        self.assertFalse(outcome['members_file'].exists())
        self.assertIsNone(self.db.execute('SELECT 1 FROM resource_cache').fetchone())
        for table, rows in expected.items():
            self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM '+table)], rows)
        self.assertIsNone(self.store.get_meta('staged_flags:msrc:'+RESOURCE))
        self.assertGreater(len(expected['advisory_evidence']), 0)
        self._assert_stream_memory()

    def crash_stage(self, outcome, tick=LATER):
        with patch.object(self.p, 'commit_staged', side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):
                self.process(outcome, tick)
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM staged_containers').fetchone())

    def test_t11_resume_flags(self):
        self.assertEqual(self.process(dict(path=RESOURCE, status=200, body=canonical(self.members()))), 'COMPLETE')
        cursor = self.cursor()
        self.crash_stage(self.outcome(coverage_complete=False))
        self.assertEqual(json.loads(self.store.get_meta('staged_flags:msrc:'+RESOURCE)), {'coverage_complete': False})
        self.p = AdapterStore(self.store, self.tmp.name)
        self.p.resume(LATER)
        self.assertEqual(self.cursor(), cursor)
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM adapter_retries').fetchone())
        with self.assertRaises(ValueError):
            self.p.rebaseline('msrc', LATER)
        self.assertEqual(self.cursor(), cursor)

    def test_t11_resume_stream(self):
        self.crash_stage(self.outcome(), T)
        with patch.object(self.p, 'process', wraps=self.p.process) as process:
            self.p.resume(T)
        self.assertEqual(self.cursor()[0], T)
        recovered = process.call_args.args[1][0]
        self.assertIn('members_file', recovered)
        self.assertNotIn('body', recovered)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 3)

    def test_t11_github_resume_base_state(self):
        # Literal oracle from the base commit_staged failure path: no second
        # process call, cache write, health update, publication or acceptance.
        for case, checksum, integrity, error, baseline in (
            ('tampered', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
             'failed', 'container digest mismatch', []),
            ('missing', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
             'failed', 'unreadable staged container', []),
            ('partial', '3a47f26f08594e95164663790d0142770803ef9243f8a183c6a73832a0a8b252',
             'intact', 'PARTIAL', [('github', 'GHSA-2345-6789-cfgh')]),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                store = Store(Path(directory)/'db'); store.migrate()
                self.addCleanup(store.connection.close)
                p = AdapterStore(store, directory, rng=Mock(uniform=Mock(return_value=1)))
                db = store.connection
                resource = 'github/example/advisories'
                records = [{'id': 'GHSA-2345-6789-cfgh', 'mapping_error': 'invented'}] if case == 'partial' else []
                with patch.object(p, 'commit_staged', side_effect=RuntimeError('crash')):
                    with self.assertRaises(RuntimeError):
                        p.process('github', [dict(path=resource, status=200, body=canonical(records))],
                                  T, required_resources=(resource,))
                stage_path = Path(db.execute('SELECT path FROM staged_containers').fetchone()[0])
                if case == 'tampered': stage_path.write_text('{}\n')
                if case == 'missing': stage_path.unlink()
                p = AdapterStore(store, directory, rng=Mock(uniform=Mock(return_value=1)))
                with patch.object(p, 'process', wraps=p.process) as process:
                    p.resume(T, source='github')
                process.assert_not_called()
                expected = {
                    'staged_containers': [('github', resource, str(stage_path), checksum, integrity, T)],
                    'adapter_retries': [('github', resource, 1, '2099-01-01T00:01:00Z', error)],
                    'manifests': [('github', resource, '', '[]', T, None)],
                    'resource_cache': [], 'source_health': [],
                    'adapter_state': [('github', None, None, T, None, 0, None)],
                    'baseline_members': baseline,
                }
                for table, rows in expected.items():
                    self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM '+table)], rows, table)
                self.assertEqual(store.get_meta('baseline_resources:github'), '["github/example/advisories"]')
                self.assertEqual(store.get_meta('baseline_pinned:github:'+resource),
                                 '["GHSA-2345-6789-cfgh"]' if case == 'partial' else None)
                self.assertIsNone(store.get_meta('staged_flags:github:'+resource))
                self.assertIsNone(store.get_meta('baseline_hold:github'))
                self.assertIsNone(store.get_meta('baseline_hold_used:github'))
                with self.assertRaises(ValueError):
                    p.rebaseline('github', LATER)
                self.assertEqual(db.execute('SELECT integrity FROM staged_containers').fetchone()[0], integrity)

    def test_t11_github_resume_required_container_order(self):
        self._assert_resume_required_container_order('github', streamed=False)

    def test_t11_stream_resume_required_container_order(self):
        self._assert_resume_required_container_order('msrc', streamed=True)

    def _assert_resume_required_container_order(self, source, *, streamed):
        # Base resume commits ALL staged containers before processing COMPLETE
        # ones. A digest failure never pins its resource, so baseline stays open.
        # A mapping failure pins and quarantines its ID, resolving the baseline;
        # the COMPLETE resource then emits the summary despite the pending retry.
        for case in ('tampered', 'partial'):
            for failing_first in (False, True):
                with self.subTest(source=source, case=case, failing_first=failing_first), \
                        tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    store = Store(Path(directory)/'db'); store.migrate()
                    self.addCleanup(store.connection.close)
                    db = store.connection
                    p = AdapterStore(store, directory, rng=Mock(uniform=Mock(return_value=1)))
                    resources = (source+'/a/advisories', source+'/b/advisories')
                    bad = resources[0 if failing_first else 1]
                    good = resources[1 if failing_first else 0]
                    p.ensure(source, T)
                    p.reconcile_required(source, resources, T)
                    # Simulate a crash after both containers are durably staged,
                    # before either commit. Resource names fix the SQLite order.
                    for resource in resources:
                        records = ([dict(id='GHSA-2345-6789-cfgh', mapping_error='invented')]
                                   if resource == bad and case == 'partial' else [])
                        path = p.stage_members(source, resource, iter(records), T,
                                               flags={} if streamed else None)
                        if resource == bad and case == 'tampered':
                            path.write_text('{}\n')
                    p = AdapterStore(store, directory, rng=Mock(uniform=Mock(return_value=1)))
                    p.resume(T, source=source)
                    expected = {
                        "SELECT state,detail FROM source_health WHERE dimension='completeness'":
                            [('unhealthy', 'retry pending')],
                        'SELECT baseline_complete FROM adapter_state':
                            [(0,)] if case == 'tampered' else [(1,)],
                        "SELECT key,watch_id,record_id,type,episode,created_at FROM events WHERE type='baseline'":
                            [] if case == 'tampered' else
                            [('|baseline:'+source+'|baseline|1', '', 'baseline:'+source, 'baseline', 1, T)],
                        'SELECT pair_key,urgency,reasons_json,json_extract(body_json,\'$.record_id\'),'
                        'json_extract(body_json,\'$.watch_id\'),json_extract(body_json,\'$.episode\'),'
                        'due_at,attempts,next_attempt_at,sent_at FROM outbox':
                            [] if case == 'tampered' else
                            [('|baseline:'+source, 'normal', '["baseline"]', 'baseline:'+source, '', 1,
                              '2099-01-01T00:00:00+00:00', 0, None, None)],
                        'SELECT source,resource,attempts,next_attempt_at,last_error FROM adapter_retries':
                            [(source, bad, 1, '2099-01-01T00:01:00Z',
                              'container digest mismatch' if case == 'tampered' else 'PARTIAL')],
                        'SELECT source,resource,digest,integrity,staged_at FROM staged_containers':
                            [(source, bad,
                              'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                              if case == 'tampered' else
                              '3a47f26f08594e95164663790d0142770803ef9243f8a183c6a73832a0a8b252',
                              'failed' if case == 'tampered' else 'intact', T)],
                    }
                    for query, rows in expected.items():
                        with self.subTest(query=query):
                            self.assertEqual([tuple(r) for r in db.execute(query)], rows)
                    self.assertIsNone(db.execute('SELECT 1 FROM staged_containers WHERE resource=?', (good,)).fetchone())
                    self.assertTrue(Path(db.execute('SELECT path FROM staged_containers').fetchone()[0]).is_file())

    def test_t11_stream_resume_bad_file(self):
        self.crash_stage(self.outcome(), T)
        path = Path(self.db.execute('SELECT path FROM staged_containers').fetchone()[0])
        path.write_text('{}\n')
        self.p.resume(T)
        self.assertEqual(self.db.execute('SELECT integrity FROM staged_containers').fetchone()[0], 'failed')
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0], 'container digest mismatch')
        self.db.execute('DELETE FROM adapter_retries')
        self.db.execute("UPDATE staged_containers SET integrity='intact'")
        self.db.commit()
        path.unlink()
        self.p.resume(T)
        self.assertEqual(self.db.execute('SELECT integrity FROM staged_containers').fetchone()[0], 'failed')
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0], 'unreadable staged container')

    def test_t12_failure_counts(self):
        self.assertEqual(self.process(self.outcome(subrequest_failures=1, coverage_complete=False)), 'PARTIAL')
        self.assertEqual(self.health('fetch'), 'unhealthy')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 3)
        self.assertIsNone(self.cursor()[0])
        self.assertEqual(self.process(self.outcome(subrequest_failures=1, subrequest_http_errors=1)), 'FAILED')
        self.assertIsNone(self.cursor()[0])
        mixed = self.members() + [dict(id='INVALID-2099-0001', mapping_error='invented')]
        self.assertEqual(self.process(self.outcome(mixed, subrequest_failures=1, subrequest_http_errors=1)), 'FAILED')
        self.assertIsNone(self.cursor()[0])
        self.assertEqual(self.process(self.outcome()), 'COMPLETE')
        self.assertEqual(self.health('fetch'), 'healthy')

    def test_t12_failure_count_alone(self):
        self.assertEqual(self.process(self.outcome(subrequest_failures=2, coverage_complete=True)), 'PARTIAL')
        self.assertEqual(self.health('fetch'), 'unhealthy')
        self.assertIsNone(self.cursor()[0])
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 3)

    def test_t12_http_failure_with_gap(self):
        self.p.gap('msrc', T, 'invented gap')
        self.assertEqual(self.process(self.outcome(subrequest_failures=1, subrequest_http_errors=1)), 'FAILED')
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0], 'FAILED')
        self.assertIsNone(self.cursor()[0])

    def test_t11_body_flags_resume(self):
        flags = dict(coverage_complete=False, subrequest_failures=2,
                     subrequest_http_errors=1, record_audit_oldest='2098-12-25T00:00:00Z')
        self.crash_stage(dict(path=RESOURCE, status=200, body=canonical(self.members())) | flags, T)
        self.assertIsNotNone(self.store.get_meta('staged_flags:msrc:'+RESOURCE))
        self.assertEqual(json.loads(self.store.get_meta('staged_flags:msrc:'+RESOURCE)), flags)
        with patch.object(self.p, 'process', wraps=self.p.process) as process:
            self.p.resume(T)
        restored = process.call_args.args[1][0]
        self.assertEqual({key: restored[key] for key in flags}, flags)
        self.assertIsNone(self.cursor()[0])
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0], 'FAILED')
        self.assertEqual(self.store.get_meta('record_audit_oldest:msrc'), flags['record_audit_oldest'])

    def test_t11_members_file_cleanup(self):
        for case in ('non-2xx', 'bad member line'):
            with self.subTest(case=case):
                outcome = self.outcome()
                if case == 'non-2xx':
                    outcome['status'] = 503
                else:
                    outcome['members_file'].write_text(canonical(self.members()[0])+'\nnot json\n')
                self.assertEqual(self.process(outcome), 'FAILED')
                self.assertFalse(outcome['members_file'].exists())
                self.assertIsNone(self.db.execute('SELECT 1 FROM staged_containers').fetchone())

    def _assert_stream_memory(self):
        # A repeated large member keeps advisory state small while the JSONL
        # input exceeds the Python allocation ceiling by more than fourfold.
        outcome = self.outcome()
        lines = [canonical(m | dict(stream_padding='invented ' * 2048))+'\n' for m in self.members()]
        with outcome['members_file'].open('w') as stream:
            for n in range(1500):
                stream.write(lines[n % 3])
        real_open = Path.open
        class LinesOnly:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def __iter__(self): return self
            def __next__(self): return next(self.stream)
            def __length_hint__(self): raise AssertionError('materialised file')
            def read(self, *args): raise AssertionError('whole file read')
            def readlines(self, *args): raise AssertionError('whole file readlines')
        def guarded_open(path, mode='r', *args, **kwargs):
            stream = real_open(path, mode, *args, **kwargs)
            return LinesOnly(stream) if path.suffix == '.jsonl' and mode == 'rb' else stream
        tracemalloc.start()
        try:
            with patch.object(Path, 'open', guarded_open):
                self.assertEqual(self.process(outcome), 'COMPLETE')
            self.assertLess(tracemalloc.get_traced_memory()[1], 6 * 1024**2)
        finally:
            tracemalloc.stop()

    def test_t12_invalid_flags(self):
        for key, values in (('subrequest_failures', (True, -1, '1', 1.0, None)),
                            ('subrequest_http_errors', (True, -1, '1', 1.0, None, 2)),
                            ('record_audit_oldest', (None, 1, False, '2099-01-01T00:00:00', 'bad'))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.process(self.outcome(**{key: value})), 'FAILED')
                    self.assertEqual(self.health('fetch'), 'unhealthy')
                    self.assertFalse((Path(self.tmp.name) / 'members.jsonl').exists())
                    self.assertIsNone(self.db.execute('SELECT 1 FROM advisories').fetchone())
                    self.assertIsNone(self.db.execute('SELECT 1 FROM staged_containers').fetchone())

    def test_t12_http_failure_resume(self):
        self.crash_stage(self.outcome(subrequest_failures=1, subrequest_http_errors=1), T)
        self.p.resume(T)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 3)
        self.assertIsNone(self.cursor()[0])
        self.assertEqual(self.health('fetch'), 'unhealthy')
        self.assertEqual(self.db.execute('SELECT last_error FROM adapter_retries').fetchone()[0], 'FAILED')

    def test_t12_record_audit(self):
        for anchor, expected in (('2098-12-25T00:00:00Z', 'unhealthy'), (None, 'healthy'), ('2098-12-26T00:00:00Z', 'healthy')):
            flags = {} if anchor is None else dict(record_audit_oldest=anchor)
            self.assertEqual(self.process(dict(path=RESOURCE, status=200, body=canonical([])) | flags), 'COMPLETE')
            self.p.finish_cycle('msrc', T)
            self.assertEqual(self.health('audit'), expected)

    def test_t12_baseline_hold(self):
        self.p.set_baseline_hold('msrc', T)
        self.assertEqual(self.process(self.outcome()), 'COMPLETE')
        self.assertEqual(self.p.summaries(), [])
        self.p.pin_baseline_member('msrc', 'LATE-2099-0001', T)
        self.p.release_baseline_hold('msrc', T)
        self.p.finish_cycle('msrc', T)
        self.assertEqual(len(self.p.summaries()), 1)
        self.p.pin_baseline_member('msrc', 'LATE-2099-0002', LATER)
        self.p.pin_baseline_member('github', 'GHSA-2345-6789-cfgh', T)
        self.assertEqual([r[0] for r in self.db.execute("SELECT source_id FROM baseline_members WHERE source_id LIKE 'LATE-%' ORDER BY source_id")], ['LATE-2099-0001', 'LATE-2099-0002'])
        self.assertIsNone(self.db.execute("SELECT 1 FROM baseline_members WHERE source='github'").fetchone())

    def test_t12_empty_dispatch(self):
        entry = replace(adapters.REGISTRY['msrc'], gate='met', independent=True)
        adapter = Mock()
        adapter.required_resources.return_value = (RESOURCE,)
        adapter.poll.return_value = [dict(path=RESOURCE, status=200, body='[]')]
        adapter.audit.return_value = (); adapter.retry.return_value = ()
        self.process(dict(path=RESOURCE, status=200, body='[]'), '2098-12-01T00:00:00Z')
        self.p.retry('msrc', RESOURCE, '2098-12-01T00:00:00Z', 'FAILED')
        # Keep old manifest and due retry while poll emits no new outcome.
        adapter.poll.return_value = ()
        with patch.object(self.p, 'process', wraps=self.p.process) as process:
            self.p.dispatch({'msrc': entry}, {'msrc': True}, {'msrc': lambda: adapter}, T)
        self.assertEqual(process.call_count, 1)
        adapter.audit.assert_called_once(); adapter.retry.assert_called_once()

    def test_s3_acknowledged_absentees(self):
        records = self.members()
        self.process(dict(path=RESOURCE, status=200, body=canonical(records)))
        small = dict(path=RESOURCE, status=200, body=canonical(records[:1]))
        self.assertEqual(self.process(small, LATER), 'PARTIAL')
        self.p.rebaseline('msrc', LATER)
        self.assertEqual(self.p.known_members('msrc', RESOURCE), {records[0]['id']})
        self.assertEqual(self.process(small, LATER), 'COMPLETE')
        self.assertEqual(self.process(dict(path=RESOURCE, status=200, body=canonical(records)), LATER), 'COMPLETE')
        self.assertEqual(self.process(small, LATER), 'PARTIAL')

    def test_s3_successive_shrinking_rebaselines(self):
        records = self.members()
        self.process(dict(path=RESOURCE, status=200, body=canonical(records)))
        for size, absent in ((2, ['FIX-2099-0003']), (1, ['FIX-2099-0002', 'FIX-2099-0003'])):
            outcome = dict(path=RESOURCE, status=200, body=canonical(records[:size]))
            self.assertEqual(self.process(outcome, LATER), 'PARTIAL')
            self.p.rebaseline('msrc', LATER)
            self.assertEqual(json.loads(self.store.get_meta('ack_absent:msrc:'+RESOURCE)), absent)
            self.assertEqual(self.process(outcome, LATER), 'COMPLETE')

    def test_bootstrap_requires_clean_nonempty_listing(self):
        from cornicen.sources.msrc_csaf import MsrcState
        state = MsrcState(self.store)
        for listing, invalid in (({'2099/a.json': [T]}, 1), ({}, 2), ({}, 0)):
            with self.subTest(listing=listing, invalid=invalid):
                state.observe_listing(listing, invalid, T)
                self.assertIsNone(state.meta('bootstrap'))
                self.assertIsNone(self.store.get_meta('baseline_hold:msrc'))
                self.assertIsNone(self.store.get_meta('baseline_hold_used:msrc'))
        clean = {'2099/b.json': [LATER], '2099/c.json': [LATER]}
        state.observe_listing(clean, 0, LATER)
        self.assertEqual(state.meta('bootstrap'), ['2099/b.json', '2099/c.json'])
        self.assertEqual(self.store.get_meta('baseline_hold:msrc'), LATER)
        state.observe_listing({'2099/d.json': [LATER]}, 0, LATER)
        self.assertEqual(state.meta('bootstrap'), ['2099/b.json', '2099/c.json'])

    def test_state_cache_bootstrap_removals(self):
        from cornicen.sources.msrc_csaf import MsrcState
        state = MsrcState(self.store)
        listing = {'2099/b.json': [T], '2099/a.json': [T]}
        state.observe_listing(listing, 0, T)
        self.assertEqual(state.meta('bootstrap'), sorted(listing))
        state.observe_listing({'2099/c.json': [T]}, 1, LATER)
        self.assertEqual([r['path'] for r in state.iter_paths()], sorted(list(listing)+['2099/c.json']))
        state.record_success('2099/a.json', [T], member(), T, raw_digest='abc')
        state.record_failure('2099/b.json', T, http_error=True)
        self.assertEqual(state.path('2099/a.json')['audit_anchor'], T)
        self.assertEqual(state.path('2099/b.json')['audit_anchor'], T)
        self.assertEqual(state.path('2099/b.json')['failure'], 'http')
        self.assertEqual(state.path('2099/b.json')['attempts'], 1)
        self.assertEqual([r['path'] for r in state.iter_cache()], ['2099/a.json'])
        self.assertTrue(self.db.execute("SELECT 1 FROM baseline_members WHERE source='msrc' AND source_id=?", (member()['id'],)).fetchone())
        for tick in (T, LATER):
            state.observe_listing({}, 0, tick)
            state.observe_listing(listing, 0, tick)
        reasons = [r[0] for r in self.db.execute('SELECT reason FROM gap_ledger')]
        self.assertEqual(len(reasons), 5)  # a,b,c first departure; a,b second departure.
        self.assertEqual(len(set(reasons)), 5)
        state.record_success('2099/b.json', [T], {'id': None, 'mapping_error': 'bad'}, LATER)
        self.assertIsNone(state.path('2099/b.json')['failure'])
        self.assertEqual(state.path('2099/b.json')['audit_anchor'], LATER)
        state.charge(T); state.set_hold(LATER); state.set_metadata({'directory_url': 'invented'}, T)
        recovered = MsrcState(self.store)
        self.assertEqual(recovered.meta('requests'), [T])
        self.assertEqual(recovered.meta('rate_hold_until'), LATER)
        self.assertEqual(recovered.meta('metadata')['fetched_at'], T)
        # Nested writes must roll back together at the durable state boundary.
        before = list(state.iter_paths(listed=False))
        gap_count = self.db.execute('SELECT count(*) FROM gap_ledger').fetchone()[0]
        original_gap = state.adapter_store.gap
        def interrupted_gap(*args):
            original_gap(*args)
            raise RuntimeError('crash')
        with patch.object(state.adapter_store, 'gap', side_effect=interrupted_gap):
            with self.assertRaises(RuntimeError):
                state.observe_listing({}, 0, LATER)
        self.assertEqual(list(state.iter_paths(listed=False)), before)
        self.assertEqual(self.db.execute('SELECT count(*) FROM gap_ledger').fetchone()[0], gap_count)
        original_pin = state.adapter_store.pin_baseline_member
        def interrupted_pin(*args):
            original_pin(*args)
            raise RuntimeError('crash')
        with patch.object(state.adapter_store, 'pin_baseline_member', side_effect=interrupted_pin):
            with self.assertRaises(RuntimeError):
                state.record_success('2099/a.json', [LATER], member() | dict(id='LATE-2099-0010'), LATER)
        self.assertEqual(list(state.iter_paths(listed=False)), before)
        self.assertIsNone(self.db.execute("SELECT 1 FROM baseline_members WHERE source_id='LATE-2099-0010'").fetchone())
        state.rng = Mock()
        state.rng.uniform.return_value = 1.2
        for _ in range(12):
            state.record_failure('2099/a.json', T)
        # Six hours is the nominal ceiling, before the specified jitter.
        self.assertEqual(state.path('2099/a.json')['next_attempt'], '2099-01-01T07:12:00Z')

    def test_transport_policy(self):
        self.assertTrue(adapters.REGISTRY['msrc'].independent)
        self.assertEqual(_destination('https://msrc.microsoft.com/csaf/advisories/changes.csv', 'msrc_csaf'), 'msrc.microsoft.com')
        for url in ('https://examplecorp.invalid/a', 'http://msrc.microsoft.com/a'):
            with self.assertRaises(ValueError): _destination(url, 'msrc_csaf')
        self.assertEqual(DOWNLOAD_BUDGETS['msrc_csaf'], dict(max_bytes=16*1024**2, deadline_seconds=60))
        class Response:
            status = 200
            headers = {}
            def read(self, size): return b''
            def __enter__(self): return self
            def __exit__(self, *args): pass
        opener = Mock(spec=['open'])
        opener.open.return_value = Response()
        http = Http('Invented-UA', {}, opener=opener, resolver=lambda *args, **kwargs: [(2, 1, 6, '', ('8.8.8.8', 443))], github_token=SecretToken('invented'))
        http.get('https://msrc.microsoft.com/csaf/advisories/changes.csv', source='msrc_csaf')
        headers = dict(opener.open.call_args.args[0].header_items())
        self.assertEqual(headers['User-agent'], 'Invented-UA')
        self.assertNotIn('Authorization', headers)

    def test_t13_gate_and_github_guard(self):
        before = adapters.status()
        self.assertEqual(before['msrc'], dict(setting=False, gate='not met', gate_name='M', effective=False))
        self.assertIn('msrc: disabled: gate M not met (setting off)', adapters.status_lines(adapters.settings({})))
        factory = Mock()
        self.p.dispatch(adapters.REGISTRY, {'msrc': True}, {'msrc': factory}, T)
        factory.assert_not_called()
        self.assertIsNone(self.db.execute('SELECT 1 FROM adapter_state').fetchone())
        self.assertEqual(self.p.process('github', [dict(path='github/example/advisories', status=200, body=canonical(self.members()))], T,
                                      required_resources=('github/example/advisories',)), 'COMPLETE')
        self.p.finish_cycle('github', T)
        self.assertEqual(dict(self.db.execute("SELECT dimension,state FROM source_health WHERE source='github'")),
                         dict(fetch='healthy', completeness='healthy', freshness='n/a', audit='healthy'))

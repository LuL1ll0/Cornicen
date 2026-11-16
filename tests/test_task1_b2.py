# script-purpose: Verify GitHub enumeration, scheduling, privacy and durable outcomes offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task1_b2.py
"""Read invented GitHub fixtures; write temporary SQLite and staging files.

Run PYTHONPATH=src python3 -m unittest tests.test_task1_b2 -v; exit 0/1.
"""
from dataclasses import replace
from datetime import timedelta
from contextlib import contextmanager
from http.client import HTTPException
from urllib.error import URLError
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import adapters, feedvalidate
from cornicen.adapterfactories import production_factories
from cornicen.adapterstore import AdapterStore, canonical, digest, instant, stamp
from cornicen.config import Config, SecretToken, load_config
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.identity import AliasMap
from cornicen.sources.github_advisories import GitHubAdvisories, GitHubState, resource_key
from cornicen.store import Store
from tests.replay_v11.github_backend import ScriptedGitHub
from tests.test_task1_b1 import watch, REPO, SEL
from tests.replay.harness import FakeClock, RecordingNotifier

ROOT = Path(__file__).resolve().parents[1]
T = '2026-11-03T01:00:00Z'
URL = 'https://api.github.com/repos/' + REPO + '/security-advisories?state=published&sort=created&direction=desc&per_page=100'
PATH = resource_key(REPO)
FIXTURE = json.loads((ROOT / 'tests/fixtures/github/advisories_sample.json').read_text())


class B2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'db')
        self.store.migrate()
        self.addCleanup(lambda: self.store.connection.close())
        self.db = self.store.connection
        self.state = GitHubState(self.store)
        self.clock = FakeClock(instant(T))
        self.server = ScriptedGitHub()
        self.watches = (watch(version='2099.7.1'),)
        self.adapter = GitHubAdvisories(self.server.http(), self.watches, self.state, self.clock)
        self.persistence = AdapterStore(self.store, self.tmp.name, rng=Mock(uniform=lambda a,b: 1))

    def page(self, body, traversal=1, occurrence=1, url=URL, headers=None, status=200,
             last=True, repository=REPO, action=0):
        self.server.add(action, repository, 'listing', occurrence, url=url, body=body,
                        traversal=traversal, last=last, headers=headers, status=status)

    def stable(self, body, **kwargs):
        for traversal in (1, 2):
            self.page(body, traversal=traversal, **kwargs)

    def process(self, outcomes):
        return self.persistence.process('github', outcomes, stamp(self.clock()), required_resources=self.adapter.required_resources())

    def poll(self):
        return self.adapter.poll(cutoff=None)

    @contextmanager
    def fresh(self):
        case = B2Tests()
        case.setUp()
        try:
            yield case
        finally:
            case.doCleanups()

    def reopen(self):
        self.store.connection.close()
        self.store = Store(Path(self.tmp.name) / 'db')
        self.db = self.store.connection
        self.state = GitHubState(self.store)
        self.persistence = AdapterStore(self.store, self.tmp.name, rng=Mock(uniform=lambda a,b: 1))
        self.adapter = GitHubAdvisories(self.server.http(), self.watches, self.state, self.clock)

    def next_action(self, action, seconds=3600):
        self.clock.now += timedelta(seconds=seconds)
        self.server.reset(action)

    def repositories(self, repositories):
        self.watches = tuple(watch(id='w' if n==0 else 'w'+str(n), version='2099.7.1',
            github=[SEL | dict(repository=r) for r in repositories[n:n+20]])
            for n in range(0, max(1,len(repositories)), 20))
        self.adapter = GitHubAdvisories(self.server.http(), self.watches, self.state, self.clock)

    def detail(self, member, action, *, status=200, headers=None):
        identity = member['ghsa_id']
        self.server.add(action, REPO, 'detail:'+identity, 1,
            url='https://api.github.com/repos/'+REPO+'/security-advisories/'+identity,
            status=status, headers=headers, body=member)

    def health(self, dimension):
        return tuple(self.db.execute('SELECT state,detail FROM source_health WHERE source=? AND dimension=?',
                                    ('github', dimension)).fetchone())

    def cursor(self):
        return self.db.execute("SELECT cursor_tick FROM adapter_state WHERE source='github'").fetchone()[0]

    def partial(self, outcomes, held=None):
        self.assertEqual(self.process(outcomes), 'PARTIAL')
        self.assertEqual(self.health('fetch')[0], 'healthy')
        self.assertEqual(self.cursor(), held)
        self.assertEqual(self.state.adapter_retries()[0]['resource'], PATH)

    def dispatch(self, engine=None):
        engine = engine or self.engine()
        return engine.dispatch_adapters(registry={'github': replace(adapters.REGISTRY['github'], gate='met')},
                                       factories=production_factories(engine, http_factory=self.server.http))

    def test_cursor_paging_follows_link(self):
        numeric = 'https://api.github.com/repositories/9001/security-advisories?after=opaque%2Bcursor'
        named = 'https://api.github.com/repos/ExampleCorp/Widget-Engine/security-advisories?after=last'
        self.server.add(0, REPO, 'metadata', 1, url='https://api.github.com/repos/'+REPO,
                        body=dict(id=9001, full_name=REPO))
        for traversal in (1, 2):
            self.page([FIXTURE[0]], traversal, headers={'Link': f'<{numeric}>; rel="next"'}, last=False)
            self.page([FIXTURE[1]], traversal, 2, numeric, {'Link': f'<{named}>; rel="next"'}, last=False)
            self.page([FIXTURE[2]], traversal, 3, named)
        result = self.poll()
        self.assertEqual(self.process(result), 'COMPLETE')
        self.assertEqual(len(self.server.requests), 7)
        self.assertEqual(len(self.state.meta('requests')), 7)
        self.assertEqual(self.state.meta('repo_ids')[REPO]['id'], 9001)
        self.assertFalse(any('&page=' in r['url'] for r in self.server.requests))

    def test_endpoint_identity(self):
        links = ['https://other.invalid/a', 'http://api.github.com/repos/'+REPO+'/security-advisories',
                 'https://api.github.com:8443/repos/'+REPO+'/security-advisories',
                 'https://user@api.github.com/repos/'+REPO+'/security-advisories',
                 'https://api.github.com/repos/examplecorp/foreign/security-advisories', URL]
        for index, link in enumerate(links):
            with self.subTest(link=link), self.fresh() as c:
                c.page([], headers={'Link': f'<{link}>; rel="next"'}, last=False)
                result = c.poll()
                c.assertTrue(result[0]['unenumerated'])
                c.partial(result)
                c.assertEqual(len(c.server.requests), 1)

    def test_redirect_identity_before_send(self):
        foreign = 'https://api.github.com/repos/examplecorp/foreign/security-advisories'
        self.repositories([REPO, 'examplecorp/foreign'])
        self.stable([], repository='examplecorp/foreign', url=URL.replace(REPO, 'examplecorp/foreign'))
        self.page('', status=302, headers={'Location': foreign}, last=False)
        # If the first hop were allowed, B would redirect back to watched A.
        self.server.add(0, REPO, 'listing', 2, url=foreign, status=302,
                        headers={'Location': URL})
        self.page([], occurrence=3)
        self.page([], traversal=2)
        result = self.poll()
        self.partial(result)
        self.assertEqual([r['url'] for r in self.server.requests if r['repository']==REPO], [URL])
        self.assertNotIn(foreign, [r['url'] for r in self.server.requests])

    def test_numeric_id_mismatch(self):
        numeric = 'https://api.github.com/repositories/9002/security-advisories?after=opaque'
        self.page([], headers={'Link': f'<{numeric}>; rel="next"'}, last=False)
        self.server.add(0, REPO, 'metadata', 1, url='https://api.github.com/repos/'+REPO,
                        body=dict(id=9001, full_name=REPO))
        self.partial(self.poll())
        self.assertEqual(len(self.server.requests), 2)

    def test_page_cap(self):
        for page in range(12):
            url = URL if page == 0 else URL + '&after=' + str(page)
            self.page([], occurrence=page+1, url=url,
                      headers={'Link': f'<{URL}&after={page+1}>; rel="next"'}, last=False)
        outcomes = self.poll()
        self.assertEqual(outcomes[0]['reason'], 'page cap')
        self.assertEqual(self.process(outcomes), 'PARTIAL')
        self.assertIsNone(self.cursor())
        self.assertEqual(self.state.adapter_retries()[0]['last_error'], 'unenumerated')
        for table in ('staged_containers', 'resource_cache', 'baseline_members', 'manifests', 'advisories'):
            self.assertEqual(self.db.execute('SELECT count(*) FROM '+table).fetchone()[0], 0, table)
        self.assertEqual(self.state.meta('schedule')[REPO]['expected_pages'], 12)

    def test_stability_needs_two_identical_traversals(self):
        for traversal in (1, 2, 3):
            self.page([FIXTURE[0] | dict(summary='Invented edit '+str(traversal))], traversal)
        result = self.poll()
        self.assertTrue(result[0]['unenumerated'])
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(self.process(result), 'PARTIAL')

    def test_stable_pair_after_drift(self):
        self.page([FIXTURE[0]], 1)
        self.page([FIXTURE[1]], 2)
        self.page([FIXTURE[1]], 3)
        result = self.poll()
        self.assertEqual(self.process(result), 'COMPLETE')
        self.assertEqual(len(self.server.requests), 3)

    def test_invalid_member_preserves_sibling(self):
        self.stable([FIXTURE[0], FIXTURE[1] | dict(updated_at='bad')])
        self.assertEqual(self.process(self.poll()), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 1)
        self.assertIn(FIXTURE[0]['ghsa_id'], self.state.known_members(PATH))

    def test_github_boundaries(self):
        for index, body in enumerate(['', '<html>', '{}', '{"error":"invented"}', '[1]']):
            with self.subTest(body=body), self.fresh() as c:
                c.page(body)
                c.assertEqual(c.process(c.poll()), 'FAILED')
                c.assertEqual(c.health('fetch')[0], 'healthy')
                c.assertIsNone(c.cursor())
                c.assertEqual(len(c.state.adapter_retries()), 1)
                for table in ('advisories','advisory_evidence','staged_containers','baseline_members'):
                    c.assertEqual(c.db.execute('SELECT count(*) FROM '+table).fetchone()[0], 0)

    def test_strict_wire_decoding(self):
        member = json.dumps(FIXTURE[0])
        bad = [member.replace('"state": "published"', '"state":"draft","state":"published"'),
               member[:-1] + ',"unused":NaN}', '[]'.encode('utf-16'), b'\xff']
        for body in bad:
            for operation in ('listing', 'metadata', 'detail'):
                with self.subTest(body=body, operation=operation), self.fresh() as c:
                    if operation == 'listing':
                        payload = '['+body+']' if isinstance(body, str) else body
                        c.stable(payload)
                    elif operation == 'metadata':
                        numeric = 'https://api.github.com/repositories/9001/security-advisories'
                        c.page([], headers={'Link': f'<{numeric}>; rel="next"'}, last=False)
                        payload = ('{"id":9001,"full_name":"'+REPO+'","unused":'+body+'}'
                                   if isinstance(body, str) else body)
                        c.server.add(0, REPO, 'metadata', 1,
                            url='https://api.github.com/repos/'+REPO, body=payload)
                    else:
                        c.stable([FIXTURE[0]])
                        c.process(c.poll())
                        c.next_action(1)
                        c.stable([], action=1)
                        payload = (body.replace('"withdrawn_at": null', '"withdrawn_at":"2099-07-01T00:00:00Z"')
                                   if isinstance(body, str) else body)
                        c.server.add(1, REPO, 'detail:'+FIXTURE[0]['ghsa_id'], 1,
                            url='https://api.github.com/repos/'+REPO+'/security-advisories/'+FIXTURE[0]['ghsa_id'],
                            body=payload)
                    outcomes = c.poll()
                    c.assertEqual(c.process(outcomes), 'FAILED' if operation=='listing' else 'PARTIAL')
                    c.assertEqual(c.health('fetch')[0], 'healthy')
                    if operation != 'detail':
                        c.assertEqual(c.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)
                    else:
                        c.assertEqual(c.state.known_members(PATH), {FIXTURE[0]['ghsa_id']})

    def test_disappearance_retraction(self):
        self.stable([FIXTURE[0]])
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.clock.now += timedelta(hours=1)
        self.server.reset(1)
        self.stable([], action=1)
        identity = FIXTURE[0]['ghsa_id']
        self.server.add(1, REPO, 'detail:'+identity, 1,
                        url='https://api.github.com/repos/'+REPO+'/security-advisories/'+identity,
                        body=FIXTURE[0] | dict(state='closed'))
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.assertEqual(self.state.known_members(PATH), set())

    def test_disappearance_404_retains_evidence(self):
        self.stable([FIXTURE[0]])
        self.process(self.poll())
        self.clock.now += timedelta(hours=1)
        self.server.reset(1)
        self.stable([], action=1)
        identity = FIXTURE[0]['ghsa_id']
        self.server.add(1, REPO, 'detail:'+identity, 1,
                        url='https://api.github.com/repos/'+REPO+'/security-advisories/'+identity, status=404)
        self.assertEqual(self.process(self.poll()), 'PARTIAL')
        self.assertIn(identity, self.state.known_members(PATH))
        self.assertEqual(self.db.execute('SELECT audited_at FROM manifests').fetchone()[0], T)

    def test_resume_unicode_lines(self):
        self.stable([FIXTURE[0] | dict(summary='Invented\u2028line\u2029title')])
        outcomes = self.poll()
        # Crash after record commits and baseline pin, before acceptance.
        with patch.object(self.persistence, '_accept_batch', side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):
                self.process(outcomes)
        self.assertEqual(self.db.execute('SELECT count(*) FROM staged_containers').fetchone()[0], 1)
        self.reopen()
        self.persistence.resume(T, source='github')
        self.assertEqual(self.cursor(), T)
        self.assertEqual(self.db.execute('SELECT count(*) FROM staged_containers').fetchone()[0], 0)
        self.assertIn(FIXTURE[0]['ghsa_id'], self.state.known_members(PATH))

    def test_resume_uses_independent_descriptor(self):
        # A synthetic independent descriptor must use the same recovery path.
        with patch.dict(adapters.REGISTRY, fixture=replace(adapters.REGISTRY['github'], name='fixture')):
            self.persistence.reconcile_required('fixture', ['logical'], T)
            self.persistence.stage_members('fixture', 'logical', [], T)
            original = self.persistence.process
            with patch.object(self.persistence, 'process', wraps=original) as process:
                self.persistence.resume(T, source='fixture', independent=adapters.REGISTRY['fixture'].independent)
            process.assert_called_once()
            self.assertEqual(self.db.execute("SELECT body FROM resource_cache WHERE source='fixture'").fetchone()[0], '{"advisories":[]}')

    def test_transport_failure_is_per_repository(self):
        for error in (URLError('secret'), OSError('secret'), TimeoutError('secret'), EOFError('secret'), HTTPException('secret')):
            with self.subTest(error=type(error).__name__), self.fresh() as c:
                repos = ['examplecorp/widget-a', 'examplecorp/widget-b', 'examplecorp/widget-c']
                c.repositories(repos)
                for r in (repos[0], repos[2]):
                    c.stable([], repository=r, url=URL.replace(REPO,r))
                c.server.add(0, repos[1], 'listing', 1, url=URL.replace(REPO,repos[1]), error=error)
                outcomes = c.poll()
                c.assertEqual([r['path'] for r in outcomes], [resource_key(r) for r in repos])
                c.assertEqual(outcomes[1], dict(path=resource_key(repos[1]), status=0, transport_error=True))
                c.assertEqual(c.process(outcomes), 'FAILED')
                c.assertEqual(c.health('fetch')[0], 'unhealthy')
                c.assertEqual(len(c.state.meta('requests')), 5)
                c.assertEqual(len(c.server.requests), 5)
                c.assertEqual({r['resource'] for r in c.state.manifests() if r['digest']}, {resource_key(repos[0]),resource_key(repos[2])})

    def test_non_200_success_is_unhealthy(self):
        for status in (202, 204):
            with self.subTest(status=status), self.fresh() as c:
                c.page([], status=status)
                c.assertEqual(c.process(c.poll()), 'FAILED')
                c.assertEqual(c.health('fetch')[0], 'unhealthy')
                c.assertEqual(len(c.state.adapter_retries()), 1)
                c.assertIsNone(c.cursor())

    def test_headerless_rate_hold_uses_retry_deadline(self):
        # Attempt two and non-unit jitter distinguish the actual backoff from 60s.
        self.persistence.retry('github', PATH, stamp(self.clock()-timedelta(hours=1)), 'FAILED')
        self.persistence.rng = Mock(uniform=lambda a,b: 1.2)
        self.page('', status=429)
        self.assertEqual(self.process(self.poll()), 'FAILED')
        deadline = self.state.adapter_retries()[0]['next_attempt_at']
        self.assertEqual(deadline, '2026-11-03T01:02:24Z')
        self.assertEqual(self.state.meta('rate_hold_until'), deadline)
        self.clock.now = instant(deadline)-timedelta(seconds=1)
        self.assertEqual(self.poll(), [])
        self.assertEqual(self.adapter.audit(PATH), ())
        self.assertEqual(self.adapter.retry(PATH), ())
        self.assertEqual(len(self.server.requests), 1)
        self.clock.now = instant(deadline)+timedelta(seconds=1)
        self.server.reset(1)
        self.stable([], action=1)
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.assertEqual(len(self.server.requests), 3)

    def test_detail_interruption_keeps_stable_progress(self):
        for redirect in (False, True):
            with self.subTest(redirect=redirect), self.fresh() as c:
                members = sorted(FIXTURE[:2], key=lambda m:m['ghsa_id'])
                c.stable(members)
                c.process(c.poll())
                c.next_action(1)
                c.stable([], action=1)
                c.detail(members[0] | dict(state='closed'), 1)
                if redirect:
                    c.detail(members[1], 1, status=302, headers={'Location':'https://api.github.com/repos/examplecorp/foreign/security-advisories/x'})
                else:
                    # The redirect's second hop exhausts the remaining budget.
                    c.detail(members[1], 1, status=302, headers={'Location':
                        'https://api.github.com/repos/'+REPO+'/security-advisories/'+members[1]['ghsa_id']+'?hop=2'})
                    c.state._put('requests', [stamp(c.clock())]*26)
                outcomes = c.poll()
                c.assertFalse(outcomes[0].get('unenumerated', False))
                c.assertFalse(json.loads(outcomes[0]['body'])['coverage_complete'])
                c.partial(outcomes, T)
                c.assertEqual(c.db.execute('SELECT state FROM advisories WHERE source_id=?', (members[0]['ghsa_id'],)).fetchone()[0], 'withdrawn')
                c.assertIn(members[1]['ghsa_id'], c.state.known_members(PATH))

    def test_normalise_uses_cycle_tick(self):
        self.stable([FIXTURE[0]])
        original = feedvalidate.validate_advisory
        seen = []
        def validate(raw, **kwargs):
            seen.append(kwargs['observed_at'])
            return original(raw, **kwargs)
        self.clock.now += timedelta(days=20)
        with patch('cornicen.sources.github_advisories.validate_advisory', validate):
            self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.assertEqual(seen, [stamp(self.clock())]*2)

    def test_transport_limit_reasons(self):
        for kind in ('body budget', 'redirect limit'):
            with self.subTest(kind=kind), self.fresh() as c:
                if kind == 'body budget':
                    c.page('x'*11)
                    c.adapter.http.download_budgets['github_advisories']['max_bytes'] = 10
                else:
                    for n in range(11):
                        url = URL if n == 0 else URL+'&after='+str(n)
                        c.page('', occurrence=n+1, url=url, status=302, last=False,
                               headers={'Location':URL+'&after='+str(n+1)})
                outcomes = c.poll()
                c.assertEqual(outcomes[0]['reason'], kind)
                c.partial(outcomes)

    def test_known_members_reuses_store(self):
        self.stable([])
        self.process(self.poll())
        original = AdapterStore.__init__
        calls = []
        def init(*args, **kwargs):
            calls.append(True)
            original(*args, **kwargs)
        with patch.object(AdapterStore, '__init__', init):
            state = GitHubState(self.store)
            for _ in range(3):
                self.assertEqual(state.known_members(PATH), set())
        self.assertEqual(len(calls), 1)

    def test_repeated_cursor_within_traversal(self):
        next_url = URL+'&after=opaque'
        self.page([], last=False, headers={'Link':f'<{next_url}>; rel="next"'})
        self.page([], occurrence=2, url=next_url, last=False,
                  headers={'Link':f'<{next_url}>; rel="next"'})
        self.partial(self.poll())
        self.assertEqual(len(self.server.requests), 2)

    def test_previously_accepted_invalid_retains_evidence(self):
        self.stable([FIXTURE[0]])
        self.process(self.poll())
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.assertTrue(before)
        prior = self.db.execute('SELECT json FROM advisories').fetchone()[0]
        self.next_action(1)
        self.stable([FIXTURE[0] | dict(updated_at='bad')], action=1)
        self.partial(self.poll(), T)
        self.assertEqual(self.health('fetch')[0], 'healthy')
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT json FROM advisories').fetchone()[0], prior)
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)

    def test_rate_hold(self):
        self.page('', status=403, headers={'Retry-After': '120'})
        self.assertEqual(self.process(self.poll()), 'FAILED')
        self.assertEqual(self.state.meta('rate_hold_until'), '2026-11-03T01:02:00Z')
        self.clock.now += timedelta(seconds=119)
        self.assertEqual(self.poll(), [])
        self.assertEqual(self.adapter.audit(PATH), ())
        self.assertEqual(self.adapter.retry(PATH), ())
        self.assertEqual(len(self.server.requests), 1)

    def test_rate_budget(self):
        repositories = ['examplecorp/widget-'+str(i).zfill(2) for i in range(70)]
        watches = tuple(watch(github=[SEL | dict(repository=r)]) for r in repositories)
        accepted = set()
        for cycle in range(5):
            self.server.reset(cycle)
            self.clock.now = instant(T) + timedelta(hours=cycle)
            self.adapter = GitHubAdvisories(self.server.http(), watches, GitHubState(self.store), self.clock)
            for repository in repositories:
                url = URL.replace(REPO, repository)
                self.stable([], repository=repository, url=url, action=cycle)
            result = self.poll()
            self.assertEqual(len(result), 14)
            self.assertEqual(self.process(result), 'COMPLETE')
            accepted.update(r['path'] for r in result)
            self.assertEqual(len(self.state.meta('requests')), 28)
            current = stamp(self.clock())
            if cycle == 0:
                history = []
            history += [self.clock()]*len([r for r in self.server.requests if r['action']==cycle])
            self.assertLessEqual(sum(0 <= (self.clock()-r).total_seconds() < 3600 for r in history), 60)
            self.assertEqual([r['path'] for r in result], [resource_key(r) for r in repositories[cycle*14:(cycle+1)*14]])
            self.assertTrue(all(self.state.meta('schedule')[r]['last_attempt']==current for r in repositories[cycle*14:(cycle+1)*14]))
            if cycle == 1:
                self.db.close()
                self.store = Store(Path(self.tmp.name)/'db')
                self.db = self.store.connection
                self.state = GitHubState(self.store)
                self.persistence = AdapterStore(self.store, self.tmp.name)
        self.assertEqual(len(accepted), 70)

    def test_audit_unconditional(self):
        self.stable([])
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.clock.now += timedelta(days=8)
        self.server.reset(1)
        self.page('', status=304, action=1)
        self.assertEqual(self.process(self.poll()), 'FAILED')
        self.assertEqual(self.db.execute('SELECT audited_at FROM manifests').fetchone()[0], T)
        for request in self.server.requests:
            self.assertFalse(any(k.lower().startswith('if-') for k in request['headers']))

    def test_rotation_moves_at_first_charge(self):
        repos = ['examplecorp/widget-a', 'examplecorp/widget-b']
        self.repositories(repos)
        with self.store.transaction():
            self.state._put('schedule', {repos[0]:dict(last_attempt=T, expected_pages=1),
                                         repos[1]:dict(last_attempt='2026-11-02T00:00:00Z', expected_pages=1)})
        self.clock.now += timedelta(hours=1)
        for r in repos:
            self.stable([], repository=r, url=URL.replace(REPO,r))
        original = self.server.open
        starts = []
        def opened(request, timeout):
            repository = next(r for r in repos if '/repos/'+r+'/' in request.full_url)
            self.assertEqual(self.state.meta('schedule')[repository]['last_attempt'], stamp(self.clock()))
            starts.append(repository)
            return original(request, timeout)
        with patch.object(self.server, 'open', opened):
            self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.assertEqual(starts, [repos[1],repos[1],repos[0],repos[0]])

    def test_rolling_hour_budget_across_cycles(self):
        repos = ['examplecorp/widget-'+str(i).zfill(2) for i in range(30)]
        self.repositories(repos)
        counts = []
        for action, seconds in enumerate((0, 1200, 1200, 1200)):
            self.next_action(action, seconds)
            for r in repos:
                self.stable([], repository=r, url=URL.replace(REPO,r), action=action)
            before = len(self.server.requests)
            self.process(self.poll())
            counts.append(len(self.server.requests)-before)
            self.assertLessEqual(counts[-1], 30)
            self.assertLessEqual(len(self.state.meta('requests')), 60)
        self.assertEqual(counts, [28,28,2,28])
        self.assertEqual(len(self.state.meta('requests')), 58)

    def test_rate_budget_backlog_exact_boundary(self):
        for accepted in (False, True):
            with self.subTest(accepted=accepted), self.fresh() as c:
                other = 'examplecorp/widget-other'
                c.repositories([REPO,other])
                if accepted:
                    c.stable([])
                    c.stable([], repository=other, url=URL.replace(REPO,other))
                    c.process(c.poll())
                else:
                    c.stable([], repository=other, url=URL.replace(REPO,other))
                    with c.store.transaction():
                        c.state._put('schedule', {REPO:dict(expected_pages=12)})
                        c.state._put('requests', [T]*10)
                    c.process(c.poll())
                held = c.cursor()
                for action, seconds in ((1,86399),(2,1)):
                    c.next_action(action, seconds)
                    with c.store.transaction():
                        c.state._put('requests', [stamp(c.clock())]*10)
                        c.state._put('schedule', {REPO:dict(expected_pages=12)})
                    c.stable([], repository=other, url=URL.replace(REPO,other), action=action)
                    c.assertEqual(c.process(c.poll()), 'COMPLETE')
                    if accepted and action==1:
                        held = stamp(c.clock())
                    c.assertEqual(c.cursor(), held)
                    c.assertEqual(c.health('completeness'), ('healthy','') if action==1 else ('unhealthy','rate budget backlog'))

    def test_drop_pending_retry(self):
        self.stable([FIXTURE[0]])
        self.process(self.poll())
        self.next_action(1)
        self.page('', status=500, action=1)
        self.process(self.poll())
        self.assertEqual(len(self.state.adapter_retries()), 1)
        self.repositories([])
        self.persistence.reconcile_required('github', (), stamp(self.clock()))
        self.next_action(2)
        self.assertEqual(self.dispatch(), {'github':'COMPLETE'})
        self.assertEqual(self.state.adapter_retries(), [])
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(len(self.state.manifests()), 1)
        self.assertIn(FIXTURE[0]['ghsa_id'], self.state.known_members(PATH))

    def test_page_cap_readmitted_with_healthy_neighbors(self):
        healthy = 'examplecorp/widget-other'
        self.repositories([REPO,healthy])
        with self.store.transaction():
            self.state._put('schedule', {REPO:dict(expected_pages=15)})
        for action in range(3):
            if action:
                self.next_action(action)
            for n in range(15):
                url = URL if n==0 else URL+'&after='+str(n)
                self.page([], occurrence=n+1, url=url, action=action, last=n==14,
                          headers={'Link':f'<{URL}&after={n+1}>; rel="next"'} if n<14 else {})
            self.stable([], repository=healthy, url=URL.replace(REPO,healthy), action=action)
            outcomes = self.poll()
            self.assertEqual(outcomes[0]['reason'], 'page cap')
            self.assertEqual(outcomes[1]['status'], 200)
            self.assertEqual(self.process(outcomes), 'PARTIAL')
            self.assertEqual(self.state.meta('schedule')[REPO]['expected_pages'], 15)
            self.assertEqual(self.state.meta('schedule')[REPO]['last_attempt'], stamp(self.clock()))
            self.assertIsNone(self.cursor())
        self.assertEqual(len(self.server.requests), 42)

    def test_due_retry_before_fourteen_healthy(self):
        healthy = ['examplecorp/widget-'+str(i).zfill(2) for i in range(14)]
        retry = 'examplecorp/widget-z'
        self.repositories(healthy+[retry])
        self.page('', status=500, repository=retry, url=URL.replace(REPO,retry))
        # Start with just the failed repository enrolled.
        self.repositories([retry])
        self.process(self.poll())
        self.repositories(healthy+[retry])
        for action in (1,2):
            self.next_action(action)
            self.page('', status=500, repository=retry, url=URL.replace(REPO,retry), action=action)
            for r in healthy:
                self.stable([], repository=r, url=URL.replace(REPO,r), action=action)
            outcomes = self.poll()
            self.assertEqual(outcomes[0]['path'], resource_key(retry))
            self.assertEqual(self.process(outcomes), 'FAILED')
            self.assertLessEqual(len([r for r in self.server.requests if r['action']==action]), 30)

    def test_raising_poll_keeps_dispatch_unhealthy_until_success(self):
        engine = self.engine()
        with patch.object(GitHubAdvisories, 'poll', side_effect=RuntimeError('secret-url-token')):
            self.assertEqual(self.dispatch(engine), {'github':'FAILED'})
        self.assertEqual(self.health('completeness'), ('unhealthy','RuntimeError: adapter error'))
        self.assertEqual(self.state.adapter_retries()[0]['resource'], '@dispatch')
        self.persistence.finish_cycle('github', stamp(self.clock()))
        self.assertEqual(self.health('completeness'), ('unhealthy','RuntimeError: adapter error'))
        self.next_action(1)
        self.stable([], action=1)
        self.assertEqual(self.dispatch(engine), {'github':'COMPLETE'})
        self.assertEqual(self.health('completeness'), ('healthy',''))
        self.assertEqual(self.cursor(), stamp(self.clock()))

    def test_audit_clock_restart_and_drop(self):
        next_url = URL+'&after=opaque'
        for action in range(4):
            if action:
                self.next_action(action)
            if action in (0,1):
                for traversal in (1,2):
                    self.page([], traversal, action=action, last=False, headers={'Link':f'<{next_url}>; rel="next"'})
                    self.page([], traversal, 2, next_url, action=action)
            elif action == 2:
                self.page('', status=304, action=action)
            else:
                self.page([], action=action, last=False, headers={'Link':f'<{URL}>; rel="next"'})
            self.assertEqual(self.process(self.poll()), 'COMPLETE' if action<2 else 'FAILED' if action==2 else 'PARTIAL')
            expected = stamp(instant(T)+timedelta(hours=min(action,1)))
            self.assertEqual(self.state.manifests()[0]['audited_at'], expected)
            self.reopen()
            self.assertEqual(self.state.manifests()[0]['audited_at'], expected)
        for r in self.server.requests:
            self.assertFalse(any(k.lower().startswith('if-') for k in r['headers']))
        before = len(self.server.requests)
        self.repositories([])
        self.next_action(4, 7*86400)
        self.assertEqual(self.dispatch(), {'github':'COMPLETE'})
        self.assertEqual(self.persistence.audits_due('github', stamp(self.clock())), [])
        self.assertEqual(self.health('audit')[0], 'healthy')
        self.assertEqual(len(self.server.requests), before)

    def engine(self):
        self.store.set_meta('baseline_complete', '1')
        config = Config(Path(self.tmp.name)/'db', Path('unused'), None,
                        'https://examplecorp.invalid', 'test', None,
                        github_token=SecretToken('invented-token-sentinel'))
        engine = Engine(self.store, self.watches, AliasMap.load(False), config, self.clock, RecordingNotifier(self.clock))
        # Match the replay backend's spec-row delivery ticks.
        engine._digest = lambda: self.clock().isoformat()
        return engine

    def test_github_ineffective_by_default(self):
        engine = self.engine()
        self.assertIn('github', production_factories(engine))
        calls = dict.fromkeys(('adapter', 'http', 'poll', 'audit', 'retry', 'transport'), 0)
        def counted(name, result=None):
            def call(*args, **kwargs):
                calls[name] += 1
                return result
            return call
        def disabled_dispatch():
            with patch.object(GitHubAdvisories, '__init__', counted('adapter')), \
                 patch.object(Http, '__init__', counted('http')), \
                 patch.object(GitHubAdvisories, 'required_resources', return_value=()), \
                 patch.object(GitHubAdvisories, 'poll', counted('poll', [])), \
                 patch.object(GitHubAdvisories, 'audit', counted('audit', [])), \
                 patch.object(GitHubAdvisories, 'retry', counted('retry', [])), \
                 patch.object(Http, 'get', counted('transport')):
                engine.dispatch_adapters()
        for values in (adapters.settings({}), dict.fromkeys(adapters.REGISTRY, False), dict.fromkeys(adapters.REGISTRY, True)):
            engine.config = replace(engine.config, adapters=values)
            disabled_dispatch()
            self.assertEqual(calls, dict.fromkeys(calls, 0))
        self.assertEqual(list(self.db.execute("SELECT k FROM meta WHERE k LIKE 'github:%' OR k LIKE 'baseline_resources:%' OR k LIKE 'required_since:%'")), [])
        # Mutation control: construction counters must detect a bypassed gate,
        # even though dispatch catches adapter exceptions.
        with patch.object(adapters.Adapter, 'effective', lambda entry, setting: setting is True):
            disabled_dispatch()
            with self.assertRaises(AssertionError):
                self.assertEqual(calls, dict.fromkeys(calls, 0))
        self.assertGreater(calls['adapter'], 0)
        self.assertGreater(calls['http'], 0)
        self.assertGreater(calls['poll'], 0)
        self.assertIn('github: disabled: gate G not met (setting on)', adapters.status_lines(adapters.settings({})))
        self.stable([])
        actual = production_factories(engine, http_factory=self.server.http)
        registry = {'github': replace(adapters.REGISTRY['github'], gate='met')}
        self.assertEqual(engine.dispatch_adapters(registry=registry, factories=actual), {'github': 'COMPLETE'})

    def test_github_request_privacy(self):
        self.watches = (watch(id='invented-watch-sentinel', version='2099.77391'), watch(id='unrelated-sentinel', github=[]))
        engine = self.engine()
        self.stable([])
        engine.dispatch_adapters(registry={'github': replace(adapters.REGISTRY['github'], gate='met')},
                                 factories=production_factories(engine, http_factory=self.server.http))
        requests = canonical(self.server.requests)
        for secret in ('invented-watch-sentinel', 'unrelated-sentinel', '2099.77391', 'invented-token-sentinel', 'Authorization'):
            self.assertNotIn(secret, requests)

    def test_fixture_shape_matches_capture(self):
        from hashlib import sha256
        def shape(v):
            if isinstance(v, dict):
                return {k:shape(v[k]) for k in sorted(v)}
            if isinstance(v, list):
                return [shape(x) for x in v]
            return 'null' if v is None else type(v).__name__
        expected = json.loads((ROOT/'tests/fixtures/github/advisories_sample.shape.json').read_text())
        self.assertEqual(len(FIXTURE), expected['members'])
        self.assertEqual(sha256(json.dumps(shape(FIXTURE), sort_keys=True).encode()).hexdigest(), expected['shape_sha256'])

    def test_audit_overdue_at_seven_days(self):
        self.stable([])
        self.process(self.poll())
        self.clock.now += timedelta(days=7)
        self.persistence.finish_cycle('github', stamp(self.clock()))
        row = self.db.execute("SELECT state FROM source_health WHERE source='github' AND dimension='audit'").fetchone()
        self.assertEqual(row[0], 'unhealthy')

    def test_pending_results_are_queued(self):
        from tests.replay_v11.fixture_adapter import ValidationBackend
        from tests.replay_v11 import harness as h
        backend = ValidationBackend(h.fixture_registry())
        self.addCleanup(backend.close)
        backend.action(dict(t=T, watchlist=h.WATCHLIST))
        for path in ('a.json','b.json'):
            backend.action(dict(t=T, adapter='fixture_a', result=dict(resources=[dict(path=path,status=200,body='[]')])))
        self.assertEqual(len(backend.pending['fixture_a']), 2)
        backend.action(dict(t=T, cycle=True))
        self.assertEqual(backend.store.connection.execute('SELECT count(*) FROM manifests').fetchone()[0], 2)

    def test_topology_drift(self):
        next_url = URL + '&after=invented'
        for traversal in (1, 2, 3):
            pages = ([FIXTURE[0]], [FIXTURE[1]]) if traversal != 2 else ([FIXTURE[0], FIXTURE[1]], [])
            self.page(pages[0], traversal, headers={'Link':f'<{next_url}>; rel="next"'}, last=False)
            self.page(pages[1], traversal, 2, next_url)
        self.assertTrue(self.poll()[0]['unenumerated'])
        self.assertEqual(len(self.server.requests), 6)

    def test_normalisation_boundaries(self):
        good = FIXTURE[0]
        cases = []
        for field in ('published_at', 'updated_at', 'withdrawn_at'):
            for value in ('bad', None):
                if field == 'withdrawn_at' and value is None:
                    continue
                cases.append(good | {field:value})
            if field != 'withdrawn_at':
                cases.append({k:v for k,v in good.items() if k != field})
        cases += [good | dict(vulnerabilities=[]), good | dict(state='closed')]
        for raw in cases:
            with self.subTest(raw=raw), self.fresh() as c:
                c.stable([raw])
                c.partial(c.poll())
                c.assertEqual(c.health('fetch')[0], 'healthy')
                c.assertEqual(c.db.execute('SELECT source_id FROM quarantine').fetchone()[0], good['ghsa_id'])
                c.assertEqual(c.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)
        for value in ('not-a-ghsa', None, 7):
            with self.subTest(id=value), self.fresh() as c:
                raw = good | dict(ghsa_id=value)
                if value is None:
                    del raw['ghsa_id']
                c.stable([raw])
                c.partial(c.poll())
                c.assertTrue(c.db.execute('SELECT source_id FROM quarantine').fetchone()[0].startswith('@invalid:'))
                c.assertEqual(c.health('fetch')[0], 'healthy')
                c.assertEqual(len(c.persistence.summaries()), 1)
                c.assertEqual(c.db.execute('SELECT count(*) FROM baseline_members').fetchone()[0], 0)
        vulnerability = good['vulnerabilities'][0] | dict(vulnerable_version_range=None)
        self.stable([good | dict(vulnerabilities=[vulnerability])])
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        stored = json.loads(self.db.execute('SELECT json FROM advisories').fetchone()[0])
        self.assertEqual(stored['evidence'][0]['status'], 'under_investigation')

    def test_cross_repository_duplicate(self):
        second = 'examplecorp/widget-other'
        watches = (watch(github=[SEL, SEL | dict(repository=second)]),)
        self.adapter = GitHubAdvisories(self.server.http(), watches, self.state, self.clock)
        self.stable([FIXTURE[0]])
        self.stable([FIXTURE[0]], repository=second, url=URL.replace(REPO, second))
        result = self.poll()
        self.assertEqual(json.loads(result[1]['body'])['advisories'],
                         [dict(id=FIXTURE[0]['ghsa_id'], mapping_error='repository conflict')])
        self.assertEqual(self.process(result), 'PARTIAL')
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 1)

    def test_growth_interrupts_and_reenters_schedule(self):
        healthy = ['examplecorp/widget-'+str(i) for i in range(9)]
        growth = 'examplecorp/widget-z'
        watches = tuple(watch(github=[SEL | dict(repository=r)]) for r in healthy+[growth])
        self.adapter = GitHubAdvisories(self.server.http(), watches, self.state, self.clock)
        for action in (0,1):
            for repository in healthy:
                self.stable([], repository=repository, url=URL.replace(REPO, repository), action=action)
            base = URL.replace(REPO, growth)
            for traversal in (1,2):
                for page in range(10):
                    url = base if page == 0 else base+'&after='+str(page)
                    self.page([], traversal, page+1, url,
                        {'Link':f'<{base}&after={page+1}>; rel="next"'} if page<9 else {},
                        last=page==9, repository=growth, action=action)
        result = self.poll()
        self.assertEqual(len(self.server.requests), 30)
        self.assertEqual(result[-1]['path'], resource_key(growth))
        self.assertTrue(result[-1]['unenumerated'])
        self.assertEqual(self.process(result), 'PARTIAL')
        self.assertEqual(self.state.meta('schedule')[growth]['expected_pages'], 10)
        self.assertIsNone(self.db.execute('SELECT cursor_tick FROM adapter_state').fetchone()[0])
        self.assertEqual(self.state.adapter_retries()[0]['resource'], resource_key(growth))
        self.assertEqual(self.state.adapter_retries()[0]['last_error'], 'unenumerated')
        self.assertTrue(all(r['digest'] for r in self.state.manifests()))
        self.assertEqual(len(self.state.manifests()), 9)
        self.clock.now += timedelta(hours=1)
        self.server.reset(1)
        result = self.poll()
        self.assertEqual(result[0]['path'], resource_key(growth))
        self.assertEqual(result[0]['status'], 200)
        self.assertEqual(self.process(result), 'COMPLETE')

    def test_partial_committed_member_disappearance(self):
        self.stable([FIXTURE[0], FIXTURE[1] | dict(updated_at='invalid')])
        self.assertEqual(self.process(self.poll()), 'PARTIAL')
        self.assertFalse(self.db.execute("SELECT 1 FROM manifests WHERE digest!=''").fetchone())
        self.clock.now += timedelta(hours=1)
        self.server.reset(1)
        self.stable([], action=1)
        identity = FIXTURE[0]['ghsa_id']
        self.server.add(1, REPO, 'detail:'+identity, 1,
            url='https://api.github.com/repos/'+REPO+'/security-advisories/'+identity, status=404)
        self.assertEqual(self.process(self.poll()), 'PARTIAL')
        self.assertIn(identity, self.state.known_members(PATH))

    def test_github_baseline_resources(self):
        repos = [REPO, 'examplecorp/widget-other', 'examplecorp/widget-third']
        self.repositories(repos)
        for _ in range(24):
            self.state.charge(T, repository='examplecorp/prior-work')
        engine = self.engine()
        for n, r in enumerate(repos):
            self.stable([FIXTURE[n]], repository=r, url=URL.replace(REPO,r))
        self.assertEqual(self.dispatch(engine), {'github':'COMPLETE'})
        self.assertEqual(len(self.state.manifests()), 2)
        self.assertEqual(self.persistence.summaries(), [])
        self.assertIsNone(self.cursor())
        self.next_action(1)
        for n,r in enumerate(repos):
            self.stable([FIXTURE[n]], repository=r, url=URL.replace(REPO,r), action=1)
        self.assertEqual(self.dispatch(engine), {'github':'COMPLETE'})
        self.assertEqual(len(self.state.manifests()), 3)
        self.assertEqual(len(self.persistence.summaries()), 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM baseline_members').fetchone()[0], 3)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type IN ('new match','correction')").fetchone()[0], 0)
        engine._flush()
        self.assertEqual(len(engine.notifier.delivered), 1)

    def test_github_baseline_resources_restart_pin(self):
        self.stable([FIXTURE[0]])
        outcomes = self.poll()
        class Crash(BaseException):
            pass
        with patch.object(feedvalidate, 'validate_advisory', side_effect=Crash):
            with self.assertRaises(Crash):
                self.process(outcomes)
        key = 'baseline_pinned:github:'+PATH
        pin = self.store.get_meta(key)
        self.assertEqual(json.loads(pin), [FIXTURE[0]['ghsa_id']])
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)
        self.reopen()
        # Recovery must reuse the existing pin, not silently pin again.
        original = self.store.set_meta
        def put(k,v):
            self.assertNotEqual(k, key)
            return original(k,v)
        with patch.object(self.store, 'set_meta', put):
            self.persistence.resume(T, source='github')
        self.assertEqual(self.store.get_meta(key), pin)
        self.assertEqual(self.cursor(), T)
        self.assertEqual(len(self.persistence.summaries()), 1)

    def test_github_baseline_resources_added_incremental(self):
        self.stable([])
        engine = self.engine()
        self.dispatch(engine)
        self.next_action(1)
        added = 'examplecorp/widget-other'
        self.repositories([REPO,added])
        engine.watches = self.watches
        self.stable([], action=1)
        self.stable([FIXTURE[0]], repository=added, url=URL.replace(REPO,added), action=1)
        self.dispatch(engine)
        keys = [r[0] for r in self.db.execute("SELECT key FROM events WHERE type='new match'")]
        self.assertEqual(keys, ['w|advisory:github:'+FIXTURE[0]['ghsa_id']+':main|new match|1'])
        self.assertIsNone(self.store.get_meta('baseline_pinned:github:'+resource_key(added)))
        self.assertEqual(len(self.persistence.summaries()), 1)

    def test_github_baseline_resources_disappearance_and_retraction(self):
        other = 'examplecorp/widget-other'
        self.repositories([REPO,other])
        self.stable([FIXTURE[0]])
        self.stable([], repository=other, url=URL.replace(REPO,other))
        self.process(self.poll())
        baseline = self.store.get_meta('baseline_resources:github')
        self.next_action(1)
        self.stable([], action=1)
        self.stable([], repository=other, url=URL.replace(REPO,other), action=1)
        self.detail(FIXTURE[0], 1, status=404)
        self.partial(self.poll(), T)
        self.assertEqual(next(r for r in self.state.manifests() if r['resource']==resource_key(other))['fetched_at'], stamp(self.clock()))
        self.next_action(2)
        self.stable([], action=2)
        self.stable([], repository=other, url=URL.replace(REPO,other), action=2)
        self.detail(FIXTURE[0] | dict(state='closed'), 2)
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        self.assertEqual(self.cursor(), stamp(self.clock()))
        self.assertEqual(self.store.get_meta('baseline_resources:github'), baseline)
        self.assertEqual(len(self.persistence.summaries()), 1)
        self.assertIsNone(self.db.execute('SELECT rebaselined_at FROM adapter_state').fetchone()[0])

    def test_github_baseline_resources_removed_pin(self):
        other = 'examplecorp/widget-other'
        self.repositories([REPO,other])
        self.stable([FIXTURE[0]])
        self.stable([], repository=other, url=URL.replace(REPO,other))
        outcomes = self.poll()
        class Crash(BaseException):
            pass
        with patch.object(feedvalidate, 'validate_advisory', side_effect=Crash):
            with self.assertRaises(Crash):
                self.process(outcomes)
        self.assertIsNotNone(self.store.get_meta('baseline_pinned:github:'+PATH))
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)
        self.repositories([other])
        self.next_action(1)
        self.stable([], repository=other, url=URL.replace(REPO,other), action=1)
        self.assertEqual(self.dispatch(), {'github':'COMPLETE'})
        self.assertEqual(self.persistence.required_resources('github'), {resource_key(other)})
        self.assertEqual(self.db.execute('SELECT count(*) FROM staged_containers').fetchone()[0], 0)
        self.assertEqual(len(self.persistence.summaries()), 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM advisories').fetchone()[0], 0)

    def test_github_baseline_resources_quarantine_repair(self):
        engine = self.engine()
        self.stable([FIXTURE[0] | dict(updated_at='bad')])
        self.assertEqual(self.dispatch(engine), {'github':'PARTIAL'})
        self.assertEqual(json.loads(self.store.get_meta('baseline_pinned:github:'+PATH)), [FIXTURE[0]['ghsa_id']])
        self.next_action(1)
        self.stable([FIXTURE[0]], action=1)
        self.assertEqual(self.dispatch(engine), {'github':'COMPLETE'})
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine').fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type='new match'").fetchone()[0], 0)
        self.assertEqual(len(self.persistence.summaries()), 1)

    def test_null_cve_initial_baseline(self):
        self.watches = (watch(version='2099.7.1', github=[SEL, SEL | dict(package='Widget Engine')]),)
        self.stable([FIXTURE[0]])
        engine = self.engine()
        self.assertEqual(self.dispatch(engine), {'github':'COMPLETE'})
        engine._flush()
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type IN ('new match','correction')").fetchone()[0], 0)
        self.assertEqual(len(self.persistence.summaries()), 1)
        self.assertEqual(len(engine.notifier.delivered), 1)

    def test_null_cve_retraction_variants(self):
        for kind in ('withdrawal','administrative','404'):
            with self.subTest(kind=kind), self.fresh() as c:
                c.watches = (watch(version='2099.7.1', github=[SEL, SEL | dict(package='Widget Engine')]),)
                engine = c.engine()
                c.stable([])
                c.dispatch(engine)
                engine._flush()
                c.next_action(1)
                c.stable([FIXTURE[0]], action=1)
                c.dispatch(engine)
                engine._flush()
                prior = [tuple(r) for r in c.db.execute('SELECT * FROM advisory_evidence')]
                c.next_action(2)
                c.stable([], action=2)
                withdrawn = FIXTURE[0] | (dict(withdrawn_at='2099-07-01T00:00:00Z') if kind=='withdrawal' else dict(state='closed', withdrawn_at=None))
                c.detail(withdrawn, 2, status=404 if kind=='404' else 200)
                c.assertEqual(c.dispatch(engine), {'github':'PARTIAL' if kind=='404' else 'COMPLETE'})
                engine._flush()
                keys = lambda: [r[0] for r in c.db.execute("SELECT key FROM events WHERE type IN ('new match','correction') ORDER BY key")]
                prefix = 'w|advisory:github:'+FIXTURE[0]['ghsa_id']+':main|'
                if kind=='404':
                    c.assertEqual(keys(), [prefix+'new match|1'])
                    c.assertEqual(c.cursor(), stamp(instant(T)+timedelta(hours=1)))
                    c.assertEqual([tuple(r) for r in c.db.execute('SELECT * FROM advisory_evidence')], prior)
                    c.assertEqual(len(c.state.adapter_retries()), 1)
                    continue
                c.assertEqual(keys(), [prefix+'correction|1',prefix+'new match|1'])
                c.next_action(3)
                c.stable([FIXTURE[0]], action=3)
                c.dispatch(engine)
                c.assertEqual(keys(), [prefix+'correction|1',prefix+'new match|1',prefix+'new match|2'])

    def test_detail_cap_commits_partial_progress(self):
        import copy
        members = []
        for n in range(10):
            member = copy.deepcopy(FIXTURE[0])
            member['ghsa_id'] = 'GHSA-2345-6789-222' + '23456789cf'[n]
            member['html_url'] = 'https://github.com/'+REPO+'/security/advisories/'+member['ghsa_id']
            members.append(member)
        self.stable(members)
        self.assertEqual(self.process(self.poll()), 'COMPLETE')
        for action in (1,2):
            self.clock.now += timedelta(hours=1)
            self.server.reset(action)
            self.stable([], action=action)
            for member in members:
                self.detail(member | dict(state='closed'), action,
                            status=404 if member in members[:5] else 200)
            self.partial(self.poll(), T)
            self.assertEqual(len([r for r in self.server.requests if r['action']==action
                                  and r['operation'].startswith('detail:')]), 5)
            self.assertLessEqual(len(self.state.meta('requests')), 30)
            self.reopen()  # Rotation survives a process restart.
        self.assertEqual(self.state.known_members(PATH), {m['ghsa_id'] for m in members[:5]})
        self.assertEqual(self.db.execute("SELECT count(*) FROM advisories WHERE state='withdrawn'").fetchone()[0], 5)

    def test_detail_budget_commits_partial_progress(self):
        members = sorted(FIXTURE, key=lambda m:m['ghsa_id'])
        self.stable(members)
        self.process(self.poll())
        self.next_action(1)
        for _ in range(26):
            self.state.charge(stamp(self.clock()), repository='examplecorp/prior-work')
        self.stable([], action=1)
        for member in members:
            self.detail(member | dict(state='closed'), 1)
        self.partial(self.poll(), T)
        self.assertEqual(len(self.state.meta('requests')), 30)
        self.assertEqual(self.db.execute("SELECT count(*) FROM advisories WHERE state='withdrawn'").fetchone()[0], 2)
        self.assertEqual(len(self.state.known_members(PATH)), 3)

    def test_old_later_page_edit_unconditional(self):
        next_url = URL+'&after=opaque'
        for action in (0,1):
            if action:
                self.next_action(action)
            later = FIXTURE[1] | dict(summary='Invented later-page edit '+str(action))
            for traversal in (1,2):
                self.page([FIXTURE[0]], traversal, action=action, last=False,
                          headers={'Link':f'<{next_url}>; rel="next"'})
                self.page([later], traversal, 2, next_url, action=action)
            self.assertEqual(self.process(self.poll()), 'COMPLETE')
            row = self.db.execute('SELECT revision,json FROM advisories WHERE source_id=?', (FIXTURE[1]['ghsa_id'],)).fetchone()
            self.assertEqual(row['revision'], str(action+1))
            self.assertEqual(json.loads(row['json'])['title'], later['summary'])
        self.assertEqual(len(self.server.requests), 8)
        self.assertTrue(all(not any(k.lower().startswith('if-') for k in r['headers']) for r in self.server.requests))

    def test_crash_accounting_projections(self):
        from collections import Counter
        from tests.replay_v11.crash_replay import run
        totals = Counter()
        for name in ('github_pages', 'github_null_cve_fix', 'github_empty', 'synthetic_github_identifier'):
            clean = run(name)
            totals.update(point.split(':')[0] for point in clean.points)
            for index, point in enumerate(clean.points):
                with self.subTest(scenario=name, point=point, index=index):
                    recovered = run(name, index)
                    self.assertTrue(recovered.crashed)
                    self.assertEqual(clean.durable, recovered.durable)
                    self.assertEqual(Counter(clean.deliveries), Counter(recovered.deliveries))
                    for case, schedule in clean.accounting.items():
                        actual = recovered.accounting[case]
                        self.assertEqual(set(schedule), set(actual))
                        for repository, expected in schedule.items():
                            row = actual[repository]
                            writes = [w for w in recovered.interrupted_accounting if w[0] == repository]
                            first = [w[2] for w in writes if w[1] == 'first']
                            self.assertIn(row.get('last_attempt'), [expected.get('last_attempt')] + first)
                            pages = [w[2] for w in writes if w[1] == 'pages']
                            self.assertIn(row['expected_pages'], [expected['expected_pages']] +
                                          [max(expected['expected_pages'], p) for p in pages])
                            expected_checks = expected.get('detail_checks', {})
                            actual_checks = row.get('detail_checks', {})
                            witnessed = [w[2] for w in writes if w[1] == 'detail']
                            self.assertEqual(set(actual_checks), set(expected_checks) | {i for i, t in witnessed})
                            for identity, tick in actual_checks.items():
                                self.assertIn(tick, [expected_checks.get(identity)] +
                                              [t for i, t in witnessed if i == identity])
        self.assertEqual(dict(totals), {'github_charge':78, 'github_set_pages':30, 'github_set_repo_id':2, 'github_check_detail':2,
            'record':72, 'enqueue':24, 'ack':12, 'alias':2})

    def test_recovery_duplicate_delivery_detected(self):
        from collections import Counter
        from tests.replay_v11.crash_replay import run
        from tests.replay_v11.github_backend import GitHubBackend
        clean = run('github_null_cve_fix')
        index = next(i for i, p in enumerate(clean.points) if p.startswith('ack:'))
        original = GitHubBackend.start_engine
        duplicates = []
        def start(backend):
            recovering = getattr(backend, 'engine', None) is not None
            original(backend)
            if recovering:
                send = backend.notifier.send
                def duplicate(notification):
                    accepted = send(notification)
                    if notification.watch_id:
                        send(notification)
                        duplicates.append(True)
                    return accepted
                backend.notifier.send = duplicate
        with patch.object(GitHubBackend, 'start_engine', start):
            recovered = run('github_null_cve_fix', index)
        self.assertTrue(recovered.crashed)
        self.assertTrue(duplicates)
        with self.assertRaises(AssertionError):
            self.assertEqual(Counter(clean.deliveries), Counter(recovered.deliveries))

    def test_unjournaled_charge_detected(self):
        from tests.replay_v11.crash_replay import run
        original = GitHubState.charge
        mutations = []
        def corrupt(state, tick, **kwargs):
            result = original(state, tick, **kwargs)
            with state.store.transaction():
                state._put('requests', state.meta('requests', []) + [tick])
            mutations.append(True)
            return result
        with patch.object(GitHubState, 'charge', corrupt):
            with self.assertRaisesRegex(AssertionError, 'unwitnessed GitHub charge'):
                run('github_empty')
        self.assertTrue(mutations)

    def test_github_oracles(self):
        from tests.replay_v11 import harness as h
        for name in ('github_pages', 'github_null_cve_fix', 'github_empty', 'synthetic_github_identifier'):
            with self.subTest(scenario=name):
                result = h.run_scenario(name)
                expected = h.load_expected(name)
                for row in expected:
                    h.assert_line(result, row, expected)
                    key = (row.get('case', 'main'), row['t'])
                    dimensions = result.snapshots[key]['dimensions']['github']
                    classification = row['state']['classification']['github']
                    # The hold-only tick performs no enumeration and retains
                    # the previous HTTP failure's health, as §8 requires.
                    held = key == ('accounting_controls', '2026-11-04T01:00:30Z')
                    if classification == 'COMPLETE' and not held:
                        self.assertEqual(dimensions, dict(fetch='healthy', completeness='healthy',
                                                         audit='healthy', freshness='n/a'))
                    elif classification == 'FAILED' or held:
                        self.assertEqual(dimensions['fetch'], 'unhealthy')
                        self.assertEqual(dimensions['completeness'], 'unhealthy')
                delivered = [(n['record'], tuple(n['reasons'])) for n in result.notifications if n['watch']]
                identity = 'advisory:github:GHSA-9gmr-x47c-hpv2:main'
                wanted = {
                    'github_pages': [('advisory:github:GHSA-369g-mrx4-7chp:main', ('new match',))],
                    'github_null_cve_fix': [(identity, ('new match',)), (identity, ('correction',)),
                                            (identity, ('new match',))],
                    'github_empty': [],
                    'synthetic_github_identifier': [('CVE-2026-105726', ('new match',))],
                }
                self.assertEqual(delivered, wanted[name])
        # §8's unresolved-disappearance variant is PARTIAL with fetching healthy.
        with self.fresh() as c:
            c.stable([FIXTURE[0]])
            c.process(c.poll())
            c.next_action(1)
            c.stable([], action=1)
            c.detail(FIXTURE[0], 1, status=404)
            c.assertEqual(c.process(c.poll()), 'PARTIAL')
            c.assertEqual(c.health('fetch')[0], 'healthy')
            c.assertEqual(c.health('completeness')[0], 'unhealthy')

    def test_readme_disclosure(self):
        text = (ROOT/'README.md').read_text()
        self.assertIn("When the GitHub advisories adapter is enabled (not in this release: gate G is unmet), GitHub sees which repositories your watches name and your IP address. Requests carry Cornicen's User-Agent, which includes its version. To turn it off:", text)
        path = Path(self.tmp.name)/'config.toml'
        disclosure = text.index('When the GitHub advisories adapter')
        self.assertLess(text.index('## Privacy'), disclosure)
        self.assertLess(disclosure, text.index('## Getting help'))
        block = re.search(r'```toml\n(.*?)```', text[disclosure:], re.S)[1]
        self.assertEqual(block, '[adapters.github]\nenabled = false\n')
        path.write_text(block)
        self.assertIs(load_config(path, {}).adapters['github'], False)
        from cornicen import __version__
        self.assertEqual(__version__, '0.4.0')


if __name__ == '__main__':
    unittest.main()

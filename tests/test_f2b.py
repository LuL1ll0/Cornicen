# script-purpose: Verify adapter health, audits and publication clocks offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_f2b.py
"""Offline F2b health checks: read invented outcomes, write temporary SQLite.

Run with unittest; exit 0 on success, 1 on failure. No network is used.
"""
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from cornicen.adapterstore import AdapterStore, instant, stamp
from cornicen.adapters import Adapter
from cornicen.store import Store
from tests.test_f1 import member

T = '2099-01-08T00:00:00Z'
S = 'fixture_a'


def resource(body='[]', **values):
    return dict(path='listing.json', status=200, body=body) | values


class F2bTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.db'
        self.store = Store(self.path)
        self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.p = AdapterStore(self.store, self.tmp.name)
        self.db = self.store.connection
        self.p.ensure(S, T)
        self.db.execute("UPDATE adapter_state SET baseline_members='[]',baseline_complete=1")

    def dimensions(self):
        return dict(self.db.execute('SELECT dimension,state FROM source_health WHERE source=?', (S,)))

    def finish(self, tick=T, **kw):
        self.p.finish_cycle(S, tick, **kw)

    def messages(self):
        return [(json.loads(r[0]), r[1]) for r in self.db.execute("SELECT reasons_json,urgency FROM outbox WHERE urgency='health' ORDER BY id")]

    def test_dimension_defaults(self):
        for raw, fetch in ((resource(json.dumps([member() | {'url':'bad'}])), 'healthy'),
                           (resource(status=500), 'unhealthy'),
                           (resource('[', transfer_complete=False), 'unhealthy'),
                           (resource('<html>failure</html>'), 'healthy')):
            with self.subTest(raw=raw):
                self.p.process(S, [raw], T)
                self.finish()
                self.assertEqual(self.dimensions(), dict(fetch=fetch, completeness='unhealthy', freshness='n/a', audit='healthy'))

    def test_partial_preserves_export_clock(self):
        clock=dict(value=stamp(instant(T)-timedelta(hours=49)),provenance='publisher_generation')
        self.p.process(S,[resource(publication_clock=clock)],T,export=True)
        self.finish(export=True)
        self.p.process(S,[resource('[{}]')],T,export=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'],'stale')
        self.p.process(S,[resource(status=500)],T,export=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'],'stale')

    def test_health_transitions(self):
        for i, raw in enumerate((resource(), resource('[{}]'), resource('[{}]'), resource(), resource(status=500))):
            tick = stamp(instant(T) + timedelta(hours=i))
            self.p.process(S, [raw], tick)
            # Processing queues no health messages; publication waits for cycle end.
            before = len(self.messages())
            self.finish(tick)
            self.assertEqual(len(self.messages()), before + (i in (1, 3, 4)))
        self.assertEqual(self.messages(), [(['unhealthy'], 'health'), (['healthy'], 'health'), (['unhealthy'], 'health')])
        self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0], 'unhealthy')

    def test_audit_schedule(self):
        paths = ('listing.json', 'metadata.json', 'members/FIX-2099-0001.json')
        self.p.process(S, [resource(path=path) for path in paths], T)
        before = stamp(instant(T) + timedelta(days=7, seconds=-1))
        exact = stamp(instant(T) + timedelta(days=7))
        late = stamp(instant(T) + timedelta(days=7, seconds=1))
        self.finish(before)
        self.assertEqual(self.dimensions()['audit'], 'healthy')
        self.assertEqual(self.p.audits_due(S, before), [])
        self.assertEqual(self.p.audits_due(S, exact), sorted(paths))
        self.p.process(S, [resource(status=304, body='')], late)
        self.finish(late)
        self.assertEqual(self.dimensions()['audit'], 'unhealthy')
        self.assertEqual(self.p.audits_due(S, late), sorted(paths))
        self.p.process(S, [resource()], late)
        self.finish(late)
        self.assertEqual(self.dimensions()['audit'], 'unhealthy')
        self.assertEqual(self.p.audits_due(S, late), sorted(paths[1:]))
        self.p.process(S, [resource(path=path) for path in paths[1:]], late)
        self.finish(late)
        self.assertEqual(self.dimensions()['audit'], 'healthy')
        adapter = Mock()
        adapter.poll.return_value = []
        adapter.audit.side_effect = lambda path: [resource(path=path)]
        next_week = stamp(instant(late) + timedelta(days=7, seconds=1))
        self.p.dispatch({S: Adapter(S,'F','met')}, {S:True}, {S:lambda:adapter}, next_week)
        self.assertEqual([c.args[0] for c in adapter.audit.call_args_list], sorted(paths))
        self.assertEqual(self.dimensions()['audit'], 'healthy')

    def test_publication_clock(self):
        clock = dict(value=stamp(instant(T)-timedelta(hours=48)), provenance='publisher_generation')
        self.p.process(S, [resource(publication_clock=clock)], T, export=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'], 'healthy')
        self.finish(stamp(instant(T)+timedelta(seconds=1)), export=True)
        self.assertEqual(self.dimensions()['freshness'], 'stale')
        for raw in (resource(), resource(headers={'Date':T}), resource(json.dumps([member() | {'updated':T}])) ,
                    resource(publication_clock=dict(value=T, provenance='gate_validated_last_modified')),
                    resource(publication_clock=dict(value='bad', provenance='publisher_generation'))):
            self.p.process(S, [raw], T, export=True)
            self.finish(export=True)
            self.assertEqual(self.dimensions()['freshness'], 'unknown')
            self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0], 'unhealthy')
        self.p.process(S, [resource(publication_clock=dict(value=T, provenance='gate_validated_last_modified'))], T,
                       export=True, last_modified_validated=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'], 'healthy')
        # Fractional precision at the 48-hour boundary must not be rounded away.
        self.p.process(S, [resource(publication_clock=clock)], T, export=True)
        self.finish('2099-01-08T00:00:00.000000001Z', export=True)
        self.assertEqual(self.dimensions()['freshness'], 'stale')
        self.p.process(S, [resource()], T)
        self.finish()
        self.assertEqual(self.dimensions()['freshness'], 'n/a')

    def test_dispatch_exception_recovers_once(self):
        registry = {S:Adapter(S,'F','met')}
        bad = Mock(side_effect=RuntimeError('broken'))
        self.p.dispatch(registry,{S:True},{S:bad},T)
        self.p.dispatch(registry,{S:True},{S:bad},T)
        adapter=Mock(); adapter.poll.return_value=[resource()]
        self.p.dispatch(registry,{S:True},{S:lambda:adapter},T)
        self.assertEqual(self.messages(), [(['unhealthy'],'health'), (['healthy'],'health')])
        self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0], 'healthy')

    def test_resume_ignores_dispatch_retry(self):
        self.p.stage_members(S,'listing.json',iter([member()]),T)
        self.p.retry(S,'@dispatch',T,'interrupted dispatch')
        self.p.resume(T,source=S)
        self.assertEqual(self.db.execute('SELECT cursor_tick FROM adapter_state WHERE source=?',(S,)).fetchone()[0],T)
        self.assertEqual(self.db.execute('SELECT count(*) FROM staged_containers').fetchone()[0],0)

    def test_dispatch_exception_recovers_on_304_once(self):
        registry = {S:Adapter(S,'F','met')}
        adapter = Mock()
        adapter.poll.side_effect = [[resource()], RuntimeError('broken'),
                                    [resource(status=304, body='')], [resource(status=304, body='')]]
        for _ in range(4):
            outcomes = self.p.dispatch(registry, {S:True}, {S:lambda:adapter}, T)
            if adapter.poll.call_count == 3:
                self.assertEqual(outcomes[S], 'COMPLETE')
                self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0], 'healthy')
                self.assertEqual(self.messages(), [(['unhealthy'],'health'), (['healthy'],'health')])
        self.assertEqual(self.messages(), [(['unhealthy'],'health'), (['healthy'],'health')])

    def test_publication_worst_resource_survives_separate_calls_and_restart(self):
        stale = dict(value=stamp(instant(T)-timedelta(hours=49)), provenance='publisher_generation')
        fresh = dict(value=T, provenance='publisher_generation')
        self.p.process(S, [resource(path='old.json', publication_clock=stale)], T, export=True)
        reopened = Store(self.path)
        self.addCleanup(reopened.connection.close)
        persistence = AdapterStore(reopened, self.tmp.name)
        persistence.process(S, [resource(path='new.json', publication_clock=fresh)], T, export=True)
        persistence.finish_cycle(S, T, export=True)
        self.assertEqual(self.dimensions()['freshness'], 'stale')
        persistence.process(S, [resource(path='old.json', status=304, body='', publication_clock=fresh)], T, export=True)
        persistence.finish_cycle(S, T, export=True)
        self.assertEqual(self.dimensions()['freshness'], 'stale')
        persistence.process(S, [resource(path='old.json', publication_clock=fresh)], T, export=True)
        persistence.finish_cycle(S, T, export=True)
        self.assertEqual(self.dimensions()['freshness'], 'healthy')

    def test_non_export_resource_does_not_replace_export_clock(self):
        self.p.process(S, [resource(publication_clock=dict(value=T, provenance='publisher_generation'))], T, export=True)
        self.p.process(S, [resource(path='metadata.json', export=False)], T, export=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'], 'healthy')
        self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0], 'healthy')

    def test_304_does_not_infer_clock_from_cached_body(self):
        self.p.process(S, [resource(json.dumps(dict(generation=T, advisories=[])))], T, export=True)
        self.p.process(S, [resource(status=304, body='')], T, export=True)
        self.finish(export=True)
        self.assertEqual(self.dimensions()['freshness'], 'unknown')

    def test_fetch_failure_survives_other_resource_success(self):
        self.p.process(S,[resource(status=500,path='metadata.json')],T)
        self.p.process(S,[resource()],T)
        self.finish()
        self.assertEqual(self.dimensions()['fetch'],'unhealthy')
        self.p.process(S,[resource(path='metadata.json')],T)
        self.finish()
        self.assertEqual(self.dimensions()['fetch'],'healthy')

    def test_clock_and_audit_survive_restart(self):
        self.p.process(S,[resource(publication_clock=dict(value=T,provenance='publisher_generation'))],T,export=True)
        self.finish(export=True)
        reopened=Store(self.path)
        self.addCleanup(reopened.connection.close)
        persistence=AdapterStore(reopened,self.tmp.name)
        tick=stamp(instant(T)+timedelta(hours=49))
        persistence.process(S,[resource(status=304,body='')],tick,export=True)
        persistence.finish_cycle(S,tick,export=True)
        self.assertEqual(self.dimensions()['freshness'],'stale')
        self.assertEqual(self.db.execute('SELECT audited_at FROM manifests').fetchone()[0],T)
        # A conditional 200 fetch also fails to establish an unconditional audit.
        late=stamp(instant(T)+timedelta(days=7,seconds=1))
        persistence.process(S,[resource(conditional=True)],late,export=True)
        persistence.finish_cycle(S,late,export=True)
        self.assertEqual(self.dimensions()['audit'],'unhealthy')

    def test_engine_delivers_dispatch_down_and_recovery_at_cycle_end(self):
        from dataclasses import replace
        from cornicen.config import Config
        from cornicen.engine import Engine
        from cornicen.identity import AliasMap
        from tests.replay.harness import FakeClock, RecordingNotifier
        from unittest.mock import patch
        clock=FakeClock(instant(T))
        notifier=RecordingNotifier(clock)
        config=replace(Config(self.path,Path('unused'),None,'https://examplecorp.invalid','test',None),adapters={S:True})
        engine=Engine(self.store,(),AliasMap.load(False),config,clock,notifier)
        adapter=Mock()
        adapter.poll.side_effect=[RuntimeError('broken'),[resource()]]
        dispatch=engine.dispatch_adapters
        with patch.object(engine,'dispatch_adapters',side_effect=lambda:dispatch(registry={S:Adapter(S,'F','met')},factories={S:lambda:adapter})):
            engine.run_cycle([],release_checks=False)
            engine.run_cycle([],release_checks=False)
        self.assertEqual([(n['reasons'],n['urgency']) for n in notifier.delivered],
                         [(['unhealthy'],'health'),(['healthy'],'health')])
        self.assertEqual(self.db.execute('SELECT state FROM health WHERE source=?',(S,)).fetchone()[0],'healthy')

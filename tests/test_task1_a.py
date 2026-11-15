# script-purpose: Verify Build A wait bounds, durable diagnostics, feed text and crash witnesses.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task1_a.py
"""Read invented records and replay fixtures; write temporary SQLite stores.

Run PYTHONPATH=src python3 -m unittest tests.test_task1_a -v; exit 0/1.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import adapters, feedvalidate as v
from cornicen.adapterstore import AdapterStore, instant, stamp
from cornicen.diagnostics import FixedDiagnostic
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.watchlist import Watch
from cornicen.versions import Scheme
from cornicen.model import Notification, FetchStatus, IngestResult, Origin
from cornicen.render import render
from cornicen.store import Store
from tests.replay_v11 import crash_replay, harness as h
from tests.replay_v11.fixture_adapter import ValidationBackend
from tests.replay.harness import FakeClock, RecordingNotifier

T = '2099-01-01T00:00:00Z'
S = 'examplecorp'


def member():
    return dict(id='EXAMPLE-2099-0001', title='Widget', url='https://examplecorp.invalid/a',
                published=T, updated=T, cves=[],
                products=[dict(id='widget', name='examplecorp:widget')],
                evidence=[dict(product_id='widget', scheme='dotted', status='known_affected')])


class Task1ATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'state.db')
        self.store.migrate()
        self.db = self.store.connection
        self.addCleanup(self.db.close)
        self.p = AdapterStore(self.store, self.tmp.name, rng=Mock(uniform=Mock(return_value=1)))

    def rows(self, table):
        return [dict(r) for r in self.db.execute('SELECT * FROM ' + table)]

    def test_retry_after_clamped(self):
        cases = [({'Retry-After': value}, 60) for value in
                 ('inf', 'nan', '-5', 'abc', 'Thu, 01 Jan 1998 00:00:00 GMT')]
        cases += [({'Retry-After': value}, 21600) for value in
                  ('1e308', '99999999', 'Tue, 01 Jan 2109 00:00:00 GMT')]
        reset = str((instant(T) + timedelta(days=3650)).timestamp())
        cases += [({'x-ratelimit-reset': reset}, 21600),
                  ({'Retry-After': '120'}, 120),
                  ({'Retry-After': '120', 'ratelimit-reset': str(instant(T).timestamp()+180)}, 180),
                  ({'Retry-After': '99999999', 'x-ratelimit-reset': reset}, 21600)]
        cases += [({key: value}, 60) for key in ('x-ratelimit-reset', 'ratelimit-reset')
                  for value in ('inf', 'nan', '-5', 'abc', '1e308', str(instant(T).timestamp()-1))]
        for n, (headers, expected) in enumerate(cases):
            with self.subTest(headers=headers):
                wait = self.p.retry(S, str(n), T, 'FAILED', **self.p._retry_headers(dict(headers=headers), T))
                self.assertEqual(wait, expected)
                deadline = self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE resource=?', (str(n),)).fetchone()[0]
                self.assertEqual((instant(deadline)-instant(T)).total_seconds(), expected)
        self.p.retry(S, 'jitter', T, 'FAILED')
        self.db.execute("UPDATE adapter_retries SET attempts=19 WHERE resource='jitter'")
        self.p.rng.uniform.return_value = 1.2
        self.assertEqual(self.p.retry(S, 'jitter', T, 'FAILED'), 21600)
        self.p.retry(S, 'overflow', '9999-12-31T23:59:59Z', 'FAILED')
        self.assertEqual(instant(self.db.execute("SELECT next_attempt_at FROM adapter_retries WHERE resource='overflow'").fetchone()[0]),
                         datetime.max.replace(tzinfo=timezone.utc))

    def test_error_detail_sanitised(self):
        token = 'ghp_' + 'a'*36 + '\x07'
        for error, expected in ((RuntimeError(token), 'RuntimeError: adapter error'),
                                (ValueError(FixedDiagnostic('x')), 'ValueError: x')):
            with self.subTest(error=type(error).__name__):
                adapter = Mock()
                adapter.poll.side_effect = error
                self.p.dispatch({S: adapters.Adapter(S, 'F', 'met')}, {S: True}, {S: lambda: adapter}, T)
                with self.subTest(sink='retry'):
                    self.assertEqual(self.db.execute("SELECT last_error FROM adapter_retries WHERE resource='@dispatch'").fetchone()[0], expected)
                for dimension in ('fetch', 'completeness'):
                    with self.subTest(sink=dimension):
                        self.assertEqual(self.db.execute('SELECT detail FROM source_health WHERE dimension=?', (dimension,)).fetchone()[0], expected)
                detail = self.db.execute('SELECT detail FROM health').fetchone()[0]
                self.assertNotIn(token, detail)
                self.assertNotIn('\x07', detail)
                self.p.stage_members(S, 'a.json', [member()], T)
                self.p.commit_staged(S, 'a.json', T, on_record=Mock(side_effect=error))
                with self.subTest(sink='quarantine'):
                    self.assertEqual(self.rows('quarantine')[0]['reason'], expected)
        for reason in ('PARTIAL', 'FAILED', '304 without cached body', 'unreadable staged container',
                       'container digest mismatch', 'unenumerated', token):
            self.p.retry(S, 'literal', T, reason)
            self.assertEqual(self.db.execute("SELECT last_error FROM adapter_retries WHERE resource='literal'").fetchone()[0],
                             'str: adapter error' if reason == token else reason)
        # Neither subclasses of FixedDiagnostic nor unsafe exception names confer trust.
        class Derived(FixedDiagnostic):
            pass
        for error, expected in ((ValueError(Derived('secret')), 'ValueError: adapter error'),
                                (type('bad\x07name', (Exception,), {})('secret'), 'Exception: adapter error'),
                                (type('x'*65, (Exception,), {})('secret'), 'Exception: adapter error')):
            self.p.retry(S, 'type', T, error)
            self.assertEqual(self.db.execute("SELECT last_error FROM adapter_retries WHERE resource='type'").fetchone()[0], expected)

    def test_advisory_text_sanitised(self):
        def set_field(raw, field, value):
            if field in ('title', 'url'):
                raw[field] = value
            elif field == 'version':
                raw['remediations'] = [dict(product_ids=['widget'], version=value)]
            elif field == 'facet.title':
                raw['facets'] = [dict(title=value)]
            elif field.startswith('facet.'):
                raw['facets'] = [dict(evidence=[deepcopy(raw['evidence'][0]) | {field.split('.')[1]: value}])]
            else:
                raw['evidence'][0][field] = value
        for field, cap in (('title', 300), ('url', 2000), ('fix', 200), ('first_fixed', 200),
                           ('facet.title', 300), ('facet.fix', 200), ('facet.first_fixed', 200), ('version', 200)):
            prefix = 'https://examplecorp.invalid/' if field == 'url' else ''
            for suffix in ('\x01', '\x85', '\u202e', '\u200b', 'over-cap', 'at-cap'):
                raw = member()
                value = (prefix + 'x'*(cap-len(prefix)+(suffix == 'over-cap')) if suffix in ('over-cap', 'at-cap')
                         else prefix + 'x' + suffix)
                set_field(raw, field, value)
                with self.subTest(field=field, suffix=suffix):
                    result = v.validate_members([raw], source=S, observed_at=T)
                    records = list(result.records)
                    if suffix == 'at-cap':
                        self.assertEqual(len(records), 1)
                        self.assertEqual(result.quarantine, [])
                    else:
                        self.assertEqual(records, [])
                        self.assertEqual(result.quarantine, [raw['id']])
                        with self.assertRaises(ValueError) as caught:
                            v.validate_advisory(raw, source=S, observed_at=T)
                        self.assertIs(type(caught.exception.args[0]), FixedDiagnostic)
        notification = Notification('key', 'widget', 'CVE-2099-0001', ('new match',), 'normal',
                                    dict(fix='2099.\u200b8\x01\ue000'))
        text = render(notification)[1]
        self.assertIn('Fix: 2099.8\n', text)
        for character in ('\u200b', '\x01', '\ue000'):
            self.assertNotIn(character, text)

    def test_crash_retry_increment_witnessed(self):
        action = ValidationBackend.action
        mutations = []

        def corrupt(backend, row):
            try:
                return action(backend, row)
            except crash_replay.Crash:
                with backend.store.transaction():
                    changed = backend.store.connection.execute('UPDATE adapter_retries SET attempts=attempts+999').rowcount
                mutations.append(changed)
                raise

        with patch.object(ValidationBackend, 'action', corrupt):
            with self.assertRaises(AssertionError) as caught:
                h.run_crash_scenario('boundary', crash_index=11)
        # The final dump can also reject the corrupt row while unwinding. Keep
        # the original crash-boundary assertion visible through its context.
        error = caught.exception
        messages = []
        while error is not None:
            messages.append(str(error))
            error = error.__context__
        self.assertIn('unwitnessed retry increment', messages)
        self.assertEqual(mutations, [1], 'control must update one committed retry row')
        totals = {}
        for name in h.scenario_names():
            run = h.run_crash_scenario(name)
            for index, point in enumerate(run.points):
                with self.subTest(scenario=name, crash=index, point=point):
                    recovered = h.run_crash_scenario(name, crash_index=index)
                    self.assertTrue(recovered.crashed)
                    self.assertEqual(recovered.durable, run.durable)
                    h.assert_notifications(recovered.result, h.load_expected(name))
                kind = point.split(':', 1)[0]
                totals[kind] = totals.get(kind, 0)+1
        self.assertEqual(totals, {'record': 278, 'alias': 36, 'enqueue': 64, 'ack': 32})

    def test_dispatch_exception_isolated(self):
        # GUARD: isolation already exists on the original; sanitising is above.
        def cycle_run(phase=None):
            with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                path = Path(directory) / 'state.db'
                store = Store(path)
                store.migrate()
                self.addCleanup(store.connection.close)
                db = store.connection
                clock = FakeClock(instant(T))
                notifier = RecordingNotifier(clock)
                watch = Watch('widget', 'Widget', (('examplecorp', 'widget'),), (),
                              '2099.7', Scheme.DOTTED, False)
                config = replace(Config(path, Path('unused'), None, 'https://examplecorp.invalid', 'test', None),
                                 adapters={S: True})
                engine = Engine(store, (watch,), AliasMap.load(False), config, clock, notifier)
                persistence = AdapterStore(store, directory)
                registry = {S: adapters.Adapter(S, 'F', 'met')}
                adapter = Mock()
                adapter.poll.return_value = []
                factory = Mock(return_value=adapter)
                if phase == 'factory':
                    factory.side_effect = RuntimeError('factory')
                elif phase == 'poll':
                    adapter.poll.side_effect = RuntimeError('poll')
                elif phase == 'lazy':
                    def broken():
                        raise RuntimeError('lazy')
                        yield
                    adapter.poll.side_effect = lambda **kw: broken()
                elif phase == 'process':
                    adapter.poll.return_value = [dict(path='a.json')]
                elif phase == 'audit':
                    with store.transaction():
                        db.execute("INSERT INTO manifests VALUES (?,?,'','[]',?,?)",
                                   (S, 'audit.json', '2098-01-01T00:00:00Z', '2098-01-01T00:00:00Z'))
                    adapter.audit.side_effect = RuntimeError('audit')
                elif phase == 'retry':
                    persistence.retry(S, 'retry.json', T, 'FAILED')
                    db.execute('UPDATE adapter_retries SET next_attempt_at=?', (T,))
                    adapter.retry.side_effect = RuntimeError('retry')
                record = dict(cveMetadata=dict(cveId='CVE-2099-0001', state='PUBLISHED'),
                              containers=dict(cna=dict(affected=[dict(vendor='examplecorp', product='widget',
                                  defaultStatus='unknown', versions=[dict(version='2099.0',
                                  versionType='custom', lessThan='2100.0', status='affected')])])))
                projections = []
                dispatch = (lambda: persistence.dispatch(registry, {S: True}, {S: factory},
                            stamp(clock()), on_health=engine._health)) if phase else lambda: None
                with patch.object(engine, 'dispatch_adapters', side_effect=dispatch):
                    for attempt in (1, 2):
                        ingest = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                              'cursor', clock(), (record,))
                        engine.run_cycle([ingest], release_checks=False)
                        projection = {}
                        for table in ('events', 'outbox', 'pairs'):
                            rows = [dict(r) for r in db.execute('SELECT * FROM '+table)]
                            projection[table] = [r for r in rows if r.get('record_id') != S and
                                                 not r.get('pair_key', '').startswith('|'+S+'|')]
                            self.assertTrue(projection[table], table+' must exercise real v1 effects')
                        projections.append(projection)
                        if phase:
                            self.assertEqual(factory.call_count, attempt, 'next cycle retries the adapter')
                            health = dict(db.execute('SELECT * FROM health WHERE source=?', (S,)).fetchone())
                            self.assertEqual((health['source'], health['state'], health['since']),
                                             (S, 'unhealthy', instant(T).isoformat()))
                            events = [dict(r) for r in db.execute('SELECT * FROM events WHERE record_id=?', (S,))]
                            self.assertEqual(events, [dict(key='|'+S+'|unhealthy|1', watch_id='', record_id=S,
                                                          type='unhealthy', episode=1, created_at=instant(T).isoformat())])
                            outbox = [dict(r) for r in db.execute('SELECT * FROM outbox WHERE pair_key=?', ('|'+S+'|health|1',))]
                            self.assertEqual(len(outbox), 1)
                            self.assertEqual(outbox[0]['urgency'], 'health')
                            self.assertEqual(json.loads(outbox[0]['reasons_json']), ['unhealthy'])
                            self.assertEqual(json.loads(outbox[0]['body_json'])['record_id'], S)
                            self.assertIsNotNone(outbox[0]['sent_at'])
                            self.assertEqual(sum(n['record'] == S for n in notifier.delivered), 1)
                        clock.now += timedelta(hours=1)
                return projections
        control = cycle_run()
        for phase in ('factory', 'poll', 'lazy', 'process', 'audit', 'retry'):
            with self.subTest(phase=phase):
                self.assertEqual(cycle_run(phase), control)

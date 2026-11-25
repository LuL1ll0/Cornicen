"""Offline Synology transport, retention, cadence and Build A regression tests."""

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
from http.client import HTTPResponse
from io import BytesIO, StringIO
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

from cornicen import adapters, cli, synology
from cornicen.adapterstore import AdapterStore, canonical, instant, stamp
from cornicen.config import DOWNLOAD_BUDGETS
from cornicen.fetch import Http, SOURCE_HOSTS
from cornicen.identity import AliasMap
from cornicen.public_text import public_text, public_token
from cornicen.sources import synology_rss as rss
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text


URL = 'https://www.synology.com/api/rssfeed/security/en-us'
TICK = '2099-01-02T00:00:00Z'
A, B, C, X = ('Synology_SA_99_' + f'{number:02d}' for number in (1, 2, 3, 99))
CVE = 'CVE-2099-81001'
OLD = 'Thu, 01 Jan 2099 00:00:00 GMT'
NEW = 'Thu, 01 Jan 2099 01:00:00 GMT'
OLDEST = '2099-01-01T00:00:00Z'
NEWEST = '2099-01-01T01:00:00Z'
BUILD = 'Fri, 02 Jan 2099 00:00:00 GMT'
TRACE = ('GET', URL, {'User-agent': 'Cornicen/test'})
WATCHES = '''
[[watch]]
id = "other"
name = "Invented watch"
match = ["microsoft:windows"]
version = "7.9.0-99999"
scheme = "opaque"
'''


def item(identity=A, date=OLD, **overrides):
    link = f'https://www.synology.com/en-us/support/security/{identity}'
    return dict(dict(guid=link, link=link, title=f'Invented advisory {identity}',
                     pubDate=date, description=f'{CVE} allows an actor to read data via a susceptible version of DSM.'),
                **overrides)


def feed(*items):
    root = ET.Element('rss')
    channel = ET.SubElement(root, 'channel')
    ET.SubElement(channel, 'lastBuildDate').text = BUILD
    for fields in items:
        element = ET.SubElement(channel, 'item')
        for field, value in fields.items():
            ET.SubElement(element, field).text = value
    return ET.tostring(root)


class ScriptedOpener:
    def __init__(self):
        self.responses = []
        self.trace = []
        self.resolved = []

    def resolver(self, host, port, **kwargs):
        self.resolved.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]

    def open(self, request, timeout):
        self.trace.append((request.get_method(), request.full_url, dict(request.header_items())))
        script = self.responses.pop(0)
        if isinstance(script, bytes):
            script = {'body': script}
        response = BytesIO(script.get('body', b''))
        response.status = script.get('status', 200)
        response.headers = script.get('headers', {})
        return response


class PowerLoss(BaseException):
    pass


class Task6B1Tests(unittest.TestCase):
    def sandbox(self, *, retention=48):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir='.')))
        self.path = directory / 'db'
        self.store = Store(self.path)
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.db = self.store.connection
        self.persistence = AdapterStore(self.store, directory)
        self.backend = ScriptedOpener()
        self.http = Http('Cornicen/test', {}, opener=self.backend.open,
                         resolver=self.backend.resolver, data_dir=directory)
        self.now = instant(TICK)
        self.adapter = self.make_adapter(retention)

    def make_adapter(self, retention):
        return rss.SynologyRss(self.http, rss.SynologyState(self.store), lambda: self.now,
                              retention_hours=retention, interval_hours=24)

    @property
    def tick(self):
        return stamp(self.now)

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)

    def poll(self, *items):
        self.backend.responses.append(feed(*items))
        outcome, = self.adapter.poll(cutoff=None)
        return outcome

    def process(self, outcome):
        return self.persistence.process(source='synology', resources=[outcome], tick=self.tick)

    def cycle(self, *items):
        return self.process(self.poll(*items))

    def dispatch(self, *, gate='met', factory=None):
        registry = {'synology': replace(adapters.REGISTRY['synology'], gate=gate)}
        return self.persistence.dispatch(registry, {'synology': True},
                                         {'synology': factory or (lambda: self.adapter)}, self.tick)

    def cell(self, sql, *params):
        row = self.db.execute(sql, params).fetchone()
        return row[0] if row else None

    def cursor(self):
        return self.cell("SELECT cursor_tick FROM adapter_state WHERE source='synology'")

    def health(self, dimension):
        return self.cell("SELECT state FROM source_health WHERE source='synology' AND dimension=?", dimension)

    def summary(self):
        encoded = self.store.get_meta('retention:synology')
        return json.loads(encoded) if encoded is not None else None

    def gaps(self):
        return {row[0] for row in self.db.execute("SELECT reason FROM gap_ledger WHERE source='synology'")}

    def baseline(self):
        self.assertEqual(self.adapter.coverage_detail, 'coverage unknown (pre-baseline)')
        self.assertEqual(self.cycle(item(), item(B, NEW)), 'COMPLETE')
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))

    def test_t9_transport_and_gate(self):
        self.assertEqual(SOURCE_HOSTS['synology'], {'www.synology.com'})
        self.assertEqual(DOWNLOAD_BUDGETS['synology'], dict(max_bytes=8 * 1024**2, deadline_seconds=120))
        self.assertIsNone(rss.SYNOLOGY_RETENTION_HOURS)
        self.sandbox()
        self.assertEqual(adapters.status()['synology'],
                         dict(setting=False, gate='not met', gate_name='S', effective=False))
        factory = Mock(side_effect=AssertionError('unmet gate constructed a factory'))
        self.assertEqual(self.dispatch(gate=adapters.REGISTRY['synology'].gate, factory=factory), {})
        factory.assert_not_called()
        self.assertEqual(self.cycle(item()), 'COMPLETE')
        self.assertEqual(self.backend.trace, [TRACE])
        for bad in ('https://example.invalid/api/rssfeed/security/en-us', URL + '/elsewhere',
                    URL + '?x=1', URL + '#x', URL + '?', URL + '#'):
            with self.subTest(url=bad):
                outcome, body = self.adapter._fetch(bad)
                self.assertIsNone(body)
                self.assertEqual(outcome, dict(path='feed', unconditional=True, status=0, transport_error=True))
                self.assertEqual(self.backend.trace, [TRACE])
                self.assertEqual(self.backend.resolved, [('www.synology.com', 443)])
        for status in (301, 302, 307):
            with self.subTest(redirect=status):
                self.sandbox()
                self.backend.responses = [dict(status=status, headers={'Location': URL}), feed(item())]
                outcome, = self.adapter.poll(cutoff=None)
                self.assertEqual(self.backend.trace, [TRACE])
                self.assertEqual(self.process(outcome), 'FAILED')
                self.assertEqual(self.health('fetch'), 'unhealthy')

    def test_t10_outcomes(self):
        normalized = synology.normalise(item())
        good = dict(body=canonical(dict(advisories=[normalized])),
                    retention=dict(ids=[A], boundary=[A], newest_ids=[A], oldest=OLDEST, newest=OLDEST, observed_at=TICK))
        cases = (
            ('good', dict(body=feed(item())), good, 'COMPLETE', 'healthy'),
            ('HTML', dict(body=b'<html/>'), dict(invalid_envelope=True), 'FAILED', 'healthy'),
            ('204', dict(status=204), dict(invalid_envelope=True, invalid_status=True), 'FAILED', 'unhealthy'),
            ('304', dict(status=304), {}, 'FAILED', 'unhealthy'),
            ('short', dict(body=b'<rss>', headers={'Content-Length': '75'}),
             dict(transfer_complete=False, body='{}'), 'PARTIAL', 'unhealthy'),
            ('429', dict(status=429, headers={'Retry-After': '7200'}), {}, 'FAILED', 'unhealthy'),
            ('503', dict(status=503), {}, 'FAILED', 'unhealthy'),
            ('oversize', dict(body=b'x' * (8 * 1024**2 + 1)),
             dict(invalid_envelope=True), 'FAILED', 'healthy'),
        )
        for label, response, additions, classification, fetch in cases:
            with self.subTest(label=label):
                self.sandbox()
                self.backend.responses.append(response)
                outcome, = self.adapter.poll(cutoff=None)
                headers = {key.lower(): value for key, value in response.get('headers', {}).items()}
                self.assertEqual(outcome, dict(path='feed', unconditional=True,
                                              status=response.get('status', 200), headers=headers, **additions))
                self.assertEqual(self.process(outcome), classification)
                self.assertEqual(self.health('fetch'), fetch)
                self.assertEqual(self.health('freshness'), 'n/a')
                if label == 'short':
                    self.assertEqual(self.cell('SELECT count(*) FROM staged_containers'), 0)
                    self.assertEqual(self.cell('SELECT count(*) FROM advisories'), 0)
                if label == '429':
                    self.assertEqual(self.cell('SELECT next_attempt_at FROM adapter_retries'),
                                     '2099-01-02T02:00:00Z')
                if label == 'good':
                    self.assertEqual(json.loads(self.store.get_meta('synology:last_build')), BUILD)

    def test_t11_body_dependent_gaps(self):
        cases = (
            ('accepted member', [item()], {'member lost'}),
            ('boundary', [item(B, NEW), item(C)], {'member lost', 'retention boundary lost'}),
            ('oldest', [item(date=NEW), item(B, NEW)], {'retention watermark moved'}),
            ('unusable guid', [item(guid=''), item(B, NEW)], set()),
            ('unusable date', [item(C, 'unusable'), item(B, NEW)], set()),
            ('usable identity and date', [item(title=''), item(B, NEW)], set()),
        )
        for label, payload, reasons in cases:
            with self.subTest(label=label):
                self.sandbox()
                self.baseline()
                self.advance(hours=24)
                outcome = self.poll(*payload)
                self.assertEqual(self.gaps(), reasons)  # Already durable before process.
                self.assertNotIn('coverage_complete', outcome)
                self.assertEqual(self.process(outcome), 'PARTIAL')
                self.assertEqual(self.cursor(), TICK)

        # The store manifest alone also holds a missing accepted member.
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        only_a = canonical(dict(advisories=[synology.normalise(item())]))
        self.assertEqual(self.process(dict(path='feed', status=200, body=only_a)), 'PARTIAL')
        self.assertEqual(self.gaps(), set())
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary()['ids'], [A, B])

    def test_t11_partial_union_and_rebaseline(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        self.assertEqual(self.cycle(item(), item(B, NEW), item(C, NEW), item(X, description='')), 'PARTIAL')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B, C], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))
        self.advance(hours=24)
        outcome = self.poll(item())
        self.assertEqual(self.gaps(), {'member lost'})
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B, C], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))
        self.advance(hours=1)
        self.persistence.rebaseline('synology', self.tick)
        self.assertEqual(self.cursor(), self.tick)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A], boundary=[A], newest_ids=[A],
                                              oldest=OLDEST, newest=OLDEST,
                                              observed_at='2099-01-04T00:00:00Z'))
        self.store.connection.close()
        self.store = Store(self.path)
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.persistence = AdapterStore(self.store, self.path.parent)
        self.adapter = self.make_adapter(48)
        self.advance(hours=24)
        self.assertEqual(self.cycle(item()), 'COMPLETE')
        self.assertEqual(self.cell('SELECT count(*) FROM gap_ledger'), 1)
        self.assertEqual(self.persistence.historical('synology'), 'unhealthy (permanent gap)')

    def test_t11_lost_partial_only_member(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        self.assertEqual(self.cycle(item(), item(B, NEW), item(C, NEW), item(X, guid='')), 'PARTIAL')
        self.advance(hours=24)
        outcome = self.poll(item(), item(B, NEW))
        self.assertEqual(self.gaps(), {'member lost'})
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.cursor(), TICK)

    def test_t11_first_acceptance(self):
        self.sandbox()
        self.assertEqual(self.cycle(item(), item(X, description='')), 'PARTIAL')
        self.assertIsNone(self.cursor())
        self.assertEqual(self.summary(), dict(accepted=False, ids=[A]))
        self.advance(hours=24)
        self.assertEqual(self.cycle(item(B, NEW)), 'COMPLETE')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[B], boundary=[B], newest_ids=[B],
                                              oldest=NEWEST, newest=NEWEST, observed_at=self.tick))

    def test_t11_withdrawals(self):
        for staged_withdrawal in (False, True):
            with self.subTest(staged_withdrawal=staged_withdrawal):
                self.sandbox()
                self.baseline()
                self.advance(hours=24)
                if staged_withdrawal:
                    outcome = self.poll(item(), item(B, NEW))
                    # Future explicit withdrawal: retain the observation as it
                    # was staged, but exclude the tombstone at commit.
                    members = json.loads(outcome['body'])['advisories']
                    members[0]['withdrawn'] = self.tick
                    outcome['body'] = canonical(dict(advisories=members))
                else:
                    self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?", (A,))
                    outcome = self.poll(item(B, NEW))
                    self.assertEqual(outcome['retention']['ids'], [B])
                self.assertEqual(self.process(outcome), 'COMPLETE')
                self.assertEqual(self.gaps(), set())
                self.assertEqual(self.summary(), dict(accepted=True, ids=[B], boundary=[B], newest_ids=[B],
                                                      oldest=NEWEST, newest=NEWEST, observed_at=self.tick))

        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?", (A,))
        self.assertEqual(self.cycle(item(B, NEW), item(X, description='')), 'PARTIAL')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[B], boundary=[], newest_ids=[B],
                                              oldest=None, newest=NEWEST, observed_at=TICK))

    def test_t11_interval_and_resume(self):
        for retention, hours, seconds, baseline, expected in (
            (48, 48, 0, False, 'COMPLETE'),
            (48, 48, 1, False, 'PARTIAL'),
            (None, 72, 0, False, 'COMPLETE'),
            (48, 72, 0, True, 'PARTIAL'),
        ):
            with self.subTest(retention=retention, hours=hours, seconds=seconds, resume=baseline):
                self.sandbox(retention=retention)
                if baseline:
                    outcome = self.poll(item(), item(B, NEW))
                    members = json.loads(outcome['body'])['advisories']
                    self.persistence.stage_members('synology', 'feed', members, TICK,
                                                   flags={'retention': outcome['retention']})
                    self.advance(hours=72)
                    self.persistence.resume(self.tick, source='synology')
                    self.assertEqual(self.cursor(), '2099-01-05T00:00:00Z')
                    self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B], boundary=[A], newest_ids=[B],
                                                          oldest=OLDEST, newest=NEWEST, observed_at=TICK))
                else:
                    self.baseline()
                    self.advance(hours=hours, seconds=seconds)
                if retention is None:
                    self.assertEqual(self.adapter.coverage_detail, 'coverage unknown (no retention contract)')
                cursor = self.cursor()
                self.assertEqual(self.cycle(item(), item(B, NEW)), expected)
                reasons = {'observation interval exceeded'} if expected == 'PARTIAL' else set()
                self.assertEqual(self.gaps(), reasons)
                self.assertEqual(self.cursor(), self.tick if expected == 'COMPLETE' else cursor)

    def test_t11_interval_independent_of_body(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=48, seconds=1)
        self.backend.responses.append(b'<html/>')
        outcome, = self.adapter.poll(cutoff=None)
        self.assertEqual(self.gaps(), {'observation interval exceeded'})
        self.assertEqual(self.process(outcome), 'FAILED')
        self.assertEqual(self.cursor(), TICK)

    def test_t11_acceptance_transaction_rolls_back(self):
        self.sandbox()
        outcome = self.poll(item())
        write = self.store.set_meta

        def cut_power(key, value):
            write(key, value)
            if key == 'retention:synology':
                raise PowerLoss()

        with patch.object(self.store, 'set_meta', side_effect=cut_power):
            with self.assertRaises(PowerLoss):
                self.process(outcome)
        self.assertIsNone(self.cursor())
        self.assertIsNone(self.summary())
        self.assertEqual(self.cell('SELECT count(*) FROM manifest_members'), 0)
        self.assertEqual(self.cell('SELECT count(*) FROM staged_containers'), 1)
        self.persistence.resume(self.tick, source='synology')
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary()['ids'], [A])

    def test_t12_duplicates(self):
        for second, classification in (
            (item(description='Different invented description.'), 'PARTIAL'),
            (item(guid=item()['guid'].replace('/support/', '/')), 'PARTIAL'),
            (item(), 'COMPLETE'),
        ):
            with self.subTest(second=second):
                self.sandbox()
                self.assertEqual(self.cycle(item(), second), classification)
                count = int(classification == 'COMPLETE')
                self.assertEqual(self.cell('SELECT count(*) FROM advisories'), count)
                self.assertEqual(self.cell('SELECT count(*) FROM manifest_members'), count)
                self.assertEqual(self.cursor(), TICK if count else None)
                self.assertEqual(self.cell('SELECT reason FROM quarantine WHERE source_id=?', A),
                                 None if count else 'same-ID conflict')
                self.assertEqual(self.summary()['ids'], [A] if count else [])

    def test_t13_cadence_and_dispatch_guard(self):
        self.sandbox()
        self.backend.responses.extend([feed(item())] * 3)
        self.assertEqual(self.dispatch(), {'synology': 'COMPLETE'})
        self.assertEqual(self.adapter.required_resources(), ('feed',))
        self.assertIsNone(self.persistence.required_resources('synology'))
        deadline = '2099-01-02T02:00:00Z'
        self.db.execute('INSERT INTO adapter_retries VALUES (?,?,?,?,?)',
                        ('synology', '@dispatch', 1, deadline, 'injected'))
        self.advance(hours=1)
        self.dispatch()
        self.assertTrue(self.adapter.skipped)
        self.assertEqual(self.backend.trace, [TRACE])
        self.assertEqual(self.cell("SELECT next_attempt_at FROM adapter_retries WHERE resource='@dispatch'"), deadline)
        self.advance(hours=1)
        self.assertEqual(self.dispatch(), {'synology': 'COMPLETE'})
        self.assertFalse(self.adapter.skipped)
        self.assertEqual(self.backend.trace, [TRACE] * 2)
        self.assertIsNone(self.cell("SELECT next_attempt_at FROM adapter_retries WHERE resource='@dispatch'"))
        self.advance(hours=23)
        self.dispatch()
        self.assertEqual(self.backend.trace, [TRACE] * 2)
        self.advance(hours=1)
        self.assertEqual(self.dispatch(), {'synology': 'COMPLETE'})
        self.assertEqual(self.backend.trace, [TRACE] * 3)

    def test_t13_audit_and_backoff(self):
        self.sandbox()
        self.backend.responses = [dict(status=503)] * 3 + [b'<html/>']
        for day in (0, 4, 8):
            self.now = instant(TICK) + timedelta(days=day)
            self.assertEqual(self.dispatch(), {'synology': 'FAILED'})
            count = len(self.backend.trace)
            self.advance(seconds=1)
            self.dispatch()
            self.assertEqual(len(self.backend.trace), count)
        self.assertEqual(self.backend.trace, [TRACE] * 3)
        self.assertEqual(self.health('audit'), 'unhealthy')
        self.assertEqual(self.persistence.audits_due('synology', self.tick), ['feed'])
        self.now = instant(self.cell('SELECT next_attempt_at FROM adapter_retries'))
        self.assertEqual(self.dispatch(), {'synology': 'FAILED'})
        self.assertEqual(self.backend.trace, [TRACE] * 4)
        self.assertEqual(self.health('audit'), 'healthy')
        self.assertEqual(self.health('fetch'), 'healthy')
        self.assertEqual(self.cell("SELECT audited_at FROM manifests WHERE resource='feed'"), self.tick)
        self.assertEqual(self.adapter.audit('feed'), [])
        self.assertEqual(self.adapter.retry('feed'), [])

    def test_t13_constructor(self):
        self.sandbox()
        for retention, interval in ((47, 24), (48, 25), (48, 0), (48, -1)):
            with self.subTest(retention=retention, interval=interval):
                with self.assertRaises(ValueError):
                    rss.SynologyRss(self.http, rss.SynologyState(self.store), lambda: self.now,
                                   retention_hours=retention, interval_hours=interval)

    def test_t13_cursor_requires_durable_health(self):
        for prior_success in (False, True):
            with self.subTest(prior_success=prior_success):
                self.sandbox()
                self.backend.responses = [feed(item())] * (3 if prior_success else 2)
                if prior_success:
                    self.assertEqual(self.dispatch(), {'synology': 'COMPLETE'})
                    self.advance(hours=24)
                accept = self.persistence._accept_batch

                def crash(*args, **kwargs):
                    accept(*args, **kwargs)
                    raise PowerLoss()

                with patch.object(self.persistence, '_accept_batch', side_effect=crash):
                    with self.assertRaises(PowerLoss):
                        self.dispatch()
                self.assertEqual(self.cursor(), self.tick)
                self.adapter = self.make_adapter(48)
                self.assertEqual(self.dispatch(), {'synology': 'COMPLETE'})
                self.assertFalse(self.adapter.skipped)
                self.assertEqual(self.backend.trace, [TRACE] * (3 if prior_success else 2))

    def stage_synology(self, *items):
        outcome = self.poll(*items)
        return self.persistence.stage_members(
            'synology', 'feed', json.loads(outcome['body'])['advisories'], self.tick,
            flags={'retention': outcome['retention']})

    def cut_power_after_summary(self):
        write = self.store.set_meta

        def cut_power(key, value):
            write(key, value)
            if key == 'retention:synology':
                raise PowerLoss()

        return patch.object(self.store, 'set_meta', side_effect=cut_power)

    def test_refused_rebaseline_tracks_committed_members_atomically(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        path = self.stage_synology(item(), item(B, NEW), item(C, NEW), item(X, title=''))
        exists = "SELECT count(*) FROM advisories WHERE source='synology' AND source_id=?"
        self.assertEqual(self.cell(exists, C), 0)
        with self.cut_power_after_summary(), self.assertRaises(PowerLoss):
            self.persistence.rebaseline('synology', self.tick)
        self.assertEqual(self.cell(exists, C), 0)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))
        self.assertTrue(path.is_file())
        with self.assertRaisesRegex(ValueError, '^cannot rebaseline invalid members$'):
            self.persistence.rebaseline('synology', self.tick)
        self.assertEqual(self.cell(exists, C), 1)
        self.assertEqual(self.cell(exists, X), 0)
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B, C], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))
        self.advance(hours=24)
        self.assertEqual(self.cycle(item(), item(B, NEW)), 'PARTIAL')
        self.assertEqual(self.gaps(), {'member lost'})

    def test_malformed_retention_outcomes_fail_before_staging(self):
        valid = dict(ids=[A], boundary=[A], newest_ids=[A], oldest=OLDEST, newest=OLDEST, observed_at=TICK)
        for malformed in (None, [], {k: v for k, v in valid.items() if k != 'newest'},
                          dict(valid, extra=True), dict(valid, ids=A), dict(valid, ids=[None]),
                          dict(valid, boundary=A), dict(valid, boundary=[7]), dict(valid, oldest=7),
                          dict(valid, newest=False), dict(valid, observed_at=[])):
            with self.subTest(retention=malformed):
                self.sandbox()
                self.assertEqual(self.process(dict(self.poll(item()), retention=malformed)), 'FAILED')
                self.assertEqual(self.health('fetch'), 'unhealthy')
                self.assertEqual(self.cell('SELECT count(*) FROM staged_containers'), 0)
                self.assertEqual(self.cell('SELECT count(*) FROM advisories'), 0)
                self.assertIsNone(self.cursor())
                self.assertIsNone(self.summary())
                self.assertEqual(self.cell('SELECT last_error FROM adapter_retries'),
                                 'ValueError: invalid retention summary')

    def test_malformed_staged_retention_fails_commit_and_resume(self):
        for path in ('commit', 'resume'):
            with self.subTest(path=path):
                self.sandbox()
                self.persistence.stage_members('synology', 'feed', [synology.normalise(item())], TICK,
                                               flags={'retention': {'ids': [A]}})
                if path == 'commit':
                    self.assertEqual(self.persistence.commit_staged('synology', 'feed', TICK), 'FAILED')
                else:
                    self.persistence.resume(TICK, source='synology')
                self.assertEqual(self.cell('SELECT integrity FROM staged_containers'), 'failed')
                self.assertEqual(self.cell('SELECT last_error FROM adapter_retries'),
                                 'ValueError: invalid retention summary')
                self.assertEqual(self.cell('SELECT count(*) FROM advisories'), 0)
                self.persistence.resume(TICK, source='synology')
                self.assertEqual(self.cell('SELECT attempts FROM adapter_retries'), 1)
                self.assertIsNone(self.summary())
                self.assertIsNone(self.cursor())

    def test_null_watermarks_require_a_valid_observation(self):
        self.sandbox()
        observation = dict(ids=[A], boundary=[], newest_ids=[], oldest=None, newest=None, observed_at=None)
        self.assertEqual(self.process(dict(self.poll(item()), retention=observation)), 'FAILED')
        self.assertEqual(self.cell('SELECT last_error FROM adapter_retries'),
                         'ValueError: invalid retention summary')
        self.assertIsNone(self.summary())
        self.sandbox(retention=None)
        observation = dict(observation, observed_at=TICK)
        self.assertEqual(self.process(dict(self.poll(item()), retention=observation)), 'COMPLETE')
        self.assertEqual(self.summary(), dict(observation, accepted=True))
        self.advance(hours=72)
        self.assertEqual(self.cycle(item()), 'COMPLETE')
        self.assertEqual(self.gaps(), set())

    def test_partial_with_open_gap_tracks_new_member(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        self.persistence.gap('synology', self.tick, 'observation interval exceeded')
        self.assertEqual(self.cycle(item(), item(B, NEW), item(C, NEW)), 'PARTIAL')
        self.assertEqual(self.cell('SELECT count(*) FROM gap_ledger WHERE acknowledged_at IS NULL'), 1)
        self.assertEqual(self.cursor(), TICK)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B, C], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))

    def test_direct_commit_writes_complete_summary(self):
        self.sandbox()
        self.stage_synology(item(), item(B, NEW))
        self.advance(hours=24)
        self.assertEqual(self.persistence.commit_staged('synology', 'feed', self.tick), 'COMPLETE')
        self.assertEqual(self.cursor(), '2099-01-03T00:00:00Z')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B], boundary=[A], newest_ids=[B],
                                              oldest=OLDEST, newest=NEWEST, observed_at=TICK))

    def test_partial_withdrawal_clears_unsupported_newest(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?", (B,))
        self.assertEqual(self.cycle(item(), item(X, title='')), 'PARTIAL')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[A], boundary=[A], newest_ids=[],
                                              oldest=OLDEST, newest=None, observed_at=TICK))

    def test_constructor_retention_floor_and_interval_without_contract(self):
        self.sandbox()
        for retention, interval in ((47, 12), (None, 0), (None, -1)):
            with self.subTest(retention=retention, interval=interval):
                with self.assertRaisesRegex(ValueError, '^invalid Synology retention or interval$'):
                    rss.SynologyRss(self.http, rss.SynologyState(self.store), lambda: self.now,
                                   retention_hours=retention, interval_hours=interval)

    def test_303_and_308_abort_at_first_get(self):
        for status in (303, 308):
            with self.subTest(status=status):
                self.sandbox()
                self.backend.responses = [dict(status=status, headers={'Location': URL}), feed(item())]
                self.assertEqual(self.adapter.poll(cutoff=None), [
                    dict(path='feed', unconditional=True, status=0, transport_error=True)])
                self.assertEqual(self.backend.trace, [TRACE])

    def test_invalid_but_dated_member_moves_watermark(self):
        self.sandbox()
        self.baseline()
        self.advance(hours=24)
        outcome = self.poll(item(date=NEW, title=''), item(B, NEW))
        self.assertEqual(outcome['retention'], dict(ids=[A, B], boundary=[A, B], newest_ids=[A, B],
                                                   oldest=NEWEST, newest=NEWEST, observed_at=self.tick))
        self.assertEqual(self.gaps(), {'retention watermark moved'})
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.cursor(), TICK)

    def test_real_truncated_http_responses(self):
        for headers, body in (
            ({'content-length': '75'}, b'<rss>'),
            ({'transfer-encoding': 'chunked'}, b'4b\r\n<rss>'),
        ):
            with self.subTest(headers=headers):
                self.sandbox()
                wire = b'HTTP/1.1 200 OK\r\n' + b''.join(
                    f'{key}: {value}\r\n'.encode('ascii') for key, value in headers.items()) + b'\r\n' + body
                response = HTTPResponse(Mock(makefile=Mock(return_value=BytesIO(wire))))
                response.begin()
                opener = Mock(open=Mock(return_value=response))
                with patch.object(self.http, 'opener', opener):
                    outcome, = self.adapter.poll(cutoff=None)
                self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(outcome, dict(path='feed', unconditional=True, status=200, headers=headers,
                                               transfer_complete=False, body='{}'))
                self.assertEqual(self.process(outcome), 'PARTIAL')
                self.assertEqual(self.health('fetch'), 'unhealthy')
                self.assertEqual(self.cell('SELECT count(*) FROM staged_containers'), 0)
                self.assertEqual(self.cell('SELECT count(*) FROM advisories'), 0)

    def test_due_requires_all_retry_deadlines(self):
        self.sandbox()
        self.baseline()
        for resource, deadline in (('feed', '2099-01-02T01:00:00Z'),
                                   ('@dispatch', '2099-01-02T02:00:00Z')):
            self.db.execute('INSERT INTO adapter_retries VALUES (?,?,?,?,?)',
                            ('synology', resource, 1, deadline, 'FAILED'))
        self.assertIs(self.adapter.state.due(self.now, self.adapter.interval), False)
        self.advance(hours=1)
        self.assertIs(self.adapter.state.due(self.now, self.adapter.interval), False)
        self.advance(hours=1)
        self.assertIs(self.adapter.state.due(self.now, self.adapter.interval), True)

    def test_due_checks_each_health_dimension_independently(self):
        for dimension in ('completeness', 'fetch'):
            with self.subTest(dimension=dimension):
                self.sandbox()
                self.baseline()
                self.advance(hours=1)
                self.assertIs(self.adapter.state.due(self.now, self.adapter.interval), False)
                self.persistence.dimension('synology', dimension, 'unhealthy', self.tick)
                self.assertIs(self.adapter.state.due(self.now, self.adapter.interval), True)

    def test_fetch_body_size_limit_is_invalid_envelope(self):
        self.sandbox()
        limit = 8 * 1024**2
        exact = feed(item()).ljust(limit, b' ')
        self.backend.responses = [exact, exact + b' ']
        ok = dict(path='feed', unconditional=True, status=200, headers={})
        self.assertEqual(self.adapter._fetch(URL), (ok, exact))
        self.assertEqual(self.adapter._fetch(URL), (dict(ok, invalid_envelope=True), None))
        self.assertEqual(self.backend.trace, [TRACE, TRACE])

    def test_non_synology_retention_is_ignored_at_outcome_and_commit(self):
        member = dict(id='advisory-1', title='Invented advisory', url='https://example.invalid/advisory-1',
                      published=TICK, updated=TICK, products=[], evidence=[], cves=[])
        valid = dict(ids=['advisory-1'], boundary=['advisory-1'], oldest=TICK, newest=TICK, observed_at=TICK)
        for path, retention in (('outcome', valid), ('outcome', {'unexpected': True}), ('commit', valid)):
            with self.subTest(path=path, retention=retention):
                self.sandbox()
                if path == 'outcome':
                    outcome = dict(path='feed', status=200, body=canonical([member]), retention=retention)
                    with patch.object(self.persistence, 'stage_members', wraps=self.persistence.stage_members) as stage:
                        self.assertEqual(self.persistence.process('fixture_a', [outcome], TICK), 'COMPLETE')
                    self.assertEqual(stage.call_args.kwargs['flags'], None)
                else:
                    self.persistence.stage_members('fixture_a', 'feed', [member], TICK,
                                                   flags={'retention': retention})
                    self.assertEqual(self.persistence.commit_staged('fixture_a', 'feed', TICK), 'COMPLETE')
                self.assertEqual(self.cell("SELECT cursor_tick FROM adapter_state WHERE source='fixture_a'"), TICK)
                self.assertEqual(self.cell("SELECT count(*) FROM meta WHERE k LIKE 'retention:%'"), 0)

    def test_resume_and_rebaseline_roll_back_summary_and_cursor_on_crash(self):
        for mode in ('resume', 'rebaseline'):
            with self.subTest(mode=mode):
                self.sandbox()
                path = self.stage_synology(item(), item(B, NEW))
                self.advance(hours=72)

                def recover():
                    if mode == 'resume':
                        self.persistence.resume(self.tick, source='synology')
                    else:
                        self.persistence.rebaseline('synology', self.tick)

                with self.cut_power_after_summary(), self.assertRaises(PowerLoss):
                    recover()
                self.assertIsNone(self.cursor())
                self.assertIsNone(self.summary())
                self.assertTrue(path.is_file())
                self.assertEqual(self.cell('SELECT count(*) FROM manifest_members'), 0)
                recover()
                self.assertEqual(self.cursor(), '2099-01-05T00:00:00Z')
                self.assertEqual(self.summary(), dict(accepted=True, ids=[A, B], boundary=[A], newest_ids=[B],
                                                      oldest=OLDEST, newest=NEWEST, observed_at=TICK))
                self.assertFalse(path.exists())

    def test_gap_ambiguous_s_upd_name(self):
        self.assertEqual(synology.products('', 'Synology has released a security update for DSM, e.g. routers '
                                               'to address an invented issue.'),
                         ([], None, {'unrecognised template': 1}))

    def test_gap_description_is_denied(self):
        self.assertEqual(public_text('description'), '[redacted]')
        self.assertIsNone(public_token('description'))

    def explain(self):
        output = StringIO()
        with redirect_stdout(output):
            status = cli.explain(self.store, load_watchlist_text(WATCHES), AliasMap.load(False), CVE, 'other')
        return status, output.getvalue()

    def test_gap_explain_filters_unlisted_synology_owner(self):
        self.sandbox()
        another_cve = 'CVE-2099-81002'
        self.assertEqual(self.cycle(item(), item(B, description=f'Invented notice for {another_cve}.')), 'COMPLETE')
        # An owner can be retained by support without listing the queried CVE.
        self.db.execute('INSERT OR IGNORE INTO advisory_support VALUES (?,?,?)', ('synology', B, CVE))
        status, output = self.explain()
        self.assertEqual(status, 0)
        self.assertEqual(output.count('Synology advisory (no version data)'), 1)
        self.assertIn(f'ID: {A}', output)
        self.assertNotIn(B, output)

    def test_gap_explain_cna_keeps_synology_section(self):
        self.sandbox()
        record = dict(cveMetadata=dict(cveId=CVE, state='PUBLISHED'),
                      containers=dict(cna=dict(affected=[dict(vendor='Microsoft', product='Windows',
                                                              defaultStatus='affected', versions=[])])))
        self.store.put_record(CVE, record, TICK)
        status, cna = self.explain()
        self.assertEqual(status, 0)
        self.assertIn('Evidence: CNA affected windows: defaultStatus affected', cna)
        self.assertEqual(self.cycle(item()), 'COMPLETE')
        self.assertEqual(self.explain(), (0, cna +
            'Synology advisory (no version data)\n'
            '  ID: Synology_SA_99_01\n'
            '  Title: Invented advisory Synology_SA_99_01\n'
            '  URL: https://www.synology.com/en-us/support/security/Synology_SA_99_01\n'
            '  Published: 2099-01-01T00:00:00Z\n'
            '  Products: diskstation manager (dsm)\n'))


if __name__ == '__main__':
    unittest.main()

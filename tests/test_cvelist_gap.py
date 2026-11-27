# script-purpose: Verify report-only coverage audit behavior with offline fixtures.
# script-class: harness
# script-trigger: Unittest discovery and make gate.
# script-tests: tests/test_cvelist_gap.py
"""Read synthetic HTTP evidence and watches; write temporary test databases.

Unittest exits 0 on success and 1 on test failure.
"""

from contextlib import redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
from threading import Event, get_ident
from time import monotonic
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode, urlsplit

from cornicen import cli
from cornicen.config import Config, SecretToken
from cornicen.engine import Engine
from cornicen.fetch import Http, _HTTPSConnection
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.releases import ReleaseState
from cornicen.render import render
from cornicen.scheduler import Scheduler
from cornicen.sources.cvelist import CveListSource, RELEASES_URL
from cornicen.sources import cvelist_gap as gap
from cornicen.store import Store, project_record
from cornicen.watchlist import load_watchlist
from tests.source_helpers import Reply, public_resolver


def at(value):
    return datetime.fromisoformat(value + 'Z')


D = '2099-01-02'
NOW = at('2099-01-03T00:01:00')
TIP, FIRST, PREV, MIDDLE, OTHER, OLDER = (char * 40 for char in 'abcdef')
ID, ID2, ID3 = 'CVE-2099-0102', 'CVE-2099-0103', 'CVE-2099-0104'
TOKEN = 'fictional-audit-credential'
PRIVATE = 'Fictional Hidden Release'
COMMIT_TIME = D + 'T00:00:07Z'
TIP_TIME = D + 'T18:00:00Z'
EOD = at(D + 'T23:59:59')
SHORT = at(D + 'T22:00:00')


def path(cve):
    return 'cves/2099/0xxx/' + cve + '.json'


def raw(cve, sha=TIP):
    return gap.RAW + sha + '/' + path(cve)


def commit(sha, stamp, *parents):
    return {'sha': sha, 'commit': {'committer': {'date': stamp}},
            'parents': [{'sha': parent, 'url': gap.COMMITS + '/' + parent} for parent in parents]}


def record(cve=ID, stamp=TIP_TIME, state='affected'):
    meta = {'cveId': cve, 'state': 'PUBLISHED'}
    if stamp is not None:
        meta['dateUpdated'] = stamp
    return {'cveMetadata': meta, 'containers': {'cna': {
        'title': PRIVATE, 'affected': [{'vendor': 'fictional', 'product': 'fictional-media',
                                       'versions': [{'version': '8.2.90', 'status': state}]}]}}}


def listing(*, tip=False, wide=False, page=1, head=TIP):
    args = {'sha': 'main' if tip else head}
    if not tip:
        args['since'] = '2099-01-01T22:00:00Z'
    args['until'] = '2099-01-03T00:00:00Z' if tip or wide else D + 'T06:00:00Z'
    args['per_page'] = 1 if tip else 100
    if page != 1:
        args['page'] = page
    return gap.COMMITS + '?' + urlencode(args)


def rate(now=NOW, mode='none', remaining=None, reset=None):
    return {'limit': 60 if mode == 'none' else 5000,
            'remaining': (60 if mode == 'none' else 5000) if remaining is None else remaining,
            'mode': mode, 'observed_at': now.isoformat(),
            'reset': (reset or now + timedelta(hours=1)).isoformat()}


def rate_headers(remaining, mode='none'):
    values = rate(mode=mode, remaining=remaining)
    return {'X-RateLimit-Limit': str(values['limit']), 'X-RateLimit-Remaining': str(remaining),
            'X-RateLimit-Reset': str(int(datetime.fromisoformat(values['reset']).timestamp()))}


def next_header(url):
    return {'Link': f'<{url}>; rel="next"'}


class FakeHttp:
    def __init__(self):
        self.routes = {}
        self.calls = []
        self.elapsed = 0
        self.owner = get_ident()
        self.http = Http('Cornicen', {}, opener=self.open, resolver=public_resolver,
                         clock=lambda: self.elapsed)

    def open(self, request, timeout):
        self.calls.append((request, timeout, get_ident()))
        value = self.routes.get(request.full_url, (b'', 404, {}))
        if callable(value):
            value = value(timeout)
        if isinstance(value, tuple):
            payload, status, headers = value
        else:
            payload, status, headers = value, 200, {}
        return Reply(payload if isinstance(payload, bytes) else json.dumps(payload).encode(), status, headers)

    @property
    def urls(self):
        return [request.full_url for request, _, _ in self.calls]

    def usual(self, candidates=(ID,)):
        self.routes.update({
            listing(tip=True): [commit(TIP, TIP_TIME, FIRST)],
            listing(): [commit(FIRST, COMMIT_TIME, PREV),
                        commit(PREV, '2099-01-01T23:52:00Z', OTHER)],
            gap.COMMITS + '/' + FIRST: {
                **commit(FIRST, COMMIT_TIME, PREV), 'files': [{'filename': path(cve)} for cve in candidates]},
            **{raw(cve): record(cve) for cve in candidates},
        })


class Notifier:
    def __init__(self):
        self.sent = []

    def send(self, notification):
        self.sent.append(notification)
        return True

    @property
    def audit(self):
        return [item for item in self.sent if item.record_id == gap.SOURCE]


class EmptySource:
    def poll(self, now):
        return []


class GapTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir='.')
        self.addCleanup(directory.cleanup)
        db_path = Path(directory.name) / 'coverage.sqlite'
        watch_path = Path(directory.name) / 'watch.toml'
        watch_path.write_text('''[[watch]]
id = "fictional-media"
name = "fictional-media"
match = ["fictional:fictional-media"]
version = "8.2.90"
scheme = "dotted"
''')
        self.store = Store(db_path)
        self.store.migrate()
        self.addCleanup(self.store._finalizer)
        self.db = self.store.connection
        self.clock = NOW
        self.config = Config(db_path, watch_path, None, 'https://notify.invalid', 'fictional', None)
        self.notifier = Notifier()
        self.engine = Engine(self.store, load_watchlist(watch_path), AliasMap.load(False),
                             self.config, lambda: self.clock, self.notifier)
        self.fake = FakeHttp()
        self.source = CveListSource(self.fake.http, self.store)
        self.audit = self.source.gap_audit
        self.set_rate()

    def set_rate(self, **kwargs):
        self.store.set_meta(gap.DELTA_RATE, json.dumps(rate(now=self.clock, **kwargs)))
        self.db.execute('DELETE FROM meta WHERE k=?', (gap.AUDIT_RATE,))
        self.audit.admission = gap._Admission(self.fake.http)

    def cursor(self, content=EOD, tag='cve_2099-01-02_at_end_of_day'):
        self.db.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',
                        ('cvelist', tag, content.isoformat()))

    def stored(self, value):
        cve = value['cveMetadata']['cveId']
        self.db.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',
                        (cve, json.dumps(project_record(value)), self.clock.isoformat()))

    def tick(self):
        return self.audit.tick(self.store, self.engine._health, self.clock)

    def day(self, key=D):
        return json.loads(self.store.get_meta(gap.DAYS))[key]

    def health(self, source=gap.SOURCE):
        return tuple(self.db.execute('SELECT state,detail FROM health WHERE source=?', (source,)).fetchone())

    def make_scheduler(self):
        lines = []
        scheduler = Scheduler(self.engine, {'cvelist': self.source, 'kev': EmptySource(), 'epss': EmptySource()},
                              lambda: self.clock, lines.append, monotonic=lambda: self.clock.timestamp())
        return scheduler, lines

    def cli(self, *arguments):
        output = io.StringIO()
        with patch.object(cli, 'load_config', return_value=self.config), redirect_stdout(output):
            code = cli.main(list(arguments))
        return code, output.getvalue()

    def test_t1_first_commit_pick_oldest(self):
        self.cursor()
        self.fake.usual()
        self.fake.routes[listing(tip=True)] = [commit(TIP, TIP_TIME, OTHER)]
        self.fake.routes[listing()] = [
            commit(OTHER, D + 'T01:20:00Z', MIDDLE), commit(MIDDLE, D + 'T00:40:00Z', FIRST),
            commit(FIRST, COMMIT_TIME, PREV), commit(PREV, '2099-01-01T23:52:00Z', OLDER)]
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True), listing(), gap.COMMITS + '/' + FIRST, raw(ID)])
        self.assertEqual(self.day()['counts'], {'absent': 1})

    def test_t2_parent_proof_and_late_retry(self):
        self.cursor()
        self.fake.usual()
        normal = self.fake.routes[listing()]
        cases = (
            [commit(FIRST, COMMIT_TIME, OTHER), normal[-1]],
            [normal[0]],
            [commit(MIDDLE, D + 'T00:40:00Z', FIRST, OTHER), *normal],
        )
        for index, history in enumerate(cases):
            with self.subTest(history=history):
                self.fake.routes[listing()] = history
                self.fake.calls.clear()
                self.tick()
                self.assertEqual(self.day()['scan'], 'undecided')
                self.assertNotIn(raw(ID), self.fake.urls)
                self.assertEqual(self.fake.urls[-1], gap.COMMITS + '/' + PREV if index == 1 else listing())
        late = commit(FIRST, D + 'T06:01:00Z', PREV)
        self.fake.routes.update({listing(): [], listing(wide=True): [self.fake.routes[listing(tip=True)][0], late],
                                 gap.COMMITS + '/' + FIRST: {**late, 'files': [{'filename': path(ID)}]},
                                 gap.COMMITS + '/' + PREV: commit(PREV, '2099-01-01T21:52:00Z', OTHER)})
        self.tick()
        self.assertEqual(self.day()['scan'], 'undecided')
        self.assertTrue(self.day()['wide'])
        self.tick()
        self.assertEqual(self.day()['scan'], 'complete')
        self.assertIn(listing(wide=True), self.fake.urls)
        self.assertIn(gap.COMMITS + '/' + PREV, self.fake.urls)

    def test_t3_follows_next_for_parent_list_proof(self):
        self.cursor()
        self.fake.usual()
        first, previous = self.fake.routes[listing()]
        second_page = listing(page=2)
        self.fake.routes[listing()] = ([first], 200, {
            'Link': f'<{second_page}>; title="fictional, \\"next\\""; REL=next'})
        self.fake.routes[second_page] = [previous]
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True), listing(), second_page,
                                         gap.COMMITS + '/' + FIRST, raw(ID)])
        self.assertEqual(self.day()['scan'], 'complete')

    def test_t4_reads_tip_not_first_and_never_writes_records(self):
        self.cursor()
        self.fake.usual()
        early = record(stamp=D + 'T00:00:05Z')
        self.stored(early)
        self.fake.routes[raw(ID, FIRST)] = early
        self.store.set_meta('pending_ingest:cvelist', '{"fictional": true}')
        self.db.execute('INSERT INTO retry_queue VALUES (?,?,?,?,?)',
                        ('cvelist', '@fetch', 1, NOW.isoformat(), 'fictional'))
        unchanged = ('records', 'cursors', 'retry_queue')
        before = {table: self.db.execute(f'SELECT * FROM {table}').fetchall() for table in unchanged}
        self.tick()
        self.assertEqual(self.day()['counts'], {'stale': 1})
        self.assertEqual(self.fake.urls[-1], raw(ID))
        self.assertEqual(before, {table: self.db.execute(f'SELECT * FROM {table}').fetchall() for table in unchanged})
        self.assertEqual(self.store.get_meta('pending_ingest:cvelist'), '{"fictional": true}')

    def test_t5_clocks_register_and_same_day_short_assets_cover(self):
        self.fake.usual(candidates=())
        self.assertEqual(self.tick()['days_open'], 1)
        self.assertEqual(set(json.loads(self.store.get_meta(gap.DAYS))), {D})
        self.assertEqual(self.day()['scan'], 'pending')
        self.assertEqual(self.fake.urls, [])
        self.cursor(SHORT, 'cve_2099-01-02_2200Z')
        self.tick()
        self.assertEqual(self.day()['scan'], 'pending')
        self.clock += timedelta(days=1)
        self.tick()
        self.clock += timedelta(days=2)
        self.tick()
        self.assertEqual(self.health()[0], 'unhealthy')
        self.assertEqual(self.day('2099-01-03')['scan'], 'pending')
        self.audit = gap.GapAudit(self.fake.http)
        self.cursor(SHORT)
        self.set_rate()
        self.tick()
        self.assertEqual(self.day()['scan'], 'complete')
        self.assertEqual(self.day()['content_time'], SHORT.isoformat())
        self.assertEqual(self.day('2099-01-03')['scan'], 'pending')

        # A later cursor covers the previous day as well.
        self.cursor(at('2099-01-04T12:00:00'), 'cve_2099-01-04_1200Z')
        no_commit = gap.COMMITS + '?' + urlencode(
            dict(sha='main', until='2099-01-04T00:00:00Z', per_page=1))
        self.fake.routes[no_commit] = self.fake.routes[listing(tip=True)]
        self.tick()
        self.assertEqual(self.day('2099-01-03')['scan'], 'complete')

    def test_t6_compares_aware_revision_before_projected_content(self):
        cases = [
            (record(stamp='2099-01-01T10:00:00Z'), record(stamp=D + 'T00:00:05Z'), 'stale'),
            (record(stamp=D + 'T20:00:00Z'), record(), 'covered'),
            (record(), record(), 'covered'),
            (record(state='not_affected'), record(), 'undecided'),
            (record(stamp=D + 'T05:00:00+04:00'), record(stamp=D + 'T02:00:00Z'), 'stale'),
            (record(stamp=None), record(), 'undecided'),
            (record(), record(stamp=None), 'undecided'),
            (record(), record(stamp='fictional'), 'undecided'),
            (record(stamp=D + 'T18:00:00'), record(stamp=D + 'T18:00:00'), 'covered'),
        ]
        cases[2][1]['containers']['cna']['descriptions'] = [{'value': PRIVATE}]
        for old, tip, outcome in cases:
            with self.subTest(old=old['cveMetadata'], tip=tip['cveMetadata'], outcome=outcome):
                self.stored(old)
                self.assertEqual(gap._compare(self.store, ID, json.dumps(tip).encode()), outcome)
        self.cursor()
        self.fake.usual()
        self.stored(record(state='not_affected'))
        self.tick()
        self.assertEqual(self.day()['scan'], 'undecided')

    def test_t7_tip_404_is_deleted_not_gap(self):
        self.cursor()
        self.fake.usual()
        self.fake.routes[raw(ID)] = (b'', 404, {})
        self.tick()
        self.assertEqual(self.day()['counts'], {'deleted': 1})
        self.assertEqual(self.db.execute('SELECT count(*) FROM records').fetchone()[0], 0)

    def test_t8_payload_bound_to_path_and_size(self):
        self.cursor()
        self.fake.usual((ID, ID2))
        detail = self.fake.routes[gap.COMMITS + '/' + FIRST]
        detail['files'].append({'filename': 'cves/deltaLog.json'})
        self.fake.routes[raw(ID)] = record(ID3)
        self.fake.routes[raw(ID2)] = json.dumps({**record(ID2), 'padding': 'x' * (3 * 1024 * 1024)}).encode()
        result = self.tick()
        self.assertEqual(result['invalid'], 2)
        self.assertEqual(self.day()['ignored'], 1)
        self.assertEqual(self.fake.urls[-2:], [raw(ID), raw(ID2)])
        self.assertEqual(self.day()['scan'], 'undecided')

    def test_t9_redirect_refused_after_first_dispatch_and_no_raw_token(self):
        self.cursor()
        self.fake.http.github_token = SecretToken(TOKEN)
        self.set_rate(mode='token')
        self.fake.usual((ID, ID2, ID3))
        self.fake.routes[raw(ID2)] = (b'', 302, {'Location': raw(ID2, FIRST)})
        self.fake.routes[raw(ID3)] = (b'', 302, {'Location': raw(ID3)})
        result = self.tick()
        self.assertEqual(self.fake.urls[-3:], [raw(ID), raw(ID2), raw(ID3)])
        self.assertEqual(result['found_absent'], 1)
        self.assertEqual(result['invalid'], 2)
        for request, _, _ in self.fake.calls:
            if urlsplit(request.full_url).hostname == 'api.github.com':
                self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
            else:
                self.assertIsNone(request.get_header('Authorization'))
        self.fake.routes[raw(ID2)] = (b'', 304, {})
        self.tick()
        self.assertEqual(self.day()['paths'][path(ID2)], 'invalid')

    def test_t10_checks_reserve_each_rest_call_and_401_keeps_delta_token(self):
        self.cursor()
        self.fake.usual()
        self.set_rate(mode='token')
        self.tick()
        self.assertEqual(self.fake.urls, [])
        self.set_rate(reset=NOW)
        self.tick()
        self.assertEqual(self.fake.urls, [])
        tip = self.fake.routes[listing(tip=True)]
        self.fake.routes[listing(tip=True)] = (tip, 200, rate_headers(9))
        self.set_rate(remaining=10)
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True)])
        self.assertEqual(self.day()['scan'], 'pending')
        self.assertEqual(self.day()['tip'], TIP)
        self.fake.http.github_token = SecretToken(TOKEN)
        self.set_rate(mode='token', remaining=100)
        self.fake.routes[listing()] = (b'', 401, {})
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True), listing()])
        self.assertIsNotNone(self.fake.http.github_token)
        self.assertEqual(self.fake.http.github_token.reveal(), TOKEN)
        self.assertEqual(self.day()['diagnostic'], 'auth')
        self.assertIsNone(self.store.get_meta('github_retry_at'))

    def test_t11_429_stays_out_of_delta_backoff(self):
        self.cursor()
        self.fake.usual()
        self.fake.routes[listing(tip=True)] = (b'', 429, {'Retry-After': '180'})
        self.tick()
        self.assertEqual(self.store.get_meta(gap.RETRY_AT), (NOW + timedelta(minutes=3)).isoformat())
        self.assertIsNone(self.store.get_meta('github_retry_at'))
        self.assertIsNone(self.store.get_meta('github_retry_mode'))
        self.fake.routes[RELEASES_URL] = ([], 200, rate_headers(40))
        self.source.poll(NOW)
        observed = json.loads(self.store.get_meta(gap.DELTA_RATE))
        self.assertEqual(observed, rate(remaining=40))
        self.assertIn(RELEASES_URL, self.fake.urls)
        self.tick()
        self.assertEqual(self.fake.urls.count(listing(tip=True)), 1)
        self.clock += timedelta(minutes=3)
        self.fake.usual()
        self.fake.routes[raw(ID)] = (b'', 403, {'Retry-After': '60'})
        self.tick()
        self.assertEqual(self.store.get_meta(gap.RETRY_AT), (self.clock + timedelta(minutes=1)).isoformat())
        self.assertIsNone(self.store.get_meta('github_retry_at'))

    def test_t12_shared_deadline_and_worker_does_not_block_scheduler(self):
        self.cursor()
        self.fake.usual((ID, ID2))
        details = gap.COMMITS + '/' + FIRST
        detail = self.fake.routes[details]

        def slow_page(timeout):
            self.fake.elapsed += 115
            return detail

        def exhaust(timeout):
            self.fake.elapsed += timeout
            return record(ID2)

        self.fake.routes.update({details: slow_page, raw(ID2): exhaust})
        result = self.tick()
        self.assertEqual([timeout for req, timeout, _ in self.fake.calls if req.full_url.startswith(gap.RAW)],
                         [5, 5])
        self.assertEqual(result['found_absent'], 1)
        self.assertEqual(self.day()['scan'], 'pending')
        self.assertTrue(all(owner != self.fake.owner for _, _, owner in self.fake.calls))
        self.assertEqual(self.day()['paths'][path(ID)], 'absent')

        gate = Event()
        entered = Event()
        lookups = []

        def resolver(host, port, **kwargs):
            lookups.append(host)
            entered.set()
            gate.wait(4)
            return public_resolver(host, port, **kwargs)

        self.fake.http.resolver = resolver
        scheduler, lines = self.make_scheduler()
        self.source.poll = EmptySource().poll
        start = monotonic()
        try:
            scheduler.tick()
            self.assertTrue(entered.is_set())
            worker = self.audit.worker
            self.assertLess(monotonic() - start, 1.8)
            self.assertEqual(json.loads(lines[-1])['cvelist_gap']['days_open'], 1)
            self.clock += timedelta(minutes=1)
            scheduler.tick()
            self.assertIs(self.audit.worker, worker)
            self.assertEqual(lookups, [gap.RAW_HOST])
            self.assertEqual(len(lines), 2)
            self.assertEqual(self.day()['scan'], 'pending')
        finally:
            gate.set()
            if self.audit.worker is not None:
                self.audit.worker.join(1)
        self.assertEqual(self.fake.urls.count(raw(ID)), 1)

    def test_t13_300_is_one_page_but_3000_is_undecided(self):
        self.cursor()
        self.fake.usual(())
        details = gap.COMMITS + '/' + FIRST
        batch = [{'filename': f'cves/2099/0xxx/CVE-2099-{i:04}.json'} for i in range(300)]
        responses = {details: self.fake.routes[details].copy()}
        responses[details]['files'] = batch
        self.fake.routes.update(responses)
        self.tick()
        self.assertEqual(self.day()['scan'], 'complete')
        self.assertEqual(sum(url.startswith(details) for url in self.fake.urls), 1)
        self.assertEqual(sum(url.startswith(gap.RAW) for url in self.fake.urls), 300)
        self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
        self.set_rate()
        for page in range(1, 11):
            url = details if page == 1 else f'{details}?page={page}'
            files = [{'filename': path(f'CVE-2099-{i:04}')} for i in range((page - 1) * 300, page * 300)]
            self.fake.routes[url] = ({**responses[details], 'files': files}, 200,
                                     next_header(f'{details}?page={page + 1}') if page < 10 else {})
        self.fake.calls.clear()
        self.tick()
        self.assertEqual(self.day()['scan'], 'undecided')
        self.assertEqual(self.day()['diagnostic'], 'file limit')
        self.assertEqual(sum(url.startswith(details) for url in self.fake.urls), 10)
        self.assertTrue(all(not url.startswith(gap.RAW) for url in self.fake.urls))

        self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
        self.set_rate()
        candidates = [f'CVE-2099-{i:04}' for i in range(110, 116)]
        self.fake.usual(candidates)
        for cve in candidates:
            self.fake.routes[raw(cve)] = {**record(cve), 'padding': 'x' * (1700 * 1024)}
        self.fake.calls.clear()
        self.tick()
        self.assertEqual(self.day()['scan'], 'pending')
        self.assertEqual(sum(url.startswith(gap.RAW) for url in self.fake.urls), 5)
        self.assertEqual(gap.summary(self.store)['found_absent'], 4)
        self.tick()
        self.assertEqual(self.day()['counts'], {'absent': 6})
        self.assertEqual(self.fake.urls.count(raw(candidates[0])), 1)

    def test_t14_escalation_independent_and_ages_undecided(self):
        self.source.poll = EmptySource().poll
        scheduler, lines = self.make_scheduler()
        scheduler.tick()
        self.assertEqual(self.health()[0], 'healthy')
        self.clock += timedelta(days=3)
        day_three = self.clock
        scheduler.tick()
        self.assertEqual(self.health(), ('unhealthy', 'delta gap: 4 days open, oldest 2099-01-02'))
        self.assertEqual(len(self.notifier.audit), 1)
        notice = self.notifier.audit[0]
        self.assertIs(type(notice.body['days_open']), int)
        self.assertEqual(notice.body['oldest_open'], D)
        self.assertEqual(render(notice)[1], 'delta gap: 4 days open, oldest 2099-01-02')

        # A clean, committed delta is separate from the unresolved coverage day.
        fresh = IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                             'cve_2099-01-06_0000Z', at('2099-01-06T00:00:00'))
        self.engine.run_cycle([fresh])
        self.assertEqual(self.health('cvelist')[0], 'healthy')
        self.assertEqual(self.health()[0], 'unhealthy')
        self.assertEqual(len(self.notifier.audit), 1)

        self.store.set_meta(gap.DAYS, json.dumps({D: {'scan': 'undecided'}}))
        self.clock = day_three
        scheduler.tick()
        self.assertEqual(self.health()[0], 'unhealthy')
        self.assertEqual(json.loads(lines[-1])['cvelist_gap']['days_undecided'], 1)

        self.store.set_meta(gap.DAYS, json.dumps({D: {'scan': 'complete',
                                                     'counts': {'stale': 1, 'absent': 1}}}))
        scheduler.tick()
        self.assertEqual(self.health()[0], 'healthy')
        self.assertEqual(sum('unhealthy' in item.reasons for item in self.notifier.audit), 1)

        # Only 14 unresolved days remain eligible. Expiry can be acknowledged
        # once, otherwise it clears after another 14 days.
        self.clock = NOW + timedelta(days=19)
        scheduler.tick()
        expired = [key for key, day in gap.status(self.store)['days'].items() if day['expired']]
        self.assertTrue(expired)
        self.assertEqual(gap.summary(self.store)['days_open'] - len(expired), 14)
        self.assertEqual(self.cli('gap', 'ack', expired[0])[0], 0)
        self.assertEqual(self.cli('gap', 'ack', expired[0])[0], 1)
        self.assertEqual(self.store.get_meta('cvelist_gap_ack_count'), '1')
        self.clock += timedelta(days=14)
        scheduler.tick()
        self.assertNotIn(expired[-1], gap.status(self.store)['days'])

    def test_t18_privacy_never_uses_free_text_detail(self):
        self.cursor()
        self.fake.usual((ID, ID2, ID3))
        self.fake.http.github_token = SecretToken(TOKEN)
        self.set_rate(mode='token')
        evidence = ' '.join((ID, path(ID), raw(ID), PRIVATE, TOKEN))
        self.fake.routes.update({raw(ID): (evidence.encode(), 404, {}),
                                 raw(ID2): (evidence.encode(), 200, {}),
                                 raw(ID3): (evidence.encode(), 429,
                                            {'X-Audit-Diagnostic': evidence, 'Retry-After': '180'})})
        scheduler, lines = self.make_scheduler()
        self.source.poll = EmptySource().poll
        scheduler.tick()
        self.clock += timedelta(days=3)
        scheduler.tick()
        surfaces = [self.cli('status')[1], self.cli('status', '--json')[1], *lines, self.health()[1],
                    *[json.dumps(asdict(notice)) for notice in self.notifier.audit]]
        self.assertTrue(self.notifier.audit)
        for notice in self.notifier.audit:
            poisoned = replace(notice, body={**notice.body, 'detail': evidence})
            surfaces.append(render(poisoned)[1])
        for surface in surfaces:
            for private in (ID, ID2, ID3, path(ID), raw(ID), PRIVATE, TOKEN):
                self.assertNotIn(private, surface)
        self.assertEqual(self.day()['diagnostic'], 'rate limited')

    def test_t19_unauthenticated_reserve_and_three_rest_calls(self):
        self.cursor()
        self.fake.usual()
        self.stored(record())
        self.set_rate(remaining=9)
        self.tick()
        self.assertEqual(self.fake.urls, [])
        self.set_rate(remaining=20)
        result = self.tick()
        self.assertEqual(result['covered'], 1)
        self.assertEqual(result['days_complete'], 1)
        self.assertEqual(sum(url.startswith(gap.COMMITS) for url in self.fake.urls), 3)
        self.assertTrue(all(request.get_header('Authorization') is None
                            for request, _, _ in self.fake.calls))

    def test_t20_zero_found_only_when_upstream_matches_store(self):
        self.cursor()
        self.fake.usual()
        self.stored(record())
        self.tick()
        self.assertIn(D + ': complete, 0 found', self.cli('status')[1])
        self.clock += timedelta(days=1)
        self.tick()
        text = self.cli('status')[1]
        self.assertIn('2099-01-03: pending', text)
        self.assertEqual(text.count('0 found'), 1)

    def test_t21_invalid_is_not_conclusive_or_zero_found(self):
        self.cursor()
        self.fake.usual()
        self.fake.routes[raw(ID)] = record(ID2)
        self.source.poll = EmptySource().poll
        scheduler, lines = self.make_scheduler()
        scheduler.tick()
        self.assertEqual(self.day()['scan'], 'undecided')
        self.clock += timedelta(days=3)
        scheduler.tick()
        self.assertEqual(self.health()[0], 'unhealthy')
        self.assertEqual(len(self.notifier.audit), 1)
        self.assertEqual(json.loads(lines[-1])['cvelist_gap']['invalid'], 1)
        for surface in [self.cli('status')[1], lines[-1], render(self.notifier.audit[0])[1]]:
            self.assertNotIn('0 found', surface)

    def test_t22_absent_and_stale_are_separate_counts(self):
        self.cursor()
        self.fake.usual((ID, ID2))
        self.stored(record(ID2, stamp='2099-01-01T10:00:00Z'))
        heartbeat = self.tick()
        self.assertEqual((heartbeat['found_absent'], heartbeat['found_stale']), (1, 1))
        text = self.cli('status')[1]
        for phrase in ('1 found (absent)', '1 found (stale)', 'stale vs end of day'):
            self.assertIn(phrase, text)

    def test_dispatch_rechecks_delta_quota_backoff_and_auth(self):
        self.cursor()
        sql_threads = []
        self.db.set_trace_callback(lambda statement: sql_threads.append(get_ident()))
        self.addCleanup(self.db.set_trace_callback, None)
        # Raw reads are not gated by the REST reserve (review r2 finding 4); see the continuation test.
        for change, stalled_host in (('quota', 'api.github.com'),
                                     ('backoff', 'api.github.com'), ('auth', 'api.github.com')):
            with self.subTest(change=change, stalled_host=stalled_host):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?, ?)',
                                (gap.DAYS, gap.REGISTERED, 'github_retry_at'))
                self.fake.http.github_token = SecretToken(TOKEN) if change == 'auth' else None
                self.source = CveListSource(self.fake.http, self.store)
                self.audit = self.source.gap_audit
                self.set_rate(mode='token' if change == 'auth' else 'none')
                self.fake.calls.clear()
                self.fake.usual()
                entered, release = Event(), Event()

                def resolver(host, port, **kwargs):
                    if host == stalled_host and get_ident() != self.fake.owner:
                        entered.set()
                        release.wait(5)
                    return public_resolver(host, port, **kwargs)

                self.fake.http.resolver = resolver
                try:
                    self.tick()
                    self.assertTrue(entered.is_set())
                    worker = self.audit.worker
                    self.assertIsNotNone(worker)
                    before = self.fake.urls.copy()
                    if change == 'quota':
                        self.fake.routes[RELEASES_URL] = ([], 200, rate_headers(9))
                        self.source._get(RELEASES_URL, NOW)
                    elif change == 'backoff':
                        self.fake.routes[RELEASES_URL] = (b'', 429, {'Retry-After': '180'})
                        with self.assertRaisesRegex(ValueError, 'HTTP 429'):
                            self.source._get(RELEASES_URL, NOW)
                        self.assertIsNotNone(self.store.get_meta('github_retry_at'))
                    else:
                        self.fake.routes[RELEASES_URL] = lambda timeout: (b'', 401, {})
                        delta_open = self.fake.http.opener

                        def drop_token(request, timeout):
                            if not request.get_header('Authorization'):
                                self.fake.routes[RELEASES_URL] = ([], 200, rate_headers(60))
                            return delta_open(request, timeout)

                        # Only the live delta transport gets this opener.
                        self.fake.http.opener = drop_token
                        try:
                            self.source._get(RELEASES_URL, NOW)
                        finally:
                            self.fake.http.opener = delta_open
                        self.assertIsNone(self.fake.http.github_token)
                finally:
                    release.set()
                    if self.audit.worker is not None:
                        self.audit.worker.join(2)
                self.assertFalse(worker.is_alive())
                delta_calls = 2 if change == 'auth' else 1
                self.assertEqual(self.fake.urls, before + [RELEASES_URL] * delta_calls)
        self.assertTrue(sql_threads)
        self.assertEqual(set(sql_threads), {self.fake.owner})

    def test_socket_dispatch_runs_after_connect_before_first_http_bytes(self):
        deadline = type('Deadline', (), {'check': lambda self: None})()
        sock = Mock()
        connected = Event()

        def check():
            self.assertTrue(connected.is_set())
            raise gap._Pause()

        connection = _HTTPSConnection('api.github.com', resolver=public_resolver,
                                      deadline=deadline, before_dispatch=check)

        def connect():
            connection.sock = sock
            connected.set()

        with patch.object(connection, 'connect', side_effect=connect), self.assertRaises(gap._Pause):
            connection.send(b'fictional request')
        sock.sendall.assert_not_called()

    def test_late_audit_rate_headers_cannot_replace_a_newer_delta_observation(self):
        self.cursor()
        self.fake.usual()
        tip_url = listing(tip=True)
        tip = self.fake.routes[tip_url]
        entered, release = Event(), Event()

        def slow_tip(timeout):
            entered.set()
            release.wait(5)
            return tip, 200, rate_headers(60)

        self.fake.routes[tip_url] = slow_tip
        self.fake.routes[RELEASES_URL] = ([], 200, rate_headers(9))
        try:
            self.tick()
            self.assertTrue(entered.is_set())
            self.source._get(RELEASES_URL, NOW)
        finally:
            release.set()
            if self.audit.worker is not None:
                self.audit.worker.join(2)
        self.tick()
        self.assertEqual(self.fake.urls, [tip_url, RELEASES_URL])
        self.assertIsNone(self.store.get_meta(gap.AUDIT_RATE))
        self.assertEqual(json.loads(self.store.get_meta(gap.DELTA_RATE))['remaining'], 9)

    def test_lineage_requires_in_bound_tip_and_matching_detail(self):
        self.cursor()
        self.fake.usual()
        early_tip = commit(TIP, D + 'T04:00:00Z', FIRST)
        self.fake.routes[listing(tip=True)] = [early_tip]
        first, previous = self.fake.routes[listing()]
        self.fake.routes[raw(ID)] = (b'', 404, {})
        for history, wrong_detail in (([first, previous], False),
                                      ([{**early_tip, 'parents': first['parents']}, first, previous], False),
                                      ([early_tip, first, previous], True)):
            with self.subTest(history=history, wrong_detail=wrong_detail):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
                self.fake.calls.clear()
                self.fake.routes[listing()] = history
                if wrong_detail:
                    detail = self.fake.routes[gap.COMMITS + '/' + FIRST]
                    detail['parents'] = early_tip['parents']
                self.tick()
                self.assertEqual(self.day()['scan'], 'undecided')
                self.assertEqual(self.day()['diagnostic'], 'commit proof')
                self.assertNotIn(raw(ID), self.fake.urls)

    def test_tip_at_midnight_or_missing_is_not_an_empty_success(self):
        self.cursor()
        for evidence in ([], [commit(TIP, '2099-01-03T00:00:00Z', FIRST)]):
            with self.subTest(evidence=evidence):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
                self.fake.routes[listing(tip=True)] = evidence
                result = self.tick()
                self.assertEqual(result['days_complete'], 0)
                self.assertEqual(self.day()['scan'], 'undecided')

    def test_t2_fallback_parent_must_match_both_sha_and_pre_midnight_date(self):
        self.cursor()
        self.fake.usual()
        self.fake.routes[listing()] = self.fake.routes[listing()][:1]
        for wrong in (commit(OTHER, '2099-01-01T21:52:00Z', OLDER),
                      commit(PREV, D + 'T00:00:00Z', OLDER),
                      commit(PREV, '2099-01-01T23:52:00Z', OLDER)):
            with self.subTest(parent=wrong):
                self.fake.calls.clear()
                self.fake.routes[gap.COMMITS + '/' + PREV] = wrong
                self.tick()
                self.assertEqual(self.day()['scan'], 'undecided')
                self.assertEqual(self.fake.urls[-1], gap.COMMITS + '/' + PREV)

    def test_detail_next_accepts_unquoted_rel_and_counts_page_two(self):
        self.cursor()
        self.fake.usual(())
        details = gap.COMMITS + '/' + FIRST
        detail = self.fake.routes[details]
        links = Message()
        links['Link'] = '<?page=2>; REL=next'
        links['Link'] = '<?page=1>; rel=first'
        self.fake.routes[details] = ({**detail, 'files': [{'filename': path(ID)}]}, 200,
                                     links)
        self.fake.routes[details + '?page=2'] = {**detail, 'files': [{'filename': path(ID2)}]}
        self.fake.routes[raw(ID2)] = record(ID2)
        self.tick()
        self.assertEqual(self.day()['counts'], {'deleted': 1, 'absent': 1})
        self.assertIn(details + '?page=2', self.fake.urls)

    def test_rejects_repeated_or_inconsistent_detail_pages_and_duplicate_ids(self):
        self.cursor()
        self.fake.usual()
        details = gap.COMMITS + '/' + FIRST
        detail = self.fake.routes[details]
        page_two = details + '?page=2'
        next_value = f'<{page_two}>; rel="last next"'
        distinct = {**detail, 'files': [{'filename': path(ID2)}]}
        cases = (
            ('duplicate page', next_value, detail, 'pagination'),
            ('empty page', next_value, {**detail, 'files': []}, 'pagination'),
            ('duplicate next', next_value + ', ' + next_value, distinct, 'pagination'),
            ('wrong endpoint', f'<{gap.COMMITS}/{OTHER}?page=2>; rel=next', distinct, 'pagination'),
            ('wrong page', f'<{details}?page=3>; rel=next', distinct, 'pagination'),
            ('duplicate ID', next_value, {**detail, 'files': [
                {'filename': path(ID).replace('/0xxx/', '/1xxx/')}]}, 'candidate identity'),
        )
        for case, link, second, diagnostic in cases:
            with self.subTest(case=case):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
                self.set_rate()
                self.fake.calls.clear()
                self.fake.routes[details] = (detail, 200, {'Link': link})
                self.fake.routes[page_two] = second
                self.tick()
                self.assertEqual(self.day()['scan'], 'undecided')
                self.assertEqual(self.day()['diagnostic'], diagnostic)
                self.assertFalse(any(url.startswith(gap.RAW) for url in self.fake.urls))

    def test_history_page_rejects_repeat_and_changed_lineage(self):
        self.cursor()
        self.fake.usual()
        first, previous = self.fake.routes[listing()]
        repeated = [commit(MIDDLE, COMMIT_TIME, FIRST), first, previous]
        for head, target, second in (
                (commit(FIRST, COMMIT_TIME, MIDDLE), listing(page=2), repeated),
                (first, listing(page=2, head=OTHER), [previous])):
            with self.subTest(target=target):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?)', (gap.DAYS, gap.REGISTERED))
                self.fake.calls.clear()
                self.fake.routes[listing()] = ([head], 200, next_header(target))
                self.fake.routes[listing(page=2)] = second
                self.tick()
                self.assertEqual(self.day()['scan'], 'undecided')
                self.assertNotIn(raw(ID), self.fake.urls)

    def test_history_three_page_cap_does_not_use_page_four(self):
        self.cursor()
        self.fake.usual()
        chain = [commit(MIDDLE, D + 'T01:00:00Z', OTHER),
                 commit(OTHER, D + 'T00:30:00Z', FIRST),
                 commit(FIRST, COMMIT_TIME, PREV),
                 commit(PREV, '2099-01-01T23:52:00Z', OLDER)]
        for page, item in enumerate(chain, 1):
            headers = next_header(listing(page=page + 1)) if page < len(chain) else {}
            self.fake.routes[listing(page=page)] = ([item], 200, headers)
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True), *(listing(page=p) for p in range(1, 4))])
        self.assertEqual(self.day()['scan'], 'undecided')
        self.assertEqual(self.day()['diagnostic'], 'pagination')

    def test_retry_oldest_attempt_first_after_restart_under_cycle_cap(self):
        self.cursor()
        candidates = tuple(f'CVE-2099-{i:04}' for i in range(301))
        self.fake.usual(candidates)
        detail = gap.COMMITS + '/' + FIRST
        original = self.fake.routes[detail]
        self.fake.routes[detail] = ({**original, 'files': original['files'][:300]}, 200,
                                    next_header(detail + '?page=2'))
        self.fake.routes[detail + '?page=2'] = {**original, 'files': original['files'][300:]}
        for cve in candidates:
            self.fake.routes[raw(cve)] = (b'fictional invalid payload', 200, {})
        last = raw(candidates[-1])
        self.tick()
        self.assertNotIn(last, self.fake.urls)
        self.assertEqual(sum(url.startswith(gap.RAW) for url in self.fake.urls), 300)
        self.tick()
        self.assertEqual(self.fake.urls.count(last), 1)
        self.fake.routes[last] = record(candidates[-1])
        self.audit = gap.GapAudit(self.fake.http)
        self.tick()
        self.assertEqual(self.fake.urls.count(last), 2)
        self.assertEqual(self.day()['paths'][path(candidates[-1])], 'absent')

    def test_completed_window_is_14_closed_utc_dates_with_pending_days(self):
        self.cursor()
        self.fake.usual()
        self.tick()
        self.clock = NOW + timedelta(days=13)
        self.assertEqual(self.tick()['found_absent'], 1)
        self.assertEqual(self.tick()['days_complete'], 1)
        self.clock = datetime.fromisoformat('2099-01-16T20:00:00-04:00')
        self.assertNotIn(D, gap.status(self.store, self.clock)['days'])
        result = self.tick()
        self.assertEqual((result['days_complete'], result['found_absent'], result['days_open']), (0, 0, 14))

    def test_first_midday_poll_registers_only_the_previous_closed_utc_day(self):
        self.clock = at('2099-01-03T12:00:00')
        self.tick()
        self.assertEqual(json.loads(self.store.get_meta(gap.DAYS)), {D: {'scan': 'pending'}})
        self.clock = at('2099-01-05T12:00:00')
        self.tick()
        self.assertEqual(sorted(json.loads(self.store.get_meta(gap.DAYS))),
                         [D, '2099-01-03', '2099-01-04'])

    def test_finished_work_is_collected_before_days_can_expire(self):
        # A poll that crosses UTC midnight must not expire a day whose result is
        # already queued: collect first, then register (which may expire it).
        calls = []
        real_register = gap._register
        with patch.object(self.audit, '_collect', side_effect=lambda *a: calls.append('collect')), \
                patch.object(gap, '_register', side_effect=lambda *a: (calls.append('register'), real_register(*a))[1]):
            self.tick()
        self.assertEqual(calls[:2], ['collect', 'register'])

    def test_expired_day_is_retained_for_14_utc_dates(self):
        self.tick()
        self.clock = NOW + timedelta(days=14)
        self.tick()
        self.assertEqual(self.day()['expired'], '2099-01-17')
        self.clock += timedelta(days=13)
        self.tick()
        self.assertIn(D, gap.status(self.store, self.clock)['days'])
        self.clock += timedelta(days=1)
        self.tick()
        self.assertNotIn(D, gap.status(self.store, self.clock)['days'])

    def test_same_id_invalid_record_is_not_covered_or_absent(self):
        self.cursor()
        self.fake.usual()
        invalid = record()
        invalid['cveMetadata']['state'] = 'fictional'
        self.fake.routes[raw(ID)] = invalid
        result = self.tick()
        self.assertEqual((result['invalid'], result['found_absent']), (1, 0))
        self.assertEqual(self.day()['scan'], 'undecided')

    def test_token_floor_and_dispatch_debit_without_response_headers(self):
        self.cursor()
        self.fake.usual()
        self.fake.http.github_token = SecretToken(TOKEN)
        self.set_rate(mode='token', remaining=99)
        self.tick()
        self.assertEqual(self.fake.urls, [])
        self.set_rate(mode='token', remaining=100)
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True)])
        self.assertEqual(self.day()['scan'], 'pending')

    def test_gap_outbox_revalidates_body_immediately_before_delivery(self):
        self.engine._health('kev', 'unhealthy', 'fictional')
        self.engine._health(gap.SOURCE, 'unhealthy', gap.health_detail(4, D), 'incomplete',
                            health_fields={'days_open': 4, 'oldest_open': D})
        secret = ' '.join((ID, path(ID), raw(ID), PRIVATE, TOKEN))
        send = self.notifier.send
        poisoned = []

        def poison_queued_gap(notice):
            if notice.record_id == 'kev':
                row = self.db.execute('SELECT id,body_json FROM outbox WHERE id > ?',
                                      (notice.key,)).fetchone()
                body = json.loads(row['body_json'])
                body.update(detail=secret, oldest_open=secret, days_open='4')
                self.db.execute('UPDATE outbox SET body_json=? WHERE id=?',
                                (json.dumps(body), row['id']))
                poisoned.append(row['id'])
            return send(notice)

        self.notifier.send = poison_queued_gap
        self.engine._flush()
        self.assertEqual(len(poisoned), 1)
        self.assertEqual(len(self.notifier.audit), 1)
        notice = self.notifier.audit[0]
        self.assertNotIn(secret, json.dumps(asdict(notice)))
        self.assertNotIn('days_open', notice.body)
        self.assertNotIn('oldest_open', notice.body)

    def stall_audit(self, host='api.github.com'):
        entered, release = Event(), Event()

        def resolver(destination, port, **kwargs):
            if destination == host and get_ident() != self.fake.owner:
                entered.set()
                release.wait(5)
            return public_resolver(destination, port, **kwargs)

        self.fake.http.resolver = resolver
        self.addCleanup(release.set)
        self.tick()
        self.assertTrue(entered.is_set())
        return release, self.audit.worker

    def test_in_flight_delta_consumes_rest_quota_at_dispatch(self):
        self.cursor()
        self.fake.usual()
        self.set_rate(remaining=10)
        release, worker = self.stall_audit()

        def delta_response(timeout):
            # The delta GET has reached its opener, but no headers have arrived.
            release.set()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(self.fake.urls, [RELEASES_URL])
            return [], 200, rate_headers(9)

        self.fake.routes[RELEASES_URL] = delta_response
        self.source._get(RELEASES_URL, NOW)
        self.assertEqual(self.day()['scan'], 'pending')

    def test_release_merge_publishes_backoff_at_rest_and_raw_dispatch(self):
        self.cursor()
        self.fake.usual()
        for host in ('api.github.com', gap.RAW_HOST):
            with self.subTest(host=host):
                self.db.execute('DELETE FROM meta WHERE k IN (?, ?, ?, ?)',
                                (gap.DAYS, gap.REGISTERED, 'github_retry_at', 'github_retry_mode'))
                self.set_rate()
                release, worker = self.stall_audit(host)
                before = self.fake.urls.copy()
                retry = (NOW + timedelta(minutes=3)).isoformat()
                state = ReleaseState(self.store, ())
                state.set_meta('github_retry_at', retry)
                state.set_meta('github_retry_mode', 'none')
                try:
                    with self.store.transaction():
                        state.merge(self.source)
                    self.assertEqual(self.store.get_meta('github_retry_at'), retry)
                finally:
                    release.set()
                    worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(self.fake.urls, before)

    def test_pagination_accepts_verified_numeric_links_for_history_and_detail(self):
        self.cursor()
        self.fake.usual()
        first, previous = self.fake.routes[listing()]
        detail = gap.COMMITS + '/' + FIRST
        numeric = 'https://api.github.com/repositories/20990001/commits'
        self.fake.routes[gap.REPOSITORY_URL] = {'id': 20990001, 'full_name': gap.REPOSITORY}
        self.fake.routes[listing()] = ([first], 200, next_header(
            listing(page=2).replace(gap.COMMITS, numeric)))
        self.fake.routes[listing(page=2)] = [previous]
        self.fake.routes[detail] = ({**first, 'files': [{'filename': 'fictional-manifest.json'}]}, 200,
                                    next_header(numeric + '/' + FIRST + '?page=2'))
        self.fake.routes[detail + '?page=2'] = {**first, 'files': [{'filename': path(ID)}]}
        self.assertEqual(self.tick()['found_absent'], 1)
        self.assertEqual(self.fake.urls, [listing(tip=True), listing(), gap.REPOSITORY_URL,
                                         listing(page=2), detail, detail + '?page=2', raw(ID)])

    def test_numeric_pagination_rejects_a_different_repository(self):
        self.cursor()
        self.fake.usual()
        first, previous = self.fake.routes[listing()]
        self.fake.routes[gap.REPOSITORY_URL] = {'id': 20990001, 'full_name': gap.REPOSITORY}
        target = listing(page=2).replace(gap.COMMITS, 'https://api.github.com/repositories/20990002/commits')
        self.fake.routes[listing()] = ([first], 200, next_header(target))
        self.fake.routes[listing(page=2)] = [previous]
        self.assertEqual(self.tick()['days_undecided'], 1)
        self.assertEqual(self.day()['diagnostic'], 'pagination')
        self.assertNotIn(listing(page=2), self.fake.urls)
        self.assertNotIn(target, self.fake.urls)

    def test_history_checkpoint_resumes_at_next_page_after_restart(self):
        self.cursor()
        self.fake.usual()
        first, previous = self.fake.routes[listing()]
        self.fake.routes[listing()] = ([first], 200, next_header(listing(page=2)))
        self.fake.routes[listing(page=2)] = [previous]
        self.set_rate(remaining=11)
        self.tick()
        self.assertEqual(self.fake.urls, [listing(tip=True), listing()])
        self.audit = gap.GapAudit(self.fake.http)
        self.set_rate()
        self.assertEqual(self.tick()['found_absent'], 1)
        self.assertEqual(self.fake.urls, [listing(tip=True), listing(), listing(page=2),
                                         gap.COMMITS + '/' + FIRST, raw(ID)])

    def test_large_detail_pages_resume_under_cycle_cap_after_restart(self):
        self.cursor()
        self.fake.usual()
        detail = gap.COMMITS + '/' + FIRST
        original = self.fake.routes[detail]
        pages = [detail, *(detail + f'?page={n}' for n in range(2, 6))]
        for index, url in enumerate(pages):
            files = [{'filename': f'fictional-notes/{index}/{n}.txt', 'patch': 'x' * 7450}
                     for n in range(300)]
            if index == 4:
                files[-1]['filename'] = path(ID)
            body = json.dumps({**original, 'files': files}).encode()
            self.assertGreater(len(body), 2 * 1024 * 1024)
            headers = next_header(pages[index + 1]) if index < 4 else {}
            self.fake.routes[url] = (body, 200, headers)
        self.tick()
        prefix = [listing(tip=True), listing(), *pages[:4]]
        self.assertEqual(self.fake.urls, prefix)
        self.assertEqual(self.day()['scan'], 'pending')
        self.audit = gap.GapAudit(self.fake.http)
        self.assertEqual(self.tick()['found_absent'], 1)
        self.assertEqual(self.fake.urls, prefix + pages[3:] + [raw(ID)])

    def test_rest_reserve_and_expired_observation_do_not_block_raw_continuation(self):
        self.cursor()
        self.fake.usual((ID, ID2))
        self.set_rate(remaining=12, reset=NOW + timedelta(minutes=1))
        self.fake.routes[raw(ID)] = (b'fictional invalid payload', 200, {})
        self.fake.routes[raw(ID2)] = (b'fictional invalid payload', 200, {})
        self.assertEqual(self.tick()['invalid'], 2)
        rest = [listing(tip=True), listing(), gap.COMMITS + '/' + FIRST]
        self.assertEqual(self.fake.urls, rest + [raw(ID), raw(ID2)])
        self.fake.routes[raw(ID)] = record()
        self.assertEqual(self.tick()['found_absent'], 1)
        self.fake.routes[raw(ID2)] = record(ID2)
        self.clock += timedelta(minutes=2)
        self.audit = gap.GapAudit(self.fake.http)
        result = self.tick()
        self.assertEqual((result['found_absent'], result['days_complete']), (2, 1))
        self.assertEqual([url for url in self.fake.urls if not url.startswith(gap.RAW)], rest)

    def test_health_delivery_uses_durable_component_despite_poisoned_routing(self):
        self.engine._health('kev', 'unhealthy', 'fictional')
        self.engine._health(gap.SOURCE, 'unhealthy', gap.health_detail(4, D), 'incomplete',
                            health_fields={'days_open': 4, 'oldest_open': D})
        private = (ID, path(ID), raw(ID), PRIVATE, TOKEN)
        send = self.notifier.send

        def poison_queued_gap(notice):
            if notice.record_id == 'kev':
                row = self.db.execute('SELECT id,body_json FROM outbox WHERE id > ?',
                                      (notice.key,)).fetchone()
                body = json.loads(row['body_json'])
                poison = ' '.join(private)
                body.update(record_id=poison, watch_id='fictional-media', name=PRIVATE,
                            repository=poison, release_behind=True, items=[{'body': poison}],
                            state='healthy', detail=poison, error=TOKEN)
                self.db.execute('UPDATE outbox SET body_json=? WHERE id=?',
                                (json.dumps(body), row['id']))
            return send(notice)

        self.notifier.send = poison_queued_gap
        self.engine._flush()
        notice, = self.notifier.audit
        self.assertEqual(notice.watch_id, '')
        title, detail, _, _ = render(notice)
        self.assertEqual((title, detail), ('Cornicen: cvelist_gap unhealthy', gap.health_detail(4, D)))
        for value in private:
            self.assertNotIn(value, json.dumps(asdict(notice)) + title + detail)

# script-purpose: Verify Debian bulk discovery, merging, safety and scheduling offline.
# script-class: harness
# script-trigger: unittest discovery and make gate.
# script-tests: tests/test_task4_b1.py
"""Read invented HTTP responses; write temporary databases and zips. unittest exits 0/1.

The 20,000-record RSS check runs in a fresh process.
"""
from dataclasses import replace
from datetime import timedelta
from io import BytesIO
import json
from pathlib import Path
import random
import resource
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings
import zipfile

from cornicen.adapterstore import AdapterStore, canonical, instant, stamp
from cornicen.adapters import REGISTRY
from cornicen.fetch import Http
from cornicen.store import Store
from cornicen.osv import normalise

ROOT = Path(__file__).resolve().parents[1]
T = '2099-01-01T00:00:00Z'
HOST = 'osv-vulnerabilities.storage.googleapis.com'
BASE = 'https://' + HOST
DISCOVERY = BASE + '/ecosystems.txt'
RESOURCE = 'debian/advisories'


def record(identity='DSA-9001-1', ecosystem='Debian:12'):
    return dict(id=identity, modified=T, details='invented', affected=[dict(
        package=dict(ecosystem=ecosystem, name='sample-package'),
        ranges=[dict(type='ECOSYSTEM', events=[dict(introduced='0'), dict(fixed='99.2-1')])])])


def archive(records=(), entries=()):
    output = BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED, allowZip64=True) as z:
        warnings.simplefilter('ignore', UserWarning)
        for r in records:
            z.writestr(r['id']+'.json', canonical(r))
        for name, body in entries:
            z.writestr(name, body)
    return output.getvalue()


class Bucket:
    def __init__(self):
        self.responses = {}; self.requests = []

    def resolver(self, host, port, **kwargs):
        assert host == HOST
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]

    def open(self, request, timeout):
        self.requests.append((request.get_method(), request.full_url, dict(request.header_items())))
        script = self.responses[request.full_url]
        if isinstance(script, list): script = script.pop(0)
        if isinstance(script, BaseException): raise script
        if isinstance(script, bytes): script = dict(body=script)
        body = script.get('body', b'')
        response = BytesIO(body)
        response.status = script.get('status', 200)
        response.headers = script.get('headers', {})
        return response


class Task4B1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.store = Store(self.directory/'db'); self.store.migrate()
        self.addCleanup(self.store.connection.close)
        self.db = self.store.connection
        self.p = AdapterStore(self.store, self.directory, rng=random.Random(1))
        self.now = instant(T)
        self.bucket = Bucket()

    def adapter(self):
        from cornicen.sources.osv_debian import DebianOsv, DebianState
        self.state = DebianState(self.store)
        self.http = Http('Cornicen/test', {}, opener=self.bucket, resolver=self.bucket.resolver, data_dir=self.directory)
        return DebianOsv(self.http, self.state, lambda: self.now, data_dir=self.directory)

    def scripts(self, a=None, b=None, discovery=None):
        self.bucket.responses = {DISCOVERY: discovery if discovery is not None else
                                 (b'Debian:12\nDebian:13\n' if b is not None else b'Debian:12\n')}
        for ecosystem, value in (('Debian:12', a), ('Debian:13', b)):
            if value is not None:
                self.bucket.responses[BASE+'/'+ecosystem.replace(':', '%3A')+'/all.zip'] = value

    def members(self, outcome):
        return [json.loads(line) for line in Path(outcome['members_file']).read_text().splitlines()]

    def process(self, outcome):
        return self.p.process('debian', [outcome], stamp(self.now), export=True, required_resources=(RESOURCE,))

    def cycle(self, adapter):
        outcome = adapter.poll(cutoff=None)[0]
        members = self.members(outcome) if 'members_file' in outcome else []
        result = self.process(outcome)
        self.now += timedelta(days=1)
        return result, members

    def health(self, dimension):
        return self.db.execute('SELECT state FROM source_health WHERE source=? AND dimension=?', ('debian', dimension)).fetchone()[0]

    def test_t10_discovery(self):
        from cornicen.sources.osv_debian import parse_discovery
        for newline in ('\n', '\r\n'):
            self.assertEqual(parse_discovery(newline.join(['', 'Debian', 'Debian:12', 'Debian', 'Debian-like', 'debian', 'Ubuntu:22.04:LTS', '']).encode()), ['Debian', 'Debian:12'])
        for body in (b'', b' \n', b'<html>', b'\xff', b'x'*101, b'Ubuntu', b'Debian\nfoo\x00', b'Debian\nfoo\xe2\x80\x8b'):
            with self.subTest(body=body):
                adapter = self.adapter(); self.scripts(discovery=body)
                outcome = adapter.poll(cutoff=None)[0]
                self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=200, invalid_envelope=True))
                self.assertEqual(self.process(outcome), 'FAILED'); self.assertEqual(self.health('fetch'), 'healthy')
                self.now += timedelta(days=1)
        self.scripts(archive([record()]), discovery=b'Debian:12\n')
        self.assertEqual(self.cycle(self.adapter())[0], 'COMPLETE')
        self.assertEqual(json.loads(self.store.get_meta('debian:copies')), {})
        self.assertTrue(all('/Debian%3A13/' not in r[1] for r in self.bucket.requests))

    def test_t10_t11_short_rebaseline_and_stale_ack(self):
        adapter = self.adapter()
        a, b = record(), record(ecosystem='Debian:13')
        other = record('DSA-9002-1'); other_b = record('DSA-9002-1', 'Debian:13')
        self.scripts(archive([a, other]), archive([b, other_b]))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.scripts(archive([a, other]), archive([other_b]))
        self.assertEqual(self.cycle(adapter), ('PARTIAL', [normalise(dict(other, affected=other['affected']+other_b['affected']))]))
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)
        self.assertEqual(self.cycle(adapter)[0], 'PARTIAL')
        self.p.rebaseline('debian', stamp(self.now))
        self.assertEqual(json.loads(self.store.get_meta('ack_absent:debian:'+RESOURCE)), [a['id']])
        # A second id loses a copy after the staged enumeration was acknowledged.
        self.scripts(archive([a, other]), discovery=b'Debian:12\n')
        result, members = self.cycle(adapter)
        self.assertEqual(result, 'PARTIAL'); self.assertEqual([m['id'] for m in members], [a['id']])
        self.assertEqual(json.loads(self.store.get_meta('ack_absent:debian:'+RESOURCE)), [])
        self.p.rebaseline('debian', stamp(self.now))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')

    def test_t10_overlong_line_invalidates_valid_discovery(self):
        self.scripts(discovery=b'Debian\n' + b'x'*101 + b'\n')
        self.bucket.responses[BASE+'/Debian/all.zip'] = archive([record(ecosystem='Debian')])
        outcome = self.adapter().poll()[0]
        self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=200, invalid_envelope=True))
        self.assertEqual(self.process(outcome), 'FAILED')
        self.assertEqual(self.health('fetch'), 'healthy')
        self.assertEqual([r[1] for r in self.bucket.requests], [DISCOVERY])

    def test_t11_overlap_with_equal_common_fields_conflicts(self):
        a = record()
        b = record()
        b['affected'][0]['package']['name'] = 'another-invented-package'
        self.assertEqual({k:v for k,v in a.items() if k != 'affected'},
                         {k:v for k,v in b.items() if k != 'affected'})
        self.scripts(archive([a]), archive([b]))
        result, members = self.cycle(self.adapter())
        self.assertEqual(members, [dict(id=a['id'], mapping_error='projection conflict')])
        self.assertEqual(result, 'PARTIAL')

    def test_t11_raw_dropped_field_difference_conflicts(self):
        a = record()
        b = dict(a, severity=[dict(type='CVSS_V3', score='invented-score')])
        self.assertEqual(normalise(a), normalise(b))
        self.scripts(archive([a]), archive([b]))
        result, members = self.cycle(self.adapter())
        self.assertEqual(members, [dict(id=a['id'], mapping_error='projection conflict')])
        self.assertEqual(result, 'PARTIAL')

    def test_t13_post_pin_longest_retry_in_both_orders(self):
        adapter = self.adapter()
        self.scripts(archive([record('seed')]))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        self.assertTrue(self.state.pinned())
        for waits in ((120, 7200), (7200, 120)):
            with self.subTest(waits=waits):
                self.scripts(*(dict(status=429, headers={'retry-after':str(wait)}) for wait in waits),
                             discovery=b'Debian:12\nDebian:13\nDebian:14\n')
                good = record('intact', 'Debian:14')
                self.bucket.responses[BASE+'/Debian%3A14/all.zip'] = archive([good])
                outcome = adapter.poll()[0]
                self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=200,
                    members_file=outcome['members_file'], coverage_complete=False,
                    subrequest_failures=2, subrequest_http_errors=2,
                    headers={'retry-after':'7200'}, rate_limited=True))
                self.assertEqual(self.members(outcome), [normalise(good)])
                self.assertEqual(self.process(outcome), 'FAILED')
                due = self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE source=? AND resource=?',
                                      ('debian', RESOURCE)).fetchone()[0]
                self.assertEqual(instant(due), self.now+timedelta(seconds=7200))
                self.assertEqual(self.db.execute("SELECT state FROM advisories WHERE source_id='intact'").fetchone()[0], 'active')
                self.now += timedelta(days=1)

    def test_t13_valid_json_over_member_cap_is_quarantined(self):
        good = record('good')
        cap = 1024**2
        entries = []
        for identity, size in (('boundary', cap), ('large-plus-one', cap + 1),
                               ('large-two-mib', 2 * cap)):
            raw = record(identity)
            body = canonical(raw).encode()
            # Trailing JSON whitespace keeps even the capped read valid, so
            # only the archive's byte limit can quarantine oversized members.
            body += b' ' * (size - len(body))
            self.assertEqual(len(body), size)
            self.assertEqual(json.loads(body), raw)
            self.assertEqual(json.loads(body[:cap + 1]), raw)
            entries.append((identity + '.json', body))
        self.scripts(archive([good], entries=entries))
        outcome = self.adapter().poll()[0]
        self.assertEqual(self.members(outcome), [normalise(record('boundary')), normalise(good),
            dict(id='large-plus-one', mapping_error='invalid archive member'),
            dict(id='large-two-mib', mapping_error='invalid archive member')])
        self.assertEqual(self.process(outcome), 'PARTIAL')
        for identity in ('good', 'boundary'):
            with self.subTest(accepted=identity):
                self.assertEqual(self.db.execute('SELECT state FROM advisories WHERE source_id=?',
                                                (identity,)).fetchone()[0], 'active')
        for identity in ('large-plus-one', 'large-two-mib'):
            with self.subTest(quarantined=identity):
                self.assertIsNone(self.db.execute('SELECT 1 FROM advisories WHERE source_id=?',
                                                 (identity,)).fetchone())

    def test_t13_exact_entry_cap_is_accepted(self):
        # Exercise the _archive seam with a real central directory and SQLite
        # index, avoiding store processing of 150,000 intentionally tiny members.
        path = self.directory/'boundary.zip'
        path.write_bytes(archive(entries=((f'x{n}.json', '{}') for n in range(150000))))
        with zipfile.ZipFile(path) as z:
            self.assertEqual(len(z.infolist()), 150000)
        index = sqlite3.connect(':memory:')
        self.addCleanup(index.close)
        with index:
            index.execute('CREATE TABLE copies(pass INTEGER,id TEXT,ordinal INTEGER,ecosystem TEXT,raw TEXT,error INTEGER)')
            self.assertTrue(self.adapter()._archive(index, 1, 0, 'Debian:12', path))
            self.assertEqual(index.execute('SELECT count(*) FROM copies').fetchone()[0], 150000)

    def test_t14_hop_requires_https_default_port_and_no_userinfo(self):
        adapter = self.adapter()
        adapter.validate_hop(DISCOVERY)
        adapter.validate_hop('https://'+HOST+':443/ecosystems.txt')
        for url in ('http://'+HOST+'/ecosystems.txt',
                    'https://'+HOST+':444/ecosystems.txt',
                    'https://user@'+HOST+'/ecosystems.txt'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                adapter.validate_hop(url)

    def test_t14_discovery_request_has_64k_limit(self):
        adapter = self.adapter()
        self.scripts(archive([record()]))
        with patch.object(self.http, 'get', wraps=self.http.get) as get:
            self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        discovery_calls = [call for call in get.call_args_list if call.args[0] == DISCOVERY]
        self.assertEqual(len(discovery_calls), 1)
        self.assertEqual(discovery_calls[0].kwargs.get('max_bytes'), 65536)

    def test_t11_merge_and_conflict_refetch(self):
        adapter = self.adapter(); a = record(); b = record(ecosystem='Debian:13')
        self.scripts(archive([a]), archive(entries=[(a['id']+'.json', json.dumps(a, indent=2))]))
        self.assertEqual(len(self.cycle(adapter)[1]), 1)
        self.scripts(archive([a]), archive([b]))
        result, members = self.cycle(adapter)
        self.assertEqual(result, 'COMPLETE'); self.assertEqual(len(members[0]['products']), 2)
        for change in ({'details':'different'}, {'modified':'2099-01-02T00:00:00Z'}, {'affected':a['affected']}):
            bad = dict(b, **change)
            if bad == a: bad['summary'] = 'overlap conflict'
            self.scripts(archive([a]), archive([bad]))
            result, members = self.cycle(adapter)
            self.assertEqual(result, 'PARTIAL'); self.assertEqual(members, [dict(id=a['id'], mapping_error='projection conflict')])
            self.assertEqual(self.db.execute('SELECT count(*) FROM advisory_evidence').fetchone()[0], 2)
            # Invalid copies must neither clear the conflict nor count as a
            # coherent pass. A later valid observation still needs two passes.
            damaged = archive(entries=[(a['id']+'.json', b'\xff')])
            self.scripts(damaged, damaged)
            result, members = self.cycle(adapter)
            self.assertEqual(result, 'PARTIAL')
            self.assertEqual(members, [dict(id=a['id'], mapping_error='invalid archive member')])
            self.assertIn(a['id'], json.loads(self.store.get_meta('debian:conflicts')))
            # Coherent first pass, unstable second pass.
            self.scripts(archive([a]), archive([b]))
            url = BASE+'/Debian%3A13/all.zip'
            self.bucket.responses[url] = [archive([b]), archive([dict(b, details='changed')])]
            self.assertEqual(self.cycle(adapter)[0], 'PARTIAL')
            self.scripts(archive([a]), archive([b])); start = len(self.bucket.requests)
            self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
            self.assertEqual(len(self.bucket.requests)-start, 6)
        self.assertEqual(json.loads(self.store.get_meta('debian:conflicts')), [])
        # An unknown OSV field named mapping_error is still raw input and must
        # pass through normalise, rather than impersonating an internal error.
        self.scripts(archive([dict(a, mapping_error='raw extension')]), archive([dict(a, mapping_error='raw extension')]))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')

    def test_t11_withdrawn_and_never_accepted_short(self):
        adapter = self.adapter(); a = record(); b = record(ecosystem='Debian:13')
        self.scripts(archive([a]), archive([b])); self.cycle(adapter)
        a['withdrawn'] = b['withdrawn'] = T
        self.scripts(archive([a]), archive([b])); self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        self.scripts(archive([a]), archive([])); self.assertEqual(self.cycle(adapter), ('COMPLETE', []))
        self.assertEqual(self.db.execute('SELECT state FROM advisories').fetchone()[0], 'withdrawn')
        c = record('DSA-9003-1'); d = dict(record('DSA-9003-1', 'Debian:13'), details='conflict')
        self.scripts(archive([a, c]), archive([d])); self.assertEqual(self.cycle(adapter)[0], 'PARTIAL')
        self.scripts(archive([a, c]), archive([]))
        result, members = self.cycle(adapter)
        self.assertEqual(result, 'PARTIAL'); self.assertIn(dict(id=c['id'], mapping_error='projection incomplete'), members)

    def test_t11_zero_copy_never_accepted_then_active(self):
        adapter = self.adapter()
        a, b = record(), record(ecosystem='Debian:13')
        self.scripts(archive([a]), archive([dict(b, details='conflict')]))
        self.assertEqual(self.cycle(adapter)[0], 'PARTIAL')
        self.assertIsNone(self.state.advisory_state(a['id']))
        self.assertEqual(self.state.meta('copies'), {a['id']: ['Debian:12', 'Debian:13']})
        self.scripts(archive(), archive())
        result, members = self.cycle(adapter)
        self.assertEqual(members, [dict(id=a['id'], mapping_error='projection incomplete')])
        self.assertEqual(result, 'PARTIAL')
        self.assertIsNotNone(self.db.execute('SELECT 1 FROM quarantine WHERE source_id=?',
                                            (a['id'],)).fetchone())
        # Recover through two coherent passes, then lose every accepted copy.
        self.scripts(archive([a]), archive([b]))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')]
        self.scripts(archive(), archive())
        self.assertEqual(self.cycle(adapter), ('PARTIAL', []))
        self.assertEqual(self.state.advisory_state(a['id']), 'active')
        self.assertEqual([tuple(r) for r in self.db.execute('SELECT * FROM advisory_evidence')], before)
        self.p.rebaseline('debian', stamp(self.now))
        self.assertEqual(self.state.acknowledged(), {a['id']})
        self.assertEqual(self.cycle(adapter), ('COMPLETE', []))

    def check_surrogate_member(self, field):
        bad, good = record('bad'), record('good')
        if field == 'package':
            bad['affected'][0]['package']['name'] = '\ud800'
        else:
            bad[field] = '\ud800'
        # Normalisation preserves these values; downstream UTF-8 staging fails.
        with self.assertRaises(UnicodeEncodeError):
            canonical(normalise(bad)).encode('utf-8', errors='strict')
        self.scripts(archive([good], entries=[('bad.json', json.dumps(bad, ensure_ascii=True))]))
        outcome = self.adapter().poll()[0]
        self.assertEqual(outcome['status'], 200)
        self.assertIn('members_file', outcome)
        self.assertEqual(self.members(outcome), [dict(id='bad', mapping_error='invalid archive member'),
                                                normalise(good)])
        self.assertEqual(self.process(outcome), 'PARTIAL')
        self.assertEqual(self.state.advisory_state('good'), 'active')
        self.assertIsNone(self.state.advisory_state('bad'))
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM quarantine WHERE source_id='bad'").fetchone())
        self.assertEqual(self.health('fetch'), 'healthy')

    def test_t13_lone_surrogate_details_isolated(self):
        self.check_surrogate_member('details')

    def test_t13_lone_surrogate_summary_isolated(self):
        self.check_surrogate_member('summary')

    def test_t13_lone_surrogate_package_isolated(self):
        self.check_surrogate_member('package')

    def test_t14_debian_user_agent_disclosure(self):
        sentence = "Requests carry Cornicen's User-Agent, which includes its version and the repository URL."
        for path, start in (('README.md', 'When the Debian adapter is enabled'),
                            ('docs/adapters.md', '## Debian via OSV')):
            with self.subTest(path=path):
                disclosure = (ROOT/path).read_text().split(start, 1)[1]
                self.assertIn(sentence, ' '.join(disclosure.split()))

    def test_t13_envelopes_and_statuses(self):
        adapter = self.adapter()
        for body in (b'<html>', b'  <html>'+archive([record()]), b'not a zip', archive()[:-22], archive(entries=[('../x.json', '{}')]),
                     archive(entries=[('a/b.json', '{}')]), archive(entries=[('CVE:2099-1.json', '{}')]),
                     archive([record(), record()])):
            with self.subTest(body=body[:20]):
                self.scripts(body)
                outcome = adapter.poll(cutoff=None)[0]
                self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=200, invalid_envelope=True))
                self.assertEqual(self.process(outcome), 'FAILED'); self.assertEqual(self.health('fetch'), 'healthy')
                self.now += timedelta(days=1)
        for discovery in (False, True):
            for status in (201, 204, 206, 304, 429):
                with self.subTest(discovery=discovery, status=status):
                    with self.store.transaction():
                        self.db.execute('DELETE FROM adapter_retries')
                    reply = dict(status=status, headers={'retry-after':'7200'})
                    self.scripts(archive([record()]), discovery=reply if discovery else None)
                    if not discovery: self.bucket.responses[BASE+'/Debian%3A12/all.zip'] = reply
                    outcome = adapter.poll(cutoff=None)[0]
                    expected = dict(path=RESOURCE, unconditional=True, status=status, headers=reply['headers'])
                    if status < 300: expected.update(invalid_envelope=True, invalid_status=True)
                    else: expected['rate_limited'] = status == 429
                    if not discovery and status < 300: expected['rate_limited'] = False
                    self.assertEqual(outcome, expected)
                    self.assertEqual(self.process(outcome), 'FAILED'); self.assertEqual(self.health('fetch'), 'unhealthy')
                    due = self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE resource=?', (RESOURCE,)).fetchone()[0]
                    self.assertEqual(instant(due), self.now+timedelta(seconds=7200))
                    self.now += timedelta(days=1)

    def test_t13_member_errors_and_limits(self):
        adapter = self.adapter()
        good = record('good')
        for body in (b'\xff', b'[]', b'{"id":"y"}', b'x'*(1024**2+1)):
            self.scripts(archive([good], [('x.json', body)]))
            outcome = adapter.poll(cutoff=None)[0]
            self.assertIn(dict(id='x', mapping_error='invalid archive member'), self.members(outcome))
            self.assertEqual(self.process(outcome), 'PARTIAL')
            self.assertEqual(self.db.execute("SELECT state FROM advisories WHERE source_id='good'").fetchone()[0], 'active')
            self.now += timedelta(days=1)
        raw = bytearray(archive([good, record('x')]))
        # Corrupt only x's stored payload, leaving its central directory intact.
        with zipfile.ZipFile(BytesIO(raw)) as z: offset = z.getinfo('x.json').header_offset
        name_len, extra_len = struct.unpack_from('<HH', raw, offset+26)
        raw[offset+30+name_len+extra_len] ^= 1
        self.scripts(bytes(raw)); outcome = adapter.poll(cutoff=None)[0]
        self.assertIn(dict(id='x', mapping_error='invalid archive member'), self.members(outcome))
        self.assertEqual(self.process(outcome), 'PARTIAL'); self.now += timedelta(days=1)
        for kind in ('encrypted', 'total', 'count'):
            raw = bytearray(archive([good]))
            central = raw.index(b'PK\x01\x02')
            if kind == 'encrypted': struct.pack_into('<H', raw, central+8, 1)
            if kind == 'total': struct.pack_into('<I', raw, central+24, 1024**3+1)
            if kind == 'count': raw = archive(entries=((f'x{n}.json', '{}') for n in range(150001)))
            self.scripts(bytes(raw)); outcome = adapter.poll(cutoff=None)[0]
            self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=200, invalid_envelope=True))
            self.assertEqual(self.process(outcome), 'FAILED'); self.now += timedelta(days=1)

    def test_t13_folded_failures_and_pin(self):
        adapter = self.adapter(); a, b = record('a'), record('b', 'Debian:13')
        short = dict(body=archive([a]), headers={'Content-Length':'999999'})
        for failure, expected in ((OSError('offline'), dict(status=0, transport_error=True)),
                                  (EOFError(), dict(status=200, transfer_complete=False, body='{}')),
                                  (short, dict(status=200, transfer_complete=False, body='{}'))):
            self.scripts(failure, archive([b])); outcome = adapter.poll(cutoff=None)[0]
            self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, **expected))
            self.assertEqual(self.process(outcome), 'FAILED' if expected['status']==0 else 'PARTIAL')
            self.assertIsNone(self.store.get_meta('baseline_pinned:debian:'+RESOURCE)); self.now += timedelta(days=1)
        slow = dict(status=429, headers={'retry-after':'7200'})
        for other in (dict(status=503, headers={'retry-after':'120'}), b'<html>'):
            for values in ((other, slow), (slow, other)):
                self.scripts(*values); outcome = adapter.poll(cutoff=None)[0]
                self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=429, headers=slow['headers'], rate_limited=True))
                self.assertEqual(self.process(outcome), 'FAILED'); self.now += timedelta(days=1)
        self.scripts(archive([a]), archive([b])); self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        self.assertEqual(json.loads(self.store.get_meta('baseline_pinned:debian:'+RESOURCE)), ['a', 'b'])
        # Rate limiting survives when the selected longest wait belongs to 503.
        self.scripts(dict(status=503, headers={'retry-after':'8000'}), dict(status=429, headers={'retry-after':'120'}))
        outcome = adapter.poll(cutoff=None)[0]
        self.assertEqual(outcome, dict(path=RESOURCE, unconditional=True, status=503, headers={'retry-after':'8000'}, rate_limited=True))
        self.assertEqual(self.process(outcome), 'FAILED'); self.now += timedelta(days=1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbox WHERE pair_key='|baseline:debian'").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM events WHERE type='new-match'").fetchone()[0], 0)
        for failure, classification, n, m in ((OSError(), 'PARTIAL', 1, 0), (slow, 'FAILED', 1, 1), (b'<html>', 'PARTIAL', 0, 0)):
            self.scripts(archive([record('c')]), failure)
            outcome = adapter.poll(cutoff=None)[0]
            expected = dict(path=RESOURCE, unconditional=True, status=200, members_file=outcome['members_file'], coverage_complete=False,
                            subrequest_failures=n, subrequest_http_errors=m, headers=slow['headers'] if m else {}, rate_limited=bool(m))
            self.assertEqual(outcome, expected)
            self.assertEqual(self.process(outcome), classification)
            self.assertIsNotNone(self.db.execute("SELECT 1 FROM advisories WHERE source_id='c'").fetchone())
            self.assertEqual(self.health('fetch'), 'unhealthy' if n else 'healthy'); self.now += timedelta(days=1)
        self.assertEqual(len(list(self.directory.glob('*.download'))), 0)
        self.assertEqual(len(list(self.directory.glob('debian-merge-*'))), 0)

    def test_t13_cleanup_on_exception(self):
        adapter = self.adapter(); self.scripts(archive([record()]))
        with patch('cornicen.sources.osv_debian.normalise', side_effect=RuntimeError('injected')):
            with self.assertRaises(RuntimeError): adapter.poll(cutoff=None)
        self.assertFalse(list(self.directory.glob('*.download')))
        self.assertFalse(list(self.directory.glob('debian-merge-*')))
        self.assertFalse(list(self.directory.glob('debian-members-*')))

    def test_t14_transport_and_gate(self):
        from cornicen.config import DOWNLOAD_BUDGETS
        from cornicen.fetch import SOURCE_HOSTS
        self.assertEqual(DOWNLOAD_BUDGETS['osv_debian'], dict(max_bytes=256*1024**2, deadline_seconds=900))
        self.assertEqual(SOURCE_HOSTS['osv_debian'], frozenset({HOST}))
        adapter = self.adapter(); self.scripts(archive([record()]))
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        adapter.validate_hop(DISCOVERY)
        adapter.validate_hop(BASE+'/Debian%3A12/all.zip')
        for bad in (BASE+'/Debian%3A99/all.zip', BASE+'/ecosystems.txt?', BASE+'/ecosystems.txt#', 'https://example.invalid/ecosystems.txt'):
            with self.assertRaises(ValueError): adapter.validate_hop(bad)
        self.scripts(archive([record()]))
        self.bucket.responses[BASE+'/Debian%3A12/all.zip'] = [dict(status=302, headers={'Location':BASE+'/Debian%3A12/all.zip'}), archive([record()])]
        self.assertEqual(self.cycle(adapter)[0], 'COMPLETE')
        for suffix in ('/Debian%3A99/all.zip', '/ecosystems.txt?x=1', '/ecosystems.txt#x', '/unlisted'):
            self.scripts(discovery=dict(status=302, headers={'Location':BASE+suffix}))
            self.assertEqual(adapter.poll(cutoff=None)[0], dict(path=RESOURCE, unconditional=True, status=0, transport_error=True))
        self.scripts(discovery=dict(status=302, headers={'Location':'https://example.invalid/ecosystems.txt'}))
        self.assertTrue(adapter.poll(cutoff=None)[0]['transport_error'])
        for _, _, headers in self.bucket.requests:
            self.assertEqual(headers, {'User-agent':'Cornicen/test'})
        factory = unittest.mock.Mock(side_effect=AssertionError('ineffective'))
        self.assertEqual(self.p.dispatch(REGISTRY, {'debian':True}, {'debian':factory}, stamp(self.now)), {})
        factory.assert_not_called(); self.assertTrue(REGISTRY['debian'].independent)
        self.assertFalse(REGISTRY['debian'].last_modified_validated)

    def dispatch(self, adapter):
        return self.p.dispatch({'debian':replace(REGISTRY['debian'], gate='met')}, {'debian':True}, {'debian':lambda:adapter}, stamp(self.now))

    def test_t15_cadence_clock_and_dispatch_backoff(self):
        adapter = self.adapter()
        early = 'Wed, 31 Dec 2098 22:00:00 GMT'; late = 'Thu, 01 Jan 2099 00:00:00 GMT'
        self.scripts(dict(body=archive([record()]), headers={'Last-Modified':late}), dict(body=archive([record('b')]), headers={'Last-Modified':early}))
        outcome = adapter.poll(cutoff=None)[0]
        self.assertEqual(outcome['publication_clock'], dict(provenance='gate_validated_last_modified', value='2098-12-31T22:00:00Z'))
        self.process(outcome); self.assertEqual(self.health('freshness'), 'unknown')
        self.now += timedelta(hours=1); count = len(self.bucket.requests)
        self.dispatch(adapter); self.assertTrue(adapter.skipped); self.assertEqual(len(self.bucket.requests), count)
        self.now += timedelta(hours=23); self.dispatch(adapter); self.assertFalse(adapter.skipped)
        self.assertEqual(list(adapter.retry(RESOURCE)), []); self.assertEqual(list(adapter.audit(RESOURCE)), [])
        # Dispatch rows take precedence even before any attempt.
        with self.store.transaction():
            self.db.execute("DELETE FROM meta WHERE k='debian:last_attempt'")
            self.db.execute('INSERT OR REPLACE INTO adapter_retries VALUES (?,?,?,?,?)', ('debian','@dispatch',9,stamp(self.now+timedelta(hours=6)), 'injected'))
        for hours in (1, 1, 4):
            self.now += timedelta(hours=hours); count = len(self.bucket.requests)
            self.dispatch(adapter)
            if hours != 4:
                self.assertEqual(len(self.bucket.requests), count)
                row = self.db.execute("SELECT attempts,next_attempt_at FROM adapter_retries WHERE resource='@dispatch'").fetchone()
                self.assertEqual(row[0], 9)
            else:
                self.assertGreater(len(self.bucket.requests), count)
                self.assertIsNone(self.db.execute("SELECT 1 FROM adapter_retries WHERE resource='@dispatch'").fetchone())
        # Exceptions raised by poll produce a real dispatch retry. Repeated
        # factory failures exercise exponential backoff through the six-hour cap.
        self.now += timedelta(days=1)
        entry = {'debian':replace(REGISTRY['debian'], gate='met')}
        with patch.object(adapter, 'poll', side_effect=RuntimeError('dispatch')):
            self.dispatch(adapter)
        due = self.db.execute("SELECT next_attempt_at FROM adapter_retries WHERE resource='@dispatch'").fetchone()[0]
        count = len(self.bucket.requests)
        self.now = instant(due)-timedelta(microseconds=1); self.dispatch(adapter)
        self.assertEqual(len(self.bucket.requests), count)
        self.now = instant(due); self.dispatch(adapter)
        self.assertGreater(len(self.bucket.requests), count)
        def factory_failure(): raise RuntimeError('factory')
        waits = []
        count = len(self.bucket.requests)
        for _ in range(12):
            self.p.dispatch(entry, {'debian':True}, {'debian':factory_failure}, stamp(self.now))
            due = self.db.execute("SELECT next_attempt_at FROM adapter_retries WHERE resource='@dispatch'").fetchone()[0]
            waits.append((instant(due)-self.now).total_seconds())
            self.assertLessEqual(waits[-1], 21600)
            self.now = instant(due)
        self.assertEqual(self.db.execute("SELECT attempts FROM adapter_retries WHERE resource='@dispatch'").fetchone()[0], 12)
        self.assertIn(21600, waits)
        self.assertEqual(len(self.bucket.requests), count)
        self.now += timedelta(days=1)
        self.scripts(dict(body=archive([record()]), headers={'last-modified':late}), archive([record('b')]))
        outcome = adapter.poll(cutoff=None)[0]
        self.assertNotIn('publication_clock', outcome)
        self.process(outcome)

    def test_t15_crash_retry_and_audit(self):
        adapter = self.adapter(); self.scripts(archive([record()]))
        # Stamp committed, no store outcome: an unfinished attempt bypasses cadence.
        with patch.object(self.http, 'get', side_effect=RuntimeError('crash after stamp')):
            with self.assertRaises(RuntimeError): adapter.poll(cutoff=None)
        self.assertEqual(self.state.meta('last_attempt'), stamp(self.now))
        outcome = adapter.poll(cutoff=None)[0]
        audit = self.p._audit_observation
        def crash_after_audit(*args):
            audit(*args)
            raise RuntimeError('crash after observation')
        with patch.object(self.p, '_audit_observation', side_effect=crash_after_audit):
            with self.assertRaises(RuntimeError): self.process(outcome)
        self.assertEqual(self.db.execute('SELECT digest FROM manifests').fetchone()[0], '')
        outcome = adapter.poll(cutoff=None)[0]
        Path(outcome['members_file']).unlink()
        self.scripts(discovery=OSError('offline'))
        self.dispatch(adapter)
        deadline = self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE resource=?', (RESOURCE,)).fetchone()[0]
        count = len(self.bucket.requests); self.now += timedelta(seconds=1)
        self.dispatch(adapter); self.assertEqual(len(self.bucket.requests), count)
        with self.store.transaction():
            self.db.execute('INSERT INTO adapter_retries VALUES (?,?,?,?,?)', ('debian','@dispatch',1,stamp(instant(deadline)+timedelta(seconds=60)), 'injected'))
        self.now = instant(deadline); self.dispatch(adapter); self.assertEqual(len(self.bucket.requests), count)
        self.now += timedelta(seconds=60); self.dispatch(adapter); self.assertGreater(len(self.bucket.requests), count)
        self.now += timedelta(days=8); self.dispatch(adapter)
        self.assertEqual(self.health('audit'), 'unhealthy')

    def test_t24_index_and_bootstrap(self):
        self.assertIn('advisory_evidence_record', [r[1] for r in self.db.execute('PRAGMA index_list(advisory_evidence)')])
        # Recreate precisely the pre-B-1 schema, preserving all rows.
        self.db.execute('DROP INDEX advisory_evidence_record'); self.db.commit()
        self.store.migrate(); snapshot = list(self.db.iterdump()); self.store.migrate()
        self.assertEqual(list(self.db.iterdump()), snapshot)
        plan = self.db.execute('EXPLAIN QUERY PLAN DELETE FROM advisory_evidence WHERE source=? AND source_id=?', ('debian','x')).fetchall()
        self.assertTrue(any('advisory_evidence_record' in r[3] for r in plan))
        started = time.monotonic()
        members = self.directory/'bootstrap.jsonl'
        with members.open('w') as f:
            for n in range(2000): f.write(canonical(normalise(record(f'DSA-90{n:04}-1')))+'\n')
        self.assertEqual(self.process(dict(path=RESOURCE, status=200, members_file=str(members))), 'COMPLETE')
        self.assertLess(time.monotonic()-started, 30)

    def test_peak_rss_reads_vmhwm_off_darwin(self):
        from tests.source_helpers import peak_rss_bytes
        status = 'Name:\tpython\nVmPeak:\t 900000 kB\nVmHWM:\t   71234 kB\nVmRSS:\t   70000 kB\n'
        self.assertEqual(peak_rss_bytes(status, platform='linux'), 71234 * 1024)
        self.assertEqual(peak_rss_bytes(None, platform='darwin', maxrss=5_000_000), 5_000_000)
        with self.assertRaises(RuntimeError):
            peak_rss_bytes('Name:\tpython\n', platform='linux')

    def test_t11_scale_rss(self):
        result = subprocess.run([sys.executable, '-m', 'tests.test_task4_b1', '--scale-child'], cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertLess(json.loads(result.stdout)['rss_bytes'], 128*1024**2)


def scale_child():
    # Generate on disk before measuring, then serve file streams through real Http.
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        directory = Path(directory)
        for ecosystem, name in (('Debian:12', 'a.zip'), ('Debian:13', 'b.zip')):
            with zipfile.ZipFile(directory/name, 'w', zipfile.ZIP_DEFLATED) as z:
                for n in range(20000):
                    r = record(f'DSA-9{n:05}-1', ecosystem)
                    z.writestr(r['id']+'.json', canonical(r))
        case = Task4B1Tests(); case.setUp()
        try:
            adapter = case.adapter(); case.scripts(b'a', b'b')
            original = case.bucket.open
            def opener(request, timeout):
                if request.full_url == DISCOVERY: return original(request, timeout)
                response = (directory/('a.zip' if '12' in request.full_url else 'b.zip')).open('rb')
                response.status = 200; response.headers = {}
                return response
            case.bucket.open = opener
            outcome = adapter.poll(cutoff=None)[0]
            with Path(outcome['members_file']).open() as f:
                assert sum(1 for _ in f) == 20000
            from tests.source_helpers import peak_rss_bytes
            print(json.dumps(dict(rss_bytes=peak_rss_bytes())))
        finally: case.doCleanups()


if __name__ == '__main__':
    if '--scale-child' in sys.argv: scale_child()
    else: unittest.main()

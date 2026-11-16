# script-purpose: Replay invented Debian bulk exports through production dispatch offline.
# script-class: harness
# script-trigger: Debian JSONL scenarios and unittest discovery.
# script-tests: tests/test_task4_b2.py, tests/replay_v11/test-osv-backend.py
"""Read action-indexed bucket scripts; write temporary stores and request traces.

No network is used. Library API; the parent unittest runner exits 0/1.
"""
from dataclasses import replace
from io import BytesIO
import json
import re
import socket
import tomllib
from urllib.parse import quote, unquote, urlsplit
import zipfile

from cornicen.adapters import REGISTRY
from cornicen.fetch import Http
from cornicen.adapterstore import canonical, instant
from cornicen.sources.osv_debian import BASE, DISCOVERY, HOST, RESOURCE
from tests.replay_v11.fixture_adapter import ValidationBackend

# Literal invalid envelopes, deliberately independent of zip implementation.
BROKEN = {'truncated': b'PK\x03\x04incomplete', 'central_directory': b'PK\x03\x04destroyed directory'}


class ScriptedOsv:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.scripts, self.requests = {}, []
        self.call_order = []
        self.tick = None
        self.reset(0)

    def reset(self, action):
        self.action, self.counters = action, {}

    def add(self, action, operation, *, occurrence=1, members=None, broken=None,
            body='', status=200, headers=None, error=None, url=None):
        expected = DISCOVERY if operation == 'discovery' else BASE+'/'+quote(operation.removeprefix('archive:'), safe='')+'/all.zip'
        if operation != 'discovery' and not operation.startswith('archive:Debian'):
            raise ValueError('invalid OSV operation')
        if members is not None:
            stream = BytesIO()
            with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
                for member in members:
                    archive.writestr(member['id']+'.json', canonical(member))
            body = stream.getvalue()
        if broken is not None:
            body = BROKEN[broken]
        headers = dict(headers or {})
        if broken == 'truncated': headers['content-length'] = str(len(body)+100)
        key = action, operation, occurrence
        assert key not in self.scripts, key
        self.scripts[key] = dict(url=url or expected, body=body, status=status,
                                 headers=headers, error=error)

    def resolver(self, host, port, **kwargs):
        assert host == HOST, host
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]

    def http(self):
        return Http('Cornicen/test', {}, opener=self, resolver=self.resolver, data_dir=self.data_dir)

    def open(self, request, timeout):
        url = request.full_url
        operation = 'discovery' if url == DISCOVERY else 'archive:'+unquote(urlsplit(url).path.split('/')[1])
        occurrence = self.counters.get(operation, 0)+1
        key = self.action, operation, occurrence
        assert key in self.scripts, ('unexpected request', key, url)
        script = self.scripts[key]
        assert request.get_method() == 'GET'
        assert script['url'] == url, (script['url'], url)
        if not self.counters:
            self.call_order.append((self.tick, 'request'))
        self.counters[operation] = occurrence
        self.requests.append(dict(action=self.action, operation=operation, method='GET', url=url,
                                  headers=dict(request.header_items())))
        if script['error'] is not None: raise OSError(script['error'])
        body = script['body']
        response = BytesIO(body.encode() if isinstance(body, str) else body)
        response.status, response.headers = script['status'], script['headers']
        return response


class DebianBackend(ValidationBackend):
    def __init__(self, registry):
        super().__init__({'debian': replace(REGISTRY['debian'], gate='met', last_modified_validated=True)})
        self.server = ScriptedOsv(self.tmp.name)
        self.action_index = self.script_action = 0

    def start_engine(self):
        previous = self.engine
        if previous is not None and previous.store is not self.store: previous.store._finalizer.detach()
        super().start_engine()
        self.engine.config.adapters['debian'] = True

    def seed(self, seed, tick):
        super().seed(seed, tick)
        if seed.get('debian_completed_baseline'):
            self.persistence.process('debian', [dict(path=RESOURCE, status=200, body='[]')],
                                     tick, required_resources=(RESOURCE,))
            with self.store.transaction():
                self.store.connection.execute("DELETE FROM outbox WHERE pair_key='|baseline:debian'")
        if 'debian_state' in seed:
            from cornicen.sources.osv_debian import DebianState
            with self.store.transaction():
                for key, value in seed['debian_state'].items(): DebianState(self.store)._put(key, value)

    def action(self, row):
        self.clock.now = instant(row['t'])
        if 'debian' in row:
            self.script_action = self.action_index
            self.server.reset(self.script_action)
            for response in row['debian']:
                self.server.add(self.script_action, **response)
        elif 'cycle' in row:
            from cornicen.adapterfactories import production_factories
            self.server.reset(self.script_action)
            self.server.tick = row['t']
            self.engine._health_verdicts = {}
            for ingest in self.ingests:
                with self.store.transaction(): self.engine._ingest(ingest)
                self.server.call_order.append((row['t'], 'ingest'))
            classification = self.engine.dispatch_adapters(registry=self.registry,
                factories=production_factories(self.engine, http_factory=self.server.http))
            self.engine._flush()
            self.ingests.clear()
            self.observed = {'classification': classification}
        else:
            super().action(row)
        self.action_index += 1

    def snapshot(self):
        result = super().snapshot()
        result['call_order'] = list(self.server.call_order)
        result['requests'] = len(self.server.requests)
        result['request_trace'] = list(self.server.requests)
        evidence = {}
        for row in self.store.connection.execute('SELECT * FROM advisory_evidence'):
            value = dict(row)
            for key in ('range', 'provenance'):
                if value[key] is not None: value[key] = json.loads(value[key])
            evidence.setdefault(value['identity'], []).append(value)
        result['evidence_rows'] = {key: sorted(rows, key=canonical) for key, rows in sorted(evidence.items())}
        result['freshness_detail'] = {r['dimension']: r['detail'] for r in self.store.connection.execute(
            "SELECT * FROM source_health WHERE source='debian' AND dimension='freshness'")}
        result['retry_detail'] = [dict(r) for r in self.store.connection.execute('SELECT * FROM adapter_retries ORDER BY source,resource')]
        return result

    def close(self):
        self.store._finalizer.detach()
        super().close()


def validate_rows(rows):
    """Admit only invented Debian identities and the bucket's exact scripted URLs."""
    from tests.replay_v11 import harness as h
    if not rows or 'watchlist' not in rows[0]: raise ValueError('first action must set watchlist')
    previous = None
    for row in rows:
        now = instant(row['t'])
        if previous is not None and now < previous: raise ValueError('t must be non-decreasing')
        previous = now
        keys = set(row)-{'t'}
        if len(keys) != 1 or not keys <= {'watchlist','seed','debian','ingest','cycle','restart','case','command','notifier'}:
            raise ValueError('unsupported Debian action')
        if 'command' in row and row['command'] != ['adapter','rebaseline','debian']: raise ValueError('unsupported command')
        for response in row.get('debian', []):
            op = response['operation']
            if op != 'discovery' and not re.fullmatch(r'archive:Debian(?::\d+)?', op): raise ValueError('invalid operation')
            expected = DISCOVERY if op == 'discovery' else BASE+'/'+quote(op[8:], safe='')+'/all.zip'
            if response.get('url', expected) != expected: raise ValueError('foreign scripted URL')
    validate_identities(rows)
    return rows


def validate_identities(rows):
    from tests.replay_v11 import harness as h
    # Translate only the explicitly permitted additions before using the legacy
    # identity validator. This does not relax any other backend's allowlist.
    def fields(value):
        if isinstance(value, list): return [fields(v) for v in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == 'watchlist': item = tomllib.loads(item); key = 'debian_watches'
                if key in ('ecosystem',) and not re.fullmatch(r'Debian(?::\d+)?', item): raise ValueError('invalid ecosystem')
                if key == 'name' and ('package' not in value) and isinstance(item, str) and item.startswith('osv-selector:'):
                    if not re.fullmatch(r'osv-selector:Debian(?::\d+)?#(?:examplessl|example-browser|sample-pkg-\d+)', item): raise ValueError('invalid selector')
                    item = 'examplecorp:widget'
                if key == 'package' and isinstance(item, str):
                    if re.fullmatch(r'osv-selector:(?:Debian|debian)(?::\d+)?#(?:examplessl|example-browser|sample-pkg-\d+)', item):
                        item = 'examplessl'
                    elif not re.fullmatch(r'examplessl|example-browser|sample-pkg-\d+', item): raise ValueError('invalid package')
                if key == 'package' and isinstance(item, dict) and not re.fullmatch(r'examplessl|example-browser|sample-pkg-\d+', item.get('name','')): raise ValueError('invalid package')
                if key == 'version' and isinstance(item, str):
                    if not re.fullmatch(r'(?:\d+:)?\d+(?:[.\d~+u-]|deb)*', item): raise ValueError('invalid version')
                    item = '1.0.0'
                result[key] = fields(item)
            return result
        return value
    encoded = json.dumps(fields(rows))
    for host in (HOST, 'security-tracker.example.invalid', 'storage.example.invalid', 'osv.dev'):
        encoded = encoded.replace('https://'+host+'/', 'https://examplecorp.invalid/')
    h.validate_identities(json.loads(encoded))
    return rows

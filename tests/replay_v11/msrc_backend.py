# script-purpose: Serve invented source-keyed CSAF scripts and replay the production adapter offline.
# script-class: harness
# script-trigger: Microsoft and Cisco offline CSAF replay scenarios.
# script-tests: tests/test_task2_b2.py, tests/test_task3_b2.py
"""Read action/operation/path scripts; write request traces and temporary stores.

Uses a scripted Http opener with no network. Parent unittest exits 0/1.
"""
from io import BytesIO
import json
from pathlib import Path
import re
import socket
from urllib.parse import urlsplit

from cornicen.fetch import Http
from tests.replay_v11.fixture_adapter import ValidationBackend

BASE = 'https://msrc.microsoft.com/csaf/advisories/'
META = 'https://msrc.microsoft.com/csaf/provider-metadata.json'


PROFILES = {
    'msrc': (BASE, META, 'msrc.microsoft.com', '/csaf/advisories/'),
    'cisco': ('https://www.cisco.com/.well-known/csaf/',
              'https://www.cisco.com/.well-known/csaf/provider-metadata.json',
              'www.cisco.com', '/.well-known/csaf/'),
}


class ScriptedCsaf:
    def __init__(self, source='msrc', *, data_dir='.'):
        self.source = source
        self.base, self.meta, self.host, self.prefix = PROFILES[source]
        self.data_dir = Path(data_dir)
        self.scripts, self.requests = {}, []
        self.reset(0)

    def reset(self, action):
        self.action, self.counters = action, {}

    def add(self, action, operation, path='', *, occurrence=1, url=None, body='', status=200, headers=None, error=None, body_fixture=None):
        if operation not in (('metadata','listing','index','record') if self.source == 'cisco' else ('metadata','listing','record')): raise ValueError('invalid operation')
        url = url or (self.meta if operation=='metadata' else self.base + ('changes.csv' if operation=='listing' else 'index.txt' if operation=='index' else path))
        if body_fixture is not None:
            if body_fixture != 'advisory_sample.json': raise ValueError('unsupported fixture')
            body = json.loads((Path(__file__).resolve().parents[1]/('fixtures/'+self.source)/body_fixture).read_text())
        key = action, operation, path, occurrence
        assert key not in self.scripts, key
        self.scripts[key] = dict(url=url, body=body, status=status, headers=headers or {}, error=error)

    def resolver(self, host, port, **kwargs):
        assert host==self.host, host
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',port))]

    def http(self):
        return Http('Cornicen/test',{},opener=self,resolver=self.resolver,data_dir=self.data_dir)

    def open(self, request, timeout):
        url=request.full_url; parsed=urlsplit(url)
        operation = 'metadata' if url==self.meta else 'listing' if url==self.base+'changes.csv' else 'index' if url==self.base+'index.txt' else 'record'
        path=parsed.path.removeprefix(self.prefix) if operation=='record' else ''
        occurrence=self.counters.get((operation,path),0)+1
        key=self.action,operation,path,occurrence
        assert key in self.scripts, ('unexpected request',key,url)
        script=self.scripts[key]
        assert script['url']==url, (script['url'],url)
        assert request.get_method()=='GET'
        self.counters[operation,path]=occurrence
        self.requests.append(dict(action=self.action,operation=operation,path=path,url=url,
                                  method='GET',headers=dict(request.header_items())))
        if script['error'] is not None:
            raise OSError(script['error']) if isinstance(script['error'],str) else script['error']
        body=script['body']
        if not isinstance(body,(str,bytes)): body=json.dumps(body)
        response=BytesIO(body.encode() if isinstance(body,str) else body)
        response.status, response.headers=script['status'], script['headers']
        return response


class CsafBackend(ValidationBackend):
    source = 'msrc'
    def __init__(self, registry):
        from dataclasses import replace
        from cornicen.adapters import REGISTRY
        super().__init__({self.source:replace(REGISTRY[self.source],gate='met')})
        self.server=ScriptedCsaf(self.source, data_dir=self.tmp.name)
        self.action_index=0; self.script_action=0

    def start_engine(self):
        previous=getattr(self,'engine',None)
        if previous is not None and previous.store is not self.store: previous.store._finalizer.detach()
        super().start_engine()
        self.engine.config.adapters[self.source]=True

    def seed(self, seed, tick):
        from cornicen.adapterstore import canonical
        from cornicen.sources.csaf_directory import state_for
        state = state_for(self.store, self.source)
        resource = state.profile.resource
        super().seed(seed,tick)
        if self.source == 'cisco' and seed.get('cisco_prior_documents'):
            from cornicen.csaf import normalise, CISCO
            members = [normalise(doc, path='2099/seed.json', directory_url=state.profile.directory_url,
                                 policy=CISCO) for doc in seed['cisco_prior_documents']]
            self.persistence.process(self.source, [dict(path=resource, status=200, body=json.dumps(members))],
                                     tick, required_resources=(resource,))
        if seed.get(self.source+'_completed_baseline'):
            self.persistence.process(self.source,[dict(path=resource,status=200,body='[]')],tick,required_resources=(resource,))
            with self.store.transaction():
                state._put('bootstrap',[])
                # This seed represents an already delivered baseline summary.
                self.store.connection.execute("DELETE FROM outbox WHERE pair_key=?", ('|baseline:'+self.source,))
        if self.source+'_state' in seed:
            with self.store.transaction():
                for key,value in seed[self.source+'_state'].items(): state._put(key,value)

    def action(self,row):
        from cornicen.adapterfactories import production_factories
        from cornicen.adapterstore import instant
        if self.source in row:
            self.clock.now=instant(row['t'])
            self.script_action=self.action_index; self.server.reset(self.script_action)
            for response in row[self.source]:
                response=dict(response)
                self.server.add(self.script_action,response.pop('operation'),response.pop('path',''),**response)
        elif 'cycle' in row:
            self.clock.now=instant(row['t'])
            self.server.reset(self.script_action)
            classification=self.engine.dispatch_adapters(registry=self.registry,
                factories=production_factories(self.engine,http_factory=self.server.http))
            self.engine._flush()
            self.observed={'classification':classification}
        else: super().action(row)
        self.action_index+=1

    def snapshot(self):
        result=super().snapshot()
        result['requests']=len(self.server.requests)
        result['request_paths']=[r['path'] for r in self.server.requests if r['operation']=='record']
        result['gaps']=self.store.connection.execute("SELECT count(*) FROM gap_ledger WHERE source=?", (self.source,)).fetchone()[0]
        result['cache_paths']=[r[0].removeprefix(self.source+':path:') for r in self.store.connection.execute(
            "SELECT k FROM meta WHERE k LIKE ? AND json_extract(v,'$.listed')=1 ORDER BY k", (self.source+':path:%',))]
        if self.source == 'cisco':
            from cornicen.adapterstore import canonical
            result['conformance'] = json.loads(self.store.get_meta('cisco:conformance') or 'null')
            result['evidence_rows'] = evidence_projection(self.store.connection)
        return result

    def close(self):
        self.store._finalizer.detach()
        super().close()


def evidence_projection(db):
    """Project every persisted evidence column, retaining duplicates and provenance."""
    from cornicen.adapterstore import canonical
    result = {}
    for row in db.execute('SELECT * FROM advisory_evidence'):
        value = dict(row)
        value['provenance'] = json.loads(value['provenance'])
        if value['range'] is not None:
            value['range'] = json.loads(value['range'])
        result.setdefault(value['source']+'|'+value['source_id'], []).append(value)
    return {key: sorted(values, key=canonical) for key, values in sorted(result.items())}


class ScriptedMsrc(ScriptedCsaf):
    def __init__(self, *, data_dir='.'):
        super().__init__('msrc', data_dir=data_dir)


class MsrcBackend(CsafBackend):
    pass


class CiscoBackend(CsafBackend):
    source = 'cisco'


def is_cisco(name):
    return name in ('cisco_platform', 'cisco_bad_member', 'cisco_inventory')


def is_csaf(name):
    return is_msrc(name) or is_cisco(name)


def backend_for(name):
    return CiscoBackend if is_cisco(name) else MsrcBackend


def is_msrc(name):
    return name in ('csaf','csaf_inventory','msrc_bootstrap')


def validate_rows(rows, source='msrc'):
    """Validate source-specific invented identities, build strings, URLs and actions."""
    from cornicen.adapterstore import instant
    from tests.replay_v11 import harness as h
    import tomllib
    if source not in PROFILES:
        raise ValueError('unsupported CSAF source')
    if not rows or 'watchlist' not in rows[0]: raise ValueError('first action must set watchlist')
    previous=None
    for row in rows:
        now=instant(row['t'])
        if previous is not None and now<previous: raise ValueError('t must be non-decreasing')
        previous=now
        keys=set(row)-{'t'}
        if len(keys)!=1 or not keys <= {'watchlist','seed',source,'cycle','restart','case','command','notifier'}:
            raise ValueError('unsupported CSAF action')
        if 'command' in row and row['command']!=['adapter','rebaseline',source]: raise ValueError('unsupported command')
        for response in row.get(source,[]):
            if response['operation'] not in (('metadata','listing','index','record') if source == 'cisco' else ('metadata','listing','record')): raise ValueError('invalid operation')
            if 'url' in response and not response['url'].startswith('https://'+PROFILES[source][2]+'/'): raise ValueError('foreign scripted URL')
    def csaf_fields(value, tracking=False):
        if isinstance(value, list):
            return [csaf_fields(item, tracking) for item in value]
        if isinstance(value, dict):
            value = dict(value)
            if source == 'cisco' and 'watchlist' in value:
                value['csaf_watches'] = tomllib.loads(value.pop('watchlist'))
            return {('csaf_product_labels' if key == 'products' and isinstance(item, list)
                     and all(isinstance(label, str) for label in item) else 'tracking_revision' if key == 'version' and (tracking or 'vectorString' in value) else key): csaf_fields(item, tracking or key == 'tracking')
                    for key, item in value.items()}
        return value
    encoded=json.dumps(csaf_fields(rows))
    if source == 'cisco':
        for identity in ('Cisco:Contoso Sample Relay Gateway', 'cisco:contoso sample relay gateway',
                         'Cisco:Contoso Sample Relay', 'cisco:contoso sample relay'):
            encoded=encoded.replace(identity, 'examplecorp:widget')
        encoded=encoded.replace('"vendor": "cisco"', '"vendor": "examplecorp"')
        encoded=encoded.replace('https://www.cisco.com/', 'https://examplecorp.invalid/')
        encoded=encoded.replace('https://sec.cloudapps.cisco.com/', 'https://examplecorp.invalid/')
        encoded=re.sub(r'93\.0\.(?:0-39[12]|5-007)', '1.0.0', encoded)
    if source == 'cisco':
        for row in rows:
            for watch in tomllib.loads(row.get('watchlist', '')).get('watch', []):
                if 'platform' in watch and watch['platform'] not in (
                        dict(vendor='cisco', product='contoso sample relay gateway'),
                        dict(vendor='cisco', product='contoso sample relay')):
                    raise ValueError('non-invented Cisco platform')
    encoded=encoded.replace('Microsoft:Contoso Sample Agent for Windows','examplecorp:widget') if source == 'msrc' else encoded
    encoded=encoded.replace('microsoft:contoso sample agent for windows','examplecorp:widget') if source == 'msrc' else encoded
    # Raw CSAF vendor ancestors are names, not watch vendor fields. Only this
    # exact captured-fixture spelling is admitted, never arbitrary Microsoft products.
    encoded=encoded.replace('https://msrc.microsoft.com/','https://examplecorp.invalid/') if source == 'msrc' else encoded
    encoded=re.sub(r'9\.4\.1200\.(7|8|9)',r'9.4.\1',encoded) if source == 'msrc' else encoded
    h.validate_identities(json.loads(encoded))
    return rows

# script-purpose: Serve invented Microsoft CSAF scripts and replay the production adapter offline.
# script-class: harness
# script-trigger: Microsoft CSAF replay scenarios and tests/test_task2_b2.py.
# script-tests: tests/test_task2_b2.py
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


class ScriptedMsrc:
    def __init__(self, *, data_dir='.'):
        self.data_dir = Path(data_dir)
        self.scripts, self.requests = {}, []
        self.reset(0)

    def reset(self, action):
        self.action, self.counters = action, {}

    def add(self, action, operation, path='', *, occurrence=1, url=None, body='', status=200, headers=None, error=None, body_fixture=None):
        if operation not in ('metadata','listing','record'): raise ValueError('invalid operation')
        url = url or (META if operation=='metadata' else BASE + ('changes.csv' if operation=='listing' else path))
        if body_fixture is not None:
            if body_fixture != 'advisory_sample.json': raise ValueError('unsupported fixture')
            body = json.loads((Path(__file__).resolve().parents[1]/'fixtures/msrc'/body_fixture).read_text())
        key = action, operation, path, occurrence
        assert key not in self.scripts, key
        self.scripts[key] = dict(url=url, body=body, status=status, headers=headers or {}, error=error)

    @staticmethod
    def resolver(host, port, **kwargs):
        assert host=='msrc.microsoft.com', host
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',port))]

    def http(self):
        return Http('Cornicen/test',{},opener=self,resolver=self.resolver,data_dir=self.data_dir)

    def open(self, request, timeout):
        url=request.full_url; parsed=urlsplit(url)
        operation = 'metadata' if url==META else 'listing' if url==BASE+'changes.csv' else 'record'
        path=parsed.path.removeprefix('/csaf/advisories/') if operation=='record' else ''
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


class MsrcBackend(ValidationBackend):
    def __init__(self, registry):
        from dataclasses import replace
        from cornicen.adapters import REGISTRY
        super().__init__({'msrc':replace(REGISTRY['msrc'],gate='met')})
        self.server=ScriptedMsrc(data_dir=self.tmp.name)
        self.action_index=0; self.script_action=0

    def start_engine(self):
        previous=getattr(self,'engine',None)
        if previous is not None and previous.store is not self.store: previous.store._finalizer.detach()
        super().start_engine()
        self.engine.config.adapters['msrc']=True

    def seed(self, seed, tick):
        from cornicen.adapterstore import canonical
        from cornicen.sources.msrc_csaf import MsrcState, RESOURCE
        super().seed(seed,tick)
        if seed.get('msrc_completed_baseline'):
            self.persistence.process('msrc',[dict(path=RESOURCE,status=200,body='[]')],tick,required_resources=(RESOURCE,))
            with self.store.transaction():
                MsrcState(self.store)._put('bootstrap',[])
                # This seed represents an already delivered baseline summary.
                self.store.connection.execute("DELETE FROM outbox WHERE pair_key='|baseline:msrc'")
        if 'msrc_state' in seed:
            state=MsrcState(self.store)
            with self.store.transaction():
                for key,value in seed['msrc_state'].items(): state._put(key,value)

    def action(self,row):
        from cornicen.adapterfactories import production_factories
        from cornicen.adapterstore import instant
        if 'msrc' in row:
            self.clock.now=instant(row['t'])
            self.script_action=self.action_index; self.server.reset(self.script_action)
            for response in row['msrc']:
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
        result['gaps']=self.store.connection.execute("SELECT count(*) FROM gap_ledger WHERE source='msrc'").fetchone()[0]
        result['cache_paths']=[r[0].removeprefix('msrc:path:') for r in self.store.connection.execute(
            "SELECT k FROM meta WHERE k LIKE 'msrc:path:%' AND json_extract(v,'$.listed')=1 ORDER BY k")]
        return result

    def close(self):
        self.store._finalizer.detach()
        super().close()


def is_msrc(name):
    return name in ('csaf','csaf_inventory','msrc_bootstrap')


def validate_rows(rows):
    """Allow only the invented fixture identity, four-part versions and MSRC URLs."""
    from cornicen.adapterstore import instant
    from tests.replay_v11 import harness as h
    if not rows or 'watchlist' not in rows[0]: raise ValueError('first action must set watchlist')
    previous=None
    for row in rows:
        now=instant(row['t'])
        if previous is not None and now<previous: raise ValueError('t must be non-decreasing')
        previous=now
        keys=set(row)-{'t'}
        if len(keys)!=1 or not keys <= {'watchlist','seed','msrc','cycle','restart','case','command','notifier'}:
            raise ValueError('unsupported Microsoft action')
        if 'command' in row and row['command']!=['adapter','rebaseline','msrc']: raise ValueError('unsupported command')
        for response in row.get('msrc',[]):
            if response['operation'] not in ('metadata','listing','record'): raise ValueError('invalid operation')
            if 'url' in response and not response['url'].startswith('https://msrc.microsoft.com/'): raise ValueError('foreign scripted URL')
    encoded=json.dumps(rows)
    encoded=encoded.replace('Microsoft:Contoso Sample Agent for Windows','examplecorp:widget')
    encoded=encoded.replace('microsoft:contoso sample agent for windows','examplecorp:widget')
    # Raw CSAF vendor ancestors are names, not watch vendor fields. Only this
    # exact captured-fixture spelling is admitted, never arbitrary Microsoft products.
    encoded=encoded.replace('https://msrc.microsoft.com/','https://examplecorp.invalid/')
    encoded=re.sub(r'9\.4\.1200\.(7|8|9)',r'9.4.\1',encoded)
    h.validate_identities(json.loads(encoded))
    return rows

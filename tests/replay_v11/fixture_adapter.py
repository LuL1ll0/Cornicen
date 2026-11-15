# script-purpose: Persist and classify invented raw fixture outcomes.
# script-class: harness
# script-trigger: tests/replay_v11/harness.py.
# script-tests: tests/test_f1.py, tests/test_f2a.py, tests/test_f3a.py, tests/test_f3b.py, tests/replay_v11/test-harness.py
"""Read replay actions; write temporary databases and staged files.

Used by unittest discovery; exit codes are the parent runner's 0/1 status.
Seeds and commands invoke the real persistence layer.
"""


def observe_pairs(connection, *, logical=False):
    """Project stored pairs for oracles, with the episode's separate latch."""
    from cornicen.advisory import logical_latch
    return [dict(watch=row['watch_id'], id=row['record_id'],
                 state='unaffected' if row['state'] == 'not_affected' else row['state'],
                 episode=row['episode'], affected_latch=logical_latch(connection, row, implicit=logical),
                 notified=bool(row['notified']))
            for row in connection.execute('''
                SELECT p.*, coalesce(l.latched, 0) AS latched
                FROM pairs p LEFT JOIN affected_latches l
                  ON l.watch_id=p.watch_id AND l.record_id=p.record_id
                 AND l.episode=p.episode
                ORDER BY p.watch_id,p.record_id''')]


class ValidationBackend:
    def __init__(self, registry):
        from pathlib import Path
        import tempfile
        from cornicen.store import Store
        from cornicen.adapterstore import AdapterStore
        self.registry = registry
        self.pending = {}
        self.observed = {'classification': {}}
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.path = Path(self.tmp.name) / 'state.db'
        self.store = Store(self.path)
        self.store.migrate()
        self.persistence = AdapterStore(self.store, self.tmp.name)
        self.sent = []
        self.seeded_stages = {}
        self.ingests = []
        self.watches = ()
        self.scopes = {}
        self.engine = None
        from tests.replay.harness import FakeClock, utc
        self.clock = FakeClock(utc('2099-11-03T00:00:00Z'))

    def start_engine(self):
        from cornicen.engine import Engine
        from cornicen.config import Config
        from cornicen.identity import AliasMap
        from tests.replay.harness import RecordingNotifier
        backend = self
        class Notifier(RecordingNotifier):
            def send(self, notification):
                if self.down:
                    return False
                from cornicen.model import Notification
                items = notification.body.get('items')
                for item in items or []:
                    backend.bodies.append(item['body'])
                    super().send(Notification(**item))
                if items is None:
                    backend.bodies.append(notification.body)
                    super().send(notification)
                return True
        if not hasattr(self, 'notifier'):
            self.bodies = []
            self.notifier = Notifier(self.clock)
            self.sent = self.notifier.delivered
        config = Config(self.path, self.path.parent / 'unused', None,
                        'https://examplecorp.invalid', 'test', None, retention_days=365)
        self.engine = Engine(self.store, self.watches, AliasMap.load(False),
                             config, self.clock, self.notifier)
        self.engine.evidence_scopes = self.scopes
        # Spec §8 requires normal delivery each tick; scheduling alone is replaced.
        self.engine._digest = lambda: self.clock().isoformat()
        from cornicen.adapterstore import AdapterStore
        self.persistence = AdapterStore(self.store, self.tmp.name,
                                        on_record=self.engine.commit_advisory,
                                        on_unknown=self.engine.observe_unknown_advisory)

    def seed(self, seed, tick):
        import json
        db = self.store.connection
        with self.store.transaction():
            if seed.get('v1_baseline_complete'):
                self.store.set_meta('baseline_complete', '1')
            if 'pairs' in seed:
                db.execute('DELETE FROM pairs')
                db.execute('DELETE FROM affected_latches')
                for row in seed['pairs']:
                    db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (row['watch'], row['id'], 'not_affected' if row['state']=='unaffected' else row['state'],
                         row['episode'], 0, 0, int(row['notified']), 'seed', 'high', self.engine.aliases.version))
                    if row['affected_latch']:
                        db.execute('INSERT INTO affected_latches VALUES (?,?,?,1)',
                                   (row['watch'], row['id'], row['episode']))
            for name, state in seed.get('adapters', {}).items():
                cursor = state.get('cursor', {})
                db.execute('INSERT OR REPLACE INTO adapter_state VALUES (?,?,?,?,?,?,NULL)',
                           (name,cursor.get('tick'),cursor.get('digest'),state.get('cutoff'),
                            json.dumps(state['baseline_members']) if state.get('baseline_members') is not None else None,
                            int(state.get('baseline_complete',False))))
                db.executemany('INSERT OR IGNORE INTO baseline_members VALUES (?,?)',
                               ((name,identity) for identity in (state.get('baseline_members') or []) if not identity.startswith('@invalid:')))
                for dimension, value in state.get('dimensions',{}).items():
                    db.execute('INSERT OR REPLACE INTO source_health VALUES (?,?,?,?,?)',
                               (name,dimension,value,tick,'seed'))
            for row in seed.get('audits',[]):
                db.execute("INSERT OR REPLACE INTO manifests VALUES (?,?,'','[]',?,?)",
                           (row['source'],row['resource'],tick,row['audited_at']))
            if 'events' in seed:
                db.execute('DELETE FROM events')
                for key in seed['events']:
                    watch,identity,reason,episode = key.split('|')
                    db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',(key,watch,identity,reason,int(episode),tick))
            if 'outbox' in seed:
                db.execute('DELETE FROM outbox')
                for row in seed['outbox']:
                    key=row['watch']+'|'+row['record']
                    body=dict(record_id=row['record'],watch_id=row['watch'],episode=row['episode'])
                    ident=self.store.queue(key,'normal',row['reasons'],body,row['due_at'])
                    db.execute('UPDATE outbox SET attempts=?,next_attempt_at=?,dirty=0 WHERE id=?',
                               (row.get('attempts',0),row.get('next_attempt_at'),ident))
            for row in seed.get('gaps',[]):
                db.execute('INSERT OR REPLACE INTO gap_ledger VALUES (?,?,?,?)',
                           (row['source'],row['opened_at'],row['reason'],row.get('acknowledged_at')))
            for row in seed.get('cache',[]):
                db.execute('INSERT OR REPLACE INTO resource_cache VALUES (?,?,?,?,?,?,?)',
                           (row['source'],row['resource'],row['body'],row.get('etag'),row.get('last_modified'),row.get('link_header'),tick))
        for row in seed.get('staged',[]):
            cached=db.execute('SELECT body FROM resource_cache WHERE source=? AND url=?',(row['source'],row['resource'])).fetchone()
            if cached:
                self.persistence.stage_members(row['source'],row['resource'],iter(json.loads(cached[0])),tick,integrity=row['integrity'])
                actual=db.execute('SELECT digest FROM staged_containers WHERE source=? AND resource=?',
                                  (row['source'],row['resource'])).fetchone()[0]
                self.seeded_stages[row['source'],row['resource']]=(actual,row['path'],row['digest'])

    def action(self, row):
        from cornicen.store import Store
        from cornicen.adapterstore import AdapterStore
        from tests.replay.harness import utc, as_ingest
        self.clock.now = utc(row['t'])
        if 'watchlist' in row:
            import tomllib
            from cornicen.watchlist import load_watchlist_text
            raw = tomllib.loads(row['watchlist'])
            self.scopes = {w['id']: {k: w[k] for k in ('release', 'platform') if k in w}
                           for w in raw['watch']}
            # The only extra fixture selector is stripped before the v1 parser.
            text = '\n'.join(line for line in row['watchlist'].splitlines()
                             if not line.startswith(('release=', 'platform=')))
            self.watches = load_watchlist_text(text)
            if self.engine is None:
                self.start_engine()
            else:
                self.engine.evidence_scopes = self.scopes
                self.engine.reload_watches(self.watches)
        if 'ingest' in row:
            self.ingests.append(as_ingest(row['ingest']))
        if 'notifier' in row:
            self.notifier.down = row['notifier'] == 'down'
        if 'seed' in row:
            self.seed(row['seed'],row['t'])
        if 'adapter' in row:
            self.pending[row['adapter']] = (row['result'], row['t'])
        if 'cycle' in row:
            classification = {}
            def dispatch():
                for name in sorted(self.pending, key=lambda name: self.registry[name].position):
                    raw, tick = self.pending[name]
                    resources=[]
                    for resource in raw['resources']:
                        resource=dict(resource)
                        # Map raw publisher metadata into the production clock contract.
                        if self.registry[name].export and resource['status']==200:
                            from cornicen import feedvalidate
                            try:
                                body=feedvalidate.decode_json(resource.get('body',''))
                                if isinstance(body,dict) and 'generation' in body:
                                    resource['publication_clock']=dict(value=body['generation'],provenance='publisher_generation')
                            except ValueError:
                                pass
                        resources.append(resource)
                    self.persistence.restore_health(name,tick)
                    classification[name] = self.persistence.process(name,resources,tick,export=self.registry[name].export)
                for name in self.pending:
                    self.persistence.finish_cycle(name, row['t'], export=self.registry[name].export)
            # Invoke engine ingest/matching and delivery, leaving the unused v1
            # source-health clocks outside these adapter-only timelines.
            self.engine._health_verdicts = {}
            for ingest in self.ingests:
                with self.store.transaction():
                    self.engine._ingest(ingest)
            dispatch()
            self.engine._flush()
            self.ingests.clear()
            self.observed = {'classification': classification}
            self.pending.clear()
        if 'command' in row:
            self.persistence.rebaseline(row['command'][2],row['t'])
        if 'restart' in row:
            self.store.connection.close()
            self.store = Store(self.path)
            self.store.migrate()
            self.start_engine()

    def snapshot(self):
        import json
        db=self.store.connection
        observed=dict(self.observed)
        observed['quarantine']=[r[0] for r in db.execute('SELECT source_id FROM quarantine ORDER BY source_id')]
        observed['cursor']={r['source']:dict(tick=r['cursor_tick'],digest=r['cursor_digest']) for r in db.execute('SELECT * FROM adapter_state') if r['cursor_tick']}
        observed['baseline']={r['source']:dict(members=[b[0] for b in db.execute('SELECT source_id FROM baseline_members WHERE source=? ORDER BY source_id',(r['source'],))],complete=bool(r['baseline_complete']),
            summaries=db.execute("SELECT count(*) FROM events WHERE type='baseline' AND record_id=?",('baseline:'+r['source'],)).fetchone()[0]) for r in db.execute('SELECT * FROM adapter_state')}
        observed['advisories']={r['source_id']:dict(digest=r['digest']) for r in db.execute('SELECT * FROM advisories')}
        for r in db.execute('SELECT source_id FROM quarantine'):
            observed['advisories'].setdefault(r[0],None)
        observed['manifests']={r['source']:[dict(b) for b in db.execute('SELECT DISTINCT source_id,digest FROM manifest_members WHERE source=? ORDER BY source_id,digest',(r['source'],))] for r in db.execute('SELECT DISTINCT source FROM manifests')}
        observed['retries']=[dict(source=r['source'],resource=r['resource']) for r in db.execute('SELECT * FROM adapter_retries ORDER BY source,resource')]
        observed['gaps']=[dict(r) for r in db.execute('SELECT * FROM gap_ledger ORDER BY source,opened_at,reason')]
        observed['events']=[r[0] for r in db.execute("SELECT key FROM events WHERE type NOT IN ('healthy','unhealthy','baseline') ORDER BY key")]
        observed['outbox']=[dict(watch=r['pair_key'].split('|')[0],record=json.loads(r['body_json'])['record_id'],
             reasons=json.loads(r['reasons_json']),episode=json.loads(r['body_json']).get('episode',1),due_at=r['due_at'],attempts=r['attempts'],next_attempt_at=r['next_attempt_at'])
             for r in db.execute('SELECT * FROM outbox WHERE sent_at IS NULL ORDER BY id')]
        observed['historical_completeness']={name:self.persistence.historical(name) for name in self.registry}
        observed['dimensions']={name:dict(db.execute('SELECT dimension,state FROM source_health WHERE source=?',(name,))) for name in self.registry}
        observed['staged']=[]
        for r in db.execute('SELECT * FROM staged_containers ORDER BY source,resource'):
            # A seed describes a logical raw file which setup spools as JSONL.
            # Preserve that label only while the actual staged digest is intact.
            seed=self.seeded_stages.get((r['source'],r['resource']))
            path,md=(seed[1],seed[2]) if seed and seed[0]==r['digest'] else (r['path'],r['digest'])
            observed['staged'].append(dict(source=r['source'],resource=r['resource'],path=path,
                                          digest=md,integrity=r['integrity']))
        observed['notification_count']=dict(advisory=sum(bool(n['watch']) for n in self.sent),total=len(self.sent))
        # Counts for F3 assertions require the real advisory delivery hook, even
        # when the observed count happens to be zero before that hook exists.
        observed['advisory_delivery_available'] = self.engine is not None
        observed['pairs'] = observe_pairs(db, logical=True)
        observed['redirects'] = [dict(r) for r in db.execute(
            'SELECT old_id,new_id FROM identity_redirects ORDER BY old_id')]
        observed['coverage'] = [dict(r) for r in db.execute(
            'SELECT child_id,parent_id,watch_id AS watch,reason,episode FROM coverage_inheritance ORDER BY child_id,watch_id')]

        from cornicen import advisory
        evidence = list(db.execute('SELECT * FROM advisory_evidence'))
        observed['evidence'] = {
            'active_sources': sorted({r['source'] for r in evidence} |
                                     ({'cvelist'} if db.execute('SELECT 1 FROM records').fetchone() else set())),
            'parent': [json.loads(r['provenance'])['evidence'] for r in evidence
                       if r['identity'].startswith('advisory:')],
            'cve_ranges': {r['identity']: [json.loads(e['range']) for e in evidence
                           if e['identity']==r['identity'] and e['range']]
                           for r in evidence if r['identity'].startswith('CVE-')},
            'cve_products': {r['identity']: sorted({json.loads(e['provenance'])['product_id']
                             for e in evidence if e['identity']==r['identity']
                             and 'product_id' in json.loads(e['provenance'])})
                             for r in evidence if r['identity'].startswith('CVE-')}}
        observed['fix'] = {r['record_id']: self.engine.advisory_fix(w, r['record_id'])
                           for r in db.execute('SELECT * FROM pairs')
                           for w in self.watches if w.id==r['watch_id']}
        observed['body'] = ({'record': self.bodies[-1]['record_id'],
                             'label': self.bodies[-1].get('label')} if self.bodies else {})
        return observed

    def notifications(self):
        return list(self.sent)

    def close(self):
        self.store.connection.close()
        self.tmp.cleanup()

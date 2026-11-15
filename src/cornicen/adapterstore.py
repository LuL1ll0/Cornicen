# script-purpose: Persist validated adapter records and reconcile staged resources.
# script-class: pipeline-tool
# script-trigger: The engine adapter dispatch and adapter rebaseline command.
# script-tests: tests/test_f3b.py, tests/test_f2a.py, tests/test_f3a.py, tests/test_r11_shells.py
"""Durable, offline adapter commits. No factories or network transports live here.

Containers are newline-delimited canonical JSON under the data directory. A
scratch SQLite index bounds Python memory and withholds late duplicate conflicts.
Adapters own decoding their wire formats and establishing container integrity.
Reads staged JSONL and SQLite state; writes advisory state and staging files.
This library has no process exit codes; the CLI uses 0 for success and 1 for errors.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import random
import sqlite3
import uuid

from cornicen import feedvalidate as v


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


def instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


class AdapterStore:
    def __init__(self, store, data_dir, *, rng=None, on_record=None, on_unknown=None):
        self.on_unknown = on_unknown
        self.on_record = on_record
        self.store = store
        self.db = store.connection
        self.directory = Path(data_dir) / 'adapter-staging'
        self.rng = rng if rng is not None else random.Random()

    def ensure(self, source, tick):
        v.source_id(source)
        with self.store.transaction():
            self.db.execute('INSERT OR IGNORE INTO adapter_state(source,cutoff) VALUES (?,?)', (source,tick))

    def stage_members(self, source, resource, members, tick, *, integrity='intact', typed=False):
        """Spool a one-shot stream before touching advisory state.

        The typed route is the engine boundary; a bad type cannot write any DB
        rows, including when it appears after otherwise valid records.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / (uuid.uuid4().hex + ('.typed.jsonl' if typed else '.jsonl'))
        checksum = sha256()
        try:
            with path.open('wb') as output:
                for member in members:
                    if typed:
                        if not isinstance(member,v.ValidatedAdvisory):
                            raise TypeError('AdapterResult requires ValidatedAdvisory records')
                        member = {'validated':member.data}
                    line = (canonical(member)+'\n').encode()
                    output.write(line)
                    checksum.update(line)
            self.ensure(source,tick)
            with self.store.transaction():
                prior = self.db.execute('SELECT path FROM staged_containers WHERE source=? AND resource=?',(source,resource)).fetchone()
                self.db.execute('INSERT OR REPLACE INTO staged_containers VALUES (?,?,?,?,?,?)',
                                (source,resource,str(path),checksum.hexdigest(),integrity,tick))
            if prior and prior[0] != str(path):
                Path(prior[0]).unlink(missing_ok=True)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    def quarantine(self, source, identity, reason, tick):
        v.source_id(identity)
        with self.store.transaction():
            self.db.execute('''INSERT INTO quarantine VALUES (?,?,?,?,?)
                ON CONFLICT(source,source_id) DO UPDATE SET reason=excluded.reason,last_at=excluded.last_at''',
                            (source,identity,reason,tick,tick))

    def _observe_unknown(self, raw, source, resource, tick, *, typed=False):
        # Never publish evidence or replace a previously accepted advisory.
        if not self.on_unknown or typed or not isinstance(raw, dict):
            return
        if self.db.execute('SELECT 1 FROM advisories WHERE source=? AND source_id=?',
                           (source, raw.get('id'))).fetchone():
            return
        try:
            shell = v.validate_advisory(dict(raw, evidence=[], associations=[],
                product_groups=[], remediations=[]), source=source,
                observed_at=tick, input_path=resource).data
        except (ValueError, TypeError, KeyError):
            return
        self.on_unknown(shell)

    def _key(self, raw, typed):
        data = raw['validated'] if typed else raw
        value = data.get('source_id' if typed else 'id') if isinstance(data,dict) else None
        try:
            return v.source_id(value),False
        except ValueError:
            return '@invalid:'+digest(raw),True

    def commit_staged(self, source, resource, tick, *, checkpoint=lambda point:None,
                      on_record=None, finalize=True, typed=False, deferred=None, initial_classification='COMPLETE', rebaseline=False, schedule_retry=True):
        row=self.db.execute('SELECT * FROM staged_containers WHERE source=? AND resource=?',(source,resource)).fetchone()
        if not row:
            raise ValueError('no staged container')
        if row['integrity'] != 'intact':
            state = 'PARTIAL' if row['integrity']=='pending' else 'FAILED'
            self.retry(source,resource,tick,state)
            return state
        path=Path(row['path'])
        typed = path.name.endswith('.typed.jsonl')
        index_path=path.with_suffix('.index')
        index_path.unlink(missing_ok=True)
        index=sqlite3.connect(index_path)
        index.execute('PRAGMA journal_mode=OFF')
        index.execute('PRAGMA cache_size=-2048')
        index.execute('CREATE TABLE members(id TEXT PRIMARY KEY,digest TEXT,conflict INTEGER DEFAULT 0,invalid INTEGER,done INTEGER DEFAULT 0)')
        checksum=sha256()
        try:
            # Pass one: integrity and ALL occurrences, including the last one.
            try:
                with path.open('rb') as stream:
                    for line in stream:
                        checksum.update(line)
                        raw=v.decode_json(line)
                        identity,invalid=self._key(raw,typed)
                        md=raw['validated']['digest'] if typed else digest(raw)
                        index.execute('''INSERT INTO members(id,digest,invalid) VALUES (?,?,?)
                            ON CONFLICT(id) DO UPDATE SET conflict=members.conflict OR members.digest!=excluded.digest''',(identity,md,invalid))
            except (ValueError,KeyError,TypeError,OSError):
                with self.store.transaction():
                    self.db.execute("UPDATE staged_containers SET integrity='failed' WHERE source=? AND resource=?",(source,resource))
                self.retry(source,resource,tick,'unreadable staged container')
                return 'FAILED'
            index.commit()
            if checksum.hexdigest()!=row['digest']:
                with self.store.transaction():
                    self.db.execute("UPDATE staged_containers SET integrity='failed' WHERE source=? AND resource=?",(source,resource))
                self.retry(source,resource,tick,'container digest mismatch')
                return 'FAILED'
            checkpoint('after_index')
            # Pin before validating members: intact and PARTIAL still pins.
            self.db.execute('ATTACH DATABASE ? AS adapter_index',(str(index_path),))
            try:
                with self.store.transaction():
                    pinned=self.db.execute('SELECT baseline_members FROM adapter_state WHERE source=?',(source,)).fetchone()[0]
                    if pinned is None:
                        self.db.execute("""INSERT OR IGNORE INTO baseline_members
                            SELECT ?,id FROM adapter_index.members WHERE invalid=0 AND id NOT GLOB '@invalid:*'
                            UNION SELECT source,source_id FROM quarantine WHERE source=? AND source_id NOT GLOB '@invalid:*'""",(source,source))
                        self.db.execute("UPDATE adapter_state SET baseline_members='[]' WHERE source=?",(source,))
            finally:
                self.db.execute('DETACH DATABASE adapter_index')
            index.execute('CREATE TABLE baseline(id TEXT PRIMARY KEY)')
            for baseline_row in self.db.execute('SELECT source_id FROM baseline_members WHERE source=?',(source,)):
                index.execute('INSERT INTO baseline VALUES (?)',(baseline_row[0],))
            classification=initial_classification
            # Pass two: validation and independent idempotent record transactions.
            with path.open('rb') as stream:
                for line in stream:
                    raw=v.decode_json(line)
                    identity,invalid=self._key(raw,typed)
                    entry=index.execute('SELECT conflict,done FROM members WHERE id=?',(identity,)).fetchone()
                    if entry[1]: continue
                    index.execute('UPDATE members SET done=1 WHERE id=?',(identity,))
                    if invalid or entry[0]:
                        classification='PARTIAL'
                        self.quarantine(source,identity,'invalid id' if invalid else 'same-ID conflict',tick)
                        continue
                    try:
                        data=(raw['validated'] if typed else v.validate_advisory(raw,source=source,observed_at=tick,input_path=resource).data)
                        if data['source']!=source:
                            raise ValueError('advisory source mismatch')
                    except (ValueError,TypeError,KeyError) as error:
                        classification='PARTIAL'
                        self.quarantine(source,identity,str(error),tick)
                        self._observe_unknown(raw, source, resource, tick, typed=typed)
                        continue
                    try:
                        with self.store.transaction():
                            prior=self.db.execute('SELECT digest,revision FROM advisories WHERE source=? AND source_id=?',(source,identity)).fetchone()
                            baseline=bool(index.execute('SELECT 1 FROM baseline WHERE id=?',(identity,)).fetchone())
                            if prior is None or prior['digest']!=data['digest']:
                                from cornicen.advisory import reconcile_facets
                                data = reconcile_facets(self.db, data)
                                revision=str(int(prior['revision'])+1) if prior else '1'
                                self.db.execute('INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?,?)',
                                    (source,identity,revision,data['digest'],canonical(data),data['observed_at'],data['published'],data['updated'],
                                     'withdrawn' if data.get('withdrawn') else 'active'))
                                callback = on_record or self.on_record
                                if callback:
                                    callback(data,baseline)
                                else:
                                    from cornicen.advisory import write_evidence
                                    write_evidence(self.db, data, baseline)
                            from cornicen.advisory import clear_shells
                            # Owner-scoped acceptance, even when no callback ran.
                            # Withdrawal never clears provisional markers.
                            clear_shells(self.db, data)
                            self.db.execute('DELETE FROM quarantine WHERE source=? AND source_id=?',(source,identity))
                    except Exception as error:
                        from cornicen.store import TransactionAborted
                        if isinstance(error, TransactionAborted):
                            raise
                        classification='PARTIAL'
                        self.quarantine(source,identity,str(error),tick)
            index.commit()
            if finalize:
                classification=self._finish_index(source,resource,tick,index,index_path,classification,checkpoint,accept=deferred is None,rebaseline=rebaseline)
            if deferred is not None and classification=='COMPLETE':
                deferred.append((resource,path,index_path))
            elif classification=='COMPLETE' and finalize:
                self._remove_stage(source,resource,path)
            elif finalize and schedule_retry:
                self.retry(source,resource,tick,classification)
            return classification
        finally:
            index.close()
            if deferred is None or not any(item[2]==index_path for item in deferred):
                index_path.unlink(missing_ok=True)

    def _manifest_digest(self, index):
        checksum=sha256(b'[')
        first=True
        for identity,md in index.execute('SELECT id,digest FROM members ORDER BY id,digest'):
            if not first: checksum.update(b',')
            checksum.update(canonical(dict(source_id=identity,digest=md)).encode())
            first=False
        checksum.update(b']')
        return checksum.hexdigest()

    def _finish_index(self,source,resource,tick,index,index_path,classification,checkpoint,*,accept=True,rebaseline=False):
        # Missing previously accepted members are computable, never a flag.
        self.db.execute('ATTACH DATABASE ? AS adapter_index',(str(index_path),))
        try:
            missing=self.db.execute('''SELECT 1 FROM manifest_members m
                WHERE source=? AND resource=? AND NOT EXISTS
                (SELECT 1 FROM adapter_index.members WHERE id=m.source_id) LIMIT 1''',(source,resource)).fetchone()
            gap=self.db.execute('SELECT 1 FROM gap_ledger WHERE source=? AND acknowledged_at IS NULL',(source,)).fetchone()
            if (missing or gap) and not rebaseline: classification='PARTIAL'
            if classification=='COMPLETE' and accept:
                md=self._manifest_digest(index)
                with self.store.transaction():
                    self._write_manifest(source,resource,md,tick,'adapter_index.members')
                    checkpoint('after_manifest')
                    self._advance_cursor(source,tick)
                    self.db.execute('DELETE FROM adapter_retries WHERE source=? AND resource=?',(source,resource))
                    self._complete_baseline(source,tick)
            return classification
        finally:
            self.db.execute('DETACH DATABASE adapter_index')

    def _write_manifest(self,source,resource,md,tick,table):
        # table is an internal attached index name, never adapter input.
        self.db.execute("""INSERT INTO manifests VALUES (?,?,?,'[]',?,?)
            ON CONFLICT(source,resource) DO UPDATE SET digest=excluded.digest,
            members='[]',fetched_at=excluded.fetched_at""",(source,resource,md,tick,tick))
        self.db.execute('DELETE FROM manifest_members WHERE source=? AND resource=?',(source,resource))
        query=f'INSERT INTO manifest_members SELECT ?,?,id,digest FROM {table}'
        params=(source,resource)
        if table=='adapter_batch.members':
            query+=' WHERE resource=?'
            params+=(resource,)
        self.db.execute(query,params)

    def _advance_cursor(self,source,tick):
        checksum=sha256(b'[')
        first=True
        for row in self.db.execute("""SELECT DISTINCT source_id,digest FROM manifest_members
                WHERE source=? ORDER BY source_id,digest""",(source,)):
            if not first: checksum.update(b',')
            checksum.update(canonical(dict(source_id=row[0],digest=row[1])).encode())
            first=False
        checksum.update(b']')
        self.db.execute('UPDATE adapter_state SET cursor_tick=?,cursor_digest=? WHERE source=?',
                        (tick,checksum.hexdigest(),source))

    def _accept_batch(self,source,tick,candidates,*,rebaseline=False):
        """Accept every required resource and the source cursor in one transaction."""
        batch_path=self.directory / (uuid.uuid4().hex+'.index')
        batch=sqlite3.connect(batch_path)
        batch.execute('PRAGMA cache_size=-2048')
        batch.execute('PRAGMA temp_store=FILE')
        batch.execute('CREATE TABLE members(resource TEXT,id TEXT,digest TEXT,PRIMARY KEY(resource,id)) WITHOUT ROWID')
        digests={}
        try:
            for resource,path,index_path in candidates:
                index=sqlite3.connect(index_path)
                try:
                    digests[resource]=self._manifest_digest(index)
                    batch.executemany('INSERT INTO members VALUES (?,?,?)',
                                      ((resource,*row) for row in index.execute('SELECT id,digest FROM members ORDER BY id,digest')))
                finally:
                    index.close()
            batch.commit()
            self.db.execute('ATTACH DATABASE ? AS adapter_batch',(str(batch_path),))
            try:
                with self.store.transaction():
                    if rebaseline:
                        self._acknowledge_rebaseline(source,tick)
                    for resource,path,index_path in candidates:
                        self._write_manifest(source,resource,digests[resource],tick,'adapter_batch.members')
                        self.db.execute('DELETE FROM adapter_retries WHERE source=? AND resource=?',(source,resource))
                    self._advance_cursor(source,tick)
                    self._complete_baseline(source,tick)
                    for resource,path,index_path in candidates:
                        self.db.execute('DELETE FROM staged_containers WHERE source=? AND resource=?',(source,resource))
            finally:
                self.db.execute('DETACH DATABASE adapter_batch')
            for resource,path,index_path in candidates:
                path.unlink(missing_ok=True)
        finally:
            batch.close()
            batch_path.unlink(missing_ok=True)

    def _complete_baseline(self,source,tick):
        blocked=self.db.execute('''SELECT 1 FROM baseline_members b
            WHERE b.source=? AND (NOT EXISTS(SELECT 1 FROM advisories a WHERE a.source=b.source AND a.source_id=b.source_id)
            OR EXISTS(SELECT 1 FROM quarantine q WHERE q.source=b.source AND q.source_id=b.source_id)) LIMIT 1''',(source,)).fetchone()
        state=self.db.execute('SELECT baseline_complete FROM adapter_state WHERE source=?',(source,)).fetchone()
        if not blocked and state and not state[0]:
            self.db.execute('UPDATE adapter_state SET baseline_complete=1 WHERE source=?',(source,))
            key='baseline:'+source
            self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',('|'+key+'|baseline|1','',key,'baseline',1,tick))
            self.store.queue('|'+key,'normal',['baseline'],dict(record_id=key,watch_id='',episode=1),instant(tick).isoformat())

    def summaries(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM events WHERE type='baseline'")]

    def _remove_stage(self,source,resource,path):
        with self.store.transaction():
            self.db.execute('DELETE FROM staged_containers WHERE source=? AND resource=?',(source,resource))
        path.unlink(missing_ok=True)

    def resume(self,tick,*,source=None):
        """Recover intact interrupted work, leaving scheduled retries in backoff."""
        sources=[source] if source is not None else [r[0] for r in self.db.execute('SELECT DISTINCT source FROM staged_containers')]
        for name in sources:
            candidates=[]
            try:
                rows=self.db.execute("""SELECT resource FROM staged_containers s
                    WHERE source=? AND integrity='intact' AND NOT EXISTS
                    (SELECT 1 FROM adapter_retries r WHERE r.source=s.source AND r.resource=s.resource)""",(name,)).fetchall()
                for row in rows:
                    self.commit_staged(name,row[0],tick,deferred=candidates)
                ready={r[0] for r in candidates}
                unresolved=any(r[0] not in ready for r in self.db.execute(
                    "SELECT resource FROM staged_containers WHERE source=? UNION SELECT resource FROM adapter_retries WHERE source=? AND resource!='@dispatch'",(name,name)))
                if candidates and not unresolved:
                    self._accept_batch(name,tick,candidates)
            finally:
                for resource,path,index_path in candidates:
                    index_path.unlink(missing_ok=True)

    def retry(self,source,resource,tick,error,*,retry_after=None,rate_reset=None):
        now=instant(tick)
        with self.store.transaction():
            row=self.db.execute('SELECT attempts FROM adapter_retries WHERE source=? AND resource=?',(source,resource)).fetchone()
            attempts=(row[0] if row else 0)+1
            wait=min(60*2**min(attempts-1,20),21600)*self.rng.uniform(.8,1.2)
            header=max(float(retry_after or 0),(rate_reset-now).total_seconds() if rate_reset else 0)
            if header>wait: wait=header
            self.db.execute('INSERT OR REPLACE INTO adapter_retries VALUES (?,?,?,?,?)',
                            (source,resource,attempts,stamp(now+timedelta(seconds=wait)),str(error)))
        return wait

    def gap(self,source,tick,reason):
        with self.store.transaction():
            if not self.db.execute('SELECT 1 FROM gap_ledger WHERE source=? AND reason=? AND acknowledged_at IS NULL',(source,reason)).fetchone():
                self.db.execute('INSERT INTO gap_ledger VALUES (?,?,?,NULL)',(source,tick,reason))

    def historical(self,source):
        return ('unhealthy (permanent gap)' if self.db.execute('SELECT 1 FROM gap_ledger WHERE source=?',(source,)).fetchone() else 'healthy')

    def _acknowledge_rebaseline(self,source,tick):
        self.db.execute("DELETE FROM baseline_members WHERE source=? AND source_id GLOB '@invalid:*'",(source,))
        self.db.execute("UPDATE adapter_state SET baseline_members='[]' WHERE source=?",(source,))
        self.db.execute('UPDATE gap_ledger SET acknowledged_at=? WHERE source=? AND acknowledged_at IS NULL',(tick,source))
        self.db.execute('UPDATE adapter_state SET rebaselined_at=?,cutoff=? WHERE source=?',(tick,tick,source))

    def rebaseline(self,source,tick):
        if not self.db.execute('SELECT 1 FROM adapter_state WHERE source=?',(source,)).fetchone():
            raise ValueError('adapter has no stored enumeration')
        staged=self.db.execute('SELECT resource,integrity FROM staged_containers WHERE source=?',(source,)).fetchall()
        if any(row['integrity']!='intact' for row in staged):
            raise ValueError('cannot rebaseline an incomplete container')
        candidates=[]
        try:
            for row in staged:
                state=self.commit_staged(source,row['resource'],tick,deferred=candidates,rebaseline=True)
                if state!='COMPLETE':
                    raise ValueError('cannot rebaseline invalid members')
            if candidates:
                self._accept_batch(source,tick,candidates,rebaseline=True)
            else:
                if not self.db.execute('SELECT 1 FROM manifests WHERE source=? AND digest!=\'\'',(source,)).fetchone():
                    raise ValueError('adapter has no accepted enumeration')
                with self.store.transaction():
                    self._acknowledge_rebaseline(source,tick)
                    self._advance_cursor(source,tick)
                    self._complete_baseline(source,tick)
        finally:
            for resource,path,index_path in candidates:
                index_path.unlink(missing_ok=True)

    def dimension(self,source,name,state,tick,detail=''):
        """Persist a dimension, retaining the instant its current state began."""
        with self.store.transaction():
            self.db.execute("""INSERT INTO source_health VALUES (?,?,?,?,?)
                ON CONFLICT(source,dimension) DO UPDATE SET state=excluded.state,
                since=CASE WHEN state=excluded.state THEN since ELSE excluded.since END,
                detail=excluded.detail""",(source,name,state,tick,detail))

    def audits_due(self,source,tick):
        """Return resources due for an unconditional request at seven days."""
        return [r['resource'] for r in self.db.execute(
            'SELECT * FROM manifests WHERE source=? ORDER BY resource',(source,))
            if self._age_limit(tick,r['audited_at'] or r['fetched_at'],7*86400,inclusive=True)]

    def _audit_observation(self,source,resource,tick):
        # Even an unsuccessful first request starts this resource's audit clock.
        successful=(resource['status']==200 and resource.get('transfer_complete',True)
                    and resource.get('integrity','intact')=='intact'
                    and not resource.get('conditional',False))
        with self.store.transaction():
            self.db.execute("""INSERT INTO manifests VALUES (?,?,'','[]',?,?)
                ON CONFLICT(source,resource) DO UPDATE SET
                audited_at=CASE WHEN excluded.audited_at IS NULL THEN manifests.audited_at
                                ELSE excluded.audited_at END""",
                (source,resource['path'],tick,tick if successful else None))

    def _publication(self,source,resources,tick,*,export,last_modified_validated,classification):
        if not export:
            self.dimension(source,'freshness','n/a',tick)
            return
        clocks=self._publication_clocks(source)
        for resource in resources:
            # Export adapters may also fetch discovery or metadata resources.
            if not resource.get('export',export): continue
            path=resource['path']
            clocks.setdefault(path,None)
            # A 304 retains the clock tied to the cached revision, even if the
            # response supplies a new clock. Never interpret cached wire bodies.
            if resource['status']==304: continue
            if not 200<=resource['status']<300: continue
            if not resource.get('transfer_complete',True) or resource.get('integrity','intact')!='intact': continue
            clock=resource.get('publication_clock')
            credible=False
            if isinstance(clock,dict):
                provenance=clock.get('provenance')
                if provenance=='publisher_generation' or (provenance=='gate_validated_last_modified' and last_modified_validated):
                    try:
                        from cornicen.feeddates import rfc3339
                        rfc3339(clock.get('value'))
                        credible=True
                    except ValueError:
                        pass
            if credible:
                clocks[path]=clock
            elif classification=='COMPLETE':
                clocks[path]=None
        self._publication_dimension(source,clocks,tick)

    def _publication_clocks(self,source):
        row=self.db.execute("SELECT detail FROM source_health WHERE source=? AND dimension='freshness'",(source,)).fetchone()
        try:
            detail=json.loads(row[0]) if row else {}
            return detail.get('resources',{}) if isinstance(detail,dict) else {}
        except (ValueError,TypeError):
            return {}

    def _publication_dimension(self,source,clocks,tick):
        states=[self._clock_state(clock,tick) if clock else 'unknown' for clock in clocks.values()]
        state='stale' if 'stale' in states else 'unknown' if not states or 'unknown' in states else 'healthy'
        self.dimension(source,'freshness',state,tick,canonical(dict(resources=clocks)))

    @staticmethod
    def _age_limit(tick,anchor,seconds,*,inclusive=False):
        from cornicen.feeddates import rfc3339, FeedDate
        start=rfc3339(anchor)
        boundary=FeedDate('',start.seconds+seconds,start.fraction)
        now=rfc3339(tick)
        return now>=boundary if inclusive else now>boundary

    def _clock_state(self,clock,tick):
        return 'stale' if self._age_limit(tick,clock['value'],48*3600) else 'healthy'

    def restore_health(self,source,tick):
        # R7: restore stored state silently; an existing row awaits cycle verdict.
        with self.store.transaction():
            rows=self.db.execute('SELECT state,detail FROM source_health WHERE source=?',(source,)).fetchall()
            if rows:
                bad=[r for r in rows if r['state'] not in ('healthy','n/a')]
                self.db.execute('INSERT OR IGNORE INTO health VALUES (?,?,?,?)',
                                (source,'unhealthy' if bad else 'healthy',tick,bad[0]['detail'] if bad else 'healthy'))

    def finish_cycle(self,source,tick,*,export=False,on_health=None):
        """Finalize dimensions and queue a transition; callers release outbox last.

        Called only for effective adapters. The dispatch gate enforces R1/R7.
        """
        rows=dict(self.db.execute('SELECT dimension,state FROM source_health WHERE source=?',(source,)))
        if not rows: return
        # Leave pre-existing sparse R7 state intact until a real observation.
        if 'audit' in rows:
            overdue=[r['resource'] for r in self.db.execute('SELECT * FROM manifests WHERE source=?',(source,))
                     if self._age_limit(tick,r['audited_at'] or r['fetched_at'],7*86400)]
            self.dimension(source,'audit','unhealthy' if overdue else 'healthy',tick,canonical(overdue))
        if export:
            self._publication_dimension(source,self._publication_clocks(source),tick)
        rows=self.db.execute('SELECT dimension,state FROM source_health WHERE source=?',(source,)).fetchall()
        bad=[r['dimension']+': '+r['state'] for r in rows if r['state'] not in ('healthy','n/a')]
        state='unhealthy' if bad else 'healthy'
        detail='; '.join(bad) if bad else 'All applicable dimensions healthy'
        with self.store.transaction():
            if on_health:
                on_health(source,state,detail)
                return
            old=self.db.execute('SELECT state FROM health WHERE source=?',(source,)).fetchone()
            self.db.execute("""INSERT INTO health VALUES (?,?,?,?) ON CONFLICT(source)
                DO UPDATE SET state=excluded.state,detail=excluded.detail,
                since=CASE WHEN state=excluded.state THEN since ELSE excluded.since END""",(source,state,tick,detail))
            if (old and old[0]==state) or (not old and state=='healthy'): return
            key='health_episode:'+source
            episode=int(self.store.get_meta(key) or '0')+1
            self.store.set_meta(key,episode)
            self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                            (f'|{source}|{state}|{episode}','',source,state,episode,tick))
            from cornicen.render import health_body
            self.store.queue(f'|{source}|health|{episode}','health',[state],
                             health_body(source,state,None,None,tick),instant(tick).isoformat(),tick)

    def dispatch(self,registry,settings,factories,tick,*,on_health=None):
        """Check both switches before constructing, polling, retrying or auditing."""
        outcomes={}
        effective=[]
        for source,entry in registry.items():
            if not entry.effective(settings.get(source,False)):
                with self.store.transaction():
                    self.db.execute('DELETE FROM health WHERE source=?',(source,))
                continue
            effective.append((source,entry))
            self.restore_health(source,tick)
            if source not in factories: continue
            options=dict(export=getattr(entry,'export',False),
                         last_modified_validated=getattr(entry,'last_modified_validated',False))
            try:
                self.resume(tick,source=source)
                adapter=factories[source]()
                state=self.db.execute('SELECT cutoff FROM adapter_state WHERE source=?',(source,)).fetchone()
                resources=adapter.poll(cutoff=state[0] if state else None)
                outcomes[source]=self.process(source,resources,tick,**options)
                with self.store.transaction():
                    self.db.execute("DELETE FROM adapter_retries WHERE source=? AND resource='@dispatch'",(source,))
                for resource in self.audits_due(source,tick):
                    waiting=self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE source=? AND resource=?',(source,resource)).fetchone()
                    if waiting and instant(waiting[0])>instant(tick): continue
                    self.process(source,adapter.audit(resource),tick,**options)
                for row in self.db.execute('SELECT * FROM adapter_retries WHERE source=?',(source,)).fetchall():
                    if instant(row['next_attempt_at'])<=instant(tick):
                        self.process(source,adapter.retry(row['resource']),tick,**options)
            except Exception as error:
                detail=f'{type(error).__name__}: {error}'
                self.ensure(source,tick)
                self.retry(source,'@dispatch',tick,detail)
                self.dimension(source,'fetch','unhealthy',tick,detail)
                self.dimension(source,'completeness','unhealthy',tick,detail)
                self._defaults(source,tick,options['export'])
                outcomes[source]='FAILED'
        for source,entry in effective:
            self.finish_cycle(source,tick,export=getattr(entry,'export',False),on_health=on_health)
        return outcomes

    def _defaults(self,source,tick,export):
        with self.store.transaction():
            for dimension,state in (('audit','healthy'),('freshness','unknown' if export else 'n/a')):
                self.db.execute('INSERT OR IGNORE INTO source_health VALUES (?,?,?,?,?)',
                                (source,dimension,state,tick,''))

    def _retry_headers(self,resource,tick):
        from email.utils import parsedate_to_datetime
        headers={key.lower():value for key,value in resource.get('headers',{}).items()}
        after=headers.get('retry-after')
        try:
            after=float(after) if after is not None else None
        except (ValueError,TypeError):
            try:
                after=(parsedate_to_datetime(after)-instant(tick)).total_seconds()
            except (ValueError,TypeError,OverflowError):
                after=None
        reset=headers.get('x-ratelimit-reset',headers.get('ratelimit-reset'))
        try:
            reset=datetime.fromtimestamp(float(reset),timezone.utc) if reset is not None else None
        except (ValueError,TypeError,OverflowError,OSError):
            reset=None
        return dict(retry_after=after,rate_reset=reset)

    def process(self,source,resources,tick,*,export=False,last_modified_validated=False):
        """Accept raw fixture/adapter resource outcomes through the real validator.

        Resources are independently publishable; the cycle cursor is advanced
        only when all required resources complete. Conditional listing responses
        never dispose of unresolved staged work or retries. A resource's export
        flag defaults to the adapter export policy; set it False for discovery
        or metadata responses that carry no export revision.
        """
        self.ensure(source,tick)
        candidates=[]
        resources=list(resources)
        try:
            state=self._process_resources(source,resources,tick,candidates)
            if resources:
                self._defaults(source,tick,export)
                previous=self.db.execute("SELECT detail FROM source_health WHERE source=? AND dimension='fetch'",(source,)).fetchone()
                try:
                    transfers=json.loads(previous[0]) if previous else {}
                    if not isinstance(transfers,dict): transfers={}
                except (ValueError,TypeError):
                    transfers={}
                transfers.pop('@dispatch',None)
                for r in resources:
                    transfers[r['path']]=((200<=r['status']<300 or r['status']==304)
                        and r.get('transfer_complete',True) and r.get('integrity','intact')=='intact')
                self.dimension(source,'fetch','healthy' if all(transfers.values()) else 'unhealthy',tick,canonical(transfers))
                self.dimension(source,'completeness','healthy' if state=='COMPLETE' else 'unhealthy',tick)
                self._publication(source,resources,tick,export=export,last_modified_validated=last_modified_validated,classification=state)
            return state
        finally:
            for resource,path,index_path in candidates:
                index_path.unlink(missing_ok=True)

    def _process_resources(self,source,resources,tick,candidates):
        states=[]
        # An outer transaction here would wrongly roll back independent commits.
        for resource in resources:
            resource=dict(resource)
            path=resource['path']
            self._audit_observation(source,resource,tick)
            conditional = resource['status']==304
            if conditional:
                cached=self.db.execute('SELECT * FROM resource_cache WHERE source=? AND url=?',(source,path)).fetchone()
                if not cached:
                    self.retry(source,path,tick,'304 without cached body');states.append('FAILED');continue
                if self.db.execute("SELECT 1 FROM staged_containers WHERE source=? UNION ALL SELECT 1 FROM adapter_retries WHERE source=? AND resource!='@dispatch'",(source,source)).fetchone():
                    # A conditional response cannot clear staged work. It can
                    # expose identities as unknown through a validated shell.
                    try:
                        body = v.decode_json(cached['body'])
                        members = body if isinstance(body, list) else body.get('advisories', [])
                        for raw in members:
                            self._observe_unknown(raw, source, path, tick)
                    except (ValueError, TypeError, AttributeError):
                        pass
                    states.append('PARTIAL');continue
                resource.update(status=200,body=cached['body'])
            result=v.validate_resource(resource,source=source,observed_at=tick)
            # Validate the envelope first; streaming member validation happens
            # in the two-pass commit, not in an already drained result stream.
            try:
                body=v.decode_json(resource.get('body',''))
                envelope=body if isinstance(body,dict) else {}
                members=envelope.get('advisories') if isinstance(body,dict) else body
                intact=(resource.get('transfer_complete',True) and resource.get('integrity','intact')=='intact')
                usable=(200<=resource['status']<300 and result.classification!='FAILED' and intact and isinstance(members,list) and not ('error' in envelope or 'errors' in envelope))
            except ValueError:
                usable=False;envelope={};members=[]
            if not usable:
                if result.classification=='PARTIAL' and isinstance(members,list):
                    self.stage_members(source,path,iter(members),tick,integrity='pending')
                self.retry(source,path,tick,result.classification,**self._retry_headers(resource,tick))
                states.append(result.classification);continue
            coverage=envelope.get('coverage_start')
            if coverage:
                current=self.db.execute('SELECT cursor_tick,cutoff FROM adapter_state WHERE source=?',(source,)).fetchone()
                if instant(coverage)>instant(current['cursor_tick'] or current['cutoff']):
                    self.gap(source,tick,'retention gap')
            self.stage_members(source,path,iter(members),tick)
            state=self.commit_staged(source,path,tick,deferred=candidates,initial_classification=result.classification,schedule_retry=False)
            if state!='COMPLETE':
                self.retry(source,path,tick,state,**self._retry_headers(resource,tick))
            headers={k.lower():val for k,val in resource.get('headers',{}).items()}
            # Cache a validated envelope even when an individual member is bad;
            # pending quarantine/staging still prevents 304 from clearing work.
            if not conditional:
                with self.store.transaction():
                    self.db.execute('INSERT OR REPLACE INTO resource_cache VALUES (?,?,?,?,?,?,?)',
                        (source,path,resource['body'],headers.get('etag'),headers.get('last-modified'),headers.get('link'),tick))
            states.append(state)
        classification='FAILED' if 'FAILED' in states else 'PARTIAL' if 'PARTIAL' in states else 'COMPLETE'
        candidate_names={r[0] for r in candidates}
        pending=any(r[0] not in candidate_names for r in self.db.execute(
            "SELECT resource FROM staged_containers WHERE source=? UNION SELECT resource FROM adapter_retries WHERE source=? AND resource!='@dispatch'",(source,source)))
        if pending and classification=='COMPLETE': classification='PARTIAL'
        if classification=='COMPLETE' and candidates:
            self._accept_batch(source,tick,candidates)
        return classification

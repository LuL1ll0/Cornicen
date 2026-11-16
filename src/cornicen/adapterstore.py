# script-purpose: Persist validated adapter records and reconcile staged resources.
# script-class: pipeline-tool
# script-trigger: The engine adapter dispatch and adapter rebaseline command.
# script-tests: tests/test_f3b.py, tests/test_f2a.py, tests/test_f3a.py, tests/test_r11_shells.py, tests/test_task1_a.py, tests/test_task1_b1.py, tests/test_task1_b2.py, tests/test_task2_b1.py, tests/test_task2_b2.py, tests/test_task3_b1.py
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
import math
import re
from pathlib import Path
import random
import sqlite3
import uuid

from cornicen import feedvalidate as v
from cornicen.diagnostics import FixedDiagnostic


_INTERNAL_REASONS = frozenset(('PARTIAL', 'FAILED', '304 without cached body',
    'unreadable staged container', 'container digest mismatch', 'unenumerated'))


def safe_detail(error):
    """Return fixed diagnostic text without formatting adapter-controlled errors."""
    name = type(error).__name__
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name):
        name = 'Exception'
    detail = (error.args[0] if error.args and type(error.args[0]) is FixedDiagnostic
              else 'adapter error')
    return name + ': ' + detail


def bounded_wait(headers, now):
    """Read HTTP wait headers; return the largest valid wait capped at six hours.

    Return None when no valid server wait exists. No files are read or written.
    """
    from email.utils import parsedate_to_datetime
    waits = []
    for key, value in headers.items():
        key = key.lower()
        if key not in ('retry-after', 'x-ratelimit-reset', 'ratelimit-reset'):
            continue
        try:
            if key == 'retry-after':
                try:
                    wait = float(value)
                except (ValueError, TypeError):
                    wait = (parsedate_to_datetime(value) - now).total_seconds()
            else:
                wait = (datetime.fromtimestamp(float(value), timezone.utc) - now).total_seconds()
            if math.isfinite(wait) and wait >= 0:
                waits.append(wait)
        except (ValueError, TypeError, OverflowError, OSError):
            continue
    return min(max(waits), 21600) if waits else None


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

    def _independent(self, source):
        from cornicen.adapters import REGISTRY
        entry = REGISTRY.get(source)
        return bool((entry and entry.independent) or
                    self.store.get_meta('required_since:' + source) is not None)

    def set_baseline_hold(self, source, tick):
        """Delay the independent summary, retaining permission for late pins."""
        self.ensure(source, tick)
        with self.store.transaction():
            self.store.set_meta('baseline_hold:' + source, tick)
            self.store.set_meta('baseline_hold_used:' + source, tick)

    def release_baseline_hold(self, source, tick):
        """Release the summary barrier; baseline membership remains durable."""
        with self.store.transaction():
            self.db.execute('DELETE FROM meta WHERE k=?', ('baseline_hold:' + source,))

    def pin_baseline_member(self, source, source_id, tick):
        """Pin a late bootstrap identity even after the summary was released."""
        if self.store.get_meta('baseline_hold_used:' + source) is None:
            return
        v.source_id(source_id)
        with self.store.transaction():
            self.db.execute('INSERT OR IGNORE INTO baseline_members VALUES (?,?)', (source,source_id))

    @staticmethod
    def _outcome_flags(resource, source):
        """Validate optional flags before any member is staged or committed."""
        from cornicen.feeddates import rfc3339
        failures = resource.get('subrequest_failures', 0)
        http_errors = resource.get('subrequest_http_errors', 0)
        if (type(failures) is not int or type(http_errors) is not int
                or not 0 <= http_errors <= failures):
            raise ValueError('invalid subrequest counts')
        from cornicen.sources.msrc_csaf import PROFILE as MICROSOFT
        from cornicen.sources.cisco_csaf import PROFILE as CISCO
        generation_key = next((p.generation_key for p in (MICROSOFT, CISCO) if p.source == source), None)
        for key in (MICROSOFT.generation_key, CISCO.generation_key):
            if key in resource and (key != generation_key or not (
                    isinstance(resource[key], str) and re.fullmatch(r'[0-9a-f]{32}', resource[key]))):
                raise ValueError('invalid CSAF generation')
        if 'record_audit_oldest' in resource:
            rfc3339(resource['record_audit_oldest'])
        return {key: resource[key] for key in ('coverage_complete', 'subrequest_failures',
                'subrequest_http_errors', 'record_audit_oldest', generation_key) if key in resource}

    @staticmethod
    def _flag_classification(state, flags):
        if state == 'FAILED' or flags.get('subrequest_http_errors', 0):
            return 'FAILED'
        if (state == 'PARTIAL' or flags.get('coverage_complete', True) is not True
                or flags.get('subrequest_failures', 0)):
            return 'PARTIAL'
        return state

    def _staged_flags(self, source, resource):
        return json.loads(self.store.get_meta(f'staged_flags:{source}:{resource}') or '{}')

    def _delete_stage_row(self, source, resource):
        self.db.execute('DELETE FROM staged_containers WHERE source=? AND resource=?', (source,resource))
        self.db.execute('DELETE FROM meta WHERE k=?', (f'staged_flags:{source}:{resource}',))

    def _process_file(self, source, resource, tick, candidates, flags):
        # Use the ordinary envelope validator for path and transport policy;
        # member decoding and validation remain streamed through the same path.
        result = v.validate_resource(dict(resource, body='[]'), source=source, observed_at=tick)
        if result.classification != 'COMPLETE':
            self.retry(source,resource['path'],tick,result.classification,**self._retry_headers(resource,tick))
            return result.classification
        try:
            path = Path(resource['members_file']).resolve()
            if not path.is_relative_to(self.directory.parent.resolve()):
                raise ValueError('members file outside data directory')
            with path.open('rb') as stream:
                self.stage_members(source,resource['path'],(v.decode_json(line) for line in stream),tick,flags=flags)
            path.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError):
            self.retry(source,resource['path'],tick,'FAILED')
            return 'FAILED'
        state = self.commit_staged(source,resource['path'],tick,deferred=candidates,schedule_retry=False)
        if state != 'COMPLETE':
            self.retry(source,resource['path'],tick,state,**self._retry_headers(resource,tick))
        return state

    def _clear_reappeared(self, source, resource):
        # Called with the current container index attached.
        key = f'ack_absent:{source}:{resource}'
        prior = self.store.get_meta(key)
        if prior is not None:
            remaining = [r[0] for r in self.db.execute('''SELECT value FROM json_each(?)
                WHERE NOT EXISTS (SELECT 1 FROM adapter_index.members WHERE id=value)''', (prior,))]
            with self.store.transaction():
                self.store.set_meta(key, canonical(remaining))

    def _acknowledge_absent(self, source):
        for resource in sorted(self.required_resources(source)):
            key = f'ack_absent:{source}:{resource}'
            acknowledged = set(json.loads(self.store.get_meta(key) or '[]'))
            staged = self.db.execute('SELECT path FROM staged_containers WHERE source=? AND resource=?',
                                     (source,resource)).fetchone()
            if staged:
                with Path(staged[0]).open('rb') as stream:
                    present = {self._key(v.decode_json(line), False)[0] for line in stream}
            else:
                present = {r[0] for r in self.db.execute('SELECT source_id FROM manifest_members WHERE source=? AND resource=?',
                                                       (source,resource))}
            acknowledged.update(self.known_members(source,resource) - present)
            acknowledged.difference_update(present)
            self.store.set_meta(key, canonical(sorted(acknowledged)))

    def required_resources(self, source):
        """Read the reconciled required logical keys, or None for shared sources."""
        if not self._independent(source):
            return None
        return set(json.loads(self.store.get_meta('required_since:' + source) or '{}'))

    def reconcile_required(self, source, resources, tick):
        """Persist the current required set before resume, polling or retry routing.

        Resources are logical keys supplied by an independent adapter, never URLs.
        Dropped histories remain; their retries and staged work are removed.
        """
        required = set(resources)
        if '@dispatch' in required:
            raise ValueError(FixedDiagnostic('invalid required resource'))
        for resource in required:
            v.safe_path(resource)
        self.ensure(source, tick)
        paths = []
        with self.store.transaction():
            previous = json.loads(self.store.get_meta('required_since:' + source) or '{}')
            self.store.set_meta('required_since:' + source,
                                canonical({r: previous.get(r, tick) for r in sorted(required)}))
            if self.store.get_meta('baseline_resources:' + source) is None:
                self.store.set_meta('baseline_resources:' + source, canonical(sorted(required)))
            for table in ('adapter_retries', 'staged_containers'):
                for row in self.db.execute(f'SELECT * FROM {table} WHERE source=?', (source,)).fetchall():
                    if row['resource'] != '@dispatch' and row['resource'] not in required:
                        if table == 'staged_containers':
                            paths.append(Path(row['path']))
                            self.db.execute('DELETE FROM meta WHERE k=?', (f"staged_flags:{source}:{row['resource']}",))
                        self.db.execute(f'DELETE FROM {table} WHERE source=? AND resource=?',
                                        (source, row['resource']))
            row = self.db.execute("SELECT detail FROM source_health WHERE source=? AND dimension='fetch'", (source,)).fetchone()
            if row:
                try:
                    transfers = json.loads(row[0])
                    transfers = {r: ok for r, ok in transfers.items() if r in required}
                except (ValueError, AttributeError):
                    transfers = {}
                self.dimension(source, 'fetch', 'healthy' if all(transfers.values()) else 'unhealthy', tick, canonical(transfers))
        for path in paths:
            path.unlink(missing_ok=True)
            path.with_suffix('.index').unlink(missing_ok=True)

    def known_members(self, source, resource):
        """Return active manifest and accepted PARTIAL-run IDs for this resource."""
        from cornicen.advisory import retracted
        known = {row[0] for row in self.db.execute(
            'SELECT source_id FROM manifest_members WHERE source=? AND resource=?', (source, resource))}
        for row in self.db.execute("""SELECT source_id,json FROM advisories WHERE source=?
                AND json_extract(json, '$.provenance.input_path') = ?""", (source, resource)):
            data = json.loads(row['json'])
            if retracted(data):
                known.discard(row['source_id'])
            else:
                known.add(row['source_id'])
        return known - set(json.loads(self.store.get_meta(f'ack_absent:{source}:{resource}') or '[]'))

    def _independent_completeness(self, source, tick):
        dispatch = self.db.execute("SELECT last_error FROM adapter_retries WHERE source=? AND resource='@dispatch'", (source,)).fetchone()
        detail = dispatch[0] if dispatch else ''
        anchors = json.loads(self.store.get_meta('required_since:' + source) or '{}')
        if not detail:
            for resource in anchors:
                if self.db.execute('SELECT 1 FROM adapter_retries WHERE source=? AND resource=?', (source, resource)).fetchone():
                    detail = 'retry pending'
                    break
        if not detail:
            for resource, since in anchors.items():
                accepted = self.db.execute("SELECT fetched_at FROM manifests WHERE source=? AND resource=? AND digest!=''", (source, resource)).fetchone()
                if self._age_limit(tick, accepted[0] if accepted else since, 86400, inclusive=True):
                    detail = 'rate budget backlog'
                    break
        self.dimension(source, 'completeness', 'unhealthy' if detail else 'healthy', tick, detail)
        return not detail

    def ensure(self, source, tick):
        v.source_id(source)
        with self.store.transaction():
            self.db.execute('INSERT OR IGNORE INTO adapter_state(source,cutoff) VALUES (?,?)', (source,tick))

    def stage_members(self, source, resource, members, tick, *, integrity='intact', typed=False, flags=None):
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
                flag_key = f'staged_flags:{source}:{resource}'
                if flags is None:
                    self.db.execute('DELETE FROM meta WHERE k=?', (flag_key,))
                else:
                    self.store.set_meta(flag_key, canonical(flags))
                    from cornicen.sources.csaf_directory import state_for
                    state = state_for(self.store, source)
                    if state is not None and state.profile.generation_key in flags:
                        state.stage_generation(flags[state.profile.generation_key])
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
                    independent = self._independent(source)
                    baseline_resources = set(json.loads(self.store.get_meta('baseline_resources:' + source) or '[]'))
                    marker = f'baseline_pinned:{source}:{resource}'
                    pin_resource = (independent and resource in baseline_resources
                                    and resource in self.required_resources(source)
                                    and self.store.get_meta(marker) is None)
                    if pin_resource:
                        self.db.execute("""INSERT OR IGNORE INTO baseline_members
                            SELECT ?,id FROM adapter_index.members WHERE invalid=0 AND id NOT GLOB '@invalid:*'""", (source,))
                        self.store.set_meta(marker, canonical([r[0] for r in index.execute(
                            "SELECT id FROM members WHERE invalid=0 AND id NOT GLOB '@invalid:*' ORDER BY id")]))
                    if not independent and pinned is None:
                        self.db.execute("""INSERT OR IGNORE INTO baseline_members
                            SELECT ?,id FROM adapter_index.members WHERE invalid=0 AND id NOT GLOB '@invalid:*'
                            UNION SELECT source,source_id FROM quarantine WHERE source=? AND source_id NOT GLOB '@invalid:*'""",(source,source))
                        self.db.execute("UPDATE adapter_state SET baseline_members='[]' WHERE source=?",(source,))
            finally:
                self.db.execute('DETACH DATABASE adapter_index')
            index.execute('CREATE TABLE baseline(id TEXT PRIMARY KEY)')
            for baseline_row in self.db.execute('SELECT source_id FROM baseline_members WHERE source=?',(source,)):
                index.execute('INSERT INTO baseline VALUES (?)',(baseline_row[0],))
            flags = self._staged_flags(source, resource)
            classification=self._flag_classification(initial_classification, flags)
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
                            raise ValueError(FixedDiagnostic('advisory source mismatch'))
                    except (ValueError,TypeError,KeyError) as error:
                        classification='PARTIAL'
                        self.quarantine(source,identity,safe_detail(error),tick)
                        self._observe_unknown(raw, source, resource, tick, typed=typed)
                        continue
                    try:
                        with self.store.transaction():
                            prior=self.db.execute('SELECT digest,revision FROM advisories WHERE source=? AND source_id=?',(source,identity)).fetchone()
                            baseline=bool(index.execute('SELECT 1 FROM baseline WHERE id=?',(identity,)).fetchone())
                            if prior is None or prior['digest']!=data['digest']:
                                from cornicen.advisory import reconcile_facets, retracted
                                data = reconcile_facets(self.db, data)
                                revision=str(int(prior['revision'])+1) if prior else '1'
                                self.db.execute('INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?,?)',
                                    (source,identity,revision,data['digest'],canonical(data),data['observed_at'],data['published'],data['updated'],
                                     'withdrawn' if retracted(data) else 'active'))
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
                        self.quarantine(source,identity,safe_detail(error),tick)
            index.commit()
            from cornicen.sources.csaf_directory import state_for
            state = state_for(self.store, source)
            if state is not None and state.profile.generation_key in flags:
                state.commit_generation(flags[state.profile.generation_key])
            classification = self._flag_classification(classification, flags)
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
                (SELECT 1 FROM adapter_index.members WHERE id=m.source_id)
                AND NOT EXISTS (SELECT 1 FROM advisories a WHERE a.source=m.source
                    AND a.source_id=m.source_id AND a.state='withdrawn') LIMIT 1''',(source,resource)).fetchone()
            if self._independent(source):
                self._clear_reappeared(source, resource)
                # A PARTIAL publication can commit members without a manifest.
                # Recovery must preserve their unresolved coverage as well.
                missing = any(not self.db.execute(
                    'SELECT 1 FROM adapter_index.members WHERE id=?', (identity,)).fetchone()
                    for identity in self.known_members(source, resource))
            gap=self.db.execute('SELECT 1 FROM gap_ledger WHERE source=? AND acknowledged_at IS NULL',(source,)).fetchone()
            if (missing or gap) and not rebaseline and classification != 'FAILED': classification='PARTIAL'
            if classification=='COMPLETE' and accept:
                md=self._manifest_digest(index)
                with self.store.transaction():
                    self._write_manifest(source,resource,md,tick,'adapter_index.members')
                    checkpoint('after_manifest')
                    self.db.execute('DELETE FROM adapter_retries WHERE source=? AND resource=?',(source,resource))
                    if self._independent(source):
                        self._delete_stage_row(source, resource)
                    self._advance_cursor(source,tick)
                    self._complete_baseline(source,tick)
            return classification
        finally:
            self.db.execute('DETACH DATABASE adapter_index')

    def _write_manifest(self,source,resource,md,tick,table):
        # table is an internal attached index name, never adapter input.
        self.db.execute("""INSERT INTO manifests VALUES (?,?,?,'[]',?,?)
            ON CONFLICT(source,resource) DO UPDATE SET digest=excluded.digest,
            members='[]',fetched_at=excluded.fetched_at,
            audited_at=CASE WHEN ? THEN excluded.audited_at ELSE manifests.audited_at END""",
            (source,resource,md,tick,tick,self._independent(source)))
        self.db.execute('DELETE FROM manifest_members WHERE source=? AND resource=?',(source,resource))
        query=f'INSERT INTO manifest_members SELECT ?,?,id,digest FROM {table}'
        params=(source,resource)
        if table=='adapter_batch.members':
            query+=' WHERE resource=?'
            params+=(resource,)
        self.db.execute(query,params)

    def _advance_cursor(self,source,tick):
        required = self.required_resources(source)
        if required is not None:
            if not self._independent_completeness(source,tick):
                return
            if any(not self.db.execute("SELECT 1 FROM manifests WHERE source=? AND resource=? AND digest!=''",
                                       (source,r)).fetchone() for r in required):
                return
        checksum=sha256(b'[')
        first=True
        required_json = None if required is None else canonical(sorted(required))
        for row in self.db.execute("""SELECT DISTINCT source_id,digest FROM manifest_members
                WHERE source=? AND (? IS NULL OR resource IN
                    (SELECT value FROM json_each(?))) ORDER BY source_id,digest""",
                (source, required_json, required_json)):
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
                        self._delete_stage_row(source, resource)
            finally:
                self.db.execute('DETACH DATABASE adapter_batch')
            for resource,path,index_path in candidates:
                path.unlink(missing_ok=True)
        finally:
            batch.close()
            batch_path.unlink(missing_ok=True)

    def _complete_baseline(self,source,tick):
        from cornicen.sources.csaf_directory import state_for
        state = state_for(self.store, source)
        if state is not None and self.store.get_meta('baseline_hold:' + source) is not None:
            state.release_if_resolved(tick)
        if self._independent(source) and self.store.get_meta('baseline_hold:' + source) is not None:
            return
        if self._independent(source):
            baseline = set(json.loads(self.store.get_meta('baseline_resources:' + source) or '[]'))
            if not baseline:
                return
            if any(self.store.get_meta(f'baseline_pinned:{source}:{r}') is None
                   for r in baseline & self.required_resources(source)):
                return
            blocked = False
            for resource in baseline & self.required_resources(source):
                members = self.store.get_meta(f'baseline_pinned:{source}:{resource}')
                if self.db.execute("""SELECT 1 FROM json_each(?) b
                    WHERE NOT EXISTS(SELECT 1 FROM advisories a WHERE a.source=? AND a.source_id=b.value)
                    AND NOT EXISTS(SELECT 1 FROM quarantine q WHERE q.source=? AND q.source_id=b.value)
                    LIMIT 1""", (members,source,source)).fetchone():
                    blocked = True
                    break
        else:
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
            self._delete_stage_row(source, resource)
        path.unlink(missing_ok=True)

    def resume(self,tick,*,source=None,independent=None):
        """Recover intact interrupted work, leaving scheduled retries in backoff."""
        sources=[source] if source is not None else [r[0] for r in self.db.execute('SELECT DISTINCT source FROM staged_containers')]
        for name in sources:
            is_independent = self._independent(name) if independent is None else independent
            candidates=[]
            recovered=[]
            try:
                rows=self.db.execute("""SELECT resource FROM staged_containers s
                    WHERE source=? AND integrity='intact' AND NOT EXISTS
                    (SELECT 1 FROM adapter_retries r WHERE r.source=s.source AND r.resource=s.resource)""",(name,)).fetchall()
                for row in rows:
                    required = self.required_resources(name)
                    if required is not None and row[0] not in required:
                        continue
                    if is_independent and self.store.get_meta(f'staged_flags:{name}:{row[0]}') is not None:
                        staged = self.db.execute('SELECT * FROM staged_containers WHERE source=? AND resource=?', (name,row[0])).fetchone()
                        path = Path(staged['path'])
                        checksum = sha256()
                        error = None
                        try:
                            with path.open('rb') as stream:
                                for line in stream:
                                    checksum.update(line)
                            if checksum.hexdigest() != staged['digest']:
                                error = 'container digest mismatch'
                        except OSError:
                            error = 'unreadable staged container'
                        if error:
                            with self.store.transaction():
                                self.db.execute("UPDATE staged_containers SET integrity='failed' WHERE source=? AND resource=?", (name,row[0]))
                            self.retry(name,row[0],tick,error)
                            continue
                        recovered.append(dict(path=row[0], status=200, members_file=path,
                                              **self._staged_flags(name,row[0])))
                    elif is_independent:
                        state = self.commit_staged(name,row[0],tick,deferred=candidates)
                        if state == 'COMPLETE':
                            staged = self.db.execute('SELECT path FROM staged_containers WHERE source=? AND resource=?', (name,row[0])).fetchone()
                            with Path(staged[0]).open('rb') as stream:
                                body = canonical(dict(advisories=[v.decode_json(line) for line in stream]))
                            recovered.append(dict(path=row[0], status=200, body=body))
                    else:
                        self.commit_staged(name,row[0],tick,deferred=candidates)
                if is_independent and recovered:
                    # Classify every recovered stream before accepting COMPLETE
                    # containers, just as the ordinary commit loop does above.
                    self.process(name, recovered, tick)
                ready={r[0] for r in candidates}
                unresolved=any(r[0] not in ready for r in self.db.execute(
                    "SELECT resource FROM staged_containers WHERE source=? UNION SELECT resource FROM adapter_retries WHERE source=? AND resource!='@dispatch'",(name,name)))
                if not is_independent and candidates and not unresolved:
                    self._accept_batch(name,tick,candidates)
            finally:
                for resource,path,index_path in candidates:
                    index_path.unlink(missing_ok=True)

    def retry(self,source,resource,tick,error,*,retry_after=None,rate_reset=None,rate_limited=False):
        now=instant(tick)
        with self.store.transaction():
            row=self.db.execute('SELECT attempts FROM adapter_retries WHERE source=? AND resource=?',(source,resource)).fetchone()
            attempts=(row[0] if row else 0)+1
            wait=min(60*2**min(attempts-1,20),21600)*self.rng.uniform(.8,1.2)
            waits = [wait]
            try:
                after = float(retry_after)
                if math.isfinite(after) and after >= 0:
                    waits.append(after)
            except (ValueError, TypeError, OverflowError, OSError):
                pass
            try:
                reset = (rate_reset-now).total_seconds()
                if math.isfinite(reset) and reset >= 0:
                    waits.append(reset)
            except (ValueError, TypeError, OverflowError, OSError):
                pass
            wait = min(max(waits),21600)
            try:
                deadline = now+timedelta(seconds=wait)
            except OverflowError:
                deadline = datetime.max.replace(tzinfo=timezone.utc)
            detail = (safe_detail(error) if isinstance(error,BaseException) else
                      error if type(error) is str and error in _INTERNAL_REASONS else
                      'str: adapter error')
            self.db.execute('INSERT OR REPLACE INTO adapter_retries VALUES (?,?,?,?,?)',
                            (source,resource,attempts,stamp(deadline),detail))
            if rate_limited:
                self.store.set_meta(source + ':rate_hold_until', canonical(stamp(deadline)))
        return wait

    def gap(self,source,tick,reason):
        with self.store.transaction():
            if not self.db.execute('SELECT 1 FROM gap_ledger WHERE source=? AND reason=? AND acknowledged_at IS NULL',(source,reason)).fetchone():
                self.db.execute('INSERT INTO gap_ledger VALUES (?,?,?,NULL)',(source,tick,reason))

    def historical(self,source):
        return ('unhealthy (permanent gap)' if self.db.execute('SELECT 1 FROM gap_ledger WHERE source=?',(source,)).fetchone() else 'healthy')

    def _acknowledge_rebaseline(self,source,tick):
        if self._independent(source):
            self._acknowledge_absent(source)
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
        required = self.required_resources(source)
        return [r['resource'] for r in self.db.execute(
            'SELECT * FROM manifests WHERE source=? ORDER BY resource',(source,))
            if (required is None or r['resource'] in required)
            and self._age_limit(tick,r['audited_at'] or r['fetched_at'],7*86400,inclusive=True)]

    def _audit_observation(self,source,resource,tick):
        # Even an unsuccessful first request starts this resource's audit clock.
        successful=(resource['status']==200 and resource.get('transfer_complete',True)
                    and resource.get('integrity','intact')=='intact'
                    and not resource.get('conditional',False) and not self._independent(source))
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
        if self._independent(source):
            self._independent_completeness(source,tick)
            with self.store.transaction():
                self._complete_baseline(source,tick)
        rows=dict(self.db.execute('SELECT dimension,state FROM source_health WHERE source=?',(source,)))
        if not rows: return
        # Leave pre-existing sparse R7 state intact until a real observation.
        if 'audit' in rows:
            required = self.required_resources(source)
            overdue=[r['resource'] for r in self.db.execute('SELECT * FROM manifests WHERE source=?',(source,))
                     if (required is None or r['resource'] in required)
                     and self._age_limit(tick,r['audited_at'] or r['fetched_at'],7*86400, inclusive=self._independent(source))]
            record_clock = self.store.get_meta('record_audit_oldest:' + source)
            if record_clock is not None and self._age_limit(tick,record_clock,7*86400,inclusive=True):
                overdue.append('record_audit_oldest')
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
                if getattr(entry,'independent',False):
                    adapter=factories[source]()
                    self.reconcile_required(source,adapter.required_resources(),tick)
                    self.resume(tick,source=source,independent=entry.independent)
                else:
                    self.resume(tick,source=source)
                    adapter=factories[source]()
                state=self.db.execute('SELECT cutoff FROM adapter_state WHERE source=?',(source,)).fetchone()
                resources=adapter.poll(cutoff=state[0] if state else None)
                if getattr(entry,'independent',False):
                    resources=list(resources)
                    with self.store.transaction():
                        self.db.execute("DELETE FROM adapter_retries WHERE source=? AND resource='@dispatch'",(source,))
                outcomes[source]=self.process(source,resources,tick,**options)
                with self.store.transaction():
                    self.db.execute("DELETE FROM adapter_retries WHERE source=? AND resource='@dispatch'",(source,))
                for resource in self.audits_due(source,tick):
                    waiting=self.db.execute('SELECT next_attempt_at FROM adapter_retries WHERE source=? AND resource=?',(source,resource)).fetchone()
                    if waiting and instant(waiting[0])>instant(tick): continue
                    results = list(adapter.audit(resource))
                    if results:
                        self.process(source,results,tick,**options)
                for row in self.db.execute('SELECT * FROM adapter_retries WHERE source=?',(source,)).fetchall():
                    if row['resource']=='@dispatch': continue
                    required=self.required_resources(source)
                    if required is not None and row['resource'] not in required: continue
                    if instant(row['next_attempt_at'])<=instant(tick):
                        results = list(adapter.retry(row['resource']))
                        if results:
                            self.process(source,results,tick,**options)
            except Exception as error:
                detail=safe_detail(error)
                self.ensure(source,tick)
                self.retry(source,'@dispatch',tick,error)
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
        wait = bounded_wait(resource.get('headers',{}),instant(tick))
        return dict(rate_limited=resource.get('rate_limited', False),
                    **(dict(retry_after=wait) if wait is not None else {}))

    def process(self,source,resources,tick,*,export=False,last_modified_validated=False,required_resources=None):
        """Accept raw fixture/adapter resource outcomes through the real validator.

        Resources are independently publishable; the cycle cursor is advanced
        only when all required resources complete. Conditional listing responses
        never dispose of unresolved staged work or retries. A resource's export
        flag defaults to the adapter export policy; set it False for discovery
        or metadata responses that carry no export revision.

        Instead of body, members_file accepts a str or Path naming JSONL under
        data_dir. It is consumed line by line and removed after durable staging.
        coverage_complete defaults to True; anything other than True holds
        coverage. subrequest_failures and subrequest_http_errors default to 0
        and require nonnegative exact ints, with HTTP errors <= total failures.
        record_audit_oldest is an optional RFC 3339 string; omit it for no clock.
        """
        self.ensure(source,tick)
        if required_resources is not None:
            self.reconcile_required(source,required_resources,tick)
        candidates=[]
        resources=list(resources)
        required=self.required_resources(source)
        if required is not None:
            resources=[r for r in resources if r['path'] in required]
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
                    try:
                        self._outcome_flags(r, source)
                        flags_valid = True
                    except ValueError:
                        flags_valid = False
                    transfers[r['path']]=(flags_valid and (r.get('unenumerated') is True or
                        ((200<=r['status']<300 or (r['status']==304 and not r.get('unconditional',False)))
                         and not (r.get('transport_error') or r.get('invalid_status'))
                         and r.get('transfer_complete',True) and r.get('integrity','intact')=='intact'))
                         and type(r.get('subrequest_failures',0)) is int and r.get('subrequest_failures',0)==0)
                self.dimension(source,'fetch','healthy' if all(transfers.values()) else 'unhealthy',tick,canonical(transfers))
                if required is None:
                    self.dimension(source,'completeness','healthy' if state=='COMPLETE' else 'unhealthy',tick)
                self._publication(source,resources,tick,export=export,last_modified_validated=last_modified_validated,classification=state)
            if required is not None:
                self._independent_completeness(source,tick)
                with self.store.transaction():
                    self._complete_baseline(source,tick)
            return state
        finally:
            for resource in resources:
                if 'members_file' in resource:
                    try:
                        path = Path(resource['members_file']).resolve()
                        if path.is_relative_to(self.directory.parent.resolve()):
                            path.unlink(missing_ok=True)
                    except (OSError, TypeError, ValueError):
                        pass
            for resource,path,index_path in candidates:
                index_path.unlink(missing_ok=True)

    def _process_resources(self,source,resources,tick,candidates):
        states=[]
        # An outer transaction here would wrongly roll back independent commits.
        for resource in resources:
            resource=dict(resource)
            path=resource['path']
            try:
                flags = self._outcome_flags(resource, source)
            except ValueError:
                self.retry(source,path,tick,'FAILED')
                states.append('FAILED')
                continue
            with self.store.transaction():
                if 'record_audit_oldest' in flags:
                    self.store.set_meta('record_audit_oldest:' + source, flags['record_audit_oldest'])
                else:
                    self.db.execute('DELETE FROM meta WHERE k=?', ('record_audit_oldest:' + source,))
            if resource.get('unenumerated') is True:
                state = self._flag_classification('PARTIAL', flags)
                self.retry(source,path,tick,'unenumerated' if state == 'PARTIAL' else state)
                states.append(state)
                continue
            self._audit_observation(source,resource,tick)
            if 'members_file' in resource:
                states.append(self._process_file(source,resource,tick,candidates,flags))
                continue
            conditional = resource['status']==304 and not resource.get('unconditional', False)
            if conditional:
                cached=self.db.execute('SELECT * FROM resource_cache WHERE source=? AND url=?',(source,path)).fetchone()
                if not cached:
                    self.retry(source,path,tick,'304 without cached body');states.append('FAILED');continue
                if self.db.execute("SELECT 1 FROM staged_containers WHERE source=? AND (? IS NULL OR resource=?) UNION ALL SELECT 1 FROM adapter_retries WHERE source=? AND resource!='@dispatch' AND (? IS NULL OR resource=?)",(source,path if self._independent(source) else None,path,source,path if self._independent(source) else None,path)).fetchone():
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
            self.stage_members(source,path,iter(members),tick,flags=flags or None)
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
        if pending and classification=='COMPLETE' and not self._independent(source): classification='PARTIAL'
        if self._independent(source):
            # All outcomes are classified before accepting resources, so a
            # later failure cannot let the cursor use its older manifest.
            # Each COMPLETE resource still gets its own acceptance transaction.
            for candidate in candidates:
                self._accept_batch(source,tick,[candidate])
        elif classification=='COMPLETE' and candidates:
            self._accept_batch(source,tick,candidates)
        return classification

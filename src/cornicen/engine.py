"""Local source-ordered state transitions and durable end-of-cycle delivery."""

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import zlib
from hashlib import sha256
from zoneinfo import ZoneInfo

import cornicen
from cornicen import applicability, validate
from cornicen.applicability import Result, State
from cornicen.config import Config
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Notifier, Origin
from cornicen.render import health_body, render
from cornicen.scheduler import safe_message
from cornicen.outbox import deliver
from cornicen.store import Store
from cornicen.watchlist import Watch
from cornicen.versions import Scheme


@dataclass
class CycleReport:
    events: list[str] = field(default_factory=list)
    sent: int = 0
    health_changes: list[tuple[str, str]] = field(default_factory=list)


class Engine:
    def __init__(self, store: Store, watches: tuple[Watch, ...], aliases: AliasMap,
                 config: Config, clock: Callable[[], datetime], notifier: Notifier):
        self.store, self.watches, self.aliases = store, watches, aliases
        self.config, self.clock, self.notifier = config, clock, notifier
        self.db = store.connection
        self.report = CycleReport()
        self._pending_report = CycleReport()
        self._attempted_records = set()
        self._identity_version = None
        with store.transaction():
            if store.get_meta('bootstrap_started_at') is None:
                store.set_meta('bootstrap_started_at', self._now().isoformat())
            store.set_meta('alias_map_version', aliases.version)
            saved = store.get_meta('applied_watches')
            canonical = self._canonical_watches(watches)
            aliases_hash = aliases.fingerprint()
            saved_aliases_hash = store.get_meta('applied_aliases_hash')
            aliases_changed = saved_aliases_hash != aliases_hash
            if saved is None and not self.db.execute('SELECT 1 FROM records UNION SELECT 1 FROM pairs LIMIT 1').fetchone():
                self._save_watches()
            elif saved != canonical or aliases_changed:
                # Missing metadata on an older DB requires a full re-match too.
                self.watches = tuple(Watch(**dict(w, match=tuple(map(tuple, w['match'])),
                    product_only=tuple(w['product_only']), scheme=Scheme(w['scheme'])))
                    for w in json.loads(saved)) if saved else ()
                self.reload_watches(watches)
            # Commit with the re-match so an interrupted startup tries again.
            store.set_meta('applied_aliases_hash', aliases_hash)
            rejected = self.db.execute("SELECT detail FROM health WHERE source='watchlist' AND state='unhealthy'").fetchone()
            pending = self.db.execute("SELECT 1 FROM retry_queue WHERE source='watchlist' UNION ALL SELECT 1 FROM dead_letters WHERE source='watchlist'").fetchone()
            if rejected and rejected[0] == 'Watchlist reload rejected' and not pending:
                self.report = self._pending_report
                self._health('watchlist', 'healthy', 'Watchlist startup validation succeeded')
                self.report = CycleReport()
        if self._identity_version is None:
            self._cache_watch_identities()

    @staticmethod
    def _canonical_watches(watches):
        return json.dumps([asdict(w) for w in sorted(watches, key=lambda w: w.id)],
                          sort_keys=True, separators=(',', ':'))

    def _cache_watch_identities(self):
        self._watch_identities = {watch.id: applicability.watch_identities(watch, self.aliases)
                                  for watch in self.watches}
        self._identity_version = self.aliases, self.aliases.version

    def _save_watches(self):
        canonical = self._canonical_watches(self.watches)
        self.store.set_meta('applied_watches', canonical)
        self.store.set_meta('applied_watches_hash', sha256(canonical.encode()).hexdigest())

    def _now(self):
        return self.clock().astimezone(timezone.utc)

    def _digest(self):
        local = self._now().astimezone(ZoneInfo(self.config.timezone))
        hour, minute = map(int, self.config.digest_time.split(':'))
        due = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if due <= local:
            due += timedelta(days=1)
        return due.astimezone(timezone.utc).isoformat()

    def _json_row(self, table, column, record_id):
        row = self.db.execute(f'SELECT json FROM {table} WHERE {column}=?', (record_id,)).fetchone()
        if row is None:
            return None
        value = zlib.decompress(row[0]) if table == 'records' and isinstance(row[0], bytes) else row[0]
        return json.loads(value)

    def _record(self, record_id):
        record = self._json_row('records', 'id', record_id)
        if record is None and self.store.get_meta('kev_only:' + record_id):
            # Evaluation context only; never store this as an accepted CNA record.
            return {'cveMetadata': {'cveId': record_id, 'state': 'PUBLISHED'},
                    'containers': {'cna': {'affected': []}}}
        return record

    def _body(self, watch, record_id, result):
        epss = self.db.execute('SELECT score,pct,date FROM epss WHERE cve=?', (record_id,)).fetchone()
        record = self._record(record_id) or {}
        containers = record.get('containers')
        cna = containers.get('cna') if isinstance(containers, dict) else None
        metrics = cna.get('metrics', []) if isinstance(cna, dict) else []
        score = max((value.get('baseScore', 0) for metric in metrics if isinstance(metric, dict)
            for key, value in metric.items() if key.startswith('cvss') and isinstance(value, dict)
            and type(value.get('baseScore')) in (float, int)), default=None) if isinstance(metrics, list) else None
        severity = score if score is not None else 0
        return {'severity': severity, 'watch_id': watch.id, 'record_id': record_id, 'name': watch.name,
                'product': watch.match[0][1] if watch.match else watch.product_only[0],
                'version': watch.version, 'eol': watch.eol, 'state': result.state.value,
                'evidence': result.evidence, 'confidence': result.confidence,
                'kev': self._json_row('kev', 'cve', record_id),
                'epss': dict(epss) if epss else None, 'epss_threshold': self.config.epss_threshold,
                'cve_title': cna.get('title') if isinstance(cna, dict) else None,
                'cna_cvss_score': score}

    def _urgent(self, body, reasons):
        if not set(reasons) & {'new match', 'KEV added'}:
            return False
        return bool(body.get('kev') or (body['state'] == 'affected' and body.get('epss')
                                       and body['epss']['score'] >= self.config.epss_threshold))

    def _event(self, watch_id, record_id, kind, episode, body, immediate=False, resolution=False):
        key = f'{watch_id}|{record_id}|{kind}|{episode}'
        if resolution:
            key += '|resolution'
        added = self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
            (key, watch_id, record_id, kind, episode, self._now().isoformat())).rowcount
        if not added:
            return
        urgency = ('health' if kind in ('healthy', 'unhealthy') else
                   'urgent' if watch_id and self._urgent(body, [kind]) else 'normal')
        now = self._now().isoformat()
        due = now if immediate or urgency == 'urgent' else self._digest()
        pair_key = f'{watch_id}|{record_id}'
        if kind == 'correction':
            pair_key += '|correction'
        elif kind in ('healthy', 'unhealthy'):
            pair_key += f'|health|{episode}'
        self.store.queue(pair_key, urgency, [kind], body, due, now)
        self.report.events.append(key)

    @staticmethod
    def _active(state, exploited):
        return state == 'affected' or (state == 'unknown' and exploited)

    def _evaluate(self, record, record_id, baseline=False, kev_added=False,
                  kev_baseline=False, reload=False, watches=None, resolving_kev_only=False):
        if record is None:
            self._health('records', 'unhealthy', 'Missing stored record: ' + record_id)
            return
        problems = validate.record(record)
        if problems:
            raise ValueError('; '.join(problems))
        self.store.dirty_record(record_id)
        kev = self._json_row('kev', 'cve', record_id)
        if self._identity_version != (self.aliases, self.aliases.version):
            self._cache_watch_identities()
        identities = {}
        pairs = {row['watch_id']: row for row in self.db.execute(
            'SELECT * FROM pairs WHERE record_id=?', (record_id,))}
        for watch in self.watches if watches is None else watches:
            old = pairs.get(watch.id)
            if applicability.rejected(record) and old:
                result = Result(State.NOT_AFFECTED, bool(kev), 'CNA record rejected', 'high')
            else:
                result = applicability.resolve(record, kev, watch, self.aliases,
                                                self._watch_identities[watch.id], identities)
            if result is None:
                if old is None:
                    continue
                result = Result(State.NOT_AFFECTED, False, 'Identity no longer matches watch', 'high')
            active = self._active(result.state.value, result.exploited)
            was_active = old and self._active(old['state'], old['exploited'])
            if old:
                episode = old['episode']
            else:
                # A removed watch can be readded without discarding sent keys.
                episode = 1 + self.db.execute(
                    'SELECT coalesce(max(episode),0) FROM events WHERE watch_id=? AND record_id=?',
                    (watch.id, record_id)).fetchone()[0]
            notified = old['notified'] if old else 0
            clearing = (was_active or notified) and result.state == State.NOT_AFFECTED
            if clearing:
                episode += 1
            historical = old['baseline'] if old else int(baseline or kev_baseline)
            self.db.execute('''INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(watch_id,record_id) DO UPDATE SET state=excluded.state,
                episode=excluded.episode, exploited=excluded.exploited, evidence=excluded.evidence,
                confidence=excluded.confidence, notified=excluded.notified, alias_map_version=excluded.alias_map_version''',
                (watch.id, record_id, result.state.value, episode, historical,
                 int(result.exploited), 0 if clearing else notified, result.evidence, result.confidence, self.aliases.version))
            body = self._body(watch, record_id, result)
            body['episode'] = episode
            # Evaluate rendering within the record savepoint, before creating events.
            render(Notification('', watch.id, record_id, (), 'normal', body))
            if clearing:
                self._drop_activation(watch.id, record_id)
                if notified and not reload:
                    self._event(watch.id, record_id, 'correction', episode - 1, body)
            elif resolving_kev_only and old and notified and old['state'] != result.state.value:
                self._event(watch.id, record_id, 'correction', episode, body, resolution=True)
            if active and not was_active:
                self.db.execute('DELETE FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                                (f'{watch.id}|{record_id}|correction',))
            if active and not was_active and not baseline and not (kev_baseline and historical):
                self._event(watch.id, record_id, 'new match', episode, body)
            if active and kev_added and not kev_baseline:
                self._event(watch.id, record_id, 'KEV added', episode, body)

    @staticmethod
    def _retry_identity(record):
        metadata = record.get('cveMetadata') if isinstance(record, dict) else None
        record_id = metadata.get('cveId') if isinstance(metadata, dict) else None
        record_id = record_id if isinstance(record_id, str) and record_id.strip() else None
        key = record_id or ('@fetch' if isinstance(record, dict) and set(record) == {'errors'}
                            else '@invalid:' + sha256(json.dumps(record, sort_keys=True).encode()).hexdigest())
        return record_id, key

    def _retry(self, source, record_id, detail):
        detail = validate.error_detail(detail)
        self.store.set_meta('last_error:' + source, detail)
        old = self.db.execute('SELECT attempts FROM retry_queue WHERE source=? AND record_id=?',
                              (source, record_id)).fetchone()
        dead = self.db.execute('SELECT attempts FROM dead_letters WHERE source=? AND record_id=?',
                               (source, record_id)).fetchone()
        attempts = (old[0] if old else dead[0] if dead else 0) + 1
        if record_id != '@fetch' and attempts >= 5:
            self.db.execute('INSERT OR REPLACE INTO dead_letters VALUES (?,?,?,?,?,?)',
                (source, record_id, attempts, (self._now() + timedelta(days=1)).isoformat(), detail, cornicen.__version__))
            self.db.execute('DELETE FROM retry_queue WHERE source=? AND record_id=?', (source, record_id))
        else:
            self.db.execute('INSERT OR REPLACE INTO retry_queue VALUES (?,?,?,?,?)',
                (source, record_id, attempts, self._now().isoformat(), detail))

    def _isolated(self, source, record, action):
        count = len(self.report.events)
        _, key = self._retry_identity(record)
        try:
            with self.store.transaction():
                action()
                for table in ('retry_queue', 'dead_letters'):
                    self.db.execute(f'DELETE FROM {table} WHERE source=? AND record_id=?', (source, key))
            return True
        except Exception as error:
            # Successful ingests remove their retries. Only failures need a
            # same-cycle suppression key; snapshots must not retain every ID.
            self._attempted_records.add((source, key))
            del self.report.events[count:]
            self._retry(source, key, f'{type(error).__name__}: {error}')
            return False

    def _apply_record(self, record, baseline=False):
        problems = validate.record(record)
        if problems:
            raise ValueError('; '.join(problems))
        record_id, _ = self._retry_identity(record)
        if record_id is None:
            raise ValueError('missing CVE ID')
        seen = self.db.execute('SELECT 1 FROM kev_seen WHERE cve=?', (record_id,)).fetchone()
        kev = self._json_row('kev', 'cve', record_id)
        self._evaluate(record, record_id, baseline=baseline,
                       kev_added=bool(kev) and not seen
                       and not self.store.get_meta('kev_baseline:' + record_id),
                       resolving_kev_only=bool(self.store.get_meta('kev_only:' + record_id)))
        self.db.execute('DELETE FROM meta WHERE k=?', ('kev_only:' + record_id,))
        if kev:
            self.db.execute('INSERT OR IGNORE INTO kev_seen VALUES (?)', (record_id,))

    def _evaluate_kev(self, record, record_id):
        seen = self.db.execute('SELECT 1 FROM kev_seen WHERE cve=?', (record_id,)).fetchone()
        baseline = bool(self.store.get_meta('record_baseline:' + record_id))
        self._evaluate(record, record_id,
                       baseline=baseline,
                       kev_added=not seen and self._json_row('kev', 'cve', record_id) is not None,
                       kev_baseline=bool(self.store.get_meta('kev_baseline:' + record_id))
                       or (baseline and not self.store.get_meta('baseline_complete')))
        self.db.execute('INSERT OR IGNORE INTO kev_seen VALUES (?)', (record_id,))

    def _rematch_record(self, record, record_id, watches=None):
        # Snapshot origin decides history; a first-KEV marker governs only KEV-added
        # events, so it must not turn a delta's new match into a baseline pair.
        baseline = (not self.store.get_meta('baseline_complete')
                    and bool(self.store.get_meta('record_baseline:' + record_id)))
        self._evaluate(record, record_id, reload=True, watches=watches, baseline=baseline)

    def _retry_records(self):
        rows = self.db.execute("SELECT *, NULL AS version FROM retry_queue WHERE record_id!='@fetch' "
                               "UNION ALL SELECT * FROM dead_letters ORDER BY source,record_id").fetchall()
        for row in rows:
            source, record_id = row['source'], row['record_id']
            if (source, record_id) in self._attempted_records:
                continue
            if datetime.fromisoformat(row['next_attempt_at']) > self._now() and (
                    row['version'] is None or row['version'] == cornicen.__version__):
                continue
            invalid = self.db.execute('SELECT json FROM invalid_revisions WHERE record_id=?', (record_id,)).fetchone() if source == 'cvelist' else None
            record = json.loads(zlib.decompress(invalid[0])) if invalid else self._record(record_id)
            if record is None:
                self._health('records', 'unhealthy', 'Missing stored record: ' + record_id)
                continue
            def apply():
                if source == 'cvelist':
                    self._apply_record(record, bool(self.store.get_meta('record_baseline:' + record_id)))
                elif source == 'kev':
                    self._evaluate_kev(record, record_id)
                else:
                    self._rematch_record(record, record_id)
            with self.store.transaction():
                self._isolated(source, record, apply)
                pending = self.db.execute('SELECT 1 FROM retry_queue WHERE source=? UNION ALL SELECT 1 FROM dead_letters WHERE source=?', (source, source)).fetchone()
                if not pending:
                    saved = self.store.get_meta('pending_ingest:' + source)
                    if saved:
                        self._complete_cursor(source, json.loads(saved))
                    self._health_verdicts[source] = ('healthy', 'Record retry succeeded', 'recovered')
                else:
                    self._health_verdicts[source] = ('unhealthy', 'Incomplete ingest; retry pending', 'incomplete')

    def _complete_cursor(self, source, saved):
        previous = self.db.execute('SELECT content_time FROM cursors WHERE source=?', (source,)).fetchone()
        content_time = saved['content_time']
        if not previous or not previous[0] or (content_time and content_time >= previous[0]):
            self.db.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)', (source, saved['cursor'], content_time))
        if source == 'cvelist':
            identity = saved.get('release_identity')
            if identity:
                self.store.set_meta('committed_cve:' + identity, '1')
            position = saved.get('release_position')
            previous_position = self.store.get_meta('cvelist_release_position')
            if position and (not previous_position or position > previous_position):
                self.store.set_meta('cvelist_release_position', position)
            if saved.get('snapshot'):
                self.store.set_meta('cvelist_snapshot_complete', '1')
        self.store.set_meta('complete:' + source, '1')
        if source == 'kev':
            self.store.set_meta('kev_initialized', '1')
        self.db.execute('DELETE FROM meta WHERE k=?', ('pending_ingest:' + source,))

    def _health(self, source, state, detail, reason=None):
        error = type(detail).__name__ if isinstance(detail, Exception) else None
        detail = safe_message(detail if error else RuntimeError(detail), self.config.ntfy_token)
        if error:
            detail = (error + ': ' + detail)[:300]
        old = self.db.execute('SELECT * FROM health WHERE source=?', (source,)).fetchone()
        if old and old['state'] == state:
            self.db.execute('UPDATE health SET detail=? WHERE source=?', (detail, source))
            return
        self.db.execute('INSERT OR REPLACE INTO health VALUES (?,?,?,?)',
                        (source, state, self._now().isoformat(), detail))
        if old is None and state == 'healthy':
            return
        episode_key = f'health_episode:{source}'
        episode = int(self.store.get_meta(episode_key) or '0') + 1
        self.store.set_meta(episode_key, episode)
        self._event('', source, state, episode, health_body(source, state, error, reason, self._now().isoformat()), True)
        self.report.health_changes.append((source, state))

    def _ingest(self, ingest):
        source = ingest.source
        if ingest.unchanged and ingest.status == FetchStatus.COMPLETE and not ingest.errors:
            self.db.execute("DELETE FROM retry_queue WHERE source=? AND record_id='@fetch'", (source,))
            pending = self.db.execute('SELECT 1 FROM retry_queue WHERE source=? UNION ALL SELECT 1 FROM dead_letters WHERE source=? LIMIT 1',
                                      (source, source)).fetchone()
            if pending is None:
                self.db.execute('DELETE FROM meta WHERE k=?', ('last_error:' + source,))
            self._health_verdicts[source] = (('unhealthy', 'Incomplete ingest; retry pending', 'incomplete') if pending else
                                             ('healthy', 'Successful unchanged fetch', 'recovered'))
            return
        if source == 'kev' and ingest.status != FetchStatus.FAILED and ingest.content_time:
            previous = self.db.execute("SELECT content_time FROM cursors WHERE source='kev'").fetchone()
            pending = self.store.get_meta('pending_ingest:kev')
            times = [previous[0] if previous else None,
                     json.loads(pending).get('content_time') if pending else None]
            if any(stamp and ingest.content_time < validate.timestamp(stamp) for stamp in times):
                detail = 'KEV dateReleased regressed'
                self._retry(source, '@fetch', detail)
                self._health_verdicts[source] = ('unhealthy', detail, 'failed')
                return
        release_identity = release_position = None
        if source == 'cvelist':
            if ingest.cursor and validate.TAG.fullmatch(ingest.cursor):
                release_identity = ingest.origin.value + ':' + ingest.cursor
                release_position = validate.release_stamp(ingest.cursor).isoformat()
            elif ingest.origin == Origin.SNAPSHOT and ingest.content_time:
                release_identity = 'snapshot:' + ingest.content_time.isoformat()
            # Snapshot tags identify their container, but coverage is midnight.
            if ingest.origin == Origin.SNAPSHOT:
                release_position = (ingest.content_time.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                                    if ingest.content_time else None)
            committed = self.store.get_meta('cvelist_release_position')
            if (release_identity and self.store.get_meta('committed_cve:' + release_identity)
                    or release_position and committed and release_position < committed):
                return
            if ingest.origin == Origin.SNAPSHOT and ingest.content_time and not self.store.get_meta('cvelist_snapshot_cutoff'):
                self.store.set_meta('cvelist_snapshot_cutoff', ingest.content_time.isoformat())
                if ingest.cursor and validate.TAG.fullmatch(ingest.cursor):
                    self.store.set_meta('cvelist_snapshot_release', ingest.cursor)
        if ingest.errors:
            self.store.set_meta('last_error:' + source, validate.error_detail('; '.join(ingest.errors)))
        complete = ingest.status == FetchStatus.COMPLETE and not ingest.errors
        transport_complete = complete
        first_kev = self.store.get_meta('kev_initialized') is None
        payload = ingest.kev if source == 'kev' else ingest.epss if source == 'epss' else None
        empty_failure = (complete and payload == {} and source in ('kev','epss')
                         and self.db.execute(f'SELECT 1 FROM {source} LIMIT 1').fetchone() is not None)
        if empty_failure:
            complete = transport_complete = False
        if ingest.status != FetchStatus.FAILED and not empty_failure:
            if source == 'cvelist':
                baseline = (ingest.origin == Origin.SNAPSHOT and not self.store.get_meta('cvelist_snapshot_complete')
                            and not self.store.get_meta('baseline_complete'))
                for record in ingest.records:
                    _, key = self._retry_identity(record)
                    problems = validate.record(record)
                    if problems:
                        self.db.execute('INSERT OR REPLACE INTO invalid_revisions VALUES (?,?)',
                                        (key, zlib.compress(json.dumps(record).encode())))
                        self.store.set_meta('last_error:' + source, validate.error_detail('; '.join(problems)))
                    else:
                        self.db.execute('DELETE FROM invalid_revisions WHERE record_id=?', (key,))
                        self.store.put_record(key, record, self._now().isoformat())
                    if baseline or not self.store.get_meta('record_baseline:' + key):
                        self.store.set_meta('record_baseline:' + key, '1' if baseline else '')
                    if not self._isolated(source, record,
                                          lambda record=record: self._apply_record(record, baseline)):
                        complete = False
            elif source == 'kev' and payload is not None:
                self.db.execute('CREATE TEMP TABLE IF NOT EXISTS incoming_kev(cve TEXT PRIMARY KEY,json TEXT)')
                self.db.execute('DELETE FROM incoming_kev')
                self.db.executemany('INSERT INTO incoming_kev VALUES (?,?)',
                                    ((key, json.dumps(entry)) for key, entry in payload.items()))
                self._dirty_evidence('kev', ('json',), transport_complete)
                removed = [row[0] for row in self.db.execute(
                    'SELECT cve FROM kev EXCEPT SELECT cve FROM incoming_kev')] if transport_complete else []
                if transport_complete:
                    self.db.execute('DELETE FROM kev')
                self.db.execute('INSERT OR REPLACE INTO kev SELECT * FROM incoming_kev')
                self.db.execute('DELETE FROM incoming_kev')
                for record_id in list(payload) + removed:
                    if first_kev and record_id in payload:
                        self.store.set_meta('kev_baseline:' + record_id, '1')
                    record = self._record(record_id)
                    if (record is None and record_id in payload and not first_kev
                            and not self.store.get_meta('kev_baseline:' + record_id)):
                        if not self.store.get_meta('baseline_complete'):
                            self.store.set_meta('kev_baseline:' + record_id, '1')
                        self.store.set_meta('kev_only:' + record_id, '1')
                        record = self._record(record_id)
                    if record is None:
                        if self.db.execute('SELECT 1 FROM pairs WHERE record_id=?', (record_id,)).fetchone():
                            self._evaluate(None, record_id)
                        continue
                    if not self._isolated(source, record,
                            lambda record=record, record_id=record_id: self._evaluate_kev(record, record_id)):
                        complete = False
            elif source == 'epss' and payload is not None:
                self.db.execute('CREATE TEMP TABLE IF NOT EXISTS incoming_epss(cve TEXT PRIMARY KEY,score REAL,pct REAL,date TEXT)')
                self.db.execute('DELETE FROM incoming_epss')
                stamp = ingest.epss_date.isoformat() if ingest.epss_date else None
                self.db.executemany('INSERT INTO incoming_epss VALUES (?,?,?,?)',
                    ((key, score, pct, stamp) for key, (score, pct) in payload.items()))
                self._dirty_evidence('epss', ('score', 'pct', 'date'), transport_complete)
                if transport_complete:
                    self.db.execute('DELETE FROM epss')
                self.db.execute('INSERT OR REPLACE INTO epss SELECT * FROM incoming_epss')
                self.db.execute('DELETE FROM incoming_epss')
                if transport_complete:
                    self.store.set_meta('last_epss_row_count', len(payload))
        if transport_complete:
            self.db.execute("DELETE FROM retry_queue WHERE source=? AND record_id='@fetch'", (source,))
            saved = {'cursor': ingest.cursor, 'content_time': ingest.content_time.isoformat() if ingest.content_time else None}
            if source == 'cvelist':
                saved.update(release_identity=release_identity, release_position=release_position,
                             snapshot=ingest.origin == Origin.SNAPSHOT)
                if ingest.origin == Origin.SNAPSHOT:
                    saved['cursor'] = None
            self.store.set_meta('pending_ingest:' + source, json.dumps(saved))
            pending = self.db.execute('SELECT 1 FROM retry_queue WHERE source=? UNION ALL SELECT 1 FROM dead_letters WHERE source=? LIMIT 1', (source, source)).fetchone()
            if pending is None:
                self._complete_cursor(source, saved)
                complete = True
            else:
                complete = False
        else:
            self._retry(source, '@fetch',
                        'Empty complete map' if empty_failure else validate.error_detail('; '.join(ingest.errors)) or 'Ingest ' + ingest.status.value)
        if complete:
            self.db.execute('DELETE FROM meta WHERE k=?', ('last_error:' + source,))
        self._health_verdicts[source] = (('healthy', 'Complete ingest', 'recovered') if complete else
                                         ('unhealthy', 'Incomplete ingest; retry pending',
                                          'failed' if ingest.status == FetchStatus.FAILED or empty_failure
                                          else 'incomplete'))

    def _dirty_evidence(self, table, columns, complete):
        # Compare only pending records against keyed, disk-backed incoming data.
        changed = ' OR '.join(f'new.{column} IS NOT old.{column}' for column in columns)
        record_id = "CAST(json_extract(outbox.body_json,'$.record_id') AS TEXT)"
        removed = (f'OR (EXISTS (SELECT 1 FROM {table} WHERE cve={record_id}) '
                   f'AND NOT EXISTS (SELECT 1 FROM incoming_{table} WHERE cve={record_id}))' if complete else '')
        self.db.execute(f'''UPDATE outbox SET dirty=1 WHERE sent_at IS NULL AND (
            EXISTS (SELECT 1 FROM incoming_{table} AS new LEFT JOIN {table} AS old USING(cve)
                    WHERE new.cve={record_id} AND (old.cve IS NULL OR {changed})) {removed})''')

    def reload_watches(self, watches: tuple[Watch, ...]) -> None:
        old_watches = self.watches
        previous = {watch.id: watch for watch in self.watches}
        alias_changed = self._identity_version != (self.aliases, self.aliases.version)
        changed = tuple(watch for watch in watches if alias_changed or previous.get(watch.id) != watch)
        self.watches = watches
        self._cache_watch_identities()
        last_report = self.report
        self.report = self._pending_report
        try:
            with self.store.transaction():
                # Re-matching is transactional; only run_cycle releases queued work.
                ids = self.db.execute('SELECT id FROM records UNION SELECT record_id FROM pairs').fetchall()
                for row in ids:
                    record_id = row[0]
                    record = self._record(record_id)
                    if record is None:
                        self._evaluate(None, record_id)
                        continue
                    self._isolated('watchlist', record,
                        lambda record=record, record_id=record_id: self._rematch_record(
                            record, record_id, watches=changed))
                pending = self.db.execute("SELECT 1 FROM retry_queue WHERE source='watchlist' UNION ALL SELECT 1 FROM dead_letters WHERE source='watchlist' LIMIT 1").fetchone()
                self._health('watchlist', 'unhealthy' if pending else 'healthy',
                             'Re-match failed; retry pending' if pending else 'Watchlist re-match complete',
                             'incomplete' if pending else 'recovered')
                active_ids = {watch.id for watch in watches}
                for watch_id in previous.keys() - active_ids:
                    for pair in self.db.execute('SELECT record_id FROM pairs WHERE watch_id=?', (watch_id,)).fetchall():
                        self._drop_activation(watch_id, pair['record_id'])
                    self.db.execute('DELETE FROM pairs WHERE watch_id=?', (watch_id,))
                for row in self.db.execute('SELECT * FROM outbox WHERE sent_at IS NULL').fetchall():
                    body = json.loads(row['body_json'])
                    if body.get('watch_id') and body['watch_id'] not in active_ids:
                        for reason in json.loads(row['reasons_json']):
                            episode = body.get('episode', 1) - int(reason == 'correction')
                            key = f"{body['watch_id']}|{body['record_id']}|{reason}|{episode}"
                            self.db.execute('DELETE FROM events WHERE key=?', (key,))
                        self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
                self.db.execute('UPDATE outbox SET dirty=1 WHERE sent_at IS NULL')
                self._save_watches()
        except BaseException:
            self.watches = old_watches
            self._cache_watch_identities()
            raise
        finally:
            self.report = last_report

    def _finish_health(self):
        verdicts = dict(self._health_verdicts)
        from cornicen.health import coverage_problem
        sources = dict.fromkeys(row['source'] for row in self.db.execute('SELECT * FROM cursors'))
        sources.update(dict.fromkeys(('cvelist', 'kev', 'epss')))
        for source in sources:
            problem = coverage_problem(source, self.store, self._now())
            if problem:
                previous = verdicts.get(source)
                detail = previous[1] + '; ' if previous and previous[0] == 'unhealthy' else ''
                # Classify persisted coverage from structured values, never diagnostics.
                cursor = self.db.execute('SELECT value,content_time FROM cursors WHERE source=?',
                                         (source,)).fetchone()
                reason = 'incomplete'
                if cursor and cursor['content_time']:
                    try:
                        stamp = datetime.fromisoformat(cursor['content_time'])
                        if stamp.tzinfo is None:
                            stamp = stamp.replace(tzinfo=timezone.utc)
                        future = stamp > self._now() + timedelta(hours=2)
                        if source == 'cvelist' and cursor['value'] and validate.TAG.fullmatch(cursor['value']):
                            future |= validate.release_stamp(cursor['value']) > self._now() + timedelta(hours=2)
                        reason = 'future-dated' if future else 'stale'
                    except (TypeError, ValueError):
                        pass
                verdicts[source] = ('unhealthy', detail + problem,
                                    previous[2] if previous and previous[0] == 'unhealthy' else reason)
        dead = {}
        for row in self.db.execute('SELECT source,record_id FROM dead_letters'):
            dead.setdefault(row['source'], []).append(row['record_id'])
        for source, records in dead.items():
            verdicts[source] = ('unhealthy', 'Dead-letter records: ' + ', '.join(records) + '; failed after 5 attempts', 'incomplete')
        for source, (state, detail, reason) in verdicts.items():
            last_error = self.store.get_meta('last_error:' + source)
            if last_error and state == 'unhealthy':
                detail += '; last error: ' + validate.error_detail(last_error)
            self._health(source, state, detail, reason)

    def _drop_activation(self, watch_id, record_id):
        row = self.db.execute('SELECT * FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                              (f'{watch_id}|{record_id}',)).fetchone()
        if row:
            body = json.loads(row['body_json'])
            for reason in json.loads(row['reasons_json']):
                key = f"{watch_id}|{record_id}|{reason}|{body.get('episode', 1)}"
                self.db.execute('DELETE FROM events WHERE key=?', (key,))
            self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))

    def _revalidate(self, row, persist=True):
        body = json.loads(row['body_json'])
        if not body.get('watch_id'):
            if row['urgency'] == 'health':
                reasons = json.loads(row['reasons_json'])
                state = 'healthy' if reasons == ['healthy'] else 'unhealthy'
                body = health_body(body['record_id'], state, body.get('error'),
                                   body.get('reason'), body.get('since') or row['due_at'])
                if not persist:
                    return dict(row, body_json=json.dumps(body))
                self.db.execute('UPDATE outbox SET body_json=? WHERE id=?',
                                (json.dumps(body), row['id']))
                return self.db.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone()
            return row
        if self._record(body['record_id']) is None:
            if persist:
                self._health('records', 'unhealthy', 'Missing stored record: ' + body['record_id'])
            return None
        watch = next((w for w in self.watches if w.id == body['watch_id']), None)
        pair = self.db.execute('SELECT * FROM pairs WHERE watch_id=? AND record_id=?',
                               (body['watch_id'], body['record_id'])).fetchone()
        reasons = json.loads(row['reasons_json'])
        if not watch or not pair or ('correction' not in reasons and not self._active(pair['state'], pair['exploited'])):
            if persist:
                self._drop_activation(body['watch_id'], body['record_id'])
                self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
            return None
        result = Result(State(pair['state']), bool(pair['exploited']), pair['evidence'], pair['confidence'])
        if reasons == ['correction']:
            # Preserve the correction's cleared state and episode until delivery.
            return row
        episode = body.get('episode', pair['episode'])
        body = self._body(watch, body['record_id'], result)
        body['episode'] = episode
        urgency = 'urgent' if self._urgent(body, reasons) else 'normal'
        due = row['due_at']
        if urgency != row['urgency']:
            due = self._now().isoformat() if urgency == 'urgent' else self._digest()
        if not persist:
            return dict(row, body_json=json.dumps(body), urgency=urgency, due_at=due)
        self.db.execute('UPDATE outbox SET body_json=?,urgency=?,due_at=? WHERE id=?',
                        (json.dumps(body), urgency, due, row['id']))
        return self.db.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone()

    def _flush(self):
        now = self._now().isoformat()
        ids = self.db.execute('''SELECT id FROM outbox WHERE sent_at IS NULL AND dirty=1
            UNION SELECT id FROM outbox INDEXED BY outbox_ready WHERE sent_at IS NULL
            AND max(due_at,coalesce(next_attempt_at,due_at))<=? ORDER BY id''', (now,)).fetchall()
        for offset in range(0, len(ids), 256):
            with self.store.transaction():
                for queued in ids[offset:offset + 256]:
                    self._refresh_pending(queued['id'])
        ready = self.db.execute('''SELECT * FROM outbox INDEXED BY outbox_ready WHERE sent_at IS NULL
            AND max(due_at,coalesce(next_attempt_at,due_at))<=? ORDER BY id''', (now,)).fetchall()
        self.report.sent += deliver(self.store, self.notifier, self._now, ready,
                                    revalidate=self._delivery_rows)

    def _refresh_pending(self, row_id):
        row = self.db.execute('SELECT * FROM outbox WHERE id=? AND sent_at IS NULL', (row_id,)).fetchone()
        if row is not None:
            row = self._revalidate(row)
            if row is not None:
                self.db.execute('UPDATE outbox SET dirty=0 WHERE id=?', (row_id,))
        return row

    def _delivery_rows(self, rows):
        """Refresh each group immediately before sending; never hold its send open."""
        ready = []
        for old in rows:
            row = self.db.execute('SELECT * FROM outbox WHERE id=? AND sent_at IS NULL', (old['id'],)).fetchone()
            row = self._revalidate(row, persist=False) if row is not None else None
            now = self._now().isoformat()
            if (row is not None and row['due_at'] <= now
                    and (not row['next_attempt_at'] or row['next_attempt_at'] <= now)):
                ready.append(row)
        return ready

    def run_cycle(self, ingests: Sequence[IngestResult]) -> CycleReport:
        self.report = self._pending_report
        self._pending_report = CycleReport()
        self._health_verdicts = {}
        self._attempted_records = set()
        order = {'cvelist': 0, 'kev': 1, 'epss': 2}
        for ingest in sorted(ingests, key=lambda i: order[i.source]):
            with self.store.transaction():
                self._ingest(ingest)
        self._retry_records()
        with self.store.transaction():
            self._finish_health()
            self.store.prune_records(self._now(), self.config.retention_days)
            if not self.store.get_meta('baseline_complete') and all(
                    self.store.get_meta('complete:' + source) for source in order):
                self.store.set_meta('baseline_complete', '1')
                count = self.db.execute("SELECT count(*) FROM pairs WHERE baseline=1 AND (state='affected' OR (state='unknown' AND exploited=1))").fetchone()[0]
                exploited = self.db.execute("SELECT count(*) FROM pairs WHERE baseline=1 AND exploited=1 AND state!='not_affected'").fetchone()[0]
                self._event('', 'baseline', 'baseline', 1,
                            {'record_id': 'baseline', 'detail': f'baseline: {count} historical matches, {exploited} exploited — run `cornicen report`'}, True)
        self._flush()
        return self.report

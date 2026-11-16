# script-purpose: Evaluate local feed evidence and deliver durable notifications.
# script-class: pipeline-tool
# script-trigger: Cornicen scheduler cycles and local command paths.
# script-tests: tests/test_engine.py, tests/test_f3a.py, tests/test_f3b.py, tests/test_r11_differential.py, tests/test_r11_shells.py, tests/test_r11_integration.py, tests/test_task1_b1.py, tests/test_task1_b2.py, tests/test_task3_a.py
"""Read feed results and stored evidence; write SQLite state and notification outbox.

Library API with no process exit codes; callers report operational failures.
"""
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import zlib
from hashlib import sha256
from zoneinfo import ZoneInfo

import cornicen
from cornicen import applicability, cnascope, validate
from cornicen import accept, advisory
from cornicen.applicability import Result, State
from cornicen.config import Config
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Notifier, Origin
from cornicen.render import health_body, render
from cornicen.store import record_ssvc
from cornicen.scheduler import redact_tokens, safe_message
from cornicen.outbox import deliver
from cornicen.store import Store, TransactionAborted
from cornicen.watchlist import Watch, GitHubSelector
from cornicen.versions import Scheme


class AdvisoryEvaluationFailed(Exception):
    """Advisory work rolled back; completed v1 work must remain committed."""


@dataclass
class CycleReport:
    events: list[str] = field(default_factory=list)
    sent: int = 0
    health_changes: list[tuple[str, str]] = field(default_factory=list)


class Engine:
    def validate_adapter_result(self, result, *, source=None, resource='records.jsonl', tick=None,
                                data_dir=None):
        """Spool the one-shot typed stream and commit through the disk index."""
        from pathlib import Path
        from cornicen.feedvalidate import AdapterResult
        from cornicen.adapterstore import AdapterStore
        if not isinstance(result, AdapterResult):
            raise TypeError('expected AdapterResult')
        # A source is required for valid commits. Check untrusted streams first
        # so the boundary always rejects a plain dict with zero database writes.
        if source is None:
            for record in result.checked_records():
                raise ValueError('adapter source and tick required')
            return result
        # The typed boundary also supports store-only validation before an
        # evaluator is initialized; initialized engines match accepted records.
        persistence = AdapterStore(self.store, data_dir or Path(self.config.db_path).parent,
                                   on_record=self.commit_advisory if hasattr(self, 'watches') else None,
                                   on_unknown=self.observe_unknown_advisory if hasattr(self, 'watches') else None)
        persistence.stage_members(source, resource, result.checked_records(), tick, typed=True)
        for identity in result.quarantine:
            persistence.quarantine(source, identity, result.quarantine_reasons.get(identity, 'invalid record'), tick)
        state = persistence.commit_staged(source, resource, tick, typed=True,
                                          initial_classification=result.classification)
        if result.classification == 'COMPLETE':
            result.classification = state
        return result

    def dispatch_adapters(self, *, registry=None, factories=None):
        """Run the effective adapter gate before every dispatch route."""
        from pathlib import Path
        from cornicen.adapters import REGISTRY
        from cornicen.adapterstore import AdapterStore
        registry = REGISTRY if registry is None else registry
        from cornicen.adapterfactories import production_factories
        factories = production_factories(self) if factories is None else factories
        persistence = AdapterStore(self.store, Path(self.config.db_path).parent, on_record=self.commit_advisory,
                                   on_unknown=self.observe_unknown_advisory)
        return persistence.dispatch(registry, self.config.adapters, factories,
                                    self._now().isoformat().replace('+00:00', 'Z'), on_health=self._health)

    def __init__(self, store: Store, watches: tuple[Watch, ...], aliases: AliasMap,
                 config: Config, clock: Callable[[], datetime], notifier: Notifier, accepts=(), release_checker=None):
        self.release_checker = release_checker
        self.accepts = tuple(accepts)
        self.acceptance_holds = frozenset()
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
            revision_changed = (store.get_meta('applied_matching_revision')
                                != str(applicability.MATCHING_REVISION))
            if saved is None and not self.db.execute('SELECT 1 FROM records UNION SELECT 1 FROM pairs LIMIT 1').fetchone():
                self._save_watches()
            elif saved != canonical or aliases_changed or revision_changed:
                # Missing metadata on an older DB requires a full re-match too.
                self.watches = tuple(Watch(**dict(w, match=tuple(map(tuple, w['match'])),
                    product_only=tuple(w['product_only']), scheme=Scheme(w['scheme']),
                    github=tuple(GitHubSelector(**g) for g in w.get('github', [])),
                    platform=tuple(w['platform'][k] for k in ('vendor', 'product')) if w.get('platform') else None))
                    for w in json.loads(saved)) if saved else ()
                previous_ids = ({row[0] for row in self.db.execute('SELECT DISTINCT watch_id FROM pairs')}
                                if saved is None else None)
                self.reload_watches(watches, force_all=revision_changed, previous_ids=previous_ids)
            self._initialize_epss_crossings()
            # Commit with the re-match so an interrupted startup tries again.
            store.set_meta('applied_aliases_hash', aliases_hash)
            store.set_meta('applied_matching_revision', applicability.MATCHING_REVISION)
            rejected = self.db.execute("SELECT detail FROM health WHERE source='watchlist' AND state='unhealthy'").fetchone()
            pending = self.db.execute("SELECT 1 FROM retry_queue WHERE source='watchlist' UNION ALL SELECT 1 FROM dead_letters WHERE source='watchlist'").fetchone()
            if rejected and rejected[0] == 'Watchlist reload rejected' and not pending:
                self.report = self._pending_report
                self._health('watchlist', 'healthy', 'Watchlist startup validation succeeded')
                self.report = CycleReport()
        if self._identity_version is None:
            self._cache_watch_identities()

    def _initialize_epss_crossings(self, watch_id=None, record_id=None):
        # NULL means no score has been observed yet. Seed upgrades from the
        # accepted map before replacing it with the first incoming scores.
        query = """INSERT OR IGNORE INTO epss_crossings(watch_id,record_id,episode,fired,threshold,rearm_ratio)
            SELECT p.watch_id,p.record_id,p.episode,
                CASE WHEN e.score IS NULL THEN NULL ELSE e.score>=? END, ?, ?
            FROM pairs p LEFT JOIN epss_crossing_scores e ON e.cve=p.record_id"""
        threshold, ratio = self.config.epss_threshold, self.config.epss_rearm_ratio
        params = (threshold, threshold, ratio)
        if watch_id is not None:
            query += ' WHERE p.watch_id=? AND p.record_id=?'
            params += (watch_id, record_id)
        self.db.execute(query, params)
        # Reconcile against the last COMPLETE, error-free map before accepting
        # incoming evidence. A config edit consumes no crossing event.
        reconcile = '''SELECT x.*, e.score FROM epss_crossings x
            JOIN epss_crossing_scores e ON e.cve=x.record_id
            WHERE (x.threshold IS NULL OR x.rearm_ratio IS NULL
                OR x.threshold!=? OR x.rearm_ratio!=?)'''
        params = (threshold, ratio)
        if watch_id is not None:
            reconcile += ' AND x.watch_id=? AND x.record_id=?'
            params += (watch_id, record_id)
        rows = self.db.execute(reconcile, params).fetchall()
        for row in rows:
            fired = row['fired']
            if row['score'] >= threshold:
                fired = 1
            elif Decimal(str(row['score'])) < Decimal(str(threshold)) * Decimal(str(ratio)):
                fired = 0
            self.db.execute('''UPDATE epss_crossings SET fired=?,threshold=?,rearm_ratio=?
                WHERE watch_id=? AND record_id=?''',
                (fired, threshold, ratio, row['watch_id'], row['record_id']))

    def _epss_crossings(self):
        watches = {w.id: w for w in self.watches}
        rearm = Decimal(str(self.config.epss_threshold)) * Decimal(str(self.config.epss_rearm_ratio))
        rows = self.db.execute("""SELECT p.*, e.score, x.fired, x.crossing, x.threshold, x.rearm_ratio
            FROM pairs p JOIN epss_crossing_scores e ON e.cve=p.record_id
            JOIN epss_crossings x ON x.watch_id=p.watch_id AND x.record_id=p.record_id""").fetchall()
        for pair in rows:
            fired = pair['fired']
            high = pair['score'] >= self.config.epss_threshold
            crossing = pair['crossing']
            if fired is None:
                fired = int(high)
            elif (pair['threshold'] != self.config.epss_threshold
                    or pair['rearm_ratio'] != self.config.epss_rearm_ratio):
                # With no accepted pre-change score, the first new observation
                # supplies the silent baseline rather than inventing a crossing.
                if high:
                    fired = 1
                elif Decimal(str(pair['score'])) < rearm:
                    fired = 0
            elif fired and Decimal(str(pair['score'])) < rearm:
                fired = 0
            elif not fired and high:
                fired = 1
                watch = watches.get(pair['watch_id'])
                entry = next((a for a in self.accepts if a.watch.casefold() == pair['watch_id'].casefold()
                              and a.cve == pair['record_id']), None)
                accepted = entry and accept.state(entry, watches, self._now(), self.config.timezone) == 'active'
                if (self.config.epss_crossing and watch and pair['state'] == 'affected'
                        and pair['notified'] and not accepted):
                    result = Result(State.AFFECTED, bool(pair['exploited']), pair['evidence'], pair['confidence'])
                    body = self._body(watch, pair['record_id'], result)
                    if body['kev'] is None and body['ssvc'].get('Exploitation') != 'active':
                        crossing += 1
                        body['episode'] = pair['episode']
                        self._event(watch.id, pair['record_id'], 'epss_crossed', pair['episode'],
                                    body, occurrence=crossing)
            self.db.execute("""UPDATE epss_crossings SET fired=?,crossing=?,threshold=?,rearm_ratio=?
                WHERE watch_id=? AND record_id=?""",
                (fired, crossing, self.config.epss_threshold, self.config.epss_rearm_ratio,
                 pair['watch_id'], pair['record_id']))

    @staticmethod
    def _canonical_watches(watches):
        return json.dumps([{k: v for k, v in dict(asdict(w),
                            platform=dict(zip(('vendor', 'product'), w.platform)) if w.platform else None,
                            github=[asdict(g) for g in sorted(w.github,
                                key=lambda g: (g.repository, g.ecosystem, g.package))]).items()
                            if (k not in ('latest_release', 'release_tag_prefix', 'platform') or v is not None)
                            and (k != 'github' or v)}
                           for w in sorted(watches, key=lambda w: w.id)],
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

    def _body(self, watch, record_id, result, *, route=None):
        epss = self.db.execute('SELECT score,pct,date FROM epss WHERE cve=?', (record_id,)).fetchone()
        record = self._record(record_id) or {}
        containers = record.get('containers')
        cna = containers.get('cna') if isinstance(containers, dict) else None
        metrics = cna.get('metrics', []) if isinstance(cna, dict) else []
        score = max((value.get('baseScore', 0) for metric in metrics if isinstance(metric, dict)
            for key, value in metric.items() if key.startswith('cvss') and isinstance(value, dict)
            and type(value.get('baseScore')) in (float, int)), default=None) if isinstance(metrics, list) else None
        severity = score if score is not None else 0
        body = {'severity': severity, 'watch_id': watch.id, 'record_id': record_id, 'name': watch.name,
                'product': watch.match[0][1] if watch.match else watch.product_only[0],
                'version': watch.version, 'eol': watch.eol, 'state': result.state.value,
                'evidence': result.evidence, 'confidence': result.confidence,
                'kev': self._json_row('kev', 'cve', record_id),
                'ssvc': record_ssvc(record),
                'epss': dict(epss) if epss else None, 'epss_threshold': self.config.epss_threshold,
                'cve_title': cna.get('title') if isinstance(cna, dict) else None,
                'cna_cvss_score': score}

        if (route or self.route(record_id, watch)) == 'advisory':
            data = advisory.metadata(self.db, record_id, watch, self.aliases,
                getattr(self, 'evidence_scopes', {}).get(watch.id),
                getattr(self, 'scope_equivalences', ()))
            if data:
                fix = self.advisory_fix(watch, record_id)
                body.update(cve_title=data['title'], advisory_url=data['url'],
                            advisory_title=data['title'],
                            fix='available; version not stated' if fix == 'available' else fix)
                if record_id.startswith('advisory:') and len(data['cves']) > 1:
                    body['label'] = 'advisory — which listed CVE affects you is not stated'
                    body['evidence'] = body['label'] + '; ' + body['evidence']
        known = [r[0] for r in self.db.execute('SELECT old_id FROM identity_redirects WHERE new_id=? ORDER BY old_id', (record_id,))]
        if known and (route or self.route(record_id, watch)) == 'advisory':
            body['also_known_as'] = known
        return body

    def route(self, identity, watch):
        return advisory.route(self.db, identity, watch, getattr(self, 'aliases', None),
            getattr(self, 'evidence_scopes', {}).get(watch.id),
            getattr(self, 'scope_equivalences', ()))

    def _advisory_matches(self, identity, watch):
        return advisory.matching_rows(self.db, identity, watch, self.aliases,
            getattr(self, 'evidence_scopes', {}).get(watch.id),
            getattr(self, 'scope_equivalences', ()))

    def advisory_result(self, watch, record_id, *, record=None, scope=None):
        return advisory.resolve(self.db, record_id, watch, self.aliases,
            record=self._record(record_id) if record is None else record,
            kev=self._json_row('kev', 'cve', record_id),
            scope=scope if scope is not None else getattr(self, 'evidence_scopes', {}).get(watch.id),
            equivalents=getattr(self, 'scope_equivalences', ()))

    def advisory_fix(self, watch, record_id, *, scope=None):
        return advisory.fix_for(self.db, record_id, watch, self.aliases,
            scope if scope is not None else getattr(self, 'evidence_scopes', {}).get(watch.id),
            getattr(self, 'scope_equivalences', ()))

    def observe_unknown_advisory(self, data):
        """Expose a validated identity shell without accepting quarantined evidence."""
        with self.store.transaction():
            for watch in self.watches:
                if not any(applicability._identity_match(*p['name'].split(':', 1), watch, self.aliases)
                           for p in data['products'] if ':' in p['name']):
                    continue
                for identity in advisory.identities(data):
                    self.db.execute('INSERT OR IGNORE INTO advisory_shells VALUES (?,?,?)',
                                    (data['source'], data['source_id'], identity))
                    advisory.remember(self.db, identity, watch, [(data['source'], data['source_id'])])
                    self.db.execute('INSERT OR IGNORE INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (watch.id, identity, 'unknown', 1, 0, 0, 0,
                         'Quarantined advisory; applicability unknown', 'medium', self.aliases.version))

    def commit_advisory(self, data, baseline=False):
        """Commit evidence and matching together; callback runs inside adapter savepoint."""
        from cornicen.adapterstore import canonical
        with self.store.transaction():
            data = advisory.reconcile_facets(self.db, data)
            self.db.execute('INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?,?)',
                (data['source'], data['source_id'],
                 (self.db.execute('SELECT revision FROM advisories WHERE source=? AND source_id=?',
                                  (data['source'], data['source_id'])).fetchone() or ['1'])[0],
                 data['digest'], canonical(data),
                 data['observed_at'], data['published'], data['updated'],
                 'withdrawn' if advisory.retracted(data) else 'active'))
            previous = {r[0] for r in self.db.execute(
                'SELECT identity FROM advisory_evidence WHERE source=? AND source_id=?',
                (data['source'], data['source_id']))}
            advisory.write_evidence(self.db, data, baseline)
            parent = advisory.parent_id(data)
            for facet in advisory.facet_records(data):
                if len(facet['cves']) == 1 and not advisory.retracted(data):
                    provisional = advisory.parent_id(facet)
                    target = facet['cves'][0]['value']
                    # A sole-CVE revision can replace membership without
                    # equating distinct CVEs or reassigning a permanent redirect.
                    if advisory.canonical_id(self.db, provisional) in (provisional, target):
                        advisory.link(self, provisional, target, data['observed_at'])
            for association in data.get('associations', []):
                child = association['cve']
                for watch in self.watches:
                    old_parent = self.db.execute(
                        'SELECT * FROM pairs WHERE watch_id=? AND record_id=? AND notified=1',
                        (watch.id, parent)).fetchone()
                    associated_rows = [r for r in advisory.rows_for(self.db, child)
                        if r['source'] == data['source'] and r['source_id'] == data['source_id']
                        and json.loads(r['provenance']).get('product_id') == association['product_id']
                        and advisory.scope_matches(r, getattr(self, 'evidence_scopes', {}).get(watch.id, {}),
                                                   getattr(self, 'scope_equivalences', ()))
                        and advisory.evaluate_row(r, watch, self.aliases) == State.AFFECTED]
                    if (old_parent and associated_rows and advisory.covered(self.db, watch.id, parent, 'new match', old_parent['episode'])
                            and self.route(child, watch) == 'advisory'
                            and self.advisory_result(watch, child).state == State.AFFECTED):
                        child_pair = self.db.execute('SELECT episode FROM pairs WHERE watch_id=? AND record_id=?',
                                                     (watch.id, child)).fetchone()
                        self.db.execute('INSERT OR IGNORE INTO coverage_inheritance VALUES (?,?,?,?,?)',
                                        (child, parent, watch.id, 'new match', child_pair[0] if child_pair else 1))
            for identity in sorted({advisory.canonical_id(self.db, i) for i in previous | set(advisory.identities(data))}):
                self._evaluate(self._record(identity), identity, baseline=baseline,
                               advisory_only=True)

    def _evaluate_advisory(self, record_id, *, record=None, **flags):
        # The caller has already partitioned watches. Use the same lifecycle
        # and policy machinery, with scoped aggregation and the affected latch.
        if 'watches' not in flags:
            flags['watches'] = tuple(w for w in self.watches if self.route(record_id, w) == 'advisory')
        if record is None:
            record = self._record(record_id)
        self._evaluate_pairs(record, record_id, advisory_path=True, **flags)

    def _urgent(self, body, reasons):
        if 'epss_crossed' in reasons:
            return True
        if not set(reasons) & {'new match', 'KEV added'}:
            return False
        return bool(body.get('kev') or (body['state'] == 'affected' and (
            body.get('ssvc', {}).get('Exploitation') == 'active' or
            (body.get('epss') and body['epss']['score'] >= self.config.epss_threshold))))

    def _event(self, watch_id, record_id, kind, episode, body, immediate=False, resolution=False, occurrence=None):
        canonical = advisory.canonical_id(self.db, record_id)
        if canonical != record_id:
            record_id = canonical
            body = dict(body, record_id=canonical)
        if occurrence is None and not resolution and self.db.execute('SELECT 1 FROM identity_redirects WHERE new_id=?', (record_id,)).fetchone() and advisory.covered(self.db, watch_id, record_id, kind, episode):
            return
        key = f'{watch_id}|{record_id}|{kind}|{episode}'
        if occurrence is not None:
            key += f'|{occurrence}'
        if resolution:
            key += '|resolution'
        added = self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
            (key, watch_id, record_id, kind, episode, self._now().isoformat())).rowcount
        if not added:
            return
        if watch_id and kind != 'correction':
            pending = self.db.execute('SELECT body_json FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                                      (f'{watch_id}|{record_id}',)).fetchone()
            previous = json.loads(pending[0]) if pending else {}
            # queue replaces the body when reasons coalesce. Keep the hold's audit
            # context until revalidation decides whether it is active or lapsed.
            body = dict(body)
            for field in ('accepted', 'acceptance_lapsed'):
                if field in previous:
                    body.setdefault(field, previous[field])
        urgency = ('health' if kind in ('healthy', 'unhealthy') else
                   'urgent' if kind != 'release_behind' and watch_id and self._urgent(body, [kind]) else 'normal')
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
                  kev_baseline=False, reload=False, watches=None, resolving_kev_only=False,
                  revision_corrections=False, advisory_only=False):
        record_id = advisory.canonical_id(self.db, record_id)
        selected = tuple(self.watches if watches is None else watches)
        has_adapters = advisory.has_routing_data(self.db, record_id)
        routes = {watch.id: self.route(record_id, watch) if has_adapters else 'v1'
                  for watch in selected}
        if advisory_only:
            selected = tuple(w for w in selected if routes[w.id] == 'advisory')
            if not selected:
                return
        flags = dict(baseline=baseline, kev_added=kev_added, kev_baseline=kev_baseline,
                     reload=reload, resolving_kev_only=resolving_kev_only,
                     revision_corrections=revision_corrections)
        if record is not None:
            problems = validate.record(record)
            if problems:
                raise ValueError('; '.join(problems))
            if not advisory_only:
                self.store.dirty_record(record_id)
        if advisory_only:
            # Adapter evidence changes only this route, including identities
            # without a CNA record. Preserve v1 pending rows and retry state.
            self.db.executemany("""UPDATE outbox SET dirty=1 WHERE sent_at IS NULL
                AND CAST(json_extract(body_json,'$.record_id') AS TEXT)=?
                AND CAST(json_extract(body_json,'$.watch_id') AS TEXT)=?""",
                ((record_id, watch.id) for watch in selected))
        v1 = tuple(w for w in selected if routes[w.id] == 'v1')
        advised = tuple(w for w in selected if routes[w.id] == 'advisory')
        if v1 and record is None and has_adapters:
            # Reload enumerates adapter-only identities too. Only a retained
            # v1 pair establishes that this identity should have a CNA record;
            # include unchanged watches when deciding missing-record health.
            owners = {r[0] for r in self.db.execute(
                'SELECT watch_id FROM pairs WHERE record_id=?', (record_id,))}
            if not any(w.id in owners and (routes[w.id] if w.id in routes
                           else self.route(record_id, w)) == 'v1'
                       for w in self.watches):
                v1 = ()
        if v1:
            self._evaluate_pairs(record, record_id, watches=v1, **flags)
        if advised:
            event_count = len(self.report.events)
            try:
                with self.store.transaction():
                    self._evaluate_advisory(record_id, record=record, watches=advised, **flags)
            except TransactionAborted:
                raise
            except Exception as error:
                del self.report.events[event_count:]
                if advisory_only:
                    # AdapterStore owns adapter retries; do not use CNA retries.
                    raise
                raise AdvisoryEvaluationFailed(f'{type(error).__name__}: {error}') from error
        if not advisory_only and (watches is None or {w.id for w in selected} == {w.id for w in self.watches}):
            # Only a full CNA evaluation completes matching-revision work.
            self.db.execute('DELETE FROM meta WHERE k=?', ('matching_revision_retry:' + record_id,))

    def _evaluate_pairs(self, record, record_id, baseline=False, kev_added=False,
                        kev_baseline=False, reload=False, watches=None, resolving_kev_only=False,
                        revision_corrections=False, advisory_path=False):
        if record is None and not advisory_path:
            self._health('records', 'unhealthy', 'Missing stored record: ' + record_id)
            return
        kev = self._json_row('kev', 'cve', record_id)
        if self._identity_version != (self.aliases, self.aliases.version):
            self._cache_watch_identities()
        identities = {}
        pairs = {row['watch_id']: row for row in self.db.execute(
            'SELECT * FROM pairs WHERE record_id=?', (record_id,))}
        for watch in self.watches if watches is None else watches:
            old = pairs.get(watch.id)
            sibling_only = False
            inherited = False
            latched = False
            if advisory_path:
                matching = self._advisory_matches(record_id, watch)
                advisory.remember(self.db, record_id, watch,
                    [(r['source'], r['source_id']) for r in matching])
                result = self.advisory_result(watch, record_id, record=record)
                cna = cnascope.scoped_verdicts(record, watch, self.aliases)
                sibling_only = (bool(matching) and not cna
                                and not any(r['identity'] == record_id for r in matching))
            elif applicability.rejected(record) and old:
                result = Result(State.NOT_AFFECTED, bool(kev), 'CNA record rejected', 'high')
            else:
                result = applicability.resolve(record, kev, watch, self.aliases,
                                                self._watch_identities[watch.id], identities)
            if result is None:
                if old is None:
                    continue
                result = Result(State.NOT_AFFECTED, False, 'Identity no longer matches watch', 'high')
            active = self._active(result.state.value, result.exploited) and not sibling_only
            was_active = old and self._active(old['state'], old['exploited'])
            if old:
                episode = old['episode']
            else:
                # A removed watch can be readded without discarding sent keys.
                episode = 1 + self.db.execute(
                    'SELECT coalesce(max(episode),0) FROM events WHERE watch_id=? AND record_id=?',
                    (watch.id, record_id)).fetchone()[0]
            notified = old['notified'] if old else 0
            if advisory_path:
                latched = advisory.logical_latch(self.db, old)
                inherited = self.db.execute("SELECT 1 FROM coverage_inheritance WHERE child_id=? AND watch_id=? AND reason='new match' AND episode=?",
                                            (record_id, watch.id, episode)).fetchone()
                notified = bool(notified or inherited)
            clearing = (latched if advisory_path else (was_active or notified)) and result.state == State.NOT_AFFECTED
            if clearing:
                episode += 1
            historical = old['baseline'] if old else int(baseline or kev_baseline)
            self.db.execute('''INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(watch_id,record_id) DO UPDATE SET state=excluded.state,
                episode=excluded.episode, exploited=excluded.exploited, evidence=excluded.evidence,
                confidence=excluded.confidence, notified=excluded.notified, alias_map_version=excluded.alias_map_version''',
                (watch.id, record_id, result.state.value, episode, historical,
                 int(result.exploited), 0 if clearing else notified, result.evidence, result.confidence, self.aliases.version))
            if advisory_path and (result.state == State.AFFECTED or (latched and not clearing)):
                self.db.execute('INSERT OR REPLACE INTO affected_latches VALUES (?,?,?,1)',
                                (watch.id, record_id, episode))
            if clearing:
                self.db.execute('DELETE FROM epss_crossings WHERE watch_id=? AND record_id=?',
                                (watch.id, record_id))
            self._initialize_epss_crossings(watch.id, record_id)
            if clearing or (old and active and old['state'] == 'not_affected'):
                self.db.execute('UPDATE epss_crossings SET fired=0 WHERE watch_id=? AND record_id=?',
                                (watch.id, record_id))
            body = self._body(watch, record_id, result, route='advisory' if advisory_path else 'v1')
            body['episode'] = episode
            # Evaluate rendering within the record savepoint, before creating events.
            render(Notification('', watch.id, record_id, (), 'normal', body))
            if clearing:
                self._drop_activation(watch.id, record_id)
                if notified and (not reload or revision_corrections):
                    self._event(watch.id, record_id, 'correction', episode - 1,
                                dict(body, episode=episode - 1) if advisory_path else body)
            elif resolving_kev_only and old and notified and old['state'] != result.state.value:
                self._event(watch.id, record_id, 'correction', episode, body, resolution=True)
            if active and not was_active and not advisory_path:
                self.db.execute('DELETE FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                                (f'{watch.id}|{record_id}|correction',))
            if active and (not notified if advisory_path else not was_active) and not baseline and not inherited and not (kev_baseline and historical):
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
        detail = validate.error_detail(redact_tokens(detail, self.config.ntfy_token, self.config.github_token, self.config.deadman_url, self.config.webhook_url, self.config.webhook_secret))
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

    def _isolated(self, source, record, action, *, key=None):
        count = len(self.report.events)
        key = key or self._retry_identity(record)[1]
        try:
            with self.store.transaction():
                try:
                    action()
                except AdvisoryEvaluationFailed as error:
                    # Catch inside the savepoint so completed v1 pairs/events
                    # survive. Leave completion markers for the full retry.
                    self._attempted_records.add((source, key))
                    self._retry(source, key, str(error))
                    return False
                for table in ('retry_queue', 'dead_letters'):
                    self.db.execute(f'DELETE FROM {table} WHERE source=? AND record_id=?', (source, key))
            return True
        except TransactionAborted:
            raise
        except Exception as error:
            if not self.db.in_transaction:
                raise TransactionAborted('transaction aborted') from error
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

    def _rematch_record(self, record, record_id, watches=None, *, revision_corrections=False):
        # Snapshot origin decides history; a first-KEV marker governs only KEV-added
        # events, so it must not turn a delta's new match into a baseline pair.
        baseline = (not self.store.get_meta('baseline_complete')
                    and bool(self.store.get_meta('record_baseline:' + record_id)))
        # Synthetic KEV-only contexts retain ingestion's historical policy.
        # A KEV marker on a stored CNA record does not make it a baseline match.
        kev_baseline = (bool(self.store.get_meta('kev_only:' + record_id))
                        and self.db.execute('SELECT 1 FROM records WHERE id=?',
                                            (record_id,)).fetchone() is None
                        and bool(self.store.get_meta('kev_baseline:' + record_id)))
        retry_key = 'matching_revision_retry:' + record_id
        if self.store.get_meta(retry_key):
            # A pending revision pass must cover all watches even if another
            # reload edits only a subset before the retry runs.
            watches = None
            revision_corrections = True
        self._evaluate(record, record_id, reload=True, watches=watches, baseline=baseline,
                       kev_baseline=kev_baseline,
                       revision_corrections=revision_corrections)

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
            if record is None and not advisory.has_routing_data(self.db, record_id):
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
                self._isolated(source, record, apply, key=record_id)
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
        error = (redact_tokens(type(detail).__name__, self.config.ntfy_token, self.config.github_token, self.config.deadman_url, self.config.webhook_url, self.config.webhook_secret)
                 if isinstance(detail, Exception) else None)
        detail = safe_message(detail if error else RuntimeError(detail), self.config.ntfy_token, self.config.github_token, self.config.deadman_url, self.config.webhook_url, self.config.webhook_secret)
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
            self.store.set_meta('last_error:' + source, validate.error_detail(redact_tokens('; '.join(ingest.errors), self.config.ntfy_token, self.config.github_token, self.config.deadman_url, self.config.webhook_url, self.config.webhook_secret)))
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
                        self.store.set_meta('last_error:' + source, validate.error_detail(redact_tokens('; '.join(problems), self.config.ntfy_token, self.config.github_token, self.config.deadman_url, self.config.webhook_url, self.config.webhook_secret)))
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
                    if record is None and not any(self.route(record_id, w) == 'advisory' for w in self.watches):
                        if self.db.execute('SELECT 1 FROM pairs WHERE record_id=?', (record_id,)).fetchone():
                            self._isolated(source, None, lambda: self._evaluate(None, record_id), key=record_id)
                        continue
                    if not self._isolated(source, record,
                            lambda record=record, record_id=record_id: self._evaluate_kev(record, record_id), key=record_id):
                        complete = False
            elif source == 'epss' and payload is not None:
                self._initialize_epss_crossings()
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
                    self.db.execute('DELETE FROM epss_crossing_scores')
                    self.db.execute('INSERT INTO epss_crossing_scores SELECT * FROM epss')
                    self._epss_crossings()
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
                        'Empty complete map' if empty_failure else (
                            '; '.join(ingest.errors) if validate.error_detail('; '.join(ingest.errors))
                            else 'Ingest ' + ingest.status.value))
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

    def reload_watches(self, watches: tuple[Watch, ...], *, force_all=False, previous_ids=None) -> None:
        old_watches = self.watches
        previous = {watch.id: watch for watch in self.watches}
        # An older database may retain only the owners, not watch definitions.
        previous_ids = set(previous) if previous_ids is None else previous_ids
        alias_changed = self._identity_version != (self.aliases, self.aliases.version)
        def matching_fields(watch):
            if watch is None:
                return None
            # Preserve existing reload behavior for CVE configuration and labels.
            return (watch.name, watch.match, watch.product_only, watch.version, watch.scheme, watch.eol, watch.github, watch.platform)
        changed = tuple(watch for watch in watches if force_all or alias_changed
                        or matching_fields(previous.get(watch.id)) != matching_fields(watch))
        self.watches = watches
        self._cache_watch_identities()
        last_report = self.report
        self.report = self._pending_report
        completed = False
        try:
            with self.store.transaction():
                # Re-matching is transactional; only run_cycle releases queued work.
                # Initial-catalog KEV rows wait for CNA records; only explicitly
                # eligible KEV-only rows have a synthetic evaluation context.
                ids = self.db.execute("""SELECT id FROM records
                    UNION SELECT record_id FROM pairs
                    UNION SELECT identity FROM advisory_evidence
                    UNION SELECT cve FROM kev WHERE EXISTS (
                        SELECT 1 FROM meta WHERE k='kev_only:' || kev.cve)
                    """).fetchall() if changed else ()
                for row in ids:
                    record_id = row[0]
                    record = self._record(record_id)
                    if force_all:
                        # Outside the record savepoint: failures keep correction policy
                        # for watchlist retries, including across process restarts.
                        self.store.set_meta('matching_revision_retry:' + record_id, '1')
                    self._isolated('watchlist', record,
                        lambda record=record, record_id=record_id: self._rematch_record(
                            record, record_id, watches=changed, revision_corrections=force_all), key=record_id)
                pending = self.db.execute("SELECT 1 FROM retry_queue WHERE source='watchlist' UNION ALL SELECT 1 FROM dead_letters WHERE source='watchlist' LIMIT 1").fetchone()
                self._health('watchlist', 'unhealthy' if pending else 'healthy',
                             'Re-match failed; retry pending' if pending else 'Watchlist re-match complete',
                             'incomplete' if pending else 'recovered')
                active_ids = {watch.id for watch in watches}
                for watch_id in previous_ids - active_ids:
                    for pair in self.db.execute('SELECT record_id FROM pairs WHERE watch_id=?', (watch_id,)).fetchall():
                        self._drop_activation(watch_id, pair['record_id'])
                        key = 'advisory_history:' + json.dumps([watch_id, pair['record_id']], separators=(',', ':'))
                        self.db.execute('DELETE FROM meta WHERE k=?', (key,))
                    self.db.execute('DELETE FROM pairs WHERE watch_id=?', (watch_id,))
                    self.db.execute('DELETE FROM affected_latches WHERE watch_id=?', (watch_id,))
                    self.db.execute('DELETE FROM epss_crossings WHERE watch_id=?', (watch_id,))
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
            completed = True
        finally:
            # Restore only in-memory state while every failure propagates unchanged.
            # The report is restored even if rebuilding the identity cache fails.
            try:
                if not completed:
                    self.watches = old_watches
                    self._cache_watch_identities()
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
        if body.get('release_behind'):
            from cornicen.releases import release_behind
            watch = next((w for w in self.watches if w.id == body['watch_id']), None)
            if (watch is None or not watch.latest_release
                    or watch.latest_release.lower() != body.get('repository', '').lower()
                    or not release_behind(watch, body['tag'])):
                if persist:
                    self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
                return None
            body.update(name=watch.name, version=watch.version)
            if persist:
                self.db.execute('UPDATE outbox SET body_json=? WHERE id=?',
                                (json.dumps(body), row['id']))
            return dict(row, body_json=json.dumps(body), urgency='normal')
        watch = next((w for w in self.watches if w.id == body['watch_id']), None)
        route = self.route(body['record_id'], watch) if watch else 'v1'
        pair = self.db.execute('SELECT * FROM pairs WHERE watch_id=? AND record_id=?',
                               (body['watch_id'], body['record_id'])).fetchone()
        reasons = json.loads(row['reasons_json'])
        if route == 'advisory':
            result = self.advisory_result(watch, body['record_id'])
            matching = self._advisory_matches(body['record_id'], watch)
            cna = cnascope.scoped_verdicts(self._record(body['record_id']), watch, self.aliases)
            sibling_only = (bool(matching) and not cna
                            and not any(r['identity'] == body['record_id'] for r in matching))
            valid = pair and (result.state == State.NOT_AFFECTED if reasons == ['correction']
                              else self._active(result.state.value, result.exploited) and not sibling_only)
            if not valid:
                if persist:
                    if not pair or not pair['notified']:
                        self._drop_activation(body['watch_id'], body['record_id'])
                    self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
                return None
            pair = dict(pair, state=result.state.value, exploited=int(result.exploited))
        else:
            if self._record(body['record_id']) is None:
                if persist:
                    self._health('records', 'unhealthy', 'Missing stored record: ' + body['record_id'])
                return None
            if not watch or not pair or ('correction' not in reasons and not self._active(pair['state'], pair['exploited'])):
                if persist:
                    self._drop_activation(body['watch_id'], body['record_id'])
                    self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
                return None
            result = Result(State(pair['state']), bool(pair['exploited']), pair['evidence'], pair['confidence'])
        if reasons == ['correction']:
            # Keep the closing episode, including a correction awaiting retry.
            return row
        previous_body = body
        episode = body.get('episode', pair['episode'])
        body = self._body(watch, body['record_id'], result, route=route)
        body['episode'] = episode
        urgency = 'urgent' if self._urgent(body, reasons) else 'normal'
        due = row['due_at']
        next_attempt = row['next_attempt_at']
        if urgency != row['urgency']:
            due = self._now().isoformat() if urgency == 'urgent' else self._digest()
        entry = next((a for a in self.accepts
                      if a.watch.casefold() == watch.id.casefold() and a.cve == body['record_id']), None)
        current = accept.state(entry, {w.id: w for w in self.watches}, self._now(),
                               self.config.timezone) if entry else None
        if 'epss_crossed' in reasons and (current == 'active' or not self.config.epss_crossing
                or pair['state'] != 'affected' or body['kev'] is not None
                or body['ssvc'].get('Exploitation') == 'active'):
            reasons.remove('epss_crossed')
            if not reasons:
                if persist:
                    self.db.execute('DELETE FROM outbox WHERE id=?', (row['id'],))
                return None
            urgency = 'urgent' if self._urgent(body, reasons) else 'normal'
            due = self._now().isoformat() if urgency == 'urgent' else self._digest()
        if current == 'active':
            held = (set(reasons) <= {'new match', 'acceptance lapsed'}
                    and not body.get('kev') and not pair['exploited'])
            body['accepted'] = dict(accept.detail(entry), held=held)
            if held:
                urgency, due = 'normal', self._digest()
                next_attempt = None
        elif previous_body.get('accepted', {}).get('held'):
            body['acceptance_lapsed'] = dict(previous_body['accepted'], why=accept.lapse_reason(current))
            body['acceptance_lapsed'].pop('held', None)
            if persist and current is None:
                if 'acceptance lapsed' not in reasons:
                    reasons.append('acceptance lapsed')
                key = f"{watch.id}|{body['record_id']}|acceptance lapsed|{episode}"
                self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                    (key, watch.id, body['record_id'], 'acceptance lapsed', episode, self._now().isoformat()))
        elif 'acceptance_lapsed' in previous_body:
            body['acceptance_lapsed'] = previous_body['acceptance_lapsed']
        if not persist:
            return dict(row, body_json=json.dumps(body), urgency=urgency, due_at=due,
                        next_attempt_at=next_attempt)
        self.db.execute('UPDATE outbox SET body_json=?,urgency=?,due_at=?,next_attempt_at=?,reasons_json=? WHERE id=?',
                        (json.dumps(body), urgency, due, next_attempt, json.dumps(reasons), row['id']))
        return self.db.execute('SELECT * FROM outbox WHERE id=?', (row['id'],)).fetchone()

    def _acceptance_lapses(self):
        watches = {watch.id: watch for watch in self.watches}
        for entry in self.accepts:
            current = accept.state(entry, watches, self._now(), self.config.timezone)
            if current not in {'lapsed-date', 'lapsed-version'}:
                continue
            watch = next(w for w in self.watches if w.id.casefold() == entry.watch.casefold())
            pair = self.db.execute('SELECT * FROM pairs WHERE watch_id=? AND record_id=?',
                                   (watch.id, entry.cve)).fetchone()
            if not pair or not self._active(pair['state'], pair['exploited']):
                continue
            result = Result(State(pair['state']), bool(pair['exploited']), pair['evidence'], pair['confidence'])
            body = self._body(watch, entry.cve, result)
            body['episode'] = pair['episode']
            pending = self.db.execute('SELECT body_json FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                                      (f'{watch.id}|{entry.cve}',)).fetchone()
            held = json.loads(pending[0]).get('accepted', {}) if pending else {}
            original = {key: held[key] for key in ('reason', 'until', 'version')} if held.get('held') else accept.detail(entry)
            body['acceptance_lapsed'] = dict(original, why=accept.lapse_reason(current))
            self._event(watch.id, entry.cve, 'acceptance lapsed', pair['episode'], body)

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

    def run_cycle(self, ingests: Sequence[IngestResult], *, release_checks=True) -> CycleReport:
        self.report = self._pending_report
        self._pending_report = CycleReport()
        self._health_verdicts = {}
        self._attempted_records = set()
        order = {'cvelist': 0, 'kev': 1, 'epss': 2}
        for ingest in (i for i in ingests if i.source == 'cvelist'):
            with self.store.transaction():
                self._ingest(ingest)
        self.dispatch_adapters()
        for ingest in sorted((i for i in ingests if i.source != 'cvelist'), key=lambda i: order[i.source]):
            with self.store.transaction():
                self._ingest(ingest)
        self._retry_records()
        with self.store.transaction():
            self._finish_health()
            self.store.prune_records(self._now(), self.config.retention_days,
                                     keep=self.acceptance_holds)
            if not self.store.get_meta('baseline_complete') and all(
                    self.store.get_meta('complete:' + source) for source in order):
                self.store.set_meta('baseline_complete', '1')
                count = self.db.execute("SELECT count(*) FROM pairs WHERE baseline=1 AND (state='affected' OR (state='unknown' AND exploited=1))").fetchone()[0]
                exploited = self.db.execute("SELECT count(*) FROM pairs WHERE baseline=1 AND exploited=1 AND state!='not_affected'").fetchone()[0]
                self._event('', 'baseline', 'baseline', 1,
                            {'record_id': 'baseline', 'detail': f'baseline: {count} historical matches, {exploited} exploited — run `cornicen report`'}, True)
        with self.store.transaction():
            self._acceptance_lapses()
        if not release_checks:
            self._flush()
            return self.report
        self._flush()
        if self.release_checker is not None:
            self.release_checker.check(self)
        return self.report

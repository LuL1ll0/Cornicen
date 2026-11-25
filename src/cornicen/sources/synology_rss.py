"""Fetch the whole Synology security feed and check accepted coverage."""

from collections import Counter
from datetime import timedelta
from http.client import HTTPException, IncompleteRead
import json

from cornicen import feeddates, synology
from cornicen.adapterstore import AdapterStore, canonical, instant, stamp
from cornicen.diagnostics import FixedDiagnostic
from cornicen.public_text import UNRECOGNISED_SUBJECT, UNRECOGNISED_TEMPLATE


SOURCE = 'synology'
RESOURCE = 'feed'
URL = 'https://www.synology.com/api/rssfeed/security/en-us'
SYNOLOGY_RETENTION_HOURS = None
_PENDING = 'poll pending'
_DIAGNOSTIC_LABELS = (UNRECOGNISED_SUBJECT, UNRECOGNISED_TEMPLATE)


class _SkipBody(Exception):
    """Stop the response hook after reading a non-200 status and headers."""


class SynologyState:
    """Persist parse observations and read the store's poll state."""

    def __init__(self, store):
        self.store = store
        self.db = store.connection

    def observe_build(self, last_build, diagnostics):
        with self.store.transaction():
            self.store.set_meta('synology:last_build', canonical(last_build))
            self.store.set_meta('synology:diagnostics', canonical(
                {label: diagnostics[label] for label in _DIAGNOSTIC_LABELS}))

    def retention(self):
        return json.loads(self.store.get_meta('retention:synology') or '{}')

    def coverage_detail(self, retention_hours):
        if not self.retention().get('accepted'):
            return 'coverage unknown (pre-baseline)'
        if retention_hours is None:
            return 'coverage unknown (no retention contract)'
        return ''

    def status_details(self):
        details = [self.coverage_detail(SYNOLOGY_RETENTION_HOURS)]
        encoded = self.store.get_meta('synology:diagnostics')
        if encoded is not None:
            counts = json.loads(encoded)
            if isinstance(counts, dict) and all(type(counts.get(label)) is int and counts[label] >= 0
                                                for label in _DIAGNOSTIC_LABELS):
                details.append(', '.join(f'{counts[label]} {label}' for label in _DIAGNOSTIC_LABELS))
        return [detail for detail in details if detail]

    def withdrawn(self):
        return {row[0] for row in self.db.execute(
            "SELECT source_id FROM advisories WHERE source=? AND state='withdrawn'", (SOURCE,))}

    def due(self, now, interval):
        retries = self.db.execute("SELECT next_attempt_at FROM adapter_retries WHERE source=? "
                                  "AND resource IN (?, '@dispatch')", (SOURCE, RESOURCE)).fetchall()
        if retries:
            return all(instant(row[0]) <= now for row in retries)
        row = self.db.execute('SELECT cursor_tick FROM adapter_state WHERE source=?', (SOURCE,)).fetchone()
        # The minute cycle dispatches more often than interval_hours, so an early
        # skip has another chance to fetch. Pinned by test_hourly_dispatch_cadence.
        if row is None or not row[0] or now - instant(row[0]) >= interval:
            return True
        health = {name: (state, detail) for name, state, detail in self.db.execute(
            'SELECT dimension,state,detail FROM source_health WHERE source=?', (SOURCE,))}
        return (len(health) != 4 or health['fetch'][0] != 'healthy'
                or health['completeness'][0] != 'healthy' or health['freshness'] != ('n/a', ''))


class SynologyRss:
    def __init__(self, http, state, clock, *, retention_hours=None, interval_hours=24):
        if not interval_hours > 0 or (retention_hours is not None and (
                not 48 <= retention_hours <= 87_600 or not interval_hours <= retention_hours / 2)):
            raise ValueError(FixedDiagnostic('invalid Synology retention or interval'))
        self.http, self.state, self.clock = http, state, clock
        self.retention_hours = retention_hours
        self.interval = timedelta(hours=interval_hours)
        self.skipped = False

    @property
    def coverage_detail(self):
        return self.state.coverage_detail(self.retention_hours)

    def required_resources(self):
        return (RESOURCE,)

    def retry(self, resource):
        return []

    def audit(self, resource):
        return []

    @staticmethod
    def validate_hop(url):
        if url != URL:
            raise ValueError(FixedDiagnostic('invalid Synology destination'))

    def _fetch(self, url):
        outcome = dict(path=RESOURCE, unconditional=True)

        def on_response(host, status, headers):
            outcome.update(status=status, headers=headers)
            if status in (301, 302, 303, 307, 308):
                raise ValueError(FixedDiagnostic('Synology RSS redirect refused'))
            if status != 200:
                raise _SkipBody

        try:
            self.validate_hop(url)
            response = self.http.get(url, source=SOURCE, on_response=on_response)
        except _SkipBody:
            if 200 <= outcome['status'] < 300:
                outcome.update(invalid_envelope=True, invalid_status=True)
            return outcome, None
        except (EOFError, IncompleteRead):
            if outcome.get('status') == 200:
                # An empty object has no member stream for the store to stage.
                return dict(outcome, transfer_complete=False, body='{}'), None
            return dict(outcome, status=0, transport_error=True), None
        except (OSError, ValueError, HTTPException) as error:
            if outcome.get('status') == 200 and str(error) == 'HTTP response body size limit exceeded':
                return dict(outcome, invalid_envelope=True), None
            return dict(path=RESOURCE, unconditional=True, status=0, transport_error=True), None
        length = response.headers.get('content-length')
        if length is not None:
            try:
                intact = int(length) == len(response.body)
            except ValueError:
                intact = False
            if not intact:
                return dict(outcome, transfer_complete=False, body='{}'), None
        return outcome, response.body

    def _summarise(self, items, members, tick, prior, gap):
        withdrawn = self.state.withdrawn()
        ids, dates = set(), {}
        decidable = True
        for item, member in zip(items, members):
            identity = member['id']
            try:
                # Mapping may reject other fields while the ID and date are usable.
                published = member.get('published') or feeddates.rfc822(item.get('pubDate')).utc()
            except (ValueError, OverflowError):
                published = None
            if identity not in withdrawn and (not identity or published is None):
                decidable = False
            if identity:
                # A current member can reactivate a tombstone. The commit hook
                # filters only IDs that are still withdrawn after the write.
                ids.add(identity)
                if published is not None:
                    dates.setdefault(published, set()).add(identity)
        oldest, newest = (min(dates), max(dates)) if dates else (None, None)
        if prior.get('accepted') and decidable:
            boundary = set(prior['boundary']) - withdrawn
            active_ids = ids - withdrawn
            if set(prior['ids']) - withdrawn - active_ids:
                gap('member lost')
            if boundary and not boundary & active_ids:
                gap('retention boundary lost')
            active_oldest = min((date for date, support in dates.items() if support - withdrawn), default=None)
            if prior['oldest'] and boundary and active_oldest:
                try:
                    moved = feeddates.rfc3339(active_oldest) > feeddates.rfc3339(prior['oldest'])
                except ValueError:
                    moved = False  # An older store may have accepted an invalid summary.
                if moved:
                    gap('retention watermark moved')
        return dict(ids=sorted(ids), boundary=sorted(dates.get(oldest, ())),
                    newest_ids=sorted(dates.get(newest, ())),
                    oldest=oldest, newest=newest, observed_at=tick)

    def poll(self, *, cutoff=None):
        now = self.clock()
        if isinstance(now, str):
            now = instant(now)
        self.skipped = not self.state.due(now, self.interval)
        if self.skipped:
            return []
        tick = stamp(now)
        persistence = AdapterStore(self.state.store, self.http.data_dir)
        # Freshness is the last dimension process() writes. Preserve its n/a
        # state while making even a later poll's unfinished health detectable.
        persistence.dimension(SOURCE, 'freshness', 'n/a', tick, _PENDING)
        prior = self.state.retention()

        def gap(reason):
            persistence.gap(SOURCE, tick, reason)

        if prior.get('accepted') and self.retention_hours is not None:
            try:
                observed = feeddates.rfc3339(prior['observed_at'])
            except ValueError:
                observed = None
            if observed is not None:
                cutoff_stamp = stamp(now - timedelta(hours=self.retention_hours))
                if feeddates.rfc3339(cutoff_stamp) > observed:
                    gap('observation interval exceeded')
        outcome, body = self._fetch(URL)
        if body is None:
            return [outcome]
        try:
            items, channel = synology.parse_feed(body)
        except ValueError:
            return [dict(outcome, invalid_envelope=True)]
        diagnostics = Counter()
        members = synology.normalise_items(items, diagnostics)
        self.state.observe_build(channel['lastBuildDate'], diagnostics)
        retention = self._summarise(items, members, tick, prior, gap)
        return [dict(outcome, body=canonical(dict(advisories=members)), retention=retention)]

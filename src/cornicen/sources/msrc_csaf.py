# script-purpose: Poll Microsoft CSAF within durable budgets and stream cached advisory members.
# script-class: pipeline-tool
# script-trigger: Offline Microsoft CSAF adapter state operations.
# script-tests: tests/test_task2_b1.py, tests/test_task2_b2.py
"""Read CSV and invented adapter results; write SQLite meta rows through MsrcState.

Library API with no process exit codes; invalid listings raise ValueError.
MsrcCsaf polls the publisher only when constructed by an effective factory.
"""
import csv
from datetime import timedelta
from hashlib import sha256
from io import StringIO
import json
import random
import re
import uuid

from cornicen.adapterstore import AdapterStore, canonical, instant, stamp
from cornicen.feeddates import rfc3339
from cornicen.feedvalidate import safe_path, source_id

from http.client import HTTPException
from pathlib import Path
import tempfile
from urllib.error import URLError
from urllib.parse import urlsplit

from cornicen.adapterstore import bounded_wait, digest
from cornicen.csaf import normalise
from cornicen.feedvalidate import decode_json
from cornicen.fetch import _destination


def parse_listing(body):
    """Return (case-sensitive path -> sorted canonical instants, invalid rows).

    A nonempty CSV with delimited rows is required. A fully valid empty
    inventory cannot be inferred from a blank transfer. No watch data is read.
    """
    try:
        text = body.decode('utf-8') if isinstance(body, bytes) else body
        if not isinstance(text, str) or not text.strip() or text.lstrip().startswith('<'):
            raise ValueError('invalid listing')
        listing, invalid, csv_rows = {}, 0, 0
        for row in csv.reader(StringIO(text, newline=''), strict=True):
            if len(row) >= 2:
                csv_rows += 1
            try:
                if len(row) != 2 or not re.fullmatch(r'[0-9]{4}/[A-Za-z0-9_.-]+\.json', row[0]):
                    raise ValueError('invalid listing row')
                path = safe_path(row[0])
                date = rfc3339(row[1])
                # Canonicalise equal instants, including redundant zero fractions.
                date = type(date)(date.raw, date.seconds, date.fraction.rstrip('0'))
                listing.setdefault(path, set()).add(date)
            except ValueError:
                invalid += 1
        if not csv_rows:
            raise ValueError('invalid listing')
        return {path: [date.utc() for date in sorted(dates)] for path, dates in sorted(listing.items())}, invalid
    except (UnicodeError, csv.Error) as error:
        raise ValueError('invalid listing') from error


class MsrcState:
    """Durable cache and accounting; each public write owns one transaction.

    Per-path rows use meta keys msrc:path:<listing path>. iter_paths and
    iter_cache stream SQLite in listing-path order, one decoded row at a time.
    A success means an intact unconditional HTTP 200, even if mapping failed.
    Cached members contain no fetch-time fields. Bootstrap pins survive release
    of the summary hold. Callers release it only after their resolution barrier.
    """
    def __init__(self, store, *, rng=None):
        self.store = store
        self.adapter_store = AdapterStore(store, '.', rng=rng)
        self.rng = rng if rng is not None else random.Random()

    def meta(self, key, default=None):
        value = self.store.get_meta('msrc:' + key)
        return json.loads(value) if value is not None else default

    def _put(self, key, value):
        self.store.set_meta('msrc:' + key, canonical(value))

    def path(self, path):
        return self.meta('path:' + safe_path(path))

    def iter_paths(self, *, listed=True):
        query = "SELECT v FROM meta WHERE k >= 'msrc:path:' AND k < 'msrc:path;'"
        if listed:
            query += " AND json_extract(v, '$.listed')=1"
        for row in self.store.connection.execute(query + ' ORDER BY k COLLATE BINARY'):
            yield json.loads(row[0])

    def iter_cache(self, *, listed=True):
        for row in self.iter_paths(listed=listed):
            if row.get('member') is not None:
                yield row

    def observe_listing(self, listing, invalid_rows, tick):
        """Pin bootstrap once; invalid rows admit paths but never remove any."""
        with self.store.transaction():
            if self.meta('bootstrap') is None and not invalid_rows and listing:
                self._put('bootstrap', sorted(listing))
                self.adapter_store.set_baseline_hold('msrc', tick)
            if not invalid_rows:
                for row in self.iter_paths():
                    if row['path'] not in listing:
                        row.update(listed=False, vanished=True, episode=row['episode'] + 1)
                        reason = 'inventory removal #' + sha256(row['path'].encode()).hexdigest()[:12] + ' e' + str(row['episode'])
                        self.adapter_store.gap('msrc', tick, reason)
                        self._put('path:' + row['path'], row)
            for path, timestamps in listing.items():
                safe_path(path)
                row = self.path(path) or dict(path=path, first_seen=tick, audit_anchor=tick,
                    timestamps=[], last_success=None, member=None, raw_digest=None,
                    attempts=0, next_attempt=None, failure=None, attempted=False, episode=0)
                row.update(listed=True, vanished=False, listed_timestamps=list(timestamps))
                self._put('path:' + path, row)

    def record_success(self, path, timestamps, member, tick, *, raw_digest=None):
        """Atomically clear failure, replace cache, reset audit and pin late IDs."""
        with self.store.transaction():
            row = self.path(path)
            if row is None:
                raise ValueError('unlisted path')
            row.update(timestamps=list(timestamps), member=member, raw_digest=raw_digest,
                       last_success=tick, audit_anchor=tick, attempts=0,
                       next_attempt=None, failure=None, attempted=True,
                       container_generation=None, staged_generation=None, committed_generation=None)
            bootstrap = self.store.get_meta('msrc:bootstrap') or '[]'
            if self.store.connection.execute('SELECT 1 FROM json_each(?) WHERE value=?', (bootstrap,path)).fetchone() and isinstance(member, dict):
                identity = member.get('id')
                try:
                    source_id(identity)
                except ValueError:
                    pass
                else:
                    self.adapter_store.pin_baseline_member('msrc', identity, tick)
            self._put('path:' + path, row)

    def record_failure(self, path, tick, *, http_error=False, retry_after=None, intact_transfer=False):
        """Keep cache and persist backoff; intact transfers reset only audit clocks."""
        with self.store.transaction():
            row = self.path(path)
            if row is None:
                raise ValueError('unlisted path')
            attempts = row['attempts'] + 1
            wait = min(60 * 2**min(attempts - 1, 20), 21600) * self.rng.uniform(.8, 1.2)
            if retry_after is not None:
                wait = max(wait, retry_after)
            row.update(attempts=attempts, next_attempt=stamp(instant(tick) + timedelta(seconds=wait)),
                       failure='http' if http_error else 'other', attempted=True)
            if intact_transfer:
                row.update(last_success=tick, audit_anchor=tick)
            self._put('path:' + path, row)

    def release_if_resolved(self, tick):
        """Release only after every bootstrap path has a durable store result."""
        bootstrap = self.meta('bootstrap')
        if bootstrap is None:
            return
        for path in bootstrap:
            row = self.path(path)
            if row is None:
                return
            if not row['listed']:
                continue
            member = row.get('member')
            if member is None:
                return
            generation = row.get('container_generation')
            if (generation is None or row.get('staged_generation') != generation
                    or row.get('committed_generation') != generation):
                return
            identity = row['resolution_key']
            if not self.store.connection.execute(
                'SELECT 1 FROM advisories WHERE source=? AND source_id=? UNION ALL '
                'SELECT 1 FROM quarantine WHERE source=? AND source_id=?',
                ('msrc', identity, 'msrc', identity)).fetchone():
                return
        self.adapter_store.release_baseline_hold('msrc', tick)

    def stage_generation(self, generation):
        """Record path participation in the transaction that installs its stage."""
        for row in self.iter_cache():
            if row.get('container_generation') == generation:
                row['staged_generation'] = generation
                self._put('path:' + row['path'], row)

    def commit_generation(self, generation):
        """Receipt only paths represented by this fully processed generation."""
        with self.store.transaction():
            for row in self.iter_cache():
                if (row.get('container_generation') == generation
                        and row.get('staged_generation') == generation):
                    row['committed_generation'] = generation
                    self._put('path:' + row['path'], row)

    def charge(self, tick):
        with self.store.transaction():
            requests = [r for r in self.meta('requests', []) if (instant(tick)-instant(r)).total_seconds() < 3600]
            requests.append(tick)
            self._put('requests', requests)

    def set_hold(self, until):
        with self.store.transaction():
            self._put('rate_hold_until', until)

    def set_metadata(self, document, tick):
        with self.store.transaction():
            self._put('metadata', dict(document=document, fetched_at=tick))


# ponytail: Local ceilings include metadata, listings and redirect hops; shared
# publisher capacity must be measured before gate M can be met.
CYCLE_LIMIT, HOUR_LIMIT = 200, 400
DIRECTORY = 'https://msrc.microsoft.com/csaf/advisories/'
METADATA_URL = 'https://msrc.microsoft.com/csaf/provider-metadata.json'
RESOURCE = 'msrc/advisories'



class MsrcCsaf:
    """Download the complete listing independently of watches; stream cached members.

    Reads scripted or publisher HTTP, writes only through MsrcState and a fresh
    JSONL file under data_dir. AdapterStore owns and deletes the returned file.
    Library API with no exit codes. retry/audit work is scheduled by poll.
    """
    def __init__(self, http, state, clock, *, data_dir=None):
        self.http, self.state, self.clock = http, state, clock
        self.data_dir = Path(data_dir if data_dir is not None else http.data_dir)

    def required_resources(self):
        return (RESOURCE,)

    def retry(self, resource):
        return ()

    def audit(self, resource):
        return ()

    def _remaining(self):
        requests = self.state.meta('requests', [])
        hourly = sum(0 <= (self.now-instant(t)).total_seconds() < 3600 for t in requests)
        return min(CYCLE_LIMIT-self.spent, HOUR_LIMIT-hourly)

    def _get(self, url):
        def validate_hop(hop):
            _destination(hop, 'msrc_csaf')
            parsed = urlsplit(hop)
            path = parsed.path
            if parsed.query or parsed.fragment or '?' in hop or '#' in hop:
                raise ValueError('foreign endpoint')
            if path not in ('/csaf/provider-metadata.json', '/csaf/advisories/changes.csv'):
                prefix = '/csaf/advisories/'
                relative = path.removeprefix(prefix)
                if not path.startswith(prefix) or not re.fullmatch(r'[0-9]{4}/[A-Za-z0-9_.-]+\.json', relative):
                    raise ValueError('foreign endpoint')
                safe_path(relative)
            if self._remaining() <= 0:
                raise ValueError('rate budget')
            self.state.charge(self.tick)
            self.spent += 1
        response = self.http.get(url, source='msrc_csaf', validate_hop=validate_hop)
        if response.status in (403, 429):
            wait = bounded_wait(response.headers, self.now)
            if wait is None:
                wait = 60 * self.state.rng.uniform(.8, 1.2)
            self.state.set_hold(stamp(self.now + timedelta(seconds=wait)))
        return response

    def _envelope(self, url, parse):
        response = None
        try:
            response = self._get(url)
            if response.status != 200:
                raise ValueError('invalid envelope')
            return parse(response.body), None
        except (URLError, OSError, EOFError, HTTPException):
            return None, dict(path=RESOURCE, status=0, transport_error=True)
        except (ValueError, TypeError, KeyError, AttributeError):
            status = response.status if response is not None else 0
            return None, dict(path=RESOURCE, status=status, invalid_envelope=True,
                              rate_limited=status in (403, 429))

    @staticmethod
    def _metadata(body):
        document = decode_json(body)
        directories = [d.get('directory_url') for d in document['distributions']]
        if sum(isinstance(d, str) and d.rstrip('/') == DIRECTORY.rstrip('/') for d in directories) != 1:
            raise ValueError('missing advisories distribution')
        return document

    def _fetch_record(self, row):
        path = row['path']
        try:
            response = self._get(DIRECTORY + path)
            if response.status != 200:
                wait = bounded_wait(response.headers, self.now)
                self.state.record_failure(path, self.tick, http_error=True, retry_after=wait)
                if response.status in (403, 429) and wait is None:
                    self.state.set_hold(self.state.path(path)['next_attempt'])
                return response.status in (403, 429)
            try:
                document = decode_json(response.body)
                member = normalise(document, path=path, directory_url=DIRECTORY)
                raw_digest = digest(document)
            except (ValueError, TypeError):
                member, raw_digest = dict(id=None, mapping_error='invalid JSON'), None
            if 'mapping_error' in member:
                cached = row.get('member') or {}
                member = dict(id=member.get('id') if member.get('id') is not None else cached.get('id'),
                              mapping_error='invalid CSAF document')
            self.state.record_success(path, row['listed_timestamps'], member, self.tick, raw_digest=raw_digest)
        except (URLError, OSError, EOFError, HTTPException, ValueError):
            self.state.record_failure(path, self.tick)
        return False

    def _container(self, invalid):
        bootstrap = self.state.meta('bootstrap')
        if bootstrap is None:
            return dict(path=RESOURCE, unenumerated=True, reason='bootstrap backlog')
        bootstrap = set(bootstrap)
        first = self.state.store.get_meta('baseline_pinned:msrc:' + RESOURCE) is None
        if first and any(not row['attempted'] and row['listed'] for path in bootstrap
                         if (row := self.state.path(path)) is not None):
            return dict(path=RESOURCE, unenumerated=True, reason='bootstrap backlog')
        complete = not invalid
        owners = {}
        for row in self.state.iter_paths():
            if row.get('member') is None or row['timestamps'] != row['listed_timestamps'] or row['failure']:
                complete = False
            if first and row['path'] not in bootstrap: continue
            member = row.get('member')
            if member is None: continue
            identity = member.get('id')
            if identity is None: continue
            previous = owners.get(identity)
            if previous is None:
                owners[identity] = [row['raw_digest'], row['path'], False]
            elif previous[0] != row['raw_digest']:
                previous[2] = True
        self.data_dir.mkdir(parents=True, exist_ok=True)
        stream = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.data_dir,
                                             prefix='msrc-members-', suffix='.jsonl', delete=False)
        self._pending_members_file = Path(stream.name)
        try:
            with stream:
                for row in self.state.iter_cache():
                    if first and row['path'] not in bootstrap: continue
                    member = row['member']; identity = member.get('id')
                    if identity is not None:
                        owner = owners[identity]
                        if row['path'] != owner[1]: continue
                        if owner[2]: member = dict(id=identity, mapping_error='path conflict')
                    stream.write(canonical(member) + '\n')
            generation = uuid.uuid4().hex
            with self.state.store.transaction():
                for row in self.state.iter_cache():
                    if first and row['path'] not in bootstrap: continue
                    member = row['member']; identity = member.get('id')
                    if identity is not None:
                        owner = owners[identity]
                        if owner[2]:
                            member = dict(id=identity, mapping_error='path conflict')
                        else:
                            # Duplicate raw copies use the owner's normalised member.
                            member = self.state.path(owner[1])['member']
                    row.update(container_generation=generation,
                               resolution_key=self.state.adapter_store._key(member, False)[0],
                               staged_generation=None, committed_generation=None)
                    self.state._put('path:' + row['path'], row)
            outcome = dict(path=RESOURCE, status=200, members_file=Path(stream.name),
                           coverage_complete=complete, msrc_generation=generation)
            return outcome
        except BaseException:
            self._pending_members_file.unlink(missing_ok=True)
            raise

    def poll(self, *, cutoff=None):
        self._pending_members_file = None
        try:
            outcomes = self._poll(cutoff=cutoff)
            failures, http_errors, oldest = 0, 0, None
            for row in self.state.iter_paths():
                failures += bool(row['failure'])
                http_errors += row['failure'] == 'http'
                anchor = row['audit_anchor']
                if oldest is None or instant(anchor) < instant(oldest):
                    oldest = anchor
            for outcome in outcomes:
                outcome.update(subrequest_failures=failures, subrequest_http_errors=http_errors)
                if oldest is not None:
                    outcome['record_audit_oldest'] = oldest
        except BaseException:
            if self._pending_members_file is not None:
                self._pending_members_file.unlink(missing_ok=True)
            raise
        self._pending_members_file = None
        return outcomes

    def _poll(self, *, cutoff=None):
        self.now = self.clock(); self.tick = stamp(self.now)
        self.spent = sum(t == self.tick for t in self.state.meta('requests', []))
        hold = self.state.meta('rate_hold_until')
        if (hold and self.now < instant(hold)) or self._remaining() <= 1:
            outcome = self._container(True)
            if 'members_file' in outcome:
                outcome['coverage_complete'] = False
            return [outcome]
        metadata = self.state.meta('metadata')
        if metadata is None or (self.now-instant(metadata['fetched_at'])).total_seconds() >= 86400:
            document, failure = self._envelope(METADATA_URL, self._metadata)
            if failure: return [failure]
            self.state.set_metadata(document, self.tick)
        if self._remaining() <= 1: return [self._container(True)]
        parsed, failure = self._envelope(DIRECTORY + 'changes.csv', parse_listing)
        if failure: return [failure]
        listing, invalid = parsed
        self.state.observe_listing(listing, invalid, self.tick)
        candidates = []
        for row in self.state.iter_paths():
            retry = row.get('next_attempt')
            if retry and self.now < instant(retry): continue
            if retry:
                priority = (0, instant(retry))
            elif row.get('member') is None or row['timestamps'] != row['listed_timestamps']:
                priority = (1, row['path'])
            elif row['last_success'] and (self.now-instant(row['last_success'])).total_seconds() >= 6*86400:
                priority = (2, instant(row['last_success']))
            else: continue
            candidates.append((*priority, row['path']))
        for _, _, path in sorted(candidates):
            if self._remaining() <= 1: break
            if self._fetch_record(self.state.path(path)): break
        return [self._container(invalid)]

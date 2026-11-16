# script-purpose: Poll and merge whole Debian OSV exports under a daily cadence.
# script-class: pipeline-tool
# script-trigger: Effective Debian adapter dispatch.
# script-tests: tests/test_task4_b1.py
"""Read bulk HTTP exports and durable state; write SQLite meta and member JSONL.

Archives and the temporary merge index live under data_dir and are removed on
return or exception. The consumer owns a returned members_file. Library API,
no process exit codes; unexpected programming or persistence errors propagate.
"""
from datetime import timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path
import json
import re
import sqlite3
import tempfile
import unicodedata
from urllib.parse import quote, unquote, urlsplit
import zipfile
import zlib

from cornicen.adapterstore import bounded_wait, canonical, instant, stamp
from cornicen.feedvalidate import decode_json
from cornicen.osv import normalise

HOST = 'osv-vulnerabilities.storage.googleapis.com'
BASE = 'https://' + HOST
DISCOVERY = BASE + '/ecosystems.txt'
RESOURCE = 'debian/advisories'
MEMBER_BYTES = 1024**2
MAX_ENTRIES = 150000
MAX_TOTAL = 1024**3
NAME = re.compile(r'([A-Za-z0-9][A-Za-z0-9._-]{0,99})\.json\Z')


def parse_discovery(body):
    """Validate the complete UTF-8 inventory and return its ordered Debian set."""
    try:
        text = body.decode('utf-8', errors='strict') if isinstance(body, bytes) else body
        if not isinstance(text, str) or not text.strip() or text.lstrip().startswith('<'):
            raise ValueError('invalid discovery')
        result = []
        for line in text.split('\n'):
            line = line.removesuffix('\r')
            if not line:
                continue
            if len(line) > 100 or any(unicodedata.category(c) in ('Cc', 'Cf') for c in line):
                raise ValueError('invalid discovery')
            if (line == 'Debian' or line.startswith('Debian:')) and line not in result:
                result.append(line)
        if not result:
            raise ValueError('invalid discovery')
        return result
    except UnicodeError:
        raise ValueError('invalid discovery') from None


class DebianState:
    """Durable adapter meta and read-only store views; no watch input."""
    def __init__(self, store):
        self.store = store
        self.db = store.connection

    def meta(self, key, default=None):
        value = self.store.get_meta('debian:' + key)
        return json.loads(value) if value is not None else default

    def _put(self, key, value):
        self.store.set_meta('debian:' + key, canonical(value))

    def attempt(self, tick):
        with self.store.transaction():
            self._put('last_attempt', tick)

    def due(self, now):
        retries = self.db.execute("""SELECT next_attempt_at FROM adapter_retries
            WHERE source='debian' AND resource IN (?, '@dispatch')""", (RESOURCE,)).fetchall()
        if retries:
            return all(instant(r[0]) <= now for r in retries)
        last = self.meta('last_attempt')
        if last is None:
            return True
        manifest = self.db.execute("SELECT digest,fetched_at FROM manifests WHERE source='debian' AND resource=?", (RESOURCE,)).fetchone()
        finished = manifest and manifest['digest'] and instant(manifest['fetched_at']) >= instant(last)
        return not finished or now-instant(last) >= timedelta(days=1)

    def pinned(self):
        return self.store.get_meta('baseline_pinned:debian:' + RESOURCE) is not None

    def advisory_state(self, identity):
        row = self.db.execute("SELECT state FROM advisories WHERE source='debian' AND source_id=?", (identity,)).fetchone()
        return row[0] if row else None

    def acknowledged(self):
        return set(json.loads(self.store.get_meta('ack_absent:debian:' + RESOURCE) or '[]'))


class DebianOsv:
    def __init__(self, http, state, clock, *, data_dir):
        self.http, self.state, self.clock = http, state, clock
        self.data_dir = Path(data_dir)
        self.ecosystems = []
        self.skipped = False

    def required_resources(self):
        return (RESOURCE,)

    def retry(self, resource):
        return []

    def audit(self, resource):
        return []

    def validate_hop(self, url):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname != HOST or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or '?' in url or '#' in url):
            raise ValueError('invalid OSV destination')
        if parsed.path == '/ecosystems.txt':
            return
        match = re.fullmatch(r'/([^/]+)/all\.zip', parsed.path)
        if not match or unquote(match[1], errors='strict') not in self.ecosystems:
            raise ValueError('invalid OSV destination')

    @staticmethod
    def _row(**values):
        return dict(path=RESOURCE, unconditional=True, **values)

    def _get(self, url, *, archive=False):
        # ponytail: Unconditional daily archive; add If-None-Match with a cached archive if bandwidth matters.
        try:
            response = self.http.get(url, source='osv_debian', budget='osv_debian',
                to_file=archive, validate_hop=self.validate_hop,
                **({} if archive else dict(max_bytes=65536)))
        except EOFError:
            return None, dict(kind='short')
        except (OSError, ValueError, HTTPException):
            return None, dict(kind='transport')
        if response.status != 200:
            return response, dict(kind='http', status=response.status, headers=dict(response.headers))
        length = response.headers.get('content-length')
        if length is not None:
            try:
                actual = response.path.stat().st_size if response.path is not None else len(response.body)
                if int(length) != actual:
                    return response, dict(kind='short')
            except (ValueError, TypeError):
                return response, dict(kind='short')
        return response, None

    def _headers(self, failures, now):
        return max((f.get('headers', {}) for f in failures),
                   key=lambda h: bounded_wait(h, now) if bounded_wait(h, now) is not None else -1,
                   default={})

    def _fold(self, failures, now):
        http = [f for f in failures if f['kind'] == 'http']
        if http:
            selected = max(http, key=lambda f: bounded_wait(f['headers'], now) if bounded_wait(f['headers'], now) is not None else -1)
            code = selected['status']
            return self._row(status=code, headers=selected['headers'],
                rate_limited=any(f['status'] in (403, 429) for f in http),
                **(dict(invalid_envelope=True, invalid_status=True) if 200 <= code < 300 else {}))
        if any(f['kind'] == 'transport' for f in failures):
            return self._row(status=0, transport_error=True)
        if any(f['kind'] == 'short' for f in failures):
            return self._row(status=200, transfer_complete=False, body='{}')
        return self._row(status=200, invalid_envelope=True)

    def _archive(self, index, pass_number, ordinal, ecosystem, path):
        """Validate the archive envelope before inserting any decoded members."""
        try:
            with Path(path).open('rb') as stream:
                while chunk := stream.read(4096):
                    stripped = chunk.lstrip()
                    if stripped:
                        if stripped.startswith(b'<'):
                            raise ValueError('unsafe archive')
                        break
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_TOTAL:
                    raise ValueError('unsafe archive')
                seen = set()
                for info in infos:
                    if not NAME.fullmatch(info.filename) or info.filename in seen or info.flag_bits & 1:
                        raise ValueError('unsafe archive')
                    seen.add(info.filename)
                for info in infos:
                    identity = NAME.fullmatch(info.filename)[1]
                    error = False
                    try:
                        with z.open(info) as member:
                            body = member.read(MEMBER_BYTES + 1)
                        if len(body) > MEMBER_BYTES:
                            raise ValueError('oversized member')
                        raw = decode_json(body)
                        if not isinstance(raw, dict) or raw.get('id') != identity:
                            raise ValueError('invalid member')
                        # Escaped lone surrogates decode as JSON but cannot be
                        # stored in SQLite or the UTF-8 member stream.
                        canonical(raw).encode('utf-8', errors='strict')
                    except (ValueError, OSError, EOFError, zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error):
                        raw = dict(id=identity, mapping_error='invalid archive member')
                        error = True
                    index.execute('INSERT INTO copies VALUES (?,?,?,?,?,?)',
                                  (pass_number, identity, ordinal, ecosystem, canonical(raw), error))
            return True
        except (zipfile.BadZipFile, ValueError, OSError, EOFError):
            index.execute('DELETE FROM copies WHERE pass=? AND ordinal=?', (pass_number, ordinal))
            return False

    def _pass(self, index, number, now):
        response, failure = self._get(DISCOVERY)
        if failure:
            if failure['kind'] == 'http':
                code = failure['status']
                row = self._row(status=code, headers=failure['headers'])
                if 200 <= code < 300:
                    row.update(invalid_envelope=True, invalid_status=True)
                else:
                    row['rate_limited'] = code in (403, 429)
                return None, [], [], row
            return None, [], [], self._row(status=0, transport_error=True)
        try:
            ecosystems = parse_discovery(response.body)
        except ValueError:
            return None, [], [], self._row(status=200, invalid_envelope=True)
        self.ecosystems = ecosystems
        with self.state.store.transaction():
            self.state._put('ecosystems', ecosystems)
        failures, dates = [], []
        for ordinal, ecosystem in enumerate(ecosystems):
            response = None
            try:
                response, failure = self._get(BASE+'/'+quote(ecosystem, safe='')+'/all.zip', archive=True)
                if not failure and not self._archive(index, number, ordinal, ecosystem, response.path):
                    failure = dict(kind='unsafe')
                if failure:
                    failures.append(dict(failure, ecosystem=ecosystem))
                else:
                    try:
                        date = parsedate_to_datetime(response.headers.get('last-modified', ''))
                        if date.tzinfo is None:
                            raise ValueError('clock has no timezone')
                        dates.append(stamp(date.astimezone(timezone.utc)))
                    except (ValueError, TypeError, OverflowError):
                        dates.append(None)
            finally:
                if response is not None and response.path is not None:
                    response.path.unlink(missing_ok=True)
        index.commit()
        return ecosystems, failures, dates, None

    @staticmethod
    def _copies(index, number, identity):
        return index.execute('SELECT ecosystem,raw,error FROM copies WHERE pass=? AND id=? ORDER BY ordinal', (number, identity)).fetchall()

    @staticmethod
    def _merge(rows):
        """Return one raw record, or None for a conflicting projection."""
        if any(r[2] for r in rows):
            return None
        if all(r[1] == rows[0][1] for r in rows):
            return json.loads(rows[0][1])
        records = [json.loads(r[1]) for r in rows]
        common = None
        scopes = set()
        for raw in records:
            fields = {k:v for k,v in raw.items() if k != 'affected'}
            # A disjoint projection must first be a valid OSV record.
            if 'mapping_error' in normalise(raw):
                return None
            ecosystems = {a['package']['ecosystem'] for a in raw.get('affected', [])}
            if common is not None and (fields != common or scopes & ecosystems):
                return None
            common = fields
            scopes.update(ecosystems)
        return dict(common, affected=[a for raw in records for a in raw.get('affected', [])])

    def poll(self, *, cutoff=None):
        now = self.clock()
        if isinstance(now, str):
            now = instant(now)
        self.skipped = not self.state.due(now)
        if self.skipped:
            return []
        self.state.attempt(stamp(now))
        index_path = None
        output_path = None
        index = None
        returned = False
        try:
            with tempfile.NamedTemporaryFile(dir=self.data_dir, prefix='debian-merge-', suffix='.sqlite', delete=False) as f:
                index_path = Path(f.name)
            index = sqlite3.connect(index_path)
            index.execute('PRAGMA journal_mode=OFF')
            index.execute('PRAGMA cache_size=-2048')
            index.execute('CREATE TABLE copies(pass INTEGER,id TEXT,ordinal INTEGER,ecosystem TEXT,raw TEXT,error INTEGER, PRIMARY KEY(pass,id,ordinal)) WITHOUT ROWID')
            ecosystems, failures, dates, fatal = self._pass(index, 1, now)
            if fatal:
                return [fatal]
            if failures and (not self.state.pinned() or len(failures) == len(ecosystems)):
                return [self._fold(failures, now)]
            conflicts = set(self.state.meta('conflicts', []))
            # Only previously conflicted, now coherent records require a second pass.
            repeat = any((rows := self._copies(index, 1, identity)) and self._merge(rows) is not None for identity in conflicts)
            stable = False
            if repeat:
                second_ecosystems, second_failures, second_dates, second_fatal = self._pass(index, 2, now)
                if second_fatal:
                    return [second_fatal]
                stable = not second_failures and second_ecosystems == ecosystems
                failures.extend(second_failures)
                dates.extend(second_dates)
                if failures and not self.state.pinned():
                    return [self._fold(failures, now)]
            tracked = self.state.meta('copies', {})
            acknowledged = self.state.acknowledged()
            index.execute('CREATE TABLE members(id TEXT PRIMARY KEY) WITHOUT ROWID')
            index.executemany('INSERT INTO members VALUES (?)', ((identity,) for identity in tracked))
            with tempfile.NamedTemporaryFile(dir=self.data_dir, prefix='debian-members-', suffix='.jsonl', mode='w', encoding='utf-8', delete=False) as output:
                output_path = Path(output.name)
                for (identity,) in index.execute('SELECT id FROM copies WHERE pass=1 UNION SELECT id FROM members ORDER BY id'):
                    rows = self._copies(index, 1, identity)
                    current = sorted(r[0] for r in rows)
                    previous = tracked.get(identity, [])
                    if not rows:
                        # Only intact or delisted archives establish absence.
                        if any(f.get('ecosystem') in previous for f in failures):
                            continue
                        if identity in acknowledged:
                            tracked[identity] = []
                            continue
                        if self.state.advisory_state(identity) not in ('active', 'withdrawn'):
                            output.write(canonical(dict(id=identity, mapping_error='projection incomplete'))+'\n')
                        continue
                    if len(current) >= 2:
                        tracked[identity] = sorted(set(previous) | set(current))
                    short = bool(set(previous) - set(current))
                    if short and identity not in acknowledged:
                        if self.state.advisory_state(identity) in ('active', 'withdrawn'):
                            continue
                        member = dict(id=identity, mapping_error='projection incomplete')
                    elif any(r[2] for r in rows):
                        # A damaged copy cannot establish coherence or clear a
                        # projection conflict from an earlier cycle.
                        member = dict(id=identity, mapping_error='invalid archive member')
                    else:
                        raw = self._merge(rows)
                        if raw is None or (identity in conflicts and
                                (not stable or rows != self._copies(index, 2, identity))):
                            member = dict(id=identity, mapping_error='projection conflict')
                            conflicts.add(identity)
                        else:
                            member = normalise(raw)
                            conflicts.discard(identity)
                            if short:
                                tracked[identity] = current
                    output.write(canonical(member)+'\n')
            with self.state.store.transaction():
                self.state._put('copies', tracked)
                self.state._put('conflicts', sorted(conflicts))
            outcome = self._row(status=200, members_file=str(output_path))
            if failures:
                outcome.update(coverage_complete=False,
                    subrequest_failures=sum(f['kind'] != 'unsafe' for f in failures),
                    subrequest_http_errors=sum(f['kind'] == 'http' for f in failures),
                    headers=self._headers(failures, now),
                    rate_limited=any(f.get('status') in (403, 429) for f in failures))
            elif dates and all(dates):
                outcome['publication_clock'] = dict(provenance='gate_validated_last_modified', value=min(dates))
            returned = True
            return [outcome]
        finally:
            if index is not None:
                index.close()
            if index_path is not None:
                index_path.unlink(missing_ok=True)
            if output_path is not None and not returned:
                output_path.unlink(missing_ok=True)

# script-purpose: Audit closed UTC days against the local CVE List store without ingesting records.
# script-class: pipeline-tool
# script-trigger: The poll scheduler after delta ingest.
# script-tests: tests/test_cvelist_gap.py
"""Read upstream commit evidence and local records; write audit metadata and health.

Library API with no process exit codes.
"""

from collections import Counter
from copy import copy
from datetime import date, datetime, time, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
import json
import logging
from queue import Empty, SimpleQueue
import re
from threading import Lock, Thread
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
import zlib

from cornicen import validate
from cornicen.gap_protocol import BodyTooLarge, NO_OVERDUE, RAW_HOST, RedirectRefused, SOURCE
from cornicen.store import project_record


DAYS = 'cvelist_gap_days'
REGISTERED = 'cvelist_gap_registered_through'
DELTA_RATE = 'cvelist_gap_delta_rate'
AUDIT_RATE = 'cvelist_gap_rate'
RETRY_AT = 'cvelist_gap_retry_at'
COMMAND = 'gap'
ACK = 'ack'
ACK_OK = 'Expired day acknowledged: '
ACK_NOT_FOUND = 'No expired day for that date'
ADAPTER = 'gap_audit'

REPOSITORY = 'CVEProject/cvelistV5'
REPOSITORY_URL = 'https://api.github.com/repos/' + REPOSITORY
COMMITS = REPOSITORY_URL + '/commits'
RAW = f'https://{RAW_HOST}/CVEProject/cvelistV5/'
SHA = re.compile(r'[a-f0-9]{40}\Z')
CANDIDATE = re.compile(r'cves/([0-9]{4})/[0-9]+xxx/(CVE-\1-[0-9]{4,})\.json\Z')
ISO_DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}\Z')
DAY = timedelta(days=1)
WINDOW = 14
CONCLUSIVE = frozenset(('stale', 'absent', 'covered', 'deleted'))
MAX_BODY = 2 * 1024 * 1024
MAX_BYTES = 8 * 1024 * 1024
MAX_FILES = 300
DETAIL_CAP = 3000


def _stamp(value):
    try:
        value = datetime.fromisoformat(value)
        if value.utcoffset() is not None:
            return value.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    return None


def iso_day(value):
    if isinstance(value, str) and ISO_DAY.fullmatch(value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    return None


def rate_observation(headers, now, mode):
    try:
        values = {key: int(headers['x-ratelimit-' + key])
                  for key in ('limit', 'remaining', 'reset')}
        if not 0 <= values['remaining'] <= values['limit']:
            return None
        values['reset'] = datetime.fromtimestamp(values['reset'], timezone.utc).isoformat()
    except (KeyError, ValueError, TypeError, OverflowError, OSError):
        return None
    return dict(values, observed_at=now.isoformat(), mode=mode)


def _admitted(rate, now, mode):
    reset = _stamp(rate.get('reset'))
    return (rate.get('mode') == mode and reset is not None and reset > now
            and rate.get('remaining', 0) >= (100 if mode == 'token' else 10))


class _Admission:
    """Share live delta constraints with the audit worker without sharing SQLite."""

    def __init__(self, http):
        self.http = http
        self.lock = Lock()
        self.token = http.github_token
        self.generation = self.revision = 0
        self.rate = None
        self.unobserved = 0
        self.in_flight = set()
        self.backoff = None

    def _sync_auth(self):
        if self.http.github_token is not self.token:
            self.token = self.http.github_token
            self.generation += 1
            self.revision += 1
            self.rate = {}
            self.unobserved = 0
            self.in_flight.clear()
        return 'token' if self.token is not None else 'none'

    def drop_token(self):
        with self.lock:
            self.http.github_token = None
            self._sync_auth()

    def set_backoff(self, until):
        with self.lock:
            self.backoff = until

    def snapshot(self, now, observations, *, rest):
        with self.lock:
            mode = self._sync_auth()
            if self.rate is None:
                self.rate = max((item for item in observations if item.get('mode') == mode),
                                key=lambda item: (_stamp(item['observed_at']), -item['remaining']),
                                default={})
                if self.rate:
                    self.rate = dict(self.rate, remaining=max(
                        0, self.rate['remaining'] - self.unobserved))
                self.unobserved = 0
            if self._allowed(now, mode, rest):
                return self.generation, mode, self.token

    def _allowed(self, now, mode, rest):
        return ((self.backoff is None or now >= self.backoff)
                and (not rest or _admitted(self.rate or {}, now, mode)))

    def _charge(self, now):
        if self.rate:
            self.rate = dict(self.rate, remaining=max(0, self.rate['remaining'] - 1),
                             observed_at=now.isoformat())
        elif self.rate is None:
            self.unobserved += 1
        self.revision += 1
        self.in_flight.add(self.revision)
        return self.revision

    def dispatch_priority(self, now, token):
        """Account for delta and release traffic without making it wait for audit."""
        with self.lock:
            self._sync_auth()
            if token is self.token:
                return self._charge(now)

    def dispatch(self, now, generation, rest):
        with self.lock:
            mode = self._sync_auth()
            if generation != self.generation or not self._allowed(now, mode, rest):
                raise _Pause()
            if rest:
                return self._charge(now), self.rate
            return None, None

    def finish(self, revision, rate=None):
        with self.lock:
            self._sync_auth()
            if revision not in self.in_flight:
                return
            self.in_flight.remove(revision)
            # A late response cannot overwrite newer dispatches or observations.
            if rate is not None and revision == self.revision:
                if self.in_flight:
                    # A response may have been generated before another request
                    # was counted upstream. Keep its reservation until refreshed.
                    rate = dict(rate, remaining=max(0, rate['remaining'] - len(self.in_flight)))
                self.rate = rate
                self.unobserved = 0
                self.revision += 1
                return self.revision, rate

    def current(self, revision):
        with self.lock:
            self._sync_auth()
            return revision == self.revision


def _read_days(store):
    return json.loads(store.get_meta(DAYS) or '{}')


def _save_days(store, days):
    store.set_meta(DAYS, json.dumps(days, separators=(',', ':')))


def _register(store, days, today):
    """On the activation poll register yesterday, then register each newly closed UTC day."""
    last = iso_day(store.get_meta(REGISTERED))
    closed = today - DAY
    if last is not None and last >= closed:
        return
    # At most two windows can survive a long shutdown: the newest open
    # days and the preceding days whose expiry is still retained.
    day = closed if last is None else max(last + DAY, today - 2 * WINDOW * DAY)
    while day <= closed:
        days.setdefault(day.isoformat(), {'scan': 'pending'})
        open_days = sorted(key for key, state in days.items()
                           if state['scan'] != 'complete' and 'expired' not in state)
        for key in open_days[:-WINDOW]:
            days[key]['expired'] = (day + DAY).isoformat()
            days[key]['counts'] = dict(_counts(days[key]))
            _clear_progress(days[key])
        day += DAY
    expired = [key for key, state in days.items() if 'expired' in state
               and (today - date.fromisoformat(state['expired'])).days >= WINDOW]
    for key in expired:
        del days[key]
    store.set_meta(REGISTERED, closed.isoformat())


def _counts(state):
    return state.get('counts') or Counter(value for value in state.get('paths', {}).values() if value is not None)


def _clear_progress(state):
    for key in ('tip', 'tip_time', 'tip_parent', 'wide', 'paths', 'attempts',
                'history', 'first', 'detail', 'repository_id'):
        state.pop(key, None)


def _outside_window(key, state, today):
    return state['scan'] == 'complete' and date.fromisoformat(key) < today - WINDOW * DAY


def _summary(days):
    counts = Counter()
    complete = undecided = expired = 0
    for state in days.values():
        counts.update(_counts(state))
        complete += state['scan'] == 'complete'
        undecided += state['scan'] == 'undecided'
        expired += 'expired' in state
    return dict(days_complete=complete, days_open=len(days) - complete,
                days_undecided=undecided, days_expired=expired, found_stale=counts['stale'],
                found_absent=counts['absent'], covered=counts['covered'],
                deleted=counts['deleted'], invalid=counts['invalid'])


def summary(store):
    return _summary(_read_days(store))


def status(store, now=None):
    days = _read_days(store)
    if now is not None:
        today = now.astimezone(timezone.utc).date()
        days = {key: state for key, state in days.items() if not _outside_window(key, state, today)}
    opened = [key for key, state in days.items() if state['scan'] != 'complete']
    return dict(_summary(days), oldest_open=min(opened, default=None),
                days={key: dict(scan=state['scan'], content_time=state.get('content_time'),
                                expired='expired' in state, diagnostic=state.get('diagnostic'),
                                found_stale=_counts(state).get('stale', 0),
                                found_absent=_counts(state).get('absent', 0))
                      for key, state in sorted(days.items())})


def status_lines(report):
    complete, opened = report['days_complete'], report['days_open']
    stale, absent = report['found_stale'], report['found_absent']
    undecided = report['days_undecided']
    heading = f'cvelist gap: {complete} complete, {stale} stale, {absent} absent, {opened} open ({undecided} undecided)'
    if report['oldest_open']:
        heading += ' · oldest ' + report['oldest_open']
    yield heading + ' · stale vs end of day'
    for key, day in report['days'].items():
        line = f'  {key}: ' + ('expired' if day['expired'] else day['scan'])
        if day['scan'] == 'complete':
            if not day['found_stale'] and not day['found_absent']:
                line += ', 0 found'
            else:
                line += f", {day['found_stale']} found (stale), {day['found_absent']} found (absent)"
        if day['content_time']:
            line += ' · asset content time ' + day['content_time']
        if day['diagnostic']:
            line += ' · ' + day['diagnostic']
        yield line


def ack(store, day):
    if iso_day(day) is None:
        return False
    with store.transaction():
        days = _read_days(store)
        if 'expired' not in days.get(day, {}):
            return False
        del days[day]
        _save_days(store, days)
        key = 'cvelist_gap_ack_count'
        store.set_meta(key, int(store.get_meta(key) or 0) + 1)
    logging.getLogger(__name__).info('delta gap: expired day acknowledged %s', day)
    return True


def health_detail(count, oldest):
    return f'delta gap: {count} days open, oldest {oldest}'


def health_fields(days, today):
    opened = sorted(key for key, state in days.items() if state['scan'] != 'complete')
    if any('expired' in days[key] or (today - date.fromisoformat(key) - DAY).days >= 3
           for key in opened):
        return dict(days_open=len(opened), oldest_open=opened[0])
    return {}


def _record_time(metadata):
    value = metadata.get('dateUpdated')
    try:
        return validate.timestamp(value) if isinstance(value, str) else None
    except (ValueError, OverflowError):
        return None


def _compare(store, cve_id, body):
    try:
        tip = json.loads(body)
        if not isinstance(tip, dict) or not isinstance(tip.get('cveMetadata'), dict):
            return 'invalid'
        metadata = tip['cveMetadata']
        if metadata.get('cveId') != cve_id:
            return 'invalid'
        tip_time = _record_time(metadata)
        if tip_time is None:
            return 'undecided'
        if validate.record(tip):
            return 'invalid'
    except (ValueError, TypeError, RecursionError):
        return 'invalid'
    row = store.connection.execute('SELECT json FROM records WHERE id=?', (cve_id,)).fetchone()
    if row is None:
        return 'absent'
    try:
        raw = zlib.decompress(row[0]) if isinstance(row[0], bytes) else row[0]
        stored = json.loads(raw)
        stored_time = _record_time(stored['cveMetadata'])
        if stored_time is None:
            return 'undecided'
        if stored_time < tip_time:
            return 'stale'
        if stored_time > tip_time or project_record(tip) == project_record(stored):
            return 'covered'
    except (KeyError, AttributeError, ValueError, TypeError, RecursionError, zlib.error):
        pass
    return 'undecided'


def _retry_at(headers, now):
    candidates = []
    try:
        candidates.append(datetime.fromtimestamp(int(headers.get('x-ratelimit-reset')), timezone.utc))
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    value = headers.get('retry-after', '')
    try:
        if value.isascii() and value.isdecimal():
            candidates.append(now + timedelta(seconds=int(value)))
        else:
            stamp = parsedate_to_datetime(value)
            candidates.append(stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc))
    except (ValueError, TypeError, OverflowError):
        pass
    return max((stamp for stamp in candidates if stamp > now), default=now + timedelta(hours=1))


def _commit_identity(entry):
    sha = entry['sha']
    stamp = _stamp(entry['commit']['committer']['date'])
    if not SHA.fullmatch(sha) or stamp is None:
        raise _Pause('commit proof')
    return sha, stamp


def _commit(entry):
    sha, stamp = _commit_identity(entry)
    parents = entry['parents']
    if not isinstance(parents, list) or len(parents) != 1:
        raise _Pause('commit proof')
    parent = parents[0]['sha']
    if not SHA.fullmatch(parent) or parent == sha:
        raise _Pause('commit proof')
    return sha, stamp, parent


_TOKEN = r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+"
_LINK = re.compile(r'[ \t]*<([^<>]*)>[ \t]*')
_PARAM = re.compile(rf';[ \t]*({_TOKEN})(?:[ \t]*=[ \t]*({_TOKEN}|"(?:[^"\\\r\n]|\\[^\r\n])*"))?[ \t]*')


def _next_page(headers, url, page):
    value = headers.get('link', '')
    target = None
    pos = 0
    while pos < len(value):
        # HTTP list fields permit empty elements. Delimiters inside URI
        # references or quoted parameters are consumed by the respective match.
        if value[pos] in ', \t':
            pos += 1
            continue
        link = _LINK.match(value, pos)
        if not link:
            raise _Pause('pagination')
        pos = link.end()
        params = {}
        while param := _PARAM.match(value, pos):
            name, arg = param.groups()
            if arg and arg.startswith('"'):
                arg = re.sub(r'\\(.)', r'\1', arg[1:-1])
            params.setdefault(name.lower(), arg or '')
            pos = param.end()
        if pos < len(value) and value[pos] != ',':
            raise _Pause('pagination')
        if 'next' in params.get('rel', '').lower().split():
            if target is not None or 'anchor' in params:
                raise _Pause('pagination')
            target = urlsplit(urljoin(url, link[1]))
    if target is None:
        return False
    origin = urlsplit(url)
    query = parse_qs(target.query, keep_blank_values=True)
    original = parse_qs(origin.query, keep_blank_values=True)
    original.pop('page', None)
    if (target.scheme != origin.scheme or target.hostname != origin.hostname
            or target.port not in (None, 443) or target.username is not None
            or target.password is not None or target.fragment
            or query.pop('page', None) != [str(page + 1)] or query != original):
        raise _Pause('pagination')
    if target.path.lower() == origin.path.lower():
        return True
    suffix = origin.path.removeprefix('/repos/' + REPOSITORY)
    numeric = re.fullmatch(r'/repositories/([1-9][0-9]*)' + re.escape(suffix), target.path)
    if numeric is None:
        raise _Pause('pagination')
    return numeric[1]


class _Pause(Exception):
    def __init__(self, diagnostic=None):
        self.diagnostic = diagnostic


class _Job:
    """Fetch immutable evidence with a private auth snapshot and no store handle."""

    def __init__(self, http, now, day, state, admission, auth):
        self.http = copy(http)
        self.admission = admission
        self.generation, self.mode, self.http.github_token = auth
        self.now = now
        self.started = http.clock()
        self.deadline = self.started + 120
        self.day = day
        self.state = state
        self.bytes_left = MAX_BYTES
        self.results = SimpleQueue()

    def _emit(self, kind, *args):
        self.results.put((kind, args))

    def _now(self):
        return self.now + timedelta(seconds=self.http.clock() - self.started)

    def _get(self, url, *, rest, path=None):
        remaining = int(self.deadline - self.http.clock())
        if remaining <= 0 or self.bytes_left <= 1:
            raise _Pause()
        revision = None

        def dispatch():
            nonlocal revision
            if self.http.clock() >= self.deadline:
                raise _Pause()
            revision, rate = self.admission.dispatch(self._now(), self.generation, rest)
            if rest:
                self._emit('rate', revision, rate)
            if path is not None:
                self._emit('attempt', path)

        def observed(host, status, headers):
            when = self._now()
            if rest:
                updated = self.admission.finish(revision, rate_observation(headers, when, self.mode))
                if updated is not None:
                    self._emit('rate', *updated)
            if status == 401:
                raise _Pause('auth')
            if status in (403, 429):
                self._emit('retry', _retry_at(headers, when).isoformat())
                raise _Pause('rate limited')

        # Transport reads one sentinel byte to distinguish a full body from a
        # truncated one. Include it in the cycle's byte budget on overflow.
        body_cap = MAX_BYTES - 1 if rest else MAX_BODY
        limit = min(body_cap, self.bytes_left - 1)
        try:
            response = self.http.get(url, source='cvelist', max_bytes=limit,
                                     follow_redirects=False, deadline_seconds=remaining,
                                     on_response=observed, before_dispatch=dispatch)
        except BodyTooLarge:
            self.bytes_left -= limit + 1
            if limit < body_cap:
                raise _Pause() from None
            raise
        finally:
            if rest:
                self.admission.finish(revision)
        self.bytes_left -= len(response.body)
        if self.http.clock() >= self.deadline:
            raise _Pause()
        return response

    def _api(self, suffix='', *, base=COMMITS):
        response = self._get(base + suffix, rest=True)
        if response.status != 200:
            raise _Pause('HTTP failure')
        return json.loads(response.body), response.headers

    def _next(self, headers, suffix, page):
        more = _next_page(headers, COMMITS + suffix, page)
        if isinstance(more, str):
            repository_id = self.state.get('repository_id')
            if repository_id is None:
                repository, _ = self._api(base=REPOSITORY_URL)
                number = repository.get('id')
                name = repository.get('full_name')
                if (type(number) is not int or number <= 0 or not isinstance(name, str)
                        or name.casefold() != REPOSITORY.casefold()):
                    raise _Pause('pagination')
                self.state['repository_id'] = repository_id = str(number)
                self._emit('state', {'repository_id': repository_id})
            if more != repository_id:
                raise _Pause('pagination')
            return True
        return more

    def _first(self, start, end, tip):
        until = end if self.state.get('wide') else start + timedelta(hours=6)
        since = start - timedelta(hours=2)
        # Filtering an immutable ancestor walk keeps the early window on the
        # same lineage even when the tip itself was committed later that day.
        query = '?' + urlencode(dict(sha=tip[0], since=_utc(since),
                                     until=_utc(until), per_page=100))
        saved = self.state.get('history') or {}
        history = [(sha, _stamp(stamp), parent) for sha, stamp, parent in saved.get('entries', ())]
        seen = {sha for sha, _, _ in history}
        page = saved.get('next', 1)
        while page is not None:
            suffix = query + (f'&page={page}' if page > 1 else '')
            entries, headers = self._api(suffix)
            more = self._next(headers, suffix, page)
            if (not isinstance(entries, list) or len(entries) > 100
                    or not entries and (page > 1 or more)):
                raise _Pause('commit proof')
            current = [_commit(entry) for entry in entries]
            for sha, stamp, _ in current:
                if sha in seen or not since <= stamp <= min(until, tip[1]):
                    raise _Pause('commit proof')
                seen.add(sha)
            joined = history[-1:] + current
            if any(new[2] != old[0] or new[1] < old[1] for new, old in zip(joined, joined[1:])):
                raise _Pause('commit proof')
            history.extend(current)
            finished = any(stamp < start for _, stamp, _ in current) or not more
            if not finished and page == 3:
                # The early window can be attempted again, but never page four.
                self._emit('state', {'history': None})
                raise _Pause('pagination')
            if tip[1] <= until:
                if not history or history[0] != tip:
                    raise _Pause('commit proof')
            elif tip[0] in seen or (tip[2] in seen and history[0][0] != tip[2]):
                raise _Pause('commit proof')
            if finished:
                page = None
            else:
                page += 1
            if page is not None or not any(stamp < start for _, stamp, _ in history):
                self._emit('state', {'history': {
                    'next': page, 'entries': [(sha, _utc(stamp), parent) for sha, stamp, parent in history],
                }})
        in_day = [entry for entry in history if start <= entry[1] < end]
        if not in_day:
            self._emit('state', {'wide': True, 'history': None})
            raise _Pause('first commit unavailable')
        first = in_day[-1]
        _, _, parent = first
        if not any(stamp < start for _, stamp, _ in history):
            try:
                proof, _ = self._api('/' + parent)
            except _Pause as pause:
                if pause.diagnostic == 'HTTP failure':
                    self._emit('state', {'history': None})
                raise
            actual, parent_time = _commit_identity(proof)
            # A parent inside the query window should have been on a list page.
            if actual != parent or parent in seen or parent_time >= since:
                self._emit('state', {'history': None})
                raise _Pause('commit proof')
        return first

    def _files(self, first):
        saved = self.state.get('detail') or {}
        files = list(saved.get('files', ()))
        seen = set(files)
        candidates = {match[2] for filename in files if (match := CANDIDATE.fullmatch(filename))}
        for page in range(saved.get('next', 1), 11):
            suffix = '/' + first[0] + (f'?page={page}' if page > 1 else '')
            detail, headers = self._api(suffix)
            if _commit(detail) != first:
                raise _Pause('commit proof')
            more = self._next(headers, suffix, page)
            batch = detail['files']
            if not isinstance(batch, list) or len(batch) > 300:
                raise _Pause('file limit')
            if not batch and (page > 1 or more):
                raise _Pause('pagination')
            for item in batch:
                filename = item['filename']
                if not isinstance(filename, str):
                    raise _Pause('invalid response')
                if filename in seen:
                    raise _Pause('pagination')
                if match := CANDIDATE.fullmatch(filename):
                    if match[2] in candidates:
                        raise _Pause('candidate identity')
                    candidates.add(match[2])
                seen.add(filename)
                files.append(filename)
            if len(files) >= DETAIL_CAP:
                raise _Pause('file limit')
            if not more:
                return files
            if page < 10:
                self._emit('state', {'detail': {'next': page + 1, 'files': files.copy()}})
        raise _Pause('file limit')

    def _run(self):
        start = datetime.combine(self.day, time(), timezone.utc)
        end = start + DAY
        tip = self.state.get('tip')
        paths = self.state.get('paths')
        if tip is None:
            commits, _ = self._api('?' + urlencode(dict(sha='main', until=_utc(end), per_page=1)))
            if not isinstance(commits, list) or len(commits) != 1:
                raise _Pause('commit proof')
            tip, stamp = _commit_identity(commits[0])
            if stamp >= end:
                raise _Pause('commit proof')
            if stamp < start:
                self._emit('state', {'paths': {}, 'ignored': 0})
                return
            _, _, parent = _commit(commits[0])
            tip_commit = (tip, stamp, parent)
            self._emit('state', {'tip': tip, 'tip_time': _utc(stamp), 'tip_parent': parent})
        else:
            tip_commit = (tip, _stamp(self.state.get('tip_time')), self.state.get('tip_parent'))
        if paths is None:
            if saved := self.state.get('first'):
                first = (saved[0], _stamp(saved[1]), saved[2])
            else:
                first = self._first(start, end, tip_commit)
                self._emit('state', {'first': (first[0], _utc(first[1]), first[2]), 'history': None})
            files = self._files(first)
            paths = dict.fromkeys(filename for filename in files if CANDIDATE.fullmatch(filename))
            self._emit('state', {'paths': dict(paths), 'ignored': len(files) - len(paths)})

        requested = 0
        attempts = self.state.get('attempts', {})
        for path in sorted(paths, key=lambda path: (attempts.get(path, 0), path)):
            if paths[path] in CONCLUSIVE:
                continue
            if requested >= MAX_FILES:
                return
            requested += 1
            try:
                response = self._get(RAW + tip + '/' + path, rest=False, path=path)
            except (BodyTooLarge, RedirectRefused):
                self._emit('file', path, 'invalid')
                continue
            self._emit('file', path, 'deleted' if response.status == 404 else
                       response.body if response.status == 200 else 'invalid')

    def run(self):
        try:
            self._run()
        except _Pause as pause:
            if pause.diagnostic:
                self._emit('state', {'scan': 'undecided', 'diagnostic': pause.diagnostic})
        except (TimeoutError, OSError, EOFError, HTTPException):
            pass
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            self._emit('state', {'scan': 'undecided', 'diagnostic': 'invalid response'})


def _utc(stamp):
    return stamp.isoformat().replace('+00:00', 'Z')


class GapAudit:
    """Poll-thread coordinator. Only this side reads and writes the store."""

    def __init__(self, http):
        self.http = http
        self.admission = _Admission(http)
        self.worker = self.job = None
        self.day = None
        self.attempted = {}

    def _collect(self, store, days):
        if self.worker is None:
            return
        finished = not self.worker.is_alive()
        state = days.get(self.day)
        attempt_order = None
        while True:
            try:
                kind, args = self.job.results.get_nowait()
            except Empty:
                break
            if kind in ('rate', 'retry'):
                if kind == 'rate':
                    revision, rate = args
                    if self.admission.current(revision):
                        store.set_meta(AUDIT_RATE, json.dumps(rate))
                else:
                    store.set_meta(RETRY_AT, args[0])
            elif state is not None and 'expired' not in state:
                if kind == 'state':
                    state.update(args[0])
                    if 'paths' in args[0]:
                        state.pop('diagnostic', None)
                        for key in ('history', 'first', 'detail', 'repository_id', 'wide'):
                            state.pop(key, None)
                elif kind == 'attempt':
                    attempts = state.setdefault('attempts', {})
                    attempt_order = (max(attempts.values(), default=0) if attempt_order is None
                                     else attempt_order) + 1
                    attempts[args[0]] = attempt_order
                else:
                    path, result = args
                    state['paths'][path] = (_compare(store, CANDIDATE.fullmatch(path)[2], result)
                                            if isinstance(result, bytes) else result)
        if state is not None and 'expired' not in state and 'paths' in state:
            paths = state['paths']
            if all(outcome in CONCLUSIVE for outcome in paths.values()):
                state['scan'] = 'complete'
                state['counts'] = dict(Counter(paths.values()))
                _clear_progress(state)
                state.pop('diagnostic', None)
            elif any(outcome in ('invalid', 'undecided') for outcome in paths.values()):
                state['scan'] = 'undecided'
        if finished:
            self.worker = self.job = None

    def _launch(self, store, days, now):
        if self.worker is not None:
            return
        self.admission.set_backoff(_stamp(store.get_meta('github_retry_at')))
        until = _stamp(store.get_meta(RETRY_AT))
        if until is not None and now < until:
            return
        cursor = store.connection.execute(
            "SELECT value,content_time FROM cursors WHERE source='cvelist'").fetchone()
        if not cursor:
            return
        try:
            cursor_day = validate.release_stamp(cursor['value']).date().isoformat()
        except ValueError:
            return
        content_time = _stamp(cursor['content_time'])
        if content_time is None:
            return
        ready = [key for key, state in days.items() if state['scan'] != 'complete'
                 and 'expired' not in state and (key < cursor_day or
                     (key == cursor_day and cursor['value'].endswith('_at_end_of_day')))]
        if not ready:
            return
        observations = [json.loads(store.get_meta(key) or '{}') for key in (AUDIT_RATE, DELTA_RATE)]
        for day in sorted(ready, key=lambda key: (self.attempted.get(key, 0), key)):
            auth = self.admission.snapshot(now, observations, rest='paths' not in days[day])
            if auth is not None:
                break
        else:
            return
        self.attempted = {key: order for key, order in self.attempted.items() if key in ready}
        self.attempted[day] = max(self.attempted.values(), default=0) + 1
        state = days[day]
        state.setdefault('content_time', content_time.isoformat())
        network_state = {key: dict(value) if isinstance(value, dict) else value
                         for key, value in state.items()}
        self.day = day
        self.job = _Job(self.http, now, date.fromisoformat(day), network_state, self.admission, auth)
        self.worker = Thread(target=self.job.run, daemon=True)
        self.worker.start()
        return self.worker

    def tick(self, store, health, now):
        now = now.astimezone(timezone.utc)
        with store.transaction():
            days = _read_days(store)
            before = json.dumps(days)
            _register(store, days, now.date())
            self._collect(store, days)
            started = self._launch(store, days, now)
            if json.dumps(days) != before:
                _save_days(store, days)
        if started is not None:
            started.join(1)
        with store.transaction():
            days = _read_days(store)
            before = json.dumps(days)
            self._collect(store, days)
            for key in [key for key, state in days.items() if _outside_window(key, state, now.date())]:
                del days[key]
            if json.dumps(days) != before:
                _save_days(store, days)
            fields = health_fields(days, now.date())
            if fields:
                health(SOURCE, 'unhealthy', health_detail(fields['days_open'], fields['oldest_open']),
                       'incomplete', health_fields=fields)
            else:
                health(SOURCE, 'healthy', NO_OVERDUE)
        return _summary(days)

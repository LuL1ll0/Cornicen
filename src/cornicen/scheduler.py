"""One process, source-ordered minute cycles and atomic inventory reloads."""

from datetime import datetime, timedelta, timezone
import json
import re
import signal
import threading
import time
import unicodedata
from urllib.parse import urlsplit, unquote, quote, quote_plus, parse_qsl

from cornicen import acceptance
from cornicen.deadman import ping
from cornicen.counts import REPORT_KEYS, report_counts
from cornicen.github import github_status
from cornicen.health import assess, active_sources
from cornicen.public_text import prepare_inventory, public_text, public_token
from cornicen.store import TransactionAborted
from cornicen.watchlist import load_document, WatchlistError


ACCEPTANCE_RETRY = timedelta(hours=1)


GITHUB_KEYS = ('auth', 'limit', 'remaining', 'reset', 'observed_at')


def redact_tokens(message, *tokens):
    message = ''.join(c for c in str(message) if not unicodedata.category(c).startswith('C'))
    secrets = set()
    for token in tokens:
        if token is None:
            continue
        secret = token.reveal()
        values = {secret}
        if secret.lower().startswith(('https://', 'http://')):
            # Include transport and diagnostic representations before public_text.
            for url in (secret, unquote(secret)):
                values.update((url, url.split('#', 1)[0]))
                try:
                    parts = urlsplit(url)
                except ValueError:
                    continue
                values.update((parts.netloc,
                               parts.netloc.rpartition('@')[0], parts.hostname or '',
                               parts.path, parts.query))
                values.update(part for part in parts.path.split('/') if len(part) >= 6)
                values.update(value for _, value in parse_qsl(parts.query) if len(value) >= 6)
                values.update(field.partition('=')[2] for field in parts.query.split('&')
                              if len(field.partition('=')[2]) >= 6)
            values.update(unquote(value) for value in tuple(values))
            values.update(quote(value, safe='') for value in tuple(values))
            values.update(quote(value, safe='/') for value in tuple(values))
            values.update(quote_plus(value, safe='') for value in tuple(values))
            values.update(quote(value, safe=':/?=@') for value in tuple(values))
        for value in values:
            for form in (value, json.dumps(value)[1:-1]):
                form = ''.join(c for c in form if not unicodedata.category(c).startswith('C'))
                if form:
                    secrets.add(form)
    # A component must not leave a suffix of a longer representation behind.
    if secrets:
        message = re.sub('|'.join(re.escape(value) for value in sorted(secrets, key=lambda v: (-len(v), v))),
                         lambda _: '[redacted]', message)
    return message


def safe_message(error, token=None, *tokens):
    """Keep operational text, never serialize payloads or inventory diagnostics."""
    if isinstance(error, WatchlistError):
        return 'Watchlist validation failed'
    if any(not isinstance(arg, (str, int, float, type(None))) for arg in error.args):
        return 'Exception details withheld (non-text payload)'
    message = redact_tokens(str(error), token, *tokens)
    # Exceptions may embed a whole record, a quoted field, or HTTP headers.
    message = re.split(r'[{}]|\[(?=[\[\{"\'])', message, maxsplit=1)[0]
    message = re.sub(r'(["\']).*?\1', '[redacted]', message)
    message = re.sub(r'(?i)(?<![A-Za-z0-9])(authorization|bearer|token|password|secret|api[_-]?key)[\s:=]+.*',
                     r'\1 [redacted]', message)
    if re.search(r'\b(cveMetadata|containers|affected|descriptions)\b', message):
        return 'Exception details withheld (record payload)'
    return message[:300] or 'Exception details withheld'


class Scheduler:
    intervals = {'cvelist': timedelta(hours=1), 'kev': timedelta(hours=6),
                 'epss': timedelta(days=1)}

    def __init__(self, engine, sources, clock=None, output=print, monotonic=None):
        self.engine, self.sources = engine, sources
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic = monotonic or time.monotonic
        self.output = output
        self.stop = threading.Event()
        self.next_poll = {}
        self.watch_stamp = self._stamp()
        self.component = 'scheduler'
        self.acceptance_started = False
        self.acceptance_stamp = None
        self.deadman_last_attempt = None
        self.deadman_result = "ok"
        self.deadman_worker = None
        self.deadman_outcome = []
        self.deadman_timed_out = False

    def _stamp(self):
        try:
            stat = self.engine.config.watchlist_path.stat()
            return stat.st_mtime_ns, stat.st_size, stat.st_ino
        except OSError:
            return None

    def _reload(self):
        stamp = self._stamp()
        if stamp == self.watch_stamp:
            return
        try:
            watches, accepts = load_document(self.engine.config.watchlist_path)
            if self._stamp() != stamp:
                raise WatchlistError(['Watchlist changed while reading'])
        except WatchlistError:
            # Never persist parser errors: they may include private inventory.
            with self.engine.store.transaction():
                self.engine._health('watchlist', 'unhealthy', 'Watchlist reload rejected')
        else:
            engine = self.engine
            if watches == engine.watches and engine._identity_version == (engine.aliases, engine.aliases.version):
                engine.accepts = accepts
                with engine.store.transaction():
                    engine.db.execute('UPDATE outbox SET dirty=1 WHERE sent_at IS NULL')
                    rejected = engine.db.execute("SELECT detail FROM health WHERE source='watchlist' AND state='unhealthy'").fetchone()
                    pending = engine.db.execute("SELECT 1 FROM retry_queue WHERE source='watchlist' UNION ALL SELECT 1 FROM dead_letters WHERE source='watchlist'").fetchone()
                    if rejected and rejected[0] == 'Watchlist reload rejected' and not pending:
                        engine._health('watchlist', 'healthy', 'Watchlist reload validation succeeded')
            else:
                engine.reload_watches(watches)
                engine.accepts = accepts
            self.watch_stamp = stamp

    def _acceptance_stamps(self):
        stamps = []
        for path in (self.engine.config.acceptance_list_path,
                     self.engine.config.acceptance_watchlist_path):
            try:
                stat = path.stat()
                stamps.append((stat.st_mtime_ns, stat.st_size, stat.st_ino))
            except OSError:
                stamps.append(None)
        return tuple(stamps)

    def _refresh_acceptance_holds(self):
        # This must precede run_cycle's retention pruning. Invalid files retain
        # the previous holds; the main evaluation reports their rejection.
        try:
            engine = self.engine
            if not engine.config.acceptance_list_path:
                return
            entries = acceptance.load_entries(engine.config.acceptance_list_path)
            engine.acceptance_holds = frozenset(cve for _, cve in entries)
            desired = json.dumps(sorted(engine.acceptance_holds))
            if engine.store.get_meta('acceptance_holds') != desired:
                with engine.store.transaction():
                    engine.store.set_meta('acceptance_holds', desired)
        except TransactionAborted:
            raise
        except Exception:
            pass

    def _acceptance(self, now):
        engine = self.engine
        try:
            if not engine.config.acceptance_list_path or not engine.store.get_meta('baseline_complete'):
                return
            stamp = self._acceptance_stamps()
            last = engine.store.get_meta('acceptance_last_run')
            try:
                previous = datetime.fromisoformat(last) if last else None
            except (ValueError, TypeError):
                previous = None
            invalid = previous is None or previous.utcoffset() is None or previous > now
            health = engine.db.execute("SELECT state FROM health WHERE source='acceptance'").fetchone()
            unhealthy = health is not None and health['state'] == 'unhealthy'
            elapsed = None if invalid else now - previous
            due = (not self.acceptance_started or stamp != self.acceptance_stamp or invalid
                   or (elapsed >= ACCEPTANCE_RETRY if unhealthy else
                       elapsed > timedelta(days=engine.config.acceptance_interval_days)))
            if not due:
                return
            try:
                entries = acceptance.load_entries(engine.config.acceptance_list_path)
                watches = acceptance.load_watches(engine.config.acceptance_watchlist_path, entries)
                outcomes = acceptance.evaluate(engine.store, entries, watches, engine.aliases)
                state, detail, reason = acceptance.verdict(outcomes)
            except acceptance.AcceptanceError:
                state, detail, reason = 'unhealthy', 'Acceptance list rejected', 'rejected'
            except TransactionAborted:
                raise
            except Exception:
                state, detail, reason = 'unhealthy', 'Acceptance self-test failed', 'failed'
            with engine.store.transaction():
                engine.store.set_meta('acceptance_last_run', now.isoformat())
                engine._health('acceptance', state, detail, reason)
            self.acceptance_started = True
            self.acceptance_stamp = stamp
            engine._flush()
        except TransactionAborted:
            raise
        except Exception:
            # Include baseline reads, health recording and delivery in the guard.
            # Even secondary failures must never expose private exception text.
            pass

    def _deadman_status(self, now):
        if self.engine.config.deadman_url is None:
            return 'off'
        # due_at is the original delivery deadline. A retry backoff must not
        # hide a still-failing delivery from the external monitor.
        failed = self.engine.db.execute(
            'SELECT 1 FROM outbox WHERE sent_at IS NULL AND attempts>0 AND due_at<=? LIMIT 1',
            (now.isoformat(),)).fetchone()
        return 'skipped' if failed else self.deadman_result

    def _collect_deadman(self):
        worker = self.deadman_worker
        if worker is None:
            return
        elapsed = self.monotonic() - self.deadman_last_attempt
        done = not worker.is_alive()
        if not done and elapsed < 30:
            return
        if not self.deadman_timed_out:
            result, finished = self.deadman_outcome[0] if done else ('failed', elapsed)
            self.deadman_result = result if finished < 30 else 'failed'
            self.deadman_timed_out = True
            # Only the scheduler touches SQLite, including timeout health.
            try:
                with self.engine.store.transaction():
                    self.engine._health('deadman',
                                        'healthy' if self.deadman_result == 'ok' else 'unhealthy',
                                        'Ping complete' if self.deadman_result == 'ok' else 'Ping failed',
                                        None if self.deadman_result == 'ok' else 'failed')
            except Exception:
                pass
        if done:
            self.deadman_worker = None

    def _deadman(self, status):
        if status in ('off', 'skipped') or self.deadman_worker is not None:
            return
        elapsed = self.monotonic()
        if (self.deadman_last_attempt is not None
                and elapsed - self.deadman_last_attempt < self.engine.config.deadman_interval_minutes * 60):
            return
        self.deadman_last_attempt = elapsed
        self.deadman_outcome = outcome = []
        self.deadman_timed_out = False
        url = self.engine.config.deadman_url.reveal()
        monotonic = self.monotonic
        def request():
            try:
                ping(url)
            except Exception:
                result = 'failed'
            else:
                result = 'ok'
            outcome.append((result, monotonic() - elapsed))
        self.deadman_worker = threading.Thread(target=request, daemon=True)
        self.deadman_worker.start()

    def tick(self):
        self.component = 'scheduler'
        if self.engine.config.deadman_url is not None:
            self._collect_deadman()
        now = self.clock()
        elapsed = self.monotonic()
        self.component = 'watchlist'
        self._reload()
        ingests = []
        counts = {}
        next_poll = dict(self.next_poll)
        try:
            for name, interval in self.intervals.items():
                counts[name] = 0
                if name not in self.next_poll or elapsed >= self.next_poll[name]:
                    self.component = name
                    results = self.sources[name].poll(now)
                    ingests.extend(results)
                    counts[name] = sum(len(result.records) + len(result.kev or {})
                                       + len(result.epss or {}) for result in results)
                    next_poll[name] = elapsed + interval.total_seconds()
            self.component = 'engine'
            self._refresh_acceptance_holds()
            report = self.engine.run_cycle(ingests)
            self._acceptance(now)
            # A failed engine cycle must retry its sources on the next minute.
            self.next_poll = next_poll
            for component in ('engine', 'scheduler'):
                row = self.engine.store.connection.execute(
                    'SELECT state FROM health WHERE source=?', (component,)).fetchone()
                if row and row['state'] == 'unhealthy':
                    with self.engine.store.transaction():
                        self.engine._health(component, 'healthy', 'Cycle completed')
                    self.engine._flush()
            self.component = 'scheduler'
            db = self.engine.store.connection
            components = (*self.intervals, 'watchlist')
            health_sources = set(components)
            health_sources.update(active_sources(self.engine.store, self.engine.config))
            health = {name: assess(name, self.engine.store, now, self.engine.config)
                      for name in health_sources}
            statuses = {name: health[name][0] for name in components}
            report_summary = dict.fromkeys(REPORT_KEYS)
            try:
                totals = report_counts(db, self.engine.watches, self.engine.accepts,
                                       now, self.engine.config.timezone)
                report_summary = {key: totals[key] for key in REPORT_KEYS}
            except Exception:
                pass
            github = dict.fromkeys(GITHUB_KEYS)
            github['auth'] = 'unknown'
            try:
                state = github_status(self.engine.store)
                values = dict.fromkeys(GITHUB_KEYS)
                values['auth'] = state['auth']
                rate = state['rate_limit']
                if rate is not None:
                    for key in ('limit', 'remaining'):
                        values[key] = rate[key]
                    for key in ('reset', 'observed_at'):
                        values[key] = int(datetime.fromisoformat(rate[key]).timestamp())
                github = values
            except Exception:
                pass
            inventory = prepare_inventory(self.engine.watches)
            health_details = {}
            withheld = 0
            for name, verdict in health.items():
                key = public_token(name, inventory)
                if key is None:
                    withheld += 1
                    continue
                health_details[key] = public_text(safe_message(RuntimeError(
                    verdict[1]), self.engine.config.ntfy_token, self.engine.config.github_token, self.engine.config.deadman_url),
                    inventory)
            deadman = self._deadman_status(self.clock())
            self.output(json.dumps({'time': now.isoformat(), 'sources': statuses,
                                    'deadman': deadman,
                                    'health_details': health_details,
                                    'health_details_withheld': withheld,
                                    'ingested': counts, 'events': len(report.events),
                                    'report': report_summary, 'github': github,
                                    'sent': report.sent, 'pending': db.execute(
                                        'SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0]},
                                   sort_keys=True))
        finally:
            for ingest in ingests:
                close = getattr(ingest.records, 'close', None)
                if close is not None:
                    close()

        self._deadman(deadman)
        return report

    def _failed_cycle(self, error):
        message = public_text(safe_message(error, self.engine.config.ntfy_token, self.engine.config.github_token, self.engine.config.deadman_url),
                              self.engine.watches)
        entry = {'time': self.clock().isoformat(), 'component': self.component,
                 'error': public_token(redact_tokens(type(error).__name__, self.engine.config.ntfy_token, self.engine.config.github_token, self.engine.config.deadman_url), self.engine.watches) or 'Exception', 'message': message}
        try:
            # Defensively discard open work before recording cycle health.
            # Health and its outbox entry must commit independently of that work.
            self.engine.store.connection.rollback()
            with self.engine.store.transaction():
                self.engine._health(self.component, 'unhealthy', error)
            self.engine._flush()
        except Exception as health_error:
            # A database/delivery outage must not defeat the cycle boundary.
            # Report the secondary failure on the same JSON line.
            entry['health_error'] = public_token(redact_tokens(type(health_error).__name__, self.engine.config.ntfy_token, self.engine.config.github_token, self.engine.config.deadman_url), self.engine.watches) or 'Exception'
            entry['health_message'] = public_text(safe_message(health_error, self.engine.config.ntfy_token, self.engine.config.github_token, self.engine.config.deadman_url),
                                                  self.engine.watches)
        self.output(json.dumps(entry, sort_keys=True))

    def run(self):
        previous = signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        try:
            while not self.stop.is_set():
                started = self.monotonic()
                try:
                    self.tick()
                except Exception as error:
                    self._failed_cycle(error)
                elapsed = self.monotonic() - started
                self.stop.wait(max(0, 60 - elapsed))
        finally:
            signal.signal(signal.SIGTERM, previous)
        return 0

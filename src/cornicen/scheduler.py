"""One process, source-ordered minute cycles and atomic inventory reloads."""

from datetime import datetime, timedelta, timezone
import json
import re
import signal
import threading
import time
import unicodedata

from cornicen.counts import REPORT_KEYS, report_counts
from cornicen.github import github_status
from cornicen.health import assess
from cornicen.public_text import prepare_inventory, public_text, public_token
from cornicen.watchlist import load_document, WatchlistError


GITHUB_KEYS = ('auth', 'limit', 'remaining', 'reset', 'observed_at')


def redact_tokens(message, *tokens):
    message = ''.join(c for c in str(message) if not unicodedata.category(c).startswith('C'))
    for token in tokens:
        if token is None:
            continue
        secret = token.reveal()
        for value in (secret, json.dumps(secret)[1:-1]):
            value = ''.join(c for c in value if not unicodedata.category(c).startswith('C'))
            if value:
                message = message.replace(value, '[redacted]')
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

    def tick(self):
        self.component = 'scheduler'
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
            report = self.engine.run_cycle(ingests)
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
            health_sources.update(row[0] for row in db.execute('SELECT source FROM health'))
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
                    verdict[1]), self.engine.config.ntfy_token, self.engine.config.github_token),
                    inventory)
            self.output(json.dumps({'time': now.isoformat(), 'sources': statuses,
                                    'health_details': health_details,
                                    'health_details_withheld': withheld,
                                    'ingested': counts, 'events': len(report.events),
                                    'report': report_summary, 'github': github,
                                    'sent': report.sent, 'pending': db.execute(
                                        'SELECT count(*) FROM outbox WHERE sent_at IS NULL').fetchone()[0]},
                                   sort_keys=True))
            return report
        finally:
            for ingest in ingests:
                close = getattr(ingest.records, 'close', None)
                if close is not None:
                    close()

    def _failed_cycle(self, error):
        message = public_text(safe_message(error, self.engine.config.ntfy_token, self.engine.config.github_token),
                              self.engine.watches)
        entry = {'time': self.clock().isoformat(), 'component': self.component,
                 'error': public_token(type(error).__name__, self.engine.watches) or 'Exception', 'message': message}
        try:
            # A failed RELEASE/commit can leave the cycle's transaction open.
            # Health and its outbox entry must commit independently of that work.
            self.engine.store.connection.rollback()
            with self.engine.store.transaction():
                self.engine._health(self.component, 'unhealthy', error)
            self.engine._flush()
        except Exception as health_error:
            # A database/delivery outage must not defeat the cycle boundary.
            # Report the secondary failure on the same JSON line.
            entry['health_error'] = public_token(type(health_error).__name__, self.engine.watches) or 'Exception'
            entry['health_message'] = public_text(safe_message(health_error, self.engine.config.ntfy_token, self.engine.config.github_token),
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

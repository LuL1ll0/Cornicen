"""SQLite state and transactional, coalesced delivery storage."""

from contextlib import contextmanager
from datetime import datetime, timedelta
from hashlib import sha256
import json
import os
import re
from pathlib import Path
import sqlite3
import zlib
import weakref

from cornicen import validate


RECORD_MIGRATION_BATCH = 128
PROJECTION_REVISION = 2
SSVC_VALUES = {'Exploitation': ('none', 'poc', 'active'),
               'Automatable': ('no', 'yes'), 'Technical Impact': ('partial', 'total')}


class TransactionAborted(Exception):
    """The enclosing transaction was lost and cannot accept more work."""


def _merge_ssvc(result, option):
    for key, values in SSVC_VALUES.items():
        value = option.get(key)
        if value in values and (key not in result or values.index(value) > values.index(result[key])):
            result[key] = value


def _ssvc(other):
    if not isinstance(other, dict) or other.get('type') != 'ssvc':
        return None
    content = other.get('content')
    if not isinstance(content, dict):
        return None
    options = content.get('options', [])
    points = {}
    clean = {'options': []}
    for option in options if isinstance(options, list) else []:
        if isinstance(option, dict):
            _merge_ssvc(points, option)
    clean['options'] = [{key: value} for key, value in points.items()]
    stamp = content.get('timestamp')
    if isinstance(stamp, str) and re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?', stamp):
        try:
            datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            clean['timestamp'] = stamp
        except ValueError:
            pass
    return {'type': 'ssvc', 'content': clean}


def record_ssvc(record):
    """Read only the allowlisted CISA decision points, including partial assessments."""
    result = {}
    containers = record.get('containers', {})
    entries = containers.get('adp', []) if isinstance(containers, dict) else []
    for entry in entries if isinstance(entries, list) else []:
        provider = entry.get('providerMetadata') if isinstance(entry, dict) else None
        if not isinstance(provider, dict) or provider.get('shortName') != 'CISA-ADP':
            continue
        metrics = entry.get('metrics', [])
        for metric in metrics if isinstance(metrics, list) else []:
            other = _ssvc(metric.get('other')) if isinstance(metric, dict) else None
            if other:
                for option in other['content']['options']:
                    _merge_ssvc(result, option)
    return result


def project_record(record):
    """Keep the stored CVE contract in spec §6.6; preserve invalid retry payloads."""
    if validate.record(record):
        return record

    def metrics(value, cisa=False):
        if not isinstance(value, list):
            return value
        result = []
        for metric in value:
            if not isinstance(metric, dict):
                result.append(metric)
                continue
            clean = {key: item for key, item in metric.items() if key.startswith('cvss')}
            other = _ssvc(metric.get('other')) if cisa else None
            if other is not None:
                clean['other'] = other
            result.append(clean)
        return result

    def adp_entry(entry):
        if not isinstance(entry, dict):
            return None
        if 'metrics' in entry and not isinstance(entry['metrics'], list):
            return None
        provider = entry.get('providerMetadata')
        cisa = isinstance(provider, dict) and provider.get('shortName') == 'CISA-ADP'
        clean = {'metrics': metrics([metric for metric in entry['metrics']
                                     if isinstance(metric, dict)], cisa)} if 'metrics' in entry else {}
        if cisa:
            clean['providerMetadata'] = {'shortName': 'CISA-ADP'}
        return clean

    result = {'cveMetadata': record['cveMetadata']}
    if 'containers' not in record:
        return result
    containers = record['containers']
    if not isinstance(containers, dict):
        return result
    projected = {}
    if 'cna' in containers:
        cna = containers['cna']
        if isinstance(cna, dict):
            projected['cna'] = {key: cna[key] for key in ('affected', 'title') if key in cna}
            if 'metrics' in cna:
                projected['cna']['metrics'] = metrics(cna['metrics'])
            provider = cna.get('providerMetadata')
            if isinstance(provider, dict) and 'shortName' in provider:
                projected['cna']['providerMetadata'] = {'shortName': provider['shortName']}
        else:
            projected['cna'] = cna
    if 'adp' in containers:
        adp = containers['adp']
        if isinstance(adp, list):
            projected['adp'] = [clean for entry in adp if (clean := adp_entry(entry)) is not None]
    result['containers'] = projected
    return result


class Store:
    def __init__(self, path: str, *, read_only=False):
        if not read_only and path != ':memory:':
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            # SQLite creates future sidecars with the database's permissions.
            for suffix in ('-wal', '-shm'):
                try:
                    os.chmod(str(path) + suffix, 0o600)
                except FileNotFoundError:
                    pass
        target = Path(path).resolve().as_uri() + '?mode=ro' if read_only else path
        self.connection = sqlite3.connect(target, isolation_level=None, uri=read_only)
        self._finalizer = weakref.finalize(self, self.connection.close)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA busy_timeout = 30000')
        # Readers inherit the writer's WAL mode. Never convert a legacy database
        # or create a journal from a diagnostic command.
        self.connection.execute('PRAGMA journal_mode' if read_only else 'PRAGMA journal_mode = WAL')
        self.connection.execute('PRAGMA foreign_keys = ON')
        self._savepoint = 0
        self._transaction_depth = 0
        self._transaction_aborted = False

    def migrate(self):
        with self.transaction():
            statements = (
                'CREATE TABLE IF NOT EXISTS http_cache(url TEXT PRIMARY KEY, etag TEXT NOT NULL, link TEXT, body BLOB NOT NULL, used_at TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, json BLOB NOT NULL, ingested_at TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, json TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS kev_seen(cve TEXT PRIMARY KEY)',
                'CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, score REAL, pct REAL, date TEXT)',
                '''CREATE TABLE IF NOT EXISTS pairs(watch_id TEXT, record_id TEXT, state TEXT NOT NULL,
                   episode INTEGER NOT NULL, baseline INTEGER NOT NULL, exploited INTEGER NOT NULL DEFAULT 0,
                   notified INTEGER NOT NULL DEFAULT 0, evidence TEXT, confidence TEXT,
                   PRIMARY KEY(watch_id, record_id))''',
                '''CREATE TABLE IF NOT EXISTS events(key TEXT PRIMARY KEY, watch_id TEXT, record_id TEXT,
                   type TEXT, episode INTEGER, created_at TEXT)''',
                '''CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, pair_key TEXT NOT NULL,
                   urgency TEXT NOT NULL, reasons_json TEXT NOT NULL, body_json TEXT NOT NULL, due_at TEXT NOT NULL,
                   attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, sent_at TEXT)''',
                'CREATE UNIQUE INDEX IF NOT EXISTS outbox_pending_pair ON outbox(pair_key) WHERE sent_at IS NULL',
                'CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY, value TEXT, content_time TEXT)',
                'CREATE TABLE IF NOT EXISTS health(source TEXT PRIMARY KEY, state TEXT, since TEXT, detail TEXT)',
                'CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)',
            )
            for statement in statements:
                self.connection.execute(statement)
            crossing_upgrade = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='epss_crossings'").fetchone() is None
            scores_upgrade = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='epss_crossing_scores'").fetchone() is None
            self.connection.execute("""CREATE TABLE IF NOT EXISTS epss_crossings(
                watch_id TEXT, record_id TEXT, episode INTEGER NOT NULL,
                fired INTEGER, crossing INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(watch_id,record_id))""")
            columns = {row['name'] for row in self.connection.execute('PRAGMA table_info(epss_crossings)')}
            for column in ('threshold', 'rearm_ratio'):
                if column not in columns:
                    self.connection.execute(f'ALTER TABLE epss_crossings ADD COLUMN {column} REAL')
            self.connection.execute('''CREATE TABLE IF NOT EXISTS epss_crossing_scores(
                cve TEXT PRIMARY KEY, score REAL, pct REAL, date TEXT)''')
            seen = self.get_meta('kev_seen')
            if seen is not None:
                self.connection.executemany('INSERT OR IGNORE INTO kev_seen VALUES (?)',
                                            ((cve,) for cve in json.loads(seen)))
                self.connection.execute("DELETE FROM meta WHERE k='kev_seen'")
            self.connection.execute('CREATE TABLE IF NOT EXISTS invalid_revisions(record_id TEXT PRIMARY KEY, json BLOB NOT NULL)')
            columns = {row['name'] for row in self.connection.execute('PRAGMA table_info(pairs)')}
            if 'alias_map_version' not in columns:
                self.connection.execute('ALTER TABLE pairs ADD COLUMN alias_map_version TEXT')
            columns = {row['name'] for row in self.connection.execute('PRAGMA table_info(outbox)')}
            if 'enqueued_at' not in columns:
                self.connection.execute('ALTER TABLE outbox ADD COLUMN enqueued_at TEXT')
            if 'dirty' not in columns:
                self.connection.execute('ALTER TABLE outbox ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1')
            self.connection.execute('''CREATE INDEX IF NOT EXISTS outbox_ready
                ON outbox(max(due_at,coalesce(next_attempt_at,due_at))) WHERE sent_at IS NULL''')
            self.connection.execute('CREATE INDEX IF NOT EXISTS outbox_dirty ON outbox(id) WHERE sent_at IS NULL AND dirty=1')
            self.connection.execute("""UPDATE outbox SET enqueued_at=coalesce(
                (SELECT min(created_at) FROM events WHERE watch_id || '|' || record_id=outbox.pair_key),
                due_at) WHERE enqueued_at IS NULL""")
            self.connection.execute("UPDATE outbox SET due_at=min(due_at,enqueued_at) WHERE urgency='urgent'")
            for table in ('retry_queue', 'dead_letters'):
                columns = {row['name'] for row in self.connection.execute(f'PRAGMA table_info({table})')}
                legacy = []
                if columns and 'last_error' not in columns:
                    legacy = self.connection.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()
                    self.connection.execute(f'DROP TABLE {table}')
                extra = ', version TEXT NOT NULL' if table == 'dead_letters' else ''
                self.connection.execute(f"""CREATE TABLE IF NOT EXISTS {table}(
                    source TEXT NOT NULL, record_id TEXT NOT NULL, attempts INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL, last_error TEXT NOT NULL{extra},
                    PRIMARY KEY(source,record_id))""")
                for row in legacy:
                    record = json.loads(row['json'])
                    key = row['record_id'] or ('@fetch' if isinstance(record, dict) and set(record) == {'errors'}
                        else '@invalid:' + sha256(json.dumps(record, sort_keys=True).encode()).hexdigest())
                    stored = self.connection.execute('SELECT ingested_at FROM records WHERE id=?', (key,)).fetchone()
                    # Old CVE retries contain revisions whose record writes were rolled back.
                    # KEV/watchlist payloads, by contrast, may predate the stored revision.
                    restore = row['source'] == 'cvelist' and (table == 'retry_queue' or
                        ('failed_at' in row.keys() and (not stored or row['failed_at'] >= stored[0])))
                    if key != '@fetch' and (not stored or restore):
                        self.put_record(key, record, stored[0] if stored else '1970-01-01T00:00:00+00:00')
                    context = json.loads(row['context_json']) if 'context_json' in row.keys() else {}
                    if context.get('baseline'):
                        self.set_meta('record_baseline:' + key, '1')
                    if context.get('kev_baseline'):
                        self.set_meta('kev_baseline:' + key, '1')
                    values = (row['source'], key, max(row['attempts'], 1) if 'attempts' in row.keys() else 1,
                              '1970-01-01T00:00:00+00:00', row['detail'])
                    if table == 'dead_letters':
                        values += ('',)
                    self.connection.execute(f"INSERT OR REPLACE INTO {table} VALUES ({','.join('?' for _ in values)})", values)
                self.connection.execute(f'CREATE INDEX IF NOT EXISTS {table}_record ON {table}(record_id)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS records_ingested ON records(ingested_at)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS pairs_record ON pairs(record_id)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS events_episode ON events(watch_id,record_id,episode)')
            self.connection.execute("""CREATE INDEX IF NOT EXISTS outbox_pending_record
                ON outbox(CAST(json_extract(body_json,'$.record_id') AS TEXT)) WHERE sent_at IS NULL""")
            if crossing_upgrade or scores_upgrade:
                # Older databases have only the merged evidence map. Do not seed
                # crossing evidence from a map with an outstanding fetch error.
                self.connection.execute('DELETE FROM epss_crossing_scores')
                if (self.get_meta('last_error:epss') is None and not self.connection.execute(
                        "SELECT 1 FROM retry_queue WHERE source='epss' AND record_id='@fetch'").fetchone()):
                    self.connection.execute('INSERT INTO epss_crossing_scores SELECT * FROM epss')
            self.set_meta('schema_version', '1')
        self._migrate_record_projection()

    def _migrate_record_projection(self):
        if self.get_meta('record_projection_version') == '1':
            return
        last = self.get_meta('record_projection_cursor')
        while True:
            # Commit each batch and its progress together. A restart resumes
            # without retaining or rolling back the entire corpus in memory.
            with self.transaction():
                query = 'SELECT id FROM records'
                params = ()
                if last is not None:
                    query += ' WHERE id>?'
                    params = (last,)
                rows = self.connection.execute(query + ' ORDER BY id LIMIT ?',
                                               (*params, RECORD_MIGRATION_BATCH)).fetchall()
                if not rows:
                    self.set_meta('record_projection_version', '1')
                    self.connection.execute("DELETE FROM meta WHERE k='record_projection_cursor'")
                    return
                for row in rows:
                    stored = self.connection.execute('SELECT json FROM records WHERE id=?', (row['id'],)).fetchone()[0]
                    raw = zlib.decompress(stored) if isinstance(stored, bytes) else stored
                    value = zlib.compress(json.dumps(project_record(json.loads(raw))).encode())
                    if value != stored:
                        self.connection.execute('UPDATE records SET json=? WHERE id=?', (value, row['id']))
                last = rows[-1]['id']
                self.set_meta('record_projection_cursor', last)

    @contextmanager
    def transaction(self):
        """Nested transactions isolate a record without committing its ingest."""
        if self._transaction_aborted:
            raise TransactionAborted('transaction aborted')
        self._savepoint += 1
        name = f'tx_{self._savepoint}'
        nested = self.connection.in_transaction
        self.connection.execute(f'SAVEPOINT {name}')
        self._transaction_depth += 1
        try:
            yield self.connection
            if self._transaction_aborted:
                raise TransactionAborted('transaction aborted')
            self.connection.execute(f'RELEASE {name}')
        except BaseException as error:
            if not nested:
                self.connection.rollback()
            elif not self._transaction_aborted and self.connection.in_transaction:
                try:
                    self.connection.execute(f'ROLLBACK TO {name}')
                    self.connection.execute(f'RELEASE {name}')
                except BaseException:
                    # SQLite may have aborted the entire transaction, or cleanup
                    # itself may fail. Never let a caller continue abandoned work.
                    self._transaction_aborted = True
                    self.connection.rollback()
                    raise TransactionAborted('transaction aborted') from error
            elif not self.connection.in_transaction:
                self._transaction_aborted = True
            if self._transaction_aborted and not isinstance(error, TransactionAborted):
                raise TransactionAborted('transaction aborted') from error
            raise
        finally:
            self._transaction_depth -= 1
            if self._transaction_depth == 0:
                self._transaction_aborted = False

    def get_meta(self, key):
        row = self.connection.execute('SELECT v FROM meta WHERE k=?', (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key, value):
        self.connection.execute('INSERT INTO meta VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
                                (key, str(value)))

    def queue(self, pair_key, urgency, reasons, body, due_at, enqueued_at=None):
        """Caller owns the transaction that also writes the associated event."""
        row = self.connection.execute(
            'SELECT * FROM outbox WHERE pair_key=? AND sent_at IS NULL', (pair_key,)).fetchone()
        if row:
            merged = list(dict.fromkeys(json.loads(row['reasons_json']) + list(reasons)))
            due = (min(due_at, row['due_at']) if row['urgency'] == urgency
                   else row['due_at'] if row['urgency'] == 'urgent' else due_at)
            urgency = 'urgent' if 'urgent' in (urgency, row['urgency']) else urgency
            self.connection.execute(
                'UPDATE outbox SET urgency=?, reasons_json=?, body_json=?, due_at=?,dirty=1 WHERE id=?',
                (urgency, json.dumps(merged), json.dumps(body), due, row['id']))
            return row['id']
        return self.connection.execute(
            'INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at,enqueued_at) VALUES (?,?,?,?,?,?)',
            (pair_key, urgency, json.dumps(list(reasons)), json.dumps(body), due_at, enqueued_at or due_at)).lastrowid

    def put_record(self, record_id, record, ingested_at):
        self.connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',
                                (record_id, zlib.compress(json.dumps(project_record(record)).encode()), ingested_at))
        self.dirty_record(record_id)

    def dirty_record(self, record_id):
        self.connection.execute("""UPDATE outbox SET dirty=1 WHERE sent_at IS NULL
            AND CAST(json_extract(body_json,'$.record_id') AS TEXT)=?""", (record_id,))

    def prune_records(self, now, retention_days, keep=()):
        cutoff = (now - timedelta(days=retention_days)).isoformat()
        self.connection.execute("""DELETE FROM records WHERE ingested_at < ?
            AND NOT EXISTS (SELECT 1 FROM pairs WHERE record_id=records.id)
            AND NOT EXISTS (SELECT 1 FROM outbox WHERE sent_at IS NULL
                            AND CAST(json_extract(body_json,'$.record_id') AS TEXT)=records.id)
            AND NOT EXISTS (SELECT 1 FROM kev WHERE cve=records.id)
            AND NOT EXISTS (SELECT 1 FROM retry_queue WHERE record_id=records.id)
            AND NOT EXISTS (SELECT 1 FROM dead_letters WHERE record_id=records.id)
            AND records.id NOT IN (SELECT value FROM json_each(?))
            AND records.id NOT IN (SELECT value FROM json_each(
                CASE WHEN json_valid((SELECT v FROM meta WHERE k='acceptance_holds'))
                    THEN CASE WHEN json_type((SELECT v FROM meta WHERE k='acceptance_holds'))='array'
                        THEN CASE WHEN NOT EXISTS (SELECT 1 FROM json_each(
                            (SELECT v FROM meta WHERE k='acceptance_holds')) WHERE type!='text')
                            THEN (SELECT v FROM meta WHERE k='acceptance_holds') ELSE '[]' END
                        ELSE '[]' END
                    ELSE '[]' END) WHERE type='text')""", (cutoff, json.dumps(list(keep))))

"""Operator commands. Inventory diagnostics stay local and use stored records."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import tomllib
import zlib

from cornicen.applicability import resolve, State
from cornicen.config import load_config
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess, container_healthy
from cornicen.identity import AliasMap, normalise, is_placeholder
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier
from cornicen.notify.ntfy import NtfyNotifier, post
from cornicen.scheduler import Scheduler, safe_message
from cornicen.sources.cvelist import CveListSource
from cornicen.sources.epss import EpssSource
from cornicen.sources.kev import KevSource
from cornicen.store import Store
from cornicen.watchlist import collisions, load_watchlist, WatchlistError


def _notifier(config):
    if config.notifier == 'file':
        return FileNotifier(config.notification_path)
    return NtfyNotifier(post, config.ntfy_url, config.ntfy_topic, config.ntfy_token)


def _record(row):
    raw = row['json']
    return json.loads(zlib.decompress(raw) if isinstance(raw, bytes) else raw)


def _active(result):
    return result is not None and (result.state == State.AFFECTED
                                   or (result.state == State.UNKNOWN and result.exploited))


def _near(record, watch, aliases):
    entries = record.get('containers', {}).get('cna', {}).get('affected', [])
    identities = set().union(*(aliases.expand(i) for i in watch.match))
    for entry in entries:
        vendor, product = entry.get('vendor', ''), entry.get('product', '')
        if not isinstance(vendor, str) or not isinstance(product, str):
            continue
        if is_placeholder(vendor) or is_placeholder(product):
            continue
        vendor, product = normalise(vendor), normalise(product)
        if product in watch.product_only or any(vendor == v or product == p for v, p in identities):
            return True
    return False


def watch_check(store, watches, aliases, days, now):
    for warning in aliases.warnings:
        print('alias warning: ' + warning)
    for collision in collisions(watches, aliases):
        print('collision: ' + collision)
    matched = {watch.id: [] for watch in watches}
    near = {watch.id: [] for watch in watches}
    cutoff = now - timedelta(days=days)
    rows = store.connection.execute('SELECT * FROM records ORDER BY id') if store else ()
    found = False
    for row in rows:
        found = True
        record = _record(row)
        text = record.get('cveMetadata', {}).get('datePublished') or row['ingested_at']
        try:
            if not isinstance(text, str):
                raise ValueError('Publication date must be a string')
            published = datetime.fromisoformat(text.replace('Z', '+00:00'))
            if published.tzinfo is None:
                published = published.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            published = datetime.fromisoformat(row['ingested_at'])
        if published < cutoff:
            continue
        kev = store.connection.execute('SELECT json FROM kev WHERE cve=?', (row['id'],)).fetchone()
        for watch in watches:
            result = resolve(record, json.loads(kev[0]) if kev else None, watch, aliases)
            if _active(result):
                matched[watch.id].append(row['id'])
            elif result is not None or _near(record, watch, aliases):
                near[watch.id].append(row['id'])
    if not found:
        print('no records ingested yet')
    for watch in watches:
        print(f'{watch.id}: matched {", ".join(matched[watch.id]) or "none"}; '
              f'near misses {", ".join(near[watch.id]) or "none"}')
    return 0


def replay(store, watches, aliases, path):
    document = tomllib.loads(path.read_text(encoding='utf-8'))
    expected = document.get('expect')
    if not isinstance(expected, list) or not expected:
        raise ValueError('Acceptance list requires [[expect]] entries')
    by_id = {watch.id: watch for watch in watches}
    entries = []
    for entry in expected:
        if (not isinstance(entry, dict) or set(entry) != {'watch_id', 'cve'}
                or not isinstance(entry['watch_id'], str) or entry['watch_id'] not in by_id
                or not isinstance(entry['cve'], str)
                or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', entry['cve'])):
            raise ValueError('Invalid acceptance entry')
        entries.append((by_id[entry['watch_id']], entry['cve']))
    success = True
    for watch, cve in entries:
        row = store.connection.execute('SELECT json FROM records WHERE id=?', (cve,)).fetchone()
        kev = store.connection.execute('SELECT json FROM kev WHERE cve=?', (cve,)).fetchone()
        record = _record(row) if row else {'cveMetadata': {'cveId': cve}}
        matched = _active(resolve(record, json.loads(kev[0]) if kev else None, watch, aliases))
        print(f'{watch.id} {cve}: {"matched" if matched else "not matched"}')
        success &= matched
    return 0 if success else 1


def _parser():
    parser = argparse.ArgumentParser(prog='cornicen')
    parser.add_argument('--config', type=Path,
                        default=Path(os.environ.get('CORNICEN_CONFIG', '/config/cornicen.toml')))
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'status', 'healthcheck', 'report'):
        commands.add_parser(name)
    watch = commands.add_parser('watch').add_subparsers(dest='watch_command', required=True)
    check = watch.add_parser('check')
    check.add_argument('--days', type=int, default=90)
    acceptance = commands.add_parser('replay')
    acceptance.add_argument('--list', type=Path, required=True)
    commands.add_parser('notify').add_subparsers(dest='notify_command', required=True).add_parser('test')
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    store = None
    config = None
    try:
        config = load_config(args.config, os.environ)
        now = lambda: datetime.now(timezone.utc)
        if args.command == 'notify':
            n = Notification('test-' + now().isoformat(), '', 'notification test', ('test',),
                             'normal', {'detail': 'Cornicen notification channel test'})
            delivered = _notifier(config).send(n)
            print('delivered' if delivered else 'delivery failed')
            return 0 if delivered else 1
        if args.command == 'watch' and not Path(config.db_path).is_file():
            if args.days <= 0:
                raise ValueError('days must be positive')
            return watch_check(None, load_watchlist(config.watchlist_path),
                               AliasMap.load(extra=config.aliases_path), args.days, now())
        if args.command != 'run' and not Path(config.db_path).is_file():
            print('unhealthy: database unavailable')
            return 1
        store = Store(config.db_path, read_only=args.command != 'run')
        if args.command == 'run':
            store.migrate()
        if args.command == 'healthcheck':
            healthy = container_healthy(store, now(), config)
            print('healthy' if healthy else 'unhealthy')
            return 0 if healthy else 1
        if args.command == 'status':
            sources = {'cvelist', 'kev', 'epss'}
            sources.update(row[0] for row in store.connection.execute('SELECT source FROM health'))
            for source in sorted(sources):
                state, detail = assess(source, store, now(), config)
                detail = safe_message(RuntimeError(detail), config.ntfy_token)
                print(f'{source}: {state}; {detail}')
            print('container: ' + ('healthy' if container_healthy(store, now(), config) else 'unhealthy'))
            print('reconcile: ' + (store.get_meta('reconcile_at') or 'none'))
            return 0
        if args.command == 'report':
            pair_columns = 'SELECT watch_id,record_id,state,alias_map_version FROM pairs WHERE '
            groups = (
                ('Baseline: affected', pair_columns + "baseline=1 AND state='affected'"),
                ('Baseline: exploited (unknown version)', pair_columns +
                 "baseline=1 AND state='unknown' AND exploited=1"),
                ('Open matches', pair_columns +
                 "baseline=0 AND (state='affected' OR (state='unknown' AND exploited=1))"),
                ('Not affected (recorded, no alert)', pair_columns + "state='not_affected'"),
                ('Dead letters', 'SELECT source,record_id,attempts FROM dead_letters'),
            )
            print('Summary: ' + '; '.join(
                f'{label}: {store.connection.execute("SELECT count(*) FROM (" + query + ")").fetchone()[0]}'
                for label, query in groups))
            for label, query in groups:
                print(label + ':')
                order = 'source,record_id' if label == 'Dead letters' else 'watch_id,record_id'
                for row in store.connection.execute(query + ' ORDER BY ' + order):
                    print(json.dumps(dict(row), sort_keys=True))
            return 0
        watches = load_watchlist(config.watchlist_path)
        aliases = AliasMap.load(extra=config.aliases_path)
        if args.command == 'watch':
            if args.days <= 0:
                raise ValueError('days must be positive')
            return watch_check(store, watches, aliases, args.days, now())
        if args.command == 'replay':
            return replay(store, watches, aliases, args.list)
        engine = Engine(store, watches, aliases, config, now, _notifier(config))
        http = Http(config.user_agent, config.user_agent_overrides,
                    data_dir=Path(config.db_path).parent,
                    download_budgets=config.download_budgets)
        return Scheduler(engine, {'cvelist': CveListSource(http, store),
                                  'kev': KevSource(http), 'epss': EpssSource(http, store)}).run()
    except Exception as error:
        message = safe_message(error, config.ntfy_token if config else None)
        print(f'command failed: {type(error).__name__}: {message}')
        return 1
    finally:
        if store is not None:
            store.connection.close()

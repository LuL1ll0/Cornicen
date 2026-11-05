"""Operator commands. Inventory diagnostics stay local and use stored records."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import tomllib
import zlib

from cornicen.applicability import resolve, State
from cornicen import accept
from cornicen.config import load_config
from cornicen.engine import Engine
from cornicen.fetch import Http
from cornicen.health import assess, container_healthy
from cornicen.identity import AliasMap, normalise, is_placeholder
from cornicen.maintenance import backup
from cornicen.model import Notification
from cornicen.notify.file import FileNotifier
from cornicen.notify.ntfy import NtfyNotifier, post
from cornicen.render import _clean_reason
from cornicen.scheduler import Scheduler, safe_message
from cornicen.sources.cvelist import CveListSource
from cornicen.sources.epss import EpssSource
from cornicen.sources.kev import KevSource
from cornicen.store import Store
from cornicen.watchlist import collisions, load_watchlist, load_document, WatchlistError
from cornicen.versions import Scheme, compare


EOL_COVERAGE_NOTICE = ('coverage limited: the vendor issues no advisories for unsupported versions; '
                       'absence of alerts is not evidence of safety')


def _eol_ids(config):
    try:
        return [watch.id for watch in load_watchlist(config.watchlist_path) if watch.eol]
    except (OSError, ValueError, WatchlistError):
        # Inventory diagnostics must remain available if the watch file cannot be loaded.
        return []


_notice_printed = False


def _coverage_notice(watch_ids, *, file=None):
    # Once per invocation: the error path re-prints only if a failure came before the notice.
    global _notice_printed
    if _notice_printed:
        return
    _notice_printed = True
    for watch_id in watch_ids:
        print(f'{watch_id}: {EOL_COVERAGE_NOTICE}', file=file)


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
    _coverage_notice(watch.id for watch in watches if watch.eol)
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


def explain(store, watches, aliases, cve, watch_id):
    watch = next((watch for watch in watches if watch.id == watch_id), None)
    if watch is None:
        print('unknown watch ID: ' + watch_id)
        return 1
    print(f'Current-file evaluation: {watch.id} {cve}; version={watch.version}; '
          f'scheme={watch.scheme.value}; alias_map_version={aliases.version}')
    pair = store.connection.execute(
        'SELECT * FROM pairs WHERE watch_id=? AND record_id=?', (watch_id, cve)).fetchone()
    print('Stored pair state: ' + (json.dumps(dict(pair), sort_keys=True) if pair else 'none'))
    row = store.connection.execute('SELECT json FROM records WHERE id=?', (cve,)).fetchone()
    if row is None:
        print('Current decision: retained record unavailable; applicability unknown')
        return 1
    kev = store.connection.execute('SELECT json FROM kev WHERE cve=?', (cve,)).fetchone()
    result = resolve(_record(row), json.loads(kev[0]) if kev else None, watch, aliases)
    if result is None:
        print('Current decision: identity miss; no identity match')
    else:
        print(f'Current decision: applicability={result.state.value}; '
              f'exploited={str(result.exploited).lower()}; confidence={result.confidence}')
        print('Evidence: ' + result.evidence)
    return 0


def outbox_list(store, failed):
    query = '''SELECT *, max(due_at,coalesce(next_attempt_at,due_at)) AS eligible_at
               FROM outbox WHERE sent_at IS NULL'''
    if failed:
        query += ' AND attempts > 0'
    count = 0
    for row in store.connection.execute(query + ' ORDER BY eligible_at,id'):
        body = json.loads(row['body_json'])
        item = {key: row[key] for key in ('id', 'urgency', 'enqueued_at', 'due_at',
                                         'attempts', 'next_attempt_at', 'eligible_at')}
        item.update(watch_id=body.get('watch_id'), record_id=body.get('record_id'),
                    component=None if body.get('watch_id') else body.get('record_id'),
                    pair_key=row['pair_key'], reasons=json.loads(row['reasons_json']),
                    revalidation='awaiting revalidation' if row['dirty'] else 'clean')
        if 'accepted' in body:
            item['accepted'] = body['accepted']
        if 'acceptance_lapsed' in body:
            item['acceptance_lapsed'] = body['acceptance_lapsed']
        print(json.dumps(item, sort_keys=True))
        count += 1
    print(f'Pending rows: {count}')
    return 0


def _accepted(config, store, now):
    watches, entries = load_document(config.watchlist_path)
    by_id = {watch.id.casefold(): watch for watch in watches}
    result = []
    for entry in entries:
        held = 0
        if store is not None and entry.watch.casefold() in by_id:
            for row in store.connection.execute(
                    'SELECT body_json FROM outbox WHERE pair_key=? AND sent_at IS NULL',
                    (f'{by_id[entry.watch.casefold()].id}|{entry.cve}',)):
                held += bool(json.loads(row[0]).get('accepted', {}).get('held'))
        result.append(dict(accept.detail(entry), watch_id=entry.watch, cve=entry.cve,
                           state=accept.state(entry, by_id, now, config.timezone), held=held))
    return result


def _accepted_text(entries):
    for entry in entries:
        until = entry['until'] or 'version change'
        if entry['until'] and entry['version'] is not None:
            until += ' or version change'
        print(f"accepted: {entry['watch_id']}/{entry['cve']} until {until} — "
              f"{entry['state']}; held {entry['held']}; {_clean_reason(entry['reason'])}")
    counts = [sum(e['state'] == state for e in entries) for state in ('active', 'unknown-watch')]
    print(f'accepted: {counts[0]} active, {len(entries) - sum(counts)} lapsed, {counts[1]} unknown watch')


def _accept_warnings(store, watches, entries, aliases, now, config):
    by_id = {watch.id.casefold(): watch for watch in watches}
    warnings = []
    for entry in entries:
        current = accept.state(entry, by_id, now, config.timezone)
        label = f'{entry.watch}/{entry.cve}'
        print(f'accepted: {label} — {current}; {_clean_reason(entry.reason)}')
        if current == 'unknown-watch':
            warnings.append(f'{label}: unknown watch id')
        elif current.startswith('lapsed'):
            warnings.append(f'{label}: lapsed ({accept.lapse_reason(current)})')
        if entry.until:
            from zoneinfo import ZoneInfo
            local_date = now.astimezone(ZoneInfo(config.timezone)).date()
            if (entry.until - local_date).days > config.accept_warn_days:
                warnings.append(f'{label}: long (more than {config.accept_warn_days} days)')
        if store is None:
            print(f'{label}: matches not checked (no database)')
        elif entry.watch.casefold() in by_id:
            row = store.connection.execute('SELECT json FROM records WHERE id=?', (entry.cve,)).fetchone()
            kev = store.connection.execute('SELECT json FROM kev WHERE cve=?', (entry.cve,)).fetchone()
            if row is None or not _active(resolve(_record(row), json.loads(kev[0]) if kev else None,
                                                  by_id[entry.watch.casefold()], aliases)):
                warnings.append(f'{label}: matches nothing')
    for warning in warnings:
        print('accept warning: ' + warning)
    return warnings


def github_status(store):
    auth = store.get_meta('github_auth') if store else None
    problem = None
    if auth in ('token', 'none'):
        mode = auth
    elif auth == 'token rejected':
        mode = 'token-rejected'
    elif auth and auth.startswith('token unusable: '):
        mode, problem = 'token-unusable', auth.removeprefix('token unusable: ')
    else:
        mode = 'unknown'
    rate = store.get_meta('github_rate_limit') if store else None
    try:
        rate = json.loads(rate) if rate else None
        if not isinstance(rate, dict) or set(rate) != {'limit', 'remaining', 'reset', 'observed_at'}:
            raise ValueError('Invalid rate limit shape')
        if any(type(rate[key]) is not int for key in ('limit', 'remaining')):
            raise ValueError('Invalid rate limit counts')
        for key in ('reset', 'observed_at'):
            stamp = datetime.fromisoformat(rate[key])
            if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
                raise ValueError('Rate limit timestamps must be UTC')
    except (ValueError, TypeError, OverflowError, RecursionError):
        rate = None
    return dict(auth=mode, problem=problem, rate_limit=rate)


def github_status_line(store):
    state = github_status(store)
    descriptions = {
        'token': 'authenticated', 'none': 'unauthenticated', 'unknown': 'authentication unknown',
        'token-unusable': f"token unusable ({state['problem']}), using unauthenticated access",
        'token-rejected': 'token rejected by GitHub (HTTP 401), using unauthenticated access; replace the token file and restart',
    }
    rate = state['rate_limit']
    detail = 'rate limit not seen yet'
    if rate:
        reset = datetime.fromisoformat(rate['reset']).astimezone(timezone.utc).strftime('%H:%M')
        observed = datetime.fromisoformat(rate['observed_at']).astimezone(timezone.utc).strftime('%H:%M')
        detail = f"rate limit {rate['remaining']}/{rate['limit']}, resets {reset} UTC (seen {observed} UTC)"
    return 'github: ' + descriptions[state['auth']] + '; ' + detail


def status_json(store, now, config):
    result = dict(schema_version=1, available=False, container_healthy=False,
                  sources={}, baseline_complete=False, reconcile_at=None, github=github_status(store))
    eol_ids = _eol_ids(config) if config else []
    if eol_ids:
        result['eol_coverage_limited'] = eol_ids
    if config is not None:
        try:
            entries = _accepted(config, store, now or datetime.now(timezone.utc))
            result['accepted'] = entries
        except WatchlistError:
            pass
    if store is not None:
        sources = {'cvelist', 'kev', 'epss'}
        sources.update(row[0] for row in store.connection.execute('SELECT source FROM health'))
        for source in sorted(sources):
            state, detail = assess(source, store, now, config)
            cursor = store.connection.execute(
                'SELECT value,content_time FROM cursors WHERE source=?', (source,)).fetchone()
            result['sources'][source] = dict(
                state=state, detail=safe_message(RuntimeError(detail), config.ntfy_token, config.github_token),
                cursor=cursor['value'] if cursor else None,
                content_time=cursor['content_time'] if cursor else None)
        result.update(available=True, container_healthy=container_healthy(store, now, config),
                      baseline_complete=bool(store.get_meta('baseline_complete')),
                      reconcile_at=store.get_meta('reconcile_at'))
    print(json.dumps(result, sort_keys=True))
    return 0 if result['available'] else 1


REPORT_GROUPS = ('baseline-affected', 'baseline-exploited', 'open', 'not-affected', 'dead-letters')


def report(store, args, eol_ids=(), config=None, now=None):
    accepted = None
    if config is not None:
        try:
            accepted = _accepted(config, store, now or datetime.now(timezone.utc))
        except WatchlistError:
            pass
    by_pair = {(e['watch_id'].casefold(), e['cve']): e for e in accepted or ()}

    def annotation(row):
        entry = by_pair.get((row['watch_id'].casefold(), row['record_id']))
        return {key: entry[key] for key in ('reason', 'until', 'version', 'state')} if entry else None

    def silent(row):
        entry = annotation(row)
        if not entry or entry['state'] != 'active':
            return False
        pair = store.connection.execute('SELECT exploited FROM pairs WHERE watch_id=? AND record_id=?',
                                        (row['watch_id'], row['record_id'])).fetchone()
        return bool(pair and not pair[0])

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
    selected = []
    for (group, (label, query)) in zip(REPORT_GROUPS, groups):
        if args.group and group not in args.group:
            continue
        params = ()
        if args.watch:
            if group == 'dead-letters':
                continue
            query += ' AND watch_id IN (' + ','.join('?' for _ in args.watch) + ')'
            params = tuple(args.watch)
        selected.append((group, label, query, params))
    if args.format == 'text':
        counts, accepted_count = [], 0
        for group, label, query, params in selected:
            rows = list(store.connection.execute(query, params))
            excluded = sum(silent(row) for row in rows) if group in REPORT_GROUPS[:3] else 0
            accepted_count += excluded
            counts.append(f'{label}: {len(rows) - excluded}')
        if accepted:
            counts.append(f'Accepted (not alerting): {accepted_count}')
        print('Summary: ' + '; '.join(counts))
        _coverage_notice(eol_ids)
    else:
        _coverage_notice(eol_ids, file=sys.stderr)
    if config is not None and accepted is None:
        print('accepted: not applied (watch list unreadable)',
              file=sys.stderr)
    for group, label, query, params in selected:
        if args.format == 'text':
            print(label + ':')
        order = 'source,record_id' if group == 'dead-letters' else 'watch_id,record_id'
        for row in store.connection.execute(query + ' ORDER BY ' + order, params):
            item = dict(row)
            if accepted is not None and group != 'dead-letters':
                item['accepted'] = annotation(row)
            if args.format == 'jsonl':
                item.update(schema_version=1, group=group)
            print(json.dumps(item, sort_keys=True))
    return 0


def _parser():
    parser = argparse.ArgumentParser(prog='cornicen')
    parser.add_argument('--config', type=Path,
                        default=Path(os.environ.get('CORNICEN_CONFIG', '/config/cornicen.toml')))
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('run', 'healthcheck'):
        commands.add_parser(name)
    report_parser = commands.add_parser('report')
    report_parser.add_argument('--watch', action='append')
    report_parser.add_argument('--group', choices=REPORT_GROUPS, action='append')
    report_parser.add_argument('--format', choices=('text', 'jsonl'), default='text')
    db = commands.add_parser('db').add_subparsers(dest='db_command', required=True)
    db.add_parser('backup').add_argument('--output', type=Path, required=True)
    version = commands.add_parser('version').add_subparsers(dest='version_command', required=True)
    comparison = version.add_parser('compare')
    comparison.add_argument('left')
    comparison.add_argument('right')
    comparison.add_argument('--scheme', choices=[scheme.value for scheme in Scheme], required=True)
    commands.add_parser('status').add_argument('--json', action='store_true')
    explanation = commands.add_parser('explain')
    explanation.add_argument('cve')
    explanation.add_argument('--watch', required=True)
    queue = commands.add_parser('outbox').add_subparsers(dest='outbox_command', required=True)
    queue.add_parser('list').add_argument('--failed', action='store_true')
    watch = commands.add_parser('watch').add_subparsers(dest='watch_command', required=True)
    check = watch.add_parser('check')
    check.add_argument('--days', type=int, default=90)
    check.add_argument('--file', type=Path)
    check.add_argument('--strict', action='store_true')
    acceptance = commands.add_parser('replay')
    acceptance.add_argument('--list', type=Path, required=True)
    commands.add_parser('notify').add_subparsers(dest='notify_command', required=True).add_parser('test')
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    store = None
    config = None
    global _notice_printed
    _notice_printed = False
    eol_ids = []
    notice_file = None
    try:
        if args.command == 'version':
            scheme = Scheme(args.scheme)
            left, right = args.left, args.right
            if scheme == Scheme.OPAQUE:
                left, right = normalise(left), normalise(right)
            relation = compare(left, right, scheme)
            print('unknown' if relation is None else
                  'less' if relation < 0 else 'greater' if relation > 0 else 'equal')
            return 1 if relation is None else 0
        # Diagnostic processes read daemon state, never the GitHub secret file.
        env = os.environ if args.command == 'run' else {
            key: value for key, value in os.environ.items() if key != 'CORNICEN_GITHUB_TOKEN_FILE'}
        config = load_config(args.config, env)
        now = lambda: datetime.now(timezone.utc)
        if args.command == 'notify':
            n = Notification('test-' + now().isoformat(), '', 'notification test', ('test',),
                             'normal', {'detail': 'Cornicen notification channel test'})
            delivered = _notifier(config).send(n)
            print('delivered' if delivered else 'delivery failed')
            return 0 if delivered else 1
        if args.command == 'watch':
            if args.days <= 0:
                raise ValueError('days must be positive')
            path = args.file if args.file is not None else config.watchlist_path
            # Keep the public validation path used by existing CLI integrations.
            load_watchlist(path)
            watches, accepts = load_document(path)
            eol_ids = [watch.id for watch in watches if watch.eol]
            aliases = AliasMap.load(extra=config.aliases_path)
            if Path(config.db_path).is_file():
                store = Store(config.db_path, read_only=True)
            watch_check(store, watches, aliases, args.days, now())
            warnings = _accept_warnings(store, watches, accepts, aliases, now(), config)
            return 1 if args.strict and (aliases.warnings or collisions(watches, aliases) or warnings) else 0
        if args.command == 'report' or (args.command == 'status' and not args.json):
            eol_ids = _eol_ids(config)
            if args.command == 'report':
                eol_ids = [watch_id for watch_id in eol_ids
                           if not args.watch or watch_id in args.watch]
                notice_file = sys.stderr if args.format == 'jsonl' else None
        if args.command != 'run' and not Path(config.db_path).is_file():
            if args.command == 'status' and args.json:
                return status_json(None, now(), config)
            print('unhealthy: database unavailable')
            _coverage_notice(eol_ids, file=notice_file)
            return 1
        store = Store(config.db_path, read_only=args.command != 'run')
        if args.command == 'run':
            store.migrate()
        if args.command == 'healthcheck':
            healthy = container_healthy(store, now(), config)
            print('healthy' if healthy else 'unhealthy')
            return 0 if healthy else 1
        if args.command == 'status':
            if args.json:
                return status_json(store, now(), config)
            sources = {'cvelist', 'kev', 'epss'}
            sources.update(row[0] for row in store.connection.execute('SELECT source FROM health'))
            for source in sorted(sources):
                state, detail = assess(source, store, now(), config)
                detail = safe_message(RuntimeError(detail), config.ntfy_token, config.github_token)
                print(f'{source}: {state}; {detail}')
            print(github_status_line(store))
            print('container: ' + ('healthy' if container_healthy(store, now(), config) else 'unhealthy'))
            print('reconcile: ' + (store.get_meta('reconcile_at') or 'none'))
            try:
                _accepted_text(_accepted(config, store, now()))
            except WatchlistError:
                print('accepted: not checked (watch list unreadable)')
            _coverage_notice(eol_ids)
            return 0
        if args.command == 'outbox':
            return outbox_list(store, args.failed)
        if args.command == 'report':
            return report(store, args, eol_ids, config, now())
        if args.command == 'db':
            backup(store.connection, args.output)
            print('SQLite backup created: ' + str(args.output))
            print('Back up watch/config/alias files separately.')
            return 0
        watches, accepts = load_document(config.watchlist_path)
        aliases = AliasMap.load(extra=config.aliases_path)
        if args.command == 'explain':
            return explain(store, watches, aliases, args.cve, args.watch)
        if args.command == 'replay':
            return replay(store, watches, aliases, args.list)
        engine = Engine(store, watches, aliases, config, now, _notifier(config), accepts=accepts)
        http = Http(config.user_agent, config.user_agent_overrides,
                    data_dir=Path(config.db_path).parent,
                    download_budgets=config.download_budgets, github_token=config.github_token)
        return Scheduler(engine, {'cvelist': CveListSource(http, store, config.github_token_problem, ntfy_token=config.ntfy_token),
                                  'kev': KevSource(http), 'epss': EpssSource(http, store)}).run()
    except Exception as error:
        if args.command == 'status' and args.json:
            return status_json(None, None, config)
        if (args.command == 'watch' and isinstance(error, WatchlistError)
                and (args.file is not None or args.strict
                     or any(problem.startswith('accept entry ') for problem in error.problems))):
            for problem in error.problems:
                print('watch validation error: ' + problem)
            return 1
        message = safe_message(error, config.ntfy_token if config else None, config.github_token if config else None)
        print(f'command failed: {type(error).__name__}: {message}')
        _coverage_notice(eol_ids, file=notice_file)
        return 1
    finally:
        if store is not None:
            store.connection.close()

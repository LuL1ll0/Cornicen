"""Read-only source and outbox health, independent of notification activity."""

from datetime import datetime, timedelta, timezone

from cornicen.validate import error_detail


def _time(value):
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def coverage_problem(source, store, now):
    cursor = store.connection.execute('SELECT value,content_time FROM cursors WHERE source=?', (source,)).fetchone()
    if not cursor or not cursor['content_time']:
        started = store.get_meta('bootstrap_started_at')
        if store.get_meta('baseline_complete') or (source == 'cvelist' and started
                and now - _time(started) > timedelta(hours=2)):
            return 'No completed fetch; bootstrap grace period expired'
        return None
    try:
        age = now - _time(cursor['content_time'])
        if age < -timedelta(hours=2):
            return 'Source content is more than 2 hours in the future'
        if source == 'cvelist' and cursor['value']:
            from cornicen.validate import TAG, release_stamp
            if TAG.fullmatch(cursor['value']) and release_stamp(cursor['value']) > now + timedelta(hours=2):
                return 'Persisted CVE cursor is more than 2 hours in the future'
    except (TypeError, ValueError):
        return 'Invalid content time'
    limit = {'cvelist': timedelta(hours=3), 'epss': timedelta(days=2)}.get(source)
    if limit is not None and age > limit:
        return 'Source content is stale'
    return None


def assess(source, store, now, config):
    if source == 'projection':
        from cornicen.store import PROJECTION_REVISION
        complete = store.get_meta('applied_projection_revision') == str(PROJECTION_REVISION)
        if not complete:
            return 'unhealthy', 'incomplete'
        skipped = int(store.get_meta('projection_skipped_records') or 0)
        return 'healthy', f'complete; {skipped} records skipped' if skipped > 0 else 'complete'
    row = store.connection.execute('SELECT state,detail FROM health WHERE source=?', (source,)).fetchone()
    if row and row['state'] == 'unhealthy':
        detail = row['detail'] or 'Incomplete fetch'
        last_error = store.get_meta('last_error:' + source)
        if last_error and 'last error:' not in detail:
            detail += '; last error: ' + error_detail(last_error)
        return 'unhealthy', detail
    if source not in ('cvelist', 'kev', 'epss'):
        return 'healthy', row['detail'] if row else 'No fetch failure'
    problem = coverage_problem(source, store, now)
    if problem:
        return 'unhealthy', problem
    cursor = store.connection.execute('SELECT content_time FROM cursors WHERE source=?', (source,)).fetchone()
    if not cursor or not cursor[0]:
        detail = 'Baseline pending'
    elif source == 'kev':
        days = max(0, (now - _time(cursor[0])).days)
        detail = f'Complete fetch; catalog {days} {"day" if days == 1 else "days"} old'
    else:
        detail = 'Complete fetch; content age within source policy'
    if source == 'cvelist' and store.get_meta('reconcile_at'):
        detail += '; full-snapshot reconcile: ' + store.get_meta('reconcile_at')
    return 'healthy', detail


def active_sources(store, config):
    return {row[0] for row in store.connection.execute('SELECT source FROM health')
            if row[0] != 'deadman' or config.deadman_url is not None}


def container_healthy(store, now, config):
    sources = {'cvelist', 'kev', 'epss'}
    sources.update(active_sources(store, config) - {'deadman'})
    if any(assess(source, store, now, config)[0] == 'unhealthy' for source in sources):
        return False
    for row in store.connection.execute('SELECT due_at FROM outbox WHERE sent_at IS NULL'):
        try:
            if now - _time(row[0]) > timedelta(minutes=config.overdue_minutes):
                return False
        except (TypeError, ValueError):
            return False
    return True

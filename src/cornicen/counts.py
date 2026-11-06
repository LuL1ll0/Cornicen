"""Report summary counts from small pair and dead-letter tables only."""

from cornicen import accept


REPORT_KEYS = ('affected', 'exploited_unknown', 'open', 'dead_letters', 'accepted')
COUNT_QUERIES = {
    'baseline-affected': ('affected', "SELECT watch_id,record_id,exploited FROM pairs WHERE baseline=1 AND state='affected'"),
    'baseline-exploited': ('exploited_unknown', "SELECT watch_id,record_id,exploited FROM pairs WHERE baseline=1 AND state='unknown' AND exploited=1"),
    'open': ('open', "SELECT watch_id,record_id,exploited FROM pairs WHERE baseline=0 AND (state='affected' OR (state='unknown' AND exploited=1))"),
    'not-affected': ('not_affected', "SELECT count(*) FROM pairs WHERE state='not_affected'"),
    'dead-letters': ('dead_letters', 'SELECT count(*) FROM dead_letters'),
}


def report_counts(db, watches, entries, now, timezone, *, groups=None, watch_ids=None):
    """Apply the report filters and subtract active non-exploited accepts."""
    by_id = {watch.id.casefold(): watch for watch in watches}
    states = {(entry.watch.casefold(), entry.cve): accept.state(entry, by_id, now, timezone)
              for entry in entries}
    counts = dict.fromkeys((*REPORT_KEYS, 'not_affected'), 0)
    for group, (key, query) in COUNT_QUERIES.items():
        if groups and group not in groups:
            continue
        params = ()
        if watch_ids:
            if group == 'dead-letters':
                continue
            query += ' AND watch_id IN (' + ','.join('?' for _ in watch_ids) + ')'
            params = tuple(watch_ids)
        rows = db.execute(query, params)
        if group in ('not-affected', 'dead-letters'):
            counts[key] = rows.fetchone()[0]
            continue
        for row in rows:
            if (not row['exploited']
                    and states.get((row['watch_id'].casefold(), row['record_id'])) == 'active'):
                counts['accepted'] += 1
            else:
                counts[key] += 1
    return counts

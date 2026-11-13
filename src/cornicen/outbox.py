"""Durable delivery of due notifications with bounded exponential retries."""

from datetime import timedelta
from dataclasses import asdict
from hashlib import sha256
import json

from cornicen.model import Notification


def deliver(store, notifier, clock, ready, *, revalidate=None):
    """Send due rows, acknowledging all digest members in one transaction."""
    db, sent = store.connection, 0
    normal, groups = [], []
    for row in ready:
        if row['urgency'] == 'normal' and json.loads(row['body_json']).get('watch_id'):
            normal.append(row)
        else:
            groups.append([row])
    if normal:
        # Severity is CNA CVSS first, then EPSS probability; stable ID breaks ties.
        normal.sort(key=lambda r: (-json.loads(r['body_json']).get('severity', 0),
            -(json.loads(r['body_json']).get('epss') or {}).get('score', -1), r['id']))
        groups.append(normal)
    groups.sort(key=lambda rows: min(r['id'] for r in rows))
    for rows in groups:
        if revalidate is not None:
            current = revalidate(rows)
            if not current:
                continue
            is_normal = lambda r: r['urgency'] == 'normal' and json.loads(r['body_json']).get('watch_id')
            if any(bool(is_normal(row)) != (rows is normal) for row in current):
                sent += deliver(store, notifier, clock, current, revalidate=revalidate)
                continue
            rows[:] = current
            if rows is normal:
                normal.sort(key=lambda r: (-json.loads(r['body_json']).get('severity', 0),
                    -(json.loads(r['body_json']).get('epss') or {}).get('score', -1), r['id']))
        items = []
        for row in rows:
            body = json.loads(row['body_json'])
            items.append(Notification(str(row['id']), body.get('watch_id', ''), body['record_id'],
                tuple(json.loads(row['reasons_json'])), row['urgency'], body))
        n = items[0]
        if rows is normal:
            # Membership and keys derive from durable rows; failed sends mark none sent.
            key = 'digest-' + sha256(','.join(str(r['id']) for r in sorted(rows, key=lambda r: r['id'])).encode()).hexdigest()[:24]
            n = Notification(key, n.watch_id if len(items) == 1 else '',
                n.record_id if len(items) == 1 else 'digest',
                n.reasons if len(items) == 1 else ('digest',), 'normal',
                {'items': [asdict(item) for item in items]})
        # Network I/O must never hold a database transaction or touch ingest retries.
        try:
            delivered = notifier.send(n)
        except Exception:
            delivered = False
        with store.transaction():
            for row, item in zip(rows, items):
                if delivered:
                    if (item.watch_id and item.body.get('state') == 'affected'
                            and item.urgency == 'urgent' and item.body.get('epss')
                            and item.body['epss']['score'] >= item.body.get('epss_threshold', .10)):
                        db.execute('''UPDATE epss_crossings SET fired=1
                            WHERE watch_id=? AND record_id=? AND threshold=?
                            AND EXISTS (SELECT 1 FROM epss_crossing_scores e
                                WHERE e.cve=record_id AND e.score>=threshold)''',
                                   (item.watch_id, item.record_id, item.body.get('epss_threshold', .10)))
                    db.execute('UPDATE outbox SET sent_at=?,attempts=attempts+1 WHERE id=?',
                                    (clock().isoformat(), row['id']))
                    if item.watch_id and set(item.reasons) & {'new match', 'KEV added', 'acceptance lapsed'}:
                        db.execute('UPDATE pairs SET notified=1 WHERE watch_id=? AND record_id=?',
                                        (item.watch_id, item.record_id))
                else:
                    delay = min(60 * 2 ** min(row['attempts'], 6), 3600)
                    db.execute('UPDATE outbox SET attempts=attempts+1,next_attempt_at=? WHERE id=?',
                                    ((clock() + timedelta(seconds=delay)).isoformat(), row['id']))
            if delivered:
                sent += 1

    return sent


class Outbox:
    def __init__(self, store, notifier, clock, *, engine=None):
        self.store, self.notifier, self.clock = store, notifier, clock
        self.engine = engine

    def flush(self):
        if self.engine is not None:
            before = self.engine.report.sent
            self.engine._flush()
            return self.engine.report.sent - before
        now = self.clock().isoformat()
        ready = self.store.connection.execute('''SELECT * FROM outbox INDEXED BY outbox_ready WHERE sent_at IS NULL
            AND max(due_at,coalesce(next_attempt_at,due_at))<=? ORDER BY id''', (now,)).fetchall()
        return deliver(self.store, self.notifier, self.clock, ready)

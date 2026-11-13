"""Plain notification text shared by the engine and delivery adapters."""

from datetime import datetime, timezone
from decimal import Decimal
import re
import unicodedata

from cornicen.model import Notification


_EOL = 'unsupported by the vendor — fixes unlikely; isolate or replace'

_HEALTH_MESSAGES = {
    'acceptance': 'acceptance self-test failed',
    'cvelist': 'CVE List ingest failed',
    'kev': 'KEV fetch failed',
    'epss': 'EPSS fetch failed',
    'engine': 'processing cycle failed',
    'scheduler': 'scheduler cycle failed',
    'watchlist': 'watch list reload rejected',
    'records': 'stored record missing',
}


_HEALTH_REASONS = frozenset(('failed', 'incomplete', 'stale', 'future-dated',
                             'rejected', 'missing', 'recovered'))


def health_body(component, state, error=None, reason=None, since=None):
    """Allow only operational metadata across the notifier boundary."""
    state = 'healthy' if state == 'healthy' else 'unhealthy'
    body = {'record_id': component, 'state': state,
            'detail': 'component recovered' if state == 'healthy' else
                      _HEALTH_MESSAGES.get(component, 'component health failed')}
    reason = ('recovered' if state == 'healthy' else
              reason if isinstance(reason, str) and reason in _HEALTH_REASONS - {'recovered'} else
              {'watchlist': 'rejected', 'records': 'missing'}.get(component, 'failed'))
    body['reason'] = reason
    if isinstance(since, str) and re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})', since):
        try:
            body['since'] = datetime.fromisoformat(since.replace('Z', '+00:00')).astimezone(
                timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
        except ValueError:
            pass
    if isinstance(error, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,99}', error):
        body['error'] = error
    return body


def _ordinal(value):
    suffix = 'th' if 10 <= value % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(value % 10, 'th')
    return f'{value}{suffix}'


def _percentage(score, threshold):
    value = Decimal(str(score)) * 100
    boundary = Decimal(str(threshold)) * 100
    precision = 2
    text = format(value, f'.{precision}g')
    # Preserve which side of the configured urgency threshold the score is on.
    while value < boundary <= Decimal(text):
        precision += 1
        text = format(value, f'.{precision}g')
    return format(Decimal(text), 'f')


def render(n: Notification) -> tuple[str, str, int, list[str]]:
    body = n.body
    if 'items' in body:
        items = [Notification(**({'watch_id': '', **item})) for item in body['items']]
        if len(items) == 1:
            title, text, _, _ = render(items[0])
            return 'Cornicen digest: 1 items', title + '\n' + text, 3, ['information_source']
        return _digest(items)
    if not n.watch_id:
        state = next((reason for reason in n.reasons if reason in ('healthy', 'unhealthy')), None)
        title = f'Cornicen: {n.record_id}'
        detail = body.get('detail', ' · '.join(n.reasons))
        if state:
            body = health_body(n.record_id, state, reason=body.get('reason'), since=body.get('since'))
            title = f'Cornicen: {body["record_id"]}'
            title += ' recovered' if state == 'healthy' else ' unhealthy'
            detail = f'{body["record_id"]}: recovered' if state == 'healthy' else (
                f'{body["record_id"]}: unhealthy — {body["reason"]}'
                + (f' since {body["since"]}' if 'since' in body else ''))
        return title, detail, 5 if state == 'unhealthy' else 3, ['information_source']
    name, product, version = _inventory(n)
    title = f'Cornicen: {n.record_id} — {name} ({product} {version})'
    if n.urgency == 'urgent':
        title = '🚨 ' + title
    lines = ['EOL: ' + _EOL] if body.get('eol') else []
    lines.append('Why: ' + ' · '.join(n.reasons))
    accepted = body.get('accepted')
    lapsed = body.get('acceptance_lapsed')
    if accepted and not accepted.get('held'):
        until = accepted.get('until') or 'version change'
        why = 'KEV listed' if body.get('kev') or 'KEV added' in n.reasons else 'exploited'
        lines.append(f"Accepted: {_clean_reason(accepted['reason'])} (until {until}) — alerting anyway: {why}")
    if lapsed:
        lines.append(f"Acceptance lapsed ({lapsed['why']}): {_clean_reason(lapsed['reason'])}")
    kev = body.get('kev')
    if kev:
        text = f'KEV: listed {kev.get("dateAdded", "date unknown")}, CISA due {kev.get("dueDate", "not stated")}'
        if kev.get('knownRansomwareCampaignUse') == 'Known':
            text += ' · known ransomware use'
        lines.append(text)
    else:
        lines.append('KEV: not listed')
    ssvc = body.get('ssvc')
    if ssvc:
        lines.append('SSVC (CISA): exploitation ' + ssvc.get('Exploitation', 'unknown')
                     + ' · automatable ' + ssvc.get('Automatable', 'unknown')
                     + ' · technical impact ' + ssvc.get('Technical Impact', 'unknown'))
    else:
        lines.append('SSVC: not assessed')
    epss = body.get('epss')
    if epss:
        percent = _percentage(epss['score'], body.get('epss_threshold', .10))
        percentile = _ordinal(round(epss['pct'] * 100))
        lines.append(f'EPSS {percent}% ({percentile} pct, {epss.get("date") or "date unknown"})')
    else:
        lines.append('EPSS: not yet scored')
    state = body.get('state', 'unknown').replace('_', ' ')
    lines.append(f'Match: {body.get("evidence", "evidence unknown")} — {state}')
    if body.get('fix'):
        lines.append('Fix: ' + body['fix'])
    lines.append('https://www.cve.org/CVERecord?id=' + n.record_id)
    cve_title = body.get('cve_title')
    if isinstance(cve_title, str):
        cve_title = ' '.join(''.join(
            ' ' if unicodedata.category(char).startswith('C') else char
            for char in cve_title).split())[:160]
    else:
        cve_title = None
    lines.append('CVE title: ' + (cve_title or 'unknown'))
    score = body.get('cna_cvss_score')
    lines.append('CNA CVSS score: ' + (str(score) if type(score) in (int, float) else 'unknown'))
    return title, '\n'.join(lines), 5 if n.urgency == 'urgent' else 3, ['rotating_light'] if n.urgency == 'urgent' else ['information_source']


def _clean_reason(reason):
    return ' '.join(''.join(' ' if unicodedata.category(char).startswith('C') else char
                            for char in reason).split())[:160]


def _epss_score(item):
    return (item.body.get('epss') or {}).get('score', -1)


def _inventory(item):
    """Use the same inventory defaults in individual titles and block context."""
    return (item.body.get('name', item.watch_id),
            item.body.get('product', 'product unknown'),
            item.body.get('version', 'version unknown'))


def _digest(items):
    """Group presentation only; leave durable membership and row ordering alone."""
    watches = {}
    for item in items:
        watches.setdefault(item.watch_id, []).append(item)
    kinds = (('new match', 'new matches'), ('KEV added', 'KEV added'),
             ('correction', 'correction'), ('acceptance lapsed', 'acceptance lapsed'))
    counts = [(sum(kind in item.reasons for item in items), label) for kind, label in kinds]
    summary = f'{len(items)} items on {len(watches)} watches'
    present = [f'{count} {label}' for count, label in counts if count]
    if present:
        summary += ': ' + ', '.join(present)
    blocks = [summary]
    ordered = sorted(watches, key=lambda watch: (
        -max(item.body.get('severity', 0) for item in watches[watch]),
        -max(_epss_score(item) for item in watches[watch]),
        (watch is not None, watch or '')))
    for watch in ordered:
        members = sorted(watches[watch],
                         key=lambda item: (-_epss_score(item), item.record_id) + (item.key,))
        representative = next((item for item in members if 'correction' not in item.reasons), members[0])
        inventory = _inventory(representative)
        name, product, version = inventory
        header = f'{name} ({product} {version}): {len(members)} items'
        lines = [header]
        for index, item in enumerate(members):
            body = item.body
            if (index < 3 or 'correction' in item.reasons or 'acceptance lapsed' in item.reasons
                    or body.get('acceptance_lapsed') or body.get('eol')
                    or _inventory(item) != inventory or not item.watch_id):
                title, text, _, _ = render(item)
                lines.append(title + '\n' + text)
            else:
                epss = body.get('epss')
                score = ('EPSS ' + _percentage(epss['score'], body.get('epss_threshold', .10)) + '%'
                         if epss else 'EPSS: not yet scored')
                state = body.get('state', 'unknown').replace('_', ' ')
                kev = 'KEV listed' if body.get('kev') else 'KEV not listed'
                ssvc = body.get('ssvc')
                active = isinstance(ssvc, dict) and ssvc.get('Exploitation') == 'active'
                lines.append(f'{item.record_id} — {score} · {state} · {kev}'
                             + (' · SSVC exploitation active' if active else ''))
        blocks.append('\n'.join(lines))
    return f'Cornicen digest: {len(items)} items', '\n\n'.join(blocks), 3, ['information_source']

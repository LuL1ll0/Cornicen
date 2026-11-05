"""Plain notification text shared by the engine and delivery adapters."""

from datetime import datetime, timezone
from decimal import Decimal
import re
import unicodedata

from cornicen.model import Notification


_EOL = 'unsupported by the vendor — fixes unlikely; isolate or replace'

_HEALTH_MESSAGES = {
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
        blocks = []
        for item in body['items']:
            title, text, _, _ = render(Notification(**item))
            blocks.append(title + '\n' + text)
        return f'Cornicen digest: {len(blocks)} items', '\n\n'.join(blocks), 3, ['information_source']
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
    title = f'Cornicen: {n.record_id} — {body.get("name", n.watch_id)} ({body.get("product", "product unknown")} {body.get("version", "version unknown")})'
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

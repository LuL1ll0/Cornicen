"""Read stored unknown pairs and build the optional digest section."""

from collections import Counter, defaultdict
import unicodedata

from cornicen import accept, adapters
from cornicen.render import _clean_reason
from cornicen.versions import Scheme


_COMPARE = {
    'version comparison unknown', 'opaque range comparison unknown',
    'wildcard line comparison unknown', 'wildcard line below its first release',
    'opaque status changes require ordering',
}
_MALFORMED = {
    'version fields outside versions[]', 'invalid defaultStatus', 'invalid versions',
    'invalid version entry', 'missing version', 'invalid changes', 'invalid change entry',
    'invalid change boundary', 'invalid change status', 'invalid boundary', 'invalid status',
    'invalid version', 'invalid lessThan', 'invalid lessThanOrEqual', 'invalid versionType',
}


def classify(evidence) -> str:
    """Give a best-effort label without exposing the stored evidence."""
    if evidence is None:
        return 'other'
    if evidence.startswith('Product-only identity match'):
        return 'product only'
    if evidence == 'Invalid CNA record metadata':
        return 'malformed record'
    if evidence == 'No matching scoped evidence; applicability unknown':
        return 'vendor advisory'
    source, delimiter, _ = evidence.partition(': ')
    if delimiter and source in adapters.REGISTRY:
        for segment in evidence.split('; '):
            source, delimiter, state = segment.partition(': ')
            if not delimiter or source not in adapters.REGISTRY or state not in (
                    'affected', 'not_affected', 'unknown'):
                break
            if state == 'unknown':
                return 'vendor advisory'
        return 'other'
    if not evidence.startswith('CNA unknown ') or '; CNA ' in evidence:
        return 'other'
    detail = evidence.partition(': ')[2]
    if detail in _COMPARE:
        return 'version compare unknown'
    if detail.startswith('versionType ') and any(
            detail.endswith(' conflicts with ' + scheme.value) for scheme in Scheme):
        return 'scheme mismatch'
    if detail in _MALFORMED:
        return 'malformed record'
    if detail.startswith("outside every range the CNA listed; the CNA's default says affected"):
        return 'default says affected'
    if detail.startswith('defaultStatus '):
        return 'no version data'
    return 'CNA says unknown'


def rows(db, watch_ids):
    """Select stored unknown pairs for the current watches, including accepts."""
    if watch_ids:
        for row in db.execute("""SELECT watch_id, record_id, state, alias_map_version, evidence,
                score FROM pairs LEFT JOIN epss ON cve = record_id
                WHERE state='unknown' AND exploited = 0 ORDER BY watch_id, record_id"""):
            if row['watch_id'] is not None and row['watch_id'].casefold() in watch_ids:
                yield row


def _why(counts):
    return [[label, n] for label, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _safe_id(record_id):
    safe = ''.join('?' if unicodedata.category(char).startswith('C') or char in '  '
                   else char for char in record_id)
    return safe if len(safe) <= 80 else safe[:77] + '...'


def section(db, watches, entries, now, timezone) -> dict | None:
    by_id = {watch.id.casefold(): watch for watch in watches}
    active = {(entry.watch.casefold(), entry.cve) for entry in entries
              if accept.state(entry, by_id, now, timezone) == 'active'}
    groups = defaultdict(list)
    totals = Counter()
    for row in rows(db, by_id):
        watch_id = row['watch_id'].casefold()
        if (watch_id, row['record_id']) in active:
            continue
        label = classify(row['evidence'])
        groups[watch_id].append((row['record_id'], row['score'], label))
        totals[label] += 1
    if not groups:
        return None
    blocks = []
    for watch_id in sorted(groups, key=lambda key: (-len(groups[key]), key))[:8]:
        watch, members = by_id[watch_id], groups[watch_id]
        product = watch.match[0][1] if watch.match else watch.product_only[0]
        ordered = sorted(members, key=lambda item: (item[1] is None, -(item[1] or 0), item[0]))
        blocks.append(dict(name=_clean_reason(watch.name), product=_clean_reason(product),
                           version=_clean_reason(watch.version), count=len(members),
                           why=_why(Counter(label for _, _, label in members)),
                           ids=[_safe_id(record_id) for record_id, _, _ in ordered[:3]],
                           more=max(0, len(members) - 3)))
    return dict(total=sum(totals.values()), watches=len(groups), why=_why(totals),
                list=blocks, more=len(groups) - len(blocks))

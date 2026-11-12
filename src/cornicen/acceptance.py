"""Read private acceptance files and evaluate stored records without writes."""

from dataclasses import dataclass
import json
import re
import tomllib
import zlib

from cornicen.applicability import resolve, State
from cornicen.watchlist import _watch


class AcceptanceError(ValueError):
    """A rejected acceptance file, with no private diagnostic text."""


def load_entries(path):
    try:
        document = tomllib.loads(path.read_text(encoding='utf-8'))
        if document.keys() - {'expect'}:
            raise ValueError
        entries = document.get('expect')
        if not isinstance(entries, list) or not entries:
            raise ValueError
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {'watch_id', 'cve'}
                    or not isinstance(entry['watch_id'], str) or not entry['watch_id']
                    or not isinstance(entry['cve'], str)
                    or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', entry['cve'])):
                raise ValueError
        return tuple((entry['watch_id'], entry['cve']) for entry in entries)
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise AcceptanceError('Acceptance list rejected') from None


def load_watches(path, entries):
    try:
        document = tomllib.loads(path.read_text(encoding='utf-8'))
        # Suppressions have no bearing on the self-test, including validation.
        document.pop('accept', None)
        if document.keys() - {'watch'}:
            raise ValueError
        # Reuse the watch validator without serializing private parser errors.
        raw = document.get('watch', [])
        if not isinstance(raw, list):
            raise ValueError
        watches = []
        for entry in raw:
            if not isinstance(entry, dict) or entry.keys() - {
                    'id', 'name', 'match', 'product_only', 'version', 'scheme', 'eol'}:
                raise ValueError
            watches.append(_watch(entry))
        by_id = {watch.id: watch for watch in watches}
        if (len({watch.id.casefold() for watch in watches}) != len(watches)
                or any(watch_id not in by_id for watch_id, _ in entries)):
            raise ValueError
        return by_id
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise AcceptanceError('Acceptance list rejected') from None


@dataclass(frozen=True)
class Outcome:
    watch_id: str
    cve: str
    verdict: str
    state: str | None = None

    def line(self):
        text = self.verdict
        if text == 'regression':
            text += f' ({self.state})'
        return f'{self.watch_id} {self.cve}: {text}'


def evaluate(store, entries, watches, aliases):
    outcomes = []
    for watch_id, cve in entries:
        row = store.connection.execute('SELECT json FROM records WHERE id=?', (cve,)).fetchone()
        if row is None:
            outcomes.append(Outcome(watch_id, cve, 'could not check'))
            continue
        raw = row[0]
        record = json.loads(zlib.decompress(raw) if isinstance(raw, bytes) else raw)
        kev = store.connection.execute('SELECT json FROM kev WHERE cve=?', (cve,)).fetchone()
        result = resolve(record, json.loads(kev[0]) if kev else None, watches[watch_id], aliases)
        state = result.state if result else None
        outcomes.append(Outcome(watch_id, cve,
                                'pass' if state == State.AFFECTED else 'regression',
                                state.value if state else 'no_match'))
    return outcomes


def verdict(outcomes):
    total = len(outcomes)
    failed = sum(item.verdict == 'regression' for item in outcomes)
    missing = sum(item.verdict == 'could not check' for item in outcomes)
    if failed or missing:
        return ('unhealthy', f'{failed} of {total} entries no longer match; {missing} could not be checked',
                'missing' if missing else 'failed')
    return 'healthy', f'{total} of {total} entries match', 'recovered'

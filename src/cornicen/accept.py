"""Explicit operator decisions and their shared, timezone-aware lapse predicate."""

from dataclasses import dataclass
from datetime import date
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class Accept:
    cve: str
    watch: str
    reason: str
    until: date | None
    until_version_change: bool
    version: str | None
    entry: int


def state(accept, watches_by_id, now, timezone):
    watch = next((watch for watch in watches_by_id.values()
                  if watch.id.casefold() == accept.watch.casefold()), None)
    if watch is None:
        return 'unknown-watch'
    if accept.until is not None and now.astimezone(ZoneInfo(timezone)).date() > accept.until:
        return 'lapsed-date'
    if accept.until_version_change and watch.version != accept.version:
        return 'lapsed-version'
    return 'active'


def detail(accept):
    return dict(reason=accept.reason, until=accept.until.isoformat() if accept.until else None,
                version=accept.version)


def lapse_reason(value):
    return {'lapsed-date': 'date passed', 'lapsed-version': 'version changed'}.get(value, 'entry removed')

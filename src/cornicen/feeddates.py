"""Timezone-bearing feed dates with exact arbitrary fractional precision."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from functools import total_ordering
import re

from cornicen.diagnostics import FixedDiagnostic

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RFC3339 = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})')


@total_ordering
@dataclass(frozen=True, eq=False)
class FeedDate:
    raw: str
    seconds: int
    fraction: str = ''

    def _key(self):
        return self.seconds, self.fraction.rstrip('0')

    def __eq__(self, other):
        if not isinstance(other, FeedDate):
            return NotImplemented
        return self._key() == other._key()

    def __lt__(self, other):
        if not isinstance(other, FeedDate):
            return NotImplemented
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def utc(self):
        base = (_EPOCH + timedelta(seconds=self.seconds)).strftime('%Y-%m-%dT%H:%M:%S')
        return base + ('.' + self.fraction if self.fraction else '') + 'Z'


def _seconds(value):
    delta = value.astimezone(timezone.utc) - _EPOCH
    return delta.days * 86400 + delta.seconds


def rfc3339(value):
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(FixedDiagnostic('invalid RFC 3339 date'))
    day, clock, fraction, zone = match.groups()
    try:
        if zone not in ('Z', 'z') and (int(zone[1:3]) > 23 or int(zone[4:]) > 59):
            raise ValueError
        stamp = datetime.fromisoformat(day + 'T' + clock + ('+00:00' if zone in ('Z', 'z') else zone))
        seconds = _seconds(stamp)
        _EPOCH + timedelta(seconds=seconds)  # UTC must also be representable.
    except (ValueError, OverflowError):
        raise ValueError(FixedDiagnostic('invalid RFC 3339 date')) from None
    return FeedDate(value, seconds, fraction or '')


def rfc822(value):
    try:
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            raise ValueError
        return FeedDate(value, _seconds(stamp))
    except (ValueError, TypeError, OverflowError, AttributeError):
        raise ValueError(FixedDiagnostic('invalid timezone-bearing RFC 822 date')) from None

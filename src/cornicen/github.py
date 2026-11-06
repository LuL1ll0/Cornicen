"""GitHub authentication and rate limits from persisted response metadata only."""

from datetime import datetime, timedelta
import json


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

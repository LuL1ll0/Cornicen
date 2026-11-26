# script-purpose: Define the coverage audit protocol shared by transport and presentation.
# script-class: pipeline-tool
# script-trigger: Coverage audit requests and health notice delivery.
# script-tests: tests/test_cvelist_gap.py
"""Read structured health identifiers; write nothing. Library API, no exit codes."""

import re

SOURCE = 'cvelist_gap'
HEALTH_EPISODE = 'cvelist_gap_health_episode'
DAYS_OPEN = 'days_open'
OLDEST_OPEN = 'oldest_open'
NO_OVERDUE = 'delta gap: healthy'
NOTICE_INCOMPLETE = 'delta gap: audit incomplete'
RAW_HOST = 'raw.githubusercontent.com'
REDIRECT_REFUSAL = 'HTTP redirect refused'
_COMPONENT = r'[a-z][a-z0-9_-]{0,99}'
_HEALTH_PAIR = re.compile(rf'\|({_COMPONENT})\|health\|[1-9][0-9]*')


def valid_health_component(value):
    return isinstance(value, str) and re.fullmatch(_COMPONENT, value) is not None


def health_component(pair_key, legacy):
    """Read the component from the durable health key, not the queued payload."""
    if match := _HEALTH_PAIR.fullmatch(pair_key):
        return match[1]
    if '|' not in pair_key and legacy != SOURCE and valid_health_component(legacy):
        return legacy


class BodyTooLarge(ValueError):
    pass


class RedirectRefused(ValueError):
    pass

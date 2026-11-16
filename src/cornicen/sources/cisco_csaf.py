# script-purpose: Bind Cisco directory policy and parse its invented index format.
# script-class: pipeline-tool
# script-trigger: Offline Cisco CSAF directory operations.
# script-tests: tests/test_task3_b1.py
"""Read index text and HTTP responses; write SQLite and member files via shared code.

Library API has no exit codes; invalid whole index bodies raise ValueError.
"""
import re

from cornicen.csaf import CISCO
from cornicen.feedvalidate import safe_path
from cornicen.sources.csaf_directory import CsafProfile, CsafState, CsafDirectory

# ponytail: Local ceilings include metadata, listings and redirect hops; gate C
# requires publisher measurements before this profile can be enabled.
CYCLE_LIMIT, HOUR_LIMIT = 200, 400
DIRECTORY = 'https://www.cisco.com/.well-known/csaf/'
METADATA_URL = DIRECTORY + 'provider-metadata.json'
RESOURCE = 'cisco/advisories'


def parse_index(body):
    """Return path-to-empty-timestamps and invalid-row count, requiring a valid path."""
    try:
        text = body.decode('utf-8') if isinstance(body, bytes) else body
        if not text.strip() or text.lstrip().startswith('<'):
            raise ValueError('invalid index')
        paths, invalid = set(), 0
        for line in text.split('\n'):
            line = line.removesuffix('\r')
            if not line:
                continue
            try:
                if not re.fullmatch(r'[0-9]{4}/[A-Za-z0-9_.-]+\.json', line):
                    raise ValueError('invalid index row')
                paths.add(safe_path(line))
            except ValueError:
                invalid += 1
        if not paths:
            raise ValueError('invalid index')
        return {path: [] for path in sorted(paths)}, invalid
    except UnicodeError as error:
        raise ValueError('invalid index') from error


PROFILE = CsafProfile('cisco', RESOURCE, 'cisco_csaf', 'www.cisco.com',
    METADATA_URL, DIRECTORY, tuple('/.well-known/csaf/' + name for name in
        ('provider-metadata.json', 'changes.csv', 'index.txt')),
    ('changes.csv', 'index.txt'), 'cisco-members-', 'cisco_generation', CISCO,
    lambda: (CYCLE_LIMIT, HOUR_LIMIT), index_parser=parse_index)


class CiscoState(CsafState):
    def __init__(self, store, *, rng=None):
        super().__init__(store, PROFILE, rng=rng)


class CiscoCsaf(CsafDirectory):
    def __init__(self, http, state, clock, *, data_dir=None):
        super().__init__(http, state, clock, PROFILE, data_dir=data_dir)

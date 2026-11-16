# script-purpose: Poll Microsoft CSAF within durable budgets and stream cached advisory members.
# script-class: pipeline-tool
# script-trigger: Offline Microsoft CSAF adapter state operations.
# script-tests: tests/test_task2_b1.py, tests/test_task2_b2.py, tests/test_task3_b1.py
"""Bind Microsoft policy to shared CSAF state and directory polling.

Read CSV and HTTP responses; write SQLite meta rows and member files via shared code.

Library API with no process exit codes; invalid listings raise ValueError.
MsrcCsaf polls the publisher only when constructed by an effective factory.
"""
import tempfile
from cornicen.csaf import MICROSOFT, normalise
from cornicen.sources.csaf_directory import CsafProfile, CsafState, CsafDirectory, parse_listing

# ponytail: Local ceilings include metadata, listings and redirect hops; shared
# publisher capacity must be measured before gate M can be met.
CYCLE_LIMIT, HOUR_LIMIT = 200, 400
DIRECTORY = 'https://msrc.microsoft.com/csaf/advisories/'
METADATA_URL = 'https://msrc.microsoft.com/csaf/provider-metadata.json'
RESOURCE = 'msrc/advisories'
PROFILE = CsafProfile('msrc', RESOURCE, 'msrc_csaf', 'msrc.microsoft.com',
    METADATA_URL, DIRECTORY, ('/csaf/provider-metadata.json', '/csaf/advisories/changes.csv'),
    ('changes.csv',), 'msrc-members-', 'msrc_generation', MICROSOFT,
    lambda: (CYCLE_LIMIT, HOUR_LIMIT))


class MsrcState(CsafState):
    def __init__(self, store, *, rng=None):
        super().__init__(store, PROFILE, rng=rng)


class MsrcCsaf(CsafDirectory):
    def __init__(self, http, state, clock, *, data_dir=None):
        super().__init__(http, state, clock, PROFILE, data_dir=data_dir)

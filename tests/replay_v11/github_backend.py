# script-purpose: Serve strictly scoped invented GitHub responses without network access.
# script-class: harness
# script-trigger: tests/test_task1_b2.py and GitHub replay scenarios.
# script-tests: tests/test_task1_b2.py
"""Read per-action repository operation scripts; write request observations in memory.

No sockets or persistent output. Parent unittest runner exits 0 success, 1 failure.
"""
from io import BytesIO
from urllib.parse import urlsplit
import json
import socket

from cornicen.fetch import Http


class ScriptedGitHub:
    """Scripts indexed by (action, repository, operation, traversal, occurrence).

    Listing traversal boundaries are explicit on response entries via `last`.
    This preserves strict URL assertions even for redirects to the initial URL.
    """
    def __init__(self):
        self.scripts = {}
        self.requests = []
        self.reset(0)

    def reset(self, action):
        self.action = action
        self.counters = {}
        self.traversals = {}

    def add(self, action, repository, operation, occurrence, *, url, body='',
            status=200, headers=None, traversal=1, last=False, method='GET', error=None):
        key = (action, repository, operation, traversal if operation == 'listing' else 0, occurrence)
        assert key not in self.scripts, key
        self.scripts[key] = dict(url=url, body=body, status=status, headers=headers or {}, last=last, method=method, error=error)

    @staticmethod
    def resolver(host, port, **kwargs):
        assert host == 'api.github.com', host
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]

    def http(self):
        return Http('Cornicen/test', {}, opener=self, resolver=self.resolver)

    def open(self, request, timeout):
        url = request.full_url
        parts = urlsplit(url).path.split('/')
        operation = ('listing' if parts[-1] == 'security-advisories' else
                     'detail:' + parts[-1] if 'security-advisories' in parts else 'metadata')
        # Numeric endpoints and case aliases are resolved from scripts rather
        # than a global response counter; no other repository can consume them.
        candidates = []
        for key, script in self.scripts.items():
            action, repository, op, traversal, occurrence = key
            if action != self.action or op != operation:
                continue
            current = self.traversals.get(repository, 1) if op == 'listing' else 0
            counter = self.counters.get((repository, op, current), 0) + 1
            if traversal == current and occurrence == counter and script['url'] == url:
                candidates.append((key, script))
        assert len(candidates) == 1, ('unexpected or ambiguous request', self.action, operation, url, candidates)
        key, script = candidates[0]
        _, repository, op, traversal, occurrence = key
        assert request.get_method() == script['method']
        self.counters[repository, op, traversal] = occurrence
        if op == 'listing' and script['last']:
            self.traversals[repository] = traversal + 1
        self.requests.append(dict(action=self.action, repository=repository, operation=op,
                                  traversal=traversal, occurrence=occurrence, url=url,
                                  headers=dict(request.header_items()), method=request.get_method()))
        if script['error'] is not None:
            raise script['error']
        body = script['body']
        if not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        response = BytesIO(body.encode() if isinstance(body, str) else body)
        response.status = script['status']
        response.headers = script['headers']
        return response


from tests.replay_v11.fixture_adapter import ValidationBackend


class GitHubBackend(ValidationBackend):
    """Use the production factory and a synthetic gate solely for offline replays."""
    def __init__(self, registry):
        from dataclasses import replace
        from cornicen.adapters import REGISTRY
        super().__init__({'github': replace(REGISTRY['github'], gate='met')})
        self.server = ScriptedGitHub()
        self.action_index = 0
        self.script_action = 0

    def start_engine(self):
        previous = getattr(self, 'engine', None)
        if previous is not None and previous.store is not self.store:
            previous.store._finalizer.detach()
        super().start_engine()

    def close(self):
        # A real Http starts deadline threads. Explicitly closed SQLite stores
        # must not later run a redundant weakref close on a timer's GC thread.
        self.store._finalizer.detach()
        super().close()

    def action(self, row):
        from cornicen.adapterfactories import production_factories
        if 'github' in row:
            self.script_action = self.action_index
            self.server.reset(self.script_action)
            for response in row['github']:
                response = dict(response)
                repository = response.pop('repository')
                operation = response.pop('operation', 'listing')
                occurrence = response.pop('occurrence', 1)
                self.server.add(self.script_action, repository, operation, occurrence, **response)
        elif 'cycle' in row:
            from cornicen.adapterstore import instant
            self.clock.now = instant(row['t'])
            self.server.reset(self.script_action)
            classification = self.engine.dispatch_adapters(
                registry=self.registry,
                factories=production_factories(self.engine, http_factory=self.server.http))
            self.engine._flush()
            self.observed = {'classification': classification}
        else:
            super().action(row)
        self.action_index += 1

    def snapshot(self):
        from cornicen.adapterstore import canonical
        result = super().snapshot()
        result['requests'] = len(self.server.requests)
        topology, previous = [], None
        for request in self.server.requests:
            if request['operation'] != 'listing':
                continue
            group = (request['action'], request['repository'], request['traversal'])
            if group != previous:
                topology.append([])
                previous = group
            script = self.server.scripts[(*group[:2], 'listing', group[2], request['occurrence'])]
            if script['status'] != 200:
                continue
            body = script['body']
            if isinstance(body, (str, bytes)):
                body = json.loads(body)
            topology[-1].append([m['ghsa_id'] for m in body])
        result['topology'] = topology
        for row in self.store.connection.execute('SELECT source_id,state FROM advisories'):
            result['advisories'][row['source_id']]['state'] = row['state']
        result['resource_manifests'] = [dict(r) for r in self.store.connection.execute(
            "SELECT resource,digest,audited_at FROM manifests WHERE source='github' ORDER BY resource")]
        return result


def is_github(name):
    return name.startswith(('github_', 'synthetic_github_'))


def validate_rows(rows):
    """Validate GitHub-only extensions without relaxing the existing oracles."""
    from tests.replay_v11 import harness as h
    previous = None
    if not rows or 'watchlist' not in rows[0]:
        raise ValueError('first action must set watchlist')
    for row in rows:
        from cornicen.adapterstore import instant
        now = instant(row['t'])
        if previous is not None and now < previous:
            raise ValueError('t must be non-decreasing')
        previous = now
        if len(set(row)-{'t'}) != 1:
            raise ValueError('one action per line')
        if 'github' in row:
            for response in row['github']:
                if not response['url'].startswith('https://api.github.com/'):
                    raise ValueError('foreign scripted URL')
        elif not set(row)-{'t'} <= {'watchlist','seed','cycle','restart','case','notifier'}:
            raise ValueError('unsupported GitHub action')
    # Narrowly redact the additional invented vocabulary into the vocabulary
    # accepted by the original provenance validator; it still checks everything.
    import re
    encoded = json.dumps(rows)
    for name in ('github-selector:', 'Widget Engine', 'Widget Core'):
        encoded = encoded.replace(name, 'invented')
    encoded = encoded.replace('CVE-2026-105726', 'CVE-2099-105726')
    encoded = re.sub(r'https://(?:api\.github\.com|github\.com)/examplecorp/', 'https://examplecorp.invalid/', encoded)
    encoded = encoded.replace('https://api.github.com/', 'https://examplecorp.invalid/')
    h.validate_identities(json.loads(encoded))
    return rows

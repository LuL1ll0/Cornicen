# script-purpose: Run timestamped foundation oracles through test-only engine hooks.
# script-class: harness
# script-trigger: tests/test_replay_v11.py and unittest discovery.
# script-tests: tests/replay_v11/test-harness.py, tests/test_f3b.py, tests/test_task1_b2.py, tests/test_task2_b2.py, tests/test_task3_b2.py, tests/test_task4_b2.py, tests/test_task6_b2.py
"""Read adjacent JSONL fixtures; write temporary SQLite databases and staged files.

Usage: PYTHONPATH=src python3 -m unittest tests.test_replay_v11
Exit 0 on success, 1 on assertion or infrastructure failure. Missing production
hooks are assertion failures, never fabricated validator or matching results.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
import tomllib
import unittest

from tests.replay.harness import as_ingest, read_jsonl, utc

FOUNDATION_TASK = 'F4'
TASKS = ('F0', 'F1', 'F2a', 'F2b', 'F3a', 'F3b', 'F4')
ORACLES = {'withdrawal_reissue', 'late_identity', 'alias_episode', 'split', 'aggregate',
           'baseline_is_local', 'bad_member', 'boundary', 'audits',
           'empty_enumeration', 'rebaseline_gap', 'synthetic_optional',
           'synthetic_identifier'}
SCENARIOS = Path(__file__).parent
WATCHLIST = '[[watch]]\nid="w"\nname="Widget"\nmatch=["examplecorp:widget"]\nversion="1.0.0"\nscheme="semver"\n'
STATE_FIELDS = {'classification', 'dimensions', 'cursor', 'quarantine', 'gaps',
                'baseline', 'pairs', 'redirects', 'outbox', 'events', 'evidence',
                'retries', 'manifests', 'staged', 'notification_count', 'coverage',
                'historical_completeness', 'fix', 'body', 'advisories', 'cutoff'}
NEW_TABLES = {'resource_cache', 'staged_containers', 'advisories', 'advisory_evidence',
              'quarantine', 'manifest_members', 'baseline_members', 'manifests', 'adapter_state', 'adapter_retries',
              'gap_ledger', 'source_health', 'identity_redirects',
              'coverage_inheritance', 'delivery_coverage', 'affected_latches', 'advisory_support', 'advisory_shells'}


@dataclass(frozen=True)
class FixtureAdapter:
    name: str
    position: int
    export: bool = False
    gate: str = 'met'


def fixture_registry():
    """A fresh registry per run; never modifies the production registry."""
    return {a.name: a for a in (FixtureAdapter('fixture_a', 1),
                               FixtureAdapter('fixture_b', 6),
                               FixtureAdapter('fixture_export', 2, True))}


# Later tasks install a factory accepting the test-only registry. A backend owns
# its real engine/store, accepts actions and returns actual persisted snapshots.
# No classification, matching, aggregation or delivery policy lives here.
BACKEND_FACTORY = None


def register_backend(factory):
    global BACKEND_FACTORY
    previous = BACKEND_FACTORY
    BACKEND_FACTORY = factory
    return previous


def scenario_names():
    return sorted(p.name.removesuffix('.input.jsonl') for p in SCENARIOS.glob('*.input.jsonl')
                  if not p.name.startswith(('github_', 'synthetic_github_', 'cisco_', 'debian_', 'synology_')) and p.name.removesuffix('.input.jsonl') not in ('csaf','csaf_inventory','msrc_bootstrap'))


def _rows(path):
    first = json.loads(path.read_text().splitlines()[0])
    if set(first) != {'#'} or '§8' not in first['#']:
        raise ValueError(f'{path}: first line must cite spec §8')
    return read_jsonl(path)


def validate_identities(rows, *, synology=False):
    allowed_matches = {'examplecorp:widget', 'examplecorp:gadget'}
    if synology:
        allowed_matches.update(('synology:diskstation manager (dsm)', 'synology:synology photo station'))
    def walk(value):
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in ('vendor', 'vendorProject') and item != 'examplecorp':
                    raise ValueError(f'non-invented vendor: {item}')
                if key == 'products' and isinstance(item, list):
                    for product in item:
                        if product.get('name') not in ('examplecorp:widget', 'examplecorp:gadget'):
                            raise ValueError('non-invented product')
                if key == 'match' and any(p not in allowed_matches for p in item):
                    raise ValueError('non-invented watch identity')
                if key == 'watchlist':
                    walk(tomllib.loads(item))
                elif key == 'body' and isinstance(item, str):
                    try:
                        decoded = json.loads(item)
                    except ValueError:
                        pass  # Deliberately invalid boundary input.
                    else:
                        walk(decoded)
                walk(item)
    walk(rows)
    text = json.dumps(rows)
    for token in re.findall(r'(?:CVE|FIX)-[A-Za-z0-9-]+', text):
        if not re.fullmatch(r'(?:CVE|FIX)-2099-\d{4,}', token):
            raise ValueError(f'non-invented identity: {token}')
    for token in re.findall(r'\b[a-z][a-z0-9_]*:[a-z][a-z0-9_]*', text):
        if token.startswith('examplecorp:') and token not in ('examplecorp:widget', 'examplecorp:gadget'):
            raise ValueError(f'non-invented product: {token}')
    for host in re.findall(r'https?://([^/\\"\s]+)', text):
        if host != 'examplecorp.invalid' and not (synology and host == 'www.synology.com'):
            raise ValueError(f'non-invented host: {host}')
    for version in re.findall(r'"(?:version|last_affected|limit|first_fixed)":\s*"([^"]+)"', text):
        if not re.fullmatch(r'\d+\.\d+\.\d+', version) and not (synology and version == '7.9.0-99999'):
            raise ValueError(f'non-three-part version: {version}')


def validate_timeline(rows, *, synology=False):
    if not rows or 'watchlist' not in rows[0]:
        raise ValueError('first action must set watchlist')
    previous = None
    pending = False
    cases = {'main'}
    cycles = 0
    for row in rows:
        now = utc(row['t'])
        if previous is not None and now < previous:
            raise ValueError('t must be non-decreasing, including across cases')
        previous = now
        keys = set(row) - {'t'}
        if 'adapter' in keys and not synology:
            if keys != {'adapter', 'result'} or row['adapter'] not in fixture_registry():
                raise ValueError('invalid adapter action')
            result = row['result']
            if not isinstance(result, dict) or set(result) != {'resources'} or not isinstance(result['resources'], list):
                raise ValueError('adapter result requires raw resources only')
            for resource in result['resources']:
                allowed = {'path', 'status', 'body', 'headers', 'transfer_complete', 'integrity'}
                if not {'path', 'status', 'body'} <= set(resource) or set(resource) - allowed:
                    raise ValueError('invalid raw resource fields')
                if type(resource['status']) is not int or not isinstance(resource['body'], str):
                    raise ValueError('invalid HTTP outcome')
                if not 100 <= resource['status'] <= 599 or not isinstance(resource.get('headers', {}), dict):
                    raise ValueError('invalid HTTP status or headers')
                if type(resource.get('transfer_complete', True)) is not bool or resource.get('integrity', 'intact') not in ('pending', 'intact', 'failed'):
                    raise ValueError('invalid transport integrity')
            pending = True
            continue
        if len(keys) != 1:
            raise ValueError('one action per input line')
        action = next(iter(keys))
        value = row[action]
        if action == 'watchlist':
            tomllib.loads(value)
        elif action == 'ingest':
            as_ingest(value)
            pending = True
        elif action == 'case':
            if pending or not isinstance(value, str) or value in cases:
                raise ValueError('case must be unique and follow committed cycle')
            cases.add(value)
        elif action == 'seed':
            if not isinstance(value, dict):
                raise ValueError('seed must describe initial state')
        elif action == 'rss' and synology:
            from tests.replay_v11.rss_backend import validate_script
            validate_script(value)
            pending = True
        elif action == 'command':
            if value != ['adapter', 'rebaseline', 'synology' if synology else 'fixture_a']:
                raise ValueError('unsupported command')
        elif action == 'pairs' and isinstance(value, list):
            pass
        elif action == 'evaluation_failure' and isinstance(value, bool):
            pass
        elif action == 'retention_days' and type(value) is int:
            pass
        elif action == 'notifier':
            if value not in ('up', 'down'):
                raise ValueError('invalid notifier state')
        elif action == 'cycle' and value is True:
            pending = False
            cycles += 1
        elif action == 'restart' and value is True and not pending:
            pass
        else:
            raise ValueError(f'invalid action: {action}')
    if pending or not cycles:
        raise ValueError('unconsumed inputs or no cycles')
    validate_identities(rows, synology=synology)
    return rows


def load_timeline(name):
    from tests.replay_v11.github_backend import is_github, validate_rows
    rows = _rows(SCENARIOS / f'{name}.input.jsonl')
    if name.startswith('debian_'):
        from tests.replay_v11.osv_backend import validate_rows as validate_debian
        return validate_debian(rows)
    from tests.replay_v11.msrc_backend import is_csaf, is_cisco, validate_rows as validate_msrc
    from tests.replay_v11.rss_backend import is_synology
    if is_csaf(name):
        return validate_msrc(rows, 'cisco' if is_cisco(name) else 'msrc')
    if is_github(name):
        return validate_rows(rows)
    return validate_timeline(rows, synology=is_synology(name))


def load_expected(name, timeline=None):
    rows = _rows(SCENARIOS / f'{name}.expected.jsonl')
    from tests.replay_v11.github_backend import is_github
    from tests.replay_v11.msrc_backend import is_csaf as is_msrc
    if is_github(name) or is_msrc(name):
        for row in rows:
            utc(row['t'])
            if row.get('lifted_by') != 'F4' or (not isinstance(row.get('state'), dict) and not (is_msrc(name) and {'watch','record','reasons','urgency'} <= set(row))):
                raise ValueError('invalid GitHub expectation')
        return rows
    from tests.replay_v11.rss_backend import is_synology, STATE_FIELDS as RSS_FIELDS
    synology = is_synology(name)
    extra_fields = RSS_FIELDS if synology else set()
    if name.startswith('debian_'):
        extra_fields = {'requests', 'request_trace', 'evidence_rows', 'freshness_detail', 'retry_detail'}
    timeline = timeline if timeline is not None else load_timeline(name)
    points = set()
    case = 'main'
    for row in timeline:
        case = row.get('case', case)
        if 'cycle' in row or 'command' in row:
            points.add((case, row['t']))
        if 'restart' in row:
            points.add((case, row['t'], 'after_restart'))
    for row in rows:
        if row.get('lifted_by') not in TASKS:
            raise ValueError('each assertion needs a valid lifted_by')
        key = (row.get('case', 'main'), row['t'])
        if 'snapshot' in row:
            if 'state' not in row or row['snapshot'] != 'after_restart':
                raise ValueError('invalid snapshot selector')
            key += (row['snapshot'],)
        if key not in points:
            raise ValueError('assertion must reference a cycle or command timestamp')
        utc(row['t'])
        keys = set(row) - {'case', 'lifted_by', 'snapshot'}
        if 'state' in row:
            if keys != {'t', 'state'} or not isinstance(row['state'], dict) or not row['state'] or set(row['state']) - (STATE_FIELDS | extra_fields):
                raise ValueError('invalid state assertion')
            validate_state(row['state'])
        elif keys != {'t', 'watch', 'record', 'reasons', 'urgency'} or row['urgency'] not in ('normal', 'urgent', 'health') or not isinstance(row['reasons'], list):
            raise ValueError('invalid notification assertion')
    if name.startswith('debian_'):
        from tests.replay_v11.osv_backend import validate_identities as validate_debian_identities
        validate_debian_identities(rows)
    else: validate_identities(rows, synology=synology)
    return rows


def validate_state(state):
    for value in state.get('classification', {}).values():
        if value not in ('COMPLETE', 'PARTIAL', 'FAILED'):
            raise ValueError('invalid classification')
    for dimensions in state.get('dimensions', {}).values():
        if set(dimensions) != {'fetch', 'completeness', 'freshness', 'audit'}:
            raise ValueError('expected all four dimensions')
        for dimension, value in dimensions.items():
            allowed = ('healthy', 'unhealthy', 'unknown', 'stale', 'n/a') if dimension == 'freshness' else ('healthy', 'unhealthy')
            if value not in allowed:
                raise ValueError('invalid dimension state')
    for value in state.get('cursor', {}).values():
        if set(value) != {'tick', 'digest'}:
            raise ValueError('cursor needs literal tick and digest')
        utc(value['tick'])
        if not re.fullmatch(r'[0-9a-f]{64}', value['digest']):
            raise ValueError('invalid cursor digest')
    for members in state.get('manifests', {}).values():
        for member in members:
            if set(member) != {'source_id', 'digest'} or not re.fullmatch(r'[0-9a-f]{64}', member['digest']):
                raise ValueError('invalid manifest member')
    for item in state.get('pairs', []):
        if set(item) != {'watch', 'id', 'state', 'episode', 'affected_latch', 'notified'} or item['episode'] < 1:
            raise ValueError('invalid pair assertion')
        if item['state'] not in ('affected', 'unaffected', 'unknown') or type(item['affected_latch']) is not bool or type(item['notified']) is not bool:
            raise ValueError('invalid pair state or latch')


@dataclass
class ReplayResult:
    notifications: list = field(default_factory=list)
    snapshots: dict = field(default_factory=dict)
    unavailable: set = field(default_factory=set)


class UnavailableBackend:
    """F0 has no adapter engine path. Preserve inputs without inventing answers."""
    def __init__(self, registry):
        self.registry = registry

    def action(self, row):
        pass

    def snapshot(self):
        return None

    def notifications(self):
        return []

    def close(self):
        pass


def run_scenario(name):
    rows = load_timeline(name)
    load_expected(name, rows)  # Schema errors always escape pending handling.
    result = ReplayResult()
    case = 'main'
    backend = None
    try:
        for row in rows:
            if backend is None or 'case' in row:
                if backend is not None:
                    backend.close()
                case = row.get('case', case)
                from tests.replay_v11.fixture_adapter import ValidationBackend
                from tests.replay_v11.github_backend import is_github, GitHubBackend
                from tests.replay_v11.msrc_backend import is_csaf as is_msrc, backend_for
                from tests.replay_v11.osv_backend import DebianBackend
                from tests.replay_v11.rss_backend import SynologyBackend, is_synology
                default = (SynologyBackend if is_synology(name) else
                           DebianBackend if name.startswith('debian_') else
                           backend_for(name) if is_msrc(name) else
                           GitHubBackend if is_github(name) else ValidationBackend)
                backend = (BACKEND_FACTORY or default)(fixture_registry())
            backend.action(row)
            if 'cycle' in row or 'command' in row or 'restart' in row:
                key = (case, row['t'])
                if 'restart' in row:
                    key += ('after_restart',)
                result.snapshots[key] = backend.snapshot()
                if result.snapshots[key] is None:
                    result.unavailable.add(key)
            if 'cycle' in row or 'command' in row:
                # Backends return cumulative notifications for their case.
                result.notifications = [n for n in result.notifications if n.get('case', 'main') != case]
                result.notifications.extend(dict(n, case=case) for n in backend.notifications())
    finally:
        if backend is not None:
            backend.close()
    return result


def is_pending(task):
    return TASKS.index(task) > TASKS.index(FOUNDATION_TASK)


def notification(row):
    return {k: v for k, v in row.items() if k != 'lifted_by'} | {'case': row.get('case', 'main')}


def assert_notifications(result, expected):
    active = [notification(row) for row in expected if 'state' not in row and not is_pending(row['lifted_by'])]
    if result.notifications != active:
        raise AssertionError(f'notifications: {result.notifications!r} != active {active!r}')


def assert_line(result, row, expected):
    key = (row.get('case', 'main'), row['t'])
    if 'snapshot' in row:
        key += (row['snapshot'],)
    if key in result.unavailable:
        raise AssertionError(f'{key}: production fixture-adapter hook not implemented')
    if 'state' in row:
        actual = result.snapshots[key]
        def compare(actual, expected, path):
            if isinstance(expected, dict):
                if not isinstance(actual, dict):
                    raise AssertionError(f'{path}: expected object, got {actual!r}')
                if not expected and actual:
                    raise AssertionError(f'{path}: expected empty object, got {actual!r}')
                for field, value in expected.items():
                    if field not in actual:
                        raise AssertionError(f'{path}.{field}: missing observation')
                    compare(actual[field], value, f'{path}.{field}')
            elif actual != expected:
                raise AssertionError(f'{path}: {actual!r} != {expected!r}')
        if ('notification_count' in row['state'] and row['lifted_by'] in ('F3a','F3b','F4')
                and not actual.get('advisory_delivery_available',False)):
            raise AssertionError('advisory delivery counts require the F3 delivery hook')
        compare(actual, row['state'], str(key))
    else:
        target = notification(row)
        needed = sum(notification(r) == target for r in expected if 'state' not in r)
        if result.notifications.count(target) != needed:
            raise AssertionError(f'notification {target!r}: expected multiplicity {needed}')


class AssertionCase(unittest.TestCase):
    """Only AssertionError from the assertion itself can be an expected failure."""
    def __init__(self, label, execute, assertion, task):
        super().__init__('runTest')
        self.label, self.execute, self.assertion, self.task = label, execute, assertion, task

    def id(self):
        return self.label

    def __str__(self):
        return self.label

    def run(self, result=None):
        result = result if result is not None else self.defaultTestResult()
        result.startTest(self)
        try:
            try:
                actual = self.execute()
            except Exception:
                result.addError(self, sys.exc_info())
                return result
            try:
                self.assertion(actual)
            except AssertionError:
                if is_pending(self.task):
                    result.addExpectedFailure(self, sys.exc_info())
                else:
                    result.addFailure(self, sys.exc_info())
            except Exception:
                result.addError(self, sys.exc_info())
            else:
                if is_pending(self.task):
                    try:
                        raise AssertionError('lifted early: update lifted_by')
                    except AssertionError:
                        result.addFailure(self, sys.exc_info())
                else:
                    result.addSuccess(self)
        finally:
            result.stopTest(self)
        return result


def oracle_suite():
    suite = unittest.TestSuite()
    for name in scenario_names():
        expected = load_expected(name)
        # Execution is deliberately outside pending wrappers. Each assertion gets
        # an independent run, avoiding shared mutable backend state across tests.
        execute = lambda name=name: run_scenario(name)
        suite.addTest(AssertionCase(f'{name}: active notification list', execute,
                                   lambda r, e=expected: assert_notifications(r, e), 'F0'))
        for index, row in enumerate(expected, 1):
            suite.addTest(AssertionCase(f'{name}:{index} [{row["lifted_by"]}]', execute,
                                       lambda r, row=row, e=expected: assert_line(r, row, e), row['lifted_by']))
    return suite


def dump_database(connection):
    def cell(value):
        return {'$blob': value.hex()} if isinstance(value, bytes) else value
    tables = {}
    for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        quoted = '"' + name.replace('"', '""') + '"'
        columns = [row[1] for row in connection.execute(f'PRAGMA table_info({quoted})')]
        rows = [[cell(v) for v in row] for row in connection.execute(f'SELECT * FROM {quoted}')]
        rows.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(',', ':')))
        tables[name] = {'columns': columns, 'rows': rows}
    return {'tables': tables, 'meta_keys': sorted(row[0] for row in connection.execute('SELECT k FROM meta'))}


def project_frozen(actual, frozen):
    tables = {}
    for name, old in frozen['tables'].items():
        current = actual['tables'][name]
        indexes = [current['columns'].index(c) for c in old['columns']]
        rows = [[row[i] for i in indexes] for row in current['rows']]
        if name == 'meta':
            key = old['columns'].index('k')
            rows = [r for r in rows if r[key] in frozen['meta_keys']]
        rows.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(',', ':')))
        tables[name] = {'columns': old['columns'], 'rows': rows}
    return {'tables': tables, 'meta_keys': frozen['meta_keys']}


def assert_additions(actual, frozen, *, foundation=True):
    """Separately enforce the exact allowed additive schema and empty data."""
    additions = set(actual['tables']) - set(frozen['tables'])
    # R-SK5: the side table alone may add rows to the frozen comparison.
    expected_tables = NEW_TABLES | {'outbox_event_keys'} if foundation else set()
    if additions != expected_tables:
        raise AssertionError(f'unexpected added tables: {additions!r}')
    for name in additions - {'outbox_event_keys'}:
        if actual['tables'][name]['rows'] != []:
            raise AssertionError(f'added table is not empty: {name}')
    for name, old in frozen['tables'].items():
        table = actual['tables'][name]
        if table['columns'] != old['columns']:
            raise AssertionError(f'unexpected columns: {name}')
    # R-SK5: admit exactly the new migration marker alongside the foundation marker.
    expected_markers = {'adapter_schema_version': '1', 'outbox_event_keys_version': '1'} if foundation else {}
    if actual['meta_keys'] != sorted([*frozen['meta_keys'], *expected_markers]):
        raise AssertionError('unexpected meta keys')
    for marker, version in expected_markers.items():
        meta = actual['tables']['meta']
        if [r for r in meta['rows'] if r[meta['columns'].index('k')] == marker] != [[marker, version]]:
            raise AssertionError(f'{marker} must be {version}')


def run_crash_scenario(name, crash_index=None):
    """Run the test-only crash/reopen wrapper; production transactions are unchanged."""
    from tests.replay_v11.crash_replay import run
    return run(name, crash_index)

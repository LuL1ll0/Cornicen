"""Shared inputs for the package parity capture and its read-only replay."""

import ast
from contextlib import closing, redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from io import StringIO
from pathlib import Path
from zipfile import ZipFile

from cornicen import acceptance, applicability, validate
from cornicen.cli import watch_check
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch, load_watchlist_text, WatchlistError

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'tests/fixtures/package_parity/baseline.json'
REVISION_2 = BASELINE.with_name('revision-2.json')
UPSTREAM = 'https://git.example.invalid/example-console'
DISTRO = 'https://packages.example.invalid/browser/'
NAME = 'example-console'
NOW = datetime(2099, 1, 1, tzinfo=timezone.utc)
EXACT_TEXT = '''[[watch]]
id = "console-exact"
name = "Example Console on a test host"
match = ["example vendor:example console"]
version = "41.7"
scheme = "dotted"
'''
EXACT = load_watchlist_text(EXACT_TEXT)[0]
LOOSE_TEXT = EXACT_TEXT.replace('console-exact', 'console-loose').replace(
    'match = ["example vendor:example console"]', 'product_only = ["example console"]')
LOOSE = load_watchlist_text(LOOSE_TEXT)[0]


def cve(offset=0):
    return f'CVE-2099-{81001 + offset}'


def record(*entries, offset=0, state='PUBLISHED'):
    return {'cveMetadata': {'cveId': cve(offset), 'state': state},
            'containers': {'cna': {'affected': list(entries)}}}


def upstream(**changes):
    return dict(dict(collectionURL=UPSTREAM, packageName=NAME, defaultStatus='unaffected',
                     versions=[dict(version='40.0', lessThan='42.0', status='affected',
                                    versionType='semver')]), **changes)


def scoped(**changes):
    return dict(dict(collectionURL=DISTRO, packageName=NAME, vendor='Example Distro',
                     product='Example Distro Linux 4', defaultStatus='affected',
                     versions=[dict(version='0:42.0-1.exd4', lessThan='*',
                                    versionType='rpm', status='unaffected')]), **changes)


def kev(identity, vendor='Other Vendor', product='Other Product'):
    return dict(cveID=identity, vendorProject=vendor, product=product)


def loose_kev(identity):
    return kev(identity, 'Example', 'Example Console')


def seed_adapter(db, identity):
    db.execute('INSERT INTO advisory_evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
               ('fixture_a', identity, 'main', identity, None, 'example vendor:example console',
                None, 'dotted', None, 'known_not_affected', None, '{}'))


def synthetic_records():
    exact = dict(vendor='example vendor', product='example console', defaultStatus='unaffected')
    loose = upstream(vendor='n/a', product=NAME)
    scoped_default = scoped(defaultStatus='unaffected')
    del scoped_default['versions']
    families = [
        [upstream(collectionURL='HTTPS://Git.Example.invalid/example-console//',
                  packageName='Example-Console')],
        [upstream(collectionURL='https://git.example.invalid/Example-Console')],
        [upstream(collectionURL='https://git.example.invalid/x?repo=Sample/')],
        [upstream(collectionURL='https://git.example.invalid/x/?')],
        [upstream(collectionURL='https://git.example.invalid/x/#')],
        [upstream(collectionURL='https://git.example.invalid/x/')],
        [upstream(collectionURL=UPSTREAM + '.git')],
        [upstream(collectionURL='https://git.example.invalid/x?re\tpo=Sample')],
        [upstream(packageName='ℌello')],
        [upstream()],
        [scoped()],
        [scoped_default],
        [upstream(), scoped(defaultStatus='unaffected')],
        [upstream(versions=[dict(version='40.0', lessThan='*', status='affected')])],
        [dict(packageName=NAME)],
        [dict(collectionURL=UPSTREAM)],
        [upstream(packageName=7)],
        [upstream(), exact],
        [loose, scoped(), dict(exact, version='40.0')],
        [scoped(), loose],
    ]
    for index, entries in enumerate(families + [list(reversed(rows)) for rows in families]):
        # Rejection is tested with affected rows, before the feed projects a tombstone.
        state = 'REJECTED' if index == 29 else 'PUBLISHED'
        yield record(*entries, offset=index, state=state)


def fixture_inputs():
    records, watches, kev_rows = {}, {}, {}

    def add_watch(watch):
        if not getattr(watch, 'package', ()):
            # Keep distinct definitions, even when a replay reuses the same ID.
            fields = asdict(watch)
            fields.pop('package', None)
            watches[json.dumps(fields, sort_keys=True)] = watch

    def watch_text(value):
        try:
            cohort = load_watchlist_text(value)
        except WatchlistError:
            return
        for watch in cohort:
            add_watch(watch)

    def literal(node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'Scheme':
            return Scheme[node.attr]
        return ast.literal_eval(node)

    def walk(value):
        if isinstance(value, dict):
            if 'cveMetadata' in value or (isinstance(value.get('containers'), dict)
                                          and 'cna' in value['containers']):
                encoded = json.dumps(value, sort_keys=True)
                records.setdefault(encoded, value)
            if 'cveID' in value and isinstance(value['cveID'], str):
                encoded = json.dumps(value, sort_keys=True)
                kev_rows.setdefault(value['cveID'], {})[encoded] = value
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and '[[watch]]' in value:
            watch_text(value)

    tests = ROOT / 'tests'
    for path in sorted(tests.rglob('*')):
        if path.parent == BASELINE.parent or path.name in ('package_parity.py', 'test_package_matching.py'):
            continue
        if path.name == 'review_handchecks.json':
            for item in json.loads(path.read_text()):
                if item['identity'] is not None:
                    add_watch(Watch('fixture', 'Fixture', (tuple(item['identity']),), (),
                                    item['version'], Scheme(item['scheme']), False))
                walk(dict(cveMetadata=dict(cveId=item['cve'], state='PUBLISHED'),
                          containers=dict(cna=dict(affected=item['affected']))))
        elif path.name == 'v0200_canonical_watches.json':
            for text in json.loads(path.read_text()).values():
                for fields in json.loads(text):
                    add_watch(Watch(**dict(fields, match=tuple(map(tuple, fields['match'])),
                                           product_only=tuple(fields['product_only']),
                                           scheme=Scheme(fields['scheme']))))
        elif path.suffix == '.json':
            walk(json.loads(path.read_text()))
        elif path.name.endswith('.input.jsonl'):
            for line in path.read_text().splitlines():
                if line.strip():
                    walk(json.loads(line))
        elif path.suffix == '.toml':
            watch_text(path.read_text())
        elif path.suffix == '.zip':
            with ZipFile(path) as archive:
                for member in archive.namelist():
                    if member.endswith('.json'):
                        walk(json.loads(archive.read(member)))
        elif path.suffix == '.py':
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant):
                    walk(node.value)
                elif isinstance(node, ast.Dict) and any(
                        isinstance(key, ast.Constant) and key.value in ('cveMetadata', 'containers')
                        for key in node.keys):
                    try:
                        value = ast.literal_eval(node)
                    except (ValueError, TypeError):
                        continue
                    walk(value)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Watch':
                    try:
                        watch = Watch(*map(literal, node.args),
                                      **{word.arg: literal(word.value) for word in node.keywords})
                        add_watch(watch)
                    except (ValueError, KeyError, TypeError):
                        # Dynamic watch construction is covered by that test's own oracle.
                        continue
    watch_text(EXACT_TEXT)
    for watch in (replace(EXACT, version='42.3'), replace(EXACT, match=(), product_only=(NAME,)),
                  replace(EXACT, match=(), product_only=('example console',))):
        add_watch(watch)
    return list(records.values()) + list(synthetic_records()), list(watches.values()), kev_rows


def acceptance_outputs():
    # Exercise the repository's pinned acceptance fixture with all three outcomes.
    from tests.test_acceptance_selftest import AcceptanceTests

    case = AcceptanceTests()
    try:
        case.setUp()
        case.pinned.write_text(case.pinned.read_text() + '\n' + LOOSE_TEXT)
        case.list.write_text(case.list.read_text() +
                             f'\n[[expect]]\nwatch_id = "{LOOSE.id}"\ncve = "{cve()}"\n')
        case.store.put_record(cve(), record(upstream()), NOW.isoformat())
        entries = acceptance.load_entries(case.list)
        watches = acceptance.load_watches(case.pinned, entries)
        def outcomes():
            return [asdict(outcome) for outcome in acceptance.evaluate(
                case.store, entries, watches, case.engine.aliases)]
        passed = outcomes()
        case.record('unorderable', default='unknown')
        case.kev()
        case.store.connection.execute('INSERT INTO kev VALUES (?,?)',
                                      (cve(), json.dumps(loose_kev(cve()))))
        regression = outcomes()
        case.store.connection.execute('DELETE FROM records')
        return {'passed': passed, 'regression': regression, 'missing': outcomes()}
    finally:
        case.doCleanups()


def kev_options(identity, fixture_kev):
    options = [None, *fixture_kev.get(identity, {}).values()]
    if isinstance(identity, str) and identity.startswith('CVE-2099-81'):
        options += [kev(identity), kev(cve(40)), loose_kev(identity)]
    return options


def watch_check_outputs():
    # Hash complete CLI output for exact and loose watches across storable T15 inputs.
    records, _, fixture_kev = fixture_inputs()
    aliases = AliasMap.load()
    digest = sha256()
    count = 0
    store = Store(':memory:')
    with closing(store.connection):
        store.migrate()
        for item in records:
            if validate.record(item):
                continue
            identity = item['cveMetadata']['cveId']
            store.connection.execute('DELETE FROM records')
            store.put_record(identity, item, NOW.isoformat())
            for row in kev_options(identity, fixture_kev):
                store.connection.execute('DELETE FROM kev')
                if row is not None:
                    store.connection.execute('INSERT INTO kev VALUES (?,?)',
                                             (identity, json.dumps(row)))
                output = StringIO()
                with redirect_stdout(output):
                    status = watch_check(store, (EXACT, LOOSE), aliases, 36500, NOW)
                digest.update(json.dumps([identity, status, output.getvalue()]).encode())
                count += 1
    return {'count': count, 'sha256': digest.hexdigest()}


def revision_2_snapshot():
    if applicability.MATCHING_REVISION != 2:
        raise ValueError('revision-2 capture requires the v0.8.0 engine')
    config = Config(':memory:', ROOT / 'tests/fixtures/watchlist_example.toml',
                    None, '', '', None)
    aliases = AliasMap.load(False)
    store = Store(':memory:')
    control = Store(':memory:')
    with closing(store.connection), closing(control.connection):
        store.migrate()
        engine = Engine(store, (EXACT,), aliases, config, lambda: NOW, None)
        store.set_meta('baseline_complete', '1')
        item = record(dict(vendor='example vendor', product='example console',
                           defaultStatus='affected'))
        engine._health_verdicts = {}
        with store.transaction():
            engine._ingest(IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA,
                                        None, NOW, records=(item, record(upstream(), offset=1))))
            row, = store.connection.execute('SELECT id FROM outbox')
            engine._refresh_pending(row['id'])
        store.connection.backup(control.connection)
        Engine(control, (EXACT,), aliases, config, lambda: NOW, None)
        expected = [[dict(row) for row in control.connection.execute(query)] for query in (
            'SELECT * FROM pairs ORDER BY 1,2', 'SELECT * FROM events ORDER BY 1,2',
            'SELECT * FROM outbox ORDER BY id')]
        return {'database': list(store.connection.iterdump()), 'expected': expected}


def outputs(check_routed=None):
    records, watches, fixture_kev = fixture_inputs()
    aliases = AliasMap.load()
    prepared = [applicability.watch_identities(watch, aliases) for watch in watches]
    # A route decision needs the real schema, not a monkeypatched router.
    store = Store(':memory:')
    with closing(store.connection):
        store.migrate()
        config = Config(':memory:', ROOT / 'tests/fixtures/watchlist_example.toml',
                        None, '', '', None)
        engine = Engine(store, (), aliases, config, lambda: NOW, None)
        for item in synthetic_records():
            seed_adapter(store.connection, item['cveMetadata']['cveId'])
        cases = []
        for item in records:
            metadata = item.get('cveMetadata')
            identity = metadata.get('cveId') if isinstance(metadata, dict) else None
            direct, cached, routes = {}, {}, {}
            for k, row in enumerate(kev_options(identity, fixture_kev)):
                identities = {}
                for w, watch in enumerate(watches):
                    key = f'{k}:{w}'
                    result = applicability.resolve(item, row, watch, aliases)
                    if result is not None:
                        direct[key] = asdict(result)
                    result = applicability.resolve(item, row, watch, aliases, prepared[w], identities)
                    if result is not None:
                        cached[key] = asdict(result)
                    if k == 0:
                        route = engine.route(identity, watch)
                        if route != 'v1':
                            if check_routed is not None:
                                check_routed(engine, item, identity, watch)
                            routes[str(w)] = [route, asdict(engine.advisory_result(
                                watch, identity, record=item))]
            cases.append([direct, cached, routes])
    return {'record_count': len(records), 'watch_count': len(watches), 'cases': cases,
            'acceptance': acceptance_outputs()}


def source_pins(source):
    return {name: sha256((source / 'cornicen' / name).read_bytes()).hexdigest()
            for name in ('cnascope.py', 'advisory.py')}

# script-purpose: Record complete replay observables for the R11 differential.
# script-class: harness
# script-trigger: R11 tests and frozen reference capture.
# script-tests: tests/test_r11_differential.py, tools/test-capture-r11-reference.py
"""Read replay JSONL; write only temporary SQLite and return observations.

Library API used by unittest (exit 0 success, 1 failure). No reference-code imports.
The capture process selects its own cornicen import path before loading this file.
"""
from contextlib import ExitStack, nullcontext, redirect_stdout
from dataclasses import asdict, replace
import gzip
import json
import inspect
import io
from pathlib import Path
import re
import sqlite3
import unittest
import tempfile
import tomllib
from unittest.mock import patch

from tests.replay.harness import FakeClock, as_ingest, read_jsonl, utc

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / 'tests/fixtures/r11_reference'
EXTRA = 'r11_adapter_watch'
VARIANTS = ('accepted', 'shell', 'support', 'mixed', 'late', 'mixed_late')
EXTRA_TEXT = '\n[[watch]]\nid="r11_adapter_watch"\nname="Adapter watch"\nmatch=["examplecorp:r11_unwatched"]\nversion="1.0.0"\nscheme="semver"\n'


def scenarios():
    return {f'{directory}/{p.name.removesuffix(".input.jsonl")}': p
            for directory in ('replay', 'replay_r11')
            for p in sorted((ROOT / 'tests' / directory).glob('*.input.jsonl'))}


def definition(path):
    rows = read_jsonl(path)
    watches = sorted({w['id'] for row in rows if 'watchlist' in row
                      for w in tomllib.loads(row['watchlist']).get('watch', [])})
    identities = sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', json.dumps(rows))))
    if not watches:
        raise ValueError(f'{path}: empty fixture cohort or identity set')
    if EXTRA in watches:
        raise ValueError('reserved watch ID')
    return rows, watches, identities


def raw_advisory(identity, number=1):
    return dict(id=f'FIX-2099-{number:04d}', title='Injected adapter title',
                url='https://examplecorp.invalid/r11', published='2099-11-03T00:00:00Z',
                updated='2099-11-03T00:00:00Z', cves=[identity],
                products=[dict(id='p', name='examplecorp:r11_unwatched')],
                evidence=[dict(product_id='p', scheme='semver', status='known_affected',
                               range=dict(introduced='1.0.0', limit='2.0.0'))])


def inject(store, identities, variant, tick, engine=None):
    """Accepted evidence goes through the same validator/persistence as fixtures.

    No commit callback: seed inventory before evaluation, without manufacturing
    watch history. Shell/support variants have no matching product or cohort pair.
    """
    from cornicen.adapterstore import AdapterStore
    from cornicen.feedvalidate import validate_advisory
    from cornicen import advisory
    db = store.connection
    with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as directory:
        persistence = AdapterStore(store, directory,
            on_record=engine.commit_advisory if engine else None)
        if variant in ('accepted', 'mixed', 'late', 'mixed_late'):
            persistence.ensure('fixture_a', tick)
            db.execute("UPDATE adapter_state SET baseline_members='[]',baseline_complete=1 WHERE source='fixture_a'")
        for number, identity in enumerate(identities, 1):
            raw = raw_advisory(identity, number)
            data = validate_advisory(raw, source='fixture_a', observed_at=tick).data
            # Demonstrate that injection does not match any cohort selector in run().
            if variant in ('accepted', 'mixed', 'late', 'mixed_late'):
                state = persistence.process('fixture_a', [dict(path=f'{number}.json', status=200,
                    body=json.dumps([raw]))], tick)
                if state != 'COMPLETE':
                    raise RuntimeError(f'injection was not accepted: {state}')
            elif variant == 'support':
                db.execute('INSERT INTO advisory_support(source,source_id,identity) VALUES (?,?,?)',
                           ('fixture_a', data['source_id'], identity))
            elif variant == 'shell':
                columns = [r[1] for r in db.execute('PRAGMA table_info(advisory_shells)')]
                if columns == ['identity']:
                    db.execute('INSERT INTO advisory_shells VALUES (?)', (identity,))
                else:
                    db.execute('INSERT INTO advisory_shells(source,source_id,identity) VALUES (?,?,?)',
                               ('fixture_a', data['source_id'], identity))
                persistence.quarantine('fixture_a', data['source_id'], 'invented quarantine', tick)
            else:
                raise ValueError(variant)
        if identities and variant in ('accepted', 'mixed', 'late', 'mixed_late') and not advisory.rows_for(db, identities[0]):
            raise RuntimeError('empty injected evidence')


def cohort_state(db, cohort):
    """Read durable cohort bookkeeping and v1 health without writes."""
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    result = {}
    for table in ('affected_latches', 'epss_crossings'):
        result[table] = ([dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY watch_id,record_id')
                          if r['watch_id'] in cohort] if table in tables else [])
    result['meta'] = [dict(r) for r in db.execute('SELECT * FROM meta ORDER BY k')
        if r['k'] in ('baseline_complete', 'applied_matching_revision', 'alias_map_version')
        or r['k'].startswith(('matching_revision_retry:', 'kev_only:', 'kev_baseline:',
                             'record_baseline:', 'committed_cve:'))]
    result['health'] = [dict(r) for r in db.execute('SELECT * FROM health ORDER BY source')
                        if r['source'] != 'fixture_a']
    return result


def probe_commit(store, engine, identities, cohort, tick):
    """Exercise the real callback with seeded bookkeeping, then restore the database backup.

    The continuing timeline still compares to the unmodified v1 oracle.
    """
    db = store.connection
    events = list(engine.report.events)
    def snapshot():
        value = cohort_state(db, cohort)
        for table in ('pairs', 'events'):
            value[table] = [dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY 1,2')
                            if r['watch_id'] in cohort]
        value['outbox'] = [dict(r) for r in db.execute('SELECT * FROM outbox ORDER BY id')
                           if json.loads(r['body_json']).get('watch_id') in cohort]
        return value
    saved = sqlite3.connect(':memory:')
    db.backup(saved)
    try:
        pairs = [dict(r) for r in db.execute('SELECT * FROM pairs')
                 if r['watch_id'] in cohort and r['record_id'] in identities]
        for pair in pairs:
            watch, identity = pair['watch_id'], pair['record_id']
            body = dict(watch_id=watch, record_id=identity, episode=pair['episode'])
            store.queue(watch + '|' + identity, 'normal', ['new match'], body, tick, tick)
            db.execute("""UPDATE outbox SET attempts=3,next_attempt_at='2100-01-02T00:00:00+00:00',
                due_at='2100-01-01T00:00:00+00:00',dirty=0 WHERE pair_key=? AND sent_at IS NULL""",
                (watch + '|' + identity,))
            db.execute('''INSERT OR REPLACE INTO epss_crossings
                (watch_id,record_id,episode,fired,crossing,threshold,rearm_ratio) VALUES (?,?,?,1,7,0.1,0.8)''',
                (watch, identity, pair['episode']))
            db.execute('INSERT OR REPLACE INTO affected_latches VALUES (?,?,?,1)',
                       (watch, identity, pair['episode']))
            store.set_meta('matching_revision_retry:' + identity, '1')
        before = snapshot()
        inject(store, identities, 'mixed_late', tick, engine=engine)
        return dict(before=before, after=snapshot())
    finally:
        saved.backup(db)
        saved.close()
        engine.report.events[:] = events


def run(path, variant=None, *, reference=False, explain=False):
    from cornicen.config import Config
    from cornicen.engine import Engine
    from cornicen.identity import AliasMap
    from cornicen.model import Notification
    from cornicen.render import render
    from cornicen.store import Store
    from cornicen.watchlist import load_watchlist_text, load_document_text
    rows, cohort, identities = definition(path)
    cohort_set = set(cohort)
    clock = FakeClock(utc(rows[0]['t']))
    deliveries, envelopes, routes = [], [], []
    audit = dict(routes=[], side_calls=[], missing=[], live=[], extra_events=False,
                 extra_outbox=False, extra_digest=False, extra_affected=False, extra_bodies=[],
                 baseline_contributions=[], commit_probes=[])
    baseline_projection = {}
    extra_addresses = set()
    explanations = []
    hooks = ExitStack()

    def required(owner, name):
        target = getattr(owner, name, None)
        if not callable(target):
            raise AssertionError(f'R11 required hook missing: {owner}.{name}')
        return target

    def observe_side(original, label):
        signature = inspect.signature(original)
        def observed(*args, **kwargs):
            bound = signature.bind(*args, **kwargs).arguments
            watch = bound.get('watch')
            # Older metadata/body helpers omit watch; recover the calling body
            # context explicitly, and fail if that seam ceases to identify it.
            if watch is None:
                for frame in inspect.stack():
                    candidate = frame.frame.f_locals.get('watch')
                    if hasattr(candidate, 'id'):
                        watch = candidate
                        break
            if watch is None:
                audit['missing'].append(f'{label}: no watch context')
            elif watch.id in cohort_set:
                audit['side_calls'].append(f'{label}:{watch.id}')
            return original(*args, **kwargs)
        return observed

    if not reference:
        from cornicen import advisory
        route = getattr(advisory, 'route', None)
        if not callable(route):
            # Keep collecting observable old-logic regressions, but this missing
            # public seam is itself an explicit failing assertion, never a skip.
            audit['missing'].append('advisory.route')
        else:
            def observed_route(db, identity, watch, *args, **kwargs):
                decision = route(db, identity, watch, *args, **kwargs)
                sites = [f.function for f in inspect.stack()
                         if f.function in ('_evaluate', '_revalidate', '_body', 'reload_watches', 'explain', 'commit_advisory')]
                item = dict(watch=watch.id, identity=identity, route=decision, sites=sites)
                routes.append(item)
                audit['routes'].append(item)
                return decision
            hooks.enter_context(patch.object(advisory, 'route', observed_route))
        for name in ('resolve', 'metadata', 'fix_for'):
            original = required(advisory, name)
            hooks.enter_context(patch.object(advisory, name, observe_side(original, 'advisory.' + name)))
        # Include future advisory body builders rather than silently ignoring one.
        for name, original in inspect.getmembers(advisory, inspect.isfunction):
            if 'body' in name:
                hooks.enter_context(patch.object(advisory, name, observe_side(original, 'advisory.' + name)))
        for name in ('advisory_result', 'advisory_fix'):
            original = required(Engine, name)
            hooks.enter_context(patch.object(Engine, name, observe_side(original, 'Engine.' + name)))

    def project_body(body):
        # Only the extra watch's counted baseline contribution is removed.
        # Preserve all other summary fields and validate the unprojected total.
        body = dict(body)
        if variant in ('mixed', 'mixed_late') and body.get('record_id') == 'baseline':
            detail = body.get('detail')
            if detail not in baseline_projection:
                raise AssertionError('R11 baseline summary missing counted contribution')
            body['detail'] = baseline_projection[detail]
        return body

    def keep(watch):
        return not watch or watch in cohort_set

    class Notifier:
        down = False
        def send(self, notification):
            if self.down:
                return False
            wire = asdict(notification)
            if wire['watch_id'] == EXTRA:
                audit['extra_bodies'].append(wire['body'])
            wire['body'] = project_body(wire['body'])
            items = wire['body'].get('items')
            if items and any(i['watch_id'] == EXTRA for i in items):
                audit['extra_digest'] = True
            if items is not None:
                items = [item for item in items if keep(item['watch_id'])]
                if not items:
                    return True
                if variant in ('mixed', 'mixed_late'):
                    items = [dict(item, key=str(int(item['key']) - sum(
                        address < int(item['key']) for address in extra_addresses))) for item in items]
                wire['body'] = dict(wire['body'], items=items)
                if len(items) == 1:
                    wire.update(watch_id=items[0]['watch_id'], record_id=items[0]['record_id'],
                                reasons=items[0]['reasons'])
                # Transport row IDs are allocated across all watches. They are
                # not event keys; bodies and rendered text retain every field.
                for item in items:
                    member = dict(item)
                    member.pop('key')
                    deliveries.append(dict(t=clock().isoformat(), **member,
                        rendered=list(render(Notification(**item)))))
                rendered = render(Notification(**wire))
            else:
                if not keep(wire['watch_id']):
                    return True
                rendered = render(Notification(**wire))
                wire.pop('key')
                deliveries.append(dict(t=clock().isoformat(), **wire, rendered=list(rendered)))
            wire.pop('key', None)
            envelopes.append(dict(t=clock().isoformat(), notification=wire, rendered=list(rendered)))
            return True

    store = Store(':memory:')
    store.migrate()
    if variant in ('mixed', 'mixed_late'):
        original_queue = required(store, 'queue')
        def queue(pair_key, urgency, reasons, body, *args, **kwargs):
            address = original_queue(pair_key, urgency, reasons, body, *args, **kwargs)
            if body.get('watch_id') == EXTRA:
                extra_addresses.add(address)
            else:
                extra_addresses.discard(address)
            return address
        store.queue = queue
    config = Config(db_path=':memory:', watchlist_path=Path('tests/fixtures/watchlist_example.toml'),
        aliases_path=None, ntfy_url='https://ntfy.invalid', ntfy_topic='replay', ntfy_token=None,
        epss_threshold=0.10, digest_time='08:00', timezone='UTC', overdue_minutes=60,
        user_agent='Cornicen/0.1.0 (+https://github.com/<owner>/cornicen)',
        user_agent_overrides={}, retention_days=365)
    notifier = Notifier()
    aliases = AliasMap.load(builtin=False)
    accepts = ()
    engine = None
    snapshots = []
    pending = []
    evaluation_failure = False
    isolation_depth = 0

    def watches(text):
        nonlocal accepts
        if path.parent.name == 'replay_r11':
            result, accepts = load_document_text(text)
        else:
            result = load_watchlist_text(text)
        if variant in ('mixed', 'mixed_late'):
            result += load_watchlist_text(EXTRA_TEXT)
        return result

    def instrument(value):
        original_isolated = required(value, '_isolated')
        def isolated(*args, **kwargs):
            nonlocal isolation_depth
            isolation_depth += 1
            try:
                return original_isolated(*args, **kwargs)
            finally:
                isolation_depth -= 1
        value._isolated = isolated
        if variant in ('mixed', 'mixed_late'):
            original_event = required(value, '_event')
            def event(watch_id, record_id, kind, episode, body, *args, **kwargs):
                if not watch_id and kind == 'baseline':
                    pairs = [dict(r) for r in value.db.execute('SELECT * FROM pairs WHERE baseline=1')]
                    def counts(selected):
                        return (sum(r['state'] == 'affected' or (r['state'] == 'unknown' and r['exploited']) for r in selected),
                                sum(bool(r['exploited']) and r['state'] != 'not_affected' for r in selected))
                    def detail(count):
                        return f'baseline: {count[0]} historical matches, {count[1]} exploited — run `cornicen report`'
                    total = counts(pairs)
                    extra = counts([r for r in pairs if r['watch_id'] == EXTRA])
                    if body['detail'] != detail(total):
                        raise AssertionError(f'R11 baseline total: {body!r}, expected {detail(total)!r}')
                    baseline_projection[body['detail']] = detail(tuple(a - b for a, b in zip(total, extra)))
                    audit['baseline_contributions'].append(extra)
                return original_event(watch_id, record_id, kind, episode, body, *args, **kwargs)
            value._event = event
        return value

    def evaluation_fault():
        if not evaluation_failure:
            return nullcontext()
        # Find the resolver binding actually used by the engine. Support the
        # module binding and a direct import; a refactor to neither fails loudly.
        from cornicen import applicability
        namespace = Engine._evaluate.__globals__
        owner = namespace.get('applicability')
        if owner is not None:
            original_resolve = required(owner, 'resolve')
        elif callable(namespace.get('resolve')):
            owner = __import__(Engine.__module__, fromlist=['resolve'])
            original_resolve = required(owner, 'resolve')
        else:
            raise AssertionError('R11 cannot find engine resolver binding')
        def failed_resolution(*args, **kwargs):
            if isolation_depth:
                raise ValueError('replay evaluation failure')
            return original_resolve(*args, **kwargs)
        return patch.object(owner, 'resolve', failed_resolution)

    try:
        initial = watches(rows[0]['watchlist'])
        engine = instrument(Engine(store, initial, aliases, config, clock, notifier, accepts=accepts))
        if variant:
            from cornicen import applicability
            identity_match = required(applicability, '_identity_match')
            for row in rows:
                if 'watchlist' in row:
                    for watch in load_watchlist_text(row['watchlist']):
                        if identity_match('examplecorp', 'r11_unwatched', watch, aliases):
                            raise ValueError('injected product matches fixture cohort')
            if variant in ('mixed', 'mixed_late') and not identity_match('examplecorp', 'r11_unwatched',
                    next(w for w in initial if w.id == EXTRA), aliases):
                raise ValueError('mixed variant extra watch does not match adapter product')
            if variant not in ('late', 'mixed_late'):
                inject(store, identities, variant, rows[0]['t'])
        for index, row in enumerate(rows):
            clock.now = utc(row['t'])
            routes.clear()
            if index == 0:
                pass
            elif 'watchlist' in row:
                selected = watches(row['watchlist'])
                engine.accepts = accepts
                engine.reload_watches(selected)
            elif 'restart' in row:
                engine = instrument(Engine(store, engine.watches, aliases, engine.config,
                                           clock, notifier, accepts=accepts))
            elif 'notifier' in row:
                notifier.down = row['notifier'] == 'down'
            elif 'ingest' in row:
                pending.append(as_ingest(row['ingest']))
            elif 'evaluation_failure' in row:
                evaluation_failure = row['evaluation_failure']
            elif 'retention_days' in row:
                engine.config = replace(engine.config, retention_days=row['retention_days'])
            elif 'aliases' in row:
                # Use the actual alias file loader, never a matching substitute.
                with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as directory:
                    alias_file = Path(directory) / 'aliases.toml'
                    alias_file.write_text(row['aliases'])
                    aliases = AliasMap.load(False, alias_file)
                engine = instrument(Engine(store, engine.watches, aliases, engine.config,
                                           clock, notifier, accepts=accepts))
            elif 'revision_reload' in row:
                with evaluation_fault():
                    engine.reload_watches(engine.watches, force_all=True)
            elif 'matching_revision' in row:
                store.set_meta('applied_matching_revision', row['matching_revision'])
                engine = instrument(Engine(store, engine.watches, aliases, engine.config,
                                           clock, notifier, accepts=accepts))
            elif 'cycle' in row:
                fault = evaluation_fault()
                with fault:
                    engine.run_cycle(pending)
                pending = []
            elif 'pairs' not in row:
                raise ValueError(f'unknown replay action: {row}')
            db = store.connection
            if variant in ('late', 'mixed_late') and not audit['live'] and row.get('cycle'):
                existing = [r[0] for r in db.execute('SELECT id FROM records ORDER BY id') if r[0] in identities]
                if existing:
                    if variant == 'mixed_late':
                        probe = probe_commit(store, engine, existing, cohort_set, row['t'])
                        audit['commit_probes'].append(probe)
                    inject(store, existing, 'late', row['t'], engine=engine)
                    audit['live'].append(dict(index=index, identities=existing))
            audit['extra_affected'] |= bool(db.execute("SELECT 1 FROM pairs WHERE watch_id=? AND state='affected'", (EXTRA,)).fetchone())
            audit['extra_events'] |= bool(db.execute('SELECT 1 FROM events WHERE watch_id=?', (EXTRA,)).fetchone())
            audit['extra_outbox'] |= bool(db.execute('SELECT 1 FROM outbox WHERE pair_key LIKE ?', (EXTRA + '|%',)).fetchone())
            if explain:
                from cornicen.cli import explain as cli_explain
                observed = []
                for watch in engine.watches:
                    if watch.id not in cohort_set:
                        continue
                    for identity in identities:
                        output = io.StringIO()
                        with redirect_stdout(output):
                            code = cli_explain(store, engine.watches, aliases, identity, watch.id)
                        observed.append(dict(watch=watch.id, identity=identity, code=code, text=output.getvalue()))
                explanations.append(observed)
            pairs = [dict(r) for r in db.execute('SELECT * FROM pairs ORDER BY watch_id,record_id')
                     if keep(r['watch_id'])]
            events = [dict(r) for r in db.execute('SELECT * FROM events ORDER BY key')
                      if keep(r['watch_id'])]
            # Row IDs are surrogate delivery addresses, not the permanent event
            # keys. Project them to the cohort's allocation order, including sent
            # rows, so an extra watch cannot perturb reference queue addresses.
            all_rows = [dict(r) for r in db.execute('SELECT * FROM outbox ORDER BY id')
                        if keep(json.loads(r['body_json']).get('watch_id', ''))]
            outbox = []
            for address, queued in enumerate(all_rows, 1):
                if queued['sent_at'] is None:
                    queued['id'] = address
                    queued['body_json'] = project_body(json.loads(queued['body_json']))
                    queued['reasons_json'] = json.loads(queued['reasons_json'])
                    outbox.append(queued)
            snapshots.append(dict(index=index, t=row['t'], pairs=pairs, events=events,
                outbox=outbox, **cohort_state(db, cohort_set), notifications=json.loads(json.dumps(deliveries)),
                rendered=json.loads(json.dumps(envelopes)), routes=[r for r in routes if r['watch'] in cohort_set]))
        result = dict(cohort=cohort, identities=identities, snapshots=snapshots)
        if not reference:
            result['audit'] = audit
        if explain:
            result['explain'] = explanations
        return result
    finally:
        hooks.close()
        store.connection.close()


def differences(actual, expected):
    """Report every differing observable at every tick, with compact first values."""
    result = []
    if actual['cohort'] != expected['cohort']:
        raise ValueError('fixture cohort changed without reference review')
    if len(actual['snapshots']) != len(expected['snapshots']):
        raise ValueError('timeline changed without reference review')
    def first_delta(got, want, path):
        if isinstance(got, dict) and isinstance(want, dict):
            for key in sorted(set(got) | set(want)):
                if key not in got or key not in want:
                    return f'{path}.{key}: observed {got.get(key, "<absent>")!r} expected {want.get(key, "<absent>")!r}'
                if got[key] != want[key]:
                    return first_delta(got[key], want[key], f'{path}.{key}')
        elif isinstance(got, list) and isinstance(want, list):
            for index, (left, right) in enumerate(zip(got, want)):
                if left != right:
                    return first_delta(left, right, f'{path}[{index}]')
            return f'{path}.length: observed {len(got)} expected {len(want)}'
        return f'{path}: observed {str(got)[:300]!r} expected {str(want)[:300]!r}'
    for got, want in zip(actual['snapshots'], expected['snapshots']):
        for field in ('pairs', 'events', 'outbox', 'notifications', 'rendered',
                      'affected_latches', 'epss_crossings', 'meta', 'health'):
            if got[field] != want[field]:
                result.append(f"tick {want['index']} {want['t']} " + first_delta(got[field], want[field], field))
        for route in got['routes']:
            if route['route'] == 'v1':
                continue
            result.append(f"tick {want['index']} route {route['watch']} {route['identity']}: observed advisory expected v1")
    audit = actual.get('audit', {})
    for probe in audit.get('commit_probes', []):
        if probe['before'] != probe['after']:
            result.append('commit cohort changed: ' + first_delta(probe['after'], probe['before'], 'commit'))
    for field in ('missing', 'side_calls'):
        if audit.get(field):
            result.append(f"{field}: {audit[field][:5]!r}")
    return result


class PendingCase(unittest.TestCase):
    """Only assertion failures may be pending; execution exceptions are errors."""
    def __init__(self, label, execute, assertion, pending=True):
        super().__init__('runTest')
        self.label, self.execute, self.assertion, self.pending = label, execute, assertion, pending

    def id(self):
        return self.label

    def __str__(self):
        return self.label

    def run(self, result=None):
        import os
        import sys
        result = result if result is not None else self.defaultTestResult()
        pending = self.pending and os.environ.get('CORNICEN_R11_PENDING') == '1'
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
                if pending:
                    result.addExpectedFailure(self, sys.exc_info())
                else:
                    result.addFailure(self, sys.exc_info())
            except Exception:
                result.addError(self, sys.exc_info())
            else:
                if pending:
                    try:
                        raise AssertionError('lifted early: remove the R11 pending designation')
                    except AssertionError:
                        result.addFailure(self, sys.exc_info())
                else:
                    result.addSuccess(self)
        finally:
            result.stopTest(self)
        return result


def load_reference(name):
    """Read a lossless JSON reference, compressed when its capture exceeds 5 MB."""
    path = REFERENCE / (name + '.json')
    if path.exists():
        return json.loads(path.read_text())
    return json.loads(gzip.decompress(path.with_suffix('.json.gz').read_bytes()))

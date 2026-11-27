# script-purpose: Verify package matching and watch transitions with invented evidence.
# script-class: harness
# script-trigger: Python unittest discovery.
# script-tests: tests/test_package_matching.py
"""Read package parity fixtures and write only test databases and watch files.

Unittest exits 0 on success and 1 on test failure.
"""

import ast
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import acceptance, advisory, advisoryidentity, cnascope
from cornicen.applicability import Result, State, resolve
from cornicen.cli import _near, main, watch_check
from cornicen.config import Config
from cornicen.diagnostics import FixedDiagnostic
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.public_text import public_text
from cornicen.releases import ReleaseChecker
from cornicen.scheduler import Scheduler
from cornicen.store import Store
from cornicen.vocabulary import WORDS
from cornicen.watchlist import (PackageSelector, WatchlistError, collisions,
    load_watchlist_text, normalise_collection_url, normalise_package_name, package_key,
    validate_watch_transition)

from tests.package_parity import (BASELINE, DISTRO, EXACT, EXACT_TEXT, NAME, NOW, REVISION_2, ROOT,
    UPSTREAM, acceptance_outputs, cve, kev, outputs, record, scoped, seed_adapter,
    source_pins, upstream, watch_check_outputs)

# R-SK5: exact additions since the vocabulary pinned by T31.
STORED_EVENT_KEY_WORDS = frozenset({
    'cascade', "json_extract(body_json,'$.watch_id", 'key(outbox_id,reason,key,legacy',
    'legacy', 'outbox,json_each(reasons_json', 'outbox.id', 'outbox_event_keys',
    'outbox_event_keys_version', 'outbox_id', 'outbox_id=', 'reason,key,legacy',
    'reason.value',
})

EXAMPLE = '''[[watch]]
id = "example-console-host"
name = "Example Console on a test host"
package = [
  { collection_url = "https://git.example.invalid/example-console", package_name = "example-console" },
  { collection_url = "https://packages.example.invalid/browser/", package_name = "example-console" },
]
version = "41.7"
scheme = "dotted"
'''
WATCH_TEXT = EXAMPLE.replace('example-console-host', 'console-host')
WATCH, = load_watchlist_text(WATCH_TEXT)
ALIASES = AliasMap.load(False)
EXACT_ENTRY = dict(vendor='example vendor', product='example console', defaultStatus='unaffected')
AFFECTED = Result(State.AFFECTED, False,
    'CNA affected example-console: 40.0 <= version < 42.0; versionType semver', 'high')
PRESENCE = Result(State.UNKNOWN, False,
    'Package identity match only; version applicability unknown', 'low')
LOOSE = Result(State.UNKNOWN, False,
    'Product-only identity match; version applicability unknown', 'low')
CANONICAL = (
    b'[{"eol":false,"id":"console-exact","match":[["example vendor","example console"]],'
    b'"name":"Example Console on a test host","product_only":[],"scheme":"dotted","version":"41.7"},'
    b'{"eol":false,"id":"console-host","match":[],"name":"Example Console on a test host",'
    b'"product_only":["example-console"],"scheme":"dotted","version":"41.7"}]'
)


def pair_result(row):
    return Result(State(row['state']), bool(row['exploited']), row['evidence'], row['confidence'])


class PackageMatchingTests(unittest.TestCase):
    def decide(self, *entries, watch=WATCH, kev_row=None, state='PUBLISHED'):
        return resolve(record(*entries, state=state), kev_row, watch, ALIASES, packages=True)

    def make_engine(self, watches=(WATCH,), *, db_path=':memory:'):
        store = Store(db_path)
        store.migrate()
        self.addCleanup(store.connection.close)
        config = Config(db_path, Path('unused'), None, '', '', None)
        engine = Engine(store, watches, ALIASES, config, lambda: NOW, Mock())
        store.set_meta('baseline_complete', '1')
        return engine

    def restart(self, engine):
        return Engine(engine.store, engine.watches, engine.aliases, engine.config,
                      engine.clock, engine.notifier)

    def ingest(self, engine, *items, catalog=None):
        source = 'cvelist' if catalog is None else 'kev'
        engine._health_verdicts = {}
        with engine.store.transaction():
            engine._ingest(IngestResult(source, FetchStatus.COMPLETE, Origin.DELTA,
                                        None, NOW, records=items, kev=catalog))

    def pair(self, engine, watch=WATCH, identity=None):
        return engine.db.execute('SELECT * FROM pairs WHERE watch_id=? AND record_id=?',
                                 (watch.id, identity or cve())).fetchone()

    def outbox(self, engine):
        return engine.db.execute('SELECT * FROM outbox ORDER BY id').fetchall()

    def tables(self, engine, watch=None):
        pairs, events = ([dict(row) for row in engine.db.execute(f'SELECT * FROM {table} ORDER BY 1,2')
                          if watch is None or row['watch_id'] == watch.id]
                         for table in ('pairs', 'events'))
        outbox = [dict(row) for row in self.outbox(engine)
                  if watch is None or json.loads(row['body_json']).get('watch_id') == watch.id]
        return pairs, events, outbox

    def test_t01_parse_example(self):
        watch, = load_watchlist_text(EXAMPLE)
        self.assertEqual((watch.match, watch.product_only), ((), ()))
        self.assertEqual(watch.package, (PackageSelector(UPSTREAM, NAME),
                                        PackageSelector(DISTRO.rstrip('/'), NAME)))

    def test_t02_fixed_diagnostics(self):
        base = WATCH_TEXT[:WATCH_TEXT.index('package =')] + 'version = "41.7"\nscheme = "dotted"\n'

        def selector(url=UPSTREAM, name=NAME):
            return '{ collection_url = ' + json.dumps(url, ensure_ascii=False) + (
                ', package_name = ' + json.dumps(name, ensure_ascii=False) + ' }')

        pair = selector()
        keys = 'package selector requires collection_url and package_name'
        bad_url = 'package collection_url is invalid'
        bad_name = 'package package_name is invalid'
        legacy = 'github and osv require match or product_only'
        cases = [
            ('[' + pair[:-1] + ', version = "41.7" }]', keys, ''),
            ('[{ collection_url = ' + json.dumps(UPSTREAM) + ' }]', keys, ''),
            ('[' + ','.join([pair] * 21) + ']', 'package must be an array of at most 20 selectors', ''),
            ('[' + pair + ']', legacy, 'osv = [{ ecosystem = "Example Distro", package = "example-console" }]'),
            ('[' + pair + ']', legacy,
             'github = [{ repository = "example-console/example-console", ecosystem = "other", package = "example-console" }]'),
            ('[' + selector(name='') + ']', bad_name, ''),
            ('[' + selector(name='\a') + ']', bad_name, ''),
            ('[' + pair + ',' + selector('https://GIT.example.invalid/example-console/') + ']',
             'duplicate package selector', ''),
            ('[]', 'match, product_only or package must declare at least one identity', ''),
            (None, 'match, product_only or package must declare at least one identity', ''),
        ]
        for invalid in ('ftp://git.example.invalid/x', 'https://',
                        'https://user@git.example.invalid/x', 'https://git.example.invalid:8443/x',
                        'https://git.example.invalid:nope/x', 'https://[fe80::1]/x',
                        'https://gït.example.invalid/x', 'https://git.example.invalid/x x',
                        'https://git.example.invalid/x\u200b', 'https://git..example.invalid/x',
                        'https://-git.example.invalid/x', 'https://git-.example.invalid/x',
                        'https://' + 'x' * 64 + '.example.invalid/x',
                        'https://git.example.invalid/x%', 'https://git.example.invalid/x%0',
                        'https://git.example.invalid/x%0x'):
            cases.append(('[' + selector(invalid) + ']', bad_url, ''))
        for value, reason, extra in cases:
            with self.subTest(value=value, extra=extra):
                line = 'package = ' + value + '\n' if value is not None else ''
                with self.assertRaises(WatchlistError) as raised:
                    load_watchlist_text(base + line + extra)
                message, = raised.exception.public_problems
                self.assertIs(type(message), FixedDiagnostic)
                self.assertEqual(message, 'watch entry 1: ' + reason)
        watch, = load_watchlist_text(base + 'package = [' + selector(name='null') + ']')
        self.assertEqual(watch.package[0].package_name, 'null')

    def test_t03_normalisers(self):
        self.assertEqual(normalise_collection_url('HTTPS://Git.Example.invalid/example-console//'), UPSTREAM)
        self.assertNotEqual(normalise_collection_url('https://git.example.invalid/Example-Console'), UPSTREAM)
        query = 'https://git.example.invalid/x?repo=Sample/'
        self.assertEqual(normalise_collection_url(query), query)
        self.assertEqual(len({normalise_collection_url('https://git.example.invalid/x/' + end)
                              for end in ('?', '#', '')}), 3)
        self.assertNotEqual(normalise_collection_url(UPSTREAM + '.git'), UPSTREAM)
        escaped = 'https://git.example.invalid/x%2f'
        self.assertEqual(normalise_collection_url(escaped), escaped)
        self.assertIsNone(package_key(upstream(collectionURL='https://git.example.invalid/x?re\tpo=Sample')))
        self.assertEqual(package_key(upstream(collectionURL='  ' + UPSTREAM + '\t')), (UPSTREAM, NAME))
        self.assertEqual(normalise_package_name('Example-Console'), NAME)
        self.assertNotEqual(normalise_package_name('ℌello'), normalise_package_name('hello'))
        self.assertEqual(normalise_package_name(' E\u0301 \u200b '), '\u00e9')

    def test_t04_vendorless_affected(self):
        self.assertEqual(self.decide(upstream()), AFFECTED)

    def test_t05_vendorless_exclusion(self):
        result = self.decide(upstream(), watch=replace(WATCH, version='42.3'))
        self.assertEqual((result.state, result.confidence), (State.NOT_AFFECTED, 'high'))

    def test_t06_product_scoped_versions_are_presence_only(self):
        self.assertEqual(self.decide(scoped()), PRESENCE)

    def test_t07_product_scoped_default_is_presence_only(self):
        item = scoped(defaultStatus='unaffected')
        del item['versions']
        self.assertEqual(self.decide(item), PRESENCE)

    def test_t08_package_beats_product_scoped(self):
        self.assertEqual(self.decide(upstream(), scoped(defaultStatus='unaffected')), AFFECTED)

    def test_t09_vendorless_open_range(self):
        self.assertEqual(self.decide(upstream(versions=[dict(version='40.0', lessThan='*',
                            status='affected')])).state, State.AFFECTED)

    def test_t10_incomplete_identity(self):
        for item in (dict(packageName=NAME), dict(collectionURL=UPSTREAM), upstream(packageName=7)):
            with self.subTest(item=item):
                self.assertIsNone(self.decide(item))

    def test_t11_exact_beats_package(self):
        entries = (EXACT_ENTRY, upstream())
        expected = self.decide(*entries, watch=EXACT)
        self.assertEqual(expected.state, State.NOT_AFFECTED)
        self.assertEqual(self.decide(*entries, watch=replace(EXACT, package=WATCH.package)), expected)

    def test_t12_package_beats_loose_match(self):
        watch = replace(WATCH, product_only=(NAME,))
        item = upstream(vendor='n/a', product=NAME)
        self.assertEqual(self.decide(item, watch=watch), AFFECTED)
        self.assertEqual(self.decide(item, watch=replace(watch, package=())), LOOSE)

    def test_package_tiers_require_literal_true(self):
        watch = replace(WATCH, product_only=(NAME,))
        item = record(upstream(vendor='n/a', product=NAME))
        self.assertEqual(resolve(item, None, watch, ALIASES, packages=True), AFFECTED)
        for flag in ('false', 1):
            with self.subTest(flag=flag):
                self.assertEqual(resolve(item, None, watch, ALIASES, packages=flag), LOOSE)

    def test_t13a_exploitation_by_cve(self):
        for case in (1, 2, 3):
            with self.subTest(case=case):
                engine = self.make_engine()
                initial = cve(1) if case != 2 else cve()
                self.ingest(engine, catalog={initial: kev(initial)})
                self.assertEqual(engine.store.get_meta('kev_initialized'), '1')
                if case != 3:
                    selected = cve() if case == 1 else cve(1)
                    self.ingest(engine, catalog={selected: kev(selected)})
                    self.assertEqual([row['cve'] for row in engine.db.execute('SELECT cve FROM kev')],
                                     [selected])
                self.ingest(engine, record(scoped()))
                self.assertEqual(pair_result(self.pair(engine)), replace(PRESENCE, exploited=case == 1))
                rows = self.outbox(engine)
                self.assertEqual([(row['urgency'], row['sent_at']) for row in rows],
                                 [('urgent', None)] if case == 1 else [])

    def test_t13b_resolver_checks_kev_id(self):
        for row, exploited in ((kev(cve(1)), False), (kev(cve()), True), (None, False)):
            with self.subTest(row=row):
                self.assertEqual(self.decide(scoped(), kev_row=row), replace(PRESENCE, exploited=exploited))

    def test_t14a_rejected_package_record(self):
        expected = Result(State.NOT_AFFECTED, False, 'CNA record rejected or withdrawn', 'high')
        self.assertEqual(self.decide(upstream(), state='REJECTED'), expected)

    def test_t14b_rejected_tombstone_reaches_stored_pair(self):
        engine = self.make_engine()
        self.ingest(engine, record(upstream()))
        self.assertEqual(pair_result(self.pair(engine)), AFFECTED)
        self.ingest(engine, {'cveMetadata': {'cveId': cve(), 'state': 'REJECTED'}})
        self.assertEqual(pair_result(self.pair(engine)),
                         Result(State.NOT_AFFECTED, False, 'CNA record rejected', 'high'))

    def test_t15_legacy_parity(self):
        baseline = json.loads(BASELINE.read_text())
        self.assertEqual(baseline['base_version'], '0.9.0')
        self.assertEqual(outputs(), baseline['outputs'])

    def test_t16_canonical_legacy_bytes_and_restore(self):
        loose = replace(WATCH, product_only=(NAME,), package=())
        watches = (loose, EXACT)
        self.assertEqual(Engine._canonical_watches(watches).encode(), CANONICAL)
        engine = self.make_engine(watches)
        engine.store.set_meta('applied_watches', CANONICAL.decode())
        engine.store.set_meta('applied_matching_revision', '2')
        before_reload = []
        original = Engine.reload_watches
        def spy(current, *args, **kwargs):
            before_reload.extend(current.watches)
            return original(current, *args, **kwargs)
        with patch.object(Engine, 'reload_watches', spy):
            self.restart(engine)
        self.assertEqual(before_reload, [EXACT, loose])
        self.assertTrue(all(watch.package == () for watch in before_reload))
        # R-P16: the package-only watch takes a new id rather than converting `loose`.
        packaged = replace(WATCH, id=WATCH.id + '-pkg')
        engine.reload_watches((packaged, EXACT))
        before_reload.clear()
        with patch.object(Engine, 'reload_watches', spy):
            Engine(engine.store, (replace(packaged, package=packaged.package[:1]), EXACT),
                   engine.aliases, engine.config, engine.clock, engine.notifier)
        self.assertEqual(before_reload, [EXACT, packaged])

    def test_t17_revision_upgrade_runs_once(self):
        snapshot = json.loads(REVISION_2.read_text())
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        store.connection.executescript('\n'.join(snapshot['database']))
        pairs, events, rows = snapshot['expected']
        self.assertEqual(store.get_meta('applied_matching_revision'), '2')
        self.assertEqual([row['dirty'] for row in store.connection.execute('SELECT * FROM outbox')], [0])
        config = Config(':memory:', Path('unused'), None, '', '', None)
        with patch.object(Engine, '_rematch_record', autospec=True,
                          side_effect=Engine._rematch_record) as rematch:
            upgraded = Engine(store, (EXACT,), ALIASES, config, lambda: NOW, Mock())
            self.assertCountEqual([call.args[2] for call in rematch.call_args_list], [cve(), cve(1)])
            rematch.reset_mock()
            self.assertEqual(store.get_meta('applied_matching_revision'), '3')
            after = self.tables(upgraded)
            self.assertEqual(after, (pairs, events, [dict(row, dirty=1) for row in rows]))
            restarted = self.restart(upgraded)
            self.assertEqual(self.tables(restarted), after)
            rematch.assert_not_called()
        # The upgrade defers rebuilding the payload until revalidation.
        restarted._refresh_pending(rows[0]['id'])
        self.assertEqual(self.tables(restarted), (pairs, events, rows))

    def test_t18_reload_only_edited_selector(self):
        before = replace(WATCH, package=WATCH.package[1:])
        engine = self.make_engine((before, EXACT))
        self.ingest(engine, record(upstream()), record(dict(EXACT_ENTRY, defaultStatus='affected'),
                                                      offset=1))
        self.assertIsNone(self.pair(engine))
        saved = self.tables(engine, EXACT)
        self.assertTrue(all(saved))
        with patch.object(engine, '_rematch_record', wraps=engine._rematch_record) as spy:
            engine.reload_watches((WATCH, EXACT))
        self.assertCountEqual([call.args[1] for call in spy.call_args_list], [cve(), cve(1)])
        self.assertTrue(all(call.kwargs['watches'] == (WATCH,) for call in spy.call_args_list))
        self.assertEqual(pair_result(self.pair(engine)), AFFECTED)
        after = self.tables(engine, EXACT)
        self.assertEqual(after[:2], saved[:2])
        self.assertEqual([dict(row, dirty=0) for row in after[2]],
                         [dict(row, dirty=0) for row in saved[2]])

    def test_t19_scopes_do_not_match_package_only(self):
        for item in (record(upstream()), record(scoped())):
            self.assertEqual(cnascope.scoped_verdicts(item, WATCH, ALIASES), ())

    def release(self):
        watch = replace(WATCH, latest_release='github:example-console/example-console')
        engine = self.make_engine((watch,))
        checker = ReleaseChecker(Mock())
        repository = watch.latest_release
        checker._record(engine, (repository,), [(repository, 'release_check:' + repository,
                                                 dict(failed=False, release='42.3'))])
        row, = (row for row in self.outbox(engine)
                if json.loads(row['body_json']).get('release_behind'))
        return watch, engine, row

    def test_t20_product_labels_in_digest(self):
        watch, engine, release = self.release()
        self.assertEqual(json.loads(release['body_json'])['product'], NAME)
        self.ingest(engine, record(upstream()), record(scoped(), offset=1))
        engine.reload_watches((replace(watch, version='40.0'),))
        engine.db.execute("UPDATE outbox SET due_at=? WHERE urgency='normal'", (NOW.isoformat(),))
        engine._flush()
        sent, = (call.args[0] for call in engine.notifier.send.call_args_list
                 if 'items' in call.args[0].body)
        items = [item['body'] for item in sent.body['items']]
        self.assertEqual([item['product'] for item in items], [NAME, NAME])
        self.assertEqual(next(item['version'] for item in items if item.get('release_behind')), '40.0')
        self.assertEqual(sent.body['applicability']['list'][0]['product'], NAME)

    def test_t21_private_collection_inventory(self):
        line = 'seen token near path source unknown'
        self.assertLessEqual(set(line.split()), WORDS)
        self.assertEqual(public_text(line), line)
        watch = replace(WATCH, package=(PackageSelector(
            'https://near.example.invalid/path?source#unknown', 'token'),))
        self.assertEqual(public_text(line, (watch,)), 'seen [redacted]')
        for word in line.split()[1:]:
            with self.subTest(word=word):
                self.assertEqual(public_text(word, (watch,)), '[redacted]')

    def test_t22_watch_check_near_miss(self):
        engine = self.make_engine()
        near = record(dict(packageName=NAME, collectionURL='https://other.example.invalid/'))
        engine.store.put_record(cve(), near, NOW.isoformat())
        printed = io.StringIO()
        with redirect_stdout(printed):
            watch_check(engine.store, (WATCH,), ALIASES, 90, NOW)
        self.assertIn(f'console-host: matched none; near misses {cve()}', printed.getvalue())
        self.assertFalse(_near(record(upstream()), WATCH, ALIASES))
        self.assertFalse(_near(record(None), WATCH, ALIASES))
        malformed = record()
        malformed['containers']['cna']['affected'] = 7
        self.assertFalse(_near(malformed, WATCH, ALIASES))

    def test_t23_package_collisions_use_tuples(self):
        first = replace(WATCH, package=WATCH.package[:1])
        other = replace(first, id=EXACT.id)
        self.assertEqual(collisions((first, other)),
                         [f'console-host and console-exact claim package {UPSTREAM} {NAME}'])
        first = replace(first, package=(PackageSelector('https://h.example.invalid/a|b', 'c'),))
        other = replace(other, package=(PackageSelector('https://h.example.invalid/a', 'b|c'),))
        self.assertEqual(collisions((first, other)), [])
        self.assertIsNone(self.decide(upstream(collectionURL='https://h.example.invalid/a',
                                               packageName='b|c'), watch=first))

    def test_t24_digest_classifies_package_presence(self):
        engine = self.make_engine()
        self.ingest(engine, record(scoped()), record(upstream(), offset=1))
        self.assertEqual(pair_result(self.pair(engine)), PRESENCE)
        self.assertEqual(len(self.outbox(engine)), 1)
        engine.db.execute('UPDATE outbox SET due_at=?', (NOW.isoformat(),))
        engine._flush()
        sent, = engine.notifier.send.call_args.args
        section = sent.body['applicability']
        self.assertEqual(section['why'], [['package only', 1]])
        self.assertEqual(section['list'][0]['ids'], [cve()])

    # T25 is test_matching_revision_pin in tests/test_rematch_revision.py.

    def test_t26_malformed_exact_still_beats_package(self):
        entries = (dict(EXACT_ENTRY, version='40.0'), upstream())
        expected = self.decide(*entries, watch=EXACT)
        self.assertEqual(expected, Result(State.UNKNOWN, False,
                         'CNA unknown example console: version fields outside versions[]', 'medium'))
        self.assertEqual(self.decide(*entries, watch=replace(EXACT, package=WATCH.package)), expected)

    def test_t27_loose_kev_beats_package_presence(self):
        watch = replace(WATCH, product_only=('example console',))
        self.assertEqual(self.decide(scoped(), watch=watch, kev_row=kev(cve(), 'Example', 'Example Console')),
                         replace(LOOSE, exploited=True))

    def test_t28_package_only_routes_plain(self):
        engine = self.make_engine((WATCH, EXACT))
        seed_adapter(engine.db, cve())
        advisory.remember(engine.db, cve(), EXACT, [('fixture_a', cve())])
        item = record(upstream())
        self.assertEqual(engine.route(cve(), WATCH), 'v1')
        self.assertEqual(engine.route(cve(), EXACT), 'advisory')
        self.ingest(engine, item)
        self.assertEqual(pair_result(self.pair(engine)), AFFECTED)
        self.assertEqual(pair_result(self.pair(engine, EXACT)),
                         advisory.resolve(engine.db, cve(), EXACT, ALIASES, record=item))
        # History is keyed by watch ID and survives a change of identity.
        advisory.remember(engine.db, cve(), WATCH, [('fixture_a', cve())])
        self.assertEqual(engine.route(cve(), WATCH), 'v1')

    def test_t29_package_only_acceptance_read_only(self):
        engine = self.make_engine()
        self.ingest(engine, record(upstream()))
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory)
            pinned, expect = path / 'pinned.toml', path / 'expect.toml'
            pinned.write_text(WATCH_TEXT)
            expect.write_text(f'[[expect]]\nwatch_id = "console-host"\ncve = "{cve()}"\n')
            entries = acceptance.load_entries(expect)
            watches = acceptance.load_watches(pinned, entries)
        before = engine.db.total_changes
        self.assertEqual(acceptance.evaluate(engine.store, entries, watches, ALIASES),
                         [acceptance.Outcome(WATCH.id, cve(), 'pass', 'affected')])
        self.assertEqual(engine.db.total_changes, before)

    def test_t30_revalidate_changed_release_product_and_name(self):
        watch, engine, row = self.release()
        changed = replace(watch, name=EXACT.id,
                          package=(replace(watch.package[0], package_name='example-console-ng'),))
        engine.reload_watches((changed,))
        body = json.loads(engine._revalidate(row)['body_json'])
        self.assertEqual((body['name'], body['product']), (changed.name, 'example-console-ng'))

    def test_t31_vocabulary_diff(self):
        old = set(json.loads(BASELINE.read_text())['words'])
        t31 = {
            'collection_url', 'collectionurl', 'package_name', 'package_scoped',
            'packagename', 'packageselector',
        }
        previous = old | t31

        def assert_delta(words):
            # R-SK5: preserve the old T31 pin and compare the new delta separately.
            self.assertSetEqual((words - STORED_EVENT_KEY_WORDS) - old, t31)
            self.assertSetEqual(previous - words, set())
            self.assertSetEqual(words - previous, STORED_EVENT_KEY_WORDS)

        assert_delta(WORDS)
        with self.assertRaisesRegex(AssertionError, 'outbox_event_keys_version_unapproved'):
            assert_delta(WORDS | {'outbox_event_keys_version_unapproved'})

    def test_t32_shared_identity_cache_keeps_package_rows_separate(self):
        first, second = (replace(WATCH, package=(WATCH.package[0],)),
                         replace(WATCH, id=EXACT.id, package=(WATCH.package[1],)))
        entries = [upstream(vendor='n/a', product='spare console'),
                   upstream(collectionURL=DISTRO, vendor='n/a', product='spare console',
                            versions=[])]
        for order in (entries, entries[::-1]):
            with self.subTest(order=order):
                engine = self.make_engine((first, second))
                self.ingest(engine, record(*order))
                self.assertEqual(self.pair(engine, first)['state'], 'affected')
                self.assertEqual(self.pair(engine, second)['state'], 'not_affected')

    def test_t33_legacy_advisory_files_are_byte_identical(self):
        self.assertEqual(source_pins(ROOT / 'src'), json.loads(BASELINE.read_text())['source_pins'])

    def test_t34_routed_watch_ignores_package(self):
        watch = replace(EXACT, package=WATCH.package)
        engine = self.make_engine((watch,))
        seed_adapter(engine.db, cve())
        item = record(upstream())
        self.assertEqual(engine.route(cve(), watch), 'advisory')
        expected = advisory.resolve(engine.db, cve(), EXACT, ALIASES, record=item)
        self.assertEqual(expected.state, State.NOT_AFFECTED)
        self.ingest(engine, item)
        self.assertEqual(pair_result(self.pair(engine, watch)), expected)

        # A vendorless CNA row can already match the legacy loose name. It
        # must not be promoted to evaluated package evidence inside scoping.
        watch = replace(watch, product_only=(NAME,))
        engine.reload_watches((watch,))
        item = record(upstream(vendor='n/a', product=NAME))
        legacy = replace(watch, package=())
        expected = advisory.resolve(engine.db, cve(), legacy, ALIASES, record=item)
        self.assertEqual(advisory.resolve(engine.db, cve(), watch,
                                         ALIASES, record=item), expected)
        self.ingest(engine, item)
        self.assertEqual(pair_result(self.pair(engine, watch)), expected)

    def seed_package_only_transition(self, path=':memory:', *, link_advisory=False):
        store = Store(path)
        self.addCleanup(store.connection.close)
        legacy = replace(EXACT, id='console-shift')
        store.migrate()
        config = Config(path, Path('unused'), None, '', '', None)
        engine = Engine(store, (legacy,), ALIASES, config, lambda: NOW, Mock())
        store.set_meta('baseline_complete', '1')
        identity = 'advisory:fixture_a:fixture-console:1' if link_advisory else cve()
        seed_adapter(engine.db, identity)
        engine.db.execute('INSERT INTO advisory_support VALUES (?,?,?)', ('fixture_a', identity, identity))
        engine.db.execute("UPDATE advisory_evidence SET status='known_affected'")
        engine._evaluate(None, identity, advisory_only=True)
        self.ingest(engine, record(dict(EXACT_ENTRY, defaultStatus='affected'),
                                   upstream(), offset=1))
        engine.db.execute('UPDATE outbox SET due_at=?', (NOW.isoformat(),))
        engine._flush()
        if link_advisory:
            advisoryidentity.link(engine, identity, cve(), NOW.isoformat())
        for identity in (cve(), cve(1)):
            pair = self.pair(engine, legacy, identity)
            self.assertEqual((pair['state'], pair['episode'], pair['notified']), ('affected', 1, 1))
        self.assertIsNone(engine._record(cve()))
        advisory.remember(engine.db, cve(55), legacy, [('fixture_a', cve())])
        return engine, replace(WATCH, id=legacy.id)

    def transition_scheduler(self, engine, directory, watch):
        path = Path(directory) / 'watch.toml'
        engine.config = replace(engine.config, watchlist_path=path)
        scheduler = Scheduler(engine, {}, clock=engine.clock)
        path.write_text(WATCH_TEXT.replace(WATCH.id, watch.id))
        return scheduler

    def transition_cli(self, engine, directory, *args):
        config = Path(directory) / 'config.toml'
        config.write_text(f'db_path = "{engine.config.db_path}"\n'
                          f'watchlist_path = "{engine.config.watchlist_path}"\n')
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(['--config', str(config), *args])
        return code, out.getvalue(), err.getvalue()

    def state_except_watchlist_health(self, engine):
        return tuple(statement for statement in engine.db.iterdump()
                     if not statement.startswith((
                         'INSERT INTO "health" VALUES',
                         """INSERT INTO "meta" VALUES('health_episode:watchlist'""",
                         """INSERT INTO "events" VALUES('|watchlist|""",
                         """INSERT INTO "sqlite_sequence" VALUES('outbox'""",
                     )) and not (statement.startswith('INSERT INTO "outbox" VALUES')
                                 and "'|watchlist|" in statement))

    def assert_watchlist_rejected(self, engine, scheduler):
        before = self.state_except_watchlist_health(engine)
        watches, accepts, stamp = engine.watches, engine.accepts, scheduler.watch_stamp
        scheduler._reload()
        self.assertEqual(engine.db.execute(
            "SELECT state,detail FROM health WHERE source='watchlist'").fetchone()[:],
            ('unhealthy', 'Watchlist reload rejected'))
        self.assertEqual((engine.watches, engine.accepts, scheduler.watch_stamp),
                         (watches, accepts, stamp))
        self.assertEqual(self.state_except_watchlist_health(engine), before)

    def seed_transition_pair(self, engine, watch):
        engine.db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                          (watch.id, cve(), 'affected', 1, 0, 0, 1,
                           'fixture', 'high', ALIASES.version))

    def test_t35_triple_prime_1_reject_reload_from_match(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            legacy = replace(EXACT, id='console-shift')
            engine = self.make_engine((legacy,))
            self.seed_transition_pair(engine, legacy)
            watch = replace(WATCH, id=legacy.id)
            scheduler = self.transition_scheduler(engine, directory, watch)
            self.assert_watchlist_rejected(engine, scheduler)

    def test_t35_triple_prime_2_reject_startup_from_applied_match(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            db_path = str(Path(directory) / 'test.db')
            store = Store(db_path)
            self.addCleanup(store.connection.close)
            store.migrate()
            legacy = replace(EXACT, id='console-shift')
            engine = Engine(store, (legacy,), ALIASES,
                            Config(db_path, Path('unused'), None, '', '', None), lambda: NOW, Mock())
            self.seed_transition_pair(engine, legacy)
            watch = replace(WATCH, id=legacy.id)
            self.transition_scheduler(engine, directory, watch)
            config = Path(directory) / 'config.toml'
            config.write_text(f'db_path = "{db_path}"\nwatchlist_path = "{engine.config.watchlist_path}"\n')
            before = list(engine.db.iterdump())
            output = io.StringIO()
            with redirect_stdout(output), patch('cornicen.cli.Scheduler') as scheduler:
                code = main(['--config', str(config), 'run'])
            self.assertEqual(code, 1)
            self.assertEqual(output.getvalue(),
                             'command failed: WatchlistError: watch entry 1: '
                             'package only watch requires a new id\n')
            scheduler.assert_not_called()
            self.assertEqual(list(engine.db.iterdump()), before)

    def test_empty_legacy_id_can_convert_in_place(self):
        for route in ('reload', 'startup', 'strict'):
            with self.subTest(route=route), tempfile.TemporaryDirectory(dir='.') as directory:
                db_path = str(Path(directory) / 'test.db')
                legacy = replace(EXACT, id='console-shift')
                engine = self.make_engine((legacy,), db_path=db_path)
                watch = replace(WATCH, id=legacy.id)
                scheduler = self.transition_scheduler(engine, directory, watch)
                if route == 'reload':
                    scheduler._reload()
                    self.assertEqual(engine.watches, (watch,))
                elif route == 'startup':
                    with patch('cornicen.cli.Scheduler') as startup:
                        startup.return_value.run.return_value = 0
                        self.assertEqual(self.transition_cli(engine, directory, 'run'), (0, '', ''))
                    self.assertEqual(startup.call_args.args[0].watches, (watch,))
                else:
                    self.assertEqual(self.transition_cli(engine, directory, 'watch', 'check', '--strict'),
                                     (0, f'no records ingested yet\n{watch.id}: matched none; near misses none\n', ''))

    def test_t38_each_stored_state_source_blocks_recycled_id(self):
        watch = replace(WATCH, id='console-shift')
        wid, cid, stamp = watch.id, cve(), NOW.isoformat()
        sources = {
            'pairs': ('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                      (wid, cid, 'affected', 1, 0, 0, 1, 'fixture', 'high', ALIASES.version)),
            'events': ('INSERT INTO events VALUES (?,?,?,?,?,?)',
                       (f'{wid}|{cid}|new match|1', wid, cid, 'new match', 1, stamp)),
            'outbox': ('INSERT INTO outbox(pair_key,urgency,reasons_json,body_json,due_at,sent_at) '
                       'VALUES (?,?,?,?,?,?)',
                       (f'{EXACT.id}|{cid}', 'normal', '["new match"]',
                        json.dumps(dict(watch_id=wid, record_id=cid)), stamp, stamp)),
            'advisory_history': ('INSERT INTO meta VALUES (?,?)',
                                 ('advisory_history:' + json.dumps([wid, cid]), '[]')),
            'delivery_coverage': ('INSERT INTO delivery_coverage VALUES (?,?,?,?,?,?)',
                                  (wid, cid, 'new match', 1, cve(1), stamp)),
            'coverage_inheritance': ('INSERT INTO coverage_inheritance VALUES (?,?,?,?,?)',
                                     (cid, cve(1), wid, 'new match', 1)),
            'affected_latches': ('INSERT INTO affected_latches VALUES (?,?,?,?)', (wid, cid, 1, 1)),
            'epss_crossings': ('INSERT INTO epss_crossings(watch_id,record_id,episode) VALUES (?,?,?)',
                               (wid, cid, 1)),
        }
        for source, (query, values) in sources.items():
            with self.subTest(source=source), tempfile.TemporaryDirectory(dir='.') as directory:
                engine = self.make_engine((EXACT,))
                engine.db.execute(query, values)
                scheduler = self.transition_scheduler(engine, directory, watch)
                self.assert_watchlist_rejected(engine, scheduler)
                with self.assertRaisesRegex(WatchlistError, 'package only watch requires a new id'):
                    engine.reload_watches((watch,))
                for saved in (True, False):
                    with self.subTest(saved=saved):
                        if not saved:
                            engine.db.execute("DELETE FROM meta WHERE k='applied_watches'")
                        with self.assertRaisesRegex(WatchlistError, 'package only watch requires a new id'):
                            Engine(engine.store, (watch,), ALIASES, engine.config, engine.clock, engine.notifier)

    def test_t38_fresh_id_ignores_other_watch_state(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine, _ = self.seed_package_only_transition()
            fresh = replace(WATCH, id='console-fresh')
            restarted = Engine(engine.store, (fresh,), ALIASES, engine.config, engine.clock, engine.notifier)
            self.assertEqual(restarted.watches, (fresh,))
            other = replace(fresh, id='console-fresh-2')
            scheduler = self.transition_scheduler(restarted, directory, other)
            scheduler._reload()
            self.assertEqual(restarted.watches, (other,))

    def test_t35_triple_prime_4_package_only_restart_keeps_pairs(self):
        watch = replace(WATCH, id='console-shift')
        engine = self.make_engine((watch,))
        self.ingest(engine, record(upstream()))
        before = self.tables(engine, watch)
        self.assertEqual(len(before[0]), 1)
        restarted = self.restart(engine)
        self.assertEqual(restarted.watches, (watch,))
        self.assertEqual(self.tables(restarted, watch), before)

    def test_t35_triple_prime_5_new_id_removes_old_pairs_and_matches_plain(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine, watch = self.seed_package_only_transition(link_advisory=True)
            renamed = replace(watch, id='console-shift-2')
            scheduler = self.transition_scheduler(engine, directory, renamed)
            scheduler._reload()
            self.assertEqual(engine.watches, (renamed,))
            self.assertFalse(self.tables(engine, watch)[0])
            self.assertIsNone(self.pair(engine, renamed))
            pair = self.pair(engine, renamed, cve(1))
            self.assertEqual(pair_result(pair), AFFECTED)
            self.assertEqual((pair['episode'], pair['notified']), (1, 0))
            self.assertEqual(engine.route(cve(1), renamed), 'v1')
            self.assertEqual(advisory.route(engine.db, cve(1), renamed, ALIASES), 'v1')
            queued, = (row for row in self.outbox(engine) if row['sent_at'] is None)
            self.assertEqual(json.loads(queued['reasons_json']), ['new match'])
            body = json.loads(queued['body_json'])
            self.assertEqual((body['watch_id'], body['record_id']), (renamed.id, cve(1)))

            self.assertTrue(self.tables(engine, watch)[1])
            self.assertIsNotNone(engine.db.execute(
                'SELECT 1 FROM delivery_coverage WHERE watch_id=?', (watch.id,)).fetchone())
            engine.config.watchlist_path.write_text(WATCH_TEXT.replace(WATCH.id, watch.id))
            self.assert_watchlist_rejected(engine, scheduler)
            with self.assertRaisesRegex(WatchlistError, 'package only watch requires a new id'):
                Engine(engine.store, (watch,), ALIASES, engine.config, engine.clock, engine.notifier)

    def test_t35_triple_prime_6_unchanged_file_keeps_v080_rejection(self):
        # R-P16 depends only on the file and the previous definitions, so an unchanged
        # file needs no revalidation; v0.8.0 keeps the rejection until the file changes.
        watch = replace(WATCH, id='console-shift')
        engine = self.make_engine((watch,))
        with tempfile.TemporaryDirectory(dir='.') as directory:
            scheduler = self.transition_scheduler(engine, directory, watch)
            scheduler._reload()
            path = engine.config.watchlist_path
            original = path.read_bytes()
            stat = path.stat()
            path.write_text('[[watch]]\n')
            self.assert_watchlist_rejected(engine, scheduler)

            # Restore the last accepted file without changing its accepted stamp.
            path.write_bytes(original)
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            self.assertEqual(scheduler._stamp(), scheduler.watch_stamp)
            scheduler._reload()
            self.assertEqual(engine.db.execute(
                "SELECT state,detail FROM health WHERE source='watchlist'").fetchone()[:],
                ('unhealthy', 'Watchlist reload rejected'))

    def test_t39_watch_check_uses_saved_definitions_before_preview(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            db_path = str(Path(directory) / 'test.db')
            engine, watch = self.seed_package_only_transition(db_path)
            self.transition_scheduler(engine, directory, watch)
            path = engine.config.watchlist_path
            before = list(engine.db.iterdump())

            for file_args in ((), ('--file', str(path))):
                with self.subTest(file_args=file_args):
                    self.assertEqual(self.transition_cli(engine, directory, 'watch', 'check',
                                                         '--strict', *file_args),
                                     (1, 'watch validation error: watch entry 1: '
                                         'package only watch requires a new id\n', ''))

            fresh = replace(watch, id='console-fresh')
            path.write_text(WATCH_TEXT.replace(WATCH.id, fresh.id))
            self.assertEqual(self.transition_cli(engine, directory, 'watch', 'check', '--strict'),
                             (0, f'{fresh.id}: matched {cve(1)}; near misses none\n', ''))
            self.assertEqual(list(engine.db.iterdump()), before)

    def test_t39_saved_package_only_id_with_state_passes_strict_check(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine = self.make_engine(db_path=str(Path(directory) / 'test.db'))
            self.seed_transition_pair(engine, WATCH)
            self.transition_scheduler(engine, directory, WATCH)
            self.assertEqual(self.transition_cli(engine, directory, 'watch', 'check', '--strict'),
                             (0, f'no records ingested yet\n{WATCH.id}: matched none; near misses none\n', ''))

    def test_older_store_missing_additive_watch_state_tables(self):
        warning = 'accepted: not applied (watch list unreadable)\n'
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine = self.make_engine((EXACT,), db_path=str(Path(directory) / 'test.db'))
            engine.db.execute('DROP TABLE coverage_inheritance')
            self.seed_transition_pair(engine, WATCH)
            self.transition_scheduler(engine, directory, WATCH)
            path = engine.config.watchlist_path
            entry = (f'\n[[accept]]\nwatch = "{WATCH.id}"\ncve = "{cve()}"\n'
                     'until = 2099-02-01\nreason = "Fixture exception"\n')
            before = list(engine.db.iterdump())
            for watch_id in ('console-fresh', WATCH.id):
                path.write_text(WATCH_TEXT.replace(WATCH.id, watch_id))
                with self.subTest(watch_id=watch_id, command='watch check'):
                    check = self.transition_cli(engine, directory, 'watch', 'check', '--strict')
                    if watch_id == WATCH.id:
                        self.assertEqual(check, (1, 'watch validation error: watch entry 1: '
                                                    'package only watch requires a new id\n', ''))
                    else:
                        self.assertEqual(check[0], 0, check)
                path.write_text((WATCH_TEXT + entry).replace(WATCH.id, watch_id))
                with self.subTest(watch_id=watch_id, command='status'):
                    code, out, err = self.transition_cli(engine, directory, 'status', '--json')
                    result = json.loads(out)
                    self.assertEqual((code, result['available']), (0, True))
                    if watch_id == WATCH.id:
                        # A rejected list reads as unreadable: v0.8.0 JSON writes no warning.
                        self.assertEqual(err, '')
                        self.assertNotIn('accepted', result)
                    else:
                        self.assertEqual(err, '')
                        self.assertEqual([e['state'] for e in result['accepted']], ['active'])
                self.assertEqual(list(engine.db.iterdump()), before)

    def test_status_json_fallback_does_not_check_accepts_without_store(self):
        # The store cannot be opened, so a package-only list cannot be validated: it reads as unreadable.
        with tempfile.TemporaryDirectory(dir='.') as directory:
            watchlist_path = Path(directory) / 'watches.toml'
            watchlist_path.write_text(WATCH_TEXT + f'\n[[accept]]\nwatch = "{WATCH.id}"\ncve = "{cve()}"\n'
                                      'until = 2099-02-01\nreason = "Fixture exception"\n')
            config = Path(directory) / 'config.toml'
            config.write_text(f'db_path = "{Path(directory) / "missing" / "absent.db"}"\n'
                              f'watchlist_path = "{watchlist_path}"\n')
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(['--config', str(config), 'status', '--json'])
            result = json.loads(out.getvalue())
            self.assertEqual((code, result['available']), (1, False))
            self.assertNotIn('accepted', result)
            self.assertEqual(err.getvalue(), '')

    def test_status_json_without_store_keeps_v080_accepts_for_selector_free_list(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            watchlist_path = Path(directory) / 'watches.toml'
            watchlist_path.write_text(EXACT_TEXT + f'\n[[accept]]\nwatch = "{EXACT.id}"\ncve = "{cve()}"\n'
                                      'until = 2099-02-01\nreason = "Fixture exception"\n')
            config = Path(directory) / 'config.toml'
            config.write_text(f'db_path = "{Path(directory) / "missing" / "absent.db"}"\n'
                              f'watchlist_path = "{watchlist_path}"\n')
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(['--config', str(config), 'status', '--json'])
            result = json.loads(out.getvalue())
            self.assertEqual((code, result['available'], err.getvalue()), (1, False, ''))
            self.assertEqual([(e['watch_id'], e['state']) for e in result['accepted']],
                             [(EXACT.id, 'active')])

    def test_unparseable_selector_free_list_keeps_v080_status_lines(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine = self.make_engine((EXACT,), db_path=str(Path(directory) / 'test.db'))
            self.transition_scheduler(engine, directory, EXACT)
            engine.config.watchlist_path.write_text(EXACT_TEXT + 'unknown_key = 1\n')
            code, out, err = self.transition_cli(engine, directory, 'status')
            self.assertEqual((code, err), (0, ''))
            self.assertEqual([line for line in out.splitlines() if 'accepted:' in line],
                             ['accepted: not checked (watch list unreadable)'])
            code, out, err = self.transition_cli(engine, directory, 'status', '--json')
            self.assertEqual((code, err), (0, ''))
            self.assertNotIn('accepted', json.loads(out))

    def test_state_tables_found_whatever_their_case(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            engine = self.make_engine((EXACT,), db_path=str(Path(directory) / 'test.db'))
            self.seed_transition_pair(engine, WATCH)
            engine.db.execute('DELETE FROM pairs')
            engine.db.execute("DELETE FROM meta WHERE k='applied_watches'")
            engine.db.execute(
                "INSERT INTO events(key, watch_id, record_id) VALUES ('k', ?, ?)", (WATCH.id, cve()))
            engine.db.execute('ALTER TABLE events RENAME TO events_tmp')
            engine.db.execute('ALTER TABLE events_tmp RENAME TO EVENTS')
            with self.assertRaisesRegex(WatchlistError, 'package only watch requires a new id'):
                validate_watch_transition(engine.store, (WATCH,))

    def test_rejected_list_metadata_matches_unreadable_file(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            legacy = replace(EXACT, id=WATCH.id)
            engine = self.make_engine((legacy,), db_path=str(Path(directory) / 'test.db'))
            self.seed_transition_pair(engine, legacy)
            # Without saved definitions, release checks would count the candidate file.
            engine.db.execute("DELETE FROM meta WHERE k='applied_watches'")
            self.transition_scheduler(engine, directory, WATCH)
            path = engine.config.watchlist_path
            candidate = (WATCH_TEXT + 'eol = true\nlatest_release = "github:example-console/example-console"\n'
                         f'\n[[accept]]\nwatch = "{WATCH.id}"\ncve = "{cve()}"\n'
                         'until = 2099-02-01\nreason = "Fixture exception"\n')
            for args in (('status',), ('status', '--json'), ('report',), ('report', '--format', 'jsonl')):
                with self.subTest(args=args):
                    path.unlink()
                    control = self.transition_cli(engine, directory, *args)
                    path.write_text(candidate)
                    actual = self.transition_cli(engine, directory, *args)
                    self.assertEqual(actual, control)
                    self.assertEqual(actual[0], 0)
                    self.assertNotIn('coverage limited', actual[1] + actual[2])
                    self.assertNotIn('Fixture exception', actual[1] + actual[2])
                    if args == ('status', '--json'):
                        result = json.loads(actual[1])
                        self.assertEqual(result['release_checks'], 0)
                        self.assertNotIn('eol_coverage_limited', result)
                        self.assertNotIn('accepted', result)
                    elif args == ('status',):
                        self.assertIn('release checks: 0\n', actual[1])

    def test_t40_rejected_reload_accepts_are_not_applied(self):
        warning = 'accepted: not applied (watch list unreadable)\n'
        with tempfile.TemporaryDirectory(dir='.') as directory:
            db_path = str(Path(directory) / 'test.db')
            engine, watch = self.seed_package_only_transition(db_path)
            self.ingest(engine, record(dict(EXACT_ENTRY, defaultStatus='affected'), offset=2))
            cid = cve(2)
            self.assertTrue(any(row['sent_at'] is None
                                and row['pair_key'] == f'{watch.id}|{cid}' for row in self.outbox(engine)))
            scheduler = self.transition_scheduler(engine, directory, watch)
            path = engine.config.watchlist_path
            package_text = path.read_text()
            entry = (f'\n[[accept]]\nwatch = "{watch.id}"\ncve = "{cid}"\n'
                     'until = 2099-02-01\nreason = "Fixture exception"\n')
            legacy_text = EXACT_TEXT.replace(EXACT.id, watch.id)
            path.write_text(legacy_text + entry)

            code, out, err = self.transition_cli(engine, directory, 'status')
            self.assertEqual((code, err), (0, ''))
            self.assertIn('accepted: 1 active', out)
            code, out, err = self.transition_cli(engine, directory, 'status', '--json')
            self.assertEqual((code, err), (0, ''))
            self.assertEqual([(e['cve'], e['state']) for e in json.loads(out)['accepted']],
                             [(cid, 'active')])
            code, out, err = self.transition_cli(engine, directory, 'report', '--group', 'open')
            self.assertEqual((code, err), (0, ''))
            self.assertIn('Accepted (not alerting): 1', out)

            path.write_text(legacy_text)
            _, unaccepted_report, _ = self.transition_cli(engine, directory, 'report', '--group', 'open')
            path.write_text(package_text + entry)
            self.assert_watchlist_rejected(engine, scheduler)
            self.assertEqual(engine.accepts, ())

            # A rejected list reads as unreadable: v0.8.0's status line, and no JSON warning.
            code, out, err = self.transition_cli(engine, directory, 'status')
            self.assertEqual((code, err), (0, ''))
            self.assertEqual([line for line in out.splitlines(keepends=True) if line.startswith('accepted:')],
                             ['accepted: not checked (watch list unreadable)\n'])
            code, out, err = self.transition_cli(engine, directory, 'status', '--json')
            self.assertEqual((code, err), (0, ''))
            self.assertNotIn('accepted', json.loads(out))

            code, out, err = self.transition_cli(engine, directory, 'report', '--group', 'open')
            self.assertEqual((code, err), (0, warning))
            self.assertEqual(out.splitlines()[0], unaccepted_report.splitlines()[0])
            code, out, err = self.transition_cli(engine, directory, 'report', '--format', 'jsonl')
            self.assertEqual((code, err), (0, warning))
            rows = [json.loads(line) for line in out.splitlines()]
            self.assertIn(cid, [row['record_id'] for row in rows])
            self.assertTrue(all('accepted' not in row for row in rows))

    def test_t36_prime_routed_inputs_ignore_selectors(self):
        def compare(engine, item, identity, watch):
            selected = replace(watch, package=WATCH.package)
            with self.subTest(identity=identity, watch=watch.id):
                self.assertEqual(cnascope.scoped_verdicts(item, selected, engine.aliases),
                                 cnascope.scoped_verdicts(item, watch, engine.aliases))
                self.assertEqual(advisory.resolve(engine.db, identity, selected, engine.aliases, record=item),
                                 advisory.resolve(engine.db, identity, watch, engine.aliases, record=item))

        outputs(check_routed=compare)
        # The loose legacy match reaches resolve inside a CNA scope. Enabling
        # package tiers there would promote it to an evaluated vendorless match.
        watch = replace(EXACT, product_only=(NAME,))
        engine = self.make_engine((watch,))
        seed_adapter(engine.db, cve())
        self.assertEqual(engine.route(cve(), watch), 'advisory')
        compare(engine, record(upstream(vendor='n/a', product=NAME)), cve(), watch)

    def test_t36_prime_resolve_call_site_flags(self):
        expected = [
            ('acceptance.py', 'evaluate', 'resolve', True),
            ('cli.py', 'watch_check', 'resolve', True),
            ('cli.py', 'replay', 'resolve', True),
            ('cli.py', 'explain', 'advisory.resolve', False),
            ('cli.py', 'explain', 'resolve', True),
            ('cli.py', '_accept_warnings', 'resolve', True),
            ('cnascope.py', 'scoped_verdicts', 'resolve', False),
            ('engine.py', 'advisory_result', 'advisory.resolve', False),
            ('engine.py', '_evaluate_pairs', 'applicability.resolve', True),
            ('adapterstore.py', '_process_file', "Path(resource['members_file']).resolve", None),
            ('adapterstore.py', '_process_file', 'self.directory.parent.resolve', None),
            ('adapterstore.py', 'process', "Path(resource['members_file']).resolve", None),
            ('adapterstore.py', 'process', 'self.directory.parent.resolve', None),
            ('csaf.py', 'resolve', 'resolve', None),
            ('csaf.py', '_index', 'resolve', None),
            ('store.py', '__init__', 'Path(path).resolve', None),
        ]
        self.assertCountEqual(self.resolve_call_sites(), expected)

    def resolve_call_sites(self, replacements=None):
        def named_resolve(node):
            return ((isinstance(node, ast.Name) and node.id == 'resolve') or
                    (isinstance(node, ast.Attribute) and node.attr == 'resolve'))

        actual = []
        replacements = replacements or {}
        src = ROOT / 'src/cornicen'
        for path in sorted((ROOT / 'src').rglob('*.py')):
            file = path.relative_to(src).as_posix() if path.is_relative_to(src) else str(path)
            tree = ast.parse(replacements[file] if file in replacements else path.read_text(),
                             filename=str(path))
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if named_resolve(node) and isinstance(node.ctx, ast.Load):
                    parent = parents[node]
                    self.assertTrue(isinstance(parent, ast.Call) and parent.func is node,
                                    f'{file}:{node.lineno}: resolve must be called directly')
                if (isinstance(node, ast.ImportFrom)
                        and any(alias.name == 'resolve' and alias.asname not in (None, 'resolve')
                                for alias in node.names)):
                    self.fail(f'{file}:{node.lineno}: resolve must be imported without an alias')
                if not isinstance(node, ast.Call) or not named_resolve(node.func):
                    continue
                self.assertFalse(any(isinstance(arg, ast.Starred) for arg in node.args)
                                 or any(keyword.arg is None for keyword in node.keywords),
                                 f'{file}:{node.lineno}: unpacked resolve argument')
                name = ast.unparse(node.func)
                owners = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
                owner = parents[node]
                while not isinstance(owner, owners):
                    owner = parents[owner]
                default = False if (file in {'acceptance.py', 'cli.py', 'cnascope.py', 'engine.py'}
                                    and name in {'resolve', 'advisory.resolve',
                                                 'applicability.resolve'}) else None
                flag = default
                if default is not None and name != 'advisory.resolve' and len(node.args) >= 7:
                    # `packages` is the seventh parameter; positional callers pass it there.
                    self.assertIsInstance(node.args[6], ast.Constant)
                    self.assertIs(type(node.args[6].value), bool)
                    flag = node.args[6].value
                for keyword in node.keywords:
                    if keyword.arg == 'packages':
                        self.assertIsInstance(keyword.value, ast.Constant)
                        self.assertIs(type(keyword.value.value), bool)
                        flag = keyword.value.value
                actual.append((file, getattr(owner, 'name', '<module>'), name, flag))
        return actual

    def test_t36_prime_reject_resolve_alias_and_unpacking(self):
        file = 'cnascope.py'
        text = (ROOT / 'src/cornicen' / file).read_text()
        call = 'resolve(scoped, None, watch, aliases)'
        self.assertIn(call, text)
        for replacement, why in (
            (text + '\nanother = resolve\n', 'resolve must be called directly'),
            (text.replace(call, call[:-1] + ', *(None, None, True))'), 'unpacked resolve argument'),
            (text.replace(call, call[:-1] + ', **{"packages": True})'), 'unpacked resolve argument'),
        ):
            with self.subTest(why=why), self.assertRaisesRegex(AssertionError, why):
                self.resolve_call_sites({file: replacement})

        file = 'applicability.py'
        text = (ROOT / 'src/cornicen' / file).read_text()
        with self.assertRaisesRegex(AssertionError, 'resolve must be called directly'):
            self.resolve_call_sites({file: text + '\nanother = resolve\n'})

    def test_t37_legacy_acceptance_and_watch_check_previews(self):
        baseline = json.loads(BASELINE.read_text())
        self.assertEqual(acceptance_outputs(), baseline['outputs']['acceptance'])
        self.assertEqual(watch_check_outputs(), baseline['watch_check'])

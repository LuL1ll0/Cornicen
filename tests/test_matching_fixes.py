# script-purpose: Check invisible identities, malformed parent versions and real revision upgrades.
# script-class: harness
# script-trigger: unittest discovery and make gate
# script-tests: tests/test_matching_fixes.py
"""Read matching code; write temporary stores and fixtures in the working tree.

Run with python -m unittest tests.test_matching_fixes. Exit codes: 0 success,
1 failed tests, 2 invalid arguments.
"""
from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen import applicability, identity
from cornicen.applicability import resolve, State
from cornicen.cli import main, _near
from cornicen.engine import Engine
from cornicen.identity import AliasMap, normalise_identity, is_placeholder
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.public_text import public_text
from cornicen.versions import Scheme
from cornicen.watchlist import load_watchlist_text, collisions
from tests import test_rematch_revision as revision_helpers

CVE = revision_helpers.CVE


CHARS = '\u00ad\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2066\u2067\u2068\u2069\ufeff'
WATCH = '''[[watch]]
id="orion"
name="Orion gadget"
match=["orion labs:nebula"]
version="3.4.1"
scheme="semver"
'''


def entry(**extra):
    return dict(vendor='orion labs', product='nebula', defaultStatus='affected', **extra)


def record(*entries):
    return {'cveMetadata': {'cveId': CVE, 'state': 'PUBLISHED'},
            'containers': {'cna': {'affected': list(entries)}}}


class MatchingFixTests(unittest.TestCase):
    def setUp(self):
        self.watch = load_watchlist_text(WATCH)[0]
        self.aliases = AliasMap.load(False)

    def result(self, *entries, watch=None, kev=None):
        return resolve(record(*entries), kev, watch or self.watch, self.aliases)

    def test_explicit_removal_set_on_all_feed_identity_fields(self):
        self.assertEqual(set(CHARS), identity.IDENTITY_IGNORABLES)
        for char in CHARS:
            for field, value in (('vendor', 'ori'+char+'on labs'), ('product', 'neb'+char+'ula')):
                with self.subTest(char=ord(char), field=field):
                    data = entry(); data[field] = value
                    result = self.result(data)
                    self.assertIsNotNone(result)
                    self.assertEqual(result.state, State.AFFECTED)
            for field, value in (('vendorProject', 'ori'+char+'on labs'), ('product', 'neb'+char+'ula')):
                kev = {'cveID': CVE, 'vendorProject': 'orion labs', 'product': 'nebula'}
                kev[field] = value
                with self.subTest(char=ord(char), field=field):
                    result = self.result(kev=kev)
                    self.assertIsNotNone(result)
                    self.assertEqual(result.state, State.UNKNOWN)
                    self.assertTrue(result.exploited)

    def test_watch_and_product_only_and_prepared_identities(self):
        for char in CHARS:
            watch = load_watchlist_text(WATCH.replace('nebula', 'neb'+char+'ula'))[0]
            self.assertEqual(self.result(entry(), watch=watch).state, State.AFFECTED)
            loose = replace(watch, match=(), product_only=('neb'+char+'ula',))
            self.assertEqual(self.result(entry(), watch=loose).state, State.UNKNOWN)
            parsed = load_watchlist_text(WATCH.replace('match=["orion labs:nebula"]',
                'product_only=["neb'+char+'ula"]'))[0]
            self.assertEqual(parsed.product_only, ('nebula',))
            self.assertTrue(is_placeholder(char))

    def test_removal_before_nfkc_and_idempotence(self):
        # Removing between combining characters must permit canonical composition.
        for char in CHARS:
            text = '  O\u0308'+char+'\u0301RION  LABS '
            expected = identity.normalise(text.replace(char, ''))
            self.assertEqual(normalise_identity(text), expected)
            self.assertEqual(normalise_identity(normalise_identity(text)), expected)
        text = 'A\u200b\u030a'
        self.assertNotEqual(identity.normalise(text).replace('\u200b', ''), normalise_identity(text))

    def test_meaningful_characters_preserved(self):
        for char in ('\u200c', '\u200d', '\ufe0f', '\u115f', '\u1160', '\u3164', '\uffa0', '\u034f'):
            text = 'orion'+char+'labs'
            self.assertEqual(normalise_identity(text), identity.normalise(text))
            self.assertNotEqual(normalise_identity(text), 'orionlabs')
        self.assertNotEqual(normalise_identity('Orion 👩‍💻'), normalise_identity('Orion 👩💻'))

    def test_alias_spellings_singleton_and_transitive_merge(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'aliases.toml'
            path.write_text('version="fiction"\n'+ '\n'.join(
                '[[alias]]\nidentities='+json.dumps(group) for group in [
                    ['ori\u200bon labs:nebula', 'orion labs:neb\u200bula'],
                    ['orion labs:neb\u200bula', 'lyra labs:comet'],
                    ['lyra la\u200bbs:comet', 'vega labs:pulse']]))
            self.aliases = AliasMap.load(False, path)
            self.assertEqual(len(self.aliases.expand(('orion labs', 'nebula'))), 3)
            for vendor, product in [('lyra labs', 'comet'), ('vega labs', 'pulse')]:
                data = entry(); data.update(vendor=vendor, product=product)
                self.assertEqual(self.result(data).state, State.AFFECTED)
            path.write_text('version="fiction"\n[[alias]]\nidentities=["orion labs:nebula", "ori\\u200bon labs:nebula"]')
            singleton = AliasMap.load(False, path)
            self.assertEqual(singleton.expand(('orion labs', 'nebula')), {('orion labs', 'nebula')})
            self.assertEqual(singleton.fingerprint(), AliasMap().fingerprint())

    def test_colliding_watches_remain_separate_and_strict_fails(self):
        text = WATCH + WATCH.replace('id="orion"', 'id="lyra"').replace('nebula', 'neb\u200bula')
        watches = load_watchlist_text(text)
        self.assertEqual([w.id for w in watches], ['orion', 'lyra'])
        self.assertEqual(len(collisions(watches, self.aliases)), 1)
        with tempfile.TemporaryDirectory(dir='.') as directory:
            path = Path(directory) / 'watch.toml'; path.write_text(text)
            with redirect_stdout(io.StringIO()):
                self.assertNotEqual(main(['watch', 'check', '--file', str(path), '--strict']), 0)

    def test_opaque_versions_keep_invisible_characters_in_applicability_and_cli(self):
        watch = replace(self.watch, scheme=Scheme.OPAQUE, version='build\u200bblue')
        data = entry(versions=[{'version': 'buildblue', 'status': 'affected'}])
        data['defaultStatus'] = 'unknown'
        self.assertEqual(self.result(data, watch=watch).state, State.UNKNOWN)
        data['versions'][0]['version'] = 'build\u200bblue'
        self.assertEqual(self.result(data, watch=watch).state, State.AFFECTED)
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(['version', 'compare', 'build\u200bblue', 'buildblue', '--scheme', 'opaque'])
        self.assertEqual((code, output.getvalue()), (1, 'unknown\n'))

    def test_parent_fields_matrix(self):
        self.aliases._links = {('orion labs', 'nebula'): {('lyra labs', 'comet')}}
        invalid = entry(version=None)
        invalid.update(defaultStatus=None, versions=None)
        self.assertIn('version fields outside versions[]', self.result(invalid).evidence)
        for key in ('version', 'lessThan', 'lessThanOrEqual', 'changes', 'versionType'):
            for value in (None, '', [], '4.0.0'):
                for versions in (None, [], [{'version': '3.4.1', 'status': 'affected'}]):
                    for default in ('affected', 'unaffected', 'unknown'):
                        for scheme in Scheme:
                            for version in ('3.4.1', '>=3.0.0,<4.0.0'):
                                for vendor, product in (("orion labs", "nebula"), ("lyra labs", "comet")):
                                    with self.subTest(key=key, value=value, versions=versions,
                                                      default=default, scheme=scheme, version=version, vendor=vendor):
                                        data = entry(**{key: value}); data['defaultStatus'] = default
                                        data.update(vendor=vendor, product=product)
                                        if versions is not None:
                                            data['versions'] = versions
                                        result = self.result(data, watch=replace(self.watch, scheme=scheme, version=version))
                                        self.assertEqual(result.state, State.UNKNOWN)
                                        self.assertIn('version fields outside versions[]', result.evidence)

    def test_malformed_unknown_not_masked_by_explicit_or_inferred_exclusion(self):
        for second in (dict(defaultStatus='unaffected'),
                       dict(defaultStatus='unknown', versions=[{'version': '0.0.0',
                            'lessThan': '2.0.0', 'status': 'affected'}])):
            data = entry(); data.update(second)
            for entries in ((entry(lessThan=None), data), (data, entry(lessThan=None))):
                self.assertEqual(self.result(*entries).state, State.UNKNOWN)

    def test_parent_fields_alias_product_only_kev_and_rejected_paths(self):
        self.aliases._links = {('orion labs', 'nebula'): {('lyra labs', 'comet')}}
        for key in ('version', 'lessThan', 'lessThanOrEqual', 'changes', 'versionType'):
            data = entry(**{key: None}); data.update(vendor='lyra labs', product='comet')
            self.assertEqual(self.result(data).state, State.UNKNOWN)
            loose = replace(self.watch, match=(), product_only=('comet',))
            self.assertIn('Product-only', self.result(data, watch=loose).evidence)
            data.update(vendor='vega labs', product='pulse')
            kev = {'cveID': CVE, 'vendorProject': 'orion labs', 'product': 'nebula'}
            result = self.result(data, kev=kev)
            self.assertEqual(result.state, State.UNKNOWN)
            self.assertIn('KEV identity', result.evidence)
        for state in ('REJECTED', 'WITHDRAWN'):
            rec = record(entry(version=None)); rec['cveMetadata']['state'] = state
            self.assertEqual(resolve(rec, None, self.watch, self.aliases).state, State.NOT_AFFECTED)

    def test_near_miss_and_public_privacy(self):
        data = entry(); data.update(vendor='ori\u200bon labs', product='comet')
        self.assertTrue(_near(record(data), self.watch, self.aliases))
        result = self.result(entry(version=None))
        text = public_text(result.evidence, (self.watch,))
        self.assertNotIn('nebula', text)
        self.assertNotIn('orion', text)
        self.assertIn('version fields outside', text)
        self.assertNotIn(result.evidence, text)


class RealUpgradeTests(unittest.TestCase):
    setUp = revision_helpers.MatchingRevisionTests.setUp
    restart = revision_helpers.MatchingRevisionTests.restart
    count = revision_helpers.MatchingRevisionTests.count

    def old_start(self):
        self.watches = load_watchlist_text(WATCH)
        with patch.object(applicability, 'MATCHING_REVISION', 1):
            return self.restart()

    def put(self, rec):
        self.store.put_record(CVE, rec, self.clock().isoformat())

    def pair(self):
        return self.db.execute('SELECT * FROM pairs').fetchone()

    def test_upgrade_unmatched_record_and_second_start_no_rematch(self):
        engine = self.old_start()
        data = entry(); data['vendor'] = 'ori\u200bon labs'
        rec = record(data); self.put(rec)
        # Reproduce revision 1's normalisation, keeping the real resolver and store.
        with patch.object(identity, 'normalise_identity', identity.normalise), \
                patch.object(applicability, 'normalise_identity', identity.normalise):
            engine._rematch_record(rec, CVE)
        self.assertIsNone(self.pair())
        self.restart()
        self.assertEqual(self.pair()['state'], 'affected')
        with patch.object(Engine, '_rematch_record', side_effect=AssertionError('unexpected rematch')):
            self.restart()
        self.assertEqual(self.store.get_meta('applied_matching_revision'), '2')

    def test_colliding_watch_ids_get_separate_stored_pairs(self):
        engine = self.old_start()
        text = WATCH + WATCH.replace('id="orion"', 'id="lyra"').replace('nebula', 'neb\u200bula')
        watches = load_watchlist_text(text)
        rec = record(entry()); self.put(rec)
        engine._rematch_record(rec, CVE)
        engine.reload_watches(watches)
        self.assertEqual([tuple(row) for row in self.db.execute(
            'SELECT watch_id,state FROM pairs ORDER BY watch_id')],
            [('lyra', 'affected'), ('orion', 'affected')])

    def test_upgrade_kev_only_without_pair_and_watch_reload(self):
        self.old_start()
        kev = {'cveID': CVE, 'vendorProject': 'ori\u200bon labs', 'product': 'nebula'}
        self.db.execute('INSERT INTO kev VALUES (?,?)', (CVE, json.dumps(kev)))
        self.store.set_meta('kev_only:' + CVE, '1')
        self.assertEqual(self.count('records'), 0)
        self.assertEqual(self.count('pairs'), 0)
        engine = self.restart()
        self.assertIsNotNone(self.pair())
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.pair()['exploited'], 1)
        self.assertEqual(self.count('records'), 0)
        self.db.execute('DELETE FROM pairs')
        engine.reload_watches((replace(self.watches[0], name='Orion renamed'),))
        self.assertEqual(self.pair()['state'], 'unknown')

    def test_first_catalog_kev_without_cna_still_waits_on_upgrade_and_reload(self):
        self.old_start()
        kev = {'cveID': CVE, 'vendorProject': 'orion labs', 'product': 'nebula'}
        self.db.execute('INSERT INTO kev VALUES (?,?)', (CVE, json.dumps(kev)))
        self.store.set_meta('kev_baseline:' + CVE, '1')
        engine = self.restart()
        engine.reload_watches((replace(self.watches[0], name='Orion renamed'),))
        self.assertIsNone(self.pair())
        self.assertIsNone(self.db.execute("SELECT 1 FROM health WHERE source='records'").fetchone())
        self.notifier.send.assert_not_called()

    def ingest_unmatched_kev_only(self, bootstrap_complete=False):
        engine = self.old_start()
        if bootstrap_complete:
            self.store.set_meta('baseline_complete', '1')
        initial = 'CVE-2099-10002'
        catalog = {initial: {'cveID': initial, 'vendorProject': 'lyra labs',
                             'product': 'comet'}}
        # Two real catalogs: the second introduces an eligible KEV-only row.
        with patch.object(identity, 'normalise_identity', identity.normalise), \
                patch.object(applicability, 'normalise_identity', identity.normalise):
            engine.run_cycle([IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
                                           None, self.clock(), kev=catalog)])
            catalog[CVE] = {'cveID': CVE, 'vendorProject': 'ori\u200bon labs',
                            'product': 'nebula'}
            engine.run_cycle([IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
                                           None, self.clock(), kev=catalog)])
        self.assertEqual(self.store.get_meta('kev_only:' + CVE), '1')
        self.assertEqual(bool(self.store.get_meta('kev_baseline:' + CVE)),
                         not bootstrap_complete)
        self.assertIsNone(self.pair())
        self.assertEqual(self.count('records'), 0)
        self.notifier.reset_mock()

    def test_upgrade_ingested_historical_kev_only_preserves_baseline(self):
        self.ingest_unmatched_kev_only()
        self.assertIsNone(self.store.get_meta('baseline_complete'))
        engine = self.restart()
        self.assertEqual((self.pair()['state'], self.pair()['exploited'],
                          self.pair()['baseline']), ('unknown', 1, 1))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM outbox WHERE urgency!='health'").fetchone()[0], 0)
        self.assertEqual(self.db.execute(
            'SELECT count(*) FROM events WHERE record_id=?', (CVE,)).fetchone()[0], 0)
        engine.run_cycle([])
        self.assertIsNone(self.store.get_meta('baseline_complete'))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM outbox WHERE urgency!='health'").fetchone()[0], 0)
        self.notifier.send.assert_not_called()

    def test_upgrade_ingested_kev_only_after_bootstrap_alerts_normally(self):
        self.ingest_unmatched_kev_only(bootstrap_complete=True)
        engine = self.restart()
        self.assertEqual((self.pair()['state'], self.pair()['exploited'],
                          self.pair()['baseline']), ('unknown', 1, 0))
        row = self.db.execute("SELECT * FROM outbox WHERE urgency!='health'").fetchone()
        self.assertEqual(row['urgency'], 'urgent')
        self.assertEqual(json.loads(row['reasons_json']), ['new match'])
        self.notifier.send.assert_not_called()
        engine.run_cycle([])
        self.notifier.send.assert_called_once()
        self.assertEqual(self.notifier.send.call_args.args[0].record_id, CVE)

    def test_upgrade_historical_kev_only_keeps_baseline_after_bootstrap_finishes(self):
        self.ingest_unmatched_kev_only()
        self.store.set_meta('baseline_complete', '1')
        engine = self.restart()
        self.assertEqual(self.pair()['baseline'], 1)
        engine.run_cycle([])
        self.assertEqual(self.db.execute(
            'SELECT count(*) FROM events WHERE record_id=?', (CVE,)).fetchone()[0], 0)
        self.assertFalse([call for call in self.notifier.send.call_args_list
                          if call.args[0].record_id == CVE])

    def test_upgrade_stored_cna_with_kev_baseline_still_alerts_normally(self):
        self.old_start()
        rec = record(entry()); self.put(rec)
        kev = {'cveID': CVE, 'vendorProject': 'orion labs', 'product': 'nebula'}
        self.db.execute('INSERT INTO kev VALUES (?,?)', (CVE, json.dumps(kev)))
        self.store.set_meta('kev_baseline:' + CVE, '1')
        # Even a retained synthetic marker cannot override a real CNA context.
        for synthetic_marker in (False, True):
            with self.subTest(synthetic_marker=synthetic_marker):
                if synthetic_marker:
                    self.store.set_meta('kev_only:' + CVE, '1')
                engine = self.restart()
                engine._rematch_record(rec, CVE)
                self.assertEqual(self.pair()['baseline'], 0)
                self.assertEqual(self.count('outbox'), 1)
                self.db.execute('DELETE FROM pairs')
                self.db.execute('DELETE FROM events')
                self.db.execute('DELETE FROM outbox')

    def test_notified_affected_to_unknown_sends_no_correction(self):
        engine = self.old_start()
        rec = record(entry()); self.put(rec)
        engine._rematch_record(rec, CVE)
        self.db.execute('UPDATE pairs SET notified=1')
        self.db.execute('DELETE FROM outbox'); self.db.execute('DELETE FROM events')
        rec['containers']['cna']['affected'][0]['lessThan'] = None
        self.put(rec)
        self.restart()
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.pair()['notified'], 1)
        self.assertEqual(self.count('outbox'), 0)
        self.assertEqual(self.count('events'), 0)
        self.notifier.send.assert_not_called()

    def test_parent_guard_upgrade_cancels_pending_unsent_alert(self):
        engine = self.old_start()
        rec = record(entry(version='3.4.1')); self.put(rec)
        # Revision 1 ignores misplaced version fields and accepts defaultStatus.
        with patch.object(applicability, '_check_types', lambda entry, scheme: None):
            engine._evaluate(rec, CVE)
        self.assertEqual(self.pair()['state'], 'affected')
        self.assertEqual(self.pair()['notified'], 0)
        self.assertEqual(self.count('outbox'), 1)
        engine = self.restart()
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.pair()['exploited'], 0)
        engine.run_cycle([])
        self.assertEqual(self.count('outbox'), 0)
        self.notifier.send.assert_not_called()

    def test_interrupted_upgrade_recovers_with_retry_marker(self):
        self.old_start()
        rec = record(entry(version=None)); self.put(rec)
        def interrupt(engine, *args, **kwargs):
            raise ValueError('fictional interruption')
        with patch.object(Engine, '_rematch_record', interrupt):
            self.restart()
        self.assertEqual(self.store.get_meta('matching_revision_retry:' + CVE), '1')
        self.assertEqual(self.count('retry_queue'), 1)
        engine = self.restart()
        self.assertEqual(self.store.get_meta('matching_revision_retry:' + CVE), '1')
        engine.run_cycle([])
        self.assertEqual(self.pair()['state'], 'unknown')
        self.assertEqual(self.count('retry_queue'), 0)
        self.assertIsNone(self.store.get_meta('matching_revision_retry:' + CVE))

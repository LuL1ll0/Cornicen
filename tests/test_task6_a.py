"""Offline Synology Build A contract, using the invented RSS fixture."""

from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cornicen import advisory, cli, feedvalidate, public_text, synology
from cornicen.adapterstore import AdapterStore, date_fields
from cornicen.applicability import State
from cornicen.config import Config
from cornicen.engine import Engine
from cornicen.identity import AliasMap
from cornicen.model import Notification
from cornicen.render import render
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text


ROOT = Path(__file__).resolve().parents[1]
FEED = (ROOT / 'tests/fixtures/synology/feed_sample.xml').read_bytes()
NOW = datetime.fromisoformat('2026-10-30T01:00:00+00:00')
TICK = '2026-10-30T01:00:00Z'
PHOTO = 'https://www.synology.com/en-us/support/security/Synology_SA_99_01'
WATCHES = '''
[[watch]]
id = "debian"
name = "DSM"
match = ["synology:diskstation manager (dsm)"]
version = "7.9.0-99999"
scheme = "debian"

[[watch]]
id = "semver"
name = "DSM"
match = ["synology:diskstation manager (dsm)"]
version = "7.9.0-99999"
scheme = "semver"

[[watch]]
id = "opaque"
name = "DSM"
match = ["synology:diskstation manager (dsm)"]
version = "7.9.0-99999"
scheme = "opaque"

[[watch]]
id = "other"
name = "Windows"
match = ["microsoft:windows"]
version = "7.9.0-99999"
scheme = "opaque"
'''


def resource(*members, path='feed'):
    return dict(path=path, status=200, body=json.dumps({'advisories': members}))


class Task6ATests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory(dir='.'))
        self.directory = Path(directory)
        self.db_path = self.directory / 'db'
        self.store = Store(self.db_path)
        self.store.migrate()
        self.addCleanup(lambda: self.store.connection.close())
        self.watches = load_watchlist_text(WATCHES)
        watch_path = self.directory / 'watches.toml'
        watch_path.write_text(WATCHES, encoding='utf-8')
        self.config = Config(str(self.db_path), watch_path, None, '', '', None)
        self.aliases = AliasMap.load(False)
        self.persistence = self.adapter()

    def adapter(self):
        engine = Engine(self.store, self.watches, self.aliases, self.config, lambda: NOW, None)
        return AdapterStore(self.store, self.directory, on_record=engine.commit_advisory)

    def process(self, *members, expected='COMPLETE', source='synology', path='feed'):
        self.assertEqual(self.persistence.process(
            source=source, resources=[resource(*members, path=path)], tick=TICK), expected)

    def data(self, identity, source='synology'):
        row = self.store.connection.execute(
            'SELECT json FROM advisories WHERE source=? AND source_id=?', (source, identity)).fetchone()
        self.assertIsNotNone(row)
        return json.loads(row[0])

    def rows(self, sql, *params):
        return [tuple(row) for row in self.store.connection.execute(sql, params)]

    def items(self):
        return synology.parse_feed(FEED)[0]

    def validate(self, member, source='synology'):
        return feedvalidate.validate_advisory(
            member, source=source, observed_at=TICK, date_fields=date_fields(source)).data

    def test_t1_envelope(self):
        items, channel = synology.parse_feed(FEED)
        self.assertEqual(len(items), 12)
        self.assertEqual(channel['lastBuildDate'], 'Fri, 30 Oct 2026 09:00:00 +0800')
        bound = FEED + b' ' * (8 * 1024**2 - len(FEED))
        self.assertEqual(synology.parse_feed(bound), (items, channel))
        with self.assertRaisesRegex(ValueError, 'invalid Synology RSS envelope'):
            synology.parse_feed(bound + b' ')
        invalid = {
            'DOCTYPE': b'<!DOCTYPE rss><rss><channel><item/></channel></rss>',
            'ENTITY': b'<rss><channel><item><![CDATA[<!ENTITY x "DSM">]]></item></channel></rss>',
            'root': b'<feed><channel><item/></channel></feed>',
            'two channels': b'<rss><channel><item/></channel><channel/></rss>',
            'no items': b'<rss><channel/></rss>',
            '5,001 items': b'<rss><channel>' + b'<item/>' * 5001 + b'</channel></rss>',
            'HTML 200': b'<html><body>GET</body></html>',
            'empty': b'',
            'malformed XML': b'<rss><channel><item></channel></rss>',
            'invalid UTF-8': b'<rss><channel><item>\xff</item></channel></rss>',
            'NUL': b'<rss><channel><item/>\0</channel></rss>',
            'UTF-16LE': '<rss><channel><item/></channel></rss>'.encode('utf-16le'),
            'too large': bound + b' ',
        }
        for label, body in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    synology.parse_feed(body)
                # Build B will translate the rejection into this outcome.
                outcome = {'path': 'feed', 'status': 200, 'invalid_envelope': True}
                self.assertEqual(feedvalidate.validate_resource(
                    outcome, source='synology', observed_at=TICK).classification, 'FAILED')
                self.assertEqual(self.persistence.process(
                    source='synology', resources=[outcome], tick=TICK), 'FAILED')
                self.assertEqual(self.rows('SELECT source FROM staged_containers'), [])
                self.assertEqual(self.rows("SELECT state FROM source_health WHERE dimension='fetch'"),
                                 [('healthy',)])

    def test_t2_mapping_and_required_fields(self):
        item = self.items()[0]
        member = synology.normalise(item)
        details = ('A vulnerability allows remote authenticated users to inject arbitrary web script '
                   'via a susceptible version of Synology Photo Station.\n\n'
                   'CVE-2099-81001 is resolved in the current release.\n\n')
        self.assertEqual({k: member[k] for k in ('id', 'guid', 'url', 'title', 'published', 'details')},
                         dict(id='Synology_SA_99_01', guid=PHOTO, url=PHOTO,
                              title='Synology-SA-99:01 Photo Station',
                              published='2026-10-29T13:12:54Z', details=details))
        self.assertNotIn('updated', member)
        self.process(member)
        stored = self.data('Synology_SA_99_01')
        self.assertEqual(stored['source_id'], 'Synology_SA_99_01')
        self.assertIsNone(stored['updated'])
        self.assertEqual(stored['mapping_version'], 'synology-templates-1')
        self.assertEqual(self.rows('SELECT updated FROM advisories'), [(None,)])
        with self.assertRaisesRegex(ValueError, '^advisory mapping failed$'):
            self.validate(dict(member, mapping_version='other'))

        bad = [('blank guid', dict(item, guid=''), 'invalid Synology guid'),
               ('off-pattern guid', dict(item, guid=PHOTO + '?GET'), 'invalid Synology guid'),
               ('no zone', dict(item, pubDate='Thu, 29 Oct 2026 21:12:54'),
                'invalid Synology URL or publication date'),
               ('description limit', dict(item, description='x' * 65537),
                'Synology description too large')]
        bad.extend((key, {k: v for k, v in item.items() if k != key}, 'missing Synology item text')
                   for key in ('link', 'title', 'pubDate', 'description'))
        for label, raw, expected in bad:
            with self.subTest(label=label):
                malformed = synology.normalise(raw)
                self.assertEqual(malformed['mapping_error'], expected)
                result = feedvalidate.validate_members(
                    [malformed], source='synology', observed_at=TICK,
                    date_fields=date_fields('synology'))
                self.assertEqual(list(result.checked_records()), [])
                self.assertEqual(result.classification, 'PARTIAL')
                self.assertEqual(len(result.quarantine), 1)
        self.assertEqual(synology.normalise(dict(item, description='x' * 65536))['details'],
                         'x' * 65536)
        fallback = synology.normalise({k: v for k, v in item.items() if k != 'guid'})
        self.assertEqual((fallback['id'], fallback['guid']), ('Synology_SA_99_01', PHOTO))

    def test_t3_templates(self):
        items = self.items()
        for index, expected in {
            0: (['Synology Photo Station'], 'S-ONE', {}),
            1: ([], 'S-NONE', {}),
            3: (['Hyper Backup', 'Mail Station'], 'S-PKG', {'unrecognised subject': 2}),
            4: (['Synology Assistant'], 'S-UPD', {}),
            5: ([], None, {'unrecognised template': 1}),
            6: ([], None, {'unrecognised template': 1}),
            7: ([], 'S-ONE', {'unrecognised subject': 1}),
        }.items():
            with self.subTest(index=index):
                self.assertEqual(synology.products(items[index]['title'], items[index]['description']), expected)
        self.assertEqual(synology.normalise(items[1])['vendor_statement'], 'none_affected')
        package = items[3]
        self.assertEqual(synology.products(package['title'], ' '.join(package['description'].split())),
                         ([], None, {'unrecognised template': 1}))
        one, update = items[0]['description'], items[4]['description']
        for description in (
            one.replace('Synology Photo Station', 'e.g. DSM'),
            one.replace('Synology Photo Station', 'DSM, etc'),
            update.replace('Synology Assistant', 'i.e. DSM'),
            one.replace('inject arbitrary web script via', 'inject arbitrary web script. It happens via'),
            'The reported issue cannot be exploited. ' + package['description'].replace(
                'Multiple vulnerabilities', 'No vulnerabilities', 1),
            'The reported issue cannot be exploited\n' + package['description'],
        ):
            with self.subTest(description=description):
                # Keep the separate valid Windows clause out of the S-UPD punctuation probe.
                description = description.split(' CVE-2099-81005')[0]
                self.assertEqual(synology.products('DSM', description), ([], None, {'unrecognised template': 1}))
        self.assertEqual(synology.products('DSM', one + items[1]['description']), (['Synology Photo Station'], 'S-ONE', {}))
        self.assertEqual(synology.products('DSM', 'The reported issue is tracked. ' + one),
                         (['Synology Photo Station'], 'S-ONE', {}))
        self.assertEqual(synology.products('DSM', package['description'].replace(
            'Mail Station', 'Mail Station\n\nSynology Assistant')),
            (['Hyper Backup', 'Mail Station'], 'S-PKG', {'unrecognised subject': 1}))

    def test_t4_cve_relationships(self):
        items = self.items()
        multiple, single, no_cve = [synology.normalise(items[i]) for i in (2, 0, 8)]
        cves = ['CVE-2099-81002', 'CVE-2099-81003', 'CVE-2099-81004', 'CVE-2099-81006',
                'CVE-2099-81008', 'CVE-2099-81009', 'CVE-2099-81010', 'CVE-2099-81012']
        self.assertEqual(multiple['cves'], cves)
        self.assertEqual(single['cves'], ['CVE-2099-81001'])
        self.assertEqual(no_cve['cves'], [])
        self.assertEqual(synology.normalise(dict(items[2], title=(
            'CVE-2099-81012 CVE-2099-81012 ' + items[2]['title'])))['cves'], [cves[-1], *cves[:-1]])
        self.process(multiple, single, no_cve)
        stored = self.data('Synology_SA_99_03')
        self.assertEqual(advisory.identities(stored), [*cves, 'advisory:synology:Synology_SA_99_03:main'])
        results = self.rows('SELECT identity, package, status, range, fix FROM advisory_evidence '
                            'WHERE source_id=? ORDER BY identity', 'Synology_SA_99_03')
        self.assertEqual(results, [(identity, 'synology:diskstation manager (dsm)',
                                    'under_investigation', None, None)
                                   for identity in [*cves, 'advisory:synology:Synology_SA_99_03:main']])
        self.assertEqual(self.rows(
            'SELECT identity, status, fix FROM advisory_evidence WHERE source_id IN (?,?) ORDER BY identity',
            'Synology_SA_99_01', 'Synology_SA_99_09'),
            [('CVE-2099-81001', 'under_investigation', None),
             ('advisory:synology:Synology_SA_99_09:main', 'under_investigation', None)])

    def test_t5_evidence_and_vendor_statement(self):
        items = self.items()
        dsm, none = [synology.normalise(items[i]) for i in (10, 1)]
        self.process(dsm, none)
        self.assertEqual(self.rows(
            'SELECT watch_id, state FROM pairs WHERE record_id=? ORDER BY watch_id', 'CVE-2099-81011'),
            [('debian', 'unknown'), ('opaque', 'unknown'), ('semver', 'unknown')])
        for watch in self.watches[:3]:
            self.assertIs(advisory.resolve(self.store.connection, 'CVE-2099-81011', watch,
                                           self.aliases).state, State.UNKNOWN)
        self.assertEqual(self.rows('SELECT identity,package,status,scheme,range,fix FROM advisory_evidence'),
                         [('CVE-2099-81011', 'synology:diskstation manager (dsm)',
                           'under_investigation', 'opaque', None, None)])
        self.assertEqual(self.rows('SELECT source_id,identity FROM advisory_support'),
                         [('Synology_SA_99_11', 'CVE-2099-81011')])
        self.assertEqual(self.data('Synology_SA_99_02')['vendor_statement'], 'none_affected')
        with self.assertRaisesRegex(ValueError, '^advisory mapping failed$'):
            self.validate(dict(none, vendor_statement='other'))
        debian = self.validate(dict(none, updated=TICK), source='debian')
        self.assertNotIn('vendor_statement', debian)
        self.assertNotIn('mapping_version', debian)

    def test_t6_explain_all_retained_owners(self):
        items = self.items()
        none, dsm = [synology.normalise(items[i]) for i in (1, 10)]
        self.process(none, dsm)

        def explain(watch, cve='CVE-2099-81007'):
            output = StringIO()
            with redirect_stdout(output):
                code = cli.explain(self.store, self.watches, self.aliases, cve, watch)
            return code, output.getvalue()

        section = (
            'Synology advisory (no version data)\n'
            '  ID: Synology_SA_99_02\n'
            '  Title: Synology-SA-99:02 Example Library\n'
            '  URL: https://www.synology.com/en-us/support/security/Synology_SA_99_02\n'
            '  Published: 2026-10-27T02:00:00Z\n'
            '  Products: none recognised\n'
            '  none affected (vendor statement)\n'
        )
        self.assertEqual(explain('opaque'), (0, section))
        self.assertEqual(explain('other'), (0, section))
        self.process(dict(none, updated=TICK), source='ubuntu')
        self.assertEqual(explain('other'), (1,
            'Current-file evaluation: other CVE-2099-81007; version=7.9.0-99999; '
            f'scheme=opaque; alias_map_version={self.aliases.version}\n'
            'Stored pair state: none\n'
            'Current decision: retained record unavailable; applicability unknown\n' + section))
        code, output = explain('opaque', 'CVE-2099-81011')
        self.assertEqual(code, 0)
        self.assertIn('Evidence: synology: unknown\nSynology advisory (no version data)\n', output)
        self.assertTrue(output.endswith(
            '  ID: Synology_SA_99_11\n'
            '  Title: Synology-SA-99:11 DSM\n'
            '  URL: https://www.synology.com/en-us/support/security/Synology_SA_99_11\n'
            '  Published: 2026-10-06T23:07:07Z\n'
            '  Products: diskstation manager (dsm)\n'))
        self.assertEqual(explain('unknown'), (1, 'unknown watch ID: unknown\n'))

    def test_t7_date_map_process_resume_rebaseline(self):
        self.assertEqual(date_fields('synology'),
                         dict(published=(True, 'rfc3339'), updated=(False, 'rfc3339'),
                              withdrawn=(False, 'rfc3339')))
        items = self.items()
        processed, recovered, rebaselined = [synology.normalise(items[i]) for i in (0, 1, 10)]
        missing = {k: v for k, v in processed.items() if k != 'published'}
        self.process(missing, expected='PARTIAL')
        self.assertEqual(self.rows('SELECT reason FROM quarantine'), [('ValueError: required advisory date missing',)])
        self.assertEqual(self.rows('SELECT source_id FROM advisories'), [])
        self.process(processed)
        self.assertEqual(self.rows('SELECT published, updated FROM advisories'), [('2026-10-29T13:12:54Z', None)])

        class ProcessLost(BaseException):
            pass

        with patch.object(self.persistence, 'commit_staged', side_effect=ProcessLost):
            with self.assertRaises(ProcessLost):
                self.process(recovered, path='resume')
        self.assertEqual(self.rows('SELECT resource FROM staged_containers'), [('resume',)])
        self.assertEqual(self.rows('SELECT source_id FROM advisories'), [('Synology_SA_99_01',)])
        self.store.connection.close()
        self.store = Store(self.db_path)
        self.persistence = self.adapter()
        self.persistence.resume(TICK, source='synology')
        self.assertEqual(self.rows('SELECT resource FROM staged_containers'), [])
        self.assertEqual(self.rows('SELECT published, updated FROM advisories WHERE source_id=?',
                                   'Synology_SA_99_02'), [('2026-10-27T02:00:00Z', None)])

        self.persistence.stage_members('synology', 'rebaseline', [rebaselined], TICK)
        self.persistence.rebaseline('synology', TICK)
        self.assertEqual(self.rows('SELECT resource FROM staged_containers'), [])
        self.assertEqual(self.rows('SELECT published, updated FROM advisories WHERE source_id=?',
                                   'Synology_SA_99_11'), [('2026-10-06T23:07:07Z', None)])

    def test_t8_fixed_public_diagnostics(self):
        items = self.items()
        capture = dict(items[7], title='2099 GET',
                       description=items[7]['description'].replace('Example Package Server', '2099 GET'))
        untemplated = dict(items[5], title='2099 GET')
        diagnostics = [synology.products(raw['title'], raw['description'])[2]
                       for raw in (capture, untemplated)]
        self.assertEqual(diagnostics, [{'unrecognised subject': 1}, {'unrecognised template': 1}])
        gaps = ('observation interval exceeded', 'retention boundary lost',
                'retention watermark moved', 'member lost')
        self.assertEqual(public_text.SYNOLOGY_GAP_REASONS, gaps)
        for wording in (*diagnostics[0], *diagnostics[1], *gaps):
            self.assertEqual(public_text.public_text(wording, self.watches), wording)

        self.process(synology.normalise(capture), synology.normalise(untemplated))
        for reason in gaps:
            self.persistence.gap('synology', TICK, reason)
        self.assertEqual(self.rows('SELECT reason FROM gap_ledger ORDER BY reason'), [(r,) for r in sorted(gaps)])
        self.process(synology.normalise(capture), synology.normalise(untemplated), expected='PARTIAL')
        self.persistence.finish_cycle('synology', TICK)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.status_json(self.store, NOW, self.config), 0)
        status = json.loads(output.getvalue())['sources']['synology']['detail']
        self.assertEqual(status, 'completeness: unhealthy; coverage unknown (pre-baseline)')
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.report(self.store, Namespace(group=[], watch=[], format='text'),
                                        config=self.config, now=NOW), 0)
        self.assertIn('Dead letters: 0', output.getvalue())
        [(key, body)] = self.rows("SELECT pair_key, body_json FROM outbox WHERE urgency='health'")
        _, notification, _, _ = render(Notification(
            key=key, watch_id='', record_id='synology', urgency='health',
            reasons=('unhealthy',), body=json.loads(body)))
        self.assertEqual(notification, 'synology: unhealthy — failed since 2026-10-30T01:00Z')
        for diagnostic_line in (status, *output.getvalue().splitlines(), notification):
            self.assertNotIn('2099', diagnostic_line)
            self.assertNotIn('GET', diagnostic_line)
        subprocess.run([sys.executable, 'tools/gen_vocabulary.py', '--check'], cwd=ROOT, check=True)


if __name__ == '__main__':
    unittest.main()

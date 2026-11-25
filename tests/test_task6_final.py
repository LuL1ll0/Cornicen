"""Read invented RSS fixtures and exercise temporary offline stores.

Run with unittest, which exits 0 on success or 1 on a test failure.
"""

from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from http.client import HTTPResponse
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cornicen import cli, feedvalidate, synology
from cornicen.adapterstore import AdapterStore, canonical, date_fields, instant, stamp
from cornicen.config import Config
from cornicen.fetch import Http
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.render import render
from cornicen.sources.synology_rss import SynologyRss, SynologyState
from cornicen.store import Store
from tests.replay_v11 import harness
from tests.replay_v11.rss_backend import SynologyBackend
from tests import test_task6_b1 as b1, test_task6_b2 as b2


class FinalReviewTests(unittest.TestCase):
    def sandbox(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir='.')))
        self.store = Store(directory / 'db')
        self.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.db = self.store.connection
        self.persistence = AdapterStore(self.store, directory)
        self.endpoint = b1.ScriptedOpener()
        self.http = Http('Cornicen/test', {}, opener=self.endpoint, data_dir=directory,
                         resolver=self.endpoint.resolver)
        self.tick = b1.TICK
        self.adapter = SynologyRss(self.http, SynologyState(self.store), lambda: instant(self.tick))
        self.config = Config(directory / 'db', directory / 'watches', None, '', '', None)

    def rows(self, sql):
        return [tuple(row) for row in self.db.execute(sql)]

    def poll(self, response):
        self.endpoint.responses.append(response)
        outcome, = self.adapter.poll()
        return outcome

    def process(self, outcome):
        return self.persistence.process('synology', [outcome], self.tick)

    def cycle(self, *items):
        return self.process(self.poll(b1.feed(*items)))

    def summary(self):
        return json.loads(self.store.get_meta('retention:synology'))

    def next_poll(self):
        self.tick = stamp(instant(self.tick) + timedelta(hours=24))

    def withdraw_first(self):
        self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?",
                        (b1.A,))

    def status_details(self):
        self.persistence.finish_cycle('synology', self.tick)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.status_json(self.store, instant(self.tick), self.config), 0)
        result = json.loads(output.getvalue())['sources']
        output = StringIO()
        with patch.object(cli, 'load_config', return_value=self.config), redirect_stdout(output):
            self.assertEqual(cli.main(['status']), 0)
        text_detail = next(line.split('; ', 1)[1] for line in output.getvalue().splitlines()
                           if line.startswith('synology: ') and '; ' in line)
        self.assertEqual(text_detail, result['synology']['detail'])
        return result

    def replay(self):
        backend = SynologyBackend(harness.fixture_registry())
        self.addCleanup(backend.close)
        backend.action({'t': b2.T1, 'watchlist': b2.WATCH})
        backend.action({'t': b2.T1, 'seed': {'v1_baseline_complete': True}})
        b2.Task6B2Tests.poll(backend, b2.T1, [b2.item(1)])
        return backend

    def test_negation_declines_both_templates(self):
        # R-G1: a negation declines only where it governs exploitation or affectedness.
        for word in ('not', 'cannot', "can't", 'never', 'no longer', 'unable to'):
            for description in (
                f'A vulnerability allows inventors to verify it {word.upper()} be exploited via a susceptible version of DSM.',
                f'Synology has released a security update for DSM {word.upper()} be affected to address a flaw.',
            ):
                with self.subTest(description=description):
                    self.assertEqual(synology.products('DSM', description),
                                     ([], None, {'unrecognised template': 1}))
        self.assertEqual(synology.products('DSM',
            'A vulnerability allows actors to read notes via a susceptible version of DSM.')[1], 'S-ONE')
        # Affirmative effects that contain "without" still route (real-feed wording).
        for effect in ('obtain privileges without consent', 'set a new password without verification'):
            with self.subTest(effect=effect):
                self.assertEqual(synology.products('DSM',
                    f'A vulnerability allows remote authenticated users to {effect} via a susceptible '
                    'version of DiskStation Manager (DSM).')[:2],
                    (['DiskStation Manager (DSM)'], 'S-ONE'))

    def test_negated_kev_notice_never_routes(self):
        backend = self.replay()
        with backend.store.transaction():
            backend.engine._ingest(IngestResult('kev', FetchStatus.COMPLETE, Origin.SNAPSHOT, None,
                instant(b2.T1), kev={b2.KEV_ID: {'cveID': b2.KEV_ID}}))
        self.assertEqual(backend.store.get_meta('kev_initialized'), '1')
        novel = b2.item(11) | {'description': (
            'A vulnerability allows administrators to verify that it cannot be exploited via a '
            f'susceptible version of DSM. It is tracked as {b2.KEV_ID}.')}
        b2.Task6B2Tests.poll(backend, b2.T2, [b2.item(1), novel])
        saved, = backend.store.connection.execute(
            "SELECT json FROM advisories WHERE source='synology' AND source_id=?", ('Synology_SA_99_11',)
        ).fetchone()
        self.assertEqual(json.loads(saved)['products'], [])
        self.assertEqual([n for n in backend.sent if n['watch']], [])

    def test_status_includes_both_coverage_states(self):
        self.sandbox()
        self.assertEqual(self.process(self.poll(b'<html/>')), 'FAILED')
        before = self.status_details()
        self.assertEqual(before['synology']['detail'],
                         'completeness: unhealthy; coverage unknown (pre-baseline)')
        self.next_poll()
        self.assertEqual(self.cycle(b1.item()), 'COMPLETE')
        after = self.status_details()
        self.assertIn('All applicable dimensions healthy; coverage unknown (no retention contract)',
                      after['synology']['detail'])
        self.assertEqual({k: v for k, v in before.items() if k != 'synology'},
                         {k: v for k, v in after.items() if k != 'synology'})
        self.assertEqual(self.rows("SELECT state,detail FROM source_health WHERE dimension='freshness'"),
                         [('n/a', '')])

    def test_diagnostics_replace_on_success_and_survive_parse_failure(self):
        self.sandbox()
        unknown = b1.item(description='A vulnerability allows someone to read data via a susceptible version of Mystery GET.')
        untemplated = b1.item(b1.B, b1.NEW, description='An invented notice with 2099 GET.')
        self.assertEqual(self.cycle(unknown, untemplated), 'COMPLETE')
        expected = {'unrecognised subject': 1, 'unrecognised template': 1}
        self.assertEqual(json.loads(self.store.get_meta('synology:diagnostics') or '{}'), expected)
        self.assertEqual(json.loads(self.store.get_meta('synology:last_build')), b1.BUILD)
        self.assertTrue(self.status_details()['synology']['detail'].endswith(
            '1 unrecognised subject, 1 unrecognised template'))
        self.next_poll()
        self.assertEqual(self.process(self.poll(b'<html/>')), 'FAILED')
        self.assertEqual(json.loads(self.store.get_meta('synology:diagnostics')), expected)
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.B, b1.NEW)), 'COMPLETE')
        self.assertEqual(json.loads(self.store.get_meta('synology:diagnostics')), dict.fromkeys(expected, 0))
        self.assertTrue(self.status_details()['synology']['detail'].endswith(
            '0 unrecognised subject, 0 unrecognised template'))

    def test_diagnostics_do_not_echo_feed_text(self):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            backend = self.replay()
            novel = b2.item(11) | {'title': 'Invented private title', 'description': (
                'Invented private description 2099 GET.')}
            capture = b2.item(2) | {'description': (
                'A vulnerability allows someone to read data via a susceptible version of Invented private subject.')}
            send = backend.notifier.send

            def render_and_send(notification):
                print(render(notification))
                return send(notification)

            # The additional malformed member generates an actual health notification.
            with patch.object(backend.notifier, 'send', side_effect=render_and_send):
                b2.Task6B2Tests.poll(backend, b2.T2, [b2.item(1), novel, capture, b2.item(12) | {'title': ''}])
            config = backend.engine.config
            self.assertEqual(cli.status_json(backend.store, instant(b2.T2), config), 0)
            self.assertEqual(cli.report(backend.store, Namespace(group=[], watch=[], format='text'),
                                        config=config, now=instant(b2.T2)), 0)
            self.assertTrue(any(n['urgency'] == 'health' for n in backend.sent))
        for output in (stdout.getvalue(), stderr.getvalue(), repr(backend.sent), repr(backend.bodies)):
            for private in ('Invented private title', 'Invented private description',
                            'Invented private subject', '2099 GET'):
                self.assertNotIn(private, output)

    def test_parse_metadata_rolls_back_together(self):
        self.sandbox()
        write = self.store.set_meta

        def crash(key, value):
            write(key, value)
            if key == 'synology:diagnostics':
                raise b1.PowerLoss()

        with patch.object(self.store, 'set_meta', side_effect=crash), self.assertRaises(b1.PowerLoss):
            self.poll(b1.feed(b1.item()))
        self.assertIsNone(self.store.get_meta('synology:last_build'))
        self.assertIsNone(self.store.get_meta('synology:diagnostics'))

    def test_non_200_decides_before_reading_body(self):
        for status, body, headers in (
            (206, b'short', {'content-length': '1000'}),
            (429, b' ' * (8 * 1024**2 + 1), {'retry-after': '7200'}),
            (503, b' ' * (8 * 1024**2 + 1), {'retry-after': '7200'}),
        ):
            with self.subTest(status=status):
                self.sandbox()
                header_bytes = b''.join(f'{k}: {v}\r\n'.encode() for k, v in headers.items())
                wire = f'HTTP/1.1 {status} Status\r\n'.encode() + header_bytes + b'\r\n' + body
                response = HTTPResponse(Mock(makefile=Mock(return_value=BytesIO(wire))))
                response.begin()
                with patch.object(self.http, 'opener', Mock(open=Mock(return_value=response))), \
                        patch.object(response, 'read1', wraps=response.read1) as read:
                    outcome, = self.adapter.poll()
                    read.assert_not_called()
                expected = dict(path='feed', unconditional=True, status=status, headers=headers)
                if status == 206:
                    expected.update(invalid_envelope=True, invalid_status=True)
                self.assertEqual(outcome, expected)
                self.assertEqual(self.process(outcome), 'FAILED')
                self.assertEqual(self.rows("SELECT state FROM source_health WHERE dimension='fetch'"),
                                 [('unhealthy',)])
                self.assertEqual(self.rows('SELECT * FROM staged_containers'), [])
                resource, retry = self.rows('SELECT resource,next_attempt_at FROM adapter_retries')[0]
                self.assertEqual(resource, 'feed')
                if 'retry-after' in headers:
                    self.assertEqual(instant(retry) - instant(self.tick), timedelta(hours=2))

    def test_retention_requires_sorted_ids_and_utc_instants(self):
        for changes in (dict(observed_at='not a date'), dict(observed_at=None),
                        dict(observed_at='2099-01-02 00:00:00Z'), dict(oldest=None),
                        dict(newest=None), dict(oldest='2099-02-30T00:00:00Z'),
                        dict(newest='2099-01-02T00:00:00+01:00'), dict(ids=[b1.B, b1.A]),
                        dict(boundary=[b1.B, b1.A]), dict(ids=[b1.A, 1]), dict(boundary=None),
                        dict(newest_ids=[b1.B, b1.A]), dict(newest_ids=[1]),
                        dict(boundary=[b1.C]), dict(newest_ids=[b1.C]),
                        dict(boundary=[]), dict(newest_ids=[])):
            with self.subTest(changes=changes):
                self.sandbox()
                outcome = self.poll(b1.feed(b1.item(), b1.item(b1.B, b1.NEW)))
                self.assertEqual(self.process(outcome | {'retention': outcome['retention'] | changes}), 'FAILED')
                self.assertEqual(self.rows('SELECT last_error FROM adapter_retries'),
                                 [('ValueError: invalid retention summary',)])
                self.assertIsNone(self.store.get_meta('retention:synology'))
                for table in ('advisories', 'manifest_members', 'staged_containers'):
                    self.assertEqual(self.rows(f'SELECT * FROM {table}'), [])

    def test_all_undated_members_are_quarantined_not_a_failed_envelope(self):
        self.sandbox()
        self.assertEqual(self.cycle(b1.item(pubDate='')), 'PARTIAL')
        self.assertEqual(self.rows('SELECT source_id,reason FROM quarantine'),
                         [(b1.A, 'ValueError: advisory mapping failed')])

    def test_partial_preserves_accepted_watermarks_after_withdrawal(self):
        self.sandbox()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.B, b1.NEW)), 'COMPLETE')
        accepted = self.summary()
        self.withdraw_first()
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(b1.B, 'Thu, 01 Jan 2099 02:00:00 GMT'),
                                    b1.item(b1.X, title='')), 'PARTIAL')
        self.assertEqual(self.summary(), accepted | {'ids': [b1.B], 'boundary': [], 'oldest': None})
        self.assertEqual(self.summary()['newest'], '2099-01-01T01:00:00Z')

    def test_partial_withdrawal_preserves_watermark_with_other_support(self):
        self.sandbox()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.B, b1.NEW), b1.item(b1.C, b1.NEW)),
                         'COMPLETE')
        accepted = self.summary()
        self.assertEqual(accepted['newest_ids'], [b1.B, b1.C])
        self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?", (b1.B,))
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.C, title='An edited active notice'),
                                   b1.item(b1.X, title='')), 'PARTIAL')
        self.assertEqual(self.summary(), accepted | {'ids': [b1.A, b1.C], 'newest_ids': [b1.C]})
        self.db.execute("UPDATE advisories SET state='withdrawn' WHERE source='synology' AND source_id=?", (b1.C,))
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.X, title='')), 'PARTIAL')
        self.assertEqual(self.summary(), accepted | {'ids': [b1.A], 'newest_ids': [], 'newest': None})

    def test_complete_withdrawal_and_rebaseline_replace_watermark_support(self):
        self.sandbox()
        outcome = self.poll(b1.feed(b1.item(), b1.item(b1.B, b1.NEW)))
        body = json.loads(outcome['body'])
        body['advisories'][0]['withdrawn'] = self.tick
        self.assertEqual(self.process(outcome | {'body': canonical(body)}), 'COMPLETE')
        self.assertEqual(self.summary(), dict(accepted=True, ids=[b1.B], boundary=[b1.B],
            newest_ids=[b1.B], oldest=b1.NEWEST, newest=b1.NEWEST, observed_at=self.tick))
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(b1.C)), 'PARTIAL')
        self.persistence.rebaseline('synology', self.tick)
        self.assertEqual(self.summary(), dict(accepted=True, ids=[b1.C], boundary=[b1.C],
            newest_ids=[b1.C], oldest=b1.OLDEST, newest=b1.OLDEST, observed_at=self.tick))

    def test_returning_active_member_is_in_accepted_summary(self):
        self.sandbox()
        self.assertEqual(self.cycle(b1.item(), b1.item(b1.B, b1.NEW)), 'COMPLETE')
        self.withdraw_first()
        self.next_poll()
        self.assertEqual(self.cycle(b1.item(title='An edited active notice'), b1.item(b1.B, b1.NEW)),
                         'COMPLETE')
        self.assertEqual(self.rows('SELECT source_id,state FROM advisories ORDER BY source_id'),
                         [(b1.A, 'active'), (b1.B, 'active')])
        self.assertEqual(self.summary(), dict(accepted=True, ids=[b1.A, b1.B], boundary=[b1.A],
            newest_ids=[b1.B], oldest=b1.OLDEST, newest=b1.NEWEST, observed_at=self.tick))

    def test_malformed_same_id_duplicate_conflicts(self):
        for second_title in ('', 'A valid invented title'):
            with self.subTest(second_title=second_title):
                self.sandbox()
                first = b1.item(title='')
                second = first | {'guid': first['guid'].replace('/support/', '/'), 'title': second_title}
                self.assertEqual(self.cycle(first, second), 'PARTIAL')
                self.assertEqual(self.rows('SELECT source_id,reason FROM quarantine'),
                                 [(b1.A, 'same-ID conflict')])
                self.assertEqual(self.rows('SELECT * FROM advisories'), [])

    def test_mapping_version_optional_and_scoped_at_store(self):
        raw = synology.normalise(b1.item())
        self.assertEqual(raw.pop('mapping_version'), synology.MAPPING_VERSION)
        with self.assertRaisesRegex(ValueError, '^advisory mapping failed$'):
            feedvalidate.validate_advisory(raw | {'mapping_version': 'invented'},
                                           source='synology', observed_at=b1.TICK,
                                           date_fields=date_fields('synology'))
        self.sandbox()
        self.assertEqual(self.process(dict(path='feed', status=200,
                                          body=canonical(dict(advisories=[raw])))), 'COMPLETE')
        [(stored,)] = self.rows('SELECT json FROM advisories')
        self.assertNotIn('mapping_version', json.loads(stored))
        validated = feedvalidate.validate_advisory(raw | {'mapping_version': 'invented', 'updated': b1.TICK},
                                                   source='github', observed_at=b1.TICK)
        self.assertNotIn('mapping_version', validated.data)

    def test_resume_accepts_batch_before_any_later_poll(self):
        self.sandbox()
        outcome = self.poll(b1.feed(b1.item()))
        path = self.persistence.stage_members('synology', 'feed', json.loads(outcome['body'])['advisories'],
                                               self.tick, flags={'retention': outcome['retention']})
        self.assertTrue(path.is_file())
        self.assertIsNone(self.store.get_meta('retention:synology'))
        self.assertEqual(self.rows('SELECT source_id FROM manifest_members'), [])
        self.next_poll()
        AdapterStore(self.store, self.http.data_dir).resume(self.tick, source='synology')
        self.assertEqual(self.rows("SELECT cursor_tick FROM adapter_state WHERE source='synology'"), [(self.tick,)])
        self.assertEqual(self.rows('SELECT source_id FROM manifest_members'), [(b1.A,)])
        self.assertEqual(self.summary(), outcome['retention'] | {'accepted': True})
        self.assertEqual(self.rows('SELECT * FROM staged_containers'), [])
        self.assertFalse(path.exists())
        self.assertEqual(len(self.endpoint.trace), 1)

    def test_negation_only_declines_exploitation_or_affectedness(self):
        dsm = ['DiskStation Manager (DSM)']
        for clause, expected in (
            ('read notes in a scenario that does not require authentication', dsm),
            ('read notes without user interaction', dsm),
            ('verify that it cannot be exploited', []),
            ("verify that it can't affect the device", []),
            ('verify that it has never been vulnerable', []),
            ('verify that it is no longer impacted', []),
            ('verify that it is unable to be susceptible', []),
        ):
            with self.subTest(clause=clause):
                text = f'A vulnerability allows actors to {clause} via a susceptible version of DSM.'
                template, diagnostics = ('S-ONE', {}) if expected else (None, {'unrecognised template': 1})
                self.assertEqual(synology.products('Invented notice', text), (expected, template, diagnostics))
        for name, expected in (
            ('DSM and Invented Not A Product', (dsm, 'S-UPD', {'unrecognised subject': 1})),
            ('DSM and Invented Not Affected', ([], None, {'unrecognised template': 1})),
        ):
            with self.subTest(name=name):
                self.assertEqual(synology.products('Invented notice',
                    f'Synology has released a security update for {name} to address a flaw.'), expected)

    def test_affirmative_kev_notice_routes_without_authentication(self):
        backend = self.replay()
        with backend.store.transaction():
            backend.engine._ingest(IngestResult('kev', FetchStatus.COMPLETE, Origin.SNAPSHOT, None,
                instant(b2.T1), kev={b2.KEV_ID: {'cveID': b2.KEV_ID}}))
        novel = b2.item(11) | {'description': (
            f'{b2.KEV_ID} allows actors to read notes in a scenario that does not require authentication '
            'via a susceptible version of DSM.')}
        b2.Task6B2Tests.poll(backend, b2.T2, [b2.item(1), novel])
        self.assertEqual([(n['watch'], n['record'], n['urgency']) for n in backend.sent if n['watch']],
                         [('w', b2.KEV_ID, 'urgent')])

    def test_withdrawn_member_does_not_mask_a_watermark_move(self):
        for withdrawn_item in (b1.item(), b1.item(pubDate='')):
            with self.subTest(withdrawn_item=withdrawn_item):
                self.sandbox()
                self.assertEqual(self.cycle(b1.item(), b1.item(b1.B, b1.NEW)), 'COMPLETE')
                self.withdraw_first()
                self.next_poll()
                self.assertEqual(self.cycle(b1.item(b1.B, b1.NEW)), 'COMPLETE')
                accepted, cursor = self.summary(), self.tick
                self.next_poll()
                self.assertEqual(self.cycle(withdrawn_item, b1.item(b1.B, 'Thu, 01 Jan 2099 02:00:00 GMT')),
                                 'PARTIAL')
                self.assertEqual(self.rows('SELECT reason FROM gap_ledger'), [('retention watermark moved',)])
                self.assertEqual(self.rows("SELECT cursor_tick FROM adapter_state WHERE source='synology'"),
                                 [(cursor,)])
                self.assertEqual(self.summary(), accepted)

    def test_undated_identifiable_members_appear_only_in_the_outcome(self):
        for link_fallback in (False, True):
            with self.subTest(link_fallback=link_fallback):
                self.sandbox()
                second = b1.item(b1.B, pubDate='')
                if link_fallback:
                    del second['guid']
                outcome = self.poll(b1.feed(b1.item(pubDate=''), second))
                self.assertEqual(outcome['retention'], dict(ids=[b1.A, b1.B], boundary=[], newest_ids=[],
                    oldest=None, newest=None, observed_at=self.tick))
                self.assertEqual(self.process(outcome), 'PARTIAL')
                self.assertEqual(self.rows('SELECT source_id FROM quarantine ORDER BY source_id'),
                                 [(b1.A,), (b1.B,)])
                self.assertEqual(self.summary(), dict(accepted=False, ids=[]))

    def test_same_id_duplicate_compares_publication_instants(self):
        self.sandbox()
        first = b1.item()
        equivalent = first | {'pubDate': 'Wed, 31 Dec 2098 19:00:00 -0500'}
        self.assertEqual(self.cycle(first, equivalent), 'COMPLETE')
        self.assertEqual(self.rows('SELECT source_id FROM manifest_members'), [(b1.A,)])
        self.assertEqual(self.rows('SELECT source_id FROM quarantine'), [])

    def test_withdrawal_fallback_groups_support_by_instant(self):
        for path in ('complete', 'resume', 'rebaseline'):
            with self.subTest(path=path):
                self.sandbox()
                latest = '2099-01-01T01:00:00.1Z'
                notices = [
                    synology.normalise(b1.item()) | {'withdrawn': self.tick},
                    synology.normalise(b1.item(b1.B)) | {'published': b1.NEWEST},
                    synology.normalise(b1.item(b1.C)) | {'published': '2099-01-01T01:00:00+00:00'},
                    synology.normalise(b1.item(b1.X)) | {'published': latest},
                ]
                retention = dict(ids=[b1.A, b1.B, b1.C, b1.X], boundary=[b1.A], newest_ids=[b1.X],
                                 oldest=b1.OLDEST, newest=latest, observed_at=self.tick)
                if path == 'complete':
                    self.assertEqual(self.process(dict(path='feed', status=200, retention=retention,
                        body=canonical(dict(advisories=notices)))), 'COMPLETE')
                else:
                    self.persistence.stage_members('synology', 'feed', notices, self.tick,
                                                   flags={'retention': retention})
                    if path == 'resume':
                        self.persistence.resume(self.tick, source='synology')
                    else:
                        self.persistence.rebaseline('synology', self.tick)
                self.assertEqual(self.summary(), retention | dict(accepted=True, ids=[b1.B, b1.C, b1.X],
                    boundary=[b1.B, b1.C], oldest=b1.NEWEST))

    def test_integer_retention_dates_fail_with_valid_support(self):
        for key in ('observed_at', 'oldest'):
            with self.subTest(key=key):
                self.sandbox()
                outcome = self.poll(b1.feed(b1.item()))
                self.assertEqual(self.process(outcome | {'retention': outcome['retention'] | {key: 7}}),
                                 'FAILED')
                self.assertEqual(self.rows('SELECT last_error FROM adapter_retries'),
                                 [('ValueError: invalid retention summary',)])
                self.assertEqual(self.rows('SELECT source_id FROM advisories'), [])
                self.assertIsNone(self.store.get_meta('retention:synology'))

    def test_retention_horizon_is_capped_at_ten_years(self):
        self.sandbox()
        args = self.http, self.adapter.state, self.adapter.clock
        self.assertEqual(SynologyRss(*args, retention_hours=87_600).retention_hours, 87_600)
        with self.assertRaisesRegex(ValueError, '^invalid Synology retention or interval$'):
            SynologyRss(*args, retention_hours=87_601)

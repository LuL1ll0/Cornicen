"""Engine and notifier contracts for the unknown applicability digest."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cornicen import adapters, applicability, engine, synology
from cornicen.adapterstore import AdapterStore
from cornicen.config import Config
from cornicen.identity import AliasMap
from cornicen.model import FetchStatus, IngestResult, Notification, Origin
from cornicen.notify.file import FileNotifier
from cornicen.notify import ntfy
from cornicen.outbox import Outbox
from cornicen.render import render
from cornicen.store import Store
from cornicen.versions import Scheme
from cornicen.watchlist import Watch, load_document_text


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 25, 8, tzinfo=timezone.utc)
WATCH_TEXT = '''
[[watch]]
id = "fictional-media"
name = "Fictional Media"
match = ["fictional:fictional player"]
version = "8.2.90"
scheme = "semver"
'''
ACCEPT_TEXT = '''
[[accept]]
cve = "CVE-2099-80006"
watch = "fictional-media"
reason = "fixture accept"
until = 2026-12-31

[[accept]]
cve = "CVE-2099-80007"
watch = "fictional-media"
reason = "fixture accept"
until = 2026-11-01
'''
(MEDIA,), ACCEPTS = load_document_text(WATCH_TEXT + ACCEPT_TEXT)
WIDGET = Watch('widget-box', 'Widget Box', (), ('widget',), '4.0.0-example', Scheme.SEMVER, False)
NAS = Watch('example-nas', 'Example NAS', (('synology', 'diskstation manager (dsm)'),),
            (), '7.9.0-99999', Scheme.DEBIAN, False)
COMPARE = 'CNA unknown fictional player: version comparison unknown'
DEFAULT = ("CNA unknown fictional player: outside every range the CNA listed; "
           "the CNA's default says affected; 8.0.0 <= version < 8.1.0")


def cve(suffix):
    return f'CVE-2099-{80000 + suffix}'


def entry(**fields):
    return dict(dict(vendor='fictional', product='fictional player'), **fields)


def record(suffix, *entries):
    return dict(cveMetadata=dict(cveId=cve(suffix), state='PUBLISHED'),
                containers=dict(cna=dict(affected=list(entries))))


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append(request)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    status = 200

    @property
    def texts(self):
        return [request.data.decode('utf-8') for request in self.requests]


class Install:
    def __init__(self, test, watches=(MEDIA,), accepts=()):
        self.directory = Path(test.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / 'notifications.jsonl'
        self.config = Config(str(self.directory / 'store.db'), self.directory / 'watches.toml',
                             None, '', '', None, adapters=dict.fromkeys(adapters.REGISTRY, False))
        self.store = Store(self.config.db_path)
        test.addCleanup(self.store.connection.close)
        self.store.migrate()
        self.db = self.store.connection
        self.now = NOW
        self.aliases = AliasMap.load(False)
        self.engine = engine.Engine(self.store, watches, self.aliases, self.config,
                                    lambda: self.now, FileNotifier(self.path), accepts=accepts)

    def ntfy(self, test):
        opener = Opener()
        test.enterContext(patch.object(ntfy, 'build_opener', return_value=opener))
        self.engine.notifier = ntfy.NtfyNotifier(ntfy.post, 'https://example.invalid', 'fixture', None)
        return opener

    def ingest(self, *records):
        return self.engine.run_cycle([
            IngestResult('cvelist', FetchStatus.COMPLETE, Origin.DELTA, None, self.now, records)
        ], release_checks=False)

    def pair(self, suffix, watch=MEDIA.id, state='unknown', *, evidence=COMPARE,
             exploited=0, notified=0, baseline=0):
        self.db.execute('INSERT INTO pairs VALUES (?,?,?,?,?,?,?,?,?,?)',
                        (watch, cve(suffix) if isinstance(suffix, int) else suffix, state,
                         1, baseline, exploited, notified, evidence, 'medium', 'fixture'))

    def selection(self):
        self.pair(1, baseline=1)
        self.pair(2, evidence=DEFAULT)
        self.pair(3, exploited=1)
        self.pair(4, state='affected')
        self.pair(5, state='not_affected')
        self.pair(6)
        self.pair(7, notified=1)
        self.pair(8, watch='removed-watch')
        self.pair(9, watch='Fictional-Media')
        return self

    def due(self, *suffixes):
        self.ingest(*(record(i, entry(defaultStatus='affected')) for i in suffixes))
        self.db.execute('UPDATE outbox SET due_at=? WHERE sent_at IS NULL', (self.now.isoformat(),))

    def health(self):
        self.engine._event('', 'kev', 'unhealthy', 1, dict(record_id='kev'), immediate=True)

    def envelopes(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def section_text(self, opener):
        _, separator, text = opener.texts[-1].partition('\n\nUnknown applicability')
        return 'Unknown applicability' + text if separator else ''

    def evidence(self, suffix=1):
        return self.db.execute('SELECT evidence FROM pairs WHERE record_id=?', (cve(suffix),)).fetchone()[0]

    def advisory(self, source, status='under_investigation'):
        self.engine.commit_advisory(dict(
            source=source, source_id='fixture', digest='fixture', title='Fixture advisory',
            published=None, updated=None, observed_at=self.now.isoformat(), provenance={},
            url='https://example.invalid/fixture',
            products=[dict(id='fixture', name='fictional:fictional player')],
            cves=[dict(value=cve(1), field_path='cve')],
            evidence=[dict(product_id='fixture', scheme='semver', status=status)]))


class UnknownDigestTests(unittest.TestCase):
    def test_T1_sent_CNA_labels(self):
        def version(value=MEDIA.version, **fields):
            return entry(versions=[dict(dict(version=value, status='unknown'), **fields)])

        cases = [
            (MEDIA, version('release'), 'version comparison unknown', 'version compare unknown'),
            (replace(MEDIA, scheme=Scheme.OPAQUE), version('8.*', lessThan=MEDIA.version),
             'opaque range comparison unknown', 'version compare unknown'),
            (replace(MEDIA, scheme=Scheme.DEBIAN),
             version(MEDIA.version + '.*', lessThan=MEDIA.version + '.0'),
             'wildcard line below its first release', 'version compare unknown'),
            (replace(MEDIA, scheme=Scheme.OPAQUE),
             version(changes=[dict(at=MEDIA.version, status='affected')]),
             'opaque status changes require ordering', 'version compare unknown'),
            (MEDIA, version(versionType='vendor scheme'),
             'versionType vendor scheme conflicts with semver', 'scheme mismatch'),
            (MEDIA, entry(lessThan=MEDIA.version), 'version fields outside versions[]', 'malformed record'),
            (MEDIA, entry(defaultStatus='affected', versions=[
                dict(version='8.0.0', lessThan='8.1.0', status='affected')]),
             DEFAULT.partition(': ')[2], 'default says affected'),
            (MEDIA, entry(defaultStatus='unknown'), 'defaultStatus unknown', 'no version data'),
            (MEDIA, version(), MEDIA.version, 'CNA says unknown'),
            (replace(MEDIA, scheme=Scheme.OPAQUE), version('release; synology: unknown'),
             'release; synology: unknown', 'CNA says unknown'),
            (replace(MEDIA, scheme=Scheme.OPAQUE), entry(defaultStatus='unaffected'),
             'defaultStatus unaffected', 'no version data'),
        ]
        for watch, data, detail, label in cases:
            with self.subTest(detail=detail):
                install = Install(self, (watch,))
                opener = install.ntfy(self)
                install.ingest(record(1, data))
                self.assertEqual(install.evidence(), 'CNA unknown fictional player: ' + detail)
                install.due(90)
                install.engine._flush()
                self.assertIn(f'Why: 1 {label}', install.section_text(opener).splitlines())
                self.assertNotIn(install.evidence(), install.section_text(opener))

        install = Install(self, (MEDIA, WIDGET))
        opener = install.ntfy(self)
        install.ingest(record(1, entry(product='widget')))
        self.assertEqual(install.evidence(), 'Product-only identity match; version applicability unknown')
        install.due(90)
        install.engine._flush()
        self.assertIn('Why: 1 product only', install.section_text(opener).splitlines())

    def test_T1_sent_advisory_labels(self):
        for source in adapters.REGISTRY:
            with self.subTest(source=source):
                install = Install(self)
                opener = install.ntfy(self)
                install.advisory(source)
                self.assertEqual(install.evidence(), f'{source}: unknown')
                self.assertIn(install.evidence().partition(': ')[0], adapters.REGISTRY)
                install.due(90)
                install.engine._flush()
                self.assertIn('Why: 1 vendor advisory', install.section_text(opener).splitlines())

        github, synology_source = (adapters.REGISTRY[name].name for name in ('github', 'synology'))
        install = Install(self)
        opener = install.ntfy(self)
        install.advisory(github, 'known_not_affected')
        install.advisory(synology_source)
        self.assertEqual(install.evidence(), 'github: not_affected; synology: unknown')
        install.due(90)
        install.engine._flush()
        self.assertIn('Why: 1 vendor advisory', install.section_text(opener).splitlines())

    def test_T1_sent_joined_CNA_and_quarantine(self):
        install = Install(self)
        opener = install.ntfy(self)
        source = next(iter(adapters.REGISTRY))
        shell = dict(source=source, source_id='fixture', cves=[dict(value=cve(1))],
                     products=[dict(name='fictional:fictional player')])
        install.engine.observe_unknown_advisory(shell)
        self.assertEqual(install.evidence(), 'Quarantined advisory; applicability unknown')
        install.due(90)
        install.engine._flush()
        self.assertIn('Why: 1 other', install.section_text(opener).splitlines())

        install.engine.scope_equivalences = ((MEDIA.version, None),)
        install.ingest(record(1, entry(versions=[dict(version='release', status='unknown')]),
                              entry(defaultStatus='unknown', release=MEDIA.version)))
        self.assertEqual(install.evidence(), COMPARE + '; CNA unknown fictional player: defaultStatus unknown')
        install.due(91)
        install.engine._flush()
        self.assertIn('Why: 1 other', install.section_text(opener).splitlines())

    def test_T1_producer_only(self):
        # These paths do not produce sent pairs on the ordinary ingestion path.
        from cornicen.unknowns import classify

        aliases = AliasMap.load(False)
        bad = entry(versions=[dict(version=MEDIA.version, lessThan=1, status='unknown')])
        result = applicability.resolve(record(1, bad), None, MEDIA, aliases)
        self.assertEqual(result.evidence, 'CNA unknown fictional player: invalid lessThan')
        self.assertEqual(classify(result.evidence), 'malformed record')
        self.assertEqual(classify('CNA unknown fictional player: wildcard line comparison unknown'),
                         'version compare unknown')
        collision = 'CNA unknown player: pro: version comparison unknown'
        for product, version, scheme in (
                ('player： pro', 'release', Scheme.SEMVER),
                ('player', 'pro: version comparison unknown', Scheme.OPAQUE)):
            watch = replace(MEDIA, match=(('fictional', product.replace('：', ':')),), scheme=scheme)
            data = entry(product=product, versions=[dict(version=version, status='unknown')])
            result = applicability.resolve(record(1, data), None, watch, aliases)
            self.assertEqual(result.evidence, collision)
            self.assertEqual(classify(result.evidence), 'CNA says unknown')

    def test_T2_selection_in_file_envelope(self):
        install = Install(self, accepts=ACCEPTS).selection()
        install.due(90)
        install.engine._flush()
        section = install.envelopes()[-1]['body']['applicability']
        self.assertEqual(section['total'], 4)
        self.assertEqual(section['watches'], 1)
        self.assertEqual(section['why'], [['version compare unknown', 3], ['default says affected', 1]])
        self.assertEqual(section['more'], 0)
        self.assertEqual([watch['count'] for watch in section['list']], [4])

        empty = Install(self)
        empty.pair(3, exploited=1)
        empty.due(90)
        empty.engine._flush()
        self.assertNotIn('applicability', empty.envelopes()[-1]['body'])

    def test_T2_accept_watch_matching_is_case_insensitive(self):
        # Exercise both spellings on the accept side, not just the watch side.
        for watch_id, accept_watch in (('Fictional-Media', 'fictional-media'),
                                       ('fictional-media', 'Fictional-Media')):
            with self.subTest(watch=watch_id, accept_watch=accept_watch):
                watches, accepts = load_document_text(
                    WATCH_TEXT.replace(MEDIA.id, watch_id) + ACCEPT_TEXT.replace(MEDIA.id, accept_watch))
                install = Install(self, watches, accepts)
                install.pair(6, watch=watch_id)
                install.pair(1, watch=watch_id)
                install.due(90)
                install.engine._flush()
                envelope, = install.envelopes()
                self.assertEqual(envelope['body']['applicability']['list'][0]['ids'], [cve(1)])

    def test_T3_exact_sent_text(self):
        install = Install(self, (MEDIA, WIDGET), ACCEPTS)
        opener = install.ntfy(self)
        install.pair(1, baseline=1)
        install.pair(2, evidence=DEFAULT)
        install.pair(7, notified=1)
        install.pair(10, watch=WIDGET.id, evidence='Product-only identity match; version applicability unknown')
        install.db.executemany('INSERT INTO epss(cve, score) VALUES (?,?)', [(cve(1), .5), (cve(7), .9)])
        install.due(90)
        install.engine._flush()
        self.assertTrue(opener.texts[-1].endswith(
            '\n\nUnknown applicability (not alerting): 4 pairs on 2 watches\n'
            'Why: 2 version compare unknown, 1 default says affected, 1 product only\n'
            'Fictional Media (fictional player 8.2.90): 3 — 2 version compare unknown, 1 default says affected\n'
            '  CVE-2099-80007, CVE-2099-80001, CVE-2099-80002\n'
            'Widget Box (widget 4.0.0-example): 1 — 1 product only\n'
            '  CVE-2099-80010'))

    def test_T4_watch_and_id_caps(self):
        watches = tuple(replace(MEDIA, id=f'w{i:02}', name=f'w{i:02}', match=(('fictional', f'player {i}'),)) for i in range(1, 11))
        install = Install(self, (MEDIA, *watches))
        opener = install.ntfy(self)
        for i, watch in enumerate(watches):
            for j in range(10 - i):
                install.pair(j + 1, watch=watch.id, evidence=DEFAULT if i == 9 else COMPARE)
        install.due(90)
        install.engine._flush()
        lines = install.section_text(opener).splitlines()
        self.assertEqual(lines[0], 'Unknown applicability (not alerting): 55 pairs on 10 watches')
        self.assertEqual(lines[1], 'Why: 54 version compare unknown, 1 default says affected')
        self.assertEqual([line.split()[0] for line in lines[2:-1:2]], [w.id for w in watches[:8]])
        self.assertEqual(lines[3], '  CVE-2099-80001, CVE-2099-80002, CVE-2099-80003 and 7 more')
        self.assertEqual(lines[-1], 'and 2 more watches: cornicen report --group unknown')

    def test_T4_byte_cap(self):
        watches = tuple(replace(MEDIA, id=f'w{i:02}', name='é' * 160, match=(('fictional', f'player {i}'),)) for i in range(8))
        install = Install(self, (MEDIA, *watches))
        opener = install.ntfy(self)
        for i, watch in enumerate(watches):
            install.pair(i + 1, watch=watch.id)
        install.due(90)
        install.engine._flush()
        section = install.section_text(opener)
        lines = section.splitlines()
        self.assertEqual(lines[:2], ['Unknown applicability (not alerting): 8 pairs on 8 watches',
                                     'Why: 8 version compare unknown'])
        shown = (len(lines) - 3) // 2
        self.assertGreater(shown, 0)
        self.assertLess(shown, 8)
        self.assertEqual(lines[-1], f'and {8 - shown} more watches: cornicen report --group unknown')
        self.assertLessEqual(len(section.encode('utf-8')), 2048)

    def test_T4_tie_clean_fields_and_safe_ids(self):
        b = replace(MEDIA, id='B-watch', name='B Watch', match=(('fictional', 'widget b'),))
        a = replace(MEDIA, id='a-watch', name='A\x1b[31m\nWatch',
                    match=(('fictional', 'widget\x00a'),), version='fixture\x07build')
        install = Install(self, (MEDIA, b, a))
        # Raw U+2028 sorts after ASCII. Sanitizing before sorting would put '?' first.
        unsafe = 'advisory:synology:fixture\u2028x\u202ey\u2029z:main'
        safe = 'advisory:synology:fixture?x?y?z:main'
        long_id = 'advisory:synology:fixture' + 'x' * 80 + ':main'
        for suffix, watch in ((1, b), (2, b), (unsafe, a), (long_id, a)):
            install.pair(suffix, watch=watch.id)
        install.due(90)
        install.engine._flush()
        self.assertEqual(len(install.path.read_text().splitlines()), 1)
        blocks = install.envelopes()[0]['body']['applicability']['list']
        self.assertEqual([block['name'] for block in blocks], ['A [31m Watch', 'B Watch'])
        self.assertEqual(blocks[0]['ids'], [long_id[:77] + '...', safe])

        opener = install.ntfy(self)
        install.due(91)
        install.engine._flush()
        lines = install.section_text(opener).splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[2], 'A [31m Watch (widget a fixture build): 2 — 2 version compare unknown')
        self.assertEqual(lines[3], f'  {long_id[:77]}..., {safe}')

    def test_T5_normal_groups_and_DB_guard(self):
        def run(path, control):
            release = replace(WIDGET, latest_release='fictional/widget')
            install = Install(self, (MEDIA, release))
            install.pair(1)
            if path in ('one', 'three'):
                install.due(*(range(90, 91) if path == 'one' else range(90, 93)))
            else:
                install.engine._event(release.id, 'release', 'release_behind', 1, dict(
                    watch_id=release.id, record_id='release', product='widget',
                    release_behind=True, repository=release.latest_release, tag=MEDIA.version),
                    immediate=True)
            send = engine.deliver

            def without_section(*args, **kwargs):
                kwargs.pop('unknown_section', None)
                return send(*args, **kwargs)

            if control:
                with patch.object(engine, 'deliver', without_section):
                    install.engine._flush()
            else:
                install.engine._flush()
            envelope, = install.envelopes()
            self.assertEqual(len(envelope['body']['items']), 3 if path == 'three' else 1)
            if path == 'release':
                self.assertTrue(envelope['body']['items'][0]['body']['release_behind'])
            snapshot = {table: [tuple(row) for row in install.db.execute(f'SELECT * FROM {table} ORDER BY 1')]
                        for table in ('outbox', 'events', 'pairs', 'epss_crossings', 'meta')}
            return envelope, snapshot

        for path in ('one', 'three', 'release'):
            with self.subTest(path=path):
                observed, snapshot = run(path, False)
                control, control_snapshot = run(path, True)
                self.assertEqual(observed['body'].pop('applicability')['total'], 1)
                self.assertEqual(observed, control)
                self.assertEqual(snapshot, control_snapshot)

    def test_T5_regrouping_keeps_only_normal_section(self):
        install = Install(self)
        install.pair(1)
        install.due(90, 91)
        original = install.engine._delivery_rows
        inputs, outputs = [], []
        promoted = None

        def revalidate(rows):
            nonlocal promoted
            inputs.append([row['urgency'] for row in rows])
            current = original(rows)
            if promoted is None:
                promoted = current[0]['id']
            current = [dict(row, urgency='urgent') if row['id'] == promoted else row for row in current]
            outputs.append([row['urgency'] for row in current])
            return current

        with patch.object(install.engine, '_delivery_rows', revalidate):
            install.engine._flush()
        self.assertEqual(inputs, [['normal', 'normal'], ['urgent'], ['normal']])
        self.assertEqual(outputs, [['urgent', 'normal'], ['urgent'], ['normal']])
        urgent, normal = install.envelopes()
        self.assertEqual(urgent['urgency'], 'urgent')
        self.assertNotIn('applicability', urgent['body'])
        self.assertEqual(normal['urgency'], 'normal')
        self.assertEqual(normal['body']['applicability']['total'], 1)

    def test_T5_health_with_zero_due_normal_rows(self):
        install = Install(self)
        install.pair(1)
        install.health()
        install.engine._flush()
        health, = install.envelopes()
        self.assertEqual(health['urgency'], 'health')
        self.assertNotIn('applicability', health['body'])
        self.assertNotIn('items', health['body'])

    def test_T5_stale_normal_row_does_not_send_a_digest(self):
        install = Install(self)
        install.pair(1)
        opener = install.ntfy(self)
        install.due(90)
        original = install.engine._delivery_rows

        def revalidate(rows):
            # Change the pair after the initial refresh, at delivery revalidation.
            row, = rows
            self.assertEqual(row['urgency'], 'normal')
            install.db.execute("UPDATE pairs SET state='not_affected' WHERE watch_id=? AND record_id=?",
                               (MEDIA.id, cve(90)))
            current = original(rows)
            self.assertEqual(current, [])
            return current

        with (patch.object(install.engine, '_delivery_rows', side_effect=revalidate) as validate,
              patch.object(install.engine.notifier, 'send', wraps=install.engine.notifier.send) as send):
            install.engine._flush()
        validate.assert_called_once()
        self.assertEqual((send.call_count, len(opener.requests)), (0, 0))

    def test_T6_retry_recomputes_without_changing_key(self):
        install = Install(self)
        install.pair(1)
        install.pair(2, state='not_affected')
        install.due(90)
        attempts = []
        file = install.engine.notifier

        class FailOnce:
            def send(self, notification):
                attempts.append(notification)
                return len(attempts) > 1 and file.send(notification)

        install.engine.notifier = FailOnce()
        install.engine._flush()
        row = install.db.execute('SELECT sent_at, attempts, next_attempt_at FROM outbox').fetchone()
        deadline = install.now + timedelta(seconds=60)
        self.assertEqual(tuple(row), (None, 1, deadline.isoformat()))
        self.assertFalse(install.path.exists())
        install.db.execute("UPDATE pairs SET state='unknown' WHERE record_id=?", (cve(2),))
        install.now = deadline - timedelta(seconds=1)
        install.engine._flush()
        self.assertEqual(len(attempts), 1)
        install.now = deadline
        install.engine._flush()
        first, second = attempts
        self.assertEqual(first.key, second.key)
        self.assertEqual(first.body['applicability']['total'], 1)
        self.assertEqual(second.body['applicability']['total'], 2)
        self.assertEqual(install.envelopes()[0]['body']['applicability']['total'], 2)

    def test_T7_failure_is_fixed_and_private(self):
        install = Install(self)
        opener = install.ntfy(self)
        install.due(90)
        captured = []
        send = install.engine.notifier.send
        deliver = engine.deliver
        stdout, stderr = io.StringIO(), io.StringIO()

        def capture(notification):
            captured.append(notification)
            return send(notification)

        def fail():
            raise RuntimeError('fictional-media CVE-2099-80001')

        def inject(*args, **kwargs):
            if 'unknown_section' in kwargs:
                kwargs['unknown_section'] = fail
            return deliver(*args, **kwargs)

        with (patch.object(install.engine.notifier, 'send', capture),
              patch.object(engine, 'deliver', inject),
              redirect_stdout(stdout), redirect_stderr(stderr)):
            install.engine._flush()
        envelope, = captured
        self.assertEqual(envelope.body['applicability'], {'unavailable': True})
        posted, = opener.texts
        self.assertTrue(posted.endswith('\n\nUnknown applicability: not available'))
        for stream in (stdout, stderr):
            self.assertNotIn('fictional-media', stream.getvalue())
            self.assertNotIn('CVE-2099-80001', stream.getvalue())

    def test_T8_render_and_engine_free_guards(self):
        install = Install(self)
        install.pair(1)
        install.due(90, 91)
        self.assertEqual(Outbox(install.store, install.engine.notifier, lambda: install.now).flush(), 1)
        envelope, = install.envelopes()
        self.assertNotIn('applicability', envelope['body'])
        for count in (1, 2):
            body = dict(items=envelope['body']['items'][:count])
            plain = Notification(**dict(envelope, body=body))
            enriched = replace(plain, body=dict(body, applicability={'unavailable': True}))
            self.assertEqual(render(plain), render(enriched))

    def test_T9_synology_inventory_reaches_unrelated_digest(self):
        install = Install(self, (MEDIA, NAS))
        opener = install.ntfy(self)
        feed = ROOT / 'tests/fixtures/synology/feed_sample.xml'
        items, _ = synology.parse_feed(feed.read_bytes())
        members = [synology.normalise(item) for item in items]
        adapter = AdapterStore(install.store, install.directory, on_record=install.engine.commit_advisory)
        result = adapter.process(source=adapters.REGISTRY['synology'].name, resources=[
            dict(path='feed', status=200, body=json.dumps({'advisories': members}))
        ], tick='2026-10-30T01:00:00Z')
        self.assertEqual(result, 'COMPLETE')
        pairs = list(install.db.execute('SELECT record_id, state, exploited FROM pairs WHERE watch_id=?', (NAS.id,)))
        self.assertEqual(len(pairs), 10)
        self.assertEqual({(row['state'], row['exploited']) for row in pairs}, {('unknown', 0)})
        self.assertIn('advisory:synology:Synology_SA_99_03:main', [row['record_id'] for row in pairs])
        install.engine._flush()
        baseline, = opener.texts
        self.assertIn('baseline', baseline)
        self.assertNotIn('Unknown applicability', baseline)

        install.due(90)
        install.engine._flush()
        lines = install.section_text(opener).splitlines()
        self.assertEqual(lines[1], 'Why: 10 vendor advisory')
        self.assertIn('Example NAS (diskstation manager (dsm) 7.9.0-99999): 10 — 10 vendor advisory', lines)

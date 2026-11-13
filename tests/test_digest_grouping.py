# script-purpose: Verify digest grouping and unchanged delivery using invented inventory.
# script-class: harness
# script-trigger: unittest discovery or python3 -m unittest tests.test_digest_grouping
# script-tests: tests/test_digest_grouping.py
"""Read in-memory fixtures and source; write no files; unittest exits 0 on pass, 1 on failure."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from itertools import permutations
from types import SimpleNamespace
import unittest

from cornicen.model import Notification
from cornicen.outbox import Outbox
from cornicen.render import render
from cornicen.store import Store


def item(number, watch='a', score=.01, reasons=('new match',), **extra):
    body = dict(watch_id=watch, record_id=f'CVE-2099-{number:04d}',
                name=f'Zyphora {watch}', product='zyphora-relay', version='73.8.91',
                severity=4, state='affected', evidence='invented bounded range',
                cve_title='Invented relay issue', cna_cvss_score=4,
                epss=None if score is None else dict(score=score, pct=.5, date='2099-01-01'))
    body.update(extra)
    return asdict(Notification(str(number), watch, body['record_id'], reasons, 'normal', body))


def digest(items):
    return Notification('fixture-digest', '', 'digest', ('digest',), 'normal', {'items': items})


def full(value):
    title, text, _, _ = render(Notification(**value))
    return title + '\n' + text


def size_fixture():
    return [item(number, score=number / 1000) for number in range(1, 51)]


class DigestGroupingTests(unittest.TestCase):
    def test_digest_grouping_header_uses_first_ordinary_in_block_order(self):
        values = [item(i, score=(9-i)/100) for i in range(1, 7)]
        values[0] = item(1, score=.08, reasons=('new match', 'correction'),
                         name='Velqora previous', product='velqora-node', version='97.31.41')
        values[1]['body']['name'] = 'Zyphora current'
        text = render(digest(list(reversed(values))))[1]
        self.assertEqual(text.split('\n\n')[1].splitlines()[0],
                         'Zyphora current (zyphora-relay 73.8.91): 6 items')
        for value in values:
            self.assertIn(full(value), text)
        # With only corrections the first ranked member supplies the header.
        for value in values:
            value['reasons'] = ('correction',)
        text = render(digest(list(reversed(values))))[1]
        self.assertEqual(text.split('\n\n')[1].splitlines()[0],
                         'Velqora previous (velqora-node 97.31.41): 6 items')

    def test_digest_grouping_each_inventory_difference_forces_full(self):
        for field, changed in [('name', 'Velqora appliance'),
                               ('product', 'velqora-node'), ('version', '97.31.41')]:
            with self.subTest(field=field):
                values = [item(i, score=(8-i)/100) for i in range(1, 7)]
                values[4]['body'][field] = changed
                before = deepcopy(values)
                text = render(digest(values))[1]
                self.assertIn(full(values[4]), text)
                self.assertNotIn(values[4]['record_id'] + ' — EPSS', text)
                self.assertIn(values[3]['record_id'] + ' — EPSS', text)
                self.assertIn(values[5]['record_id'] + ' — EPSS', text)
                self.assertEqual(values, before)

    def test_digest_grouping_notification_key_breaks_duplicate_record_ties(self):
        values = [item(7, reasons=('new match',)), item(7, reasons=('correction',)),
                  item(8), item(9), item(10)]
        values[0]['key'], values[1]['key'] = 'row-a', 'row-b'
        expected = render(digest(values))
        for order in permutations(values):
            self.assertEqual(render(digest(order)), expected)
        self.assertLess(expected[1].index('Why: new match'), expected[1].index('Why: correction'))

    def test_digest_grouping_missing_and_null_watch_ids_render_stably(self):
        values = [item(1, None), item(2, ''), item(3, 'a')]
        values[1].pop('watch_id')
        values[1]['body'].pop('watch_id')
        expected = render(digest(values))
        for order in permutations(values):
            self.assertEqual(render(digest(order)), expected)
        for value in values:
            self.assertIn('Cornicen: ' + value['record_id'], expected[1])
        # Also exercise member ranking within a null-watch block below cutoff.
        nulls = [item(i, None) for i in range(4, 9)]
        text = render(digest(nulls + values))[1]
        for value in nulls:
            self.assertIn('Cornicen: ' + value['record_id'], text)

    def _assert_lapse_guard_with_stale_header(self, **fields):
        values = [item(i, score=(9-i)/100) for i in range(1, 6)]
        values[0] = item(1, score=.08, reasons=('correction',),
                         name='Velqora previous', product='velqora-node', version='97.31.41')
        values[-1] = item(5, score=.01, **fields)
        text = render(digest(values))[1]
        # The lapse row matches the chosen ordinary inventory, so the inventory
        # guard cannot mask either independent lapse guard in mutation testing.
        self.assertIn(full(values[-1]), text)
        self.assertNotIn(values[-1]['record_id'] + ' — EPSS', text)
        self.assertEqual(text.split('\n\n')[1].splitlines()[0],
                         'Zyphora a (zyphora-relay 73.8.91): 5 items')

    def test_digest_grouping_lapsed_reason_only_below_cutoff(self):
        self._assert_lapse_guard_with_stale_header(reasons=('acceptance lapsed',))

    def test_digest_grouping_lapsed_metadata_only_below_cutoff(self):
        self._assert_lapse_guard_with_stale_header(
            acceptance_lapsed=dict(why='version', reason='invented review'))

    def test_digest_grouping_single_item_legacy_bytes(self):
        value = item(1)
        expected = ('Cornicen digest: 1 items', full(value), 3, ['information_source'])
        self.assertEqual(render(digest([value])), expected)
        self.assertEqual(render(digest([value]))[1].encode(), expected[1].encode())
        self.assertTrue(render(digest([value, item(2)]))[1].startswith('2 items on 1 watches:'))

    def test_digest_grouping_summary_reason_counts(self):
        values = [item(1, reasons=('new match', 'KEV added', 'KEV added')),
                  item(2, reasons=('correction',), state='not_affected'),
                  item(3, 'b', reasons=('acceptance lapsed',)), item(4, 'b')]
        self.assertEqual(render(digest(values))[1].splitlines()[0],
                         '4 items on 2 watches: 2 new matches, 1 KEV added, 1 correction, 1 acceptance lapsed')
        self.assertEqual(render(digest([item(1), item(2)]))[1].splitlines()[0],
                         '2 items on 1 watches: 2 new matches')

    def test_digest_grouping_two_watches_top_three_and_unscored(self):
        values = [item(i + offset, watch, score) for watch, offset in [('a', 0), ('b', 10)]
                  for i, score in [(1, None), (2, .02), (3, .03), (4, .04), (5, .05)]]
        text = render(digest(values))[1]
        for watch, offset in [('a', 0), ('b', 10)]:
            self.assertIn(f'Zyphora {watch} (zyphora-relay 73.8.91): 5 items', text)
            for i in [5, 4, 3]:
                self.assertIn(full(values[(0 if watch == 'a' else 5) + i - 1]), text)
            scored = f'CVE-2099-{offset + 2:04d} — EPSS 2.0% · affected · KEV not listed'
            unscored = f'CVE-2099-{offset + 1:04d} — EPSS: not yet scored · affected · KEV not listed'
            self.assertIn(scored, text)
            self.assertIn(unscored, text)
            self.assertLess(text.index(scored), text.index(unscored))
        self.assertEqual(text.count('Cornicen: CVE-2099-'), 6)
        self.assertEqual(sum(' — EPSS' in line for line in text.splitlines()), 4)
        small = values[2:5]
        self.assertEqual(render(digest(small))[1].count('Cornicen: CVE-2099-'), 3)

    def test_digest_grouping_fifth_correction_stays_full(self):
        values = [item(i, score=(6-i)/100) for i in range(1, 6)]
        values[-1] = item(5, score=.01, reasons=('correction',), state='not_affected')
        text = render(digest(values))[1]
        self.assertIn('Zyphora a (zyphora-relay 73.8.91): 5 items', text)
        self.assertIn(full(values[-1]), text)
        self.assertIn('Why: correction', text)
        self.assertIn('— not affected', text)
        self.assertNotIn('CVE-2099-0005 — EPSS', text)

    def test_digest_grouping_eol_and_acceptance_lapsed_stay_full(self):
        values = [item(i, score=(7-i)/100) for i in range(1, 7)]
        values[4] = item(5, score=.02, eol=True)
        values[5] = item(6, score=.01, reasons=('acceptance lapsed',),
                         acceptance_lapsed=dict(why='date', reason='invented review'))
        text = render(digest(values))[1]
        self.assertIn('Zyphora a (zyphora-relay 73.8.91): 6 items', text)
        for value in values[4:]:
            self.assertIn(full(value), text)
        self.assertIn('EOL: unsupported by the vendor', text)
        self.assertIn('Acceptance lapsed (date): invented review', text)

    def test_digest_grouping_deterministic_severity_epss_watch_and_record_order(self):
        values = [item(5, 'b', .02), item(4, 'a', .02), item(3, 'a', .02),
                  item(2, 'c', .01, severity=9), item(1, 'd', .03)]
        text = render(digest(values))[1]
        self.assertEqual(text, render(digest(list(reversed(values))))[1])
        headers = [f'Zyphora {watch} (zyphora-relay 73.8.91):' for watch in 'cdab']
        self.assertEqual(sorted(headers, key=text.index), headers)
        self.assertLess(text.index('Cornicen: CVE-2099-0003'), text.index('Cornicen: CVE-2099-0004'))

    def test_digest_grouping_delivery_key_rows_and_notified_unchanged(self):
        store = Store(':memory:')
        store.migrate()
        self.addCleanup(store.connection.close)
        now = datetime(2099, 1, 1, tzinfo=timezone.utc)
        values = [item(i, score=i/100) for i in range(1, 6)]
        for value in values:
            store.connection.execute('INSERT INTO pairs(watch_id,record_id,state,episode,baseline,exploited,alias_map_version) VALUES (?,?,?,?,?,?,?)',
                                     ('a', value['record_id'], 'affected', 1, 0, 0, 'fixture'))
            store.queue('a|' + value['record_id'], 'normal', value['reasons'], value['body'], now.isoformat())
        rows = store.connection.execute('SELECT * FROM outbox ORDER BY id').fetchall()
        captured = []
        def send(notification):
            captured.append((deepcopy(notification), render(notification)))
            return True
        outbox = Outbox(store, SimpleNamespace(send=send), lambda: now)
        self.assertEqual(outbox.flush(), 1)
        notification, rendered = captured[0]
        ids = [row['id'] for row in rows]
        self.assertEqual(notification.key, 'digest-' + sha256(','.join(map(str, ids)).encode()).hexdigest()[:24])
        self.assertEqual([value['record_id'] for value in notification.body['items']],
                         [value['record_id'] for value in reversed(values)])
        self.assertEqual([row[0] for row in store.connection.execute('SELECT id FROM outbox WHERE sent_at=? ORDER BY id', (now.isoformat(),))], ids)
        self.assertEqual([row[0] for row in store.connection.execute('SELECT notified FROM pairs')], [1]*5)
        self.assertEqual(outbox.flush(), 0)
        self.assertTrue(rendered[1].startswith('5 items on 1 watches: 5 new matches'))

"""Exact regression checks for the Synology Build A controller rulings."""

from contextlib import redirect_stdout
from importlib import reload
from io import StringIO
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from cornicen import cli, feedvalidate, public_text, synology
from cornicen.adapterstore import AdapterStore, date_fields
from cornicen.identity import AliasMap
from cornicen.store import Store
from cornicen.watchlist import load_watchlist_text
from tests import test_task6_a as fixture


DSM = 'DiskStation Manager (DSM)'
SRM = 'Synology Router Manager (SRM)'
ONE = 'A vulnerability allows a local user to gain privileges via a susceptible version of '
UPDATE = 'Synology has released a security update for '
NONE = "None of Synology's products are affected by"
PACKAGE = ('A vulnerability allows a local user to gain privileges via susceptible versions '
           'of the following packages in DSM:\nHyper Backup\n')
UNMATCHED = ([], None, {'unrecognised template': 1})
FIRST_CVE = 'CVE-2099-81001'
STATEMENT_CVE = 'CVE-2099-81019'
SECOND_STATEMENT_CVE = 'CVE-2099-81018'


def item(index=0, **changes):
    return synology.parse_feed(fixture.FEED)[0][index] | changes


def products(description):
    return synology.products('Fixture title', description)


def validated(member, source='synology'):
    return feedvalidate.validate_advisory(
        member, source=source, observed_at=fixture.TICK, date_fields=date_fields(source)).data


class TemplateReviewTests(unittest.TestCase):
    def test_case_insensitive_lookup(self):
        self.assertEqual(products(ONE + 'Synology Diskstation Manager (DSM).'), ([DSM], 'S-ONE', {}))
        self.assertEqual(synology._captures('S-ONE', ['  synology diskstation manager (dsm)  ']),
                         ([DSM], 'S-ONE', {}))

    def test_multiple_names(self):
        for prefix, suffix, template in ((ONE, '.', 'S-ONE'), (UPDATE, ' to address a flaw.', 'S-UPD')):
            for separator in (', and ', ', ', ' and ', ' or '):
                with self.subTest(template=template, separator=separator):
                    self.assertEqual(products(prefix + DSM + separator + SRM + suffix),
                                     ([DSM, SRM], template, {}))
            self.assertEqual(products(prefix + DSM + ', ' + SRM + ' and Example Box' + suffix),
                             ([DSM, SRM], template, {'unrecognised subject': 1}))

    def test_vpn_alias(self):
        self.assertEqual(products(ONE + 'Synology VPN Plus Server.'),
                         (['VPN Plus Server'], 'S-ONE', {}))

    def test_update_precedes_packages(self):
        desc = UPDATE + 'Synology Assistant to address a flaw.\n' + PACKAGE
        self.assertEqual(products(desc), (['Synology Assistant'], 'S-UPD', {}))
        self.assertEqual(products(PACKAGE), (['Hyper Backup'], 'S-PKG', {}))

    def test_none_requires_sentence_start(self):
        desc = 'The publisher says ' + NONE + f' {STATEMENT_CVE}.'
        self.assertEqual(synology.analyse_description(desc), (*UNMATCHED, None))

    def test_update_requires_sentence_start(self):
        self.assertEqual(products('The publisher says ' + UPDATE + 'DSM to address a flaw.'), UNMATCHED)

    def test_one_requires_sentence_start(self):
        self.assertEqual(products('The publisher says ' + ONE + 'DSM.'), UNMATCHED)

    def test_lowercase_after_dot_is_not_a_boundary(self):
        desc = ONE.replace('privileges', 'privileges as described etc.') + 'DSM.'
        self.assertEqual(products(desc), ([DSM], 'S-ONE', {}))

    def test_decimal_dot_is_not_a_boundary(self):
        desc = ONE.replace('privileges', 'privileges on PHP 8.2') + 'DSM.'
        self.assertEqual(products(desc), ([DSM], 'S-ONE', {}))

    def test_lowercase_ambiguous_name(self):
        self.assertEqual(products(ONE + 'e.g. dsm.'), UNMATCHED)

    def test_none_requires_remainder(self):
        self.assertEqual(synology.analyse_description(NONE + '.'), (*UNMATCHED, None))

    def test_update_requires_remainder(self):
        self.assertEqual(products(UPDATE + 'DSM to address.'), UNMATCHED)

    def test_package_requires_actor_and_effect(self):
        self.assertEqual(products(PACKAGE.replace('a local user to gain privileges', '')), UNMATCHED)
        self.assertEqual(products(PACKAGE.replace('a local user', ' ')), UNMATCHED)
        self.assertEqual(products(PACKAGE.replace('gain privileges', ' ')), UNMATCHED)

    def test_all_table_names_and_cna_strings_resolve(self):
        for alias, (_, cna_product) in synology.SYNOLOGY_PRODUCTS.items():
            for name in (alias, cna_product):
                with self.subTest(name=name, expected=cna_product):
                    self.assertEqual(products(ONE + name + '.'), ([cna_product], 'S-ONE', {}))

    def test_bare_drive_is_not_a_product(self):
        self.assertEqual(products(ONE + 'Drive.'), ([], 'S-ONE', {'unrecognised subject': 1}))

    def test_capture_diagnostic_carries_only_a_count(self):
        # Unwatched diagnostic words and numbers can pass the public-text filter.
        capture = 'GET 2099'
        self.assertEqual(public_text.public_text(capture), capture)
        names, template, counts = products(ONE + DSM + ' and ' + capture + '.')
        self.assertEqual((names, template), ([DSM], 'S-ONE'))
        self.assertEqual([(public_text.public_text(key), count) for key, count in counts.items()],
                         [('unrecognised subject', 1)])
        self.assertEqual(counts, {'unrecognised subject': 1})


class MappingReviewTests(unittest.TestCase):
    def test_title_300_characters_accepted(self):
        title = 'é' * 300
        self.assertEqual(synology.normalise(item(title=title))['title'], title)

    def test_title_301_characters_rejected(self):
        self.assertEqual(synology.normalise(item(title='a' * 301)),
                         {'id': 'Synology_SA_99_01', 'mapping_error': 'invalid Synology title'})

    def test_title_control_character_rejected(self):
        self.assertEqual(synology.normalise(item(title='Bad\nTitle')),
                         {'id': 'Synology_SA_99_01', 'mapping_error': 'invalid Synology title'})

    def test_guid_with_and_without_support(self):
        for guid in (fixture.PHOTO, fixture.PHOTO.replace('/support', '')):
            with self.subTest(guid=guid):
                member = synology.normalise(item(guid=guid))
                self.assertEqual((member['id'], member['guid']), ('Synology_SA_99_01', guid))

    def test_guid_id_120_characters_accepted(self):
        identity = 'A._-' * 30
        guid = f'https://www.synology.com/en-us/support/security/{identity}'
        member = synology.normalise(item(guid=guid))
        self.assertEqual((member['id'], member['guid']), (identity, guid))
        self.assertEqual(validated(member)['source_id'], identity)

    def test_guid_id_121_characters_rejected(self):
        guid = f'https://www.synology.com/en-us/support/security/{"A" * 121}'
        self.assertEqual(synology.normalise(item(guid=guid)),
                         {'id': None, 'guid': guid, 'mapping_error': 'invalid Synology guid'})

    def test_display_url_comes_from_link(self):
        link = 'https://www.synology.com/en-us/security/DisplayPage'
        member = synology.normalise(item(link=link))
        self.assertEqual((member['id'], member['guid'], member['url']),
                         ('Synology_SA_99_01', fixture.PHOTO, link))
        self.assertEqual(validated(member)['url'], link)

    def test_cve_with_three_digit_suffix_not_extracted(self):
        self.assertEqual(synology.normalise(item(description='CVE-2099-123 and CVE-2099-1234.'))['cves'],
                         ['CVE-2099-1234'])

    def test_prefixed_cve_not_extracted(self):
        self.assertEqual(synology.normalise(item(description='XCVE-2099-81001 and CVE-2099-81002.'))['cves'],
                         ['CVE-2099-81002'])

    def test_scoped_statement_keeps_affirmative_product(self):
        desc = ONE + DSM + f'. {NONE} {STATEMENT_CVE}.'
        member = synology.normalise(item(title=FIRST_CVE, description=desc))
        key = 'synology:diskstation manager (dsm)'
        self.assertEqual(member['products'], [{'id': key, 'name': key}])
        self.assertEqual(member['evidence'],
                         [{'product_id': key, 'scheme': 'opaque', 'status': 'under_investigation'}])
        self.assertEqual(member['cves'], [FIRST_CVE, STATEMENT_CVE])
        self.assertEqual(member['vendor_statement'], 'none_affected')
        self.assertEqual(member['statement_cves'], [STATEMENT_CVE])

    def test_statement_scope_order_deduplication_and_isolation(self):
        desc = (f'{NONE} {STATEMENT_CVE}, {SECOND_STATEMENT_CVE} and {STATEMENT_CVE}. '
                f'This advisory also mentions {FIRST_CVE}. {NONE} CVE-2099-81020.')
        member = synology.normalise(item(title=FIRST_CVE, description=desc))
        self.assertEqual(member['statement_cves'], [STATEMENT_CVE, SECOND_STATEMENT_CVE, 'CVE-2099-81020'])

    def test_fixture_statement_only_has_no_products(self):
        member = synology.normalise(item(1))
        self.assertEqual((member['products'], member['evidence'], member['vendor_statement'],
                          member['statement_cves']), ([], [], 'none_affected', ['CVE-2099-81007']))

    def test_statement_scope_kept_only_with_synology_statement(self):
        member = synology.normalise(item(1))
        self.assertEqual(validated(member)['statement_cves'], ['CVE-2099-81007'])
        self.assertFalse('statement_cves' in validated(member | {'updated': fixture.TICK}, 'debian'))
        member.pop('vendor_statement')
        self.assertFalse('statement_cves' in validated(member))

    def test_statement_scope_validates_cve_id_list(self):
        member = synology.normalise(item(1))
        for invalid in ('CVE-2099-81007', [7], ['CVE-2099-123'], ['XCVE-2099-81007']):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, '^advisory mapping failed$'):
                validated(member | {'statement_cves': invalid})


class ExplainReviewTests(unittest.TestCase):
    def setUp(self):
        self.watches = load_watchlist_text(fixture.WATCHES)
        self.aliases = AliasMap.load(False)
        self.cna_cve = 'CVE-2099-81007'
        self.record = {
            'cveMetadata': {'cveId': self.cna_cve, 'state': 'PUBLISHED'},
            'containers': {'cna': {'affected': [{
                'vendor': 'Microsoft', 'product': 'Windows', 'defaultStatus': 'affected', 'versions': [],
            }]}},
        }
        self.cna_output = (
            f'Current-file evaluation: other {self.cna_cve}; version=7.9.0-99999; '
            f'scheme=opaque; alias_map_version={self.aliases.version}\n'
            'Stored pair state: none\n'
            'Current decision: applicability=affected; exploited=false; confidence=high\n'
            'Evidence: CNA affected windows: defaultStatus affected\n'
        )

    def explain(self, store, cve, watch='other'):
        output = StringIO()
        with redirect_stdout(output):
            code = cli.explain(store, self.watches, self.aliases, cve, watch)
        return code, output.getvalue()

    def test_cna_output_plus_synology_section(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir='.')))
        store = Store(directory / 'db')
        self.addCleanup(store.connection.close)
        store.migrate()
        store.put_record(self.cna_cve, self.record, fixture.TICK)
        self.assertEqual(self.explain(store, self.cna_cve), (0, self.cna_output))
        self.assertEqual(AdapterStore(store, directory).process(
            source='synology', resources=[fixture.resource(synology.normalise(item(1)))],
            tick=fixture.TICK), 'COMPLETE')
        self.assertEqual(self.explain(store, self.cna_cve), (0, self.cna_output +
            'Synology advisory (no version data)\n'
            '  ID: Synology_SA_99_02\n'
            '  Title: Synology-SA-99:02 Example Library\n'
            '  URL: https://www.synology.com/en-us/support/security/Synology_SA_99_02\n'
            '  Published: 2026-10-27T02:00:00Z\n'
            '  Products: none recognised\n'
            '  none affected (vendor statement)\n'))

    def test_legacy_db_without_adapter_schema(self):
        store = Store(':memory:')
        self.addCleanup(store.connection.close)
        db = store.connection
        db.executescript("""
            CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE records (id TEXT PRIMARY KEY, json TEXT);
            CREATE TABLE pairs (watch_id TEXT, record_id TEXT, state TEXT);
            CREATE TABLE kev (cve TEXT PRIMARY KEY, json TEXT);
        """)
        db.execute('INSERT INTO records VALUES (?, ?)', (self.cna_cve, json.dumps(self.record)))
        self.assertEqual(self.explain(store, self.cna_cve), (0, self.cna_output))

    def test_statement_line_only_for_scoped_cve(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir='.')))
        store = Store(directory / 'db')
        self.addCleanup(store.connection.close)
        store.migrate()
        desc = ONE + DSM + f'. {NONE} {STATEMENT_CVE}.'
        member = synology.normalise(item(title=FIRST_CVE, description=desc))
        self.assertEqual(AdapterStore(store, directory).process(
            source='synology', resources=[fixture.resource(member)], tick=fixture.TICK), 'COMPLETE')
        section = (
            'Synology advisory (no version data)\n'
            '  ID: Synology_SA_99_01\n'
            '  Title: CVE-2099-81001\n'
            '  URL: https://www.synology.com/en-us/support/security/Synology_SA_99_01\n'
            '  Published: 2026-10-29T13:12:54Z\n'
            '  Products: diskstation manager (dsm)\n'
        )
        self.assertEqual(self.explain(store, FIRST_CVE), (0, section))
        self.assertEqual(self.explain(store, STATEMENT_CVE), (0, section + '  none affected (vendor statement)\n'))


class ProductPrivacyTests(unittest.TestCase):
    def test_common_joining_words_stay_public(self):
        for word in ('for', 'and', 'of', 'the'):
            with self.subTest(word=word):
                self.assertNotIn(word, public_text._NON_DIAGNOSTIC_WORDS)
                self.assertEqual(public_text.public_text(word), word)
        self.assertEqual(public_text.public_text('Surveillance'), '[redacted]')

    def test_words_public_before_the_adapter_stay_public(self):
        # Review r2 item 3: these were in the vocabulary before task 6; redacting them
        # would hide the source name and ordinary diagnostics.
        for word in ('active', 'backup', 'container', 'download', 'file', 'synology'):
            with self.subTest(word=word):
                self.assertEqual(public_text.public_text(word), word)
        self.assertEqual(public_text.public_text('download failed: file not found'),
                         'download failed: file not found')

    def test_product_only_words_are_not_common(self):
        for word in ('business', 'surveillance', 'station', 'diskstation', 'router'):
            with self.subTest(word=word):
                self.assertNotIn(word, public_text._COMMON_WORDS)
                self.assertIn(word, public_text._NON_DIAGNOSTIC_WORDS)

    def test_srm_and_container_manager_aliases_resolve(self):
        self.assertEqual(synology.products('SRM', 'A vulnerability allows remote attackers to read files via a susceptible version of SRM.')[0],
                         ['Synology Router Manager (SRM)'])
        self.assertEqual(synology.products('X', 'A vulnerability allows remote attackers to read files via a susceptible version of Container Manager.')[0],
                         ['Synology Docker'])

    def test_every_product_word_is_denied(self):
        for name, (_, cna) in synology.SYNOLOGY_PRODUCTS.items():
            for word in re.findall(r'[A-Za-z0-9]+', name + ' ' + cna):
                if word.lower() in public_text._COMMON_WORDS:
                    continue
                with self.subTest(word=word):
                    self.assertIn(word.lower(), public_text._NON_DIAGNOSTIC_WORDS)
                    self.assertEqual(public_text.public_text(word), '[redacted]')

    def test_new_product_words_are_automatically_denied(self):
        words = ('security', 'update', 'exact', 'status')
        for word in words:
            self.assertEqual(public_text.public_text(word), word)
        try:
            with patch.dict(synology.SYNOLOGY_PRODUCTS, {'Security Update': ('Synology', 'Exact Status')}):
                reload(public_text)
                for word in words:
                    self.assertIn(word, public_text._NON_DIAGNOSTIC_WORDS)
                    self.assertEqual(public_text.public_text(word), '[redacted]')
        finally:
            reload(public_text)

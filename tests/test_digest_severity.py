"""Digest ranking uses CNA severity before exploit probability."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest
from tests import test_engine as helpers


class DigestSeverityTests(unittest.TestCase):
    setUp = helpers.EngineTests.setUp
    start = helpers.EngineTests.start
    ingest = helpers.EngineTests.ingest

    def test_higher_cvss_precedes_higher_epss(self):
        self.start()
        high, low = deepcopy(self.record), deepcopy(self.record)
        for record, cve, severity in ((high, 'CVE-2026-1001', 9.8),
                                       (low, 'CVE-2026-1002', 2.1)):
            record['cveMetadata']['cveId'] = cve
            record['containers']['cna']['metrics'] = [{'cvssV3_1': {'baseScore': severity}}]
        captured = []
        self.engine.notifier = SimpleNamespace(send=lambda n: captured.append(n) or True)
        scores = replace(self.baseline[2], cursor='scores', content_time=self.clock(),
                         epss={'CVE-2026-1001': (.01, .1), 'CVE-2026-1002': (.09, .9)},
                         epss_date=self.clock().date())
        self.engine.run_cycle([self.ingest([low, high]), scores])
        self.assertEqual(captured, [])
        self.clock.now = self.clock.now.replace(hour=8, minute=0)
        self.engine.run_cycle([])
        self.assertEqual(len(captured), 1)
        items = captured[0].body['items']
        self.assertEqual([item['record_id'] for item in items],
                         ['CVE-2026-1001', 'CVE-2026-1002'])
        self.assertEqual([item['body']['severity'] for item in items], [9.8, 2.1])
        self.assertEqual([item['body']['epss']['score'] for item in items], [.01, .09])

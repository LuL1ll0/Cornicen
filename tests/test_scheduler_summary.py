"""Operator log values must reflect ingestion and persisted health."""
from dataclasses import replace
import json
import unittest
from cornicen.model import FetchStatus
from tests import test_scheduler as helpers


class SchedulerSummaryTests(unittest.TestCase):
    setUp = helpers.SchedulerTests.setUp

    def test_summary_values_reflect_failed_source_and_completed_work(self):
        cve = self.sources['cvelist'].poll.return_value[0]
        self.sources['cvelist'].poll.return_value = [replace(cve, records=({
            'cveMetadata': {'cveId': 'CVE-2026-1000', 'state': 'PUBLISHED'},
            'containers': {'cna': {'affected': []}}},))]
        epss = self.sources['epss'].poll.return_value[0]
        self.sources['epss'].poll.return_value = [replace(epss,
            status=FetchStatus.FAILED, cursor=None, content_time=None, errors=('bad CSV',))]
        self.scheduler.tick()
        summary = json.loads(self.lines[0])
        self.assertEqual(summary['sources'], {'cvelist': 'healthy', 'kev': 'healthy',
                                            'epss': 'unhealthy', 'watchlist': 'healthy'})
        self.assertEqual(summary['ingested'], {'cvelist': 1, 'kev': 0, 'epss': 0})
        self.assertEqual(summary['events'], 1)
        self.assertEqual(summary['sent'], 1)
        self.assertEqual(summary['pending'], 0)

"""Check RSS replay isolation and process-loss handling against adjacent fixtures.

Read offline JSONL inputs, write temporary replay stores, and exit 0/1 via unittest.
"""

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from tests.replay_v11 import harness as h


class RssHarnessTests(unittest.TestCase):
    def test_synology_host_is_scoped_to_synology_scenarios(self):
        # No RSS action or Synology watch to fail before the host check.
        row = dict(t='2099-01-01T00:00:00Z', watchlist=h.WATCHLIST)
        url = 'https://www.synology.com/en-us/support/security/Synology_SA_99_01'
        timeline = [row, dict(t=row['t'], seed={'display_url': url}), dict(t=row['t'], cycle=True)]
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            path = Path(tmp)
            data = ''.join(json.dumps(row) + '\n' for row in [{'#': 'Spec §8 host scope.'}, *timeline])
            for name in ('synology_host', 'synthetic_rss'):
                (path / f'{name}.input.jsonl').write_text(data)
            with patch.object(h, 'SCENARIOS', path):
                self.assertEqual(h.load_timeline('synology_host'), timeline)
                with self.assertRaisesRegex(ValueError, 'non-invented host: www.synology.com'):
                    h.load_timeline('synthetic_rss')

    def test_synology_actions_and_state_keys_are_scoped(self):
        tick = '2099-01-01T00:00:00Z'
        watch = dict(t=tick, watchlist=h.WATCHLIST)
        poll = dict(t=tick, cycle=True)
        for action in (dict(rss={'broken': 'html'}), dict(command=['adapter', 'rebaseline', 'synology'])):
            timeline = [watch, dict(t=tick, **action), poll]
            h.validate_timeline(timeline, synology=True)
            with self.assertRaises(ValueError):
                h.validate_timeline(timeline)
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            path = Path(tmp)
            # A legacy-named scenario cannot consume a Synology retention summary.
            rows = [{'#': 'Spec §8 state scope.'}, dict(t=tick, lifted_by='F4', state={'retention_summary': {}})]
            data = ''.join(json.dumps(row) + '\n' for row in rows)
            for name in ('synology_scope', 'synthetic_rss'):
                (path / f'{name}.expected.jsonl').write_text(data)
            with patch.object(h, 'SCENARIOS', path):
                self.assertEqual(h.load_expected('synology_scope', [watch, poll]), rows[1:])
                with self.assertRaisesRegex(ValueError, 'invalid state'):
                    h.load_expected('synthetic_rss', [watch, poll])

    def test_synology_watch_identity_and_version_are_scoped(self):
        for text in ('{"match": ["synology:diskstation manager (dsm)"]}', '{"version": "7.9.0-99999"}'):
            rows = [json.loads(text)]
            h.validate_identities(rows, synology=True)
            with self.assertRaises(ValueError):
                h.validate_identities(rows)

    def test_durable_stage_survives_process_loss(self):
        name = 'synology_t1t2'
        points = h.run_crash_scenario(name).points
        index = next(i for i, point in enumerate(points)
                     if point.startswith('synology_stage_members:') and point.endswith(':after'))
        result = h.run_crash_scenario(name, index)
        self.assertTrue(result.crashed)
        self.assertEqual(result.survived_stages, 1)


if __name__ == '__main__':
    unittest.main()

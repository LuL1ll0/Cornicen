import json
from pathlib import Path
import unittest

from tests.replay.harness import load_expected, load_timeline, run_scenario


class ReplayTests(unittest.TestCase):
    def test_range_changes_exclusion(self):
        self.assertEqual(run_scenario("range_changes_exclusion"), load_expected("range_changes_exclusion"))

    def test_less_than_or_equal_endpoint(self):
        self.assertEqual(run_scenario("less_than_or_equal_endpoint"), load_expected("less_than_or_equal_endpoint"))

    def test_default_status_affected(self):
        self.assertEqual(run_scenario("default_status_affected"), load_expected("default_status_affected"))

    def test_cna_not_affected_beats_kev(self):
        self.assertEqual(run_scenario("cna_not_affected_beats_kev"), load_expected("cna_not_affected_beats_kev"))

    def test_same_cycle_coalesce(self):
        self.assertEqual(run_scenario("same_cycle_coalesce"), load_expected("same_cycle_coalesce"))

    def test_revised_after_baseline(self):
        self.assertEqual(run_scenario("revised_after_baseline"), load_expected("revised_after_baseline"))

    def test_rejected_after_notify(self):
        self.assertEqual(run_scenario("rejected_after_notify"), load_expected("rejected_after_notify"))

    def test_episode_rearm(self):
        self.assertEqual(run_scenario("episode_rearm"), load_expected("episode_rearm"))

    def test_rename_watch_silent(self):
        self.assertEqual(run_scenario("rename_watch_silent"), load_expected("rename_watch_silent"))

    def test_version_change_into_range(self):
        self.assertEqual(run_scenario("version_change_into_range"), load_expected("version_change_into_range"))

    def test_epss_promotion(self):
        self.assertEqual(run_scenario("epss_promotion"), load_expected("epss_promotion"))

    def test_quiet_thirty_days(self):
        self.assertEqual(run_scenario("quiet_thirty_days"), load_expected("quiet_thirty_days"))

    def test_kev_empty_200_unhealthy(self):
        self.assertEqual(run_scenario("kev_empty_200_unhealthy"), load_expected("kev_empty_200_unhealthy"))

    def test_epss_row_collapse_unhealthy(self):
        self.assertEqual(run_scenario("epss_row_collapse_unhealthy"), load_expected("epss_row_collapse_unhealthy"))

    def test_delta_errors_partial(self):
        self.assertEqual(run_scenario("delta_errors_partial"), load_expected("delta_errors_partial"))

    def test_baseline_summary(self):
        self.assertEqual(run_scenario("baseline_summary"), load_expected("baseline_summary"))

    def test_replay_twice_idempotent(self):
        for path in sorted((Path(__file__).parent / 'replay').glob('*.input.jsonl')):
            name = path.name.removesuffix('.input.jsonl')
            with self.subTest(scenario=name):
                self.assertEqual(run_scenario(name, twice=True), load_expected(name))

    def test_downtime_catch_up(self):
        self.assertEqual(run_scenario("downtime_catch_up"), load_expected("downtime_catch_up"))

    def test_kev_only_unknown_exploited(self):
        self.assertEqual(run_scenario("kev_only_unknown_exploited"), load_expected("kev_only_unknown_exploited"))

    def test_kev_merges_into_queued(self):
        self.assertEqual(run_scenario("kev_merges_into_queued"), load_expected("kev_merges_into_queued"))

    def test_unsent_unknown_reactivation(self):
        self.assertEqual(run_scenario("unsent_unknown_reactivation"), load_expected("unsent_unknown_reactivation"))

    def test_correction_separate_from_activation(self):
        self.assertEqual(run_scenario("correction_separate_from_activation"), load_expected("correction_separate_from_activation"))

    def test_reconcile_snapshot_is_new(self):
        self.assertEqual(run_scenario("reconcile_snapshot_is_new"), load_expected("reconcile_snapshot_is_new"))

    def test_never_sent_episode_has_no_correction(self):
        self.assertEqual(run_scenario("never_sent_episode_has_no_correction"), load_expected("never_sent_episode_has_no_correction"))

    def test_health_stale_does_not_recover(self):
        self.assertEqual(run_scenario("health_stale_does_not_recover"), load_expected("health_stale_does_not_recover"))

    def test_health_transitions_survive_outage(self):
        self.assertEqual(run_scenario("health_transitions_survive_outage"), load_expected("health_transitions_survive_outage"))

    def test_watch_removed_readded(self):
        self.assertEqual(run_scenario("watch_removed_readded"), load_expected("watch_removed_readded"))

    def test_urgent_mid_cycle_waits_for_cycle_end(self):
        self.assertEqual(run_scenario("urgent_mid_cycle_waits_for_cycle_end"), load_expected("urgent_mid_cycle_waits_for_cycle_end"))

    def test_malformed_record_dead_letter(self):
        self.assertEqual(run_scenario("malformed_record_dead_letter"), load_expected("malformed_record_dead_letter"))

    def test_watch_removed_readded_after_delivery(self):
        self.assertEqual(run_scenario("watch_removed_readded_after_delivery"), load_expected("watch_removed_readded_after_delivery"))

    def test_every_scenario_file_has_expected(self):
        root = Path(__file__).parent / "replay"
        inputs = {p.name.removesuffix(".input.jsonl") for p in root.glob("*.input.jsonl")}
        expected = {p.name.removesuffix(".expected.jsonl") for p in root.glob("*.expected.jsonl")}
        methods = {name.removeprefix("test_") for name in dir(self)
                   if name.startswith("test_") and name != "test_every_scenario_file_has_expected"}
        self.assertEqual(inputs, methods)
        self.assertEqual(inputs, expected)
        for name in sorted(inputs):
            with self.subTest(scenario=name):
                self.assertIn("#", json.loads(
                    (root / f"{name}.expected.jsonl").read_text().splitlines()[0]))
                load_timeline(name)
                load_expected(name)

    def test_flush_preserves_record_retry(self):
        self.assertEqual(run_scenario("flush_preserves_record_retry"), load_expected("flush_preserves_record_retry"))

    def test_kev_retry_current_record(self):
        self.assertEqual(run_scenario("kev_retry_current_record"), load_expected("kev_retry_current_record"))

    def test_retention_kev_refresh(self):
        self.assertEqual(run_scenario("retention_kev_refresh"), load_expected("retention_kev_refresh"))

    def test_dead_letter_recovers(self):
        self.assertEqual(run_scenario("dead_letter_recovers"), load_expected("dead_letter_recovers"))

    def test_kev_waits_for_record(self):
        self.assertEqual(run_scenario("kev_waits_for_record"), load_expected("kev_waits_for_record"))

    def test_reactivation_discards_correction(self):
        self.assertEqual(run_scenario("reactivation_discards_correction"), load_expected("reactivation_discards_correction"))

    def test_bootstrap_snapshot_restart(self):
        self.assertEqual(run_scenario('bootstrap_snapshot_restart'), load_expected('bootstrap_snapshot_restart'))

    def test_bootstrap_reconcile_before_other_feeds(self):
        self.assertEqual(run_scenario('bootstrap_reconcile_before_other_feeds'), load_expected('bootstrap_reconcile_before_other_feeds'))

    def test_clock_rewind_unhealthy(self):
        self.assertEqual(run_scenario('clock_rewind_unhealthy'), load_expected('clock_rewind_unhealthy'))

    def test_bootstrap_grace_expired(self):
        self.assertEqual(run_scenario('bootstrap_grace_expired'), load_expected('bootstrap_grace_expired'))

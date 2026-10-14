from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detection.rules import AlertDetector
from storage.database import clear_alerts, fetch_alerts, initialize_database, insert_alert


class TestAlertDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AlertDetector(packet_rate_threshold=80, alert_cooldown=0.001)
        self.detector.reset()
        self.database_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.database_directory.cleanup)
        self.database_path_patch = patch(
            "storage.database.DATABASE_PATH",
            Path(self.database_directory.name) / "test-alerts.db",
        )
        self.database_path_patch.start()
        self.addCleanup(self.database_path_patch.stop)

    def test_normal_traffic_does_not_trigger_critical_alert(self):
        alerts = self.detector.record_window({"packets": 35, "bytes": 2500, "tcp": 18, "udp": 10, "icmp": 3, "other": 4, "syn": 3, "source_counts": {"10.0.0.1": 35}}, "simulated")
        self.assertEqual(alerts, [])

    def test_high_packet_rate_triggers_rule(self):
        alerts = self.detector.record_window({"packets": 120, "bytes": 9000, "tcp": 70, "udp": 20, "icmp": 7, "other": 23, "syn": 13, "source_counts": {"10.0.0.1": 120}}, "simulated")
        names = [alert.rule_name for alert in alerts]
        self.assertIn("high_packet_rate", names)

    def test_sustained_high_traffic_triggers_sustained_overload(self):
        for _ in range(3):
            alerts = self.detector.record_window({"packets": 130, "bytes": 15000, "tcp": 75, "udp": 25, "icmp": 5, "other": 25, "syn": 18, "source_counts": {"10.0.0.1": 130}}, "simulated")
            if _ == 2:
                self.assertTrue(any(alert.rule_name == "sustained_overload" for alert in alerts))

    def test_traffic_spike_can_be_detected_against_warmed_up_baseline(self):
        for _ in range(8):
            self.detector.record_window({"packets": 20, "bytes": 2000, "tcp": 10, "udp": 6, "icmp": 2, "other": 2, "syn": 2, "source_counts": {"10.0.0.1": 20}}, "simulated")
        alerts = self.detector.record_window({"packets": 90, "bytes": 8000, "tcp": 50, "udp": 15, "icmp": 5, "other": 20, "syn": 7, "source_counts": {"10.0.0.1": 90}}, "simulated")
        self.assertTrue(any(alert.rule_name == "sudden_traffic_spike" for alert in alerts))

    def test_empty_traffic_windows_do_not_crash_detector(self):
        alerts = self.detector.record_window({}, "simulated")
        self.assertEqual(alerts, [])

    def test_duplicate_window_id_is_processed_only_once(self):
        window = {"window_id": 1, "packets": 120, "bytes": 9000}
        first = self.detector.record_window(window, "simulated")
        baseline_length = len(self.detector.baseline)
        second = self.detector.record_window(window, "simulated")
        self.assertIn("high_packet_rate", [alert.rule_name for alert in first])
        self.assertEqual(second, [])
        self.assertEqual(len(self.detector.baseline), baseline_length)
        self.assertEqual(len(self.detector.window_history), 1)

    def test_elapsed_window_calculates_packet_rate_before_detection(self):
        detector = AlertDetector(packet_rate_threshold=100, alert_cooldown=0)
        alerts = detector.record_window(
            {"packets": 100, "bytes": 1000, "elapsed_seconds": 0.5},
            "simulated",
        )
        high_rate = next(alert for alert in alerts if alert.rule_name == "high_packet_rate")
        self.assertEqual(high_rate.observed_value, 200)
        self.assertIn("200.0 packets/sec", high_rate.explanation)

    def test_source_concentration_and_syn_anomaly_are_detected(self):
        detector = AlertDetector(
            packet_rate_threshold=1000,
            source_concentration_threshold=0.7,
            syn_ratio_threshold=0.35,
            alert_cooldown=0,
        )
        alerts = detector.record_window(
            {
                "packets": 100,
                "tcp": 100,
                "syn": 50,
                "source_counts": {"10.0.0.1": 80, "10.0.0.2": 20},
            },
            "simulated",
        )
        by_rule = {alert.rule_name: alert for alert in alerts}
        self.assertIn("source_concentration", by_rule)
        self.assertIn("syn_anomaly", by_rule)
        self.assertIn("80.0%", by_rule["source_concentration"].explanation)
        self.assertIn("50.0%", by_rule["syn_anomaly"].explanation)

    def test_cooldown_prevents_duplicate_alerts(self):
        first = self.detector.record_window({"packets": 120, "bytes": 9000, "tcp": 70, "udp": 20, "icmp": 7, "other": 23, "syn": 13, "source_counts": {"10.0.0.1": 120}}, "simulated")
        second = self.detector.record_window({"packets": 121, "bytes": 9100, "tcp": 71, "udp": 21, "icmp": 8, "other": 21, "syn": 14, "source_counts": {"10.0.0.1": 121}}, "simulated")
        self.assertTrue(len(first) >= 1)
        self.assertEqual(sum(1 for alert in second if alert.rule_name == "high_packet_rate"), 0)

    def test_sqlite_saves_and_retrieves_alert_records(self):
        initialize_database()
        clear_alerts()
        alert = {
            "timestamp": "2026-10-14T00:00:00Z",
            "severity": "Critical",
            "rule_name": "high_packet_rate",
            "observed_value": 130.0,
            "threshold_value": 80,
            "explanation": "High packet rate observed.",
            "traffic_source": "simulated",
        }
        insert_alert(alert)
        rows = fetch_alerts(severity="Critical", traffic_source="simulated", limit=10)
        self.assertTrue(any(row["rule_name"] == "high_packet_rate" for row in rows))
        clear_alerts()


if __name__ == "__main__":
    unittest.main()

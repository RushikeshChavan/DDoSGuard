from __future__ import annotations

import unittest

from simulator.traffic_simulator import TrafficSimulator


class TestTrafficSimulator(unittest.TestCase):
    def test_normal_scenario_generates_reasonable_window(self):
        sim = TrafficSimulator(scenario="normal", speed_multiplier=1.0, duration_seconds=5, seed=42)
        sim.start()
        window = sim.next_window()
        self.assertIsNotNone(window)
        self.assertGreater(window["packets"], 0)
        self.assertGreater(window["bytes"], 0)
        self.assertIn("source_counts", window)

    def test_spike_scenario_increases_packet_volume(self):
        sim = TrafficSimulator(scenario="spike", speed_multiplier=1.0, duration_seconds=10, seed=7)
        sim.start()
        baseline = [sim.next_window() for _ in range(8)]
        window = sim.next_window()
        self.assertIsNotNone(window)
        self.assertLess(max(item["packets"] for item in baseline), 80)
        self.assertGreater(window["packets"], 80)
        self.assertEqual(sum(window["source_counts"].values()), window["packets"])

    def test_ddos_scenario_has_multi_source_synthetic_traffic_and_syn_load(self):
        sim = TrafficSimulator(scenario="ddos", speed_multiplier=1.0, duration_seconds=10, seed=9)
        sim.start()
        window = sim.next_window()
        self.assertIsNotNone(window)
        self.assertGreater(len(window["source_counts"]), 5)
        self.assertGreater(window["syn"], 0)
        self.assertGreater(window["packets"], 200)
        self.assertEqual(sum(window["source_counts"].values()), window["packets"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class TrafficSimulator:
    def __init__(
        self,
        scenario: str = "normal",
        speed_multiplier: float = 1.0,
        duration_seconds: int = 30,
        seed: int = 42,
    ) -> None:
        self.scenario = scenario
        self.speed_multiplier = max(0.1, float(speed_multiplier))
        self.duration_seconds = max(5, int(duration_seconds))
        self.seed = seed
        self.rng = random.Random(seed)
        self.is_running = False
        self.is_paused = False
        self.current_window = 0
        self.total_packets = 0
        self.window_history: List[Dict[str, Any]] = []

    def reset(self) -> None:
        self.is_running = False
        self.is_paused = False
        self.current_window = 0
        self.total_packets = 0
        self.window_history.clear()
        self.rng.seed(self.seed)

    def start(self) -> None:
        self.is_running = True
        self.is_paused = False

    def pause(self) -> None:
        self.is_paused = True

    def resume(self) -> None:
        self.is_paused = False

    def stop(self) -> None:
        self.is_running = False
        self.is_paused = False

    def _generate_normal_window(self) -> Dict[str, Any]:
        base_packets = int(35 + self.rng.uniform(-12, 18) * self.speed_multiplier)
        packets = max(8, base_packets)
        bytes_sent = packets * self.rng.randint(60, 180)
        tcp = max(1, int(packets * self.rng.uniform(0.45, 0.62)))
        udp = max(1, int(packets * self.rng.uniform(0.20, 0.35)))
        icmp = min(
            max(0, int(packets * self.rng.uniform(0.08, 0.15))),
            max(0, packets - tcp - udp),
        )
        other = max(0, packets - tcp - udp - icmp)
        syn = max(0, int(tcp * self.rng.uniform(0.08, 0.18)))
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "packets": packets,
            "bytes": bytes_sent,
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp,
            "other": other,
            "syn": syn,
            "source_counts": self._distribute_sources(packets, self.rng.randint(6, 12)),
            "traffic_source": "simulation",
        }

    def _generate_spike_window(self) -> Dict[str, Any]:
        if self.current_window < 8:
            return self._generate_normal_window()
        if self.current_window < 16:
            packets = int(140 + self.rng.uniform(20, 90) * self.speed_multiplier)
        else:
            packets = int(50 + self.rng.uniform(-10, 25) * self.speed_multiplier)
        tcp = max(1, int(packets * self.rng.uniform(0.45, 0.58)))
        udp = max(1, int(packets * self.rng.uniform(0.2, 0.3)))
        icmp = min(
            max(0, int(packets * self.rng.uniform(0.05, 0.1))),
            max(0, packets - tcp - udp),
        )
        other = max(0, packets - tcp - udp - icmp)
        syn = max(0, int(tcp * self.rng.uniform(0.12, 0.25)))
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "packets": packets,
            "bytes": packets * self.rng.randint(100, 220),
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp,
            "other": other,
            "syn": syn,
            "source_counts": self._distribute_sources(packets, self.rng.randint(8, 16)),
            "traffic_source": "simulation",
        }

    def _generate_ddos_window(self) -> Dict[str, Any]:
        packets = int(240 + self.rng.uniform(70, 200) * self.speed_multiplier)
        tcp = max(1, int(packets * self.rng.uniform(0.6, 0.75)))
        udp = max(1, int(packets * self.rng.uniform(0.12, 0.18)))
        icmp = min(
            max(0, int(packets * self.rng.uniform(0.06, 0.12))),
            max(0, packets - tcp - udp),
        )
        other = max(0, packets - tcp - udp - icmp)
        syn = max(0, int(tcp * self.rng.uniform(0.42, 0.68)))
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "packets": packets,
            "bytes": packets * self.rng.randint(120, 260),
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp,
            "other": other,
            "syn": syn,
            "source_counts": self._distribute_sources(packets, self.rng.randint(12, 30)),
            "traffic_source": "simulation",
        }

    def _distribute_sources(self, packets: int, source_count: int) -> Dict[str, int]:
        source_count = min(max(1, source_count), packets)
        source_counts = {
            f"10.0.0.{index + 1}": packets // source_count
            for index in range(source_count)
        }
        remainder = packets % source_count
        for index in range(remainder):
            ip = f"10.0.0.{index + 1}"
            source_counts[ip] += 1
        return source_counts

    def next_window(self) -> Optional[Dict[str, Any]]:
        if not self.is_running or self.is_paused or self.current_window >= self.duration_seconds:
            return None

        if self.scenario == "normal":
            window = self._generate_normal_window()
        elif self.scenario == "spike":
            window = self._generate_spike_window()
        elif self.scenario == "ddos":
            window = self._generate_ddos_window()
        else:
            window = self._generate_normal_window()

        self.current_window += 1
        self.total_packets += int(window.get("packets", 0) or 0)
        window["window_id"] = self.current_window
        window["elapsed_seconds"] = 1.0
        self.window_history.append(window)
        return window

    def describe_scenario(self) -> str:
        descriptions = {
            "normal": "Normal traffic with moderate fluctuations and realistic protocol mix.",
            "spike": "Traffic spike scenario: a sharp burst followed by a gradual return to baseline.",
            "ddos": "Simulated DDoS-like event: sustained overload with many synthetic sources and elevated SYN activity.",
        }
        return descriptions.get(self.scenario, descriptions["normal"])

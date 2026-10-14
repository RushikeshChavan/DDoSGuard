from __future__ import annotations

import time
import math
from collections import deque
from dataclasses import dataclass
from statistics import mean
from typing import Any, Deque, Dict, List, Optional


@dataclass
class DetectorAlert:
    timestamp: str
    rule_name: str
    severity: str
    observed_value: float
    threshold_value: Any
    explanation: str
    traffic_source: str = "unknown"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "explanation": self.explanation,
            "traffic_source": self.traffic_source,
        }


class AlertDetector:
    def __init__(
        self,
        packet_rate_threshold: float = 120.0,
        spike_multiplier: float = 2.5,
        sustained_window_count: int = 3,
        source_concentration_threshold: float = 0.7,
        syn_ratio_threshold: float = 0.35,
        alert_cooldown: float = 20.0,
        baseline_window_size: int = 12,
    ) -> None:
        self.packet_rate_threshold = float(packet_rate_threshold)
        self.spike_multiplier = float(spike_multiplier)
        self.sustained_window_count = int(sustained_window_count)
        self.source_concentration_threshold = float(source_concentration_threshold)
        self.syn_ratio_threshold = float(syn_ratio_threshold)
        self.alert_cooldown = float(alert_cooldown)
        self.baseline_window_size = max(3, int(baseline_window_size))

        self.baseline: Deque[float] = deque(maxlen=self.baseline_window_size)
        self.window_history: Deque[Dict[str, Any]] = deque(maxlen=120)
        self.cooldowns: Dict[str, float] = {}
        self.consecutive_overload_windows = 0
        self.last_packets_per_second = 0.0
        self.last_window_id: Dict[str, int] = {}

    def reset(self) -> None:
        self.baseline.clear()
        self.window_history.clear()
        self.cooldowns.clear()
        self.consecutive_overload_windows = 0
        self.last_packets_per_second = 0.0
        self.last_window_id.clear()

    def calculate_baseline(self) -> float:
        if not self.baseline:
            return 0.0
        return mean(self.baseline)

    def _should_cooldown(self, rule_name: str) -> bool:
        now = time.time()
        last_seen = self.cooldowns.get(rule_name)
        if last_seen is None:
            return False
        return (now - last_seen) < self.alert_cooldown

    def _record_cooldown(self, rule_name: str) -> None:
        self.cooldowns[rule_name] = time.time()

    @staticmethod
    def _safe_ratio(numerator: float, denominator: float) -> float:
        if denominator <= 0:
            return 0.0
        return float(numerator) / float(denominator)

    def _build_alert(
        self,
        rule_name: str,
        severity: str,
        observed_value: float,
        threshold_value: Any,
        explanation: str,
        traffic_source: str,
    ) -> Optional[DetectorAlert]:
        if self._should_cooldown(rule_name):
            return None
        alert = DetectorAlert(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            rule_name=rule_name,
            severity=severity,
            observed_value=observed_value,
            threshold_value=threshold_value,
            explanation=explanation,
            traffic_source=traffic_source,
        )
        self._record_cooldown(rule_name)
        return alert

    def record_window(self, window: Optional[Dict[str, Any]], traffic_source: str = "unknown") -> List[DetectorAlert]:
        if not window:
            return []

        window_id = window.get("window_id")
        if window_id is not None:
            try:
                current_id = int(window_id)
            except (TypeError, ValueError):
                current_id = None
            if current_id is not None:
                previous_id = self.last_window_id.get(traffic_source)
                if previous_id is not None and current_id <= previous_id:
                    return []
                self.last_window_id[traffic_source] = current_id

        self.window_history.append(window)

        def safe_number(key: str) -> float:
            try:
                value = float(window.get(key, 0) or 0)
            except (TypeError, ValueError):
                return 0.0
            return value if math.isfinite(value) and value >= 0 else 0.0

        packets = safe_number("packets")
        bytes_sent = safe_number("bytes")
        try:
            elapsed = float(window.get("elapsed_seconds", 1.0) or 1.0)
        except (TypeError, ValueError):
            elapsed = 1.0
        if not math.isfinite(elapsed) or elapsed <= 0:
            elapsed = 1.0
        pps = safe_number("packets_per_second") if "packets_per_second" in window else packets / elapsed
        self.last_packets_per_second = pps
        baseline_value = self.calculate_baseline()

        alerts: List[DetectorAlert] = []

        if pps > self.packet_rate_threshold:
            severity = "Normal"
            if pps >= self.packet_rate_threshold * 1.8:
                severity = "Warning"
            if pps >= self.packet_rate_threshold * 2.5:
                severity = "Critical"
            explanation = (
                f"Rule high_packet_rate: observed {pps:.1f} packets/sec, threshold "
                f"{self.packet_rate_threshold:.1f} packets/sec. This indicates elevated traffic, "
                "but it is not proof of a DDoS attack by itself."
            )
            alert = self._build_alert(
                "high_packet_rate",
                severity,
                pps,
                self.packet_rate_threshold,
                explanation,
                traffic_source,
            )
            if alert:
                alerts.append(alert)

        if baseline_value > 0 and pps > baseline_value * self.spike_multiplier and len(self.baseline) >= self.baseline_window_size // 2:
            explanation = (
                f"Rule sudden_traffic_spike: observed {pps:.1f} packets/sec, threshold "
                f"{baseline_value * self.spike_multiplier:.1f} packets/sec "
                f"({self.spike_multiplier:.2f}x the prior rolling baseline of {baseline_value:.1f})."
            )
            severity = "Warning" if pps < baseline_value * 4 else "Critical"
            alert = self._build_alert(
                "sudden_traffic_spike",
                severity,
                pps,
                baseline_value * self.spike_multiplier,
                explanation,
                traffic_source,
            )
            if alert:
                alerts.append(alert)

        if pps > self.packet_rate_threshold:
            self.consecutive_overload_windows += 1
        else:
            self.consecutive_overload_windows = 0

        if self.consecutive_overload_windows >= self.sustained_window_count:
            explanation = (
                f"Rule sustained_overload: observed {pps:.1f} packets/sec, threshold "
                f"{self.packet_rate_threshold:.1f} packets/sec for "
                f"{self.consecutive_overload_windows} consecutive windows. "
                "This is a possible DDoS-like condition but still requires corroborating evidence."
            )
            severity = "Warning" if self.consecutive_overload_windows < self.sustained_window_count + 2 else "Critical"
            alert = self._build_alert(
                "sustained_overload",
                severity,
                pps,
                self.packet_rate_threshold,
                explanation,
                traffic_source,
            )
            if alert:
                alerts.append(alert)

        sources = window.get("source_counts") or {}
        if sources and len(sources) > 1:
            source_values = [safe_number_value(value) for value in sources.values()]
            top_source = max(source_values) if source_values else 0
            total_source_packets = sum(source_values)
            concentration = self._safe_ratio(top_source, total_source_packets)
            if concentration >= self.source_concentration_threshold:
                explanation = (
                    f"Rule source_concentration: observed {concentration * 100:.1f}% from one source, "
                    f"threshold {self.source_concentration_threshold * 100:.1f}%. "
                    "High source concentration can happen in focused bursts, but it does not by itself confirm a DDoS attack."
                )
                severity = "Warning" if concentration < 0.85 else "Critical"
                alert = self._build_alert(
                    "source_concentration",
                    severity,
                    concentration,
                    self.source_concentration_threshold,
                    explanation,
                    traffic_source,
                )
                if alert:
                    alerts.append(alert)

        tcp_packets = safe_number("tcp")
        syn_packets = safe_number("syn")
        if tcp_packets > 0:
            syn_ratio = self._safe_ratio(syn_packets, tcp_packets)
            if syn_packets > 0 and syn_ratio >= self.syn_ratio_threshold:
                explanation = (
                    f"Rule syn_anomaly: observed SYN/TCP ratio {syn_ratio * 100:.1f}%, "
                    f"threshold {self.syn_ratio_threshold * 100:.1f}%. Elevated SYN activity may suggest a SYN-flood-like condition, "
                    "but SYN counts alone cannot confirm a SYN flood."
                )
                severity = "Warning" if syn_ratio < 0.6 else "Critical"
                alert = self._build_alert(
                    "syn_anomaly",
                    severity,
                    syn_ratio,
                    self.syn_ratio_threshold,
                    explanation,
                    traffic_source,
                )
                if alert:
                    alerts.append(alert)

        self.baseline.append(pps)

        return alerts


def safe_number_value(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) and number >= 0 else 0.0

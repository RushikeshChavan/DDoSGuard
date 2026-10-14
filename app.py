from __future__ import annotations

import time
import math
from typing import Any, Dict, Optional

import pandas as pd
import streamlit as st

from capture.packet_capture import PacketCapture, discover_interfaces
from detection.rules import AlertDetector
from simulator.traffic_simulator import TrafficSimulator
from storage.database import clear_alerts, fetch_alerts, initialize_database, insert_alert

st.set_page_config(page_title="DDoSGuard", page_icon="🛡️", layout="wide")

EMPTY_WINDOW: Dict[str, Any] = {
    "packets": 0,
    "bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
    "syn": 0,
    "source_counts": {},
}


def ensure_state() -> None:
    defaults = {
        "simulator": TrafficSimulator(scenario="normal", speed_multiplier=1.0, duration_seconds=30),
        "detector": AlertDetector(),
        "live_capture": PacketCapture(),
        "history": [],
        "traffic_history": [],
        "is_monitoring": False,
        "monitoring_source": None,
        "last_measurement_at": None,
        "latest_window": dict(EMPTY_WINDOW),
        "last_simulation_error": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def normalize_window(window: Optional[Dict[str, Any]], source: str, elapsed: float) -> Dict[str, Any]:
    normalized = dict(EMPTY_WINDOW)
    if window:
        normalized.update(window)
    normalized["traffic_source"] = source
    for key in ("packets", "bytes", "tcp", "udp", "icmp", "other", "syn"):
        try:
            value = int(normalized.get(key, 0) or 0)
        except (TypeError, ValueError, OverflowError):
            value = 0
        normalized[key] = max(value, 0)
    try:
        elapsed_seconds = float(normalized.get("elapsed_seconds", elapsed) or elapsed)
    except (TypeError, ValueError):
        elapsed_seconds = elapsed
    if not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
        elapsed_seconds = max(elapsed, 0.001)
    normalized["elapsed_seconds"] = elapsed_seconds
    normalized["packets_per_second"] = normalized["packets"] / elapsed_seconds
    normalized["bytes_per_second"] = normalized["bytes"] / elapsed_seconds
    normalized["source_counts"] = normalized.get("source_counts") or {}
    return normalized


def add_alert(alert_dict: Dict[str, Any]) -> None:
    st.session_state.history.insert(0, alert_dict)
    st.session_state.history = st.session_state.history[:30]
    insert_alert(alert_dict)


initialize_database()
ensure_state()

with st.sidebar:
    st.title("DDoSGuard")
    st.caption("Rule-based detection of suspicious traffic patterns.")
    st.write("Alerts describe possible anomalies, not confirmed attacks.")

    source = st.radio("Traffic source", ["Simulation", "Live Capture"], index=0)
    source_key = "simulated" if source == "Simulation" else "real"

    interface_name: Optional[str] = None
    if source == "Live Capture":
        interfaces = discover_interfaces()
        interface_options = [item["name"] for item in interfaces]
        if interface_options:
            interface_name = st.selectbox("Capture interface", interface_options)
        else:
            st.warning("No Windows interfaces were discovered. Install Npcap or use Simulation mode.")

    st.subheader("Detection thresholds")
    packet_threshold = st.slider("Packet rate threshold (packets/sec)", 20, 400, 120, 5)
    spike_multiplier = st.slider("Baseline multiplier", 1.5, 5.0, 2.5, 0.1)
    sustained_windows = st.slider("Sustained windows", 2, 8, 3, 1)
    cooldown = st.slider("Alert cooldown (seconds)", 5, 120, 20, 5)
    source_threshold = st.slider("Source concentration threshold", 0.5, 0.95, 0.7, 0.05)
    syn_threshold = st.slider("SYN ratio threshold", 0.1, 0.8, 0.35, 0.05)

    st.subheader("Simulation controls")
    scenario = st.selectbox("Scenario", ["normal", "spike", "ddos"], index=0)
    sim_speed = st.slider("Simulation speed", 0.5, 3.0, 1.0, 0.1)
    sim_duration = st.slider("Simulation duration (seconds)", 5, 60, 30, 5)

    start_col, stop_col = st.columns(2)
    start_btn = start_col.button("Start", use_container_width=True, disabled=st.session_state.is_monitoring)
    stop_btn = stop_col.button("Stop", use_container_width=True, disabled=not st.session_state.is_monitoring)
    reset_btn = st.button("Reset", use_container_width=True)

    if st.session_state.is_monitoring and st.session_state.monitoring_source != source_key:
        st.session_state.simulator.stop()
        st.session_state.live_capture.stop()
        st.session_state.is_monitoring = False
        st.session_state.monitoring_source = None
        st.rerun()

    if start_btn:
        st.session_state.detector = AlertDetector(
            packet_rate_threshold=packet_threshold,
            spike_multiplier=spike_multiplier,
            sustained_window_count=sustained_windows,
            source_concentration_threshold=source_threshold,
            syn_ratio_threshold=syn_threshold,
            alert_cooldown=cooldown,
        )
        st.session_state.last_measurement_at = None
        st.session_state.latest_window = dict(EMPTY_WINDOW)
        st.session_state.traffic_history = []
        st.session_state.last_processed_live_window_id = None
        st.session_state.last_simulation_error = ""
        st.session_state.monitoring_source = source_key
        st.session_state.is_monitoring = True

        if source == "Simulation":
            sim = st.session_state.simulator
            sim.reset()
            sim.scenario = scenario
            sim.speed_multiplier = sim_speed
            sim.duration_seconds = sim_duration
            sim.start()
        elif interface_name:
            try:
                st.session_state.live_capture.stop()
                st.session_state.live_capture.start(interface_name)
            except (OSError, ValueError, RuntimeError) as exc:
                st.session_state.is_monitoring = False
                st.session_state.monitoring_source = None
                st.session_state.last_simulation_error = str(exc)
        else:
            st.session_state.is_monitoring = False
            st.session_state.monitoring_source = None
            st.session_state.last_simulation_error = "Select an available interface before starting live capture."

    if stop_btn or reset_btn:
        st.session_state.is_monitoring = False
        st.session_state.monitoring_source = None
        st.session_state.simulator.stop()
        st.session_state.live_capture.stop()

    if reset_btn:
        st.session_state.simulator.reset()
        st.session_state.detector.reset()
        st.session_state.latest_window = dict(EMPTY_WINDOW)
        st.session_state.traffic_history = []
        st.session_state.last_measurement_at = None
        st.session_state.last_simulation_error = ""

    if start_btn or stop_btn or reset_btn:
        st.rerun()

    st.caption("Simulation is synthetic and does not transmit traffic. Live capture is read-only.")


def render_dashboard() -> None:
    was_monitoring = st.session_state.is_monitoring
    source = st.session_state.monitoring_source or (
        "simulated" if st.session_state.get("selected_source", "Simulation") == "Simulation" else "real"
    )

    if st.session_state.is_monitoring:
        now = time.monotonic()
        previous = st.session_state.last_measurement_at
        elapsed = max(now - previous, 0.001) if previous is not None else 1.0
        st.session_state.last_measurement_at = now

        if source == "simulated":
            try:
                raw_window = st.session_state.simulator.next_window()
            except Exception as exc:
                st.session_state.last_simulation_error = f"Simulation failed: {exc}"
                raw_window = None
            if raw_window is None:
                st.session_state.is_monitoring = False
                st.session_state.monitoring_source = None
                st.session_state.simulator.stop()
            else:
                raw_window["elapsed_seconds"] = elapsed
                window = normalize_window(raw_window, source, elapsed)
                alerts = st.session_state.detector.record_window(window, source)
                for alert in alerts:
                    add_alert(alert.as_dict())
                st.session_state.latest_window = window
                st.session_state.traffic_history.append(window)
        else:
            live = st.session_state.live_capture
            with live.lock:
                capture_error = live.error_message
            for raw_window in live.get_pending_windows():
                window = normalize_window(raw_window, source, elapsed)
                alerts = st.session_state.detector.record_window(window, source)
                for alert in alerts:
                    add_alert(alert.as_dict())
                st.session_state.latest_window = window
                st.session_state.traffic_history.append(window)
            if capture_error:
                st.error(capture_error)
                st.session_state.last_simulation_error = capture_error
                st.session_state.is_monitoring = False
                st.session_state.monitoring_source = None
                live.stop()

    if was_monitoring and not st.session_state.is_monitoring:
        st.session_state.refresh_should_stop = True

        st.session_state.traffic_history = st.session_state.traffic_history[-120:]

    window = st.session_state.latest_window
    latest_severity = st.session_state.history[0].get("severity", "Normal") if st.session_state.history else "Normal"

    st.title("DDoSGuard")
    mode_label = "Simulation — synthetic traffic only" if source == "simulated" else "Live Capture — local traffic metadata"
    st.subheader(mode_label)
    st.markdown(
        f"Monitoring: **{'Active' if st.session_state.is_monitoring else 'Idle'}** "
        f"| Most recent alert severity: **{latest_severity}**"
    )
    if source == "simulated":
        st.caption(st.session_state.simulator.describe_scenario())
    if st.session_state.last_simulation_error:
        st.error(st.session_state.last_simulation_error)

    cols = st.columns(4)
    cols[0].metric("Packets/sec", f"{window.get('packets_per_second', 0):,.1f}")
    cols[1].metric("Bytes/sec", f"{window.get('bytes_per_second', 0):,.1f}")
    total_packets = (
        st.session_state.simulator.total_packets
        if source == "simulated"
        else st.session_state.live_capture.total_packets
    )
    cols[2].metric("Total packets observed", f"{total_packets:,}")
    cols[3].metric("Unique source IPs", f"{len(window.get('source_counts') or {}):,}")

    history_df = pd.DataFrame(st.session_state.traffic_history)
    if len(history_df) > 1:
        history_df["window"] = range(1, len(history_df) + 1)
        st.subheader("Traffic rates")
        chart_cols = st.columns(2)
        chart_cols[0].line_chart(history_df.set_index("window")["packets_per_second"])
        chart_cols[1].line_chart(history_df.set_index("window")["bytes_per_second"])
    else:
        st.caption("Charts appear after at least two measurement windows.")

    st.subheader("Protocol distribution")
    protocol_data = pd.DataFrame(
        {
            "protocol": ["TCP", "UDP", "ICMP", "Other"],
            "packets": [window.get(key, 0) for key in ("tcp", "udp", "icmp", "other")],
        }
    ).set_index("protocol")
    st.bar_chart(protocol_data)

    source_counts = window.get("source_counts") or {}
    if source_counts:
        st.subheader("Packets by source IP")
        st.bar_chart(pd.DataFrame({"packets": source_counts}))

    st.subheader("Recent alerts")
    if st.session_state.history:
        st.dataframe(pd.DataFrame(st.session_state.history).head(10), width="stretch")
    else:
        st.info("No alerts yet. Start monitoring to generate events.")

    st.subheader("Persistent alert history")
    filter_cols = st.columns(2)
    severity_filter = filter_cols[0].selectbox("Severity", ["All", "Normal", "Warning", "Critical"])
    traffic_filter = filter_cols[1].selectbox("Traffic source", ["All", "simulated", "real"])
    records = fetch_alerts(
        severity=None if severity_filter == "All" else severity_filter,
        traffic_source=None if traffic_filter == "All" else traffic_filter,
        limit=100,
    )
    if records:
        alert_frame = pd.DataFrame(records)
        st.dataframe(alert_frame, width="stretch")
        st.download_button(
            "Export alerts as CSV",
            data=alert_frame.to_csv(index=False),
            file_name="ddosguard_alert_history.csv",
            mime="text/csv",
        )
    else:
        st.info("No persistent alerts match these filters.")

    if st.button("Clear persistent alert history"):
        clear_alerts()
        st.session_state.history.clear()
        st.rerun()

    if not st.session_state.is_monitoring and source == "simulated" and st.session_state.simulator.current_window >= st.session_state.simulator.duration_seconds:
        st.info("Simulation completed. Start again or reset to run another scenario.")

    if st.session_state.get("refresh_should_stop"):
        st.session_state.refresh_should_stop = False
        st.rerun()


st.session_state.selected_source = source
fragment_refresh = "1s" if st.session_state.is_monitoring else None
st.fragment(run_every=fragment_refresh)(render_dashboard)()

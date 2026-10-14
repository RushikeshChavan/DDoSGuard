from __future__ import annotations

import threading
import time
from collections import defaultdict
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

try:
    from scapy.all import sniff
    from scapy.arch.windows import get_windows_if_list
except Exception:  # pragma: no cover - fallback for environments without Scapy.
    sniff = None
    get_windows_if_list = None


class PacketCapture:
    def __init__(self, interface_name: Optional[str] = None) -> None:
        self.interface_name = interface_name
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.latest_window: Dict[str, Any] = {"packets": 0, "bytes": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "syn": 0, "ack": 0, "source_counts": {}, "traffic_source": "live"}
        self.total_packets = 0
        self.error_message = ""
        self.window_id = 0
        self.pending_windows: Queue[Dict[str, Any]] = Queue()

    def _set_error(self, message: str) -> None:
        with self.lock:
            self.error_message = message

    def _summarize_packet(self, packet: Any) -> Dict[str, Any]:
        fields = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "size": int(len(packet)),
            "ip_version": None,
            "source_ip": None,
            "destination_ip": None,
            "protocol": "other",
            "tcp_syn": False,
            "tcp_ack": False,
            "udp_packet": False,
        }

        if hasattr(packet, "haslayer") and packet.haslayer("IP"):
            ip_layer = packet["IP"]
            fields["ip_version"] = getattr(ip_layer, "version", None)
            fields["source_ip"] = ip_layer.src
            fields["destination_ip"] = ip_layer.dst
            fields["protocol"] = str(ip_layer.proto)

        if hasattr(packet, "haslayer") and packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            fields["protocol"] = "tcp"
            fields["tcp_syn"] = bool(getattr(tcp_layer, "flags", "") & 0x02)
            fields["tcp_ack"] = bool(getattr(tcp_layer, "flags", "") & 0x10)
        elif hasattr(packet, "haslayer") and packet.haslayer("UDP"):
            fields["protocol"] = "udp"
            fields["udp_packet"] = True
        elif hasattr(packet, "haslayer") and packet.haslayer("ICMP"):
            fields["protocol"] = "icmp"

        return fields

    def _process_packets(self, packet_list: List[Any], elapsed_seconds: float) -> None:
        counts = defaultdict(int)
        tcp = udp = icmp = other = syn = ack = 0
        total_bytes = 0
        for packet in packet_list:
            meta = self._summarize_packet(packet)
            total_bytes += int(meta["size"])
            if meta["source_ip"]:
                counts[meta["source_ip"]] += 1
            if meta["protocol"] == "tcp":
                tcp += 1
            elif meta["protocol"] == "udp":
                udp += 1
            elif meta["protocol"] == "icmp":
                icmp += 1
            else:
                other += 1

            if meta["tcp_syn"]:
                syn += 1
            if meta["tcp_ack"]:
                ack += 1

        with self.lock:
            self.total_packets += len(packet_list)
            self.window_id += 1
            self.latest_window = {
                "packets": len(packet_list),
                "bytes": total_bytes,
                "tcp": tcp,
                "udp": udp,
                "icmp": icmp,
                "other": other,
                "syn": syn,
                "ack": ack,
                "source_counts": dict(counts),
                "traffic_source": "live",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "window_id": self.window_id,
                "elapsed_seconds": max(float(elapsed_seconds), 0.001),
            }
            self.pending_windows.put(dict(self.latest_window))

    def get_pending_windows(self) -> List[Dict[str, Any]]:
        windows = []
        while True:
            try:
                windows.append(self.pending_windows.get_nowait())
            except Empty:
                return windows

    def _capture_loop(self, interface_name: str) -> None:
        while not self.stop_event.is_set():
            try:
                if sniff is None or get_windows_if_list is None:
                    self._set_error("Scapy is not available. Please install requirements.txt and ensure WinPcap/Npcap is installed if live capture is required.")
                    break
                started_at = time.monotonic()
                collected = sniff(iface=interface_name, store=True, timeout=1, count=0)
                self._process_packets(collected or [], time.monotonic() - started_at)
            except PermissionError:
                self._set_error("Live capture requires elevated privileges or a permitted capture driver. Run the terminal as Administrator or use simulation mode.")
                break
            except OSError as exc:
                self._set_error(f"Capture error: {exc}")
                break
            except Exception as exc:  # pragma: no cover - runtime-specific failure
                self._set_error(f"Live capture failed: {exc}")
                break

    def start(self, interface_name: Optional[str] = None) -> None:
        if self.thread and self.thread.is_alive():
            raise RuntimeError("A capture worker is already running or shutting down.")
        iface = interface_name or self.interface_name
        if not iface:
            raise ValueError("No interface selected for live capture.")
        self.interface_name = iface
        self.stop_event.clear()
        self._set_error("")
        self.window_id = 0
        self.get_pending_windows()
        self.thread = threading.Thread(target=self._capture_loop, args=(iface,), daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                self._set_error("Capture is still shutting down; wait before starting another capture.")


def discover_interfaces() -> List[Dict[str, Any]]:
    if get_windows_if_list is None:
        return []
    try:
        raw = get_windows_if_list()
    except Exception:
        return []
    interfaces: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            name = item.get("name") or item.get("description") or "Unknown"
            desc = item.get("description") or "Windows interface"
            interfaces.append({"name": name, "description": desc})
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            interfaces.append({"name": str(item[0]), "description": str(item[1])})
    return interfaces


__all__ = ["PacketCapture", "discover_interfaces"]

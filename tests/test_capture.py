from __future__ import annotations

import unittest
from unittest.mock import patch

from capture.packet_capture import PacketCapture


class FakePacket:
    def __len__(self):
        return 64

    def haslayer(self, _layer):
        return False


class TestPacketCapture(unittest.TestCase):
    def test_capture_collects_and_processes_packets(self):
        capture = PacketCapture("test-interface")

        def sniff_packets(**kwargs):
            capture.stop_event.set()
            self.assertTrue(kwargs["store"])
            return [FakePacket()]

        with patch("capture.packet_capture.sniff", side_effect=sniff_packets):
            capture.start()
            capture.thread.join(timeout=2)

        self.assertFalse(capture.thread.is_alive())
        windows = capture.get_pending_windows()
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]["packets"], 1)
        self.assertEqual(windows[0]["bytes"], 64)
        self.assertEqual(windows[0]["other"], 1)


if __name__ == "__main__":
    unittest.main()

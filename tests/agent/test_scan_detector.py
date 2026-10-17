import unittest

import _paths  # noqa: F401
from ezhik_agent.scan_detector import ScanDetector


class ScanDetectorTests(unittest.TestCase):
    def detector(self):
        return ScanDetector(
            window_seconds=60,
            tcp_vertical_ports=5,
            udp_vertical_ports=7,
            subnet_hosts=4,
            subnet_ports=6,
            subnet_endpoints=8,
            cooldown_seconds=30,
        )

    def test_vertical_scan(self):
        detector = self.detector()
        report = None
        for offset, port in enumerate(range(1000, 1005)):
            report = detector.observe(
                "123",
                ("tcp", 40000 + offset, "8.8.8.8", port),
                now=float(offset),
            )
        self.assertEqual(report["reason"], "vertical-port-scan")
        self.assertEqual(report["details"]["target_protocol"], "tcp")
        self.assertEqual(report["unique_endpoints"], 5)

    def test_udp_vertical_scan_has_separate_higher_threshold(self):
        detector = self.detector()
        reports = []
        for offset, port in enumerate(range(1000, 1007)):
            reports.append(
                detector.observe(
                    "123",
                    ("udp", 40000 + offset, "8.8.8.8", port),
                    now=float(offset),
                )
            )
        self.assertTrue(all(report is None for report in reports[:6]))
        self.assertEqual(reports[-1]["reason"], "vertical-port-scan")
        self.assertEqual(reports[-1]["details"]["target_protocol"], "udp")

    def test_tcp_and_udp_ports_are_not_combined(self):
        detector = self.detector()
        reports = []
        for offset in range(4):
            reports.append(
                detector.observe(
                    "123",
                    ("tcp", 40000 + offset, "8.8.8.8", 1000 + offset),
                    now=float(offset),
                )
            )
            reports.append(
                detector.observe(
                    "123",
                    ("udp", 41000 + offset, "8.8.8.8", 2000 + offset),
                    now=float(offset) + 0.1,
                )
            )
        self.assertTrue(all(report is None for report in reports))

    def test_subnet_scan(self):
        detector = self.detector()
        report = None
        for offset in range(8):
            report = detector.observe(
                "123",
                (
                    "udp",
                    50000,
                    f"8.8.4.{10 + (offset % 4)}",
                    2000 + (offset % 6),
                ),
                now=float(offset),
            )
        self.assertEqual(report["reason"], "subnet-port-scan")

    def test_common_port_fanout_is_not_scan(self):
        detector = self.detector()
        reports = []
        for offset in range(20):
            report = detector.observe(
                "123",
                ("tcp", 40000 + offset, f"8.8.{offset // 10}.{offset + 1}", 443),
                now=float(offset) / 10,
            )
            reports.append(report)
        self.assertTrue(all(report is None for report in reports))

    def test_random_peer_fanout_is_not_scan(self):
        for proto in ("tcp", "udp"):
            with self.subTest(proto=proto):
                detector = self.detector()
                reports = []
                for offset in range(100):
                    report = detector.observe(
                        "123",
                        (
                            proto,
                            50000 + offset,
                            f"20.{10 + offset}.0.9",
                            3000 + offset,
                        ),
                        now=float(offset) / 10,
                    )
                    reports.append(report)
                self.assertTrue(all(report is None for report in reports))

    def test_private_destination_is_ignored(self):
        detector = self.detector()
        for offset in range(20):
            report = detector.observe(
                "123",
                ("tcp", 40000 + offset, "10.0.0.1", 1000 + offset),
                now=float(offset),
            )
            self.assertIsNone(report)

    def test_failed_connect_destination_can_trigger_vertical_scan(self):
        detector = self.detector()
        report = None
        for offset, port in enumerate(range(20000, 20005)):
            report = detector.observe_destination(
                "123",
                "tcp",
                f"8.8.8.8:{port}",
                now=float(offset),
            )
        self.assertEqual(report["reason"], "vertical-port-scan")

    def test_vertical_report_excludes_unrelated_destinations(self):
        detector = self.detector()
        for offset in range(10):
            detector.observe(
                "123",
                ("tcp", 30000 + offset, f"20.{20 + offset}.0.1", 443),
                now=float(offset),
            )

        report = None
        for offset, port in enumerate(range(20000, 20005), start=10):
            report = detector.observe(
                "123",
                ("tcp", 40000 + offset, "8.8.8.8", port),
                now=float(offset),
            )

        self.assertEqual(report["unique_endpoints"], 5)
        self.assertEqual(report["unique_ips"], 1)
        self.assertTrue(
            all(
                item["remote_ip"] == "8.8.8.8"
                for item in report["sample_endpoints"]
            )
        )

    def test_destination_and_opened_socket_are_deduplicated(self):
        detector = self.detector()
        detector.observe_destination(
            "123",
            "tcp",
            "8.8.8.8:443",
            now=0.0,
        )
        detector.observe(
            "123",
            ("tcp", 50000, "8.8.8.8", 443),
            now=0.1,
        )

        state = detector._clients["123"]["long"]
        self.assertEqual(len(state.endpoints), 1)


if __name__ == "__main__":
    unittest.main()

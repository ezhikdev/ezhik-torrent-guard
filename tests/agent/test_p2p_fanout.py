import unittest

import _paths  # noqa: F401
from ezhik_agent.scan_detector import ScanDetector, fanout_port


def detector(**kw):
    defaults = dict(scan_enabled=True, fanout_enabled=True, udp_fanout_hosts=30, udp_fanout_networks=10,
                    tcp_fanout_hosts=40, tcp_fanout_networks=12, cooldown_seconds=60)
    defaults.update(kw)
    return ScanDetector(**defaults)


def spread_ip(i):
    # Different /16 for every 3 hosts, public ranges only.
    return f"{40 + (i // 3) % 150}.{(i * 7) % 250}.{i % 200}.{(i * 13) % 250 + 1}"


class P2PFanoutTests(unittest.TestCase):
    def test_dht_like_udp_fanout_is_reported(self):
        d = detector()
        report = None
        for i in range(30):
            report = d.observe("77", ("udp", 50000, spread_ip(i), 20000 + i * 37), now=float(i) / 10) or report
        self.assertIsNotNone(report)
        self.assertEqual(report["reason"], "p2p-fanout")
        self.assertEqual(report["family"], "p2p")
        self.assertGreaterEqual(report["details"]["unique_hosts"], 30)

    def test_quic_and_common_ports_are_ignored(self):
        d = detector()
        reports = []
        for i in range(200):
            port = (443, 80, 53, 3478, 19302, 8443)[i % 6]
            reports.append(d.observe("77", ("udp", 50000, spread_ip(i), port), now=float(i) / 10))
        self.assertTrue(all(r is None for r in reports))
        self.assertFalse(fanout_port(443))
        self.assertTrue(fanout_port(51413))

    def test_concentrated_hosts_do_not_trigger_fanout(self):
        d = detector(scan_enabled=False)
        reports = []
        # Many hosts but all inside two /16 networks (e.g. one CDN/game provider).
        for i in range(120):
            ip = f"{51 + (i % 2)}.68.{i // 50}.{i % 250 + 1}"
            reports.append(d.observe("77", ("udp", 50000, ip, 30000 + i), now=float(i) / 10))
        self.assertTrue(all(r is None for r in reports))

    def test_fanout_disabled_by_default_flag(self):
        d = detector(fanout_enabled=False)
        reports = [d.observe("77", ("udp", 50000, spread_ip(i), 20000 + i), now=float(i) / 10) for i in range(60)]
        self.assertTrue(all(r is None for r in reports))

    def test_scan_and_p2p_cooldowns_are_independent(self):
        d = detector(tcp_vertical_ports=5)
        scan = None
        for port in range(1000, 1005):
            scan = d.observe("9", ("tcp", 1, "8.8.8.8", port), now=1.0) or scan
        self.assertEqual(scan["family"], "scan")
        p2p = None
        for i in range(30):
            p2p = d.observe("9", ("udp", 2, spread_ip(i), 40000 + i), now=2.0 + i / 100) or p2p
        self.assertEqual(p2p["family"], "p2p")

    def test_window_expiry(self):
        d = detector(window_seconds=10)
        for i in range(29):
            self.assertIsNone(d.observe("5", ("udp", 1, spread_ip(i), 40000 + i), now=0.0))
        # Everything above expired: one more host must not trigger.
        self.assertIsNone(d.observe("5", ("udp", 1, spread_ip(99), 41000), now=100.0))


if __name__ == "__main__":
    unittest.main()

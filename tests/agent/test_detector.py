import unittest

import _paths  # noqa: F401
from ezhik_agent.detector import Detector, DetectorConfig, access_re

LOCAL = "203.0.113.5"


def make(**overrides):
    raw = {"local_ip": LOCAL, "container": "remnanode",
           "torrent": {"enabled": True, "cooldown_seconds": 900},
           "scan": {"enabled": False}, "p2p": {"enabled": False}}
    raw.update(overrides)
    events = []
    det = Detector(DetectorConfig(raw), events.append, fast_log="/dev/null")
    return det, events


def access(ts, dest, email, proto="tcp", detour=" [vless-in >> DIRECT]"):
    return f"2026/10/16 12:00:{ts} from 10.0.0.2:5555 accepted {proto}:{dest}{detour} email: {email}\n"


def recv(ts, rid, dest, proto="tcp"):
    return f"2026/10/16 12:00:{ts} [Info] [{rid}] proxy/vless/inbound: received request for {proto}:{dest}\n"


def opened(ts, rid, dest, local_port, proto="tcp"):
    ip, port = dest.rsplit(":", 1)
    return (f"2026/10/16 12:00:{ts} [Info] [{rid}] proxy/freedom: connection opened to {proto}:{dest}, "
            f"local endpoint {LOCAL}:{local_port}, remote endpoint {ip}:{port}\n")


def alert(local_port, dest, proto="TCP"):
    ip, port = dest.rsplit(":", 1)
    return (f"10/16/2026-12:00:01.000000  [**] [1:9900010:3] EZHIK nDPI BitTorrent flow [**] "
            f"[Classification: (null)] [Priority: 3] {{{proto}}} {LOCAL}:{local_port} -> {ip}:{port}\n")


class AttributionTests(unittest.TestCase):
    def test_exact_bittorrent_attribution(self):
        det, events = make()
        dest = "93.184.216.34:6881"
        det.process_access(access("00.100000", dest, "4242"))
        det.process_info(recv("00.100100", "777", dest))
        det.process_info(opened("00.101000", "777", dest, 40001))
        det.process_suricata(alert(40001, dest))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["type"], "torrent")
        self.assertEqual(event["client_id"], "4242")
        self.assertEqual(event["data"]["socket"]["local_port"], 40001)

    def test_alert_before_mapping_is_kept_pending(self):
        det, events = make()
        dest = "198.51.100.7:51413"
        det.process_suricata(alert(40002, dest, "UDP"))
        self.assertEqual(events, [])
        det.process_access(access("00.200000", dest, "17", proto="udp"))
        det.process_info(recv("00.200050", "888", dest, proto="udp"))
        det.process_info(opened("00.201000", "888", dest, 40002, proto="udp"))
        self.assertEqual([e["client_id"] for e in events], ["17"])

    def test_ambiguous_request_is_not_attributed(self):
        det, events = make()
        dest = "93.184.216.34:6881"
        det.process_access(access("00.100000", dest, "1"))
        det.process_access(access("00.100001", dest, "2"))
        det.process_info(recv("00.100000", "900", dest))
        det.process_info(opened("00.101000", "900", dest, 40003))
        det.process_suricata(alert(40003, dest))
        self.assertEqual(events, [])
        self.assertEqual(det.stats["ambiguous_request"], 1)

    def test_cooldown_suppresses_duplicates(self):
        det, events = make()
        for i, port in enumerate((41000, 41001)):
            dest = f"93.184.216.{40 + i}:6881"
            rid = str(1000 + i)
            det.process_access(access("00.300000", dest, "55"))
            det.process_info(recv("00.300010", rid, dest))
            det.process_info(opened("00.300020", rid, dest, port))
            det.process_suricata(alert(port, dest))
        self.assertEqual(len(events), 1)
        self.assertEqual(det.stats["bt_exact"], 2)

    def test_access_regex_without_detour(self):
        line = "2026/10/16 12:00:00.000001 from 1.2.3.4:1 accepted udp:8.8.8.8:53 email: 99"
        match = access_re.search(line)
        self.assertEqual(match.groups(), ("udp", "8.8.8.8:53", "99"))

    def test_scan_event_from_access_destinations(self):
        det, events = make(torrent={"enabled": False}, scan={"enabled": True, "tcp_vertical_ports": 5})
        for i, port in enumerate(range(2000, 2005)):
            det.process_access(access(f"0{i}.000000", f"8.8.8.8:{port}", "31"))
        self.assertEqual([e["type"] for e in events], ["scan"])
        self.assertEqual(events[0]["data"]["reason"], "vertical-port-scan")


class ConfigTests(unittest.TestCase):
    def test_p2p_requires_torrent(self):
        cfg = DetectorConfig({"torrent": {"enabled": False}, "p2p": {"enabled": True}})
        self.assertFalse(cfg.p2p_enabled)
        self.assertFalse(cfg.any_enabled)

    def test_identical_config_does_not_reset_windows(self):
        det, _ = make(scan={"enabled": True})
        before = det.scan_detector
        det.running = True  # pretend readers are up; nothing must restart
        det.update_config(DetectorConfig({"local_ip": LOCAL, "container": "remnanode",
                                          "torrent": {"enabled": True, "cooldown_seconds": 900},
                                          "scan": {"enabled": True}, "p2p": {"enabled": False}}))
        self.assertIs(det.scan_detector, before)


if __name__ == "__main__":
    unittest.main()

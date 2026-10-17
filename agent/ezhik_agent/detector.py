"""Exact BitTorrent attribution and behaviour detection.

This is the Torrent Guard 1.x engine moved into a class:

  Xray access log: destination + authenticated client ID
    -> Xray info log: request ID + logical destination
    -> Xray info log: request ID + actual local/remote socket
    -> in-RAM socket owner record
    -> Suricata strict-nDPI alert for the same socket
    -> unique client attribution -> event for the panel

Attribution refuses ambiguous request and socket ownership instead of
guessing. All connection metadata lives in RAM with short TTLs. The detector
only *reports*; sanctions are decided centrally by the panel.
"""

import json
import logging
import queue
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from . import paths
from .scan_detector import ScanDetector

log = logging.getLogger("ezhik.detector")

BT_SID = "9900010"
BT_ALERT_MARKER = f"[1:{BT_SID}:"
BT_ALERT_MARKER_BYTES = BT_ALERT_MARKER.encode("ascii")

# Evidence window.
WINDOW = 300

# access <-> request-id correlation
ACCESS_TTL = 3.0
REQUEST_TTL = 5.0
MATCH_WINDOW = 0.250
AMBIGUITY_SLACK = 0.003

# actual outbound socket ownership
SOCKET_TTL = 180.0

# Suricata may report an alert slightly before the Xray mapping.
PENDING_BT_TTL = 30.0

# Xray >= 1.8 / 25.x / 26.x access line:
#   from 1.2.3.4:5555 accepted tcp:8.8.8.8:443 [in >> out] email: 123
# Detour and reason are optional, so do not require them.
access_re = re.compile(
    r"accepted\s+(tcp|udp):(\S+)(?:\s.*?)?\semail:\s*(\S+)"
)

recv_re = re.compile(
    r"\[Info\]\s+\[(\d+)\].*?"
    r"received request for\s+"
    r"(tcp|udp):(\S+)"
)

open_re = re.compile(
    r"\[Info\]\s+\[(\d+)\].*?"
    r"connection opened to\s+"
    r"(tcp|udp):(.+?),\s+"
    r"local endpoint\s+(.+?),\s+"
    r"remote endpoint\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
)

suri_re = re.compile(
    rf"\[1:{BT_SID}:\d+\].*?"
    r"\{(TCP|UDP)\}\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
    r"\s+->\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
)

local_port_re = re.compile(r":(\d+)$")

STAT_KEYS = (
    "access", "requests", "mapped_requests", "opened", "bound_sockets",
    "bt_alerts", "bt_exact", "torrent_events", "scan_events", "p2p_events",
    "ambiguous_request", "ambiguous_socket", "filtered_info", "filtered_access",
    "queue_dropped",
)


@lru_cache(maxsize=8)
def _log_second_timestamp(value):
    return datetime.strptime(value, "%Y/%m/%d %H:%M:%S").timestamp()


def log_timestamp(line):
    try:
        stamp = line[:26]
        if len(stamp) != 26 or stamp[19] != "." or not stamp[20:].isdigit():
            return None
        return _log_second_timestamp(stamp[:19]) + int(stamp[20:]) / 1_000_000
    except Exception:
        return None


def relevant_line(name, line):
    if name == "info":
        return b"received request for " in line or b"connection opened to " in line
    if name == "access":
        return b"accepted " in line
    if name == "suricata":
        return BT_ALERT_MARKER_BYTES in line
    return True


class DetectorConfig:
    """Effective detection settings for this node (from the panel)."""

    def __init__(self, raw=None):
        raw = raw or {}
        self.key = json.dumps(raw, sort_keys=True, default=str)
        torrent = raw.get("torrent") or {}
        scan = raw.get("scan") or {}
        p2p = raw.get("p2p") or {}
        self.local_ip = str(raw.get("local_ip") or "").strip()
        self.container = str(raw.get("container") or "remnanode").strip() or "remnanode"
        self.torrent_enabled = bool(torrent.get("enabled", False))
        self.torrent_cooldown = max(30, int(torrent.get("cooldown_seconds", 900)))
        self.scan_enabled = bool(scan.get("enabled", False))
        self.p2p_enabled = bool(p2p.get("enabled", False)) and self.torrent_enabled
        self.scan = {
            "window_seconds": int(scan.get("window_seconds", 60)),
            "tcp_vertical_ports": int(scan.get("tcp_vertical_ports", 50)),
            "udp_vertical_ports": int(scan.get("udp_vertical_ports", 100)),
            "subnet_hosts": int(scan.get("subnet_hosts", 16)),
            "subnet_ports": int(scan.get("subnet_ports", 50)),
            "subnet_endpoints": int(scan.get("subnet_endpoints", 100)),
            "cooldown_seconds": int(scan.get("cooldown_seconds", 300)),
            "udp_fanout_hosts": int(p2p.get("udp_hosts", 120)),
            "udp_fanout_networks": int(p2p.get("udp_networks", 40)),
            "tcp_fanout_hosts": int(p2p.get("tcp_hosts", 150)),
            "tcp_fanout_networks": int(p2p.get("tcp_networks", 50)),
        }

    @property
    def any_enabled(self):
        return self.torrent_enabled or self.scan_enabled or self.p2p_enabled

    def reader_signature(self):
        return (self.local_ip, self.container, self.torrent_enabled, self.any_enabled)


class Detector:
    def __init__(self, config, emit, fast_log=None):
        self.config = config
        self.emit = emit
        self.fast_log = str(fast_log or paths.SURICATA_FAST_LOG)
        self.running = False
        self._thread = None
        self._procs = []
        self._procs_lock = threading.Lock()
        self.events = queue.Queue(maxsize=100000)
        self.stats = {key: 0 for key in STAT_KEYS}
        self.last_line_at = {"access": None, "info": None, "suricata": None}
        self.reader_errors = {}
        self._reset_state()
        self._build_scan_detector()

    # ------------------------------------------------------------ lifecycle

    def _reset_state(self):
        self.access_by_dest = defaultdict(deque)
        self.access_expiry = deque()
        self.requests = {}
        self.request_expiry = deque()
        self.requests_by_dest = defaultdict(set)
        self.opened = {}
        self.opened_expiry = deque()
        self.socket_owners = defaultdict(deque)
        self.socket_expiry = deque()
        self.pending_bt = {}
        self.pending_bt_expiry = deque()
        self.hits = defaultdict(dict)
        self.hits_expiry = deque()
        self.announced = {}
        self.announced_expiry = deque()

    def _build_scan_detector(self):
        c = self.config
        self.scan_detector = ScanDetector(
            scan_enabled=c.scan_enabled,
            fanout_enabled=c.p2p_enabled,
            **c.scan,
        )

    def update_config(self, config):
        """Apply new settings. Readers restart only when their inputs change."""
        if config.key == self.config.key:
            if config.any_enabled and not self.running:
                self.start()
            return
        restart = config.reader_signature() != self.config.reader_signature()
        self.config = config
        self._build_scan_detector()
        if restart and self.running:
            self.stop()
            self.start()
        elif config.any_enabled and not self.running:
            self.start()

    def start(self):
        if self.running or not self.config.any_enabled:
            return
        if not self.config.local_ip:
            log.error("Detector not started: node WAN IPv4 is unknown")
            return
        self._reset_state()
        self.running = True
        self.cleanup_container_tails()
        specs = [
            ("access", ["docker", "exec", self.config.container, "tail", "-n", "0", "-F", paths.XRAY_ACCESS_LOG]),
            ("info", ["docker", "exec", self.config.container, "tail", "-n", "0", "-F", paths.XRAY_INFO_LOG]),
        ]
        if self.config.torrent_enabled:
            specs.append(("suricata", ["tail", "-n", "0", "-F", self.fast_log]))
        for name, cmd in specs:
            threading.Thread(target=self._reader, args=(name, cmd), name=f"reader-{name}", daemon=True).start()
        self._thread = threading.Thread(target=self._loop, name="detector", daemon=True)
        self._thread.start()
        log.info(
            "Detector started: torrent=%s scan=%s p2p=%s container=%s ip=%s",
            self.config.torrent_enabled, self.config.scan_enabled, self.config.p2p_enabled,
            self.config.container, self.config.local_ip,
        )

    def stop(self):
        if not self.running:
            return
        self.running = False
        with self._procs_lock:
            procs, self._procs = self._procs, []
        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        self.cleanup_container_tails()
        self.privacy_cleanup()
        log.info("Detector stopped; RAM evidence discarded")

    # --------------------------------------------------------------- readers

    def _reader(self, name, cmd):
        backoff = 1.0
        while self.running:
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as exc:
                self.reader_errors[name] = str(exc)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            with self._procs_lock:
                self._procs.append(proc)
            started = time.time()
            for line in proc.stdout:
                if not self.running:
                    break
                self.last_line_at[name] = time.time()
                if not relevant_line(name, line):
                    if name == "info":
                        self.stats["filtered_info"] += 1
                    elif name == "access":
                        self.stats["filtered_access"] += 1
                    continue
                try:
                    self.events.put((name, line.decode("utf-8", errors="replace")), timeout=1)
                except queue.Full:
                    self.stats["queue_dropped"] += 1
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                err = proc.stderr.read().decode("utf-8", "replace").strip() if proc.stderr else ""
            except Exception:
                err = ""
            with self._procs_lock:
                if proc in self._procs:
                    self._procs.remove(proc)
            if not self.running:
                return
            self.reader_errors[name] = err[:300] or f"reader exited with code {proc.poll()}"
            # A reader that ran for a while restarts fast (container restart).
            backoff = 1.0 if time.time() - started > 30 else min(backoff * 2, 30)
            time.sleep(backoff)

    def _loop(self):
        last_cleanup = time.time()
        while self.running:
            try:
                source, line = self.events.get(timeout=0.5)
                if source == "access":
                    self.process_access(line)
                elif source == "info":
                    self.process_info(line)
                elif source == "suricata":
                    self.process_suricata(line)
            except queue.Empty:
                pass
            except Exception:
                log.exception("Detector failed to process a line")
            now = time.time()
            if now - last_cleanup >= 2:
                self.cleanup()
                last_cleanup = now

    # ------------------------------------------------- Xray request mapping

    def bind_socket(self, rid):
        req = self.requests.get(rid)
        op = self.opened.get(rid)
        if not req or not op:
            return
        email = req.get("email")
        if not email:
            return
        # One request-id may reach this point several times; the socket must
        # be registered only once.
        if req.get("bound"):
            return

        key = (op["proto"], op["local_port"], op["remote_ip"], op["remote_port"])
        now = time.time()
        owner_record = (now, email)
        self.socket_owners[key].append(owner_record)
        self.socket_expiry.append((now + SOCKET_TTL, key, owner_record))
        req["bound"] = True
        req["socket_key"] = key
        self.stats["bound_sockets"] += 1

        self.process_scan_socket(email, key)

        # strict nDPI may already have produced an alert.
        pending_ts = self.pending_bt.get(key)
        if pending_ts is not None:
            if now - pending_ts <= PENDING_BT_TTL:
                self.attribute_bt(key)
            self.pending_bt.pop(key, None)

    def try_map_request(self, rid):
        req = self.requests.get(rid)
        if not req:
            return
        if req.get("email"):
            self.bind_socket(rid)
            return

        candidates = self.access_by_dest.get((req["proto"], req["dest"]))
        if not candidates:
            return

        scored = []
        for ts, email in candidates:
            dt = abs(ts - req["ts"])
            if dt <= MATCH_WINDOW:
                scored.append((dt, email))
        if not scored:
            return

        scored.sort(key=lambda x: x[0])
        best_dt, best_email = scored[0]
        # Different clients used the same destination at nearly the same time:
        # do not guess.
        competing = {email for dt, email in scored if dt <= best_dt + AMBIGUITY_SLACK}
        if len(competing) != 1:
            self.stats["ambiguous_request"] += 1
            return

        req["email"] = best_email
        self.stats["mapped_requests"] += 1
        self.bind_socket(rid)

    def process_access(self, line):
        line = line.replace("\\:", ":")
        ts = log_timestamp(line)
        if ts is None:
            return
        m = access_re.search(line)
        if not m:
            return
        proto, dest, email = m.groups()
        proto = proto.lower()
        key = (proto, dest)
        self.access_by_dest[key].append((ts, email))
        self.access_expiry.append((ts + ACCESS_TTL, key))
        self.stats["access"] += 1

        self.process_scan_destination(email, proto, dest)

        # "received request" may have been logged slightly before access.
        for rid in list(self.requests_by_dest.get(key, ())):
            self.try_map_request(rid)

    def process_info(self, line):
        line = line.replace("\\:", ":")
        ts = log_timestamp(line)
        if ts is None:
            return

        m = recv_re.search(line) if "received request for " in line else None
        if m:
            rid, proto, dest = m.groups()
            proto = proto.lower()
            created = time.time()
            self.requests[rid] = {
                "ts": ts,
                "proto": proto,
                "dest": dest,
                "created": created,
                "email": None,
                "bound": False,
                "socket_key": None,
            }
            self.requests_by_dest[(proto, dest)].add(rid)
            self.request_expiry.append((created + REQUEST_TTL, rid, created))
            self.stats["requests"] += 1
            self.try_map_request(rid)
            return

        m = open_re.search(line) if "connection opened to " in line else None
        if not m:
            return
        rid, proto, _logical_dest, local_endpoint, remote_ip, remote_port = m.groups()
        port_match = local_port_re.search(local_endpoint)
        if not port_match:
            return
        created = time.time()
        self.opened[rid] = {
            "created": created,
            "proto": proto.lower(),
            "local_port": int(port_match.group(1)),
            "remote_ip": remote_ip,
            "remote_port": int(remote_port),
        }
        self.opened_expiry.append((created + REQUEST_TTL, rid, created))
        self.stats["opened"] += 1
        self.bind_socket(rid)

    # ------------------------------------------------- port-scan evidence

    def handle_scan_report(self, client, report):
        if report is None:
            return
        family = report.get("family", "scan")
        self.stats["p2p_events" if family == "p2p" else "scan_events"] += 1
        report["node_ip"] = self.config.local_ip
        log.warning(
            "[%s DETECTED] client=%s reason=%s endpoints=%s ips=%s ports=%s",
            family.upper(), client, report["reason"], report["unique_endpoints"],
            report["unique_ips"], report["unique_ports"],
        )
        self.emit({
            "type": family,
            "client_id": str(client),
            "detected_at": report["detected_at"],
            "data": report,
        })

    def process_scan_destination(self, client, proto, destination):
        if not (self.config.scan_enabled or self.config.p2p_enabled):
            return
        self.handle_scan_report(client, self.scan_detector.observe_destination(client, proto, destination))

    def process_scan_socket(self, client, key):
        if not (self.config.scan_enabled or self.config.p2p_enabled):
            return
        self.handle_scan_report(client, self.scan_detector.observe(client, key))

    # ------------------------------------------------ BitTorrent evidence

    def current_client_evidence(self, client):
        client_hits = self.hits.get(client, {})
        remote_counts = defaultdict(int)
        for _proto, _local_port, remote_ip, remote_port in client_hits:
            remote_counts[(remote_ip, remote_port)] += 1
        return len(client_hits), len(remote_counts), max(remote_counts.values(), default=0)

    def add_hit(self, client, key):
        now = time.time()
        client_hits = self.hits[client]
        if key in client_hits:
            client_hits[key] = now
            self.hits_expiry.append((now + WINDOW, client, key, now))
            return False

        client_hits[key] = now
        self.hits_expiry.append((now + WINDOW, client, key, now))
        exact_sockets, unique_remotes, max_same_remote = self.current_client_evidence(client)
        log.info("[BT EXACT] client=%s sockets=%s remote_unique=%s", client, exact_sockets, unique_remotes)

        # Immediate policy: the first exact strict-nDPI BitTorrent socket owned
        # by one authenticated client is enough. The cooldown suppresses
        # duplicate reports while a sanction is pending on the panel.
        last = self.announced.get(client, 0)
        if now - last < self.config.torrent_cooldown:
            return True
        self.announced[client] = now
        self.announced_expiry.append((now + self.config.torrent_cooldown, client, now))
        self.stats["torrent_events"] += 1
        proto, local_port, remote_ip, remote_port = key
        self.emit({
            "type": "torrent",
            "client_id": str(client),
            "detected_at": now,
            "data": {
                "reason": "first-exact-bittorrent",
                "exact_sockets": exact_sockets,
                "unique_remotes": unique_remotes,
                "same_remote_max": max_same_remote,
                "socket": {
                    "protocol": proto,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                },
                "node_ip": self.config.local_ip,
            },
        })
        return True

    def attribute_bt(self, key):
        now = time.time()
        dq = self.socket_owners.get(key)
        if not dq:
            return False
        while dq and now - dq[0][0] > SOCKET_TTL:
            dq.popleft()
        if not dq:
            self.socket_owners.pop(key, None)
            return False
        users = {email for ts, email in dq if now - ts <= SOCKET_TTL}
        # One exact socket in the window must belong to exactly one client.
        if len(users) != 1:
            self.stats["ambiguous_socket"] += 1
            return False
        if self.add_hit(next(iter(users)), key):
            self.stats["bt_exact"] += 1
        return True

    def process_suricata(self, line):
        m = suri_re.search(line)
        if not m:
            return
        proto, sip, sport, dip, dport = m.groups()
        proto = proto.lower()
        sport, dport = int(sport), int(dport)
        local_ip = self.config.local_ip
        if sip == local_ip:
            key = (proto, sport, dip, dport)
        elif dip == local_ip:
            key = (proto, dport, sip, sport)
        else:
            return
        self.stats["bt_alerts"] += 1
        if self.attribute_bt(key):
            return
        pending_ts = time.time()
        self.pending_bt[key] = pending_ts
        self.pending_bt_expiry.append((pending_ts + PENDING_BT_TTL, key, pending_ts))

    # ----------------------------------------------------------- cleanup

    def cleanup(self):
        now = time.time()

        while self.access_expiry and self.access_expiry[0][0] < now:
            _expires, key = self.access_expiry.popleft()
            dq = self.access_by_dest.get(key)
            if dq is None:
                continue
            while dq and now - dq[0][0] > ACCESS_TTL:
                dq.popleft()
            if not dq:
                self.access_by_dest.pop(key, None)

        while self.request_expiry and self.request_expiry[0][0] < now:
            _expires, rid, created = self.request_expiry.popleft()
            req = self.requests.get(rid)
            if not req or req["created"] != created:
                continue
            key = (req["proto"], req["dest"])
            dest_requests = self.requests_by_dest.get(key)
            if dest_requests is not None:
                dest_requests.discard(rid)
                if not dest_requests:
                    self.requests_by_dest.pop(key, None)
            self.requests.pop(rid, None)
            self.opened.pop(rid, None)

        while self.opened_expiry and self.opened_expiry[0][0] < now:
            _expires, rid, created = self.opened_expiry.popleft()
            op = self.opened.get(rid)
            if op and op["created"] == created and rid not in self.requests:
                self.opened.pop(rid, None)

        while self.socket_expiry and self.socket_expiry[0][0] < now:
            _expires, key, record = self.socket_expiry.popleft()
            dq = self.socket_owners.get(key)
            if dq is None:
                continue
            if dq and dq[0] == record:
                dq.popleft()
            if not dq:
                self.socket_owners.pop(key, None)

        while self.pending_bt_expiry and self.pending_bt_expiry[0][0] < now:
            _expires, key, pending_ts = self.pending_bt_expiry.popleft()
            if self.pending_bt.get(key) == pending_ts:
                self.pending_bt.pop(key, None)

        while self.hits_expiry and self.hits_expiry[0][0] < now:
            _expires, client, key, hit_ts = self.hits_expiry.popleft()
            client_hits = self.hits.get(client)
            if not client_hits:
                continue
            if client_hits.get(key) == hit_ts:
                client_hits.pop(key, None)
            if not client_hits:
                self.hits.pop(client, None)

        while self.announced_expiry and self.announced_expiry[0][0] < now:
            _expires, client, announced_ts = self.announced_expiry.popleft()
            if self.announced.get(client) == announced_ts:
                self.announced.pop(client, None)

        self.scan_detector.cleanup(now)

    def cleanup_container_tails(self):
        """Kill tail readers left inside the container by a previous agent."""
        script = (
            'for P in /proc/[0-9]*; do '
            '[ -r "$P/comm" ] || continue; '
            '[ "$(cat "$P/comm" 2>/dev/null)" = "tail" ] || continue; '
            'CMD=$(tr "\\000" " " < "$P/cmdline" 2>/dev/null); '
            'case "$CMD" in *"/dev/shm/xray-access.log"*|*"/dev/shm/xray-info.log"*) '
            'kill "${P##*/}" 2>/dev/null || true ;; esac; done'
        )
        try:
            subprocess.run(
                ["docker", "exec", self.config.container, "sh", "-c", script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
            )
        except Exception:
            pass

    def privacy_cleanup(self):
        try:
            Path(self.fast_log).write_text("")
        except Exception:
            pass
        try:
            subprocess.run(
                ["docker", "exec", self.config.container, "sh", "-c",
                 ": > /dev/shm/xray-access.log; : > /dev/shm/xray-info.log"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
            )
        except Exception:
            pass

    # ------------------------------------------------------------- status

    def snapshot(self):
        now = time.time()

        def age(value):
            return None if value is None else round(now - value, 1)

        return {
            "running": self.running,
            "torrent": self.config.torrent_enabled,
            "scan": self.config.scan_enabled,
            "p2p": self.config.p2p_enabled,
            "stats": dict(self.stats),
            "scan_clients": self.scan_detector.active_clients(),
            "pending_alerts": len(self.pending_bt),
            "queue": self.events.qsize(),
            "last_line_age": {k: age(v) for k, v in self.last_line_at.items()},
            "reader_errors": dict(self.reader_errors),
        }

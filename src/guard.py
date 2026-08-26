#!/usr/bin/env python3

import os
import re
import time
import signal
import queue
import threading
import subprocess

from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from functools import lru_cache

import remnawave_actions as remna_actions
import scan_detector
import telegram_notifier


def _app_version():
    here = Path(__file__).resolve().parent
    for candidate in (here / "VERSION", here.parent / "VERSION"):
        try:
            value = candidate.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
    return "unknown"


APP_VERSION = _app_version()


# ============================================================
# CONFIG
# ============================================================

def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default, minimum=1):
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    return max(minimum, value)


def _env_clients(name):
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip().isdigit()}


LOCAL_IP = os.getenv("EZHIK_LOCAL_IP", "").strip()
REMNANODE_CONTAINER = os.getenv("EZHIK_REMNANODE_CONTAINER", "remnanode").strip() or "remnanode"

ACCESS_LOG = "/dev/shm/xray-access.log"
INFO_LOG = "/dev/shm/xray-info.log"
SURI_LOG = "/dev/shm/ezhik-suricata-fast.log"

BT_SID = "9900010"
BT_ALERT_MARKER = f"[1:{BT_SID}:"
BT_ALERT_MARKER_BYTES = BT_ALERT_MARKER.encode("ascii")

DRY_RUN = _env_bool("EZHIK_DRY_RUN", False)
PROTECTED_CLIENTS = _env_clients("EZHIK_PROTECTED_CLIENTS")
TEST_CLIENT = os.getenv("EZHIK_TEST_CLIENT", "").strip()

SCAN_ENABLED = _env_bool("EZHIK_SCAN_ENABLED", True)
SCAN_DRY_RUN = _env_bool("EZHIK_SCAN_DRY_RUN", True)
SCAN_BLOCK_SECONDS = _env_int("EZHIK_SCAN_BLOCK_SECONDS", 3600, minimum=0)
SCAN_WINDOW_SECONDS = _env_int("EZHIK_SCAN_WINDOW_SECONDS", 60)
SCAN_BURST_WINDOW_SECONDS = _env_int("EZHIK_SCAN_BURST_WINDOW_SECONDS", 15)
SCAN_VERTICAL_PORTS = _env_int("EZHIK_SCAN_VERTICAL_PORTS", 20, minimum=2)
SCAN_BURST_ENDPOINTS = _env_int("EZHIK_SCAN_BURST_ENDPOINTS", 100, minimum=2)
SCAN_BURST_PORTS = _env_int("EZHIK_SCAN_BURST_PORTS", 50, minimum=2)
SCAN_SUBNET_HOSTS = _env_int("EZHIK_SCAN_SUBNET_HOSTS", 16, minimum=2)
SCAN_SUBNET_PORTS = _env_int("EZHIK_SCAN_SUBNET_PORTS", 50, minimum=2)
SCAN_COOLDOWN_SECONDS = _env_int("EZHIK_SCAN_COOLDOWN_SECONDS", 300)

# Evidence window.
WINDOW = 300

# First exact strict-nDPI BitTorrent socket triggers the policy.
# The cooldown follows the configured freeze duration.
FREEZE_SECONDS = _env_int("EZHIK_FREEZE_SECONDS", 900)
STATS_INTERVAL = _env_int("EZHIK_STATS_INTERVAL", 60)

# access ↔ request-id correlation
ACCESS_TTL = 3.0
REQUEST_TTL = 5.0

MATCH_WINDOW = 0.250
AMBIGUITY_SLACK = 0.003

# actual outbound socket ownership
SOCKET_TTL = 180.0

# Suricata может прислать alert немного раньше Xray mapping.
PENDING_BT_TTL = 30.0

SCAN_DETECTOR = scan_detector.ScanDetector(
    window_seconds=SCAN_WINDOW_SECONDS,
    burst_window_seconds=SCAN_BURST_WINDOW_SECONDS,
    vertical_ports=SCAN_VERTICAL_PORTS,
    burst_endpoints=SCAN_BURST_ENDPOINTS,
    burst_ports=SCAN_BURST_PORTS,
    subnet_hosts=SCAN_SUBNET_HOSTS,
    subnet_ports=SCAN_SUBNET_PORTS,
    cooldown_seconds=SCAN_COOLDOWN_SECONDS,
)


# ============================================================
# REGEX
# ============================================================

access_re = re.compile(
    r'accepted\s+'
    r'(tcp|udp):(\S+)\s+'
    r'\[[^\]]+\]\s+'
    r'email:\s*(\S+)'
)

recv_re = re.compile(
    r'\[Info\]\s+\[(\d+)\].*?'
    r'received request for\s+'
    r'(tcp|udp):(\S+)'
)

open_re = re.compile(
    r'\[Info\]\s+\[(\d+)\].*?'
    r'connection opened to\s+'
    r'(tcp|udp):(.+?),\s+'
    r'local endpoint\s+(.+?),\s+'
    r'remote endpoint\s+'
    r'(\d+\.\d+\.\d+\.\d+):(\d+)'
)

suri_re = re.compile(
    rf'\[1:{BT_SID}:\d+\].*?'
    r'\{(TCP|UDP)\}\s+'
    r'(\d+\.\d+\.\d+\.\d+):(\d+)'
    r'\s+->\s+'
    r'(\d+\.\d+\.\d+\.\d+):(\d+)'
)

# ============================================================
# STATE — RAM ONLY
# ============================================================

# (proto, logical destination)
# -> deque[(timestamp, email)]
access_by_dest = defaultdict(deque)
access_expiry = deque()

# request-id -> request information
requests = {}
request_expiry = deque()

# (proto, logical destination) -> set(request-id)
requests_by_dest = defaultdict(set)

# request-id -> outbound socket info
opened = {}
opened_expiry = deque()

# Exact Xray socket ->
# deque[(timestamp, email)]
socket_owners = defaultdict(deque)
socket_expiry = deque()

# nDPI alert, который ещё ждёт ownership.
# socket -> timestamp
pending_bt = {}
pending_bt_expiry = deque()

# client ->
# exact socket -> timestamp
hits = defaultdict(dict)
hits_expiry = deque()

# client -> timestamp last WOULD_FREEZE
announced = {}
announced_expiry = deque()

stats = {
    "access": 0,
    "requests": 0,
    "mapped_requests": 0,
    "opened": 0,

    # Теперь реально unique request-id/socket bindings.
    "bound_sockets": 0,

    "bt_alerts": 0,
    "bt_exact": 0,
    "scan_alerts": 0,

    "ambiguous_request": 0,
    "ambiguous_socket": 0,
    "filtered_info": 0,
    "filtered_access": 0,
    "queue_dropped": 0,
}

events = queue.Queue(maxsize=100000)

running = True


# ============================================================
# SIGNALS
# ============================================================

def stop(*_):
    global running
    running = False


# ============================================================
# HELPERS
# ============================================================

@lru_cache(maxsize=8)
def _log_second_timestamp(value):
    return datetime.strptime(
        value,
        "%Y/%m/%d %H:%M:%S",
    ).timestamp()


def log_timestamp(line):
    try:
        stamp = line[:26]

        if (
            len(stamp) != 26
            or stamp[19] != "."
            or not stamp[20:].isdigit()
        ):
            return None

        return (
            _log_second_timestamp(stamp[:19])
            + int(stamp[20:]) / 1_000_000
        )

    except Exception:
        return None


def relevant_line(name, line):
    if isinstance(line, bytes):
        if name == "info":
            return (
                b"received request for " in line
                or b"connection opened to " in line
            )

        if name == "access":
            return b"accepted " in line

        if name == "suricata":
            return BT_ALERT_MARKER_BYTES in line

        return True

    if name == "info":
        return (
            "received request for " in line
            or "connection opened to " in line
        )

    if name == "access":
        return "accepted " in line

    if name == "suricata":
        return BT_ALERT_MARKER in line

    return True


def reader(name, cmd):
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
        )

        for line in proc.stdout:

            if not running:
                break

            if not relevant_line(name, line):
                if name == "info":
                    stats["filtered_info"] += 1
                elif name == "access":
                    stats["filtered_access"] += 1
                continue

            line = line.decode("utf-8", errors="replace")

            try:
                events.put(
                    (name, line),
                    timeout=1,
                )

            except queue.Full:
                stats["queue_dropped"] += 1

        try:
            proc.terminate()
        except Exception:
            pass

    except Exception as exc:
        print(
            f"[READER ERROR] {name}: {exc}",
            flush=True,
        )


def start_readers():

    specs = [
        (
            "access",
            [
                "docker",
                "exec",
                REMNANODE_CONTAINER,
                "tail",
                "-n",
                "0",
                "-F",
                ACCESS_LOG,
            ],
        ),

        (
            "info",
            [
                "docker",
                "exec",
                REMNANODE_CONTAINER,
                "tail",
                "-n",
                "0",
                "-F",
                INFO_LOG,
            ],
        ),

        (
            "suricata",
            [
                "tail",
                "-n",
                "0",
                "-F",
                SURI_LOG,
            ],
        ),
    ]

    for name, cmd in specs:

        threading.Thread(
            target=reader,
            args=(name, cmd),
            daemon=True,
        ).start()


# ============================================================
# XRAY request-id → email → actual socket
# ============================================================

def bind_socket(rid):
    req = requests.get(rid)
    op = opened.get(rid)

    if not req or not op:
        return

    email = req.get("email")

    if not email:
        return

    # ========================================================
    # V2 FIX:
    #
    # один request-id может попадать сюда несколько раз:
    # - после access
    # - после received request
    # - после connection opened
    #
    # но socket должен быть зарегистрирован только ОДИН раз.
    # ========================================================

    if req.get("bound"):
        return

    key = (
        op["proto"],
        op["local_port"],
        op["remote_ip"],
        op["remote_port"],
    )

    now = time.time()
    owner_record = (
        now,
        email,
    )

    socket_owners[key].append(owner_record)
    socket_expiry.append(
        (
            now + SOCKET_TTL,
            key,
            owner_record,
        )
    )

    req["bound"] = True
    req["socket_key"] = key

    stats["bound_sockets"] += 1

    process_scan_socket(
        email,
        key,
    )

    # Возможно strict nDPI уже успел дать alert.
    pending_ts = pending_bt.get(key)

    if pending_ts is not None:

        if now - pending_ts <= PENDING_BT_TTL:
            attribute_bt(key)

        pending_bt.pop(
            key,
            None,
        )


def try_map_request(rid):
    req = requests.get(rid)

    if not req:
        return

    if req.get("email"):

        bind_socket(rid)

        return

    key = (
        req["proto"],
        req["dest"],
    )

    candidates = access_by_dest.get(key)

    if not candidates:
        return

    scored = []

    for ts, email in candidates:

        dt = abs(
            ts - req["ts"]
        )

        if dt <= MATCH_WINDOW:

            scored.append(
                (
                    dt,
                    email,
                )
            )

    if not scored:
        return

    scored.sort(
        key=lambda x: x[0]
    )

    best_dt, best_email = scored[0]

    # Если практически одновременно тот же destination
    # использовали разные клиенты — не угадываем.
    competing = {
        email
        for dt, email in scored
        if dt <= best_dt + AMBIGUITY_SLACK
    }

    if len(competing) != 1:

        stats["ambiguous_request"] += 1

        return

    req["email"] = best_email

    stats["mapped_requests"] += 1

    bind_socket(rid)


def process_access(line):

    line = line.replace("\\:", ":")

    ts = log_timestamp(line)

    if ts is None:
        return

    m = access_re.search(line)

    if not m:
        return

    proto, dest, email = m.groups()

    proto = proto.lower()

    key = (
        proto,
        dest,
    )

    access_by_dest[key].append(
        (
            ts,
            email,
        )
    )
    access_expiry.append(
        (
            ts + ACCESS_TTL,
            key,
        )
    )

    stats["access"] += 1

    # received request мог появиться чуть раньше access.
    for rid in requests_by_dest.get(key, ()):
        try_map_request(rid)


def process_info(line):

    line = line.replace("\\:", ":")

    ts = log_timestamp(line)

    if ts is None:
        return

    # --------------------------------------------------------
    # received request
    # --------------------------------------------------------

    m = (
        recv_re.search(line)
        if "received request for " in line
        else None
    )

    if m:

        rid, proto, dest = m.groups()

        proto = proto.lower()

        created = time.time()

        requests[rid] = {
            "ts": ts,
            "proto": proto,
            "dest": dest,
            "created": created,
            "email": None,

            # V2 dedup.
            "bound": False,
            "socket_key": None,
        }

        requests_by_dest[
            (
                proto,
                dest,
            )
        ].add(rid)
        request_expiry.append(
            (
                created + REQUEST_TTL,
                rid,
                created,
            )
        )

        stats["requests"] += 1

        try_map_request(rid)

        return

    # --------------------------------------------------------
    # connection opened
    # --------------------------------------------------------

    m = (
        open_re.search(line)
        if "connection opened to " in line
        else None
    )

    if not m:
        return

    (
        rid,
        proto,
        _logical_dest,
        local_endpoint,
        remote_ip,
        remote_port,
    ) = m.groups()

    port_match = re.search(
        r':(\d+)$',
        local_endpoint,
    )

    if not port_match:
        return

    local_port = int(
        port_match.group(1)
    )

    created = time.time()

    opened[rid] = {
        "created": created,
        "proto": proto.lower(),
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": int(remote_port),
    }
    opened_expiry.append(
        (
            created + REQUEST_TTL,
            rid,
            created,
        )
    )

    stats["opened"] += 1

    bind_socket(rid)


# ============================================================
# PORT-SCAN EVIDENCE
# ============================================================

def process_scan_socket(client, key):

    if not SCAN_ENABLED:
        return

    report = SCAN_DETECTOR.observe(
        client,
        key,
    )

    if report is None:
        return

    stats["scan_alerts"] += 1

    if client in PROTECTED_CLIENTS:
        action = "PROTECTED_NO_ACTION"

    elif SCAN_DRY_RUN:
        action = "WOULD_BLOCK"

    else:
        queued = remna_actions.queue_freeze(
            client,
            duration_seconds=SCAN_BLOCK_SECONDS,
            reason="port-scan",
            forget_after_disable=(SCAN_BLOCK_SECONDS == 0),
        )
        action = (
            "BLOCK_QUEUED"
            if queued
            else "NO_ACTION_ALREADY_BLOCKED_OR_PENDING"
        )

    report.update(
        {
            "node_ip": LOCAL_IP,
            "action": action,
            "block_seconds": SCAN_BLOCK_SECONDS,
        }
    )

    duration = (
        "permanent"
        if SCAN_BLOCK_SECONDS == 0
        else f"{SCAN_BLOCK_SECONDS // 60}m"
    )

    print()
    print(
        f"[SCAN DETECTED] "
        f"client={client} "
        f"reason={report['reason']} "
        f"window={report['window_seconds']}s "
        f"endpoints={report['unique_endpoints']} "
        f"ips={report['unique_ips']} "
        f"ports={report['unique_ports']} "
        f"action={action} "
        f"duration={duration}",
        flush=True,
    )
    print()

    telegram_notifier.notify_scan(
        report
    )


# ============================================================
# BITTORRENT EVIDENCE
# ============================================================

def current_client_evidence(client):
    client_hits = hits.get(
        client,
        {},
    )

    exact_sockets = len(
        client_hits
    )

    remote_counts = defaultdict(int)

    for socket_key in client_hits:

        (
            _proto,
            _local_port,
            remote_ip,
            remote_port,
        ) = socket_key

        remote_counts[
            (
                remote_ip,
                remote_port,
            )
        ] += 1

    unique_remotes = len(
        remote_counts
    )

    max_same_remote = max(
        remote_counts.values(),
        default=0,
    )

    return (
        exact_sockets,
        unique_remotes,
        max_same_remote,
    )


def threshold_reached(client):

    (
        exact_sockets,
        unique_remotes,
        max_same_remote,
    ) = current_client_evidence(client)

    # Immediate policy:
    # первый exact strict-nDPI BitTorrent socket,
    # точно связанный с Xray authenticated client,
    # уже является основанием для санкции.
    return exact_sockets >= 1


def add_hit(client, key):

    now = time.time()

    client_hits = hits[client]

    # Один exact socket считается только один раз.
    if key in client_hits:

        client_hits[key] = now
        hits_expiry.append(
            (
                now + WINDOW,
                client,
                key,
                now,
            )
        )

        return False

    client_hits[key] = now
    hits_expiry.append(
        (
            now + WINDOW,
            client,
            key,
            now,
        )
    )

    (
        exact_sockets,
        unique_remotes,
        max_same_remote,
    ) = current_client_evidence(client)

    marker = (
        " <=== TEST"
        if TEST_CLIENT and client == TEST_CLIENT
        else ""
    )

    print(
        f"[BT EXACT] "
        f"client={client} "
        f"sockets={exact_sockets} "
        f"remote_unique={unique_remotes} "
        f"same_remote_max={max_same_remote}"
        f"{marker}",
        flush=True,
    )

    if not threshold_reached(client):
        return True

    # --------------------------------------------------------
    # Protected client
    # --------------------------------------------------------

    if client in PROTECTED_CLIENTS:

        print(
            f"[PROTECTED] "
            f"client={client} "
            f"threshold reached — NO ACTION",
            flush=True,
        )

        return True

    # --------------------------------------------------------
    # Cooldown
    # --------------------------------------------------------

    last = announced.get(
        client,
        0,
    )

    if now - last < FREEZE_SECONDS:
        return True

    announced[client] = now
    announced_expiry.append(
        (
            now + FREEZE_SECONDS,
            client,
            now,
        )
    )

    if DRY_RUN:

        reason = "first-exact-bittorrent"

        print()
        print(
            f"[WOULD_FREEZE] "
            f"client={client} "
            f"duration={FREEZE_SECONDS // 60}m "
            f"reason={reason} "
            f"exact_bt_sockets={exact_sockets} "
            f"remote_unique={unique_remotes} "
            f"same_remote_max={max_same_remote}",
            flush=True,
        )
        print()

    else:

        remna_actions.queue_freeze(
            client
        )

    return True


def attribute_bt(key):

    now = time.time()

    dq = socket_owners.get(key)

    if not dq:
        return False

    while dq and (
        now - dq[0][0] > SOCKET_TTL
    ):
        dq.popleft()

    if not dq:
        socket_owners.pop(key, None)
        return False

    users = {
        email
        for ts, email in dq
        if now - ts <= SOCKET_TTL
    }

    # Один exact socket в нашем window должен принадлежать
    # ровно одному клиенту.
    if len(users) != 1:

        stats["ambiguous_socket"] += 1

        return False

    client = next(
        iter(users)
    )

    # add_hit сам дедуплицирует socket.
    is_new = add_hit(
        client,
        key,
    )

    if is_new:
        stats["bt_exact"] += 1

    return True


def process_suricata(line):

    m = suri_re.search(line)

    if not m:
        return

    (
        proto,
        sip,
        sport,
        dip,
        dport,
    ) = m.groups()

    proto = proto.lower()
    sport = int(sport)
    dport = int(dport)

    if sip == LOCAL_IP:

        key = (
            proto,
            sport,
            dip,
            dport,
        )

    elif dip == LOCAL_IP:

        key = (
            proto,
            dport,
            sip,
            sport,
        )

    else:
        return

    stats["bt_alerts"] += 1

    if attribute_bt(key):
        return

    pending_ts = time.time()
    pending_bt[key] = pending_ts
    pending_bt_expiry.append(
        (
            pending_ts + PENDING_BT_TTL,
            key,
            pending_ts,
        )
    )


# ============================================================
# CLEANUP
# ============================================================

def cleanup():

    now = time.time()

    # --------------------------------------------------------
    # Access events
    # --------------------------------------------------------

    while access_expiry and access_expiry[0][0] < now:
        _expires, key = access_expiry.popleft()
        dq = access_by_dest.get(key)

        if dq is None:
            continue

        if not dq:
            access_by_dest.pop(key, None)
            continue

        while dq and now - dq[0][0] > ACCESS_TTL:
            dq.popleft()

        if not dq:
            access_by_dest.pop(key, None)

    # --------------------------------------------------------
    # Requests
    # --------------------------------------------------------

    while request_expiry and request_expiry[0][0] < now:
        _expires, rid, created = request_expiry.popleft()
        req = requests.get(rid)

        if not req or req["created"] != created:
            continue

        key = (
            req["proto"],
            req["dest"],
        )

        dest_requests = requests_by_dest.get(key)

        if dest_requests is not None:
            dest_requests.discard(rid)

            if not dest_requests:
                requests_by_dest.pop(key, None)

        requests.pop(rid, None)
        opened.pop(rid, None)

    # --------------------------------------------------------
    # Orphan opens
    # --------------------------------------------------------

    while opened_expiry and opened_expiry[0][0] < now:
        _expires, rid, created = opened_expiry.popleft()
        op = opened.get(rid)

        if (
            op
            and op["created"] == created
            and rid not in requests
        ):
            opened.pop(rid, None)

    # --------------------------------------------------------
    # Socket ownership TTL
    # --------------------------------------------------------

    while socket_expiry and socket_expiry[0][0] < now:
        _expires, key, record = socket_expiry.popleft()
        dq = socket_owners.get(key)

        if dq is None:
            continue

        if not dq:
            socket_owners.pop(key, None)
            continue

        if dq[0] == record:
            dq.popleft()

        if not dq:
            socket_owners.pop(key, None)

    # --------------------------------------------------------
    # Pending BT alerts
    # --------------------------------------------------------

    while pending_bt_expiry and pending_bt_expiry[0][0] < now:
        _expires, key, pending_ts = pending_bt_expiry.popleft()

        if pending_bt.get(key) == pending_ts:
            pending_bt.pop(key, None)

    # --------------------------------------------------------
    # Evidence window
    # --------------------------------------------------------

    while hits_expiry and hits_expiry[0][0] < now:
        _expires, client, key, hit_ts = hits_expiry.popleft()
        client_hits = hits.get(client)

        if not client_hits:
            continue

        if client_hits.get(key) == hit_ts:
            client_hits.pop(key, None)

        if not client_hits:
            hits.pop(client, None)

    while announced_expiry and announced_expiry[0][0] < now:
        _expires, client, announced_ts = announced_expiry.popleft()

        if announced.get(client) == announced_ts:
            announced.pop(client, None)

    if SCAN_ENABLED:
        SCAN_DETECTOR.cleanup(now)


# ============================================================
# PRIVACY CLEANUP
# ============================================================

def privacy_cleanup():

    try:
        Path(
            SURI_LOG
        ).write_text("")

    except Exception:
        pass

    try:
        subprocess.run(
            [
                "docker",
                "exec",
                REMNANODE_CONTAINER,
                "sh",
                "-lc",
                ": > /dev/shm/xray-access.log; "
                ": > /dev/shm/xray-info.log",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

    except Exception:
        pass


# ============================================================
# STATS
# ============================================================

def print_stats():

    req = stats["requests"]
    mapped = stats["mapped_requests"]

    if req:

        mapped_pct = (
            mapped / req
        ) * 100

    else:

        mapped_pct = 0.0

    print(
        "[STATS] "
        f"req={req} "
        f"mapped={mapped} "
        f"mapped_pct={mapped_pct:.1f}% "
        f"bound={stats['bound_sockets']} "
        f"bt={stats['bt_alerts']} "
        f"exact={stats['bt_exact']} "
        f"scan={stats['scan_alerts']} "
        f"scan_clients={SCAN_DETECTOR.active_clients() if SCAN_ENABLED else 0} "
        f"pending={len(pending_bt)} "
        f"amb_req={stats['ambiguous_request']} "
        f"amb_sock={stats['ambiguous_socket']} "
        f"filtered_info={stats['filtered_info']} "
        f"filtered_access={stats['filtered_access']} "
        f"dropped={stats['queue_dropped']} "
        f"queue={events.qsize()}",
        flush=True,
    )


# ============================================================
# MAIN
# ============================================================

def main():
    if not LOCAL_IP:
        raise RuntimeError("EZHIK_LOCAL_IP is not configured")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print("================================================")
    print(f" EZHIK TORRENT GUARD v{APP_VERSION}")
    print(" MODE: " + ("DRY RUN" if DRY_RUN else "LIVE REMNAWAVE"))
    print()
    print(" Exact Xray socket <-> strict nDPI attribution")
    print(
        " Port-scan protection: "
        + (
            "DISABLED"
            if not SCAN_ENABLED
            else (
                "OBSERVE"
                if SCAN_DRY_RUN
                else "LIVE REMNAWAVE"
            )
        )
    )
    print()
    print(" Trigger: FIRST exact strict-nDPI BitTorrent socket")
    print()
    print(
        " Remnawave actions: "
        + (
            "ENABLED FOR AT LEAST ONE DETECTOR"
            if (
                not DRY_RUN
                or (
                    SCAN_ENABLED
                    and not SCAN_DRY_RUN
                )
            )
            else "DISABLED"
        )
    )
    print(" Developer: ezhikdev | Telegram: @ezhikdev")
    print(" GitHub: https://github.com/ezhikdev")
    print("================================================")
    print()

    actions_enabled = (
        not DRY_RUN
        or (
            SCAN_ENABLED
            and not SCAN_DRY_RUN
        )
    )

    if actions_enabled:
        remna_actions.start()

    if SCAN_ENABLED:
        telegram_notifier.start()

    start_readers()

    last_cleanup = time.time()
    last_stats = time.time()

    try:
        while running:
            try:
                source, line = events.get(timeout=0.5)

                if source == "access":
                    process_access(line)
                elif source == "info":
                    process_info(line)
                elif source == "suricata":
                    process_suricata(line)

            except queue.Empty:
                pass

            now = time.time()

            if now - last_cleanup >= 2:
                cleanup()
                last_cleanup = now

            if now - last_stats >= STATS_INTERVAL:
                print_stats()
                last_stats = now

    finally:
        print()
        print(
            f"Stopping Torrent Guard v{APP_VERSION}...",
            flush=True,
        )

        if SCAN_ENABLED:
            telegram_notifier.stop()

        if actions_enabled:
            remna_actions.stop()

        privacy_cleanup()

        print(
            "RAM connection logs truncated.",
            flush=True,
        )


if __name__ == "__main__":
    main()

"""Listening sockets on the host and who owns them.

Used by the firewall (what must stay reachable) and the Nginx manager
(port conflicts). RemnaNode runs in the host network namespace, so Xray and
the node API appear here with their process names.
"""

import re

from .util import run

ROLE_BY_PROCESS = {
    "sshd": "ssh",
    "xray": "xray",
    "rw-core": "xray",
    "nginx": "nginx",
    "node": "remnanode",
    "rw-node": "remnanode",  # RemnaNode 3.4+ renames its processes

    "docker-proxy": "docker",
}

_LINE_RE = re.compile(r"^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+(?:\s+users:\(\((.*)\)\))?")


def _address_scope(address):
    address = address.strip("[]")
    if address.startswith("%") or address in ("*", "0.0.0.0", "::"):
        return "any"
    if address.startswith("127.") or address == "::1":
        return "loopback"
    return "specific"


def listening():
    """Return [{proto, address, port, scope, process, role}] (deduplicated)."""
    result = run(["ss", "-H", "-l", "-n", "-t", "-u", "-p"], timeout=20)
    seen = {}
    for line in (result.stdout or "").splitlines():
        match = _LINE_RE.match(line.strip())
        if not match:
            continue
        proto, address, port, users = match.groups()
        process = ""
        if users:
            name = re.match(r'"([^"]+)"', users)
            process = name.group(1) if name else ""
        address = address.split("%")[0]
        key = (proto, address, int(port))
        if key in seen:
            continue
        seen[key] = {
            "proto": proto,
            "address": address.strip("[]"),
            "port": int(port),
            "scope": _address_scope(address),
            "process": process,
            "role": ROLE_BY_PROCESS.get(process, "other"),
        }
    return sorted(seen.values(), key=lambda x: (x["port"], x["proto"]))


def ipvs_services():
    """IPVS virtual services (e.g. EzhikLB UDP). They have no listening socket
    but their packets pass the INPUT hook before IPVS, so a firewall must allow them."""
    out = []
    for path, family in (("/proc/net/ip_vs", 4),):
        try:
            lines = open(path, encoding="ascii").read().splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("TCP", "UDP") and ":" in parts[1]:
                hexaddr, hexport = parts[1].split(":")[:2]
                try:
                    port = int(hexport, 16)
                    address = ".".join(str(int(hexaddr[i:i + 2], 16)) for i in (0, 2, 4, 6)) if len(hexaddr) == 8 else hexaddr
                except ValueError:
                    continue
                out.append({"proto": parts[0].lower(), "address": address, "port": port,
                            "scope": "specific", "process": "ipvs", "role": "ipvs"})
    return out


def ephemeral_range():
    try:
        low, high = open("/proc/sys/net/ipv4/ip_local_port_range", encoding="ascii").read().split()
        return int(low), int(high)
    except (OSError, ValueError):
        return 32768, 60999


def services():
    """Everything reachable from outside right now: sockets + IPVS.

    Xray's own unconnected UDP sockets in the kernel's ephemeral range are
    outbound relays, not services: they are skipped so the list stays stable
    and no random ports get opened. Xray inbound ports come from Remnawave.
    """
    low, high = ephemeral_range()
    items = [p for p in listening()
             if p["scope"] != "loopback"
             and not (p["proto"] == "udp" and p["role"] == "xray" and low <= p["port"] <= high)]
    return items + ipvs_services()


def ssh_ports():
    """sshd listening ports (anti-lockout); falls back to sshd -T and 22."""
    ports = {p["port"] for p in listening() if p["role"] == "ssh" and p["proto"] == "tcp"}
    if not ports:
        result = run(["sshd", "-T"], timeout=15)
        for line in (result.stdout or "").splitlines():
            if line.startswith("port "):
                try:
                    ports.add(int(line.split()[1]))
                except (IndexError, ValueError):
                    pass
    return sorted(ports or {22})


def public_ports(proto=None):
    return sorted({
        p["port"] for p in listening()
        if p["scope"] != "loopback" and (proto is None or p["proto"] == proto)
    })


def port_busy(port, proto="tcp", ignore_roles=()):
    for item in listening():
        if item["port"] == port and item["proto"] == proto and item["role"] not in ignore_roles:
            return item
    return None

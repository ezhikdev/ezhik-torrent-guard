"""Central firewall policy: global rules + per-node overrides + discovered ports."""

import ipaddress
import re
import socket
import time
import uuid
from urllib.parse import urlparse

from .db import loads

POLICIES = ("public", "whitelist", "closed")
ROLES = ("xray", "remnanode", "nginx", "ipvs", "docker", "other")
PORTS_RE = re.compile(r"^\s*\d{1,5}(\s*-\s*\d{1,5})?(\s*,\s*\d{1,5}(\s*-\s*\d{1,5})?)*\s*$")

DEFAULT_FIREWALL = {
    "enabled_default": False,
    "rules": [
        {"id": "ssh", "proto": "tcp", "ports": "22", "sources": [], "comment": "SSH", "enabled": True},
        {"id": "http", "proto": "tcp", "ports": "80", "sources": [], "comment": "HTTP", "enabled": True},
        {"id": "https", "proto": "tcp", "ports": "443", "sources": [], "comment": "HTTPS", "enabled": True},
    ],
    "auto": {"xray": "public", "remnanode": "whitelist", "nginx": "public", "ipvs": "public",
             "docker": "public", "other": "public"},
    "remnanode_sources": [],
    "icmp": True,
    "anti_lockout": True,
    "confirm_seconds": 90,
}

ROLE_LABEL = {"xray": "Xray inbound", "remnanode": "API RemnaNode", "nginx": "Nginx", "ipvs": "IPVS (балансировка)",
              "docker": "Docker (опубликован)", "other": "другой сервис", "panel": "Ezhik Guard панель"}


class FirewallError(ValueError):
    pass


def validate_rule(rule, require_id=True):
    out = {
        "id": str(rule.get("id") or uuid.uuid4().hex[:8])[:32],
        "proto": rule.get("proto") or "tcp",
        "ports": str(rule.get("ports") or "").replace(" ", ""),
        "sources": [],
        "comment": str(rule.get("comment") or "")[:60],
        "enabled": bool(rule.get("enabled", True)),
    }
    if out["proto"] not in ("tcp", "udp", "any"):
        raise FirewallError("протокол: tcp, udp или any")
    if not PORTS_RE.match(out["ports"]):
        raise FirewallError(f"порты {out['ports']!r}: например 443, 80,443 или 10000-10100")
    for part in out["ports"].split(","):
        bounds = [int(x) for x in part.split("-")]
        if any(not 1 <= b <= 65535 for b in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise FirewallError(f"недопустимый диапазон {part}")
    for source in rule.get("sources") or []:
        source = str(source).strip()
        if not source:
            continue
        try:
            out["sources"].append(str(ipaddress.ip_network(source, strict=False)))
        except ValueError:
            raise FirewallError(f"{source!r} не IP-адрес и не подсеть (CIDR)")
    return out


def validate_global(value, current):
    merged = {**DEFAULT_FIREWALL, **current, **{k: v for k, v in value.items() if k in DEFAULT_FIREWALL}}
    merged["rules"] = [validate_rule(r) for r in merged.get("rules") or []]
    auto = dict(DEFAULT_FIREWALL["auto"])
    for role, policy in (merged.get("auto") or {}).items():
        if role in auto and policy in POLICIES:
            auto[role] = policy
    merged["auto"] = auto
    merged["remnanode_sources"] = validate_rule({"ports": "1", "sources": merged.get("remnanode_sources")})["sources"]
    merged["enabled_default"] = bool(merged.get("enabled_default"))
    merged["icmp"] = bool(merged.get("icmp", True))
    merged["anti_lockout"] = bool(merged.get("anti_lockout", True))
    merged["confirm_seconds"] = max(30, min(600, int(merged.get("confirm_seconds") or 90)))
    return merged


def validate_node(value):
    value = value or {}
    out = {"enabled": value.get("enabled") if value.get("enabled") in (True, False) else None,
           "disabled_rules": [str(x)[:32] for x in value.get("disabled_rules") or []],
           "rules": [validate_rule(r) for r in value.get("rules") or []],
           "ports": {}}
    for key, policy in (value.get("ports") or {}).items():
        if re.fullmatch(r"(tcp|udp)/\d{1,5}", str(key)) and policy in POLICIES:
            out["ports"][key] = policy
    return out


_dns_cache = {}


def resolve_host(url, cached_only=False):
    host = urlparse(url or "").hostname
    if not host:
        return []
    cached = _dns_cache.get(host)
    if cached and (cached_only or time.time() - cached[0] < 600):
        return cached[1]
    if cached_only:
        return []
    try:
        ips = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except OSError:
        ips = []
    _dns_cache[host] = (time.time(), ips)
    return ips


UDP_NETWORKS = {"kcp", "mkcp", "quic", "hysteria", "hysteria2"}
BOTH_PROTOCOLS = {"shadowsocks", "dokodemo-door", "tunnel", "socks", "mixed"}


def inbound_protos(raw):
    """Transport protocols an Xray inbound listens on (from its raw config)."""
    protocol = str(raw.get("protocol") or "").lower()
    network = str((raw.get("streamSettings") or {}).get("network") or "raw").lower()
    if protocol in ("wireguard", "hysteria") or network in UDP_NETWORKS:
        return ("udp",)
    if protocol in BOTH_PROTOCOLS:
        declared = str((raw.get("settings") or {}).get("network") or "tcp,udp").lower()
        return tuple(p for p in ("tcp", "udp") if p in declared) or ("tcp", "udp")
    return ("tcp",)


def plan(node, global_cfg, report, remnawave_url=None, remnanode_port=None, nginx_ports=(), inbound_ports=(),
         internal_ports=()):
    """Return (agent_config, table_for_ui) for one node.

    ``inbound_ports``: ports (or (port, protos) pairs) of non-loopback Xray
    inbounds known from Remnawave. ``internal_ports``: TCP ports Nginx proxies
    to locally; they stay closed from outside unless overridden.
    """
    override = validate_node(loads(node.get("firewall"), {}) or {})
    enabled = override["enabled"] if override["enabled"] is not None else global_cfg["enabled_default"]
    rules = [r for r in global_cfg["rules"] if r["enabled"] and r["id"] not in override["disabled_rules"]]
    rules += [r for r in override["rules"] if r["enabled"]]
    snapshot = (report or {}).get("ports") or {}
    whitelist = sorted(set(resolve_host(remnawave_url, cached_only=True)) | set(global_cfg["remnanode_sources"]))
    entries, auto_rules = [], []

    def add(proto, port, role, process, policy, origin):
        key = f"{proto}/{port}"
        entries.append({"key": key, "proto": proto, "port": port, "role": role, "label": ROLE_LABEL.get(role, role),
                        "process": process, "policy": policy, "origin": origin})
        if policy == "public":
            auto_rules.append({"proto": proto, "ports": str(port), "sources": [], "comment": f"auto {role}"})
        elif policy == "whitelist" and whitelist:
            auto_rules.append({"proto": proto, "ports": str(port), "sources": whitelist, "comment": f"auto {role} whitelist"})

    seen = set()
    for port in snapshot.get("panel_ports") or []:
        seen.add(f"tcp/{port}")
        add("tcp", port, "panel", "ezhik-guard", "public", "панель на этой ноде")
    for port in nginx_ports:
        if f"tcp/{port}" not in seen:
            seen.add(f"tcp/{port}")
            add("tcp", port, "nginx", "nginx", override["ports"].get(f"tcp/{port}", "public"), "Nginx frontend")
    ssh = set(snapshot.get("ssh") or [])
    # Xray inbounds known from Remnawave (covers UDP inbounds whose sockets
    # look like ephemeral ones and inbounds of a container still starting).
    internal = {int(p) for p in internal_ports}
    inbound_map = {}
    for item in inbound_ports:
        port, protos = (item, ("tcp", "udp")) if isinstance(item, int) else item
        inbound_map.setdefault(int(port), set()).update(protos)
    for port in sorted(inbound_map):
        for proto in ("tcp", "udp"):
            key = f"{proto}/{port}"
            if proto in inbound_map[port] and key not in seen and not (proto == "tcp" and port in ssh):
                seen.add(key)
                if proto == "tcp" and port in internal:
                    add(proto, port, "xray", "xray", override["ports"].get(key) or "closed", "внутренний (за Nginx)")
                else:
                    add(proto, port, "xray", "xray", override["ports"].get(key) or global_cfg["auto"]["xray"],
                        "Remnawave inbound")
    for item in snapshot.get("services") or []:
        key = f"{item['proto']}/{item['port']}"
        if key in seen or (item["proto"] == "tcp" and item["port"] in ssh):
            continue
        seen.add(key)
        role = item.get("role") or "other"
        if remnanode_port and item["port"] == remnanode_port and item["proto"] == "tcp":
            role = "remnanode"
        if role not in ROLES:
            role = "other"
        behind_nginx = item["proto"] == "tcp" and item["port"] in internal
        policy = override["ports"].get(key) or ("closed" if behind_nginx else global_cfg["auto"][role])
        add(item["proto"], item["port"], role, item.get("process") or "", policy,
            "настройка ноды" if key in override["ports"] else
            "внутренний (за Nginx)" if behind_nginx else "автоматически")
    # Never enforce before the node reported what is listening: Xray ports
    # would be closed and every VPN connection on the node would drop.
    known = "services" in snapshot
    cfg = {
        "enabled": bool(enabled) and known,
        "rules": [{k: r[k] for k in ("proto", "ports", "sources", "comment")} for r in rules] + auto_rules,
        "icmp": global_cfg["icmp"],
        "anti_lockout": global_cfg["anti_lockout"],
        "confirm_seconds": global_cfg["confirm_seconds"],
    }
    warnings = []
    if any(e["policy"] == "whitelist" for e in entries) and not whitelist:
        warnings.append("Белый список пуст: укажите Remnawave или IP в «Firewall → Белый список» — иначе порты закроются.")
    if enabled and not known:
        warnings.append("Агент ещё не прислал список портов — firewall включится после первой синхронизации.")
    return cfg, {"enabled": bool(enabled), "entries": entries, "rules": rules, "whitelist": whitelist,
                 "ssh": sorted(ssh), "warnings": warnings, "override": override}

"""Inbound firewall managed by the panel.

Design:
* One own nftables table ``inet ezhik_guard``. Other tables (Docker,
  iptables-nft, fail2ban, ufw, EzhikLB) are never modified. A drop in any
  base chain is final, so our table can only add restrictions on top of them.
* input: policy drop; established/related, loopback, essential ICMP/ICMPv6,
  SSH (anti-lockout) and the rules from the panel are accepted.
* forward: new connections DNAT-ed into Docker bridges (published container
  ports) must match an allowed port; everything else forwarded is untouched.
* Every change is atomic (one ``nft -f`` transaction) and guarded by a
  dead-man switch: a systemd timer restores the previous table after
  ``confirm_seconds`` unless the agent proves it still reaches the panel.
"""

import hashlib
import ipaddress
import logging
import re
import threading
import time

from . import paths, ports
from .util import atomic_write, run

log = logging.getLogger("ezhik.firewall")

TABLE = "ezhik_guard"
ROLLBACK_UNIT = "ezhik-guard-fw-rollback"
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


class FirewallError(RuntimeError):
    pass


def _ports(spec):
    out = []
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        if not PORTS_RE.match(part):
            raise FirewallError(f"invalid port {part!r}")
        bounds = [int(x) for x in part.split("-")]
        if any(not 1 <= b <= 65535 for b in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise FirewallError(f"invalid port range {part!r}")
        out.append(part)
    if not out:
        raise FirewallError("empty port list")
    return "{ " + ", ".join(out) + " }"


def _sources(values):
    v4, v6 = [], []
    for value in values or []:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


def render(cfg):
    """Build the full table definition (deterministic text)."""
    lines = [
        f"table inet {TABLE} {{",
        "  chain input {",
        "    type filter hook input priority filter + 10; policy drop;",
        "    ct state established,related accept",
        "    ct state invalid drop",
        '    iifname "lo" accept',
    ]
    if cfg.get("icmp", True):
        lines += [
            "    icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept",
            "    icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem,"
            " nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query } accept",
        ]
    else:
        # Neighbour discovery is required for IPv6 to work at all.
        lines.append("    icmpv6 type { packet-too-big, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept")
    if cfg.get("anti_lockout", True):
        ssh = cfg.get("ssh_ports") or [22]
        lines.append(f'    tcp dport {_ports(",".join(map(str, ssh)))} accept comment "ssh anti-lockout"')
    forward = []
    for rule in cfg.get("rules") or []:
        port_set = _ports(rule["ports"])
        protos = ["tcp", "udp"] if rule.get("proto", "tcp") in ("any", "both") else [rule.get("proto", "tcp")]
        comment = re.sub(r'[^\w .:/@()-]', "", str(rule.get("comment") or ""))[:60]
        v4, v6 = _sources(rule.get("sources"))
        for proto in protos:
            if proto not in ("tcp", "udp"):
                raise FirewallError(f"invalid protocol {proto}")
            tail = f'{proto} dport {port_set} accept' + (f' comment "{comment}"' if comment else "")
            if not v4 and not v6:
                lines.append(f"    {tail}")
            if v4:
                lines.append(f"    ip saddr {{ {', '.join(v4)} }} {tail}")
            if v6:
                lines.append(f"    ip6 saddr {{ {', '.join(v6)} }} {tail}")
            forward.append((proto, port_set, v4, v6))
    lines += ['    counter comment "ezhik-guard dropped"', "  }"]
    lines += [
        "  chain forward {",
        "    type filter hook forward priority filter + 10; policy accept;",
        "    ct state established,related accept",
    ]
    if cfg.get("docker_forward", True):
        # One rule per bridge pattern: nft 1.0.x cannot mix wildcard interface
        # names inside an anonymous set.
        for iface in ("docker0", "br-*"):
            for proto, port_set, v4, v6 in forward:
                base = (f'ct status dnat ct state new oifname "{iface}" meta l4proto {proto} '
                        f'ct original proto-dst {port_set}')
                if not v4 and not v6:
                    lines.append(f"    {base} accept")
                if v4:
                    lines.append(f"    ip saddr {{ {', '.join(v4)} }} {base} accept")
                if v6:
                    lines.append(f"    ip6 saddr {{ {', '.join(v6)} }} {base} accept")
            lines.append(f'    ct status dnat ct state new oifname "{iface}" counter drop comment "ezhik-guard docker"')
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def current():
    result = run(["nft", "list", "table", "inet", TABLE], timeout=20)
    return result.stdout if result.returncode == 0 else None


def _transaction(definition):
    """Replace our table atomically (works whether or not it exists)."""
    body = f"add table inet {TABLE}\ndelete table inet {TABLE}\n"
    return body + (definition or "")


def _nft_file(text, check=False):
    path = paths.STATE_DIR / ("fw-check.nft" if check else "fw-apply.nft")
    atomic_write(path, text, 0o600)
    result = run(["nft", "-c", "-f", str(path)] if check else ["nft", "-f", str(path)], timeout=30)
    if result.returncode != 0:
        raise FirewallError((result.stderr or result.stdout or "nft failed").strip()[:600])


class Firewall:
    def __init__(self, verify):
        self.verify = verify          # callable() -> bool: can we still reach the panel?
        self._fallback_timer = None

    # dead-man switch -------------------------------------------------

    def _arm(self, restore_path, seconds):
        self._disarm()
        result = run(["systemd-run", "--unit", ROLLBACK_UNIT, "--collect", f"--on-active={int(seconds)}s",
                      "/usr/sbin/nft", "-f", str(restore_path)], timeout=20)
        if result.returncode != 0:
            # No systemd (containers/tests): an in-process timer still protects
            # against a hung verification, not against the agent dying.
            self._fallback_timer = threading.Timer(seconds, lambda: run(["nft", "-f", str(restore_path)]))
            self._fallback_timer.daemon = True
            self._fallback_timer.start()

    def _disarm(self):
        for unit in (f"{ROLLBACK_UNIT}.timer", f"{ROLLBACK_UNIT}.service"):
            run(["systemctl", "stop", unit], timeout=20)
        run(["systemctl", "reset-failed", f"{ROLLBACK_UNIT}.timer", f"{ROLLBACK_UNIT}.service"], timeout=20)
        if self._fallback_timer:
            self._fallback_timer.cancel()
            self._fallback_timer = None

    # apply -------------------------------------------------------------

    def apply(self, cfg, state):
        """Converge to cfg. Returns a status message; raises on failure."""
        if not cfg or not cfg.get("enabled"):
            if current() is None:
                return "disabled"
            backup = current()
            atomic_write(paths.STATE_DIR / "fw-backup.nft", backup, 0o600)
            _nft_file(f"add table inet {TABLE}\ndelete table inet {TABLE}\n")
            state.pop("firewall_hash", None)
            return "disabled (rules removed)"

        cfg = dict(cfg)
        cfg["ssh_ports"] = sorted(set(cfg.get("ssh_ports") or []) | set(ports.ssh_ports()))
        definition = render(cfg)
        digest = hashlib.sha256(definition.encode()).hexdigest()[:16]
        live = current()
        if live is not None and state.get("firewall_hash") == digest:
            return "active"

        _nft_file(_transaction(definition), check=True)
        restore = paths.STATE_DIR / "fw-restore.nft"
        atomic_write(restore, _transaction(live), 0o600)
        atomic_write(paths.STATE_DIR / "fw-backup.nft", live or "", 0o600)
        seconds = max(30, int(cfg.get("confirm_seconds") or 90))
        self._arm(restore, seconds)
        try:
            _nft_file(_transaction(definition))
            ok = False
            for _ in range(3):
                time.sleep(2)
                if self.verify():
                    ok = True
                    break
            if not ok:
                raise FirewallError("после применения правил нет связи с панелью — правила откатаны")
        except Exception:
            try:
                _nft_file(_transaction(live))
            finally:
                self._disarm()
            raise
        self._disarm()
        state["firewall_hash"] = digest
        log.info("Firewall applied (%d rules)", len(cfg.get("rules") or []))
        return "active"

    def counters(self):
        text = current() or ""
        dropped = re.search(r'counter packets (\d+) bytes \d+ comment "ezhik-guard dropped"', text)
        return {"dropped_packets": int(dropped.group(1)) if dropped else 0}

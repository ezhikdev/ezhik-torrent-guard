"""Detection and clean removal of previous installations.

Torrent Guard 1.x (installed by its own install.sh) and the Ezhik Cert
Manager agent are replaced by this agent. Only objects those installers
created are touched; unrelated services, packages and firewall rules are
left alone. Configuration and sanction state are archived first and active
1.x sanctions are handed over to the panel so they still auto-expire.
"""

import io
import json
import logging
import re
import shutil
import tarfile
import time

from . import paths
from .util import read_json, run

log = logging.getLogger("ezhik.legacy")

LEGACY_UNITS = (
    "ezhik-torrent-guard.service",
    "ezhik-ram-log-guard.service",
    "ezhik-suricata.service",
    "ezhik-cert-agent.service",
)
LEGACY_UNIT_FILES = (
    "/etc/systemd/system/ezhik-torrent-guard.service",
    "/etc/systemd/system/ezhik-ram-log-guard.service",
    "/etc/systemd/system/ezhik-suricata.service",
    "/etc/systemd/system/ezhik-cert-agent.service",
)
LEGACY_DIRS = (
    "/etc/systemd/system/ezhik-torrent-guard.service.d",
    "/opt/ezhik-torrent-guard",
    "/opt/ezhik-torrent-guard-build",
    "/opt/ezhik-cert-agent",
)
LEGACY_FILES = (
    "/usr/local/sbin/ezhik-ram-log-guard.sh",
    "/usr/local/sbin/ezhik-torrent-guard-cleanup.sh",
    "/dev/shm/ezhik-suricata-fast.log",
    "/var/log/ezhik-torrent-guard-install.log",
)
# Archived, then removed.
LEGACY_CONFIG_DIRS = (
    "/etc/ezhik-torrent-guard",
    "/var/lib/ezhik-torrent-guard",
    "/etc/ezhik-cert-agent",
)
OWNED_MARKER = ".ezhik-guard-owned"
FIREWALL_MARKERS = re.compile(r"ezhik[-_ ]?(torrent|guard|suricata)", re.I)


def _exists(path):
    target = paths.p(path)
    return target.exists() or target.is_symlink()


def legacy_runtime_dirs():
    base = paths.p("/opt")
    if not base.exists():
        return []
    return sorted(
        "/" + d.relative_to(paths.ROOT).as_posix()
        for d in base.glob("ezhik-suricata-*")
        if d.is_dir() and not (d / OWNED_MARKER).exists()
    )


def detect():
    found = {
        "units": [u for u, f in zip(LEGACY_UNITS, LEGACY_UNIT_FILES) if _exists(f)],
        "paths": [p for p in LEGACY_DIRS + LEGACY_FILES + LEGACY_CONFIG_DIRS if _exists(p)],
        "runtimes": legacy_runtime_dirs(),
        "version": None,
        "cert_agent": _exists("/etc/systemd/system/ezhik-cert-agent.service") or _exists("/opt/ezhik-cert-agent"),
    }
    version_file = paths.p("/opt/ezhik-torrent-guard/VERSION")
    if version_file.exists():
        found["version"] = version_file.read_text(encoding="utf-8").strip()[:20]
    found["present"] = bool(found["units"] or found["paths"] or found["runtimes"])
    return found


def read_sanctions():
    """Active Torrent Guard 1.x sanctions that still need an auto-unfreeze."""
    data = read_json(paths.p("/var/lib/ezhik-torrent-guard/sanctions.json"), {}) or {}
    sanctions = data.get("sanctions") if isinstance(data, dict) else None
    out = []
    for client, rec in (sanctions or {}).items():
        if not str(client).isdigit() or not isinstance(rec, dict):
            continue
        out.append({
            "client_id": str(client),
            "legacy_uuid": rec.get("uuid"),
            "disabled_at": rec.get("disabled_at"),
            "unfreeze_at": rec.get("unfreeze_at"),
            "reason": rec.get("reason", "bittorrent"),
        })
    return out


def read_settings():
    """Non-secret 1.x settings, offered to the panel as a migration hint."""
    settings = {}
    try:
        for line in paths.p("/etc/ezhik-torrent-guard/settings.env").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                settings[key.strip()] = value.strip()
    except OSError:
        pass
    keep = ("EZHIK_PROTECTED_CLIENTS", "EZHIK_FREEZE_SECONDS", "EZHIK_DRY_RUN", "EZHIK_SCAN_ENABLED",
            "EZHIK_SCAN_DRY_RUN", "EZHIK_SCAN_BLOCK_SECONDS", "EZHIK_REMNANODE_CONTAINER")
    return {k: settings[k] for k in keep if k in settings}


def archive_configs():
    present = [d for d in LEGACY_CONFIG_DIRS if _exists(d)]
    if not present:
        return None
    paths.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    target = paths.BACKUP_DIR / f"legacy-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for directory in present:
            archive.add(paths.p(directory), arcname=directory.lstrip("/"))
    target.write_bytes(buffer.getvalue())
    target.chmod(0o600)
    return str(target)


def _kill_container_tails(container):
    script = (
        'for P in /proc/[0-9]*; do [ -r "$P/comm" ] || continue; '
        '[ "$(cat "$P/comm" 2>/dev/null)" = "tail" ] || continue; '
        'CMD=$(tr "\\000" " " < "$P/cmdline" 2>/dev/null); '
        'case "$CMD" in *"/dev/shm/xray-access.log"*|*"/dev/shm/xray-info.log"*) '
        'kill "${P##*/}" 2>/dev/null || true ;; esac; done'
    )
    run(["docker", "exec", container, "sh", "-c", script], timeout=15)


def remove_firewall_leftovers():
    """Delete only iptables/nft objects explicitly named or commented as ezhik guard."""
    removed = []
    for tool in ("iptables", "ip6tables"):
        dump = run([f"{tool}-save"], timeout=30)
        if dump.returncode != 0:
            continue
        table = None
        for line in dump.stdout.splitlines():
            if line.startswith("*"):
                table = line[1:].strip()
            elif line.startswith("-A ") and FIREWALL_MARKERS.search(line):
                args = line[3:].split()
                result = run([tool, "-t", table, "-D", *args], timeout=30)
                if result.returncode == 0:
                    removed.append(f"{tool}:{table}:{line[:80]}")
    nft = run(["nft", "-j", "list", "tables"], timeout=30)
    if nft.returncode == 0:
        try:
            for item in json.loads(nft.stdout).get("nftables", []):
                table = item.get("table")
                if table and FIREWALL_MARKERS.search(table.get("name", "")):
                    run(["nft", "delete", "table", table["family"], table["name"]], timeout=30)
                    removed.append(f"nft:{table['family']}:{table['name']}")
        except ValueError:
            pass
    return removed


def remove(container="remnanode", keep_runtime=None):
    """Stop and delete every legacy component. Returns a report."""
    report = {"backup": None, "removed": [], "firewall": [], "errors": []}
    try:
        report["backup"] = archive_configs()
    except Exception as exc:
        report["errors"].append(f"backup: {exc}")
        # Without a backup the sanction state could be lost: keep config dirs.
        log.error("Legacy backup failed; configuration will be preserved: %s", exc)

    for unit in LEGACY_UNITS:
        run(["systemctl", "disable", "--now", unit], timeout=90)
    _kill_container_tails(container)

    for path in LEGACY_UNIT_FILES + LEGACY_FILES:
        target = paths.p(path)
        if target.exists() or target.is_symlink():
            try:
                target.unlink()
                report["removed"].append(path)
            except OSError as exc:
                report["errors"].append(f"{path}: {exc}")
    removable_dirs = list(LEGACY_DIRS)
    if report["backup"]:
        removable_dirs += list(LEGACY_CONFIG_DIRS)
    for runtime in legacy_runtime_dirs():
        if runtime != keep_runtime:
            removable_dirs.append(runtime)
            removable_dirs.append(runtime + ".previous")
    for path in removable_dirs:
        target = paths.p(path)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            if target.exists():
                report["errors"].append(f"{path}: not removed")
            else:
                report["removed"].append(path)

    report["firewall"] = remove_firewall_leftovers()
    run(["systemctl", "daemon-reload"], timeout=60)
    run(["systemctl", "reset-failed"], timeout=60)
    log.info("Legacy cleanup: removed=%d errors=%d backup=%s",
             len(report["removed"]), len(report["errors"]), report["backup"])
    return report

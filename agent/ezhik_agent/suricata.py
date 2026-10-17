"""Suricata + strict nDPI runtime management on a node.

The runtime is a prebuilt, verified archive (see scripts/build-runtime.sh).
The panel caches it from GitHub Releases and serves it to nodes; the archive
SHA-256 comes from the panel over the authenticated agent channel.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import time
from pathlib import Path

from . import paths, system
from .util import CommandError, atomic_write, read_json, run

log = logging.getLogger("ezhik.suricata")

RULE = (
    'alert ip any any -> any any (msg:"EZHIK nDPI BitTorrent flow"; '
    "ndpi-protocol:BitTorrent; flowbits:isnotset,ezhik_bt_seen; "
    "flowbits:set,ezhik_bt_seen; sid:9900010; rev:3;)\n"
)

UNIT_TEMPLATE = """[Unit]
Description=Ezhik Guard passive BitTorrent sensor (Suricata + strict nDPI)
After=network-online.target
Wants=network-online.target
PartOf=ezhik-guard-agent.service

[Service]
Type=simple
ExecStartPre=/bin/sh -c ': > {fast_log}; chmod 600 {fast_log}'
ExecStart={binary} -c {config} --af-packet={interface} -S {rules}
Restart=always
RestartSec=3
KillSignal=SIGINT
TimeoutStopSec=20
Nice=5
CPUWeight=50

[Install]
WantedBy=multi-user.target
"""

# Ubuntu 24.04 renamed many libraries during the 64-bit time_t transition.
T64_RENAMES = {
    "libpcap0.8": "libpcap0.8t64",
    "libmagic1": "libmagic1t64",
    "libnet1": "libnet1",
    "libcap2": "libcap2",
}


class RuntimeError_(RuntimeError):
    pass


def runtime_prefix(engine):
    return paths.p(engine["runtime_prefix"])


def installed_engine(engine):
    manifest = read_json(runtime_prefix(engine) / "ezhik-runtime-manifest.json", {}) or {}
    return manifest.get("engine_id")


def binary(engine):
    return runtime_prefix(engine) / "bin" / "suricata"


def plugin(engine):
    return runtime_prefix(engine) / "lib" / "ezhik" / "ndpi.so"


def is_installed(engine):
    return (
        installed_engine(engine) == engine["engine_id"]
        and (runtime_prefix(engine) / ".ezhik-guard-owned").is_file()
        and binary(engine).is_file()
        and plugin(engine).is_file()
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_members(archive):
    for member in archive.getmembers():
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise RuntimeError_(f"runtime archive contains unsafe path: {name}")
        if member.issym() or member.islnk():
            # Library symlinks inside the prefix are plain relative names.
            target = member.linkname
            if target.startswith("/") or ".." in Path(target).parts:
                raise RuntimeError_(f"runtime archive contains unsafe link: {name}")
        if member.isdev():
            raise RuntimeError_(f"runtime archive contains a device file: {name}")
        # The archive records the build user's uid (e.g. 1001). Files executed
        # by root must never be owned by an arbitrary local account.
        member.uid = member.gid = 0
        member.uname = member.gname = "root"
        member.mode &= 0o755  # no setuid, no group/other write
    return archive.getmembers()


def extract_zst(archive_path, destination):
    """Extract .tar.zst through the system zstd binary (stdlib has no zstd)."""
    destination.mkdir(parents=True, exist_ok=True)
    tar_path = destination.parent / (destination.name + ".tar")
    result = run(["zstd", "-d", "-q", "-f", str(archive_path), "-o", str(tar_path)], timeout=600)
    if result.returncode != 0:
        raise RuntimeError_(f"cannot decompress runtime: {result.stderr.strip()[:300]}")
    try:
        with tarfile.open(tar_path) as archive:
            members = _safe_members(archive)
            try:
                archive.extractall(destination, members=members, filter="fully_trusted")
            except TypeError:  # Python without extraction filters
                archive.extractall(destination, members=members)
    finally:
        tar_path.unlink(missing_ok=True)


def resolve_packages(names):
    """Map manifest package names onto what exists in this Ubuntu release."""
    resolved, missing = [], []
    for name in names:
        candidates = [name]
        renamed = T64_RENAMES.get(name)
        if renamed and renamed != name:
            candidates.append(renamed)
        if name.endswith("t64"):
            candidates.append(name[:-3])
        else:
            candidates.append(name + "t64")
        for candidate in candidates:
            if system.package_available(candidate):
                resolved.append(candidate)
                break
        else:
            missing.append(name)
    return resolved, missing


def install(engine, archive_path, os_version, progress=None):
    """Install a downloaded runtime archive. Raises on any validation failure."""
    progress = progress or (lambda stage: None)
    expected = engine["sha256"].lower()
    progress("verifying")
    actual = sha256_file(archive_path)
    if actual != expected:
        raise RuntimeError_(f"runtime checksum mismatch: expected {expected[:12]}, got {actual[:12]}")

    progress("extracting")
    staging = paths.DOWNLOAD_DIR / "runtime-staging"
    shutil.rmtree(staging, ignore_errors=True)
    extract_zst(archive_path, staging)

    manifest = read_json(staging / "runtime-manifest.json", {}) or {}
    if manifest.get("engine_id") != engine["engine_id"]:
        raise RuntimeError_(f"runtime manifest engine {manifest.get('engine_id')} != {engine['engine_id']}")
    if manifest.get("runtime_prefix") != engine["runtime_prefix"]:
        raise RuntimeError_("runtime prefix mismatch")
    staged_prefix = staging / engine["runtime_prefix"].lstrip("/")
    if not (staged_prefix / "bin" / "suricata").is_file():
        raise RuntimeError_("runtime archive has no suricata binary")

    progress("dependencies")
    packages, missing = resolve_packages(manifest.get("runtime_packages") or [])
    if missing:
        log.warning("Runtime packages unknown on this OS, relying on ldd check: %s", ", ".join(missing))
    system.ensure_packages(packages)
    for target in (staged_prefix / "bin" / "suricata", staged_prefix / "lib" / "ezhik" / "ndpi.so"):
        unresolved = system.missing_libraries(target)
        if unresolved:
            raise RuntimeError_(
                f"Ubuntu {os_version}: missing shared libraries for {target.name}: {', '.join(unresolved)}"
            )

    progress("activating")
    final = runtime_prefix(engine)
    backup = final.with_name(final.name + ".previous")
    shutil.rmtree(backup, ignore_errors=True)
    if final.exists():
        os.replace(final, backup)
    try:
        final.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staged_prefix), str(final))
        (final / ".ezhik-guard-owned").write_text(engine["engine_id"] + "\n", encoding="utf-8")
        result = run([str(binary(engine)), "--build-info"], timeout=30)
        if result.returncode != 0:
            raise RuntimeError_(f"suricata --build-info failed: {result.stderr.strip()[:300]}")
    except Exception:
        shutil.rmtree(final, ignore_errors=True)
        if backup.exists():
            os.replace(backup, final)
        raise
    shutil.rmtree(backup, ignore_errors=True)
    shutil.rmtree(staging, ignore_errors=True)
    log.info("Suricata runtime %s installed", engine["engine_id"])


def render_config(engine, interface, wan_ip):
    """Render the passive RAM-only config next to the agent (needs python3-yaml)."""
    import yaml  # system package python3-yaml; imported lazily

    source = runtime_prefix(engine) / "etc" / "suricata" / "suricata.yaml"
    with source.open("r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle)
    if not isinstance(cfg, dict):
        raise RuntimeError_("invalid stock suricata.yaml")

    etc = runtime_prefix(engine) / "etc" / "suricata"
    fast_log = str(paths.SURICATA_FAST_LOG)
    cfg["plugins"] = [str(plugin(engine))]
    cfg["default-log-dir"] = str(Path(fast_log).parent)
    cfg["classification-file"] = str(etc / "classification.config")
    cfg["reference-config-file"] = str(etc / "reference.config")
    if (etc / "threshold.config").is_file():
        cfg["threshold-file"] = str(etc / "threshold.config")
    cfg["af-packet"] = [
        {
            "interface": interface,
            "threads": 1,
            "cluster-id": 98,
            "cluster-type": "cluster_flow",
            "defrag": False,
            "tpacket-v3": True,
            "bpf-filter": f"src host {wan_ip}",
        }
    ]
    if isinstance(cfg.get("stats"), dict):
        cfg["stats"]["enabled"] = False

    outputs = cfg.get("outputs")
    if not isinstance(outputs, list):
        outputs = []
    cleaned = [{"fast": {"enabled": True, "filename": fast_log, "append": True}}]
    for item in outputs:
        if not isinstance(item, dict) or "fast" in item:
            continue
        for value in item.values():
            if isinstance(value, dict):
                value["enabled"] = False
        cleaned.append(item)
    cfg["outputs"] = cleaned

    logging_cfg = cfg.get("logging")
    if isinstance(logging_cfg, dict) and isinstance(logging_cfg.get("outputs"), list):
        for item in logging_cfg["outputs"]:
            if isinstance(item, dict):
                if isinstance(item.get("file"), dict):
                    item["file"]["enabled"] = False
                if isinstance(item.get("console"), dict):
                    item["console"]["enabled"] = True
                if isinstance(item.get("syslog"), dict):
                    item["syslog"]["enabled"] = False

    rendered = "%YAML 1.1\n---\n" + yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False)
    atomic_write(paths.SURICATA_CONFIG, rendered, 0o644)
    atomic_write(paths.SURICATA_RULES, RULE, 0o644)


def test_config(engine):
    result = run([str(binary(engine)), "-T", "-c", str(paths.SURICATA_CONFIG), "-S", str(paths.SURICATA_RULES)], timeout=120)
    if result.returncode != 0:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-6:])
        raise RuntimeError_(f"suricata -T failed: {tail[:600]}")


def write_unit(engine, interface):
    unit = UNIT_TEMPLATE.format(
        binary=binary(engine),
        config=paths.SURICATA_CONFIG,
        interface=interface,
        rules=paths.SURICATA_RULES,
        fast_log=paths.SURICATA_FAST_LOG,
    )
    target = paths.SYSTEMD_DIR / paths.SURICATA_UNIT
    current = target.read_text(encoding="utf-8") if target.exists() else None
    if current != unit:
        atomic_write(target, unit, 0o644)
        system.systemctl("daemon-reload")
        return True
    return False


def config_fingerprint(engine, interface, wan_ip):
    payload = json.dumps([engine["engine_id"], interface, wan_ip, RULE, UNIT_TEMPLATE], sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def ensure_running(engine, interface, wan_ip, state):
    """Idempotently configure and start the sensor."""
    fingerprint = config_fingerprint(engine, interface, wan_ip)
    changed = False
    if state.get("suricata_fingerprint") != fingerprint or not paths.SURICATA_CONFIG.exists():
        render_config(engine, interface, wan_ip)
        test_config(engine)
        changed = True
    changed = write_unit(engine, interface) or changed
    if changed:
        system.systemctl("enable", paths.SURICATA_UNIT, check=True)
        system.systemctl("restart", paths.SURICATA_UNIT, check=True)
        state["suricata_fingerprint"] = fingerprint
    elif not system.unit_active(paths.SURICATA_UNIT):
        system.systemctl("start", paths.SURICATA_UNIT, check=True)
    for _ in range(10):
        if system.unit_active(paths.SURICATA_UNIT):
            return
        time.sleep(1)
    raise RuntimeError_("ezhik-guard-suricata.service is not active: " + system.unit_failure_hint(paths.SURICATA_UNIT))


def stop():
    if (paths.SYSTEMD_DIR / paths.SURICATA_UNIT).exists():
        system.systemctl("disable", "--now", paths.SURICATA_UNIT)
    try:
        paths.SURICATA_FAST_LOG.write_text("")
    except OSError:
        pass


def version_string(engine):
    result = run([str(binary(engine)), "-V"], timeout=10)
    match = re.search(r"version\s+(\S+)", result.stdout or "")
    return match.group(1) if match else None


def remove_all():
    stop()
    (paths.SYSTEMD_DIR / paths.SURICATA_UNIT).unlink(missing_ok=True)
    shutil.rmtree(paths.SURICATA_CONFIG_DIR, ignore_errors=True)


__all__ = ["CommandError"]

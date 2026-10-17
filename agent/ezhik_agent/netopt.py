"""TCP BBR congestion control (per-node switch)."""

from . import paths
from .util import atomic_write, read_json, run, write_json

SYSCTL_FILE = paths.p("/etc/sysctl.d/99-ezhik-guard-bbr.conf")
SAVED = paths.STATE_DIR / "bbr-previous.json"
CONTENT = "# Managed by Ezhik Guard\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"


def _get(key):
    result = run(["sysctl", "-n", key], timeout=10)
    return result.stdout.strip() if result.returncode == 0 else None


def status():
    return {"congestion": _get("net.ipv4.tcp_congestion_control"), "qdisc": _get("net.core.default_qdisc"),
            "available": _get("net.ipv4.tcp_available_congestion_control")}


def apply(enabled):
    if enabled:
        if not SAVED.exists():
            write_json(SAVED, {"congestion": _get("net.ipv4.tcp_congestion_control"),
                               "qdisc": _get("net.core.default_qdisc")})
        if "bbr" not in (_get("net.ipv4.tcp_available_congestion_control") or ""):
            run(["modprobe", "tcp_bbr"], timeout=20)
            if "bbr" not in (_get("net.ipv4.tcp_available_congestion_control") or ""):
                raise RuntimeError("ядро не поддерживает BBR (модуль tcp_bbr недоступен)")
        atomic_write(paths.p("/etc/modules-load.d/ezhik-guard-bbr.conf"), "tcp_bbr\n", 0o644)
        atomic_write(SYSCTL_FILE, CONTENT, 0o644)
        run(["sysctl", "-w", "net.core.default_qdisc=fq"], timeout=10)
        result = run(["sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"], timeout=10)
        if result.returncode != 0 or _get("net.ipv4.tcp_congestion_control") != "bbr":
            raise RuntimeError("не удалось включить BBR: " + (result.stderr or "").strip()[:200])
        return "BBR включён"
    if SYSCTL_FILE.exists():
        SYSCTL_FILE.unlink()
        paths.p("/etc/modules-load.d/ezhik-guard-bbr.conf").unlink(missing_ok=True)
        previous = read_json(SAVED, {}) or {}
        if previous.get("congestion"):
            run(["sysctl", "-w", f"net.ipv4.tcp_congestion_control={previous['congestion']}"], timeout=10)
        if previous.get("qdisc"):
            run(["sysctl", "-w", f"net.core.default_qdisc={previous['qdisc']}"], timeout=10)
        SAVED.unlink(missing_ok=True)
        return "BBR выключен, восстановлены прежние значения"
    return None

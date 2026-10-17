"""Host facts, metrics and thin wrappers around system tools."""

import os
import platform
import re
import shutil
import socket
import time
from pathlib import Path

from . import paths
from .util import CommandError, run

_apt_updated = 0.0


# ------------------------------------------------------------------ facts


def os_release():
    data = {}
    try:
        for line in paths.p("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
    except OSError:
        pass
    return {
        "id": data.get("ID", "unknown"),
        "version": data.get("VERSION_ID", "unknown"),
        "pretty": data.get("PRETTY_NAME", platform.platform()),
        "codename": data.get("VERSION_CODENAME", ""),
    }


def arch():
    machine = platform.machine().lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)


def hostname():
    return socket.gethostname()


def boot_time():
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def wan_route():
    """Return (interface, ipv4) used for the default IPv4 route."""
    result = run(["ip", "-4", "route", "get", "1.1.1.1"], timeout=10)
    line = (result.stdout or "").splitlines()[0] if result.stdout else ""
    dev = re.search(r"\bdev\s+(\S+)", line)
    src = re.search(r"\bsrc\s+(\S+)", line)
    return (dev.group(1) if dev else None, src.group(1) if src else None)


def interface_has_ip(interface, ip):
    result = run(["ip", "-4", "-o", "addr", "show", "dev", interface], timeout=10)
    return f" {ip}/" in (result.stdout or "")


# ---------------------------------------------------------------- metrics


class Metrics:
    """Cheap /proc based sampler; deltas are computed between calls."""

    def __init__(self):
        self._cpu = None
        self._cpu_value = None
        self._net = None
        self._net_at = None

    @staticmethod
    def _read_cpu():
        fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        values = list(map(int, fields))
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle

    @staticmethod
    def _read_net(interface):
        try:
            base = Path("/sys/class/net") / interface / "statistics"
            return int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
        except (OSError, ValueError, TypeError):
            return None

    def sample(self, interface=None):
        out = {}
        try:
            total, idle = self._read_cpu()
            if self._cpu is None:
                self._cpu = (total, idle)
            else:
                dt, di = total - self._cpu[0], idle - self._cpu[1]
                # Need >= ~1 s of jiffies across all CPUs for a stable figure.
                if dt >= 100 * (os.cpu_count() or 1):
                    self._cpu_value = round(max(0.0, min(100.0, 100.0 * (1 - di / dt))), 1)
                    self._cpu = (total, idle)
            if self._cpu_value is not None:
                out["cpu"] = self._cpu_value
        except (OSError, ValueError, IndexError):
            pass
        try:
            mem = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, value = line.split(":", 1)
                mem[key] = int(value.split()[0]) * 1024
            out["mem_total"] = mem.get("MemTotal")
            out["mem_used"] = mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)
        except (OSError, ValueError):
            pass
        try:
            out["load"] = [round(x, 2) for x in os.getloadavg()]
        except OSError:
            pass
        try:
            usage = shutil.disk_usage("/")
            out["disk_total"], out["disk_used"] = usage.total, usage.used
        except OSError:
            pass
        try:
            out["uptime"] = int(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError):
            pass
        if interface:
            now = time.monotonic()
            net = self._read_net(interface)
            if net and self._net and self._net_at:
                elapsed = max(0.001, now - self._net_at)
                out["rx_bps"] = max(0, int((net[0] - self._net[0]) * 8 / elapsed))
                out["tx_bps"] = max(0, int((net[1] - self._net[1]) * 8 / elapsed))
            if net:
                out["rx_total"], out["tx_total"] = net
            self._net, self._net_at = net, now
        out["cpu_count"] = os.cpu_count()
        return out


# ---------------------------------------------------------------- systemd


def systemctl(*args, check=False, timeout=90):
    return run(["systemctl", *args], timeout=timeout, check=check)


def unit_active(unit):
    return systemctl("is-active", "--quiet", unit, timeout=15).returncode == 0


def unit_state(unit):
    result = systemctl("show", unit, "--property=ActiveState,SubState,LoadState,NRestarts", timeout=15)
    state = {}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            state[key] = value
    return state


def unit_failure_hint(unit):
    result = run(["journalctl", "-u", unit, "-n", "8", "--no-pager", "-o", "cat"], timeout=15)
    return " | ".join(line.strip() for line in (result.stdout or "").splitlines()[-8:])[:600]


# -------------------------------------------------------------------- apt


def package_installed(name):
    result = run(["dpkg-query", "-W", "-f=${Status}", name], timeout=30)
    return result.returncode == 0 and result.stdout.strip() == "install ok installed"


def package_available(name):
    if package_installed(name):
        return True
    result = run(["apt-cache", "show", "--no-all-versions", name], timeout=60)
    return result.returncode == 0 and "Package:" in (result.stdout or "")


def ensure_packages(names):
    global _apt_updated
    missing = [name for name in names if not package_installed(name)]
    if not missing:
        return
    env_prefix = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"]
    lock = ["-o", "DPkg::Lock::Timeout=300"]
    if time.time() - _apt_updated > 3600:
        run(env_prefix + ["apt-get", *lock, "update"], timeout=900)
        _apt_updated = time.time()
    result = run(env_prefix + ["apt-get", *lock, "install", "-y", "--no-install-recommends", *missing], timeout=1800)
    if result.returncode != 0:
        raise CommandError(["apt-get", "install", *missing], result)


def missing_libraries(binary_path):
    result = run(["ldd", str(binary_path)], timeout=30)
    return sorted({line.split()[0] for line in (result.stdout or "").splitlines() if "not found" in line})


# ----------------------------------------------------------------- docker


def docker_available():
    return run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20).returncode == 0


def docker_version():
    result = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
    return result.stdout.strip() if result.returncode == 0 else None


def container_state(name):
    result = run(["docker", "inspect", "--format", "{{.State.Status}}|{{.State.StartedAt}}|{{.Config.Image}}", name], timeout=20)
    if result.returncode != 0:
        return None
    status, started, image = (result.stdout.strip().split("|") + ["", "", ""])[:3]
    return {"status": status, "started_at": started, "image": image}


def detect_remnanode_container():
    if container_state("remnanode"):
        return "remnanode"
    result = run(["docker", "ps", "--format", "{{.Names}}"], timeout=20)
    names = [n for n in (result.stdout or "").split() if re.search(r"remna.*node|node.*remna", n, re.I)]
    return names[0] if len(names) == 1 else None


def xray_logs_present(container):
    result = run(
        ["docker", "exec", container, "sh", "-c",
         f"test -e {paths.XRAY_ACCESS_LOG} && test -e {paths.XRAY_INFO_LOG} && echo ok"],
        timeout=20,
    )
    return result.returncode == 0 and "ok" in result.stdout


def container_files_sizes(container, files):
    script = "; ".join(f"stat -c '%n %s' {f} 2>/dev/null" for f in files)
    result = run(["docker", "exec", container, "sh", "-c", script], timeout=20)
    sizes = {}
    for line in (result.stdout or "").splitlines():
        parts = line.rsplit(" ", 1)
        if len(parts) == 2 and parts[1].isdigit():
            sizes[parts[0]] = int(parts[1])
    return sizes

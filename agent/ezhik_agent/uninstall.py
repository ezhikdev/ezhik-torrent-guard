"""Complete agent removal. Leaves Docker, RemnaNode and certificates alone."""

import shutil
import subprocess
import sys

from . import firewall, netopt, nginx, paths, site, suricata
from .util import run

UNITS = ("ezhik-guard-agent.service", "ezhik-guard-suricata.service", "ezhik-guard-agent-rollback.service")


def uninstall_now(keep_certificates=True):
    # Stop the agent first so it cannot recreate anything while we clean up.
    run(["systemctl", "disable", "--now", "ezhik-guard-agent.service"], timeout=60)
    try:
        suricata.remove_all()
    except Exception as exc:  # keep going: removal must be best effort
        print(f"suricata: {exc}", file=sys.stderr)
    # 2.1 components: hand ports 80/443 back, drop our nftables table (it would
    # keep filtering without an agent), restore the previous TCP congestion control.
    for name, action in (
        ("nginx", lambda: nginx.NginxManager().apply({"mode": "direct"}, {}, None, {})),
        ("firewall", lambda: run(["nft", "delete", "table", "inet", firewall.TABLE], timeout=30)),
        ("bbr", lambda: netopt.apply(False)),
        ("site", lambda: shutil.rmtree(site.ROOT, ignore_errors=True)),
    ):
        try:
            action()
        except Exception as exc:
            print(f"{name}: {exc}", file=sys.stderr)
    shutil.rmtree(paths.SYSTEMD_DIR / "ezhik-guard-agent.service.d", ignore_errors=True)
    for unit in UNITS:
        if unit != "ezhik-guard-agent.service":
            run(["systemctl", "disable", "--now", unit], timeout=60)
    for unit in UNITS:
        (paths.SYSTEMD_DIR / unit).unlink(missing_ok=True)
    for runtime in paths.p("/opt").glob("ezhik-suricata-*"):
        if (runtime / ".ezhik-guard-owned").exists():
            shutil.rmtree(runtime, ignore_errors=True)
    for directory in (paths.STATE_DIR, paths.CONFIG_DIR, paths.p("/opt/ezhik-guard/agent")):
        shutil.rmtree(directory, ignore_errors=True)
    for parent in ("/opt/ezhik-guard", "/etc/ezhik-guard", "/var/lib/ezhik-guard"):
        try:
            directory = paths.p(parent)
            if directory.exists() and not any(directory.iterdir()):
                directory.rmdir()
        except OSError:
            pass
    paths.SURICATA_FAST_LOG.unlink(missing_ok=True)
    run(["systemctl", "daemon-reload"], timeout=60)
    run(["systemctl", "reset-failed"], timeout=60)
    print("Ezhik Guard agent removed. Certificates in the Xray directory were kept.")
    return 0


def uninstall_detached():
    """Run uninstall from a transient unit so it survives the agent's stop."""
    script = (
        "import sys; sys.path.insert(0, '/opt/ezhik-guard/agent/current'); "
        "from ezhik_agent.uninstall import uninstall_now; uninstall_now()"
    )
    staged = paths.p("/run/ezhik-guard-uninstall")
    shutil.rmtree(staged, ignore_errors=True)
    try:
        shutil.copytree(paths.CURRENT_LINK.resolve(), staged)
        script = script.replace("/opt/ezhik-guard/agent/current", str(staged))
    except OSError:
        pass
    result = run(["systemd-run", "--unit", "ezhik-guard-uninstall", "--collect", "/usr/bin/python3", "-c", script], timeout=30)
    if result.returncode != 0:
        subprocess.Popen(["/usr/bin/python3", "-c", script], start_new_session=True)

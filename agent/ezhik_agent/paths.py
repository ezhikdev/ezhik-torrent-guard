"""Filesystem layout of a node.

Every absolute path is resolved through ``EZHIK_ROOT`` (default ``/``) so the
agent can be exercised end-to-end inside a sandbox directory by tests.
"""

import os
from pathlib import Path

ROOT = Path(os.environ.get("EZHIK_ROOT", "/"))


def p(path):
    """Map an absolute host path into the configured root."""
    return ROOT / str(path).lstrip("/")


APP_DIR = p("/opt/ezhik-guard/agent")
RELEASES_DIR = APP_DIR / "releases"
CURRENT_LINK = APP_DIR / "current"
PREVIOUS_LINK = APP_DIR / "previous"
# The panel may share the host (/etc/ezhik-guard/panel), so the agent keeps
# strictly to its own subdirectories.
CONFIG_DIR = p("/etc/ezhik-guard/agent")
CONFIG_FILE = CONFIG_DIR / "agent.json"
STATE_DIR = p("/var/lib/ezhik-guard/agent")
STATE_FILE = STATE_DIR / "state.json"
DESIRED_FILE = STATE_DIR / "desired.json"
OUTBOX_FILE = STATE_DIR / "outbox.jsonl"
UPDATE_FILE = STATE_DIR / "update.json"
DOWNLOAD_DIR = STATE_DIR / "downloads"
BACKUP_DIR = p("/var/backups/ezhik-guard/agent")
SYSTEMD_DIR = p("/etc/systemd/system")

RUNTIME_PARENT = p("/opt")
SURICATA_UNIT = "ezhik-guard-suricata.service"
AGENT_UNIT = "ezhik-guard-agent.service"
SURICATA_CONFIG_DIR = CONFIG_DIR / "suricata"
SURICATA_CONFIG = SURICATA_CONFIG_DIR / "suricata.yaml"
SURICATA_RULES = SURICATA_CONFIG_DIR / "ezhik-torrent-only.rules"

# Inside the RemnaNode container (not remapped: these are container paths).
XRAY_ACCESS_LOG = "/dev/shm/xray-access.log"
XRAY_INFO_LOG = "/dev/shm/xray-info.log"
SURICATA_FAST_LOG = p("/dev/shm/ezhik-guard-suricata-fast.log")


def ensure_private_dirs():
    for directory in (CONFIG_DIR, STATE_DIR, DOWNLOAD_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass

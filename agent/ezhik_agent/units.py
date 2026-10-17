"""systemd units owned by the agent (kept in sync on every start)."""

from . import paths, system
from .util import atomic_write

AGENT_UNIT = """[Unit]
Description=Ezhik Guard node agent
After=network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5
OnFailure=ezhik-guard-agent-rollback.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ezhik-guard/agent/current
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=/opt/ezhik-guard/agent/current
ExecStart=/usr/bin/python3 -m ezhik_agent run
Restart=always
RestartSec=3
KillSignal=SIGINT
TimeoutStopSec=20
UMask=0077

[Install]
WantedBy=multi-user.target
"""

ROLLBACK_UNIT = """[Unit]
Description=Ezhik Guard agent rollback after a failed update

[Service]
Type=oneshot
Environment=PYTHONPATH=/opt/ezhik-guard/agent/previous
ExecStart=/usr/bin/python3 -m ezhik_agent rollback
"""


def sync():
    changed = False
    for name, content in (
        (paths.AGENT_UNIT, AGENT_UNIT),
        ("ezhik-guard-agent-rollback.service", ROLLBACK_UNIT),
    ):
        target = paths.SYSTEMD_DIR / name
        try:
            current = target.read_text(encoding="utf-8")
        except OSError:
            current = None
        if current != content:
            atomic_write(target, content, 0o644)
            changed = True
    if changed:
        system.systemctl("daemon-reload")
    return changed

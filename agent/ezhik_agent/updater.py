"""Self-update from the panel.

Releases live in /opt/ezhik-guard/agent/releases/<version>; ``current`` and
``previous`` are symlinks. A new release is verified (SHA-256 from the
authenticated channel, safe archive paths, VERSION, byte-compilation) before
the symlink flips. If the new agent crash-loops, systemd's OnFailure hook
(ezhik-guard-agent-rollback.service) flips back to ``previous``.
"""

import compileall
import logging
import os
import re
import shutil
import tarfile
import time
from pathlib import Path

from . import __version__, paths
from .util import read_json, run, write_json

log = logging.getLogger("ezhik.updater")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?$")
RESTART_EXIT_CODE = 75


class UpdateError(RuntimeError):
    pass


def _safe_extract(archive_path, destination):
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts:
                raise UpdateError(f"unsafe path in agent bundle: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise UpdateError(f"unsupported member in agent bundle: {member.name}")
            member.uid = member.gid = 0
            member.uname = member.gname = "root"
        try:
            archive.extractall(destination, members=members, filter="data")
        except TypeError:
            archive.extractall(destination, members=members)


def prepare_release(archive_path, version):
    if not VERSION_RE.match(version):
        raise UpdateError(f"invalid version {version!r}")
    paths.RELEASES_DIR.mkdir(parents=True, exist_ok=True)
    staging = paths.RELEASES_DIR / f".{version}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(mode=0o755)
    try:
        _safe_extract(archive_path, staging)
        bundled = (staging / "VERSION").read_text(encoding="utf-8").strip() if (staging / "VERSION").exists() else ""
        if bundled != version:
            raise UpdateError(f"bundle VERSION {bundled!r} does not match {version!r}")
        if not (staging / "ezhik_agent" / "main.py").is_file():
            raise UpdateError("bundle has no ezhik_agent package")
        if not compileall.compile_dir(str(staging / "ezhik_agent"), quiet=1, force=True):
            raise UpdateError("bundle does not compile with this Python")
        final = paths.RELEASES_DIR / version
        shutil.rmtree(final, ignore_errors=True)
        os.replace(staging, final)
        return final
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _point(link, target):
    tmp = link.with_name(link.name + ".tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(os.path.relpath(target, link.parent), tmp)
    os.replace(tmp, link)


def activate(release_dir, version):
    current = paths.CURRENT_LINK
    if current.is_symlink():
        _point(paths.PREVIOUS_LINK, current.resolve())
    _point(current, release_dir)
    write_json(paths.UPDATE_FILE, {
        "from": __version__,
        "to": version,
        "started_at": time.time(),
        "status": "restarting",
    })
    log.info("Agent %s activated; restarting", version)


def confirm_running():
    """Called by a freshly started agent; returns an update report or None."""
    info = read_json(paths.UPDATE_FILE)
    if not info or info.get("status") not in ("restarting", "rolled-back"):
        return None
    if info.get("status") == "rolled-back":
        info["result"] = "rolled-back"
    elif info.get("to") == __version__:
        info["result"] = "ok"
    else:
        info["result"] = "failed"
    info["status"] = "reported-pending"
    info["finished_at"] = time.time()
    write_json(paths.UPDATE_FILE, info)
    return info


def acknowledge():
    info = read_json(paths.UPDATE_FILE)
    if info:
        info["status"] = "done"
        write_json(paths.UPDATE_FILE, info)


def prune_releases(keep=3):
    if not paths.RELEASES_DIR.exists():
        return
    protected = {p.resolve() for p in (paths.CURRENT_LINK, paths.PREVIOUS_LINK) if p.is_symlink()}
    releases = sorted(
        (d for d in paths.RELEASES_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")),
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    for directory in releases[keep:]:
        if directory.resolve() not in protected:
            shutil.rmtree(directory, ignore_errors=True)


def rollback():
    """Entry point for ezhik-guard-agent-rollback.service."""
    previous = paths.PREVIOUS_LINK
    if not previous.is_symlink():
        return 1
    target = previous.resolve()
    if not target.is_dir():
        return 1
    failed = paths.CURRENT_LINK.resolve() if paths.CURRENT_LINK.is_symlink() else None
    _point(paths.CURRENT_LINK, target)
    info = read_json(paths.UPDATE_FILE, {}) or {}
    info.update({"status": "rolled-back", "failed_release": str(failed), "rolled_back_at": time.time()})
    write_json(paths.UPDATE_FILE, info)
    run(["systemctl", "reset-failed", paths.AGENT_UNIT], timeout=30)
    run(["systemctl", "restart", paths.AGENT_UNIT], timeout=60)
    return 0

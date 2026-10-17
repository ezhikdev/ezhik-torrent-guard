"""Stub website served by the Nginx frontend.

Versions live in /var/www/ezhik-guard-site/releases/<version>; ``current`` is
a symlink, so switching is atomic and Nginx needs no reload.
"""

import os
import shutil
import tarfile
from pathlib import Path

from . import paths
from .util import atomic_write

ROOT = paths.p("/var/www/ezhik-guard-site")
RELEASES = ROOT / "releases"
CURRENT = ROOT / "current"
MAX_FILES, MAX_BYTES = 5000, 200 << 20

DEFAULT_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title><style>body{font-family:system-ui,sans-serif;margin:0;display:grid;place-items:center;
min-height:100vh;background:#f4f5f7;color:#222}main{text-align:center}h1{font-weight:600}</style></head>
<body><main><h1>Site is under construction</h1><p>Please check back later.</p></main></body></html>
"""


class SiteError(RuntimeError):
    pass


def _public_dir(path):
    """mkdir -p with 0755 on every level we own (the agent runs with UMask=0077,
    but Nginx workers must be able to traverse and read the site)."""
    path.mkdir(parents=True, exist_ok=True)
    current = path
    www = paths.p("/var/www")
    while True:
        try:
            os.chmod(current, 0o755)
        except OSError:
            pass
        if current == www or current.parent == current or www not in current.parents:
            break
        current = current.parent


def _point(target):
    tmp = ROOT / ".current.tmp"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(os.path.relpath(target, ROOT), tmp)
    os.replace(tmp, CURRENT)


def ensure_default():
    if CURRENT.exists():
        return
    default = RELEASES / "builtin"
    _public_dir(default)
    atomic_write(default / "index.html", DEFAULT_HTML, 0o644)
    _point(default)


def installed_version():
    try:
        return Path(os.readlink(CURRENT)).name
    except OSError:
        return None


def install(archive_path, version):
    if not version or "/" in version or version.startswith("."):
        raise SiteError("invalid site version")
    staging = RELEASES / f".{version}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    _public_dir(staging)
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES:
            raise SiteError("слишком много файлов в сайте")
        for member in members:
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
                raise SiteError(f"недопустимый элемент архива: {member.name}")
            total += member.size
            member.uid = member.gid = 0
            member.uname = member.gname = "root"
            member.mode = 0o755 if member.isdir() else 0o644
        if total > MAX_BYTES:
            raise SiteError("сайт больше 200 МБ")
        try:
            archive.extractall(staging, members=members, filter="data")
        except TypeError:
            archive.extractall(staging, members=members)
    for directory in [staging, *[p for p in staging.rglob("*") if p.is_dir()]]:
        os.chmod(directory, 0o755)
    if not (staging / "index.html").exists():
        atomic_write(staging / "index.html", DEFAULT_HTML, 0o644)
    final = RELEASES / version
    shutil.rmtree(final, ignore_errors=True)
    os.replace(staging, final)
    _point(final)
    keep = {final.name, "builtin"}
    for old in sorted((d for d in RELEASES.iterdir() if d.is_dir() and d.name not in keep and not d.name.startswith(".")),
                      key=lambda d: d.stat().st_mtime, reverse=True)[2:]:
        shutil.rmtree(old, ignore_errors=True)
    _public_dir(final)


def use_builtin():
    ensure_default()
    _public_dir(RELEASES / "builtin")
    if (RELEASES / "builtin").exists():
        _point(RELEASES / "builtin")

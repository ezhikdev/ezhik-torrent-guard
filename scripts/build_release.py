#!/usr/bin/env python3
"""Build dist/ezhik-guard.tar.gz (+ .sha256), the single release asset.

Layout inside the archive (installed to /opt/ezhik-guard/panel/releases/<v>):
  ezhik-guard/VERSION, RUNTIME.env, install.sh, uninstall.sh
  ezhik-guard/panel/ezhik_panel/..., panel/requirements.txt
  ezhik-guard/agent/ezhik_agent/..., agent/VERSION   (served to nodes)
  ezhik-guard/web/...                               (built UI, web/dist)
  ezhik-guard/packaging/...

Usage: python scripts/build_release.py [--skip-web] [--out dist]
"""

import argparse
import gzip
import hashlib
import io
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".sh", ".txt", ".env", ".md", ".html", ".css", ".js", ".json", ".rules", ".service", ""}
SKIP_PARTS = {"__pycache__", ".pytest_cache", "node_modules"}


def build_web():
    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    subprocess.run([npm, "run", "build"], cwd=ROOT / "web", check=True)


def add_file(archive, source, arcname, executable=False):
    data = source.read_bytes()
    if source.suffix in TEXT_SUFFIXES and b"\0" not in data[:4096]:
        data = data.replace(b"\r\n", b"\n")
    info = tarfile.TarInfo(arcname)
    info.size = len(data)
    info.mode = 0o755 if executable or source.suffix == ".sh" else 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    archive.addfile(info, io.BytesIO(data))


def add_tree(archive, source, prefix):
    for path in sorted(source.rglob("*")):
        if any(part in SKIP_PARTS for part in path.parts) or path.suffix == ".pyc":
            continue
        if path.is_file():
            add_file(archive, path, f"{prefix}/{path.relative_to(source).as_posix()}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-web", action="store_true")
    parser.add_argument("--out", default="dist")
    args = parser.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not args.skip_web:
        build_web()
    web = ROOT / "web" / "dist"
    if not (web / "index.html").exists():
        raise SystemExit("web/dist is missing; run without --skip-web")

    out = ROOT / args.out
    out.mkdir(exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        base = "ezhik-guard"
        for name in ("VERSION", "RUNTIME.env", "install.sh", "uninstall.sh", "README.md"):
            if (ROOT / name).exists():
                add_file(archive, ROOT / name, f"{base}/{name}")
        add_tree(archive, ROOT / "panel" / "ezhik_panel", f"{base}/panel/ezhik_panel")
        add_file(archive, ROOT / "panel" / "requirements.txt", f"{base}/panel/requirements.txt")
        add_tree(archive, ROOT / "agent" / "ezhik_agent", f"{base}/agent/ezhik_agent")
        add_file(archive, ROOT / "VERSION", f"{base}/agent/VERSION")
        add_tree(archive, web, f"{base}/web")
        add_tree(archive, ROOT / "packaging", f"{base}/packaging")
    raw = buffer.getvalue()
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(raw)
    target = out / "ezhik-guard.tar.gz"
    target.write_bytes(compressed.getvalue())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (out / "ezhik-guard.tar.gz.sha256").write_text(f"{digest}  ezhik-guard.tar.gz\n", encoding="ascii")
    print(f"ezhik-guard {version}: {target} ({len(target.read_bytes()) // 1024} KiB) sha256={digest}")


if __name__ == "__main__":
    main()

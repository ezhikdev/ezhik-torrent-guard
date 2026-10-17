"""Agent bundle, Suricata runtime cache, update checks and panel self-update."""

import hashlib
import io
import json
import logging
import os
import tarfile
import threading
import time
from pathlib import Path

import httpx

from . import __version__

log = logging.getLogger("ezhik.releases")


def _parse_env(path):
    values = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def version_tuple(value):
    parts = []
    for item in str(value or "0").lstrip("v").split("-")[0].split("."):
        parts.append(int(item) if item.isdigit() else 0)
    return tuple((parts + [0, 0, 0])[:3])


class Releases:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.runtime_env = _parse_env(config.install_dir / "RUNTIME.env")
        self._agent = None
        self._lock = threading.Lock()
        self._download_locks = {}
        self.latest = None
        self.latest_checked = 0

    # ------------------------------------------------------------ agent

    def agent_bundle(self):
        """(version, sha256, path) of the agent shipped with this panel."""
        with self._lock:
            if self._agent and Path(self._agent[2]).exists():
                return self._agent
            source = self.config.install_dir / "agent"
            version = (source / "VERSION").read_text(encoding="utf-8").strip() if (source / "VERSION").exists() else __version__
            target = self.config.cache_dir / f"agent-{version}.tar.gz"
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz", compresslevel=9) as archive:
                for path in sorted(source.rglob("*")):
                    if "__pycache__" in path.parts or path.suffix == ".pyc":
                        continue
                    arcname = path.relative_to(source).as_posix()
                    info = archive.gettarinfo(str(path), arcname)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    if path.is_file():
                        info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                        with open(path, "rb") as handle:
                            archive.addfile(info, handle)
                    elif path.is_dir():
                        info.mode = 0o755
                        archive.addfile(info)
            data = buffer.getvalue()
            target.write_bytes(data)
            self._agent = (version, hashlib.sha256(data).hexdigest(), str(target))
            return self._agent

    # ----------------------------------------------------------- runtime

    def engine(self):
        env = self.runtime_env
        return {
            "engine_id": f"suricata-{env.get('SURICATA_VERSION')}-ndpi-{env.get('NDPI_VERSION')}-r{env.get('RUNTIME_REVISION')}",
            "runtime_prefix": f"/opt/ezhik-suricata-{env.get('SURICATA_VERSION')}",
        }

    def available_runtimes(self):
        out = {}
        for key, value in self.runtime_env.items():
            if key.startswith("RUNTIME_SHA256_UBUNTU_"):
                version = key[len("RUNTIME_SHA256_UBUNTU_"):].replace("_", ".")
                out[version] = value
        return out

    def runtime_for(self, os_info):
        """Pick the runtime build for a node OS (exact, else nearest older)."""
        if not os_info or os_info.get("id") != "ubuntu":
            return None
        available = self.available_runtimes()
        if not available:
            return None
        wanted = version_tuple(os_info.get("version"))
        candidates = sorted(available, key=version_tuple)
        chosen = None
        for candidate in candidates:
            if version_tuple(candidate) <= wanted:
                chosen = candidate
        chosen = chosen or candidates[0]
        asset = f"{self.runtime_env.get('RUNTIME_ASSET_PREFIX')}-ubuntu-{chosen}-amd64.tar.zst"
        return {
            **self.engine(),
            "asset": asset,
            "sha256": available[chosen],
            "built_for": chosen,
            "url": f"/agent/v1/runtime/{asset}",
        }

    def runtime_path(self, asset):
        """Return a verified local copy, downloading it from GitHub on demand."""
        valid = {f"{self.runtime_env.get('RUNTIME_ASSET_PREFIX')}-ubuntu-{v}-amd64.tar.zst": sha
                 for v, sha in self.available_runtimes().items()}
        if asset not in valid:
            raise LookupError("unknown runtime asset")
        target = self.config.cache_dir / asset
        lock = self._download_locks.setdefault(asset, threading.Lock())
        with lock:
            if target.exists() and _sha256(target) == valid[asset]:
                return target
            local = self.config.install_dir / "runtime" / asset
            if local.exists() and _sha256(local) == valid[asset]:
                return local
            url = (f"https://github.com/{self.config.github_repo}/releases/download/"
                   f"{self.runtime_env.get('RUNTIME_RELEASE_TAG')}/{asset}")
            log.info("Downloading runtime %s", url)
            tmp = target.with_suffix(".part")
            digest = hashlib.sha256()
            with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
                response.raise_for_status()
                with open(tmp, "wb") as out:
                    for chunk in response.iter_bytes(1 << 20):
                        digest.update(chunk)
                        out.write(chunk)
            if digest.hexdigest() != valid[asset]:
                tmp.unlink(missing_ok=True)
                raise RuntimeError("runtime checksum mismatch")
            os.replace(tmp, target)
            return target

    # ----------------------------------------------------------- updates

    def check_latest(self, force=False):
        if not force and self.latest and time.time() - self.latest_checked < 3600:
            return self.latest
        try:
            response = httpx.get(f"https://api.github.com/repos/{self.config.github_repo}/releases/latest",
                                 timeout=15, headers={"Accept": "application/vnd.github+json"})
            if response.status_code == 200:
                data = response.json()
                self.latest = {
                    "version": str(data.get("tag_name", "")).lstrip("v"),
                    "published_at": data.get("published_at"),
                    "notes": (data.get("body") or "")[:4000],
                    "url": data.get("html_url"),
                }
            self.latest_checked = time.time()
        except Exception as exc:
            log.warning("Update check failed: %s", exc)
        return self.latest

    def update_available(self):
        latest = self.latest
        return bool(latest and version_tuple(latest["version"]) > version_tuple(__version__))

    @property
    def update_request_file(self):
        return self.config.data_dir / "update-request.json"

    @property
    def update_status_file(self):
        return self.config.data_dir / "update-status.json"

    def request_panel_update(self, actor):
        payload = {"requested_at": time.time(), "actor": actor, "from": __version__,
                   "to": (self.latest or {}).get("version")}
        tmp = self.update_request_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, self.update_request_file)
        self.update_status_file.write_text(json.dumps({"state": "requested", **payload}), encoding="utf-8")

    def update_status(self):
        try:
            return json.loads(self.update_status_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

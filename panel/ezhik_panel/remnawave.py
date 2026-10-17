"""Remnawave API adapter for panel 2.x and 3.x.

Remnawave 3.0 removed the user ``uuid`` and ``/api/users/by-id/{id}``;
every user route now takes the numeric ``id`` (which is also the Xray
client ``email`` on the nodes, unchanged since 2.x). This adapter detects
the panel generation once (``/api/system/metadata``, then route probing),
exposes one interface, and re-detects automatically after a panel upgrade.
"""

import json
import logging
import threading
import time
import urllib.error
import urllib.request

from . import __version__

log = logging.getLogger("ezhik.remnawave")


class Remnawave:
    def __init__(self, base_url, token, timeout=10):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token or ""
        self.timeout = timeout
        self.api = None            # "v3" | "v2"
        self.panel_version = None
        self._lock = threading.Lock()

    @property
    def configured(self):
        return bool(self.base_url and self.token)

    # -------------------------------------------------------------- http

    def request(self, method, path, body=None):
        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": f"Ezhik-Guard/{__version__}",
        }
        if method == "POST" and body is None:
            data = b""
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _decode(exc.read())
        except Exception as exc:
            return 0, {"_transport_error": repr(exc)[:300]}

    # --------------------------------------------------------- detection

    def detect(self, probe_id=None, force=False):
        with self._lock:
            if self.api and not force:
                return self.api
            code, payload = self.request("GET", "/api/system/metadata")
            version = None
            if code == 200 and isinstance(payload.get("response"), dict):
                version = str(payload["response"].get("version") or "") or None
            if version:
                self.panel_version = version
                major = version.lstrip("v").split(".")[0]
                self.api = "v3" if major.isdigit() and int(major) >= 3 else "v2"
                return self.api
            # Token without the metadata scope: probe the user routes.
            # 2.x: /by-id/{id} exists (200, or 404 with an errorCode).
            # 3.x: /by-id/ is gone (bare 404); /{id} answers 200 without uuid
            #      or 404 with an errorCode.
            probe = str(probe_id or 1)
            code, payload = self.request("GET", f"/api/users/by-id/{probe}")
            if code == 200 or (code == 404 and app_error(payload)):
                self.api = "v2"
                return self.api
            code, payload = self.request("GET", f"/api/users/{probe}")
            user = payload.get("response") if isinstance(payload, dict) else None
            if (code == 200 and isinstance(user, dict) and "uuid" not in user) or (
                code == 404 and app_error(payload)
            ):
                self.api = "v3"
            return self.api

    def invalidate(self):
        with self._lock:
            self.api = None

    # ------------------------------------------------------------- users

    def get_user(self, client_id):
        """Return (http_code, user) with a normalised ``identity`` field."""
        api = self.detect(probe_id=client_id) or "v3"
        path = f"/api/users/{client_id}" if api == "v3" else f"/api/users/by-id/{client_id}"
        code, payload = self.request("GET", path)
        if code in (400, 404) and not app_error(payload):
            # Route shape mismatch: the panel was probably upgraded.
            self.invalidate()
            api = self.detect(probe_id=client_id, force=True) or api
            path = f"/api/users/{client_id}" if api == "v3" else f"/api/users/by-id/{client_id}"
            code, payload = self.request("GET", path)
        if code != 200:
            return code, None
        user = payload.get("response") if isinstance(payload, dict) else None
        if not isinstance(user, dict):
            return 0, None
        try:
            if int(user.get("id")) != int(client_id):
                log.error("Remnawave returned user %s for id %s; refusing", user.get("id"), client_id)
                return 0, None
        except (TypeError, ValueError):
            return 0, None
        user["identity"] = identity(user)
        user["_api"] = api
        return code, user

    def _action_path(self, user, action):
        if user.get("_api") == "v2" and user.get("uuid"):
            return f"/api/users/{user['uuid']}/actions/{action}"
        return f"/api/users/{user['id']}/actions/{action}"

    def disable(self, user):
        return self.request("POST", self._action_path(user, "disable"))

    def enable(self, user):
        return self.request("POST", self._action_path(user, "enable"))

    def check(self):
        """Connection test for the settings page."""
        self.invalidate()
        api = self.detect()
        code, payload = self.request("GET", "/api/users/stream?size=1" if api == "v3" else "/api/users?size=1")
        if code == 0:
            return {"ok": False, "error": payload.get("_transport_error", "connection failed")}
        if code in (401, 403):
            return {"ok": False, "error": f"HTTP {code}: токен отклонён или не хватает прав", "api": api}
        return {
            "ok": code == 200,
            "api": api,
            "panel_version": self.panel_version,
            "error": None if code == 200 else f"HTTP {code}",
        }


def identity(user):
    """Stable owner fingerprint: 2.x uuid; 3.x numeric id + creation time."""
    if user.get("uuid"):
        return f"uuid:{user['uuid']}"
    return f"id:{user.get('id')}:{user.get('createdAt') or ''}"


def compatible_identity(stored, current):
    """Accept a 2.x uuid identity recorded before the panel moved to 3.x."""
    if not stored or stored == current:
        return True
    if stored.startswith("uuid:") and current.startswith("id:"):
        return True
    return False


def _decode(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return {"_raw": raw.decode("utf-8", errors="replace")[:300]}


def _find_error_code(obj):
    if isinstance(obj, dict):
        code = obj.get("errorCode")
        if isinstance(code, str):
            return code
        for value in obj.values():
            found = _find_error_code(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _find_error_code(value)
            if found:
                return found
    return None


find_error_code = _find_error_code


def app_error(payload):
    """Application error code (A0xx). E000 means a generic/route error."""
    code = _find_error_code(payload)
    return code if code and code.startswith("A") else None


def now():
    return time.time()

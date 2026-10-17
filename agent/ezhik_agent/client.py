"""HTTPS client for the panel's agent API.

The agent trusts only the panel's private CA (delivered in the install
command and stored in agent.json), so no public certificate or domain is
needed and a man-in-the-middle cannot impersonate the panel.
"""

import hashlib
import json
import ssl
import urllib.error
import urllib.request

from . import __version__


class PanelError(RuntimeError):
    def __init__(self, status, message, payload=None):
        self.status = status
        self.payload = payload or {}
        super().__init__(f"panel HTTP {status}: {message}")


def make_ssl_context(ca_pem):
    if ca_pem:
        ctx = ssl.create_default_context(cadata=ca_pem)
        # The chain must end at the panel's private CA, which only the panel
        # can sign with; the panel may be reached by IP or any DNS name.
        ctx.check_hostname = False
    else:
        ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class PanelClient:
    def __init__(self, url, token=None, ca_pem=None, node_id=None):
        self.url = url.rstrip("/")
        self.token = token
        self.node_id = node_id
        self.ctx = make_ssl_context(ca_pem) if self.url.startswith("https://") else None

    def _headers(self, extra=None):
        headers = {
            "Accept": "application/json",
            "User-Agent": f"ezhik-guard-agent/{__version__}",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.node_id:
            headers["X-Ezhik-Node"] = self.node_id
        headers.update(extra or {})
        return headers

    def request(self, method, path, body=None, timeout=30):
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"detail": raw.decode("utf-8", "replace")[:300]}
            detail = payload.get("detail") if isinstance(payload, dict) else None
            raise PanelError(exc.code, detail or exc.reason, payload) from None

    def download(self, path, destination, expected_sha256=None, timeout=120, limit=512 << 20):
        req = urllib.request.Request(self.url + path, headers=self._headers({"Accept": "*/*"}))
        digest = hashlib.sha256()
        size = 0
        tmp = destination.with_name(destination.name + ".part")
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as response, open(tmp, "wb") as out:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise PanelError(413, "download exceeds size limit")
                    digest.update(chunk)
                    out.write(chunk)
        except urllib.error.HTTPError as exc:
            tmp.unlink(missing_ok=True)
            raise PanelError(exc.code, exc.reason) from None
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        actual = digest.hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            tmp.unlink(missing_ok=True)
            raise PanelError(0, f"checksum mismatch for {path}")
        tmp.replace(destination)
        return actual

"""Panel on its own domain: DNS/reachability checks and extra listeners.

The original web port (8443 by default) always keeps working, so switching
from IP to a domain can never lock the admin out. Port 80 serves ACME
HTTP-01 challenges and redirects to HTTPS; port 443 (optional) serves the
same UI with the domain certificate.
"""

import asyncio
import json
import logging
import os
import secrets
import socket
import subprocess

import dns.resolver
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

log = logging.getLogger("ezhik.domain")


def server_addresses():
    """Addresses of this host: interfaces plus the public IPv4/IPv6 seen from outside."""
    found = set()
    try:
        out = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            parts = line.split()
            if "inet" in parts or "inet6" in parts:
                key = "inet" if "inet" in parts else "inet6"
                found.add(parts[parts.index(key) + 1].split("/")[0])
    except (OSError, subprocess.SubprocessError):
        pass
    for url in ("https://api.ipify.org", "https://api6.ipify.org"):
        try:
            response = httpx.get(url, timeout=5)
            if response.status_code == 200 and len(response.text) < 60:
                found.add(response.text.strip())
        except httpx.HTTPError:
            pass
    return sorted(found)


def resolve(domain, resolvers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = resolvers or ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 8
    out = {}
    for rtype in ("A", "AAAA"):
        try:
            out[rtype] = sorted(r.address for r in resolver.resolve(domain, rtype))
        except Exception:
            out[rtype] = []
    return out


def check(domain, config, settings, challenge_tokens):
    records = resolve(domain, config.dns_resolvers)
    addresses = server_addresses()
    resolved = records["A"] + records["AAAA"]
    matching = [ip for ip in resolved if ip in addresses]
    result = {
        "domain": domain, "a": records["A"], "aaaa": records["AAAA"], "server": addresses,
        "dns_ok": bool(resolved) and len(matching) == len(resolved),
        "dns_partial": bool(matching) and len(matching) != len(resolved),
        "http": None, "https": None,
    }
    http_port = settings.get("http_port") or 0
    if http_port and matching:
        token = secrets.token_urlsafe(12)
        challenge_tokens[f"check:{token}"] = token
        try:
            url = f"http://{domain}{'' if http_port == 80 else f':{http_port}'}/.well-known/ezhik-guard-check/{token}"
            response = httpx.get(url, timeout=8, follow_redirects=False)
            result["http"] = {"ok": response.status_code == 200 and response.text.strip() == token,
                              "status": response.status_code}
        except httpx.HTTPError as exc:
            result["http"] = {"ok": False, "error": str(exc)[:200]}
        finally:
            challenge_tokens.pop(f"check:{token}", None)
    https_port = settings.get("https_port") or config.web_port
    if matching:
        try:
            response = httpx.get(f"https://{domain}{'' if https_port == 443 else f':{https_port}'}/healthz", timeout=8)
            result["https"] = {"ok": response.status_code == 200, "status": response.status_code, "trusted": True}
        except httpx.HTTPError as exc:
            result["https"] = {"ok": False, "trusted": False, "error": str(exc)[:200]}
    return result


def port_free(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def build_http_app(ctx):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/.well-known/acme-challenge/{token}")
    def acme(token: str):
        value = ctx.certs.http_challenges.get(token)
        if not value:
            return PlainTextResponse("not found", status_code=404)
        return PlainTextResponse(value)

    @app.get("/.well-known/ezhik-guard-check/{token}")
    def probe(token: str):
        value = ctx.certs.http_challenges.get(f"check:{token}")
        return PlainTextResponse(value or "unknown", status_code=200 if value else 404)

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST"])
    def redirect(path: str, request: Request):
        panel = ctx.settings.panel()
        host = panel.get("domain") or (request.headers.get("host") or "").split(":")[0]
        port = panel.get("https_port") or ctx.config.web_port
        suffix = "" if port == 443 else f":{port}"
        query = f"?{request.url.query}" if request.url.query else ""
        return RedirectResponse(f"https://{host}{suffix}/{path}{query}", status_code=301)

    return app


class Listeners:
    """Starts/stops the optional port-80 and port-443 servers at runtime."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.servers = {}   # port -> (server, task)
        self.errors = {}
        self.loop = None

    def bind(self, loop):
        self.loop = loop

    def request_reconcile(self):
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.reconcile(), self.loop)

    async def _start(self, port, app, ssl_files=None):
        import uvicorn

        if not port_free(port):
            self.errors[port] = f"порт {port} занят другим процессом"
            log.error("Cannot listen on %s: busy", port)
            return
        kwargs = {}
        if ssl_files:
            kwargs = {"ssl_certfile": ssl_files[0], "ssl_keyfile": ssl_files[1]}
        server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning",
                                               access_log=False, server_header=False, **kwargs))
        server.install_signal_handlers = lambda: None

        async def run():
            try:
                await server.serve()
            except BaseException as exc:  # uvicorn exits the process on bind errors
                self.errors[port] = f"не удалось слушать порт {port}: {exc!r}"[:200]
                log.error("Listener %s failed: %r", port, exc)

        task = asyncio.create_task(run())
        self.servers[port] = (server, task)
        for _ in range(50):
            if server.started or task.done():
                break
            await asyncio.sleep(0.1)
        if server.started and ssl_files:
            self.ctx.ssl_contexts.append(server.config.ssl)
        if server.started:
            self.errors.pop(port, None)
            log.info("Extra listener on port %s started", port)

    async def _stop(self, port):
        server, task = self.servers.pop(port)
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=10)
        except asyncio.TimeoutError:
            task.cancel()
        if server.config.ssl in self.ctx.ssl_contexts:
            self.ctx.ssl_contexts.remove(server.config.ssl)

    async def reconcile(self):
        from .app import build_admin_app

        panel = self.ctx.settings.panel()
        wanted = {}
        if panel.get("http_port"):
            wanted[int(panel["http_port"])] = "http"
        if panel.get("https_port") and int(panel["https_port"]) != self.ctx.config.web_port:
            wanted[int(panel["https_port"])] = "https"
        for port in list(self.servers):
            if port not in wanted:
                await self._stop(port)
        for port, kind in wanted.items():
            if port in self.servers and not self.servers[port][1].done():
                continue
            self.servers.pop(port, None)
            if kind == "http":
                await self._start(port, build_http_app(self.ctx))
            else:
                await self._start(port, self.ctx.admin_app or build_admin_app(self.ctx), self.ctx.web_cert_files())
        self._write_state()

    def http_ready(self):
        port = self.ctx.settings.panel().get("http_port")
        entry = self.servers.get(int(port)) if port else None
        return bool(entry and entry[0].started and not entry[1].done())

    def _write_state(self):
        path = self.ctx.config.data_dir / "listeners.json"
        active = sorted(port for port, (server, task) in self.servers.items() if server.started and not task.done())
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"ports": active}), encoding="utf-8")
        os.replace(tmp, path)

    def status(self):
        return {
            "active": sorted(p for p, (s, t) in self.servers.items() if s.started and not t.done()),
            "errors": dict(self.errors),
        }

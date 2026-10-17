"""HTTP layer: admin API + SPA (web port) and agent API (agent port)."""

import io
import json
import logging
import time
import zipfile
from pathlib import Path

import mimetypes

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__, security
from .certificates import CertError, analyze, covers, normalize_domains, provider_public
from .dns_providers import AcmeDnsProvider, CloudflareProvider, DnsError
from .db import loads
from .nodes import NodeError
from . import nginx_routes, panel_domain
from .certificates import HTTP01, normalize_domain
from .firewall import FirewallError, resolve_host
from .remnawave import Remnawave
from .settings_service import ValidationError
from .sites import DEFAULT_PREVIEW_HTML, SiteError, rewrite

log = logging.getLogger("ezhik.app")

SESSION_COOKIE = "ezhik_session"
SESSION_TTL = 7 * 86400
LOGIN_WINDOW, LOGIN_MAX_FAILURES = 900, 10


def client_ip(request, trusted):
    ip = request.client.host if request.client else ""
    if ip in trusted:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        real = request.headers.get("x-real-ip", "").strip()
        return forwarded or real or ip
    return ip


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        else:
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            )
        return response


def _error_handlers(app):
    @app.exception_handler(LookupError)
    async def not_found(_request, exc):
        return JSONResponse({"detail": str(exc).strip("'") or "Не найдено"}, status_code=404)

    for cls in (NodeError, CertError, ValidationError, DnsError, SiteError, FirewallError, nginx_routes.RouteError):
        @app.exception_handler(cls)
        async def invalid(_request, exc):
            return JSONResponse({"detail": str(exc)}, status_code=400)


# =================================================================== admin


def build_admin_app(ctx):
    app = FastAPI(title="Ezhik Guard", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeaders)
    _error_handlers(app)
    db, cfg = ctx.db, ctx.config

    # ------------------------------------------------------------ session

    def current_session(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            raise HTTPException(401, "Требуется вход")
        session = db.one(
            "SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?",
            (security.token_hash(token),),
        )
        now = time.time()
        if not session or session["expires_at"] < now:
            raise HTTPException(401, "Сессия истекла")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("x-csrf-token") != session["csrf"]:
                raise HTTPException(403, "CSRF-проверка не пройдена")
        if now - session["last_seen_at"] > 60:
            db.execute("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE token_hash=?",
                       (now, now + SESSION_TTL, session["token_hash"]))
        return session

    def actor(session=Depends(current_session)):
        return session["username"]

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.post("/api/auth/login")
    def login(request: Request, response: Response, body: dict = Body(...)):
        ip = client_ip(request, cfg.trusted_proxies)
        now = time.time()
        failures = db.scalar("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND at>?", (ip, now - LOGIN_WINDOW))
        if failures >= LOGIN_MAX_FAILURES:
            raise HTTPException(429, "Слишком много попыток входа. Повторите через 15 минут.")
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        admin = db.one("SELECT * FROM admins WHERE username=?", (username,))
        if not admin or not security.verify_password(password, admin["password_hash"]):
            db.execute("INSERT INTO login_attempts(ip,at) VALUES(?,?)", (ip, now))
            db.audit(username or "?", "auth.login_failed", detail={"ip": ip})
            time.sleep(0.6)
            raise HTTPException(401, "Неверный логин или пароль")
        db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
        token, csrf = security.new_token(32), security.new_token(18)
        db.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf,created_at,last_seen_at,expires_at,ip,user_agent) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (security.token_hash(token), admin["id"], csrf, now, now, now + SESSION_TTL, ip,
             request.headers.get("user-agent", "")[:200]),
        )
        db.execute("UPDATE admins SET last_login_at=? WHERE id=?", (now, admin["id"]))
        db.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
        db.audit(username, "auth.login", detail={"ip": ip})
        response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True,
                            secure=cfg.web_tls, samesite="strict", path="/")
        return {"username": username, "csrf": csrf}

    @app.get("/api/auth/me")
    def me(session=Depends(current_session)):
        return {"username": session["username"], "csrf": session["csrf"], "version": __version__}

    @app.post("/api/auth/logout")
    def logout(response: Response, session=Depends(current_session)):
        db.execute("DELETE FROM sessions WHERE token_hash=?", (session["token_hash"],))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.post("/api/auth/password")
    def change_password(body: dict = Body(...), session=Depends(current_session)):
        admin = db.one("SELECT * FROM admins WHERE id=?", (session["admin_id"],))
        if not security.verify_password(str(body.get("current") or ""), admin["password_hash"]):
            raise HTTPException(400, "Текущий пароль указан неверно")
        new = str(body.get("new") or "")
        if len(new) < 10:
            raise HTTPException(400, "Новый пароль должен содержать не менее 10 символов")
        db.execute("UPDATE admins SET password_hash=?, password_changed_at=? WHERE id=?",
                   (security.hash_password(new), time.time(), admin["id"]))
        db.execute("DELETE FROM sessions WHERE admin_id=? AND token_hash!=?", (admin["id"], session["token_hash"]))
        db.audit(session["username"], "auth.password_changed")
        return {"ok": True}

    @app.get("/api/auth/sessions")
    def sessions(session=Depends(current_session)):
        rows = db.all("SELECT token_hash, created_at, last_seen_at, ip, user_agent FROM sessions WHERE admin_id=? "
                      "ORDER BY last_seen_at DESC", (session["admin_id"],))
        for row in rows:
            row["current"] = row["token_hash"] == session["token_hash"]
            row["id"] = row.pop("token_hash")[:16]
        return rows

    @app.delete("/api/auth/sessions/{sid}")
    def revoke_session(sid: str, session=Depends(current_session)):
        db.execute("DELETE FROM sessions WHERE admin_id=? AND substr(token_hash,1,16)=? AND token_hash!=?",
                   (session["admin_id"], sid, session["token_hash"]))
        return {"ok": True}

    # ---------------------------------------------------------- dashboard

    @app.get("/api/dashboard")
    def dashboard(range: str = "24h", _=Depends(current_session)):
        period = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}.get(range, 86400)
        now = time.time()
        nodes = ctx.nodes.list()
        bucket = 3600 if period <= 86400 else 6 * 3600 if period <= 7 * 86400 else 86400
        certs = ctx.certs.list()
        expiring = [c for c in certs if c["not_after"] and c["not_after"] - now < 21 * 86400]
        protection = ctx.settings.protection()
        rw = ctx.settings.remnawave()
        return {
            "nodes": {
                "total": len(nodes),
                "online": sum(1 for n in nodes if n["online"]),
                "offline": sum(1 for n in nodes if not n["online"] and n["status"] == "active"),
                "pending": sum(1 for n in nodes if n["status"] == "pending"),
                "problems": sum(1 for n in nodes if n["problems"]),
                "outdated": sum(1 for n in nodes if n["update_available"]),
                "torrent": sum(1 for n in nodes if n["torrent_enabled"] and n["status"] == "active"),
                "scan": sum(1 for n in nodes if n["scan_enabled"] and n["status"] == "active"),
            },
            "counts": ctx.events.counts(now - period),
            "prev_counts": ctx.events.counts(now - 2 * period) if period <= 7 * 86400 else {},
            "series": ctx.events.timeseries(now - period, bucket),
            "bucket": bucket,
            "since": now - period,
            "top_clients": ctx.events.top_clients(now - period),
            "recent": ctx.events.list(limit=12),
            "sanctions": {
                "active": db.scalar("SELECT COUNT(*) FROM sanctions WHERE state='active'") or 0,
                "pending": db.scalar("SELECT COUNT(*) FROM sanctions WHERE state='pending'") or 0,
            },
            "certificates": {
                "total": len(certs),
                "expiring": [{"id": c["id"], "name": c["name"], "not_after": c["not_after"]} for c in expiring],
                "failed": sum(1 for c in certs if c["status"] == "failed"),
            },
            "modes": {k: protection[k]["mode"] for k in ("torrent", "p2p", "scan")},
            "p2p_enabled": protection["p2p"]["enabled"],
            "remnawave_configured": bool(rw.get("url") and rw.get("token")),
            "node_cards": [{k: n[k] for k in ("id", "name", "online", "status", "ip", "problems", "metrics",
                                              "torrent_enabled", "scan_enabled", "agent_version",
                                              "update_available", "last_seen_at")} for n in nodes],
            "update": ctx.releases.latest if ctx.releases.update_available() else None,
        }

    # -------------------------------------------------------------- nodes

    @app.get("/api/nodes")
    def list_nodes(_=Depends(current_session)):
        return {"nodes": ctx.nodes.list(), "agent_version": ctx.releases.agent_bundle()[0]}

    @app.post("/api/nodes")
    def create_node(body: dict = Body(...), who=Depends(actor)):
        node = ctx.nodes.create(body.get("name"), who, body.get("torrent_enabled"), body.get("scan_enabled"),
                                body.get("container"), body.get("tags"))
        return {"node": ctx.nodes.public(node, detail=True), "install": ctx.nodes.install_command(node["id"])}

    @app.get("/api/nodes/{node_id}")
    def get_node(node_id: str, _=Depends(current_session)):
        node = ctx.nodes.public(ctx.nodes.get(node_id), detail=True)
        node["uptime_strip"] = ctx.nodes.uptime_strip(node_id)
        return node

    @app.patch("/api/nodes/{node_id}")
    def patch_node(node_id: str, body: dict = Body(...), who=Depends(actor)):
        return ctx.nodes.update_node(node_id, body, who)

    @app.delete("/api/nodes/{node_id}")
    def delete_node(node_id: str, uninstall: bool = True, who=Depends(actor)):
        return {"result": ctx.nodes.delete(node_id, uninstall, who)}

    @app.post("/api/nodes/{node_id}/install-command")
    def install_command(node_id: str, _=Depends(actor)):
        return ctx.nodes.install_command(node_id)

    @app.post("/api/nodes/{node_id}/update")
    def update_node_agent(node_id: str, who=Depends(actor)):
        return {"requested": ctx.nodes.request_update(node_id, who)}

    @app.post("/api/nodes/{node_id}/command")
    def node_command(node_id: str, body: dict = Body(...), who=Depends(actor)):
        return {"id": ctx.nodes.command(node_id, body.get("type"), body.get("args"), who)}

    @app.get("/api/nodes/{node_id}/metrics")
    def node_metrics(node_id: str, period: str = "24h", _=Depends(current_session)):
        seconds = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400}.get(period, 86400)
        return {"points": ctx.nodes.metrics(node_id, seconds),
                "events": ctx.events.timeseries(time.time() - seconds, max(300, seconds // 48), node_id)}

    @app.post("/api/nodes/bulk")
    def bulk(body: dict = Body(...), who=Depends(actor)):
        ids = [str(i) for i in body.get("ids") or []][:500]
        return {"done": ctx.nodes.bulk(ids, body.get("action"), body.get("value"), who)}

    @app.post("/api/nodes/update-all")
    def update_all(who=Depends(actor)):
        ids = [n["id"] for n in ctx.nodes.list() if n["update_available"] and n["status"] == "active"]
        return {"done": ctx.nodes.bulk(ids, "update_agent", None, who)}

    @app.post("/api/nodes/reorder")
    def reorder(body: dict = Body(...), _=Depends(actor)):
        ctx.nodes.reorder([str(i) for i in body.get("ids") or []])
        return {"ok": True}

    # ------------------------------------------------------------- events

    @app.get("/api/events")
    def events(type: str = "", node: str = "", client: str = "", q: str = "", before: float = 0,
               since: float = 0, limit: int = 100, _=Depends(current_session)):
        types = [t for t in type.split(",") if t] or None
        return {"events": ctx.events.list(types=types, node_id=node or None, client_id=client or None,
                                          q=q or None, before=before or None, since=since or None, limit=limit)}

    @app.get("/api/clients/{client_id}")
    def client_info(client_id: str, _=Depends(current_session)):
        if not client_id.isdigit():
            raise HTTPException(400, "ID клиента — число")
        info = {"client_id": client_id, "events": ctx.events.list(client_id=client_id, limit=100),
                "sanction": db.one("SELECT * FROM sanctions WHERE client_id=?", (client_id,)),
                "history": db.all("SELECT * FROM sanction_history WHERE client_id=? ORDER BY at DESC LIMIT 50", (client_id,)),
                "protected": client_id in ctx.settings.protected_clients(), "remnawave": None}
        rw = ctx.sanctions.client()
        if rw.configured:
            code, user = rw.get_user(client_id)
            if user:
                info["remnawave"] = {k: user.get(k) for k in (
                    "id", "username", "status", "shortUuid", "expireAt", "telegramId", "description", "tag")}
                info["remnawave"]["api"] = user.get("_api")
            else:
                info["remnawave_error"] = f"HTTP {code}"
        return info

    # ---------------------------------------------------------- sanctions

    @app.get("/api/sanctions")
    def sanctions(_=Depends(current_session)):
        rows = db.all("SELECT s.*, n.name AS node_name FROM sanctions s LEFT JOIN nodes n ON n.id=s.node_id "
                      "ORDER BY s.created_at DESC")
        history = db.all("SELECT h.*, n.name AS node_name FROM sanction_history h LEFT JOIN nodes n ON n.id=h.node_id "
                         "ORDER BY h.at DESC LIMIT 300")
        return {"sanctions": rows, "history": history,
                "protected_clients": sorted(ctx.settings.protected_clients(), key=int)}

    @app.post("/api/sanctions/{client_id}/release")
    def release(client_id: str, who=Depends(actor)):
        try:
            return ctx.sanctions.release(client_id, who)
        except RuntimeError as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/sanctions/{client_id}/forget")
    def forget(client_id: str, who=Depends(actor)):
        ctx.sanctions.forget(client_id, who)
        return {"ok": True}

    @app.post("/api/sanctions/{client_id}/hold")
    def hold(client_id: str, body: dict = Body(...), who=Depends(actor)):
        ctx.sanctions.set_hold(client_id, bool(body.get("hold")))
        db.audit(who, "sanction.hold", client_id, {"hold": bool(body.get("hold"))})
        return {"ok": True}

    @app.post("/api/sanctions/{client_id}/extend")
    def extend(client_id: str, body: dict = Body(...), who=Depends(actor)):
        ctx.sanctions.extend(client_id, int(body.get("seconds") or 0))
        db.audit(who, "sanction.extend", client_id, body)
        return {"ok": True}

    @app.post("/api/sanctions/block")
    def manual_block(body: dict = Body(...), who=Depends(actor)):
        client_id = str(body.get("client_id") or "").strip()
        result = ctx.sanctions.queue_freeze(client_id, "manual", int(body.get("seconds") or 3600))
        db.audit(who, "sanction.manual_block", client_id, {"result": result})
        if result != "queued":
            raise HTTPException(400, {"protected": "Клиент в списке защищённых", "exists": "Уже заблокирован",
                                      "not_configured": "Remnawave не настроен", "invalid": "ID — число"}.get(result, result))
        return {"ok": True}

    # ----------------------------------------------------------- settings

    @app.get("/api/settings")
    def get_settings(_=Depends(current_session)):
        rw = ctx.settings.remnawave()
        tg = ctx.settings.telegram()
        return {
            "protection": ctx.settings.protection(),
            "remnawave": {"url": rw.get("url"), "token_set": bool(rw.get("token")),
                          "token_hint": security.mask(rw.get("token") or "")},
            "telegram": {**{k: v for k, v in tg.items() if k != "token"}, "token_set": bool(tg.get("token"))},
            "acme": ctx.settings.acme(),
            "panel": {**ctx.settings.panel(), "agent_url": ctx.nodes.agent_base_url(),
                      "web_port": cfg.web_port, "agent_port": cfg.agent_port},
        }

    @app.put("/api/settings/protection")
    def put_protection(body: dict = Body(...), who=Depends(actor)):
        result = ctx.settings.set_protection(body, who)
        ctx.nodes.wake()
        return result

    @app.put("/api/settings/remnawave")
    def put_remnawave(body: dict = Body(...), who=Depends(actor)):
        ctx.settings.set_remnawave(body.get("url"), body.get("token"), who)
        return {"ok": True}

    @app.post("/api/settings/remnawave/test")
    def test_remnawave(body: dict = Body(default={}), _=Depends(actor)):
        stored = ctx.settings.remnawave()
        client = Remnawave(body.get("url") or stored.get("url"), body.get("token") or stored.get("token"))
        if not client.configured:
            raise HTTPException(400, "Укажите адрес панели и API-токен")
        return client.check()

    @app.put("/api/settings/telegram")
    def put_telegram(body: dict = Body(...), who=Depends(actor)):
        ctx.settings.set_telegram(dict(body), who)
        return {"ok": True}

    @app.post("/api/settings/telegram/test")
    def test_telegram(body: dict = Body(default={}), _=Depends(actor)):
        try:
            ctx.notifier.test(body.get("token"), body.get("chat_id"))
        except Exception as exc:
            raise HTTPException(400, str(exc))
        return {"ok": True}

    @app.put("/api/settings/acme")
    def put_acme(body: dict = Body(...), who=Depends(actor)):
        ctx.settings.set_acme(body, who)
        return {"ok": True}

    @app.put("/api/settings/panel")
    def put_panel(body: dict = Body(...), who=Depends(actor)):
        allowed = {k: body[k] for k in ("public_host", "web_cert_id", "timezone", "http_port", "https_port")
                   if k in body}
        if allowed.get("web_cert_id"):
            cert = ctx.certs.get(allowed["web_cert_id"])
            if not cert["version"]:
                raise HTTPException(400, "Сертификат ещё не выпущен")
        result = ctx.settings.set_panel(allowed, who)
        ctx.apply_web_certificate()
        return result

    # -------------------------------------------------------- certificates

    @app.get("/api/certificates")
    def list_certs(_=Depends(current_session)):
        providers = [provider_public(r, ctx.secrets) for r in db.all("SELECT * FROM dns_providers ORDER BY name")]
        return {"certificates": ctx.certs.list(), "providers": providers, "acme": ctx.settings.acme()}

    @app.post("/api/certificates/analyze")
    def analyze_domains(body: dict = Body(...), _=Depends(current_session)):
        domains = normalize_domains(body.get("domains") or [])
        return {"domains": domains, "hints": analyze(domains)}

    @app.post("/api/certificates")
    def create_cert(body: dict = Body(...), who=Depends(actor)):
        return ctx.certs.create(body.get("name"), body.get("domains") or [], body.get("provider_id"),
                                body.get("key_type") or "ec256", body.get("auto_renew", True), who)

    @app.post("/api/certificates/upload")
    def upload_cert(body: dict = Body(...), who=Depends(actor)):
        return ctx.certs.upload(body.get("name"), body.get("fullchain") or "", body.get("privkey") or "", who)

    @app.get("/api/certificates/{cert_id}")
    def get_cert(cert_id: str, _=Depends(current_session)):
        cert = ctx.certs.get(cert_id)
        for node in cert["nodes"]:
            node["covered"] = covers(set(cert["domains"]), node["domain"]) if node.get("domain") else None
        return cert

    @app.patch("/api/certificates/{cert_id}")
    def patch_cert(cert_id: str, body: dict = Body(...), who=Depends(actor)):
        return ctx.certs.update(cert_id, body.get("name"), body.get("auto_renew"), body.get("provider_id"),
                                body.get("domains"), who)

    @app.delete("/api/certificates/{cert_id}")
    def delete_cert(cert_id: str, who=Depends(actor)):
        ctx.certs.delete(cert_id, who)
        return {"ok": True}

    @app.post("/api/certificates/{cert_id}/renew")
    def renew_cert(cert_id: str, who=Depends(actor)):
        cert = ctx.certs.get(cert_id)
        if cert["source"] != "acme":
            raise HTTPException(400, "Загруженный сертификат нельзя перевыпустить; загрузите новый")
        if cert["status"] == "pending_dns":
            raise HTTPException(400, "Ожидается публикация TXT-записей")
        db.execute("UPDATE certificates SET challenge=NULL, next_attempt_at=NULL WHERE id=?", (cert_id,))
        db.audit(who, "cert.renew", cert_id)
        return {"started": ctx.certs.start_issue(cert_id)}

    @app.post("/api/certificates/{cert_id}/confirm-dns")
    def confirm_dns(cert_id: str, _=Depends(actor)):
        return ctx.certs.confirm_manual(cert_id)

    @app.get("/api/certificates/{cert_id}/dns-check")
    def dns_check(cert_id: str, _=Depends(current_session)):
        return {"records": ctx.certs.check_records(cert_id)}

    @app.get("/api/certificates/{cert_id}/download")
    def download_cert(cert_id: str, who=Depends(actor)):
        cert = ctx.certs.get(cert_id)
        bundle = ctx.certs.bundle(cert_id)
        db.audit(who, "cert.download", cert_id)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("fullchain.pem", bundle["fullchain_pem"])
            archive.writestr("privkey.pem", bundle["privkey_pem"])
        name = "".join(c if c.isalnum() or c in "-_." else "_" for c in cert["name"])[:60] or "certificate"
        return Response(buffer.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{name}.zip"'})

    # ------------------------------------------------------- dns providers

    @app.post("/api/dns-providers")
    def create_provider(body: dict = Body(...), who=Depends(actor)):
        import uuid as _uuid

        kind = body.get("type")
        name = str(body.get("name") or "").strip()[:60]
        if not name:
            raise HTTPException(400, "Укажите название")
        if kind == "cloudflare":
            token = str(body.get("token") or "").strip()
            if not token:
                raise HTTPException(400, "Укажите API-токен Cloudflare")
            try:
                CloudflareProvider(token).verify()
            except Exception as exc:
                raise HTTPException(400, f"Cloudflare отклонил токен: {exc}")
            creds = {"token": token}
        elif kind == "acmedns":
            server = str(body.get("server") or "https://auth.acme-dns.io").strip().rstrip("/")
            if not server.startswith("https://"):
                raise HTTPException(400, "Адрес acme-dns должен начинаться с https://")
            try:
                reg = AcmeDnsProvider.register(server)
            except Exception as exc:
                raise HTTPException(400, f"acme-dns: {exc}")
            creds = {"server": server, "username": reg["username"], "password": reg["password"],
                     "subdomain": reg["subdomain"], "fulldomain": reg["fulldomain"]}
        else:
            raise HTTPException(400, "Тип провайдера: cloudflare или acmedns")
        pid = _uuid.uuid4().hex[:12]
        db.execute("INSERT INTO dns_providers(id,name,type,credentials,created_at) VALUES(?,?,?,?,?)",
                   (pid, name, kind, ctx.secrets.encrypt(json.dumps(creds)), time.time()))
        db.audit(who, "dns_provider.create", pid, {"type": kind, "name": name})
        return provider_public(db.one("SELECT * FROM dns_providers WHERE id=?", (pid,)), ctx.secrets)

    @app.delete("/api/dns-providers/{pid}")
    def delete_provider(pid: str, who=Depends(actor)):
        used = db.scalar("SELECT COUNT(*) FROM certificates WHERE provider_id=?", (pid,))
        if used:
            raise HTTPException(400, f"Провайдер используется сертификатами: {used}")
        db.execute("DELETE FROM dns_providers WHERE id=?", (pid,))
        db.audit(who, "dns_provider.delete", pid)
        return {"ok": True}

    # ------------------------------------------------------------- system

    @app.get("/api/system")
    def system_info(_=Depends(current_session)):
        agent_version, agent_sha, _p = ctx.releases.agent_bundle()
        return {
            "version": __version__,
            "agent_version": agent_version,
            "agent_sha256": agent_sha,
            "latest": ctx.releases.latest,
            "update_available": ctx.releases.update_available(),
            "update_status": ctx.releases.update_status(),
            "started_at": ctx.started_at,
            "runtimes": ctx.releases.available_runtimes(),
            "engine": ctx.releases.engine(),
            "ca_fingerprint": ctx.pki.ca_fingerprint(),
            "db_size": Path(cfg.db_path).stat().st_size if Path(cfg.db_path).exists() else 0,
        }

    @app.post("/api/system/check-updates")
    def check_updates(_=Depends(actor)):
        ctx.releases.check_latest(force=True)
        return {"latest": ctx.releases.latest, "update_available": ctx.releases.update_available()}

    @app.post("/api/system/update")
    def update_panel(who=Depends(actor)):
        ctx.releases.request_panel_update(who)
        db.audit(who, "panel.update_requested")
        return {"ok": True}

    @app.get("/api/system/audit")
    def audit(limit: int = 200, _=Depends(current_session)):
        rows = db.all("SELECT * FROM audit ORDER BY at DESC LIMIT ?", (max(1, min(1000, limit)),))
        for row in rows:
            try:
                row["detail"] = json.loads(row["detail"]) if row["detail"] else None
            except ValueError:
                pass
        return rows

    # ------------------------------------------------------ firewall/network

    @app.get("/api/settings/firewall")
    def get_firewall(_=Depends(current_session)):
        rw = ctx.settings.remnawave()
        return {"firewall": ctx.settings.firewall(), "network": ctx.settings.network(),
                "remnawave_ips": resolve_host(rw.get("url"), cached_only=True),
                "remnawave_cache": {"at": ctx.remnawave_cache.get("at"), "error": ctx.remnawave_cache.get("error"),
                                    "nodes": len(ctx.remnawave_cache.get("nodes") or [])}}

    @app.put("/api/settings/firewall")
    def put_firewall(body: dict = Body(...), who=Depends(actor)):
        return ctx.settings.set_firewall(body, who)

    @app.put("/api/settings/network")
    def put_network(body: dict = Body(...), who=Depends(actor)):
        return ctx.settings.set_network(body, who)

    @app.post("/api/remnawave/refresh")
    def refresh_remnawave(_=Depends(actor)):
        ctx.refresh_remnawave()
        return {"nodes": len(ctx.remnawave_cache.get("nodes") or []), "error": ctx.remnawave_cache.get("error")}

    @app.post("/api/nodes/{node_id}/nginx/remnawave-sync")
    def remnawave_sync(node_id: str, body: dict = Body(...), who=Depends(actor)):
        """Adjust ONE inbound of the node's Remnawave profile to match a route.
        Without confirm=true only a before/after preview is returned."""
        node = ctx.nodes.get(node_id)
        cfg_nginx = nginx_routes.node_config(node)
        route = next((r for r in cfg_nginx["routes"] if r["id"] == body.get("route_id")), None)
        if not route:
            raise HTTPException(404, "Маршрут не найден")
        rw_node = ctx.nodes.remnawave_node(node)
        if not rw_node:
            raise HTTPException(400, "Нода не сопоставлена с Remnawave")
        profile_uuid = (rw_node.get("configProfile") or {}).get("activeConfigProfileUuid")
        tag = body.get("inbound_tag") or next((c["inbound"] for c in nginx_routes.check_routes(cfg_nginx, rw_node)
                                              if c["route_id"] == route["id"]), None)
        if not profile_uuid or not tag:
            raise HTTPException(400, "Не найден профиль или inbound для синхронизации")
        client = ctx.sanctions.client()
        profile = client.config_profile(profile_uuid)
        config = profile.get("config") or {}
        try:
            new = nginx_routes.patch_profile(config, tag, route)
        except nginx_routes.RouteError as exc:
            raise HTTPException(400, str(exc))
        shared = [n.get("name") for n in (ctx.remnawave_cache.get("nodes") or [])
                  if (n.get("configProfile") or {}).get("activeConfigProfileUuid") == profile_uuid]
        if not body.get("confirm"):
            before = next(i for i in config.get("inbounds", []) if i.get("tag") == tag)
            after = next(i for i in new.get("inbounds", []) if i.get("tag") == tag)
            return {"preview": True, "profile": profile.get("name"), "inbound": tag, "shared_with": shared,
                    "before": before, "after": after}
        client.update_config_profile(profile_uuid, new)
        db.audit(who, "remnawave.profile_inbound_sync", profile_uuid, {"inbound": tag, "node": node_id})
        ctx.refresh_remnawave()
        return {"ok": True, "profile": profile.get("name"), "inbound": tag}

    def vision_plan(node_id):
        """(node, rw_node, profile, before, after, check) for the node's Vision inbound."""
        node = ctx.nodes.get(node_id)
        cfg_nginx = nginx_routes.node_config(node)
        if cfg_nginx["mode"] != "vision":
            raise HTTPException(400, "Нода не в режиме Vision + TLS Fallback")
        rw_node = ctx.nodes.remnawave_node(node)
        check = nginx_routes.check_vision(cfg_nginx, rw_node, ctx.nodes.vision_context(node))
        if check["problems"]:
            raise HTTPException(400, "Синхронизация невозможна: " + "; ".join(check["problems"]))
        profile_uuid = ((rw_node or {}).get("configProfile") or {}).get("activeConfigProfileUuid")
        if not profile_uuid:
            raise HTTPException(400, "У ноды в Remnawave нет профиля конфигурации")
        profile = ctx.sanctions.client().config_profile(profile_uuid)
        config = profile.get("config") or {}
        container_dir = (loads(node.get("cert_target"), {}) or {}).get("container_dir") or "/etc/xray/ssl"
        tag = cfg_nginx["vision"]["inbound_tag"]
        try:
            new = nginx_routes.patch_vision(config, tag, cfg_nginx, container_dir)
        except nginx_routes.RouteError as exc:
            raise HTTPException(400, str(exc))
        before = next(i for i in config.get("inbounds", []) if i.get("tag") == tag)
        after = next(i for i in new.get("inbounds", []) if i.get("tag") == tag)
        return node, profile_uuid, profile, new, before, after, check

    def apply_vision(node_id, who):
        node, profile_uuid, profile, new, before, after, check = vision_plan(node_id)
        if not check["agent_ready"]:
            raise HTTPException(409, "Агент ещё не освободил порт 443 и не поднял fallback-порты Nginx")
        ctx.sanctions.client().update_config_profile(profile_uuid, new)
        db.audit(who, "remnawave.vision_sync", profile_uuid, {"inbound": after.get("tag"), "node": node_id})
        db.set_json(f"vision_sync:{node_id}", {"state": "done", "at": time.time(), "by": who})
        ctx.events.record_system("node", f"Vision: inbound {after.get('tag')} настроен в Remnawave для {node['name']}",
                                 "info", node_id=node_id)
        ctx.refresh_remnawave()
        return {"ok": True, "profile": profile.get("name"), "inbound": after.get("tag")}

    def vision_ready(node_id):
        """Confirmed sync, started by the first report in which Nginx is ready."""
        pending = db.get_json(f"vision_sync:{node_id}") or {}
        try:
            apply_vision(node_id, pending.get("by") or "admin")
        except Exception as exc:  # keep the reason for the UI
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            db.set_json(f"vision_sync:{node_id}", dict(pending, state="failed", error=str(detail)[:400], at=time.time()))
            ctx.events.record_system("node", "Vision: синхронизация с Remnawave не выполнена", "error",
                                     node_id=node_id, data={"detail": str(detail)[:400]})

    ctx.nodes.vision_ready_hook = vision_ready

    @app.post("/api/nodes/{node_id}/nginx/vision-sync")
    def vision_sync(node_id: str, body: dict = Body(...), who=Depends(actor)):
        """Preview (default), apply now (confirm) or apply when the agent is ready (confirm + when_ready)."""
        if body.get("cancel"):
            db.set_json(f"vision_sync:{node_id}", None)
            return {"ok": True}
        node, profile_uuid, profile, new, before, after, check = vision_plan(node_id)
        if not body.get("confirm"):
            return {"preview": True, "profile": profile.get("name"), "inbound": after.get("tag"),
                    "before": before, "after": after, "drift": check["drift"], "notes": check["notes"],
                    "agent_ready": check["agent_ready"]}
        if check["agent_ready"]:
            return apply_vision(node_id, who)
        if not body.get("when_ready"):
            raise HTTPException(409, "Агент ещё не переключил Nginx — подтвердите синхронизацию «когда будет готово»")
        db.set_json(f"vision_sync:{node_id}", {"state": "waiting", "at": time.time(), "by": who})
        db.audit(who, "remnawave.vision_sync_scheduled", profile_uuid, {"inbound": after.get("tag"), "node": node_id})
        return {"ok": True, "scheduled": True}

    # ------------------------------------------------------------- sites

    @app.get("/api/sites")
    def list_sites(_=Depends(current_session)):
        sites = ctx.sites.list()
        default = next((x for x in sites if x["is_default"]), None)
        status = []
        for node in ctx.nodes.list():
            if not nginx_routes.uses_nginx(node["nginx"]):
                continue
            site_row, version = ctx.sites.effective_for({"site_id": node["site_id"]})
            status.append({"id": node["id"], "name": node["name"], "online": node["online"],
                           "site": site_row["name"] if site_row else "встроенная", "wanted": version or "builtin",
                           "installed": (node["site_state"] or {}).get("version")})
        return {"sites": sites, "default": default["id"] if default else None, "nodes": status}

    @app.post("/api/sites/upload")
    async def upload_site(file: UploadFile = File(...), name: str = Form(""), site_id: str = Form(""),
                          note: str = Form(""), who=Depends(actor)):
        data = await file.read(160 << 20)
        if len(data) >= 160 << 20:
            raise HTTPException(413, "ZIP больше 160 МБ")
        return ctx.sites.upload(data, name or (file.filename or "Сайт").rsplit(".", 1)[0], site_id or None, note, who)

    @app.patch("/api/sites/{site_id}")
    def patch_site(site_id: str, body: dict = Body(...), who=Depends(actor)):
        ctx.sites.update(site_id, body.get("name"), body.get("is_default"), who)
        ctx.nodes.wake()
        return ctx.sites.get(site_id)

    @app.post("/api/sites/{site_id}/publish")
    def publish_site(site_id: str, body: dict = Body(...), who=Depends(actor)):
        ctx.sites.publish(site_id, str(body.get("version")), who)
        ctx.nodes.wake()
        return ctx.sites.get(site_id)

    @app.delete("/api/sites/{site_id}")
    def delete_site(site_id: str, who=Depends(actor)):
        ctx.sites.delete(site_id, who)
        ctx.nodes.wake()
        return {"ok": True}

    @app.delete("/api/sites/{site_id}/versions/{version}")
    def delete_site_version(site_id: str, version: str, who=Depends(actor)):
        ctx.sites.delete_version(site_id, version, who)
        return {"ok": True}

    @app.get("/api/sites/{site_id}/preview")
    def site_preview(site_id: str, version: str = "", _=Depends(current_session)):
        site = ctx.sites.get(site_id)
        version = version or site["draft_version"] or site["current_version"]
        if not version:
            raise HTTPException(404, "У сайта нет версий")
        return {"url": f"/site-mask/{ctx.sites.preview_token(site_id, version)}/", "version": version}

    @app.get("/api/nodes/{node_id}/site-preview")
    def node_site_preview(node_id: str, _=Depends(current_session)):
        site, version = ctx.sites.effective_for(ctx.nodes.get(node_id))
        if not site:
            return {"url": "/site-mask/builtin/", "version": "builtin"}
        return {"url": f"/site-mask/{ctx.sites.preview_token(site['id'], version)}/", "version": version}

    preview_headers = {
        # Uploaded JavaScript runs in an opaque origin: no access to the admin
        # session, cookies or panel API, even though the URL is on the panel.
        "Content-Security-Policy": "sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads; "
                                   "default-src 'self' data: blob: https: 'unsafe-inline' 'unsafe-eval'",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        # The sandboxed page has an opaque ("null") origin, so module scripts,
        # fonts and fetch() of its own files are cross-origin requests. The
        # files are already reachable by anyone holding the token and no
        # credentials are allowed, so a wildcard exposes nothing new.
        "Access-Control-Allow-Origin": "*",
    }

    @app.get("/site-mask/")
    def site_mask_root(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if not token or not db.one("SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?",
                                   (security.token_hash(token), time.time())):
            raise HTTPException(401, "Войдите в панель, чтобы открыть предпросмотр")
        default = ctx.sites.default()
        if not default or not default["current_version"]:
            return RedirectResponse("/site-mask/builtin/")
        return RedirectResponse(f"/site-mask/{ctx.sites.preview_token(default['id'], default['current_version'])}/")

    @app.get("/site-mask/{token}/{path:path}")
    def site_mask(token: str, path: str):
        if token == "builtin":
            return Response(DEFAULT_PREVIEW_HTML, media_type="text/html", headers=preview_headers)
        directory = ctx.sites.resolve_token(token)
        if directory is None:
            raise HTTPException(404, "Ссылка предпросмотра устарела — откройте её заново из панели")
        prefix = f"/site-mask/{token}"
        root = directory.resolve()
        candidates = [path, path.rstrip("/") + "/index.html", path + ".html"] if path else ["index.html"]
        target, status = None, 200
        for candidate in candidates:
            item = (root / candidate).resolve()
            if (item == root or root in item.parents) and item.is_file():
                target = item
                break
        if target is None:
            fallback = root / "404.html"
            target, status = (fallback, 404) if fallback.exists() else (root / "index.html", 200)
        kind = target.suffix.lower()
        if kind in (".html", ".htm"):
            return Response(rewrite(target.read_bytes(), "html", prefix), status_code=status,
                            media_type="text/html; charset=utf-8", headers=preview_headers)
        if kind == ".css":
            return Response(rewrite(target.read_bytes(), "css", prefix), media_type="text/css; charset=utf-8",
                            headers=preview_headers)
        if kind in (".js", ".mjs"):
            return Response(rewrite(target.read_bytes(), "js", prefix), media_type="text/javascript; charset=utf-8",
                            headers=preview_headers)
        media = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        return FileResponse(target, media_type=media, headers=preview_headers)

    # ------------------------------------------------------------ domain

    @app.get("/api/system/domain")
    def domain_status(_=Depends(current_session)):
        panel = ctx.settings.panel()
        cert = None
        if panel.get("domain_cert_id"):
            try:
                cert = ctx.certs.get(panel["domain_cert_id"])
            except LookupError:
                cert = None
        return {"domain": panel.get("domain"), "http_port": panel.get("http_port"), "https_port": panel.get("https_port"),
                "web_port": cfg.web_port, "certificate": cert, "listeners": ctx.listeners.status(),
                "acme_email": ctx.settings.acme().get("email"),
                "active": bool(cert and cert["version"] and panel.get("web_cert_id") == cert["id"])}

    @app.post("/api/system/domain/check")
    def domain_check(body: dict = Body(...), _=Depends(actor)):
        domain = normalize_domain(str(body.get("domain") or ""))
        if domain.startswith("*."):
            raise HTTPException(400, "Для панели нужен обычный домен, не wildcard")
        return panel_domain.check(domain, cfg, ctx.settings.panel(), ctx.certs.http_challenges)

    @app.post("/api/system/domain/apply")
    def domain_apply(body: dict = Body(...), who=Depends(actor)):
        domain = normalize_domain(str(body.get("domain") or ""))
        if domain.startswith("*."):
            raise HTTPException(400, "Для панели нужен обычный домен, не wildcard")
        challenge = body.get("challenge") or HTTP01
        http_port = 80 if (challenge == HTTP01 or body.get("redirect_http")) else 0
        https_port = 443 if body.get("listen_443") else 0
        if not ctx.settings.acme().get("email"):
            email = str(body.get("email") or "").strip()
            if not email:
                raise HTTPException(400, "Укажите e-mail для Let's Encrypt")
            ctx.settings.set_acme({"email": email}, who)
        panel = ctx.settings.set_panel({"domain": domain, "http_port": http_port, "https_port": https_port}, who)
        ctx.listeners.request_reconcile()
        for _ in range(30):
            time.sleep(0.2)
            if not http_port or ctx.listeners.http_ready():
                break
        if challenge == HTTP01 and not ctx.listeners.http_ready():
            raise HTTPException(400, "Панель не смогла занять порт 80: "
                                + str(ctx.listeners.status()["errors"].get(80, "порт занят"))
                                + ". Освободите его или выберите DNS-провайдера.")
        cert = None
        if panel.get("domain_cert_id"):
            try:
                cert = ctx.certs.get(panel["domain_cert_id"])
                if cert["domains"] != [domain] or cert["source"] != "acme":
                    cert = None
            except LookupError:
                cert = None
        if cert:
            db.execute("UPDATE certificates SET provider_id=?, challenge=NULL, next_attempt_at=NULL WHERE id=?",
                       (challenge, cert["id"]))
            ctx.certs.start_issue(cert["id"])
        else:
            cert = ctx.certs.create(f"Панель {domain}", [domain], challenge, "ec256", True, who)
            ctx.settings.set_panel({"domain_cert_id": cert["id"]}, who)
        if body.get("agents_use_domain"):
            ctx.settings.set_panel({"public_host": domain}, who)
        db.audit(who, "panel.domain", domain, {"challenge": challenge, "https_port": https_port})
        return {"ok": True, "certificate_id": cert["id"]}

    @app.post("/api/system/domain/reset")
    def domain_reset(who=Depends(actor)):
        ctx.settings.set_panel({"domain": "", "http_port": 0, "https_port": 0, "web_cert_id": None,
                                "domain_cert_id": None}, who)
        ctx.apply_web_certificate()
        ctx.listeners.request_reconcile()
        return {"ok": True}

    # ----------------------------------------------------------------- SPA

    web_dir = cfg.web_dir

    @app.get("/{path:path}")
    def spa(path: str):
        if path.startswith(("api/", "agent/")):
            raise HTTPException(404)
        target = (web_dir / path).resolve()
        if path and target.is_file() and web_dir.resolve() in target.parents:
            headers = {"Cache-Control": "public, max-age=31536000, immutable"} if path.startswith("assets/") else {}
            return FileResponse(target, headers=headers)
        index = web_dir / "index.html"
        if not index.exists():
            return PlainTextResponse("Ezhik Guard: web UI is not built", status_code=503)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app


# =================================================================== agent


def build_agent_app(ctx):
    app = FastAPI(title="Ezhik Guard agent API", docs_url=None, redoc_url=None, openapi_url=None)
    _error_handlers(app)
    db = ctx.db

    def node_auth(request: Request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else ""
        node = ctx.nodes.authenticate(token)
        if not node:
            if ctx.nodes.was_deleted(token):
                raise HTTPException(410, "node was deleted in the panel")
            raise HTTPException(401, "invalid node credentials")
        return node

    def ip_of(request):
        return client_ip(request, ctx.config.trusted_proxies)

    @app.get("/install.sh")
    def install_script():
        template = (ctx.config.install_dir / "packaging" / "install-agent.sh").read_text(encoding="utf-8")
        script = (template.replace("@@PANEL_URL@@", ctx.nodes.agent_base_url())
                  .replace("@@CA_PEM@@", ctx.pki.ca_pem.strip())
                  .replace("@@PIN@@", ctx.pki.server_pin())
                  .replace("@@VERSION@@", ctx.releases.agent_bundle()[0]))
        return PlainTextResponse(script, media_type="text/x-shellscript")

    @app.get("/agent/v1/bootstrap/agent.tar.gz")
    def bootstrap_bundle():
        # Public on purpose: the bundle is open source and the install script
        # verifies its SHA-256 (embedded via the pinned TLS channel).
        version, sha, path = ctx.releases.agent_bundle()
        return FileResponse(path, media_type="application/gzip", headers={"X-Agent-Version": version, "X-SHA256": sha})

    @app.get("/agent/v1/bootstrap/agent.sha256")
    def bootstrap_sha():
        version, sha, _path = ctx.releases.agent_bundle()
        return PlainTextResponse(f"{sha}  {version}\n")

    @app.post("/agent/v1/register")
    def register(request: Request, body: dict = Body(...)):
        try:
            return ctx.nodes.register(str(body.get("install_token") or ""), body, ip_of(request))
        except PermissionError as exc:
            raise HTTPException(403, str(exc))

    @app.post("/agent/v1/sync")
    async def sync(request: Request, body: dict = Body(...)):
        node = node_auth(request)
        return await ctx.nodes.sync(node, body, ip_of(request))

    @app.post("/agent/v1/goodbye")
    def goodbye(request: Request):
        """The agent is about to uninstall itself (panel-initiated removal)."""
        node = node_auth(request)
        if node["status"] == "removing":
            ctx.nodes.finish_removal(node["id"])
        return {"ok": True}

    @app.post("/agent/v1/events")
    def events(request: Request, body: dict = Body(...)):
        node = node_auth(request)
        items = body.get("events") if isinstance(body.get("events"), list) else []
        return {"accepted": ctx.events.ingest(node, items)}

    @app.post("/agent/v1/legacy")
    def legacy(request: Request, body: dict = Body(...)):
        node = node_auth(request)
        sanctions = body.get("sanctions") if isinstance(body.get("sanctions"), list) else []
        adopted = ctx.sanctions.adopt_legacy(sanctions, node["id"])
        settings = body.get("settings") if isinstance(body.get("settings"), dict) else {}
        protected = [c for c in str(settings.get("EZHIK_PROTECTED_CLIENTS") or "").split(",") if c.strip().isdigit()]
        if protected:
            current = ctx.settings.protection()
            merged = sorted(set(current["protected_clients"]) | {c.strip() for c in protected}, key=int)
            if merged != current["protected_clients"]:
                ctx.settings.set_protection({"protected_clients": merged}, "legacy-migration")
        version = (body.get("detected") or {}).get("version")
        ctx.events.record_system("node", f"На {node['name']} найдена старая версия Torrent Guard {version or ''} — "
                                 f"удаляется; перенесено санкций: {adopted}", "warn", node_id=node["id"],
                                 data={"detected": body.get("detected"), "adopted": adopted})
        return {"adopted": adopted}

    @app.get("/agent/v1/ping")
    def ping(request: Request):
        node_auth(request)
        return {"ok": True, "time": time.time()}

    @app.get("/agent/v1/site/{site_id}/{name}")
    def site_bundle(site_id: str, name: str, request: Request):
        node = node_auth(request)
        site, version = ctx.sites.effective_for(node)
        if not site or site["id"] != site_id or name != f"{version}.tar.gz":
            raise HTTPException(404, "site not assigned to this node")
        return FileResponse(ctx.sites.bundle_path(site_id, version), media_type="application/gzip")

    @app.get("/agent/v1/certificate")
    def certificate(request: Request):
        node = node_auth(request)
        if not node["cert_id"]:
            raise HTTPException(404, "no certificate assigned")
        return ctx.certs.bundle(node["cert_id"])

    @app.get("/agent/v1/agent-bundle/{name}")
    def agent_bundle(name: str, request: Request):
        node_auth(request)
        version, _sha, path = ctx.releases.agent_bundle()
        if name != f"{version}.tar.gz":
            raise HTTPException(404, "unknown agent version")
        return FileResponse(path, media_type="application/gzip")

    @app.get("/agent/v1/runtime/{asset}")
    def runtime(asset: str, request: Request):
        node_auth(request)
        try:
            path = ctx.releases.runtime_path(asset)
        except LookupError:
            raise HTTPException(404, "unknown runtime")
        except Exception as exc:
            log.exception("Runtime download failed")
            raise HTTPException(502, f"runtime unavailable: {exc}")
        return FileResponse(path, media_type="application/zstd")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app

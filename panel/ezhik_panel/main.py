"""Panel entry point and CLI."""

import argparse
import asyncio
import logging
import os
import secrets
import shutil
import signal
import ssl
import sys
import threading
import time

from . import __version__, config as config_mod, security
from .certificates import CertificateService
from .db import Database
from .events import EventService
from .nodes import NodeService
from .notifier import Notifier
from .pki import PKI
from .releases import Releases
from .sanctions import SanctionService
from .settings_service import SettingsService

log = logging.getLogger("ezhik.panel")


class Context:
    def __init__(self, cfg):
        self.config = cfg
        self.started_at = time.time()
        self.db = Database(cfg.db_path)
        self.secrets = security.SecretBox(cfg.data_dir / "secret.key")
        self.settings = SettingsService(self.db, self.secrets)
        self.notifier = Notifier(self.settings)
        self.events = EventService(self.db, self.settings, self.notifier)
        self.sanctions = SanctionService(self.db, self.settings, self.events)
        self.events.sanctions = self.sanctions
        self.releases = Releases(cfg, self.db)
        self.pki = PKI(cfg.pki_dir)
        names = [n for n in {cfg.public_host, self.settings.panel().get("public_host")} if n]
        self.pki.ensure(names)
        self.certs = CertificateService(self.db, self.settings, self.secrets, self.events, cfg,
                                        on_change=self._cert_changed)
        self.nodes = NodeService(self.db, self.settings, self.events, self.releases, self.certs, self.pki, cfg)
        self.web_ssl = None
        self.settings.listeners.append(self._settings_changed)
        self._stop = threading.Event()

    def _cert_changed(self, cert_id):
        for row in self.db.all("SELECT id FROM nodes WHERE cert_id=?", (cert_id,)):
            self.nodes.wake(row["id"])
        if self.settings.panel().get("web_cert_id") == cert_id:
            self.apply_web_certificate()

    def _settings_changed(self, section):
        if section == "panel":
            names = [n for n in {self.config.public_host, self.settings.panel().get("public_host")} if n]
            self.pki.ensure(names)

    def web_cert_files(self):
        cert_id = self.settings.panel().get("web_cert_id")
        if cert_id:
            cert, key = self.certs.paths(cert_id)
            if cert.exists() and key.exists():
                return str(cert), str(key)
        return str(self.pki.server_cert_path), str(self.pki.server_key_path)

    def apply_web_certificate(self):
        """Hot-swap the UI certificate for new TLS handshakes."""
        if self.web_ssl is None:
            return
        cert, key = self.web_cert_files()
        try:
            self.web_ssl.load_cert_chain(cert, key)
            log.info("Web UI certificate loaded from %s", cert)
        except (OSError, ssl.SSLError) as exc:
            log.error("Cannot load web certificate: %s", exc)

    # ------------------------------------------------------------ jobs

    def start_background(self):
        self.notifier.start()
        self.sanctions.start()
        threading.Thread(target=self._jobs, name="jobs", daemon=True).start()
        threading.Thread(target=self.releases.agent_bundle, daemon=True).start()

    def _jobs(self):
        last = {"monitor": 0, "certs": 0, "cleanup": 0, "updates": 0}
        while not self._stop.wait(5):
            now = time.time()
            try:
                if now - last["monitor"] >= 15:
                    self.nodes.monitor()
                    last["monitor"] = now
                if now - last["certs"] >= 900:
                    self.certs.renew_due()
                    last["certs"] = now
                if now - last["cleanup"] >= 3600:
                    self.events.cleanup()
                    self.db.execute("DELETE FROM login_attempts WHERE at<?", (now - 86400,))
                    last["cleanup"] = now
                if now - last["updates"] >= 6 * 3600:
                    self.releases.check_latest(force=True)
                    last["updates"] = now
            except Exception:
                log.exception("Background job failed")


async def serve(ctx):
    import uvicorn

    from .app import build_admin_app, build_agent_app

    cfg = ctx.config
    admin_app = build_admin_app(ctx)
    agent_app = build_agent_app(ctx)
    web_kwargs = {}
    if cfg.web_tls:
        cert, key = ctx.web_cert_files()
        web_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
    web = uvicorn.Server(uvicorn.Config(
        admin_app, host=cfg.web_host, port=cfg.web_port, log_level="warning", access_log=False,
        proxy_headers=False, server_header=False, timeout_keep_alive=30, **web_kwargs))
    agent = uvicorn.Server(uvicorn.Config(
        agent_app, host=cfg.agent_host, port=cfg.agent_port, log_level="warning", access_log=False,
        proxy_headers=False, server_header=False, timeout_keep_alive=75,
        ssl_certfile=str(ctx.pki.server_cert_path), ssl_keyfile=str(ctx.pki.server_key_path)))
    for server in (web, agent):
        server.install_signal_handlers = lambda: None
    ctx.nodes.bind_loop(asyncio.get_running_loop())

    loop = asyncio.get_running_loop()

    def shutdown(*_):
        web.should_exit = True
        agent.should_exit = True
        ctx._stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            signal.signal(sig, shutdown)

    async def capture_ssl():
        while not web.started:
            await asyncio.sleep(0.2)
        ctx.web_ssl = web.config.ssl

    log.info("Ezhik Guard panel %s: UI %s://%s:%s, agents https://%s:%s", __version__,
             "https" if cfg.web_tls else "http", cfg.web_host, cfg.web_port, cfg.agent_host, cfg.agent_port)
    await asyncio.gather(web.serve(), agent.serve(), capture_ssl())


# -------------------------------------------------------------------- CLI


def cmd_admin(cfg, username, password=None, reset=False):
    db = Database(cfg.db_path)
    generated = password is None
    password = password or secrets.token_urlsafe(12)
    existing = db.one("SELECT id FROM admins WHERE username=?", (username,))
    if existing and not reset:
        print(f"admin {username} already exists", file=sys.stderr)
        return 1
    if existing:
        db.execute("UPDATE admins SET password_hash=?, password_changed_at=? WHERE id=?",
                   (security.hash_password(password), time.time(), existing["id"]))
        db.execute("DELETE FROM sessions WHERE admin_id=?", (existing["id"],))
    else:
        db.execute("INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
                   (username, security.hash_password(password), time.time()))
    db.audit("cli", "admin.reset" if existing else "admin.create", username)
    if generated:
        print(password)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ezhik-guard-panel")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run")
    admin = sub.add_parser("admin", help="create an admin or reset a password")
    admin.add_argument("--username", default="admin")
    admin.add_argument("--password")
    admin.add_argument("--reset", action="store_true")
    node = sub.add_parser("create-node", help="create a node and print its install command")
    node.add_argument("--name", required=True)
    sub.add_parser("has-admin")
    sub.add_parser("info")
    sub.add_parser("version")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    if args.command == "version":
        print(__version__)
        return 0
    cfg = config_mod.load()
    if args.command == "admin":
        return cmd_admin(cfg, args.username, args.password, args.reset)
    if args.command == "has-admin":
        db = Database(cfg.db_path)
        return 0 if db.scalar("SELECT COUNT(*) FROM admins") else 1
    if args.command == "create-node":
        ctx = Context(cfg)
        existing = ctx.db.one("SELECT id FROM nodes WHERE name=? COLLATE NOCASE", (args.name,))
        node_id = existing["id"] if existing else ctx.nodes.create(args.name, "cli")["id"]
        print(ctx.nodes.install_command(node_id)["command"])
        return 0
    if args.command == "info":
        ctx = Context(cfg)
        print(f"version={__version__}")
        print(f"agent_url={ctx.nodes.agent_base_url()}")
        print(f"ca_fingerprint={ctx.pki.ca_fingerprint()}")
        return 0
    ctx = Context(cfg)
    ctx.start_background()
    try:
        asyncio.run(serve(ctx))
    finally:
        ctx._stop.set()
    return 0


__all__ = ["main", "Context", "os", "shutil"]

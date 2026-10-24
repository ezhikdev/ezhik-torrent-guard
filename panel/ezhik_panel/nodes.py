"""Nodes: onboarding, desired state, long-poll sync, health and history."""

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
import uuid

from . import firewall as fw
from . import nginx_routes, security
from .db import loads
from .events import node_flag

log = logging.getLogger("ezhik.nodes")

OFFLINE_AFTER = 75
INSTALL_TOKEN_TTL = 24 * 3600
NAME_RE = re.compile(r"^[\w .@()\-\[\]]{1,64}$", re.UNICODE)
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


class NodeError(ValueError):
    pass


class NodeService:
    def __init__(self, db, settings, events, releases, certs_provider, pki, config):
        self.db = db
        self.settings = settings
        self.events = events
        self.releases = releases
        self.certs = certs_provider
        self.pki = pki
        self.config = config
        self.loop = None
        self._waiters = {}
        self._lock = threading.Lock()
        self._last_metric = {}
        self._last_seen_mem = {}
        self.sites = None
        self.remnawave_cache = {}
        self.vision_ready_hook = None   # set by the app: performs a confirmed Remnawave sync

    # --------------------------------------------------------------- wake

    def bind_loop(self, loop):
        self.loop = loop

    def _waiter(self, node_id):
        with self._lock:
            event = self._waiters.get(node_id)
            if event is None:
                event = asyncio.Event()
                self._waiters[node_id] = event
            return event

    def wake(self, node_id=None):
        """Release long-polls (one node, or every node when None)."""
        if self.loop is None:
            return
        with self._lock:
            targets = list(self._waiters.values()) if node_id is None else [self._waiters.get(node_id)]
        for event in targets:
            if event is not None:
                self.loop.call_soon_threadsafe(event.set)

    # ------------------------------------------------------------- queries

    def get(self, node_id):
        row = self.db.one("SELECT * FROM nodes WHERE id=?", (node_id,))
        if not row:
            raise LookupError("Нода не найдена")
        return row

    def public(self, row, detail=False):
        protection = self.settings.protection()
        report = loads(row.get("report"), {}) or {}
        facts = loads(row.get("facts"), {}) or {}
        now = time.time()
        online = bool(row["last_seen_at"] and now - row["last_seen_at"] < OFFLINE_AFTER)
        components = report.get("components") or {}
        problems = [f"{name}: {c.get('message')}" for name, c in components.items() if c and not c.get("ok")]
        agent_bundle = self.releases.agent_bundle()
        out = {
            "id": row["id"],
            "name": row["name"],
            "status": row["status"],
            "online": online,
            "last_seen_at": row["last_seen_at"],
            "state_changed_at": row["state_changed_at"],
            "created_at": row["created_at"],
            "hostname": row["hostname"],
            "ip": facts.get("wan_ip") or row["last_ip"],
            "last_ip": row["last_ip"],
            "agent_version": row["agent_version"],
            "agent_latest": agent_bundle[0],
            "update_available": bool(row["agent_version"] and row["agent_version"] != agent_bundle[0]),
            "updating": bool(row["desired_agent_version"] and row["desired_agent_version"] != row["agent_version"]),
            "update_state": (report.get("update") or {}),
            "os": (facts.get("os") or {}).get("pretty"),
            "os_version": (facts.get("os") or {}).get("version"),
            "kernel": facts.get("kernel"),
            "arch": facts.get("arch"),
            "docker": facts.get("docker"),
            "container": row["container"] or facts.get("container") or "remnanode",
            "container_override": row["container"],
            "container_state": facts.get("container_state"),
            "boot_time": facts.get("boot_time"),
            "metrics": report.get("metrics") or {},
            "torrent_enabled": node_flag(row["torrent_enabled"], protection["torrent"]["default_enabled"]),
            "scan_enabled": node_flag(row["scan_enabled"], protection["scan"]["default_enabled"]),
            "torrent_override": row["torrent_enabled"],
            "scan_override": row["scan_enabled"],
            "detector": report.get("detector") or {},
            "components": components,
            "problems": problems,
            "cert_id": row["cert_id"],
            "cert_state": report.get("cert"),
            "cert_target": loads(row["cert_target"], {}) or {},
            "domain": row["domain"],
            "interface": row["interface"],
            "wan_ip": row["wan_ip"],
            "tags": loads(row["tags"], []) or [],
            "notes": row["notes"] or "",
            "synced": bool(row["applied_generation"] and row["applied_generation"] == self.generation_for(row)),
            "legacy": report.get("legacy"),
            "outbox": report.get("outbox"),
            "nginx": nginx_routes.node_config(row),
            "nginx_state": report.get("nginx") or {},
            "firewall_state": report.get("firewall") or {},
            "firewall_override": loads(row.get("firewall"), {}) or {},
            "bbr": row.get("bbr"),
            "bbr_state": report.get("bbr") or {},
            "site_id": row.get("site_id"),
            "site_state": report.get("site") or {},
            "remnawave_node_hint": row.get("remnawave_node"),
        }
        if detail:
            plan_cfg, plan = self.firewall_plan(row)
            plan["applied_enabled"] = plan_cfg["enabled"]
            out["firewall"] = plan
            out["ports"] = report.get("ports") or {}
            rw = self.remnawave_node(row)
            out["remnawave"] = {"uuid": rw.get("uuid"), "name": rw.get("name"), "address": rw.get("address"),
                                "port": rw.get("port"), "inbounds": [
                                    {k: i.get(k) for k in ("tag", "type", "network", "security", "port")}
                                    for i in ((rw.get("configProfile") or {}).get("activeInbounds") or [])]} if rw else None
            out["remnawave_status"] = None if rw else self.remnawave_status(row)
            out["route_checks"] = nginx_routes.check_routes(out["nginx"], rw, (report.get("ports") or {}).get("container_network"))
            if out["nginx"]["mode"] == "vision":
                out["vision_check"] = nginx_routes.check_vision(out["nginx"], rw, self.vision_context(row, report))
                out["vision_pending"] = self.db.get_json(f"vision_sync:{row['id']}")
            out["diagnostics"] = loads(row["diagnostics"], None)
            out["diagnostics_at"] = row["diagnostics_at"]
            out["facts"] = facts
            out["availability"] = {
                "24h": self.availability(row["id"], 86400),
                "7d": self.availability(row["id"], 7 * 86400),
                "30d": self.availability(row["id"], 30 * 86400),
            }
        return out

    def list(self):
        rows = self.db.all("SELECT * FROM nodes ORDER BY sort, name COLLATE NOCASE")
        return [self.public(r) for r in rows]

    # ----------------------------------------------------------- onboarding

    def create(self, name, actor="admin", torrent=None, scan=None, container=None, tags=None):
        name = (name or "").strip()
        if not NAME_RE.match(name):
            raise NodeError("Название: 1–64 символа, буквы, цифры, пробел и .-_@()[]")
        if self.db.scalar("SELECT 1 FROM nodes WHERE name=? COLLATE NOCASE", (name,)):
            raise NodeError("Нода с таким названием уже существует")
        if container and not CONTAINER_RE.match(container):
            raise NodeError("Недопустимое имя контейнера")
        node_id = uuid.uuid4().hex[:12]
        now = time.time()
        self.db.execute(
            "INSERT INTO nodes(id,name,status,created_at,torrent_enabled,scan_enabled,container,tags,sort) "
            "VALUES(?,?,?,?,?,?,?,?,(SELECT COALESCE(MAX(sort),0)+1 FROM nodes))",
            (node_id, name, "pending", now, _tri(torrent), _tri(scan), container or None,
             json.dumps(tags or [], ensure_ascii=False)),
        )
        self.db.audit(actor, "node.create", node_id, {"name": name})
        return self.get(node_id)

    def issue_install_token(self, node_id):
        node = self.get(node_id)
        token = security.new_token(24)
        now = time.time()
        self.db.execute("DELETE FROM install_tokens WHERE node_id=?", (node_id,))
        self.db.execute(
            "INSERT INTO install_tokens(token_hash,node_id,created_at,expires_at) VALUES(?,?,?,?)",
            (security.token_hash(token), node["id"], now, now + INSTALL_TOKEN_TTL),
        )
        return token, now + INSTALL_TOKEN_TTL

    def agent_base_url(self):
        host = self.settings.panel().get("public_host") or self.config.public_host or "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"https://{host}:{self.config.agent_port}"

    def install_command(self, node_id):
        token, expires = self.issue_install_token(node_id)
        base = self.agent_base_url()
        pin = self.pki.server_pin()
        command = (
            f"curl -fsSL --pinnedpubkey '{pin}' -k {base}/install.sh | sudo bash -s -- --token {token}"
        )
        return {"command": command, "expires_at": expires, "panel_url": base, "pin": pin}

    def register(self, install_token, payload, ip):
        record = self.db.one("SELECT * FROM install_tokens WHERE token_hash=?", (security.token_hash(install_token or ""),))
        now = time.time()
        if not record or record["used_at"] or record["expires_at"] < now:
            raise PermissionError("Токен установки недействителен или истёк. Сгенерируйте новую команду в панели.")
        node = self.get(record["node_id"])
        token = security.new_token(32)
        facts = {
            "hostname": str(payload.get("hostname") or "")[:120],
            "os": payload.get("os") if isinstance(payload.get("os"), dict) else {},
            "arch": str(payload.get("arch") or "")[:20],
            "wan_interface": payload.get("wan_interface"),
            "wan_ip": payload.get("wan_ip"),
        }
        with self.db.tx() as conn:
            conn.execute("UPDATE install_tokens SET used_at=? WHERE token_hash=?", (now, record["token_hash"]))
            conn.execute(
                "UPDATE nodes SET token_hash=?, status=CASE WHEN status='pending' THEN 'active' ELSE status END, "
                "registered_at=?, last_seen_at=?, hostname=?, last_ip=?, facts=?, agent_version=? WHERE id=?",
                (security.token_hash(token), now, now, facts["hostname"], ip, json.dumps(facts),
                 str(payload.get("agent_version") or "")[:32], node["id"]),
            )
        self.db.audit("agent", "node.register", node["id"], {"ip": ip, "hostname": facts["hostname"]})
        self.events.record_system("node", f"Нода {node['name']} подключена ({ip})", node_id=node["id"])
        return {"node_id": node["id"], "node_token": token, "name": node["name"]}

    def authenticate(self, token):
        if not token:
            return None
        return self.db.one("SELECT * FROM nodes WHERE token_hash=?", (security.token_hash(token),))

    # --------------------------------------------------------- desired state

    def desired_config(self, node):
        protection = self.settings.protection()
        facts = loads(node.get("facts"), {}) or {}
        torrent = node_flag(node["torrent_enabled"], protection["torrent"]["default_enabled"])
        scan = node_flag(node["scan_enabled"], protection["scan"]["default_enabled"])
        if node["status"] != "active":
            torrent = scan = False
        cfg = {
            "detector": {
                "container": node["container"] or facts.get("container") or "remnanode",
                "torrent": {"enabled": torrent, "cooldown_seconds": protection["torrent"]["freeze_seconds"]},
                "p2p": {
                    "enabled": bool(protection["p2p"]["enabled"]) and torrent,
                    "udp_hosts": protection["p2p"]["udp_hosts"],
                    "udp_networks": protection["p2p"]["udp_networks"],
                    "tcp_hosts": protection["p2p"]["tcp_hosts"],
                    "tcp_networks": protection["p2p"]["tcp_networks"],
                },
                "scan": {"enabled": scan, **{k: protection["scan"][k] for k in (
                    "window_seconds", "tcp_vertical_ports", "udp_vertical_ports", "subnet_hosts",
                    "subnet_ports", "subnet_endpoints", "cooldown_seconds")}},
            },
            "interface": node["interface"] or None,
            "wan_ip": node["wan_ip"] or None,
            "runtime": self.releases.runtime_for(facts.get("os")),
            "log_max_bytes": protection["log_max_bytes"],
            "remove_legacy": protection.get("remove_legacy", True),
            "cert": None,
            "site": None,
            "cert_target": loads(node["cert_target"], {}) or {},
            "cert_remove": bool(node["cert_remove"]),
            "agent": None,
        }
        if node["cert_id"]:
            cert = self.db.one("SELECT id, name, version, domains FROM certificates WHERE id=?", (node["cert_id"],))
            if cert and cert["version"]:
                cfg["cert"] = {"id": cert["id"], "name": cert["name"], "version": cert["version"],
                               "domains": loads(cert["domains"], [])}
        nginx_cfg = nginx_routes.node_config(node)
        if not nginx_cfg["server_name"] and node.get("domain"):
            nginx_cfg["server_name"] = node["domain"]
        cfg["nginx"] = nginx_cfg
        if nginx_routes.uses_nginx(nginx_cfg) and self.sites:
            site, version = self.sites.effective_for(node)
            if site:
                sha = self.db.scalar("SELECT sha256 FROM site_versions WHERE site_id=? AND version=?", (site["id"], version))
                cfg["site"] = {"id": site["id"], "name": site["name"], "version": version, "sha256": sha,
                               "url": f"/agent/v1/site/{site['id']}/{version}.tar.gz"}
        network = self.settings.network()
        cfg["bbr"] = bool(node["bbr"]) if node.get("bbr") is not None else (True if network["bbr_default"] else None)
        cfg["firewall"] = self.firewall_plan(node)[0]
        if node["desired_agent_version"]:
            version, sha, _path = self.releases.agent_bundle()
            if node["desired_agent_version"] == version:
                cfg["agent"] = {"version": version, "sha256": sha, "url": f"/agent/v1/agent-bundle/{version}.tar.gz"}
        return cfg

    def vision_context(self, node, report=None):
        report = report if report is not None else (loads(node.get("report"), {}) or {})
        cert = None
        if node.get("cert_id"):
            row = self.db.one("SELECT id, name, version, domains FROM certificates WHERE id=?", (node["cert_id"],))
            if row:
                cert = {"id": row["id"], "name": row["name"], "version": row["version"],
                        "domains": loads(row["domains"], [])}
        nginx_cfg = nginx_routes.node_config(node)
        return {
            "cert": cert,
            "cert_state": report.get("cert") or {},
            "cert_target": loads(node.get("cert_target"), {}) or {},
            "server_name": nginx_cfg["server_name"] or node.get("domain") or "",
            "nginx_state": report.get("nginx") or {},
            "container_network": (report.get("ports") or {}).get("container_network"),
            "rw_nodes": (self.remnawave_cache or {}).get("nodes") or [],
        }

    def remnawave_status(self, node):
        """Why a node is not matched with Remnawave (shown instead of a generic hint)."""
        cache = self.remnawave_cache or {}
        if cache.get("error"):
            return f"Не удалось получить ноды из Remnawave: {cache['error']}"
        if not cache.get("nodes"):
            return "Список нод Remnawave ещё не получен — проверьте «Настройки → Remnawave» и права API-ключа (nodes:list)"
        hint = (node.get("remnawave_node") or "").strip()
        if hint:
            return f"В Remnawave нет ноды с UUID или адресом «{hint}»"
        return "Ни одна нода Remnawave не совпала по IP/домену — укажите UUID ноды в «Параметры»"

    def remnawave_node(self, node):
        """Matching Remnawave node from the background cache (never blocks)."""
        cache = (self.remnawave_cache or {}).get("nodes") or []
        facts = loads(node.get("facts"), {}) or {}
        addresses = {facts.get("wan_ip"), node.get("last_ip"), node.get("wan_ip"), node.get("domain")}
        hint = (node.get("remnawave_node") or "").strip().lower()
        for item in cache:
            if hint and hint in (str(item.get("uuid") or "").lower(), str(item.get("address") or "").strip().lower()):
                return item
        for item in cache:
            if str(item.get("address") or "").strip() in addresses:
                return item
        return None

    def firewall_plan(self, node):
        rw = self.remnawave_node(node)
        report = loads(node.get("report"), {}) or {}
        inbound_ports = []
        for inbound in ((rw or {}).get("configProfile") or {}).get("activeInbounds") or []:
            raw = inbound.get("rawInbound") or {}
            listen = str(raw.get("listen") or "0.0.0.0")
            if inbound.get("port") and not listen.startswith("127.") and listen not in ("::1", "localhost"):
                inbound_ports.append((int(inbound["port"]), fw.inbound_protos(raw)))
        nginx = nginx_routes.node_config(node)
        internal = [r["upstream_port"] for r in nginx.get("routes") or []
                    if nginx_routes.uses_nginx(nginx) and r.get("enabled")
                    and nginx_routes.is_local(r.get("upstream_host"))]
        return fw.plan(node, self.settings.firewall(), report,
                       remnawave_url=self.settings.remnawave().get("url"),
                       remnanode_port=(rw or {}).get("port"),
                       nginx_ports=nginx_routes.public_ports(nginx),
                       inbound_ports=inbound_ports, internal_ports=internal)

    def generation_for(self, node, config=None):
        config = config if config is not None else self.desired_config(node)
        return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:16]

    # ----------------------------------------------------------------- sync

    def record_report(self, node, body, ip):
        now = time.time()
        facts = body.get("facts")
        prev_seen = node["last_seen_at"]
        fields = {
            "last_seen_at": now,
            "last_ip": ip,
            "agent_version": str(body.get("agent_version") or node["agent_version"] or "")[:32],
            "applied_generation": str(body.get("applied_generation") or "")[:32] or None,
            "report": json.dumps({k: body.get(k) for k in (
                "metrics", "detector", "components", "cert", "runtime", "update", "legacy", "outbox",
                "ports", "nginx", "firewall", "bbr", "site")},
                ensure_ascii=False)[:200000],
        }
        if isinstance(facts, dict):
            fields["facts"] = json.dumps(facts, ensure_ascii=False)[:20000]
            fields["hostname"] = str(facts.get("hostname") or "")[:120]
        if body.get("diagnostics") is not None:
            fields["diagnostics"] = json.dumps(body["diagnostics"], ensure_ascii=False)[:100000]
            fields["diagnostics_at"] = body.get("diagnostics_at") or now
        if not node["online"]:
            fields["online"] = 1
            fields["state_changed_at"] = now
        if node["desired_agent_version"] and fields["agent_version"] == node["desired_agent_version"]:
            fields["desired_agent_version"] = None
            self.events.record_system("node", f"Агент на {node['name']} обновлён до {fields['agent_version']}",
                                      node_id=node["id"])
        sets = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE nodes SET {sets} WHERE id=?", (*fields.values(), node["id"]))
        if not node["online"] and node["status"] == "active" and node["state_changed_at"]:
            self.events.record_system("node", f"Нода {node['name']} снова на связи", node_id=node["id"])

        # Availability: credit the time since the previous report (<= 60 s).
        if prev_seen and now - prev_seen <= 90:
            credit = min(60.0, now - prev_seen)
            hour = int(now // 3600) * 3600
            self.db.execute(
                "INSERT INTO node_uptime(node_id,hour,online_seconds) VALUES(?,?,?) "
                "ON CONFLICT(node_id,hour) DO UPDATE SET online_seconds=MIN(3600, online_seconds+excluded.online_seconds)",
                (node["id"], hour, credit),
            )
        metrics = body.get("metrics") or {}
        minute = int(now // 60) * 60
        if metrics and self._last_metric.get(node["id"]) != minute:
            self._last_metric[node["id"]] = minute
            mem = None
            if metrics.get("mem_total"):
                mem = round(100.0 * (metrics.get("mem_used") or 0) / metrics["mem_total"], 1)
            self.db.execute(
                "INSERT OR REPLACE INTO node_metrics(node_id,ts,cpu,mem,rx,tx,load1) VALUES(?,?,?,?,?,?,?)",
                (node["id"], minute, metrics.get("cpu"), mem, metrics.get("rx_bps"), metrics.get("tx_bps"),
                 (metrics.get("load") or [None])[0]),
            )
        for cid in body.get("acks") or []:
            self.db.execute("UPDATE node_commands SET done_at=? WHERE id=? AND node_id=?", (now, cid, node["id"]))
        pending = self.db.get_json(f"vision_sync:{node['id']}")
        nginx_state = body.get("nginx") or {}
        if pending and pending.get("state") == "waiting" and nginx_state.get("mode") == "vision" \
                and nginx_state.get("fallback_ok") and self.vision_ready_hook:
            self.db.set_json(f"vision_sync:{node['id']}", dict(pending, state="running"))
            threading.Thread(target=self.vision_ready_hook, args=(node["id"],), daemon=True).start()
        report = body.get("update_report")
        report_key = f"update_report:{node['id']}"
        if isinstance(report, dict) and self.db.get_json(report_key) == report.get("started_at"):
            report = None  # already processed (re-sent after a lost response)
        elif isinstance(report, dict):
            self.db.set_json(report_key, report.get("started_at"))
        if isinstance(report, dict) and report.get("result") == "rolled-back":
            # Do not retry a release that crash-looped; the admin can retry.
            self.db.execute("UPDATE nodes SET desired_agent_version=NULL WHERE id=?", (node["id"],))
            data = dict(report, details={"Версия": f"{report.get('from')} → {report.get('to')}"})
            if _version_tuple(report.get("from")) < (2, 1, 2) and \
                    (report.get("rolled_back_at") or 0) - (report.get("started_at") or 0) < 30:
                data["detail"] = UNIT_FIX_HINT
            self.events.record_system("node", f"Обновление агента на {node['name']} откатено", "error",
                                      node_id=node["id"], data=data)

    def pending_commands(self, node_id):
        rows = self.db.all(
            "SELECT id, type, args FROM node_commands WHERE node_id=? AND done_at IS NULL AND "
            "(delivered_at IS NULL OR delivered_at < ?) ORDER BY created_at",
            (node_id, time.time() - 120),
        )
        now = time.time()
        for row in rows:
            self.db.execute("UPDATE node_commands SET delivered_at=? WHERE id=?", (now, row["id"]))
            row["args"] = loads(row["args"], {})
        return rows

    async def sync(self, node, body, ip):
        self.record_report(node, body, ip)
        node = self.get(node["id"])
        if node["status"] == "removing":
            commands = [{"id": "uninstall-" + node["id"], "type": "uninstall"}]
            return {"generation": None, "config": None, "commands": commands, "server_time": time.time()}
        if body.get("push"):
            # Out-of-band state report (e.g. Nginx became ready): no config, no commands.
            return {"pushed": True, "server_time": time.time()}
        wait = max(0, min(30, int(body.get("wait") or 0)))
        waiter = self._waiter(node["id"])
        waiter.clear()
        config = self.desired_config(node)
        generation = self.generation_for(node, config)
        commands = self.pending_commands(node["id"])
        if generation == body.get("applied_generation") and not commands and wait:
            try:
                await asyncio.wait_for(waiter.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass
            node = self.get(node["id"])
            config = self.desired_config(node)
            generation = self.generation_for(node, config)
            commands = self.pending_commands(node["id"])
        return {"generation": generation, "config": config, "commands": commands, "server_time": time.time()}

    # --------------------------------------------------------------- admin

    def update_node(self, node_id, data, actor="admin"):
        node = self.get(node_id)
        fields = {}
        if "name" in data:
            name = str(data["name"]).strip()
            if not NAME_RE.match(name):
                raise NodeError("Недопустимое название")
            if self.db.scalar("SELECT 1 FROM nodes WHERE name=? COLLATE NOCASE AND id!=?", (name, node_id)):
                raise NodeError("Нода с таким названием уже существует")
            fields["name"] = name
        for key in ("torrent_enabled", "scan_enabled"):
            if key in data:
                fields[key] = _tri(data[key])
        if "container" in data:
            value = (data["container"] or "").strip() or None
            if value and not CONTAINER_RE.match(value):
                raise NodeError("Недопустимое имя контейнера")
            fields["container"] = value
        if "interface" in data:
            value = (data["interface"] or "").strip() or None
            if value and not IFACE_RE.match(value):
                raise NodeError("Недопустимое имя интерфейса")
            fields["interface"] = value
        if "wan_ip" in data:
            value = (data["wan_ip"] or "").strip() or None
            if value and not IPV4_RE.match(value):
                raise NodeError("Укажите IPv4-адрес")
            fields["wan_ip"] = value
        if "domain" in data:
            fields["domain"] = (data["domain"] or "").strip().lower()[:253] or None
        if "notes" in data:
            fields["notes"] = str(data["notes"] or "")[:2000]
        if "tags" in data:
            tags = [str(t).strip()[:32] for t in (data["tags"] or []) if str(t).strip()][:12]
            fields["tags"] = json.dumps(tags, ensure_ascii=False)
        if "status" in data:
            if data["status"] not in ("active", "disabled"):
                raise NodeError("Недопустимый статус")
            if node["status"] in ("active", "disabled"):
                fields["status"] = data["status"]
        if "cert_id" in data:
            cert_id = data["cert_id"] or None
            if cert_id and not self.db.scalar("SELECT 1 FROM certificates WHERE id=?", (cert_id,)):
                raise NodeError("Сертификат не найден")
            fields["cert_id"] = cert_id
            fields["cert_remove"] = 1 if (not cert_id and data.get("cert_remove")) else 0
        if "cert_target" in data:
            fields["cert_target"] = json.dumps(_cert_target(data["cert_target"] or {}))
        if "nginx" in data:
            try:
                nginx_cfg = nginx_routes.validate(data["nginx"])
            except nginx_routes.RouteError as exc:
                raise NodeError(str(exc))
            if nginx_cfg["mode"] == "vision":
                rw = self.remnawave_node(node)
                if rw and not nginx_cfg["vision"]["inbound_tag"]:
                    raise NodeError("Выберите VLESS inbound для режима Vision")
                conflicts = nginx_routes.vision_conflicts(nginx_cfg, rw)
                if conflicts:
                    raise NodeError("Режим Vision небезопасен: " + "; ".join(conflicts))
            else:
                self.db.set_json(f"vision_sync:{node_id}", None)
            fields["nginx"] = json.dumps(nginx_cfg)
        if "firewall" in data:
            try:
                fields["firewall"] = json.dumps(fw.validate_node(data["firewall"]))
            except fw.FirewallError as exc:
                raise NodeError(str(exc))
        if "bbr" in data:
            fields["bbr"] = _tri(data["bbr"])
        if "site_id" in data:
            site_id = data["site_id"] or None
            if site_id not in (None, "builtin") and not self.db.scalar("SELECT 1 FROM sites WHERE id=?", (site_id,)):
                raise NodeError("Сайт не найден")
            fields["site_id"] = site_id
        if "remnawave_node" in data:
            fields["remnawave_node"] = (data["remnawave_node"] or "").strip()[:64] or None
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            self.db.execute(f"UPDATE nodes SET {sets} WHERE id=?", (*fields.values(), node_id))
            self.db.audit(actor, "node.update", node_id, fields)
            self.wake(node_id)
        return self.public(self.get(node_id), detail=True)

    def bulk(self, ids, action, value=None, actor="admin"):
        done = []
        for node_id in ids:
            try:
                if action == "update_agent":
                    self.request_update(node_id, actor)
                elif action in ("torrent_enabled", "scan_enabled"):
                    self.update_node(node_id, {action: value}, actor)
                elif action == "firewall_enabled":
                    override = loads(self.get(node_id).get("firewall"), {}) or {}
                    self.update_node(node_id, {"firewall": {**override, "enabled": None if _tri(value) is None else bool(_tri(value))}}, actor)
                elif action == "bbr":
                    self.update_node(node_id, {"bbr": value}, actor)
                elif action == "diagnose":
                    self.command(node_id, "diagnose", actor=actor)
                elif action == "status":
                    self.update_node(node_id, {"status": value}, actor)
                else:
                    raise NodeError("Неизвестное действие")
                done.append(node_id)
            except LookupError:
                continue
        return done

    def request_update(self, node_id, actor="admin"):
        node = self.get(node_id)
        version = self.releases.agent_bundle()[0]
        if node["agent_version"] == version:
            return False
        self.db.execute("UPDATE nodes SET desired_agent_version=? WHERE id=?", (version, node_id))
        self.db.audit(actor, "node.update_agent", node_id, {"from": node["agent_version"], "to": version})
        self.wake(node_id)
        return True

    def command(self, node_id, kind, args=None, actor="admin"):
        if kind not in ("diagnose", "resync", "restart_detector", "restart_suricata", "restart_agent"):
            raise NodeError("Неизвестная команда")
        self.get(node_id)
        cid = uuid.uuid4().hex[:16]
        self.db.execute("INSERT INTO node_commands(id,node_id,type,args,created_at) VALUES(?,?,?,?,?)",
                        (cid, node_id, kind, json.dumps(args or {}), time.time()))
        self.db.audit(actor, f"node.command.{kind}", node_id)
        self.wake(node_id)
        return cid

    def delete(self, node_id, uninstall=True, actor="admin"):
        node = self.get(node_id)
        online = node["last_seen_at"] and time.time() - node["last_seen_at"] < OFFLINE_AFTER
        if uninstall and online and node["token_hash"]:
            self.db.execute("UPDATE nodes SET status='removing' WHERE id=?", (node_id,))
            self.wake(node_id)
            self.db.audit(actor, "node.uninstall", node_id)
            return "removing"
        self._forget(node)
        self.db.audit(actor, "node.delete", node_id, {"name": node["name"]})
        return "deleted"

    def _forget(self, node):
        if node.get("token_hash"):
            # An offline agent that comes back with this token is told to uninstall.
            deleted = self.db.get_json("deleted_node_tokens", []) or []
            deleted = ([node["token_hash"]] + [t for t in deleted if t != node["token_hash"]])[:2000]
            self.db.set_json("deleted_node_tokens", deleted)
        self.db.execute("DELETE FROM nodes WHERE id=?", (node["id"],))
        self.db.execute("DELETE FROM node_metrics WHERE node_id=?", (node["id"],))
        self.db.execute("DELETE FROM node_uptime WHERE node_id=?", (node["id"],))

    def was_deleted(self, token):
        return bool(token) and security.token_hash(token) in (self.db.get_json("deleted_node_tokens", []) or [])

    def finish_removal(self, node_id):
        node = self.db.one("SELECT * FROM nodes WHERE id=?", (node_id,))
        if node:
            self._forget(node)
            self.events.record_system("node", f"Нода {node['name']} удалена, агент деинсталлирован")

    def reorder(self, ids, actor="admin"):
        """Manual order (drag and drop in the UI). Unknown and repeated ids are
        ignored; nodes missing from the list (added meanwhile in another tab)
        keep their relative order after the listed ones."""
        current = [r["id"] for r in self.db.all("SELECT id FROM nodes ORDER BY sort, name COLLATE NOCASE")]
        known = set(current)
        ordered = list(dict.fromkeys(i for i in ids if i in known))
        listed = set(ordered)
        ordered += [i for i in current if i not in listed]
        if ordered == current:
            return ordered
        with self.db.tx() as conn:
            conn.executemany("UPDATE nodes SET sort=? WHERE id=?", [(index, node_id) for index, node_id in enumerate(ordered)])
        self.db.audit(actor, "node.reorder", None, {"count": len(ordered)})
        return ordered

    # ------------------------------------------------------------ history

    def availability(self, node_id, period):
        now = time.time()
        node = self.db.one("SELECT registered_at, created_at FROM nodes WHERE id=?", (node_id,))
        if not node:
            return None
        start = max(now - period, node["registered_at"] or node["created_at"])
        if now - start < 60:
            return None
        online = self.db.scalar(
            "SELECT COALESCE(SUM(online_seconds),0) FROM node_uptime WHERE node_id=? AND hour>=?",
            (node_id, int(start // 3600) * 3600),
        ) or 0
        return round(min(100.0, 100.0 * online / (now - start)), 2)

    def metrics(self, node_id, period):
        since = time.time() - period
        rows = self.db.all("SELECT ts, cpu, mem, rx, tx, load1 FROM node_metrics WHERE node_id=? AND ts>=? ORDER BY ts",
                           (node_id, since))
        step = 60 if period <= 6 * 3600 else 300 if period <= 2 * 86400 else 1800
        buckets = {}
        for row in rows:
            key = int(row["ts"] // step) * step
            bucket = buckets.setdefault(key, {"ts": key, "n": 0, "cpu": 0, "mem": 0, "rx": 0, "tx": 0})
            bucket["n"] += 1
            for field in ("cpu", "mem", "rx", "tx"):
                bucket[field] += row[field] or 0
        out = []
        for key in sorted(buckets):
            b = buckets[key]
            out.append({"ts": key, **{f: round(b[f] / b["n"], 1) for f in ("cpu", "mem", "rx", "tx")}})
        return out

    def uptime_strip(self, node_id, hours=48):
        now_hour = int(time.time() // 3600) * 3600
        start = now_hour - (hours - 1) * 3600
        rows = {r["hour"]: r["online_seconds"] for r in self.db.all(
            "SELECT hour, online_seconds FROM node_uptime WHERE node_id=? AND hour>=?", (node_id, start))}
        node = self.db.one("SELECT registered_at FROM nodes WHERE id=?", (node_id,))
        registered = (node or {}).get("registered_at") or time.time()
        out = []
        for i in range(hours):
            hour = start + i * 3600
            if hour + 3600 < registered:
                out.append({"hour": hour, "value": None})
                continue
            span = min(3600, time.time() - max(hour, registered))
            value = rows.get(hour, 0)
            out.append({"hour": hour, "value": round(min(1.0, value / span), 3) if span > 0 else None})
        return out

    def monitor(self):
        """Mark nodes offline; called periodically."""
        now = time.time()
        for row in self.db.all("SELECT id, name, last_seen_at, online, status FROM nodes WHERE online=1"):
            if not row["last_seen_at"] or now - row["last_seen_at"] > OFFLINE_AFTER:
                self.db.execute("UPDATE nodes SET online=0, state_changed_at=? WHERE id=?", (now, row["id"]))
                if row["status"] == "active":
                    self.events.record_system("node", f"Нода {row['name']} недоступна", "error", node_id=row["id"])
        self.db.execute("DELETE FROM node_metrics WHERE ts<?", (now - 8 * 86400,))
        self.db.execute("DELETE FROM node_uptime WHERE hour<?", (now - 35 * 86400,))
        self.db.execute("DELETE FROM install_tokens WHERE expires_at<? OR used_at<?", (now - 86400, now - 86400))
        self.db.execute("DELETE FROM node_commands WHERE created_at<?", (now - 7 * 86400,))


# Agents before 2.1.2 install a unit without SuccessExitStatus=75; on systemd
# >= 254 (Ubuntu 24.04) their deliberate post-update restart fires OnFailure and
# rolls the update back within seconds. A one-time drop-in fixes it.
UNIT_FIX_HINT = (
    "Ubuntu 24.04 (systemd ≥ 254): старый юнит агента считает плановый перезапуск после обновления сбоем. "
    "Выполните на ноде один раз и повторите обновление: "
    "mkdir -p /etc/systemd/system/ezhik-guard-agent.service.d && "
    "printf '[Service]\\nSuccessExitStatus=75\\n' > /etc/systemd/system/ezhik-guard-agent.service.d/10-restart.conf && "
    "systemctl daemon-reload"
)


def _version_tuple(value):
    try:
        return tuple(int(x) for x in str(value).split("-")[0].split(".")[:3])
    except ValueError:
        return (0,)


def _tri(value):
    if value is None or value == "inherit":
        return None
    return 1 if value in (True, 1, "1", "true", "on") else 0


def _cert_target(raw):
    out = {}
    mode = raw.get("mode") or "auto"
    if mode not in ("auto", "docker", "systemd", "files"):
        raise NodeError("Недопустимый режим доставки сертификата")
    out["mode"] = mode
    for key in ("dir", "container_dir"):
        value = (raw.get(key) or "").strip()
        if value:
            if not value.startswith("/") or ".." in value.split("/"):
                raise NodeError(f"{key}: нужен абсолютный путь")
            out[key] = value
    container = (raw.get("container") or "").strip()
    if container:
        if not CONTAINER_RE.match(container):
            raise NodeError("Недопустимое имя контейнера/юнита")
        out["container"] = container
    apply = raw.get("apply") or "restart"
    if apply not in ("restart", "none", "command"):
        raise NodeError("Недопустимый способ применения")
    out["apply"] = apply
    if apply == "command":
        command = (raw.get("command") or "").strip()
        if not command or len(command) > 300:
            raise NodeError("Укажите команду перезагрузки (до 300 символов)")
        out["command"] = command
    return out

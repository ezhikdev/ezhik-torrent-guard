"""Detection ingest, central protection policy and the event log."""

import json
import logging
import time
import uuid

log = logging.getLogger("ezhik.events")

DETECTION_TYPES = ("torrent", "p2p", "scan")

REASON_TITLES = {
    "first-exact-bittorrent": "BitTorrent-трафик",
    "vertical-port-scan": "Перебор портов одного IP",
    "subnet-port-scan": "Сканирование подсети /24",
    "p2p-fanout": "P2P/DHT-рассылка по множеству узлов",
}

ACTION_TITLES = {
    "QUEUED": "блокировка поставлена в очередь",
    "EXISTS": "уже заблокирован или в очереди",
    "OBSERVE": "режим наблюдения — без блокировки",
    "PROTECTED": "защищённый клиент — без блокировки",
    "NOT_CONFIGURED": "Remnawave не настроен",
    "STALE": "событие устарело — без блокировки",
    "FEATURE_OFF": "защита на ноде выключена",
}


class EventService:
    def __init__(self, db, settings, notifier):
        self.db = db
        self.settings = settings
        self.notifier = notifier
        self.sanctions = None  # set after construction (circular)

    # ------------------------------------------------------------- ingest

    def ingest(self, node, items):
        accepted = []
        protection = self.settings.protection()
        protected = set(protection.get("protected_clients") or [])
        now = time.time()
        for item in items[:500]:
            event_id = str(item.get("id") or "")
            etype = item.get("type")
            if not event_id or len(event_id) > 64 or etype not in DETECTION_TYPES:
                if event_id:
                    accepted.append(event_id)
                continue
            if self.db.scalar("SELECT 1 FROM events WHERE id=?", (event_id,)):
                accepted.append(event_id)
                continue
            client_id = str(item.get("client_id") or "")
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            detected_at = float(item.get("detected_at") or now)
            action, detail = self._decide(node, etype, client_id, detected_at, protection, protected, event_id)
            reason = data.get("reason") or etype
            title = REASON_TITLES.get(reason, reason)
            severity = "warn" if action in ("QUEUED", "EXISTS") else "info"
            self.db.execute(
                "INSERT OR IGNORE INTO events(id,node_id,type,severity,client_id,detected_at,received_at,action,title,data) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (event_id, node["id"], etype, severity, client_id, detected_at, now, action, title,
                 json.dumps({**data, "action_detail": detail}, ensure_ascii=False)[:20000]),
            )
            accepted.append(event_id)
            log.info("[%s] node=%s client=%s reason=%s action=%s", etype.upper(), node["name"], client_id, reason, action)
            try:
                self.notifier.detection(node, etype, client_id, title, action, ACTION_TITLES.get(action, action), data, protection)
            except Exception:
                log.exception("Notification failed")
        return accepted

    def _decide(self, node, etype, client_id, detected_at, protection, protected, event_id):
        policy = protection["torrent" if etype == "torrent" else etype]
        if etype == "torrent":
            enabled = _node_flag(node.get("torrent_enabled"), protection["torrent"]["default_enabled"])
            duration = protection["torrent"]["freeze_seconds"]
        elif etype == "p2p":
            enabled = protection["p2p"]["enabled"] and _node_flag(node.get("torrent_enabled"), protection["torrent"]["default_enabled"])
            duration = protection["p2p"]["block_seconds"]
        else:
            enabled = _node_flag(node.get("scan_enabled"), protection["scan"]["default_enabled"])
            duration = protection["scan"]["block_seconds"]
        if not enabled:
            return "FEATURE_OFF", None
        if client_id in protected:
            return "PROTECTED", None
        if policy.get("mode") != "enforce":
            return "OBSERVE", None
        if time.time() - detected_at > protection["max_event_age_seconds"]:
            return "STALE", None
        result = self.sanctions.queue_freeze(client_id, etype, duration, node_id=node["id"], event_id=event_id)
        return {"queued": "QUEUED", "exists": "EXISTS", "protected": "PROTECTED",
                "not_configured": "NOT_CONFIGURED"}.get(result, "FAILED"), result

    # ------------------------------------------------------- system events

    def record_system(self, etype, title, severity="info", node_id=None, client_id=None, action=None, data=None):
        event_id = "sys-" + uuid.uuid4().hex[:20]
        now = time.time()
        self.db.execute(
            "INSERT INTO events(id,node_id,type,severity,client_id,detected_at,received_at,action,title,data) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (event_id, node_id, etype, severity, client_id, now, now, action, title,
             json.dumps(data or {}, ensure_ascii=False)[:20000]),
        )
        try:
            self.notifier.system(etype, title, severity, node_id, data or {})
        except Exception:
            log.exception("Notification failed")
        return event_id

    # -------------------------------------------------------------- queries

    def list(self, *, types=None, node_id=None, client_id=None, since=None, until=None, q=None, limit=100, before=None):
        where, params = [], []
        if types:
            where.append(f"e.type IN ({','.join('?' * len(types))})")
            params += list(types)
        if node_id:
            where.append("e.node_id=?")
            params.append(node_id)
        if client_id:
            where.append("e.client_id=?")
            params.append(str(client_id))
        if since:
            where.append("e.detected_at>=?")
            params.append(float(since))
        if until:
            where.append("e.detected_at<=?")
            params.append(float(until))
        if before:
            where.append("e.detected_at<?")
            params.append(float(before))
        if q:
            where.append("(e.title LIKE ? OR e.client_id LIKE ? OR n.name LIKE ?)")
            params += [f"%{q}%"] * 3
        sql = ("SELECT e.*, n.name AS node_name FROM events e LEFT JOIN nodes n ON n.id=e.node_id "
               + (("WHERE " + " AND ".join(where)) if where else "")
               + " ORDER BY e.detected_at DESC LIMIT ?")
        params.append(max(1, min(500, int(limit))))
        rows = self.db.all(sql, params)
        for row in rows:
            try:
                row["data"] = json.loads(row["data"]) if row["data"] else {}
            except ValueError:
                row["data"] = {}
        return rows

    def counts(self, since):
        rows = self.db.all(
            "SELECT type, action, COUNT(*) c FROM events WHERE detected_at>=? GROUP BY type, action", (since,))
        out = {}
        for row in rows:
            bucket = out.setdefault(row["type"], {"total": 0, "blocked": 0})
            bucket["total"] += row["c"]
            if row["action"] in ("QUEUED",):
                bucket["blocked"] += row["c"]
        return out

    def timeseries(self, since, bucket_seconds, node_id=None):
        params = [bucket_seconds, bucket_seconds, since]
        node_filter = ""
        if node_id:
            node_filter = " AND node_id=?"
            params.append(node_id)
        rows = self.db.all(
            "SELECT CAST(detected_at/? AS INTEGER)*? AS bucket, type, COUNT(*) c FROM events "
            f"WHERE detected_at>=? AND type IN ('torrent','p2p','scan'){node_filter} GROUP BY bucket, type ORDER BY bucket",
            params,
        )
        return rows

    def top_clients(self, since, limit=8):
        return self.db.all(
            "SELECT client_id, COUNT(*) c, MAX(detected_at) last, GROUP_CONCAT(DISTINCT type) types FROM events "
            "WHERE detected_at>=? AND type IN ('torrent','p2p','scan') AND client_id IS NOT NULL AND client_id!='' "
            "GROUP BY client_id ORDER BY c DESC LIMIT ?",
            (since, limit),
        )

    def cleanup(self, keep_days=90, keep_rows=500000):
        self.db.execute("DELETE FROM events WHERE detected_at<?", (time.time() - keep_days * 86400,))
        total = self.db.scalar("SELECT COUNT(*) FROM events") or 0
        if total > keep_rows:
            self.db.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY detected_at ASC LIMIT ?)",
                (total - keep_rows,),
            )
        self.db.execute("DELETE FROM sanction_history WHERE at<?", (time.time() - 180 * 86400,))
        self.db.execute("DELETE FROM audit WHERE at<?", (time.time() - 365 * 86400,))


def _node_flag(value, default):
    return bool(default) if value is None else bool(value)


node_flag = _node_flag

"""Central sanction ledger and Remnawave worker.

The safety rules of Torrent Guard 1.x are preserved:

* a user is only ever disabled when currently ACTIVE (an already disabled
  user is never "owned" and never auto-enabled);
* ambiguous write outcomes (timeouts, 5xx, 408, unexpected 200 bodies) are
  remembered so a later DISABLED / A029 is recognised as our own action;
* auto-enable happens only for a user we disabled, whose identity did not
  change, who is still DISABLED and who is not on hold;
* permanent blocks are forgotten after a confirmed disable, leaving the
  operator to re-enable in Remnawave.

Unlike 1.x the ledger is shared by all nodes: one user detected on several
nodes gets exactly one sanction.
"""

import logging
import threading
import time

from .remnawave import Remnawave, compatible_identity, find_error_code

log = logging.getLogger("ezhik.sanctions")

RETRY_SECONDS = 60


class SanctionService:
    def __init__(self, db, settings_service, events_sink):
        self.db = db
        self.settings = settings_service
        self.events = events_sink
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._client = None
        self._client_key = None

    # ------------------------------------------------------------ helpers

    def client(self):
        cfg = self.settings.remnawave()
        key = (cfg.get("url"), cfg.get("token"))
        if key != self._client_key:
            self._client = Remnawave(cfg.get("url"), cfg.get("token"))
            self._client_key = key
        return self._client

    def _get(self, client_id):
        return self.db.one("SELECT * FROM sanctions WHERE client_id=?", (client_id,))

    def _update(self, client_id, **fields):
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE sanctions SET {sets} WHERE client_id=?", (*fields.values(), client_id))

    def _history(self, rec, outcome, detail=""):
        self.db.execute(
            "INSERT INTO sanction_history(client_id,username,reason,node_id,outcome,detail,at) VALUES(?,?,?,?,?,?,?)",
            (rec["client_id"], rec.get("username"), rec.get("reason"), rec.get("node_id"), outcome, detail, time.time()),
        )

    def _event(self, rec, action, title, severity="info", detail=None):
        self.events.record_system(
            "sanction", title, severity=severity, client_id=rec["client_id"], node_id=rec.get("node_id"),
            action=action, data={"reason": rec.get("reason"), "detail": detail, "username": rec.get("username")},
        )

    # ---------------------------------------------------------------- API

    def queue_freeze(self, client_id, reason, duration_seconds, node_id=None, event_id=None):
        client_id = str(client_id)
        if not client_id.isdigit():
            return "invalid"
        if client_id in self.settings.protected_clients():
            return "protected"
        if not self.client().configured:
            return "not_configured"
        duration_seconds = max(0, int(duration_seconds))
        now = time.time()
        try:
            self.db.execute(
                """INSERT INTO sanctions(client_id,state,reason,node_id,event_id,duration_seconds,
                   forget_after_disable,created_at,next_retry_at,source)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (client_id, "pending", reason, node_id, event_id, duration_seconds,
                 1 if duration_seconds == 0 else 0, now, now, "detector"),
            )
        except Exception:
            return "exists"
        log.info("[ACTION QUEUED] client=%s reason=%s duration=%s", client_id, reason,
                 "permanent" if duration_seconds == 0 else f"{duration_seconds}s")
        self._wake.set()
        return "queued"

    def adopt_legacy(self, items, node_id):
        """Take over still-running Torrent Guard 1.x sanctions from a node."""
        adopted = 0
        for item in items:
            client_id = str(item.get("client_id", ""))
            unfreeze_at = item.get("unfreeze_at")
            if not client_id.isdigit() or not isinstance(unfreeze_at, (int, float)):
                continue
            legacy_uuid = item.get("legacy_uuid")
            try:
                self.db.execute(
                    """INSERT INTO sanctions(client_id,state,reason,node_id,identity,duration_seconds,created_at,
                       disabled_at,unfreeze_at,next_retry_at,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (client_id, "active", str(item.get("reason") or "bittorrent"), node_id,
                     f"uuid:{legacy_uuid}" if legacy_uuid else None,
                     max(0, int(unfreeze_at - (item.get("disabled_at") or unfreeze_at))),
                     time.time(), item.get("disabled_at"), float(unfreeze_at), float(unfreeze_at), "legacy-1.x"),
                )
                adopted += 1
            except Exception:
                continue
        if adopted:
            self._wake.set()
        return adopted

    def release(self, client_id, actor):
        """Admin: enable the user in Remnawave now and drop the sanction."""
        rec = self._get(client_id)
        if not rec:
            raise LookupError("sanction not found")
        if rec["state"] == "pending":
            self.db.execute("DELETE FROM sanctions WHERE client_id=?", (client_id,))
            self._history(rec, "cancelled", f"by {actor}")
            return {"ok": True, "message": "Ожидающая блокировка отменена"}
        api = self.client()
        code, user = api.get_user(client_id)
        if user is None:
            raise RuntimeError(f"Remnawave: пользователь недоступен (HTTP {code})")
        if user.get("status") == "DISABLED":
            code, payload = api.enable(user)
            if code != 200 and find_error_code(payload) != "A030":
                raise RuntimeError(f"Remnawave enable: HTTP {code} {find_error_code(payload) or ''}")
        self.db.execute("DELETE FROM sanctions WHERE client_id=?", (client_id,))
        self._history(rec, "released", f"manual by {actor}")
        self._event(rec, "RELEASED", f"Клиент {client_id} разблокирован вручную")
        return {"ok": True, "message": "Пользователь включён в Remnawave"}

    def forget(self, client_id, actor):
        rec = self._get(client_id)
        if not rec:
            raise LookupError("sanction not found")
        self.db.execute("DELETE FROM sanctions WHERE client_id=?", (client_id,))
        self._history(rec, "forgotten", f"by {actor}; Remnawave not changed")

    def set_hold(self, client_id, hold):
        self._update(str(client_id), hold=1 if hold else 0)

    def extend(self, client_id, seconds):
        rec = self._get(client_id)
        if not rec or rec["state"] != "active":
            raise LookupError("active sanction not found")
        until = max(time.time(), rec["unfreeze_at"] or 0) + int(seconds)
        self._update(client_id, unfreeze_at=until, next_retry_at=until)

    # ------------------------------------------------------------- worker

    def start(self):
        threading.Thread(target=self._worker, name="sanctions", daemon=True).start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def _worker(self):
        while not self._stop.is_set():
            try:
                if self.client().configured:
                    self._process_due_freezes()
                    self._process_due_unfreezes()
            except Exception:
                log.exception("Sanction worker iteration failed")
            self._wake.wait(1.0)
            self._wake.clear()

    def _process_due_freezes(self):
        now = time.time()
        rows = self.db.all(
            "SELECT client_id FROM sanctions WHERE state='pending' AND next_retry_at<=? ORDER BY next_retry_at LIMIT 5",
            (now,),
        )
        for row in rows:
            self._freeze(row["client_id"])

    def _process_due_unfreezes(self):
        now = time.time()
        rows = self.db.all(
            "SELECT client_id FROM sanctions WHERE state='active' AND unfreeze_at IS NOT NULL "
            "AND unfreeze_at<=? AND next_retry_at<=? ORDER BY unfreeze_at LIMIT 20",
            (now, now),
        )
        for row in rows:
            self._unfreeze(row["client_id"])

    # ------------------------------------------------------------- freeze

    def _remove(self, rec, outcome, detail):
        self.db.execute("DELETE FROM sanctions WHERE client_id=?", (rec["client_id"],))
        self._history(rec, outcome, detail)

    def _retry_freeze(self, rec, reason, may_have_disabled=False, ambiguous_at=None):
        fields = {"last_error": str(reason), "next_retry_at": time.time() + RETRY_SECONDS}
        if may_have_disabled:
            fields["may_have_disabled"] = 1
            if rec.get("ambiguous_since") is None:
                fields["ambiguous_since"] = float(ambiguous_at or time.time())
        self._update(rec["client_id"], **fields)
        log.warning("[FREEZE RETRY] client=%s reason=%s may_have_disabled=%s", rec["client_id"], reason,
                    bool(may_have_disabled or rec.get("may_have_disabled")))

    def _confirm_frozen(self, rec, ident, source, disabled_at=None):
        now = time.time()
        disabled_at = min(float(disabled_at), now) if isinstance(disabled_at, (int, float)) else now
        if rec["duration_seconds"] == 0 or rec["forget_after_disable"]:
            self._remove(rec, "blocked-permanent", source)
            self._event(rec, "BLOCKED", f"Клиент {rec['client_id']} заблокирован бессрочно", "warn",
                        "Разблокировка вручную в Remnawave")
            return
        unfreeze_at = disabled_at + rec["duration_seconds"]
        self._update(rec["client_id"], state="active", identity=ident, disabled_at=disabled_at,
                     unfreeze_at=unfreeze_at, next_retry_at=unfreeze_at, last_error=None, source=source)
        self._history(rec, "frozen", source)
        minutes = max(1, round(rec["duration_seconds"] / 60))
        self._event(rec, "FROZEN", f"Клиент {rec['client_id']} заморожен на {minutes} мин", "warn",
                    {"unfreeze_at": unfreeze_at})

    def _freeze(self, client_id):
        rec = self._get(client_id)
        if not rec or rec["state"] != "pending":
            return
        if client_id in self.settings.protected_clients():
            self._remove(rec, "skipped", "protected client")
            return
        api = self.client()
        code, user = api.get_user(client_id)
        if user is None:
            if code == 404:
                self._remove(rec, "skipped", "user not found in Remnawave")
                return
            self._retry_freeze(rec, f"resolve-failed-http-{code}")
            return
        status, ident = user.get("status"), user["identity"]
        if user.get("username"):
            self._update(client_id, username=str(user["username"])[:120])
            rec["username"] = user["username"]
        if rec.get("identity") and not compatible_identity(rec["identity"], ident):
            self._remove(rec, "refused", "user identity changed")
            return
        self._update(client_id, identity=ident)

        # Earlier attempt had an ambiguous outcome and the user is now
        # DISABLED: our request most likely succeeded.
        if status == "DISABLED" and rec["may_have_disabled"]:
            self._confirm_frozen(rec, ident, "recovered-ambiguous-disable", rec.get("ambiguous_since"))
            return
        # A user that is not ACTIVE was not disabled by us: never own it.
        if status != "ACTIVE":
            self._remove(rec, "skipped", f"status={status}; not owned")
            self._event(rec, "SKIPPED", f"Клиент {client_id} уже {status}; блокировка не требуется")
            return

        attempt_started = time.time()
        had_ambiguous = bool(rec["may_have_disabled"])
        self._update(client_id, disable_attempts=rec["disable_attempts"] + 1, last_disable_attempt_at=attempt_started)
        code, payload = api.disable(user)
        if code == 200:
            new_status = (payload.get("response") or {}).get("status")
            if new_status == "DISABLED":
                self._confirm_frozen(rec, ident, "api-200")
            else:
                self._retry_freeze(rec, f"http-200-unexpected-status-{new_status}", True, attempt_started)
            return
        error_code = find_error_code(payload)
        if error_code == "A029":
            if had_ambiguous:
                self._confirm_frozen(rec, ident, "recovered-A029", rec.get("ambiguous_since"))
            else:
                self._remove(rec, "skipped", "already disabled (A029) on first attempt")
            return
        if code == 0 or code >= 500 or code == 408:
            self._retry_freeze(rec, f"http-{code}-error-{error_code}", True, attempt_started)
            return
        if code in (425, 429):
            self._retry_freeze(rec, f"http-{code}-error-{error_code}")
            return
        log.error("[API ERROR] disable client=%s http=%s error=%s; giving up", client_id, code, error_code)
        self._remove(rec, "failed", f"http {code} {error_code}")
        self._event(rec, "FAILED", f"Не удалось заблокировать клиента {client_id}: HTTP {code} {error_code or ''}", "error")

    # ----------------------------------------------------------- unfreeze

    def _retry_unfreeze(self, rec, reason):
        self._update(rec["client_id"], next_retry_at=time.time() + RETRY_SECONDS, last_error=reason)
        log.warning("[UNFREEZE RETRY] client=%s reason=%s", rec["client_id"], reason)

    def _unfreeze(self, client_id):
        rec = self._get(client_id)
        if not rec or rec["state"] != "active":
            return
        if rec["hold"]:
            self._retry_unfreeze(rec, "admin-hold")
            return
        api = self.client()
        code, user = api.get_user(client_id)
        if user is None:
            self._retry_unfreeze(rec, f"resolve-failed-http-{code}")
            return
        if not compatible_identity(rec.get("identity"), user["identity"]):
            self._retry_unfreeze(rec, "identity-mismatch")
            return
        status = user.get("status")
        if status == "ACTIVE":
            self._remove(rec, "already-active", "enabled by someone else")
            return
        if status != "DISABLED":
            self._remove(rec, "skipped", f"status={status}; will not force ACTIVE")
            return
        code, payload = api.enable(user)
        if code == 200:
            if (payload.get("response") or {}).get("status") == "ACTIVE":
                self._remove(rec, "unfrozen", "auto")
                self._event(rec, "UNFROZEN", f"Клиент {client_id} автоматически разблокирован")
            else:
                self._retry_unfreeze(rec, "unexpected-status")
            return
        if find_error_code(payload) == "A030":
            self._remove(rec, "unfrozen", "already active (A030)")
            return
        self._retry_unfreeze(rec, f"http-{code}-error-{find_error_code(payload)}")

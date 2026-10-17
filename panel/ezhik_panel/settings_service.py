"""Global settings stored in the kv table, with defaults and validation."""

import copy
import threading

DEFAULT_PROTECTION = {
    "torrent": {
        "mode": "enforce",             # enforce | observe
        "freeze_seconds": 900,
        "default_enabled": True,
    },
    "p2p": {
        "enabled": True,
        "mode": "observe",
        "block_seconds": 900,
        "udp_hosts": 120,
        "udp_networks": 40,
        "tcp_hosts": 150,
        "tcp_networks": 50,
    },
    "scan": {
        "mode": "observe",
        "block_seconds": 3600,         # 0 = permanent (manual unblock in Remnawave)
        "default_enabled": True,
        "window_seconds": 60,
        "tcp_vertical_ports": 50,
        "udp_vertical_ports": 100,
        "subnet_hosts": 16,
        "subnet_ports": 50,
        "subnet_endpoints": 100,
        "cooldown_seconds": 300,
    },
    "protected_clients": [],
    "log_max_bytes": 8 * 1024 * 1024,
    "max_event_age_seconds": 1800,
    "remove_legacy": True,
}

DEFAULT_REMNAWAVE = {"url": "", "token": None}
DEFAULT_TELEGRAM = {
    "token": None, "chat_id": "", "enabled": False,
    "notify": {"torrent": True, "p2p": True, "scan": True, "nodes": True, "certs": True, "sanctions": False},
}
DEFAULT_ACME = {
    "email": "",
    "directory": "https://acme-v02.api.letsencrypt.org/directory",
    "renew_days": 30,
}
DEFAULT_PANEL = {"web_cert_id": None, "public_host": "", "timezone": "Europe/Moscow"}

LIMITS = {
    ("torrent", "freeze_seconds"): (60, 30 * 86400),
    ("p2p", "block_seconds"): (60, 30 * 86400),
    ("p2p", "udp_hosts"): (20, 5000),
    ("p2p", "udp_networks"): (5, 5000),
    ("p2p", "tcp_hosts"): (20, 5000),
    ("p2p", "tcp_networks"): (5, 5000),
    ("scan", "block_seconds"): (0, 30 * 86400),
    ("scan", "window_seconds"): (10, 600),
    ("scan", "tcp_vertical_ports"): (5, 5000),
    ("scan", "udp_vertical_ports"): (5, 5000),
    ("scan", "subnet_hosts"): (2, 256),
    ("scan", "subnet_ports"): (2, 5000),
    ("scan", "subnet_endpoints"): (2, 50000),
    ("scan", "cooldown_seconds"): (30, 86400),
}


class ValidationError(ValueError):
    pass


def _merge(defaults, value):
    out = copy.deepcopy(defaults)
    for key, item in (value or {}).items():
        if key in out and isinstance(out[key], dict) and isinstance(item, dict):
            out[key] = _merge(out[key], item)
        elif key in out:
            out[key] = item
    return out


class SettingsService:
    def __init__(self, db, secrets):
        self.db = db
        self.secrets = secrets
        self._lock = threading.Lock()
        self.listeners = []

    def _changed(self, section):
        for listener in self.listeners:
            try:
                listener(section)
            except Exception:
                pass

    # ------------------------------------------------------------ protection

    def protection(self):
        return _merge(DEFAULT_PROTECTION, self.db.get_json("protection", {}))

    def protected_clients(self):
        return {str(c) for c in self.protection().get("protected_clients") or []}

    def set_protection(self, value, actor="system"):
        merged = _merge(self.protection(), value)
        for section in ("torrent", "p2p", "scan"):
            if merged[section].get("mode") not in ("enforce", "observe"):
                raise ValidationError(f"{section}.mode must be enforce or observe")
        for (section, key), (low, high) in LIMITS.items():
            try:
                number = int(merged[section][key])
            except (TypeError, ValueError):
                raise ValidationError(f"{section}.{key} must be a number")
            if not low <= number <= high:
                raise ValidationError(f"{section}.{key} must be between {low} and {high}")
            merged[section][key] = number
        clients = []
        for item in merged.get("protected_clients") or []:
            item = str(item).strip()
            if not item.isdigit():
                raise ValidationError(f"protected client id must be numeric: {item}")
            clients.append(item)
        merged["protected_clients"] = sorted(set(clients), key=int)
        merged["log_max_bytes"] = max(1 << 20, min(256 << 20, int(merged.get("log_max_bytes") or (8 << 20))))
        merged["max_event_age_seconds"] = max(60, min(86400, int(merged.get("max_event_age_seconds") or 1800)))
        merged["remove_legacy"] = bool(merged.get("remove_legacy", True))
        self.db.set_json("protection", merged)
        self.db.audit(actor, "settings.protection", detail=merged)
        self._changed("protection")
        return merged

    # ------------------------------------------------------------- remnawave

    def remnawave(self):
        raw = _merge(DEFAULT_REMNAWAVE, self.db.get_json("remnawave", {}))
        raw["token"] = self.secrets.decrypt(raw.get("token")) if raw.get("token") else None
        return raw

    def set_remnawave(self, url, token, actor="system"):
        current = self.db.get_json("remnawave", {}) or {}
        url = (url or "").strip().rstrip("/")
        if url and not url.startswith(("http://", "https://")):
            url = "https://" + url
        stored = {"url": url, "token": current.get("token")}
        if token:
            token = token.strip()
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            stored["token"] = self.secrets.encrypt(token)
        self.db.set_json("remnawave", stored)
        self.db.audit(actor, "settings.remnawave", detail={"url": url, "token_changed": bool(token)})
        self._changed("remnawave")

    # -------------------------------------------------------------- telegram

    def telegram(self):
        raw = _merge(DEFAULT_TELEGRAM, self.db.get_json("telegram", {}))
        raw["token"] = self.secrets.decrypt(raw.get("token")) if raw.get("token") else None
        return raw

    def set_telegram(self, value, actor="system"):
        current = self.db.get_json("telegram", {}) or {}
        merged = _merge(DEFAULT_TELEGRAM, current)
        token = value.pop("token", None)
        merged = _merge(merged, value)
        if token:
            merged["token"] = self.secrets.encrypt(token.strip())
        elif value.get("clear_token"):
            merged["token"] = None
        else:
            merged["token"] = current.get("token")
        chat = str(merged.get("chat_id") or "").strip()
        if chat and not chat.lstrip("-").isdigit():
            raise ValidationError("chat_id must be numeric")
        merged["chat_id"] = chat
        self.db.set_json("telegram", merged)
        self.db.audit(actor, "settings.telegram", detail={"enabled": merged.get("enabled"), "chat_id": chat})

    # ------------------------------------------------------------------ acme

    def acme(self):
        return _merge(DEFAULT_ACME, self.db.get_json("acme", {}))

    def set_acme(self, value, actor="system"):
        merged = _merge(self.acme(), value)
        email = str(merged.get("email") or "").strip()
        if email and ("@" not in email or " " in email):
            raise ValidationError("invalid ACME email")
        if not str(merged.get("directory", "")).startswith("https://"):
            raise ValidationError("ACME directory must be an https URL")
        merged["renew_days"] = max(7, min(60, int(merged.get("renew_days") or 30)))
        self.db.set_json("acme", merged)
        self.db.audit(actor, "settings.acme", detail=merged)

    # ----------------------------------------------------------------- panel

    def panel(self):
        return _merge(DEFAULT_PANEL, self.db.get_json("panel", {}))

    def set_panel(self, value, actor="system"):
        merged = _merge(self.panel(), value)
        self.db.set_json("panel", merged)
        self.db.audit(actor, "settings.panel", detail=merged)
        self._changed("panel")
        return merged

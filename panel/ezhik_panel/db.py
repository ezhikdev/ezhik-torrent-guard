"""SQLite storage (WAL) with idempotent, ordered migrations."""

import json
import sqlite3
import threading
import time
from contextlib import contextmanager

MIGRATIONS = [
    # 1: base schema
    """
    CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at REAL NOT NULL,
        last_login_at REAL,
        password_changed_at REAL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
        csrf TEXT NOT NULL,
        created_at REAL NOT NULL,
        last_seen_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        ip TEXT,
        user_agent TEXT
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        ip TEXT NOT NULL,
        at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts(ip, at);

    CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',      -- pending | active | disabled | removing
        token_hash TEXT,
        created_at REAL NOT NULL,
        registered_at REAL,
        last_seen_at REAL,
        last_ip TEXT,
        hostname TEXT,
        agent_version TEXT,
        facts TEXT,
        report TEXT,
        diagnostics TEXT,
        diagnostics_at REAL,
        torrent_enabled INTEGER,
        scan_enabled INTEGER,
        container TEXT,
        interface TEXT,
        wan_ip TEXT,
        domain TEXT,
        cert_id TEXT,
        cert_target TEXT,
        cert_remove INTEGER NOT NULL DEFAULT 0,
        desired_agent_version TEXT,
        applied_generation TEXT,
        tags TEXT,
        notes TEXT,
        online INTEGER NOT NULL DEFAULT 0,
        state_changed_at REAL,
        sort INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS install_tokens (
        token_hash TEXT PRIMARY KEY,
        node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        used_at REAL
    );
    CREATE TABLE IF NOT EXISTS node_commands (
        id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        args TEXT,
        created_at REAL NOT NULL,
        delivered_at REAL,
        done_at REAL
    );
    CREATE TABLE IF NOT EXISTS node_metrics (
        node_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        cpu REAL, mem REAL, rx INTEGER, tx INTEGER, load1 REAL,
        PRIMARY KEY (node_id, ts)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS node_uptime (
        node_id TEXT NOT NULL,
        hour INTEGER NOT NULL,
        online_seconds REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (node_id, hour)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        node_id TEXT,
        type TEXT NOT NULL,                -- torrent | p2p | scan | node | cert | system | sanction
        severity TEXT NOT NULL DEFAULT 'info',
        client_id TEXT,
        detected_at REAL NOT NULL,
        received_at REAL NOT NULL,
        action TEXT,
        title TEXT,
        data TEXT
    );
    CREATE INDEX IF NOT EXISTS events_time ON events(detected_at DESC);
    CREATE INDEX IF NOT EXISTS events_node ON events(node_id, detected_at DESC);
    CREATE INDEX IF NOT EXISTS events_client ON events(client_id, detected_at DESC);
    CREATE INDEX IF NOT EXISTS events_type ON events(type, detected_at DESC);

    CREATE TABLE IF NOT EXISTS sanctions (
        client_id TEXT PRIMARY KEY,
        state TEXT NOT NULL,               -- pending | active
        reason TEXT NOT NULL,
        node_id TEXT,
        event_id TEXT,
        identity TEXT,
        username TEXT,
        duration_seconds INTEGER NOT NULL,
        forget_after_disable INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        disabled_at REAL,
        unfreeze_at REAL,
        next_retry_at REAL NOT NULL,
        disable_attempts INTEGER NOT NULL DEFAULT 0,
        may_have_disabled INTEGER NOT NULL DEFAULT 0,
        ambiguous_since REAL,
        last_disable_attempt_at REAL,
        last_error TEXT,
        hold INTEGER NOT NULL DEFAULT 0,
        source TEXT
    );
    CREATE TABLE IF NOT EXISTS sanction_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        username TEXT,
        reason TEXT,
        node_id TEXT,
        outcome TEXT NOT NULL,
        detail TEXT,
        at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sanction_history_at ON sanction_history(at DESC);

    CREATE TABLE IF NOT EXISTS dns_providers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,                -- cloudflare | acmedns | manual
        credentials TEXT,                  -- encrypted JSON
        created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS certificates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        domains TEXT NOT NULL,             -- JSON list, first is primary
        source TEXT NOT NULL,              -- acme | upload
        provider_id TEXT,
        key_type TEXT NOT NULL DEFAULT 'ec256',
        status TEXT NOT NULL,              -- new | pending_dns | issuing | valid | failed | expired
        auto_renew INTEGER NOT NULL DEFAULT 1,
        version INTEGER NOT NULL DEFAULT 0,
        issued_at REAL,
        not_before REAL,
        not_after REAL,
        fingerprint TEXT,
        issuer TEXT,
        last_error TEXT,
        last_attempt_at REAL,
        next_attempt_at REAL,
        challenge TEXT,                    -- JSON for manual DNS
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at REAL NOT NULL,
        actor TEXT,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT
    );
    CREATE INDEX IF NOT EXISTS audit_at ON audit(at DESC);
    """,
    # 2: firewall, nginx frontend, BBR, stub sites
    """
    ALTER TABLE nodes ADD COLUMN nginx TEXT;
    ALTER TABLE nodes ADD COLUMN firewall TEXT;
    ALTER TABLE nodes ADD COLUMN bbr INTEGER;
    ALTER TABLE nodes ADD COLUMN site_id TEXT;
    ALTER TABLE nodes ADD COLUMN remnawave_node TEXT;
    CREATE TABLE IF NOT EXISTS sites (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0,
        current_version TEXT,
        draft_version TEXT,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS site_versions (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        version TEXT NOT NULL,
        files INTEGER NOT NULL,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        note TEXT,
        created_at REAL NOT NULL,
        PRIMARY KEY (site_id, version)
    );
    """,
]


class Database:
    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self.migrate()

    def migrate(self):
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            for index, script in enumerate(MIGRATIONS, start=1):
                if index <= version:
                    continue
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _split(script):
                        self._conn.execute(statement)
                    self._conn.execute(f"PRAGMA user_version={index}")
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise

    @contextmanager
    def tx(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def execute(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql, params=()):
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def all(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def scalar(self, sql, params=()):
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return row[0] if row else None

    # ------------------------------------------------------------ kv store

    def get_json(self, key, default=None):
        row = self.one("SELECT value FROM kv WHERE key=?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def set_json(self, key, value):
        self.execute(
            "INSERT INTO kv(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, json.dumps(value, ensure_ascii=False), time.time()),
        )

    def audit(self, actor, action, target=None, detail=None):
        self.execute(
            "INSERT INTO audit(at,actor,action,target,detail) VALUES(?,?,?,?,?)",
            (time.time(), actor, action, target, json.dumps(detail, ensure_ascii=False) if detail is not None else None),
        )


def _split(script):
    statements, buffer = [], []
    for line in script.splitlines():
        buffer.append(line)
        if line.rstrip().endswith(";"):
            statement = "\n".join(buffer).strip()
            if statement.strip(";").strip():
                statements.append(statement)
            buffer = []
    rest = "\n".join(buffer).strip()
    if rest:
        statements.append(rest)
    return statements


def loads(value, default=None):
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default

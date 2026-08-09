#!/usr/bin/env python3

import os
import json
import time
import queue
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime


# ============================================================
# CONFIG
# ============================================================

ENV_FILE = "/etc/ezhik-torrent-guard/api.env"

STATE_DIR = Path("/var/lib/ezhik-torrent-guard")
STATE_FILE = STATE_DIR / "sanctions.json"

def _env_int(name, default, minimum=1):
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    return max(minimum, value)


def _env_clients(name):
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip().isdigit()}


FREEZE_SECONDS = _env_int("EZHIK_FREEZE_SECONDS", 900)

# API retry after temporary failure
RETRY_SECONDS = 60

# Defense in depth.
PROTECTED_CLIENTS = _env_clients("EZHIK_PROTECTED_CLIENTS")

# FIRST LIVE CANARY:
# only this user may receive API writes.
#
# After successful full test:
# WRITE_ALLOWLIST = None
WRITE_ALLOWLIST = None

# Optional emergency admin hold:
#
# one numeric client ID per line.
#
# Example:
# echo 12345 >> /etc/ezhik-torrent-guard/hold.txt
#
# Guard will NOT auto-enable users listed here.
HOLD_FILE = Path("/etc/ezhik-torrent-guard/hold.txt")


# ============================================================
# INTERNAL STATE
# ============================================================

_running = threading.Event()

_actions = queue.Queue()

_lock = threading.RLock()

_queued = set()

_sanctions = {}

_base_url = None
_token = None

_worker_thread = None


# ============================================================
# CONFIG LOADING
# ============================================================

def _load_env_file():

    cfg = {}

    with open(ENV_FILE, encoding="utf-8") as f:

        for raw in f:

            line = raw.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip()

            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in ("'", '"')
            ):
                value = value[1:-1]

            cfg[key] = value

    base_url = cfg.get(
        "REMNAWAVE_BASE_URL",
        "",
    ).rstrip("/")

    token = cfg.get(
        "REMNAWAVE_API_TOKEN",
        "",
    )

    if not base_url:
        raise RuntimeError(
            "REMNAWAVE_BASE_URL missing"
        )

    if not token:
        raise RuntimeError(
            "REMNAWAVE_API_TOKEN missing"
        )

    return base_url, token


# ============================================================
# PERSISTENT SANCTION STATE
# ============================================================

def _save_state_locked():

    STATE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    os.chmod(
        STATE_DIR,
        0o700,
    )

    tmp = STATE_FILE.with_suffix(
        ".json.tmp"
    )

    data = {
        "version": 1,
        "sanctions": _sanctions,
    }

    tmp.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    os.chmod(
        tmp,
        0o600,
    )

    os.replace(
        tmp,
        STATE_FILE,
    )

    os.chmod(
        STATE_FILE,
        0o600,
    )


def _load_state():

    global _sanctions

    STATE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    os.chmod(
        STATE_DIR,
        0o700,
    )

    if not STATE_FILE.exists():

        with _lock:

            _sanctions = {}

            _save_state_locked()

        return

    try:

        raw = json.loads(
            STATE_FILE.read_text(
                encoding="utf-8"
            )
        )

        sanctions = raw.get(
            "sanctions",
            {},
        )

        if not isinstance(
            sanctions,
            dict,
        ):
            raise ValueError(
                "sanctions is not object"
            )

        cleaned = {}

        for client, rec in sanctions.items():

            if not isinstance(
                rec,
                dict,
            ):
                continue

            if not str(client).isdigit():
                continue

            uuid = rec.get("uuid")
            unfreeze_at = rec.get(
                "unfreeze_at"
            )

            if not uuid:
                continue

            if not isinstance(
                unfreeze_at,
                (int, float),
            ):
                continue

            cleaned[str(client)] = rec

        with _lock:

            _sanctions = cleaned

            _save_state_locked()

    except Exception as exc:

        raise RuntimeError(
            f"cannot load sanction state: {exc}"
        )


# ============================================================
# API
# ============================================================

def _decode_json(raw):

    if not raw:
        return {}

    try:

        return json.loads(
            raw.decode(
                "utf-8",
                errors="replace",
            )
        )

    except Exception:

        return {
            "_raw": raw.decode(
                "utf-8",
                errors="replace",
            )
        }


def _api(method, path):

    url = (
        _base_url
        + path
    )

    data = (
        b""
        if method == "POST"
        else None
    )

    request = urllib.request.Request(
        url=url,
        data=data,
        method=method,
        headers={
            "Authorization":
                f"Bearer {_token}",

            "Accept":
                "application/json",

            "User-Agent":
                "Ezhik-Torrent-Guard/1.0.0",
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:

            body = response.read()

            return (
                response.status,
                _decode_json(body),
            )

    except urllib.error.HTTPError as exc:

        body = exc.read()

        return (
            exc.code,
            _decode_json(body),
        )

    except Exception as exc:

        return (
            0,
            {
                "_transport_error":
                    repr(exc),
            },
        )


def _find_error_code(obj):

    if isinstance(
        obj,
        dict,
    ):

        code = obj.get(
            "errorCode"
        )

        if isinstance(
            code,
            str,
        ):
            return code

        for value in obj.values():

            found = _find_error_code(
                value
            )

            if found:
                return found

    elif isinstance(
        obj,
        list,
    ):

        for value in obj:

            found = _find_error_code(
                value
            )

            if found:
                return found

    return None


def _resolve_user(client):

    code, payload = _api(
        "GET",
        f"/api/users/by-id/{client}",
    )

    if code != 200:

        print(
            f"[API ERROR] "
            f"resolve client={client} "
            f"http={code}",
            flush=True,
        )

        return None

    user = payload.get(
        "response"
    )

    if not isinstance(
        user,
        dict,
    ):

        print(
            f"[API ERROR] "
            f"resolve client={client} "
            f"invalid response",
            flush=True,
        )

        return None

    try:

        api_id = int(
            user.get("id")
        )

        expected_id = int(
            client
        )

    except Exception:

        print(
            f"[API ERROR] "
            f"resolve client={client} "
            f"invalid numeric id",
            flush=True,
        )

        return None

    if api_id != expected_id:

        print(
            f"[API SECURITY] "
            f"client mismatch: "
            f"wanted={client} "
            f"got={api_id}",
            flush=True,
        )

        return None

    uuid = user.get(
        "uuid"
    )

    if not isinstance(
        uuid,
        str,
    ) or not uuid:

        print(
            f"[API ERROR] "
            f"client={client} "
            f"has no uuid",
            flush=True,
        )

        return None

    return user


# ============================================================
# SAFETY
# ============================================================

def _is_held(client):

    try:

        if not HOLD_FILE.exists():
            return False

        for raw in HOLD_FILE.read_text(
            encoding="utf-8"
        ).splitlines():

            value = raw.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            if value == client:
                return True

    except Exception:

        pass

    return False


def _write_allowed(client):

    if client in PROTECTED_CLIENTS:

        print(
            f"[PROTECTED] "
            f"client={client} "
            f"API write blocked",
            flush=True,
        )

        return False

    if (
        WRITE_ALLOWLIST is not None
        and client
        not in WRITE_ALLOWLIST
    ):

        print(
            f"[CANARY BLOCK] "
            f"client={client} "
            f"not in API write allowlist",
            flush=True,
        )

        return False

    return True


# ============================================================
# FREEZE
# ============================================================

def queue_freeze(client):

    client = str(
        client
    )

    if not _write_allowed(
        client
    ):
        return False

    with _lock:

        if client in _sanctions:

            return False

        if client in _queued:

            return False

        _queued.add(
            client
        )

    _actions.put(
        (
            "freeze",
            client,
        )
    )

    print(
        f"[ACTION QUEUED] "
        f"client={client} "
        f"action=freeze",
        flush=True,
    )

    return True


def _freeze(client):

    if not _write_allowed(
        client
    ):
        return

    user = _resolve_user(
        client
    )

    if user is None:
        return

    status = user.get(
        "status"
    )

    uuid = user.get(
        "uuid"
    )

    # Critical safety:
    # if user is already disabled / expired / limited,
    # Torrent Guard did NOT disable them and therefore
    # must NOT schedule an automatic enable.
    if status != "ACTIVE":

        print(
            f"[FREEZE SKIP] "
            f"client={client} "
            f"status={status} "
            f"no auto-unfreeze scheduled",
            flush=True,
        )

        return

    code, payload = _api(
        "POST",
        f"/api/users/{uuid}/actions/disable",
    )

    if code == 200:

        response = payload.get(
            "response",
            {},
        )

        new_status = response.get(
            "status"
        )

        if new_status != "DISABLED":

            print(
                f"[API ERROR] "
                f"disable client={client} "
                f"http=200 "
                f"unexpected_status={new_status}",
                flush=True,
            )

            return

        now = time.time()

        unfreeze_at = (
            now
            + FREEZE_SECONDS
        )

        record = {
            "client_id": client,
            "uuid": uuid,
            "disabled_at": now,
            "unfreeze_at": unfreeze_at,
            "next_retry_at": unfreeze_at,
            "reason": "bittorrent",
        }

        with _lock:

            _sanctions[
                client
            ] = record

            _save_state_locked()

        when = datetime.fromtimestamp(
            unfreeze_at
        ).astimezone()

        print()
        print(
            f"[FROZEN] "
            f"client={client} "
            f"duration={FREEZE_SECONDS // 60}m "
            f"until={when.isoformat(timespec='seconds')}",
            flush=True,
        )
        print()

        return

    error_code = _find_error_code(
        payload
    )

    # Already disabled:
    # IMPORTANT: do not create Torrent Guard sanction,
    # because Guard does not own this disable.
    if error_code == "A029":

        print(
            f"[FREEZE SKIP] "
            f"client={client} "
            f"already disabled "
            f"(A029); "
            f"no auto-unfreeze",
            flush=True,
        )

        return

    print(
        f"[API ERROR] "
        f"disable client={client} "
        f"http={code} "
        f"error={error_code}",
        flush=True,
    )


# ============================================================
# UNFREEZE
# ============================================================

def _remove_sanction(
    client,
):

    with _lock:

        _sanctions.pop(
            client,
            None,
        )

        _save_state_locked()


def _retry_later(
    client,
    reason,
):

    with _lock:

        rec = _sanctions.get(
            client
        )

        if rec is None:
            return

        rec[
            "next_retry_at"
        ] = (
            time.time()
            + RETRY_SECONDS
        )

        _save_state_locked()

    print(
        f"[UNFREEZE RETRY] "
        f"client={client} "
        f"in={RETRY_SECONDS}s "
        f"reason={reason}",
        flush=True,
    )


def _unfreeze(client):

    with _lock:

        rec = _sanctions.get(
            client
        )

        if rec is None:
            return

        expected_uuid = rec.get(
            "uuid"
        )

    if _is_held(
        client
    ):

        _retry_later(
            client,
            "admin-hold",
        )

        return

    user = _resolve_user(
        client
    )

    if user is None:

        _retry_later(
            client,
            "resolve-failed",
        )

        return

    current_uuid = user.get(
        "uuid"
    )

    status = user.get(
        "status"
    )

    if current_uuid != expected_uuid:

        print(
            f"[UNFREEZE SECURITY] "
            f"client={client} "
            f"uuid changed; "
            f"refusing enable",
            flush=True,
        )

        _retry_later(
            client,
            "uuid-mismatch",
        )

        return

    # Someone already enabled the user manually.
    if status == "ACTIVE":

        print(
            f"[UNFREEZE] "
            f"client={client} "
            f"already ACTIVE; "
            f"local sanction cleared",
            flush=True,
        )

        _remove_sanction(
            client
        )

        return

    # Do NOT override natural/system statuses.
    if status != "DISABLED":

        print(
            f"[UNFREEZE SKIP] "
            f"client={client} "
            f"status={status}; "
            f"will not force ACTIVE",
            flush=True,
        )

        _remove_sanction(
            client
        )

        return

    code, payload = _api(
        "POST",
        f"/api/users/{expected_uuid}/actions/enable",
    )

    if code == 200:

        response = payload.get(
            "response",
            {},
        )

        new_status = response.get(
            "status"
        )

        if new_status != "ACTIVE":

            _retry_later(
                client,
                f"unexpected-status-{new_status}",
            )

            return

        print()
        print(
            f"[UNFROZEN] "
            f"client={client} "
            f"status=ACTIVE",
            flush=True,
        )
        print()

        _remove_sanction(
            client
        )

        return

    error_code = _find_error_code(
        payload
    )

    # Already enabled.
    if error_code == "A030":

        print(
            f"[UNFROZEN] "
            f"client={client} "
            f"already ACTIVE "
            f"(A030)",
            flush=True,
        )

        _remove_sanction(
            client
        )

        return

    _retry_later(
        client,
        f"http-{code}-error-{error_code}",
    )


def _process_due_unfreezes():

    now = time.time()

    with _lock:

        due = []

        for client, rec in (
            _sanctions.items()
        ):

            unfreeze_at = float(
                rec.get(
                    "unfreeze_at",
                    0,
                )
            )

            next_retry_at = float(
                rec.get(
                    "next_retry_at",
                    unfreeze_at,
                )
            )

            if (
                now >= unfreeze_at
                and now >= next_retry_at
            ):
                due.append(
                    client
                )

    for client in due:

        _unfreeze(
            client
        )


# ============================================================
# WORKER
# ============================================================

def _worker():

    while _running.is_set():

        _process_due_unfreezes()

        try:

            action, client = (
                _actions.get(
                    timeout=1.0
                )
            )

        except queue.Empty:

            continue

        try:

            if action == "freeze":

                _freeze(
                    client
                )

        except Exception as exc:

            print(
                f"[ACTION ERROR] "
                f"client={client} "
                f"error={exc!r}",
                flush=True,
            )

        finally:

            with _lock:

                _queued.discard(
                    client
                )

            try:
                _actions.task_done()
            except Exception:
                pass


# ============================================================
# PUBLIC START / STOP
# ============================================================

def start():

    global _base_url
    global _token
    global _worker_thread

    _base_url, _token = (
        _load_env_file()
    )

    _load_state()

    _running.set()

    _worker_thread = threading.Thread(
        target=_worker,
        name="remnawave-actions",
        daemon=True,
    )

    _worker_thread.start()

    with _lock:

        sanctions_count = len(
            _sanctions
        )

    allow = (
        "ALL"
        if WRITE_ALLOWLIST is None
        else ",".join(
            sorted(
                WRITE_ALLOWLIST
            )
        )
    )

    print(
        f"[REMNAWAVE] "
        f"API worker started "
        f"allowlist={allow} "
        f"pending_sanctions={sanctions_count}",
        flush=True,
    )


def stop():

    _running.clear()

    worker = _worker_thread

    if worker is not None:

        worker.join(
            timeout=2
        )

    print(
        "[REMNAWAVE] "
        "API worker stopped; "
        "sanctions preserved",
        flush=True,
    )

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

# client -> persistent freeze attempt state.
# Kept separately from confirmed sanctions so an ambiguous disable request
# can be recovered safely after API/network failures or Guard restarts.
_pending_freezes = {}

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
        "version": 2,
        "sanctions": _sanctions,
        "pending_freezes": _pending_freezes,
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
    global _pending_freezes

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
            _pending_freezes = {}

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

        pending_freezes = raw.get(
            "pending_freezes",
            {},
        )

        if not isinstance(
            sanctions,
            dict,
        ):
            raise ValueError(
                "sanctions is not object"
            )

        if not isinstance(
            pending_freezes,
            dict,
        ):
            pending_freezes = {}

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

        cleaned_pending = {}

        for client, rec in pending_freezes.items():

            client = str(client)

            if not client.isdigit():
                continue

            if not isinstance(rec, dict):
                continue

            # A confirmed sanction always wins over a pending attempt.
            if client in cleaned:
                continue

            uuid = rec.get("uuid")

            if uuid is not None and (
                not isinstance(uuid, str)
                or not uuid
            ):
                uuid = None

            created_at = rec.get(
                "created_at",
                time.time(),
            )

            next_retry_at = rec.get(
                "next_retry_at",
                time.time(),
            )

            if not isinstance(
                created_at,
                (int, float),
            ):
                created_at = time.time()

            if not isinstance(
                next_retry_at,
                (int, float),
            ):
                next_retry_at = time.time()

            try:
                disable_attempts = max(
                    0,
                    int(
                        rec.get(
                            "disable_attempts",
                            0,
                        )
                        or 0
                    ),
                )
            except Exception:
                disable_attempts = 0

            ambiguous_since = rec.get(
                "ambiguous_since"
            )

            if not isinstance(
                ambiguous_since,
                (int, float),
            ):
                ambiguous_since = None

            last_disable_attempt_at = rec.get(
                "last_disable_attempt_at"
            )

            if not isinstance(
                last_disable_attempt_at,
                (int, float),
            ):
                last_disable_attempt_at = None

            cleaned_pending[client] = {
                "client_id": client,
                "uuid": uuid,
                "created_at": float(created_at),
                "next_retry_at": float(next_retry_at),
                "disable_attempts": disable_attempts,
                "may_have_disabled": bool(
                    rec.get("may_have_disabled", False)
                ),
                "ambiguous_since": (
                    float(ambiguous_since)
                    if ambiguous_since is not None
                    else None
                ),
                "last_disable_attempt_at": (
                    float(last_disable_attempt_at)
                    if last_disable_attempt_at is not None
                    else None
                ),
                "last_error": str(
                    rec.get("last_error", "")
                ),
            }

        with _lock:

            _sanctions = cleaned
            _pending_freezes = cleaned_pending

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

def _remove_pending_freeze(client):

    with _lock:

        _pending_freezes.pop(
            client,
            None,
        )

        _save_state_locked()


def _ensure_pending_freeze(client):

    with _lock:

        rec = _pending_freezes.get(
            client
        )

        if rec is None:

            now = time.time()

            rec = {
                "client_id": client,
                "uuid": None,
                "created_at": now,
                "next_retry_at": now,
                "disable_attempts": 0,
                "may_have_disabled": False,
                "ambiguous_since": None,
                "last_disable_attempt_at": None,
                "last_error": "",
            }

            _pending_freezes[
                client
            ] = rec

            _save_state_locked()

        return dict(rec)


def _freeze_retry_later(
    client,
    reason,
    may_have_disabled=False,
    ambiguous_at=None,
):

    with _lock:

        rec = _pending_freezes.get(
            client
        )

        if rec is None:
            return

        if may_have_disabled:

            rec[
                "may_have_disabled"
            ] = True

            if rec.get(
                "ambiguous_since"
            ) is None:

                when = (
                    ambiguous_at
                    if isinstance(
                        ambiguous_at,
                        (int, float),
                    )
                    else time.time()
                )

                rec[
                    "ambiguous_since"
                ] = float(when)

        rec[
            "last_error"
        ] = str(reason)

        rec[
            "next_retry_at"
        ] = (
            time.time()
            + RETRY_SECONDS
        )

        _save_state_locked()

        ambiguous = bool(
            rec.get(
                "may_have_disabled",
                False,
            )
        )

    print(
        f"[FREEZE RETRY] "
        f"client={client} "
        f"in={RETRY_SECONDS}s "
        f"reason={reason} "
        f"may_have_disabled={'yes' if ambiguous else 'no'}",
        flush=True,
    )


def _confirm_frozen(
    client,
    uuid,
    source,
    disabled_at=None,
):

    now = time.time()

    if not isinstance(
        disabled_at,
        (int, float),
    ):
        disabled_at = now

    # Never claim the disable predates the time we actually know about.
    disabled_at = min(
        float(disabled_at),
        now,
    )

    unfreeze_at = (
        disabled_at
        + FREEZE_SECONDS
    )

    record = {
        "client_id": client,
        "uuid": uuid,
        "disabled_at": disabled_at,
        "unfreeze_at": unfreeze_at,
        "next_retry_at": unfreeze_at,
        "reason": "bittorrent",
        "source": source,
    }

    with _lock:

        _pending_freezes.pop(
            client,
            None,
        )

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
        f"until={when.isoformat(timespec='seconds')} "
        f"source={source}",
        flush=True,
    )
    print()


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

        if client in _pending_freezes:

            return False

        if client in _queued:

            return False

        now = time.time()

        _pending_freezes[
            client
        ] = {
            "client_id": client,
            "uuid": None,
            "created_at": now,
            "next_retry_at": now,
            "disable_attempts": 0,
            "may_have_disabled": False,
            "ambiguous_since": None,
            "last_disable_attempt_at": None,
            "last_error": "",
        }

        _queued.add(
            client
        )

        _save_state_locked()

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

        _remove_pending_freeze(
            client
        )

        return

    pending = _ensure_pending_freeze(
        client
    )

    user = _resolve_user(
        client
    )

    if user is None:

        _freeze_retry_later(
            client,
            "resolve-failed",
            may_have_disabled=False,
        )

        return

    status = user.get(
        "status"
    )

    uuid = user.get(
        "uuid"
    )

    expected_uuid = pending.get(
        "uuid"
    )

    if (
        expected_uuid
        and uuid != expected_uuid
    ):

        print(
            f"[FREEZE SECURITY] "
            f"client={client} "
            f"uuid changed; "
            f"refusing further writes",
            flush=True,
        )

        _remove_pending_freeze(
            client
        )

        return

    with _lock:

        rec = _pending_freezes.get(
            client
        )

        if rec is None:
            return

        rec["uuid"] = uuid

        may_have_disabled = bool(
            rec.get(
                "may_have_disabled",
                False,
            )
        )

        ambiguous_since = rec.get(
            "ambiguous_since"
        )

        _save_state_locked()

    # If an earlier disable request had an ambiguous outcome and the
    # same user is now DISABLED, assume our prior request succeeded.
    # This is the key recovery path for: POST reached panel -> user was
    # disabled -> response/connection was lost.
    if (
        status == "DISABLED"
        and may_have_disabled
    ):

        print(
            f"[FREEZE RECOVERED] "
            f"client={client} "
            f"already DISABLED after ambiguous prior attempt; "
            f"treating disable as Torrent Guard owned",
            flush=True,
        )

        _confirm_frozen(
            client,
            uuid,
            "recovered-ambiguous-disable",
            disabled_at=ambiguous_since,
        )

        return

    # Critical safety:
    # on the first attempt, or after failures that definitely did not
    # perform a write, an already non-ACTIVE user is NOT ours.
    if status != "ACTIVE":

        print(
            f"[FREEZE SKIP] "
            f"client={client} "
            f"status={status} "
            f"no auto-unfreeze scheduled",
            flush=True,
        )

        _remove_pending_freeze(
            client
        )

        return

    with _lock:

        rec = _pending_freezes.get(
            client
        )

        if rec is None:
            return

        had_ambiguous_prior_attempt = bool(
            rec.get(
                "may_have_disabled",
                False,
            )
        )

        prior_ambiguous_since = rec.get(
            "ambiguous_since"
        )

        attempt_started = time.time()

        rec["disable_attempts"] = int(
            rec.get(
                "disable_attempts",
                0,
            )
        ) + 1

        rec[
            "last_disable_attempt_at"
        ] = attempt_started

        _save_state_locked()

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

        if new_status == "DISABLED":

            _confirm_frozen(
                client,
                uuid,
                "api-200",
            )

            return

        # HTTP 200 with an unexpected body is ambiguous: the write may
        # have happened, so preserve ownership uncertainty and verify on
        # the next pass instead of losing the sanction.
        _freeze_retry_later(
            client,
            f"http-200-unexpected-status-{new_status}",
            may_have_disabled=True,
            ambiguous_at=attempt_started,
        )

        return

    error_code = _find_error_code(
        payload
    )

    # FIRST attempt returns A029 -> user was already disabled before
    # Torrent Guard owned any ambiguous write. Never auto-enable them.
    #
    # A029 AFTER an earlier ambiguous disable attempt -> the previous
    # request may have succeeded and only its response was lost. Treat
    # that disable as ours and start the normal freeze timer.
    if error_code == "A029":

        if had_ambiguous_prior_attempt:

            print(
                f"[FREEZE RECOVERED] "
                f"client={client} "
                f"A029 after ambiguous prior disable; "
                f"treating disable as Torrent Guard owned",
                flush=True,
            )

            _confirm_frozen(
                client,
                uuid,
                "recovered-A029",
                disabled_at=prior_ambiguous_since,
            )

            return

        print(
            f"[FREEZE SKIP] "
            f"client={client} "
            f"already disabled "
            f"(A029) on first disable attempt; "
            f"no auto-unfreeze",
            flush=True,
        )

        _remove_pending_freeze(
            client
        )

        return

    # No HTTP response / server-side failure can be ambiguous: the
    # panel may have committed the disable before the response was lost.
    if (
        code == 0
        or code >= 500
    ):

        _freeze_retry_later(
            client,
            f"http-{code}-error-{error_code}",
            may_have_disabled=True,
            ambiguous_at=attempt_started,
        )

        return

    # HTTP 408 is ambiguous for a POST: depending on the proxy/server,
    # the action may have reached the application before the timeout was
    # reported. Preserve ownership uncertainty and verify on retry.
    if code == 408:

        _freeze_retry_later(
            client,
            f"http-{code}-error-{error_code}",
            may_have_disabled=True,
            ambiguous_at=attempt_started,
        )

        return

    # These transient responses normally reject the request before the
    # action is committed. Retry, but do not claim ownership.
    if code in {
        425,
        429,
    }:

        _freeze_retry_later(
            client,
            f"http-{code}-error-{error_code}",
            may_have_disabled=False,
        )

        return

    print(
        f"[API ERROR] "
        f"disable client={client} "
        f"http={code} "
        f"error={error_code}; "
        f"not retrying deterministic failure",
        flush=True,
    )

    _remove_pending_freeze(
        client
    )


def _process_due_freezes():

    now = time.time()

    with _lock:

        due = []

        for client, rec in (
            _pending_freezes.items()
        ):

            # Initial queued action owns this client until its first
            # processing attempt finishes.
            if client in _queued:
                continue

            next_retry_at = float(
                rec.get(
                    "next_retry_at",
                    0,
                )
            )

            if now >= next_retry_at:
                due.append(
                    (next_retry_at, client)
                )

    if not due:
        return

    # Process only one retry per worker pass so a dead panel cannot make
    # a large pending-freeze backlog starve due unfreezes.
    due.sort()

    _freeze(
        due[0][1]
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

        _process_due_freezes()
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

        pending_freezes_count = len(
            _pending_freezes
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
        f"pending_sanctions={sanctions_count} "
        f"pending_freezes={pending_freezes_count}",
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

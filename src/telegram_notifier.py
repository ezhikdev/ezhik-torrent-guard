#!/usr/bin/env python3

import json
import os
import queue
import secrets
import threading
import urllib.error
import urllib.request

from datetime import datetime, timezone
from pathlib import Path


ENV_FILE = "/etc/ezhik-torrent-guard/telegram.env"
INCIDENT_DIR = Path("/var/lib/ezhik-torrent-guard/incidents")
MAX_INCIDENT_FILES = 100

_running = threading.Event()
_events = queue.Queue(maxsize=100)
_worker_thread = None
_bot_token = None
_chat_id = None


def _load_env_file():
    path = Path(ENV_FILE)
    if not path.is_file():
        return None, None

    cfg = {}
    with path.open(encoding="utf-8") as source:
        for raw in source:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            cfg[key.strip()] = value.strip()

    token = cfg.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = cfg.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return None, None
    return token, chat_id


def _format_duration(seconds):
    if seconds == 0:
        return "permanent (manual Remnawave unblock)"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _incident_text(report):
    detected = datetime.fromtimestamp(
        report["detected_at"],
        tz=timezone.utc,
    ).isoformat(timespec="seconds")

    lines = [
        "Ezhik Torrent Guard - port-scan incident",
        "",
        f"detected_at_utc: {detected}",
        f"node_ip: {report.get('node_ip', 'unknown')}",
        f"client_id: {report['client_id']}",
        f"reason: {report['reason']}",
        f"action: {report.get('action', 'unknown')}",
        f"block_duration: {_format_duration(report['block_seconds'])}",
        f"window_seconds: {report['window_seconds']}",
        f"unique_endpoints: {report['unique_endpoints']}",
        f"unique_ips: {report['unique_ips']}",
        f"unique_ports: {report['unique_ports']}",
    ]

    for key, value in sorted(report.get("details", {}).items()):
        lines.append(f"{key}: {value}")

    lines.extend(["", "sample_endpoints:"])
    for item in report.get("sample_endpoints", []):
        lines.append(
            f"{item['protocol'].upper()} "
            f"{item['remote_ip']}:{item['remote_port']}"
        )

    lines.append("")
    return "\n".join(lines)


def _write_incident(report):
    INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(INCIDENT_DIR, 0o700)

    stamp = datetime.fromtimestamp(
        report["detected_at"],
        tz=timezone.utc,
    ).strftime("%Y%m%dT%H%M%SZ")
    name = (
        f"port-scan-{stamp}-client-{report['client_id']}-"
        f"{secrets.token_hex(3)}.txt"
    )
    path = INCIDENT_DIR / name
    path.write_text(_incident_text(report), encoding="utf-8")
    os.chmod(path, 0o600)

    files = sorted(
        INCIDENT_DIR.glob("port-scan-*.txt"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for old in files[MAX_INCIDENT_FILES:]:
        try:
            old.unlink()
        except OSError:
            pass

    return path


def _multipart(fields, file_path):
    boundary = "----EzhikTorrentGuard" + secrets.token_hex(12)
    chunks = []

    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                ).encode(),
                str(value).encode("utf-8"),
                b"\r\n",
            ]
        )

    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                'Content-Disposition: form-data; name="document"; '
                f'filename="{file_path.name}"\r\n'
            ).encode(),
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n",
            file_path.read_bytes(),
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return boundary, b"".join(chunks)


def _send(report, file_path):
    detected = datetime.fromtimestamp(
        report["detected_at"],
        tz=timezone.utc,
    ).isoformat(timespec="seconds")
    caption = (
        "Ezhik Port-Scan Guard\n"
        f"Client: {report['client_id']}\n"
        f"Node: {report.get('node_ip', 'unknown')}\n"
        f"Time: {detected}\n"
        f"Reason: {report['reason']}\n"
        f"Action: {report.get('action', 'unknown')}\n"
        f"Block: {_format_duration(report['block_seconds'])}\n"
        f"Endpoints/IPs/ports: {report['unique_endpoints']}/"
        f"{report['unique_ips']}/{report['unique_ports']}"
    )

    boundary, body = _multipart(
        {
            "chat_id": _chat_id,
            "caption": caption,
        },
        file_path,
    )
    request = urllib.request.Request(
        url=f"https://api.telegram.org/bot{_bot_token}/sendDocument",
        data=body,
        method="POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Ezhik-Torrent-Guard",
        },
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
        if response.status != 200 or not payload.get("ok"):
            raise RuntimeError(f"Telegram rejected notification: HTTP {response.status}")


def _safe_error(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f"http-{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"network-{type(exc.reason).__name__}"
    return type(exc).__name__


def _worker():
    while _running.is_set() or not _events.empty():
        try:
            report = _events.get(timeout=1.0)
        except queue.Empty:
            continue

        path = None
        try:
            path = _write_incident(report)
            if _bot_token and _chat_id:
                _send(report, path)
                marker = "TELEGRAM SENT"
            else:
                marker = "INCIDENT SAVED"
            print(
                f"[{marker}] client={report['client_id']} file={path.name}",
                flush=True,
            )
        except (OSError, ValueError, urllib.error.URLError, RuntimeError) as exc:
            print(
                f"[TELEGRAM ERROR] client={report['client_id']} "
                f"error={_safe_error(exc)} "
                f"file={path.name if path is not None else 'not-written'}",
                flush=True,
            )
        finally:
            _events.task_done()


def start():
    global _bot_token, _chat_id, _worker_thread

    try:
        _bot_token, _chat_id = _load_env_file()
    except OSError as exc:
        _bot_token, _chat_id = None, None
        print(
            f"[TELEGRAM ERROR] config={_safe_error(exc)}; local reports only",
            flush=True,
        )
    _running.set()
    _worker_thread = threading.Thread(
        target=_worker,
        name="telegram-notifier",
        daemon=True,
    )
    _worker_thread.start()
    print(
        "[TELEGRAM] notifier started"
        if _bot_token and _chat_id
        else "[TELEGRAM] disabled; local incident reports enabled",
        flush=True,
    )
    return True


def notify_scan(report):
    if not _running.is_set():
        return False

    try:
        _events.put_nowait(dict(report))
        return True
    except queue.Full:
        print(
            f"[TELEGRAM DROPPED] client={report.get('client_id', 'unknown')} queue=full",
            flush=True,
        )
        return False


def stop():
    _running.clear()
    worker = _worker_thread
    if worker is not None:
        worker.join(timeout=3)
    print("[TELEGRAM] notifier stopped", flush=True)

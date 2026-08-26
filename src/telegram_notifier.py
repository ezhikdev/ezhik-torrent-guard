#!/usr/bin/env python3

import html
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


REASON_LABELS = {
    "vertical-port-scan": "Перебор портов одного IP-адреса",
    "subnet-port-scan": "Сканирование адресов одной подсети /24",
}

ACTION_LABELS = {
    "WOULD_BLOCK": "Наблюдение — клиент не заблокирован",
    "BLOCK_QUEUED": "Блокировка поставлена в очередь",
    "PROTECTED_NO_ACTION": "Защищённый клиент — блокировка не применяется",
    "NO_ACTION_ALREADY_BLOCKED_OR_PENDING": (
        "Клиент уже заблокирован или ожидает блокировки"
    ),
}


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
        return "бессрочно; разблокировка вручную в Remnawave"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} ч."
    if seconds % 60 == 0:
        return f"{seconds // 60} мин."
    return f"{seconds} сек."


def _format_time(timestamp):
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).strftime("%d.%m.%Y %H:%M:%S UTC")


def _reason_label(reason):
    return REASON_LABELS.get(reason, reason)


def _action_label(action):
    return ACTION_LABELS.get(action, action)


def _target_lines(details):
    if "target_ip" in details:
        return [
            f"Целевой IP: {details['target_ip']}",
            f"Уникальных портов цели: {details['target_unique_ports']}",
        ]
    if "target_subnet" in details:
        return [
            f"Целевая подсеть: {details['target_subnet']}",
            f"Уникальных адресов подсети: {details['subnet_unique_hosts']}",
            f"Уникальных портов подсети: {details['subnet_unique_ports']}",
            f"Уникальных назначений подсети: {details['subnet_unique_endpoints']}",
        ]
    return []


def _incident_text(report):
    detected = _format_time(report["detected_at"])
    details = report.get("details", {})

    lines = [
        "Ezhik Torrent Guard — отчёт о сканировании портов",
        "",
        f"Время обнаружения: {detected}",
        f"IP ноды: {report.get('node_ip', 'неизвестно')}",
        f"ID клиента: {report['client_id']}",
        f"Нарушение: {_reason_label(report['reason'])}",
        f"Реакция: {_action_label(report.get('action', 'неизвестно'))}",
        f"Настроенная блокировка: {_format_duration(report['block_seconds'])}",
        "",
        f"Окно анализа: {report['window_seconds']} сек.",
        f"Уникальных назначений: {report['unique_endpoints']}",
        f"Уникальных IP-адресов: {report['unique_ips']}",
        f"Уникальных портов: {report['unique_ports']}",
    ]

    target_lines = _target_lines(details)
    if target_lines:
        lines.extend([""] + target_lines)

    lines.extend(["", "Примеры назначений:"])
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
    detected = _format_time(report["detected_at"])
    reason = _reason_label(report["reason"])
    action = _action_label(report.get("action", "неизвестно"))
    details = report.get("details", {})

    caption_lines = [
        "🚨 <b>Обнаружено сканирование портов</b>",
        "",
        f"👤 <b>Клиент:</b> {html.escape(str(report['client_id']))}",
        f"🌐 <b>Нода:</b> {html.escape(str(report.get('node_ip', 'неизвестно')))}",
        f"🕒 <b>Время:</b> {html.escape(detected)}",
        "",
        f"🔎 <b>Нарушение:</b> {html.escape(reason)}",
    ]

    if "target_ip" in details:
        caption_lines.append(
            f"🎯 <b>Цель:</b> {html.escape(str(details['target_ip']))} · "
            f"портов: <b>{int(details['target_unique_ports'])}</b>"
        )
    elif "target_subnet" in details:
        caption_lines.append(
            f"🎯 <b>Подсеть:</b> {html.escape(str(details['target_subnet']))} · "
            f"адресов: <b>{int(details['subnet_unique_hosts'])}</b> · "
            f"портов: <b>{int(details['subnet_unique_ports'])}</b> · "
            f"назначений: <b>{int(details['subnet_unique_endpoints'])}</b>"
        )

    caption_lines.extend(
        [
            (
                f"📊 <b>За {int(report['window_seconds'])} сек.:</b> "
                f"назначений {int(report['unique_endpoints'])} · "
                f"IP {int(report['unique_ips'])} · "
                f"портов {int(report['unique_ports'])}"
            ),
            "",
            f"🛡 <b>Реакция:</b> {html.escape(action)}",
            (
                "⏳ <b>Блокировка по настройке:</b> "
                f"{html.escape(_format_duration(report['block_seconds']))}"
            ),
            "",
            "📎 Полный технический отчёт приложен к сообщению.",
        ]
    )
    caption = "\n".join(caption_lines)

    boundary, body = _multipart(
        {
            "chat_id": _chat_id,
            "caption": caption,
            "parse_mode": "HTML",
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

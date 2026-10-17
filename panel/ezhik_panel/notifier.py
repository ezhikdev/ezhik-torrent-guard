"""Telegram notifications from the panel (non-blocking queue)."""

import html
import json
import logging
import queue
import secrets
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("ezhik.notifier")

TYPE_EMOJI = {"torrent": "🧲", "p2p": "🕸", "scan": "📡", "node": "🖥", "cert": "🔐", "sanction": "⛔", "system": "⚙️"}


def _fmt_duration(seconds):
    if seconds == 0:
        return "бессрочно (снять вручную в Remnawave)"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} ч."
    if seconds % 60 == 0:
        return f"{seconds // 60} мин."
    return f"{seconds} сек."


def _fmt_time(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")


def scan_report_text(node, client_id, title, action_title, data, protection):
    details = data.get("details") or {}
    duration = protection["scan"]["block_seconds"] if data.get("family") != "p2p" else protection["p2p"]["block_seconds"]
    lines = [
        "Ezhik Guard — отчёт о сетевом инциденте",
        "",
        f"Время обнаружения: {_fmt_time(data.get('detected_at') or time.time())}",
        f"Нода: {node.get('name')} ({data.get('node_ip') or node.get('last_ip') or '—'})",
        f"ID клиента Remnawave: {client_id}",
        f"Нарушение: {title}",
        f"Реакция: {action_title}",
        f"Настроенная блокировка: {_fmt_duration(duration)}",
        "",
        f"Окно наблюдения: {data.get('window_seconds')} сек.",
        f"Уникальных назначений: {data.get('unique_endpoints')}",
        f"Уникальных IP: {data.get('unique_ips')}",
        f"Уникальных портов: {data.get('unique_ports')}",
    ]
    for key, value in details.items():
        lines.append(f"{key}: {value}")
    lines += ["", "Примеры назначений (до 100):"]
    for item in data.get("sample_endpoints") or []:
        lines.append(f"  {str(item.get('protocol')).upper():4} {item.get('remote_ip')}:{item.get('remote_port')}")
    return "\n".join(lines) + "\n"


class Notifier:
    def __init__(self, settings):
        self.settings = settings
        self._queue = queue.Queue(maxsize=500)
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._worker, name="telegram", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _cfg(self):
        cfg = self.settings.telegram()
        if not cfg.get("enabled") or not cfg.get("token") or not cfg.get("chat_id"):
            return None
        return cfg

    def _put(self, item):
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            log.warning("Telegram queue full; dropping notification")

    # ------------------------------------------------------------ producers

    def detection(self, node, etype, client_id, title, action, action_title, data, protection):
        cfg = self._cfg()
        if not cfg or not cfg["notify"].get(etype, True):
            return
        if action in ("EXISTS", "FEATURE_OFF", "STALE"):
            return
        text = (
            f"{TYPE_EMOJI.get(etype, '•')} <b>{html.escape(title)}</b>\n"
            f"Нода: <b>{html.escape(node.get('name') or '')}</b>\n"
            f"Клиент: <code>{html.escape(client_id)}</code>\n"
            f"Реакция: {html.escape(action_title)}"
        )
        document = None
        if etype in ("scan", "p2p"):
            document = (
                f"incident-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{client_id}.txt",
                scan_report_text(node, client_id, title, action_title, data, protection),
            )
        self._put({"text": text, "document": document})

    def system(self, etype, title, severity, node_id, data):
        cfg = self._cfg()
        if not cfg:
            return
        key = {"node": "nodes", "cert": "certs", "sanction": "sanctions"}.get(etype)
        if key is None or not cfg["notify"].get(key, True):
            return
        if etype == "sanction" and severity == "info":
            return
        self._put({"text": f"{TYPE_EMOJI.get(etype, '•')} {html.escape(title)}", "document": None})

    def test(self, token=None, chat_id=None):
        cfg = self.settings.telegram()
        token = token or cfg.get("token")
        chat_id = chat_id or cfg.get("chat_id")
        if not token or not chat_id:
            raise ValueError("Укажите токен бота и chat ID")
        self._send(token, chat_id, "✅ Ezhik Guard: тестовое уведомление")

    # ------------------------------------------------------------- delivery

    def _worker(self):
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            cfg = self._cfg()
            if not cfg:
                continue
            for attempt in range(3):
                try:
                    if item.get("document"):
                        self._send_document(cfg["token"], cfg["chat_id"], item["text"], *item["document"])
                    else:
                        self._send(cfg["token"], cfg["chat_id"], item["text"])
                    break
                except Exception as exc:
                    log.warning("Telegram delivery failed (%s): %s", attempt + 1, exc)
                    time.sleep(2 + attempt * 3)

    @staticmethod
    def _api(token, method, data, headers):
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"Telegram HTTP {exc.code}: {body[:200]}") from None

    def _send(self, token, chat_id, text):
        data = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                           "disable_web_page_preview": True}).encode()
        return self._api(token, "sendMessage", data, {"Content-Type": "application/json"})

    def _send_document(self, token, chat_id, caption, filename, content):
        boundary = "----ezhik" + secrets.token_hex(12)
        parts = []

        def field(name, value):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())

        field("chat_id", chat_id)
        field("caption", caption[:1000])
        field("parse_mode", "HTML")
        parts.append(
            (f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\n'
             "Content-Type: text/plain; charset=utf-8\r\n\r\n").encode() + content.encode("utf-8") + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        return self._api(token, "sendDocument", b"".join(parts),
                         {"Content-Type": f"multipart/form-data; boundary={boundary}"})

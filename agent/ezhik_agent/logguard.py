"""Caps the size of the RAM logs (Suricata fast.log and both Xray logs)."""

import logging
import threading

from . import paths
from .util import run

log = logging.getLogger("ezhik.logguard")


class LogGuard:
    def __init__(self, get_settings):
        self.get_settings = get_settings
        self._stop = threading.Event()
        self.truncations = 0

    def start(self):
        threading.Thread(target=self._loop, name="log-guard", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(10):
            try:
                self.check()
            except Exception:
                log.exception("RAM log guard iteration failed")

    def check(self):
        container, max_bytes, active = self.get_settings()
        if not active:
            return
        fast = paths.SURICATA_FAST_LOG
        try:
            if fast.exists() and fast.stat().st_size > max_bytes:
                fast.write_text("")
                self.truncations += 1
        except OSError:
            pass
        script = (
            f'MAX={int(max_bytes)}; for F in {paths.XRAY_ACCESS_LOG} {paths.XRAY_INFO_LOG}; do '
            '[ -f "$F" ] || continue; S=$(stat -c %s "$F" 2>/dev/null || echo 0); '
            'if [ "$S" -gt "$MAX" ]; then : > "$F"; echo T; fi; done'
        )
        result = run(["docker", "exec", container, "sh", "-c", script], timeout=20)
        self.truncations += (result.stdout or "").count("T")

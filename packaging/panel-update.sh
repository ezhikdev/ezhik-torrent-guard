#!/usr/bin/env bash
# Runs as root via ezhik-guard-panel-update.path when the panel requests a
# self-update ("Update" button). Uses the installer of the running release,
# which always downloads the latest GitHub release and rolls back on failure.
set -uo pipefail

DATA_DIR=/var/lib/ezhik-guard/panel
STATUS="$DATA_DIR/update-status.json"
REQUEST="$DATA_DIR/update-request.json"
LOG=/var/log/ezhik-guard-panel-update.log
BASE=/opt/ezhik-guard/panel

[ -f "$REQUEST" ] || exit 0
status() {
  printf '{"state":"%s","at":%s,"message":"%s"}\n' "$1" "$(date +%s)" "${2//\"/\'}" >"$STATUS.tmp"
  chown ezhik-guard:ezhik-guard "$STATUS.tmp" 2>/dev/null || true
  mv "$STATUS.tmp" "$STATUS"
}

status running "Загрузка и установка новой версии"
rm -f "$REQUEST"
# Prefer the current installer from GitHub (fixes in it apply even when the
# installed release has an older copy); fall back to the bundled one.
INSTALLER="$(mktemp /tmp/ezhik-guard-install.XXXXXX)"
if ! curl -fsSL --retry 3 https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/install.sh -o "$INSTALLER"; then
  cp "$BASE/current/install.sh" "$INSTALLER"
fi
if bash "$INSTALLER" --update >"$LOG" 2>&1; then
  status done "Обновлено до $(cat "$BASE/current/VERSION")"
else
  status failed "$(tail -n 3 "$LOG" | tr '\n' ' ' | cut -c1-300)"
fi

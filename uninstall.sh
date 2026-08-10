#!/usr/bin/env bash

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
APP_DIR="/opt/ezhik-torrent-guard"
APP_VERSION="unknown"
if [ -r "$APP_DIR/VERSION" ]; then
    APP_VERSION="$(tr -d '[:space:]' <"$APP_DIR/VERSION")"
elif [ -r "$SCRIPT_DIR/VERSION" ]; then
    APP_VERSION="$(tr -d '[:space:]' <"$SCRIPT_DIR/VERSION")"
fi
SURICATA_VERSION="8.0.6"
if [ -r "$APP_DIR/RUNTIME.env" ]; then
    installed_suricata="$(sed -n 's/^SURICATA_VERSION=//p' "$APP_DIR/RUNTIME.env" | tail -n1)"
    if [[ "$installed_suricata" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SURICATA_VERSION="$installed_suricata"
    fi
fi
SURICATA_PREFIX="/opt/ezhik-suricata-$SURICATA_VERSION"
CONFIG_DIR="/etc/ezhik-torrent-guard"
STATE_DIR="/var/lib/ezhik-torrent-guard"
BUILD_DIR="/opt/ezhik-torrent-guard-build"
PURGE=0
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --force) FORCE=1 ;;
        -h|--help)
            cat <<'HELP'
Usage: bash uninstall.sh [--purge] [--force]

  --purge  Also remove /etc/ezhik-torrent-guard and sanction state.
  --force  Continue even if active local sanctions are recorded.
HELP
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

cat <<'BANNER'
============================================================
                   EZHIK TORRENT GUARD
                       UNINSTALLER
============================================================

 Developer : ezhikdev
 Telegram  : @ezhikdev
 GitHub    : https://github.com/ezhikdev

============================================================
BANNER

[ "${EUID:-$(id -u)}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

ACTIVE_SANCTIONS=""
if [ -f "$STATE_DIR/sanctions.json" ]; then
    ACTIVE_SANCTIONS="$(python3 - "$STATE_DIR/sanctions.json" <<'PY' 2>/dev/null || true
import json, sys
try:
    data=json.load(open(sys.argv[1], encoding='utf-8'))
    sanctions=data.get('sanctions') or {}
    print(','.join(map(str, sanctions.keys())))
except Exception:
    pass
PY
)"
fi

if [ -n "$ACTIVE_SANCTIONS" ] && [ "$FORCE" -ne 1 ]; then
    cat >&2 <<EOF
[FAIL] Active Torrent Guard sanctions are still recorded:
       $ACTIVE_SANCTIONS

Stopping the Guard now can leave those subscriptions disabled because
there will be no worker left to perform the scheduled auto-unfreeze.

Wait for the sanctions to expire, or handle them manually, then retry.
Use --force only if you explicitly accept that responsibility.
EOF
    exit 1
fi

systemctl disable --now \
    ezhik-torrent-guard.service \
    ezhik-ram-log-guard.service \
    ezhik-suricata.service \
    >/dev/null 2>&1 || true

if [ -x /usr/local/sbin/ezhik-torrent-guard-cleanup.sh ]; then
    /usr/local/sbin/ezhik-torrent-guard-cleanup.sh >/dev/null 2>&1 || true
fi

rm -f \
    /etc/systemd/system/ezhik-torrent-guard.service \
    /etc/systemd/system/ezhik-ram-log-guard.service \
    /etc/systemd/system/ezhik-suricata.service \
    /usr/local/sbin/ezhik-ram-log-guard.sh \
    /usr/local/sbin/ezhik-torrent-guard-cleanup.sh

rm -rf /etc/systemd/system/ezhik-torrent-guard.service.d
rm -rf "$APP_DIR" "$SURICATA_PREFIX" "$BUILD_DIR"
rm -f /dev/shm/ezhik-suricata-fast.log

if [ "$PURGE" -eq 1 ]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR"
    echo "[ OK ] Configuration and state purged."
else
    echo "[INFO] Preserved: $CONFIG_DIR"
    echo "[INFO] Preserved: $STATE_DIR"
fi

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed >/dev/null 2>&1 || true

cat <<EOF

[ OK ] Ezhik Torrent Guard v$APP_VERSION removed.

The uninstaller did NOT:
  - change your Remnawave/Xray profile;
  - change iptables/NFQUEUE;
  - automatically re-enable stock suricata.service.
EOF

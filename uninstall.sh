#!/usr/bin/env bash
# Ezhik Guard uninstaller.
#   uninstall.sh            remove everything Ezhik Guard installed on this host
#   uninstall.sh --agent    only the node agent (Suricata runtime, units, state)
#   uninstall.sh --panel    only the panel (a backup of its data is kept)
#   --purge                 do not keep the panel backup
# Docker, RemnaNode, Xray certificates and unrelated firewall rules are untouched.
# Prefer deleting a node in the panel: then active blocks are handled centrally.
set -uo pipefail

WHAT="all"
PURGE=""
for arg in "$@"; do
  case "$arg" in
    --agent) WHAT="agent" ;;
    --panel) WHAT="panel" ;;
    --purge) PURGE="--purge" ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[ "${EUID:-$(id -u)}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

if [ "$WHAT" != "panel" ] && [ -d /opt/ezhik-guard/agent/current ]; then
  echo "[ezhik] removing node agent"
  PYTHONPATH=/opt/ezhik-guard/agent/current python3 -m ezhik_agent uninstall
fi

if [ "$WHAT" != "agent" ] && [ -d /opt/ezhik-guard/panel ]; then
  echo "[ezhik] removing panel"
  INSTALLER=/opt/ezhik-guard/panel/current/install.sh
  if [ -f "$INSTALLER" ]; then
    bash "$INSTALLER" --uninstall $PURGE
  else
    bash <(curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/install.sh) --uninstall $PURGE
  fi
fi
echo "[ezhik] done"

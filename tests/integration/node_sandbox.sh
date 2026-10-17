#!/usr/bin/env bash
# Rootless node sandbox for integration tests (run on a test server).
#   node_sandbox.sh setup NAME TOKEN PANEL_URL     prepare sandbox + legacy fixture, register
#   node_sandbox.sh start NAME                     start the agent in background
#   node_sandbox.sh stop NAME
#   node_sandbox.sh env NAME                       print exports for manual commands
set -euo pipefail

BASE="${EG_TEST:-$HOME/eg-test}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cmd="$1"; name="$2"
N="$BASE/nodes/$name"
SB="$N/root"
C="$N/container"

export_env() {
  export EZHIK_ROOT="$SB"
  export EZHIK_FAKE_CONTAINER="$C"
  export EZHIK_FAKE_STATE="$N/systemd.json"
  export EZHIK_FAKE_LOG="$N/calls.log"
  export PATH="$HERE/fakebin:$PATH"
  export LD_LIBRARY_PATH="$BASE/libs"
  export PYTHONPATH="$SB/opt/ezhik-guard/agent/current"
  export PYTHONDONTWRITEBYTECODE=1
}

legacy_fixture() {
  mkdir -p "$SB/opt/ezhik-torrent-guard" "$SB/etc/ezhik-torrent-guard" "$SB/var/lib/ezhik-torrent-guard" \
           "$SB/etc/systemd/system/ezhik-torrent-guard.service.d" "$SB/usr/local/sbin" "$SB/opt/ezhik-suricata-8.0.6/bin" \
           "$SB/dev/shm"
  echo "1.2.4" >"$SB/opt/ezhik-torrent-guard/VERSION"
  echo "print('old guard')" >"$SB/opt/ezhik-torrent-guard/guard.py"
  printf 'EZHIK_PROTECTED_CLIENTS=7,8\nEZHIK_FREEZE_SECONDS=900\nEZHIK_DRY_RUN=false\n' >"$SB/etc/ezhik-torrent-guard/settings.env"
  printf 'REMNAWAVE_BASE_URL=https://old\nREMNAWAVE_API_TOKEN=old\n' >"$SB/etc/ezhik-torrent-guard/api.env"
  now=$(date +%s)
  cat >"$SB/var/lib/ezhik-torrent-guard/sanctions.json" <<JSON
{"version": 2, "pending_freezes": {}, "sanctions": {"5": {"client_id": "5", "uuid": "legacy-uuid-5", "disabled_at": $((now - 600)), "unfreeze_at": $((now + 60)), "reason": "bittorrent"}}}
JSON
  for u in ezhik-torrent-guard ezhik-suricata ezhik-ram-log-guard; do echo "[Service]" >"$SB/etc/systemd/system/$u.service"; done
  echo "[Service]" >"$SB/etc/systemd/system/ezhik-torrent-guard.service.d/cleanup.conf"
  echo "#!/bin/sh" >"$SB/usr/local/sbin/ezhik-ram-log-guard.sh"
  echo "#!/bin/sh" >"$SB/usr/local/sbin/ezhik-torrent-guard-cleanup.sh"
  echo "old" >"$SB/opt/ezhik-suricata-8.0.6/bin/suricata"
  : >"$SB/dev/shm/ezhik-suricata-fast.log"
  # Something unrelated that must survive the cleanup.
  mkdir -p "$SB/opt/unrelated-app" "$SB/etc/systemd/system"
  echo keep >"$SB/opt/unrelated-app/keep.txt"
  echo "[Service]" >"$SB/etc/systemd/system/unrelated.service"
  echo '{"suricata.service": "inactive"}' >"$N/systemd.json"
}

case "$cmd" in
  setup)
    token="$3"; panel="$4"
    rm -rf "$N"; mkdir -p "$SB" "$C/dev/shm" "$C/etc/xray"
    : >"$C/dev/shm/xray-access.log"; : >"$C/dev/shm/xray-info.log"
    legacy_fixture
    cp /etc/os-release "$SB/etc/os-release" 2>/dev/null || true
    export_env
    pin="$(curl -sk "$panel/install.sh" | sed -n 's/^PIN="\(.*\)"$/\1/p')"
    curl -fsS --pinnedpubkey "$pin" -k "$panel/agent/v1/bootstrap/agent.sha256" -o "$N/agent.sha256"
    curl -fsS --pinnedpubkey "$pin" -k "$panel/agent/v1/bootstrap/agent.tar.gz" -o "$N/agent.tar.gz"
    read -r sha version <"$N/agent.sha256"
    echo "$sha  $N/agent.tar.gz" | sha256sum -c - >/dev/null
    mkdir -p "$SB/opt/ezhik-guard/agent/releases/$version"
    tar -xzf "$N/agent.tar.gz" -C "$SB/opt/ezhik-guard/agent/releases/$version"
    ln -sfn "releases/$version" "$SB/opt/ezhik-guard/agent/current"
    curl -sk "$panel/install.sh" | awk '/^@@CA_PEM@@|<<.__CA__/{f=1;next} /^__CA__/{f=0} f' >"$N/ca.pem"
    python3 -m ezhik_agent register --panel "$panel" --token "$token" --ca-file "$N/ca.pem" --name "$name"
    echo "sandbox $name ready (agent $version)"
    ;;
  start)
    export_env
    [ -f "$N/agent.pid" ] && kill -- "-$(cat "$N/agent.pid")" 2>/dev/null || true
    sleep 1
    # Emulates systemd: Restart=always, StartLimitBurst=5 -> OnFailure=rollback.
    setsid bash -c '
      fails=0
      while true; do
        start=$(date +%s); python3 -m ezhik_agent run; c=$?; echo "[supervisor] agent exited $c"
        [ $c -eq 0 ] && exit 0
        if [ $c -ne 75 ] && [ $(( $(date +%s) - start )) -lt 10 ]; then fails=$((fails+1)); else fails=0; fi
        if [ $fails -ge 5 ]; then
          echo "[supervisor] start limit hit -> OnFailure rollback"
          PYTHONPATH="$EZHIK_ROOT/opt/ezhik-guard/agent/previous" python3 -m ezhik_agent rollback; fails=0
        fi
        sleep 1
      done' >>"$N/agent.log" 2>&1 </dev/null &
    echo $! >"$N/agent.pid"
    echo "agent $name started pid $(cat "$N/agent.pid")"
    ;;
  stop)
    # setsid made the supervisor a process-group leader: stop the whole group.
    [ -f "$N/agent.pid" ] && kill -- "-$(cat "$N/agent.pid")" 2>/dev/null || true
    rm -f "$N/agent.pid"
    ;;
  env)
    echo "export EZHIK_ROOT='$SB' EZHIK_FAKE_CONTAINER='$C' EZHIK_FAKE_STATE='$N/systemd.json' EZHIK_FAKE_LOG='$N/calls.log' PATH='$HERE/fakebin:'\"\$PATH\" LD_LIBRARY_PATH='$BASE/libs' PYTHONPATH='$SB/opt/ezhik-guard/agent/current'"
    ;;
esac

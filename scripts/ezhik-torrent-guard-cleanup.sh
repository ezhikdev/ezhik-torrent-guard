#!/bin/sh

CONTAINER="${EZHIK_REMNANODE_CONTAINER:-remnanode}"

docker exec "$CONTAINER" sh -lc '
for P in /proc/[0-9]*; do
    [ -r "$P/comm" ] || continue
    [ "$(cat "$P/comm" 2>/dev/null)" = "tail" ] || continue

    CMD=$(tr "\000" " " < "$P/cmdline" 2>/dev/null)

    case "$CMD" in
        *"/dev/shm/xray-access.log"*|*"/dev/shm/xray-info.log"*)
            PID=${P##*/}
            kill "$PID" 2>/dev/null || true
            ;;
    esac
done
' >/dev/null 2>&1 || true

exit 0

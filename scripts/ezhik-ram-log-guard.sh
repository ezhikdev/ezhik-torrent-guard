#!/bin/sh

MAX="${EZHIK_RAM_LOG_MAX_BYTES:-8388608}"
CONTAINER="${EZHIK_REMNANODE_CONTAINER:-remnanode}"

while true; do
    F=/dev/shm/ezhik-suricata-fast.log
    SIZE=$(stat -c %s "$F" 2>/dev/null || echo 0)

    if [ "$SIZE" -gt "$MAX" ]; then
        : > "$F"
        echo "[RAMLOG] truncated $F size=$SIZE"
    fi

    docker exec "$CONTAINER" sh -c '
        MAX="'"$MAX"'"
        for F in /dev/shm/xray-access.log /dev/shm/xray-info.log; do
            [ -f "$F" ] || continue
            SIZE=$(stat -c %s "$F" 2>/dev/null || echo 0)
            if [ "$SIZE" -gt "$MAX" ]; then
                : > "$F"
                echo "[RAMLOG] truncated $F size=$SIZE"
            fi
        done
    ' 2>/dev/null || true

    sleep 10
done

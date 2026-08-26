#!/usr/bin/env bash

set -o pipefail

APP_VERSION=""
REPO_SLUG="ezhikdev/ezhik-torrent-guard"
REPO_RAW="https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main"
RELEASE_BASE="https://github.com/$REPO_SLUG/releases"
APP_DIR="/opt/ezhik-torrent-guard"
SURICATA_PREFIX="/opt/ezhik-suricata-8.0.6"
CONFIG_DIR="/etc/ezhik-torrent-guard"
STATE_DIR="/var/lib/ezhik-torrent-guard"
BUILD_DIR="/opt/ezhik-torrent-guard-build"
INSTALL_LOG="/var/log/ezhik-torrent-guard-install.log"
STAGE_DIR="$(mktemp -d /tmp/ezhik-torrent-guard-installer.XXXXXX 2>/dev/null || true)"

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
else
    SCRIPT_DIR=""
fi

banner() {
    cat <<'BANNER'
============================================================
                   EZHIK TORRENT GUARD
============================================================

 Torrent protection for Xray + Remnawave

 Developer : ezhikdev
 Telegram  : @ezhikdev
 GitHub    : https://github.com/ezhikdev

============================================================
BANNER
}

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }

RUNTIME_SWAPPED=0
RUNTIME_BACKUP=""
SERVICES_STOPPED=0
APP_METADATA_CHANGED=0
APP_METADATA_BACKUP="$STAGE_DIR/app-metadata-backup"

backup_app_metadata() {
    local name

    mkdir -p "$APP_METADATA_BACKUP" || die "Cannot prepare application metadata backup"
    for name in VERSION RUNTIME.env install-manifest.json; do
        if [ -f "$APP_DIR/$name" ]; then
            cp -p "$APP_DIR/$name" "$APP_METADATA_BACKUP/$name" || \
                die "Cannot preserve $name before update"
        else
            : >"$APP_METADATA_BACKUP/$name.missing"
        fi
    done
    APP_METADATA_CHANGED=1
}

restore_app_metadata() {
    local name

    [ "$APP_METADATA_CHANGED" -eq 1 ] || return 0
    for name in VERSION RUNTIME.env install-manifest.json; do
        if [ -f "$APP_METADATA_BACKUP/$name" ]; then
            cp -p "$APP_METADATA_BACKUP/$name" "$APP_DIR/$name" || true
        elif [ -f "$APP_METADATA_BACKUP/$name.missing" ]; then
            rm -f "$APP_DIR/$name"
        fi
    done
    APP_METADATA_CHANGED=0
}

rollback_runtime() {
    if [ "$RUNTIME_SWAPPED" -eq 1 ] && [ -n "$RUNTIME_BACKUP" ]; then
        warn "Restoring the previous Suricata runtime..."
        systemctl stop ezhik-suricata.service ezhik-torrent-guard.service \
            >/dev/null 2>&1 || true
        rm -rf "$SURICATA_PREFIX"
        if [ -d "$RUNTIME_BACKUP" ]; then
            mv "$RUNTIME_BACKUP" "$SURICATA_PREFIX" || true
        fi
        RUNTIME_SWAPPED=0
    fi

    restore_app_metadata

    if [ "$SERVICES_STOPPED" -eq 1 ]; then
        systemctl start ezhik-suricata.service ezhik-ram-log-guard.service \
            ezhik-torrent-guard.service >/dev/null 2>&1 || true
        SERVICES_STOPPED=0
    fi
}

die() {
    rollback_runtime
    printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2
    exit 1
}

SPINNER_CHARS="|/-\\"
UI_DYNAMIC=0
if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
    UI_DYNAMIC=1
fi

format_elapsed() {
    local seconds="$1"
    printf '%02d:%02d' $((seconds / 60)) $((seconds % 60))
}

ui_line() {
    # Best-effort terminal output. Build commands continue even if the SSH TTY disappears.
    printf '%b' "$*" 2>/dev/null || true
}

progress_bar() {
    local pct="$1"
    local width=20 filled empty bar_fill bar_empty

    filled=$((pct * width / 100))
    empty=$((width - filled))
    printf -v bar_fill '%*s' "$filled" ''
    printf -v bar_empty '%*s' "$empty" ''
    printf '%s%s' "${bar_fill// /#}" "${bar_empty// /-}"
}

progress_status() {
    local pct="$1"
    shift
    [ "$UI_DYNAMIC" -eq 1 ] || return 0
    ui_line "\\r\\033[2K\\033[1;36m[$(progress_bar "$pct")]\\033[0m $(printf '%3d' "$pct")%  $*"
}

progress_done() {
    local pct="$1"
    shift
    if [ "$UI_DYNAMIC" -eq 1 ]; then
        ui_line "\\r\\033[2K\\033[1;36m[$(progress_bar "$pct")]\\033[0m $(printf '%3d' "$pct")%  $* \\033[1;32mOK\\033[0m\\n"
    else
        printf '[%3d%%] %s OK\n' "$pct" "$*"
    fi
}

run_timed_logged() {
    local pct="$1"
    local label="$2"
    shift 2
    local started now elapsed frame=0 pid rc

    started="$(date +%s)"
    "$@" >>"$INSTALL_LOG" 2>&1 &
    pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        now="$(date +%s)"
        elapsed=$((now - started))
        local spin="${SPINNER_CHARS:$((frame % 4)):1}"
        progress_status "$pct" "$label  $spin  elapsed $(format_elapsed "$elapsed")"
        frame=$((frame + 1))
        sleep 1
    done

    wait "$pid"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        ui_line "\\n"
        tail -n 50 "$INSTALL_LOG" >&2 2>/dev/null || true
        die "$label failed (exit $rc). Log: $INSTALL_LOG"
    fi

    now="$(date +%s)"
    elapsed=$((now - started))
    progress_done "$pct" "$label  ($(format_elapsed "$elapsed"))"
}

download_with_progress() {
    local pct="$1"
    local label="$2"
    local url="$3"
    local dest="$4"

    local total=0 current=0 percent=0
    local width=24 filled empty
    local bar_fill bar_empty
    local started now elapsed
    local pid rc current_mb total_mb

    rm -f "$dest"

    # Try to discover the archive size before downloading it.
    total="$(
        curl -fsSIL --retry 2 --connect-timeout 15 "$url" 2>>"$INSTALL_LOG" |
        awk '
            BEGIN { IGNORECASE=1 }
            /^content-length:/ {
                gsub("\r", "", $2)
                if ($2 ~ /^[0-9]+$/)
                    size=$2
            }
            END { print size+0 }
        '
    )"

    started="$(date +%s)"

    # Run curl quietly in the background while the UI tracks the file size.
    curl -fL \
        --retry 3 \
        --connect-timeout 15 \
        --silent \
        --show-error \
        "$url" \
        -o "$dest" >>"$INSTALL_LOG" 2>&1 &

    pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        current="$(stat -c '%s' "$dest" 2>/dev/null || printf '0')"

        now="$(date +%s)"
        elapsed=$((now - started))

        if [ "$total" -gt 0 ]; then
            percent=$((current * 100 / total))
            [ "$percent" -gt 99 ] && percent=99

            filled=$((percent * width / 100))
            empty=$((width - filled))

            printf -v bar_fill '%*s' "$filled" ''
            printf -v bar_empty '%*s' "$empty" ''

            bar_fill="${bar_fill// /#}"
            bar_empty="${bar_empty// /-}"

            current_mb="$(awk "BEGIN {printf \"%.1f\", $current/1048576}")"
            total_mb="$(awk "BEGIN {printf \"%.1f\", $total/1048576}")"

            progress_status "$pct" \
                "$label  [${bar_fill}${bar_empty}] $(printf '%3d' "$percent")%  ${current_mb}/${total_mb} MiB  $(format_elapsed "$elapsed")"
        else
            current_mb="$(awk "BEGIN {printf \"%.1f\", $current/1048576}")"

            progress_status "$pct" \
                "$label  downloaded ${current_mb} MiB  $(format_elapsed "$elapsed")"
        fi

        sleep 0.5
    done

    wait "$pid"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        ui_line "\\n"
        tail -n 30 "$INSTALL_LOG" >&2 2>/dev/null || true
        die "$label failed (exit $rc). Log: $INSTALL_LOG"
    fi

    progress_status "$pct" \
        "$label  [########################] 100%"
    sleep 0.2

    progress_done "$pct" "$label"
}

latest_build_activity() {
    tail -n 120 "$INSTALL_LOG" 2>/dev/null | \
        grep -E '(^|[[:space:]])(CC|CXX|CCLD|AR|LD)[[:space:]]|Compiling |Building |Linking |Finished ' | \
        tail -n 1 | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g' | cut -c1-68
}

run_build_progress() {
    local overall_start="$1"
    local overall_end="$2"
    local label="$3"
    shift 3

    local started now elapsed frame=0 pid rc activity spin

    started="$(date +%s)"
    "$@" >>"$INSTALL_LOG" 2>&1 &
    pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        now="$(date +%s)"
        elapsed=$((now - started))
        spin="${SPINNER_CHARS:$((frame % 4)):1}"
        activity="$(latest_build_activity)"
        [ -n "$activity" ] || activity="compiler active"

        progress_status "$overall_start" "$label  $spin  elapsed $(format_elapsed "$elapsed")  $activity"
        frame=$((frame + 1))
        sleep 2
    done

    wait "$pid"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        ui_line "\\n"
        tail -n 60 "$INSTALL_LOG" >&2 2>/dev/null || true
        die "$label failed (exit $rc). Log: $INSTALL_LOG"
    fi

    now="$(date +%s)"
    elapsed=$((now - started))
    progress_done "$overall_end" "$label  build 100%  ($(format_elapsed "$elapsed"))"
}

run_logged() {
    "$@" >>"$INSTALL_LOG" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        tail -n 40 "$INSTALL_LOG" >&2 2>/dev/null || true
        die "Command failed (exit $rc): $*"
    fi
}

prompt() {
    local text="$1"
    local default="${2:-}"
    local value

    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$text" "$default" >/dev/tty
    else
        printf '%s: ' "$text" >/dev/tty
    fi

    IFS= read -r value </dev/tty || die "Cannot read from /dev/tty"
    [ -n "$value" ] || value="$default"
    printf '%s' "$value"
}

prompt_secret_existing() {
    local text="$1"
    local existing="$2"
    local value

    if [ -n "$existing" ]; then
        printf '%s [press Enter to keep current token]: ' "$text" >/dev/tty
    else
        printf '%s: ' "$text" >/dev/tty
    fi
    IFS= read -r -s value </dev/tty || die "Cannot read secret from /dev/tty"
    printf '\n' >/dev/tty
    [ -n "$value" ] || value="$existing"
    printf '%s' "$value"
}

confirm() {
    local text="$1"
    local default="${2:-N}"
    local suffix="[y/N]"
    local value

    [ "$default" = "Y" ] && suffix="[Y/n]"
    printf '%s %s: ' "$text" "$suffix" >/dev/tty
    IFS= read -r value </dev/tty || return 1
    value="${value:-$default}"
    value="$(printf '%s' "$value" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"

    case "$value" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

repo_file() {
    local rel="$1"
    local dest="$2"

    mkdir -p "$(dirname "$dest")" || die "Cannot create staging directory"

    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$rel" ]; then
        cp "$SCRIPT_DIR/$rel" "$dest" || die "Cannot copy local $rel"
    else
        curl -fsSL "$REPO_RAW/$rel" -o "$dest" || die "Cannot download $rel from GitHub"
    fi
}

load_app_version() {
    local value=""

    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/VERSION" ]; then
        value="$(tr -d '[:space:]' <"$SCRIPT_DIR/VERSION")"
    else
        value="$(curl -fsSL "$REPO_RAW/VERSION" 2>>"$INSTALL_LOG" || true)"
        value="$(printf '%s' "$value" | tr -d '[:space:]')"
    fi

    [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
        die "Repository VERSION is missing or invalid: ${value:-empty}"
    APP_VERSION="$value"
}

config_value() {
    local file="$1"
    local key="$2"

    [ -r "$file" ] || return 0
    sed -n "s/^${key}=//p" "$file" | tail -n1
}

config_positive_or_default() {
    local file="$1"
    local key="$2"
    local default="$3"
    local value

    value="$(config_value "$file" "$key")"
    if [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s' "$value"
    else
        printf '%s' "$default"
    fi
}

installed_engine_id() {
    local manifest="$SURICATA_PREFIX/ezhik-runtime-manifest.json"
    [ -r "$manifest" ] || return 0

    python3 - "$manifest" <<'PY_ENGINE' 2>/dev/null || true
import json
import sys

try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get("engine_id", ""))
except Exception:
    pass
PY_ENGINE
}

archive_paths_safe() {
    local archive="$1"

    ! tar --zstd -tf "$archive" 2>/dev/null | awk '
        /^\// { bad=1 }
        /(^|\/)\.\.($|\/)/ { bad=1 }
        END { exit bad ? 0 : 1 }
    '
}

APT_UPDATED=0
ensure_packages() {
    local pct="$1"
    local label="$2"
    shift 2
    local package status
    local -a missing=()

    for package in "$@"; do
        status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
        [ "$status" = "install ok installed" ] || missing+=("$package")
    done

    if [ "${#missing[@]}" -eq 0 ]; then
        progress_done "$pct" "$label (already installed)"
        return 0
    fi

    if [ "$APT_UPDATED" -eq 0 ]; then
        run_timed_logged 22 "Updating apt package index" apt-get update
        APT_UPDATED=1
    fi

    run_timed_logged "$pct" "$label" \
        env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

select_build_jobs() {
    local mode="${EZHIK_BUILD_MODE:-balanced}"
    local cpus
    cpus="$(nproc 2>/dev/null || printf '2')"
    [ "$cpus" -ge 1 ] || cpus=1

    case "$mode" in
        eco)
            BUILD_JOBS=1
            ;;
        balanced)
            BUILD_JOBS=$(((cpus + 1) / 2))
            [ "$BUILD_JOBS" -gt 4 ] && BUILD_JOBS=4
            ;;
        fast)
            BUILD_JOBS="$cpus"
            ;;
        *)
            die "Invalid EZHIK_BUILD_MODE=$mode (expected eco, balanced, or fast)"
            ;;
    esac

    [ "$BUILD_JOBS" -ge 1 ] || BUILD_JOBS=1
    BUILD_MODE="$mode"
}

normalize_panel_url() {
    local value="$1"

    value="${value%/}"
    case "$value" in
        http://*|https://*) ;;
        *) value="https://$value" ;;
    esac
    printf '%s' "$value"
}

canonical_clients() {
    local raw="$1"
    local compact item out=""
    local -a parts

    compact="$(printf '%s' "$raw" | tr -d '[:space:]')"
    [ -n "$compact" ] || { printf ''; return 0; }

    IFS=',' read -r -a parts <<<"$compact"
    for item in "${parts[@]}"; do
        [[ "$item" =~ ^[0-9]+$ ]] || return 1
        if [ -z "$out" ]; then
            out="$item"
        else
            out="$out,$item"
        fi
    done

    printf '%s' "$out"
}

rust_version_ok() {
    command -v rustc >/dev/null 2>&1 || return 1

    python3 - <<'PY' >/dev/null 2>&1
import re
import subprocess
import sys

try:
    s = subprocess.check_output(["rustc", "--version"], text=True)
except Exception:
    sys.exit(1)

m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
if not m:
    sys.exit(1)

ver = tuple(map(int, m.groups()))
sys.exit(0 if ver >= (1, 75, 0) else 1)
PY
}

check_xray_logs() {
    docker exec "$REMNANODE_CONTAINER" sh -lc \
        'test -e /dev/shm/xray-access.log && test -e /dev/shm/xray-info.log' \
        >/dev/null 2>&1
}

ensure_suricata_yaml_header() {
    local config="$1"

    python3 - "$config" <<'PY_YAML_HEADER'
from pathlib import Path
import sys

p = Path(sys.argv[1])
lines = p.read_text().splitlines()

# Suricata 8 requires these to be the first two lines. The renderer uses
# PyYAML, which does not preserve the original YAML directive/document marker.
while lines and lines[0].strip() in ("%YAML 1.1", "---"):
    lines.pop(0)

p.write_text("%YAML 1.1\n---\n" + "\n".join(lines) + "\n")
PY_YAML_HEADER
}

banner

[ "${EUID:-$(id -u)}" -eq 0 ] || die "Run installer as root."
[ -r /dev/tty ] || die "Interactive TTY is required for panel URL/API key prompts."
[ -n "$STAGE_DIR" ] || die "Cannot create temporary staging directory."

mkdir -p "$(dirname "$INSTALL_LOG")" || die "Cannot create log directory"
: >"$INSTALL_LOG" || die "Cannot write $INSTALL_LOG"
chmod 600 "$INSTALL_LOG" || true
trap 'rm -rf "$STAGE_DIR"' EXIT

for cmd in apt-get docker dpkg-query ip python3 systemctl tar; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

if ! command -v curl >/dev/null 2>&1; then
    info "Installing curl..."
    run_logged apt-get update
    run_logged env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
fi

load_app_version
ok "Target Torrent Guard version: v$APP_VERSION"

INSTALLED_VERSION=""
if [ -r "$APP_DIR/VERSION" ]; then
    INSTALLED_VERSION="$(tr -d '[:space:]' <"$APP_DIR/VERSION")"
fi

if [[ "$INSTALLED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if dpkg --compare-versions "$INSTALLED_VERSION" eq "$APP_VERSION"; then
        ok "Torrent Guard v$APP_VERSION is already installed"
        if systemctl is-active --quiet ezhik-suricata.service 2>/dev/null && \
           systemctl is-active --quiet ezhik-torrent-guard.service 2>/dev/null && \
           systemctl is-active --quiet ezhik-ram-log-guard.service 2>/dev/null; then
            confirm "Run repair/reconfiguration anyway?" N || exit 0
        else
            warn "One or more Torrent Guard services are unhealthy; continuing in repair mode."
        fi
    elif dpkg --compare-versions "$INSTALLED_VERSION" lt "$APP_VERSION"; then
        info "Torrent Guard update available: v$INSTALLED_VERSION -> v$APP_VERSION"
        confirm "Install this update?" Y || exit 0
    else
        die "Installed version v$INSTALLED_VERSION is newer than v$APP_VERSION; downgrade refused."
    fi
elif [ -d "$APP_DIR" ]; then
    warn "Legacy Torrent Guard installation detected; it will be upgraded to v$APP_VERSION."
fi

[ -r /etc/os-release ] || die "Cannot detect OS."
# shellcheck disable=SC1091
. /etc/os-release
OS_VERSION_ID="${VERSION_ID:-unknown}"

[ "${ID:-}" = "ubuntu" ] || die "v$APP_VERSION supports Ubuntu only."
case "$OS_VERSION_ID" in
    22.04|24.04) ;;
    *)
        warn "Ubuntu $OS_VERSION_ID has not been production-tested with this installer."
        confirm "Continue anyway?" N || exit 1
        ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ;;
    *) die "v$APP_VERSION is tested for x86_64/amd64 only (detected: $ARCH)." ;;
esac

if docker inspect remnanode >/dev/null 2>&1; then
    REMNANODE_CONTAINER="remnanode"
else
    mapfile -t NODE_CANDIDATES < <(docker ps --format '{{.Names}}' | grep -Ei 'remna.*node|node.*remna' || true)
    if [ "${#NODE_CANDIDATES[@]}" -eq 1 ]; then
        REMNANODE_CONTAINER="${NODE_CANDIDATES[0]}"
    else
        die "Could not uniquely detect the RemnaNode container. Expected container name: remnanode"
    fi
fi
ok "RemnaNode container: $REMNANODE_CONTAINER"

ROUTE="$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1)"
WAN_IF="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$ROUTE")"
WAN_IP="$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$ROUTE")"

[ -n "$WAN_IF" ] || die "Could not detect WAN interface."
[ -n "$WAN_IP" ] || die "Could not detect WAN IPv4."
ok "WAN: $WAN_IF / $WAN_IP"

EXISTING_PANEL_URL="$(config_value "$CONFIG_DIR/api.env" REMNAWAVE_BASE_URL)"
EXISTING_API_TOKEN="$(config_value "$CONFIG_DIR/api.env" REMNAWAVE_API_TOKEN)"
EXISTING_PROTECTED="$(config_value "$CONFIG_DIR/settings.env" EZHIK_PROTECTED_CLIENTS)"
EXISTING_FREEZE_SECONDS="$(config_value "$CONFIG_DIR/settings.env" EZHIK_FREEZE_SECONDS)"
EXISTING_DRY_RUN="$(config_value "$CONFIG_DIR/settings.env" EZHIK_DRY_RUN)"
EXISTING_SCAN_ENABLED="$(config_value "$CONFIG_DIR/settings.env" EZHIK_SCAN_ENABLED)"
EXISTING_SCAN_DRY_RUN="$(config_value "$CONFIG_DIR/settings.env" EZHIK_SCAN_DRY_RUN)"
EXISTING_SCAN_BLOCK_SECONDS="$(config_value "$CONFIG_DIR/settings.env" EZHIK_SCAN_BLOCK_SECONDS)"
EXISTING_TELEGRAM_TOKEN="$(config_value "$CONFIG_DIR/telegram.env" TELEGRAM_BOT_TOKEN)"
EXISTING_TELEGRAM_CHAT_ID="$(config_value "$CONFIG_DIR/telegram.env" TELEGRAM_CHAT_ID)"
SCAN_WINDOW_SECONDS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_WINDOW_SECONDS 60)"
SCAN_BURST_WINDOW_SECONDS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_BURST_WINDOW_SECONDS 15)"
SCAN_VERTICAL_PORTS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_VERTICAL_PORTS 20)"
SCAN_BURST_ENDPOINTS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_BURST_ENDPOINTS 100)"
SCAN_BURST_PORTS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_BURST_PORTS 50)"
SCAN_SUBNET_HOSTS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_SUBNET_HOSTS 16)"
SCAN_SUBNET_PORTS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_SUBNET_PORTS 50)"
SCAN_COOLDOWN_SECONDS="$(config_positive_or_default "$CONFIG_DIR/settings.env" EZHIK_SCAN_COOLDOWN_SECONDS 300)"

FREEZE_DEFAULT=15
if [[ "$EXISTING_FREEZE_SECONDS" =~ ^[0-9]+$ ]] && \
   [ "$EXISTING_FREEZE_SECONDS" -ge 60 ]; then
    FREEZE_DEFAULT=$((EXISTING_FREEZE_SECONDS / 60))
fi

printf '\n' >/dev/tty
PANEL_URL="$(prompt 'Remnawave panel domain or URL' "$EXISTING_PANEL_URL")"
PANEL_URL="$(normalize_panel_url "$PANEL_URL")"
API_TOKEN="$(prompt_secret_existing \
    'Remnawave Panel API token (paste token only)' \
    "$EXISTING_API_TOKEN")"
[ -n "$API_TOKEN" ] || die "API key cannot be empty."

PROTECTED_RAW="$(prompt \
    'Protected Remnawave client IDs, comma-separated (optional)' \
    "$EXISTING_PROTECTED")"
PROTECTED_CLIENTS="$(canonical_clients "$PROTECTED_RAW")" || die "Protected IDs must be numeric and comma-separated."

FREEZE_MINUTES="$(prompt 'Freeze duration in minutes' "$FREEZE_DEFAULT")"
[[ "$FREEZE_MINUTES" =~ ^[0-9]+$ ]] || die "Freeze duration must be a number."
if [ "$FREEZE_MINUTES" -lt 1 ] || [ "$FREEZE_MINUTES" -gt 1440 ]; then
    die "Freeze duration must be between 1 and 1440 minutes."
fi
FREEZE_SECONDS=$((FREEZE_MINUTES * 60))

LIVE_DEFAULT=Y
[ "$EXISTING_DRY_RUN" = "true" ] && LIVE_DEFAULT=N

if confirm "Enable LIVE Remnawave enforcement after install?" "$LIVE_DEFAULT"; then
    DRY_RUN="false"
    MODE="LIVE"
else
    DRY_RUN="true"
    MODE="DRY RUN"
fi
ok "Enforcement mode selected: $MODE"

SCAN_ENABLED_DEFAULT=Y
[ "$EXISTING_SCAN_ENABLED" = "false" ] && SCAN_ENABLED_DEFAULT=N

if confirm "Enable port-scan detection?" "$SCAN_ENABLED_DEFAULT"; then
    SCAN_ENABLED="true"

    SCAN_BLOCK_DEFAULT=60
    if [[ "$EXISTING_SCAN_BLOCK_SECONDS" =~ ^[0-9]+$ ]]; then
        SCAN_BLOCK_DEFAULT=$((EXISTING_SCAN_BLOCK_SECONDS / 60))
    fi

    SCAN_BLOCK_MINUTES="$(prompt \
        'Port-scan block duration in minutes (0 = permanent)' \
        "$SCAN_BLOCK_DEFAULT")"
    [[ "$SCAN_BLOCK_MINUTES" =~ ^[0-9]+$ ]] || \
        die "Port-scan block duration must be zero or a positive number."
    if [ "$SCAN_BLOCK_MINUTES" -gt 10080 ]; then
        die "Port-scan block duration must be between 0 and 10080 minutes."
    fi
    SCAN_BLOCK_SECONDS=$((SCAN_BLOCK_MINUTES * 60))

    SCAN_LIVE_DEFAULT=N
    [ "$EXISTING_SCAN_DRY_RUN" = "false" ] && SCAN_LIVE_DEFAULT=Y
    if confirm "Enable LIVE port-scan enforcement after install?" "$SCAN_LIVE_DEFAULT"; then
        SCAN_DRY_RUN="false"
        SCAN_MODE="LIVE"
    else
        SCAN_DRY_RUN="true"
        SCAN_MODE="OBSERVE"
    fi

    TELEGRAM_TOKEN="$(prompt_secret_existing \
        'Telegram bot token (optional; Enter keeps/disables)' \
        "$EXISTING_TELEGRAM_TOKEN")"
    TELEGRAM_CHAT_ID="$(prompt \
        'Telegram admin chat ID (optional)' \
        "$EXISTING_TELEGRAM_CHAT_ID")"

    if { [ -n "$TELEGRAM_TOKEN" ] && [ -z "$TELEGRAM_CHAT_ID" ]; } || \
       { [ -z "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; }; then
        die "Telegram bot token and chat ID must be configured together."
    fi
    if [ -n "$TELEGRAM_TOKEN" ]; then
        [[ "$TELEGRAM_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || \
            die "Telegram bot token format is invalid."
        [[ "$TELEGRAM_CHAT_ID" =~ ^-?[0-9]+$ ]] || \
            die "Telegram chat ID must be numeric."
    fi
else
    SCAN_ENABLED="false"
    SCAN_DRY_RUN="true"
    SCAN_MODE="DISABLED"
    SCAN_BLOCK_MINUTES=60
    SCAN_BLOCK_SECONDS=3600
    TELEGRAM_TOKEN="$EXISTING_TELEGRAM_TOKEN"
    TELEGRAM_CHAT_ID="$EXISTING_TELEGRAM_CHAT_ID"
fi
ok "Port-scan protection selected: $SCAN_MODE"

AUTH_HEADERS="$STAGE_DIR/remnawave-headers.txt"
printf 'Authorization: Bearer %s\nAccept: application/json\n' "$API_TOKEN" >"$AUTH_HEADERS" || \
    die "Cannot create temporary API auth file"
chmod 600 "$AUTH_HEADERS"

info "Checking Remnawave API authentication..."
HTTP_CODE="$(curl -sS --connect-timeout 8 --max-time 15 -o /dev/null -w '%{http_code}' \
    -H "@$AUTH_HEADERS" \
    "$PANEL_URL/api/users/tags" 2>>"$INSTALL_LOG" || true)"

if [ "$HTTP_CODE" != "200" ]; then
    HTTP_CODE="$(curl -sS --connect-timeout 8 --max-time 15 -o /dev/null -w '%{http_code}' \
        -H "@$AUTH_HEADERS" \
        "$PANEL_URL/api/users" 2>>"$INSTALL_LOG" || true)"
fi

if [ "$HTTP_CODE" != "200" ]; then
    [ "$HTTP_CODE" != "401" ] || warn 'HTTP 401: paste the Panel API token only - without "Bearer " and without REMNAWAVE_API_TOKEN='
    die "Remnawave API authentication failed (HTTP ${HTTP_CODE:-0})."
fi
ok "Remnawave API authentication successful"

if check_xray_logs; then
    ok "Xray RAM logs detected inside $REMNANODE_CONTAINER"
else
    warn "Xray RAM logs are not currently visible inside $REMNANODE_CONTAINER."
    cat >/dev/tty <<'XRAY_LOG_NOTICE'
Torrent Guard requires the Remnawave/Xray profile to use:

  "log": {
    "access": "/dev/shm/xray-access.log",
    "error": "/dev/shm/xray-info.log",
    "loglevel": "info"
  }

Without these two RAM logs exact user attribution will not work.
XRAY_LOG_NOTICE
    confirm "Continue installation anyway?" N || exit 1
fi

# From here onward installation is non-interactive. Ignore SIGHUP so a dropped SSH session
# does not intentionally terminate the compiler/installer. Output may disappear, but the log remains.
trap '' HUP

if systemctl cat suricata.service >/dev/null 2>&1; then
    if systemctl is-active --quiet suricata.service 2>/dev/null || \
       systemctl is-enabled --quiet suricata.service 2>/dev/null; then
        warn "stock suricata.service is active and/or enabled. It can conflict with Ezhik's passive sensor."
        confirm "Disable stock suricata.service?" Y || \
            die "Disable the stock Suricata service first, then run the installer again."
        systemctl disable --now suricata.service >>"$INSTALL_LOG" 2>&1 || \
            die "Could not disable stock suricata.service"
        ok "stock suricata.service disabled"
    fi
fi

info "Preparing Torrent Guard repository files..."
for rel in \
    VERSION \
    RUNTIME.env \
    src/guard.py \
    src/remnawave_actions.py \
    src/scan_detector.py \
    src/telegram_notifier.py \
    suricata/ezhik-torrent-only.rules \
    scripts/ezhik-ram-log-guard.sh \
    scripts/ezhik-torrent-guard-cleanup.sh \
    scripts/patch_ndpi_strict.py \
    scripts/patch_suricata_ndpi.py \
    scripts/build-runtime.sh \
    scripts/verify-runtime.py \
    scripts/render_suricata_config.py \
    systemd/ezhik-torrent-guard.service \
    systemd/ezhik-ram-log-guard.service \
    systemd/ezhik-suricata.service.template \
    systemd/ezhik-torrent-guard-cleanup.conf
do
    repo_file "$rel" "$STAGE_DIR/$rel"
done

STAGED_VERSION="$(tr -d '[:space:]' <"$STAGE_DIR/VERSION")"
[ "$STAGED_VERSION" = "$APP_VERSION" ] || \
    die "Repository changed during installation: expected v$APP_VERSION, got v$STAGED_VERSION"

# shellcheck disable=SC1091
. "$STAGE_DIR/RUNTIME.env"
ENGINE_ID="suricata-${SURICATA_VERSION}-ndpi-${NDPI_VERSION}-r${RUNTIME_REVISION}"
SURICATA_PREFIX="/opt/ezhik-suricata-${SURICATA_VERSION}"
SURICATA_BIN="$SURICATA_PREFIX/bin/suricata"
SURICATA_CONFIG="$SURICATA_PREFIX/etc/suricata/suricata.yaml"
PLUGIN_PATH="$SURICATA_PREFIX/lib/ezhik/ndpi.so"
ok "Repository files ready"

BOOTSTRAP_PACKAGES=(ca-certificates curl python3 python3-yaml zstd)
BUILD_PACKAGES=(
    git autoconf automake build-essential cargo cbindgen gettext flex bison
    libjansson-dev libjson-c-dev libpcap-dev libpcre2-dev libtool libyaml-dev
    pkg-config rustc zlib1g-dev libnetfilter-queue-dev libnfnetlink-dev
    libcap-ng-dev libmagic-dev libnet1-dev libnuma-dev libmaxminddb-dev
    librrd-dev libgcrypt20-dev libgpg-error-dev libcurl4-openssl-dev
)

CURRENT_ENGINE="$(installed_engine_id)"
RUNTIME_SOURCE="installed"
RUNTIME_ROOT=""

if [ "$CURRENT_ENGINE" = "$ENGINE_ID" ] && \
   [ -x "$SURICATA_BIN" ] && \
   [ -f "$SURICATA_CONFIG" ] && \
   [ -f "$PLUGIN_PATH" ]; then
    progress_done 85 "Reusing installed runtime $ENGINE_ID"
else
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR/dist" "$BUILD_DIR/runtime-root" || \
        die "Cannot prepare $BUILD_DIR"

    ensure_packages 30 "Installing runtime tools" "${BOOTSTRAP_PACKAGES[@]}"

    ASSET_NAME="ezhik-runtime-${APP_VERSION}-ubuntu-${OS_VERSION_ID}-amd64.tar.zst"
    ASSET_URL="$RELEASE_BASE/download/v${APP_VERSION}/$ASSET_NAME"
    ASSET_PATH="$BUILD_DIR/$ASSET_NAME"
    CHECKSUM_PATH="$ASSET_PATH.sha256"
    USE_PREBUILT=0

    if [ "${EZHIK_FORCE_SOURCE:-0}" != "1" ] && \
       { [ "$OS_VERSION_ID" = "22.04" ] || [ "$OS_VERSION_ID" = "24.04" ]; } && \
       curl -fsIL --retry 2 --connect-timeout 10 "$ASSET_URL" \
           >>"$INSTALL_LOG" 2>&1; then
        USE_PREBUILT=1
    fi

    if [ "$USE_PREBUILT" -eq 1 ]; then
        RUNTIME_SOURCE="release-binary"
        download_with_progress 55 "Downloading prebuilt runtime" \
            "$ASSET_URL" "$ASSET_PATH"
        curl -fsSL --retry 3 "$ASSET_URL.sha256" -o "$CHECKSUM_PATH" || \
            die "Cannot download runtime checksum"
    else
        RUNTIME_SOURCE="source-build"
        warn "No prebuilt runtime for Ubuntu $OS_VERSION_ID; falling back to source build."
        ensure_packages 34 "Installing build dependencies" "${BUILD_PACKAGES[@]}"

        if ! rust_version_ok; then
            warn "Rust >= 1.75 is unavailable; installing a minimal rustup toolchain."
            curl -fsSL https://sh.rustup.rs -o "$STAGE_DIR/rustup.sh" || \
                die "Cannot download rustup"
            run_logged sh "$STAGE_DIR/rustup.sh" -y --profile minimal
            export PATH="/root/.cargo/bin:$PATH"
            rust_version_ok || die "Rust >= 1.75 is still unavailable."
        fi

        select_build_jobs
        TOTAL_CPUS="$(nproc 2>/dev/null || printf '2')"
        info "Source build mode: $BUILD_MODE ($BUILD_JOBS/$TOTAL_CPUS CPU jobs)"
        run_build_progress 40 82 "Building Suricata+nDPI runtime" \
            env BUILD_JOBS="$BUILD_JOBS" bash "$STAGE_DIR/scripts/build-runtime.sh" \
                --output-dir "$BUILD_DIR/dist" \
                --work-dir "$BUILD_DIR/source" \
                --jobs "$BUILD_JOBS"

        ASSET_PATH="$BUILD_DIR/dist/$ASSET_NAME"
        CHECKSUM_PATH="$ASSET_PATH.sha256"
    fi

    [ -f "$ASSET_PATH" ] || die "Runtime archive is missing: $ASSET_PATH"
    [ -f "$CHECKSUM_PATH" ] || die "Runtime checksum is missing: $CHECKSUM_PATH"
    (
        cd "$(dirname "$ASSET_PATH")"
        sha256sum -c "$(basename "$CHECKSUM_PATH")"
    ) >>"$INSTALL_LOG" 2>&1 || die "Runtime archive checksum mismatch"

    archive_paths_safe "$ASSET_PATH" || die "Runtime archive contains unsafe paths"
    run_timed_logged 84 "Extracting runtime" \
        tar --zstd -xf "$ASSET_PATH" -C "$BUILD_DIR/runtime-root"

    RUNTIME_ROOT="$BUILD_DIR/runtime-root"
    run_logged python3 "$STAGE_DIR/scripts/verify-runtime.py" \
        "$RUNTIME_ROOT" \
        --app-version "$APP_VERSION" \
        --engine-id "$ENGINE_ID" \
        --os-version "$OS_VERSION_ID" \
        --arch amd64 \
        --cpu-baseline "$CPU_BASELINE" \
        --runtime-prefix "$SURICATA_PREFIX"

    mapfile -t RUNTIME_PACKAGES < <(
        python3 - "$RUNTIME_ROOT/runtime-manifest.json" <<'PY_PACKAGES'
import json
import sys

for package in json.load(open(sys.argv[1], encoding="utf-8")).get("runtime_packages", []):
    print(package)
PY_PACKAGES
    )
    [ "${#RUNTIME_PACKAGES[@]}" -gt 0 ] || \
        die "Runtime manifest has no dependency package list"
    ensure_packages 86 "Installing runtime libraries" "${RUNTIME_PACKAGES[@]}"

    STAGED_PREFIX="$RUNTIME_ROOT$SURICATA_PREFIX"
    STAGED_BIN="$STAGED_PREFIX/bin/suricata"
    STAGED_CONFIG="$STAGED_PREFIX/etc/suricata/suricata.yaml"
    STAGED_PLUGIN="$STAGED_PREFIX/lib/ezhik/ndpi.so"
    STAGED_CLASSIFICATION="$STAGED_PREFIX/etc/suricata/classification.config"
    STAGED_REFERENCE="$STAGED_PREFIX/etc/suricata/reference.config"
    STAGED_THRESHOLD="$STAGED_PREFIX/etc/suricata/threshold.config"

    [ -f "$STAGED_CLASSIFICATION" ] || \
        die "Staged classification.config is missing"
    [ -f "$STAGED_REFERENCE" ] || die "Staged reference.config is missing"

    run_logged python3 "$STAGE_DIR/scripts/render_suricata_config.py" \
        "$STAGED_CONFIG" "$WAN_IF" "$WAN_IP" "$STAGED_PLUGIN"
    run_logged ensure_suricata_yaml_header "$STAGED_CONFIG"
    STAGED_TEST_ARGS=(
        -T -c "$STAGED_CONFIG"
        -S "$STAGE_DIR/suricata/ezhik-torrent-only.rules"
        --set "classification-file=$STAGED_CLASSIFICATION"
        --set "reference-config-file=$STAGED_REFERENCE"
    )
    if [ -f "$STAGED_THRESHOLD" ]; then
        STAGED_TEST_ARGS+=(--set "threshold-file=$STAGED_THRESHOLD")
    fi
    "$STAGED_BIN" "${STAGED_TEST_ARGS[@]}" \
        >>"$INSTALL_LOG" 2>&1 || die "Staged Suricata runtime validation failed"

    progress_done 85 "Runtime ready ($RUNTIME_SOURCE)"
fi

progress_status 88 "Installing Torrent Guard files"
ui_line "\n"
info "Installing Torrent Guard files..."

# Compilation/download and staged validation happen while the current services
# are still running. Stop them only for the short atomic install phase.
systemctl stop ezhik-torrent-guard.service ezhik-ram-log-guard.service ezhik-suricata.service \
    >/dev/null 2>&1 || true
SERVICES_STOPPED=1

if [ -n "$RUNTIME_ROOT" ]; then
    STAGED_PREFIX="$RUNTIME_ROOT$SURICATA_PREFIX"
    [ -d "$STAGED_PREFIX" ] || die "Staged runtime prefix is missing"

    RUNTIME_BACKUP="${SURICATA_PREFIX}.previous"
    rm -rf "$RUNTIME_BACKUP"
    if [ -d "$SURICATA_PREFIX" ]; then
        mv "$SURICATA_PREFIX" "$RUNTIME_BACKUP" || \
            die "Cannot preserve the previous Suricata runtime"
    fi
    mv "$STAGED_PREFIX" "$SURICATA_PREFIX" || {
        [ ! -d "$RUNTIME_BACKUP" ] || mv "$RUNTIME_BACKUP" "$SURICATA_PREFIX"
        die "Cannot activate the new Suricata runtime"
    }
    RUNTIME_SWAPPED=1
fi

mkdir -p "$APP_DIR/suricata" "$APP_DIR/lib" "$CONFIG_DIR" "$STATE_DIR" || \
    die "Cannot create application directories"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

backup_app_metadata
install -m 644 "$STAGE_DIR/VERSION" "$APP_DIR/VERSION" || die "Cannot install VERSION"
install -m 644 "$STAGE_DIR/RUNTIME.env" "$APP_DIR/RUNTIME.env" || die "Cannot install RUNTIME.env"
install -m 700 "$STAGE_DIR/src/guard.py" "$APP_DIR/guard.py" || die "Cannot install guard.py"
install -m 700 "$STAGE_DIR/src/remnawave_actions.py" "$APP_DIR/remnawave_actions.py" || \
    die "Cannot install remnawave_actions.py"
install -m 700 "$STAGE_DIR/src/scan_detector.py" "$APP_DIR/scan_detector.py" || \
    die "Cannot install scan_detector.py"
install -m 700 "$STAGE_DIR/src/telegram_notifier.py" "$APP_DIR/telegram_notifier.py" || \
    die "Cannot install telegram_notifier.py"
install -m 644 "$STAGE_DIR/suricata/ezhik-torrent-only.rules" \
    "$APP_DIR/suricata/ezhik-torrent-only.rules" || die "Cannot install torrent rule"
install -m 755 "$STAGE_DIR/scripts/ezhik-ram-log-guard.sh" \
    /usr/local/sbin/ezhik-ram-log-guard.sh || die "Cannot install RAM log guard"
install -m 755 "$STAGE_DIR/scripts/ezhik-torrent-guard-cleanup.sh" \
    /usr/local/sbin/ezhik-torrent-guard-cleanup.sh || die "Cannot install cleanup script"

# API and Telegram credentials are kept out of the process EnvironmentFile.
umask 077
cat >"$CONFIG_DIR/api.env" <<__API_ENV__
REMNAWAVE_BASE_URL=$PANEL_URL
REMNAWAVE_API_TOKEN=$API_TOKEN
__API_ENV__

cat >"$CONFIG_DIR/telegram.env" <<__TELEGRAM_ENV__
TELEGRAM_BOT_TOKEN=$TELEGRAM_TOKEN
TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID
__TELEGRAM_ENV__

cat >"$CONFIG_DIR/settings.env" <<__SETTINGS_ENV__
EZHIK_LOCAL_IP=$WAN_IP
EZHIK_REMNANODE_CONTAINER=$REMNANODE_CONTAINER
EZHIK_PROTECTED_CLIENTS=$PROTECTED_CLIENTS
EZHIK_FREEZE_SECONDS=$FREEZE_SECONDS
EZHIK_DRY_RUN=$DRY_RUN
EZHIK_SCAN_ENABLED=$SCAN_ENABLED
EZHIK_SCAN_DRY_RUN=$SCAN_DRY_RUN
EZHIK_SCAN_BLOCK_SECONDS=$SCAN_BLOCK_SECONDS
EZHIK_SCAN_WINDOW_SECONDS=$SCAN_WINDOW_SECONDS
EZHIK_SCAN_BURST_WINDOW_SECONDS=$SCAN_BURST_WINDOW_SECONDS
EZHIK_SCAN_VERTICAL_PORTS=$SCAN_VERTICAL_PORTS
EZHIK_SCAN_BURST_ENDPOINTS=$SCAN_BURST_ENDPOINTS
EZHIK_SCAN_BURST_PORTS=$SCAN_BURST_PORTS
EZHIK_SCAN_SUBNET_HOSTS=$SCAN_SUBNET_HOSTS
EZHIK_SCAN_SUBNET_PORTS=$SCAN_SUBNET_PORTS
EZHIK_SCAN_COOLDOWN_SECONDS=$SCAN_COOLDOWN_SECONDS
EZHIK_TEST_CLIENT=
EZHIK_STATS_INTERVAL=60
EZHIK_RAM_LOG_MAX_BYTES=8388608
__SETTINGS_ENV__

chmod 600 "$CONFIG_DIR/api.env" "$CONFIG_DIR/telegram.env" "$CONFIG_DIR/settings.env"
touch "$CONFIG_DIR/hold.txt"
chmod 600 "$CONFIG_DIR/hold.txt"

run_logged python3 "$STAGE_DIR/scripts/render_suricata_config.py" \
    "$SURICATA_CONFIG" "$WAN_IF" "$WAN_IP" "$PLUGIN_PATH"

# The renderer rewrites YAML and may drop Suricata's required directive/document marker.
# Normalize them after every render before running suricata -T.
run_logged ensure_suricata_yaml_header "$SURICATA_CONFIG"
[ "$(sed -n '1p' "$SURICATA_CONFIG")" = "%YAML 1.1" ] || \
    die "Suricata YAML header repair failed: first line is invalid"
[ "$(sed -n '2p' "$SURICATA_CONFIG")" = "---" ] || \
    die "Suricata YAML header repair failed: second line is invalid"

python3 - "$APP_DIR/install-manifest.json" <<PY_INSTALL_MANIFEST
import json
import pathlib
import sys
import time

pathlib.Path(sys.argv[1]).write_text(
    json.dumps(
        {
            "format": 1,
            "app_version": "${APP_VERSION}",
            "engine_id": "${ENGINE_ID}",
            "runtime_source": "${RUNTIME_SOURCE}",
            "installed_at": int(time.time()),
            "os": "ubuntu",
            "os_version": "${OS_VERSION_ID}",
            "arch": "amd64",
        },
        indent=2,
        sort_keys=True,
    ) + "\\n",
    encoding="utf-8",
)
PY_INSTALL_MANIFEST
chmod 600 "$APP_DIR/install-manifest.json"

: >/dev/shm/ezhik-suricata-fast.log
chmod 600 /dev/shm/ezhik-suricata-fast.log || true

progress_status 93 "Validating Suricata configuration"
ui_line "\n"
info "Validating Suricata configuration..."
"$SURICATA_BIN" -T -c "$SURICATA_CONFIG" \
    -S "$APP_DIR/suricata/ezhik-torrent-only.rules" >>"$INSTALL_LOG" 2>&1 || {
        tail -n 60 "$INSTALL_LOG" >&2
        die "Suricata configuration test failed"
    }
progress_done 95 "Suricata configuration valid"

install -m 644 "$STAGE_DIR/systemd/ezhik-torrent-guard.service" \
    /etc/systemd/system/ezhik-torrent-guard.service || die "Cannot install Guard unit"
install -m 644 "$STAGE_DIR/systemd/ezhik-ram-log-guard.service" \
    /etc/systemd/system/ezhik-ram-log-guard.service || die "Cannot install RAM log unit"

sed \
    -e "s|@@SURICATA_BIN@@|$SURICATA_BIN|g" \
    -e "s|@@SURICATA_CONFIG@@|$SURICATA_CONFIG|g" \
    -e "s|@@WAN_IF@@|$WAN_IF|g" \
    "$STAGE_DIR/systemd/ezhik-suricata.service.template" \
    >/etc/systemd/system/ezhik-suricata.service || die "Cannot render Suricata unit"
chmod 644 /etc/systemd/system/ezhik-suricata.service

mkdir -p /etc/systemd/system/ezhik-torrent-guard.service.d || \
    die "Cannot create systemd drop-in directory"
install -m 644 "$STAGE_DIR/systemd/ezhik-torrent-guard-cleanup.conf" \
    /etc/systemd/system/ezhik-torrent-guard.service.d/cleanup.conf || \
    die "Cannot install cleanup drop-in"

progress_status 97 "Installing and enabling systemd services"
ui_line "\n"
systemctl daemon-reload || die "systemd daemon-reload failed"
systemctl enable ezhik-suricata.service ezhik-torrent-guard.service ezhik-ram-log-guard.service \
    >>"$INSTALL_LOG" 2>&1 || die "Could not enable services"

systemctl start ezhik-suricata.service || die "Could not start ezhik-suricata.service"
sleep 2
systemctl start ezhik-ram-log-guard.service || die "Could not start ezhik-ram-log-guard.service"
systemctl start ezhik-torrent-guard.service || die "Could not start ezhik-torrent-guard.service"
sleep 3

FAILED=0
for svc in ezhik-suricata ezhik-torrent-guard ezhik-ram-log-guard; do
    if systemctl is-active --quiet "$svc.service"; then
        ok "$svc.service is active"
    else
        warn "$svc.service is NOT active"
        systemctl --no-pager --full status "$svc.service" >&2 || true
        FAILED=1
    fi
done
[ "$FAILED" -eq 0 ] || die "One or more services failed to start."
SERVICES_STOPPED=0
progress_done 100 "Torrent Guard installation complete"

PLUGIN_SHA="$(sha256sum "$PLUGIN_PATH" | awk '{print $1}')"
SURI_VERSION="$($SURICATA_BIN --build-info 2>/dev/null | sed -n 's/^This is Suricata version /Suricata /p' | head -n1)"

# The new runtime is healthy; rollback data is no longer needed.
RUNTIME_SWAPPED=0
APP_METADATA_CHANGED=0
[ -z "$RUNTIME_BACKUP" ] || rm -rf "$RUNTIME_BACKUP"
rm -f "$APP_DIR/lib/ndpi.so"

# Delete build sources only after all services are healthy.
rm -rf "$BUILD_DIR"
rm -f "$AUTH_HEADERS"
unset API_TOKEN

cat <<__INSTALL_DONE__

============================================================
             INSTALLATION COMPLETE - v$APP_VERSION
============================================================

 Developer          : ezhikdev
 Telegram           : @ezhikdev
 GitHub              : https://github.com/ezhikdev

 RemnaNode           : $REMNANODE_CONTAINER
 WAN                 : $WAN_IF / $WAN_IP
 Remnawave panel     : $PANEL_URL
 Mode                : $MODE
 Freeze              : $FREEZE_MINUTES minute(s)
 Port-scan mode      : $SCAN_MODE
 Port-scan block     : $([ "$SCAN_BLOCK_MINUTES" -eq 0 ] && printf 'permanent' || printf '%s minute(s)' "$SCAN_BLOCK_MINUTES")
 Telegram alerts     : $([ -n "$TELEGRAM_TOKEN" ] && printf 'enabled' || printf 'disabled')
 Protected IDs       : ${PROTECTED_CLIENTS:-none}
 Suricata            : ${SURI_VERSION:-8.0.6}
 strict nDPI plugin  : ${PLUGIN_SHA:0:16}...

 Services:
   ezhik-suricata       ACTIVE
   ezhik-torrent-guard  ACTIVE
   ezhik-ram-log-guard  ACTIVE

 Logs:
   journalctl -fu ezhik-torrent-guard

 Installer log       : $INSTALL_LOG

 NOTE: v$APP_VERSION detectors currently support IPv4 only.
============================================================
__INSTALL_DONE__

exit 0

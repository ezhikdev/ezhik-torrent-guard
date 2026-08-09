#!/usr/bin/env bash

set -o pipefail

APP_VERSION="1.0.2"
REPO_RAW="https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main"
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
die()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

INSTALL_STARTED_AT="$(date +%s)"
SPINNER_CHARS='|/-\\'

format_elapsed() {
    local seconds="$1"
    printf '%02d:%02d' $((seconds / 60)) $((seconds % 60))
}

ui_line() {
    # Best-effort terminal output. Build commands continue even if the SSH TTY disappears.
    printf '%b' "$*" 2>/dev/null || true
}

progress_status() {
    local pct="$1"
    shift
    ui_line "\\r\\033[2K\\033[1;36m[$(printf '%3d' "$pct")%]\\033[0m $*"
}

progress_done() {
    local pct="$1"
    shift
    ui_line "\\r\\033[2K\\033[1;36m[$(printf '%3d' "$pct")%]\\033[0m $* \\033[1;32mOK\\033[0m\\n"
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

    # Пытаемся узнать размер файла заранее.
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

    # Сам curl работает тихо в фоне.
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

count_ndpi_work() {
    local root="$1"
    find "$root/src" "$root/example" -type f \
        \( -name '*.o' -o -name '*.lo' \) 2>/dev/null | wc -l
}

count_ndpi_total() {
    local root="$1"
    find "$root/src" "$root/example" -type f \
        \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) 2>/dev/null | wc -l
}

count_suricata_work() {
    local root="$1"
    local c rust
    c="$(find "$root/src" "$root/plugins" -type f \
        \( -name '*.o' -o -name '*.lo' \) 2>/dev/null | wc -l)"
    rust="$(find "$root/rust/target/release/deps" -maxdepth 1 -type f \
        \( -name '*.rlib' -o -name '*.so' \) 2>/dev/null | wc -l)"
    printf '%d' $((c + rust))
}

count_suricata_total() {
    local root="$1"
    local c rust
    c="$(find "$root/src" "$root/plugins" -type f -name '*.c' 2>/dev/null | wc -l)"
    rust="$(grep -c '^\[\[package\]\]' "$root/rust/Cargo.lock" 2>/dev/null || true)"
    printf '%d' $((c + rust))
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
    local kind="$4"
    local root="$5"
    shift 5

    local started now elapsed frame=0 pid rc total done sub overall activity spin

    case "$kind" in
        ndpi) total="$(count_ndpi_total "$root")" ;;
        suricata) total="$(count_suricata_total "$root")" ;;
        *) total=0 ;;
    esac
    [ "${total:-0}" -gt 0 ] || total=1

    started="$(date +%s)"
    "$@" >>"$INSTALL_LOG" 2>&1 &
    pid=$!

    while kill -0 "$pid" 2>/dev/null; do
        case "$kind" in
            ndpi) done="$(count_ndpi_work "$root")" ;;
            suricata) done="$(count_suricata_work "$root")" ;;
            *) done=0 ;;
        esac

        sub=$((done * 100 / total))
        [ "$sub" -lt 0 ] && sub=0
        [ "$sub" -gt 98 ] && sub=98
        overall=$((overall_start + (overall_end - overall_start) * sub / 100))

        now="$(date +%s)"
        elapsed=$((now - started))
        spin="${SPINNER_CHARS:$((frame % 4)):1}"
        activity="$(latest_build_activity)"
        [ -n "$activity" ] || activity="compiler active"

        progress_status "$overall" "$label  $spin  build ~$(printf '%2d' "$sub")%  $(format_elapsed "$elapsed")  $activity"
        frame=$((frame + 1))
        sleep 1
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

prompt_secret() {
    local text="$1"
    local value

    printf '%s: ' "$text" >/dev/tty
    IFS= read -r -s value </dev/tty || die "Cannot read secret from /dev/tty"
    printf '\n' >/dev/tty
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

    case "$value" in
        y|Y|yes|YES|Yes) return 0 ;;
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

for cmd in apt-get docker ip python3 systemctl tar; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

if ! command -v curl >/dev/null 2>&1; then
    info "Installing curl..."
    run_logged apt-get update
    run_logged env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl
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

printf '\n' >/dev/tty
PANEL_URL="$(prompt 'Remnawave panel domain or URL')"
PANEL_URL="$(normalize_panel_url "$PANEL_URL")"
API_TOKEN="$(prompt_secret 'Remnawave Panel API token (paste token only)')"
[ -n "$API_TOKEN" ] || die "API key cannot be empty."

PROTECTED_RAW="$(prompt 'Protected Remnawave client IDs, comma-separated (optional)' '')"
PROTECTED_CLIENTS="$(canonical_clients "$PROTECTED_RAW")" || die "Protected IDs must be numeric and comma-separated."

FREEZE_MINUTES="$(prompt 'Freeze duration in minutes' '15')"
[[ "$FREEZE_MINUTES" =~ ^[0-9]+$ ]] || die "Freeze duration must be a number."
[ "$FREEZE_MINUTES" -ge 1 ] && [ "$FREEZE_MINUTES" -le 1440 ] || \
    die "Freeze duration must be between 1 and 1440 minutes."
FREEZE_SECONDS=$((FREEZE_MINUTES * 60))

if confirm "Enable LIVE Remnawave enforcement after install?" Y; then
    DRY_RUN="false"
    MODE="LIVE"
else
    DRY_RUN="true"
    MODE="DRY RUN"
fi

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
    [ "$HTTP_CODE" != "401" ] || warn 'HTTP 401: paste the Panel API token only — without "Bearer " and without REMNAWAVE_API_TOKEN='
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
    src/guard.py \
    src/remnawave_actions.py \
    suricata/ezhik-torrent-only.rules \
    scripts/ezhik-ram-log-guard.sh \
    scripts/ezhik-torrent-guard-cleanup.sh \
    scripts/patch_ndpi_strict.py \
    scripts/patch_suricata_ndpi.py \
    scripts/render_suricata_config.py \
    systemd/ezhik-torrent-guard.service \
    systemd/ezhik-ram-log-guard.service \
    systemd/ezhik-suricata.service.template \
    systemd/ezhik-torrent-guard-cleanup.conf
do
    repo_file "$rel" "$STAGE_DIR/$rel"
done
ok "Repository files ready"

info "Installing build dependencies (details: $INSTALL_LOG)..."
run_timed_logged 22 "apt-get update" apt-get update
run_timed_logged 30 "Installing build dependencies" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git \
    autoconf automake build-essential cargo cbindgen gettext flex bison \
    libjansson-dev libjson-c-dev libpcap-dev libpcre2-dev libtool libyaml-dev \
    pkg-config rustc zlib1g-dev libnetfilter-queue-dev libnfnetlink-dev \
    libcap-ng-dev libmagic-dev libnet1-dev libnuma-dev libmaxminddb-dev \
    librrd-dev libgcrypt20-dev libgpg-error-dev libcurl4-openssl-dev \
    python3 python3-yaml
ok "Build dependencies installed"

if ! rust_version_ok; then
    warn "Rust >= 1.75 is not available in the current PATH; installing a minimal Rust toolchain with rustup."
    curl -fsSL https://sh.rustup.rs -o "$STAGE_DIR/rustup.sh" || die "Cannot download rustup"
    run_logged sh "$STAGE_DIR/rustup.sh" -y --profile minimal
    export PATH="/root/.cargo/bin:$PATH"
    rust_version_ok || die "Rust >= 1.75 is still unavailable."
fi
ok "Rust toolchain: $(rustc --version)"

# Stop only our own services on re-install. Never touch arbitrary Suricata processes.
systemctl stop ezhik-torrent-guard.service ezhik-ram-log-guard.service ezhik-suricata.service \
    >/dev/null 2>&1 || true

NDPI_STOCK="$BUILD_DIR/nDPI-4.14"
NDPI_STRICT="$BUILD_DIR/nDPI-4.14-strict"
SURI_SRC="$BUILD_DIR/suricata-8.0.6"
SURICATA_BIN="$SURICATA_PREFIX/bin/suricata"
SURICATA_CONFIG="$SURICATA_PREFIX/etc/suricata/suricata.yaml"
BUILD_READY_MARKER="$BUILD_DIR/.ezhik-runtime-ready-suricata-8.0.6-ndpi-4.14"
PLUGIN_SRC="$SURI_SRC/plugins/ndpi/.libs/ndpi.so"
REUSE_BUILD=0

# If a previous run finished compilation but failed later (for example during
# config validation), reuse the verified build instead of wasting 10+ minutes.
if [ -f "$BUILD_READY_MARKER" ] && \
   [ -f "$NDPI_STRICT/src/lib/libndpi.a" ] && \
   [ -x "$SURICATA_BIN" ] && \
   [ -f "$SURICATA_CONFIG" ] && \
   [ -f "$PLUGIN_SRC" ] && \
   ! ldd "$PLUGIN_SRC" 2>/dev/null | grep -q 'not found'; then
    REUSE_BUILD=1
    ok "Previous completed nDPI/Suricata build detected; reusing it"
    progress_done 85 "Reusing completed Suricata build"
fi

if [ "$REUSE_BUILD" -eq 0 ]; then
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR" || die "Cannot create $BUILD_DIR"

    info "Building strict nDPI 4.14..."
    download_with_progress 34 "Downloading nDPI 4.14" \
        "https://github.com/ntop/nDPI/archive/refs/tags/4.14.tar.gz" \
        "$BUILD_DIR/ndpi-4.14.tar.gz"
    run_timed_logged 36 "Extracting nDPI 4.14" tar -xzf "$BUILD_DIR/ndpi-4.14.tar.gz" -C "$BUILD_DIR"

    [ -d "$NDPI_STOCK" ] || die "Unexpected nDPI archive layout."
    cp -a "$NDPI_STOCK" "$NDPI_STRICT" || die "Cannot create strict nDPI tree"

    run_timed_logged 38 "Applying strict BitTorrent patch" python3 \
        "$STAGE_DIR/scripts/patch_ndpi_strict.py" \
        "$NDPI_STRICT/src/lib/protocols/bittorrent.c"
    run_timed_logged 40 "Configuring nDPI build system" bash -lc \
        "cd '$NDPI_STRICT' && ./autogen.sh && ./configure"
    run_build_progress 40 50 "Building strict nDPI" ndpi "$NDPI_STRICT" \
        bash -lc "cd '$NDPI_STRICT' && nice -n 10 make -j2"

    [ -f "$NDPI_STRICT/src/lib/libndpi.a" ] || die "strict libndpi.a was not built"
    ok "strict nDPI 4.14 built"

    info "Building Suricata 8.0.6 with strict nDPI plugin..."
    download_with_progress 54 "Downloading Suricata 8.0.6" \
        "https://www.openinfosecfoundation.org/download/suricata-8.0.6.tar.gz" \
        "$BUILD_DIR/suricata-8.0.6.tar.gz"
    run_timed_logged 56 "Extracting Suricata 8.0.6" tar -xzf "$BUILD_DIR/suricata-8.0.6.tar.gz" -C "$BUILD_DIR"

    [ -d "$SURI_SRC" ] || die "Unexpected Suricata archive layout."

    run_timed_logged 58 "Applying Suricata nDPI patch" python3 \
        "$STAGE_DIR/scripts/patch_suricata_ndpi.py" \
        "$SURI_SRC/plugins/ndpi/ndpi.c"

    rm -rf "$SURICATA_PREFIX"
    run_timed_logged 60 "Configuring Suricata 8.0.6" bash -lc \
        "cd '$SURI_SRC' && ./configure --prefix='$SURICATA_PREFIX' --sysconfdir='$SURICATA_PREFIX/etc' --localstatedir='$SURICATA_PREFIX/var' --enable-ndpi --with-ndpi='$NDPI_STRICT'"
    run_build_progress 60 82 "Building Suricata 8.0.6" suricata "$SURI_SRC" \
        bash -lc "cd '$SURI_SRC' && nice -n 10 make -j2"
    run_timed_logged 85 "Installing Suricata runtime" bash -lc \
        "cd '$SURI_SRC' && make install && make install-conf"

    [ -x "$SURICATA_BIN" ] || die "Suricata binary not installed at $SURICATA_BIN"
    [ -f "$SURICATA_CONFIG" ] || die "Suricata config not installed at $SURICATA_CONFIG"
    [ -f "$PLUGIN_SRC" ] || die "strict Suricata nDPI plugin was not built"
    if ldd "$PLUGIN_SRC" 2>/dev/null | grep -q 'not found'; then
        ldd "$PLUGIN_SRC" >&2 || true
        die "strict nDPI plugin has missing runtime libraries"
    fi

    # Keep this marker until the whole installer succeeds. If a later step fails,
    # the next run can safely skip compilation. BUILD_DIR is deleted on success.
    : >"$BUILD_READY_MARKER"
    ok "Suricata 8.0.6 built"
fi

progress_status 88 "Installing Torrent Guard files"
ui_line "\n"
info "Installing Torrent Guard files..."
mkdir -p "$APP_DIR/suricata" "$APP_DIR/lib" "$CONFIG_DIR" "$STATE_DIR" || \
    die "Cannot create application directories"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

install -m 700 "$STAGE_DIR/src/guard.py" "$APP_DIR/guard.py" || die "Cannot install guard.py"
install -m 700 "$STAGE_DIR/src/remnawave_actions.py" "$APP_DIR/remnawave_actions.py" || \
    die "Cannot install remnawave_actions.py"
install -m 644 "$STAGE_DIR/suricata/ezhik-torrent-only.rules" \
    "$APP_DIR/suricata/ezhik-torrent-only.rules" || die "Cannot install torrent rule"
install -m 755 "$PLUGIN_SRC" "$APP_DIR/lib/ndpi.so" || die "Cannot install strict nDPI plugin"
install -m 755 "$STAGE_DIR/scripts/ezhik-ram-log-guard.sh" \
    /usr/local/sbin/ezhik-ram-log-guard.sh || die "Cannot install RAM log guard"
install -m 755 "$STAGE_DIR/scripts/ezhik-torrent-guard-cleanup.sh" \
    /usr/local/sbin/ezhik-torrent-guard-cleanup.sh || die "Cannot install cleanup script"

# API credentials are deliberately kept out of the process EnvironmentFile.
umask 077
cat >"$CONFIG_DIR/api.env" <<__API_ENV__
REMNAWAVE_BASE_URL=$PANEL_URL
REMNAWAVE_API_TOKEN=$API_TOKEN
__API_ENV__

cat >"$CONFIG_DIR/settings.env" <<__SETTINGS_ENV__
EZHIK_LOCAL_IP=$WAN_IP
EZHIK_REMNANODE_CONTAINER=$REMNANODE_CONTAINER
EZHIK_PROTECTED_CLIENTS=$PROTECTED_CLIENTS
EZHIK_FREEZE_SECONDS=$FREEZE_SECONDS
EZHIK_DRY_RUN=$DRY_RUN
EZHIK_TEST_CLIENT=
EZHIK_STATS_INTERVAL=60
EZHIK_RAM_LOG_MAX_BYTES=8388608
__SETTINGS_ENV__

chmod 600 "$CONFIG_DIR/api.env" "$CONFIG_DIR/settings.env"
touch "$CONFIG_DIR/hold.txt"
chmod 600 "$CONFIG_DIR/hold.txt"

run_logged python3 "$STAGE_DIR/scripts/render_suricata_config.py" \
    "$SURICATA_CONFIG" "$WAN_IF" "$WAN_IP" "$APP_DIR/lib/ndpi.so"

# The renderer rewrites YAML and may drop Suricata's required directive/document marker.
# Normalize them after every render before running suricata -T.
run_logged ensure_suricata_yaml_header "$SURICATA_CONFIG"
[ "$(sed -n '1p' "$SURICATA_CONFIG")" = "%YAML 1.1" ] || \
    die "Suricata YAML header repair failed: first line is invalid"
[ "$(sed -n '2p' "$SURICATA_CONFIG")" = "---" ] || \
    die "Suricata YAML header repair failed: second line is invalid"

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
progress_done 100 "Torrent Guard installation complete"

PLUGIN_SHA="$(sha256sum "$APP_DIR/lib/ndpi.so" | awk '{print $1}')"
SURI_VERSION="$($SURICATA_BIN --build-info 2>/dev/null | sed -n 's/^This is Suricata version /Suricata /p' | head -n1)"

# Delete build sources only after all services are healthy.
rm -rf "$BUILD_DIR"
rm -f "$AUTH_HEADERS"
unset API_TOKEN

cat <<__INSTALL_DONE__

============================================================
             INSTALLATION COMPLETE — v$APP_VERSION
============================================================

 Developer          : ezhikdev
 Telegram           : @ezhikdev
 GitHub              : https://github.com/ezhikdev

 RemnaNode           : $REMNANODE_CONTAINER
 WAN                 : $WAN_IF / $WAN_IP
 Remnawave panel     : $PANEL_URL
 Mode                : $MODE
 Freeze              : $FREEZE_MINUTES minute(s)
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

 NOTE: v$APP_VERSION detects IPv4 BitTorrent traffic only.
============================================================
__INSTALL_DONE__

exit 0
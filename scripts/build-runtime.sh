#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck disable=SC1091
. "$REPO_DIR/RUNTIME.env"

APP_VERSION="$(tr -d '[:space:]' <"$REPO_DIR/VERSION")"
ENGINE_ID="suricata-${SURICATA_VERSION}-ndpi-${NDPI_VERSION}-r${RUNTIME_REVISION}"
RUNTIME_PREFIX="/opt/ezhik-suricata-${SURICATA_VERSION}"
PORTABLE_CFLAGS="-O2 -pipe -march=${CPU_BASELINE} -mtune=generic"
PORTABLE_RUSTFLAGS="-C target-cpu=${CPU_BASELINE}"

OUTPUT_DIR=""
WORK_DIR=""
BUILD_JOBS="${BUILD_JOBS:-2}"
KEEP_WORK=0

usage() {
    cat <<'USAGE'
usage: build-runtime.sh --output-dir DIR [options]

Options:
  --work-dir DIR    Reusable build directory (default: temporary directory)
  --jobs N          Parallel Make/Cargo jobs (default: 2)
  --keep-work       Keep a temporary build directory after completion
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-dir)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --work-dir)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            WORK_DIR="$2"
            shift 2
            ;;
        --jobs)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            BUILD_JOBS="$2"
            shift 2
            ;;
        --keep-work)
            KEEP_WORK=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$OUTPUT_DIR" ] || { usage >&2; exit 2; }
[[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || {
    printf 'Invalid --jobs value: %s\n' "$BUILD_JOBS" >&2
    exit 2
}

[ -r /etc/os-release ] || { printf 'Cannot detect operating system\n' >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || {
    printf 'Runtime builder currently supports Ubuntu, detected: %s\n' "${ID:-unknown}" >&2
    exit 1
}

case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    *) printf 'Runtime builder supports amd64 only\n' >&2; exit 1 ;;
esac

OS_VERSION="${VERSION_ID:-unknown}"
ASSET_NAME="ezhik-runtime-${APP_VERSION}-ubuntu-${OS_VERSION}-${ARCH}.tar.zst"

created_work=0
if [ -z "$WORK_DIR" ]; then
    WORK_DIR="$(mktemp -d /tmp/ezhik-runtime-build.XXXXXX)"
    created_work=1
else
    mkdir -p "$WORK_DIR"
fi

cleanup() {
    if [ "$created_work" -eq 1 ] && [ "$KEEP_WORK" -eq 0 ]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

NDPI_ARCHIVE="$WORK_DIR/ndpi-${NDPI_VERSION}.tar.gz"
SURI_ARCHIVE="$WORK_DIR/suricata-${SURICATA_VERSION}.tar.gz"
NDPI_SRC="$WORK_DIR/nDPI-${NDPI_VERSION}"
SURI_SRC="$WORK_DIR/suricata-${SURICATA_VERSION}"
PACKAGE_ROOT="$WORK_DIR/package-root"

printf '[runtime] engine=%s os=ubuntu-%s arch=%s jobs=%s\n' \
    "$ENGINE_ID" "$OS_VERSION" "$ARCH" "$BUILD_JOBS"

rm -rf "$NDPI_SRC" "$SURI_SRC" "$PACKAGE_ROOT"
mkdir -p "$PACKAGE_ROOT"

printf '[runtime] Downloading nDPI %s\n' "$NDPI_VERSION"
curl -fL --retry 3 --connect-timeout 15 \
    "https://github.com/ntop/nDPI/archive/refs/tags/${NDPI_VERSION}.tar.gz" \
    -o "$NDPI_ARCHIVE"
tar -xzf "$NDPI_ARCHIVE" -C "$WORK_DIR"

printf '[runtime] Applying strict BitTorrent patch\n'
python3 "$REPO_DIR/scripts/patch_ndpi_strict.py" \
    "$NDPI_SRC/src/lib/protocols/bittorrent.c"

printf '[runtime] Configuring nDPI %s\n' "$NDPI_VERSION"
(
    cd "$NDPI_SRC"
    CFLAGS="$PORTABLE_CFLAGS" ./autogen.sh
)

printf '[runtime] Building nDPI %s\n' "$NDPI_VERSION"
(
    cd "$NDPI_SRC"
    nice -n 10 make -j"$BUILD_JOBS"
)
[ -f "$NDPI_SRC/src/lib/libndpi.a" ] || {
    printf 'nDPI static library was not built\n' >&2
    exit 1
}

printf '[runtime] Downloading Suricata %s\n' "$SURICATA_VERSION"
curl -fL --retry 3 --connect-timeout 15 \
    "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
    -o "$SURI_ARCHIVE"
tar -xzf "$SURI_ARCHIVE" -C "$WORK_DIR"

printf '[runtime] Applying BitTorrent-only nDPI plugin patch\n'
python3 "$REPO_DIR/scripts/patch_suricata_ndpi.py" \
    "$SURI_SRC/plugins/ndpi/ndpi.c"

printf '[runtime] Configuring Suricata %s\n' "$SURICATA_VERSION"
(
    cd "$SURI_SRC"
    CARGO_BUILD_JOBS="$BUILD_JOBS" \
    CFLAGS="$PORTABLE_CFLAGS" \
    RUSTFLAGS="$PORTABLE_RUSTFLAGS" \
    ./configure \
        --prefix="$RUNTIME_PREFIX" \
        --sysconfdir="$RUNTIME_PREFIX/etc" \
        --localstatedir="$RUNTIME_PREFIX/var" \
        --disable-gccmarch-native \
        --enable-ndpi \
        --with-ndpi="$NDPI_SRC"
)

printf '[runtime] Building Suricata %s\n' "$SURICATA_VERSION"
(
    cd "$SURI_SRC"
    CARGO_BUILD_JOBS="$BUILD_JOBS" \
    RUSTFLAGS="$PORTABLE_RUSTFLAGS" \
    MAKEFLAGS="-j$BUILD_JOBS" \
    nice -n 10 make -j"$BUILD_JOBS"
)

printf '[runtime] Installing staged runtime\n'
(
    cd "$SURI_SRC"
    make DESTDIR="$PACKAGE_ROOT" install
    make DESTDIR="$PACKAGE_ROOT" install-conf
)

STAGED_PREFIX="$PACKAGE_ROOT$RUNTIME_PREFIX"
STAGED_BIN="$STAGED_PREFIX/bin/suricata"
PLUGIN_SRC="$SURI_SRC/plugins/ndpi/.libs/ndpi.so"
PLUGIN_DIR="$STAGED_PREFIX/lib/ezhik"
PLUGIN_PATH="$PLUGIN_DIR/ndpi.so"

[ -x "$STAGED_BIN" ] || { printf 'Staged Suricata binary is missing\n' >&2; exit 1; }
[ -f "$PLUGIN_SRC" ] || { printf 'Staged nDPI plugin is missing\n' >&2; exit 1; }

mkdir -p "$PLUGIN_DIR"
install -m 755 "$PLUGIN_SRC" "$PLUGIN_PATH"

if ldd "$STAGED_BIN" 2>/dev/null | grep -q 'not found'; then
    ldd "$STAGED_BIN" >&2 || true
    printf 'Suricata runtime has missing shared libraries\n' >&2
    exit 1
fi
if ldd "$PLUGIN_PATH" 2>/dev/null | grep -q 'not found'; then
    ldd "$PLUGIN_PATH" >&2 || true
    printf 'nDPI plugin has missing shared libraries\n' >&2
    exit 1
fi

PATCHSET_SHA="$({
    cat "$REPO_DIR/scripts/patch_ndpi_strict.py"
    cat "$REPO_DIR/scripts/patch_suricata_ndpi.py"
} | sha256sum | awk '{print $1}')"
SURICATA_SHA="$(sha256sum "$STAGED_BIN" | awk '{print $1}')"
PLUGIN_SHA="$(sha256sum "$PLUGIN_PATH" | awk '{print $1}')"
MANIFEST="$PACKAGE_ROOT/runtime-manifest.json"
mapfile -t RUNTIME_PACKAGE_LIST < <({
    ldd "$STAGED_BIN"
    ldd "$PLUGIN_PATH"
} | awk '
    /=> \// { print $3 }
    /^\// { print $1 }
' | while IFS= read -r library; do
    canonical="$(readlink -f "$library" 2>/dev/null || true)"
    owner="$(
        dpkg-query -S "$library" ${canonical:+"$canonical"} 2>/dev/null \
            | head -n1 || true
    )"
    [ -n "$owner" ] || continue
    package="${owner%%: /*}"
    printf '%s\n' "${package%:amd64}"
done | sort -u)

[ "${#RUNTIME_PACKAGE_LIST[@]}" -gt 0 ] || {
    printf 'Could not determine runtime dependency packages\n' >&2
    exit 1
}
RUNTIME_PACKAGES="${RUNTIME_PACKAGE_LIST[*]}"
printf '[runtime] Dependency packages: %s\n' "$RUNTIME_PACKAGES"

python3 - "$MANIFEST" <<PY
import json
import pathlib
import sys

data = {
    "format": 1,
    "app_version": "${APP_VERSION}",
    "engine_id": "${ENGINE_ID}",
    "os": "ubuntu",
    "os_version": "${OS_VERSION}",
    "arch": "${ARCH}",
    "cpu_baseline": "${CPU_BASELINE}",
    "suricata_version": "${SURICATA_VERSION}",
    "ndpi_version": "${NDPI_VERSION}",
    "patchset_sha256": "${PATCHSET_SHA}",
    "suricata_sha256": "${SURICATA_SHA}",
    "plugin_sha256": "${PLUGIN_SHA}",
    "runtime_prefix": "${RUNTIME_PREFIX}",
    "runtime_packages": "${RUNTIME_PACKAGES}".split(),
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(data, indent=2, sort_keys=True) + "\\n",
    encoding="utf-8",
)
PY

install -m 644 "$MANIFEST" "$STAGED_PREFIX/ezhik-runtime-manifest.json"

printf '[runtime] Packaging %s\n' "$ASSET_NAME"
tar --zstd -cf "$OUTPUT_DIR/$ASSET_NAME" -C "$PACKAGE_ROOT" .
(
    cd "$OUTPUT_DIR"
    sha256sum "$ASSET_NAME" >"$ASSET_NAME.sha256"
)
cp "$MANIFEST" "$OUTPUT_DIR/$ASSET_NAME.manifest.json"

printf '[runtime] Created %s\n' "$OUTPUT_DIR/$ASSET_NAME"

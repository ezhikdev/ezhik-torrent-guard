#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--app-version", required=True)
    parser.add_argument("--engine-id", required=True)
    parser.add_argument("--os-version", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--runtime-prefix", required=True)
    args = parser.parse_args()

    manifest_path = args.root / "runtime-manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    expected = {
        "format": 1,
        "app_version": args.app_version,
        "engine_id": args.engine_id,
        "os": "ubuntu",
        "os_version": args.os_version,
        "arch": args.arch,
        "runtime_prefix": args.runtime_prefix,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise SystemExit(
                f"runtime manifest mismatch: {key}={data.get(key)!r}, "
                f"expected {value!r}"
            )

    packages = data.get("runtime_packages")
    if not isinstance(packages, list) or not packages:
        raise SystemExit("runtime manifest has no dependency package list")
    if any(
        not isinstance(package, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package)
        for package in packages
    ):
        raise SystemExit("runtime manifest contains an invalid dependency package")

    prefix = args.root / args.runtime_prefix.lstrip("/")
    binary = prefix / "bin" / "suricata"
    plugin = prefix / "lib" / "ezhik" / "ndpi.so"

    if not binary.is_file():
        raise SystemExit(f"runtime binary missing: {binary}")
    if not plugin.is_file():
        raise SystemExit(f"runtime plugin missing: {plugin}")

    if sha256(binary) != data.get("suricata_sha256"):
        raise SystemExit("Suricata binary checksum mismatch")
    if sha256(plugin) != data.get("plugin_sha256"):
        raise SystemExit("nDPI plugin checksum mismatch")

    print(data["engine_id"])


if __name__ == "__main__":
    main()

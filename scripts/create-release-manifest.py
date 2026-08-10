#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from pathlib import Path


ASSET_RE = re.compile(
    r"^ezhik-runtime-(?P<version>[^-]+)-ubuntu-"
    r"(?P<os_version>[0-9.]+)-(?P<arch>[^.]+)\.tar\.zst$"
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    runtimes = {}
    engine_ids = set()

    for asset in sorted(args.dist.glob("*.tar.zst")):
        match = ASSET_RE.match(asset.name)
        if not match:
            continue
        if match.group("version") != args.version:
            raise SystemExit(f"unexpected asset version: {asset.name}")

        sidecar = Path(str(asset) + ".manifest.json")
        runtime = json.loads(sidecar.read_text(encoding="utf-8"))
        expected = {
            "format": 1,
            "app_version": args.version,
            "os": "ubuntu",
            "os_version": match.group("os_version"),
            "arch": match.group("arch"),
        }
        for key, value in expected.items():
            if runtime.get(key) != value:
                raise SystemExit(
                    f"sidecar mismatch for {asset.name}: "
                    f"{key}={runtime.get(key)!r}, expected {value!r}"
                )
        engine_ids.add(runtime["engine_id"])
        key = f"ubuntu-{match.group('os_version')}-{match.group('arch')}"
        runtimes[key] = {
            "asset": asset.name,
            "sha256": sha256(asset),
            "engine_id": runtime["engine_id"],
        }

    if len(runtimes) != 2:
        raise SystemExit(f"expected two runtime assets, found {len(runtimes)}")
    if len(engine_ids) != 1:
        raise SystemExit("runtime assets do not share one engine_id")

    data = {
        "format": 1,
        "app_version": args.version,
        "tag": f"v{args.version}",
        "engine_id": engine_ids.pop(),
        "runtimes": runtimes,
    }
    args.output.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

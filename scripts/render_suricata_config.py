#!/usr/bin/env python3
import sys
from pathlib import Path
import yaml

if len(sys.argv) != 5:
    raise SystemExit(
        "usage: render_suricata_config.py CONFIG WAN_IF WAN_IP PLUGIN_PATH"
    )

config_path = Path(sys.argv[1])
wan_if = sys.argv[2]
wan_ip = sys.argv[3]
plugin_path = sys.argv[4]

with config_path.open("r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

if not isinstance(cfg, dict):
    raise SystemExit("invalid Suricata YAML")

# Load exactly our strict nDPI plugin.
cfg["plugins"] = [plugin_path]

# Keep every Suricata output in RAM by default. Only fast.log is needed by Guard.
cfg["default-log-dir"] = "/dev/shm"

# Passive outbound-only AF_PACKET capture.
cfg["af-packet"] = [
    {
        "interface": wan_if,
        "threads": 1,
        "cluster-id": 99,
        "cluster-type": "cluster_flow",
        "defrag": False,
        "tpacket-v3": True,
        "bpf-filter": f"src host {wan_ip}",
    }
]

# Reduce periodic stats work/logging where the config supports it.
if isinstance(cfg.get("stats"), dict):
    cfg["stats"]["enabled"] = False

outputs = cfg.get("outputs")
if not isinstance(outputs, list):
    outputs = []
    cfg["outputs"] = outputs

seen_fast = False
for item in outputs:
    if not isinstance(item, dict):
        continue

    if "fast" in item and isinstance(item["fast"], dict):
        item["fast"]["enabled"] = True
        item["fast"]["filename"] = "/dev/shm/ezhik-suricata-fast.log"
        item["fast"]["append"] = True
        seen_fast = True

    if "eve-log" in item and isinstance(item["eve-log"], dict):
        item["eve-log"]["enabled"] = False

    if "pcap-log" in item and isinstance(item["pcap-log"], dict):
        item["pcap-log"]["enabled"] = False

    if "stats" in item and isinstance(item["stats"], dict):
        item["stats"]["enabled"] = False

    if "file-store" in item and isinstance(item["file-store"], dict):
        item["file-store"]["enabled"] = False

if not seen_fast:
    outputs.insert(
        0,
        {
            "fast": {
                "enabled": True,
                "filename": "/dev/shm/ezhik-suricata-fast.log",
                "append": True,
            }
        },
    )

# Journal is enough for engine diagnostics. Disable Suricata's own disk file logger.
logging = cfg.get("logging")
if isinstance(logging, dict):
    log_outputs = logging.get("outputs")
    if isinstance(log_outputs, list):
        for item in log_outputs:
            if not isinstance(item, dict):
                continue
            if "file" in item and isinstance(item["file"], dict):
                item["file"]["enabled"] = False
            if "console" in item and isinstance(item["console"], dict):
                item["console"]["enabled"] = True

rendered = yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False)
with config_path.open("w", encoding="utf-8") as f:
    f.write("%YAML 1.1\n---\n")
    f.write(rendered)

print(f"Suricata config rendered for {wan_if} / {wan_ip}")

#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: patch_suricata_ndpi.py /path/to/plugins/ndpi/ndpi.c")

p = Path(sys.argv[1])
s = p.read_text()
marker = "EZHIK: conservative DPI settings"

if marker in s:
    print("Suricata nDPI conservative settings already present")
    raise SystemExit(0)

needle = "    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);\n"
if s.count(needle) != 1:
    raise SystemExit("could not find unique nDPI initialization anchor")

block = needle + '''\n    /* EZHIK: conservative DPI settings */\n    if (ndpi_set_config(context->ndpi, NULL, "fpc", "disable") != NDPI_CFG_OK)\n        FatalError("nDPI: failed to disable FPC");\n\n    if (ndpi_set_config(context->ndpi, NULL, "lru.bittorrent.size", "0") != NDPI_CFG_OK)\n        FatalError("nDPI: failed to disable BitTorrent LRU");\n\n    if (ndpi_set_config(context->ndpi, NULL, "dpi.guess_on_giveup", "0") != NDPI_CFG_OK)\n        FatalError("nDPI: failed to disable protocol guessing");\n'''

p.write_text(s.replace(needle, block, 1))
print("Suricata nDPI conservative settings applied")

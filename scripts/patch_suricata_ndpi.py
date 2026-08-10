#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: patch_suricata_ndpi.py /path/to/plugins/ndpi/ndpi.c")

p = Path(sys.argv[1])
s = p.read_text()
marker = "EZHIK: BitTorrent-only DPI settings"

if marker in s:
    print("Suricata nDPI BitTorrent-only settings already present")
    raise SystemExit(0)

stock_mask = '''    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);
'''
restricted_mask = '''    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_RESET(protos);
    NDPI_BITMASK_ADD(protos, NDPI_PROTOCOL_BITTORRENT);
    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);
'''

if s.count(stock_mask) != 1:
    raise SystemExit("could not find unique nDPI protocol-mask anchor")

s = s.replace(stock_mask, restricted_mask, 1)

old_marker = "EZHIK: conservative DPI settings"
if old_marker in s:
    s = s.replace(old_marker, marker, 1)
else:
    needle = "    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);\n"
    block = needle + '''
    /* EZHIK: BitTorrent-only DPI settings */
    if (ndpi_set_config(context->ndpi, NULL, "fpc", "disable") != NDPI_CFG_OK)
        FatalError("nDPI: failed to disable FPC");

    if (ndpi_set_config(context->ndpi, NULL, "lru.bittorrent.size", "0") != NDPI_CFG_OK)
        FatalError("nDPI: failed to disable BitTorrent LRU");

    if (ndpi_set_config(context->ndpi, NULL, "dpi.guess_on_giveup", "0") != NDPI_CFG_OK)
        FatalError("nDPI: failed to disable protocol guessing");
'''
    s = s.replace(needle, block, 1)

p.write_text(s)
print("Suricata nDPI BitTorrent-only settings applied")

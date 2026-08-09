#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: patch_ndpi_strict.py /path/to/bittorrent.c")

p = Path(sys.argv[1])
s = p.read_text()
old = "if(rc == 1 || bt_proto != NULL || (rc == 2 && flow->packet_counter > 2))"
new = "if(rc == 1 || bt_proto != NULL)"

if new in s and old not in s:
    print("strict nDPI BitTorrent patch already present")
    raise SystemExit(0)

count = s.count(old)
if count != 1:
    raise SystemExit(f"expected exactly one stock BitTorrent heuristic, found {count}")

p.write_text(s.replace(old, new, 1))
print("strict nDPI BitTorrent patch applied")

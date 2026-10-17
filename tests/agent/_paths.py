import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for sub in ("agent", "panel", "tests/support"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)

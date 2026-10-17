"""Ezhik Guard node agent.

Runs on every protected Xray / RemnaNode server. Pure standard library so it
works with the system Python of Ubuntu 22.04 (3.10) and 24.04 (3.12) without
pip or virtual environments.
"""

from pathlib import Path


def _read_version():
    here = Path(__file__).resolve().parent
    for candidate in (here / "VERSION", here.parent / "VERSION", here.parent.parent / "VERSION"):
        try:
            value = candidate.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
    return "0.0.0"


__version__ = _read_version()

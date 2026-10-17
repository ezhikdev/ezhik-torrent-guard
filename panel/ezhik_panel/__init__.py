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

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("ezhik.agent")


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, value, mode=0o600):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def run(argv, timeout=60, check=False, input_text=None):
    """Run a command and never raise on a missing binary."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except FileNotFoundError as exc:
        result = subprocess.CompletedProcess(argv, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        result = subprocess.CompletedProcess(argv, 124, exc.stdout or "", f"timeout after {timeout}s")
    if check and result.returncode != 0:
        raise CommandError(argv, result)
    return result


class CommandError(RuntimeError):
    def __init__(self, argv, result):
        details = (result.stderr or result.stdout or "").strip().replace("\n", " ")
        if len(details) > 400:
            details = details[:397] + "..."
        self.result = result
        super().__init__(f"{' '.join(map(str, argv[:3]))} failed with code {result.returncode}: {details}")


def short_error(exc, limit=500):
    text = str(exc) or exc.__class__.__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."

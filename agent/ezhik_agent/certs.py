"""TLS certificate delivery to Xray on the node.

Ported from Ezhik Cert Manager's agent: validate, back up, atomically
replace, apply to the runtime (Docker container or systemd unit) and roll
back on any failure. The host copy in ``dir`` is canonical; a recreated
container is re-seeded from it automatically.
"""

import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from . import paths
from .util import CommandError, run

log = logging.getLogger("ezhik.certs")

CERT_FILES = (("fullchain.pem", 0o644), ("privkey.pem", 0o600))
DEFAULT_TARGET = {
    "mode": "auto",            # auto | docker | systemd | files
    "dir": "/etc/xray/ssl",    # canonical host directory
    "container": "remnanode",
    "container_dir": "/etc/xray/ssl",
    "apply": "restart",        # restart | none (hot reload via Xray ocspStapling) | command
    "command": "",
}


class CertError(RuntimeError):
    pass


def target_config(raw):
    cfg = dict(DEFAULT_TARGET)
    cfg.update({k: v for k, v in (raw or {}).items() if v not in (None, "")})
    for key in ("dir", "container_dir"):
        if not str(cfg[key]).startswith("/") or ".." in Path(cfg[key]).parts:
            raise CertError(f"{key} must be an absolute path")
    if not re.fullmatch(r"[A-Za-z0-9@_.-]+", str(cfg["container"])):
        raise CertError("container name contains unsupported characters")
    return cfg


def _openssl(args, stdin=None):
    result = run(["openssl", *args], timeout=30, input_text=stdin)
    if result.returncode != 0:
        raise CertError(f"openssl {args[0]} failed: {(result.stderr or '').strip()[:200]}")
    return result.stdout


def inspect_pair(cert_pem, key_pem):
    """Return (dns_names, not_after) and verify that the key matches."""
    if "PRIVATE KEY" not in key_pem or "BEGIN CERTIFICATE" not in cert_pem:
        raise CertError("bundle is not PEM")
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "c.pem"
        key_path = Path(tmp) / "k.pem"
        cert_path.write_text(cert_pem, encoding="ascii")
        key_path.write_text(key_pem, encoding="ascii")
        os.chmod(key_path, 0o600)
        cert_pub = _openssl(["x509", "-noout", "-pubkey", "-in", str(cert_path)])
        key_pub = _openssl(["pkey", "-pubout", "-in", str(key_path)])
        if cert_pub.strip() != key_pub.strip():
            raise CertError("certificate and private key do not match")
        text = _openssl(["x509", "-noout", "-text", "-in", str(cert_path)])
        end = _openssl(["x509", "-noout", "-enddate", "-in", str(cert_path)])
    names = set(re.findall(r"DNS:([^,\s]+)", text))
    not_after = end.strip().split("=", 1)[-1]
    return names, not_after


def covers(names, domain):
    domain = domain.lower().rstrip(".")
    if domain in names:
        return True
    labels = domain.split(".", 1)
    return len(labels) == 2 and f"*.{labels[1]}" in names


def detect_runtime(cfg):
    if cfg["mode"] in ("docker", "systemd", "files"):
        return cfg["mode"]
    name = cfg["container"]
    unit = run(["systemctl", "show", "--property=LoadState", "--value", name], timeout=20)
    if unit.returncode == 0 and unit.stdout.strip() not in ("", "not-found"):
        return "systemd"
    container = run(["docker", "inspect", "--format", "{{.State.Running}}", name], timeout=20)
    if container.returncode == 0 and container.stdout.strip() in ("true", "false"):
        return "docker"
    return "files"


def _require(label, result):
    if result.returncode != 0:
        raise CertError(f"{label}: {(result.stderr or result.stdout or '').strip()[:300]}")


def copy_to_docker(cfg, source_dir):
    name, cdir = cfg["container"], cfg["container_dir"]
    mk = run(["docker", "exec", name, "mkdir", "-p", cdir])
    if mk.returncode != 0:
        # Stopped container: docker cp can still create the directory.
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / Path(cdir).name
            staging.mkdir(mode=0o755)
            for filename, mode in CERT_FILES:
                shutil.copy2(source_dir / filename, staging / filename)
                os.chmod(staging / filename, mode)
            _require("docker cp", run(["docker", "cp", str(staging), f"{name}:{Path(cdir).parent}/"]))
        return
    for filename, mode in CERT_FILES:
        _require(f"copy {filename}", run(["docker", "cp", str(source_dir / filename), f"{name}:{cdir}/{filename}"]))
        _require(f"chmod {filename}", run(["docker", "exec", name, "chmod", f"{mode:o}", f"{cdir}/{filename}"]))


def remove_from_docker(cfg):
    for filename, _mode in CERT_FILES:
        run(["docker", "exec", cfg["container"], "rm", "-f", f"{cfg['container_dir']}/{filename}"])


def docker_matches_host(cfg, source_dir):
    for filename, _mode in CERT_FILES:
        source = source_dir / filename
        if not source.is_file():
            return False
        result = run(["docker", "exec", cfg["container"], "cat", f"{cfg['container_dir']}/{filename}"])
        if result.returncode != 0 or result.stdout != source.read_text(encoding="ascii"):
            return False
    return True


def process_list_has_xray(processes):
    for line in processes.lower().splitlines():
        command = line.replace("\\", "/")
        if "/xray " in command or "/rw-core " in command or command.endswith("/xray") or command.endswith("/rw-core"):
            return True
        if " -config http+unix:///run/remnawave-internal-" in command:
            return True
    return False


def restart_docker(cfg, attempts=20):
    import time

    name = cfg["container"]
    _require(f"restart {name}", run(["docker", "restart", name], timeout=120))
    reason = "container is not running"
    for attempt in range(attempts):
        running = run(["docker", "inspect", "--format", "{{.State.Running}}", name], timeout=20)
        if running.returncode == 0 and running.stdout.strip() == "true":
            top = run(["docker", "top", name], timeout=20)
            # Never include process output in errors: Remnawave's command line
            # can contain an internal token.
            if top.returncode == 0 and process_list_has_xray(top.stdout):
                return
            reason = "Xray process not found after restart"
        if attempt + 1 < attempts:
            time.sleep(1.5)
    raise CertError(f"{name}: {reason}")


def apply(cfg, runtime, directory):
    if cfg["apply"] == "command" and cfg.get("command"):
        import shlex

        _require("reload command", run(shlex.split(cfg["command"]), timeout=120))
        return
    if runtime == "docker":
        copy_to_docker(cfg, directory)
        if cfg["apply"] == "restart":
            restart_docker(cfg)
    elif runtime == "systemd" and cfg["apply"] == "restart":
        unit = cfg["container"]
        if run(["systemctl", "reload", unit], timeout=90).returncode != 0:
            _require(f"restart {unit}", run(["systemctl", "restart", unit], timeout=120))
        _require(f"{unit} active", run(["systemctl", "is-active", "--quiet", unit], timeout=20))


def install(bundle, raw_target):
    """Install a certificate bundle; roll back on failure. Returns not_after."""
    cfg = target_config(raw_target)
    cert_pem, key_pem = bundle["fullchain_pem"], bundle["privkey_pem"]
    names, not_after = inspect_pair(cert_pem, key_pem)
    for domain in bundle.get("domains") or []:
        if domain not in names:
            raise CertError(f"certificate does not contain {domain}")

    runtime = detect_runtime(cfg)
    directory = paths.p(cfg["dir"])
    directory.mkdir(parents=True, exist_ok=True)
    backup = directory / ".ezhik-backup"
    if backup.exists():
        shutil.rmtree(backup)
    backup.mkdir(mode=0o700)
    for filename, _mode in CERT_FILES:
        if (directory / filename).exists():
            shutil.copy2(directory / filename, backup / filename)
    try:
        with tempfile.TemporaryDirectory(dir=directory) as tmp:
            for (filename, mode), content in zip(CERT_FILES, (cert_pem, key_pem)):
                staged = Path(tmp) / filename
                staged.write_text(content, encoding="ascii")
                os.chmod(staged, mode)
                os.replace(staged, directory / filename)
        apply(cfg, runtime, directory)
    except Exception as install_error:
        for filename, _mode in CERT_FILES:
            if (backup / filename).exists():
                os.replace(backup / filename, directory / filename)
            else:
                (directory / filename).unlink(missing_ok=True)
        try:
            if runtime == "docker":
                if all((directory / f).exists() for f, _ in CERT_FILES):
                    copy_to_docker(cfg, directory)
                else:
                    remove_from_docker(cfg)
                if cfg["apply"] == "restart":
                    restart_docker(cfg)
            else:
                apply(cfg, runtime, directory)
        except Exception as rollback_error:
            raise CertError(f"{install_error}; rollback failed: {rollback_error}") from install_error
        raise
    finally:
        shutil.rmtree(backup, ignore_errors=True)
    log.info("Certificate %s v%s installed (%s)", bundle.get("certificate_id"), bundle.get("version"), runtime)
    return not_after


def remove(raw_target):
    """Stop using a certificate on this node: delete files and re-apply."""
    cfg = target_config(raw_target)
    runtime = detect_runtime(cfg)
    directory = paths.p(cfg["dir"])
    for filename, _mode in CERT_FILES:
        (directory / filename).unlink(missing_ok=True)
    if runtime == "docker":
        remove_from_docker(cfg)
        if cfg["apply"] == "restart":
            restart_docker(cfg)
    elif runtime == "systemd" and cfg["apply"] == "restart":
        run(["systemctl", "restart", cfg["container"]], timeout=120)


def restore_container_copy(raw_target):
    """Re-seed a recreated container from the canonical host copy."""
    cfg = target_config(raw_target)
    directory = paths.p(cfg["dir"])
    if not all((directory / f).is_file() for f, _ in CERT_FILES):
        return False
    if detect_runtime(cfg) != "docker":
        return False
    if docker_matches_host(cfg, directory):
        return False
    copy_to_docker(cfg, directory)
    if cfg["apply"] == "restart":
        restart_docker(cfg)
    return True


def installed_fingerprint(raw_target):
    cfg = target_config(raw_target)
    cert = paths.p(cfg["dir"]) / "fullchain.pem"
    if not cert.is_file():
        return None
    try:
        out = _openssl(["x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert)])
        return out.strip().split("=", 1)[-1].replace(":", "").lower()
    except CertError:
        return None


__all__ = ["CertError", "CommandError", "install", "remove", "restore_container_copy", "covers"]

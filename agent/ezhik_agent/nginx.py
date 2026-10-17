"""Nginx frontend in front of Xray (per-node mode "frontend").

Direct mode leaves Nginx alone (or stops the Nginx we installed ourselves).
Frontend mode writes one managed file, validates it with ``nginx -t``,
reloads, verifies real responses and restores the previous state on any
failure. Foreign Nginx configs are never edited; the stock Ubuntu default
site is disabled (and restored later) only because it would claim port 80.
"""

import logging
import re
import shutil
import ssl
import socket
import time
from pathlib import Path

from . import certs, paths, ports, site, system
from .util import atomic_write, run

log = logging.getLogger("ezhik.nginx")

CONF = paths.p("/etc/nginx/conf.d/ezhik-guard.conf")
DEFAULT_SITE = paths.p("/etc/nginx/sites-enabled/default")
STATE_DIR = paths.STATE_DIR / "nginx"
SITE_ROOT = paths.p("/var/www/ezhik-guard-site")
SELF_SIGNED = paths.CONFIG_DIR / "nginx"
HTTP_TRANSPORTS = {"grpc", "ws", "httpupgrade", "xhttp"}
NAME_RE = re.compile(r"^[A-Za-z0-9._~-]{1,100}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")


class NginxError(RuntimeError):
    pass


# ----------------------------------------------------------------- render


def validate_route(route):
    transport = route.get("transport")
    if transport not in HTTP_TRANSPORTS:
        raise NginxError(f"транспорт {transport!r} нельзя направить через HTTP location Nginx "
                         "(REALITY/RAW/TCP/KCP/QUIC работают только напрямую в Xray)")
    port = int(route.get("public_port") or 443)
    if not 1 <= port <= 65535 or port == 80:
        raise NginxError(f"недопустимый публичный порт {port}")
    upstream_port = int(route.get("upstream_port") or 0)
    if not 1 <= upstream_port <= 65535:
        raise NginxError("укажите внутренний порт Xray")
    host = str(route.get("upstream_host") or "127.0.0.1")
    if not re.fullmatch(r"[A-Za-z0-9.:\[\]-]{1,100}", host):
        raise NginxError("недопустимый внутренний адрес Xray")
    if transport == "grpc":
        if not NAME_RE.match(str(route.get("service_name") or "")):
            raise NginxError("serviceName: латиница, цифры и ._~-")
    else:
        if not PATH_RE.match(str(route.get("path") or "")):
            raise NginxError("path должен начинаться с / и содержать только латиницу, цифры и ._~/-")
    return port, host, upstream_port


def _upstream(host, port):
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def _location(route):
    port, host, upstream_port = validate_route(route)
    target = _upstream(host, upstream_port)
    transport = route["transport"]
    if transport == "grpc":
        name = route["service_name"]
        return port, f"""
    # gRPC {name} -> Xray {target} (TLS terminated here, plain h2c inside)
    location ~ ^/{re.escape(name)}/(Tun|TunMulti)$ {{
        if ($content_type !~ "^application/grpc") {{ return 404; }}
        client_max_body_size 0;
        client_body_timeout 1h;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_pass grpc://{target};
    }}"""
    path = route["path"].rstrip("/") or "/"
    if transport in ("ws", "httpupgrade"):
        return port, f"""
    # {transport} {path} -> Xray {target}
    location = {path} {{
        if ($http_upgrade = "") {{ return 404; }}
        proxy_pass http://{target};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }}"""
    return port, f"""
    # xhttp {path} -> Xray {target}
    location ^~ {path}/ {{
        client_max_body_size 0;
        proxy_pass http://{target};
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }}"""


def render(cfg, cert_file, key_file):
    routes = [r for r in cfg.get("routes") or [] if r.get("enabled", True)]
    by_port = {}
    for route in routes:
        port, block = _location(route)
        by_port.setdefault(port, []).append(block)
    https_ports = sorted(set(by_port) | {443})
    server_name = cfg.get("server_name") or "_"
    if server_name != "_" and not re.fullmatch(r"[A-Za-z0-9.*-]{1,253}", server_name):
        raise NginxError("недопустимое имя сервера")
    root = SITE_ROOT / "current"
    out = ["# Managed by Ezhik Guard agent. Manual changes are overwritten.", ""]
    if cfg.get("http_redirect", True):
        out.append("""server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location / { return 301 https://$host$request_uri; }
}""")
    for port in https_ports:
        out.append(f"""
server {{
    listen {port} ssl http2 default_server;
    listen [::]:{port} ssl http2 default_server;
    server_name {server_name};

    ssl_certificate {cert_file};
    ssl_certificate_key {key_file};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:EZHIK_GUARD:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    root {root};
    index index.html index.htm;
{''.join(by_port.get(port, []))}

    # Everything else is the stub site.
    location / {{
        try_files $uri $uri/ $uri.html /index.html;
    }}
}}""")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- helpers


def installed():
    return shutil.which("nginx") is not None or (paths.ROOT != Path("/") and (paths.p("/usr/sbin/nginx")).exists())


def _nginx(*args, timeout=60):
    return run(["nginx", *args], timeout=timeout)


def _is_stock_default(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "root /var/www/html;" in text and "default_server" in text and "server_name _;" in text


def foreign_listeners(wanted):
    """Ports from `wanted` that other (non-Ezhik) nginx configs already listen on."""
    result = _nginx("-T", timeout=30)
    text = result.stdout or ""
    conflicts = set()
    current_file = None
    for line in text.splitlines():
        if line.startswith("# configuration file "):
            current_file = line[len("# configuration file "):].rstrip(":")
            continue
        if current_file is None or current_file.endswith("ezhik-guard.conf") or current_file.endswith("sites-enabled/default"):
            continue
        conflicts.update((port, current_file) for port in listen_ports(line) if port in wanted)
    return sorted(conflicts)


def listen_ports(line):
    """Ports of every `listen` directive on a config line (one-line servers too)."""
    code = line.split("#", 1)[0]
    ports = []
    for match in re.finditer(r"(?:^|[;{\s])listen\s+([^;\s]+)", code):
        target = match.group(1)
        port = target.rsplit(":", 1)[-1] if ":" in target and not target.endswith("]") else target
        if port.isdigit():
            ports.append(int(port))
        elif not any(ch.isdigit() for ch in target.rsplit(":", 1)[-1]):
            ports.append(80)  # host-only or unix socket form -> default port 80
    return ports


def ensure_selfsigned():
    cert, key = SELF_SIGNED / "selfsigned.pem", SELF_SIGNED / "selfsigned.key"
    if not cert.exists() or not key.exists():
        SELF_SIGNED.mkdir(parents=True, exist_ok=True)
        result = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                      "-nodes", "-days", "3650", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                     timeout=60)
        if result.returncode != 0:
            raise NginxError("не удалось создать временный сертификат: " + (result.stderr or "")[:200])
        key.chmod(0o600)
    return cert, key


def _probe(port, path="/", grpc=False, timeout=6):
    """HTTPS request to 127.0.0.1:port; returns the HTTP status code."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if grpc:
        result = run(["curl", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
                      "-H", "content-type: application/grpc", "--max-time", str(timeout),
                      f"https://127.0.0.1:{port}{path}"], timeout=timeout + 5)
        return int(result.stdout or 0) if (result.stdout or "").isdigit() else 0
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
            head = tls.recv(64).decode("latin-1")
    match = re.match(r"HTTP/1\.[01] (\d{3})", head)
    return int(match.group(1)) if match else 0


def _tcp_open(host, port, timeout=3):
    try:
        with socket.create_connection((host.strip("[]"), port), timeout=timeout):
            return True
    except OSError:
        return False


# ------------------------------------------------------------------ apply


class NginxManager:
    def __init__(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.marker_installed = STATE_DIR / "installed-by-ezhik"
        self.marker_default = STATE_DIR / "default-site.disabled"
        self.last = {}

    def _restore_default_site(self):
        backup = STATE_DIR / "default-site.link"
        if self.marker_default.exists() and backup.exists() and not DEFAULT_SITE.exists():
            target = backup.read_text(encoding="utf-8").strip()
            DEFAULT_SITE.symlink_to(target)
        self.marker_default.unlink(missing_ok=True)

    def apply(self, cfg, cert_target, container_network, state):
        mode = (cfg or {}).get("mode") or "direct"
        if mode == "frontend":
            return self._frontend(cfg, cert_target, container_network, state)
        return self._direct(state)

    def _direct(self, state):
        if not CONF.exists():
            if self.marker_installed.exists() and system.unit_active("nginx.service"):
                system.systemctl("disable", "--now", "nginx.service")
            return "direct (Nginx не используется)"
        backup = STATE_DIR / "conf.backup"
        shutil.copy2(CONF, backup)
        CONF.unlink()
        self._restore_default_site()
        if self.marker_installed.exists():
            system.systemctl("disable", "--now", "nginx.service")
        else:
            test = _nginx("-t")
            if test.returncode != 0:
                shutil.copy2(backup, CONF)
                raise NginxError("после удаления конфигурации nginx -t не проходит: " + (test.stderr or "")[-300:])
            system.systemctl("reload", "nginx.service")
        state.pop("nginx_hash", None)
        log.info("Nginx frontend disabled; Xray serves its ports directly")
        return "direct: frontend выключен"

    def _frontend(self, cfg, cert_target, container_network, state):
        routes = [r for r in cfg.get("routes") or [] if r.get("enabled", True)]
        for route in routes:
            validate_route(route)
            host = str(route.get("upstream_host") or "127.0.0.1")
            if host.startswith("127.") or host in ("::1", "localhost"):
                if container_network and container_network != "host":
                    raise NginxError(f"контейнер RemnaNode в сети {container_network!r}: адрес {host} "
                                     "из контейнера недоступен. Используйте IP контейнера или опубликованный порт.")
        if not installed():
            system.ensure_packages(["nginx"])
            self.marker_installed.write_text("1", encoding="utf-8")
        wanted = sorted({int(r.get("public_port") or 443) for r in routes} | {443}
                        | ({80} if cfg.get("http_redirect", True) else set()))
        busy = []
        for port in wanted:
            owner = ports.port_busy(port, "tcp", ignore_roles=("nginx",))
            if owner:
                busy.append(f"{port} ({owner['process'] or owner['role']})")
        if busy:
            raise NginxError("порты заняты другими процессами: " + ", ".join(busy)
                             + ". Для Xray переведите inbound на внутренний адрес/порт.")
        conflicts = foreign_listeners(set(wanted))
        if conflicts and not cfg.get("force"):
            raise NginxError("другие конфигурации Nginx уже слушают эти порты: "
                             + ", ".join(f"{p} в {f}" for p, f in conflicts))

        cert_dir = paths.p(certs.target_config(cert_target).get("dir", "/etc/xray/ssl"))
        cert_file, key_file = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
        tls_note = ""
        if not (cert_file.exists() and key_file.exists()):
            cert_file, key_file = ensure_selfsigned()
            tls_note = " · временный самоподписанный сертификат"
        site.ensure_default()

        text = render(cfg, cert_file, key_file)
        import hashlib

        digest = hashlib.sha256((text + str(cert_file.stat().st_mtime)).encode()).hexdigest()[:16]
        if CONF.exists() and state.get("nginx_hash") == digest and system.unit_active("nginx.service"):
            return f"frontend: {len(routes)} маршрут(ов){tls_note}"

        backup = STATE_DIR / "conf.backup"
        had_conf = CONF.exists()
        if had_conf:
            shutil.copy2(CONF, backup)
        disabled_default = False
        if DEFAULT_SITE.is_symlink() or DEFAULT_SITE.exists():
            if _is_stock_default(DEFAULT_SITE) or cfg.get("force"):
                link = DEFAULT_SITE.resolve() if DEFAULT_SITE.is_symlink() else DEFAULT_SITE
                (STATE_DIR / "default-site.link").write_text(str(link), encoding="utf-8")
                DEFAULT_SITE.unlink()
                self.marker_default.write_text("1", encoding="utf-8")
                disabled_default = True

        def rollback(reason):
            if had_conf:
                shutil.copy2(backup, CONF)
            else:
                CONF.unlink(missing_ok=True)
            if disabled_default:
                self._restore_default_site()
            if _nginx("-t").returncode == 0:
                system.systemctl("reload", "nginx.service")
            raise NginxError(reason + " — восстановлена предыдущая конфигурация")

        atomic_write(CONF, text, 0o644)
        test = _nginx("-t")
        if test.returncode != 0:
            rollback("nginx -t: " + (test.stderr or test.stdout or "").strip()[-400:])
        system.systemctl("enable", "nginx.service")
        if system.unit_active("nginx.service"):
            result = system.systemctl("reload", "nginx.service")
        else:
            result = system.systemctl("start", "nginx.service")
        if result.returncode != 0:
            rollback("Nginx не перезапустился: " + system.unit_failure_hint("nginx.service"))
        time.sleep(1)
        checks = []
        try:
            status = _probe(443)
            if status not in (200, 301, 302, 403):
                rollback(f"заглушка на 443 ответила HTTP {status}")
            checks.append(f"443 → {status}")
            for route in routes:
                if route["transport"] == "grpc":
                    code = _probe(int(route.get("public_port") or 443), f"/{route['service_name']}/Tun", grpc=True)
                    reachable = _tcp_open(str(route.get("upstream_host") or "127.0.0.1"), int(route["upstream_port"]))
                    route_state = "ok" if reachable else "Xray не слушает внутренний порт"
                    checks.append(f"grpc {route['service_name']}: HTTP {code}, upstream {route_state}")
                else:
                    reachable = _tcp_open(str(route.get("upstream_host") or "127.0.0.1"), int(route["upstream_port"]))
                    checks.append(f"{route['transport']} {route['path']}: upstream {'ok' if reachable else 'не отвечает'}")
        except NginxError:
            raise
        except Exception as exc:
            rollback(f"проверка HTTPS не прошла: {exc}")
        state["nginx_hash"] = digest
        self.last = {"checks": checks, "at": time.time()}
        log.info("Nginx frontend applied: %s", "; ".join(checks))
        return f"frontend: {len(routes)} маршрут(ов){tls_note}"


def container_network(name):
    result = run(["docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", name], timeout=20)
    return result.stdout.strip() if result.returncode == 0 else None

"""Nginx in front of / behind Xray (per-node Nginx mode).

* direct   — Nginx is left alone (or the Nginx we installed is stopped);
* frontend — Nginx terminates TLS on 443 and proxies HTTP transports to Xray;
* vision   — Xray terminates TLS on 443 (VLESS RAW + TLS + XTLS Vision) and its
  fallbacks hand ordinary HTTPS visitors to Nginx on local ports
  (HTTP/1.1 and h2c, PROXY protocol), which serves the stub site and the
  HTTP routes of port 443.

Every apply writes one managed file, validates it with ``nginx -t``, reloads,
verifies real responses and restores the previous state on any failure.
Foreign Nginx configs are never edited; the stock Ubuntu default site is
disabled (and restored later) only because it would claim port 80.
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


def _routes_by_port(cfg):
    by_port = {}
    for route in cfg.get("routes") or []:
        if route.get("enabled", True):
            port, block = _location(route)
            by_port.setdefault(port, []).append(block)
    return by_port


def _server_name(cfg):
    server_name = cfg.get("server_name") or "_"
    if server_name != "_" and not re.fullmatch(r"[A-Za-z0-9.*-]{1,253}", server_name):
        raise NginxError("недопустимое имя сервера")
    return server_name


REDIRECT_SERVER = """server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location / { return 301 https://$host$request_uri; }
}"""

SITE_LOCATION = """
    # Everything else is the stub site.
    location / {
        try_files $uri $uri/ $uri.html /index.html;
    }"""


def _tls_server(port, server_name, cert_file, key_file, blocks):
    return f"""
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
    root {SITE_ROOT / "current"};
    index index.html index.htm;
{''.join(blocks)}
{SITE_LOCATION}
}}"""


def render(cfg, cert_file, key_file):
    by_port = _routes_by_port(cfg)
    server_name = _server_name(cfg)
    out = ["# Managed by Ezhik Guard agent. Manual changes are overwritten.", ""]
    if cfg.get("http_redirect", True):
        out.append(REDIRECT_SERVER)
    for port in sorted(set(by_port) | {443}):
        out.append(_tls_server(port, server_name, cert_file, key_file, by_port.get(port, [])))
    return "\n".join(out) + "\n"


def vision_settings(cfg):
    vision = dict(cfg.get("vision") or {})
    vision.setdefault("http1_port", 8001)
    vision.setdefault("h2_port", 8002)
    vision.setdefault("h2", True)
    vision.setdefault("proxy_protocol", True)
    for key in ("http1_port", "h2_port"):
        if not 1024 <= int(vision[key]) <= 65535:
            raise NginxError("локальные порты fallback: 1024–65535")
    return vision


def render_vision(cfg, cert_file, key_file):
    """Xray owns 443; its fallbacks reach this config on 127.0.0.1 only."""
    vision = vision_settings(cfg)
    by_port = _routes_by_port(cfg)
    server_name = _server_name(cfg)
    pp = " proxy_protocol" if vision["proxy_protocol"] else ""
    listens = [f"    listen 127.0.0.1:{vision['http1_port']}{pp} default_server;"]
    if vision["h2"]:
        listens.append(f"    listen 127.0.0.1:{vision['h2_port']} http2{pp} default_server;")
    real_ip = ("\n    # Real visitor address from Xray (fallback xver 1).\n"
               "    set_real_ip_from 127.0.0.1;\n    real_ip_header proxy_protocol;") if vision["proxy_protocol"] else ""
    out = ["# Managed by Ezhik Guard agent. Manual changes are overwritten.",
           "# Mode: VLESS RAW + TLS + XTLS Vision on Xray :443, fallbacks -> this Nginx.", ""]
    if cfg.get("http_redirect", True):
        out.append(REDIRECT_SERVER)
    out.append(f"""
# Fallback target for Xray :443 (TLS is already terminated by Xray).
server {{
{chr(10).join(listens)}
    server_name _;{real_ip}

    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    root {SITE_ROOT / "current"};
    index index.html index.htm;
{''.join(by_port.get(443, []))}
{SITE_LOCATION}
}}""")
    for port in sorted(p for p in by_port if p != 443):
        out.append(_tls_server(port, server_name, cert_file, key_file, by_port[port]))
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


def _curl_code(args, timeout=8):
    """(status, http_version) of a curl request; (0, "") when it failed."""
    result = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{http_version}", "--max-time", str(timeout),
                  *args], timeout=timeout + 5)
    parts = (result.stdout or "").split()
    if len(parts) == 2 and parts[0].isdigit():
        return int(parts[0]), parts[1]
    return 0, ""


def probe_fallback(port, proxy_protocol, h2):
    args = ["--haproxy-protocol"] if proxy_protocol else []
    args += ["--http2-prior-knowledge"] if h2 else ["--http1.1"]
    return _curl_code(args + [f"http://127.0.0.1:{port}/"])


def probe_vision_443(server_name, alpn_h2):
    """Ordinary HTTPS visitor through Xray :443 -> fallback -> Nginx."""
    host = server_name if server_name and server_name != "_" and "*" not in server_name else "localhost"
    return _curl_code(["-k", "--resolve", f"{host}:443:127.0.0.1", "--http2" if alpn_h2 else "--http1.1",
                       f"https://{host}/"])


def cert_in_container(cert_target, network=None):
    """True/False when the Xray container can read the node certificate; None if unknown."""
    try:
        cfg = certs.target_config(cert_target)
    except Exception:
        return None
    check = run(["docker", "inspect", "--format", "{{.State.Running}}", cfg["container"]], timeout=20)
    if check.returncode != 0:
        # No container (systemd Xray): the host files are what Xray reads.
        host = paths.p(cfg["dir"])
        return (host / "fullchain.pem").exists() and (host / "privkey.pem").exists()
    if check.stdout.strip() != "true":
        return None
    result = run(["docker", "exec", cfg["container"], "sh", "-c",
                  f"test -r {cfg['container_dir']}/fullchain.pem && test -r {cfg['container_dir']}/privkey.pem"],
                 timeout=20)
    return result.returncode == 0


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
        if mode == "vision":
            return self._vision(cfg, cert_target, container_network, state)
        self.last = {"mode": "direct", "at": time.time()}
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
                             + ". Для Xray переведите inbound на внутренний адрес/порт"
                             + (" (если это inbound режима Vision — сначала уберите его с 443 в Remnawave)"
                                if any(b.startswith("443 ") for b in busy) else "") + ".")
        conflicts = foreign_listeners(set(wanted))
        if conflicts and not cfg.get("force"):
            raise NginxError("другие конфигурации Nginx уже слушают эти порты: "
                             + ", ".join(f"{p} в {f}" for p, f in conflicts))

        cert_file, key_file, tls_note = self._tls_files(cert_target)
        site.ensure_default()
        text = render(cfg, cert_file, key_file)
        digest = _digest(text, cert_file)
        if CONF.exists() and state.get("nginx_hash") == digest and system.unit_active("nginx.service"):
            return f"frontend: {len(routes)} маршрут(ов){tls_note}"

        def verify():
            checks = []
            status = _probe(443)
            if status not in (200, 301, 302, 403):
                raise NginxError(f"заглушка на 443 ответила HTTP {status}")
            checks.append(f"443 → {status}")
            for route in routes:
                reachable = _tcp_open(str(route.get("upstream_host") or "127.0.0.1"), int(route["upstream_port"]))
                if route["transport"] == "grpc":
                    code = _probe(int(route.get("public_port") or 443), f"/{route['service_name']}/Tun", grpc=True)
                    checks.append(f"grpc {route['service_name']}: HTTP {code}, upstream "
                                  f"{'ok' if reachable else 'Xray не слушает внутренний порт'}")
                else:
                    checks.append(f"{route['transport']} {route['path']}: upstream {'ok' if reachable else 'не отвечает'}")
            return checks

        checks = self._install(text, cfg, verify)
        state["nginx_hash"] = digest
        self.last = {"mode": "frontend", "checks": checks, "at": time.time()}
        log.info("Nginx frontend applied: %s", "; ".join(checks))
        return f"frontend: {len(routes)} маршрут(ов){tls_note}"

    # shared ----------------------------------------------------------

    def _tls_files(self, cert_target):
        cert_dir = paths.p(certs.target_config(cert_target).get("dir", "/etc/xray/ssl"))
        cert_file, key_file = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
        if cert_file.exists() and key_file.exists():
            return cert_file, key_file, ""
        cert_file, key_file = ensure_selfsigned()
        return cert_file, key_file, " · временный самоподписанный сертификат"

    def _install(self, text, cfg, verify):
        """Write the managed config, reload, verify; restore the previous state on failure."""
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
        try:
            return verify()
        except NginxError as exc:
            rollback(str(exc))
        except Exception as exc:
            rollback(f"проверка не прошла: {exc}")

    # vision ----------------------------------------------------------

    def _vision(self, cfg, cert_target, container_network, state):
        vision = vision_settings(cfg)
        routes = [r for r in cfg.get("routes") or [] if r.get("enabled", True)]
        for route in routes:
            validate_route(route)
        if container_network and container_network != "host":
            raise NginxError(f"контейнер RemnaNode в сети {container_network!r}: fallback Xray на 127.0.0.1 "
                             "не дойдёт до Nginx. Нужна сеть host (как в стандартной установке RemnaNode).")
        # The Xray inbound will read the certificate inside the container: check before touching anything.
        in_container = cert_in_container(cert_target, container_network)
        self.last = {**self.last, "mode": "vision", "cert_in_container": in_container}
        if in_container is False:
            ccfg = certs.target_config(cert_target)
            raise NginxError(f"сертификата нет внутри контейнера {ccfg['container']} ({ccfg['container_dir']}). "
                             "Назначьте сертификат ноде и выберите установку в Docker-контейнер.")
        if not installed():
            system.ensure_packages(["nginx"])
            self.marker_installed.write_text("1", encoding="utf-8")
        public = sorted({int(r.get("public_port") or 443) for r in routes} - {443}
                        | ({80} if cfg.get("http_redirect", True) else set()))
        local = [vision["http1_port"]] + ([vision["h2_port"]] if vision["h2"] else [])
        busy = []
        for port in public + local:
            owner = ports.port_busy(port, "tcp", ignore_roles=("nginx",))
            if owner:
                busy.append(f"{port} ({owner['process'] or owner['role']})")
        owner443 = ports.port_busy(443, "tcp", ignore_roles=("nginx", "xray"))
        if owner443:
            busy.append(f"443 ({owner443['process'] or owner443['role']})")
        if busy:
            raise NginxError("порты заняты другими процессами: " + ", ".join(busy))
        conflicts = foreign_listeners(set(public + local))
        if conflicts and not cfg.get("force"):
            raise NginxError("другие конфигурации Nginx уже слушают эти порты: "
                             + ", ".join(f"{p} в {f}" for p, f in conflicts))

        cert_file, key_file, _note = self._tls_files(cert_target)
        site.ensure_default()
        text = render_vision(cfg, cert_file, key_file)
        digest = _digest(text, cert_file)

        def verify():
            checks = []
            code, version = probe_fallback(vision["http1_port"], vision["proxy_protocol"], False)
            if code not in (200, 301, 302, 403):
                raise NginxError(f"fallback HTTP/1.1 127.0.0.1:{vision['http1_port']} ответил {code or 'ошибкой'}")
            checks.append(f"fallback HTTP/1.1 → {code}")
            if vision["h2"]:
                code, version = probe_fallback(vision["h2_port"], vision["proxy_protocol"], True)
                if code not in (200, 301, 302, 403) or version != "2":
                    raise NginxError(f"fallback HTTP/2 127.0.0.1:{vision['h2_port']} ответил {code or 'ошибкой'}")
                checks.append(f"fallback h2c → {code}")
            for route in routes:
                reachable = _tcp_open(str(route.get("upstream_host") or "127.0.0.1"), int(route["upstream_port"]))
                where = "через fallback" if int(route.get("public_port") or 443) == 443 else f":{route['public_port']}"
                checks.append(f"{route['transport']} {route.get('service_name') or route.get('path')} ({where}): "
                              f"upstream {'ok' if reachable else 'не отвечает'}")
            return checks

        if not (CONF.exists() and state.get("nginx_hash") == digest and system.unit_active("nginx.service")):
            checks = self._install(text, cfg, verify)
            state["nginx_hash"] = digest
            log.info("Nginx vision fallback applied: %s", "; ".join(checks))
        else:
            checks = self.last.get("checks") or verify()
        e2e = self.vision_e2e(cfg)
        self.last = {"mode": "vision", "checks": checks, "fallback_ok": True, "cert_in_container": in_container,
                     "e2e": e2e, "at": time.time()}
        return "vision: " + e2e["summary"]

    def vision_e2e(self, cfg):
        """State of Xray :443 as an ordinary browser sees it."""
        owner = ports.port_busy(443, "tcp")
        if not owner:
            return {"ok": False, "summary": "fallback готов, ждёт inbound Xray на 443 (синхронизация с Remnawave)"}
        if owner["role"] != "xray":
            return {"ok": False, "summary": f"443 занят {owner['process'] or owner['role']}"}
        vision = vision_settings(cfg)
        h1 = probe_vision_443(cfg.get("server_name"), False)
        out = {"http1": h1[0]}
        if vision["h2"]:
            h2 = probe_vision_443(cfg.get("server_name"), True)
            out["h2"] = h2[0]
            out["h2_version"] = h2[1]
        good = h1[0] in (200, 301, 302, 403) and (not vision["h2"] or out["h2"] in (200, 301, 302, 403))
        out["ok"] = good
        out["summary"] = ("Xray :443 → сайт-заглушка: HTTP/1.1 " + str(h1[0])
                          + (f", HTTP/2 {out['h2']}" if vision["h2"] else "")) if good else \
            f"Xray слушает 443, но обычный HTTPS не доходит до сайта (HTTP/1.1 {h1[0]}" + \
            (f", HTTP/2 {out.get('h2')}" if vision["h2"] else "") + ") — проверьте fallbacks и сертификат inbound"
        return out


def _digest(text, cert_file):
    import hashlib

    return hashlib.sha256((text + str(cert_file.stat().st_mtime)).encode()).hexdigest()[:16]


def container_network(name):
    result = run(["docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", name], timeout=20)
    return result.stdout.strip() if result.returncode == 0 else None

"""Per-node Nginx modes: validation and Remnawave inbound compatibility.

* direct   — Nginx is not used;
* frontend — Nginx terminates TLS on 80/443 and proxies HTTP transports to Xray;
* vision   — Xray terminates TLS on 443 (VLESS RAW + TLS + XTLS Vision) and
  hands everything that is not VLESS to a local Nginx through fallbacks.
"""

import copy
import ipaddress
import re
import uuid

from .db import loads

HTTP_TRANSPORTS = {"grpc": "gRPC", "ws": "WebSocket", "httpupgrade": "HTTPUpgrade", "xhttp": "XHTTP"}
XRAY_NETWORK = {"grpc": "grpc", "ws": "ws", "httpupgrade": "httpupgrade", "xhttp": "xhttp"}
NAME_RE = re.compile(r"^[A-Za-z0-9._~-]{1,100}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:\[\]-]{1,100}$")


class RouteError(ValueError):
    pass


DEFAULT_VISION = {"inbound_tag": "", "http1_port": 8001, "h2_port": 8002, "h2": True, "proxy_protocol": True}
DEFAULT_NGINX = {"mode": "direct", "routes": [], "http_redirect": True, "server_name": "", "force": False,
                 "vision": dict(DEFAULT_VISION)}
MODES = ("direct", "frontend", "vision")
VISION_FLOW = "xtls-rprx-vision"


def validate_route(route):
    transport = route.get("transport")
    if transport not in HTTP_TRANSPORTS:
        raise RouteError("Через Nginx можно направить только gRPC, WebSocket, HTTPUpgrade и XHTTP. "
                         "REALITY, RAW/TCP, mKCP и QUIC работают только напрямую в Xray.")
    out = {
        "id": str(route.get("id") or uuid.uuid4().hex[:8])[:16],
        "enabled": bool(route.get("enabled", True)),
        "transport": transport,
        "public_port": int(route.get("public_port") or 443),
        "upstream_host": str(route.get("upstream_host") or "127.0.0.1").strip(),
        "upstream_port": int(route.get("upstream_port") or 0),
        "service_name": "",
        "path": "",
        "inbound_tag": str(route.get("inbound_tag") or "")[:100],
    }
    if not 1 <= out["public_port"] <= 65535 or out["public_port"] == 80:
        raise RouteError("Публичный порт: 1–65535, кроме 80 (он занят редиректом на HTTPS)")
    if not 1 <= out["upstream_port"] <= 65535:
        raise RouteError("Укажите внутренний порт Xray")
    if not HOST_RE.match(out["upstream_host"]):
        raise RouteError("Недопустимый внутренний адрес Xray")
    if transport == "grpc":
        out["service_name"] = str(route.get("service_name") or "").strip().strip("/")
        if not NAME_RE.match(out["service_name"]):
            raise RouteError("serviceName: латиница, цифры и символы ._~-")
    else:
        out["path"] = "/" + str(route.get("path") or "").strip().strip("/")
        if not PATH_RE.match(out["path"]) or out["path"] == "/":
            raise RouteError("path: например /ws или /api/stream")
    return out


def validate(value):
    value = value or {}
    out = dict(DEFAULT_NGINX)
    mode = value.get("mode") or "direct"
    if mode not in MODES:
        raise RouteError("Режим: direct, frontend или vision")
    out["mode"] = mode
    out["vision"] = validate_vision(value.get("vision"))
    out["routes"] = [validate_route(r) for r in value.get("routes") or []]
    out["http_redirect"] = bool(value.get("http_redirect", True))
    out["force"] = bool(value.get("force", False))
    name = str(value.get("server_name") or "").strip().lower()
    if name and not re.fullmatch(r"[a-z0-9.*-]{1,253}", name):
        raise RouteError("Недопустимое имя сервера")
    out["server_name"] = name
    seen = set()
    for route in out["routes"]:
        key = (route["public_port"], route["service_name"] or route["path"])
        if key in seen:
            raise RouteError(f"Два маршрута с одинаковым путём на порту {route['public_port']}")
        seen.add(key)
    if mode == "vision":
        reserved = {80, 443} | {r["public_port"] for r in out["routes"] if r["public_port"] != 443}
        for key in ("http1_port", "h2_port"):
            if out["vision"][key] in reserved:
                raise RouteError(f"Локальный порт fallback {out['vision'][key]} совпадает с публичным портом")
        if not out["vision"]["h2"] and any(r["transport"] == "grpc" and r["public_port"] == 443 and r["enabled"]
                                            for r in out["routes"]):
            raise RouteError("gRPC на 443 в режиме Vision идёт через fallback HTTP/2 — включите HTTP/2")
    return out


def validate_vision(value):
    value = value or {}
    out = dict(DEFAULT_VISION)
    out["inbound_tag"] = str(value.get("inbound_tag") or "").strip()[:100]
    for key in ("http1_port", "h2_port"):
        port = int(value.get(key) or DEFAULT_VISION[key])
        if not 1024 <= port <= 65535:
            raise RouteError("Локальные порты fallback: 1024–65535")
        out[key] = port
    if out["http1_port"] == out["h2_port"]:
        raise RouteError("Порты fallback HTTP/1.1 и HTTP/2 должны различаться")
    out["h2"] = bool(value.get("h2", True))
    out["proxy_protocol"] = bool(value.get("proxy_protocol", True))
    return out


def node_config(node):
    try:
        return validate(loads(node.get("nginx"), {}) or {})
    except RouteError:
        return dict(DEFAULT_NGINX)


def is_local(host):
    """Upstream on this machine or its private/Docker networks (not exposed via Nginx)."""
    host = str(host or "").strip("[]")
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def public_ports(cfg):
    """Public ports Nginx itself listens on (443 belongs to Xray in vision mode)."""
    if cfg["mode"] == "direct":
        return []
    ports = {r["public_port"] for r in cfg["routes"] if r["enabled"]}
    if cfg["mode"] == "frontend":
        ports.add(443)
    else:
        ports.discard(443)
    if cfg["http_redirect"]:
        ports.add(80)
    return sorted(ports)


def uses_nginx(cfg):
    return cfg["mode"] in ("frontend", "vision")


# ------------------------------------------------------- Remnawave check


def _inbound_listen(raw):
    return str((raw or {}).get("listen") or "0.0.0.0")


def _transport_name(raw, inbound):
    stream = (raw or {}).get("streamSettings") or {}
    return str(stream.get("network") or inbound.get("network") or "raw").lower().replace("splithttp", "xhttp")


def check_routes(cfg, rw_node, container_network=None):
    """Compare routes with the node's real inbounds; returns list of results."""
    inbounds = ((rw_node or {}).get("configProfile") or {}).get("activeInbounds") or []
    results = []
    for route in cfg["routes"]:
        problems, notes, match = [], [], None
        for inbound in inbounds:
            raw = inbound.get("rawInbound") or {}
            if route.get("inbound_tag") and inbound.get("tag") == route["inbound_tag"]:
                match = inbound
                break
            if int(inbound.get("port") or raw.get("port") or 0) == route["upstream_port"]:
                match = inbound
        if not rw_node:
            notes.append("Нода не сопоставлена с Remnawave — совместимость не проверена")
        elif not match:
            problems.append(f"В профиле Remnawave нет inbound на порту {route['upstream_port']}")
        else:
            raw = match.get("rawInbound") or {}
            stream = raw.get("streamSettings") or {}
            network = _transport_name(raw, match)
            if network != XRAY_NETWORK[route["transport"]]:
                problems.append(f"inbound {match.get('tag')} использует транспорт {network}, а маршрут — {route['transport']}")
            security = str(stream.get("security") or match.get("security") or "none").lower()
            if security != "none":
                problems.append(f"inbound {match.get('tag')}: security={security}; за Nginx нужно security: none "
                                "(TLS завершает Nginx)")
            if route["transport"] == "grpc":
                name = ((stream.get("grpcSettings") or {}).get("serviceName") or "")
                if name != route["service_name"]:
                    problems.append(f"serviceName в Xray «{name}», в маршруте «{route['service_name']}»")
            else:
                key = {"ws": "wsSettings", "httpupgrade": "httpupgradeSettings", "xhttp": "xhttpSettings"}[route["transport"]]
                settings = stream.get(key) or stream.get("splithttpSettings") or {}
                path = settings.get("path") or "/"
                if path.rstrip("/") != route["path"].rstrip("/"):
                    problems.append(f"path в Xray «{path}», в маршруте «{route['path']}»")
            listen = _inbound_listen(raw)
            if listen in ("0.0.0.0", "::"):
                notes.append(f"inbound слушает {listen}:{route['upstream_port']} — доступен и в обход Nginx; "
                             f"лучше listen {route['upstream_host']} (или закройте порт в firewall)")
            elif listen != route["upstream_host"] and not route["upstream_host"].startswith("127."):
                notes.append(f"inbound слушает {listen}, маршрут ведёт на {route['upstream_host']}")
        for inbound in inbounds:
            port = int(inbound.get("port") or 0)
            listen = _inbound_listen(inbound.get("rawInbound"))
            if cfg["mode"] == "vision" and port == 443 and route["public_port"] == 443 and \
                    inbound.get("tag") == cfg["vision"]["inbound_tag"]:
                continue  # the Vision inbound owns 443 and hands HTTP over to Nginx
            if port == route["public_port"] and listen not in ("127.0.0.1", "::1"):
                problems.append(f"inbound {inbound.get('tag')} занимает публичный порт {port} — Nginx не сможет его слушать")
        if container_network and container_network != "host" and route["upstream_host"].startswith("127."):
            problems.append(f"RemnaNode в сети Docker «{container_network}»: 127.0.0.1 из Nginx недоступен")
        results.append({"route_id": route["id"], "inbound": (match or {}).get("tag"), "problems": problems,
                        "notes": notes, "ok": not problems, "snippet": snippet(route)})
    return results


def snippet(route):
    stream = {"network": XRAY_NETWORK[route["transport"]], "security": "none"}
    if route["transport"] == "grpc":
        stream["grpcSettings"] = {"serviceName": route["service_name"]}
    elif route["transport"] == "ws":
        stream["wsSettings"] = {"path": route["path"]}
    elif route["transport"] == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": route["path"]}
    else:
        stream["xhttpSettings"] = {"path": route["path"]}
    return {"listen": route["upstream_host"], "port": route["upstream_port"], "streamSettings": stream}


def patch_profile(config, tag, route):
    """Return a copy of a Remnawave profile config with one inbound adjusted."""
    config = copy.deepcopy(config)
    for inbound in config.get("inbounds") or []:
        if inbound.get("tag") == tag:
            wanted = snippet(route)
            current = inbound.get("streamSettings") or {}
            # Only listen/port/security/path may change: turning a REALITY or
            # another transport into this route would break its users.
            if current.get("security") == "reality":
                raise RouteError(f"inbound {tag} использует REALITY — его нельзя перевести за Nginx")
            network = current.get("network") or "raw"
            if network != wanted["streamSettings"]["network"]:
                raise RouteError(f"inbound {tag} использует транспорт {network}, а маршрут — "
                                 f"{wanted['streamSettings']['network']}; транспорт не меняется автоматически")
            inbound["listen"] = wanted["listen"]
            inbound["port"] = wanted["port"]
            stream = inbound.setdefault("streamSettings", {})
            for key in ("tlsSettings", "realitySettings"):
                stream.pop(key, None)
            stream.update(wanted["streamSettings"])
            return config
    raise RouteError(f"inbound {tag} не найден в профиле")


# ------------------------------------------------------------ Vision + TLS fallback


def vision_fallbacks(vision):
    xver = 1 if vision["proxy_protocol"] else 0
    out = [{"dest": f"127.0.0.1:{vision['http1_port']}", "xver": xver}]
    if vision["h2"]:
        out.append({"alpn": "h2", "dest": f"127.0.0.1:{vision['h2_port']}", "xver": xver})
    return out


def vision_alpn(vision):
    return ["h2", "http/1.1"] if vision["h2"] else ["http/1.1"]


def cert_paths(container_dir):
    base = (container_dir or "/etc/xray/ssl").rstrip("/")
    return f"{base}/fullchain.pem", f"{base}/privkey.pem"


def _norm_dest(dest):
    text = str(dest or "").strip()
    if text.isdigit():
        return f"127.0.0.1:{text}"
    return text.replace("localhost:", "127.0.0.1:")


def _norm_fallbacks(items):
    return sorted((str(i.get("alpn") or ""), str(i.get("path") or ""), _norm_dest(i.get("dest")), int(i.get("xver") or 0))
                  for i in items or [])


def _covers(names, host):
    host = (host or "").lower()
    for name in names or []:
        name = name.lower()
        if name == host or (name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count(".")):
            return True
    return False


def _active(rw_node):
    return ((rw_node or {}).get("configProfile") or {}).get("activeInbounds") or []


def vision_conflicts(cfg, rw_node):
    """Hard conflicts that make the vision mode unsafe to enable at all."""
    if not rw_node:
        return []
    problems = []
    tag = cfg["vision"]["inbound_tag"]
    inbound = next((i for i in _active(rw_node) if i.get("tag") == tag), None)
    if tag and inbound:
        raw = inbound.get("rawInbound") or {}
        stream = raw.get("streamSettings") or {}
        protocol = raw.get("protocol") or inbound.get("type")
        if protocol != "vless":
            problems.append(f"inbound {tag}: протокол {protocol}, для Vision нужен VLESS")
        if str(stream.get("security") or inbound.get("security") or "").lower() == "reality":
            problems.append(f"inbound {tag} использует REALITY — его не трогаем; выберите отдельный VLESS inbound")
        network = _transport_name(raw, inbound)
        if network not in ("raw", "tcp"):
            problems.append(f"inbound {tag} использует транспорт {network}; Vision работает только на RAW (TCP)")
    for other in _active(rw_node):
        if other.get("tag") == tag:
            continue
        raw = other.get("rawInbound") or {}
        if int(other.get("port") or raw.get("port") or 0) == 443 and _inbound_listen(raw) not in ("127.0.0.1", "::1"):
            kind = str((raw.get("streamSettings") or {}).get("security") or other.get("security") or "").upper()
            problems.append(f"inbound {other.get('tag')} ({kind or 'без TLS'}) уже занимает порт 443 на этой ноде")
    return problems


def check_vision(cfg, rw_node, ctx):
    """Vision mode vs the node's Remnawave inbound, certificate and agent state.

    ctx: cert (dict|None), cert_state, cert_target, server_name, nginx_state,
    container_network, rw_nodes (all Remnawave nodes from the cache).
    Returns problems (block sync), warnings (shown, but the admin may sync anyway),
    drift (what a sync would change) and notes.
    """
    vision = cfg["vision"]
    problems, warnings, drift, notes = [], [], [], []
    tag = vision["inbound_tag"]
    inbound = next((i for i in _active(rw_node) if i.get("tag") == tag), None) if tag else None
    profile_uuid = ((rw_node or {}).get("configProfile") or {}).get("activeConfigProfileUuid")
    container_dir = (ctx.get("cert_target") or {}).get("container_dir") or "/etc/xray/ssl"
    cert_file, key_file = cert_paths(container_dir)
    if not rw_node:
        problems.append("Нода не сопоставлена с Remnawave — укажите её в «Параметры»")
    elif not tag:
        problems.append("Выберите VLESS inbound для Vision")
    elif not inbound:
        problems.append(f"inbound {tag} не активен на этой ноде в Remnawave")
    problems += vision_conflicts(cfg, rw_node)
    shared = []
    if inbound:
        for other in ctx.get("rw_nodes") or []:
            if other.get("uuid") == rw_node.get("uuid"):
                continue
            prof = other.get("configProfile") or {}
            if prof.get("activeConfigProfileUuid") == profile_uuid and \
                    any(i.get("uuid") == inbound.get("uuid") for i in prof.get("activeInbounds") or []):
                shared.append(str(other.get("name")))
        if shared:
            warnings.append("inbound активен и на других нодах общего профиля (" + ", ".join(shared)
                            + ") — изменение затронет и их; лучше вынести Vision в отдельный inbound этой ноды")
    if not ctx.get("cert"):
        problems.append("Ноде не назначен сертификат (карточка «SSL-сертификат»)")
    else:
        state = ctx.get("cert_state") or {}
        if state.get("error"):
            problems.append(f"Сертификат не установлен на ноде: {state['error']}")
        elif not state.get("version"):
            problems.append("Сертификат ещё не установлен на ноде")
        if ctx.get("server_name") and not _covers(ctx["cert"].get("domains"), ctx["server_name"]):
            notes.append(f"Сертификат ({', '.join(ctx['cert'].get('domains') or [])}) не покрывает {ctx['server_name']}")
        if (ctx.get("cert_target") or {}).get("mode") == "files":
            notes.append("Сертификат ставится «только файлами на хосте»: Xray в контейнере получит продлённый "
                         "сертификат, только если каталог смонтирован в RemnaNode. Надёжнее — установка в Docker-контейнер")
    network = ctx.get("container_network")
    if network and network != "host":
        problems.append(f"RemnaNode в сети Docker «{network}»: fallback на 127.0.0.1 из контейнера не дойдёт до Nginx")
    state = ctx.get("nginx_state") or {}
    if state.get("mode") == "vision" and state.get("cert_in_container") is False:
        problems.append(f"Файлов сертификата нет внутри контейнера RemnaNode ({container_dir}) — выберите установку "
                        "«в Docker-контейнер» в карточке «SSL-сертификат» или смонтируйте каталог")
    if inbound:
        raw = inbound.get("rawInbound") or {}
        settings = raw.get("settings") or {}
        stream = raw.get("streamSettings") or {}
        tls = stream.get("tlsSettings") or {}
        if int(raw.get("port") or inbound.get("port") or 0) != 443:
            drift.append(f"port {raw.get('port') or inbound.get('port')} → 443")
        if _inbound_listen(raw) not in ("0.0.0.0", "::"):
            drift.append(f"listen {_inbound_listen(raw)} → 0.0.0.0")
        security = str(stream.get("security") or "none").lower()
        if security != "tls":
            drift.append(f"security {security} → tls")
            notes.append("Клиентам этого inbound нужно обновить подписку: появятся TLS и flow xtls-rprx-vision")
        if settings.get("flow") not in (None, VISION_FLOW):
            drift.append(f"flow «{settings.get('flow')}» → {VISION_FLOW}")
        certs = tls.get("certificates") or []
        if not any(c.get("certificateFile") == cert_file and c.get("keyFile") == key_file for c in certs):
            drift.append(f"сертификат → {cert_file}")
        if sorted(tls.get("alpn") or []) != sorted(vision_alpn(vision)):
            drift.append("alpn → " + ", ".join(vision_alpn(vision)))
        if _norm_fallbacks(settings.get("fallbacks")) != _norm_fallbacks(vision_fallbacks(vision)):
            drift.append("fallbacks → Nginx " + ", ".join(f["dest"] for f in vision_fallbacks(vision)))
        if str(settings.get("decryption") or "none") != "none":
            drift.append("decryption → none")
    agent_ready = state.get("mode") == "vision" and bool(state.get("fallback_ok"))
    if cfg["mode"] == "vision" and not agent_ready:
        notes.append("Агент ещё не переключил Nginx на локальные fallback-порты — синхронизация станет доступна после этого")
    return {"inbound": tag or None, "problems": problems, "warnings": warnings, "drift": drift, "notes": notes,
            "shared_with": shared,
            "ok": not problems and not drift, "agent_ready": agent_ready,
            "can_sync": bool(inbound) and not problems and bool(drift) and agent_ready,
            "e2e": state.get("e2e"), "cert_file": cert_file}


def patch_vision(config, tag, cfg, container_dir):
    """Copy of a profile config with ONE inbound turned into VLESS RAW+TLS+Vision with Nginx fallbacks.

    Only that inbound changes; its clients, sniffing and other tlsSettings keys stay.
    """
    vision = cfg["vision"]
    config = copy.deepcopy(config)
    cert_file, key_file = cert_paths(container_dir)
    for inbound in config.get("inbounds") or []:
        if inbound.get("tag") != tag:
            continue
        if inbound.get("protocol") != "vless":
            raise RouteError(f"inbound {tag}: протокол {inbound.get('protocol')}, для Vision нужен VLESS")
        stream = inbound.setdefault("streamSettings", {})
        if stream.get("security") == "reality":
            raise RouteError(f"inbound {tag} использует REALITY — его не меняем")
        if (stream.get("network") or "raw") not in ("raw", "tcp"):
            raise RouteError(f"inbound {tag} использует транспорт {stream.get('network')}; транспорт не меняется автоматически")
        for other in config.get("inbounds") or []:
            if other is not inbound and int(other.get("port") or 0) == 443 and \
                    str(other.get("listen") or "0.0.0.0") not in ("127.0.0.1", "::1"):
                raise RouteError(f"inbound {other.get('tag')} в этом профиле уже на порту 443")
        inbound["listen"] = "0.0.0.0"
        inbound["port"] = 443
        settings = inbound.setdefault("settings", {})
        settings["decryption"] = "none"
        settings["flow"] = VISION_FLOW
        settings["fallbacks"] = vision_fallbacks(vision)
        stream["network"] = stream.get("network") or "raw"
        stream["security"] = "tls"
        stream.pop("realitySettings", None)
        tls = dict(stream.get("tlsSettings") or {})
        tls["alpn"] = vision_alpn(vision)
        tls.setdefault("minVersion", "1.2")
        tls["certificates"] = [{"certificateFile": cert_file, "keyFile": key_file, "ocspStapling": 3600}]
        stream["tlsSettings"] = tls
        return config
    raise RouteError(f"inbound {tag} не найден в профиле")

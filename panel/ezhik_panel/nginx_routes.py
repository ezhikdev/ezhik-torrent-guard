"""Per-node Nginx frontend: validation and Remnawave inbound compatibility."""

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


DEFAULT_NGINX = {"mode": "direct", "routes": [], "http_redirect": True, "server_name": "", "force": False}


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
    if mode not in ("direct", "frontend"):
        raise RouteError("Режим: direct или frontend")
    out["mode"] = mode
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
    if cfg["mode"] != "frontend":
        return []
    ports = {443} | {r["public_port"] for r in cfg["routes"] if r["enabled"]}
    if cfg["http_redirect"]:
        ports.add(80)
    return sorted(ports)


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

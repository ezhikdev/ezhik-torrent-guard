#!/usr/bin/env python3

import ipaddress
import time

from collections import Counter, defaultdict, deque


class _Window:
    def __init__(self, seconds):
        self.seconds = float(seconds)
        self.events = deque()
        self.endpoints = Counter()
        self.ports = Counter()
        self.ips = Counter()
        self.ip_ports = defaultdict(Counter)
        self.subnet_ips = defaultdict(Counter)
        self.subnet_ports = defaultdict(Counter)

    @staticmethod
    def _decrement(counter, key):
        current = counter.get(key, 0)
        if current <= 1:
            counter.pop(key, None)
        else:
            counter[key] = current - 1

    def expire(self, now):
        cutoff = now - self.seconds

        while self.events and self.events[0][0] < cutoff:
            _ts, endpoint, remote_ip, remote_port, subnet = self.events.popleft()

            self._decrement(self.endpoints, endpoint)
            self._decrement(self.ports, remote_port)
            self._decrement(self.ips, remote_ip)

            ip_ports = self.ip_ports.get(remote_ip)
            if ip_ports is not None:
                self._decrement(ip_ports, remote_port)
                if not ip_ports:
                    self.ip_ports.pop(remote_ip, None)

            subnet_ips = self.subnet_ips.get(subnet)
            if subnet_ips is not None:
                self._decrement(subnet_ips, remote_ip)
                if not subnet_ips:
                    self.subnet_ips.pop(subnet, None)

            subnet_ports = self.subnet_ports.get(subnet)
            if subnet_ports is not None:
                self._decrement(subnet_ports, remote_port)
                if not subnet_ports:
                    self.subnet_ports.pop(subnet, None)

    def add(self, now, proto, remote_ip, remote_port, subnet):
        self.expire(now)

        endpoint = (proto, remote_ip, remote_port)
        if endpoint in self.endpoints:
            return

        self.events.append((now, endpoint, remote_ip, remote_port, subnet))
        self.endpoints[endpoint] += 1
        self.ports[remote_port] += 1
        self.ips[remote_ip] += 1
        self.ip_ports[remote_ip][remote_port] += 1
        self.subnet_ips[subnet][remote_ip] += 1
        self.subnet_ports[subnet][remote_port] += 1

    def empty(self):
        return not self.events

    def sample_endpoints(self, limit=100):
        values = sorted(
            self.endpoints,
            key=lambda item: (item[0], ipaddress.ip_address(item[1]), item[2]),
        )
        return [
            {
                "protocol": proto,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
            }
            for proto, remote_ip, remote_port in values[:limit]
        ]


class ScanDetector:
    """Bounded RAM-only detector for attributed Xray destinations/sockets."""

    def __init__(
        self,
        *,
        window_seconds=60,
        burst_window_seconds=15,
        vertical_ports=20,
        burst_endpoints=100,
        burst_ports=50,
        subnet_hosts=16,
        subnet_ports=50,
        cooldown_seconds=300,
        clock=time.time,
    ):
        self.window_seconds = max(1, int(window_seconds))
        self.burst_window_seconds = max(1, int(burst_window_seconds))
        self.vertical_ports = max(2, int(vertical_ports))
        self.burst_endpoints = max(2, int(burst_endpoints))
        self.burst_ports = max(2, int(burst_ports))
        self.subnet_hosts = max(2, int(subnet_hosts))
        self.subnet_ports = max(2, int(subnet_ports))
        self.cooldown_seconds = max(1, int(cooldown_seconds))
        self.clock = clock

        self._clients = {}
        self._announced = {}
        self._next_cleanup_at = 0.0

    @staticmethod
    def _public_ipv4(value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None

        if address.version != 4 or not address.is_global:
            return None

        return address

    @staticmethod
    def _subnet(address):
        return str(ipaddress.ip_network(f"{address}/24", strict=False))

    def _state(self, client):
        state = self._clients.get(client)
        if state is None:
            state = {
                "long": _Window(self.window_seconds),
                "burst": _Window(self.burst_window_seconds),
            }
            self._clients[client] = state
        return state

    def _report(self, client, reason, now, window, details):
        self._announced[client] = now
        return {
            "client_id": client,
            "detected_at": now,
            "reason": reason,
            "window_seconds": int(window.seconds),
            "unique_endpoints": len(window.endpoints),
            "unique_ips": len(window.ips),
            "unique_ports": len(window.ports),
            "details": details,
            "sample_endpoints": window.sample_endpoints(),
        }

    def observe(self, client, socket_key, now=None):
        client = str(client)
        if not client.isdigit():
            return None

        try:
            proto, _local_port, remote_ip, remote_port = socket_key
            proto = str(proto).lower()
            remote_port = int(remote_port)
        except (TypeError, ValueError):
            return None

        if proto not in {"tcp", "udp"} or not 1 <= remote_port <= 65535:
            return None

        address = self._public_ipv4(remote_ip)
        if address is None:
            return None

        now = self.clock() if now is None else float(now)
        last = self._announced.get(client)
        if last is not None and now - last < self.cooldown_seconds:
            return None

        subnet = self._subnet(address)
        state = self._state(client)
        long_window = state["long"]
        burst_window = state["burst"]

        for window in (long_window, burst_window):
            window.add(now, proto, str(address), remote_port, subnet)

        vertical_count = len(long_window.ip_ports[str(address)])
        if vertical_count >= self.vertical_ports:
            return self._report(
                client,
                "vertical-port-scan",
                now,
                long_window,
                {
                    "target_ip": str(address),
                    "target_unique_ports": vertical_count,
                },
            )

        subnet_host_count = len(long_window.subnet_ips[subnet])
        subnet_port_count = len(long_window.subnet_ports[subnet])
        if (
            subnet_host_count >= self.subnet_hosts
            and subnet_port_count >= self.subnet_ports
        ):
            return self._report(
                client,
                "subnet-port-scan",
                now,
                long_window,
                {
                    "target_subnet": subnet,
                    "subnet_unique_hosts": subnet_host_count,
                    "subnet_unique_ports": subnet_port_count,
                },
            )

        if (
            len(burst_window.endpoints) >= self.burst_endpoints
            and len(burst_window.ports) >= self.burst_ports
        ):
            return self._report(
                client,
                "distributed-port-scan",
                now,
                burst_window,
                {
                    "burst_unique_endpoints": len(burst_window.endpoints),
                    "burst_unique_ports": len(burst_window.ports),
                },
            )

        return None

    def observe_destination(self, client, proto, destination, now=None):
        """Observe an authenticated Xray request even when connect fails."""

        destination = str(destination).strip()
        if not destination or destination.startswith("["):
            return None

        try:
            remote_ip, remote_port = destination.rsplit(":", 1)
        except ValueError:
            return None

        return self.observe(
            client,
            (
                str(proto).lower(),
                0,
                remote_ip,
                remote_port,
            ),
            now=now,
        )

    def cleanup(self, now=None):
        now = self.clock() if now is None else float(now)
        if now < self._next_cleanup_at:
            return
        self._next_cleanup_at = now + 10.0

        for client, state in list(self._clients.items()):
            state["long"].expire(now)
            state["burst"].expire(now)
            if state["long"].empty() and state["burst"].empty():
                self._clients.pop(client, None)

        for client, announced_at in list(self._announced.items()):
            if now - announced_at >= self.cooldown_seconds:
                self._announced.pop(client, None)

    def active_clients(self):
        return len(self._clients)

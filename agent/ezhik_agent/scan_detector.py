"""RAM-only behaviour detectors for attributed Xray destinations.

Two independent families share one sliding window per client:

* port scans (vertical scan of one IP, dense scan of one /24) - unchanged
  from Torrent Guard 1.x;
* P2P fan-out: a client talking to hundreds of unrelated public hosts on
  random high ports within a minute. This is the DHT / uTP / peer-swarm
  pattern that hosting providers report as "port scan" and that encrypted
  BitTorrent clients produce even when strict nDPI cannot classify a flow.
"""

import ipaddress
import time

from collections import Counter, defaultdict, deque

# Destination ports that legitimate many-host applications use. They never
# count towards P2P fan-out.
COMMON_SERVICE_PORTS = frozenset(
    {
        1194, 1701, 1723, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
        3478, 3479, 3480, 3481, 5060, 5061, 5222, 5223, 5228, 5349, 8000,
        8008, 8080, 8088, 8443, 8880, 8888, 9993, 10000,
    }
    | set(range(19302, 19310))
    | set(range(8801, 8811))
)


def fanout_port(port):
    return port >= 1024 and port not in COMMON_SERVICE_PORTS


class _Window:
    def __init__(self, seconds):
        self.seconds = float(seconds)
        self.events = deque()
        self.endpoints = Counter()
        self.ports = Counter()
        self.ips = Counter()
        self.protocol_ip_ports = defaultdict(Counter)
        self.protocol_subnet_ips = defaultdict(Counter)
        self.protocol_subnet_ports = defaultdict(Counter)
        self.protocol_subnet_endpoints = defaultdict(Counter)
        # P2P fan-out: protocol -> Counter(remote_ip) / Counter(/16 network)
        self.fanout_ips = defaultdict(Counter)
        self.fanout_nets = defaultdict(Counter)

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
            _ts, endpoint, remote_ip, remote_port, subnet, net16 = self.events.popleft()
            proto = endpoint[0]

            self._decrement(self.endpoints, endpoint)
            self._decrement(self.ports, remote_port)
            self._decrement(self.ips, remote_ip)

            protocol_ip = (proto, remote_ip)
            ip_ports = self.protocol_ip_ports.get(protocol_ip)
            if ip_ports is not None:
                self._decrement(ip_ports, remote_port)
                if not ip_ports:
                    self.protocol_ip_ports.pop(protocol_ip, None)

            protocol_subnet = (proto, subnet)
            for table, key in (
                (self.protocol_subnet_ips, remote_ip),
                (self.protocol_subnet_ports, remote_port),
                (self.protocol_subnet_endpoints, endpoint),
            ):
                values = table.get(protocol_subnet)
                if values is not None:
                    self._decrement(values, key)
                    if not values:
                        table.pop(protocol_subnet, None)

            if net16 is not None:
                for table, key in ((self.fanout_ips, remote_ip), (self.fanout_nets, net16)):
                    values = table.get(proto)
                    if values is not None:
                        self._decrement(values, key)
                        if not values:
                            table.pop(proto, None)

    def add(self, now, proto, remote_ip, remote_port, subnet, net16):
        self.expire(now)

        endpoint = (proto, remote_ip, remote_port)
        if endpoint in self.endpoints:
            return

        self.events.append((now, endpoint, remote_ip, remote_port, subnet, net16))
        self.endpoints[endpoint] += 1
        self.ports[remote_port] += 1
        self.ips[remote_ip] += 1
        protocol_ip = (proto, remote_ip)
        protocol_subnet = (proto, subnet)
        self.protocol_ip_ports[protocol_ip][remote_port] += 1
        self.protocol_subnet_ips[protocol_subnet][remote_ip] += 1
        self.protocol_subnet_ports[protocol_subnet][remote_port] += 1
        self.protocol_subnet_endpoints[protocol_subnet][endpoint] += 1
        if net16 is not None:
            self.fanout_ips[proto][remote_ip] += 1
            self.fanout_nets[proto][net16] += 1

    def empty(self):
        return not self.events

    def sample_endpoints(self, values=None, limit=100):
        values = self.endpoints if values is None else values
        values = sorted(
            values,
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
        tcp_vertical_ports=50,
        udp_vertical_ports=100,
        subnet_hosts=16,
        subnet_ports=50,
        subnet_endpoints=100,
        cooldown_seconds=300,
        scan_enabled=True,
        fanout_enabled=False,
        udp_fanout_hosts=120,
        udp_fanout_networks=40,
        tcp_fanout_hosts=150,
        tcp_fanout_networks=50,
        clock=time.time,
    ):
        self.window_seconds = max(1, int(window_seconds))
        self.tcp_vertical_ports = max(2, int(tcp_vertical_ports))
        self.udp_vertical_ports = max(2, int(udp_vertical_ports))
        self.subnet_hosts = max(2, int(subnet_hosts))
        self.subnet_ports = max(2, int(subnet_ports))
        self.subnet_endpoints = max(2, int(subnet_endpoints))
        self.cooldown_seconds = max(1, int(cooldown_seconds))
        self.scan_enabled = bool(scan_enabled)
        self.fanout_enabled = bool(fanout_enabled)
        self.fanout_thresholds = {
            "udp": (max(10, int(udp_fanout_hosts)), max(2, int(udp_fanout_networks))),
            "tcp": (max(10, int(tcp_fanout_hosts)), max(2, int(tcp_fanout_networks))),
        }
        self.clock = clock

        self._clients = {}
        # (client, family) -> last report timestamp
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

    @staticmethod
    def _net16(address):
        packed = address.packed
        return f"{packed[0]}.{packed[1]}.0.0/16"

    def _state(self, client):
        state = self._clients.get(client)
        if state is None:
            state = {
                "long": _Window(self.window_seconds),
            }
            self._clients[client] = state
        return state

    def _cooling(self, client, family, now):
        last = self._announced.get((client, family))
        return last is not None and now - last < self.cooldown_seconds

    def _report(self, client, family, reason, now, window, details, evidence):
        evidence = set(evidence)
        evidence_ips = {endpoint[1] for endpoint in evidence}
        evidence_ports = {endpoint[2] for endpoint in evidence}
        self._announced[(client, family)] = now
        return {
            "client_id": client,
            "family": family,
            "detected_at": now,
            "reason": reason,
            "window_seconds": int(window.seconds),
            "unique_endpoints": len(evidence),
            "unique_ips": len(evidence_ips),
            "unique_ports": len(evidence_ports),
            "details": details,
            "sample_endpoints": window.sample_endpoints(evidence),
        }

    @staticmethod
    def _ip_evidence(window, proto, remote_ip):
        return {
            endpoint
            for endpoint in window.endpoints
            if endpoint[0] == proto and endpoint[1] == remote_ip
        }

    @staticmethod
    def _subnet_evidence(window, proto, subnet):
        network = ipaddress.ip_network(subnet)
        return {
            endpoint
            for endpoint in window.endpoints
            if endpoint[0] == proto
            and ipaddress.ip_address(endpoint[1]) in network
        }

    @staticmethod
    def _fanout_evidence(window, proto):
        return {
            endpoint
            for endpoint in window.endpoints
            if endpoint[0] == proto and fanout_port(endpoint[2])
        }

    def observe(self, client, socket_key, now=None):
        if not (self.scan_enabled or self.fanout_enabled):
            return None

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
        scan_cooling = self._cooling(client, "scan", now)
        fanout_cooling = self._cooling(client, "p2p", now)
        if (not self.scan_enabled or scan_cooling) and (not self.fanout_enabled or fanout_cooling):
            return None

        subnet = self._subnet(address)
        net16 = self._net16(address) if fanout_port(remote_port) else None
        state = self._state(client)
        long_window = state["long"]
        long_window.add(now, proto, str(address), remote_port, subnet, net16)
        remote_ip = str(address)

        if self.scan_enabled and not scan_cooling:
            report = self._check_scan(client, now, long_window, proto, remote_ip, subnet)
            if report is not None:
                return report

        if self.fanout_enabled and not fanout_cooling:
            return self._check_fanout(client, now, long_window, proto)

        return None

    def _check_scan(self, client, now, long_window, proto, remote_ip, subnet):
        protocol_ip = (proto, remote_ip)
        vertical_count = len(long_window.protocol_ip_ports[protocol_ip])
        vertical_threshold = (
            self.tcp_vertical_ports
            if proto == "tcp"
            else self.udp_vertical_ports
        )
        if vertical_count >= vertical_threshold:
            evidence = self._ip_evidence(long_window, proto, remote_ip)
            return self._report(
                client,
                "scan",
                "vertical-port-scan",
                now,
                long_window,
                {
                    "target_protocol": proto,
                    "target_ip": remote_ip,
                    "target_unique_ports": vertical_count,
                    "target_port_threshold": vertical_threshold,
                },
                evidence,
            )

        protocol_subnet = (proto, subnet)
        subnet_host_count = len(long_window.protocol_subnet_ips[protocol_subnet])
        subnet_port_count = len(long_window.protocol_subnet_ports[protocol_subnet])
        subnet_endpoint_count = len(
            long_window.protocol_subnet_endpoints[protocol_subnet]
        )
        if (
            subnet_host_count >= self.subnet_hosts
            and subnet_port_count >= self.subnet_ports
            and subnet_endpoint_count >= self.subnet_endpoints
        ):
            evidence = self._subnet_evidence(long_window, proto, subnet)
            return self._report(
                client,
                "scan",
                "subnet-port-scan",
                now,
                long_window,
                {
                    "target_protocol": proto,
                    "target_subnet": subnet,
                    "subnet_unique_hosts": subnet_host_count,
                    "subnet_unique_ports": subnet_port_count,
                    "subnet_unique_endpoints": subnet_endpoint_count,
                },
                evidence,
            )
        return None

    def _check_fanout(self, client, now, long_window, proto):
        hosts_needed, nets_needed = self.fanout_thresholds[proto]
        hosts = len(long_window.fanout_ips.get(proto, ()))
        if hosts < hosts_needed:
            return None
        nets = len(long_window.fanout_nets.get(proto, ()))
        if nets < nets_needed:
            return None
        evidence = self._fanout_evidence(long_window, proto)
        return self._report(
            client,
            "p2p",
            "p2p-fanout",
            now,
            long_window,
            {
                "target_protocol": proto,
                "unique_hosts": hosts,
                "unique_networks16": nets,
                "host_threshold": hosts_needed,
                "network_threshold": nets_needed,
            },
            evidence,
        )

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
            if state["long"].empty():
                self._clients.pop(client, None)

        for key, announced_at in list(self._announced.items()):
            if now - announced_at >= self.cooldown_seconds:
                self._announced.pop(key, None)

    def active_clients(self):
        return len(self._clients)

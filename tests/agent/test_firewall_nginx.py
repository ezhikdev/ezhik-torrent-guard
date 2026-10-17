import unittest
from pathlib import Path

import _paths  # noqa: F401
from ezhik_agent import firewall, nginx


class FirewallRenderTests(unittest.TestCase):
    def cfg(self, **kw):
        base = {"rules": [{"proto": "tcp", "ports": "22,80,443", "sources": []},
                          {"proto": "udp", "ports": "10000-10100", "sources": ["203.0.113.0/24", "2001:db8::/32"]}],
                "ssh_ports": [22, 2222]}
        base.update(kw)
        return base

    def test_default_drop_with_essentials(self):
        text = firewall.render(self.cfg())
        self.assertIn("policy drop;", text)
        self.assertIn("ct state established,related accept", text)
        self.assertIn('iifname "lo" accept', text)
        self.assertIn("tcp dport { 22, 2222 } accept", text)
        self.assertIn("nd-neighbor-solicit", text)

    def test_sources_split_by_family(self):
        text = firewall.render(self.cfg())
        self.assertIn("ip saddr { 203.0.113.0/24 } udp dport { 10000-10100 } accept", text)
        self.assertIn("ip6 saddr { 2001:db8::/32 } udp dport { 10000-10100 } accept", text)

    def test_docker_forward_guard(self):
        text = firewall.render(self.cfg())
        self.assertIn('ct status dnat ct state new oifname "docker0" meta l4proto tcp ct original proto-dst', text)
        self.assertIn('ct status dnat ct state new oifname "br-*" meta l4proto tcp ct original proto-dst', text)
        self.assertIn('counter drop comment "ezhik-guard docker"', text)

    def test_any_protocol(self):
        text = firewall.render({"rules": [{"proto": "any", "ports": "53"}]})
        self.assertIn("tcp dport { 53 } accept", text)
        self.assertIn("udp dport { 53 } accept", text)

    def test_invalid_ports_rejected(self):
        for bad in ("0", "70000", "10-5", "22;drop", ""):
            with self.assertRaises(firewall.FirewallError, msg=bad):
                firewall.render({"rules": [{"proto": "tcp", "ports": bad}]})

    def test_comment_is_sanitized(self):
        text = firewall.render({"rules": [{"proto": "tcp", "ports": "1", "comment": 'x"; drop; #'}]})
        self.assertNotIn('";', text.split("comment")[-1].split("\n")[0])


class NginxRenderTests(unittest.TestCase):
    route = {"transport": "grpc", "public_port": 443, "service_name": "cdn-service",
             "upstream_host": "127.0.0.1", "upstream_port": 10443}

    def render(self, routes, **kw):
        return nginx.render({"routes": routes, **kw}, Path("/c.pem"), Path("/k.pem"))

    def test_grpc_route(self):
        text = self.render([self.route])
        self.assertIn("location ~ ^/cdn\\-service/(Tun|TunMulti)$", text)
        self.assertIn("grpc_pass grpc://127.0.0.1:10443;", text)
        self.assertIn("listen 443 ssl http2 default_server;", text)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", text)
        self.assertIn("return 301 https://$host$request_uri;", text)
        self.assertIn("try_files $uri $uri/ $uri.html /index.html;", text)

    def test_ws_and_xhttp(self):
        text = self.render([{"transport": "ws", "path": "/ws", "upstream_port": 10444},
                            {"transport": "xhttp", "path": "/xh", "upstream_port": 10445, "public_port": 8443}])
        self.assertIn("location = /ws {", text)
        self.assertIn('proxy_set_header Upgrade $http_upgrade;', text)
        self.assertIn("location ^~ /xh/ {", text)
        self.assertIn("listen 8443 ssl http2 default_server;", text)

    def test_reality_and_raw_rejected(self):
        for transport in ("tcp", "raw", "reality", "kcp", "quic"):
            with self.assertRaises(nginx.NginxError):
                self.render([{**self.route, "transport": transport}])

    def test_injection_rejected(self):
        with self.assertRaises(nginx.NginxError):
            self.render([{**self.route, "service_name": "x; } server { listen 1"}])
        with self.assertRaises(nginx.NginxError):
            self.render([{"transport": "ws", "path": "/a{b}", "upstream_port": 1}])

    def test_listen_parsing(self):
        line = "server { listen 443 ssl; listen [::]:8443 ssl http2; server_name x; }  # listen 9"
        self.assertEqual(nginx.listen_ports(line), [443, 8443])
        self.assertEqual(nginx.listen_ports("    listen 127.0.0.1:8080 default_server;"), [8080])
        self.assertEqual(nginx.listen_ports("    listen 80;"), [80])

    def test_no_redirect(self):
        self.assertNotIn("return 301", self.render([self.route], http_redirect=False))

    def test_vision_fallback_server(self):
        cfg = {"mode": "vision", "routes": [self.route, {"transport": "ws", "path": "/ws", "upstream_port": 10444,
                                                         "public_port": 8443}],
               "vision": {"http1_port": 8001, "h2_port": 8002, "h2": True, "proxy_protocol": True}}
        text = nginx.render_vision(cfg, Path("/c.pem"), Path("/k.pem"))
        self.assertNotIn("listen 443", text)  # Xray owns 443
        self.assertIn("listen 127.0.0.1:8001 proxy_protocol default_server;", text)
        self.assertIn("listen 127.0.0.1:8002 http2 proxy_protocol default_server;", text)
        self.assertIn("real_ip_header proxy_protocol;", text)
        fallback = text.split("# Fallback target")[1].split("listen 8443")[0]
        self.assertIn("grpc_pass grpc://127.0.0.1:10443;", fallback)  # 443 routes go through the fallback
        self.assertIn("listen 8443 ssl http2 default_server;", text)  # other ports keep TLS in Nginx
        self.assertIn("return 301 https://$host$request_uri;", text)

    def test_vision_http1_only_without_proxy_protocol(self):
        cfg = {"mode": "vision", "routes": [], "vision": {"h2": False, "proxy_protocol": False}}
        text = nginx.render_vision(cfg, Path("/c.pem"), Path("/k.pem"))
        self.assertIn("listen 127.0.0.1:8001 default_server;", text)
        self.assertNotIn("8002", text)
        self.assertNotIn("proxy_protocol", text)


if __name__ == "__main__":
    unittest.main()

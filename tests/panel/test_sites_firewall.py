import io
import tempfile
import unittest
import zipfile
from pathlib import Path

import _paths  # noqa: F401
from ezhik_panel import firewall as fw
from ezhik_panel import nginx_routes
from ezhik_panel.sites import SiteError, extract_zip, rewrite


def make_zip(files, symlink=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "/etc/passwd")
    return buffer.getvalue()


class ZipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = Path(self.tmp.name) / "site"

    def tearDown(self):
        self.tmp.cleanup()

    def test_folder_prefix_is_stripped(self):
        count, _size, skipped = extract_zip(make_zip({"mysite/index.html": "<h1>x</h1>", "mysite/css/a.css": "a{}",
                                                      "mysite/run.php": "<?php"}), self.target)
        self.assertEqual(count, 2)
        self.assertTrue((self.target / "css" / "a.css").exists())
        self.assertEqual(skipped, ["mysite/run.php"])

    def test_traversal_rejected(self):
        with self.assertRaises(SiteError):
            extract_zip(make_zip({"../evil.html": "x", "index.html": "y"}), self.target)
        with self.assertRaises(SiteError):
            extract_zip(make_zip({"/abs/index.html": "x"}), self.target)

    def test_symlink_rejected(self):
        with self.assertRaises(SiteError):
            extract_zip(make_zip({"index.html": "y"}, symlink="link.html"), self.target)

    def test_index_required(self):
        with self.assertRaises(SiteError):
            extract_zip(make_zip({"page.html": "x"}), self.target)

    def test_not_zip(self):
        with self.assertRaises(SiteError):
            extract_zip(b"not a zip", self.target)


class SiteServiceTests(unittest.TestCase):
    def test_versions_in_the_same_second_are_unique(self):
        from types import SimpleNamespace
        from ezhik_panel.db import Database
        from ezhik_panel.sites import SiteService
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            sites = SiteService(db, SimpleNamespace(data_dir=Path(tmp)), b"k" * 32)
            first = sites.upload(make_zip({"index.html": b"one"}), "A")
            second = sites.upload(make_zip({"index.html": b"two"}), site_id=first["site"]["id"])
            other = sites.upload(make_zip({"index.html": b"three"}), "B")
            versions = {first["version"], second["version"], other["version"]}
            self.assertEqual(len(versions), 3)
            root = Path(tmp) / "sites" / first["site"]["id"]
            self.assertEqual((root / first["version"] / "index.html").read_bytes(), b"one")
            self.assertEqual((root / second["version"] / "index.html").read_bytes(), b"two")


class RewriteTests(unittest.TestCase):
    def test_root_relative_urls(self):
        html = b'<link href="/css/a.css"><img src="/img/a.png" srcset="/a.png 1x, /b.png 2x">' \
               b'<a href="//cdn.example/x">c</a><a href="page.html">r</a><div style="background:url(/bg.jpg)"></div>'
        out = rewrite(html, "html", "/site-mask/T")
        self.assertIn('href="/site-mask/T/css/a.css"', out)
        self.assertIn('src="/site-mask/T/img/a.png"', out)
        self.assertIn("/site-mask/T/a.png 1x, /site-mask/T/b.png 2x", out)
        self.assertIn('href="//cdn.example/x"', out)
        self.assertIn('href="page.html"', out)
        self.assertIn("url(/site-mask/T/bg.jpg)", out)

    def test_css(self):
        out = rewrite(b"@import '/x.css'; a{background:url('/i.png')} b{background:url(data:x)}", "css", "/p")
        self.assertIn("@import '/p/x.css'", out)
        self.assertIn("url('/p/i.png')", out)
        self.assertIn("url(data:x)", out)

    def test_runtime_shim_and_js_imports(self):
        out = rewrite(b"<html><head><title>t</title></head><body></body></html>", "html", "/site-mask/T")
        self.assertTrue(out.startswith('<html><head><script>(function(){var P="/site-mask/T";'))
        self.assertEqual(out.count("<script>"), 1)
        js = rewrite(b'import a from "/js/a.js"; import("/js/b.js"); x = "/not-an-import";', "js", "/p")
        self.assertIn('from "/p/js/a.js"', js)
        self.assertIn('import("/p/js/b.js")', js)
        self.assertIn('"/not-an-import"', js)


class FirewallPlanTests(unittest.TestCase):
    def plan(self, report, node_fw=None, **kw):
        cfg = fw.validate_global({"enabled_default": True, "remnanode_sources": ["198.51.100.7"]}, {})
        node = {"firewall": __import__("json").dumps(node_fw or {})}
        return fw.plan(node, cfg, report, **kw)

    def report(self):
        return {"ports": {"ssh": [22], "panel_ports": [], "services": [
            {"proto": "tcp", "port": 22, "role": "ssh", "process": "sshd"},
            {"proto": "tcp", "port": 8443, "role": "xray", "process": "xray"},
            {"proto": "tcp", "port": 2222, "role": "remnanode", "process": "node"},
            {"proto": "udp", "port": 2305, "role": "ipvs", "process": "ipvs"},
        ]}}

    def test_classification(self):
        cfg, table = self.plan(self.report(), remnanode_port=2222)
        policies = {e["key"]: e["policy"] for e in table["entries"]}
        self.assertEqual(policies["tcp/8443"], "public")
        self.assertEqual(policies["tcp/2222"], "whitelist")
        self.assertEqual(policies["udp/2305"], "public")
        self.assertNotIn("tcp/22", policies)  # SSH is handled by anti-lockout
        whitelist_rule = next(r for r in cfg["rules"] if r["ports"] == "2222")
        self.assertEqual(whitelist_rule["sources"], ["198.51.100.7/32"])
        self.assertTrue(cfg["enabled"])

    def test_node_override_closes_port(self):
        cfg, table = self.plan(self.report(), {"ports": {"udp/2305": "closed"}})
        self.assertFalse(any(r["ports"] == "2305" for r in cfg["rules"]))

    def test_not_enforced_before_ports_known(self):
        cfg, table = self.plan({})
        self.assertFalse(cfg["enabled"])
        self.assertTrue(table["warnings"])

    def test_inbound_protocols_and_internal_upstreams(self):
        raw = lambda proto, net: {"protocol": proto, "streamSettings": {"network": net}}
        self.assertEqual(fw.inbound_protos(raw("vless", "raw")), ("tcp",))
        self.assertEqual(fw.inbound_protos(raw("vless", "grpc")), ("tcp",))
        self.assertEqual(fw.inbound_protos(raw("vless", "kcp")), ("udp",))
        self.assertEqual(fw.inbound_protos({"protocol": "shadowsocks", "settings": {"network": "tcp,udp"}}), ("tcp", "udp"))
        self.assertEqual(fw.inbound_protos({"protocol": "hysteria"}), ("udp",))
        cfg, table = self.plan(self.report(), inbound_ports=[(9443, ("tcp",)), (10443, ("tcp",))],
                               internal_ports=[10443])
        policies = {e["key"]: e["policy"] for e in table["entries"]}
        self.assertEqual(policies["tcp/9443"], "public")
        self.assertNotIn("udp/9443", policies)
        self.assertEqual(policies["tcp/10443"], "closed")
        self.assertFalse(any(r["ports"] == "10443" for r in cfg["rules"]))
        _, table = self.plan(self.report(), {"ports": {"tcp/10443": "public"}},
                             inbound_ports=[(10443, ("tcp",))], internal_ports=[10443])
        self.assertEqual({e["key"]: e["policy"] for e in table["entries"]}["tcp/10443"], "public")

    def test_nginx_ports_public(self):
        cfg, _ = self.plan(self.report(), nginx_ports=[80, 443])
        self.assertTrue(any(r["ports"] == "443" and not r["sources"] for r in cfg["rules"]))


class RouteCheckTests(unittest.TestCase):
    def rw_node(self, **raw):
        inbound = {"tag": "grpc-in", "port": 10443, "network": "grpc", "security": "none",
                   "rawInbound": {"listen": "127.0.0.1", "port": 10443,
                                  "streamSettings": {"network": "grpc", "security": "none",
                                                     "grpcSettings": {"serviceName": "cdn-service"}}}}
        inbound["rawInbound"].update(raw)
        reality = {"tag": "reality", "port": 443, "network": "tcp", "security": "reality",
                   "rawInbound": {"listen": "0.0.0.0", "port": 443}}
        return {"configProfile": {"activeInbounds": [inbound, reality]}}

    def cfg(self, **route):
        base = {"transport": "grpc", "public_port": 443, "service_name": "cdn-service", "upstream_port": 10443}
        base.update(route)
        return nginx_routes.validate({"mode": "frontend", "routes": [base]})

    def test_conflicting_reality_on_443(self):
        result = nginx_routes.check_routes(self.cfg(), self.rw_node())[0]
        self.assertFalse(result["ok"])
        self.assertTrue(any("занимает публичный порт 443" in p for p in result["problems"]))

    def test_service_name_mismatch(self):
        result = nginx_routes.check_routes(self.cfg(public_port=8443, service_name="other"), self.rw_node())[0]
        self.assertTrue(any("serviceName" in p for p in result["problems"]))

    def test_matching_inbound(self):
        result = nginx_routes.check_routes(self.cfg(public_port=8443), self.rw_node())[0]
        self.assertTrue(result["ok"], result["problems"])

    def test_patch_profile_only_touches_inbound(self):
        config = {"inbounds": [{"tag": "grpc-in", "port": 1, "listen": "0.0.0.0", "streamSettings": {
            "network": "grpc", "security": "tls", "tlsSettings": {"x": 1}}}, {"tag": "other", "port": 2}],
            "outbounds": [{"tag": "direct"}]}
        route = self.cfg(public_port=8443)["routes"][0]
        new = nginx_routes.patch_profile(config, "grpc-in", route)
        inbound = new["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["streamSettings"]["security"], "none")
        self.assertNotIn("tlsSettings", inbound["streamSettings"])
        self.assertEqual(new["inbounds"][1], {"tag": "other", "port": 2})
        self.assertEqual(config["inbounds"][0]["listen"], "0.0.0.0")  # original untouched

    def test_patch_profile_refuses_other_transport_or_reality(self):
        route = self.cfg(public_port=8443)["routes"][0]
        for stream in ({"network": "raw", "security": "reality", "realitySettings": {}}, {"network": "ws"}):
            config = {"inbounds": [{"tag": "x", "port": 1, "streamSettings": stream}]}
            with self.assertRaises(nginx_routes.RouteError):
                nginx_routes.patch_profile(config, "x", route)

    def test_reality_route_rejected(self):
        with self.assertRaises(nginx_routes.RouteError):
            nginx_routes.validate({"mode": "frontend", "routes": [{"transport": "tcp", "upstream_port": 1}]})


if __name__ == "__main__":
    unittest.main()

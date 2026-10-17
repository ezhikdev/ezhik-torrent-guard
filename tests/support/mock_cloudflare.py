#!/usr/bin/env python3
"""Cloudflare DNS API mock that publishes TXT records into pebble-challtestsrv.

usage: mock_cloudflare.py --port 18491 --zone example.com --challtestsrv http://127.0.0.1:18055
Point the panel at it with EZHIK_CLOUDFLARE_API=http://127.0.0.1:18491/client/v4
"""
import argparse
import json
import re
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

records = {}


def challtest(base, path, payload):
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), method="POST")
    urllib.request.urlopen(req, timeout=10).read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18491)
    parser.add_argument("--zone", default="example.com")
    parser.add_argument("--challtestsrv", default="http://127.0.0.1:18055")
    parser.add_argument("--token", default="cf-test-token")
    args = parser.parse_args()
    zone_id = "zone-" + args.zone.replace(".", "-")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def reply(self, payload, code=200):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def auth(self):
            if self.headers.get("Authorization") != f"Bearer {args.token}":
                self.reply({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}, 403)
                return False
            return True

        def do_GET(self):
            if not self.auth():
                return
            if self.path.startswith("/client/v4/user/tokens/verify"):
                return self.reply({"success": True, "result": {"status": "active"}})
            m = re.search(r"/client/v4/zones\?name=([^&]+)", self.path)
            if m:
                found = m.group(1) == args.zone
                return self.reply({"success": True, "result": [{"id": zone_id, "name": args.zone}] if found else []})
            self.reply({"success": False, "errors": [{"message": "not found"}]}, 404)

        def do_POST(self):
            if not self.auth():
                return
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            record_id = uuid.uuid4().hex
            records[record_id] = body
            challtest(args.challtestsrv, "/set-txt", {"host": body["name"] + ".", "value": body["content"]})
            self.reply({"success": True, "result": {"id": record_id, **body}})

        def do_DELETE(self):
            if not self.auth():
                return
            record_id = self.path.rsplit("/", 1)[-1]
            rec = records.pop(record_id, None)
            if rec and not any(r["name"] == rec["name"] for r in records.values()):
                challtest(args.challtestsrv, "/clear-txt", {"host": rec["name"] + "."})
            self.reply({"success": True, "result": {"id": record_id}})

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"mock cloudflare on :{args.port} zone {args.zone}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

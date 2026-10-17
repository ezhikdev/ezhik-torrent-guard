"""In-process Remnawave API mock following the 2.8.x and 3.4.x contracts.

v3: users have no ``uuid``; /api/users/{id}, /api/users/{id}/actions/*.
v2: users have ``uuid``; /api/users/by-id/{id}, /api/users/{uuid}/actions/*.
Unknown routes answer like Nest: 404 with errorCode E000.
"""

import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockRemnawave:
    def __init__(self, api="v3", metadata_allowed=True, token="secret-token"):
        self.api = api
        self.metadata_allowed = metadata_allowed
        self.token = token
        self.users = {}
        self.calls = []
        self.fail_next = {}  # action -> ("apply"|"drop", status)
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def add_user(self, user_id, status="ACTIVE"):
        user = {
            "id": user_id, "shortUuid": uuid.uuid4().hex[:16], "username": f"user{user_id}", "status": status,
            "vlessUuid": str(uuid.uuid4()), "createdAt": "2026-01-01T00:00:00.000Z",
            "expireAt": "2027-01-01T00:00:00.000Z",
        }
        if self.api == "v2":
            user["uuid"] = str(uuid.uuid4())
        self.users[user_id] = user
        return user

    def _find(self, key):
        if self.api == "v3":
            return self.users.get(int(key)) if key.isdigit() else None
        return next((u for u in self.users.values() if u.get("uuid") == key), None)

    def _handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _send(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _error(self, code, error_code, message="error"):
                self._send(code, {"timestamp": "now", "path": self.path, "message": message, "errorCode": error_code})

            def _route(self, method):
                with mock.lock:
                    mock.calls.append((method, self.path))
                if self.headers.get("Authorization") != f"Bearer {mock.token}":
                    return self._error(401, "E401", "Unauthorized")
                path = self.path.split("?")[0]
                if method == "GET" and path == "/api/system/metadata":
                    if not mock.metadata_allowed:
                        return self._error(403, "E403", "Forbidden")
                    version = "3.4.4" if mock.api == "v3" else "2.8.1"
                    return self._send(200, {"response": {"version": version, "build": {"time": "", "number": "1"}}})
                if method == "GET" and path == "/api/users/stream" and mock.api == "v3":
                    return self._send(200, {"response": {"users": list(mock.users.values())[:1], "nextCursor": None}})
                if method == "GET" and path == "/api/users" and mock.api == "v2":
                    return self._send(200, {"response": {"users": list(mock.users.values())[:1]}})
                m = re.fullmatch(r"/api/users/by-id/(\d+)", path)
                if m and method == "GET" and mock.api == "v2":
                    user = mock.users.get(int(m.group(1)))
                    return self._send(200, {"response": user}) if user else self._error(404, "A025", "User not found")
                m = re.fullmatch(r"/api/users/([^/]+)", path)
                if m and method == "GET":
                    if mock.api == "v2" and not re.fullmatch(r"[0-9a-f-]{36}", m.group(1)):
                        return self._send(400, {"message": "Validation failed", "errors": []})
                    user = mock._find(m.group(1))
                    return self._send(200, {"response": user}) if user else self._error(404, "A025", "User not found")
                m = re.fullmatch(r"/api/users/([^/]+)/actions/(disable|enable)", path)
                if m and method == "POST":
                    user = mock._find(m.group(1))
                    if not user:
                        if mock.api == "v2" and m.group(1).isdigit():
                            return self._send(400, {"message": "Validation failed"})
                        return self._error(404, "A025", "User not found")
                    action = m.group(2)
                    target = "DISABLED" if action == "disable" else "ACTIVE"
                    if user["status"] == target:
                        return self._error(400, "A029" if action == "disable" else "A030", "already")
                    failure = mock.fail_next.pop(action, None)
                    if failure:
                        mode, status = failure
                        if mode == "apply":
                            user["status"] = target
                        return self._error(status, "A028", "fail")
                    user["status"] = target
                    return self._send(200, {"response": user})
                return self._error(404, "E000", f"Cannot {method} {path}")

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self._route("POST")

        return Handler


if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Standalone Remnawave API mock")
    parser.add_argument("--api", default="v3", choices=["v2", "v3"])
    parser.add_argument("--port", type=int, default=18490)
    parser.add_argument("--users", default="1-50", help="id range to create, e.g. 1-50")
    parser.add_argument("--token", default="secret-token")
    parser.add_argument("--state", default="mock-remnawave-state.json", help="status dump for test scripts")
    args = parser.parse_args()
    mock = MockRemnawave(api=args.api, token=args.token)
    mock.server.server_close()
    mock.server = ThreadingHTTPServer(("127.0.0.1", args.port), mock._handler())
    low, high = (int(x) for x in args.users.split("-"))
    for uid in range(low, high + 1):
        mock.add_user(uid)

    print(f"mock remnawave {args.api} on {mock.url}", flush=True)
    threading.Thread(target=mock.server.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(5)
            disabled = sorted(u["id"] for u in mock.users.values() if u["status"] != "ACTIVE")
            with open(args.state, "w") as handle:
                json.dump({"disabled": disabled, "calls": mock.calls[-200:]}, handle)
    except KeyboardInterrupt:
        pass

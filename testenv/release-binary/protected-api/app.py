import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Handler(BaseHTTPRequestHandler):
    server_version = "release-protected-api/1.0"

    def log_message(self, format, *args):
        return

    def _send_json(self, status_code, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/v1/health":
            self._send_json(200, {"ok": True, "service": "release-protected-api"})
            return
        if parsed.path == "/v1/products":
            self._send_json(
                200,
                {
                    "items": [
                        {"id": 1, "name": "starter-plan"},
                        {"id": 2, "name": "pro-plan"},
                    ]
                },
            )
            return
        if parsed.path == "/v1/whoami":
            self._send_json(
                200,
                {
                    "host": self.headers.get("Host", ""),
                    "x_forwarded_host": self.headers.get("X-Forwarded-Host", ""),
                    "x_forwarded_proto": self.headers.get("X-Forwarded-Proto", ""),
                    "x_protected_host": self.headers.get("X-Protected-Host", ""),
                },
            )
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/v1/auth/login":
            body_len = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(body_len) if body_len > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                payload = {}
            username = payload.get("username", "unknown")
            self._send_json(
                200,
                {
                    "token": f"demo-token-for-{username}",
                    "issued_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            return
        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()

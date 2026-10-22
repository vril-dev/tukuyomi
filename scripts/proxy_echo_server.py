#!/usr/bin/env python3
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(send_body=False)

    def do_POST(self):
        self._drain_body()
        self._respond()

    def do_PUT(self):
        self._drain_body()
        self._respond()

    def do_PATCH(self):
        self._drain_body()
        self._respond()

    def do_DELETE(self):
        self._drain_body()
        self._respond()

    def do_OPTIONS(self):
        self._respond()

    def log_message(self, _format, *_args):
        return

    def _drain_body(self):
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _respond(self, send_body=True):
        payload = {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "x_service": self.headers.get("X-Service", ""),
            "x_route": self.headers.get("X-Route", ""),
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream-Echo", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

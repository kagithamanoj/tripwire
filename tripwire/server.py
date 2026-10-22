"""Local demo web server (stdlib only). Demo-grade: no auth, no persistence.

On AWS the same API runs in Lambda (see lambda_handler.py).
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import api


class Handler(BaseHTTPRequestHandler):
    def _run(self, method: str) -> None:
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if 0 < n <= api.MAX_BODY else b""
        code, payload, ctype = api.handle(method, self.path, body if n <= api.MAX_BODY else b"x" * (api.MAX_BODY + 1))
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in api.security_headers().items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._run("GET")

    def do_POST(self):
        self._run("POST")

    def log_message(self, *a):  # keep stdout quiet
        pass


def serve(port: int = 8080) -> None:
    print(f"Tripwire on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

#!/usr/bin/env python3
"""mock 上游：HTTP(19000) + HTTPS(19444，自签证书)；任意请求回显 JSON。"""
import hashlib
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _echo(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        info = {
            "method": self.command,
            "path": self.path,
            "headers": hdrs,
            "body_len": len(body),
            "body_sha": hashlib.sha256(body).hexdigest()[:16],
        }
        data = json.dumps(info, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Upstream-Secret", "should-be-removed")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _echo

    def log_message(self, *a):  # noqa: N802
        pass


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", 19000), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("test-cert.pem", "test-key.pem")
    httpsd = ThreadingHTTPServer(("127.0.0.1", 19444), H)
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Thread(target=httpsd.serve_forever, daemon=True).start()
    print("mock upstream up: http 19000 / https 19444", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()

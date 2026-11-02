"""Run a synthetic loopback target: python -m fixtures.safe_targets.server."""

import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow-header":
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                for _ in range(40):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(0.05)
                self.wfile.write(b"\r\nContent-Length: 0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if self.path == "/redirect-outside":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        elif self.path == "/redirect-inside":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_inside_path)
        elif self.path == "/redirect-excluded":
            self.send_response(302)
            self.send_header("Location", "/excluded")
        elif self.path == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
        else:
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Demo-Secret", "never-retain-this-header-value")
        if self.path == "/large-headers":
            self.send_header("X-Large", "x" * 65000)
            self.send_header("X-Large-2", "x" * 1000)
        if self.server.secure_headers:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Set-Cookie",
                "demo=never-retain-this-cookie-value; HttpOnly; SameSite=Strict; Path=/",
            )
        else:
            self.send_header("Set-Cookie", "demo=never-retain-this-cookie-value; Path=/")
        self.end_headers()
        try:
            self.wfile.write(b"<h1>Synthetic SHARAY laboratory fixture</h1><p>never-retain-this-body</p>")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format, *args):
        pass


def create_server(port: int = 0, secure_headers: bool = False) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)
    server.secure_headers = secure_headers
    server.redirect_inside_path = "/app"
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument(
        "--secure-headers",
        action="store_true",
        help="Enable the seeded remediation for retesting.",
    )
    args = parser.parse_args()
    server = create_server(args.port, args.secure_headers)
    print(
        f"Synthetic laboratory listening at http://127.0.0.1:{server.server_port}/",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

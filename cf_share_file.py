#!/usr/bin/env python3
"""Share one file over the internet through a Cloudflare quick tunnel.

Serves FILE on a local HTTP server (127.0.0.1, random port), starts
`cloudflared tunnel --url ...` and prints the public URL of the file.
With --auth USER:PASSWORD every request needs HTTP Basic Auth.
Ctrl+C stops the server and the tunnel.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TUNNEL_URL = re.compile(r"https://(?!api\.)[a-z0-9-]+\.trycloudflare\.com")


def make_handler(path: str, url_path: str, auth: str | None):
    expected = "Basic " + base64.b64encode(auth.encode()).decode() if auth else None
    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    name = os.path.basename(path)
    disposition = "inline; filename*=UTF-8''" + urllib.parse.quote(name)

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, body: bool) -> None:
            if expected and not hmac.compare_digest(
                self.headers.get("Authorization", "").encode(), expected.encode()
            ):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="cf_share_file"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if urllib.parse.urlsplit(self.path).path != url_path:
                self.send_error(404)
                return
            try:
                f = open(path, "rb")
            except OSError:
                self.send_error(404)
                return
            with f:
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(os.fstat(f.fileno()).st_size))
                self.send_header("Content-Disposition", disposition)
                self.end_headers()
                if body:
                    try:
                        shutil.copyfileobj(f, self.wfile)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

        def do_GET(self) -> None:
            self._serve(True)

        def do_HEAD(self) -> None:
            self._serve(False)

    return Handler


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("file", help="file to share")
    p.add_argument("--auth", metavar="USER:PASSWORD", help="require HTTP Basic Auth")
    p.add_argument("--port", type=int, default=0, help="local port (default: random)")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        p.error(f"not a file: {args.file}")
    if args.auth is not None and ":" not in args.auth:
        p.error("--auth must be USER:PASSWORD")
    if not shutil.which("cloudflared"):
        p.error("cloudflared not found in PATH")

    path = os.path.abspath(args.file)
    url_path = "/" + urllib.parse.quote(os.path.basename(path))
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), make_handler(path, url_path, args.auth)
    )
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Local:  http://127.0.0.1:{port}{url_path}", file=sys.stderr)

    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    try:
        found = False
        log = []
        for line in proc.stderr:  # keep draining so cloudflared never blocks
            if not found:
                log.append(line)
                m = TUNNEL_URL.search(line)
                if m:
                    found = True
                    print(m.group(0) + url_path, flush=True)
                    print("(DNS may need a few seconds; Ctrl+C to stop)", file=sys.stderr)
        code = proc.wait()
        if not found:
            sys.stderr.write("".join(log[-20:]))
        print(f"cloudflared exited with code {code}", file=sys.stderr)
        return code or 1
    except KeyboardInterrupt:
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        server.shutdown()


if __name__ == "__main__":
    sys.exit(main())

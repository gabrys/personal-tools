import base64
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cloudflared_notify  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "cloudflared_notify.py"

FAKE_CLOUDFLARED = """#!/usr/bin/env python3
import sys, time
print("INF Requesting new quick Tunnel on trycloudflare.com...", flush=True)
print("INF |  https://quiet-river-1234.trycloudflare.com  |", flush=True)
print("ARGS " + " ".join(sys.argv[1:]), flush=True)
time.sleep(30)
"""


class NoteStub:
    """Records POSTs; replies with the queued statuses, then 201."""

    def __init__(self, statuses=()):
        self.posts = []
        self.statuses = list(statuses)
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                stub.posts.append((self.path, self.headers.get("Authorization"), self.headers.get_content_type(), body))
                status = stub.statuses.pop(0) if stub.statuses else 201
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/note/Tunnel"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def wait_posts(self, n, timeout=5.0):
        deadline = time.time() + timeout
        while len(self.posts) < n and time.time() < deadline:
            time.sleep(0.02)
        return self.posts


class TunnelUrlTest(unittest.TestCase):
    def test_matches_quick_tunnel_url_only(self):
        m = cloudflared_notify.TUNNEL_URL.search("INF |  https://quiet-river-1234.trycloudflare.com  |")
        self.assertEqual(m.group(0), "https://quiet-river-1234.trycloudflare.com")
        self.assertIsNone(cloudflared_notify.TUNNEL_URL.search('Post "https://api.trycloudflare.com/tunnel"'))
        self.assertIsNone(cloudflared_notify.TUNNEL_URL.search("https://www.cloudflare.com/website-terms/"))


class NotifierTest(unittest.TestCase):
    def setUp(self):
        self.stub = None

    def tearDown(self):
        if self.stub:
            self.stub.close()

    def test_posts_text_plain_with_basic_auth(self):
        self.stub = NoteStub()
        n = cloudflared_notify.Notifier(self.stub.url, "alice", "s3cret", delays=(0.01,))
        n.submit("https://a-b.trycloudflare.com").join(5)
        path, auth, ctype, body = self.stub.posts[0]
        self.assertEqual(path, "/note/Tunnel")
        self.assertEqual(auth, "Basic " + base64.b64encode(b"alice:s3cret").decode())
        self.assertEqual(ctype, "text/plain")
        self.assertEqual(body, b"https://a-b.trycloudflare.com\n")

    def test_no_auth_header_without_user(self):
        self.stub = NoteStub()
        n = cloudflared_notify.Notifier(self.stub.url, None, "", delays=(0.01,))
        n.submit("https://a-b.trycloudflare.com").join(5)
        self.assertIsNone(self.stub.posts[0][1])

    def test_retries_server_errors(self):
        self.stub = NoteStub(statuses=[502, 503])
        n = cloudflared_notify.Notifier(self.stub.url, "u", "p", delays=(0.01,))
        n.submit("https://a-b.trycloudflare.com").join(5)
        self.assertEqual(len(self.stub.posts), 3)

    def test_does_not_retry_unauthorized(self):
        self.stub = NoteStub(statuses=[401, 401])
        n = cloudflared_notify.Notifier(self.stub.url, "u", "wrong", delays=(0.01,))
        n.submit("https://a-b.trycloudflare.com").join(5)
        self.assertEqual(len(self.stub.posts), 1)

    def test_newer_url_cancels_older_retries(self):
        n = cloudflared_notify.Notifier("http://127.0.0.1:9/note/x", "u", "p", delays=(30,))
        old = n.submit("https://old.trycloudflare.com")
        time.sleep(0.2)
        n.current = "https://new.trycloudflare.com"
        n.wake.set()
        old.join(5)
        self.assertFalse(old.is_alive())


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = Path(self.tmp.name) / "cloudflared"
        self.fake.write_text(FAKE_CLOUDFLARED)
        self.fake.chmod(0o755)
        self.stub = NoteStub()

    def tearDown(self):
        self.stub.close()
        self.tmp.cleanup()

    def _start(self):
        env = {**os.environ, "AAP_TUNNEL_POST_USER": "alice", "AAP_TUNNEL_POST_PASSWORD": "pw"}
        return subprocess.Popen(
            [sys.executable, str(SCRIPT), "--url", "http://localhost:8787/", "--post-url", self.stub.url,
             "--cloudflared", str(self.fake)],
            env=env, stderr=subprocess.PIPE, text=True,
        )

    def test_posts_url_and_exits_cleanly_on_sigterm(self):
        proc = self._start()
        try:
            posts = self.stub.wait_posts(1)
            self.assertEqual(posts[0][3], b"https://quiet-river-1234.trycloudflare.com\n")
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(5), 0)
            err = proc.stderr.read()
            self.assertIn("ARGS tunnel --no-autoupdate --url http://localhost:8787/", err)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stderr.close()

    def test_exits_nonzero_when_cloudflared_dies(self):
        self.fake.write_text("#!/bin/sh\necho boom\nexit 0\n")
        proc = self._start()
        try:
            self.assertEqual(proc.wait(5), 1)
        finally:
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()

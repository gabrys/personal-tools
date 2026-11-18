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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cloudflared_notify  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "cloudflared_notify.py"

FAKE_CLOUDFLARED = """#!/usr/bin/env python3
import sys, time
print("INF Requesting new quick Tunnel on trycloudflare.com...", flush=True)
print("INF |  https://quiet-river-1234.trycloudflare.com  |", flush=True)
print("ARGS " + " ".join(sys.argv[1:]), flush=True)
import os
print("ENV " + " ".join(sorted(k for k in os.environ if k.startswith("AAP_"))), flush=True)
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


class StatusStub:
    """Answers GET /api/status with the queued (status, body) pairs, then the last one."""

    def __init__(self, replies):
        self.replies = list(replies)
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                status, body = stub.replies.pop(0) if len(stub.replies) > 1 else stub.replies[0]
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class CheckStatusTest(unittest.TestCase):
    def test_ok_and_failures(self):
        stub = StatusStub([(200, '{"status": "OK"}'), (200, '{"status": "DOWN"}'), (502, "bad gateway"),
                           (200, "<html>")])
        try:
            self.assertIsNone(cloudflared_notify.check_status(stub.url + "/"))
            self.assertIn("unexpected response", cloudflared_notify.check_status(stub.url))
            self.assertEqual(cloudflared_notify.check_status(stub.url), "HTTP 502 Bad Gateway")
            self.assertIn("unexpected response", cloudflared_notify.check_status(stub.url))
        finally:
            stub.close()
        self.assertIsNotNone(cloudflared_notify.check_status("http://127.0.0.1:9", timeout=2))


FAST_HEALTH = dict(HEALTH_INTERVAL=0.02, HEALTH_JITTER=0.01)


class WatchTunnelTest(unittest.TestCase):
    PUBLIC = "https://a-b.trycloudflare.com"
    LOCAL = "http://127.0.0.1:8787"

    def _watch(self, public_results, local_ok=True, seconds=None):
        calls = []
        results = list(public_results)

        def check(base):
            calls.append(base)
            if base == self.LOCAL:
                return None if local_ok else "connection refused"
            return results.pop(0) if results else None

        dead, stopped = threading.Event(), threading.Event()
        with mock.patch.multiple(cloudflared_notify, check_status=check, **FAST_HEALTH):
            t = threading.Thread(target=cloudflared_notify.watch_tunnel,
                                 args=(self.PUBLIC, self.LOCAL, stopped, dead.set))
            t.start()
            if seconds is not None:
                time.sleep(seconds)
                stopped.set()
            t.join(5)
        return dead, calls

    def test_replaces_after_consecutive_public_only_failures(self):
        dead, calls = self._watch(["HTTP 530"] * 3)
        self.assertTrue(dead.is_set())
        self.assertEqual(calls[:2], [self.PUBLIC, self.LOCAL])  # both, on every tick

    def test_success_resets_the_count(self):
        dead, _ = self._watch(["x", "x", None, "x", "x", None], seconds=0.5)
        self.assertFalse(dead.is_set())

    def test_local_outage_does_not_replace(self):
        dead, calls = self._watch(["x"] * 20, local_ok=False, seconds=0.5)
        self.assertFalse(dead.is_set())
        self.assertGreater(len(calls), 4)


FLAKY_CLOUDFLARED = """#!/usr/bin/env python3
import pathlib, sys, time
counter = pathlib.Path(sys.argv[0] + ".runs")
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
print(f"INF |  https://tunnel-{n}.trycloudflare.com  |", flush=True)
time.sleep(30)
"""


class ReplaceTunnelTest(unittest.TestCase):
    def test_dead_tunnel_is_replaced_and_new_url_posted(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "cloudflared"
            fake.write_text(FLAKY_CLOUDFLARED)
            fake.chmod(0o755)
            stub = NoteStub()
            local = StatusStub([(200, '{"status": "OK"}')])
            original = cloudflared_notify.check_status

            def check(base, timeout=10.0):
                # Tunnel 1 is dead; tunnel 2 and the local service are fine.
                return "HTTP 530" if "tunnel-1." in base else original(base, timeout)

            def stop_when_done():
                stub.wait_posts(2, timeout=10)
                os.kill(os.getpid(), signal.SIGTERM)

            old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
            threading.Thread(target=stop_when_done, daemon=True).start()
            try:
                with mock.patch.multiple(cloudflared_notify, check_status=check, HEALTH_FAILURES=2, **FAST_HEALTH):
                    code = cloudflared_notify.main(
                        ["--url", local.url, "--post-url", stub.url, "--cloudflared", str(fake)])
            finally:
                signal.signal(signal.SIGTERM, old_term)
                signal.signal(signal.SIGINT, old_int)
                stub.close()
                local.close()
            self.assertEqual(code, 0)
            self.assertEqual([p[3] for p in stub.posts[:2]],
                             [b"https://tunnel-1.trycloudflare.com\n", b"https://tunnel-2.trycloudflare.com\n"])
            self.assertEqual((Path(tmp) / "cloudflared.runs").read_text(), "2")


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
            self.assertNotIn("AAP_TUNNEL_POST", err)  # credentials never reach cloudflared
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

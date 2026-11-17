#!/usr/bin/env python3
"""Run a Cloudflare quick tunnel and POST its public URL to a note.

Starts `cloudflared tunnel --url URL`, passes its output through, and when the
https://*.trycloudflare.com address appears, POSTs it as text/plain to
--post-url. Basic auth credentials come from AAP_TUNNEL_POST_USER and
AAP_TUNNEL_POST_PASSWORD (environment, so they never show up in `ps`).

A failed POST never stops the tunnel: network and 5xx errors are retried with
backoff, other HTTP errors (e.g. 401) are logged once. The script exits with
cloudflared's exit code.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request

TUNNEL_URL = re.compile(r"https://(?!api\.)[a-z0-9-]+\.trycloudflare\.com")
RETRY_DELAYS = (2, 5, 10, 30, 60, 120, 300)
RETRYABLE_STATUSES = {408, 429}


def log(msg: str) -> None:
    print(f"[cloudflared_notify] {msg}", file=sys.stderr, flush=True)


def post_note(post_url: str, text: str, user: str | None, password: str, timeout: float = 15.0) -> int:
    req = urllib.request.Request(
        post_url,
        data=text.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    if user:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


class Notifier:
    """Posts the newest tunnel URL; a newer URL cancels retries for an older one."""

    def __init__(self, post_url: str, user: str | None, password: str, delays=RETRY_DELAYS) -> None:
        self.post_url = post_url
        self.user = user
        self.password = password
        self.delays = delays
        self.current: str | None = None
        self.wake = threading.Event()
        self.lock = threading.Lock()

    def submit(self, tunnel_url: str) -> threading.Thread:
        with self.lock:
            self.current = tunnel_url
        self.wake.set()  # interrupt a pending retry for an older URL
        thread = threading.Thread(target=self._run, args=(tunnel_url,), daemon=True)
        thread.start()
        return thread

    def _is_current(self, tunnel_url: str) -> bool:
        with self.lock:
            return self.current == tunnel_url

    def _run(self, tunnel_url: str) -> None:
        self.wake.clear()
        attempt = 0
        while self._is_current(tunnel_url):
            try:
                status = post_note(self.post_url, tunnel_url + "\n", self.user, self.password)
                log(f"posted {tunnel_url} to {self.post_url} (HTTP {status})")
                return
            except urllib.error.HTTPError as exc:
                if exc.code < 500 and exc.code not in RETRYABLE_STATUSES:
                    log(f"posting to {self.post_url} failed: HTTP {exc.code} {exc.reason}; not retrying")
                    return
                err = f"HTTP {exc.code} {exc.reason}"
            except (urllib.error.URLError, OSError) as exc:
                err = str(getattr(exc, "reason", exc))
            delay = self.delays[min(attempt, len(self.delays) - 1)]
            attempt += 1
            log(f"posting to {self.post_url} failed: {err}; retrying in {delay}s")
            if self.wake.wait(delay):
                return  # a newer URL took over


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Cloudflare quick tunnel and POST its URL to a note")
    parser.add_argument("--url", required=True, help="local service to expose, e.g. http://localhost:8787")
    parser.add_argument("--post-url", required=True, help="where to POST the tunnel URL (text/plain)")
    parser.add_argument("--cloudflared", default="cloudflared", help="cloudflared executable")
    args = parser.parse_args(argv)

    user = os.environ.get("AAP_TUNNEL_POST_USER") or None
    password = os.environ.get("AAP_TUNNEL_POST_PASSWORD", "")
    if not user:
        log("AAP_TUNNEL_POST_USER is not set; posting without basic auth")

    proc = subprocess.Popen(
        [args.cloudflared, "tunnel", "--no-autoupdate", "--url", args.url],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    stopping = threading.Event()

    def stop(signum: int, _frame) -> None:
        stopping.set()
        proc.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    notifier = Notifier(args.post_url, user, password)
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stderr.write(line)
        sys.stderr.flush()
        match = TUNNEL_URL.search(line)
        if match and match.group(0) != notifier.current:
            log(f"tunnel URL: {match.group(0)}")
            notifier.submit(match.group(0))
    code = proc.wait()
    log(f"cloudflared exited with {code}")
    if stopping.is_set():
        return 0  # asked to stop: a clean exit, not a failure for systemd
    return code if code > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

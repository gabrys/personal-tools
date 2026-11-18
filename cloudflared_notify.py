#!/usr/bin/env python3
"""Run a Cloudflare quick tunnel and POST its public URL to a note.

Starts `cloudflared tunnel --url URL`, passes its output through, and when the
https://*.trycloudflare.com address appears, POSTs it as text/plain to
--post-url. Basic auth credentials come from AAP_TUNNEL_POST_USER and
AAP_TUNNEL_POST_PASSWORD (environment, so they never show up in `ps`).

A failed POST never stops the tunnel: network and 5xx errors are retried with
backoff, other HTTP errors (e.g. 401) are logged once.

Quick tunnels sometimes stop serving while cloudflared keeps running, so the
public URL's --health-path (default /api/status) is polled about once a
minute. After --health-failures failed checks in a row, while the same path
still answers on the local --url, cloudflared is restarted for a fresh tunnel
whose URL is posted again. Otherwise the script exits with cloudflared's exit
code.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
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


def check_status(base_url: str, path: str, timeout: float = 10.0) -> str | None:
    """GET base_url + path; None when it answers 200 {"status": "OK"}, else why not."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}),
                                    timeout=timeout) as resp:
            body = resp.read(4096)
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code} {exc.reason}"
    except (urllib.error.URLError, OSError) as exc:
        return str(getattr(exc, "reason", exc))
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "response is not JSON"
    if not isinstance(data, dict) or data.get("status") != "OK":
        return f"unexpected response: {body[:200]!r}"
    return None


class HealthWatcher:
    """Polls the public tunnel URL; calls on_dead() once it has failed
    `failures` times in a row while the local service still answers."""

    def __init__(self, local_url: str, path: str, on_dead, interval: float = 60.0, jitter: float = 15.0,
                 failures: int = 3, retry_delay: float | None = None, check=None) -> None:
        self.local_url = local_url
        self.path = path
        self.on_dead = on_dead
        self.interval = interval
        self.jitter = jitter
        self.failures = failures
        # After a failure, recheck sooner than the regular interval.
        self.retry_delay = min(10.0, interval) if retry_delay is None else retry_delay
        self.check = check or (lambda base, path: check_status(base, path))
        self.public_url: str | None = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def watch(self, public_url: str) -> None:
        self.public_url = public_url
        if not self.thread.is_alive():
            self.thread.start()

    def stop(self) -> None:
        self.stopped.set()

    def _run(self) -> None:
        failed = 0
        # The first check waits a full interval: a fresh hostname needs time to resolve.
        delay = self.interval + random.uniform(-self.jitter, self.jitter)
        while not self.stopped.wait(max(delay, 0.0)):
            url = self.public_url
            assert url is not None
            err = self.check(url, self.path)
            if err is None:
                if failed:
                    log(f"{url} is answering again")
                failed = 0
            else:
                local_err = self.check(self.local_url, self.path)
                if local_err is not None:
                    # The tunnel is not the problem; a new one would not help.
                    log(f"{url} check failed ({err}), but so does {self.local_url} ({local_err}); keeping the tunnel")
                    failed = 0
                else:
                    failed += 1
                    log(f"{url} check failed ({err}); {failed}/{self.failures}")
                    if failed >= self.failures:
                        log(f"{url} looks dead; restarting cloudflared for a new tunnel")
                        self.stopped.set()
                        self.on_dead()
                        return
            if failed:
                delay = self.retry_delay
            else:
                delay = self.interval + random.uniform(-self.jitter, self.jitter)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Cloudflare quick tunnel and POST its URL to a note")
    parser.add_argument("--url", required=True, help="local service to expose, e.g. http://localhost:8787")
    parser.add_argument("--post-url", required=True, help="where to POST the tunnel URL (text/plain)")
    parser.add_argument("--cloudflared", default="cloudflared", help="cloudflared executable")
    parser.add_argument("--health-path", default="/api/status",
                        help='path that must answer {"status": "OK"} through the tunnel; empty disables the check')
    parser.add_argument("--health-interval", type=float, default=60.0, help="seconds between checks (default 60)")
    parser.add_argument("--health-jitter", type=float, default=15.0,
                        help="random +/- seconds added to each interval (default 15)")
    parser.add_argument("--health-failures", type=int, default=3,
                        help="failed checks in a row before the tunnel is replaced (default 3)")
    args = parser.parse_args(argv)

    user = os.environ.get("AAP_TUNNEL_POST_USER") or None
    password = os.environ.get("AAP_TUNNEL_POST_PASSWORD", "")
    if not user:
        log("AAP_TUNNEL_POST_USER is not set; posting without basic auth")

    # cloudflared logs its environment at startup; keep our credentials out of it.
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("AAP_TUNNEL_")}
    stopping = threading.Event()
    current: dict[str, subprocess.Popen] = {}

    def stop(signum: int, _frame) -> None:
        stopping.set()
        if "proc" in current:
            current["proc"].terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    notifier = Notifier(args.post_url, user, password)
    while not stopping.is_set():
        proc = subprocess.Popen(
            [args.cloudflared, "tunnel", "--no-autoupdate", "--url", args.url],
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        current["proc"] = proc
        if stopping.is_set():  # a signal arrived before `proc` was registered
            proc.terminate()
        replace = threading.Event()

        def tunnel_dead(proc: subprocess.Popen = proc, replace: threading.Event = replace) -> None:
            replace.set()
            proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()

        watcher = HealthWatcher(args.url, args.health_path, tunnel_dead, interval=args.health_interval,
                                jitter=args.health_jitter, failures=args.health_failures)
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stderr.write(line)
            sys.stderr.flush()
            match = TUNNEL_URL.search(line)
            if not match:
                continue
            if match.group(0) != notifier.current:
                log(f"tunnel URL: {match.group(0)}")
                notifier.submit(match.group(0))
            if args.health_path:
                watcher.watch(match.group(0))
        code = proc.wait()
        watcher.stop()
        log(f"cloudflared exited with {code}")
        if stopping.is_set():
            break
        if not replace.is_set():
            return code if code > 0 else 1
        log("starting a new tunnel")
    return 0  # asked to stop: a clean exit, not a failure for systemd


if __name__ == "__main__":
    raise SystemExit(main())

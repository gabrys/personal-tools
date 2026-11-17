import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import time
import tomllib
import unittest
import urllib.error
import urllib.request

import aap_ui


class AAPUITest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.rules_path = Path(self.tmp.name) / "rules.json"
        self.hub = aap_ui.ApprovalHub(aap_ui.RuleStore(self.rules_path))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), aap_ui.make_handler(self.hub))
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _req(self, method: str, path: str, body: dict | None = None, headers: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method,
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def _wait_review_done(self, req_id: str, timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            _, rec = self._req("GET", f"/api/aap/v1/requests/{req_id}")
            if (rec.get("review") or {}).get("status") == "done" or time.monotonic() > deadline:
                return rec
            time.sleep(0.02)

    def test_aap_idempotency_and_lifecycle(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._req("POST", "/api/aap/v1/requests", {"tool": "Bash", "arguments": {"command": "ls"}})
        self.assertEqual(ctx.exception.code, 400)

        payload = {"tool": "Bash", "arguments": {"command": "git status"}}
        status, created = self._req(
            "POST", "/api/aap/v1/requests", payload, {"Idempotency-Key": "k1"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["status"], "pending")
        self.assertEqual(created["command_tokens"], ["git", "status"])
        self.assertEqual(created["command_prefixes"], ["git *", "git status *"])

        status2, replayed = self._req(
            "POST", "/api/aap/v1/requests", payload, {"Idempotency-Key": "k1"}
        )
        self.assertEqual(status2, 200)
        self.assertEqual(replayed["id"], created["id"])

        with self.assertRaises(urllib.error.HTTPError) as ctx2:
            self._req(
                "POST",
                "/api/aap/v1/requests",
                {"tool": "Bash", "arguments": {"command": "rm -rf /"}},
                {"Idempotency-Key": "k1"},
            )
        self.assertEqual(ctx2.exception.code, 409)

        # Approve once and consume
        status3, decided = self._req(
            "POST",
            f"/api/ui/requests/{created['id']}/decision",
            {"decision": "approved"},
        )
        self.assertEqual(status3, 200)
        self.assertEqual(decided["status"], "approved")

        status4, consumed = self._req(
            "POST", f"/api/aap/v1/requests/{created['id']}/consume", {}
        )
        self.assertEqual(status4, 200)
        self.assertIsNotNone(consumed["consumption"]["consumed_at"])

    def test_allow_always_prefix_and_tool_rules(self) -> None:
        _, r1 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "git status -s"}},
            {"Idempotency-Key": "p1"},
        )
        _, r2 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "git status --branch"}},
            {"Idempotency-Key": "p2"},
        )
        # Allow always with prefix "git status *" should approve both r1 and pending r2
        self._req(
            "POST",
            f"/api/ui/requests/{r1['id']}/decision",
            {"decision": "approved", "allow_always": "prefix", "prefix": "git status *"},
        )
        _, r2_after = self._req("GET", f"/api/aap/v1/requests/{r2['id']}")
        self.assertEqual(r2_after["status"], "approved")

        # Subsequent matching call auto-approves immediately
        _, r3 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "git status"}},
            {"Idempotency-Key": "p3"},
        )
        self.assertEqual(r3["status"], "approved")

        # Non-matching command still waits in queue
        _, r4 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "git push origin main"}},
            {"Idempotency-Key": "p4"},
        )
        self.assertEqual(r4["status"], "pending")

        # Delete the rule and verify git status is pending again
        rules = self.hub.rules.list_rules()
        self.assertEqual(len(rules), 1)
        self._req("DELETE", f"/api/ui/rules/{rules[0]['id']}")
        _, r5 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "git status"}},
            {"Idempotency-Key": "p5"},
        )
        self.assertEqual(r5["status"], "pending")

    def test_hook_end_to_end_allow_and_deny(self) -> None:
        # Pre-seed a tool rule for Read so hook resolves immediately
        self.hub.rules.add_rule(aap_ui.Rule(id="r-read", kind="tool", tool="Read", action="allow"))

        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = aap_ui.run_hook(
                "claude-code",
                self.base_url,
                stdin_text=json.dumps({"tool_name": "Read", "tool_input": {"file_path": "a.py"}}),
            )
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "allow")

        # Codex allow exits 0 with empty stdout (Codex rejects permissionDecision:allow without updatedInput)
        buf_codex = io.StringIO()
        with redirect_stdout(buf_codex):
            rc_codex = aap_ui.run_hook(
                "codex",
                self.base_url,
                stdin_text=json.dumps({"tool_name": "Read", "tool_input": {"file_path": "a.py"}}),
            )
        self.assertEqual(rc_codex, 0)
        self.assertEqual(buf_codex.getvalue(), "")

        # Test deny in background thread while hook long-polls
        def deny_soon() -> None:
            import time
            for _ in range(50):
                state = self.hub.ui_state()
                if state["pending"]:
                    self.hub.decide_request(state["pending"][0]["id"], "denied", reason="No rm")
                    return
                time.sleep(0.02)

        t = threading.Thread(target=deny_soon, daemon=True)
        t.start()
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            rc2 = aap_ui.run_hook(
                "codex",
                self.base_url,
                stdin_text=json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf x"}}),
            )
        self.assertEqual(rc2, 0)
        out2 = json.loads(buf2.getvalue())
        self.assertEqual(out2["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(out2["hookSpecificOutput"]["permissionDecisionReason"], "No rm")

    def test_install_and_eject_claude_and_codex(self) -> None:
        claude_cfg = Path(self.tmp.name) / "settings.json"
        claude_cfg.write_text('{"theme": "auto"}\n', encoding="utf-8")
        codex_cfg = Path(self.tmp.name) / "config.toml"
        codex_cfg.write_text("model = 'gpt-6.1-sol'\n", encoding="utf-8")

        script = Path(aap_ui.__file__).resolve()
        aap_ui.install_claude(script, claude_cfg, "http://127.0.0.1:8787")
        aap_ui.install_codex(script, codex_cfg, "http://127.0.0.1:8787")

        c_data = json.loads(claude_cfg.read_text(encoding="utf-8"))
        self.assertIn("PreToolUse", c_data["hooks"])
        x_data = tomllib.loads(codex_cfg.read_text(encoding="utf-8"))
        self.assertIn("PreToolUse", x_data["hooks"])

        aap_ui.eject_claude(claude_cfg)
        aap_ui.eject_codex(codex_cfg)

        c_after = json.loads(claude_cfg.read_text(encoding="utf-8"))
        self.assertNotIn("hooks", c_after)
        x_after = tomllib.loads(codex_cfg.read_text(encoding="utf-8"))
        self.assertNotIn("hooks", x_after)
        self.assertEqual(x_after["model"], "gpt-6.1-sol")

    def test_antigravity_hook_and_install(self) -> None:
        self.hub.rules.add_rule(
            aap_ui.Rule(
                id="r-agy",
                kind="command_prefix",
                tool="run_command",
                action="allow",
                prefix="pytest *",
            )
        )
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = aap_ui.run_hook(
                "antigravity",
                self.base_url,
                stdin_text=json.dumps(
                    {
                        "toolCall": {
                            "id": "tc-1",
                            "name": "run_command",
                            "args": {"CommandLine": "pytest -q"},
                        },
                        "cwd": "/tmp",
                    }
                ),
            )
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["decision"], "allow")

        agy_hooks = Path(self.tmp.name) / "hooks.json"
        script = Path(aap_ui.__file__).resolve()
        aap_ui.install_antigravity(script, agy_hooks, "http://127.0.0.1:8787")
        data = json.loads(agy_hooks.read_text(encoding="utf-8"))
        self.assertIn("aap-ui", data)
        aap_ui.eject_antigravity(agy_hooks)
        data_after = json.loads(agy_hooks.read_text(encoding="utf-8"))
        self.assertNotIn("aap-ui", data_after)

    def test_usage_endpoint_fetches_in_background_and_throttles(self) -> None:
        calls = []
        release = threading.Event()

        def fake_fetch():
            calls.append(1)
            release.wait(5)
            return {"providers": {"codex": {"name": "Codex", "error": None, "groups": []}}, "agents": {}}

        cache = aap_ui.UsageCache(fetch=fake_fetch, interval=60)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), aap_ui.make_handler(self.hub, usage=cache))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        url = f"http://127.0.0.1:{srv.server_address[1]}/api/ui/usage"

        def get():
            with urllib.request.urlopen(url, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))

        first = get()
        self.assertTrue(first["loading"])
        self.assertIsNone(first["data"])
        self.assertTrue(get()["loading"])

        release.set()
        deadline = time.monotonic() + 5
        while (snap := get())["loading"] and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(snap["data"]["providers"]["codex"]["name"], "Codex")
        self.assertIsNotNone(snap["updated_at"])
        self.assertEqual(len(calls), 1)

    def test_usage_cache_reports_fetch_errors(self) -> None:
        def broken():
            raise RuntimeError("boom")

        cache = aap_ui.UsageCache(fetch=broken, interval=60)
        cache.snapshot()
        deadline = time.monotonic() + 5
        while (snap := cache.snapshot())["loading"] and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(snap["error"], "boom")
        self.assertIsNone(snap["data"])

    def test_tab_urls_serve_the_ui(self) -> None:
        for path in ("/", "/history", "/ai-usage"):
            with urllib.request.urlopen(f"{self.base_url}{path}", timeout=5.0) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("AAP Approval Queue", resp.read().decode("utf-8"))
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(f"{self.base_url}/nope", timeout=5.0)

    def test_restart_endpoint(self) -> None:
        called = threading.Event()
        srv = ThreadingHTTPServer(
            ("127.0.0.1", 0), aap_ui.make_handler(self.hub, on_restart=called.set)
        )
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{srv.server_address[1]}/api/ui/restart",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.assertEqual(resp.status, 202)
            self.assertTrue(called.wait(timeout=2.0))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_choose_review_agent(self) -> None:
        def usage(claude: float | None, codex: float | None) -> dict:
            def prov(pct: float | None) -> dict:
                if pct is None:
                    return {"error": "boom", "groups": []}
                return {"groups": [{"windows": [
                    {"label": "5h", "used_percent": pct},
                    {"label": "Weekly", "used_percent": 99},
                ]}]}
            return {"providers": {"claude": prov(claude), "codex": prov(codex)}}

        pick = lambda rt, c, x: aap_ui.choose_review_agent(rt, usage(c, x))[0]
        # Both under 80%: the competitor reviews.
        self.assertEqual(pick("claude-code", 70, 10), "codex")
        self.assertEqual(pick("codex", 10, 70), "claude")
        # Either over 80%: lower usage wins, even if that is the requester.
        self.assertEqual(pick("claude-code", 10, 85), "claude")
        self.assertEqual(pick("codex", 90, 85), "codex")
        self.assertEqual(pick("codex", 80, 20), "codex")
        # Other requesters: lower usage wins.
        self.assertEqual(pick("antigravity", 30, 20), "codex")
        self.assertEqual(pick("antigravity", 20, 30), "claude")
        # Ties prefer the competitor.
        self.assertEqual(pick("claude-code", 90, 90), "codex")
        # Unknown usage.
        self.assertEqual(pick("antigravity", None, 50), "codex")
        self.assertEqual(pick("claude-code", None, None), "codex")
        self.assertEqual(aap_ui.choose_review_agent("antigravity", None)[0], "claude")

    def test_review_uses_chosen_agent(self) -> None:
        class FakeUsage:
            def snapshot(self) -> dict:
                return {"data": {"providers": {
                    "claude": {"groups": [{"windows": [{"label": "5h", "used_percent": 10}]}]},
                    "codex": {"groups": [{"windows": [{"label": "5h", "used_percent": 20}]}]},
                }}}

        self.hub.usage = FakeUsage()
        # The stub echoes the --agent it received as the explanation.
        self.hub.review_cmd = [
            sys.executable,
            "-c",
            "import json, sys; sys.stdin.read(); print(json.dumps({'decision': 'accept', 'explanation': sys.argv[-1], 'deny_reason': ''}))",
        ]
        _, req = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "python3 -c 'print(1)\n# line 2\n# line 3\n# line 4'"},
             "context": {"runtime": "claude-code"}},
            {"Idempotency-Key": "agent-pick"},
        )
        self._req("POST", f"/api/ui/requests/{req['id']}/review", {})
        done = self._wait_review_done(req["id"])
        self.assertEqual(done["review"]["agent"], "codex")
        self.assertEqual(done["review"]["explanation"], "codex")

    def test_path_and_url_token_splitting_and_matching(self) -> None:
        toks, prefs = aap_ui.command_tokens_and_prefixes("rm /tmp/foo")
        self.assertEqual(toks, ["rm", "/tmp", "/foo"])
        self.assertEqual(prefs, ["rm *", "rm /tmp/*", "rm /tmp/foo/*"])

        toks2, prefs2 = aap_ui.command_tokens_and_prefixes(
            "curl http://foo.bar/api/v2/get_stuff"
        )
        self.assertEqual(
            toks2, ["curl", "http:/", "/foo.bar", "/api", "/v2", "/get_stuff"]
        )
        self.assertEqual(
            prefs2,
            [
                "curl *",
                "curl http:/*",
                "curl http://foo.bar/*",
                "curl http://foo.bar/api/*",
                "curl http://foo.bar/api/v2/*",
                "curl http://foo.bar/api/v2/get_stuff/*",
            ],
        )

        # Wildcard matching within arguments and trailing *
        self.assertTrue(aap_ui._command_matches_prefix("rm /tmp/foo/bar", "rm /tmp/*"))
        self.assertFalse(aap_ui._command_matches_prefix("rm /tmp2/foo", "rm /tmp/*"))
        self.assertTrue(aap_ui._command_matches_prefix("git status", "git status *"))
        self.assertTrue(aap_ui._command_matches_prefix("git status -s", "git status *"))
        self.assertTrue(
            aap_ui._command_matches_prefix(
                "curl http://api.xyz/v1/users", "curl http://*.xyz/*"
            )
        )
        self.assertFalse(
            aap_ui._command_matches_prefix(
                "curl http://api.evil.com/v1/users", "curl http://*.xyz/*"
            )
        )

    def test_trailing_slash_wildcard_includes_base(self) -> None:
        command = "curl --silent --show-error --max-time 5 -X POST "
        base = "http://127.0.0.1:8787/api/ui/restart"
        pattern = command + base + "/*"
        for suffix in ("", "/", "/child", "/child/nested"):
            with self.subTest(suffix=suffix):
                self.assertTrue(aap_ui._command_matches_prefix(command + base + suffix, pattern))
        for suffix in ("-other", "ed", "?query=1"):
            with self.subTest(suffix=suffix):
                self.assertFalse(aap_ui._command_matches_prefix(command + base + suffix, pattern))
        self.assertTrue(aap_ui._command_matches_prefix("rm /tmp", "rm /tmp/*"))
        self.assertFalse(aap_ui._command_matches_prefix("rm /tmp2", "rm /tmp/*"))
        self.assertTrue(aap_ui._match_token_wildcard("http://*.xyz/*", "http://api.xyz"))
        self.assertFalse(aap_ui._match_token_wildcard("http://*.xyz/*", "http://api.xyz.evil"))
        self.assertFalse(aap_ui._match_token_wildcard("/tmp/*/file", "/tmp/file"))

    def test_compound_command_splitting_and_partial_approval(self) -> None:
        cmd = (
            "rg -n 'layout_width|layout_left' apps/server/app/templates/trainer_calendar.html "
            "&& tail -35 apps/server/app/static/app.css "
            "&& tail -35 docs/v0.6_checklist.md"
        )
        parts = aap_ui.split_compound_command(cmd)
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].startswith("rg -n"))
        self.assertIn("layout_width|layout_left", parts[0])
        self.assertTrue(parts[1].startswith("tail -35"))
        self.assertTrue(parts[2].startswith("tail -35"))

        # Subshell stays unsplit (fail-closed)
        self.assertEqual(aap_ui.split_compound_command("echo $(rm -rf /) && ls"), ["echo $(rm -rf /) && ls"])

        # Redirections containing & must not be split as background operators
        self.assertEqual(aap_ui.split_compound_command("xyz 2>&1"), ["xyz 2>&1"])
        self.assertEqual(
            aap_ui.split_compound_command("xyz 2>&1 && ls -la"),
            ["xyz 2>&1", "ls -la"],
        )
        self.assertEqual(
            aap_ui.split_compound_command("xyz &>out.log; cat out.log"),
            ["xyz &>out.log; cat out.log"],
        )
        self.assertEqual(
            aap_ui.split_compound_command('echo "a>" & ls'),
            ['echo "a>" & ls'],
        )

        # Unsupported blocks stay intact; request validation rejects them.
        self.assertEqual(
            aap_ui.split_compound_command("for wdt in 600 1200; do chromium --headless=new; done"),
            ["for wdt in 600 1200; do chromium --headless=new; done"],
        )
        self.assertEqual(
            aap_ui.split_compound_command("if grep -q a b; then echo ok; else echo no; fi"),
            ["if grep -q a b; then echo ok; else echo no; fi"],
        )

        # `timeout` wrapper splits before `--` or before the first letter-prefixed argument
        self.assertEqual(
            aap_ui.split_compound_command("timeout -x 124 30 command arg1"),
            ["timeout -x 124 30", "command arg1"],
        )
        self.assertEqual(
            aap_ui.split_compound_command("timeout 30 -- /usr/bin/ls -la && echo done"),
            ["timeout 30", "-- /usr/bin/ls -la", "echo done"],
        )
        self.assertEqual(
            aap_ui.split_compound_command("timeout 30"),
            ["timeout 30"],
        )
        self.assertEqual(
            aap_ui.split_compound_command("docker ps"),
            ["docker ps"],
        )

        # Pre-allow rg; only the two tail subcommands should remain pending
        self.hub.rules.add_rule(
            aap_ui.Rule(id="r-rg", kind="command_prefix", tool="Bash", action="allow", prefix="rg *")
        )
        _, created = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": cmd}},
            {"Idempotency-Key": "cmp-1"},
        )
        self.assertEqual(created["status"], "pending")
        self.assertEqual([sc["status"] for sc in created["subcommands"]], ["approved", "pending", "pending"])

        # Allowing prefix "tail -35 *" on subcommand 1 approves BOTH subcommand 1 and 2 and the whole request
        _, after = self._req(
            "POST",
            f"/api/ui/requests/{created['id']}/decision",
            {
                "decision": "approved",
                "allow_always": "prefix",
                "prefix": "tail -35 *",
                "sub_index": 1,
            },
        )
        self.assertEqual(after["status"], "approved")
        self.assertEqual([sc["status"] for sc in after["subcommands"]], ["approved", "approved", "approved"])

    def test_update_command_rule(self) -> None:
        _, rule = self._req(
            "POST",
            "/api/ui/rules",
            {"kind": "command_prefix", "tool": "run_command", "action": "allow", "prefix": "git status"},
        )
        status, updated = self._req(
            "PUT",
            f"/api/ui/rules/{rule['id']}",
            {"action": "deny", "prefix": "git push"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["action"], "deny")
        self.assertEqual(updated["prefix"], "git push")

    def test_approve_creates_12h_ttl_exact_rule_and_expires(self) -> None:
        payload = {"tool": "Bash", "arguments": {"command": "echo hello"}}
        _, r1 = self._req(
            "POST", "/api/aap/v1/requests", payload, {"Idempotency-Key": "ttl-1"}
        )
        self._req(
            "POST",
            f"/api/ui/requests/{r1['id']}/decision",
            {"decision": "approved"},
        )
        rules = self.hub.rules.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["kind"], "exact")
        self.assertIsNotNone(rules[0]["expires_at"])

        # Same exact call auto-approves
        _, r2 = self._req(
            "POST", "/api/aap/v1/requests", payload, {"Idempotency-Key": "ttl-2"}
        )
        self.assertEqual(r2["status"], "approved")

        # Expired rule is pruned and no longer auto-approves
        self.hub.rules._rules[0].expires_at = "2020-01-01T00:00:00Z"
        self.assertEqual(self.hub.rules.list_rules(), [])
        _, r3 = self._req(
            "POST", "/api/aap/v1/requests", payload, {"Idempotency-Key": "ttl-3"}
        )
        self.assertEqual(r3["status"], "pending")

    def test_rw_path_rule_replaces_covered_path_rules(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = aap_ui.RuleStore(Path(tmp.name) / "rules.json")

        def path_rule(prefix: str, mode: str, action: str = "allow", hits: int = 1) -> aap_ui.Rule:
            return aap_ui.Rule(id=prefix + mode + action, kind="path_prefix", tool="*",
                               action=action, prefix=prefix, mode=mode, hits=hits)

        store.add_rule(path_rule("/a/*", "ro"))
        store.add_rule(path_rule("/a/b/*", "rw", hits=2))
        store.add_rule(path_rule("/a/b/c.txt", "ro"))
        store.add_rule(path_rule("/ab/*", "ro"))
        store.add_rule(path_rule("/a/secret/*", "rw", action="deny"))
        store.add_rule(path_rule("/x/*", "ro"))

        # Adding ro does not replace anything.
        store.add_rule(path_rule("/x/y/*", "ro"))
        self.assertEqual(len(store.list_rules()), 7)

        added = store.add_rule(path_rule("/a/*", "rw"))
        rules = {(r["prefix"], r["mode"], r["action"]) for r in store.list_rules()}
        self.assertEqual(rules, {
            ("/a/*", "rw", "allow"),
            ("/ab/*", "ro", "allow"),
            ("/a/secret/*", "rw", "deny"),
            ("/x/*", "ro", "allow"),
            ("/x/y/*", "ro", "allow"),
        })
        self.assertEqual(added.hits, 1 + 1 + 2 + 1)

    def test_read_file_path_prefix_tokens_and_matching(self) -> None:
        _, created = self._req(
            "POST",
            "/api/aap/v1/requests",
            {
                "tool": "read_file",
                "arguments": {"Path": "/home/gabrys/Pictures/Screenshots/Screenshot 1.png"},
            },
            {"Idempotency-Key": "rf-1"},
        )
        self.assertEqual(
            created["command_tokens"],
            ["/home", "/gabrys", "/Pictures", "/Screenshots", "/Screenshot 1.png"],
        )
        self.assertEqual(
            created["command_prefixes"][3],
            "/home/gabrys/Pictures/Screenshots/*",
        )

        # Allow prefix /home/gabrys/Pictures/Screenshots/*
        self._req(
            "POST",
            f"/api/ui/requests/{created['id']}/decision",
            {
                "decision": "approved",
                "allow_always": "prefix",
                "prefix": "/home/gabrys/Pictures/Screenshots/*",
            },
        )

        # Another screenshot in the same directory auto-approves
        _, r2 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {
                "tool": "read_file",
                "arguments": {"Path": "/home/gabrys/Pictures/Screenshots/Other.png", "StartLine": 1, "EndLine": 50},
            },
            {"Idempotency-Key": "rf-2"},
        )
        self.assertEqual(r2["status"], "approved")

        # File outside that directory still waits
        _, r3 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "read_file", "arguments": {"Path": "/etc/passwd"}},
            {"Idempotency-Key": "rf-3"},
        )
        self.assertEqual(r3["status"], "pending")

    def test_search_web_domain_rule(self) -> None:
        _, created = self._req(
            "POST",
            "/api/aap/v1/requests",
            {
                "tool": "search_web",
                "arguments": {"domain": "github.com", "query": "codex PreToolUse"},
            },
            {"Idempotency-Key": "sw-1"},
        )
        self.assertEqual(created["status"], "pending")

        self._req(
            "POST",
            f"/api/ui/requests/{created['id']}/decision",
            {"decision": "approved", "allow_always": "domain", "prefix": "github.com"},
        )

        # Another query on the same domain auto-approves
        _, r2 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {
                "tool": "search_web",
                "arguments": {"domain": "github.com", "query": "another query"},
            },
            {"Idempotency-Key": "sw-2"},
        )
        self.assertEqual(r2["status"], "approved")

        # Different domain still waits
        _, r3 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {
                "tool": "search_web",
                "arguments": {"domain": "example.com", "query": "test"},
            },
            {"Idempotency-Key": "sw-3"},
        )
        self.assertEqual(r3["status"], "pending")

    def test_rule_hit_counter(self) -> None:
        _, rule = self._req(
            "POST",
            "/api/ui/rules",
            {"kind": "command_prefix", "tool": "Bash", "action": "allow", "prefix": "git status"},
        )
        self.assertEqual(rule["hits"], 0)

        for idx in range(2):
            _, req = self._req(
                "POST",
                "/api/aap/v1/requests",
                {"tool": "Bash", "arguments": {"command": "git status"}},
                {"Idempotency-Key": f"hits-{idx}"},
            )
            self.assertEqual(req["status"], "approved")

        _, ui_state = self._req("GET", "/api/ui/state")
        matched_rule = next(r for r in ui_state["rules"] if r["id"] == rule["id"])
        self.assertEqual(matched_rule["hits"], 2)

        # Rule created from a user click starts with hits == 1
        _, pending_req = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "ls -la"}},
            {"Idempotency-Key": "hits-click-1"},
        )
        _, decided = self._req(
            "POST",
            f"/api/ui/requests/{pending_req['id']}/decision",
            {"decision": "approved", "allow_always": "prefix", "prefix": "ls *"},
        )
        _, ui_state2 = self._req("GET", "/api/ui/state")
        clicked_rule = next(r for r in ui_state2["rules"] if r["id"] == decided["decision"]["rule_id"])
        self.assertEqual(clicked_rule["hits"], 1)

    def test_python_c_review_flow(self) -> None:
        self.hub.review_cmd = [
            sys.executable,
            "-c",
            "import json, sys; s = sys.stdin.read(); print(json.dumps({'decision': 'accept', 'explanation': 'Prints a value.', 'deny_reason': ''} if 'LGTM' in s else {'decision': 'reject', 'explanation': 'Assigns a password.', 'deny_reason': \"Remove the password; read it from the environment instead.\"}))",
        ]
        _, py_req = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "python3 -c 'print(1 + 1) # LGTM\n# line 2\n# line 3\n# line 4'"}},
            {"Idempotency-Key": "py-rev-1"},
        )
        self.assertEqual(py_req["python_script"], "print(1 + 1) # LGTM\n# line 2\n# line 3\n# line 4")

        status, rev = self._req("POST", f"/api/ui/requests/{py_req['id']}/review", {})
        self.assertEqual(status, 200)
        self.assertEqual(rev["review"]["status"], "running")

        # Review only records the verdict; the request stays pending.
        done = self._wait_review_done(py_req["id"])
        self.assertEqual(done["status"], "pending")
        self.assertEqual(done["review"]["decision"], "approved")
        self.assertEqual(done["review"]["deny_reason"], "")
        self.assertTrue(done["review"]["explanation"])

        # The single Accept action approves once without creating a rule.
        _, accepted = self._req(
            "POST",
            f"/api/ui/requests/{py_req['id']}/decision",
            {"decision": "approved"},
        )
        self.assertEqual(accepted["status"], "approved")
        self.assertNotIn("rule_id", accepted["decision"])

        # Rejected verdict is shown, not applied.
        _, bad_py = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "python3 -c 'PASSWORD=123\n# line 2\n# line 3\n# line 4'"}},
            {"Idempotency-Key": "py-rev-bad"},
        )
        self._req("POST", f"/api/ui/requests/{bad_py['id']}/review", {})
        done_bad = self._wait_review_done(bad_py["id"])
        self.assertEqual(done_bad["status"], "pending")
        self.assertEqual(done_bad["review"]["decision"], "denied")
        self.assertEqual(done_bad["review"]["explanation"], "Assigns a password.")
        self.assertEqual(done_bad["review"]["deny_reason"], "Remove the password; read it from the environment instead. " + aap_ui.SIMPLE_SCRIPT_HINT)

        # Plain Approve on a python script creates no rule.
        _, once = self._req(
            "POST", f"/api/ui/requests/{bad_py['id']}/decision", {"decision": "approved"}
        )
        self.assertEqual(once["status"], "approved")
        self.assertNotIn("rule_id", once["decision"])

        _, non_py = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "ls -la"}},
            {"Idempotency-Key": "py-rev-2"},
        )
        self.assertIsNone(non_py["python_script"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._req("POST", f"/api/ui/requests/{non_py['id']}/review", {})
        self.assertEqual(ctx.exception.code, 400)

    def test_python_test_endpoint_is_dry_run(self) -> None:
        self.hub.review_cmd = [
            sys.executable,
            "-c",
            "import json, sys; s = sys.stdin.read(); print(json.dumps({'decision': 'accept', 'explanation': 'Prints a value.', 'deny_reason': ''} if 'LGTM' in s else {'decision': 'reject', 'explanation': 'Assigns a password.', 'deny_reason': \"Remove the password; read it from the environment instead.\"}))",
        ]
        status, ok = self._req("POST", "/api/ui/test", {"script": "print('x') # LGTM"})
        self.assertEqual(status, 200)
        self.assertEqual(ok["decision"], "approved")
        self.assertEqual(ok["stage"], "review · claude")
        self.assertEqual(ok["command"], "python3 -c 'print('\"'\"'x'\"'\"') # LGTM'")

        _, bad = self._req("POST", "/api/ui/test", {"script": "PASSWORD=123"})
        self.assertEqual(bad["decision"], "denied")
        self.assertEqual(bad["explanation"], "Assigns a password.")
        self.assertEqual(bad["reason"], bad["deny_reason"])
        self.assertEqual(bad["reason"], "Remove the password; read it from the environment instead. " + aap_ui.SIMPLE_SCRIPT_HINT)

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._req("POST", "/api/ui/test", {"script": "  "})
        self.assertEqual(ctx.exception.code, 400)

        _, ui_state = self._req("GET", "/api/ui/state")
        self.assertEqual(ui_state["pending"], [])
        self.assertEqual(ui_state["history"], [])

    def test_expired_and_cancelled_stay_in_queue_until_decided_and_persist(self) -> None:
        _, exp_req = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "echo old"}, "timeout": 0.05},
            {"Idempotency-Key": "stay-exp"},
        )
        _, can_req = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Bash", "arguments": {"command": "echo cancelled"}},
            {"Idempotency-Key": "stay-can"},
        )
        time.sleep(0.08)
        self._req("DELETE", f"/api/aap/v1/requests/{can_req['id']}")

        _, ui_state = self._req("GET", "/api/ui/state")
        ids_in_queue = {r["id"]: r["status"] for r in ui_state["pending"]}
        self.assertEqual(ids_in_queue.get(exp_req["id"]), "expired")
        self.assertEqual(ids_in_queue.get(can_req["id"]), "cancelled")

        # Persisted in queue.json across ApprovalHub reload
        reloaded = aap_ui.ApprovalHub(aap_ui.RuleStore(self.rules_path))
        reloaded_ids = {r["id"] for r in reloaded.ui_state()["pending"]}
        self.assertIn(exp_req["id"], reloaded_ids)
        self.assertIn(can_req["id"], reloaded_ids)

        # Deciding removes from Queue
        self._req("POST", f"/api/ui/requests/{exp_req['id']}/decision", {"decision": "denied"})
        self._req("POST", f"/api/ui/requests/{can_req['id']}/decision", {"decision": "denied"})
        _, ui_after = self._req("GET", "/api/ui/state")
        self.assertEqual(ui_after["pending"], [])

    def test_path_ro_and_rw_levels(self) -> None:
        _, req_r = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "read_file", "arguments": {"Path": "/tmp/proj/a.py"}},
            {"Idempotency-Key": "ro-1"},
        )
        self.assertEqual(req_r["path_mode"], "ro")

        _, dec = self._req(
            "POST",
            f"/api/ui/requests/{req_r['id']}/decision",
            {"decision": "approved", "allow_always": "prefix", "prefix": "/tmp/proj/*"},
        )
        rule_id = dec["decision"]["rule_id"]

        # Read across runtimes auto-approves under ro
        _, req_r2 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Read", "arguments": {"file_path": "/tmp/proj/b.py"}},
            {"Idempotency-Key": "ro-2"},
        )
        self.assertEqual(req_r2["status"], "approved")

        # Write stays pending under ro
        _, req_w = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "Edit", "arguments": {"file_path": "/tmp/proj/b.py"}},
            {"Idempotency-Key": "rw-1"},
        )
        self.assertEqual(req_w["status"], "pending")
        self.assertEqual(req_w["path_mode"], "rw")

        # Upgrading rule to rw allows both write and read
        status, updated = self._req("PUT", f"/api/ui/rules/{rule_id}", {"mode": "rw"})
        self.assertEqual(status, 200)
        self.assertEqual(updated["mode"], "rw")

        _, req_w2 = self._req(
            "POST",
            "/api/aap/v1/requests",
            {"tool": "edit_file", "arguments": {"Path": "/tmp/proj/c.py"}},
            {"Idempotency-Key": "rw-2"},
        )
        self.assertEqual(req_w2["status"], "approved")


if __name__ == "__main__":
    unittest.main()

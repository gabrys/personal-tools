#!/usr/bin/env python3
"""Lightweight AAP (Agent Approval Protocol) server, Web UI, and PreToolUse hook."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import html
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_RULES_PATH = Path.home() / ".config" / "aap-ui" / "rules.json"
DEFAULT_CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
DEFAULT_CODEX_CONFIG = Path.home() / ".codex" / "config.toml"
DEFAULT_ANTIGRAVITY_HOOKS = Path.home() / ".gemini" / "config" / "hooks.json"
TERMINAL_STATUSES = {"approved", "denied", "expired", "cancelled"}
UNSUPPORTED_SHELL_REASON = (
    "This command contains unsupported shell constructs. Rewrite it as a single "
    "python3 -c '…' command, or run several commands separately if that makes "
    "sense for the task."
)
FILE_REDIRECTION_REASON = (
    "File redirections are not supported. Perform file operations separately "
    "using tools whose file access is checked against path-based rules."
)
_ASSIGNMENT = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]*=")
_RESERVED_WORDS = {
    "for", "while", "until", "if", "then", "else", "elif", "fi", "do", "done",
    "case", "esac", "in", "function", "select", "time", "coproc", "!", "[[", "]]",
}


@dataclass
class ShellCommand:
    text: str
    words: list[str]
    assignments: int
    operator_after: str = ""


class UnsupportedShell(ValueError):
    pass


def parse_shell_command(command: str) -> list[ShellCommand]:
    """Parse the supported shell subset without evaluation; retain source/operators.

    This deliberately rejects full Bash syntax. Normalized words omit only the
    supported descriptor duplications and output redirections to /dev/null.
    """
    tokens: list[tuple[str, str, int, int]] = []
    decoded_words: dict[int, str] = {}
    i = 0
    while i < len(command):
        ch = command[i]
        if ch in " \t":
            i += 1
            continue
        start = i
        if ch in ";\n|&<>":
            op = next((op for op in (
                ";;&", "<<<", "<<-", "&>>", "&&", "||", "|&", "<<", ">>",
                ">&", "<&", "&>", "<>", ">|", ";;", ";&",
            ) if command.startswith(op, i)), ch)
            i += len(op)
            if op not in {"&&", "||", "|", ";", "\n", ">", ">>", ">&", "<", "<&", "&>", "&>>", "<>", ">|"}:
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            kind = "separator" if op in {"&&", "||", "|", ";", "\n"} else "redirect"
            tokens.append((kind, op, start, i))
            continue
        quote = ""
        decoded: list[str] = []
        while i < len(command):
            ch = command[i]
            if not quote and (ch in " \t\n" or ch in ";|&<>"):
                break
            if not quote and ch.isspace():
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            if ch == "\\" and quote != "'":
                if i + 1 >= len(command) or command[i + 1] == "\n":
                    raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
                if quote == '"' and command[i + 1] not in '\\"$`':
                    decoded.append("\\")
                decoded.append(command[i + 1])
                i += 2
                continue
            if ch in "\"'":
                if not quote:
                    quote = ch
                elif quote == ch:
                    quote = ""
                else:
                    decoded.append(ch)
                i += 1
                continue
            if quote != "'" and ch in "$`":
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            if not quote and (ch in "(){}*?[]~" or (ch == "#" and i == start)):
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            decoded.append(ch)
            i += 1
        if quote:
            raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
        tokens.append(("word", command[start:i], start, i))
        decoded_words[start] = "".join(decoded)

    result: list[ShellCommand] = []
    words: list[str] = []
    word_spans: list[tuple[int, int]] = []
    assignments = 0
    has_redirect = False
    start = 0
    j = 0

    def emit(end: int, operator: str):
        nonlocal words, word_spans, assignments, has_redirect
        if len(words) <= assignments:
            raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
        if len(words) > assignments and words[assignments] == "timeout":
            split_idx = next(
                (k for k in range(assignments + 1, len(words))
                 if words[k] == "--" or (words[k] and words[k][0].isalpha())),
                None,
            )
            if split_idx is not None:
                split_pos = word_spans[split_idx][0]
                result.append(ShellCommand(command[start:split_pos].strip(), words[:split_idx], assignments, ""))
                result.append(ShellCommand(command[split_pos:end].strip(), words[split_idx:], 0, operator))
                words = []
                word_spans = []
                assignments = 0
                has_redirect = False
                return
        result.append(ShellCommand(command[start:end].strip(), words, assignments, operator))
        words = []
        word_spans = []
        assignments = 0
        has_redirect = False

    while j < len(tokens):
        kind, raw, begin, end = tokens[j]
        if kind == "separator":
            if words:
                emit(begin, raw)
            elif raw != "\n" or has_redirect:
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            start = end
            j += 1
            continue
        fd = ""
        if (kind == "word" and raw.isascii() and raw.isdigit() and j + 1 < len(tokens)
                and tokens[j + 1][0] == "redirect" and end == tokens[j + 1][2]
                and tokens[j + 1][1] not in {"&>", "&>>"}):
            fd = raw
            j += 1
            kind, raw, begin, end = tokens[j]
        if kind == "redirect":
            has_redirect = True
            if j + 1 >= len(tokens) or tokens[j + 1][0] != "word":
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            target = decoded_words[tokens[j + 1][2]]
            if raw in {">&", "<&"}:
                if raw != ">&" or (fd, target) not in {("2", "1"), ("1", "2")}:
                    raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
            elif not (raw in {">", ">>", "&>", "&>>"} and target == "/dev/null"
                      and fd in {"", "1", "2"}):
                raise UnsupportedShell(FILE_REDIRECTION_REASON)
            j += 2
            continue
        value = decoded_words[begin]
        if len(words) == assignments:
            if _ASSIGNMENT.match(raw):
                assignments += 1
            elif raw in _RESERVED_WORDS:
                raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
        words.append(value)
        word_spans.append((begin, end))
        j += 1
    if words:
        emit(len(command), "")
    elif has_redirect or (result and result[-1].operator_after in {"&&", "||", "|"}):
        raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
    if not result:
        raise UnsupportedShell(UNSUPPORTED_SHELL_REASON)
    return result


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_after_iso(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def parse_timeout_seconds(value: Any, default: float = 604800.0) -> float:
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return default
    raw = value.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if raw[-1] in units:
        try:
            return max(1.0, float(raw[:-1]) * units[raw[-1]])
        except ValueError:
            return default
    try:
        return max(1.0, float(raw))
    except ValueError:
        return default


def split_compound_command(command: str) -> list[str]:
    """Return supported commands; preserve rejected input for legacy callers."""
    try:
        return [part.text for part in parse_shell_command(command)]
    except UnsupportedShell:
        return [command.strip()] if command.strip() else []


def extract_python_c_script(command: str) -> str | None:
    """Return the inline script if command is `python[3] -c '<script>'`."""
    text = command.strip()
    if not text:
        return None
    try:
        parts = parse_shell_command(text)
        if len(parts) != 1:
            return None
        part = parts[0]
        tokens = part.words[part.assignments:]
    except ValueError:
        return None
    if len(tokens) < 3:
        return None
    exe = Path(tokens[0]).name
    if not re.match(r"^python3?(?:\.\d+)*$", exe):
        return None
    if tokens[1] != "-c":
        return None
    return tokens[2]


def is_reviewable_python_script(script: str | None) -> bool:
    return script is not None and (len(script.splitlines()) > 3 or len(script) > 200)


def extract_reviewable_python_script(command: str) -> str | None:
    script = extract_python_c_script(command)
    return script if is_reviewable_python_script(script) else None


def _split_word_segments(word: str) -> list[str]:
    """Split /paths and http(s)://URLs into slash-prefixed segments."""
    if word.startswith(("http://", "https://")):
        idx = word.find("://")
        scheme = word[: idx + 2]  # e.g. "http:/" or "https:/"
        rest = word[idx + 2 :]
        segs = re.findall(r"/[^/]*", rest)
        return [scheme, *segs] if segs else [word]
    if word.startswith("/") and len(word) > 1:
        segs = re.findall(r"/[^/]*", word)
        return segs if segs else [word]
    return [word]


def _with_trailing_wildcard(prefix: str) -> str:
    p = prefix.strip()
    if not p or p.endswith("*"):
        return p
    try:
        tokens = shlex.split(p)
        last = tokens[-1] if tokens else ""
    except ValueError:
        last = p.split()[-1] if p.split() else ""
    if _is_path_or_url_prefix(last):
        return p + "*" if p.endswith("/") else p + "/*"
    return p + " *"


def command_tokens_and_prefixes(command: str) -> tuple[list[str], list[str]]:
    """Return (tokens, shlex-joined wildcard prefixes) for interactive prefix selection."""
    if not command or not command.strip():
        return [], []
    try:
        parts = parse_shell_command(command)
        if len(parts) != 1:
            return [], []
        words = parts[0].words
        assignment_count = parts[0].assignments
    except ValueError:
        return [], []
    if not words:
        return [], []

    tokens: list[str] = []
    prefixes: list[str] = []
    prior_words: list[str] = []
    for index, word in enumerate(words):
        segs = _split_word_segments(word)
        acc = ""
        for seg in segs:
            acc += seg
            tokens.append(seg)
            if index >= assignment_count:
                prefixes.append(_with_trailing_wildcard(shlex.join([*prior_words, acc])))
        prior_words.append(word)
    # The token bar pairs tokens with prefixes. Group assignments with the
    # executable rather than exposing assignment-only approval buttons.
    if assignment_count:
        tokens = [" ".join(tokens[:assignment_count + 1]), *tokens[assignment_count + 1:]]
    return tokens, prefixes


def suggest_command_prefixes(command: str) -> list[str]:
    """Return sensible command prefixes (1-token, 2-token, etc.) for Bash."""
    if not command or not command.strip():
        return []
    try:
        parts = parse_shell_command(command)
        if len(parts) != 1:
            return []
        tokens = parts[0].words
        offset = parts[0].assignments
    except ValueError:
        return []
    if not tokens:
        return []
    prefixes: list[str] = []
    if len(tokens) >= offset + 2:
        prefixes.append(shlex.join(tokens[:offset + 2]))
    prefixes.append(shlex.join(tokens[:offset + 1]))
    if len(tokens) >= offset + 3:
        prefixes.append(shlex.join(tokens[:offset + 3]))
    # Deduplicate preserving order
    seen: set[str] = set()
    return [p for p in prefixes if not (p in seen or seen.add(p))]


def _is_path_or_url_prefix(token: str) -> bool:
    return token.startswith(("/", "http:/", "https:/"))


def _match_token_wildcard(pattern_tok: str, actual_tok: str) -> bool:
    if "*" not in pattern_tok:
        return pattern_tok == actual_tok
    # A trailing /* includes the base itself and slash descendants.
    if pattern_tok.endswith("/*"):
        base = pattern_tok[:-2]
        regex = ".*".join(re.escape(part) for part in base.split("*"))
        return re.fullmatch(regex + r"(?:/.*)?", actual_tok) is not None
    regex = "^" + ".*".join(re.escape(part) for part in pattern_tok.split("*")) + "$"
    return re.match(regex, actual_tok) is not None


def _command_matches_prefix(command: str, prefix: str) -> bool:
    cmd = command.strip()
    pref = prefix.strip()
    if not cmd or not pref:
        return False
    try:
        parts = parse_shell_command(cmd)
        if len(parts) != 1:
            return False
        cmd_tokens = parts[0].words
        pref_tokens = shlex.split(pref)
    except ValueError:
        return False
    if not pref_tokens:
        return False
    prefix_assignments = 0
    for token in pref_tokens:
        if not _ASSIGNMENT.match(token):
            break
        prefix_assignments += 1
    if prefix_assignments != parts[0].assignments:
        return False

    # Trailing standalone "*" matches 0 or more remaining arguments
    if pref_tokens[-1] == "*":
        req_tokens = pref_tokens[:-1]
        if len(cmd_tokens) < len(req_tokens):
            return False
        return all(_match_token_wildcard(p, c) for p, c in zip(req_tokens, cmd_tokens))

    if len(cmd_tokens) != len(pref_tokens):
        return False
    return all(_match_token_wildcard(p, c) for p, c in zip(pref_tokens, cmd_tokens))


READ_PATH_TOOLS = {
    "read_file",
    "Read",
    "view_file",
    "list_dir",
    "find_by_name",
    "grep_search",
    "Glob",
    "Grep",
}
WRITE_PATH_TOOLS = {
    "edit_file",
    "write_file",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "apply_patch",
}


def _path_tool_level(tool: str) -> str | None:
    if tool in READ_PATH_TOOLS:
        return "ro"
    if tool in WRITE_PATH_TOOLS:
        return "rw"
    return None


def _extract_path_arg(arguments: dict[str, Any]) -> str | None:
    for key in ("Path", "file_path", "path", "TargetFile", "DirectoryPath", "SearchPath"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def _rule_path_level(rule: "Rule") -> str:
    if rule.mode in {"ro", "rw"}:
        return rule.mode
    return "rw" if _path_tool_level(rule.tool) == "rw" else "ro"


# Tools that run a shell command line (Claude Code/Codex, Antigravity).
SHELL_TOOLS = {"Bash", "run_command"}


def mobile_notifications(pending: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Notifications for the Android app: one per request awaiting a decision.
    The app shows new ids, updates known ones and dismisses ids that are gone."""
    out = []
    for req in pending:
        if req.get("status") != "pending":
            continue
        args = req.get("arguments") or {}
        runtime = (req.get("context") or {}).get("runtime") or "agent"
        tool = "run" if req.get("tool") in SHELL_TOOLS else str(req.get("tool"))
        text = args.get("command") or args.get("CommandLine")
        if not isinstance(text, str):
            path = args.get("file_path") or args.get("path") or args.get("Path")
            text = path if isinstance(path, str) else json.dumps(args, ensure_ascii=False)
        out.append({"id": req["id"], "title": f"{runtime}: {tool}", "text": text})
    return out

# Where a decision came from, stored as decision["labels"] (in this order):
#   rule      - an existing permanent rule matched
#   prior     - an earlier Accept (12h exact-call rule) matched
#   ai-review - a finished AI review of the script was available
#   click     - the operator clicked
#   lazy      - no operator reaction; applied automatically after 30s
#   new-12h   - this decision accepted this exact call for 12h (exact rule)
#   new-rule  - this decision created a permanent rule
DECISION_LABELS = ["rule", "prior", "ai-review", "click", "lazy", "new-12h", "new-rule"]


def rule_decision_reason(rule: "Rule") -> str:
    if rule.action == "deny" and rule.reason.strip():
        return rule.reason.strip()
    return f"Matched rule ({rule.kind})"


def rule_specificity(rule: "Rule") -> tuple[int, int]:
    """How narrowly a rule targets calls: exact calls over prefix rules over
    whole-tool rules, then by the literal (non-wildcard) length of the prefix,
    so `git status *` (10) is more specific than `git *` (3)."""
    if rule.kind == "exact":
        return (2, 0)
    if rule.kind in {"command_prefix", "path_prefix", "domain"}:
        return (1, len(rule.prefix.replace("*", "").strip()))
    return (0, 0 if rule.tool == "*" else 1)


def rule_label(rule: "Rule") -> str:
    return "prior" if rule.kind == "exact" else "rule"


def merge_labels(*groups: Any) -> list[str]:
    """Union of label lists, in DECISION_LABELS order."""
    found = {label for group in groups for label in (group or []) if label in DECISION_LABELS}
    return [label for label in DECISION_LABELS if label in found]


@dataclass
class Rule:
    id: str
    kind: str  # "tool" | "command_prefix" | "path_prefix" | "domain" | "exact"
    tool: str
    action: str = "allow"  # "allow" | "deny"
    prefix: str = ""
    mode: str = ""  # "ro" | "rw" for path_prefix rules
    arguments: dict[str, Any] | None = None
    created_at: str = field(default_factory=utc_now_iso)
    expires_at: str | None = None
    hits: int = 0
    reason: str = ""  # deny rules: told to the agent instead of "Matched rule (...)"

    def is_expired(self, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return (now or datetime.now(timezone.utc)) >= exp

    def matches(self, tool: str, arguments: dict[str, Any]) -> bool:
        command = arguments.get("command") or arguments.get("CommandLine")
        if (self.action == "allow" and isinstance(command, str)
                and extract_reviewable_python_script(command) is not None):
            return False
        if self.is_expired():
            return False
        if self.kind == "path_prefix":
            req_level = _path_tool_level(tool)
            if req_level is not None and (self.mode in {"ro", "rw"} or self.tool == "*" or _path_tool_level(self.tool) is not None):
                rule_level = _rule_path_level(self)
                if rule_level == "ro" and req_level != "ro":
                    return False
            elif self.tool != "*" and self.tool != tool:
                return False
            path_val = _extract_path_arg(arguments)
            return isinstance(path_val, str) and _match_token_wildcard(self.prefix, path_val)
        if self.tool != "*" and self.tool != tool and not (
            # A shell command is the same command whichever agent's shell
            # tool runs it (Bash for Claude Code/Codex, run_command for
            # Antigravity), so command rules apply across them.
            self.kind == "command_prefix" and self.tool in SHELL_TOOLS and tool in SHELL_TOOLS
        ):
            return False
        if self.kind == "tool":
            return True
        if self.kind == "command_prefix":
            command = arguments.get("command") or arguments.get("CommandLine")
            return isinstance(command, str) and _command_matches_prefix(command, self.prefix)
        if self.kind == "domain":
            dom = arguments.get("domain")
            if self.prefix == "*":
                return True
            return isinstance(dom, str) and _match_token_wildcard(self.prefix, dom)
        if self.kind == "exact":
            return (self.arguments or {}) == (arguments or {})
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "tool": self.tool,
            "action": self.action,
            "prefix": self.prefix,
            "mode": self.mode,
            "arguments": self.arguments,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hits": self.hits,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            kind=str(data.get("kind") or "tool"),
            tool=str(data.get("tool") or "*"),
            action=str(data.get("action") or "allow"),
            prefix=str(data.get("prefix") or ""),
            mode=str(data.get("mode") or ""),
            arguments=data.get("arguments"),
            created_at=str(data.get("created_at") or utc_now_iso()),
            expires_at=data.get("expires_at"),
            hits=int(data.get("hits") or 0),
            reason=str(data.get("reason") or ""),
        )


class RuleStore:
    """Thread-safe JSON-backed rule store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._rules: list[Rule] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._rules = []
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self._rules = [Rule.from_dict(item) for item in data if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError):
            self._rules = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([r.to_dict() for r in self._rules], indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def _prune_expired_locked(self) -> None:
        now = datetime.now(timezone.utc)
        kept = [r for r in self._rules if not r.is_expired(now)]
        if len(kept) != len(self._rules):
            self._rules = kept
            self._save()

    def list_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            self._prune_expired_locked()
            return [r.to_dict() for r in self._rules]

    def match(self, tool: str, arguments: dict[str, Any], record_hit: bool = True) -> Rule | None:
        """The most specific matching rule wins; on equal specificity deny
        beats allow, then the newest rule wins. So [deny `git *`] +
        [allow `git status *`] allows `git status` but no other git command."""
        with self._lock:
            self._prune_expired_locked()
            best: Rule | None = None
            best_key: tuple[tuple[int, int], int] | None = None
            for rule in self._rules:
                if rule.matches(tool, arguments):
                    key = (rule_specificity(rule), 1 if rule.action == "deny" else 0)
                    if best_key is None or key > best_key:
                        best, best_key = rule, key
            if best is not None and record_hit:
                best.hits += 1
                self._save()
            return best

    @staticmethod
    def _superseded_by(existing: Rule, rule: Rule) -> bool:
        """True if allow-rw path rule `rule` covers allow path rule `existing`
        (same path or a subpath, ro or rw)."""
        if not (rule.kind == existing.kind == "path_prefix"):
            return False
        if rule.action != "allow" or existing.action != "allow":
            return False
        if _rule_path_level(rule) != "rw":
            return False
        if rule.tool not in ("*", existing.tool):
            return False
        base = existing.prefix[:-2] if existing.prefix.endswith("/*") else existing.prefix
        return existing.prefix == rule.prefix or _match_token_wildcard(rule.prefix, base)

    def add_rule(self, rule: Rule) -> Rule:
        with self._lock:
            # A new rw path rule replaces ro/rw rules for the same path or subpaths.
            replaced = [r for r in self._rules if self._superseded_by(r, rule)]
            if replaced:
                rule.hits += sum(r.hits for r in replaced)
                self._rules = [r for r in self._rules if r not in replaced]
                self._rules.insert(0, rule)
                self._save()
                return rule
            def same_target(r: Rule) -> bool:
                return (
                    r.kind == rule.kind
                    and r.tool == rule.tool
                    and r.prefix == rule.prefix
                    and _rule_path_level(r) == _rule_path_level(rule)
                    and r.arguments == rule.arguments
                )

            # The same rule with the opposite action is replaced.
            self._rules = [r for r in self._rules if not (same_target(r) and r.action != rule.action)]
            # Avoid duplicate identical rules
            for existing in self._rules:
                if same_target(existing):
                    if rule.hits > 0:
                        existing.hits += rule.hits
                    if rule.reason.strip():
                        existing.reason = rule.reason.strip()
                        self._save()
                    return existing
            self._rules.insert(0, rule)
            self._save()
            return rule

    def record_hit(self, rule_id: str) -> None:
        with self._lock:
            for rule in self._rules:
                if rule.id == rule_id:
                    rule.hits += 1
                    self._save()
                    return

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            if len(self._rules) != before:
                self._save()
                return True
            return False

    def update_rule(
        self,
        rule_id: str,
        action: str | None = None,
        prefix: str | None = None,
        arguments: dict[str, Any] | None = None,
        mode: str | None = None,
        reason: str | None = None,
    ) -> Rule | None:
        with self._lock:
            for rule in self._rules:
                if rule.id == rule_id:
                    if action in {"allow", "deny"}:
                        rule.action = action
                    if isinstance(reason, str):
                        rule.reason = reason.strip()
                    if prefix is not None and rule.kind in {"command_prefix", "path_prefix", "domain"}:
                        rule.prefix = prefix.strip()
                    if mode in {"ro", "rw"} and rule.kind == "path_prefix":
                        rule.mode = mode
                    if arguments is not None and rule.kind == "exact":
                        rule.arguments = arguments
                    self._save()
                    return rule
            return None



SIMPLE_SCRIPT_HINT = "Prefer simple, explicit scripts."


def run_python_review(review_cmd: list[str], script: str) -> dict[str, str]:
    """Run the reviewer and preserve the script explanation and actionable denial."""
    explanation = ""
    try:
        proc = subprocess.run(
            review_cmd,
            input=script,
            text=True,
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise ValueError(
                f"Auto-review exited with {proc.returncode}" + (f": {err}" if err else "")
            )
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            raise ValueError("Review output must be a JSON object")
        explanation = data.get("explanation")
        deny_reason = data.get("deny_reason")
        decision = data.get("decision")
        if (
            decision not in ("accept", "reject")
            or not isinstance(explanation, str)
            or not isinstance(deny_reason, str)
            or (decision == "accept" and (not explanation.strip() or deny_reason.strip()))
            or (decision == "reject" and not deny_reason.strip())
        ):
            raise ValueError("Invalid review output; expected decision, explanation and deny_reason")
        explanation = explanation.strip()
        if decision == "accept":
            return {"decision": "approved", "explanation": explanation, "deny_reason": ""}
        deny_reason = deny_reason.strip()
    except Exception as exc:
        explanation = ""
        deny_reason = f"Auto-review error: {exc}. Fix the reviewer setup and retry."
    return {
        "decision": "denied",
        "explanation": explanation,
        "deny_reason": f"{deny_reason} {SIMPLE_SCRIPT_HINT}",
    }


def choose_review_agent(runtime: str, data: dict[str, Any] | None) -> tuple[str, str]:
    """Prefer the competing agent unless usage calls for the less loaded one."""
    competitor = "codex" if runtime == "claude-code" else "claude"
    usage: dict[str, float] = {}
    providers = (data or {}).get("providers") or {}
    for agent in ("claude", "codex"):
        provider = providers.get(agent) or {}
        if provider.get("error"):
            continue
        for group in provider.get("groups") or []:
            for window in group.get("windows") or []:
                label = str(window.get("label") or "").lower()
                used = window.get("used_percent")
                if "5h" in label and isinstance(used, (int, float)):
                    usage[agent] = max(usage.get(agent, 0.0), float(used))
    if len(usage) == 2:
        if runtime in ("claude-code", "codex") and max(usage.values()) < 80:
            return competitor, "Both agents are below 80% usage; use the competing agent."
        agent = min(usage, key=lambda name: (usage[name], name != competitor))
        return agent, f"Selected {agent} with lower 5h usage ({usage[agent]:g}%)."
    if usage:
        agent = next(iter(usage))
        return agent, f"Usage is available only for {agent} ({usage[agent]:g}% used)."
    return competitor, "Usage unavailable; prefer the competing agent."


class ApprovalHub:
    """In-memory AAP request queue with long-polling and SSE notifications."""

    def __init__(self, rules: RuleStore, history_limit: int = 100) -> None:
        self.rules = rules
        # `--agent <name>` is appended per review by choose_review_agent().
        self.review_cmd: list[str] = [
            sys.executable,
            str(Path(__file__).resolve().with_name("review_python.py")),
        ]
        self.usage: UsageCache | None = None
        self._cond = threading.Condition()
        self._requests: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}  # key -> (payload_hash, req_id)
        self._history: deque[str] = deque(maxlen=history_limit)
        self._subscribers: set[queue.Queue[str]] = set()
        self._queue_path = self.rules.path.with_name("queue.json")
        # Every decision is appended here (one JSON record per line), so the
        # History tab survives restarts and wait times can be analysed later.
        self._history_path = self.rules.path.with_name("history.jsonl")
        self._load_history()
        self._load_queue()

    def _load_history(self) -> None:
        """Restore the most recent decided records from history.jsonl."""
        if not self._history_path.exists():
            return
        latest: dict[str, dict[str, Any]] = {}
        try:
            with self._history_path.open(encoding="utf-8") as f:
                # A request can be logged more than once (e.g. expired, then
                # decided); the last line for an id wins.
                for line in deque(f, maxlen=(self._history.maxlen or 100) * 5):
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict) and item.get("id"):
                        latest.pop(item["id"], None)
                        latest[item["id"]] = item
        except OSError:
            return
        for item in latest.values():  # oldest first, so the newest ends up in front
            item.pop("logged_at", None)
            item["in_queue"] = False
            self._requests[item["id"]] = item
            self._history.appendleft(item["id"])

    def _add_history(self, req_id: str) -> None:
        """Move req_id to the front of the history and append it to the log."""
        if req_id in self._history:
            self._history.remove(req_id)
        self._history.appendleft(req_id)
        record = self._requests.get(req_id)
        if record is None:
            return
        try:
            self._history_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps({**self._public_view(record), "logged_at": utc_now_iso()}, ensure_ascii=False)
            with self._history_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def _load_queue(self) -> None:
        if not self._queue_path.exists():
            return
        try:
            items = json.loads(self._queue_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            for target in [item, *(item.get("subcommands") or [])]:
                if target.get("python_script") is not None and not is_reviewable_python_script(target["python_script"]):
                    target["python_script"] = None
                    target.pop("review", None)
            item.setdefault("in_queue", True)
            item.setdefault("deadline_ts", time.monotonic() + parse_timeout_seconds(item.get("timeout")))
            self._requests[item["id"]] = item

    def _save_queue(self) -> None:
        try:
            self._queue_path.parent.mkdir(parents=True, exist_ok=True)
            queued = [self._public_view(r) for r in self._requests.values() if r.get("in_queue")]
            tmp = self._queue_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(queued, indent=2), encoding="utf-8")
            tmp.replace(self._queue_path)
        except OSError:
            pass

    def subscribe(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=64)
        with self._cond:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue[str]) -> None:
        with self._cond:
            self._subscribers.discard(q)

    def _notify_ui(self, event: str = "update") -> None:
        dead: list[queue.Queue[str]] = []
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    def create_request(
        self, payload: dict[str, Any], idempotency_key: str
    ) -> tuple[dict[str, Any], int]:
        received_at = time.time()
        canonical = json.dumps(payload, sort_keys=True)
        tool = str(payload.get("tool") or "")
        arguments = payload.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        context = payload.get("context")
        if not isinstance(context, dict):
            context = {}
        timeout_sec = parse_timeout_seconds(payload.get("timeout"))

        with self._cond:
            if idempotency_key in self._idempotency:
                prev_payload, prev_id = self._idempotency[idempotency_key]
                if prev_payload != canonical:
                    raise ValueError("idempotency_conflict")
                return dict(self._requests[prev_id]), HTTPStatus.OK

            req_id = str(uuid.uuid4())
            now = utc_now_iso()
            cmd_str = str(arguments.get("command") or arguments.get("CommandLine") or "")
            has_cmd = "command" in arguments or "CommandLine" in arguments
            shell_parts: list[ShellCommand] = []
            shell_error = ""
            if has_cmd:
                try:
                    shell_parts = parse_shell_command(cmd_str)
                except UnsupportedShell as exc:
                    shell_error = str(exc)
            sub_cmds = [part.text for part in shell_parts]

            subcommands: list[dict[str, Any]] = []
            if shell_error:
                status = "denied"
                decision = {"status": status, "decided_at": now, "reason": shell_error}
            elif len(sub_cmds) > 1:
                all_approved = True
                any_denied: Rule | None = None
                allow_labels: set[str] = set()
                for idx, sc in enumerate(sub_cmds):
                    sc_rule = self.rules.match(tool, {"command": sc})
                    sc_tokens, sc_prefixes = command_tokens_and_prefixes(sc)
                    if sc_rule is not None and sc_rule.action == "allow":
                        allow_labels.add(rule_label(sc_rule))
                        sc_status = "approved"
                    elif sc_rule is not None and sc_rule.action == "deny":
                        sc_status = "denied"
                        any_denied = any_denied or sc_rule
                        all_approved = False
                    else:
                        sc_status = "pending"
                        all_approved = False
                    subcommands.append(
                        {
                            "index": idx,
                            "command": sc,
                            "operator_after": shell_parts[idx].operator_after,
                            "status": sc_status,
                            "command_tokens": sc_tokens,
                            "command_prefixes": sc_prefixes,
                            "python_script": extract_reviewable_python_script(sc),
                            "review": None,
                            "rule_id": sc_rule.id if sc_rule else None,
                            "labels": [rule_label(sc_rule)] if sc_rule else [],
                        }
                    )
                if any_denied is not None:
                    status = "denied"
                    decision = {
                        "status": "denied",
                        "decided_at": now,
                        "reason": rule_decision_reason(any_denied),
                        "rule_id": any_denied.id,
                        "labels": [rule_label(any_denied)],
                    }
                elif all_approved:
                    status = "approved"
                    decision = {
                        "status": "approved",
                        "decided_at": now,
                        "reason": "All subcommands matched allow rules",
                        "rule_ids": [sc["rule_id"] for sc in subcommands if sc.get("rule_id")],
                        "labels": merge_labels(allow_labels),
                    }
                else:
                    status = "pending"
                    decision = None
            else:
                matched = self.rules.match(tool, arguments)
                status = "pending"
                decision = None
                if matched is not None:
                    status = "approved" if matched.action == "allow" else "denied"
                    decision = {
                        "status": status,
                        "decided_at": now,
                        "reason": rule_decision_reason(matched),
                        "rule_id": matched.id,
                        "labels": [rule_label(matched)],
                    }

            path_val = _extract_path_arg(arguments)
            path_mode: str | None = None
            if has_cmd:
                cmd_tokens, cmd_prefixes = command_tokens_and_prefixes(cmd_str)
            elif isinstance(path_val, str) and path_val.strip():
                segs = _split_word_segments(path_val.strip())
                cmd_tokens = segs
                cmd_prefixes = []
                acc = ""
                for seg in segs:
                    acc += seg
                    cmd_prefixes.append(acc + "*" if acc.endswith("/") else acc + "/*")
                path_mode = _path_tool_level(tool) or "ro"
            else:
                cmd_tokens, cmd_prefixes = [], []
            record: dict[str, Any] = {
                "id": req_id,
                "tool": tool,
                "server": payload.get("server") or "",
                "arguments": arguments,
                "agent_reasoning": payload.get("agent_reasoning") or "",
                "timeout": payload.get("timeout") or "604800s",
                "deadline_ts": time.monotonic() + timeout_sec,
                "context": context,
                "status": status,
                "created_at": now,
                "decision": decision,
                "consumption": None,
                "suggested_prefixes": suggest_command_prefixes(cmd_str) if cmd_str else [],
                "command_tokens": cmd_tokens,
                "command_prefixes": cmd_prefixes,
                "subcommands": subcommands,
                "python_script": extract_reviewable_python_script(cmd_str) if (has_cmd and not subcommands) else None,
                "path_mode": path_mode,
                "review": None,
                "in_queue": status == "pending",
            }
            python_targets = [
                target for target in [record, *subcommands]
                if target.get("python_script") is not None and target["status"] == "pending"
            ]
            if status == "pending" and python_targets:
                record["ui_visible_after"] = received_at + 10.0
                reveal = threading.Timer(
                    max(0.0, record["ui_visible_after"] - time.time()),
                    lambda: self._reveal_request(req_id),
                )
                reveal.daemon = True
                reveal.start()
            self._requests[req_id] = record
            self._idempotency[idempotency_key] = (canonical, req_id)
            if status == "pending":
                if subcommands:
                    for sc in subcommands:
                        if sc["status"] == "pending" and sc.get("python_script") is not None:
                            self.review_request(req_id, sub_index=sc["index"])
                elif record["python_script"] is not None:
                    self.review_request(req_id)
            if status in TERMINAL_STATUSES:
                self._add_history(req_id)
            else:
                self._save_queue()
            self._cond.notify_all()
            self._notify_ui()
            return self._public_view(record), HTTPStatus.CREATED

    def _reveal_request(self, req_id: str) -> None:
        with self._cond:
            record = self._requests.get(req_id)
            if record is not None and record.get("in_queue"):
                self._notify_ui()

    def _check_expiry(self, record: dict[str, Any]) -> None:
        if record["status"] == "pending" and time.monotonic() >= record["deadline_ts"]:
            record["status"] = "expired"
            record["decision"] = {
                "status": "expired",
                "decided_at": utc_now_iso(),
                "reason": "Approval request timed out",
            }
            self._add_history(record["id"])
            self._save_queue()
            self._cond.notify_all()
            self._notify_ui()

    @staticmethod
    def _public_view(record: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in record.items() if k != "deadline_ts"}

    def get_request(self, req_id: str, wait_sec: float = 0.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + max(0.0, min(wait_sec, 30.0))
        with self._cond:
            record = self._requests.get(req_id)
            if record is None:
                return None
            self._check_expiry(record)
            while record["status"] == "pending" and time.monotonic() < deadline:
                remaining = min(deadline - time.monotonic(), max(0.1, record["deadline_ts"] - time.monotonic()))
                if remaining <= 0:
                    break
                self._cond.wait(timeout=remaining)
                self._check_expiry(record)
            return self._public_view(record)

    def _rule_for_decision(
        self,
        record: dict[str, Any],
        target_sub: dict[str, Any] | None,
        action: str,
        allow_always: str | None,
        prefix: str,
        reason: str = "",
    ) -> Rule | None:
        """The rule a UI decision creates: whole tool, domain, prefix, or
        (allow only) this exact call for 12h."""
        tool = record["tool"]
        args = {"command": target_sub["command"]} if target_sub is not None else record["arguments"]
        base = {"id": str(uuid.uuid4()), "tool": tool, "action": action, "hits": 1, "reason": reason}
        if allow_always == "tool":
            return Rule(kind="tool", **base)
        if allow_always == "domain":
            chosen = prefix.strip() or str(args.get("domain") or "").strip()
            return Rule(kind="domain", prefix=chosen, **base) if chosen else None
        if allow_always == "prefix":
            chosen = prefix.strip() or (
                record["suggested_prefixes"][0] if record["suggested_prefixes"] else ""
            )
            if not chosen:
                return None
            if "command" in args or "CommandLine" in args:
                return Rule(kind="command_prefix", prefix=chosen, **base)
            # A deny path rule blocks reads and writes alike.
            mode = "rw" if action == "deny" else (_path_tool_level(tool) or "ro")
            return Rule(kind="path_prefix", prefix=chosen, mode=mode, **{**base, "tool": "*"})
        if action != "allow":
            return None
        # Plain Approve remembers this exact call with a 12h TTL
        return Rule(kind="exact", arguments=args, expires_at=utc_after_iso(12 * 3600), **base)

    def _apply_new_rule(
        self, rule: Rule, record: dict[str, Any], target_sub: dict[str, Any] | None
    ) -> None:
        """Decide other pending requests (and steps) that the new rule now
        governs, i.e. where it is the rule RuleStore.match picks."""

        def governs(tool: str, arguments: dict[str, Any]) -> bool:
            winner = self.rules.match(tool, arguments, record_hit=False)
            return winner is not None and winner.id == rule.id

        status = "approved" if rule.action == "allow" else "denied"
        for other in self._requests.values():
            if other["status"] != "pending":
                continue
            if status == "denied" and other is record:
                continue  # decide_request denies it itself
            other_subs = other.get("subcommands") or []
            if other_subs:
                hit = False
                for sc in other_subs:
                    if sc["status"] == "pending" and governs(other["tool"], {"command": sc["command"]}):
                        sc["status"] = status
                        sc["rule_id"] = rule.id
                        sc["labels"] = [rule_label(rule)]
                        hit = True
                        if sc is not target_sub:
                            self.rules.record_hit(rule.id)
                if status == "approved" and all(sc["status"] == "approved" for sc in other_subs):
                    labels = merge_labels(*(s.get("labels") for s in other_subs))
                elif status == "denied" and hit:
                    labels = [rule_label(rule)]
                else:
                    continue
            elif other is not record and governs(other["tool"], other["arguments"]):
                labels = [rule_label(rule)]
                self.rules.record_hit(rule.id)
            else:
                continue
            other["status"] = status
            other["in_queue"] = False
            other["decision"] = {
                "status": status,
                "decided_at": utc_now_iso(),
                "reason": rule_decision_reason(rule),
                "rule_id": rule.id,
                "labels": labels,
            }
            self._add_history(other["id"])

    def decide_request(
        self,
        req_id: str,
        decision_status: str,
        reason: str = "",
        allow_always: str | None = None,
        prefix: str = "",
        sub_index: int | None = None,
        lazy: bool = False,
    ) -> dict[str, Any] | None:
        """Decide from the UI; `lazy` marks an automatic decision made because
        the operator did not react (labels the decision "lazy", not "click")."""
        if decision_status not in {"approved", "denied"}:
            raise ValueError("invalid_decision")
        with self._cond:
            record = self._requests.get(req_id)
            if record is None:
                return None
            self._check_expiry(record)
            if record["status"] not in {"pending", "expired", "cancelled"} and not record.get("in_queue"):
                return self._public_view(record)

            subcommands: list[dict[str, Any]] = record.get("subcommands") or []
            target_sub: dict[str, Any] | None = None
            if subcommands and sub_index is not None:
                if 0 <= sub_index < len(subcommands):
                    target_sub = subcommands[sub_index]

            created_rule: dict[str, Any] | None = None
            one_time = (
                target_sub.get("python_script") is not None if target_sub is not None
                else record.get("python_script") is not None
                    or any(sc.get("python_script") is not None for sc in subcommands)
            )
            # Long Python scripts never create approval rules. Denials create a
            # rule only when one was asked for (tool/domain/prefix); the deny
            # reason becomes the rule's reason for later matches.
            new_rule: Rule | None = None
            if decision_status == "approved" and not one_time:
                new_rule = self._rule_for_decision(record, target_sub, "allow", allow_always, prefix)
            elif decision_status == "denied" and allow_always in {"tool", "domain", "prefix"}:
                new_rule = self._rule_for_decision(record, target_sub, "deny", allow_always, prefix, reason.strip())
            if new_rule is not None:
                created_rule = self.rules.add_rule(new_rule).to_dict()
                self._apply_new_rule(Rule.from_dict(created_rule), record, target_sub)

            target = target_sub if target_sub is not None else record
            review = target.get("review")
            own_labels = merge_labels(
                ["ai-review"] if isinstance(review, dict) and review.get("status") == "done" and review.get("decision") else [],
                ["lazy" if lazy else "click"],
                [] if created_rule is None else ["new-12h" if created_rule.get("kind") == "exact" else "new-rule"],
            )

            if target_sub is not None:
                target_sub["status"] = decision_status
                target_sub["labels"] = own_labels
                if created_rule is not None:
                    target_sub["rule_id"] = created_rule["id"]
                if decision_status == "denied":
                    record["status"] = "denied"
                    record["in_queue"] = False
                    record["decision"] = {
                        "status": "denied",
                        "decided_at": utc_now_iso(),
                        "reason": reason.strip() or f"Denied subcommand: {target_sub['command']}",
                        "labels": own_labels,
                    }
                    if created_rule is not None:
                        record["decision"]["rule_id"] = created_rule["id"]
                    self._add_history(req_id)
                elif all(sc["status"] == "approved" for sc in subcommands):
                    record["status"] = "approved"
                    record["in_queue"] = False
                    record["decision"] = {
                        "status": "approved",
                        "decided_at": utc_now_iso(),
                        "reason": reason.strip() or "All subcommands approved",
                        "labels": merge_labels(*(sc.get("labels") for sc in subcommands)),
                    }
                    if created_rule is not None:
                        record["decision"]["rule_id"] = created_rule["id"]
                    self._add_history(req_id)
                self._save_queue()
                self._cond.notify_all()
                self._notify_ui()
                return self._public_view(record)

            record["status"] = decision_status
            record["in_queue"] = False
            record["decision"] = {
                "status": decision_status,
                "decided_at": utc_now_iso(),
                "reason": reason.strip() or (
                    "Approved in UI" if decision_status == "approved" else "Denied in UI"
                ),
                "labels": own_labels,
            }
            if created_rule is not None:
                record["decision"]["rule_id"] = created_rule["id"]
            self._add_history(req_id)
            self._save_queue()
            self._cond.notify_all()
            self._notify_ui()
            return self._public_view(record)

    def review_request(self, req_id: str, sub_index: int | None = None) -> dict[str, Any] | None:
        with self._cond:
            record = self._requests.get(req_id)
            if record is None:
                return None
            target: dict[str, Any] = record
            if sub_index is not None:
                subs = record.get("subcommands") or []
                if not isinstance(sub_index, int) or sub_index < 0 or sub_index >= len(subs):
                    raise ValueError("Invalid sub_index")
                target = subs[sub_index]
            script = target.get("python_script")
            if not isinstance(script, str) or not script:
                raise ValueError("Not a python -c script")
            existing = target.get("review")
            if isinstance(existing, dict) and existing.get("status") == "running":
                return self._public_view(record)
            runtime = str((record.get("context") or {}).get("runtime") or "")
            agent, agent_why = self._pick_review_agent(runtime)
            target["review"] = {
                "status": "running",
                "started_at": utc_now_iso(),
                "summary": "Reviewing script...",
                "agent": agent,
                "agent_reason": agent_why,
            }
            review_cmd = [*self.review_cmd, "--agent", agent]
            cwd = str((record.get("context") or {}).get("cwd") or "")
            if cwd:
                review_cmd += ["--cwd", cwd]
            self._notify_ui()

        def _finish() -> None:
            # Only record the verdict; the user decides in the UI.
            verdict = run_python_review(review_cmd, script)
            with self._cond:
                target["review"] = {
                    "status": "done",
                    "finished_at": utc_now_iso(),
                    **verdict,
                    "agent": agent,
                    "agent_reason": agent_why,
                }
                python_targets = [
                    entry for entry in [record, *(record.get("subcommands") or [])]
                    if entry.get("python_script") is not None and entry["status"] == "pending"
                ]
                if all((entry.get("review") or {}).get("status") == "done" for entry in python_targets):
                    record["ui_visible_after"] = 0.0
                self._save_queue()
                self._notify_ui()

        threading.Thread(target=_finish, daemon=True).start()
        return self._public_view(record)

    def _pick_review_agent(self, runtime: str) -> tuple[str, str]:
        data = self.usage.snapshot().get("data") if self.usage is not None else None
        return choose_review_agent(runtime, data)

    def consume_request(self, req_id: str) -> tuple[dict[str, Any] | None, int]:
        with self._cond:
            record = self._requests.get(req_id)
            if record is None:
                return None, HTTPStatus.NOT_FOUND
            if record["status"] != "approved":
                return self._public_view(record), HTTPStatus.CONFLICT
            if record["consumption"] is None:
                record["consumption"] = {"consumed_at": utc_now_iso()}
                self._notify_ui()
            return self._public_view(record), HTTPStatus.OK

    def cancel_request(self, req_id: str) -> dict[str, Any] | None:
        with self._cond:
            record = self._requests.get(req_id)
            if record is None:
                return None
            if record["status"] == "pending":
                record["status"] = "cancelled"
                record["decision"] = {
                    "status": "cancelled",
                    "decided_at": utc_now_iso(),
                    "reason": "Cancelled by agent",
                }
                self._add_history(record["id"])
                self._save_queue()
                self._cond.notify_all()
                self._notify_ui()
            return self._public_view(record)

    def ui_state(self) -> dict[str, Any]:
        with self._cond:
            for r in list(self._requests.values()):
                self._check_expiry(r)
            pending = [
                self._public_view(r)
                for r in self._requests.values()
                if r.get("in_queue", r["status"] == "pending")
                and (
                    r["status"] != "pending"
                    or time.time() >= r.get("ui_visible_after", 0.0)
                )
            ]
            pending.sort(key=lambda r: r["created_at"])
            history = [
                self._public_view(self._requests[rid])
                for rid in self._history
                if rid in self._requests
            ]
            return {
                "pending": pending,
                "history": history[:50],
                "rules": self.rules.list_rules(),
            }


USAGE_REFRESH_SECONDS = 30.0


def fetch_ai_usage() -> dict[str, Any]:
    """usage_data() from ai_usage.py, which lives next to this script."""
    script_dir = str(Path(__file__).resolve().parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import ai_usage

    return ai_usage.usage_data()


class UsageCache:
    """
    AI usage for the UI's usage tab.

    Fetching runs the agents' CLIs and takes many seconds, so it happens
    in a background thread, at most once per `interval`. start() keeps the
    data fresh from server start on, so the tab never waits for a first
    fetch; a stale snapshot() also kicks off a refresh.
    """

    def __init__(self, fetch: Any = None, interval: float = USAGE_REFRESH_SECONDS) -> None:
        self._fetch = fetch or fetch_ai_usage
        self.interval = interval
        self._lock = threading.Lock()
        self._data: dict[str, Any] | None = None
        self._error: str | None = None
        self._updated_at: str | None = None
        self._started: float | None = None
        self._fetching = False

    def start(self) -> None:
        def loop() -> None:
            while True:
                self.snapshot()
                time.sleep(1.0)

        threading.Thread(target=loop, name="usage-refresh", daemon=True).start()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            stale = self._started is None or time.monotonic() - self._started >= self.interval
            if stale and not self._fetching:
                self._fetching = True
                self._started = time.monotonic()
                threading.Thread(target=self._refresh, daemon=True).start()
            return {
                "data": self._data,
                "error": self._error,
                "updated_at": self._updated_at,
                "loading": self._fetching,
                "interval": self.interval,
            }

    def _refresh(self) -> None:
        try:
            data, error = self._fetch(), None
        except Exception as exc:  # noqa: BLE001 - shown in the UI
            data, error = None, str(exc) or exc.__class__.__name__
        with self._lock:
            if data is not None:
                self._data = data
            self._error = error
            self._updated_at = utc_now_iso()
            self._fetching = False


UI_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>aap-ui</title>
<link id="favicon" rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><path d='M16 2 4 6v9c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V6z' fill='%23238636'/><path d='m10 16 4 4 8-8' fill='none' stroke='%23fff' stroke-width='3.2' stroke-linecap='round' stroke-linejoin='round'/></svg>" />
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --green: #238636; --green-h: #2ea043;
    --blue: #1f6feb; --blue-h: #388bfd; --red: #da3633; --red-h: #f85149;
    --amber: #d29922;
    /* With a request the panel fits its card, between these bounds. */
    --queue-min-height: min(200px, calc(100dvh - 144px));
    --queue-max-height: min(640px, calc(100dvh - 144px));
    --queue-bar-height: 40px;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); }
  header { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px 20px; padding: 14px 20px; border-bottom: 1px solid var(--border); background: var(--card); position: sticky; top: 0; z-index: 10; }
  header h1 { margin: 0; font-size: 16px; display: flex; align-items: center; gap: 10px; }
  .status-dot { flex: none; width: 10px; height: 10px; border-radius: 50%; background: var(--red-h); box-shadow: 0 0 0 3px rgba(248, 81, 73, 0.25); }
  .status-dot.online { background: var(--green-h); box-shadow: 0 0 0 3px rgba(46, 160, 67, 0.25); }
  .status-dot[hidden] { display: none; }
  .badge { font-size: 12px; padding: 2px 8px; border-radius: 999px; background: #21262d; color: var(--muted); }
  .badge.pending { background: rgba(210, 153, 34, 0.2); color: var(--amber); }
  .tabs { display: flex; gap: 8px; }
  .tab { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  .tab.active { background: #21262d; color: var(--text); border-color: #8b949e; }
  main { max-width: 960px; margin: 20px auto; padding: 0 16px 40px; }
  .layout { display: flex; flex-direction: column; gap: 18px; }
  body { padding-bottom: var(--queue-bar-height); transition: padding-bottom 180ms ease; }
  /* --queue-panel-height is the measured panel height (ResizeObserver). */
  body.has-queue { padding-bottom: var(--queue-panel-height, var(--queue-min-height)); }
  .queue-panel { position: fixed; inset: auto 0 0; height: var(--queue-bar-height); z-index: 20; display: flex; flex-direction: column; background: #111b27; border-top: 1px solid var(--border); transition: height 180ms ease, border-color 180ms ease; }
  body.has-queue .queue-panel { height: auto; min-height: var(--queue-min-height); max-height: var(--queue-max-height); border-top-color: var(--amber); box-shadow: 0 -8px 28px rgba(0, 0, 0, 0.35); }
  .queue-inner { width: 100%; max-width: 960px; flex: 1; min-height: 0; margin: 0 auto; padding: 10px 16px; display: flex; flex-direction: column; justify-content: center; }
  .queue-nav { display: inline-flex; align-items: center; gap: 8px; text-transform: none; letter-spacing: 0; font-variant-numeric: tabular-nums; }
  .queue-nav[hidden] { display: none; }
  .queue-nav button { min-width: 30px; padding: 2px 8px; font-size: 16px; line-height: 1.2; }
  .queue-nav button:disabled { opacity: 0.35; cursor: default; }
  body.has-queue .queue-inner { padding: 14px 16px; justify-content: flex-start; }
  body:not(.has-queue) #queue-title { margin: 0; font-weight: 400; text-transform: none; letter-spacing: 0; }
  @media (prefers-reduced-motion: reduce) {
    body, .queue-panel { transition: none; }
  }
  .queue-content { flex: 1; min-height: 0; overflow-y: auto; overscroll-behavior: contain; scrollbar-gutter: stable; }
  .queue-content .card:last-child { margin-bottom: 0; }
  .queue-content pre { max-height: 144px; overflow-y: auto; }
  @media (max-width: 640px) {
    header { gap: 10px 14px; padding: 12px 16px; }
    .queue-content input.reason { min-width: 140px; }
  }
  .panel-title { font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 10px; display: flex; align-items: center; justify-content: space-between; }
  .sub-title { font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 14px 0 8px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
  .rule-card { background: #1c2128; border-color: #363d46; transition: border-color 0.1s, background 0.1s; }
  .rule-card .card-head { display: flow-root; margin-bottom: 0; }
  .rule-card .card-head > div:last-child { line-height: 1.65; }
  /* Approved (12h TTL): long commands are cut to 7 lines (full text in the tooltip). */
  .ttl-row { display: flex; align-items: flex-start; gap: 6px; }
  .ttl-row .pill { flex: none; }
  code.ttl-code { display: block; min-width: 0; max-height: calc(7 * 1.65em + 4px); overflow: hidden; }
  .rule-card .btn-group { float: right; margin: 0 0 -3px 12px; }
  .rule-card .action-icon { margin-right: 6px; position: relative; top: 2px; }
  .rule-card:hover { border-color: #58a6ff; background: #232a35; }
  .card-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
  .meta { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .meta .auto-decide { margin-right: 6px; }
  .pill { font-size: 11px; padding: 2px 7px; border-radius: 4px; background: #21262d; color: var(--text); font-family: ui-monospace, monospace; }
  .pill.claude-code { background: rgba(210, 153, 34, 0.18); color: #f0b754; }
  .pill.codex { background: rgba(56, 139, 253, 0.18); color: #79c0ff; }
  .pill.antigravity { background: rgba(163, 113, 247, 0.18); color: #d2a8ff; }
  .pill.mode-ro { background: rgba(56, 139, 253, 0.14); color: #79c0ff; border: 1px solid rgba(88, 166, 255, 0.28); }
  .pill.mode-rw { background: rgba(210, 153, 34, 0.18); color: #f0b754; border: 1px solid rgba(210, 153, 34, 0.35); }
  pre { margin: 8px 0; padding: 10px; background: #0d1117; border: 1px solid var(--border); border-radius: 6px; overflow-x: auto; font-size: 12.5px; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; align-items: center; }
  .btn-group { display: flex; gap: 6px; align-items: center; }
  select.action-sel { background: #0d1117; border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 6px 8px; font-size: 13px; }
  button { border: 0; border-radius: 6px; padding: 7px 12px; font-size: 13px; font-weight: 500; cursor: pointer; color: #fff; }
  button.approve { background: var(--green); } button.approve:hover { background: var(--green-h); }
  button.always { background: var(--blue); } button.always:hover { background: var(--blue-h); }
  button.deny { background: var(--red); } button.deny:hover { background: var(--red-h); }
  button.ghost { background: #21262d; color: var(--text); border: 1px solid var(--border); transition: background 0.1s, border-color 0.1s; }
  button.ghost:hover { background: #30363d; border-color: #8b949e; }
  button.del-btn { background: rgba(218, 54, 51, 0.16); color: #ffa198; border: 1px solid rgba(248, 81, 73, 0.35); transition: background 0.1s, color 0.1s, border-color 0.1s; }
  button.del-btn:hover { background: rgba(218, 54, 51, 0.48); color: #fff; border-color: var(--red); }
  button.icon-btn { display: inline-flex; align-items: center; justify-content: center; padding: 6px; }
  button.icon-btn svg { width: 15px; height: 15px; fill: none; stroke: currentColor; stroke-width: 1.9; stroke-linecap: round; stroke-linejoin: round; display: block; }
  .hits-pill { color: #79c0ff; border-color: rgba(88, 166, 255, 0.25); background: rgba(31, 111, 235, 0.08); font-variant-numeric: tabular-nums; }
  .hits-link { text-decoration: none; cursor: pointer; transition: background 0.1s, border-color 0.1s, color 0.1s; }
  .hits-link:hover { background: rgba(31, 111, 235, 0.24); border-color: #58a6ff; color: #fff; }
  .filter-bar { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 10px 14px; margin-bottom: 12px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; font-size: 13px; color: var(--muted); }
  .rule-jump-link { display: inline-flex; align-items: center; gap: 4px; font-family: ui-monospace, monospace; font-size: 11.5px; color: #79c0ff; background: rgba(31, 111, 235, 0.12); border: 1px solid rgba(88, 166, 255, 0.3); border-radius: 4px; padding: 1px 7px; text-decoration: none; cursor: pointer; transition: background 0.1s, border-color 0.1s, color 0.1s; }
  /* Exact-call rules can carry whole file contents: clip the link to 2 lines. */
  .rule-jump-link { display: inline-block; vertical-align: top; max-width: 100%; max-height: calc(2 * 1.45em + 4px); overflow: hidden; line-height: 1.45; overflow-wrap: anywhere; }
  .rule-jump-link:hover { background: rgba(31, 111, 235, 0.28); border-color: #58a6ff; color: #fff; }
  @keyframes rulePulse {
    0% { border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.45); background: #263142; }
    100% { border-color: #58a6ff; box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.22); background: #232a35; }
  }
  .rule-highlight { border-color: #58a6ff !important; background: #232a35 !important; box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.25); animation: rulePulse 1.2s ease-out; }
  input.reason { background: #0d1117; border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 6px 10px; font-size: 13px; flex: 1; min-width: 180px; }
  .empty { text-align: center; color: var(--muted); padding: 48px 16px; border: 1px dashed var(--border); border-radius: 8px; }
  .status-approved { color: #3fb950; } .status-denied, .status-expired, .status-cancelled { color: #f85149; }
  .prefix-builder { margin: 8px 0 4px; padding: 8px 10px; background: #0d1117; border: 1px solid var(--border); border-radius: 6px; }
  .prefix-label { font-size: 11px; color: var(--muted); margin-bottom: 6px; display: flex; justify-content: space-between; gap: 8px; min-width: 0; }
  .prefix-preview { font-family: ui-monospace, monospace; color: #79c0ff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .token-bar { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
  .approve-label { font-size: 12px; font-weight: 600; color: var(--muted); margin-right: 2px; }
  .token-btn { background: #21262d; color: var(--text); border: 1px solid var(--border); border-radius: 5px; padding: 4px 8px; font-size: 12.5px; font-family: ui-monospace, monospace; cursor: pointer; transition: background 0.08s, border-color 0.08s; max-width: 100%; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; text-align: left; }
  .token-btn.lit { background: rgba(31, 111, 235, 0.35); border-color: var(--blue-h); color: #fff; }
  .deny-mode .token-btn.lit { background: rgba(248, 81, 73, 0.3); border-color: #f85149; }
  .deny-mode .prefix-preview { color: #ff7b72; }
  button.mode-toggle { font-size: 12px; font-weight: 600; color: var(--muted); background: none; border: 1px dashed var(--border); border-radius: 5px; padding: 3px 7px; margin-right: 2px; cursor: pointer; }
  button.mode-toggle:hover { color: var(--text); border-color: var(--muted); }
  .deny-mode button.mode-toggle { color: #ff7b72; border-color: #f85149; border-style: solid; }
  .rule-reason-row { display: flex; margin-top: 6px; }
  input.reason.invalid { border-color: #f85149; }
  .rule-reason-text { margin-top: 4px; font-size: 12px; color: var(--muted); }
  code.rule-code { font-family: ui-monospace, monospace; font-size: 13px; background: #0d1117; border: 1px solid var(--border); padding: 2px 7px; border-radius: 4px; color: var(--text); overflow-wrap: anywhere; word-break: break-word; }
  .chip-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
  .rule-chip { display: inline-flex; align-items: center; gap: 10px; background: #1c2128; border: 1px solid #363d46; border-radius: 8px; padding: 8px 12px; font-size: 13px; transition: border-color 0.1s, background 0.1s; }
  .rule-chip:hover { border-color: #58a6ff; background: #232a35; }
  .rule-chip code { font-family: ui-monospace, monospace; font-size: 13px; color: var(--text); }
  button.review-btn { background: #6e40c9; }
  button.review-btn:hover { background: #8957e5; }
  button.review-btn:disabled { opacity: 0.65; cursor: wait; }
  .u-agy { --u: #33d17a; } .u-claude { --u: #c061cb; } .u-codex { --u: #3584e4; }
  .u-status { text-transform: none; letter-spacing: 0; font-size: 12px; }
  .u-provider { margin-bottom: 18px; }
  .u-provider .panel-title > span:first-child { display: inline-flex; align-items: center; gap: 8px; color: var(--text); }
  .u-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--u); }
  /* One grid for all providers; each card is a subgrid, so text columns are
     as wide as their longest content in any card and the bar takes the rest. */
  .u-grid { display: grid; grid-template-columns: max-content max-content minmax(60px, 1fr) max-content max-content max-content; font-size: 13px; }
  .u-provider, .u-card { grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; }
  .u-provider > .panel-title { grid-column: 1 / -1; }
  .u-card { padding: 4px 0; }
  .u-cell { display: flex; align-items: center; padding: 9px 16px; white-space: nowrap; border-top: 1px solid #21262d; }
  .u-cell.u-first { border-top-color: var(--border); }
  .u-th { font-weight: 500; font-size: 11.5px; color: var(--muted); padding: 8px 16px 6px; border-top: 0; }
  .u-c-model { grid-column: 1; font-weight: 600; align-items: flex-start; }
  .u-th.u-c-model { font-weight: 500; }
  .u-c-window { grid-column: 2; }
  .u-c-bar { grid-column: 3; }
  .u-c-used { grid-column: 4; justify-content: flex-end; font-variant-numeric: tabular-nums; }
  .u-c-pace { grid-column: 5; justify-content: flex-end; font-variant-numeric: tabular-nums; }
  .u-c-resets { grid-column: 6; }
  .u-c-rest { grid-column: 3 / -1; }
  .u-c-full { grid-column: 1 / -1; border-top: 0; min-width: 0; }
  .u-clip { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
  .u-group-row { grid-column: 1 / -1; display: none; }
  .u-track { position: relative; flex: 1; height: 10px; border-radius: 5px; background: #21262d; overflow: hidden; }
  .u-track span { position: absolute; top: 0; bottom: 0; }
  .u-elapsed { left: 0; background: rgba(139, 148, 158, 0.16); }
  .u-fill { left: 0; background: var(--u); }
  .u-over { background: #f85149; }
  .u-mark { width: 2px; margin-left: -1px; background: #e6edf3; opacity: 0.75; }
  .u-used { font-weight: 600; }
  .u-red { color: #f85149; } .u-dim { color: var(--muted); }
  .u-when { color: var(--muted); font-size: 11.5px; margin-left: 6px; }
  .u-alert { font-size: 11.5px; text-transform: none; letter-spacing: 0; color: #ffa198; background: rgba(218, 54, 51, 0.16); border: 1px solid rgba(248, 81, 73, 0.35); border-radius: 999px; padding: 1px 8px; }
  .u-heading { margin-bottom: 16px; }
  /* Header usage strip: one meter per model group. */
  /* Name + tabs on the left, usage strip on the right; the strip never
     shrinks, so when it does not fit it wraps to a row of its own. */
  .head-main { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 20px; }
  header h1, header .tabs { flex: none; white-space: nowrap; }
  .hu { flex: none; max-width: 100%; display: flex; align-items: center; gap: 8px; overflow-x: auto; scrollbar-width: none; }
  .hu[hidden] { display: none; }
  .hu-meter { flex: none; position: relative; width: 116px; height: 26px; border-radius: 6px; background: #21262d; border: 1px solid var(--border); overflow: hidden; cursor: pointer; }
  .hu-meter:hover { border-color: #8b949e; }
  /* Only the usage table is shown, framed like a popover. */
  .hu-pop { position: fixed; z-index: 40; width: min(720px, calc(100vw - 16px)); pointer-events: none; }
  .hu-pop[hidden] { display: none; }
  .hu-pop .u-provider { margin-bottom: 0; }
  .hu-pop .u-provider > .panel-title { display: none; }
  .hu-pop .u-card { margin: 0; border-color: #8b949e; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); }
  .hu-meter > span { position: absolute; top: 0; bottom: 0; }
  .hu-fill { left: 0; background: var(--u); opacity: 0.45; }
  .hu-over { background: #f85149; opacity: 0.55; }
  .hu-mark { width: 1px; background: #e6edf3; opacity: 0.25; }
  .hu-meter > .hu-text { left: 0; right: 0; display: flex; align-items: center; justify-content: space-between; gap: 6px; padding: 0 8px; font-size: 12px; font-weight: 600; white-space: nowrap; text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8); font-variant-numeric: tabular-nums; }
  .hu-text small { font-weight: 400; color: var(--muted); }
  .hu-warn { color: var(--amber); }
  .hu .u-track { height: 6px; border-radius: 3px; }
  @media (max-width: 640px) {
    /* Model names move to a row above their windows; Pace and dates go. */
    .u-cell { padding-left: 10px; padding-right: 10px; }
    .u-c-model, .u-c-pace, .u-when { display: none; }
    .u-group-row { display: flex; font-weight: 600; padding-top: 10px; padding-bottom: 2px; border-top-color: var(--border); }
    .u-cell.u-first { border-top: 0; }
  }
  .review-box { margin: 8px 0 4px; padding: 8px 10px; background: rgba(110, 64, 201, 0.12); border: 1px solid rgba(137, 87, 229, 0.4); border-radius: 6px; font-size: 12.5px; color: #d2a8ff; }
  .pill.python { background: rgba(55, 118, 171, 0.25); color: #79b8ff; border-color: rgba(55, 118, 171, 0.6); font-weight: 600; }
  .py-script, .queue-content pre.py-script, .call-cmd, .queue-content pre.call-cmd { max-height: calc(7.25em + 22px); overflow: hidden; white-space: pre-wrap; overflow-wrap: anywhere; }
  .py-script { border-left: 3px solid rgba(55, 118, 171, 0.7); }
  .copy-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 2px 0 8px; }
  .copy-meta { margin-left: auto; }
  .copy-btn { font-size: 11.5px; padding: 3px 8px; }
  .test-result { padding: 10px 12px; border-radius: 6px; border: 1px solid var(--border); display: flex; flex-direction: column; gap: 6px; }
  .test-result.approved { border-color: rgba(63, 185, 80, 0.6); background: rgba(63, 185, 80, 0.08); }
  .test-result.denied { border-color: rgba(248, 81, 73, 0.6); background: rgba(248, 81, 73, 0.08); }
  /* Decision-source labels in History. */
  .pill.dl { font-size: 11px; vertical-align: 1px; }
  .dl-rule { color: #79c0ff; border-color: rgba(56, 139, 253, 0.5); background: rgba(56, 139, 253, 0.12); }
  .dl-prior { color: #56d4dd; border-color: rgba(57, 197, 207, 0.5); background: rgba(57, 197, 207, 0.12); }
  .dl-ai-review { color: #d2a8ff; border-color: rgba(137, 87, 229, 0.5); background: rgba(137, 87, 229, 0.14); }
  .dl-click { color: #c9d1d9; border-color: var(--border); background: #21262d; }
  .dl-lazy { color: #e3b341; border-color: rgba(210, 153, 34, 0.5); background: rgba(210, 153, 34, 0.14); }
  .dl-new-rule, .dl-new-12h { color: #7ee787; border-color: rgba(63, 185, 80, 0.5); background: rgba(63, 185, 80, 0.12); }
  .verdict-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .auto-decide { display: inline-flex; align-items: center; gap: 8px; font-size: 12.5px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .auto-decide button { padding: 2px 10px; font-size: 12px; font-weight: 400; }
  .full-cmd-box { margin: 8px 0; padding: 8px 10px; background: rgba(110, 118, 129, 0.08); border: 1px dashed var(--border); border-radius: 6px; }
  .full-cmd-box summary { cursor: pointer; font-size: 11.5px; font-weight: 600; color: var(--muted); user-select: none; }
  .full-cmd-box pre { margin: 6px 0 0; max-height: 180px; overflow-y: auto; opacity: 0.9; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
</head>
<body>
<header>
  <div class="head-main">
    <h1><span id="status-dot" class="status-dot" role="status" hidden></span>aap-ui</h1>
    <div class="tabs">
      <button class="tab" data-tab="live">Rules</button>
      <button class="tab active" data-tab="history">History</button>
      <button class="tab" data-tab="usage">AI usage</button>
    </div>
  </div>
  <div id="header-usage" class="hu" aria-label="AI usage" hidden></div>
  <div id="hu-pop" class="hu-pop" hidden></div>
</header>
<main id="app"></main>
<section id="queue-panel" class="queue-panel" aria-labelledby="queue-title">
  <div class="queue-inner">
    <h2 id="queue-title" class="panel-title"><span id="queue-label">Nothing to review</span>
      <span id="queue-nav" class="queue-nav" hidden>
        <button id="queue-prev" class="ghost" onclick="queueStep(-1)" title="Previous request" aria-label="Previous request">&lsaquo;</button>
        <span id="queue-pos" aria-live="polite"></span>
        <button id="queue-next" class="ghost" onclick="queueStep(1)" title="Next request" aria-label="Next request">&rsaquo;</button>
      </span></h2>
    <div id="queue-content" class="queue-content" tabindex="0" aria-label="Requests awaiting approval" hidden></div>
  </div>
</section>
<script>
let state = { pending: [], history: [], rules: [] };
let activeTab = 'history';
let editingRuleId = null;
let historyRuleFilter = null;
let highlightedRuleId = null;
let highlightTimer = null;
let queueMarkup = null;
const reasonDrafts = new Map();
const seededReasons = new Map();  // reason input id -> reviewer reason already pre-filled

function reasonInputId(requestId, subIndex = null) {
  return 'reason-' + requestId + (subIndex === null ? '' : '-sub-' + subIndex);
}

document.getElementById('queue-content').addEventListener('input', event => {
  if (event.target.matches('input.reason')) {
    reasonDrafts.set(event.target.id, event.target.value);
    cancelAutoDecideForInput(event.target.id);
  }
});

// History is the default tab (at /); /history stays as an alias for old links.
const TAB_PATHS = { live: '/rules', history: '/', usage: '/ai-usage' };

// Verdict box for the queue's Review button.
function renderVerdict(decision, reason, stage, extra = '', explanation = '', headExtra = '') {
  const ok = decision === 'approved';
  return `
    <div class="test-result ${ok ? 'approved' : 'denied'}">
      <div class="verdict-head"><span><strong class="status-${esc(decision)}">${ok ? 'LOOKS GOOD' : 'REQUEST CHANGES'}</strong>
        <span class="pill">${esc(stage || '')}</span></span>${headExtra}</div>
      ${explanation ? `<div><strong>Script:</strong> ${esc(explanation)}</div>` : ''}
      ${reason ? `<div>${esc(reason)}</div>` : ''}
      ${extra}
    </div>`;
}

function tabFromPath() {
  if (location.pathname === '/history') return 'history';
  return Object.keys(TAB_PATHS).find(t => TAB_PATHS[t] === location.pathname) || 'history';
}

// Switches tabs and keeps the URL in sync; `push` is false when the URL
// already says where we are (page load, back/forward).
function setTab(tab, push = true) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  if (push && location.pathname !== TAB_PATHS[tab]) history.pushState({ tab }, '', TAB_PATHS[tab]);
  render();
  if (tab === 'usage') fetchUsage();
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    historyRuleFilter = null;
    setTab(btn.dataset.tab);
  };
});

window.addEventListener('popstate', () => {
  historyRuleFilter = null;
  setTab(tabFromPath(), false);
});

let usage = null;
async function fetchUsage() {
  try {
    const res = await fetch('/api/ui/usage');
    usage = await res.json();
  } catch (e) {
    usage = { error: String(e), interval: usage ? usage.interval : 30 };
  }
  renderHeaderUsage();
  if (activeTab === 'usage') render();
}

// Header strip: one meter per model group, side by side, with the name and
// percentage inside it. Each meter shows the group's window furthest ahead
// of its expected usage; the full table lives in the AI usage tab.
let headerUsageMarkup = null;
const HEADER_USAGE_SHORT = { 'Claude and GPT': 'Cl+GPT', 'Gemini 4 Argon': 'Argon' };

function huMeter(key, name, w, fallback, tip, group = '') {
  // Hovering shows this model group's AI usage rows in a popover.
  const open = `<div class="hu-meter u-${esc(key)}" data-provider="${esc(key)}" data-group="${esc(group)}" aria-label="${esc(tip)}" onclick="historyRuleFilter = null; setTab('usage')">`;
  if (!w || w.used_percent == null) {
    return open + `<span class="hu-text"><span>${esc(name)}</span><span class="u-dim">n/a</span></span></div>`;
  }
  const clamp = v => Math.max(0, Math.min(100, v));
  const used = clamp(w.used_percent);
  const pace = w.expected_percent == null ? null : clamp(w.expected_percent);
  const onTime = pace == null ? used : Math.min(used, pace);
  const cls = w.used_percent >= 80 ? 'u-red' : (pace != null && used > pace ? 'hu-warn' : '');
  return open +
    `<span class="hu-fill" style="width:${onTime}%"></span>` +
    (used > onTime ? `<span class="hu-over" style="left:${onTime}%;width:${used - onTime}%"></span>` : '') +
    (pace != null ? `<span class="hu-mark" style="left:${pace}%"></span>` : '') +
    `<span class="hu-text"><span>${esc(name)}${fallback ? ` <small>${esc(fallback)}</small>` : ''}</span>` +
    `<span class="${cls}">${w.used_percent}%</span></span></div>`;
}

function renderHeaderUsage() {
  const el = document.getElementById('header-usage');
  const data = usage && usage.data;
  const items = [];
  for (const [key, p] of Object.entries((data && data.providers) || {})) {
    if (p.error) {
      items.push(huMeter(key, p.name, null, '', p.name + ': ' + p.error));
      continue;
    }
    const groups = (p.groups || []).filter(g => (g.windows || []).length);
    for (const g of groups) {
      const full = groups.length === 1 || g.name === 'All models' ? p.name : g.name.replace(/ +models$/i, '');
      const name = HEADER_USAGE_SHORT[full] || full;
      const tip = [p.name + (name === p.name ? '' : ' · ' + g.name)].concat(g.windows.map(w => {
        if (w.used_percent == null) return `${w.label}: unavailable`;
        let t = `${w.label}: ${w.used_percent}% used`;
        if (w.expected_percent != null) t += `, pace ${w.expected_percent}%`;
        if (w.reset) t += `, resets ${fmtIn(w.reset)} (${fmtWhen(w.reset)})`;
        return t;
      })).join('\\n');
      // The window furthest ahead of its expected usage, labelled 5h/7d.
      const over = x => x.used_percent == null ? -Infinity : x.used_percent - (x.expected_percent ?? x.used_percent);
      const w = g.windows.reduce((a, b) => (over(b) > over(a) ? b : a));
      items.push(huMeter(key, name, w, w.label === 'Weekly' ? '7d' : w.label, tip, g.name));
    }
  }
  const markup = items.join('');
  if (markup === headerUsageMarkup) return;
  headerUsageMarkup = markup;
  el.innerHTML = markup;
  el.hidden = !markup;
  if (huPopKey) showUsagePopover(huPopKey, huPopGroup);  // keep an open popover fresh
}

// Popover under a header meter with that model group's rows from the AI
// usage tab (same markup); a provider-level error shows the whole provider.
let huPopKey = null;
let huPopGroup = '';
let huPopAnchor = null;
function showUsagePopover(key, group, anchor = huPopAnchor) {
  const pop = document.getElementById('hu-pop');
  const p = usage && usage.data && usage.data.providers && usage.data.providers[key];
  if (!p || !anchor || !anchor.isConnected) {
    anchor = [...document.querySelectorAll('#header-usage .hu-meter')]
      .find(m => m.dataset.provider === key && m.dataset.group === group);
    if (!p || !anchor) { hideUsagePopover(); return; }
  }
  huPopKey = key;
  huPopGroup = group;
  huPopAnchor = anchor;
  const shown = group ? { ...p, groups: (p.groups || []).filter(g => g.name === group) } : p;
  const markup = `<div class="u-grid">${usageProvider(key, shown)}</div>`;
  if (pop.innerHTML !== markup) pop.innerHTML = markup;
  pop.hidden = false;
  const r = anchor.getBoundingClientRect();
  const width = pop.offsetWidth;
  pop.style.top = `${Math.round(r.bottom + 8)}px`;
  pop.style.left = `${Math.round(Math.max(8, Math.min(r.left, window.innerWidth - width - 8)))}px`;
}

function hideUsagePopover() {
  huPopKey = null;
  huPopGroup = '';
  huPopAnchor = null;
  document.getElementById('hu-pop').hidden = true;
}

document.getElementById('header-usage').addEventListener('mouseover', e => {
  const meter = e.target.closest('.hu-meter');
  if (meter && meter !== huPopAnchor) showUsagePopover(meter.dataset.provider, meter.dataset.group, meter);
});
document.getElementById('header-usage').addEventListener('mouseout', e => {
  const to = e.relatedTarget;
  if (!to || !to.closest || !to.closest('.hu-meter')) hideUsagePopover();
});

// Where a decision came from (decision.labels, set by the server). Records
// without labels (decided before they existed) show none.
const DECISION_LABEL_INFO = {
  'rule': ['rule', 'An existing rule matched'],
  'prior': ['prior accept', 'An earlier Accept (12h) of this exact call matched'],
  'ai-review': ['AI review', 'Decided with an AI review of the script'],
  'click': ['click', 'The operator clicked'],
  'lazy': ['lazy', 'No operator reaction: applied automatically after 30s'],
  'new-12h': ['+ 12h', 'This decision accepted this exact call for 12h (linked below)'],
  'new-rule': ['+ rule', 'This decision created a permanent rule (linked below)'],
};

const GENERATED_REASONS = ['All subcommands matched allow rules', 'All subcommands approved', 'Approved in UI', 'Denied in UI'];
function isGeneratedReason(reason) {
  reason = reason || '';
  return GENERATED_REASONS.includes(reason) || reason.startsWith('Matched rule (')
    || reason.startsWith('Auto-accepted for 12h after') || reason.startsWith('Auto-accepted after review');
}

function renderDecisionLabels(req) {
  const labels = (req.decision && req.decision.labels) || [];
  return labels.map(l => {
    const [text, tip] = DECISION_LABEL_INFO[l] || [l, ''];
    return ` <span class="pill dl dl-${esc(l)}" title="${esc(tip)}">${esc(text)}</span>`;
  }).join('');
}

// How long the agent waited for the decision (omitted for instant rule matches).
function fmtWaited(req) {
  const d = req.decision || {};
  const ms = Date.parse(d.decided_at) - Date.parse(req.created_at);
  if (isNaN(ms) || ms < 1000) return '';
  const s = Math.round(ms / 1000);
  const text = s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
  return `<span title="Time from request to decision">waited ${text}</span>`;
}

function fmtReset(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d)) return null;
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtIn(iso) {
  const ms = Date.parse(iso) - Date.now();
  if (isNaN(ms)) return null;
  if (ms <= 0) return 'now';
  const mins = Math.round(ms / 60000);
  const d = Math.floor(mins / 1440), h = Math.floor(mins % 1440 / 60), m = mins % 60;
  return 'in ' + (d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`);
}

function fmtWhen(iso) {
  const d = new Date(iso);
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toDateString() === new Date().toDateString()
    ? time : d.toLocaleDateString([], { weekday: 'short' }) + ' ' + time;
}

// Bar: usage in the provider's color (red where it runs ahead of the
// elapsed share of the window), elapsed time shaded, a tick at the pace mark.
function usageBar(used, expected) {
  const clamp = v => Math.max(0, Math.min(100, v));
  used = clamp(used);
  const mark = expected == null ? null : clamp(expected);
  const onTime = mark == null ? used : Math.min(used, mark);
  let html = '';
  if (mark != null) html += `<span class="u-elapsed" style="width:${mark}%"></span>`;
  html += `<span class="u-fill" style="width:${onTime}%"></span>`;
  if (used > onTime) html += `<span class="u-over" style="left:${onTime}%;width:${used - onTime}%"></span>`;
  if (mark != null) html += `<span class="u-mark" style="left:${mark}%"></span>`;
  return `<div class="u-track">${html}</div>`;
}

// One grid row of a usage window; `first` marks the first row of a model group.
function usageCells(item, first) {
  const cell = (cls, html, attrs = '') => `<div class="u-cell ${cls}${first ? ' u-first' : ''}"${attrs}>${html}</div>`;
  const used = item.used_percent;
  const label = cell('u-c-window', esc(item.label));
  if (used == null) return label + cell('u-c-rest u-dim', 'unavailable');
  const exp = item.expected_percent;
  const ahead = exp != null && used > exp;
  let reset;
  if (item.reset) reset = `${esc(fmtIn(item.reset))}<span class="u-when">${esc(fmtWhen(item.reset))}</span>`;
  else if (item.reset_text) reset = esc(item.reset_text);
  else reset = `<span class="u-dim">${used === 0 ? 'not started' : 'unknown'}</span>`;
  return label +
    cell('u-c-bar', usageBar(used, exp)) +
    cell('u-c-used u-used' + (ahead ? ' u-red' : ''), used + '%') +
    cell('u-c-pace u-dim', exp == null ? '–' : exp + '%') +
    cell('u-c-resets', reset, item.reset ? ` title="${esc(fmtReset(item.reset))}"` : '');
}

function usageProvider(key, p) {
  const groups = p.groups || [];
  // Used-up windows: flag them next to the provider name.
  const exhausted = [];
  for (const g of groups) for (const w of g.windows) {
    if (w.used_percent == null || w.used_percent < 99) continue;
    let t = 'exhausted, resets ' + (w.reset ? fmtWhen(w.reset) : w.reset_text || '?');
    if (groups.length > 1 && g.name !== 'All models') t = g.name + ': ' + t;
    if (!exhausted.includes(t)) exhausted.push(t);
  }
  const alerts = exhausted.map(t => `<span class="u-alert">${esc(t)}</span>`).join(' ');
  let body;
  if (p.error) {
    body = `<div class="u-cell u-c-full u-red" title="${esc(p.error)}"><span class="u-clip">Unavailable: ${esc(p.error)}</span></div>`;
  } else {
    // Every provider gets the same columns so all cards line up. A lone
    // group named after the provider itself (Codex) covers all its models.
    const modelName = g => groups.length === 1 && [key, p.name.toLowerCase()].includes(g.name.toLowerCase())
      ? 'All models' : g.name;
    body = '<div class="u-cell u-th u-c-model">Models</div><div class="u-cell u-th u-c-window">Window</div>' +
      '<div class="u-cell u-th u-c-bar">Usage</div><div class="u-cell u-th u-c-used">Used</div>' +
      '<div class="u-cell u-th u-c-pace" title="Elapsed share of the window">Pace</div>' +
      '<div class="u-cell u-th u-c-resets">Resets</div>' +
      groups.map(g =>
        `<div class="u-cell u-group-row">${esc(modelName(g))}</div>` +
        g.windows.map((w, i) =>
          (i === 0 ? `<div class="u-cell u-c-model u-first" style="grid-row: span ${g.windows.length}">${esc(modelName(g))}</div>` : '') +
          usageCells(w, i === 0)).join('')).join('');
  }
  return `<section class="u-provider u-${esc(key)}">` +
    `<h2 class="panel-title"><span><span class="u-dot"></span>${esc(p.name)}</span><span>${alerts}</span></h2>` +
    `<div class="card u-card">${body}</div></section>`;
}

function renderUsage() {
  const u = usage || {};
  const status = [`refreshes every ${u.interval || 30}s`];
  if (u.loading) status.push('refreshing…');
  else if (u.updated_at) status.push('updated ' + new Date(u.updated_at).toLocaleTimeString());
  let body;
  if (u.data) body = '<div class="u-grid">' + Object.entries(u.data.providers).map(([k, p]) => usageProvider(k, p)).join('') + '</div>';
  else if (u.error && !u.loading) body = `<div class="empty u-red">Unavailable: ${esc(u.error)}</div>`;
  else body = '';
  return `<h2 class="panel-title u-heading"><span>AI usage</span><span class="u-status">${esc(status.join(' · '))}</span></h2>${body}`;
}

const FAVICON_SHIELD = "M16 2 4 6v9c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V6z";
let faviconPending = null;
function setFavicon(pending) {
  if (pending === faviconPending) return;
  faviconPending = pending;
  const glyph = pending
    ? "<path d='M16 9v8' stroke='%230d1117' stroke-width='3.4' stroke-linecap='round'/><circle cx='16' cy='22.5' r='2' fill='%230d1117'/>"
    : "<path d='m10 16 4 4 8-8' fill='none' stroke='%23fff' stroke-width='3.2' stroke-linecap='round' stroke-linejoin='round'/>";
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><path d='" + FAVICON_SHIELD +
    "' fill='" + (pending ? "%23d29922" : "%23238636") + "'/>" + glyph + "</svg>";
  document.getElementById('favicon').href = 'data:image/svg+xml,' + svg;
}

function openRuleHistory(ruleId) {
  historyRuleFilter = ruleId;
  setTab('history');
}

function clearHistoryFilter() {
  historyRuleFilter = null;
  render();
}

function jumpToRule(ruleId) {
  historyRuleFilter = null;
  highlightedRuleId = ruleId;
  setTab('live');
  const el = document.getElementById('rule-' + ruleId);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  if (highlightTimer) clearTimeout(highlightTimer);
  highlightTimer = setTimeout(() => {
    highlightedRuleId = null;
    const cur = document.getElementById('rule-' + ruleId);
    if (cur) cur.classList.remove('rule-highlight');
  }, 2400);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function fetchState() {
  const res = await fetch('/api/ui/state');
  state = await res.json();
  render();
}

async function decide(id, decision, allowAlways = null, prefix = '', subIndex = null, reasonOverride = null) {
  const reasonEl = document.getElementById(reasonInputId(id, subIndex));
  const reason = reasonOverride ?? (reasonEl ? reasonEl.value : '');
  await fetch('/api/ui/requests/' + encodeURIComponent(id) + '/decision', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ decision, reason, allow_always: allowAlways, prefix, sub_index: subIndex })
  });
  await fetchState();
}

async function deleteRule(id) {
  if (editingRuleId === id) editingRuleId = null;
  await fetch('/api/ui/rules/' + encodeURIComponent(id), { method: 'DELETE' });
  await fetchState();
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && editingRuleId) {
    cancelEditRule();
  }
});

function startEditRule(id) {
  editingRuleId = id;
  render();
  const inp = document.getElementById('edit-val-' + id);
  if (inp && !inp.disabled) {
    inp.focus();
    inp.setSelectionRange(inp.value.length, inp.value.length);
  }
}

function cancelEditRule() {
  editingRuleId = null;
  fetchState();
}

async function saveEditRule(id, kind) {
  const action = document.getElementById('edit-action-' + id).value;
  const val = document.getElementById('edit-val-' + id).value.trim();
  const body = { action };
  const reasonEl = document.getElementById('edit-reason-' + id);
  if (reasonEl && action === 'deny') body.reason = reasonEl.value.trim();
  const modeEl = document.getElementById('edit-mode-' + id);
  if (modeEl) body.mode = modeEl.value;
  if (kind === 'command_prefix' || kind === 'path_prefix' || kind === 'domain') {
    body.prefix = val;
  } else if (kind === 'exact') {
    const rule = state.rules.find(r => r.id === id);
    const key = (rule && rule.arguments && 'CommandLine' in rule.arguments) ? 'CommandLine' : 'command';
    body.arguments = { [key]: val };
  }
  await fetch('/api/ui/rules/' + encodeURIComponent(id), {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  editingRuleId = null;
  await fetchState();
}

// Expanded full-command boxes stay open across periodic re-renders.
const openScripts = new Set();

function isPython(target) {
  return !!target && target.python_script != null;
}

// Tool label for the card head: inline `python3 -c` scripts show as Python.
// Shell tools (Bash for Claude Code/Codex, run_command for Antigravity) all
// run a command line, so they share one label; the real name is the tooltip.
const SHELL_TOOL_NAMES = ['Bash', 'run_command'];
function toolLabel(req, target = req) {
  if (isPython(target)) return `<span class="pill python">Python</span>`;
  if (SHELL_TOOL_NAMES.includes(req.tool)) return `<strong title="${esc(req.tool)}">run</strong>`;
  return `<strong>${esc(req.tool)}</strong>`;
}

// Keep the full source in the DOM; CSS limits the visible preview.
function renderPythonScript(script) {
  return `<pre class="py-script">${esc(script)}</pre>`;
}

// Body of a card: the script for Python, otherwise the formatted call.
// `meta` (queue cards: working directory; history: wait and time) goes
// right-aligned on the copy-button line.
function renderCallBody(req, target, key, meta = '') {
  const command = target === req ? formatArgs(req) : target.command;
  // Long commands are clipped like Python scripts; the copy buttons hold the full text.
  const body = isPython(target) ? renderPythonScript(target.python_script) : `<pre class="call-cmd">${esc(command)}</pre>`;
  const buttons = [copyBtn(key + '-cmd', 'Copy command', command)];
  if (isPython(target)) buttons.push(copyBtn(key + '-py', 'Copy script', target.python_script));
  if (target !== req) buttons.push(copyBtn(key + '-full', 'Copy full command', formatArgs(req)));
  return body + `<div class="copy-bar">${buttons.join('')}${meta ? `<div class="meta copy-meta">${meta}</div>` : ''}</div>`;
}

// Texts behind the copy buttons, by key, so they stay out of the HTML attributes.
const copyTexts = new Map();

function copyBtn(key, label, text) {
  copyTexts.set(key, String(text));
  return `<button class="ghost copy-btn" onclick="copyText('${esc(key)}', this)">${esc(label)}</button>`;
}

async function copyText(key, btn) {
  const text = copyTexts.get(key) || '';
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const label = btn.textContent;
  btn.textContent = 'Copied ✓';
  btn.disabled = true;
  setTimeout(() => { btn.textContent = label; btn.disabled = false; }, 1200);
}

function formatArgs(req) {
  if (req.arguments && typeof req.arguments.command === 'string') {
    return req.arguments.command;
  }
  if (req.arguments && typeof req.arguments.CommandLine === 'string') {
    return req.arguments.CommandLine;
  }
  if (req.arguments && req.tool === 'search_web') {
    const d = req.arguments.domain ? `[${req.arguments.domain}] ` : '';
    return `${d}${req.arguments.query || ''}`;
  }
  if (req.arguments) {
    const p = req.arguments.Path || req.arguments.file_path || req.arguments.path;
    if (typeof p === 'string') {
      const s = req.arguments.StartLine;
      const e = req.arguments.EndLine;
      return (s || e) ? `${p} (L${s || 1}-${e || ''})` : p;
    }
  }
  return JSON.stringify(req.arguments || {}, null, 2);
}

// Token bars start in Approve mode; the label toggles a card's bar to Deny
// mode, where a click creates a deny rule with the reason typed below it.
const denyModes = new Set();  // token bar keys in Deny mode

function tokenBarKey(reqId, subIndex = null) {
  return subIndex === null ? reqId : `${reqId}-sub-${subIndex}`;
}

function ruleReasonInputId(reqId, subIndex = null) {
  return 'rule-reason-' + tokenBarKey(reqId, subIndex);
}

function tokenPreviewIdle(deny) {
  return deny
    ? 'Type the reason, then click a token to deny always up to that prefix'
    : 'Hover & click a token to allow always up to that prefix';
}

function highlightTokens(reqId, idx) {
  const bar = document.getElementById('tokens-' + reqId);
  const preview = document.getElementById('preview-' + reqId);
  if (!bar) return;
  const deny = denyModes.has(reqId);
  const btns = bar.querySelectorAll('.token-btn');
  btns.forEach((b, i) => b.classList.toggle('lit', idx >= 0 && i <= idx));
  if (preview) {
    if (idx >= 0 && btns[idx]) {
      preview.textContent = (deny ? 'Click to deny always: ' : 'Click to allow always: ') + btns[idx].dataset.prefix;
    } else {
      preview.textContent = tokenPreviewIdle(deny);
    }
  }
}

function toggleTokenMode(reqId, subIndex = null) {
  const key = tokenBarKey(reqId, subIndex);
  if (denyModes.has(key)) {
    denyModes.delete(key);
  } else {
    denyModes.add(key);
    // Choosing Deny is a decision in progress: stop the auto-accept.
    if (autoCurrent && autoCurrent.reqId === reqId && autoCurrent.subIndex === subIndex) {
      cancelAutoDecide(autoCurrent.key);
    }
  }
  queueMarkup = null;
  render();
  const input = document.getElementById(ruleReasonInputId(reqId, subIndex));
  if (input) input.focus();
}

function tokenClick(btn, reqId, subIndex = null) {
  if (!denyModes.has(tokenBarKey(reqId, subIndex))) {
    decide(reqId, 'approved', 'prefix', btn.dataset.prefix, subIndex);
    return;
  }
  const input = document.getElementById(ruleReasonInputId(reqId, subIndex));
  const reason = input ? input.value.trim() : '';
  if (!reason) {
    if (input) { input.classList.add('invalid'); input.focus(); }
    return;
  }
  decide(reqId, 'denied', 'prefix', btn.dataset.prefix, subIndex, reason);
}

function renderTokenBar(reqId, tokens, prefixes, subIndex = null, approveLabel = 'Approve:') {
  if (!tokens.length || tokens.length !== prefixes.length) return '';
  const domKey = tokenBarKey(reqId, subIndex);
  const deny = denyModes.has(domKey);
  const subArg = subIndex === null ? 'null' : subIndex;
  const buttons = tokens.map((tok, i) =>
    `<button class="token-btn" data-prefix="${esc(prefixes[i])}"
      onmouseenter="highlightTokens('${esc(domKey)}', ${i})"
      onclick="tokenClick(this, '${esc(reqId)}', ${subArg})"
    >${esc(tok)}</button>`
  ).join('');
  const reasonRow = deny
    ? `<div class="rule-reason-row"><input class="reason" id="${esc(ruleReasonInputId(reqId, subIndex))}" placeholder="Deny reason, told to the agent (required)..." oninput="this.classList.remove('invalid')" /></div>`
    : '';
  return `
    <div class="prefix-builder${deny ? ' deny-mode' : ''}" onmouseleave="highlightTokens('${esc(domKey)}', -1)">
      <div class="prefix-label">
        <span id="preview-${esc(domKey)}" class="prefix-preview">${esc(tokenPreviewIdle(deny))}</span>
      </div>
      <div class="token-bar" id="tokens-${esc(domKey)}"><button class="mode-toggle" onclick="toggleTokenMode('${esc(reqId)}', ${subArg})" title="Switch between creating allow and deny rules">${esc(deny ? 'Deny:' : approveLabel)}</button>${buttons}</div>
      ${reasonRow}
    </div>`;
}

function renderReviewBtn(reqId, target, subIndex = null) {
  if (!target || !target.python_script) return '';
  const st = target.review && target.review.status;
  const label = st === 'running' ? 'Reviewing...' : (st === 'done' ? 'Re-review' : 'Review');
  const disabled = st === 'running' ? 'disabled' : '';
  const subArg = subIndex === null ? 'null' : subIndex;
  return `<button class="review-btn" ${disabled} onclick="startReview('${esc(reqId)}', ${subArg})">${label}</button>`;
}

function renderReviewBox(review, autoHtml = '') {
  if (!review) return '';
  const by = review.agent ? ` by ${review.agent}` : '';
  if (review.status === 'running') {
    return `<div class="review-box" title="${esc(review.agent_reason || '')}">⏳ Reviewing${esc(by)}...</div>`;
  }
  if (!review.decision) return `<div class="review-box">🔎 ${esc(review.summary || review.status)}</div>`;
  return renderVerdict(review.decision, review.deny_reason ?? (review.explanation ? '' : review.summary), 'review' + by,
    review.agent_reason ? `<div class="meta">${esc(review.agent_reason)}</div>` : '', review.explanation, autoHtml);
}

// Auto-decision: only the request currently shown in the queue is decided
// automatically, and only while the operator is away. Any mouse or keyboard
// activity over the page stops the countdown; once there has been none for
// AUTO_IDLE_MS, a countdown of AUTO_DECIDE_MS starts. When it fires and the
// next request takes its place, that one gets its own countdown, so a long
// queue is decided one request at a time. Python scripts are auto-decided
// only after a review (its verdict is applied); other requests are accepted
// for 12h (exact call). Typing a reason cancels the shown request's
// auto-decision for good.
const AUTO_IDLE_MS = 10000;
const AUTO_DECIDE_MS = 30000;
const autoCancelled = new Set();
const autoFired = new Set();
let autoCurrent = null;  // {key, reqId, subIndex, decision, allowAlways, verb, review, deadline|null}
let lastActivity = Date.now();

function noteActivity() {
  lastActivity = Date.now();
  if (autoCurrent && autoCurrent.deadline !== null) {
    autoCurrent.deadline = null;
    updateAutoCounts();
  }
}
for (const ev of ['mousemove', 'mousedown', 'wheel', 'keydown', 'touchstart']) {
  document.addEventListener(ev, noteActivity, { capture: true, passive: true });
}

// Keyboard shortcut: Shift+A (outside text fields) presses Accept on the
// shown request, i.e. 12h for plain requests, once for Python scripts.
document.addEventListener('keydown', e => {
  if (e.code !== 'KeyA' || !e.shiftKey || e.ctrlKey || e.metaKey || e.altKey || e.repeat) return;
  if (e.target.closest && e.target.closest('input, textarea, select, [contenteditable]')) return;
  const accept = document.querySelector('#queue-content button.approve');
  if (!accept) return;
  e.preventDefault();
  accept.click();
});

function autoAction(req, target, subIndex) {
  if (req.status !== 'pending') return null;
  const base = req.id + '#' + (subIndex === null ? '' : subIndex);
  if (target.python_script != null) {
    const r = target.review;
    if (!(r && r.status === 'done' && r.decision)) return null;
    const approved = r.decision === 'approved';
    return { key: base + '@' + r.finished_at, reqId: req.id, subIndex, review: r,
             decision: approved ? 'approved' : 'denied', allowAlways: null,
             verb: approved ? 'Auto-accept' : 'Auto-deny' };
  }
  return { key: base, reqId: req.id, subIndex, review: null,
           decision: 'approved', allowAlways: 'exact', verb: 'Auto-accept' };
}

function renderAutoDecide(action) {
  if (!action) return '';
  if (autoCancelled.has(action.key)) return '<span class="auto-decide u-dim">Auto-decision cancelled</span>';
  return `<span class="auto-decide ${action.decision === 'approved' ? 'status-approved' : 'status-denied'}">` +
    `<span class="auto-count"></span></span>`;
}

// Called by render() with the card now shown; keeps the running countdown
// while the same card stays shown. A newly shown card starts without one;
// autoDecideTick() starts it once the operator has been idle long enough.
function syncAutoCurrent(card) {
  const a = card && card.auto;
  if (!a || autoCancelled.has(a.key) || autoFired.has(a.key)) {
    autoCurrent = null;
    return;
  }
  const deadline = autoCurrent && autoCurrent.key === a.key ? autoCurrent.deadline : null;
  autoCurrent = { ...a, deadline };
}

function cancelAutoDecide(key) {
  autoCancelled.add(key);
  if (autoCurrent && autoCurrent.key === key) autoCurrent = null;
  queueMarkup = null;  // force the queue to re-render without the countdown
  render();
}

// Typing in the shown card's reason box cancels its auto-decision.
function cancelAutoDecideForInput(inputId) {
  if (autoCurrent && reasonInputId(autoCurrent.reqId, autoCurrent.subIndex) === inputId) {
    cancelAutoDecide(autoCurrent.key);
  }
}

// Tab title: pending count with the running auto-action countdown, then the
// app name, e.g. "3 requests (12s) · aap-ui"; just "aap-ui" when idle.
let titlePending = 0;
function updateTitle(now = Date.now()) {
  let title = 'aap-ui';
  if (titlePending) {
    let lead = `${titlePending} ${titlePending === 1 ? 'request' : 'requests'}`;
    if (autoCurrent && autoCurrent.deadline !== null) {
      lead += ` (${Math.max(0, Math.ceil((autoCurrent.deadline - now) / 1000))}s)`;
    }
    title = `${lead} · ${title}`;
  }
  if (document.title !== title) document.title = title;
}

function updateAutoCounts(now = Date.now()) {
  updateTitle(now);
  for (const el of document.querySelectorAll('.auto-count')) {
    if (!autoCurrent || autoCurrent.deadline === null) { el.textContent = ''; continue; }
    const left = Math.max(0, Math.ceil((autoCurrent.deadline - now) / 1000));
    el.textContent = `${autoCurrent.verb} in ${left}s`;
  }
}

async function autoDecideTick() {
  const now = Date.now();
  const a = autoCurrent;
  if (a && a.deadline === null && now - lastActivity >= AUTO_IDLE_MS) a.deadline = now + AUTO_DECIDE_MS;
  updateAutoCounts(now);
  if (!a || a.deadline === null || now < a.deadline || autoFired.has(a.key)) return;
  autoFired.add(a.key);
  autoCurrent = null;
  const inputId = reasonInputId(a.reqId, a.subIndex);
  const input = document.getElementById(inputId);
  const typed = input ? input.value : (reasonDrafts.get(inputId) || '');
  const by = a.review && a.review.agent ? ` by ${a.review.agent}` : '';
  let reason;
  if (!a.review) reason = `Auto-accepted for 12h after ${AUTO_DECIDE_MS / 1000}s`;
  else if (a.decision === 'approved') reason = `Auto-accepted after review${by}`;
  else reason = typed || a.review.deny_reason || a.review.summary || `Auto-denied after review${by}`;
  try {
    await fetch('/api/ui/requests/' + encodeURIComponent(a.reqId) + '/decision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: a.decision, reason, allow_always: a.allowAlways, prefix: '', sub_index: a.subIndex, lazy: true }),
    });
  } catch (e) {}
  await fetchState();
}
setInterval(autoDecideTick, 500);

// Long Python scripts are accepted once; ordinary commands keep 12h acceptance.
function renderApproveActions(reqId, target, subIndex = null) {
  const id = esc(reqId);
  const subArg = subIndex === null ? 'null' : subIndex;
  const python = target.python_script != null;
  const allowAlways = python ? 'null' : "'exact'";
  const title = python ? 'Accept this script once' : 'Accept exact call for 12h';
  return `<button class="approve" onclick="decide('${id}','approved',${allowAlways},'',${subArg})" title="${title}">Accept${python ? '' : ' (12h)'}</button>`;
}

// When the reviewer suggests denial, pre-fill only the actionable deny reason.
function suggestedReason(target) {
  const r = target && target.review;
  return r && r.status === 'done' && r.decision === 'denied' ? (r.deny_reason ?? r.summary ?? '') : '';
}

async function startReview(id, subIndex = null) {
  await fetch('/api/ui/requests/' + encodeURIComponent(id) + '/review', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(subIndex === null ? {} : { sub_index: subIndex }),
  });
}

// One entry per decision the user has to make: {key, inputId, html}.
function renderQueue() {
  const cards = [];
  for (const req of state.pending) {
    const rt = (req.context && req.context.runtime) || 'agent';
    const cwd = (req.context && req.context.cwd) || '';
    const stalePill = req.status && req.status !== 'pending'
      ? ` <span class="pill status-${esc(req.status)}">${esc(req.status)}</span>`
      : '';
    const subs = (req.subcommands || []).filter(sc => sc.status === 'pending');
    if (subs.length) {
      for (const sc of subs) {
        const tokenBar = sc.python_script != null ? '' : renderTokenBar(req.id, sc.command_tokens || [], sc.command_prefixes || [], sc.index);
        const approveAction = renderApproveActions(req.id, sc, sc.index);
        const auto = autoAction(req, sc, sc.index);
        cards.push({ key: req.id + '#' + sc.index, inputId: reasonInputId(req.id, sc.index), ruleReasonId: ruleReasonInputId(req.id, sc.index), barKey: tokenBarKey(req.id, sc.index), auto, html: `
          <div class="card">
            <div class="card-head">
              <div><span class="pill ${esc(rt)}">${esc(rt)}</span> ${toolLabel(req, sc)} <span class="pill">step ${sc.index + 1}/${req.subcommands.length}</span>${stalePill}</div>
              <div class="meta">${renderAutoDecide(auto)}<span>${esc(req.created_at)}</span></div>
            </div>
            ${renderCallBody(req, sc, 'q-' + req.id + '-' + sc.index, `<span>${esc(cwd)}</span>`)}
            <details class="full-cmd-box" ${openScripts.has('full-' + req.id) ? 'open' : ''} ontoggle="if (this.open) openScripts.add('full-${esc(req.id)}'); else openScripts.delete('full-${esc(req.id)}')"><summary>Full command</summary><pre>${esc(formatArgs(req))}</pre></details>
            ${renderReviewBox(sc.review)}
            ${tokenBar}
            <div class="actions">
              ${approveAction}
              ${renderReviewBtn(req.id, sc, sc.index)}
              <input class="reason" id="${esc(reasonInputId(req.id, sc.index))}" data-suggested="${esc(suggestedReason(sc))}" placeholder="Optional deny/approve note..." />
              <button class="deny" onclick="decide('${esc(req.id)}','denied',null,'',${sc.index})">Deny</button>
            </div>
          </div>` });
      }
      continue;
    }
    const tokenBarLabel = req.path_mode ? `Approve (${req.path_mode}):` : 'Approve:';
    const tokenBar = req.python_script != null ? '' : renderTokenBar(req.id, req.command_tokens || [], req.command_prefixes || [], null, tokenBarLabel);
    const approveAction = renderApproveActions(req.id, req);
    const dom = (req.tool === 'search_web' && req.arguments && req.arguments.domain) ? String(req.arguments.domain) : '';
    const domainBtn = dom
      ? `<button class="always" onclick="decide('${esc(req.id)}','approved','domain','${esc(dom)}')">Allow domain: ${esc(dom)}</button>`
      : '';
    const allowToolBtn = (tokenBar || domainBtn || req.python_script != null)
      ? ''
      : `<button class="always" onclick="decide('${esc(req.id)}','approved','tool')" title="Allow always: ${esc(req.tool)}">Allow</button>`;
    const auto = autoAction(req, req, null);
    cards.push({ key: req.id, inputId: reasonInputId(req.id), ruleReasonId: ruleReasonInputId(req.id), barKey: tokenBarKey(req.id), auto, html: `
      <div class="card">
        <div class="card-head">
          <div><span class="pill ${esc(rt)}">${esc(rt)}</span> ${toolLabel(req)}${stalePill}</div>
          <div class="meta">${renderAutoDecide(auto)}<span>${esc(req.created_at)}</span></div>
        </div>
        ${renderCallBody(req, req, 'q-' + req.id, `<span>${esc(cwd)}</span>`)}
        ${renderReviewBox(req.review)}
        ${tokenBar}
        <div class="actions">
          ${approveAction}
          ${domainBtn}
          ${renderReviewBtn(req.id, req)}
          ${allowToolBtn}
          <input class="reason" id="reason-${esc(req.id)}" data-suggested="${esc(suggestedReason(req))}" placeholder="Optional deny/approve note..." />
          <button class="deny" onclick="decide('${esc(req.id)}','denied')">Deny</button>
        </div>
      </div>` });
  }
  return cards;
}

// The queue shows one card at a time. queueKey follows the shown card while
// the list changes; when it disappears (decided), the card that took its
// place is shown, clamped to the end of the list.
let queueKey = null;
let queueIndex = 0;

function currentQueueIndex(cards) {
  const found = cards.findIndex(c => c.key === queueKey);
  queueIndex = found >= 0 ? found : Math.min(queueIndex, Math.max(cards.length - 1, 0));
  queueKey = cards.length ? cards[queueIndex].key : null;
  return queueIndex;
}

function queueStep(delta) {
  const cards = renderQueue();
  if (!cards.length) return;
  const idx = Math.min(Math.max(currentQueueIndex(cards) + delta, 0), cards.length - 1);
  queueIndex = idx;
  queueKey = cards[idx].key;
  render();
}

function formatCommandRule(r) {
  if (r.kind === 'tool') return '*';
  if (r.kind === 'command_prefix' || r.kind === 'path_prefix' || r.kind === 'domain') return (r.prefix || '').trim();
  const args = r.arguments || {};
  return args.command || args.CommandLine || JSON.stringify(args);
}

const ICON_PENCIL = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 5 4 4M4 20l4-1L20 7a2.8 2.8 0 0 0-4-4L4 15z"/></svg>';
const ICON_TRASH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14M10 11v6m4-6v6"/></svg>';

function actionBadge(action) {
  if (action === 'deny') {
    return `<span class="action-icon" title="deny" style="display:inline-flex;align-items:center;justify-content:center;font-size:13px">⛔</span>`;
  }
  return `<span class="action-icon" title="allow" style="display:inline-flex;align-items:center;justify-content:center"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#3fb950" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.5 3.5L13 4.5"/></svg></span>`;
}

function hitsLink(r) {
  return `<a href="#history" class="pill hits-pill hits-link" onclick="openRuleHistory('${esc(r.id)}');return false;" title="Show history for this rule">${Number(r.hits || 0)}</a>`;
}

function pathModeOf(r) {
  if (r.mode === 'ro' || r.mode === 'rw') return r.mode;
  const rwTools = new Set(['edit_file', 'write_file', 'write_to_file', 'replace_file_content', 'multi_replace_file_content', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'apply_patch']);
  return rwTools.has(r.tool) ? 'rw' : 'ro';
}

function renderRuleCard(r, editable = false) {
  if (editable && editingRuleId === r.id) {
    const curVal = (r.kind === 'command_prefix' || r.kind === 'path_prefix' || r.kind === 'domain')
      ? (r.prefix || '')
      : r.kind === 'exact'
        ? ((r.arguments && (r.arguments.command || r.arguments.CommandLine)) || '')
        : '*';
    const disabled = r.kind === 'tool' ? 'disabled' : '';
    const curMode = pathModeOf(r);
    const modeSel = r.kind === 'path_prefix'
      ? `<select class="action-sel" id="edit-mode-${esc(r.id)}"><option value="ro" ${curMode === 'ro' ? 'selected' : ''}>ro</option><option value="rw" ${curMode === 'rw' ? 'selected' : ''}>rw</option></select>`
      : '';
    return `
      <div class="card">
        <div class="actions" style="margin-top:0">
          <select class="action-sel" id="edit-action-${esc(r.id)}" onchange="document.getElementById('edit-reason-${esc(r.id)}').hidden = this.value !== 'deny'">
            <option value="allow" ${r.action === 'allow' ? 'selected' : ''}>allow</option>
            <option value="deny" ${r.action === 'deny' ? 'selected' : ''}>deny</option>
          </select>
          ${modeSel}
          <input class="reason" id="edit-val-${esc(r.id)}" value="${esc(curVal)}" ${disabled} onkeydown="if(event.key==='Enter')saveEditRule('${esc(r.id)}','${esc(r.kind)}')" />
          <button class="approve" onclick="saveEditRule('${esc(r.id)}','${esc(r.kind)}')">Save</button>
          <button class="ghost" onclick="cancelEditRule()">Cancel</button>
        </div>
        <div class="rule-reason-row">
          <input class="reason" id="edit-reason-${esc(r.id)}" value="${esc(r.reason || '')}" placeholder="Deny reason, told to the agent..." ${r.action === 'deny' ? '' : 'hidden'} onkeydown="if(event.key==='Enter')saveEditRule('${esc(r.id)}','${esc(r.kind)}')" />
        </div>
      </div>`;
  }
  const desc = editable
    ? formatCommandRule(r)
    : (r.kind === 'tool' ? r.tool : `${r.tool} ${JSON.stringify(r.arguments || {})}`);
  const editBtn = editable
    ? `<button class="ghost icon-btn" onclick="startEditRule('${esc(r.id)}')" title="Edit" aria-label="Edit">${ICON_PENCIL}</button>`
    : '';
  const modeBadge = r.kind === 'path_prefix'
    ? `<span class="pill mode-${esc(pathModeOf(r))}">${esc(pathModeOf(r))}</span> `
    : '';
  const hitsBadge = hitsLink(r);
  const hl = highlightedRuleId === r.id ? ' rule-highlight' : '';
  return `
    <div class="card rule-card${hl}" id="rule-${esc(r.id)}">
      <div class="card-head">
        <div class="btn-group">${hitsBadge}${editBtn}<button class="del-btn icon-btn" onclick="deleteRule('${esc(r.id)}')" title="Delete" aria-label="Delete">${ICON_TRASH}</button></div>
        <div>${actionBadge(r.action)} ${modeBadge}<code class="rule-code">${esc(desc)}</code></div>
      </div>
      ${r.action === 'deny' && r.reason ? `<div class="rule-reason-text">${esc(r.reason)}</div>` : ''}
    </div>`;
}

function formatTtlLeft(iso) {
  if (!iso) return '';
  const ms = Date.parse(iso) - Date.now();
  if (ms <= 0) return 'expired';
  const mins = Math.ceil(ms / 60000);
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return h ? `${h}h ${m}m` : `${m}m`;
}

function renderRules() {
  if (!state.rules.length) {
    return '<div class="empty">No saved rules yet. Click "Allow always" on any request to create one.</div>';
  }
  const ttlRules = state.rules
    .filter(r => r.expires_at || r.kind === 'exact')
    .sort((a, b) => (a.expires_at || '').localeCompare(b.expires_at || ''));
  const permRules = state.rules.filter(r => !(r.expires_at || r.kind === 'exact'));

  const isPathRule = r => r.kind === 'path_prefix';
  const isDomainRule = r => r.kind === 'domain';
  const isCommandRule = r => r.tool === 'run_command' || r.tool === 'Bash' || r.kind === 'command_prefix';
  const pathRules = permRules
    .filter(isPathRule)
    .sort((a, b) => formatCommandRule(a).localeCompare(formatCommandRule(b)));
  const domainRules = permRules
    .filter(isDomainRule)
    .sort((a, b) => formatCommandRule(a).localeCompare(formatCommandRule(b)));
  const cmdRules = permRules
    .filter(r => !isPathRule(r) && !isDomainRule(r) && isCommandRule(r))
    .sort((a, b) => formatCommandRule(a).localeCompare(formatCommandRule(b)));
  const toolPills = permRules
    .filter(r => !isPathRule(r) && !isDomainRule(r) && !isCommandRule(r))
    .sort((a, b) => (a.tool || '').localeCompare(b.tool || ''));

  let html = '';
  if (toolPills.length) {
    html += `<section><h2 class="panel-title"><span>Tools</span></h2><div class="chip-row">` + toolPills.map(r => `
      <span class="rule-chip${highlightedRuleId === r.id ? ' rule-highlight' : ''}" id="rule-${esc(r.id)}">
        ${actionBadge(r.action)}
        <code class="rule-code">${esc(r.tool)}</code>
        ${hitsLink(r)}
        <button class="del-btn icon-btn" onclick="deleteRule('${esc(r.id)}')" title="Delete" aria-label="Delete">${ICON_TRASH}</button>
      </span>`).join('') + `</div></section>`;
  }
  if (pathRules.length) {
    html += `<section><h2 class="panel-title"><span>Paths</span></h2>` + pathRules.map(r => renderRuleCard(r, true)).join('') + `</section>`;
  }
  if (domainRules.length) {
    html += `<section><h2 class="panel-title"><span>Domains</span></h2>` + domainRules.map(r => renderRuleCard(r, true)).join('') + `</section>`;
  }
  if (cmdRules.length) {
    html += `<section><h2 class="panel-title"><span>Commands</span></h2>` + cmdRules.map(r => renderRuleCard(r, true)).join('') + `</section>`;
  }
  if (ttlRules.length) {
    html += `<section><h2 class="panel-title"><span>Approved (12h TTL)</span></h2>` + ttlRules.map(r => {
      const args = r.arguments || {};
      const cmd = args.command || args.CommandLine;
      const desc = cmd || `${r.tool} ${JSON.stringify(args)}`;
      const ttl = formatTtlLeft(r.expires_at);
      return `
        <div class="card rule-card${highlightedRuleId === r.id ? ' rule-highlight' : ''}" id="rule-${esc(r.id)}">
          <div class="card-head">
            <div class="btn-group">${hitsLink(r)}<button class="del-btn icon-btn" onclick="deleteRule('${esc(r.id)}')" title="Delete" aria-label="Delete">${ICON_TRASH}</button></div>
            <div class="ttl-row"><span class="pill">${esc(ttl)}</span><code class="rule-code ttl-code" title="${esc(desc)}">${esc(desc)}</code></div>
          </div>
        </div>`;
    }).join('') + `</section>`;
  }
  return html;
}

function render() {
  const pendingCount = state.pending.reduce((acc, req) => {
    const subs = (req.subcommands || []).filter(sc => sc.status === 'pending');
    return acc + (subs.length ? subs.length : 1);
  }, 0);
  titlePending = pendingCount;
  updateTitle();
  setFavicon(pendingCount > 0);
  const queueContent = document.getElementById('queue-content');
  queueContent.hidden = pendingCount === 0;
  document.body.classList.toggle('has-queue', pendingCount > 0);
  document.getElementById('queue-label').textContent = pendingCount ? 'Approval Request' : 'Nothing to review';
  const cards = renderQueue();
  const idx = currentQueueIndex(cards);
  const nav = document.getElementById('queue-nav');
  nav.hidden = cards.length === 0;
  document.getElementById('queue-pos').textContent = cards.length ? (idx + 1) + '/' + cards.length : '';
  document.getElementById('queue-prev').disabled = idx <= 0;
  document.getElementById('queue-next').disabled = idx >= cards.length - 1;
  const markup = cards.length ? cards[idx].html : '';
  syncAutoCurrent(cards[idx]);
  // Drafts of cards that are only hidden (not decided) must survive.
  const liveInputIds = new Set(cards.flatMap(c => [c.inputId, c.ruleReasonId]));
  const liveBars = new Set(cards.map(c => c.barKey));
  for (const key of denyModes) {
    if (!liveBars.has(key)) denyModes.delete(key);
  }
  if (markup !== queueMarkup) {
    const focused = document.activeElement;
    const selection = queueContent.contains(focused) && focused.matches('input.reason')
      ? {id: focused.id, start: focused.selectionStart, end: focused.selectionEnd, direction: focused.selectionDirection}
      : null;
    for (const input of queueContent.querySelectorAll('input.reason')) {
      reasonDrafts.set(input.id, input.value);
    }
    const sameCard = queueContent.dataset.key === (queueKey || '');
    const scrollTop = sameCard ? queueContent.scrollTop : 0;
    queueContent.innerHTML = markup;
    updateAutoCounts();
    queueContent.dataset.key = queueKey || '';
    const remaining = liveInputIds;
    for (const input of queueContent.querySelectorAll('input.reason')) {
      let value = reasonDrafts.get(input.id) ?? '';
      // Pre-fill the reviewer's deny reason once per review result unless the
      // user already typed something; afterwards it is an ordinary draft.
      const suggested = input.dataset.suggested || '';
      if (suggested && seededReasons.get(input.id) !== suggested) {
        seededReasons.set(input.id, suggested);
        if (!value) value = suggested;
      }
      input.value = value;
    }
    for (const key of reasonDrafts.keys()) {
      if (!remaining.has(key)) reasonDrafts.delete(key);
    }
    for (const key of seededReasons.keys()) {
      if (!remaining.has(key)) seededReasons.delete(key);
    }
    if (selection) {
      const input = document.getElementById(selection.id);
      if (input) {
        input.focus({preventScroll: true});
        input.setSelectionRange(selection.start, selection.end, selection.direction);
      }
    }
    queueContent.scrollTop = scrollTop;
    queueMarkup = markup;
  }

  const app = document.getElementById('app');
  if (activeTab === 'live') {
    if (!editingRuleId || !document.getElementById('edit-val-' + editingRuleId)) {
      app.innerHTML = '<div class="layout">' + renderRules() + '</div>';
    }
  } else if (activeTab === 'usage') {
    app.innerHTML = renderUsage();
  } else {
    let filterBanner = '';
    let items = state.history;
    if (historyRuleFilter) {
      const ruleObj = state.rules.find(r => r.id === historyRuleFilter);
      const label = ruleObj ? formatCommandRule(ruleObj) : historyRuleFilter;
      filterBanner = `
        <div class="filter-bar">
          <span>Filtered by rule: <code class="rule-code">${esc(label)}</code></span>
          <button class="ghost" onclick="clearHistoryFilter()">Clear filter</button>
        </div>`;
      items = state.history.filter(req => {
        const d = req.decision || {};
        if (d.rule_id === historyRuleFilter) return true;
        if (Array.isArray(d.rule_ids) && d.rule_ids.includes(historyRuleFilter)) return true;
        if (Array.isArray(req.subcommands) && req.subcommands.some(sc => sc.rule_id === historyRuleFilter)) return true;
        return false;
      });
    }
    if (!items.length) {
      app.innerHTML = filterBanner + `<div class="empty">${historyRuleFilter ? 'No history entries for this rule.' : 'No decisions yet.'}</div>`;
      return;
    }
    app.innerHTML = filterBanner + items.map(req => {
      const rt = (req.context && req.context.runtime) || 'agent';
      const d = req.decision || {};
      // Generated reasons ("Matched rule (...)", "Approved in UI", ...) are
      // never shown: the labels say where a decision came from.
      const reason = isGeneratedReason(d.reason) ? '' : (d.reason || '');
      const ruleIds = [];
      if (d.rule_id) ruleIds.push(d.rule_id);
      if (Array.isArray(d.rule_ids)) {
        for (const id of d.rule_ids) if (id && !ruleIds.includes(id)) ruleIds.push(id);
      }
      if (Array.isArray(req.subcommands)) {
        for (const sc of req.subcommands) if (sc.rule_id && !ruleIds.includes(sc.rule_id)) ruleIds.push(sc.rule_id);
      }
      const ruleLinks = ruleIds.map(rid => {
        const ruleObj = state.rules.find(r => r.id === rid);
        if (!ruleObj) return '';
        const lbl = ruleObj.kind === 'tool' ? ruleObj.tool : (formatCommandRule(ruleObj) || ruleObj.tool || rid);
        return `<a href="#rule-${esc(rid)}" class="rule-jump-link" onclick="jumpToRule('${esc(rid)}');return false;" title="Jump to rule: ${esc(lbl)}">↳ ${esc(lbl)}</a>`;
      }).filter(Boolean).join(' ');
      return `
        <div class="card">
          <div class="card-head">
            <div><span class="pill ${esc(rt)}">${esc(rt)}</span> ${toolLabel(req)} <span class="status-${esc(req.status)}">${esc(req.status)}</span>${renderDecisionLabels(req)}</div>
            <div class="meta">${ruleLinks}<span>${esc(reason)}</span></div>
          </div>
          ${renderCallBody(req, req, 'h-' + req.id, `${fmtWaited(req)}<span>${esc(req.created_at)}</span>`)}
        </div>`;
    }).join('');
  }
}

setTab(tabFromPath(), false);
fetchState();
// Header dot: green while GET /api/status answers OK, red otherwise.
let statusChecking = false;
async function checkStatus() {
  if (statusChecking) return;
  statusChecking = true;
  let online = false;
  try {
    const res = await fetch('/api/status', { cache: 'no-store', signal: AbortSignal.timeout(2500) });
    online = res.ok && (await res.json()).status === 'OK';
  } catch (e) { /* offline */ }
  statusChecking = false;
  const dot = document.getElementById('status-dot');
  const label = online ? 'aap-ui is online' : 'aap-ui is offline';
  dot.classList.toggle('online', online);
  dot.title = label;
  dot.setAttribute('aria-label', label);
  dot.hidden = false;
}
checkStatus();
setInterval(checkStatus, 3000);

const ev = new EventSource('/api/ui/events');
ev.onmessage = () => fetchState();
ev.onerror = () => checkStatus();
ev.onopen = () => checkStatus();
setInterval(fetchState, 5000);
// The server refetches at most every 30 s; polling often only picks up
// a finished refresh sooner.
// The usage tab polls every 3s; elsewhere every 15s for the header strip.
let usageTick = 0;
setInterval(() => { if (activeTab === 'usage' || ++usageTick % 5 === 0) fetchUsage(); }, 3000);
fetchUsage();

// The queue panel's height follows its card; keep the page's bottom padding
// equal to it so nothing hides behind the fixed panel.
new ResizeObserver(([entry]) => {
  const h = entry.borderBoxSize && entry.borderBoxSize[0]
    ? entry.borderBoxSize[0].blockSize : entry.target.offsetHeight;
  document.body.style.setProperty('--queue-panel-height', Math.ceil(h) + 'px');
}).observe(document.getElementById('queue-panel'));
</script>
</body>
</html>
"""


def make_handler(
    hub: ApprovalHub, on_restart: Any | None = None, usage: UsageCache | None = None
) -> type[BaseHTTPRequestHandler]:
    usage_cache = usage or UsageCache()

    class AAPHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            # Live state: never let the browser serve a cached copy.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            return data

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            if path in ("/", "/rules", "/history", "/ai-usage"):
                body = UI_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/mobile/notification":
                self._send_json(HTTPStatus.OK, mobile_notifications(hub.ui_state()["pending"]))
                return

            if path == "/api/status":
                self._send_json(HTTPStatus.OK, {"status": "OK"})
                return

            if path == "/api/ui/state":
                self._send_json(HTTPStatus.OK, hub.ui_state())
                return

            if path == "/api/ui/usage":
                self._send_json(HTTPStatus.OK, usage_cache.snapshot())
                return

            if path == "/api/ui/events":
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                q = hub.subscribe()
                try:
                    self.wfile.write(b"data: connected\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            msg = q.get(timeout=15.0)
                            self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                            self.wfile.flush()
                        except queue.Empty:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    hub.unsubscribe(q)
                return

            if path.startswith("/api/aap/v1/requests/"):
                req_id = path[len("/api/aap/v1/requests/") :].strip("/")
                wait_sec = 0.0
                if "wait" in qs:
                    try:
                        wait_sec = float(qs["wait"][0])
                    except ValueError:
                        wait_sec = 0.0
                record = hub.get_request(req_id, wait_sec=wait_sec)
                if record is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "request_not_found"})
                else:
                    self._send_json(HTTPStatus.OK, record)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/api/aap/v1/requests":
                idem = self.headers.get("Idempotency-Key", "").strip()
                if not idem:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing_idempotency_key"})
                    return
                try:
                    payload = self._read_json()
                except (ValueError, json.JSONDecodeError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if not payload.get("tool"):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing_tool"})
                    return
                try:
                    record, status = hub.create_request(payload, idem)
                except ValueError as exc:
                    if str(exc) == "idempotency_conflict":
                        self._send_json(HTTPStatus.CONFLICT, {"error": "idempotency_conflict"})
                        return
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_json(status, record)
                return

            if path.startswith("/api/aap/v1/requests/") and path.endswith("/consume"):
                req_id = path[len("/api/aap/v1/requests/") : -len("/consume")].strip("/")
                record, status = hub.consume_request(req_id)
                if record is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "request_not_found"})
                else:
                    self._send_json(status, record)
                return

            if path.startswith("/api/ui/requests/") and path.endswith("/review"):
                req_id = path[len("/api/ui/requests/") : -len("/review")].strip("/")
                try:
                    payload = self._read_json()
                    record = hub.review_request(
                        req_id=req_id,
                        sub_index=payload.get("sub_index"),
                    )
                except (ValueError, json.JSONDecodeError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if record is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "request_not_found"})
                else:
                    self._send_json(HTTPStatus.OK, record)
                return

            if path.startswith("/api/ui/requests/") and path.endswith("/decision"):
                req_id = path[len("/api/ui/requests/") : -len("/decision")].strip("/")
                try:
                    payload = self._read_json()
                    record = hub.decide_request(
                        req_id=req_id,
                        decision_status=str(payload.get("decision") or ""),
                        reason=str(payload.get("reason") or ""),
                        allow_always=payload.get("allow_always"),
                        prefix=str(payload.get("prefix") or ""),
                        sub_index=payload.get("sub_index"),
                        lazy=bool(payload.get("lazy")),
                    )
                except (ValueError, json.JSONDecodeError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if record is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "request_not_found"})
                else:
                    self._send_json(HTTPStatus.OK, record)
                return

            if path == "/api/ui/rules":
                try:
                    payload = self._read_json()
                    rule = hub.rules.add_rule(Rule.from_dict(payload))
                    self._send_json(HTTPStatus.CREATED, rule.to_dict())
                except (ValueError, json.JSONDecodeError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            if path == "/api/restart":
                if on_restart is None:
                    self._send_json(HTTPStatus.NOT_IMPLEMENTED, {"error": "restart_unsupported"})
                    return
                self._send_json(HTTPStatus.ACCEPTED, {"status": "restarting"})
                threading.Timer(0.15, on_restart).start()
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_PUT(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/ui/rules/"):
                rule_id = path[len("/api/ui/rules/") :].strip("/")
                try:
                    payload = self._read_json()
                except (ValueError, json.JSONDecodeError) as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                updated = hub.rules.update_rule(
                    rule_id=rule_id,
                    action=payload.get("action"),
                    prefix=payload.get("prefix"),
                    arguments=payload.get("arguments"),
                    mode=payload.get("mode"),
                    reason=payload.get("reason"),
                )
                if updated is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "rule_not_found"})
                else:
                    self._send_json(HTTPStatus.OK, updated.to_dict())
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_DELETE(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/aap/v1/requests/"):
                req_id = path[len("/api/aap/v1/requests/") :].strip("/")
                record = hub.cancel_request(req_id)
                if record is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "request_not_found"})
                else:
                    self._send_json(HTTPStatus.OK, record)
                return

            if path.startswith("/api/ui/rules/"):
                rule_id = path[len("/api/ui/rules/") :].strip("/")
                if hub.rules.delete_rule(rule_id):
                    self._send_json(HTTPStatus.OK, {"deleted": rule_id})
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "rule_not_found"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    return AAPHandler


def _hook_output(runtime: str, decision: str, reason: str = "") -> str:
    if runtime == "antigravity":
        payload: dict[str, Any] = {"decision": decision}
        if reason:
            payload["reason"] = reason
        return json.dumps(payload)
    if runtime == "codex" and decision == "allow":
        # Codex PreToolUse rejects permissionDecision:"allow" without updatedInput;
        # exiting 0 with empty stdout allows the tool call cleanly.
        return ""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason or (runtime == "codex" and decision == "deny"):
        payload["hookSpecificOutput"]["permissionDecisionReason"] = reason or "Denied"
    return json.dumps(payload)


def _http_json(
    method: str, url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: float = 35.0
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_hook(
    runtime: str,
    base_url: str,
    stdin_text: str | None = None,
    fail_open: bool = False,
) -> int:
    raw = stdin_text if stdin_text is not None else sys.stdin.read()
    try:
        event = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        print(_hook_output(runtime, "deny", f"Invalid PreToolUse JSON: {exc}"))
        return 0

    tool_call = event.get("toolCall") if isinstance(event.get("toolCall"), dict) else {}
    tool = str(
        tool_call.get("name") or event.get("tool_name") or event.get("tool") or "unknown"
    )
    arguments = tool_call.get("args") if isinstance(tool_call.get("args"), dict) else event.get("tool_input")
    if not isinstance(arguments, dict):
        arguments = {}

    aap_payload = {
        "tool": tool,
        "arguments": arguments,
        "timeout": "604800s",
        "context": {
            "runtime": runtime,
            "cwd": event.get("cwd") or "",
            "session_id": event.get("session_id") or event.get("sessionId") or "",
            "call_id": tool_call.get("id") or event.get("tool_use_id") or event.get("call_id") or "",
            "hook_event": event.get("hook_event_name") or event.get("hookEventName") or "PreToolUse",
        },
    }
    base = base_url.rstrip("/")
    try:
        created = _http_json(
            "POST",
            f"{base}/api/aap/v1/requests",
            payload=aap_payload,
            headers={"Idempotency-Key": str(uuid.uuid4())},
            timeout=10.0,
        )
        req_id = created["id"]
        current = created
        while current.get("status") == "pending":
            current = _http_json(
                "GET",
                f"{base}/api/aap/v1/requests/{req_id}?wait=25",
                timeout=35.0,
            )
        if current.get("status") == "approved":
            _http_json(
                "POST",
                f"{base}/api/aap/v1/requests/{req_id}/consume",
                payload={},
                headers={"Idempotency-Key": str(uuid.uuid4())},
                timeout=10.0,
            )
            out = _hook_output(runtime, "allow")
            if out:
                print(out)
            return 0
        reason = (current.get("decision") or {}).get("reason") or f"Request {current.get('status')}"
        print(_hook_output(runtime, "deny", str(reason)))
        return 0
    except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError) as exc:
        if fail_open:
            out = _hook_output(runtime, "allow", f"AAP server unreachable (fail-open): {exc}")
            if out:
                print(out)
            return 0
        print(_hook_output(runtime, "deny", f"AAP server unreachable at {base}: {exc}"))
        return 0


def _backup_file(path: Path) -> None:
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.bak-{stamp}")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def _hook_command(script_path: Path, runtime: str, url: str) -> str:
    return f"{shlex.quote(str(script_path))} hook {runtime} --url {shlex.quote(url)}"


def _is_aap_ui_hook(cmd: str) -> bool:
    return "aap_ui.py hook " in cmd


def install_claude(script_path: Path, settings_path: Path, url: str) -> None:
    data: dict[str, Any] = {}
    if settings_path.exists():
        _backup_file(settings_path)
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    hooks = data.setdefault("hooks", {})
    pre = [
        entry
        for entry in hooks.get("PreToolUse", [])
        if not any(_is_aap_ui_hook(h.get("command", "")) for h in entry.get("hooks", []))
    ]
    pre.append(
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": _hook_command(script_path, "claude-code", url),
                    "timeout": 604860,
                }
            ],
        }
    )
    hooks["PreToolUse"] = pre
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def eject_claude(settings_path: Path) -> None:
    if not settings_path.exists():
        return
    _backup_file(settings_path)
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return
    pre = [
        entry
        for entry in hooks.get("PreToolUse", [])
        if not any(_is_aap_ui_hook(h.get("command", "")) for h in entry.get("hooks", []))
    ]
    if pre:
        hooks["PreToolUse"] = pre
    else:
        hooks.pop("PreToolUse", None)
    if not hooks:
        data.pop("hooks", None)
    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


_CODEX_BLOCK_START = "# BEGIN aap-ui hook\n"
_CODEX_BLOCK_END = "# END aap-ui hook\n"


def _strip_codex_block(text: str) -> str:
    if _CODEX_BLOCK_START in text and _CODEX_BLOCK_END in text:
        before, rest = text.split(_CODEX_BLOCK_START, 1)
        _, after = rest.split(_CODEX_BLOCK_END, 1)
        return (before.rstrip() + "\n\n" + after.lstrip()).strip() + "\n"
    return text


def install_codex(script_path: Path, config_path: Path, url: str) -> None:
    text = ""
    if config_path.exists():
        _backup_file(config_path)
        text = _strip_codex_block(config_path.read_text(encoding="utf-8"))
    cmd = _hook_command(script_path, "codex", url).replace("'", "''")
    block = (
        f"{_CODEX_BLOCK_START}"
        f"[hooks]\n"
        f"[[hooks.PreToolUse]]\n"
        f"matcher = '.*'\n\n"
        f"[[hooks.PreToolUse.hooks]]\n"
        f"command = '{cmd}'\n"
        f"timeout = 604860\n"
        f"type = 'command'\n"
        f"{_CODEX_BLOCK_END}"
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    new_text = (text.rstrip() + "\n\n" + block) if text.strip() else block
    config_path.write_text(new_text, encoding="utf-8")


def eject_codex(config_path: Path) -> None:
    if not config_path.exists():
        return
    _backup_file(config_path)
    text = _strip_codex_block(config_path.read_text(encoding="utf-8"))
    config_path.write_text(text, encoding="utf-8")


def install_antigravity(script_path: Path, hooks_path: Path, url: str) -> None:
    data: dict[str, Any] = {}
    if hooks_path.exists():
        _backup_file(hooks_path)
        raw = hooks_path.read_text(encoding="utf-8").strip()
        if raw:
            data = json.loads(raw)
    data["aap-ui"] = {
        "PreToolUse": [
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "type": "command",
                        "command": _hook_command(script_path, "antigravity", url),
                        "timeout": 604860,
                    }
                ],
            }
        ]
    }
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def eject_antigravity(hooks_path: Path) -> None:
    if not hooks_path.exists():
        return
    _backup_file(hooks_path)
    raw = hooks_path.read_text(encoding="utf-8").strip()
    if not raw:
        return
    data = json.loads(raw)
    if isinstance(data, dict):
        data.pop("aap-ui", None)
        hooks_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def serve(host: str, port: int, rules_path: Path) -> None:
    hub = ApprovalHub(RuleStore(rules_path))
    restarting = threading.Event()

    def trigger_restart() -> None:
        restarting.set()
        server.shutdown()

    usage = UsageCache()
    usage.start()
    hub.usage = usage
    server = ThreadingHTTPServer((host, port), make_handler(hub, on_restart=trigger_restart, usage=usage))
    print(f"AAP UI listening on http://{host}:{port} (rules: {rules_path})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    if restarting.is_set():
        print("Restarting AAP UI...", flush=True)
        os.execv(sys.executable, [sys.executable, *sys.argv])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight AAP server, UI, and hooks")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="Run the AAP server and Web UI")
    p_serve.add_argument("--host", default=DEFAULT_HOST)
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_serve.add_argument("--rules", type=Path, default=DEFAULT_RULES_PATH)

    p_hook = sub.add_parser("hook", help="PreToolUse hook client (reads stdin JSON)")
    p_hook.add_argument("runtime", choices=["claude-code", "codex", "antigravity"])
    p_hook.add_argument("--url", default=os.environ.get("AAP_URL", f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"))
    p_hook.add_argument("--fail-open", action="store_true")

    p_inst = sub.add_parser("install", help="Install PreToolUse hooks for Claude Code, Codex, and Antigravity")
    p_inst.add_argument("--url", default=f"http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    p_inst.add_argument("--claude-settings", type=Path, default=DEFAULT_CLAUDE_SETTINGS)
    p_inst.add_argument("--codex-config", type=Path, default=DEFAULT_CODEX_CONFIG)
    p_inst.add_argument("--antigravity-hooks", type=Path, default=DEFAULT_ANTIGRAVITY_HOOKS)

    p_ej = sub.add_parser("eject", help="Remove PreToolUse hooks from Claude Code, Codex, and Antigravity")
    p_ej.add_argument("--claude-settings", type=Path, default=DEFAULT_CLAUDE_SETTINGS)
    p_ej.add_argument("--codex-config", type=Path, default=DEFAULT_CODEX_CONFIG)
    p_ej.add_argument("--antigravity-hooks", type=Path, default=DEFAULT_ANTIGRAVITY_HOOKS)

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        serve(args.host, args.port, args.rules)
        return 0
    if args.cmd == "hook":
        return run_hook(args.runtime, args.url, fail_open=args.fail_open)
    if args.cmd == "install":
        script_path = Path(__file__).resolve()
        install_claude(script_path, args.claude_settings, args.url)
        install_codex(script_path, args.codex_config, args.url)
        install_antigravity(script_path, args.antigravity_hooks, args.url)
        print(
            f"Installed hooks in {args.claude_settings}, {args.codex_config}, and {args.antigravity_hooks}"
        )
        return 0
    if args.cmd == "eject":
        eject_claude(args.claude_settings)
        eject_codex(args.codex_config)
        eject_antigravity(args.antigravity_hooks)
        print(
            f"Removed hooks from {args.claude_settings}, {args.codex_config}, and {args.antigravity_hooks}"
        )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

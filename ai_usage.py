#!/usr/bin/env python3
"""
AI Usage Monitor — Codex, Claude Code, Antigravity.

Python 3.9+, standard library only.

Usage:
    python3 ai_usage.py
    python3 ai_usage.py --once
    python3 ai_usage.py --only codex
    python3 ai_usage.py --interval 60
"""

import argparse
import calendar
import datetime as dt
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional
from zoneinfo import ZoneInfo


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

REFRESH_INTERVAL = 30
TERMINAL_TITLE = "AI usage"
CODEX_TIMEOUT = 20
CLAUDE_TIMEOUT = 60
AGY_TIMEOUT = 60

FIVE_HOURS = dt.timedelta(hours=5)
ONE_WEEK = dt.timedelta(days=7)

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[90m",
    "light": "\033[37m",
    "red": "\033[91m",
    "codex": "\033[94m",
    "claude": "\033[95m",
    "agy": "\033[92m",
}


# ------------------------------------------------------------
# Data models
# ------------------------------------------------------------

@dataclass
class UsageWindow:
    label: str
    used: Optional[float]
    reset: Optional[dt.datetime] = None
    reset_text: Optional[str] = None
    duration: Optional[dt.timedelta] = None

    def expected(self, now):
        """
        Percentage of the window that has elapsed.

        Usage above this value is ahead of schedule.
        None when the reset time or duration is unknown.
        """
        if self.reset is None or not self.duration:
            return None

        remaining = (
            self.reset - now
        ) / self.duration

        return 100 * max(
            0.0, min(1.0, 1 - remaining)
        )


@dataclass
class UsageGroup:
    name: str
    windows: list = field(default_factory=list)


@dataclass
class ProviderResult:
    name: str
    source: str
    live: bool = True
    groups: list = field(default_factory=list)
    error: Optional[str] = None
    updated_at: Optional[dt.datetime] = None


# ------------------------------------------------------------
# Time helpers
# ------------------------------------------------------------

def now_local():
    return dt.datetime.now().astimezone()


def parse_time(value):
    if value is None:
        return None

    try:
        if isinstance(value, (int, float)):
            return dt.datetime.fromtimestamp(
                value, dt.timezone.utc
            ).astimezone()

        parsed = dt.datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=now_local().tzinfo
            )

        return parsed.astimezone()

    except (ValueError, TypeError, OverflowError):
        return None


def parse_claude_reset(raw):
    if not raw:
        return None

    parsed = parse_time(raw)
    if parsed:
        return parsed

    pattern = (
        r"([A-Za-z]{3})\s+(\d{1,2}),?\s+"
        r"(\d{1,2})(?::(\d{2}))?(am|pm)"
        r"(?:\s*\(([^)]+)\))?"
    )

    match = re.fullmatch(
        pattern, str(raw).strip(), re.I
    )

    if not match:
        return None

    try:
        month = list(calendar.month_abbr).index(
            match.group(1).title()
        )

        day = int(match.group(2))
        hour = int(match.group(3)) % 12
        minute = int(match.group(4) or 0)

        if match.group(5).lower() == "pm":
            hour += 12

        zone_name = match.group(6)

        zone = (
            ZoneInfo(zone_name)
            if zone_name
            else now_local().tzinfo
        )

        current = dt.datetime.now(zone)

        candidate = dt.datetime(
            current.year,
            month,
            day,
            hour,
            minute,
            tzinfo=zone,
        )

        if candidate < current - dt.timedelta(days=1):
            candidate = candidate.replace(
                year=current.year + 1
            )

        return candidate.astimezone()

    except (ValueError, KeyError):
        return None


def format_time(value):
    if value is None:
        return None

    return value.astimezone().strftime(
        "%Y-%m-%d %H:%M"
    )


# ------------------------------------------------------------
# Codex — App Server JSON-RPC
# ------------------------------------------------------------

def fetch_codex():
    result = ProviderResult(
        name="Codex",
        source="app-server",
    )

    proc = None

    try:
        proc = subprocess.Popen(
            ["codex", "app-server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

        messages = queue.Queue()

        def reader():
            try:
                for line in proc.stdout:
                    try:
                        messages.put(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            finally:
                messages.put(None)

        threading.Thread(
            target=reader,
            daemon=True,
        ).start()

        def send(message):
            proc.stdin.write(
                json.dumps(message) + "\n"
            )
            proc.stdin.flush()

        def receive(request_id):
            deadline = (
                time.monotonic() + CODEX_TIMEOUT
            )

            while True:
                remaining = (
                    deadline - time.monotonic()
                )

                if remaining <= 0:
                    raise RuntimeError(
                        "App Server timeout"
                    )

                try:
                    message = messages.get(
                        timeout=remaining
                    )
                except queue.Empty:
                    raise RuntimeError(
                        "App Server timeout"
                    ) from None

                if message is None:
                    raise RuntimeError(
                        "App Server exited"
                    )

                if (
                    not isinstance(message, dict)
                    or message.get("id") != request_id
                ):
                    continue

                if "error" in message:
                    raise RuntimeError(
                        str(message["error"])
                    )

                return message.get("result") or {}

        send({
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "ai_usage",
                    "title": "AI Usage Monitor",
                    "version": "2.0.0",
                }
            },
        })

        receive(1)

        send({
            "method": "initialized",
            "params": {},
        })

        send({
            "id": 2,
            "method": "account/rateLimits/read",
        })

        response = receive(2)

        buckets = response.get(
            "rateLimitsByLimitId"
        )

        if not isinstance(buckets, dict) or not buckets:
            single = response.get("rateLimits")

            if isinstance(single, dict):
                buckets = {
                    single.get("limitId") or "default":
                    single
                }
            else:
                buckets = {}

        if not buckets:
            raise RuntimeError(
                "No rate limits returned"
            )

        for bucket_id, bucket in buckets.items():
            if not isinstance(bucket, dict):
                continue

            group = UsageGroup(
                name=(
                    bucket.get("limitName")
                    or str(bucket_id)
                )
            )

            for slot in ("primary", "secondary"):
                item = bucket.get(slot)

                if not isinstance(item, dict):
                    continue

                duration = item.get(
                    "windowDurationMins"
                )

                if not isinstance(
                    duration, (int, float)
                ):
                    duration = None

                if duration == 300:
                    label = "5h"
                elif (
                    duration is not None
                    and duration >= 8640
                ):
                    label = "Weekly"
                elif duration is not None:
                    label = f"{duration:g} min"
                else:
                    label = slot.title()

                group.windows.append(
                    UsageWindow(
                        label=label,
                        used=item.get("usedPercent"),
                        reset=parse_time(
                            item.get("resetsAt")
                        ),
                        duration=(
                            dt.timedelta(
                                minutes=duration
                            )
                            if duration
                            else None
                        ),
                    )
                )

            if group.windows:
                result.groups.append(group)

        if not result.groups:
            raise RuntimeError(
                "No usable rate limits"
            )

    except Exception as exc:
        result.error = str(exc)

    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()

                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            for stream in (
                proc.stdin,
                proc.stdout,
            ):
                if stream:
                    stream.close()

    return result


# ------------------------------------------------------------
# Claude — claude -p /usage
# ------------------------------------------------------------

def fetch_claude():
    result = ProviderResult(
        name="Claude",
        source="claude -p /usage",
    )

    try:
        process = subprocess.run(
            ["claude", "-p", "/usage"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CLAUDE_TIMEOUT,
        )

        if process.returncode != 0:
            raise RuntimeError(
                process.stderr.strip()
                or f"Exit code {process.returncode}"
            )

        pattern = re.compile(
            r"^\s*"
            r"Current (session|week)"
            r"(?:\s*\(([^)]*)\))?"
            r"\s*:\s*"
            r"([0-9]+(?:[.,][0-9]+)?)%"
            r"\s*used"
            r"(?:\s*[·|]\s*resets\s+(.+))?"
            r"\s*$",
            re.I,
        )

        # The session limit covers every model; weekly limits
        # are reported per model scope, e.g. "(all models)"
        # or "(Fable)". Group windows by that scope.
        default_scope = "All models"
        groups = {}

        for line in process.stdout.splitlines():
            match = pattern.match(line)

            if not match:
                continue

            kind, scope, used, reset = match.groups()

            if kind.lower() == "session":
                label = "5h"
                duration = FIVE_HOURS
                scope = default_scope
            else:
                label = "Weekly"
                duration = ONE_WEEK
                scope = (scope or "").strip()
                scope = (
                    scope[0].upper() + scope[1:]
                    if scope
                    else default_scope
                )

            if scope not in groups:
                groups[scope] = UsageGroup(name=scope)

            parsed_reset = parse_claude_reset(
                reset
            )

            groups[scope].windows.append(
                UsageWindow(
                    label=label,
                    used=float(
                        used.replace(",", ".")
                    ),
                    reset=parsed_reset,
                    reset_text=(
                        reset
                        if reset and not parsed_reset
                        else None
                    ),
                    duration=duration,
                )
            )

        if not groups:
            raise RuntimeError(
                "Could not parse /usage output"
            )

        result.groups.extend(groups.values())

    except Exception as exc:
        result.error = str(exc)

    return result


# ------------------------------------------------------------
# Antigravity — agy -p /usage
# ------------------------------------------------------------

AGY_WINDOWS = {
    "5h": ("5h", FIVE_HOURS),
    "weekly": ("Weekly", ONE_WEEK),
}


def fetch_agy():
    result = ProviderResult(
        name="Antigravity",
        source="agy -p /usage",
    )

    try:
        process = subprocess.run(
            [
                "agy",
                "-p",
                "/usage",
                "--output-format",
                "json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=AGY_TIMEOUT,
        )

        if process.returncode != 0:
            raise RuntimeError(
                process.stderr.strip()
                or f"Exit code {process.returncode}"
            )

        try:
            data = json.loads(process.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(
                "Could not parse /usage output"
            ) from None

        groups = (
            data.get("command", {})
            .get("data", {})
            .get("groups")
        )

        if not isinstance(groups, list):
            raise RuntimeError(
                "No quota groups in /usage output"
            )

        for entry in groups:
            if not isinstance(entry, dict):
                continue

            group = UsageGroup(
                name=str(
                    entry.get("name") or "Models"
                )
            )

            buckets = [
                bucket
                for bucket in entry.get("buckets", [])
                if isinstance(bucket, dict)
            ]

            # Show the 5h window before the weekly one.
            order = list(AGY_WINDOWS)

            buckets.sort(
                key=lambda bucket: (
                    order.index(bucket["window"])
                    if bucket.get("window") in order
                    else len(order)
                )
            )

            for bucket in buckets:
                remaining = bucket.get(
                    "remaining_fraction"
                )

                if not isinstance(
                    remaining, (int, float)
                ):
                    continue

                window = bucket.get("window")

                label, duration = AGY_WINDOWS.get(
                    window,
                    (
                        str(
                            bucket.get("name")
                            or window
                            or "Limit"
                        ),
                        None,
                    ),
                )

                group.windows.append(
                    UsageWindow(
                        label=label,
                        used=(1 - remaining) * 100,
                        reset=parse_time(
                            bucket.get("reset_time")
                        ),
                        duration=duration,
                    )
                )

            if group.windows:
                result.groups.append(group)

        if not result.groups:
            raise RuntimeError(
                "No usable quotas in /usage output"
            )

    except Exception as exc:
        result.error = str(exc)

    return result


# ------------------------------------------------------------
# Parallel data collection
# ------------------------------------------------------------

# Display order: alphabetical.
FETCHERS = {
    "agy": fetch_agy,
    "claude": fetch_claude,
    "codex": fetch_codex,
}

NAMES = {
    "agy": "Antigravity",
    "claude": "Claude",
    "codex": "Codex",
}

# Short agent names for the one-line summary.
AGENT_SHORT_NAMES = {
    "agy-gemini": "gem",
    "agy-claude-gpt": "agx",
    "agy-argon": "arg",
    "claude": "cd",
    "codex": "cx",
}

# Summary line: this many agents furthest above target,
# then "|", then this many furthest below.
SUMMARY_EXTREMES = 2


def collect(only=None):
    """
    Fetch providers concurrently.

    Each worker returns structured data.
    No worker prints anything.

    Rendering happens only after all futures complete.
    """
    selected = (
        [only]
        if only
        else list(FETCHERS)
    )

    with ThreadPoolExecutor(
        max_workers=len(selected)
    ) as executor:
        futures = {
            name: executor.submit(
                FETCHERS[name]
            )
            for name in selected
        }

        results = {}

        for name in selected:
            try:
                results[name] = (
                    futures[name].result()
                )
            except Exception as exc:
                results[name] = ProviderResult(
                    name=NAMES[name],
                    source="unknown",
                    error=str(exc),
                )

    return results


# ------------------------------------------------------------
# Terminal rendering
# ------------------------------------------------------------

def paint(text, style, enabled=True):
    if not enabled:
        return text

    return (
        ANSI[style]
        + text
        + ANSI["reset"]
    )


def progress_bar(
    used,
    expected,
    width,
    provider,
    colors,
):
    """
    Bar of `width` cells.

    Filled cells show usage. When the expected usage
    (elapsed share of the window) is known, the empty
    part is split into two shades of grey at that point
    (darker: time already elapsed, lighter: time left),
    and cells used beyond it are drawn in red: that
    usage is ahead of schedule.
    """
    used = max(
        0.0,
        min(100.0, float(used))
    )

    filled = round(width * used / 100)

    if expected is None:
        mark = None
        on_time = filled
    else:
        mark = round(width * expected / 100)
        on_time = min(filled, mark)

    cells = [
        ("█", provider)
        for _ in range(on_time)
    ]

    cells += [
        ("█" if colors else "▓", "red")
        for _ in range(filled - on_time)
    ]

    elapsed_empty = (
        max(filled, mark)
        if mark is not None
        else filled
    )

    cells += [
        ("▒" if not colors else "░", "dim")
        for _ in range(elapsed_empty - filled)
    ]

    cells += [
        ("░", "light" if mark is not None else "dim")
        for _ in range(width - elapsed_empty)
    ]

    return "".join(
        paint(char, style, colors)
        for char, style in cells
    )


def render_window(
    item,
    provider,
    label_width,
    bar_width,
    detail,
    colors,
):
    label = f"  {item.label:<{label_width}}"

    if item.used is None:
        return f"{label}  unavailable"

    used = max(
        0.0,
        min(100.0, float(item.used))
    )

    percentage = int(used + 0.5)

    reset = format_time(item.reset)

    # Narrow terminals: values only, no "used" / "resets".
    prefix = "resets " if detail else ""

    if reset:
        reset_text = prefix + reset
    elif item.reset_text:
        reset_text = prefix + item.reset_text
    elif percentage == 0:
        reset_text = "not started"
    else:
        reset_text = "reset unavailable"

    expected = item.expected(now_local())

    bar = progress_bar(
        used,
        expected,
        bar_width,
        provider,
        colors,
    )

    used_text = (
        f"{percentage:3d}% used"
        if detail
        else f"{percentage:3d}%"
    )

    if expected is not None and used > expected:
        # Ahead of schedule: flag the number as well.
        used_text = paint(used_text, "red", colors)

    return (
        f"{label}  [{bar}]  "
        + used_text
        + paint(
            f" · {reset_text}",
            "dim",
            colors,
        )
    )


# Placeholder for a horizontal rule; render_screen replaces it
# once the width of the widest content line is known.
DIVIDER = "\0divider"
HEADER = "\0header"
# Compact provider header: a rule with the name in it. The
# painted name follows the marker; render_screen fills in the
# rule once the width is known.
RULE = "\0rule"

# Minimum spaces between "AI usage" and the header's right part.
HEADER_GAP = 5

ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*m")


def visible_width(text):
    """Width on screen, ignoring color codes."""
    return len(ANSI_ESCAPE.sub("", text))


def render_provider(
    provider,
    result,
    label_width,
    bar_width,
    detail,
    compact,
    colors,
):
    lines = []

    if not compact:
        lines.append(DIVIDER)

    header = paint(
        result.name if compact else f"  {result.name}",
        provider,
        colors,
    )

    # Windows that are used up: say in the header when
    # each of them resets, so it stands out.
    exhausted = []

    for group in result.groups:
        for item in group.windows:
            if item.used is None or item.used < 99:
                continue

            reset = (
                format_time(item.reset)
                or item.reset_text
                or "unknown"
            )

            text = f"resets {reset}"

            # "All models" adds nothing: the limit applies to
            # everything, so the bare reset time says it all.
            if (
                len(result.groups) > 1
                and group.name != "All models"
            ):
                text = f"{group.name} {text}"

            if text not in exhausted:
                exhausted.append(text)

    if exhausted:
        header += paint(
            " · " + " · ".join(exhausted),
            "red",
            colors,
        )

    if compact:
        lines.append(RULE + header)
    else:
        lines.append(header)
        lines.append(DIVIDER)

    if result.error:
        lines.append(
            paint(
                f"  Unavailable: "
                f"{result.error}",
                "red",
                colors,
            )
        )
        return lines

    if result.updated_at:
        updated = format_time(
            result.updated_at
        )

        age = max(
            0,
            (
                now_local()
                - result.updated_at
            ).total_seconds(),
        )

        lines.append(
            paint(
                f"  Last update: {updated}"
                f" ({int(age / 60)} min ago)",
                "dim",
                colors,
            )
        )

    show_group_names = len(result.groups) > 1

    for index, group in enumerate(result.groups):
        if show_group_names:
            if index and not compact:
                lines.append("")

            lines.append(
                paint(
                    f"  {group.name.upper()}",
                    "bold",
                    colors,
                )
            )

        for item in group.windows:
            lines.append(
                render_window(
                    item,
                    provider,
                    label_width,
                    bar_width,
                    detail,
                    colors,
                )
            )

    return lines


def render_screen(results, interval, compact=None):
    """
    Pure rendering.

    No subprocesses, threads, or network requests.

    `compact` drops the header line and blank lines between
    groups, folds each provider header into a single rule
    and leaves out the closing rule. When
    None, the full layout is used if it fits the terminal
    height, the compact one otherwise.
    """
    size = shutil.get_terminal_size((100, 20))
    width = min(100, size.columns)

    if compact is None:
        full = render_screen(results, interval, False)

        # The screen ends with a newline, so the cursor needs
        # one more row; otherwise the terminal scrolls by one
        # line and the header is lost.
        if full.count("\n") < size.lines:
            return full

        return render_screen(results, interval, True)

    colors = (
        sys.stdout.isatty()
        and not os.environ.get(
            "NO_COLOR"
        )
    )

    label_width = max(
        (
            len(item.label)
            for result in results.values()
            for group in result.groups
            for item in group.windows
        ),
        default=0,
    )

    # Same bar width on every line: leave room for the label,
    # brackets, "NNN% used" and "resets YYYY-MM-DD HH:MM".
    # When even a minimal bar does not fit, drop the words
    # "used" and "resets" (detail 0) and give the bar the
    # room they free up.
    MIN_BAR = 10
    detail = 0

    for level, reserved in ((1, 45), (0, 33)):
        if width - label_width - reserved >= MIN_BAR:
            detail = level
            break

    bar_width = max(
        MIN_BAR,
        min(36, width - label_width - reserved),
    )

    # The compact layout has no "AI usage" header line.
    lines = [] if compact else [HEADER]

    for provider, result in results.items():
        # A blank line between providers, none above the first.
        if lines and lines[-1] != HEADER:
            lines.append("")

        lines.extend(
            render_provider(
                provider,
                result,
                label_width,
                bar_width,
                detail,
                compact,
                colors,
            )
        )

    if not compact:
        lines.append("")
        lines.append(DIVIDER)

    # Rules one cell wider than the widest content line, for
    # symmetry with the indent, never wider than the terminal.
    divider_width = min(
        width,
        1
        + max(
            (
                visible_width(line)
                for line in lines
                if line not in (DIVIDER, HEADER)
                and not line.startswith(RULE)
            ),
            default=width,
        ),
    )

    divider = paint(
        "─" * divider_width,
        "dim",
        colors,
    )

    # Header spread over the same width as the rules: title
    # at the left edge, refresh info at the right edge.
    title = "AI usage"
    refresh = f"refreshing every {interval:g} seconds"
    exit_hint = "Ctrl+C to exit"

    # Drop the refresh note, then the exit hint, unless at
    # least HEADER_GAP cells separate them from the title.
    for info in (
        f"{refresh} · {exit_hint}",
        exit_hint,
        "",
    ):
        gap = divider_width - len(title) - len(info)

        if gap >= HEADER_GAP or not info:
            break

    gap = max(0, gap)

    header = (
        paint(title, "bold", colors)
        + " " * gap
        + paint(info, "dim", colors)
    )

    def rule_with(name):
        # "── Name ─────": the name keeps its own color.
        name = name[len(RULE):]
        rest = divider_width - visible_width(name) - 4

        return (
            paint("── ", "dim", colors)
            + name
            + paint(" " + "─" * max(0, rest), "dim", colors)
        )

    lines = [
        divider if line == DIVIDER
        else header if line == HEADER
        else rule_with(line) if line.startswith(RULE)
        else line
        for line in lines
    ]

    return "\n".join(lines) + "\n"


# ------------------------------------------------------------
# Agents: one score per model family
# ------------------------------------------------------------

# (agent, provider, group name). A None group means the
# provider's only group. Groups not listed (e.g. Claude's
# per-model weekly limit) are ignored here.
AGENTS = [
    ("agy-gemini", "agy", "gemini models"),
    ("agy-claude-gpt", "agy", "claude and gpt models"),
    ("agy-argon", "agy", "gemini 4 argon"),
    ("claude", "claude", "all models"),
    ("codex", "codex", None),
]


def agent_scores(results, now=None):
    """
    How far each agent is ahead of its usage target.

    For every window of the agent's group the target is the
    elapsed share of the window; the score is `used - target`
    in percentage points, and the agent's score is the larger
    of its 5h and 7d scores. Positive: using faster than time
    passes. Windows that have not started yet are skipped.
    None: no data (provider error, unknown reset).
    """
    now = now or now_local()
    scores = {}

    for agent, provider, group_name in AGENTS:
        result = results.get(provider)
        score = None

        if result is not None and not result.error:
            for group in result.groups:
                if (
                    group_name is not None
                    and group.name.lower() != group_name
                ):
                    continue

                for item in group.windows:
                    expected = item.expected(now)

                    if item.used is None or expected is None:
                        continue

                    if item.used == 0:
                        # Window not started yet (e.g. an idle
                        # 5h session): nothing to judge, let the
                        # other window decide.
                        continue

                    delta = float(item.used) - expected

                    if score is None or delta > score:
                        score = delta

        scores[agent] = score

    return scores


# ------------------------------------------------------------
# One-line summary (window title)
# ------------------------------------------------------------

def short_reset(value, now):
    if value is None:
        return "?"

    value = value.astimezone()

    if value.date() == now.date():
        return value.strftime("%H:%M")

    return value.strftime("%d.%m")


def exhausted_resets(results, now):
    """
    Agent -> reset time text of its used-up window, if any.
    """
    resets = {}

    for agent, provider, group_name in AGENTS:
        result = results.get(provider)

        if result is None or result.error:
            continue

        for group in result.groups:
            if (
                group_name is not None
                and group.name.lower() != group_name
            ):
                continue

            for item in group.windows:
                if item.used is not None and item.used >= 99:
                    resets[agent] = short_reset(
                        item.reset, now
                    )
                    break

            if agent in resets:
                break

    return resets


def summary_line(results):
    """
    The agents furthest above and furthest below target.

    Example: "gem ↓8 cx ↓5 | arg ↑29 agx ×18:41"

    Entries run from best to worst; "|" separates the
    SUMMARY_EXTREMES best from the SUMMARY_EXTREMES worst.
    A used-up agent shows its reset time instead of a number.
    """
    now = now_local()
    scores = agent_scores(results, now)
    resets = exhausted_resets(results, now)

    entries = []

    for agent, score in scores.items():
        short = AGENT_SHORT_NAMES.get(agent, agent)

        if agent in resets:
            # Nothing left to use: worst of all.
            entries.append(
                (float("inf"), f"{short} ×{resets[agent]}")
            )
        elif score is not None:
            arrow = "↑" if score > 0 else "↓"

            entries.append(
                (score, f"{short} {arrow}{abs(score):.0f}")
            )

    if not entries:
        return TERMINAL_TITLE

    entries.sort(key=lambda entry: -entry[0])

    worst = entries[:SUMMARY_EXTREMES]
    best = entries[SUMMARY_EXTREMES:][-SUMMARY_EXTREMES:]

    parts = [text for _, text in worst]

    if best:
        parts.append("|")
        parts.extend(text for _, text in best)

    return " ".join(reversed(parts))


def set_title(text):
    if sys.stdout.isatty():
        # OSC 0: set the terminal window title.
        sys.stdout.write(f"\033]0;{text}\007")


# ------------------------------------------------------------
# Main loop
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "AI usage dashboard "
            "(stdlib only)"
        )
    )

    parser.add_argument(
        "--only",
        choices=list(FETCHERS),
    )

    parser.add_argument(
        "--once",
        action="store_true",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=REFRESH_INTERVAL,
    )

    args = parser.parse_args()

    if args.interval <= 0:
        parser.error(
            "--interval must be positive"
        )

    tty = sys.stdout.isatty()

    def draw(results):
        if tty:
            sys.stdout.write("\033[H\033[2J")

        sys.stdout.write(
            render_screen(results, args.interval)
        )

    # Last results, redrawn when the terminal is resized.
    latest = {"results": None}

    def on_resize(signum, frame):
        if latest["results"] is not None:
            draw(latest["results"])
            sys.stdout.flush()

    if tty and hasattr(signal, "SIGWINCH"):
        signal.signal(signal.SIGWINCH, on_resize)

    try:
        set_title(TERMINAL_TITLE)

        if tty:
            # Hide the cursor; restored in the finally block.
            sys.stdout.write("\033[?25l")

        sys.stdout.write(
            "Collecting AI usage\n"
        )
        sys.stdout.flush()

        next_start = time.monotonic()

        while True:
            # Each fetch starts one interval after the previous
            # fetch started, so the screen refreshes at a steady
            # pace regardless of how long fetching takes.
            next_start += args.interval

            # 1. Fetch all providers in parallel.
            results = collect(args.only)

            # 2. Render only after all fetches finish, and
            #    replace the entire terminal view.
            latest["results"] = results
            draw(results)
            set_title(summary_line(results))
            sys.stdout.flush()

            if args.once:
                break

            now = time.monotonic()

            if next_start < now:
                # Fetching took longer than the interval.
                next_start = now

            time.sleep(next_start - now)

    except KeyboardInterrupt:
        print("\nStopped.")

    finally:
        if tty:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

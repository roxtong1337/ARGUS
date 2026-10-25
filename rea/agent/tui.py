"""ARGUS terminal interface.

A REPL with live tool output. Deliberately built on plain ANSI escapes rather
than ``curses``: it works over SSH, inside a container, and in a recorded demo,
and it degrades to no colour when the output is not a terminal.

The UI holds no logic. It renders what :class:`~rea.agent.session.AgentSession`
emits and forwards what the operator types, which is why the web front-end can
share the same core without the two drifting apart.
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import Optional

from .session import AgentSession
from ..agent import AGENT_NAME, AGENT_TAGLINE

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

SEVERITY_COLOUR = {
    "critical": RED,
    "high": MAGENTA,
    "medium": YELLOW,
    "low": BLUE,
    "info": DIM,
}

VERDICT_COLOUR = {
    "malicious": RED,
    "suspicious": YELLOW,
    "low-risk": BLUE,
    "clean": GREEN,
}

BANNER = f"""\
{BOLD}{CYAN}  ┌───────────────────────────────────────────────────────────────┐
  │  {AGENT_NAME} · reverse-engineering analyst agent{RESET}{BOLD}{CYAN}                   │
  └───────────────────────────────────────────────────────────────┘{RESET}
  {DIM}static analysis + sandboxed detonation · offline · type{RESET} help {DIM}for commands{RESET}
"""


class Colour:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET


def _supports_colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("REA_FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render_scan(data: dict, colour: Colour, width: int = 78) -> str:
    """Render a scan report for the terminal."""
    if not data:
        return ""
    artifact = data.get("artifact", data)
    out = []

    summary = artifact.get("summary", {})
    verdict = (summary.get("verdict") or artifact.get("verdict") or "unknown").lower()
    score = summary.get("risk_score", artifact.get("risk_score", 0))
    vcolour = VERDICT_COLOUR.get(verdict, "")

    file_type = artifact.get("file_type", {}) or {}
    hashes = artifact.get("hashes", {}) or {}

    out.append("")
    out.append(f"  {colour('verdict', BOLD)}   {colour(verdict.upper(), BOLD, vcolour)}"
               f"  {colour(f'({score}/100)', DIM)}")
    out.append(f"  {colour('type', BOLD)}      {file_type.get('description') or file_type.get('kind') or 'unknown'}")
    if hashes.get("sha256"):
        out.append(f"  {colour('sha256', BOLD)}    {colour(hashes['sha256'], DIM)}")
    out.append(f"  {colour('size', BOLD)}      {artifact.get('size', 0)} bytes")

    indicators = artifact.get("indicators", {}) or {}
    if indicators:
        out.append("")
        out.append(f"  {colour('INDICATORS', BOLD)}")
        for key, values in sorted(indicators.items()):
            if not values:
                continue
            out.append(f"    {colour(key, CYAN)} ({len(values)})")
            for value in values[:5]:
                out.append(f"      {str(value)[:width - 8]}")
            if len(values) > 5:
                out.append(f"      {colour(f'... {len(values) - 5} more', DIM)}")

    findings = artifact.get("findings", []) or []
    if findings:
        out.append("")
        out.append(f"  {colour('FINDINGS', BOLD)} ({len(findings)})")
        ordered = sorted(findings, key=lambda f: -f.get("score", 0))
        for finding in ordered[:14]:
            severity = finding.get("severity", "info")
            sc = SEVERITY_COLOUR.get(severity, "")
            out.append(
                f"    {colour(f'[{severity:8}]', sc)} {finding.get('score', 0):>3}  "
                f"{finding.get('title', finding.get('id', '?'))}"
            )
            if finding.get("detail"):
                for line in textwrap.wrap(finding["detail"], width - 18)[:2]:
                    out.append(f"              {colour(line, DIM)}")
            for evidence in (finding.get("evidence") or [])[:3]:
                out.append(f"              {colour('· ' + str(evidence)[:width - 16], DIM)}")
        if len(ordered) > 14:
            out.append(f"    {colour(f'... {len(ordered) - 14} more finding(s)', DIM)}")

    dynamic = (artifact.get("stats", {}) or {}).get("dynamic")
    if dynamic and dynamic.get("telemetry"):
        telemetry = dynamic["telemetry"]
        out.append("")
        out.append(
            f"  {colour('SANDBOX', BOLD)}   {telemetry.get('event_count', 0)} syscall event(s) "
            f"in {colour(dynamic.get('backend', '?'), CYAN)}"
            f"{colour(' (isolated)', GREEN) if dynamic.get('isolated') else colour(' (NOT isolated)', RED)}"
        )
        counts = telemetry.get("syscall_counts", {}) or {}
        if counts:
            top = ", ".join(f"{name}×{n}" for name, n in list(counts.items())[:8])
            out.append(f"    {colour(top, DIM)}")
        if telemetry.get("addresses"):
            out.append(f"    network: {', '.join(telemetry['addresses'][:5])}")
        if telemetry.get("stdout"):
            out.append(f"    {colour('stdout:', BOLD)}")
            for line in telemetry["stdout"].splitlines()[:6]:
                out.append(f"      {colour(line[:width - 8], DIM)}")

    errors = artifact.get("errors") or []
    if errors:
        out.append("")
        out.append(f"  {colour('WARNINGS', YELLOW)}")
        for error in errors[:4]:
            out.append(f"    {colour(str(error)[:width - 6], DIM)}")

    out.append("")
    return "\n".join(out)


def render_tool_call(record: dict, colour: Colour) -> str:
    arguments = record.get("arguments") or {}
    rendered = " ".join(f"{k}={v}" for k, v in arguments.items() if v not in ("", None, {}))
    mark = colour("✓", GREEN) if record.get("ok") else colour("✗", RED)
    return f"  {mark} {colour(record.get('tool', '?'), BOLD)} {colour(rendered, DIM)}"


class Tui:
    def __init__(self, session: Optional[AgentSession] = None, colour: Optional[bool] = None,
                 stream=None):
        self.stream = stream or sys.stdout
        self.colour = Colour(_supports_colour(self.stream) if colour is None else colour)
        self.session = session or AgentSession(on_event=self._on_event)

    # ---- event plumbing ------------------------------------------------

    def _on_event(self, kind: str, payload: dict) -> None:
        if kind == "tool_start":
            arguments = payload.get("arguments") or {}
            rendered = " ".join(f"{k}={v}" for k, v in arguments.items() if v not in ("", None, {}))
            self._write(f"\n  {self.colour('▸', CYAN)} {self.colour(payload['tool'], BOLD)} "
                        f"{self.colour(rendered, DIM)}")

    def _write(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    # ---- the loop ------------------------------------------------------

    def banner(self) -> None:
        self._write(BANNER)

    def run(self) -> int:
        self.banner()
        while True:
            try:
                line = input(f"{self.colour('argus', BOLD, CYAN)}{self.colour('>', DIM)} ")
            except (EOFError, KeyboardInterrupt):
                self._write(f"\n{self.colour('session ended', DIM)}")
                return 0

            command = line.strip()
            if not command:
                continue
            if command in ("exit", "quit", ":q"):
                self._write(self.colour("session ended", DIM))
                return 0
            if command == "clear":
                self._write("\033[2J\033[H")
                self.banner()
                continue

            self._dispatch(command)

    def _dispatch(self, command: str) -> None:
        try:
            produced = self.session.handle(command)
        except Exception as exc:
            self._write(self.colour(f"  error: {exc}", RED))
            return

        # Render the newest agent reply. A reply that came with structured data
        # is a tool result, so the artifact view is the useful rendering.
        for message in produced:
            if message.role != "agent":
                continue
            if isinstance(message.data, dict):
                self._render_data(message.data)
            else:
                self._write(f"  {message.content}")

        artifact = self.session.artifact
        if artifact is not None:
            self._write(render_scan(artifact.to_dict(), self.colour))

    def _render_data(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        if data.get("error"):
            self._write(f"  {self.colour(data.get('summary', 'failed'), RED)}")
            return
        if "integrations" in data:
            for entry in data["integrations"]:
                marker = self.colour("●", GREEN) if entry.get("available") else self.colour("○", DIM)
                self._write(f"  {marker} {self.colour(entry['name'], BOLD)} — {entry.get('description', '')}")
        elif "rules" in data:
            for rule in data["rules"]:
                severity = rule.get("severity", "medium")
                self._write(
                    f"  {self.colour(f'[{severity:8}]', SEVERITY_COLOUR.get(severity, ''))} "
                    f"{rule.get('score', '0'):>3}  {rule['name']}  {self.colour(rule.get('description', ''), DIM)}"
                )
        elif "backends" in data:
            for backend in data["backends"]:
                marker = self.colour("●", GREEN) if backend.get("available") else self.colour("○", DIM)
                safety = self.colour("isolated", GREEN) if backend.get("isolated") else self.colour("NOT isolated", RED)
                self._write(f"  {marker} {self.colour(backend['name'], BOLD)} ({safety}) — {backend.get('description', '')}")
        elif data.get("summary"):
            self._write(f"  {self.colour(data['summary'], DIM)}")


def run_tui(session: Optional[AgentSession] = None) -> int:
    return Tui(session=session).run()

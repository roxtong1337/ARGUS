"""The agent session: intent parsing, planning and tool dispatch.

A session holds the conversation, the most recent artifact and the transcript of
tool calls. Both front-ends drive the same object, which is why the TUI and the
web UI behave identically.

Two things are worth calling out.

**The planner is deterministic by default.** Input here is a hostile sample, and
a sample's strings are attacker-controlled. Feeding them to an LLM planner turns
a malicious file into a prompt-injection vector. :class:`RulePlanner` decides
from the operator's command and the artifact's *structure*, never from sample
content, so it cannot be steered by the file under analysis. An LLM planner can
be supplied through the :class:`Planner` protocol when the deployment allows it.

**Every tool call is recorded.** The transcript is what a front-end renders and
what makes the agent auditable: you can see which capability ran, with which
arguments, and what came back.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol

from .tools import ToolRegistry, ToolResult, build_default_registry

DEFAULT_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Message:
    role: str
    content: str
    data: Any = None

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content, "data": self.data}


@dataclass
class PlanStep:
    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""


class Planner(Protocol):
    """Anything that can turn a request into a list of tool calls."""

    def plan(self, text: str, session: "AgentSession") -> List[PlanStep]:
        ...


class RulePlanner:
    """Deterministic intent parser.

    Understands a small command language, and otherwise falls back to a
    sensible triage sequence. It never reads the sample's contents, only the
    operator's words and the artifact's metadata, so a malicious file cannot
    influence the plan.
    """

    def plan(self, text: str, session: "AgentSession") -> List[PlanStep]:
        raw = text.strip()
        lowered = raw.lower()

        if not raw:
            return []

        if lowered in ("help", "?", "commands"):
            return [PlanStep(tool="__help__", rationale="operator asked for help")]

        # "scan <path>", "triage <path>", or a bare path
        tokens = _split(raw)
        verb = tokens[0].lower() if tokens else ""
        rest = tokens[1:]

        if verb in ("scan", "triage", "analyze", "analyse", "check"):
            if not rest:
                return [PlanStep(tool="__help__", rationale="scan needs a path")]
            return [PlanStep(tool="scan", arguments={"path": rest[0]},
                             rationale=f"static analysis of {rest[0]}")]

        if verb in ("detonate", "run", "execute", "sandbox", "dynamic"):
            path = rest[0] if rest and not rest[0].startswith("--") else ""
            timeout = _flag_int(rest, "--timeout", 20)
            return [PlanStep(tool="detonate", arguments={"path": path, "timeout": timeout},
                             rationale="run the sample in the sandbox and observe behaviour")]

        if verb in ("send", "deliver", "ship", "export"):
            target = rest[0] if rest else "hermes"
            config = _flag_config(rest)
            min_sev = _flag_value(rest, "--min-severity", "")
            args: Dict[str, Any] = {"target": target, "config": config}
            if min_sev:
                args["min_severity"] = min_sev
            return [PlanStep(tool="send", arguments=args,
                             rationale=f"deliver the report to {target}")]

        if verb in ("integrations", "targets"):
            return [PlanStep(tool="integrations", rationale="list delivery targets")]

        if verb in ("rules", "rulepack"):
            return [PlanStep(tool="rules", rationale="list loaded detections")]

        if verb in ("sandbox", "status"):
            return [PlanStep(tool="sandbox", rationale="report sandbox readiness")]

        if verb in ("full", "all", "investigate"):
            # The flagship flow: static, then dynamic, then deliver if configured.
            path = rest[0] if rest else ""
            steps = [
                PlanStep(tool="scan", arguments={"path": path}, rationale="static triage first"),
                PlanStep(tool="detonate", arguments={"path": path, "timeout": 20},
                         rationale="confirm with observed behaviour"),
            ]
            return steps

        # A bare path is the most common thing an analyst types.
        if len(tokens) == 1 and _looks_like_path(tokens[0]):
            return [PlanStep(tool="scan", arguments={"path": tokens[0]},
                             rationale="path detected, running static analysis")]

        # Anything else: if we already have an artifact, offer the next useful
        # step rather than pretending to understand.
        if session.artifact is not None:
            if "dynamic" not in session.artifact.stats:
                return [PlanStep(tool="detonate", arguments={},
                                 rationale="no behavioural data yet for the current artifact")]
            return [PlanStep(tool="__help__", rationale="nothing specific to do")]

        return [PlanStep(tool="__help__", rationale="could not map that to a capability")]


class AgentSession:
    """Conversation state plus tool dispatch."""

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        planner: Optional[Planner] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.registry = registry or build_default_registry()
        self.planner: Planner = planner or RulePlanner()
        self.on_event = on_event
        self.history: List[Message] = []
        self.transcript: List[dict] = []
        self.artifact = None

    # ---- introspection -------------------------------------------------

    def tools(self) -> List[dict]:
        return self.registry.describe()

    def _emit(self, kind: str, payload: dict) -> None:
        if self.on_event:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass

    def _say(self, role: str, content: str, data: Any = None) -> Message:
        message = Message(role=role, content=content, data=data)
        self.history.append(message)
        self._emit("message", message.to_dict())
        return message

    # ---- the main entry point -----------------------------------------

    def handle(self, text: str) -> List[Message]:
        """Process one operator request and return the messages produced."""
        produced: List[Message] = []
        self._say("user", text)
        self._emit("user", {"text": text})

        steps = self.planner.plan(text, self)
        if not steps:
            produced.append(self._say("agent", "Tell me what to do. Try: `help`."))
            return produced

        for step in steps:
            if step.tool == "__help__":
                produced.append(self._say("agent", HELP_TEXT))
                continue
            produced.append(self._run_tool(step))
        return produced

    def _run_tool(self, step: PlanStep) -> Message:
        tool = self.registry.get(step.tool)
        if tool is None:
            return self._say("agent", f"I do not have a `{step.tool}` capability.")

        self._emit("tool_start", {"tool": step.tool, "arguments": step.arguments,
                                  "rationale": step.rationale})
        record = {"tool": step.tool, "arguments": step.arguments, "rationale": step.rationale}
        try:
            result: ToolResult = tool.handler(**step.arguments)
        except TypeError as exc:
            result = ToolResult(ok=False, summary=f"bad arguments for {step.tool}: {exc}",
                                error="bad_arguments")
        except Exception as exc:
            result = ToolResult(ok=False, summary=f"{step.tool} failed: {exc}", error=str(exc))

        if result.artifacts:
            self.artifact = result.artifacts[-1]

        record.update({"ok": result.ok, "summary": result.summary, "error": result.error})
        self.transcript.append(record)
        self._emit("tool_end", record)

        if not result.ok:
            return self._say("agent", f"{step.tool}: {result.summary}", data=result.to_dict())

        return self._say("agent", result.summary, data=result.to_dict())

    # ---- serialisation for the web front-end --------------------------

    def snapshot(self) -> dict:
        return {
            "history": [m.to_dict() for m in self.history],
            "transcript": self.transcript,
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "tools": self.tools(),
        }


HELP_TEXT = """\
ARGUS — capabilities

  scan <path>              static analysis: format, hashes, IOC, rules, verdict
  detonate <path>          run the file in an isolated sandbox and record behaviour
  full <path>              scan, then detonate
  send <target>            deliver the report (hermes, http, webhook, local, stdout)
  integrations             list delivery targets
  rules                    list loaded detections
  sandbox                  report whether detonation is available
  help                     this text

Examples
  scan samples/malicious_sample.sh
  full samples/malicious_sample.sh
  send hermes --min-severity medium
  detonate /tmp/suspect.bin --timeout 30

Notes
  * detonation requires a container runtime; `sandbox` will tell you if it is ready
  * nothing is executed unless you explicitly ask for `detonate` or `full`
"""


# ----------------------------------------------------------------------
# Small parsing helpers
# ----------------------------------------------------------------------


def _split(text: str) -> List[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _looks_like_path(token: str) -> bool:
    return (
        "/" in token
        or token.startswith(".")
        or token.endswith((".sh", ".exe", ".dll", ".so", ".bin", ".elf", ".py", ".ps1", ".js"))
    )


def _flag_value(tokens: List[str], flag: str, default: str) -> str:
    for i, token in enumerate(tokens):
        if token == flag and i + 1 < len(tokens):
            return tokens[i + 1]
        if token.startswith(flag + "="):
            return token.split("=", 1)[1]
    return default


def _flag_int(tokens: List[str], flag: str, default: int) -> int:
    value = _flag_value(tokens, flag, "")
    try:
        return int(value) if value else default
    except ValueError:
        return default


def _flag_config(tokens: List[str]) -> Dict[str, str]:
    """Collect ``key=value`` pairs as adapter configuration."""
    config: Dict[str, str] = {}
    for token in tokens:
        if token.startswith("--") or "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key:
            config[key] = value
    return config

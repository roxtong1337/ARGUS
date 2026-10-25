"""ARGUS: the analyst agent that drives REA.

ARGUS is the operator-facing side of the toolkit. REA answers "what is this
file"; ARGUS answers "what should I do next about this file" by calling REA's
capabilities as tools and keeping a session of what happened.

Two front-ends share this core, so behaviour is identical in both:

* :mod:`rea.agent.tui` — a terminal interface for an analyst on a box
* :mod:`rea.web.server` — a browser interface for a demo or a team

The planner is deliberately deterministic. It runs offline, has no API key, and
cannot be prompt-injected, which matters when the input is a hostile sample
whose *strings* are attacker-controlled. An LLM planner can be plugged in via
:class:`~rea.agent.session.Planner`, but the default has to work in a locked-down
hackathon environment.
"""

from __future__ import annotations

from .session import AgentSession, Message, Planner, RulePlanner
from .tools import Tool, ToolRegistry, ToolResult, build_default_registry

AGENT_NAME = "ARGUS"
AGENT_TAGLINE = "Automated Reverse-engineering Guidance and Understanding System"

__all__ = [
    "AGENT_NAME",
    "AGENT_TAGLINE",
    "AgentSession",
    "Message",
    "Planner",
    "RulePlanner",
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "build_default_registry",
]

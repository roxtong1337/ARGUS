"""Report renderers.

Each renderer takes an :class:`~rea.core.model.Artifact` and returns a string.
``json`` is the machine format the Hermes adapter consumes; ``sarif`` lets REA
results show up in code-scanning dashboards; ``markdown`` and ``text`` are for
humans and for the hackathon demo.
"""

from __future__ import annotations

from .render import RENDERERS, render, to_json, to_markdown, to_sarif, to_text

__all__ = ["RENDERERS", "render", "to_json", "to_markdown", "to_sarif", "to_text"]

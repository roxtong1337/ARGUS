"""Stdout integration: pretty-print or dump the report to the console.

Useful for demos, piping into ``jq`` and CI logs.
"""

from __future__ import annotations

import json
from typing import Any

from ..core.model import Artifact
from .base import Integration, IntegrationResult
from .registry import register


@register
class StdoutIntegration(Integration):
    name = "stdout"
    description = "Print the report to standard output (JSON or compact summary)."

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        mode = self.cfg("mode", "summary")
        if mode == "json":
            text = json.dumps(artifact.to_dict(), indent=2, default=str)
        else:
            text = _summary_text(artifact)
        print(text)
        return IntegrationResult(
            integration=self.name,
            ok=True,
            detail=f"printed {mode} report",
            payload_size=len(text),
        )


def _summary_text(artifact: Artifact) -> str:
    lines = [
        f"path        : {artifact.path}",
        f"size        : {artifact.size} bytes",
        f"type        : {artifact.file_type.description if artifact.file_type else 'unknown'}",
        f"sha256      : {artifact.hashes.sha256 if artifact.hashes else '-'}",
        f"verdict     : {artifact.verdict} (score {artifact.risk_score}/100)",
        f"findings    : {len(artifact.findings)}",
        f"strings     : {len(artifact.strings)}",
        f"indicators  : {sum(len(v) for v in artifact.indicators.values())}",
    ]
    if artifact.findings:
        lines.append("--- findings ---")
        for f in sorted(artifact.findings, key=lambda x: -x.score):
            lines.append(f"[{f.severity:8}] {f.score:3}  {f.title}  ({f.id})")
    return "\n".join(lines)

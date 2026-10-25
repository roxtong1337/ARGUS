"""Local integration: append reports to a JSONL archive on disk.

This is the offline default. It gives the team a searchable case archive during
a hackathon with no network, and doubles as the replay source for testing the
Hermes adapter.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from ..core.model import Artifact
from .base import Integration, IntegrationResult
from .registry import register


@register
class LocalArchiveIntegration(Integration):
    name = "local"
    description = "Append the report as one JSON line to a local archive file."

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.path = self.cfg("path", os.path.join("rea-reports", "artifacts.jsonl"), env="REA_ARCHIVE")

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        record = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "report": artifact.to_dict(),
        }
        record.update(extra)
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        line = json.dumps(record, default=str) + "\n"
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            return IntegrationResult(
                integration=self.name, ok=False, detail=f"write failed: {exc}"
            )
        return IntegrationResult(
            integration=self.name,
            ok=True,
            detail=f"appended to {self.path}",
            payload_size=len(line),
            extra={"archive": self.path},
        )

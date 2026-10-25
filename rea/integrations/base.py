"""Base contract for every outbound integration."""

from __future__ import annotations

import abc
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.model import Artifact


class IntegrationError(RuntimeError):
    """Raised when an integration cannot deliver its payload."""


@dataclass
class IntegrationResult:
    """Outcome of a single delivery attempt."""

    integration: str
    ok: bool
    detail: str = ""
    status_code: Optional[int] = None
    payload_size: int = 0
    response: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "integration": self.integration,
            "ok": self.ok,
            "detail": self.detail,
            "status_code": self.status_code,
            "payload_size": self.payload_size,
            "response": self.response[:2000],
            "extra": self.extra,
        }


class Integration(abc.ABC):
    """Base class for result sinks.

    Subclasses declare a ``name`` and implement :meth:`send`. Configuration is
    passed as a dict and may also be sourced from the environment, which keeps
    secrets out of command lines and shell history.
    """

    name: str = "integration"
    description: str = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config: Dict[str, Any] = dict(config or {})

    # ---- helpers available to subclasses ------------------------------

    def cfg(self, key: str, default: Any = None, env: Optional[str] = None) -> Any:
        """Look up config, falling back to an environment variable."""
        if key in self.config and self.config[key] is not None:
            return self.config[key]
        if env:
            value = os.environ.get(env)
            if value not in (None, ""):
                return value
        return default

    def build_payload(self, artifact: Artifact, **extra: Any) -> Dict[str, Any]:
        """The canonical REA payload. Subclasses may extend or reshape it."""
        payload: Dict[str, Any] = {
            "source": "rea",
            "schema": "rea.artifact/v1",
            "artifact": artifact.to_dict(),
        }
        payload.update(extra)
        return payload

    @staticmethod
    def encode(payload: Dict[str, Any]) -> bytes:
        return json.dumps(payload, indent=2, sort_keys=False, default=str).encode("utf-8")

    # ---- contract ------------------------------------------------------

    @abc.abstractmethod
    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        """Deliver the artifact's report. Must not raise on network failure."""

    # ---- introspection -------------------------------------------------

    def describe(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.__class__.__name__} name={self.name!r}>"


def should_send(artifact: Artifact, min_severity: str = "info", min_score: int = 0) -> bool:
    """Gate used by callers that only want interesting samples forwarded."""
    from ..core.model import SEVERITY_ORDER

    threshold = SEVERITY_ORDER.get(min_severity, 0)
    for f in artifact.findings:
        if SEVERITY_ORDER.get(f.severity, 0) >= threshold:
            return True
    return artifact.risk_score >= min_score

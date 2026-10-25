"""Generic HTTP integration: POST the REA payload to any JSON endpoint.

This is the escape hatch. If the target system is not Hermes and has no dedicated
adapter yet, point this at its URL with the right auth headers and it will work.
"""

from __future__ import annotations

from typing import Any, Dict

from ..core.model import Artifact
from . import http_client
from .base import Integration, IntegrationError, IntegrationResult
from .registry import register


@register
class HttpIntegration(Integration):
    name = "http"
    description = "POST the report as JSON to an arbitrary HTTP endpoint."

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        token = self.cfg("token", env="REA_HTTP_TOKEN")
        if token:
            scheme = self.cfg("auth_scheme", "Bearer")
            headers["Authorization"] = f"{scheme} {token}"
        api_key = self.cfg("api_key", env="REA_HTTP_API_KEY")
        if api_key:
            headers[self.cfg("api_key_header", "X-API-Key")] = api_key
        for key, value in (self.cfg("headers", {}) or {}).items():
            headers[key] = str(value)
        return headers

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        url = self.cfg("url", env="REA_HTTP_URL")
        if not url:
            return IntegrationResult(
                integration=self.name, ok=False, detail="no url configured"
            )

        payload = self.build_payload(artifact, **extra)
        if self.cfg("wrap", False):
            payload = {"event": self.cfg("event", "rea.scan"), "data": payload}

        body = self.encode(payload)
        if self.cfg("dry_run", False):
            return IntegrationResult(
                integration=self.name,
                ok=True,
                detail=f"dry-run: would POST {len(body)} bytes to {url}",
                payload_size=len(body),
            )

        try:
            status, response = http_client.post_json(
                url,
                payload,
                headers=self._headers(),
                timeout=float(self.cfg("timeout", 15.0)),
                retries=int(self.cfg("retries", 2)),
                verify_tls=bool(self.cfg("verify_tls", True)),
            )
        except Exception as exc:
            return IntegrationResult(
                integration=self.name, ok=False, detail=str(exc), payload_size=len(body)
            )

        ok = 200 <= status < 300
        return IntegrationResult(
            integration=self.name,
            ok=ok,
            detail=f"HTTP {status}",
            status_code=status,
            payload_size=len(body),
            response=response,
        )

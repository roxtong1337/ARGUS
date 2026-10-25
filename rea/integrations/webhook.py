"""Webhook integration with optional HMAC request signing.

Targets the common pattern used by chat ops and SOAR platforms: a shared secret
plus an HMAC-SHA256 signature header so the receiver can verify authenticity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict

from ..core.model import Artifact
from . import http_client
from .base import Integration, IntegrationResult
from .registry import register


@register
class WebhookIntegration(Integration):
    name = "webhook"
    description = "POST to a webhook URL, optionally HMAC-SHA256 signed."

    def _headers(self, body: bytes) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        secret = self.cfg("secret", env="REA_WEBHOOK_SECRET")
        if secret:
            timestamp = str(int(time.time()))
            signed = f"{timestamp}.".encode() + body
            signature = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
            header = self.cfg("signature_header", "X-REA-Signature")
            headers[header] = f"sha256={signature}"
            headers["X-REA-Timestamp"] = timestamp
        token = self.cfg("token", env="REA_WEBHOOK_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for key, value in (self.cfg("headers", {}) or {}).items():
            headers[key] = str(value)
        return headers

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        url = self.cfg("url", env="REA_WEBHOOK_URL")
        if not url:
            return IntegrationResult(integration=self.name, ok=False, detail="no url configured")

        payload = self.build_payload(artifact, **extra)
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
                headers=self._headers(body),
                timeout=float(self.cfg("timeout", 15.0)),
                retries=int(self.cfg("retries", 2)),
                verify_tls=bool(self.cfg("verify_tls", True)),
            )
        except Exception as exc:
            return IntegrationResult(
                integration=self.name, ok=False, detail=str(exc), payload_size=len(body)
            )

        return IntegrationResult(
            integration=self.name,
            ok=200 <= status < 300,
            detail=f"HTTP {status}",
            status_code=status,
            payload_size=len(body),
            response=response,
        )

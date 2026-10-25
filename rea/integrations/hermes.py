"""Hermes integration.

REA does not assume a fixed Hermes API shape. Real deployments differ on the
endpoint path, the auth scheme and the expected body, so this adapter is driven
entirely by configuration and exposes three payload modes:

``raw``
    Send ``{"source": "rea", "schema": "rea.artifact/v1", "artifact": {...}}``.
    Use this when Hermes ingests REA reports as-is.

``envelope``
    Wrap the report in ``{"event": <event_name>, "timestamp": ..., "data": {...}}``,
    the shape most event buses and ingestion gateways expect.

``detections``
    Flatten the artifact into one detection record per finding, which is what a
    SIEM / SOAR / case-management backend usually wants. Indicator fields are
    promoted to top level so they can be indexed directly.

Configuration keys (each also readable from an environment variable):

    base_url        REA_HERMES_URL        e.g. https://hermes.example.com
    path            REA_HERMES_PATH       default /api/v1/ingest
    payload_mode    REA_HERMES_MODE       raw | envelope | detections
    auth_style      REA_HERMES_AUTH       bearer | apikey | basic | none
    token           REA_HERMES_TOKEN      bearer token
    api_key         REA_HERMES_API_KEY    API key value
    api_key_header  REA_HERMES_KEY_HEADER default X-API-Key
    username        REA_HERMES_USER
    password        REA_HERMES_PASS
    source_name     REA_HERMES_SOURCE     default "rea"
    verify_tls                            default true
    timeout / retries / dry_run

Example::

    from rea.integrations import create

    hermes = create("hermes", {
        "base_url": "https://hermes.internal",
        "path": "/api/v1/ingest",
        "auth_style": "bearer",
        "payload_mode": "detections",
    })
    result = hermes.send(artifact)
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List

from ..core.model import Artifact
from . import http_client
from .base import Integration, IntegrationResult
from .registry import register

PAYLOAD_MODES = ("raw", "envelope", "detections")


@register
class HermesIntegration(Integration):
    name = "hermes"
    description = "Deliver REA reports to the Hermes platform (configurable schema and auth)."

    # ---- configuration -------------------------------------------------

    @property
    def base_url(self) -> str:
        return str(self.cfg("base_url", "", env="REA_HERMES_URL")).rstrip("/")

    @property
    def path(self) -> str:
        return str(self.cfg("path", "/api/v1/ingest", env="REA_HERMES_PATH"))

    @property
    def payload_mode(self) -> str:
        mode = str(self.cfg("payload_mode", "envelope", env="REA_HERMES_MODE")).lower()
        if mode not in PAYLOAD_MODES:
            raise ValueError(f"payload_mode must be one of {PAYLOAD_MODES}, got {mode!r}")
        return mode

    @property
    def source_name(self) -> str:
        return str(self.cfg("source_name", "rea", env="REA_HERMES_SOURCE"))

    def _headers(self) -> Dict[str, str]:
        style = str(self.cfg("auth_style", "bearer", env="REA_HERMES_AUTH")).lower()
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if style == "bearer":
            token = self.cfg("token", env="REA_HERMES_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif style == "apikey":
            key = self.cfg("api_key", env="REA_HERMES_API_KEY")
            if key:
                headers[str(self.cfg("api_key_header", "X-API-Key"))] = str(key)
        elif style == "basic":
            user = str(self.cfg("username", "", env="REA_HERMES_USER"))
            password = str(self.cfg("password", "", env="REA_HERMES_PASS"))
            if user:
                blob = base64.b64encode(f"{user}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {blob}"
        elif style != "none":
            raise ValueError(f"unknown auth_style {style!r}")

        for key, value in (self.cfg("headers", {}) or {}).items():
            headers[key] = str(value)
        return headers

    def _endpoint(self) -> str:
        if not self.base_url:
            return ""
        return http_client.join_url(self.base_url, self.path)

    # ---- payload shaping -----------------------------------------------

    def to_detection(self, artifact: Artifact, finding=None) -> Dict[str, Any]:
        """Flatten an artifact (optionally one finding) into a detection record."""
        h = artifact.hashes
        detection: Dict[str, Any] = {
            "source": self.source_name,
            "schema": "rea.detection/v1",
            "artifact": {
                "path": artifact.path,
                "basename": artifact.metadata.get("basename"),
                "size": artifact.size,
                "type": artifact.file_type.kind if artifact.file_type else "unknown",
                "type_description": artifact.file_type.description if artifact.file_type else "",
                "arch": artifact.file_type.arch if artifact.file_type else None,
                "sha256": h.sha256 if h else None,
                "sha1": h.sha1 if h else None,
                "md5": h.md5 if h else None,
                "ssdeep_like": h.ssdeep_like if h else None,
            },
            "verdict": artifact.verdict,
            "risk_score": artifact.risk_score,
            "scanned_at": artifact.scanned_at,
            "indicators": artifact.indicators,
            "capabilities": artifact.stats.get("capabilities", []),
            "import_categories": artifact.stats.get("import_categories", {}),
            "tags": list(self.cfg("tags", []) or []),
        }
        if finding is not None:
            detection["detection"] = {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "score": finding.score,
                "detail": finding.detail,
                "evidence": finding.evidence,
                "tags": finding.tags,
                "source": finding.source,
            }
        else:
            detection["detections"] = [f.to_dict() for f in artifact.findings]
        return detection

    def build_hermes_payload(self, artifact: Artifact, **extra: Any) -> Any:
        mode = self.payload_mode
        if mode == "raw":
            payload: Any = self.build_payload(artifact, **extra)
            payload["source"] = self.source_name
            return payload
        if mode == "envelope":
            return {
                "event": self.cfg("event", "rea.scan.completed"),
                "source": self.source_name,
                "timestamp": artifact.scanned_at,
                "data": self.build_payload(artifact, **extra),
            }
        # detections: one record per finding, or a single summary record when clean
        if artifact.findings:
            records = [self.to_detection(artifact, f) for f in artifact.findings]
        else:
            records = [self.to_detection(artifact)]
        if self.cfg("batch", True):
            return {"source": self.source_name, "events": records}
        return records

    # ---- delivery ------------------------------------------------------

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        endpoint = self._endpoint()
        if not endpoint:
            return IntegrationResult(
                integration=self.name, ok=False, detail="no base_url configured"
            )

        try:
            payload = self.build_hermes_payload(artifact, **extra)
        except ValueError as exc:
            return IntegrationResult(integration=self.name, ok=False, detail=str(exc))

        body = json.dumps(payload, default=str).encode("utf-8")
        if self.cfg("dry_run", False):
            return IntegrationResult(
                integration=self.name,
                ok=True,
                detail=f"dry-run: would POST {len(body)} bytes to {endpoint} (mode={self.payload_mode})",
                payload_size=len(body),
                extra={"endpoint": endpoint, "mode": self.payload_mode},
            )

        try:
            status, response = http_client.post_json(
                endpoint,
                payload,
                headers=self._headers(),
                timeout=float(self.cfg("timeout", 15.0)),
                retries=int(self.cfg("retries", 2)),
                verify_tls=bool(self.cfg("verify_tls", True)),
            )
        except Exception as exc:
            return IntegrationResult(
                integration=self.name,
                ok=False,
                detail=str(exc),
                payload_size=len(body),
                extra={"endpoint": endpoint, "mode": self.payload_mode},
            )

        ok = 200 <= status < 300
        return IntegrationResult(
            integration=self.name,
            ok=ok,
            detail=f"HTTP {status}",
            status_code=status,
            payload_size=len(body),
            response=response,
            extra={"endpoint": endpoint, "mode": self.payload_mode},
        )

    def send_many(self, artifacts: List[Artifact], **extra: Any) -> List[IntegrationResult]:
        return [self.send(a, **extra) for a in artifacts]

    def health(self) -> IntegrationResult:
        """Probe the configured base URL to confirm reachability and auth."""
        endpoint = self._endpoint()
        if not endpoint:
            return IntegrationResult(integration=self.name, ok=False, detail="no base_url configured")
        try:
            status, response = http_client.get_json(
                endpoint, headers=self._headers(), timeout=float(self.cfg("timeout", 10.0))
            )
        except Exception as exc:
            return IntegrationResult(integration=self.name, ok=False, detail=str(exc))
        return IntegrationResult(
            integration=self.name,
            ok=status < 500,
            detail=f"HTTP {status}",
            status_code=status,
            response=response,
        )

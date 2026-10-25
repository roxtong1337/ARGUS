# Hermes integration

REA does not assume a particular Hermes API. Endpoint paths, auth schemes and
body shapes differ between deployments, so the adapter is configuration-driven.
You point it at your Hermes, pick a payload shape, and it works. When your
Hermes team publishes a concrete spec, only the config changes — no code.

## Quick start

```bash
rea send suspicious.exe --to hermes \
  --set base_url=https://hermes.internal \
  --set path=/api/v1/ingest \
  --set auth_style=bearer \
  --set token="$HERMES_TOKEN" \
  --set payload_mode=detections
```

Or from Python:

```python
from rea.analysis.pipeline import Pipeline
from rea.integrations import create

artifact = Pipeline(rule_paths=["rules"]).scan_path("suspicious.exe")

hermes = create("hermes", {
    "base_url": "https://hermes.internal",
    "path": "/api/v1/ingest",
    "auth_style": "bearer",
    "payload_mode": "detections",
})
result = hermes.send(artifact)
print(result.ok, result.status_code, result.detail)
```

Always dry-run first to see exactly what would be sent:

```bash
rea send suspicious.exe --to hermes --dry-run \
  --set base_url=https://hermes.internal --set payload_mode=detections
```

## Configuration reference

Every key can also come from an environment variable, which keeps secrets out of
shell history and process listings.

| Key | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `base_url` | `REA_HERMES_URL` | — (required) | Scheme, host and optional prefix |
| `path` | `REA_HERMES_PATH` | `/api/v1/ingest` | Endpoint path appended to the base |
| `payload_mode` | `REA_HERMES_MODE` | `envelope` | `raw`, `envelope` or `detections` |
| `auth_style` | `REA_HERMES_AUTH` | `bearer` | `bearer`, `apikey`, `basic` or `none` |
| `token` | `REA_HERMES_TOKEN` | — | Bearer token |
| `api_key` | `REA_HERMES_API_KEY` | — | API key value |
| `api_key_header` | `REA_HERMES_KEY_HEADER` | `X-API-Key` | Header carrying the API key |
| `username` / `password` | `REA_HERMES_USER` / `REA_HERMES_PASS` | — | Basic auth credentials |
| `source_name` | `REA_HERMES_SOURCE` | `rea` | Value sent as the event source |
| `event` | — | `rea.scan.completed` | Event name in `envelope` mode |
| `tags` | — | `[]` | Static tags added to every detection |
| `batch` | — | `true` | Wrap detections in `{"events": [...]}` |
| `timeout` | — | `15` | Per-request timeout in seconds |
| `retries` | — | `2` | Retries with exponential backoff |
| `verify_tls` | — | `true` | Set false only for a lab with self-signed certs |
| `dry_run` | — | `false` | Build the payload without sending |
| `headers` | — | `{}` | Extra headers to merge in |

Retry behaviour: 5xx and 429 responses and network errors are retried with
exponential backoff; other 4xx responses fail immediately, because a bad request
will not become good on the second attempt.

## Payload modes

### `raw`

The report as REA produces it. Use this when Hermes stores REA reports verbatim.

```json
{
  "source": "rea",
  "schema": "rea.artifact/v1",
  "artifact": { "path": "...", "hashes": {...}, "findings": [...] }
}
```

### `envelope`

The report wrapped in an event envelope, the shape most ingestion gateways and
event buses expect.

```json
{
  "event": "rea.scan.completed",
  "source": "rea",
  "timestamp": "2026-10-25T11:08:02+00:00",
  "data": { "source": "rea", "schema": "rea.artifact/v1", "artifact": {...} }
}
```

### `detections`

One record per finding, with artifact and indicator fields promoted to the top
level so a SIEM, SOAR or case-management backend can index them directly. A clean
sample produces a single summary record so you still get telemetry.

```json
{
  "source": "rea",
  "events": [
    {
      "source": "rea",
      "schema": "rea.detection/v1",
      "artifact": {
        "path": "...", "basename": "...", "size": 795,
        "type": "script", "type_description": "Script with shebang",
        "arch": null, "sha256": "...", "sha1": "...", "md5": "...",
        "ssdeep_like": "..."
      },
      "verdict": "malicious",
      "risk_score": 100,
      "scanned_at": "...",
      "indicators": { "urls": ["..."], "ipv4": ["..."] },
      "capabilities": ["network communication (C2 or exfiltration capable)"],
      "import_categories": { "network": 12 },
      "tags": [],
      "detection": {
        "id": "RULE_Reverse_Shell_Dev_Tcp",
        "title": "Reverse_Shell_Dev_Tcp",
        "severity": "critical",
        "score": 45,
        "detail": "Bash reverse shell over /dev/tcp",
        "evidence": ["$a @ 0x194: '/dev/tcp/'"],
        "tags": ["rule"],
        "source": "rules/downloaders.rea"
      }
    }
  ]
}
```

## What your Hermes side needs to accept

At minimum, an endpoint that accepts `POST` with `Content-Type: application/json`
and returns a 2xx. The payload above is self-describing: every record carries
`schema`, so your ingester can version its parsing.

If Hermes expects something else, there are three escalating options:

1. **Reshape with config** — `payload_mode`, `path`, `event`, `source_name`,
   `tags` and `headers` cover most integration mismatches.
2. **Use the generic `http` adapter** — same payloads, arbitrary endpoint, no
   Hermes-specific naming:
   ```bash
   rea send f.bin --to http --set url=https://hermes.internal/ingest --set token="$T"
   ```
3. **Write a dedicated adapter** — see below. It is about 30 lines.

## Writing a custom adapter

Adapters are discovered by name. Drop a module in `rea/integrations/` and
register the class; nothing else needs to change.

```python
from typing import Any
from ..core.model import Artifact
from . import http_client
from .base import Integration, IntegrationResult
from .registry import register


@register
class HermesV2Integration(Integration):
    name = "hermes-v2"
    description = "Hermes API v2, which wants a flat detection list."

    def send(self, artifact: Artifact, **extra: Any) -> IntegrationResult:
        url = self.cfg("url", env="REA_HERMES_V2_URL")
        if not url:
            return IntegrationResult(integration=self.name, ok=False, detail="no url")

        payload = {
            "detections": [
                self.to_flat(f) | {"sha256": artifact.hashes.sha256}
                for f in artifact.findings
            ]
        }
        try:
            status, body = http_client.post_json(
                url, payload, headers={"Authorization": f"Bearer {self.cfg('token')}"}
            )
        except Exception as exc:
            return IntegrationResult(integration=self.name, ok=False, detail=str(exc))
        return IntegrationResult(
            integration=self.name, ok=200 <= status < 300,
            status_code=status, detail=f"HTTP {status}", response=body,
        )

    @staticmethod
    def to_flat(finding) -> dict:
        return {"id": finding.id, "severity": finding.severity, "score": finding.score}
```

Then add the module name to the discovery tuple in
`rea/integrations/registry.py`:

```python
for module in ("local", "stdout", "http", "webhook", "hermes", "hermes_v2"):
```

Verify with `rea integrations` and a dry run.

## Operational notes

- **Gate what you send.** `--min-severity` and `--min-score` avoid flooding
  Hermes with clean-file telemetry during a bulk triage run.
- **Secrets.** Prefer environment variables over `--set` on a shared machine;
  command lines are visible in `ps`.
- **Health.** `create("hermes", cfg).health()` does a `GET` on the configured
  endpoint and reports the status, which is useful as a pre-flight check in a
  pipeline or a hackathon demo.
- **Offline mode.** Use `--to local` during development; the JSONL archive is the
  same payload shape the Hermes adapter would send, so replaying it into Hermes
  later is straightforward.

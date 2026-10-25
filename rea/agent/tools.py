"""Tools ARGUS can call.

A tool is a thin, typed wrapper over a REA capability. Wrapping (rather than
calling the pipeline directly) buys three things: the agent can describe what it
can do, a front-end can render a tool call without knowing REA internals, and a
new capability becomes available to every front-end by registering it once.

Tools return :class:`ToolResult`, never raise. A tool that fails reports why,
because an agent that dies on a bad file is worse than one that says "that file
is unreadable".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..analysis.pipeline import Pipeline
from ..core.model import Artifact
from ..integrations import create as create_integration
from ..integrations import describe_all
from ..integrations.registry import available as available_integrations

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules"
)


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: Any = None
    error: str = ""
    artifacts: List[Artifact] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "summary": self.summary, "error": self.error, "data": self.data}


@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict[str, str]
    handler: Callable[..., ToolResult]
    examples: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "examples": self.examples,
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def all(self) -> List[Tool]:
        return [self._tools[n] for n in self.names()]

    def describe(self) -> List[dict]:
        return [t.to_dict() for t in self.all()]


# ----------------------------------------------------------------------
# Handlers
# ----------------------------------------------------------------------


def _make_scan(holder: Dict) -> Callable[..., ToolResult]:
    def scan(
        path: str = "",
        data: Optional[bytes] = None,
        name: str = "",
        rules: Optional[List[str]] = None,
    ) -> ToolResult:
        pipeline = Pipeline(rule_paths=rules if rules is not None else [RULES_DIR])
        try:
            if data is not None:
                artifact = pipeline.scan_bytes(data, name or "upload.bin")
            elif path:
                if not os.path.isfile(path):
                    return ToolResult(ok=False, summary=f"no such file: {path}", error="not_found")
                artifact = pipeline.scan_path(path)
            else:
                return ToolResult(ok=False, summary="scan needs a path or data", error="bad_arguments")
        except Exception as exc:
            return ToolResult(ok=False, summary=f"scan failed: {exc}", error=str(exc))

        holder["last"] = artifact
        return ToolResult(
            ok=True,
            summary=(
                f"{os.path.basename(artifact.path)}: {artifact.verdict.upper()} "
                f"(score {artifact.risk_score}/100, {len(artifact.findings)} finding(s))"
            ),
            data=artifact.to_dict(),
            artifacts=[artifact],
        )

    return scan


def _make_detonate(holder: Dict, detonator_factory: Callable) -> Callable[..., ToolResult]:
    def detonate(
        path: str = "",
        name: str = "",
        timeout: int = 20,
        backend: str = "docker",
        confirm: bool = False,
    ) -> ToolResult:
        artifact = holder.get("last")
        target = path or (artifact.path if artifact else "")
        if not target or not os.path.isfile(target):
            return ToolResult(ok=False, summary="detonate needs a real file path", error="not_found")

        kind = artifact.file_type.kind if artifact and artifact.path == target else ""
        detonator = detonator_factory(backend=backend, timeout=timeout)
        ready, reason = detonator.check()
        if not ready:
            return ToolResult(ok=False, summary=reason, error="sandbox_unavailable")

        result = detonator.detonate(target, kind=kind)
        if not result.ok:
            return ToolResult(
                ok=False,
                summary=result.error or result.skipped_reason or "detonation failed",
                error="detonation_failed",
                data=result.to_dict(),
            )

        if artifact is not None and artifact.path == target:
            for finding in result.findings:
                artifact.add_finding(finding)
            artifact.stats["dynamic"] = result.to_dict()

        telemetry = result.telemetry
        summary = (
            f"detonated in an isolated {result.backend} sandbox: "
            f"{len(telemetry.events)} syscall event(s), {len(result.findings)} behavioural finding(s)"
            if telemetry
            else "detonation produced no telemetry"
        )
        return ToolResult(
            ok=True,
            summary=summary,
            data=result.to_dict(),
            artifacts=([artifact] if artifact else []),
        )

    return detonate


def _make_send(holder: Dict) -> Callable[..., ToolResult]:
    def send(
        target: str = "hermes",
        config: Optional[Dict[str, str]] = None,
        min_severity: str = "",
    ) -> ToolResult:
        artifact = holder.get("last")
        if artifact is None:
            return ToolResult(ok=False, summary="nothing to send; scan a file first", error="no_artifact")

        if target not in available_integrations():
            return ToolResult(
                ok=False,
                summary=f"unknown integration {target!r}; available: {', '.join(available_integrations())}",
                error="unknown_integration",
            )

        cfg: Dict[str, Any] = dict(config or {})
        if min_severity:
            cfg["min_severity"] = min_severity

        integration = create_integration(target, cfg)
        result = integration.send(artifact)
        return ToolResult(
            ok=result.ok,
            summary=f"{target}: {result.detail or ('delivered' if result.ok else 'failed')}",
            error="" if result.ok else "delivery_failed",
            data={
                "integration": result.integration,
                "status_code": result.status_code,
                "detail": result.detail,
                "endpoint": result.endpoint,
            },
        )

    return send


def _list_integrations() -> ToolResult:
    described = describe_all()
    return ToolResult(
        ok=True,
        summary=f"{len(described)} integration(s) available: {', '.join(available_integrations())}",
        data={"integrations": described},
    )


def _list_rules() -> ToolResult:
    from ..analysis.rules import load_rule_dir

    try:
        rules = load_rule_dir(RULES_DIR)
    except Exception as exc:
        return ToolResult(ok=False, summary=f"could not load rules: {exc}", error=str(exc))
    return ToolResult(
        ok=True,
        summary=f"{len(rules)} rule(s) loaded from the bundled pack",
        data={
            "rules": [
                {
                    "name": r.name,
                    "severity": r.meta.get("severity", "medium"),
                    "score": r.meta.get("score", "0"),
                    "description": r.meta.get("description", ""),
                    "source": os.path.basename(r.source),
                }
                for r in rules
            ]
        },
    )


def _sandbox_status(detonator_factory: Callable) -> ToolResult:
    from ..dynamic import list_backends

    backends = list_backends()
    detonator = detonator_factory()
    ready, reason = detonator.check()
    return ToolResult(
        ok=ready,
        summary=(
            f"detonation ready via the {detonator.backend_name} backend"
            if ready
            else f"detonation unavailable: {reason}"
        ),
        error="" if ready else "sandbox_unavailable",
        data={"backends": backends, "ready": ready, "reason": reason},
    )


def build_default_registry(detonator_factory: Optional[Callable] = None) -> ToolRegistry:
    """Build the standard tool set."""
    if detonator_factory is None:
        from ..dynamic import Detonator

        def detonator_factory(backend="docker", timeout=20, **_):
            return Detonator(backend=backend, timeout=timeout)

    holder: Dict[str, Any] = {}
    registry = ToolRegistry()

    registry.register(
        Tool(
            name="scan",
            description="Static analysis of a file: format, hashes, imports, IOC, rule matches, verdict.",
            parameters={"path": "file to scan", "rules": "optional list of rule directories"},
            handler=_make_scan(holder),
            examples=["scan samples/malicious_sample.sh"],
        )
    )
    registry.register(
        Tool(
            name="detonate",
            description="Run a file in an isolated sandbox and report observed behaviour (syscalls, network, files).",
            parameters={"path": "file to run", "timeout": "seconds before the sample is killed"},
            handler=_make_detonate(holder, detonator_factory),
            examples=["detonate samples/malicious_sample.sh"],
        )
    )
    registry.register(
        Tool(
            name="send",
            description="Deliver the last report to an integration such as hermes, http or webhook.",
            parameters={"target": "integration name", "config": "adapter settings"},
            handler=_make_send(holder),
            examples=["send hermes"],
        )
    )
    registry.register(
        Tool(
            name="integrations",
            description="List available delivery integrations and their settings.",
            parameters={},
            handler=_list_integrations,
            examples=["integrations"],
        )
    )
    registry.register(
        Tool(
            name="rules",
            description="List the loaded detection rules with severity and score.",
            parameters={},
            handler=_list_rules,
            examples=["rules"],
        )
    )
    registry.register(
        Tool(
            name="sandbox",
            description="Report whether the detonation sandbox is available.",
            parameters={},
            handler=lambda: _sandbox_status(detonator_factory),
            examples=["sandbox"],
        )
    )
    return registry

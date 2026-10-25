"""Concrete report renderers: text, markdown, json and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Callable, Dict

from ..core.model import Artifact

VERDICT_BADGE = {
    "malicious": "MALICIOUS",
    "suspicious": "SUSPICIOUS",
    "low-risk": "LOW-RISK",
    "clean": "CLEAN",
}


def to_json(artifact: Artifact, indent: int = 2) -> str:
    return json.dumps(artifact.to_dict(), indent=indent, default=str)


def to_text(artifact: Artifact) -> str:
    ft = artifact.file_type
    h = artifact.hashes
    lines = []
    rule = "=" * 72
    lines.append(rule)
    lines.append(f"REA report: {artifact.path}")
    lines.append(rule)
    lines.append(f"  size        : {artifact.size:,} bytes")
    lines.append(f"  type        : {ft.description if ft else 'unknown'}")
    if ft and ft.arch:
        lines.append(f"  arch        : {ft.arch} ({ft.bits}-bit {ft.endian}-endian)")
    if h:
        lines.append(f"  md5         : {h.md5}")
        lines.append(f"  sha1        : {h.sha1}")
        lines.append(f"  sha256      : {h.sha256}")
        lines.append(f"  fuzzy       : {h.ssdeep_like}")
    lines.append(f"  scanned_at  : {artifact.scanned_at}")
    lines.append(f"  verdict     : {VERDICT_BADGE.get(artifact.verdict, artifact.verdict)}"
                 f" (risk score {artifact.risk_score}/100)")
    lines.append("")

    if artifact.stats.get("capabilities"):
        lines.append("Capabilities")
        lines.append("-" * 72)
        for cap in artifact.stats["capabilities"]:
            lines.append(f"  * {cap}")
        lines.append("")

    if artifact.sections:
        lines.append(f"Sections ({len(artifact.sections)})")
        lines.append("-" * 72)
        lines.append(f"  {'name':<24} {'offset':>10} {'size':>10} {'entropy':>8}  flags")
        for s in artifact.sections[:40]:
            lines.append(
                f"  {s.name[:24]:<24} {s.offset:>10} {s.size:>10} {s.entropy:>8.3f}  {','.join(s.flags)}"
            )
        lines.append("")

    if artifact.imports:
        by_cat: Dict[str, list] = {}
        for imp in artifact.imports:
            by_cat.setdefault(imp.category, []).append(imp.name)
        lines.append(f"Imports ({len(artifact.imports)} across {len(by_cat)} categories)")
        lines.append("-" * 72)
        for cat, names in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"  {cat} ({len(names)}): {', '.join(sorted(set(names))[:8])}"
                         + (" ..." if len(set(names)) > 8 else ""))
        lines.append("")

    if artifact.indicators:
        lines.append("Indicators of compromise")
        lines.append("-" * 72)
        for kind, values in artifact.indicators.items():
            lines.append(f"  {kind} ({len(values)}):")
            for v in values[:8]:
                lines.append(f"      {v}")
            if len(values) > 8:
                lines.append(f"      ... and {len(values) - 8} more")
        lines.append("")

    if artifact.findings:
        lines.append(f"Findings ({len(artifact.findings)})")
        lines.append("-" * 72)
        for f in sorted(artifact.findings, key=lambda x: (-x.score, x.id)):
            lines.append(f"  [{f.severity.upper():<8}] {f.score:>3}  {f.title}")
            lines.append(f"             id={f.id} source={f.source or 'heuristic'}")
            if f.detail:
                lines.append(f"             {f.detail}")
            for ev in f.evidence[:4]:
                lines.append(f"             - {ev}")
        lines.append("")

    if artifact.errors:
        lines.append("Analysis warnings")
        lines.append("-" * 72)
        for e in artifact.errors:
            lines.append(f"  ! {e}")
        lines.append("")

    return "\n".join(lines)


def to_markdown(artifact: Artifact) -> str:
    ft = artifact.file_type
    h = artifact.hashes
    out = []
    out.append(f"# REA report: `{artifact.path}`")
    out.append("")
    out.append(f"**Verdict: {VERDICT_BADGE.get(artifact.verdict, artifact.verdict)}** "
               f"(risk score {artifact.risk_score}/100)")
    out.append("")
    out.append("| Property | Value |")
    out.append("| --- | --- |")
    out.append(f"| Size | {artifact.size:,} bytes |")
    out.append(f"| Type | {ft.description if ft else 'unknown'} |")
    if ft and ft.arch:
        out.append(f"| Architecture | {ft.arch} ({ft.bits}-bit) |")
    if h:
        out.append(f"| SHA-256 | `{h.sha256}` |")
        out.append(f"| SHA-1 | `{h.sha1}` |")
        out.append(f"| MD5 | `{h.md5}` |")
    out.append(f"| Scanned at | {artifact.scanned_at} |")
    out.append("")

    if artifact.stats.get("capabilities"):
        out.append("## Capabilities")
        out.append("")
        for cap in artifact.stats["capabilities"]:
            out.append(f"- {cap}")
        out.append("")

    if artifact.findings:
        out.append("## Findings")
        out.append("")
        out.append("| Severity | Score | Title | ID |")
        out.append("| --- | --- | --- | --- |")
        for f in sorted(artifact.findings, key=lambda x: (-x.score, x.id)):
            out.append(f"| {f.severity} | {f.score} | {f.title} | `{f.id}` |")
        out.append("")
        for f in sorted(artifact.findings, key=lambda x: (-x.score, x.id)):
            out.append(f"### {f.title} (`{f.id}`)")
            out.append("")
            if f.detail:
                out.append(f.detail)
                out.append("")
            if f.evidence:
                out.append("Evidence:")
                out.append("")
                for ev in f.evidence[:8]:
                    out.append(f"- `{ev}`")
                out.append("")

    if artifact.indicators:
        out.append("## Indicators of compromise")
        out.append("")
        for kind, values in artifact.indicators.items():
            out.append(f"**{kind}** ({len(values)})")
            out.append("")
            for v in values[:15]:
                out.append(f"- `{v}`")
            out.append("")

    if artifact.sections:
        out.append("## Sections")
        out.append("")
        out.append("| Name | Offset | Size | Entropy | Flags |")
        out.append("| --- | --- | --- | --- | --- |")
        for s in artifact.sections[:50]:
            out.append(f"| `{s.name}` | {s.offset} | {s.size} | {s.entropy:.3f} | {','.join(s.flags)} |")
        out.append("")

    return "\n".join(out)


def to_sarif(artifact: Artifact) -> str:
    """SARIF 2.1.0 output so findings surface in code-scanning dashboards."""
    rules = {}
    results = []
    for f in artifact.findings:
        rules[f.id] = {
            "id": f.id,
            "name": f.id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail or f.title},
            "properties": {
                "severity": f.severity,
                "score": f.score,
                "tags": f.tags,
            },
        }
        results.append(
            {
                "ruleId": f.id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.detail or f.title},
                "properties": {"score": f.score, "evidence": f.evidence[:10]},
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "REA",
                        "informationUri": "https://example.invalid/rea",
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": artifact.path},
                        "hashes": {
                            "sha-256": artifact.hashes.sha256 if artifact.hashes else ""
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, default=str)


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }.get(severity, "warning")


RENDERERS: Dict[str, Callable[[Artifact], str]] = {
    "text": to_text,
    "markdown": to_markdown,
    "md": to_markdown,
    "json": to_json,
    "sarif": to_sarif,
}


def render(artifact: Artifact, fmt: str = "text") -> str:
    fmt = (fmt or "text").lower()
    if fmt not in RENDERERS:
        raise KeyError(f"unknown report format {fmt!r}; available: {', '.join(sorted(RENDERERS))}")
    return RENDERERS[fmt](artifact)

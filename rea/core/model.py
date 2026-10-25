"""The artifact model: the single object every stage reads from and writes to.

The pipeline is deliberately linear and side-effect free:

    load() -> Artifact -> parsers enrich -> analysis scores -> report renders

Keeping one mutable-but-well-defined model means new parsers, new rule types
and new output formats can be added without touching each other.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .formats import FileType, detect
from .hashing import Hashes, hash_bytes


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Section:
    """A parsed section / segment from a container format."""

    name: str
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    flags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "entropy": self.entropy,
            "flags": self.flags,
        }
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class Import:
    """An imported symbol, grouped by the library that provides it."""

    library: str
    name: str
    category: str = "other"

    def to_dict(self) -> dict:
        return {"library": self.library, "name": self.name, "category": self.category}


@dataclass
class Finding:
    """A single piece of evidence produced by the analysis stage."""

    id: str
    title: str
    severity: str  # info | low | medium | high | critical
    score: int = 0
    detail: str = ""
    evidence: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "detail": self.detail,
            "evidence": self.evidence,
            "tags": self.tags,
            "source": self.source,
        }


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Artifact:
    """Everything REA knows about one input file."""

    path: str
    size: int = 0
    file_type: Optional[FileType] = None
    hashes: Optional[Hashes] = None
    sections: List[Section] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    scanned_at: str = field(default_factory=_now)

    # ---- construction -------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes, path: str = "<memory>") -> "Artifact":
        art = cls(path=path, size=len(data))
        art.file_type = detect(data, path)
        art.hashes = hash_bytes(data)
        art.metadata["basename"] = os.path.basename(path)
        return art

    @classmethod
    def load(cls, path: str, max_bytes: int = 256 << 20) -> "Artifact":
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
        art = cls.from_bytes(data, path)
        art.size = size
        if size > max_bytes:
            art.errors.append(
                f"file truncated for analysis at {max_bytes} bytes (full size {size})"
            )
        art.metadata["mtime"] = datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        ).isoformat()
        return art

    # ---- mutation helpers ---------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_strings(self, values: List[str]) -> None:
        self.strings.extend(values)

    # ---- derived ------------------------------------------------------

    @property
    def risk_score(self) -> int:
        """Sum of finding scores, capped at 100."""
        return min(100, sum(f.score for f in self.findings))

    @property
    def verdict(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "malicious"
        if score >= 40:
            return "suspicious"
        if score >= 15:
            return "low-risk"
        return "clean"

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {k: [] for k in SEVERITY_ORDER}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "basename": self.metadata.get("basename"),
            "size": self.size,
            "file_type": self.file_type.to_dict() if self.file_type else None,
            "hashes": self.hashes.to_dict() if self.hashes else None,
            "scanned_at": self.scanned_at,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "sections": [s.to_dict() for s in self.sections],
            "imports": [i.to_dict() for i in self.imports],
            "exports": self.exports,
            "strings_count": len(self.strings),
            "strings": self.strings,
            "indicators": self.indicators,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "metadata": self.metadata,
            "errors": self.errors,
        }

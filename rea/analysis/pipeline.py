"""The scan pipeline: one function that ties every stage together.

Stages are individually switchable so callers can trade depth for speed during
mass triage, e.g. ``Pipeline(strings=False, rules=False)`` for a hash-only pass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from ..core import loader
from ..core.model import Artifact, Finding
from . import iocs, rules as rules_mod, scoring, strings as strings_mod


@dataclass
class Pipeline:
    """Configuration for a scan run."""

    extract_strings: bool = True
    extract_iocs: bool = True
    run_rules: bool = True
    run_heuristics: bool = True
    max_bytes: int = 256 << 20
    rule_paths: List[str] = field(default_factory=list)
    rules: Optional[List[rules_mod.Rule]] = None
    progress: Optional[Callable[[str], None]] = None

    def _load_rules(self) -> List[rules_mod.Rule]:
        if self.rules is not None:
            return self.rules
        loaded: List[rules_mod.Rule] = []
        for path in self.rule_paths:
            try:
                if os.path.isdir(path):
                    loaded.extend(rules_mod.load_rule_dir(path))
                else:
                    loaded.extend(rules_mod.load_rule_file(path))
            except (OSError, rules_mod.RuleSyntaxError) as exc:
                if self.progress:
                    self.progress(f"rule load failed for {path}: {exc}")
        self.rules = loaded
        return loaded

    def scan_bytes(self, data: bytes, path: str = "<memory>") -> Artifact:
        art = Artifact.from_bytes(data, path=path)
        art.size = len(data)
        return self._analyse(art, data)

    def scan_path(self, path: str) -> Artifact:
        art = loader.load(path, max_bytes=self.max_bytes)
        data = _read(path, self.max_bytes)
        loader.parse(art, data)
        return self._analyse(art, data)

    # ------------------------------------------------------------------

    def _analyse(self, art: Artifact, data: bytes) -> Artifact:
        if self.progress:
            self.progress(f"scanning {art.path} ({art.size} bytes)")

        if self.extract_strings:
            art.strings = strings_mod.extract(data)
            art.stats["string_count"] = len(art.strings)

        if self.extract_iocs:
            art.indicators = iocs.extract(art.strings, raw=data)

        if self.run_rules:
            loaded = self._load_rules()
            if loaded:
                matches = rules_mod.scan(data, loaded)
                for m in matches:
                    art.add_finding(
                        Finding(
                            id=f"RULE_{m.rule.name}",
                            title=m.rule.name,
                            severity=m.rule.severity,
                            score=m.rule.score,
                            detail=m.rule.description,
                            evidence=m.evidence,
                            tags=list(m.rule.tags) + ["rule"],
                            source=m.rule.source,
                        )
                    )
                art.stats["rules_evaluated"] = len(loaded)
                art.stats["rules_matched"] = len(matches)

        if self.run_heuristics:
            scoring.run(art, data)

        art.stats["summary"] = scoring.summary(art)
        return art


def _read(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(max_bytes)


def scan_path(path: str, **kwargs) -> Artifact:
    return Pipeline(**kwargs).scan_path(path)


def scan_bytes(data: bytes, path: str = "<memory>", **kwargs) -> Artifact:
    return Pipeline(**kwargs).scan_bytes(data, path=path)

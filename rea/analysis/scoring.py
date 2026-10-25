"""Heuristic scoring: turn structural facts into weighted findings.

Rules give high-precision verdicts. Heuristics cover the long tail that no rule
author anticipated. Each heuristic is a small pure function so the weighting can
be tuned and unit-tested independently, and so a hackathon team can add one in
ten lines.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from ..core.hashing import high_entropy_ratio, printable_ratio
from ..core.model import Artifact, Finding
from .categorize import capabilities_from_categories, category_summary

Heuristic = Callable[[Artifact, bytes], List[Finding]]


def _f(fid: str, title: str, severity: str, score: int, detail: str = "", evidence=None, tags=None) -> Finding:
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        score=score,
        detail=detail,
        evidence=evidence or [],
        tags=tags or [],
        source="heuristic",
    )


def h_packed(art: Artifact, data: bytes) -> List[Finding]:
    """High entropy with few strings usually means packed or encrypted."""
    if len(data) < 4096:
        return []
    ratio = high_entropy_ratio(data, threshold=7.2)
    string_density = len(art.strings) / (len(data) / 1024) if data else 0
    out = []
    if ratio >= 0.6:
        out.append(
            _f(
                "HEUR_PACKED_ENTROPY",
                "Large high-entropy regions",
                "medium",
                20,
                f"{ratio:.0%} of 4 KiB windows exceed 7.2 bits/byte, typical of packing or encryption.",
                [f"high_entropy_ratio={ratio:.3f}", f"strings={len(art.strings)}"],
                ["packing", "evasion"],
            )
        )
    if len(data) > 65536 and string_density < 0.5:
        out.append(
            _f(
                "HEUR_LOW_STRING_DENSITY",
                "Very low string density in a large binary",
                "low",
                10,
                f"only {string_density:.2f} strings per KiB in a {len(data)}-byte file.",
                tags=["packing"],
            )
        )
    return out


def h_executable_writable_sections(art: Artifact, data: bytes) -> List[Finding]:
    """A section that is both writable and executable is a red flag."""
    hits = [s.name for s in art.sections if "W" in s.flags and "X" in s.flags]
    hits += [s.name for s in art.sections if "WRITE" in s.flags and "EXEC" in s.flags]
    if not hits:
        return []
    return [
        _f(
            "HEUR_WX_SECTION",
            "Writable and executable section",
            "high",
            25,
            "sections that are both writable and executable enable self-modifying or injected code.",
            evidence=sorted(set(hits))[:10],
            tags=["injection", "evasion"],
        )
    ]


def h_packers_by_section_name(art: Artifact, data: bytes) -> List[Finding]:
    known = {
        "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
        ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
        ".aspack": "ASPack", ".adata": "ASPack", ".nsp0": "NsPack",
        ".petite": "Petite", ".mpress1": "MPRESS", ".enigma1": "Enigma",
        ".boom": "Boom", "pec1": "PECompact", "fsg!": "FSG",
    }
    hits = []
    for s in art.sections:
        key = s.name.lower()
        if key in known:
            hits.append(f"{s.name} ({known[key]})")
    if not hits:
        return []
    return [
        _f(
            "HEUR_PACKER_SECTION",
            "Known packer section names",
            "medium",
            18,
            "section names match a known executable packer.",
            evidence=hits,
            tags=["packing"],
        )
    ]


def h_capabilities(art: Artifact, data: bytes) -> List[Finding]:
    """Summarise import categories into capability findings."""
    names = [i.name for i in art.imports]
    if not names:
        return []
    counts = category_summary(names)
    art.stats["import_categories"] = counts
    capabilities = capabilities_from_categories(counts)
    art.stats["capabilities"] = capabilities
    out: List[Finding] = []

    weights = {
        "process_injection": ("Capable of process injection", "high", 30),
        "crypto": ("Uses cryptographic primitives", "low", 8),
        "network": ("Performs network communication", "medium", 12),
        "anti_analysis": ("Anti-analysis or evasion primitives", "medium", 14),
        "credential_access": ("Credential access primitives", "high", 22),
        "persistence": ("Persistence primitives", "medium", 16),
        "privilege": ("Privilege manipulation primitives", "medium", 12),
    }
    for category, (title, severity, score) in weights.items():
        if counts.get(category):
            out.append(
                _f(
                    f"HEUR_CAP_{category.upper()}",
                    title,
                    severity,
                    score,
                    f"{counts[category]} imports classified as '{category}'.",
                    evidence=[i.name for i in art.imports if i.category == category][:10],
                    tags=["capability", category],
                )
            )

    # Network + crypto together is a strong ransomware / C2 signal.
    if counts.get("network") and counts.get("crypto"):
        out.append(
            _f(
                "HEUR_NET_CRYPTO",
                "Network plus crypto combination",
                "high",
                20,
                "combining network I/O with encryption is characteristic of ransomware or encrypted C2.",
                tags=["ransomware", "c2"],
            )
        )
    return out


def h_anti_analysis_combo(art: Artifact, data: bytes) -> List[Finding]:
    names = {i.name.lower() for i in art.imports}
    markers = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "ptrace"}
    present = sorted(names & markers)
    if len(present) >= 1 and art.imports:
        return [
            _f(
                "HEUR_ANTIDEBUG",
                "Debugger detection",
                "medium",
                15,
                "the sample checks for a debugger, indicating evasion intent.",
                evidence=present,
                tags=["anti-analysis"],
            )
        ]
    return []


def h_script_indicators(art: Artifact, data: bytes) -> List[Finding]:
    info = art.metadata.get("script")
    if not info:
        return []
    out: List[Finding] = []
    patterns = info.get("suspicious_patterns", {})
    mapping = {
        "download_execute": ("Downloads and executes remote code", "critical", 35),
        "reverse_shell": ("Reverse shell pattern", "critical", 40),
        "destruction": ("Destructive command pattern", "critical", 40),
        "credential_theft": ("Credential theft pattern", "high", 30),
        "persistence": ("Persistence pattern", "medium", 18),
        "obfuscation": ("Obfuscated code", "medium", 20),
    }
    for key, (title, severity, score) in mapping.items():
        if patterns.get(key):
            out.append(
                _f(
                    f"HEUR_SCRIPT_{key.upper()}",
                    title,
                    severity,
                    score,
                    f"matched {len(patterns[key])} pattern(s) typical of {key.replace('_', ' ')}.",
                    evidence=patterns[key][:5],
                    tags=["script", key],
                )
            )
    obf = info.get("obfuscation_score", 0.0)
    if obf >= 0.4:
        out.append(
            _f(
                "HEUR_SCRIPT_OBFUSCATION_SCORE",
                "High obfuscation score",
                "medium",
                15,
                f"structural obfuscation score {obf:.2f} (encoding, long tokens, dense variable use).",
                tags=["script", "obfuscation"],
            )
        )
    return out


def h_indicators(art: Artifact, data: bytes) -> List[Finding]:
    ind = art.indicators
    out: List[Finding] = []
    if ind.get("crypto_wallets"):
        out.append(
            _f(
                "HEUR_WALLET",
                "Cryptocurrency wallet address present",
                "high",
                30,
                "embedded wallet addresses appear in ransom notes and extortion payloads.",
                evidence=ind["crypto_wallets"][:5],
                tags=["ransomware"],
            )
        )
    if len(ind.get("ipv4", [])) >= 3 and len(ind.get("urls", [])) >= 1:
        out.append(
            _f(
                "HEUR_C2_INFRA",
                "Multiple hardcoded network endpoints",
                "medium",
                15,
                "several IP addresses plus URLs suggest hardcoded command-and-control infrastructure.",
                evidence=(ind.get("ipv4", [])[:5] + ind.get("urls", [])[:3]),
                tags=["c2"],
            )
        )
    if ind.get("registry_keys"):
        out.append(
            _f(
                "HEUR_REGISTRY",
                "Registry keys referenced",
                "low",
                8,
                "registry references may indicate configuration or persistence.",
                evidence=ind["registry_keys"][:5],
                tags=["persistence"],
            )
        )
    onion = [u for u in ind.get("urls", []) if ".onion" in u] + [
        d for d in ind.get("domains", []) if d.endswith(".onion")
    ]
    if onion:
        out.append(
            _f(
                "HEUR_TOR",
                "Tor hidden service reference",
                "high",
                25,
                "references to .onion addresses indicate anonymised infrastructure.",
                evidence=onion[:5],
                tags=["tor", "c2"],
            )
        )
    return out


def h_anomalies(art: Artifact, data: bytes) -> List[Finding]:
    out: List[Finding] = []
    ratio = printable_ratio(data)
    if len(data) > 1024 and ratio > 0.98:
        out.append(
            _f(
                "HEUR_MOSTLY_PRINTABLE",
                "File is almost entirely printable",
                "info",
                5,
                f"{ratio:.1%} of bytes are printable; this looks like a text artefact rather than a compiled binary.",
                tags=["text"],
            )
        )
    # Overlay: data appended past the last section, common for droppers.
    if art.sections:
        last = max((s.offset + s.size) for s in art.sections if s.size)
        if last and len(data) - last > 4096:
            out.append(
                _f(
                    "HEUR_OVERLAY",
                    "Data appended after the last section",
                    "low",
                    10,
                    f"{len(data) - last} bytes of overlay, which can hide embedded payloads.",
                    evidence=[f"overlay_size={len(data) - last}"],
                    tags=["overlay"],
                )
            )
    if art.errors:
        out.append(
            _f(
                "HEUR_PARSE_ERRORS",
                "Structural parse errors",
                "info",
                3,
                "the file could not be fully parsed, which is itself suspicious for a genuine sample.",
                evidence=art.errors[:5],
                tags=["malformed"],
            )
        )
    return out


def h_rule_pressure(art: Artifact, data: bytes) -> List[Finding]:
    """Escalate when many independent low/medium findings agree."""
    substantive = [f for f in art.findings if f.severity in ("medium", "high", "critical")]
    if len(substantive) >= 4:
        return [
            _f(
                "HEUR_CORROBORATION",
                "Multiple independent signals corroborate",
                "high",
                15,
                f"{len(substantive)} independent medium-or-higher findings agree on this sample.",
                evidence=[f.title for f in substantive][:8],
                tags=["corroboration"],
            )
        ]
    return []


HEURISTICS: List[Heuristic] = [
    h_packed,
    h_executable_writable_sections,
    h_packers_by_section_name,
    h_capabilities,
    h_anti_analysis_combo,
    h_script_indicators,
    h_indicators,
    h_anomalies,
    h_rule_pressure,
]


def run(art: Artifact, data: bytes, extra: List[Heuristic] | None = None) -> List[Finding]:
    """Run all heuristics and attach the findings to the artifact."""
    produced: List[Finding] = []
    for fn in list(HEURISTICS) + list(extra or []):
        try:
            produced.extend(fn(art, data))
        except Exception as exc:
            art.errors.append(f"heuristic {fn.__name__} failed: {exc.__class__.__name__}: {exc}")
    for f in produced:
        art.add_finding(f)
    return produced


def summary(art: Artifact) -> Dict[str, object]:
    return {
        "verdict": art.verdict,
        "risk_score": art.risk_score,
        "finding_count": len(art.findings),
        "by_severity": {k: len(v) for k, v in art.findings_by_severity().items()},
        "capabilities": art.stats.get("capabilities", []),
    }

"""Parser for interpreted content: shell, PowerShell, Python, JS, PHP.

Scripts are a first-class malware delivery format, so REA treats them as
parseable rather than as opaque text. The parser records structural facts that
the scoring engine and rule engine can key on.
"""

from __future__ import annotations

import re

from ..core.model import Artifact

SUSPICIOUS_PATTERNS = {
    "download_execute": [
        r"(?i)curl\s+[^\n|]*\|\s*(?:ba|z|d)?sh",
        r"(?i)wget\s+[^\n|]*\|\s*(?:ba|z|d)?sh",
        r"(?i)Invoke-WebRequest[^\n]*(?:Invoke-Expression|iex)",
        r"(?i)IEX\s*\(\s*New-Object\s+Net\.WebClient",
        r"(?i)DownloadString\(",
        r"(?i)DownloadFile\(",
        r"(?i)certutil\s+-urlcache",
        r"(?i)bitsadmin\s+/transfer",
    ],
    "obfuscation": [
        r"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}",
        r"(?i)FromBase64String",
        r"(?i)eval\s*\(\s*(?:base64|atob)",
        r"(?i)exec\s*\(\s*bytes\.fromhex",
        r"(?i)String\.fromCharCode",
        r"\$\([A-Za-z_]\w*\)",  # shell variable-in-command obfuscation
        r"(?i)\bchr\s*\(\s*\d+\s*\)\s*\+",
    ],
    "reverse_shell": [
        r"(?i)/dev/tcp/",
        r"(?i)ncat?\s+.*-e\s+/bin/(?:ba)?sh",
        r"(?i)socat\s+exec:",
        r"(?i)bash\s+-i\s+>&\s*/dev/tcp",
        r"(?i)New-Object\s+System\.Net\.Sockets\.TCPClient",
    ],
    "persistence": [
        r"(?i)schtasks\s+/create",
        r"(?i)reg\s+add\s+.*\\Run",
        r"(?i)crontab\s+-",
        r"(?i)/etc/rc\.local",
        r"(?i)New-Service",
        r"(?i)\.bashrc|\.profile|\.zshrc",
        r"(?i)LaunchAgents|LaunchDaemons",
    ],
    "credential_theft": [
        r"(?i)/etc/shadow",
        r"(?i)\.ssh/id_rsa",
        r"(?i)Login\s+Data",
        r"(?i)mimikatz",
        r"(?i)lsass",
        r"(?i)wallet\.dat",
    ],
    "destruction": [
        r"(?i)rm\s+-rf\s+/\s*$",
        r"(?i):\(\)\s*\{.*\};:",  # fork bomb
        r"(?i)dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/",
        r"(?i)vssadmin\s+delete\s+shadows",
        r"(?i)wbadmin\s+delete\s+catalog",
    ],
}

SHEBANG_INTERPRETERS = {
    "sh": "shell", "bash": "shell", "dash": "shell", "zsh": "shell", "ksh": "shell",
    "python": "python", "python2": "python", "python3": "python",
    "perl": "perl", "ruby": "ruby", "node": "javascript", "php": "php",
    "pwsh": "powershell",
}


def parse(art: Artifact, data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    art.metadata["script"] = {
        "lines": text.count("\n") + 1,
        "characters": len(text),
        "shebang": "",
        "interpreter": _guess_interpreter(text, art),
        "obfuscation_score": 0.0,
    }

    if text.startswith("#!"):
        first = text.splitlines()[0]
        art.metadata["script"]["shebang"] = first[:200]

    matches = {}
    for label, patterns in SUSPICIOUS_PATTERNS.items():
        hits = []
        for pat in patterns:
            try:
                m = re.search(pat, text)
            except re.error:
                continue
            if m:
                hits.append(m.group(0)[:160])
        if hits:
            matches[label] = hits
    art.metadata["script"]["suspicious_patterns"] = matches

    art.metadata["script"]["obfuscation_score"] = _obfuscation_score(text)


def _guess_interpreter(text: str, art: Artifact) -> str:
    if text.startswith("#!"):
        parts = text.splitlines()[0][2:].split()
        for p in parts:
            base = p.rsplit("/", 1)[-1]
            if base in SHEBANG_INTERPRETERS:
                return SHEBANG_INTERPRETERS[base]
            if base == "env" and len(parts) > 1:
                nxt = parts[parts.index(p) + 1] if parts.index(p) + 1 < len(parts) else ""
                if nxt in SHEBANG_INTERPRETERS:
                    return SHEBANG_INTERPRETERS[nxt]
    ext = art.path.rsplit(".", 1)[-1].lower() if "." in art.path else ""
    return {
        "ps1": "powershell", "psm1": "powershell", "bat": "batch", "cmd": "batch",
        "vbs": "vbscript", "js": "javascript", "py": "python", "sh": "shell",
        "php": "php", "pl": "perl", "rb": "ruby",
    }.get(ext, "unknown")


def _obfuscation_score(text: str) -> float:
    """Heuristic 0.0-1.0 score for how obfuscated a script looks."""
    if not text:
        return 0.0
    signals = 0.0
    signals += min(1.0, text.count("\\x") / 20)
    signals += min(1.0, len(re.findall(r"[A-Za-z0-9+/=]{80,}", text)) / 3)
    signals += min(1.0, text.count("^") / 20) if "cmd" in text.lower()[:200] else 0.0
    signals += min(1.0, len(re.findall(r"\$[A-Za-z_]\w*\s*=", text)) / 50)
    avg_line = len(text) / max(1, text.count("\n") + 1)
    signals += min(1.0, max(0.0, (avg_line - 200) / 800))
    return round(min(1.0, signals / 4), 4)

"""Indicator of Compromise (IOC) harvesting from extracted strings and bytes.

Indicators are deduplicated, normalised and grouped by type so they can be
dropped straight into a blocklist or pushed to the Hermes platform.
"""

from __future__ import annotations

import base64
import re
from typing import Dict, List

URL_RE = re.compile(r"\b(?:https?|ftp|tcp|udp|wss?)://[^\s\"'<>\)\]\}]{4,300}", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|cc|tk|ml|ga|gq|onion|su|pw|club|online|site|shop|live|dev|app|me|co|id|my|sg|jp|kr|de|uk|br|in|au)\b", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
REGISTRY_RE = re.compile(r"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[^\s\"'<>|]{1,120})+")
WINPATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]{1,80}\\){0,8}[^\\/:*?\"<>|\r\n]{1,80}")
UNIXPATH_RE = re.compile(r"(?<![\w./])/(?:etc|tmp|var|usr|home|opt|root|dev|proc|bin|sbin|lib)(?:/[\w.\-]{1,60}){0,8}")
MUTEX_RE = re.compile(r"(?i)\b(?:Global|Local)\\[A-Za-z0-9_\-{}]{4,80}\b")
USERAGENT_RE = re.compile(r"\bMozilla/\d\.\d[^\r\n\"']{0,120}")
CRYPTO_KEYWORDS = re.compile(r"(?i)\b(?:encrypt|decrypt|ransom|bitcoin|monero|wallet|AES-?\d{3}|private[_ ]key)\b")
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

BENIGN_DOMAINS = {
    "schemas.microsoft.com", "www.w3.org", "example.com", "localhost",
    "schemas.openxmlformats.org", "purl.org", "ns.adobe.com", "xml.apache.org",
}


def extract(texts: List[str], raw: bytes = b"", limits: int = 200) -> Dict[str, List[str]]:
    """Return indicators grouped by type."""
    joined = "\n".join(texts)
    out: Dict[str, List[str]] = {}

    urls = _dedupe(URL_RE.findall(joined), limits)
    out["urls"] = urls

    domains = []
    for d in DOMAIN_RE.findall(joined):
        d = d.lower().rstrip(".")
        if d in BENIGN_DOMAINS or _is_ip(d):
            continue
        domains.append(d)
    out["domains"] = _dedupe(domains, limits)

    ips = [ip for ip in _dedupe(IPV4_RE.findall(joined), limits) if not _is_private_ip(ip)]
    out["ipv4"] = ips

    out["emails"] = _dedupe(EMAIL_RE.findall(joined), limits)
    out["registry_keys"] = _dedupe(REGISTRY_RE.findall(joined), limits)
    out["windows_paths"] = _dedupe(WINPATH_RE.findall(joined), limits)
    out["unix_paths"] = _dedupe(UNIXPATH_RE.findall(joined), limits)
    out["mutexes"] = _dedupe(MUTEX_RE.findall(joined), limits)
    out["user_agents"] = _dedupe(USERAGENT_RE.findall(joined), limits)

    # Financial indicators: very high signal for ransomware triage.
    wallets = []
    for rx, label in ((BTC_RE, "btc"), (XMR_RE, "xmr"), (ETH_RE, "eth")):
        for w in rx.findall(joined):
            if rx is BTC_RE and not _valid_btc(w):
                continue
            wallets.append(f"{label}:{w}")
    out["crypto_wallets"] = _dedupe(wallets, 50)

    hashes = _dedupe(SHA256_RE.findall(joined), 50)
    out["embedded_sha256"] = hashes
    out["embedded_md5"] = _dedupe(MD5_RE.findall(joined), 50)

    # Base64 blobs that decode to something meaningful are worth flagging.
    blobs = []
    for b in BASE64_RE.findall(joined)[:50]:
        decoded = _try_b64(b)
        if decoded:
            blobs.append(decoded[:120])
    out["base64_blobs"] = _dedupe(blobs, 25)

    if raw:
        out["urls"] = _dedupe(out["urls"] + _urls_from_bytes(raw), limits)

    return {k: v for k, v in out.items() if v}


def all_values(indicators: Dict[str, List[str]]) -> List[str]:
    flat: List[str] = []
    for values in indicators.values():
        flat.extend(values)
    return flat


def _urls_from_bytes(raw: bytes) -> List[str]:
    text = raw.decode("latin-1", "replace")
    return URL_RE.findall(text)


def _dedupe(values: List[str], limit: int) -> List[str]:
    seen = set()
    out = []
    for v in values:
        v = v.strip().rstrip(".,;)\"'")
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _try_b64(blob: str) -> str:
    padded = blob + "=" * (-len(blob) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        return ""
    if len(decoded) < 12:
        return ""
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(decoded) < 0.85:
        return ""
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.decode("latin-1", "replace")


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value))


def _is_private_ip(ip: str) -> bool:
    try:
        a, b, *_ = (int(p) for p in ip.split("."))
    except ValueError:
        return False
    if a in (10, 127, 0):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a >= 224:
        return True
    return False


def _valid_btc(value: str) -> bool:
    """Reject obvious false positives such as long hex runs."""
    if len(value) < 26:
        return False
    if re.fullmatch(r"[a-f0-9]+", value):
        return False
    return True

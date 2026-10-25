"""Hashing, entropy and byte-level statistics.

All pure-stdlib. Hashes are streamed in chunks so multi-hundred-megabyte
samples do not blow up memory during triage.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

CHUNK = 1 << 20  # 1 MiB


@dataclass
class Hashes:
    md5: str
    sha1: str
    sha256: str
    ssdeep_like: str = ""

    def to_dict(self) -> dict:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "ssdeep_like": self.ssdeep_like,
        }


def hash_bytes(data: bytes) -> Hashes:
    return Hashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        ssdeep_like=fuzzy_hash(data),
    )


def hash_file(path: str) -> Hashes:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    buf = bytearray()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            if len(buf) < 1 << 20:
                buf.extend(chunk)
    return Hashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        ssdeep_like=fuzzy_hash(bytes(buf)),
    )


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def entropy_windows(data: bytes, window: int = 4096, step: int = 2048) -> List[dict]:
    """Sliding-window entropy, used to spot packed or encrypted regions."""
    out: List[dict] = []
    if len(data) < window:
        return [{"offset": 0, "length": len(data), "entropy": round(entropy(data), 4)}]
    for off in range(0, len(data) - window + 1, step):
        out.append(
            {
                "offset": off,
                "length": window,
                "entropy": round(entropy(data[off : off + window]), 4),
            }
        )
    return out


def high_entropy_ratio(data: bytes, threshold: float = 7.2, window: int = 4096) -> float:
    """Fraction of windows whose entropy exceeds ``threshold``."""
    wins = entropy_windows(data, window=window, step=window)
    if not wins:
        return 0.0
    high = sum(1 for w in wins if w["entropy"] >= threshold)
    return high / len(wins)


def byte_histogram(data: bytes) -> Dict[int, int]:
    counts = Counter(data)
    return {b: counts.get(b, 0) for b in range(256)}


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def null_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.count(0) / len(data)


def fuzzy_hash(data: bytes) -> str:
    """A cheap ssdeep-like context triggered piecewise hash.

    This is intentionally a simplified local implementation: it gives stable,
    comparable digests for near-duplicate detection without an external
    dependency. It is NOT byte-compatible with ssdeep.
    """
    if not data:
        return "0::"

    block = 64
    while block * 64 < len(data):
        block *= 2

    pieces: List[int] = []
    h = 0
    window: List[int] = []
    for b in data:
        window.append(b)
        h = (h * 31 + b) & 0xFFFFFFFF
        if len(window) >= 7:
            h = (h ^ (window[-7] * 7)) & 0xFFFFFFFF
        if h % block == block - 1 and len(pieces) < 64:
            pieces.append(h & 0x3F)
            h = 0
    if not pieces:
        pieces = [h & 0x3F]

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return f"{block}:" + "".join(alphabet[p] for p in pieces[:64])


def hamming_fuzzy(a: str, b: str) -> int:
    """Compare two fuzzy hashes; lower score means more similar."""
    try:
        ba, _, ha = a.partition(":")
        bb, _, hb = b.partition(":")
        score = abs(int(ba) - int(bb)) * 100
    except ValueError:
        return 100
    if len(ha) != len(hb):
        score += abs(len(ha) - len(hb)) * 2
    score += sum(1 for x, y in zip(ha, hb) if x != y)
    return score

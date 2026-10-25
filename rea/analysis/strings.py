"""String extraction for both ASCII and UTF-16LE text.

Malware commonly stores configuration, C2 endpoints and mutexes as UTF-16
strings, so scanning only ASCII misses a lot. REA extracts both encodings and
keeps the byte offset of each hit so findings can point back into the file.
"""

from __future__ import annotations

import re
from typing import List, Tuple

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
# UTF-16LE: printable char followed by a null byte, repeated.
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

MAX_STRINGS = 20000
MAX_STRING_LEN = 4096


def extract(data: bytes, min_len: int = 4, limit: int = MAX_STRINGS) -> List[str]:
    """Return unique strings, ASCII first, ordered by first appearance."""
    seen = set()
    out: List[str] = []
    for value, _off in extract_with_offsets(data, min_len=min_len, limit=limit):
        if value not in seen:
            seen.add(value)
            out.append(value)
            if len(out) >= limit:
                break
    return out


def extract_with_offsets(
    data: bytes, min_len: int = 4, limit: int = MAX_STRINGS
) -> List[Tuple[str, int]]:
    results: List[Tuple[str, int]] = []

    for m in ASCII_RE.finditer(data):
        s = m.group(0)
        if len(s) < min_len:
            continue
        results.append((s[:MAX_STRING_LEN].decode("ascii", "replace"), m.start()))
        if len(results) >= limit:
            return results

    for m in UTF16_RE.finditer(data):
        raw = m.group(0)
        s = raw.decode("utf-16-le", "replace").rstrip("\x00")
        if len(s) < min_len:
            continue
        results.append((s[:MAX_STRING_LEN], m.start()))
        if len(results) >= limit:
            break

    results.sort(key=lambda t: t[1])
    return results


def interesting(strings: List[str], patterns: List[str], limit: int = 100) -> List[str]:
    """Filter strings against a list of regexes, preserving order."""
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            continue
    out = []
    for s in strings:
        if any(c.search(s) for c in compiled):
            out.append(s)
            if len(out) >= limit:
                break
    return out

"""Load an artifact and drive the format-specific parsers over it."""

from __future__ import annotations

from typing import Callable, List

from .model import Artifact

ParserFn = Callable[[Artifact, bytes], None]


def _parser_table() -> dict:
    from ..parsers import elf, macho, pe, scripts

    return {
        "elf": elf.parse,
        "pe": pe.parse,
        "macho": macho.parse,
        "script": scripts.parse,
        "text": scripts.parse,
    }


def load(path: str, max_bytes: int = 256 << 20) -> Artifact:
    """Read ``path`` into an :class:`Artifact` without running any parser."""
    return Artifact.load(path, max_bytes=max_bytes)


def load_and_parse(path: str, max_bytes: int = 256 << 20) -> Artifact:
    """Read and parse a file, enriching the artifact with format metadata."""
    art = Artifact.load(path, max_bytes=max_bytes)
    data = _read(path, max_bytes)
    parse(art, data)
    return art


def _read(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(max_bytes)


def parse(art: Artifact, data: bytes) -> Artifact:
    """Run the parser matching the detected format. Unknown formats are fine."""
    kind = art.file_type.kind if art.file_type else "data"
    fn: ParserFn | None = _parser_table().get(kind)
    if fn is None:
        return art
    try:
        fn(art, data)
    except Exception as exc:  # a malformed sample must never abort a scan
        art.errors.append(f"parser '{kind}' failed: {exc.__class__.__name__}: {exc}")
    return art

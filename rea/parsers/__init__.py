"""Format-specific parsers.

Each module exposes ``parse(artifact, data) -> None`` and mutates the artifact
in place, adding sections, imports, exports and metadata. Parsers must never
raise on malformed input; the loader wraps them defensively but they are also
written to fail soft internally.
"""

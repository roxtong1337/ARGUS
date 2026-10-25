"""Registry so integrations are discoverable by name from the CLI.

Adapters register themselves on import. ``available()`` triggers discovery of
the built-in modules exactly once, and third-party code can call
:func:`register` to add its own without touching this package.
"""

from __future__ import annotations

from typing import Dict, List, Type

from .base import Integration

_REGISTRY: Dict[str, Type[Integration]] = {}
_DISCOVERED = False


def register(cls: Type[Integration]) -> Type[Integration]:
    """Class decorator that adds an integration to the registry."""
    key = getattr(cls, "name", None)
    if not key:
        raise ValueError(f"{cls.__name__} must define a 'name' attribute")
    _REGISTRY[key] = cls
    return cls


def _discover() -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return
    _DISCOVERED = True
    # Import for side effects (registration). Keep failures non-fatal so a
    # partially installed environment still works.
    for module in ("local", "stdout", "http", "webhook", "hermes"):
        try:
            __import__(f"{__package__}.{module}")
        except Exception:
            continue


def get(name: str) -> Type[Integration]:
    _discover()
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown integration {name!r}; available: {known}")
    return _REGISTRY[name]


def create(name: str, config: dict | None = None) -> Integration:
    return get(name)(config or {})


def available() -> List[str]:
    _discover()
    return sorted(_REGISTRY)


def describe_all() -> List[dict]:
    _discover()
    return [cls({}).describe() for _, cls in sorted(_REGISTRY.items())]

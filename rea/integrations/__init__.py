"""Pluggable integrations: ship REA results somewhere else.

The integration layer is deliberately small and dependency-free. Every
integration implements :class:`Integration` and is registered by name, so adding
a new destination (Hermes, MISP, TheHive, a SIEM, a Slack webhook) means adding
one module and one ``@register`` decorator - no changes to the core.

Configuration comes from a plain dict so it can be sourced from CLI flags,
environment variables or a config file without the adapters caring.
"""

from __future__ import annotations

from .base import Integration, IntegrationError, IntegrationResult
from .registry import available, create, describe_all, get, register

__all__ = [
    "Integration",
    "IntegrationError",
    "IntegrationResult",
    "available",
    "create",
    "describe_all",
    "get",
    "register",
]

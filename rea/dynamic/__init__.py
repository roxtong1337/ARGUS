"""Dynamic analysis: run a sample in a sandbox and observe what it does.

This is the part static analysis cannot give you. A packed sample with no
readable strings still has to call ``connect()``, ``execve()`` and
``unlink()`` when it runs, and those calls are the behaviour.

Safety is not optional here, so the design is deliberately constrained:

* every sample runs inside a container, never on the host;
* the container has **no network**, **no capabilities**, a **PID limit**, a
  **memory limit** and a **wall-clock timeout**;
* the sample is mounted read-only and executed as an unprivileged user;
* the sandbox backend is pluggable, so an environment without a container
  runtime reports that clearly instead of silently running something unsafe.

The runner produces *telemetry*: a structured list of syscall-derived events.
:mod:`rea.dynamic.behaviors` turns that into findings that feed the same scoring
engine the static side uses.
"""

from __future__ import annotations

from .backends import BackendError, SandboxBackend, get_backend, list_backends
from .behaviors import analyse_telemetry
from .runner import DetonationResult, Detonator
from .telemetry import Event, Telemetry, parse_strace

__all__ = [
    "BackendError",
    "DetonationResult",
    "Detonator",
    "Event",
    "SandboxBackend",
    "Telemetry",
    "analyse_telemetry",
    "get_backend",
    "list_backends",
    "parse_strace",
]

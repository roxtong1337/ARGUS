"""The detonator: orchestrate one sandboxed execution and collect telemetry.

Policy lives here so the backend stays a dumb executor. The runner decides what
to trace, how long to allow, what limits to apply, and how to turn a raw
execution result into a :class:`Telemetry`.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core.model import Artifact, Finding
from .backends import BackendError, ExecutionResult, get_backend
from .behaviors import analyse_telemetry
from .telemetry import Telemetry, parse_strace

# A curated trace set. Tracing everything drowns the log in memory-management
# noise; these are the syscalls that describe behaviour.
TRACE_SYSCALLS = ",".join(
    [
        "execve", "execveat", "clone", "clone3", "fork", "vfork",
        "openat", "open", "creat",
        "unlink", "unlinkat", "rename", "renameat", "mkdir", "mkdirat",
        "chmod", "fchmodat", "chown",
        "socket", "connect", "bind", "listen", "accept",
        "sendto", "recvfrom", "sendmsg", "recvmsg",
        "ptrace", "prctl", "kill", "tkill",
        "setuid", "setgid", "setresuid",
        "mount", "umount2", "pivot_root", "chroot",
        "init_module", "finit_module", "delete_module",
        "mprotect", "memfd_create",
        "symlink", "symlinkat", "link", "linkat",
        "truncate", "ftruncate",
    ]
)

MARKERS = {
    "meta": "@@REA_META",
    "stdout": "@@REA_STDOUT",
    "stderr": "@@REA_STDERR",
    "trace": "@@REA_TRACE",
}

# Containers cannot execute Windows or macOS binaries.
RUNNABLE_KINDS = {"elf", "script", "text", "data"}


@dataclass
class DetonationResult:
    """Outcome of one detonation attempt."""

    ok: bool
    backend: str
    isolated: bool
    telemetry: Optional[Telemetry] = None
    findings: List[Finding] = field(default_factory=list)
    error: str = ""
    skipped_reason: str = ""
    execution: Optional[ExecutionResult] = None

    @property
    def executed(self) -> bool:
        return self.ok and self.telemetry is not None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "backend": self.backend,
            "isolated": self.isolated,
            "executed": self.executed,
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "telemetry": self.telemetry.to_dict() if self.telemetry else None,
            "findings": [f.to_dict() for f in self.findings],
        }


class Detonator:
    """Runs samples in a sandbox and reports what they did."""

    def __init__(
        self,
        backend: str = "docker",
        timeout: int = 20,
        memory_mb: int = 256,
        pids: int = 128,
        image: str = "rea-sandbox:latest",
        allow_unsafe: bool = False,
        keep_workdir: bool = False,
        extra_config: Optional[Dict] = None,
    ):
        self.backend_name = backend
        config: Dict = {"image": image, "allow_unsafe": allow_unsafe}
        config.update(extra_config or {})
        self.backend = get_backend(backend, config)
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.pids = pids
        self.keep_workdir = keep_workdir

    # ---- preflight -----------------------------------------------------

    def check(self) -> tuple:
        """Return ``(ready, reason)`` so callers can explain a refusal."""
        if not self.backend.available():
            if self.backend_name == "docker":
                return False, (
                    "docker backend not ready: the daemon is not reachable or the sandbox "
                    "image is missing. Build it with: docker build -t rea-sandbox:latest sandbox/"
                )
            return False, (
                f"backend {self.backend_name!r} is unavailable; the local backend requires "
                f"allow_unsafe=True and runs samples on the host"
            )
        return True, ""

    # ---- detonation ----------------------------------------------------

    def detonate(self, path: str, kind: str = "") -> DetonationResult:
        """Execute ``path`` in the sandbox and parse the resulting telemetry."""
        ready, reason = self.check()
        if not ready:
            return DetonationResult(
                ok=False, backend=self.backend_name,
                isolated=self.backend.isolated, error=reason,
            )

        if kind and kind not in RUNNABLE_KINDS:
            return DetonationResult(
                ok=False,
                backend=self.backend_name,
                isolated=self.backend.isolated,
                skipped_reason=(
                    f"format {kind!r} cannot be executed in a Linux sandbox; "
                    f"static analysis only for this sample"
                ),
            )

        if not os.path.isfile(path):
            return DetonationResult(
                ok=False, backend=self.backend_name,
                isolated=self.backend.isolated, error=f"no such file: {path}",
            )

        # The sample is bind-mounted read-only and executed by uid 1000 inside
        # the container, so it must be world-readable or the run fails with a
        # confusing EACCES in the trace instead of a clear message here.
        if not os.access(path, os.R_OK) or not (os.stat(path).st_mode & 0o044):
            return DetonationResult(
                ok=False, backend=self.backend_name, isolated=self.backend.isolated,
                error=(
                    f"{path} is not readable by the sandbox user; "
                    f"chmod 644 it (mode {oct(os.stat(path).st_mode & 0o777)})"
                ),
            )

        workdir = tempfile.mkdtemp(prefix="rea-detonation-")
        try:
            command = self._build_command()
            try:
                execution = self.backend.run(
                    command=command,
                    sample_path=path,
                    workdir=workdir,
                    timeout=self.timeout,
                    memory_mb=self.memory_mb,
                    pids=self.pids,
                )
            except BackendError as exc:
                return DetonationResult(
                    ok=False, backend=self.backend_name,
                    isolated=self.backend.isolated, error=str(exc),
                )

            telemetry = self._parse(execution)
            findings = analyse_telemetry(telemetry)
            return DetonationResult(
                ok=True,
                backend=self.backend_name,
                isolated=self.backend.isolated,
                telemetry=telemetry,
                findings=findings,
                execution=execution,
            )
        finally:
            if not self.keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)

    def _build_command(self) -> List[str]:
        """The in-container command: copy, run under strace, dump everything.

        The sample is mounted read-only at ``/sample/sample``. We copy it to the
        writable tmpfs, mark it executable, run it under ``strace`` with a hard
        timeout, then print the trace between markers so the host can parse it.

        Lines are joined with newlines rather than ``;`` because shell compound
        commands need explicit separators and a stray ``;`` bug is invisible once
        everything is on one line.
        """
        lines = [
            "set -u",
            "cp /sample/sample /work/sample.bin 2>/dev/null",
            "if [ ! -f /work/sample.bin ]; then echo 'REA_COPY_FAILED'; exit 90; fi",
            "chmod +x /work/sample.bin 2>/dev/null || true",
            f"timeout -s KILL {self.timeout} strace -f -qq -tt -s 256 "
            f"-e trace={TRACE_SYSCALLS} -o /work/trace.log /work/sample.bin "
            "> /work/out.txt 2> /work/err.txt",
            "RC=$?",
            f"echo '{MARKERS['meta']} RC='$RC",
            f"echo '{MARKERS['stdout']}'",
            "cat /work/out.txt 2>/dev/null || true",
            f"echo '{MARKERS['stderr']}'",
            "cat /work/err.txt 2>/dev/null || true",
            f"echo '{MARKERS['trace']}'",
            "cat /work/trace.log 2>/dev/null || true",
        ]
        return ["/bin/sh", "-c", "\n".join(lines)]

    def _parse(self, execution: ExecutionResult) -> Telemetry:
        sections = _split_markers(execution.stdout)
        trace_text = sections.get("trace", "")
        telemetry = parse_strace(trace_text)

        telemetry.stdout = sections.get("stdout", "")
        telemetry.stderr = sections.get("stderr", "")
        telemetry.duration_seconds = execution.duration_seconds
        telemetry.timed_out = execution.timed_out
        telemetry.killed_by_signal = execution.killed_by_signal
        telemetry.truncated = execution.truncated

        meta = sections.get("meta", "")
        rc = _extract_rc(meta)
        telemetry.exit_code = rc
        if rc == 137:
            telemetry.timed_out = True
            telemetry.notes.append(
                f"sample exceeded the {self.timeout}s wall-clock limit and was killed"
            )
        if "REA_COPY_FAILED" in execution.stdout:
            telemetry.notes.append("could not stage the sample inside the sandbox")

        if not telemetry.events:
            telemetry.notes.append(
                "no traced syscalls recorded; the sample may have exited immediately "
                "or requires an interpreter absent from the sandbox image"
            )
        return telemetry

    # ---- integration with the pipeline ---------------------------------

    def apply(self, artifact: Artifact) -> DetonationResult:
        """Detonate the artifact's file and attach findings to it."""
        kind = artifact.file_type.kind if artifact.file_type else ""
        result = self.detonate(artifact.path, kind=kind)

        artifact.stats["dynamic"] = {
            "attempted": True,
            "backend": result.backend,
            "isolated": result.isolated,
            "executed": result.executed,
            "error": result.error,
            "skipped_reason": result.skipped_reason,
        }
        if result.telemetry:
            artifact.stats["dynamic"]["telemetry"] = result.telemetry.to_dict()

        for finding in result.findings:
            artifact.add_finding(finding)
        return result


def _split_markers(text: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current: Optional[str] = None
    buffer: List[str] = []

    reverse = {v: k for k, v in MARKERS.items()}
    for line in text.splitlines():
        stripped = line.strip()
        matched = None
        for marker, key in reverse.items():
            if stripped.startswith(marker):
                matched = key
                if key == "meta":
                    sections["meta"] = stripped[len(marker):].strip()
                break
        if matched:
            if current is not None:
                sections[current] = "\n".join(buffer)
            current = None if matched == "meta" else matched
            buffer = []
            continue
        if current is not None:
            buffer.append(line)

    if current is not None:
        sections[current] = "\n".join(buffer)
    return sections


def _extract_rc(meta: str) -> Optional[int]:
    for token in meta.split():
        if token.startswith("RC="):
            try:
                return int(token[3:])
            except ValueError:
                return None
    return None

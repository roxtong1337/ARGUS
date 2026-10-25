"""Sandbox backends: how a sample actually gets executed, isolated.

The backend abstraction exists so REA can detonate safely wherever it is
deployed. A backend knows how to run a command inside an isolated environment
and return its output plus an exit status. The detonation *policy* (limits,
timeouts, what to trace) lives in the runner, not here.

Shipped backends:

``docker``
    Runs the sample in a locked-down container: no network, all capabilities
    dropped, ``no-new-privileges``, read-only sample mount, PID and memory
    limits. This is the default and the only one considered safe for a real
    sample.

``local``
    Runs the sample directly on the host with resource limits. **This is not a
    sandbox.** It exists so the pipeline can be tested in an environment with no
    container runtime, and it refuses to run unless explicitly forced.

Neither backend is ever selected silently: if the requested backend is
unavailable, :func:`get_backend` raises :class:`BackendError` rather than
falling back to something weaker.
"""

from __future__ import annotations

import abc
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class BackendError(RuntimeError):
    """Raised when a backend cannot be used or cannot run a sample."""


@dataclass
class ExecutionResult:
    """Raw result of running a command in a backend."""

    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    killed_by_signal: str = ""
    truncated: bool = False
    notes: List[str] = field(default_factory=list)
    command: List[str] = field(default_factory=list)


class SandboxBackend(abc.ABC):
    """Contract every execution backend implements."""

    name: str = "backend"
    description: str = ""
    #: True only for backends that provide real isolation.
    isolated: bool = False

    def __init__(self, config: Optional[Dict] = None):
        self.config: Dict = dict(config or {})

    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this backend can run right now."""

    @abc.abstractmethod
    def run(
        self,
        command: List[str],
        sample_path: str,
        workdir: str,
        timeout: int,
        memory_mb: int,
        pids: int,
    ) -> ExecutionResult:
        """Execute ``command`` with ``sample_path`` available to it."""

    def describe(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "isolated": self.isolated,
            "available": self.available(),
        }

    @staticmethod
    def _run_process(cmd: List[str], timeout: int, env: Optional[Dict] = None) -> ExecutionResult:
        """Run a host process, capturing output and enforcing a timeout."""
        start = time.time()
        timed_out = False
        truncated = False
        killed_by_signal = ""
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
                check=False,
            )
            exit_code: Optional[int] = proc.returncode
            stdout = proc.stdout.decode("utf-8", "replace")
            stderr = proc.stderr.decode("utf-8", "replace")
            if exit_code is not None and exit_code < 0:
                killed_by_signal = f"signal {-exit_code}"
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = None
            stdout = (exc.stdout or b"").decode("utf-8", "replace")
            stderr = (exc.stderr or b"").decode("utf-8", "replace")
        except OSError as exc:
            raise BackendError(f"cannot execute backend command: {exc}") from exc

        max_output = 4 << 20
        if len(stdout) > max_output or len(stderr) > max_output:
            truncated = True
            stdout = stdout[:max_output]
            stderr = stderr[:max_output]

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.time() - start,
            timed_out=timed_out,
            killed_by_signal=killed_by_signal,
            truncated=truncated,
            command=cmd,
        )


class DockerBackend(SandboxBackend):
    """Runs the sample inside a locked-down container."""

    name = "docker"
    description = "Isolated container: no network, no capabilities, resource limits."
    isolated = True

    @property
    def image(self) -> str:
        return str(self.config.get("image", "rea-sandbox:latest"))

    def _docker_cmd(self) -> List[str]:
        # Prefer a direct call; fall back to sudo when the socket needs it.
        if self.config.get("sudo") is True:
            return ["sudo", "docker"]
        if self.config.get("sudo") is False:
            return ["docker"]
        return ["docker"] if os.access("/var/run/docker.sock", os.W_OK) else ["sudo", "docker"]

    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            proc = subprocess.run(
                self._docker_cmd() + ["image", "inspect", self.image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def run(
        self,
        command: List[str],
        sample_path: str,
        workdir: str,
        timeout: int,
        memory_mb: int,
        pids: int,
    ) -> ExecutionResult:
        if not self.available():
            raise BackendError(
                f"docker backend unavailable (daemon down, or image {self.image!r} not built). "
                f"Build it with: docker build -t {self.image} sandbox/"
            )

        sample_abs = os.path.abspath(sample_path)
        work_abs = os.path.abspath(workdir)
        os.makedirs(work_abs, exist_ok=True)

        # tmpfs mounts are root-owned by default, so the unprivileged analysis
        # user could not write to them. Claim them for that uid explicitly.
        uid = int(self.config.get("uid", 1000))
        gid = int(self.config.get("gid", 1000))

        docker = self._docker_cmd() + [
            "run",
            "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(pids),
            "--memory", f"{memory_mb}m",
            "--memory-swap", f"{memory_mb}m",
            "--cpus", str(self.config.get("cpus", 1)),
            "--read-only",
            # /work must be executable so the staged sample can run. /tmp stays
            # noexec on purpose: the sample can still write a dropped payload
            # there, and a blocked execve is itself observable evidence.
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size=64m,uid={uid},gid={gid}",
            "--tmpfs", f"/work:rw,exec,nosuid,size=64m,uid={uid},gid={gid}",
            "-v", f"{sample_abs}:/sample/sample:ro",
            "-w", "/work",
            self.image,
        ] + command

        # The container's own timeout is the safety net; the host timeout is
        # slightly longer so we see the container's own diagnostics first.
        return self._run_process(docker, timeout=timeout + 15)


class LocalBackend(SandboxBackend):
    """Runs the sample directly on the host. NOT a sandbox.

    Only for pipeline testing in environments with no container runtime. It
    requires ``allow_unsafe=True`` because running unknown code on the host is
    exactly the thing REA is supposed to prevent.
    """

    name = "local"
    description = "Runs on the host with rlimits. NOT isolated; requires allow_unsafe."
    isolated = False

    def available(self) -> bool:
        return bool(self.config.get("allow_unsafe", False))

    def run(
        self,
        command: List[str],
        sample_path: str,
        workdir: str,
        timeout: int,
        memory_mb: int,
        pids: int,
    ) -> ExecutionResult:
        if not self.available():
            raise BackendError(
                "the 'local' backend runs samples on the host and is disabled by default. "
                "Pass allow_unsafe=True only on a disposable machine."
            )
        os.makedirs(workdir, exist_ok=True)

        def _limit():
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_NPROC, (pids, pids))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        start = time.time()
        try:
            proc = subprocess.run(
                command,
                cwd=workdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                preexec_fn=_limit,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                exit_code=None,
                stdout=(exc.stdout or b"").decode("utf-8", "replace"),
                stderr=(exc.stderr or b"").decode("utf-8", "replace"),
                duration_seconds=time.time() - start,
                timed_out=True,
                command=command,
                notes=["local backend: host timeout reached"],
            )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout.decode("utf-8", "replace"),
            stderr=proc.stderr.decode("utf-8", "replace"),
            duration_seconds=time.time() - start,
            command=command,
        )


_BACKENDS = {
    DockerBackend.name: DockerBackend,
    LocalBackend.name: LocalBackend,
}


def get_backend(name: str, config: Optional[Dict] = None) -> SandboxBackend:
    if name not in _BACKENDS:
        # An unknown name is a caller mistake, not a runtime failure, so it is
        # a ValueError; BackendError is reserved for a backend that exists but
        # cannot run.
        raise ValueError(
            f"unknown backend {name!r}; available: {', '.join(sorted(_BACKENDS))}"
        )
    return _BACKENDS[name](config)


def list_backends() -> List[Dict[str, object]]:
    return [cls({}).describe() for cls in _BACKENDS.values()]

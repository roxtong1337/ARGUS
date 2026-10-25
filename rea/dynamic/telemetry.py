"""Parse syscall traces into structured telemetry.

The parser is decoupled from the sandbox: it takes text shaped like ``strace``
output and returns a :class:`Telemetry`. That means the behaviour analysis is
unit-testable against captured logs with no container runtime present, and a
future backend (eBPF, ETW, a hypervisor agent) only has to produce the same event
shape.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# 1234  11:19:54.526426 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x7ffd...) = 0
# The pid and the -tt timestamp are both optional so the parser accepts plain
# strace output, strace -f output, and strace -f -tt output.
_CALL_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?"
    r"(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<ret>.+?)\s*$"
)

# Syscalls whose *attempt* is the interesting fact, regardless of the result.
# A blocked connect() still proves the sample tried to reach a host.
INTERESTING = {
    "execve", "execveat", "clone", "clone3", "fork", "vfork",
    "openat", "open", "openat2", "creat",
    "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat",
    "chmod", "chown", "fchmodat", "fchownat",
    "socket", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "ptrace", "prctl", "kill", "tkill", "tgkill",
    "setuid", "setgid", "seteuid", "setegid", "setresuid", "setresgid",
    "mount", "umount2", "pivot_root", "chroot",
    "init_module", "finit_module", "delete_module", "kexec_load",
    "mmap", "mprotect", "memfd_create",
    "ioctl", "setsockopt", "getsockopt",
    "symlink", "symlinkat", "link", "linkat",
    "utimensat", "truncate", "ftruncate",
    "dup2", "dup3", "pipe", "pipe2",
    "getrandom", "clock_nanosleep", "nanosleep",
    "inotify_add_watch", "fanotify_mark",
}

# openat flags that mean "write" rather than "read"
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")

_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_SOCKADDR_RE = re.compile(r'sin_addr=inet_addr\("([^"]+)"\)')
_SOCKADDR6_RE = re.compile(r'inet_pton\(AF_INET6,\s*"([^"]+)"')
_UNIX_PATH_RE = re.compile(r'sun_path="([^"]+)"')
_RET_ERR_RE = re.compile(r"^-1\s+(\w+)")
_RET_NUM_RE = re.compile(r"^(-?\d+)")

AT_VARIANTS = {
    "openat", "openat2", "unlinkat", "mkdirat", "renameat", "renameat2",
    "fchmodat", "fchownat", "symlinkat", "linkat", "faccessat", "newfstatat",
    "execveat", "utimensat",
}


@dataclass
class Event:
    """One observed syscall."""

    pid: int
    name: str
    args: str
    result: str
    failed: bool = False
    errno: str = ""
    strings: List[str] = field(default_factory=list)
    path: str = ""
    address: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "syscall": self.name,
            "path": self.path,
            "address": self.address,
            "failed": self.failed,
            "errno": self.errno,
            "result": self.result,
        }


@dataclass
class Telemetry:
    """Everything observed during one detonation."""

    events: List[Event] = field(default_factory=list)
    exit_code: Optional[int] = None
    timed_out: bool = False
    killed_by_signal: str = ""
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    notes: List[str] = field(default_factory=list)

    # ---- convenience views used by behaviours.py ----------------------

    def by_syscall(self, *names: str) -> List[Event]:
        wanted = set(names)
        return [e for e in self.events if e.name in wanted]

    def successful(self, *names: str) -> List[Event]:
        return [e for e in self.by_syscall(*names) if e.succeeded]

    def unique_paths(self, *names: str) -> List[str]:
        seen, out = set(), []
        for e in self.by_syscall(*names):
            if e.path and e.path not in seen:
                seen.add(e.path)
                out.append(e.path)
        return out

    def addresses(self) -> List[str]:
        seen, out = set(), []
        for e in self.by_syscall("connect", "sendto", "bind"):
            if e.address and e.address not in seen:
                seen.add(e.address)
                out.append(e.address)
        return out

    def counts(self) -> Dict[str, int]:
        return dict(Counter(e.name for e in self.events).most_common())

    def to_dict(self) -> dict:
        return {
            "event_count": len(self.events),
            "syscall_counts": self.counts(),
            "addresses": self.addresses(),
            "child_programs": sorted(
                {
                    (e.strings[0].rsplit("/", 1)[-1] if e.strings else "")
                    for e in self.by_syscall("execve")[1:]
                    if e.strings
                }
            ),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "killed_by_signal": self.killed_by_signal,
            "duration_seconds": round(self.duration_seconds, 3),
            "stdout": self.stdout[:8000],
            "stderr": self.stderr[:8000],
            "truncated": self.truncated,
            "notes": self.notes,
            "events": [e.to_dict() for e in self.events[:2000]],
        }


def parse_strace(text: str, base_pid: Optional[int] = None) -> Telemetry:
    """Turn raw ``strace`` output into a :class:`Telemetry`."""
    telemetry = Telemetry()
    root_pid = base_pid

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("---"):
            if any(sig in line for sig in ("SIGKILL", "SIGSEGV", "SIGABRT", "SIGILL")):
                telemetry.notes.append(line[:200])
            continue
        if "unfinished" in line or "<... " in line or "resumed" in line:
            continue

        match = _CALL_RE.match(line)
        if not match:
            continue

        name = match.group("name")
        if name not in INTERESTING:
            continue

        pid = int(match.group("pid")) if match.group("pid") else (root_pid or 0)
        if root_pid is None:
            root_pid = pid
        args = match.group("args")
        result = match.group("ret")

        event = Event(pid=pid, name=name, args=args, result=result)
        event.strings = [_unescape(s) for s in _STR_RE.findall(args)]

        failed_match = _RET_ERR_RE.match(result)
        if failed_match:
            event.failed = True
            event.errno = failed_match.group(1)
        elif not _RET_NUM_RE.match(result):
            event.failed = True

        event.path = _extract_path(name, args, event.strings)
        event.address = _extract_address(args)
        telemetry.events.append(event)

    return telemetry


def _extract_path(name: str, args: str, strings: List[str]) -> str:
    """Best-effort extraction of the filesystem path an event refers to."""
    if name in ("renameat", "renameat2", "symlinkat", "linkat"):
        return " -> ".join(strings[:2]) if len(strings) >= 2 else (strings[0] if strings else "")
    if name in ("execve", "execveat"):
        return strings[0] if strings else ""
    if name == "mount":
        return strings[1] if len(strings) > 1 else (strings[0] if strings else "")
    if name in AT_VARIANTS:
        # For the *at variants the path is the first string after the dirfd.
        return strings[0] if strings else ""
    return strings[0] if strings else ""


def _extract_address(args: str) -> str:
    for regex in (_SOCKADDR_RE, _SOCKADDR6_RE, _UNIX_PATH_RE):
        m = regex.search(args)
        if m:
            return m.group(1)
    return ""


def is_write_open(args: str) -> bool:
    return any(flag in args for flag in WRITE_FLAGS)


def _unescape(value: str) -> str:
    out = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(nxt, nxt))
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)

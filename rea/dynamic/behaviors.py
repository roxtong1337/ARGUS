"""Turn observed behaviour into findings.

This is where the dynamic side plugs into the same scoring engine as the static
side: a :class:`~rea.core.model.Finding` produced here is indistinguishable from
one produced by a rule or a heuristic, so verdicts, reports and the Hermes
payload all work unchanged.

Design notes:

* An *attempted* syscall counts. A blocked ``connect()`` returning
  ``EACCES`` or ``ENETUNREACH`` still proves intent, so most checks look at
  attempts and only a few require success.
* Deliberately noisy syscalls (``mmap``, ``mprotect``) are never findings on
  their own; they only contribute to compound signals such as a
  write-then-execute memory pattern.
* Every check is a small pure function over a :class:`Telemetry`, so a team can
  add one in ten lines.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Set

from ..core.model import Finding
from .telemetry import Telemetry, is_write_open

BehaviorCheck = Callable[[Telemetry], List[Finding]]

# Files that indicate the sample is reading secrets rather than data.
SENSITIVE_PATHS = {
    "/etc/shadow": "shadow password file",
    "/etc/passwd": "password database",
    "/etc/sudoers": "sudo configuration",
    "/root/.ssh/": "root SSH keys",
    ".ssh/id_rsa": "SSH private key",
    ".ssh/id_ed25519": "SSH private key",
    ".ssh/authorized_keys": "SSH authorised keys",
    ".bash_history": "shell history",
    ".aws/credentials": "AWS credentials",
    ".docker/config.json": "Docker registry credentials",
    ".kube/config": "Kubernetes credentials",
    "wallet.dat": "cryptocurrency wallet",
    ".mozilla/firefox": "browser profile",
    "Login Data": "browser saved passwords",
    "Cookies": "browser cookies",
    ".netrc": "stored credentials",
    ".git-credentials": "stored Git credentials",
}

# Directories a legitimate program rarely touches but a wiper or ransomware does.
DESTRUCTIVE_TARGETS = ("/etc/", "/boot/", "/dev/", "/var/lib/", "/usr/lib/")

SHELLS = {"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ash", "/usr/bin/bash"}

DOWNLOADERS = ("wget", "curl", "fetch", "nc", "ncat", "socat", "tftp", "ftp")

SUSPICIOUS_BINARIES = {
    "nc": "netcat, often used for reverse shells",
    "ncat": "netcat, often used for reverse shells",
    "socat": "socket relay, often used for reverse shells",
    "nmap": "network scanner",
    "chmod": "permission changes",
    "crontab": "scheduled task persistence",
    "systemctl": "service manipulation",
    "insmod": "kernel module loading",
    "rm": "file deletion",
    "dd": "raw disk write",
    "mkfifo": "named pipe, often for shells",
    "base64": "payload decoding",
    "xxd": "payload decoding",
}

# prctl options that indicate anti-analysis. libc emits PR_SET_NAME and
# PR_SET_MM_ARG_START at startup, so those are deliberately excluded: including
# them would make every dynamically linked program look suspicious.
SUSPICIOUS_PRCTL = (
    "PR_SET_DUMPABLE",
    "PR_SET_PTRACER",
    "PR_SET_SECCOMP",
    "PR_SET_SECUREBITS",
)


def _f(fid: str, title: str, severity: str, score: int, detail: str = "",
       evidence=None, tags=None) -> Finding:
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        score=score,
        detail=detail,
        evidence=evidence or [],
        tags=tags or [],
        source="dynamic",
    )


# ----------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------


def check_network(telemetry: Telemetry) -> List[Finding]:
    connects = telemetry.by_syscall("connect", "sendto")
    if not connects:
        return []
    addresses = telemetry.addresses()
    succeeded = [e for e in connects if e.succeeded]
    evidence = [f"{e.name} -> {e.address or '(unparsed)'}" for e in connects[:10]]

    severity, score = ("high", 30) if succeeded else ("medium", 20)
    detail = (
        f"{len(connects)} outbound connection attempt(s), {len(succeeded)} succeeded."
        if succeeded
        else f"{len(connects)} outbound connection attempt(s); all were blocked by the sandbox."
    )
    return [
        _f(
            "DYN_NETWORK",
            "Attempts network communication",
            severity,
            score,
            detail + " A network call at runtime is direct evidence of C2 or exfiltration behaviour.",
            evidence=evidence,
            tags=["dynamic", "network", "c2"],
        )
    ]


def check_process_spawning(telemetry: Telemetry) -> List[Finding]:
    execs = telemetry.by_syscall("execve", "execveat")
    # The first execve is the sandbox launching the sample itself.
    children = execs[1:]
    if not children:
        return []
    programs = []
    for e in children:
        name = e.strings[0] if e.strings else e.path
        programs.append(name.rsplit("/", 1)[-1] if name else "?")
    unique = sorted(set(programs))

    findings = [
        _f(
            "DYN_CHILD_PROCESSES",
            "Spawns child processes",
            "medium",
            15,
            f"executed {len(children)} additional program(s) at runtime.",
            evidence=unique[:10],
            tags=["dynamic", "execution"],
        )
    ]

    shells = [p for p in unique if p in {"sh", "bash", "dash", "zsh", "ash", "busybox"}]
    if shells:
        findings.append(
            _f(
                "DYN_SHELL_SPAWN",
                "Spawns a shell",
                "high",
                25,
                "launching a shell at runtime is typical of droppers and command execution.",
                evidence=shells,
                tags=["dynamic", "execution", "shell"],
            )
        )

    notable = [f"{p} ({SUSPICIOUS_BINARIES[p]})" for p in unique if p in SUSPICIOUS_BINARIES]
    if notable:
        findings.append(
            _f(
                "DYN_NOTABLE_BINARIES",
                "Invokes security-relevant utilities",
                "medium",
                15,
                "utilities that are commonly abused by post-exploitation tooling.",
                evidence=notable[:10],
                tags=["dynamic", "execution"],
            )
        )
    return findings


def check_credential_access(telemetry: Telemetry) -> List[Finding]:
    hits: List[str] = []
    for event in telemetry.by_syscall("openat", "open", "openat2", "execve"):
        path = event.path
        if not path:
            continue
        for needle, label in SENSITIVE_PATHS.items():
            if needle in path:
                hits.append(f"{path} ({label})")
                break
    if not hits:
        return []
    return [
        _f(
            "DYN_CREDENTIAL_ACCESS",
            "Reads credential or secret material",
            "critical",
            40,
            "the sample opened files that hold credentials, keys or browser secrets.",
            evidence=sorted(set(hits))[:10],
            tags=["dynamic", "credential-access", "exfiltration"],
        )
    ]


def check_destructive_filesystem(telemetry: Telemetry) -> List[Finding]:
    deletions = telemetry.by_syscall("unlink", "unlinkat")
    renames = telemetry.by_syscall("rename", "renameat", "renameat2")
    findings: List[Finding] = []

    if deletions:
        targets = [e.path for e in deletions if e.path]
        severity, score = ("high", 30) if len(deletions) > 5 else ("medium", 15)
        findings.append(
            _f(
                "DYN_FILE_DELETION",
                "Deletes files",
                severity,
                score,
                f"{len(deletions)} unlink call(s) observed.",
                evidence=sorted(set(targets))[:10] or [f"{len(deletions)} unlink calls"],
                tags=["dynamic", "impact"],
            )
        )

    if renames:
        targets = [e.path for e in renames if e.path]
        findings.append(
            _f(
                "DYN_FILE_RENAME",
                "Renames files",
                "medium",
                15,
                f"{len(renames)} rename call(s); mass renaming is a ransomware signature.",
                evidence=sorted(set(targets))[:10],
                tags=["dynamic", "ransomware"],
            )
        )

    sensitive = [e.path for e in deletions + renames if e.path and any(
        e.path.startswith(t) or t in e.path for t in DESTRUCTIVE_TARGETS)]
    if sensitive:
        findings.append(
            _f(
                "DYN_SENSITIVE_PATHS_MODIFIED",
                "Modifies system paths",
                "critical",
                40,
                "files under system directories were deleted or renamed.",
                evidence=sorted(set(sensitive))[:10],
                tags=["dynamic", "impact", "wiper"],
            )
        )
    return findings


def check_persistence(telemetry: Telemetry) -> List[Finding]:
    paths: Set[str] = set()
    for event in telemetry.by_syscall(
        "openat", "open", "openat2", "creat", "symlinkat", "linkat", "renameat"
    ):
        if not event.path or not is_write_open(event.args):
            continue
        if any(
            marker in event.path
            for marker in (
                "/etc/cron", "crontab", "/etc/rc", "/etc/init.d", "systemd/system",
                "/.bashrc", "/.profile", "/.ssh/authorized_keys", "/etc/passwd",
                "/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload",
            )
        ):
            paths.add(event.path)
    if not paths:
        return []
    return [
        _f(
            "DYN_PERSISTENCE",
            "Writes to a persistence location",
            "high",
            30,
            "the sample modified files that cause code to run later (scheduled tasks, "
            "startup scripts, shell profiles, dynamic linker preload).",
            evidence=sorted(paths)[:10],
            tags=["dynamic", "persistence"],
        )
    ]


def check_writable_executable_memory(telemetry: Telemetry) -> List[Finding]:
    prot = telemetry.by_syscall("mprotect")
    wrote_exec = any("PROT_EXEC" in e.args and "PROT_WRITE" in e.args for e in prot)
    memfd = telemetry.by_syscall("memfd_create")
    if not (wrote_exec or memfd):
        return []
    evidence = []
    if wrote_exec:
        evidence.append("mprotect(PROT_WRITE|PROT_EXEC)")
    if memfd:
        evidence.append("memfd_create (anonymous executable memory)")
    return [
        _f(
            "DYN_RWX_MEMORY",
            "Creates writable and executable memory",
            "high",
            30,
            "self-modifying code or an in-memory payload; a common packer and "
            "shellcode-execution technique.",
            evidence=evidence,
            tags=["dynamic", "evasion", "injection"],
        )
    ]


def check_anti_analysis(telemetry: Telemetry) -> List[Finding]:
    findings: List[Finding] = []
    ptrace = telemetry.by_syscall("ptrace")
    if ptrace:
        findings.append(
            _f(
                "DYN_ANTI_DEBUG",
                "Calls ptrace",
                "medium",
                20,
                "ptrace is used to detect or obstruct a debugger.",
                evidence=[f"ptrace({e.args[:80]})" for e in ptrace[:5]],
                tags=["dynamic", "anti-analysis"],
            )
        )
    prctl = [
        e for e in telemetry.by_syscall("prctl")
        if any(option in e.args for option in SUSPICIOUS_PRCTL)
    ]
    if prctl:
        findings.append(
            _f(
                "DYN_PRCTL",
                "Manipulates process attributes",
                "medium",
                15,
                "prctl options that change debugging or memory-mapping behaviour, "
                "which anti-analysis code uses to hide from a tracer.",
                evidence=[e.args[:80] for e in prctl[:5]],
                tags=["dynamic", "anti-analysis"],
            )
        )
    return findings


def check_privilege(telemetry: Telemetry) -> List[Finding]:
    """Flag attempts to *become root*, not routine privilege dropping.

    An attempt counts even when it fails: in the sandbox every escalation is
    refused by design, so requiring success would hide the very behaviour worth
    reporting. libc's startup ``setuid(<current uid>)`` is a no-op and is
    excluded by looking only for uid/gid 0.
    """
    escalation = [
        e
        for e in telemetry.by_syscall(
            "setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid"
        )
        if re.match(r"^0\b", e.args.strip())
    ]
    if not escalation:
        return []
    return [
        _f(
            "DYN_PRIVILEGE_ESCALATION",
            "Attempts to gain root",
            "high",
            30,
            "the sample called a privilege-changing syscall with uid or gid 0; "
            "the sandbox refuses this, but the intent is the finding.",
            evidence=[f"{e.name}({e.args[:40]}) = {e.result}" for e in escalation[:5]],
            tags=["dynamic", "privilege"],
        )
    ]


def check_container_escape(telemetry: Telemetry) -> List[Finding]:
    escape = telemetry.by_syscall("mount", "pivot_root", "chroot", "init_module", "finit_module")
    if not escape:
        return []
    return [
        _f(
            "DYN_CONTAINER_ESCAPE",
            "Attempts to escape the sandbox",
            "critical",
            45,
            "mount, pivot_root, chroot or kernel-module operations were attempted. "
            "In a real environment these indicate an escape or rootkit attempt.",
            evidence=[f"{e.name}({e.args[:70]})" for e in escape[:5]],
            tags=["dynamic", "escape", "rootkit"],
        )
    ]


def check_long_sleep(telemetry: Telemetry) -> List[Finding]:
    sleeps = telemetry.by_syscall("clock_nanosleep", "nanosleep")
    if not sleeps:
        return []
    return [
        _f(
            "DYN_SLEEP",
            "Sleeps during execution",
            "low",
            8,
            "delays are used to defeat sandbox time limits and automated analysis.",
            evidence=[f"{e.name}({e.args[:60]})" for e in sleeps[:5]],
            tags=["dynamic", "evasion"],
        )
    ]


def check_timeout(telemetry: Telemetry) -> List[Finding]:
    if not telemetry.timed_out:
        return []
    return [
        _f(
            "DYN_TIMEOUT",
            "Sample ran until the timeout",
            "medium",
            15,
            "the sample did not terminate on its own, which is typical of malware that "
            "polls, beacons or sleeps indefinitely.",
            evidence=[f"wall-clock limit reached after {telemetry.duration_seconds:.1f}s"],
            tags=["dynamic", "evasion"],
        )
    ]


def check_activity_summary(telemetry: Telemetry) -> List[Finding]:
    """A corroboration signal: a lot of distinct syscalls means real activity."""
    interesting = {
        "connect", "execve", "unlink", "openat", "ptrace", "mprotect",
        "mount", "setuid", "sendto", "memfd_create", "symlinkat",
    }
    present = {e.name for e in telemetry.events} & interesting
    if len(present) < 6:
        return []
    return [
        _f(
            "DYN_ACTIVE_SAMPLE",
            "Broad runtime activity",
            "medium",
            12,
            f"the sample exercised {len(present)} distinct behavioural syscall families, "
            f"which is inconsistent with a passive or inert file.",
            evidence=sorted(present),
            tags=["dynamic", "corroboration"],
        )
    ]


CHECKS: List[BehaviorCheck] = [
    check_network,
    check_process_spawning,
    check_credential_access,
    check_destructive_filesystem,
    check_persistence,
    check_writable_executable_memory,
    check_anti_analysis,
    check_privilege,
    check_container_escape,
    check_long_sleep,
    check_timeout,
    check_activity_summary,
]


def analyse_telemetry(telemetry: Telemetry) -> List[Finding]:
    """Run every behaviour check and return the findings."""
    findings: List[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(telemetry))
        except Exception:
            # A malformed trace must not break a scan.
            continue
    return findings


def behaviour_summary(telemetry: Telemetry) -> Dict[str, object]:
    """A compact, JSON-friendly overview of what a sample did.

    Includes the findings themselves so a caller gets the whole behavioural
    picture from one call instead of running the checks twice.
    """
    findings = analyse_telemetry(telemetry)
    return {
        "event_count": len(telemetry.events),
        "unique_syscalls": sorted({e.name for e in telemetry.events}),
        "network_attempts": len(telemetry.by_syscall("connect", "sendto")),
        "addresses": telemetry.addresses(),
        "child_programs": sorted(
            {
                (e.strings[0].rsplit("/", 1)[-1] if e.strings else "")
                for e in telemetry.by_syscall("execve")[1:]
                if e.strings
            }
        ),
        "timed_out": telemetry.timed_out,
        "exit_code": telemetry.exit_code,
        "findings": [f.to_dict() for f in findings],
    }

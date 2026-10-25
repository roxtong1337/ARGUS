# Detonation chamber

Static analysis sees what a file *contains*. Detonation sees what it *does*.
This document covers the sandbox design, the telemetry it produces, the
behavioural checks, and — importantly — what the isolation does **not** protect
against.

Detonation is opt-in. Nothing runs unless you ask for `detonate` or `full`.

## Design in one picture

```
 host                          │  container (rea-sandbox:latest)
                               │
 sample ──bind mount (ro)─────►│  /sample/sample
                               │        │ cp
                               │        ▼
                               │  /work/sample.bin   (tmpfs, exec)
                               │        │
                               │        ▼
                               │  strace -f ──► /work/trace.log
                               │        │
                               │        ▼
                               │   syscall events
                               │        │
 markers ◄─── stdout ──────────┘        │
   │                                    │
   ▼                                    ▼
 parse_strace() ──► Telemetry ──► behaviour checks ──► Finding[]
                                                          │
                                                          ▼
                                        merged into the same Artifact
                                        as static findings
```

Dynamic findings are ordinary `Finding` objects with `source="dynamic"`. The
scoring engine, the four report formats and the Hermes payload need no special
case for them.

## Isolation layers

Each layer is independent, so a failure in one does not remove the others.

| Layer | Mechanism |
| --- | --- |
| Separate filesystem | The sample is bind-mounted read-only; the root filesystem is `--read-only`. |
| No privilege | Runs as uid 1000 `analyst`, with `--cap-drop ALL` and `--security-opt no-new-privileges`. |
| No network | `--network none`. A `connect()` still appears in the trace, but cannot leave the container. |
| Resource caps | `--pids-limit`, `--memory`/`--memory-swap` equal (no swap escape), `--cpus`. |
| Hard timeout | `timeout -s KILL` inside the container, plus a longer host-side guard. |
| Write isolation | `/work` and `/tmp` are tmpfs and vanish with the container; `--rm` removes it. |
| Kernel attack surface | A minimal Alpine image: no compiler, no package manager at runtime. |

### Why `/work` is executable and `/tmp` is not

The staged sample has to run, so `/work` is mounted `exec`. `/tmp` is mounted
`noexec` on purpose: a sample can still *write* a dropped payload there, and the
blocked `execve` is itself useful evidence. This turns a limitation into a
signal.

### Why tmpfs ownership is set explicitly

Docker mounts tmpfs root-owned. Without `uid=`/`gid=` the unprivileged analysis
user cannot write to its own work directory, and the run fails with an
`EACCES` that looks like a sandbox bug rather than a permissions mistake. The
runner therefore passes `uid=1000,gid=1000` on both tmpfs mounts.

## Backends

| Backend | Isolated | Notes |
| --- | --- | --- |
| `docker` | yes | The default, and the only one that is genuinely isolated. |
| `local` | **no** | Runs on the host with `rlimits` only. Refused unless you pass `--allow-unsafe`. |

`rea sandbox` prints both, with an explicit `NOT ISOLATED` marker for `local`.
When no container runtime is available the runner refuses and the toolkit stays
static; it never silently falls back to running the sample on the host.

## Telemetry

`strace -f -qq -tt` is asked for a curated syscall set, and the output is parsed
into structured events:

| Field | Meaning |
| --- | --- |
| `pid` | Thread or process id, so a child's activity is attributable |
| `name` | Syscall name |
| `args` | Raw argument text |
| `result` | Return value as text |
| `succeeded` | Whether the call returned non-negative |
| `errno` | Symbolic error, e.g. `EACCES`, `ENETUNREACH` |
| `strings` | Quoted strings extracted from the arguments |

Three deliberate choices:

1. **Failed calls are kept.** A `connect()` returning `ENETUNREACH` is proof the
   sample tried to reach a host. The sandbox blocking it does not make the
   intent less interesting.
2. **The sample's own `execve` is excluded from "child programs".** The first
   `execve` is the sample itself; counting it would list every sample as having
   spawned a process named after itself.
3. **Noisy syscalls are never findings on their own.** `mmap` and `mprotect`
   appear in almost every process, so they only contribute to compound signals
   such as a write-then-execute memory pattern.

## Behavioural checks

| Finding id | Severity | Score | Trigger |
| --- | --- | --- | --- |
| `DYN_CREDENTIAL_ACCESS` | critical | 40 | Reads `/etc/shadow`, SSH keys, cloud credentials, wallets, browser secrets |
| `DYN_CONTAINER_ESCAPE` | critical | 45 | `mount`, `pivot_root`, `chroot`, module loading |
| `DYN_SENSITIVE_PATHS_MODIFIED` | critical | 40 | Deletes or renames paths under `/etc`, `/boot`, `/usr/lib`, `/var/lib` |
| `DYN_PERSISTENCE` | high | 30 | Writes to cron, systemd, `rc.local`, profile scripts |
| `DYN_RWX_MEMORY` | high | 30 | `mprotect` to `PROT_EXEC` on a writable mapping |
| `DYN_PRIVILEGE_ESCALATION` | high | 30 | `setuid`/`setgid`/`setresuid` with uid or gid 0 |
| `DYN_SHELL_SPAWN` | high | 25 | Spawns `/bin/sh`, `/bin/bash`, … |
| `DYN_FILE_DELETION` | medium → high | 15 → 30 | `unlink`/`unlinkat`; escalates above five calls |
| `DYN_NETWORK` | medium → high | 20 → 30 | Any `connect`/`sendto`; escalates if a connection succeeded |
| `DYN_ANTI_DEBUG` | medium | 20 | Calls `ptrace` |
| `DYN_CHILD_PROCESSES` | medium | 15 | Spawns other programs |
| `DYN_NOTABLE_BINARIES` | medium | 15 | Invokes `nc`, `socat`, `nmap`, `dd`, … |
| `DYN_PRCTL` | medium | 15 | `prctl` with `PR_SET_DUMPABLE`/`PR_SET_PTRACER`/… |
| `DYN_FILE_RENAME` | medium | 15 | `rename`/`renameat` |
| `DYN_TIMEOUT` | medium | 15 | The sample never finished |
| `DYN_ACTIVE_SAMPLE` | medium | 12 | Broad runtime activity across many syscalls |
| `DYN_SLEEP` | low | 8 | Long `nanosleep`, a classic sandbox-evasion stall |

False positives were treated as bugs, not as noise to be filtered later. Two
examples that were fixed rather than tolerated:

- `prctl(PR_SET_NAME, ...)` is emitted by musl at startup, so the anti-analysis
  check matches only a short list of genuinely suspicious `prctl` options.
- libc calls `setuid(<current uid>)` at startup. The privilege check looks for
  uid or gid 0 specifically, so a routine no-op is not reported.

There is a regression test asserting that a trace of a plain `ls` produces no
high or critical findings.

## Known limitations

Be honest about these when you present the tool:

- **Linux only.** The sandbox runs ELF binaries and shell scripts. A PE or
  Mach-O sample is reported as `skipped_reason` — it cannot be executed here,
  and pretending otherwise would be worse than saying so.
- **Interpreted samples need their interpreter in the image.** A sample written
  in a language the image lacks will exit immediately with few syscalls. The
  image carries `sh`, `bash`, `curl`, `netcat` and `socat`; extend
  `sandbox/Dockerfile` if your samples need more.
- **No evasion resistance.** A sample that detects `ptrace`, or that waits for
  an interactive desktop that does not exist, will behave differently than on a
  real victim. This is a triage tool, not a full sandbox appliance.
- **Not a VM boundary.** This is container isolation sharing the host kernel. A
  kernel-level container escape is out of scope. For genuinely untrusted
  samples, run the whole toolkit inside a disposable VM.
- **`strace` is not free.** Tracing slows the sample, so timing-sensitive
  behaviour may differ.
- **The sample must be world-readable.** It is executed by uid 1000 inside the
  container, so a mode like `600` fails. The runner detects this before starting
  the container and reports it plainly instead of leaving a confusing `EACCES`
  in the trace.

## Extending it

A new behavioural check is a pure function over `Telemetry` returning
`List[Finding]`. Add it to `CHECKS` in `rea/dynamic/behaviors.py`:

```python
def check_dns(telemetry: Telemetry) -> List[Finding]:
    lookups = telemetry.by_syscall("sendto")  # or whatever the signal is
    if not lookups:
        return []
    return [_f("DYN_DNS", "Performs DNS lookups", "low", 8,
               evidence=[e.args[:60] for e in lookups[:5]],
               tags=["dynamic", "network"])]
```

A new backend implements the `SandboxBackend` protocol in
`rea/dynamic/backends.py` — `check()`, `run()`, `describe()` — and is registered
in `_BACKENDS`. Because the runner only talks to that interface, a `podman`,
`nsjail` or `firejail` backend needs no change anywhere else.

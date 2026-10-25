# REA — Reverse Engineering Anything

An offline-first reverse-engineering toolkit for binary and script triage, built
for a cyber hackathon and designed to plug into an external platform (Hermes)
without coupling the two.

REA answers one question fast: **what is this file, what can it do, and how
dangerous does it look?** Static analysis needs the Python standard library
alone — no pip install, no network, no external binaries. Sandboxed detonation
is optional and layers on top when a container runtime is available.

```
$ rea scan suspicious.sh
verdict     : MALICIOUS (risk score 100/100)
findings    : 12
  [CRITICAL]  45  Ransomware_Shadow_Copy_Deletion
  [CRITICAL]  45  Reverse_Shell_Dev_Tcp
  [CRITICAL]  40  Downloader_Curl_Pipe_Shell
```

Two front-ends drive the same analysis core:

* **ARGUS**, the analyst agent — a terminal REPL and a browser console
* the **`rea`** CLI, for scripting and CI

## Why it exists

During incident response and malware triage you usually have minutes, a locked
down laptop, and a pile of unknown files. Heavyweight platforms want a full
agent, a licence and a network connection. REA is the opposite: one directory,
`python -m rea.cli scan`, done. Results are structured JSON that any backend can
ingest.

Static analysis alone, though, cannot see what a file *does* — it only sees what
it *contains*. REA therefore adds a detonation chamber: the sample runs inside a
locked-down container with no network and no capabilities, and REA records the
syscalls it makes. Static and dynamic findings feed the same scoring engine, so
a verdict, a report or a Hermes payload is identical in shape either way.

## Features

**Static analysis (stdlib only, always available)**

- **Format aware** — hand-written ELF, PE and Mach-O parsers (sections, segments,
  imports, exports, entropy per section) plus a script analyser for shell,
  PowerShell, Python, JS and PHP.
- **Own rule engine** — a YARA-like DSL in pure Python: text, hex-with-wildcards
  and regex strings, modifiers (`nocase`, `wide`), and conditions using
  `any/all/N of them`, wildcard sets, `filesize` and boolean logic.
- **IOC harvesting** — URLs, domains, public IPs, registry keys, Windows/Unix
  paths, mutexes, user agents, crypto wallets and decodable base64 blobs.
- **Heuristic scoring** — entropy/packing detection, W+X sections, known packer
  sections, import-capability inference (injection, crypto, network, persistence),
  overlay detection and cross-signal corroboration.
- **Four report formats** — text, Markdown, JSON and SARIF 2.1.0.
- **CI friendly** — exit code 0 clean, 2 suspicious, 3 malicious.

**Sandboxed detonation (optional, needs a container runtime)**

- **Layered isolation** — a dedicated image, unprivileged user, `--network none`,
  all capabilities dropped, `no-new-privileges`, a read-only root filesystem,
  pid/memory/cpu limits and a hard timeout. Nothing runs unless you ask.
- **Syscall telemetry** — `strace` output is parsed into structured events, with
  failed calls kept because a blocked `connect()` still proves intent.
- **Behavioural findings** — credential access, persistence writes, C2 attempts,
  child processes, root-escalation attempts, W+X memory, container-escape
  attempts, anti-analysis `prctl` use, long sleeps and timeouts.
- **Honest refusal** — with no container runtime REA says so and stays static,
  rather than running a sample on the host.

**Delivery and front-ends**

- **Pluggable output** — `stdout`, `local` JSONL archive, generic `http`, HMAC
  signed `webhook`, and a fully configurable **`hermes`** adapter.
- **ARGUS agent** — a deterministic planner over a tool registry, with a TUI and
  a stdlib-only web console.

## Install

No dependencies. Python 3.9+.

```bash
git clone <your-repo> rea && cd rea
python -m rea.cli scan /bin/ls          # run straight from the checkout
pip install -e .                        # or install the `rea` entry point
```

Detonation additionally needs Docker (or another container runtime). Build the
sandbox image once:

```bash
docker build -t rea-sandbox:latest sandbox/
python -m rea.cli sandbox              # confirm it is ready
```

## Usage

```bash
# triage one file
rea scan suspicious.exe

# machine-readable, for a pipeline
rea scan suspicious.exe --format json -o report.json

# SARIF for a code-scanning dashboard
rea scan suspicious.exe --format sarif

# bulk triage a directory into JSONL
rea batch ./samples -o reports.jsonl

# work with rule packs
rea rules check rules/
rea rules list rules/

# static analysis, then run it in the sandbox and merge both views
rea detonate samples/malicious_sample.sh

# is detonation available, and how isolated is it?
rea sandbox

# scan and deliver to Hermes
rea send suspicious.exe --to hermes \
  --set base_url=https://hermes.internal \
  --set auth_style=bearer \
  --set payload_mode=detections \
  --min-severity medium
```

### ARGUS, the analyst agent

One agent, two front-ends, identical behaviour:

```bash
rea agent                          # terminal REPL
rea agent --mode web               # browser console on http://127.0.0.1:12000
rea agent --mode web --token s3cret --host 0.0.0.0   # exposed, token-gated
```

In either front-end you type the same commands:

```
scan samples/malicious_sample.sh    static triage
detonate samples/malicious_sample.sh run it in the sandbox
full samples/malicious_sample.sh    both, in sequence
send hermes --min-severity medium   deliver the report
sandbox                             is detonation available?
rules                               what detections are loaded?
```

The planner is **deterministic and offline**. A sample's strings are
attacker-controlled, so feeding them to an LLM planner would turn a malicious
file into a prompt-injection vector; ARGUS decides from your command and the
artifact's structure only. An LLM planner can be supplied through the `Planner`
protocol when a deployment allows it.

Use the CLI as a gate:

```bash
if ! rea scan "$FILE" --quiet --format json > /dev/null; then
  echo "REA flagged $FILE"
fi
```

## Library use

```python
from rea.analysis.pipeline import Pipeline
from rea.dynamic import Detonator

artifact = Pipeline(rule_paths=["rules"]).scan_path("suspicious.sh")
print(artifact.verdict, artifact.risk_score)

detonator = Detonator(backend="docker", timeout=20)
ready, reason = detonator.check()
if ready:
    detonator.apply(artifact)          # merges behavioural findings in place
    print(artifact.stats["dynamic"]["telemetry"]["addresses"])
```

## Project layout

```
rea/
  core/          format detection, hashing/entropy, the artifact model, loader
  parsers/       elf.py  pe.py  macho.py  scripts.py
  analysis/      strings.py  iocs.py  rules.py  categorize.py  scoring.py  pipeline.py
  dynamic/       backends.py  runner.py  telemetry.py  behaviors.py
  agent/         session.py  tools.py  tui.py       (ARGUS)
  web/           server.py  static/index.html       (ARGUS web console)
  integrations/  base.py  registry.py  stdout.py  local.py  http.py  webhook.py  hermes.py
  report/        render.py (text, markdown, json, sarif)
  cli.py         argument parsing and the eight subcommands
rules/           bundled rule packs (.rea)
sandbox/         Dockerfile for the detonation image
tests/           unittest suite, runnable without pytest
samples/         synthetic malicious and benign samples
docs/            ARCHITECTURE.md  RULES.md  HERMES.md  DETONATION.md  ARGUS.md
```

## Tests

```bash
python -m tests.run     # no pytest required
pytest tests/ -q        # if you have pytest
```

The suite covers the parsers, the rule engine, IOC extraction, scoring, all four
report formats, the CLI, every integration, the strace parser, the behavioural
checks, the agent planner and the web API. Network integrations are tested
against a real HTTP server on a loopback port, and the detonation tests run a
real sandboxed process — the code paths under test are the real ones, not stubs.
When no container runtime is present those tests assert the refusal instead of
skipping silently, so the suite cannot pass while pretending isolation exists.

## Safety

Static analysis never executes, unpacks or emulates a sample, and the parsers
fail soft: a malformed or hostile file produces a warning in `artifact.errors`,
never a crash and never code execution.

Detonation is opt-in and layered. A sample only runs when you ask for
`detonate`/`full`, and only inside the sandbox image with no network, no
capabilities and a hard timeout. If no container runtime is available REA
refuses instead of falling back to the host. See
[docs/DETONATION.md](docs/DETONATION.md) for the full threat model, including
what the isolation does *not* protect against.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the stages fit together
- [docs/RULES.md](docs/RULES.md) — the rule language reference
- [docs/HERMES.md](docs/HERMES.md) — the integration contract, with an adapter guide
- [docs/DETONATION.md](docs/DETONATION.md) — the sandbox design and threat model
- [docs/ARGUS.md](docs/ARGUS.md) — the agent, its tools and both front-ends

## License

MIT. See [LICENSE](LICENSE).

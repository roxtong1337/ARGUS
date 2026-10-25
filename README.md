# REA — Reverse Engineering Anything

An offline-first static analysis toolkit for binary triage, built for a cyber
hackathon and designed to plug into an external platform (Hermes) without
coupling the two.

REA answers one question fast: **what is this file, what can it do, and how
dangerous does it look?** It does that with the Python standard library alone —
no pip install, no network, no external binaries.

```
$ rea scan suspicious.sh
verdict     : MALICIOUS (risk score 100/100)
findings    : 12
  [CRITICAL]  45  Ransomware_Shadow_Copy_Deletion
  [CRITICAL]  45  Reverse_Shell_Dev_Tcp
  [CRITICAL]  40  Downloader_Curl_Pipe_Shell
```

## Why it exists

During incident response and malware triage you usually have minutes, a locked
down laptop, and a pile of unknown files. Heavyweight platforms want a full
agent, a licence and a network connection. REA is the opposite: one directory,
`python rea scan`, done. Results are structured JSON that any backend can ingest.

## Features

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
- **Pluggable output** — `stdout`, `local` JSONL archive, generic `http`, HMAC
  signed `webhook`, and a fully configurable **`hermes`** adapter.
- **Four report formats** — text, Markdown, JSON and SARIF 2.1.0.
- **CI friendly** — exit code 0 clean, 2 suspicious, 3 malicious.

## Install

No dependencies. Python 3.9+.

```bash
git clone <your-repo> rea && cd rea
python -m rea.cli scan /bin/ls          # run straight from the checkout
pip install -e .                        # or install the `rea` entry point
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

# scan and deliver to Hermes
rea send suspicious.exe --to hermes \
  --set base_url=https://hermes.internal \
  --set auth_style=bearer \
  --set payload_mode=detections \
  --min-severity medium
```

Use it as a gate:

```bash
if ! rea scan "$FILE" --quiet --format json > /dev/null; then
  echo "REA flagged $FILE"
fi
```

## Library use

```python
from rea.analysis.pipeline import Pipeline

artifact = Pipeline(rule_paths=["rules"]).scan_path("suspicious.exe")
print(artifact.verdict, artifact.risk_score)
for finding in artifact.findings:
    print(finding.severity, finding.title)
```

## Project layout

```
rea/
  core/          format detection, hashing/entropy, the artifact model, loader
  parsers/       elf.py  pe.py  macho.py  scripts.py
  analysis/      strings.py  iocs.py  rules.py  categorize.py  scoring.py  pipeline.py
  integrations/  base.py  registry.py  stdout.py  local.py  http.py  webhook.py  hermes.py
  report/        render.py (text, markdown, json, sarif)
  cli.py         argument parsing and the five subcommands
rules/           bundled rule packs (.rea)
tests/           unittest suite, runnable without pytest
samples/         synthetic malicious and benign samples
docs/            ARCHITECTURE.md  RULES.md  HERMES.md
```

## Tests

```bash
python -m tests.run     # no pytest required
pytest tests/ -q        # if you have pytest
```

The suite covers the parsers, the rule engine, IOC extraction, scoring, all four
report formats, the CLI and every integration. Network integrations are tested
against a real HTTP server on a loopback port — the code paths under test are
the real ones, not stubs.

## Safety

REA performs **static analysis only**. It never executes, unpacks or emulates a
sample. Parsers are written to fail soft: a malformed or hostile file produces a
warning in `artifact.errors`, never a crash and never code execution.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the stages fit together
- [docs/RULES.md](docs/RULES.md) — the rule language reference
- [docs/HERMES.md](docs/HERMES.md) — the integration contract, with an adapter guide

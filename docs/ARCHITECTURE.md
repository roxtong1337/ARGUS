# Architecture

REA is a linear pipeline over one mutable model. Every stage reads the same
`Artifact`, adds to it, and knows nothing about the stages around it. That is
what makes the toolkit easy to extend: a new parser, rule type or output format
touches exactly one file.

```
                    ┌───────────────────────────────┐
   file on disk ───▶│ core/loader                   │
                    │  detect format, hash, entropy │
                    └───────────────┬───────────────┘
                                    │  Artifact (sections, imports, metadata)
                                    ▼
                    ┌───────────────────────────────┐
                    │ parsers/                      │
                    │  elf  pe  macho  scripts      │
                    └───────────────┬───────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │ analysis/                     │
                    │  strings → iocs               │
                    │  rules  → findings            │
                    │  scoring (heuristics)         │
                    └───────────────┬───────────────┘
                                    │  findings, indicators, verdict, score
                                    ▼
        ┌───────────────────────────┴───────────────────────────┐
        ▼                                                       ▼
┌──────────────────┐                                 ┌──────────────────────┐
│ report/          │                                 │ integrations/        │
│  text markdown   │                                 │  stdout local http   │
│  json  sarif     │                                 │  webhook hermes      │
└──────────────────┘                                 └──────────────────────┘
```

## The artifact model

`rea/core/model.py` defines the single object everything operates on.

| Field | Written by | Meaning |
| --- | --- | --- |
| `file_type` | `core/formats` | Format, architecture, bit width, endianness |
| `hashes` | `core/hashing` | MD5, SHA-1, SHA-256, fuzzy digest |
| `sections` | parsers | Sections or segments with per-section entropy and flags |
| `imports` / `exports` | parsers | Symbols, each import tagged with a behavioural category |
| `strings` | `analysis/strings` | ASCII and UTF-16 strings with offsets |
| `indicators` | `analysis/iocs` | Grouped IOCs |
| `findings` | rules + heuristics | Evidence, each with a severity and a score |
| `stats` | pipeline | Capability list, rule counts, summary |
| `errors` | any stage | Non-fatal problems; a scan never dies on a bad sample |

Derived values are computed, not stored: `risk_score` is the capped sum of
finding scores, and `verdict` maps that score to `clean`, `low-risk`,
`suspicious` or `malicious`. Change the thresholds in one place and the whole
tool follows.

## Stage contracts

**Parsers** — `parse(artifact, data) -> None`. They mutate the artifact and must
never raise. The loader wraps them defensively and records failures in
`artifact.errors`. A malformed PE, a truncated ELF and a random blob all produce
a usable report rather than a traceback.

**Analysis** — `run(artifact, data)`. Each module is independent:
`strings` and `iocs` populate data, `rules` and `scoring` produce findings.
`Pipeline` can switch any of them off, which is how a hash-only pass over a large
corpus stays fast.

**Integrations** — `send(artifact) -> IntegrationResult`. They never raise on
network failure; they return `ok=False` with a reason. That keeps a delivery
problem from aborting a triage run.

**Reports** — `render(artifact, fmt) -> str`. Pure functions, no side effects.

## Scoring model

Two sources of signal feed one score.

*Rules* are high precision: a named behaviour with an explicit weight.

```yara
meta:
    severity = "critical"
    score    = 45
```

*Heuristics* cover what no rule anticipated. `analysis/scoring.py` holds a list
of small pure functions, each returning zero or more findings. They detect
packing via entropy, W+X sections, known packer section names, capability
combinations from imports (network plus crypto is ransomware-shaped),
anti-debugging imports, script patterns, suspicious indicators and structural
anomalies.

The final pass, `h_rule_pressure`, raises a finding when four or more independent
medium-or-higher signals agree. Corroboration is a stronger signal than any one
heuristic, and it is what keeps the verdict stable as rules are added.

Scores sum and cap at 100:

| Score | Verdict |
| --- | --- |
| 0–14 | clean |
| 15–39 | low-risk |
| 40–69 | suspicious |
| 70–100 | malicious |

## The rule engine

`analysis/rules.py` is a tokenizer plus a recursive-descent parser plus a small
evaluator. It is deliberately not a YARA binding: no C dependency, no build step,
and rules are data you can inspect and version.

The tokenizer resolves one ambiguity up front. A `{` opens either a rule body or
a hex string, so the tokenizer looks ahead: if the contents match a byte-pattern
shape (`4D 5A ?? 90`), it emits a hex token, otherwise a punctuation token. That
one decision removes the need for a context-sensitive grammar.

Conditions compile to a node tree once, at load time, then evaluate against a
match table per file. `any of them`, `all of them`, `N of them`, wildcard sets
(`any of ($note*)`), `filesize`, integer reads and boolean logic are supported.

## Failure philosophy

Triage runs over untrusted input, so every stage is written to degrade instead
of aborting:

- parsers record an error and return partial data,
- the rule engine skips a rule whose regex will not compile rather than failing
  the file,
- heuristics are individually wrapped, so one bad heuristic costs one finding,
- integrations return a failed result instead of raising.

A scan of a hostile file always produces a report. It may be a report full of
warnings, but it is a report.

## Performance

Entropy is computed per section and over sliding windows only where needed.
Hashing streams in 1 MiB chunks. String extraction is capped at 20,000 entries
and 4 KiB per string. The default analysis cap is 256 MiB, overridable with
`--max-bytes`. For a corpus, prefer `rea batch` so rules load once for the whole
run instead of once per file.

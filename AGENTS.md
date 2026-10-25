# AGENTS.md

Repository memory for REA (Reverse Engineering Anything).

## What this project is

An offline-first static analysis toolkit for binary triage, built for a cyber
hackathon. It has **zero third-party dependencies** and must keep working on a
bare Python 3.9+ install with no network access. That constraint is the point:
the tool has to run on a judge's laptop, an air-gapped responder machine or a CI
runner without a setup step.

## Hard rules

- **No new runtime dependencies.** Standard library only. Do not add `pefile`,
  `pyelftools`, `yara-python`, `requests` or anything else to `dependencies`.
  If a capability is needed, implement it. Dev-only tools under the `dev` extra
  are acceptable (pytest already is), but the test suite must still run with
  `python -m tests.run` and no pytest.
- **Static analysis only.** Never execute, unpack, emulate or detonate a sample.
  No `subprocess` call may run sample content.
- **Parsers must fail soft.** A malformed or hostile file produces an entry in
  `artifact.errors`, never an exception and never a crash. Wrap risky parsing in
  try/except and record the failure.
- **Integrations must not raise on network failure.** Return
  `IntegrationResult(ok=False, detail=...)`. Delivery problems must never abort a
  triage run.
- **Tests must exercise real code paths.** No mocks or stubs for the code under
  test. Network integrations are verified against a real `HTTPServer` on a
  loopback port (see `ServerFixture` in `tests/test_rea.py`).

## Layout

```
rea/core/          formats.py hashing.py model.py loader.py
rea/parsers/       elf.py pe.py macho.py scripts.py
rea/analysis/      strings.py iocs.py rules.py categorize.py scoring.py pipeline.py
rea/integrations/  base.py registry.py stdout.py local.py http.py webhook.py hermes.py
rea/report/        render.py
rea/cli.py         the five subcommands
rules/             bundled .rea rule packs
tests/             test_rea.py factories.py run.py
docs/              ARCHITECTURE.md RULES.md HERMES.md
```

## Commands

```bash
python -m tests.run                 # full suite, no pytest needed
python -m rea.cli scan <file>       # triage one file
python -m rea.cli batch <dir> -o out.jsonl
python -m rea.cli rules check rules/
python -m rea.cli integrations
./demo.sh                           # end-to-end demo incl. a local Hermes stand-in
```

Exit codes are a contract: 0 clean/low-risk, 2 suspicious, 3 malicious, 1 error.
Do not change them without updating the README and the CLI tests.

## Things that will bite you

- **The rule tokenizer resolves `{` by lookahead.** A `{` becomes a HEX token if
  its contents look like a byte pattern, otherwise a punctuation token. This is
  what lets one character both open a rule body and delimit a hex string. If you
  touch `_tokenize_rules`, keep `test_hex_pattern_with_wildcards` passing.
- **String modifiers must be whitelisted, not greedily consumed.** An earlier bug
  swallowed the `condition:` keyword as a modifier because the loop ate any
  identifier. Only consume words in `_KNOWN_MODIFIERS`.
- **`_RuleParser` needs the `json` import** to re-quote condition string literals.
- **YARA `wide` semantics differ here.** `wide` means *also* match UTF-16LE, not
  *only*. This is documented in `docs/RULES.md`; do not "fix" it silently.
- **Header names from `http.server` are title-cased** (`X-Rea-Signature`). Tests
  must compare case-insensitively.
- **`describe_all` is exported from `rea/integrations/__init__.py`.** Adding a
  registry function means adding it to both `registry.py` and the package
  `__init__`, or the CLI import breaks.
- **Hermes has no fixed schema by contract.** It is config-driven on purpose.
  Do not hardcode a path or an auth scheme; keep `payload_mode`, `auth_style`,
  `path` and `base_url` overridable, and prefer environment variables for
  secrets.

## Adding a rule

Put it in the matching pack under `rules/` (one theme per file), set `severity`
and `score` deliberately, and run `python -m rea.cli rules check rules/`. Prefer
`2 of them` over `any of them` for generic tokens.

## Adding an integration

Subclass `Integration` in `rea/integrations/`, decorate with `@register`, give it
a unique `name`, and add the module name to the discovery tuple in
`registry.py`. Return `IntegrationResult` in every path. Add a test that runs it
against `ServerFixture`.

## Verification before finishing work

1. `python -m tests.run` — all green.
2. `python -m rea.cli rules check rules/` — all packs parse.
3. `./demo.sh` — full pipeline incl. a real HTTP delivery.
4. `python -m rea.cli scan samples/benign_sample.sh` still reports CLEAN, and
   `samples/malicious_sample.sh` still reports MALICIOUS. False positives are the
   fastest way to lose a demo.

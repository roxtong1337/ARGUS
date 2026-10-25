# AGENTS.md

Repository memory for REA (Reverse Engineering Anything).

## What this project is

An offline-first reverse-engineering toolkit for binary and script triage, built
for a cyber hackathon. **Static analysis has zero third-party dependencies** and
must keep working on a bare Python 3.9+ install with no network access. That
constraint is the point: the tool has to run on a judge's laptop, an air-gapped
responder machine or a CI runner without a setup step.

Sandboxed detonation is a second, **opt-in** layer that needs a container runtime
and is never required for the toolkit to work. Two front-ends drive the same
core: the `rea` CLI, and the **ARGUS** agent (terminal REPL + web console).

## Hard rules

- **No new runtime dependencies.** Standard library only. Do not add `pefile`,
  `pyelftools`, `yara-python`, `requests` or anything else to `dependencies`.
  If a capability is needed, implement it. Dev-only tools under the `dev` extra
  are acceptable (pytest already is), but the test suite must still run with
  `python -m tests.run` and no pytest. A container runtime is an *external
  service*, not a Python dependency — the Docker backend shells out to `docker`
  and must degrade to a clean refusal when it is absent.
- **Static analysis never executes a sample.** The parser and analysis path must
  not run, unpack or emulate sample content. All `subprocess` use that touches a
  sample belongs in `rea/dynamic/`, which is opt-in.
- **Detonation is opt-in and must refuse honestly.** A sample only runs via
  `detonate`/`full`, only through a `SandboxBackend`, and only if
  `backend.check()` says it is ready. Never fall back to running a sample on the
  host. `LocalBackend` is not isolated and requires explicit
  `allow_unsafe=True`. If isolation cannot be provided, report that and stay
  static — a silent downgrade is a security bug.
- **Keep `--network none` in the Docker backend.** Failed `connect()` calls are
  deliberately kept as evidence, but nothing may actually reach the network.
- **Parsers must fail soft.** A malformed or hostile file produces an entry in
  `artifact.errors`, never an exception and never a crash. Wrap risky parsing in
  try/except and record the failure. The same applies to the strace parser and
  the behaviour checks: a malformed trace yields fewer findings, not a traceback.
- **Integrations must not raise on network failure.** Return
  `IntegrationResult(ok=False, detail=...)`. Delivery problems must never abort a
  triage run.
- **Tests must exercise real code paths.** No mocks or stubs for the code under
  test. Network integrations are verified against a real `HTTPServer` on a
  loopback port (see `ServerFixture` in `tests/test_rea.py`), and detonation is
  verified by actually running a sample in the sandbox. When no container runtime
  is present, detonation tests must assert the refusal rather than `skipTest`, so
  the suite cannot pass while pretending isolation exists.
- **The agent planner must stay deterministic.** A sample's strings are
  attacker-controlled, so `RulePlanner` must never feed sample content into a
  decision. That is a prompt-injection boundary, not a style preference. An LLM
  planner is allowed only behind the `Planner` protocol, opt-in.
- **The web UI must not use `innerHTML`.** Everything it renders can originate
  from a hostile sample. Build DOM nodes and set `textContent`.

## Layout

```
rea/core/          formats.py hashing.py model.py loader.py
rea/parsers/       elf.py pe.py macho.py scripts.py
rea/analysis/      strings.py iocs.py rules.py categorize.py scoring.py pipeline.py
rea/dynamic/       backends.py runner.py telemetry.py behaviors.py
rea/agent/         session.py tools.py tui.py        (ARGUS)
rea/web/           server.py static/index.html       (ARGUS web console)
rea/integrations/  base.py registry.py stdout.py local.py http.py webhook.py hermes.py
rea/report/        render.py
rea/cli.py         the eight subcommands
rules/             bundled .rea rule packs
sandbox/           Dockerfile for the detonation image
tests/             test_rea.py test_agent.py factories.py run.py
docs/              ARCHITECTURE.md RULES.md HERMES.md DETONATION.md ARGUS.md
```

## Commands

```bash
python -m tests.run                 # full suite, no pytest needed
python -m rea.cli scan <file>       # triage one file
python -m rea.cli batch <dir> -o out.jsonl
python -m rea.cli rules check rules/
python -m rea.cli integrations
python -m rea.cli sandbox           # is detonation available?
python -m rea.cli detonate <file>   # static + sandboxed execution
python -m rea.cli agent             # ARGUS terminal REPL
python -m rea.cli agent --mode web  # ARGUS browser console
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
- **`sandbox` and `detonate` are different intents.** `sandbox` asks whether
  detonation is available; `detonate` runs a file. Folding them into one verb
  made the `sandbox` command execute a sample. Keep the verbs separate in
  `RulePlanner.plan`, and keep `_sandbox_status` free of side effects.
- **`BANNER` must stay plain text.** Colour is applied in `Tui.banner()` through
  the `Colour` helper. Baking ANSI codes into the constant makes `--no-colour`
  a lie, because `print` cannot strip what is already in the string.
- **A `Tui` handed an existing session must wire `on_event` itself.** Passing
  `on_event=` to the constructor only covers the case where the Tui builds the
  session. The CLI injects one, so the constructor wires it when it is unset.
- **`cmd_detonate` must check the file before scanning.** The static pipeline
  raises `FileNotFoundError` for a missing path; every other command returns
  exit 1 with a message. Match that, or the exit-code contract breaks.
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

## Adding a behaviour check

Add a pure function over `Telemetry` returning `List[Finding]` in
`rea/dynamic/behaviors.py` and append it to `CHECKS`. Two rules learned the hard
way: **an attempted syscall counts** (a blocked `connect()` still proves intent),
and **noisy syscalls are never findings alone** (`mmap`/`mprotect` appear in
almost every process, so they only feed compound signals). Add a benign-trace
regression test — false positives are how a sandbox tool loses credibility.

## Adding a backend

Implement the `SandboxBackend` protocol (`check()`, `run()`, `describe()`) in
`rea/dynamic/backends.py` and register it in `_BACKENDS`. The runner only talks
to that interface, so nothing else needs to change. A backend that is not
isolated must say so in `describe()` and refuse unless explicitly allowed.

## Adding an agent tool

Register a `Tool` on the registry from `build_default_registry()`. Both
front-ends pick it up automatically. Then add a deterministic branch to
`RulePlanner.plan` — decide from the operator's command, never from file content.

## Verification before finishing work

1. `python -m tests.run` — all green.
2. `python -m rea.cli rules check rules/` — all packs parse.
3. `./demo.sh` — full pipeline incl. a real HTTP delivery.
4. `python -m rea.cli sandbox` — reports readiness honestly.
5. `python -m rea.cli detonate samples/malicious_sample.sh` — real findings.
6. `python -m rea.cli scan samples/benign_sample.sh` still reports CLEAN, and
   `samples/malicious_sample.sh` still reports MALICIOUS. False positives are the
   fastest way to lose a demo.
7. If you touched the web UI, load it in a browser and run a `full` command —
   the API tests do not catch a broken page.

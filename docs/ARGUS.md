# ARGUS — the analyst agent

ARGUS (*Automated Reverse-engineering Guidance and Understanding System*) is the
operator-facing side of REA. REA answers "what is this file"; ARGUS answers
"what should I do next about this file", by calling REA's capabilities as tools
and keeping a record of what happened.

It has two front-ends over one core, so behaviour cannot drift between them:

* a **terminal REPL** — `rea agent`
* a **browser console** — `rea agent --mode web`

```
        ┌──────────────────────────────┐
        │  AgentSession                │
        │   • RulePlanner              │
        │   • ToolRegistry             │
        │   • history + transcript     │
        └───────────┬──────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
   Tui (ANSI)             web (http.server)
```

## Why the planner is deterministic

The input to this agent is a hostile sample, and a sample's strings are
attacker-controlled. Handing those strings to an LLM planner turns a malicious
file into a prompt-injection vector: a sample could contain text crafted to make
the agent exfiltrate a report or run a command.

`RulePlanner` therefore decides from **the operator's command and the artifact's
structure only**. It never reads sample content. That keeps the agent usable
offline, with no API key, and safe against the files it is pointed at.

An LLM planner is still possible: implement the `Planner` protocol (one method,
`plan(text, session) -> List[PlanStep]`) and pass it to `AgentSession`. The
protocol exists precisely so a deployment that wants an LLM can have one without
weakening the default.

## Tools

Tools are thin, typed wrappers over REA capabilities. Each returns a
`ToolResult` and never raises, because an agent that dies on a bad file is worse
than one that says "that file is unreadable".

| Tool | Purpose |
| --- | --- |
| `scan` | Static analysis: format, hashes, imports, IOC, rule matches, verdict |
| `detonate` | Run the sample in the sandbox and report observed behaviour |
| `send` | Deliver the report to `hermes`, `http`, `webhook`, `local` or `stdout` |
| `integrations` | List delivery targets and their settings |
| `rules` | List loaded detections with severity and score |
| `sandbox` | Report whether detonation is available, and via which backend |

Registering a tool makes it available to **both** front-ends at once. That is
the main reason the registry exists rather than calling the pipeline directly.

## Command language

Both front-ends accept the same commands:

| Command | Effect |
| --- | --- |
| `scan <path>` | Static analysis |
| `detonate <path> [--timeout N]` | Sandboxed execution |
| `full <path>` | `scan` then `detonate` |
| `send <target> [key=value …] [--min-severity S]` | Deliver the report |
| `integrations` | List targets |
| `rules` | List detections |
| `sandbox` | Detonation readiness |
| `help` | Usage text |

A bare path is treated as `scan <path>`, because that is the most common thing
an analyst types. `key=value` pairs after `send` become adapter configuration,
so a target can be pointed at a new endpoint without editing a file:

```
send hermes base_url=https://hermes.internal auth_style=bearer
```

## Terminal front-end

```bash
rea agent                     # interactive
rea agent --no-colour         # for logs
rea agent --exec "full samples/malicious_sample.sh"   # non-interactive, for demos
```

Built on plain ANSI escapes rather than `curses`, so it works over SSH, inside a
container and in a recorded demo, and degrades to no colour when the output is
not a terminal.

## Web front-end

```bash
rea agent --mode web                                   # http://127.0.0.1:12000
rea agent --mode web --token s3cret                    # require a shared token
rea agent --mode web --host 0.0.0.0 --token s3cret     # expose deliberately
```

Built on `http.server` with no framework and no dependencies.

### API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | The single-page UI |
| `GET` | `/api/health` | Liveness, agent name, sandbox readiness |
| `GET` | `/api/tools` | Capability catalogue |
| `GET` | `/api/state` | Current session snapshot |
| `POST` | `/api/command` | `{"text": "scan /path"}` |
| `POST` | `/api/upload?name=x.sh` | Raw bytes in the body; scans the upload |

### Security notes

The web service can execute samples, so it is treated as sensitive.

- **Binds `127.0.0.1` by default.** `--host 0.0.0.0` is a deliberate choice and
  the server prints a warning when you make it.
- **Optional shared token.** `--token` or `REA_WEB_TOKEN` gates every `/api/`
  call. Comparison uses `secrets.compare_digest`, so it is not timing-sensitive.
- **One session per browser, via an `HttpOnly` cookie.** Sessions are isolated
  from each other and expire after an hour of inactivity.
- **Uploads never land on a client-controlled path.** The filename is reduced to
  a sanitised basename and written into a private temp directory, then deleted
  once the report is built.
- **The UI never uses `innerHTML`.** Everything rendered can originate from a
  hostile sample — file names, strings, IOC values — so the front-end builds DOM
  nodes and sets `textContent`. A malicious filename cannot become script
  execution in the analyst's browser.
- **Uploads are capped** at 64 MiB, and oversized bodies are rejected before
  being read into memory.

## Adding a tool

```python
from rea.agent.tools import Tool, ToolResult, build_default_registry

def handler(path: str = "") -> ToolResult:
    return ToolResult(ok=True, summary=f"looked at {path}", data={"path": path})

registry = build_default_registry()
registry.register(Tool(
    name="look",
    description="Do something new with a file.",
    parameters={"path": "file to look at"},
    handler=handler,
    examples=["look /tmp/a.bin"],
))
session = AgentSession(registry=registry)
```

To make the planner understand a new verb, add a branch to `RulePlanner.plan`.
Keep it deterministic: decide from the command, not from file content.

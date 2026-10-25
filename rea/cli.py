"""Command line interface for REA.

    rea scan <file>                       triage one artifact
    rea scan <file> --format markdown     render as markdown
    rea batch <dir> --json out.jsonl      triage a directory
    rea rules check rules/                validate a rule pack
    rea rules list rules/                 list rules in a pack
    rea integrations                      list available sinks
    rea send <file> --to hermes ...       scan and deliver to Hermes

Exit codes: 0 clean/low-risk, 2 suspicious, 3 malicious, 1 usage or IO error.
This makes REA usable as a CI gate.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .analysis import rules as rules_mod
from .analysis.pipeline import Pipeline
from .core.model import Artifact
from .integrations import available as available_integrations
from .integrations import create as create_integration
from .integrations import describe_all
from .report import render

DEFAULT_RULE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def _default_rules() -> List[str]:
    return [DEFAULT_RULE_DIR] if os.path.isdir(DEFAULT_RULE_DIR) else []


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rea",
        description="REA - Reverse Engineering Anything: offline static analysis for cyber triage.",
        epilog="Examples:\n"
        "  rea scan suspicious.exe\n"
        "  rea scan payload.sh --format markdown --rules rules/\n"
        "  rea batch ./samples --output reports.jsonl --quiet\n"
        "  rea send sample.bin --to hermes --base-url https://hermes.internal --mode detections\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"rea {__version__}")
    sub = parser.add_subparsers(dest="command")

    # scan ---------------------------------------------------------------
    scan = sub.add_parser("scan", help="analyse a single file")
    scan.add_argument("file")
    scan.add_argument("-f", "--format", default="text",
                      choices=["text", "markdown", "md", "json", "sarif"], help="report format")
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--rules", action="append", default=None,
                      help="rule file or directory (repeatable); defaults to the bundled pack")
    scan.add_argument("--no-strings", action="store_true", help="skip string extraction")
    scan.add_argument("--no-iocs", action="store_true", help="skip IOC extraction")
    scan.add_argument("--no-rules", action="store_true", help="skip rule matching")
    scan.add_argument("--no-heuristics", action="store_true", help="skip heuristic scoring")
    scan.add_argument("--max-bytes", type=int, default=256 << 20, help="cap the bytes analysed")
    scan.add_argument("--json", action="store_true", help="shorthand for --format json")
    scan.add_argument("--quiet", action="store_true", help="suppress progress output")

    # batch --------------------------------------------------------------
    batch = sub.add_parser("batch", help="analyse many files")
    batch.add_argument("paths", nargs="+", help="files, directories or globs")
    batch.add_argument("-o", "--output", default="-", help="JSONL output path ('-' for stdout)")
    batch.add_argument("--rules", action="append", default=None)
    batch.add_argument("--max-bytes", type=int, default=256 << 20)
    batch.add_argument("--quiet", action="store_true")

    # rules --------------------------------------------------------------
    rules = sub.add_parser("rules", help="work with rule packs")
    rules_sub = rules.add_subparsers(dest="rules_command")
    for name, help_text in (("check", "validate rules and report syntax errors"),
                            ("list", "list the rules in a pack")):
        p = rules_sub.add_parser(name, help=help_text)
        p.add_argument("path", nargs="?", default=DEFAULT_RULE_DIR)

    # integrations -------------------------------------------------------
    sub.add_parser("integrations", help="list available output integrations")

    # send ---------------------------------------------------------------
    send = sub.add_parser("send", help="scan a file and deliver the report to an integration")
    send.add_argument("file")
    send.add_argument("--to", required=True, help="integration name (see 'rea integrations')")
    send.add_argument("--config", help="JSON file with integration config")
    send.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                      help="override a single config value (repeatable)")
    send.add_argument("--min-severity", default="info",
                      choices=["info", "low", "medium", "high", "critical"],
                      help="only send when a finding at least this severe exists")
    send.add_argument("--min-score", type=int, default=0, help="only send when risk score >= N")
    send.add_argument("--rules", action="append", default=None)
    send.add_argument("--dry-run", action="store_true", help="build the payload but do not POST")
    send.add_argument("--quiet", action="store_true")

    return parser


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------


def _make_pipeline(args) -> Pipeline:
    rule_paths = args.rules if args.rules else _default_rules()
    return Pipeline(
        extract_strings=not getattr(args, "no_strings", False),
        extract_iocs=not getattr(args, "no_iocs", False),
        run_rules=not getattr(args, "no_rules", False),
        run_heuristics=not getattr(args, "no_heuristics", False),
        max_bytes=getattr(args, "max_bytes", 256 << 20),
        rule_paths=rule_paths,
    )


def cmd_scan(args) -> int:
    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 1

    pipeline = _make_pipeline(args)
    if not args.quiet:
        pipeline.progress = lambda msg: print(f"[rea] {msg}", file=sys.stderr)

    artifact = pipeline.scan_path(args.file)
    fmt = "json" if args.json else args.format
    text = render(artifact, fmt)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        if not args.quiet:
            print(f"[rea] report written to {args.output}", file=sys.stderr)
    else:
        print(text)

    return _exit_code(artifact)


def _collect_files(patterns: List[str]) -> List[str]:
    files: List[str] = []
    for pattern in patterns:
        if os.path.isdir(pattern):
            for root, _dirs, names in os.walk(pattern):
                for name in sorted(names):
                    files.append(os.path.join(root, name))
        elif os.path.isfile(pattern):
            files.append(pattern)
        else:
            files.extend(sorted(glob.glob(pattern, recursive=True)))
    seen = set()
    unique = []
    for f in files:
        if f not in seen and os.path.isfile(f):
            seen.add(f)
            unique.append(f)
    return unique


def cmd_batch(args) -> int:
    files = _collect_files(args.paths)
    if not files:
        print("error: no input files matched", file=sys.stderr)
        return 1

    pipeline = _make_pipeline(args)
    sink = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")

    counts = {"clean": 0, "low-risk": 0, "suspicious": 0, "malicious": 0}
    worst = 0
    try:
        for i, path in enumerate(files, 1):
            try:
                artifact = pipeline.scan_path(path)
            except OSError as exc:
                print(json.dumps({"path": path, "error": str(exc)}), file=sink)
                continue
            counts[artifact.verdict] = counts.get(artifact.verdict, 0) + 1
            worst = max(worst, _exit_code(artifact))
            sink.write(json.dumps(artifact.to_dict(), default=str) + "\n")
            if not args.quiet:
                print(f"[rea] {i}/{len(files)} {artifact.verdict:10} {path}", file=sys.stderr)
            sink.flush()
    finally:
        if sink is not sys.stdout:
            sink.close()

    if not args.quiet:
        print(f"[rea] done: {counts}", file=sys.stderr)
    return worst


def cmd_rules(args) -> int:
    path = args.path
    if args.rules_command == "check":
        targets = (
            sorted(
                os.path.join(path, f)
                for f in os.listdir(path)
                if f.endswith((".rea", ".yar", ".yara"))
            )
            if os.path.isdir(path)
            else [path]
        )
        failures = 0
        for target in targets:
            try:
                loaded = rules_mod.load_rule_file(target)
                print(f"OK    {target} ({len(loaded)} rule(s))")
            except (OSError, rules_mod.RuleSyntaxError) as exc:
                print(f"FAIL  {target}: {exc}", file=sys.stderr)
                failures += 1
        return 1 if failures else 0

    if args.rules_command == "list":
        loaded = (
            rules_mod.load_rule_dir(path)
            if os.path.isdir(path)
            else rules_mod.load_rule_file(path)
        )
        for r in loaded:
            print(f"{r.severity:8} {r.score:3}  {r.name:40} {r.description[:60]}")
        print(f"total: {len(loaded)} rule(s)")
        return 0

    print("error: specify 'check' or 'list'", file=sys.stderr)
    return 1


def cmd_integrations(_args) -> int:
    print("Available integrations:\n")
    for info in describe_all():
        print(f"  {info['name']:12} {info['description']}")
    print("\nUse 'rea send <file> --to <name> --set key=value' to deliver a report.")
    return 0


def cmd_send(args) -> int:
    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 1

    config = {}
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as fh:
                config = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read config {args.config}: {exc}", file=sys.stderr)
            return 1
    for item in args.set:
        if "=" not in item:
            print(f"error: --set expects KEY=VALUE, got {item!r}", file=sys.stderr)
            return 1
        key, _, value = item.partition("=")
        config[key.strip()] = _coerce(value)

    if args.dry_run:
        config["dry_run"] = True

    try:
        integration = create_integration(args.to, config)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"available: {', '.join(available_integrations())}", file=sys.stderr)
        return 1

    pipeline = _make_pipeline(args)
    if not args.quiet:
        pipeline.progress = lambda msg: print(f"[rea] {msg}", file=sys.stderr)
    artifact = pipeline.scan_path(args.file)

    if not _passes_gate(artifact, args.min_severity, args.min_score):
        print(
            f"[rea] skipping delivery: verdict={artifact.verdict} "
            f"score={artifact.risk_score} below gate "
            f"(min-severity={args.min_severity}, min-score={args.min_score})",
            file=sys.stderr,
        )
        return _exit_code(artifact)

    result = integration.send(artifact)
    status = "OK " if result.ok else "ERR"
    print(f"[rea] {status} {result.integration}: {result.detail}")
    if result.extra:
        print(f"[rea]     {json.dumps(result.extra, default=str)}")
    return 0 if result.ok else 1


def _coerce(value: str):
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("none", "null"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _passes_gate(artifact: Artifact, min_severity: str, min_score: int) -> bool:
    from .core.model import SEVERITY_ORDER

    threshold = SEVERITY_ORDER.get(min_severity, 0)
    if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in artifact.findings):
        return True
    return artifact.risk_score >= min_score and min_score > 0


def _exit_code(artifact: Artifact) -> int:
    return {"clean": 0, "low-risk": 0, "suspicious": 2, "malicious": 3}.get(artifact.verdict, 0)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "scan": cmd_scan,
        "batch": cmd_batch,
        "rules": cmd_rules,
        "integrations": cmd_integrations,
        "send": cmd_send,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n[rea] interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

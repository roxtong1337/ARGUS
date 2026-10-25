"""Test suite for REA, runnable with pytest or the bundled fallback runner.

    python -m tests.run        # no pytest needed
    pytest tests/ -q           # if pytest is installed

The tests deliberately exercise real code paths: real parsing of synthetic
binaries, real rule evaluation, real report rendering. Network integrations are
tested against a local HTTP server started on a loopback port, not a mock.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import contextlib
import io
import shutil
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rea.analysis import iocs, rules as rules_mod
from rea.analysis.pipeline import Pipeline
from rea.core import formats, hashing
from rea.core.model import Artifact
from rea.integrations import create as create_integration
from rea.integrations import available, describe_all
from rea.report import render
from tests import factories

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(ROOT_DIR, "samples")


# ----------------------------------------------------------------------
# A real HTTP server so integration tests exercise actual sockets.
# ----------------------------------------------------------------------


class _RecordingHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"_raw": body.decode("latin-1", "replace")}
        _RecordingHandler.received.append(
            {"path": self.path, "headers": dict(self.headers), "body": parsed}
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"healthy"}')

    def log_message(self, *args):  # silence test noise
        pass


class ServerFixture:
    """Context manager that runs a real HTTP server on a free loopback port."""

    def __init__(self):
        _RecordingHandler.received = []
        self.server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    @property
    def received(self):
        return _RecordingHandler.received

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


# ----------------------------------------------------------------------
# Format detection
# ----------------------------------------------------------------------


class TestFormats(unittest.TestCase):
    def test_detects_elf(self):
        ft = formats.detect(factories.make_elf(), "a.out")
        self.assertEqual(ft.kind, "elf")
        self.assertEqual(ft.arch, "x86-64")
        self.assertTrue(ft.is_executable)

    def test_detects_pe(self):
        ft = formats.detect(factories.make_pe(), "a.exe")
        self.assertEqual(ft.kind, "pe")
        self.assertEqual(ft.arch, "x86")

    def test_detects_script_by_shebang(self):
        ft = formats.detect(b"#!/bin/sh\necho hi\n", "x.sh")
        self.assertEqual(ft.kind, "script")

    def test_unknown_binary(self):
        ft = formats.detect(bytes(range(256)) * 4, "blob.bin")
        self.assertIn(ft.kind, ("data", "text"))

    def test_empty_file(self):
        ft = formats.detect(b"", "empty")
        self.assertEqual(ft.kind, "data")


class TestHashing(unittest.TestCase):
    def test_known_sha256(self):
        h = hashing.hash_bytes(b"abc")
        self.assertEqual(
            h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(h.md5, "900150983cd24fb0d6963f7d28e17f72")

    def test_entropy_bounds(self):
        self.assertEqual(hashing.entropy(b""), 0.0)
        self.assertAlmostEqual(hashing.entropy(b"\x00" * 100), 0.0, places=6)
        self.assertAlmostEqual(hashing.entropy(bytes(range(256)) * 10), 8.0, places=6)

    def test_fuzzy_hash_stability(self):
        a = hashing.fuzzy_hash(b"the quick brown fox" * 100)
        b = hashing.fuzzy_hash(b"the quick brown fox" * 100)
        c = hashing.fuzzy_hash(bytes(range(256)) * 40)
        self.assertEqual(a, b)
        self.assertLess(hashing.hamming_fuzzy(a, b), hashing.hamming_fuzzy(a, c))

    def test_high_entropy_ratio(self):
        random_like = bytes((i * 167 + 13) % 256 for i in range(16384))
        low = hashing.high_entropy_ratio(b"\x00" * 16384)
        high = hashing.high_entropy_ratio(random_like)
        self.assertLess(low, high)


# ----------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------


class TestParsers(unittest.TestCase):
    def test_elf_sections_and_metadata(self):
        art = Artifact.from_bytes(factories.make_elf(), "sample")
        from rea.core import loader

        loader.parse(art, factories.make_elf())
        self.assertEqual(art.file_type.kind, "elf")
        self.assertGreaterEqual(len(art.sections), 2)
        self.assertEqual(art.metadata["elf"]["class"], "ELF64")
        self.assertEqual(art.errors, [])

    def test_pe_sections_and_metadata(self):
        data = factories.make_pe(sections=4)
        art = Artifact.from_bytes(data, "sample.exe")
        from rea.core import loader

        loader.parse(art, data)
        self.assertEqual(art.file_type.kind, "pe")
        self.assertGreaterEqual(len(art.sections), 3)
        self.assertIn("pe", art.metadata)
        self.assertTrue(art.metadata["pe"]["aslr"])

    def test_truncated_elf_does_not_raise(self):
        art = Artifact.from_bytes(b"\x7fELF\x02\x01", "broken")
        from rea.core import loader

        loader.parse(art, b"\x7fELF\x02\x01")
        # either it parsed nothing or recorded an error, but it must not throw
        self.assertTrue(art.errors or not art.sections)

    def test_malformed_pe_does_not_raise(self):
        art = Artifact.from_bytes(b"MZ" + b"\x00" * 100, "broken.exe")
        from rea.core import loader

        loader.parse(art, b"MZ" + b"\x00" * 100)
        self.assertTrue(art.errors or art.metadata)

    def test_script_parser_flags_patterns(self):
        art = Artifact.from_bytes(factories.make_script_malicious(), "evil.sh")
        from rea.core import loader

        loader.parse(art, factories.make_script_malicious())
        patterns = art.metadata["script"]["suspicious_patterns"]
        self.assertIn("download_execute", patterns)
        self.assertIn("reverse_shell", patterns)


# ----------------------------------------------------------------------
# IOC extraction
# ----------------------------------------------------------------------


class TestIOCs(unittest.TestCase):
    def test_extracts_network_and_wallet_indicators(self):
        text = [
            "http://evil.example.com/stage2",
            "connect to 203.0.113.7 now",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]
        ind = iocs.extract(text)
        self.assertTrue(any("evil.example.com" in u for u in ind.get("urls", [])))
        self.assertIn("203.0.113.7", ind.get("ipv4", []))
        self.assertTrue(ind.get("crypto_wallets"))
        self.assertTrue(ind.get("registry_keys"))

    def test_filters_private_ips_and_benign_domains(self):
        ind = iocs.extract(["http://192.168.1.1/x", "http://www.w3.org/2001/xmlns"])
        self.assertNotIn("192.168.1.1", ind.get("ipv4", []))

    def test_base64_decoding(self):
        import base64

        payload = base64.b64encode(b"this is a hidden command string").decode()
        ind = iocs.extract([payload])
        self.assertTrue(any("hidden command" in b for b in ind.get("base64_blobs", [])))


# ----------------------------------------------------------------------
# Rules engine
# ----------------------------------------------------------------------


class TestRulesEngine(unittest.TestCase):
    def test_parse_simple_rule(self):
        text = """
        rule T {
            meta:
                severity = "high"
                score = 10
            strings:
                $a = "hello" nocase
            condition:
                $a
        }
        """
        rules = rules_mod.parse_rules(text)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].severity, "high")
        self.assertEqual(rules[0].score, 10)

    def test_rule_matches_nocase(self):
        rule = rules_mod.parse_rules(
            'rule T { strings: $a = "HELLO" nocase condition: $a }'
        )[0]
        matches = rules_mod.scan(b"say hello there", [rule])
        self.assertEqual(len(matches), 1)

    def test_rule_does_not_match(self):
        rule = rules_mod.parse_rules('rule T { strings: $a = "zzz" condition: $a }')[0]
        self.assertEqual(rules_mod.scan(b"nothing here", [rule]), [])

    def test_hex_pattern_with_wildcards(self):
        rule = rules_mod.parse_rules(
            "rule T { strings: $a = { 4D 5A ?? 00 } condition: $a }"
        )[0]
        self.assertEqual(len(rules_mod.scan(b"\x4d\x5a\x90\x00rest", [rule])), 1)
        self.assertEqual(rules_mod.scan(b"\x4d\x5a\x90\x01rest", [rule]), [])

    def test_count_condition(self):
        rule = rules_mod.parse_rules(
            """
            rule T {
                strings:
                    $a = "one"
                    $b = "two"
                    $c = "three"
                condition:
                    2 of them
            }
            """
        )[0]
        self.assertEqual(len(rules_mod.scan(b"one two", [rule])), 1)
        self.assertEqual(rules_mod.scan(b"one only", [rule]), [])

    def test_boolean_and_or(self):
        rule = rules_mod.parse_rules(
            """
            rule T {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    $a and not $b
            }
            """
        )[0]
        self.assertEqual(len(rules_mod.scan(b"alpha", [rule])), 1)
        self.assertEqual(rules_mod.scan(b"alpha beta", [rule]), [])

    def test_wildcard_identifier_set(self):
        rule = rules_mod.parse_rules(
            """
            rule T {
                strings:
                    $note1 = "pay up"
                    $note2 = "or else"
                    $other = "unrelated"
                condition:
                    any of ($note*)
            }
            """
        )[0]
        self.assertEqual(len(rules_mod.scan(b"pay up", [rule])), 1)
        self.assertEqual(rules_mod.scan(b"unrelated", [rule]), [])

    def test_filesize_condition(self):
        rule = rules_mod.parse_rules("rule T { condition: filesize > 100 }")[0]
        self.assertEqual(len(rules_mod.scan(b"x" * 200, [rule])), 1)
        self.assertEqual(rules_mod.scan(b"x" * 10, [rule]), [])

    def test_invalid_rule_raises(self):
        with self.assertRaises(rules_mod.RuleSyntaxError):
            rules_mod.parse_rules("rule T { strings: $a = condition: }")

    def test_bundled_pack_loads_and_matches(self):
        rules = rules_mod.load_rule_dir(RULES_DIR)
        self.assertGreaterEqual(len(rules), 8)
        sample = factories.make_script_malicious()
        matches = rules_mod.scan(sample, rules)
        names = {m.rule.name for m in matches}
        self.assertIn("Downloader_Curl_Pipe_Shell", names)
        self.assertIn("Ransomware_Shadow_Copy_Deletion", names)


# ----------------------------------------------------------------------
# Pipeline and scoring
# ----------------------------------------------------------------------


class TestPipeline(unittest.TestCase):
    def test_malicious_script_scores_high(self):
        art = Pipeline(rule_paths=[RULES_DIR]).scan_bytes(
            factories.make_script_malicious(), "evil.sh"
        )
        self.assertIn(art.verdict, ("suspicious", "malicious"))
        self.assertGreater(art.risk_score, 40)

    def test_benign_script_scores_clean(self):
        art = Pipeline(rule_paths=[RULES_DIR]).scan_bytes(
            factories.make_script_benign(), "ok.sh"
        )
        self.assertLess(art.risk_score, 40)
        self.assertIn(art.verdict, ("clean", "low-risk"))

    def test_scan_real_system_binary(self):
        candidate = None
        for path in ("/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/env"):
            if os.path.isfile(path):
                candidate = path
                break
        if candidate is None:
            self.skipTest("no system binary available")
        art = Pipeline(rule_paths=[RULES_DIR]).scan_path(candidate)
        self.assertEqual(art.file_type.kind, "elf")
        self.assertGreater(len(art.sections), 5)
        self.assertEqual(art.verdict, "clean")

    def test_pipeline_stages_can_be_disabled(self):
        art = Pipeline(
            rule_paths=[RULES_DIR],
            extract_strings=False,
            extract_iocs=False,
            run_rules=False,
            run_heuristics=False,
        ).scan_bytes(factories.make_script_malicious(), "evil.sh")
        self.assertEqual(art.strings, [])
        self.assertEqual(art.findings, [])

    def test_scan_path_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_malicious())
            art = Pipeline(rule_paths=[RULES_DIR]).scan_path(path)
            self.assertEqual(art.path, path)
            self.assertTrue(art.hashes.sha256)

    def test_capabilities_extracted(self):
        art = Pipeline(rule_paths=[RULES_DIR]).scan_bytes(
            factories.make_script_malicious(), "evil.sh"
        )
        self.assertTrue(art.stats.get("capabilities") or art.findings)


# ----------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------


class TestReports(unittest.TestCase):
    def setUp(self):
        self.art = Pipeline(rule_paths=[RULES_DIR]).scan_bytes(
            factories.make_script_malicious(), "evil.sh"
        )

    def test_json_roundtrip(self):
        data = json.loads(render(self.art, "json"))
        self.assertEqual(data["path"], "evil.sh")
        self.assertIn("hashes", data)
        self.assertIn("findings", data)

    def test_text_report_contains_key_fields(self):
        text = render(self.art, "text")
        self.assertIn("evil.sh", text)
        self.assertIn("verdict", text)
        self.assertIn(self.art.hashes.sha256, text)

    def test_markdown_report(self):
        md = render(self.art, "markdown")
        self.assertIn("# REA report", md)
        self.assertIn("| Severity |", md)

    def test_sarif_is_valid_json_with_results(self):
        doc = json.loads(render(self.art, "sarif"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_unknown_format_raises(self):
        with self.assertRaises(KeyError):
            render(self.art, "nope")


# ----------------------------------------------------------------------
# Integrations (against a real local server)
# ----------------------------------------------------------------------


class TestIntegrations(unittest.TestCase):
    def setUp(self):
        self.art = Pipeline(rule_paths=[RULES_DIR]).scan_bytes(
            factories.make_script_malicious(), "evil.sh"
        )

    @staticmethod
    def _header(request: dict, name: str) -> str:
        for key, value in request["headers"].items():
            if key.lower() == name.lower():
                return value
        return ""

    def test_registry_lists_builtin_integrations(self):
        names = available()
        for expected in ("hermes", "http", "webhook", "local", "stdout"):
            self.assertIn(expected, names)
        self.assertTrue(describe_all())

    def test_unknown_integration_raises(self):
        with self.assertRaises(KeyError):
            create_integration("does-not-exist")

    def test_local_archive_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "reports.jsonl")
            result = create_integration("local", {"path": archive}).send(self.art)
            self.assertTrue(result.ok)
            with open(archive, encoding="utf-8") as fh:
                record = json.loads(fh.readline())
            self.assertEqual(record["report"]["path"], "evil.sh")

    def test_http_integration_posts_real_payload(self):
        with ServerFixture() as server:
            result = create_integration(
                "http", {"url": f"{server.url}/ingest", "token": "secret-token"}
            ).send(self.art)
            self.assertTrue(result.ok, result.detail)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(len(server.received), 1)
            body = server.received[0]["body"]
            self.assertEqual(body["schema"], "rea.artifact/v1")
            self.assertEqual(body["artifact"]["path"], "evil.sh")
            self.assertIn("Bearer secret-token", self._header(server.received[0], "Authorization"))

    def test_webhook_signature_header_present(self):
        with ServerFixture() as server:
            result = create_integration(
                "webhook", {"url": f"{server.url}/hook", "secret": "s3cret"}
            ).send(self.art)
            self.assertTrue(result.ok, result.detail)
            signature = self._header(server.received[0], "X-REA-Signature")
            self.assertTrue(signature.startswith("sha256="), signature)

    def test_hermes_envelope_mode(self):
        with ServerFixture() as server:
            result = create_integration(
                "hermes",
                {
                    "base_url": server.url,
                    "path": "/api/v1/ingest",
                    "auth_style": "bearer",
                    "token": "tok",
                    "payload_mode": "envelope",
                },
            ).send(self.art)
            self.assertTrue(result.ok, result.detail)
            body = server.received[0]["body"]
            self.assertEqual(body["event"], "rea.scan.completed")
            self.assertEqual(body["data"]["schema"], "rea.artifact/v1")
            self.assertEqual(server.received[0]["path"], "/api/v1/ingest")

    def test_hermes_detections_mode_flattens_findings(self):
        with ServerFixture() as server:
            result = create_integration(
                "hermes",
                {
                    "base_url": server.url,
                    "path": "/ingest",
                    "payload_mode": "detections",
                    "auth_style": "apikey",
                    "api_key": "k123",
                },
            ).send(self.art)
            self.assertTrue(result.ok, result.detail)
            body = server.received[0]["body"]
            self.assertIn("events", body)
            first = body["events"][0]
            self.assertEqual(first["schema"], "rea.detection/v1")
            self.assertIn("sha256", first["artifact"])
            self.assertIn("detection", first)
            self.assertEqual(self._header(server.received[0], "X-API-Key"), "k123")

    def test_hermes_raw_mode(self):
        with ServerFixture() as server:
            result = create_integration(
                "hermes",
                {"base_url": server.url, "path": "/raw", "payload_mode": "raw"},
            ).send(self.art)
            self.assertTrue(result.ok, result.detail)
            body = server.received[0]["body"]
            self.assertEqual(body["source"], "rea")
            self.assertIn("artifact", body)

    def test_hermes_basic_auth(self):
        with ServerFixture() as server:
            create_integration(
                "hermes",
                {
                    "base_url": server.url,
                    "path": "/x",
                    "auth_style": "basic",
                    "username": "u",
                    "password": "p",
                },
            ).send(self.art)
            auth = self._header(server.received[0], "Authorization")
            self.assertTrue(auth.startswith("Basic "))

    def test_hermes_missing_base_url_reports_failure(self):
        result = create_integration("hermes", {}).send(self.art)
        self.assertFalse(result.ok)
        self.assertIn("base_url", result.detail)

    def test_hermes_invalid_mode_reports_failure(self):
        result = create_integration(
            "hermes", {"base_url": "http://127.0.0.1:1", "payload_mode": "bogus"}
        ).send(self.art)
        self.assertFalse(result.ok)

    def test_hermes_health_probe(self):
        with ServerFixture() as server:
            result = create_integration(
                "hermes", {"base_url": server.url, "path": "/health"}
            ).health()
            self.assertTrue(result.ok)
            self.assertEqual(result.status_code, 200)

    def test_hermes_unreachable_host_fails_cleanly(self):
        result = create_integration(
            "hermes",
            {"base_url": "http://127.0.0.1:9", "path": "/x", "retries": 0, "timeout": 1},
        ).send(self.art)
        self.assertFalse(result.ok)
        self.assertTrue(result.detail)

    def test_dry_run_does_not_contact_server(self):
        with ServerFixture() as server:
            result = create_integration(
                "hermes",
                {"base_url": server.url, "path": "/x", "dry_run": True},
            ).send(self.art)
            self.assertTrue(result.ok)
            self.assertEqual(server.received, [])

    def test_env_var_configuration(self):
        with ServerFixture() as server:
            os.environ["REA_HERMES_URL"] = server.url
            os.environ["REA_HERMES_PATH"] = "/from-env"
            os.environ["REA_HERMES_TOKEN"] = "envtoken"
            try:
                result = create_integration("hermes", {}).send(self.art)
            finally:
                for key in ("REA_HERMES_URL", "REA_HERMES_PATH", "REA_HERMES_TOKEN"):
                    os.environ.pop(key, None)
            self.assertTrue(result.ok, result.detail)
            self.assertEqual(server.received[0]["path"], "/from-env")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        from rea import cli

        return cli.main(argv)

    def test_scan_exit_code_clean_for_benign(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ok.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_benign())
            code = self._run(["scan", path, "--quiet", "--format", "json"])
            self.assertEqual(code, 0)

    def test_scan_exit_code_high_for_malicious(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evil.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_malicious())
            code = self._run(["scan", path, "--quiet", "--format", "json"])
            self.assertIn(code, (2, 3))

    def test_scan_writes_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "evil.sh")
            dst = os.path.join(tmp, "report.md")
            with open(src, "wb") as fh:
                fh.write(factories.make_script_malicious())
            code = self._run(["scan", src, "--quiet", "--format", "markdown", "-o", dst])
            self.assertIn(code, (2, 3))
            with open(dst, encoding="utf-8") as fh:
                self.assertIn("# REA report", fh.read())

    def test_scan_missing_file_errors(self):
        code = self._run(["scan", "/nonexistent/file", "--quiet"])
        self.assertEqual(code, 1)

    def test_batch_outputs_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in (
                ("a.sh", factories.make_script_benign()),
                ("b.sh", factories.make_script_malicious()),
            ):
                with open(os.path.join(tmp, name), "wb") as fh:
                    fh.write(content)
            out = os.path.join(tmp, "out.jsonl")
            self._run(["batch", tmp, "-o", out, "--quiet"])
            with open(out, encoding="utf-8") as fh:
                lines = [json.loads(l) for l in fh if l.strip()]
            self.assertEqual(len(lines), 2)

    def test_rules_check_valid_pack(self):
        self.assertEqual(self._run(["rules", "check", RULES_DIR]), 0)

    def test_rules_list(self):
        self.assertEqual(self._run(["rules", "list", RULES_DIR]), 0)

    def test_integrations_command(self):
        self.assertEqual(self._run(["integrations"]), 0)

    def test_send_dry_run_to_hermes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evil.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_malicious())
            code = self._run(
                [
                    "send", path, "--to", "hermes", "--dry-run", "--quiet",
                    "--set", "base_url=http://127.0.0.1:9",
                    "--set", "payload_mode=detections",
                ]
            )
            self.assertEqual(code, 0)

    def test_send_respects_min_score_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ok.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_benign())
            code = self._run(
                [
                    "send", path, "--to", "hermes", "--dry-run", "--quiet",
                    "--set", "base_url=http://127.0.0.1:9",
                    "--min-severity", "critical",
                ]
            )
            self.assertEqual(code, 0)

    def test_send_to_unknown_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ok.sh")
            with open(path, "wb") as fh:
                fh.write(factories.make_script_benign())
            code = self._run(["send", path, "--to", "nope", "--quiet"])
            self.assertEqual(code, 1)


# ----------------------------------------------------------------------
# CLI: the detonate, sandbox and agent subcommands
# ----------------------------------------------------------------------


def _docker_ready() -> bool:
    from rea.dynamic import Detonator

    ready, _ = Detonator(backend="docker").check()
    return ready


DOCKER_READY = _docker_ready()


class TestCliSandbox(unittest.TestCase):
    def _run(self, argv):
        from rea import cli

        return cli.main(argv)

    def test_sandbox_reports_readiness_and_exit_code(self):
        """The exit code must agree with what the command prints."""
        from rea.dynamic import Detonator

        ready, _ = Detonator().check()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(["sandbox"])
        text = out.getvalue()
        self.assertIn("docker", text)
        self.assertIn("local", text)
        # The local backend is never isolated, and must always say so.
        self.assertIn("NOT ISOLATED", text)
        self.assertEqual(code, 0 if ready else 1)

    def test_sandbox_never_claims_local_is_isolated(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self._run(["sandbox"])
        local_line = [l for l in out.getvalue().splitlines() if "] local" in l][0]
        self.assertIn("NOT ISOLATED", local_line)


class TestCliDetonate(unittest.TestCase):
    def _run(self, argv):
        from rea import cli

        return cli.main(argv)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rea-cli-")
        self.sample = os.path.join(self.tmp, "probe.sh")
        with open(self.sample, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nprintf 'cli-detonation-marker\\n'\n")
        os.chmod(self.sample, 0o644)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file_errors_before_touching_the_sandbox(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = self._run(["detonate", "/nonexistent/x.bin", "--quiet"])
        self.assertEqual(code, 1)

    def test_local_backend_is_refused_without_allow_unsafe(self):
        """No container runtime, no --allow-unsafe: it must refuse, not run."""
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = self._run(["detonate", self.sample, "--backend", "local", "--quiet"])
        self.assertEqual(code, 1)
        self.assertIn("unavailable", err.getvalue().lower())

    def test_unknown_backend_is_rejected_by_the_parser(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self._run(["detonate", self.sample, "--backend", "nope", "--quiet"])

    @unittest.skipUnless(DOCKER_READY, "no container runtime available")
    def test_detonate_emits_a_json_report_with_dynamic_findings(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(
                ["detonate", self.sample, "--timeout", "25", "--format", "json", "--quiet"]
            )
        payload = json.loads(out.getvalue())
        self.assertIn(code, (0, 2, 3))
        self.assertIn("stats", payload)
        dynamic = payload["stats"]["dynamic"]
        self.assertTrue(dynamic["executed"])
        self.assertTrue(dynamic["isolated"])
        self.assertGreater(dynamic["telemetry"]["event_count"], 0)

    @unittest.skipUnless(DOCKER_READY, "no container runtime available")
    def test_detonate_writes_report_to_a_file(self):
        dst = os.path.join(self.tmp, "report.md")
        with contextlib.redirect_stderr(io.StringIO()):
            self._run(["detonate", self.sample, "--timeout", "25",
                       "--format", "markdown", "-o", dst, "--quiet"])
        with open(dst, encoding="utf-8") as handle:
            self.assertIn("# REA report", handle.read())

    @unittest.skipUnless(DOCKER_READY, "no container runtime available")
    def test_detonate_non_runnable_format_is_reported_not_crashed(self):
        """A PE cannot run on Linux; the run must still produce a report."""
        path = os.path.join(self.tmp, "thing.exe")
        with open(path, "wb") as handle:
            handle.write(b"MZ" + b"\x00" * 200)
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = self._run(["detonate", path, "--timeout", "20", "--format", "json", "--quiet"])
        payload = json.loads(out.getvalue())
        self.assertIsInstance(code, int)
        self.assertIn("skipped", err.getvalue().lower() + json.dumps(payload).lower())


class TestCliAgent(unittest.TestCase):
    def _run(self, argv):
        from rea import cli

        return cli.main(argv)

    def test_agent_exec_scan_prints_a_verdict(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(["agent", "--no-colour", "--exec", f"scan {SAMPLES_DIR}/malicious_sample.sh"])
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ARGUS", text)
        self.assertIn("MALICIOUS", text)

    def test_agent_exec_full_runs_scan_then_detonate(self):
        if not DOCKER_READY:
            self.skipTest("no container runtime available")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(
                ["agent", "--no-colour", "--exec", f"full {SAMPLES_DIR}/malicious_sample.sh"]
            )
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("scan", text)
        self.assertIn("detonate", text)
        self.assertIn("syscall event", text)

    def test_agent_exec_help_lists_capabilities(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(["agent", "--no-colour", "--exec", "help"])
        self.assertEqual(code, 0)
        self.assertIn("detonate", out.getvalue())

    def test_agent_exec_sandbox_reports_backend(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(["agent", "--no-colour", "--exec", "sandbox"])
        self.assertEqual(code, 0)
        self.assertIn("docker", out.getvalue())

    def test_agent_exec_accepts_repeated_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run([
                "agent", "--no-colour",
                "--exec", "integrations",
                "--exec", "rules",
            ])
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("hermes", text)

    def test_agent_exec_unknown_command_does_not_crash(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = self._run(["agent", "--no-colour", "--exec", "exfiltrate everything"])
        self.assertEqual(code, 0)
        self.assertIn("ARGUS", out.getvalue())

    def test_agent_web_mode_serves_the_api(self):
        """Start the real server on a free port, hit it, then shut it down."""
        from rea.web.server import make_server

        server = make_server(host="127.0.0.1", port=0, token="")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=30) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["agent"], "ARGUS")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

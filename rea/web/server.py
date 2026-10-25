"""ARGUS web front-end.

A small JSON API plus a single-page UI, built on ``http.server`` so it needs no
web framework. It exposes exactly the same :class:`~rea.agent.session.AgentSession`
the terminal interface drives, so the two front-ends cannot diverge.

Endpoints:

``GET  /``                the single-page UI
``GET  /api/health``      liveness, agent name and sandbox readiness
``GET  /api/tools``       the capability catalogue
``GET  /api/state``       the current session snapshot
``POST /api/command``     ``{"text": "scan /path"}`` — run a request
``POST /api/upload``      raw bytes, filename in ``?name=`` — scan an upload

Deployment notes:

* binds ``127.0.0.1`` by default; use ``--host 0.0.0.0`` deliberately
* uploads are written to a private temp directory with a sanitised basename,
  never to a path the client controls
* an optional shared token (``--token`` or ``REA_WEB_TOKEN``) gates every API
  call, because this service can execute samples
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import tempfile
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from ..agent import AGENT_NAME, AGENT_TAGLINE
from ..agent.session import AgentSession

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_UPLOAD = 64 << 20  # 64 MiB
COOKIE_NAME = "argus_sid"

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class SessionStore:
    """One agent session per browser, keyed by cookie."""

    def __init__(self, ttl_seconds: int = 3600):
        self._sessions: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        self.ttl = ttl_seconds

    def get(self, sid: Optional[str]) -> tuple:
        with self._lock:
            self._reap()
            if sid and sid in self._sessions:
                session, _ = self._sessions[sid]
                self._sessions[sid] = (session, time.time())
                return sid, session
            new_sid = secrets.token_urlsafe(18)
            session = AgentSession()
            self._sessions[new_sid] = (session, time.time())
            return new_sid, session

    def _reap(self) -> None:
        now = time.time()
        stale = [sid for sid, (_, seen) in self._sessions.items() if now - seen > self.ttl]
        for sid in stale:
            self._sessions.pop(sid, None)


def _sanitise_filename(name: str) -> str:
    base = os.path.basename(name or "").strip() or "upload.bin"
    cleaned = _SAFE_NAME_RE.sub("_", base).lstrip(".") or "upload.bin"
    return cleaned[:120]


class ArgusHandler(BaseHTTPRequestHandler):
    server_version = "ARGUS"
    sys_version = ""

    # injected by the server factory
    store: SessionStore
    token: str = ""
    detonator_factory = None

    # ---- plumbing ------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # quieter default logging
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send_json(self, payload: dict, status: int = HTTPStatus.OK, cookie: str = "") -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if cookie:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}={cookie}; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, content_type: str, status: int = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json({"ok": False, "error": message}, status=status)

    def _authorised(self) -> bool:
        if not self.token:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer ") and secrets.compare_digest(header[7:], self.token):
            return True
        return secrets.compare_digest(self.headers.get("X-Argus-Token", ""), self.token)

    def _session(self) -> tuple:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie[COOKIE_NAME].value if COOKIE_NAME in cookie else None
        return self.store.get(sid)

    def _read_body(self, limit: int = MAX_UPLOAD) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > limit:
            raise ValueError(f"body too large: {length} bytes (limit {limit})")
        return self.rfile.read(length)

    # ---- routes --------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path

        if route in ("/", "/index.html"):
            return self._serve_static("index.html")
        if route.startswith("/static/"):
            return self._serve_static(route[len("/static/"):])

        if route.startswith("/api/") and not self._authorised():
            return self._error(HTTPStatus.UNAUTHORIZED, "missing or invalid token")

        if route == "/api/health":
            sandbox = {"ready": False, "reason": "not initialised"}
            if self.detonator_factory is not None:
                try:
                    detonator = self.detonator_factory()
                    ready, reason = detonator.check()
                    sandbox = {"ready": ready, "reason": reason, "backend": detonator.backend_name}
                except Exception as exc:
                    sandbox = {"ready": False, "reason": str(exc)}
            return self._send_json({
                "ok": True,
                "agent": AGENT_NAME,
                "tagline": AGENT_TAGLINE,
                "sandbox": sandbox,
                "version": "1.0",
            })

        if route == "/api/tools":
            _, session = self._session()
            return self._send_json({"ok": True, "tools": session.tools()})

        if route == "/api/state":
            sid, session = self._session()
            return self._send_json({"ok": True, "state": session.snapshot()}, cookie=sid)

        return self._error(HTTPStatus.NOT_FOUND, "unknown route")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path

        if not self._authorised():
            return self._error(HTTPStatus.UNAUTHORIZED, "missing or invalid token")

        if route == "/api/command":
            return self._handle_command()
        if route == "/api/upload":
            return self._handle_upload(parsed.query)
        return self._error(HTTPStatus.NOT_FOUND, "unknown route")

    def _handle_command(self) -> None:
        try:
            payload = json.loads(self._read_body(1 << 20) or b"{}")
        except ValueError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except json.JSONDecodeError:
            return self._error(HTTPStatus.BAD_REQUEST, "body must be JSON")

        text = str(payload.get("text", "")).strip()
        if not text:
            return self._error(HTTPStatus.BAD_REQUEST, "missing 'text'")

        sid, session = self._session()
        try:
            session.handle(text)
        except Exception as exc:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"agent error: {exc}")
        return self._send_json({"ok": True, "state": session.snapshot()}, cookie=sid)

    def _handle_upload(self, query: str) -> None:
        params = parse_qs(query)
        name = _sanitise_filename((params.get("name") or ["upload.bin"])[0])
        try:
            data = self._read_body()
        except ValueError as exc:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, str(exc))
        if not data:
            return self._error(HTTPStatus.BAD_REQUEST, "empty upload")

        sid, session = self._session()
        workdir = tempfile.mkdtemp(prefix="argus-upload-")
        target = os.path.join(workdir, name)
        try:
            with open(target, "wb") as handle:
                handle.write(data)
            os.chmod(target, 0o600)
            session.handle(f"scan {target}")
        except Exception as exc:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"scan failed: {exc}")
        finally:
            # The artifact carries the report; the bytes are no longer needed.
            try:
                os.remove(target)
                os.rmdir(workdir)
            except OSError:
                pass
        return self._send_json({"ok": True, "state": session.snapshot()}, cookie=sid)

    # ---- static --------------------------------------------------------

    def _serve_static(self, relative: str) -> None:
        safe = os.path.normpath("/" + relative).lstrip("/")
        if safe.startswith("..") or os.path.isabs(safe):
            return self._error(HTTPStatus.FORBIDDEN, "invalid path")
        full = os.path.join(STATIC_DIR, safe)
        if not os.path.isfile(full):
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        content_type, _ = mimetypes.guess_type(full)
        with open(full, "rb") as handle:
            body = handle.read()
        self._send_bytes(body, content_type or "application/octet-stream")


def make_server(
    host: str = "127.0.0.1",
    port: int = 12000,
    token: str = "",
    verbose: bool = False,
    detonator_factory=None,
) -> ThreadingHTTPServer:
    """Build (but do not start) the HTTP server."""
    handler = type("BoundArgusHandler", (ArgusHandler,), {
        "store": SessionStore(),
        "token": token,
        # staticmethod, otherwise Python binds it to the handler instance and
        # the factory is called with an unexpected `self`.
        "detonator_factory": staticmethod(detonator_factory) if detonator_factory else None,
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.verbose = verbose
    return server


def serve(host: str = "127.0.0.1", port: int = 12000, token: str = "", verbose: bool = False) -> int:
    """Run the web front-end until interrupted."""
    from ..dynamic import Detonator

    def detonator_factory():
        return Detonator()

    server = make_server(host, port, token=token, verbose=verbose,
                         detonator_factory=detonator_factory)
    display_host = "localhost" if host in ("0.0.0.0", "127.0.0.1") else host
    print(f"  {AGENT_NAME} web interface")
    print(f"  http://{display_host}:{server.server_address[1]}/")
    if host == "0.0.0.0":
        print("  listening on all interfaces — anyone who can reach this port can run samples")
    if token:
        print("  token authentication is enabled")
    print("  press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down")
    finally:
        server.server_close()
    return 0

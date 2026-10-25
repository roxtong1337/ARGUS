"""Shared HTTP plumbing built on urllib so there is no external dependency."""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


def post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
    retries: int = 2,
    backoff: float = 0.8,
    verify_tls: bool = True,
) -> Tuple[int, str]:
    """POST a JSON body, retrying transient failures.

    Returns ``(status_code, body)``. Raises the last error if every attempt
    fails, so callers can decide how to surface it.
    """
    body = json.dumps(payload, default=str).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    hdrs.update(headers or {})

    ctx = None
    if url.lower().startswith("https") and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace") if exc.fp else ""
            # 4xx other than 429 are not worth retrying.
            if exc.code < 500 and exc.code != 429:
                return exc.code, detail
            last_error = RuntimeError(f"HTTP {exc.code}: {detail[:300]}")
        except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError) as exc:
            last_error = exc
        if attempt < retries:
            time.sleep(backoff * (2**attempt))

    raise RuntimeError(f"request to {url} failed: {last_error}")


def get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> Tuple[int, str]:
    hdrs = {"Accept": "application/json"}
    hdrs.update(headers or {})
    ctx = None
    if url.lower().startswith("https") and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace") if exc.fp else ""


def join_url(base: str, *parts: str) -> str:
    base = base.rstrip("/")
    tail = "/".join(p.strip("/") for p in parts if p)
    return f"{base}/{tail}" if tail else base

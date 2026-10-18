# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Tools, cache, auth, alerts, rate limiting, telemetry — no external services."""
import time

import pytest
from fastapi import HTTPException

from harnis.alerts import AlertDispatcher, discord_payload, slack_payload
from harnis.auth import decode_token, mint_token
from harnis.tools import WorkspaceError, safe_path

fakeredis = pytest.importorskip("fakeredis")


# -- tools --------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["/etc/passwd", "../../etc/passwd", "a/../../x"])
def test_safe_path_blocks_escape(tmp_path, bad):
    with pytest.raises(WorkspaceError):
        safe_path(tmp_path, bad)


def test_safe_path_blocks_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside_dir"
    outside.mkdir(exist_ok=True)
    try:
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs Developer Mode or admin rights on Windows")
    with pytest.raises(WorkspaceError):
        safe_path(tmp_path, "link/passwd")


@pytest.mark.parametrize("bad", [
    "C:\\Windows\\system32", "c:/x", "C:relative", "\\\\server\\share\\f", "\\rooted",
    "..\\..\\escape.txt", "a\\..\\..\\b", "~/secrets", "nul.txt", "COM1", "con",
    "bad:name.py", "trailing.", "x/ space ", "a\x00b",
])
def test_paths_rejected_on_every_os(tmp_path, bad):
    """These are checked by string rules, so they fail identically on Linux,
    macOS and Windows."""
    with pytest.raises(WorkspaceError):
        safe_path(tmp_path, bad)


def test_backslashes_and_dots_normalize_to_posix(tmp_path):
    from harnis.tools import normalize_rel
    assert normalize_rel("src\\pkg\\mod.py") == "src/pkg/mod.py"
    assert normalize_rel("./src//a.py") == "src/a.py"
    assert safe_path(tmp_path, "src\\a.py") == (tmp_path / "src" / "a.py").resolve()


def test_text_io_is_utf8_and_preserves_newlines(tmp_path):
    from harnis.tools import read_text, write_text
    p = tmp_path / "f.txt"
    write_text(p, "caf\u00e9\r\nline2\n")
    assert p.read_bytes() == "caf\u00e9\r\nline2\n".encode("utf-8")
    assert read_text(p) == "caf\u00e9\r\nline2\n"


def test_list_workspace_uses_forward_slashes(tmp_path):
    from harnis.tools import list_workspace
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "c.py").write_bytes(b"")
    assert list_workspace(tmp_path) == ["a/b/c.py"]


# -- cache --------------------------------------------------------------------
def test_cache_is_tenant_and_scope_isolated():
    from harnis.cache import SemanticCache

    c = SemanticCache(fakeredis.FakeRedis(), threshold=0.1)
    c.store("acme", "support:v0", "What are your opening hours?", "9 to 5")
    assert c.lookup("acme", "support:v0", "what are your opening hours") == "9 to 5"
    assert c.lookup("globex", "support:v0", "What are your opening hours?") is None
    assert c.lookup("acme", "support:v1", "What are your opening hours?") is None
    assert c.lookup("acme", "support:v0", "How do I reset my password?") is None


# -- auth ---------------------------------------------------------------------
def test_token_roundtrip_and_tampering():
    t = mint_token("alice", "acme", ["user"])
    p = decode_token(t)
    assert (p.user_id, p.tenant_id, p.has("user"), p.has("reviewer")) == ("alice", "acme", True, False)
    head, body, sig = t.split(".")
    with pytest.raises(HTTPException):
        decode_token(f"{head}.{body}.{sig[:-2]}xx")


def test_alg_none_is_rejected():
    import jwt
    forged = jwt.encode({"sub": "x", "tenant_id": "acme", "roles": ["admin"], "exp": int(time.time()) + 60,
                         "iss": "harnis", "aud": "harnis-api"}, key=None, algorithm="none")
    with pytest.raises(HTTPException):
        decode_token(forged)


def test_unsafe_ids_rejected():
    with pytest.raises(ValueError):
        mint_token("alice", "../etc", ["user"])
    with pytest.raises(ValueError):
        mint_token("a:b", "acme", ["user"])


def test_expired_token_rejected():
    with pytest.raises(HTTPException):
        decode_token(mint_token("a", "acme", ["user"], ttl_seconds=-10))


# -- alerts -------------------------------------------------------------------
def test_alert_payload_shapes():
    s = slack_payload("loop_detected", "acme", "s1", {"status": "escalated"})
    d = discord_payload("loop_detected", "acme", "s1", {"status": "escalated"})
    assert "blocks" in s and s["text"]
    assert d["embeds"][0]["title"].endswith("loop_detected")


def test_alerts_are_deduplicated():
    a = AlertDispatcher(redis=fakeredis.FakeRedis(), dedupe_seconds=60)
    a("loop_detected", "acme", "s1", {})
    a("loop_detected", "acme", "s2", {})
    a("loop_detected", "globex", "s3", {})
    assert len(a.sent) == 2


# -- rate limiting ------------------------------------------------------------
def test_token_bucket():
    from harnis.infra import RateLimiter, SessionLock

    r = fakeredis.FakeRedis()
    rl = RateLimiter(r, capacity=2, refill_per_second=0.01)
    assert rl.allow("acme", "u")[0] and rl.allow("acme", "u")[0]
    allowed, wait = rl.allow("acme", "u")
    assert not allowed and wait > 0
    assert rl.allow("acme", "other")[0]  # buckets are per user

    lock = SessionLock(r)
    with lock.hold("s1") as a:
        with lock.hold("s1") as b:
            assert a and not b
    with lock.hold("s1") as c:
        assert c


# -- telemetry ----------------------------------------------------------------
def test_latency_processor_alerts_on_slow_span():
    from opentelemetry.sdk.trace import TracerProvider

    from harnis.telemetry import LatencyAlertProcessor

    fired = []
    provider = TracerProvider()
    provider.add_span_processor(LatencyAlertProcessor({"slow.op": 5}, lambda *a: fired.append(a)))
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("slow.op"):
        time.sleep(0.02)
    with tracer.start_as_current_span("fast.op"):
        pass
    assert len(fired) == 1 and fired[0][3]["span"] == "slow.op"


# -- telemetry: collector down -------------------------------------------------------
def test_collector_down_filter_rate_limits_exporter_noise():
    import logging

    from harnis.telemetry import CollectorDownFilter

    now = [0.0]
    f = CollectorDownFilter("http://127.0.0.1:4317", interval=300, clock=lambda: now[0])

    def rec(msg):
        return logging.LogRecord("opentelemetry.exporter.otlp.proto.grpc.exporter", logging.WARNING, "x", 1,
                                 msg, (), None)

    first = rec("Transient error StatusCode.UNAVAILABLE encountered while exporting traces")
    assert f.filter(first) and "python tasks.py up" in first.getMessage()
    assert not any(f.filter(rec("Failed to export traces to 127.0.0.1:4317")) for _ in range(19))
    assert not f.filter(rec("Queue full, dropping Span."))
    now[0] = 301
    again = rec("Failed to export traces to 127.0.0.1:4317")
    assert f.filter(again) and "20 similar messages suppressed" in again.getMessage()
    assert f.filter(rec("some unrelated message"))


def test_collector_reachable_handles_closed_port():
    import socket

    from harnis.telemetry import collector_reachable

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert not collector_reachable(f"http://127.0.0.1:{port}", timeout=0.5)
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0)); srv.listen()
        assert collector_reachable(f"http://127.0.0.1:{srv.getsockname()[1]}")

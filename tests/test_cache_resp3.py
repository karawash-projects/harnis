# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The RediSearch path of the semantic cache under redis-py 8 (RESP3 wire) with
OpenTelemetry's Redis instrumentation enabled.

No search-enabled server is needed: the client's network layer is replaced by
one that returns the RESP3 reply Redis 8 / Redis Stack sends for FT.SEARCH, so
the real redis-py parser and the real instrumentation hook both run.
"""
import pytest
import redis
from opentelemetry.sdk.trace import TracerProvider

from harnis.cache import SemanticCache, first_hit

RESP3_REPLY = {
    b"attributes": [],
    b"format": b"STRING",
    b"results": [{
        b"id": b"hcache:acme:abc",
        b"extra_attributes": {b"response": b"We open 9 to 5.", b"dist": b"0.0123"},
        b"values": [],
    }],
    b"total_results": 1,
    b"warning": [],
}


def fake_client(reply=RESP3_REPLY) -> redis.Redis:
    r = redis.Redis()  # never connects: the command layer below is replaced

    def _execute_command(*args, **options):
        cmd = args[0].upper() if isinstance(args[0], str) else args[0]
        if cmd == "FT.SEARCH":
            return reply
        if cmd == "FT.INFO":
            return {b"index_name": b"idx:harnis_cache"}
        raise AssertionError(f"unexpected command {args!r}")

    r._execute_command = _execute_command  # type: ignore[method-assign]
    return r


@pytest.fixture
def instrumented():
    from opentelemetry.instrumentation.redis import RedisInstrumentor

    import opentelemetry.instrumentation.redis as otel_redis

    original_hook = otel_redis._add_search_attributes
    inst = RedisInstrumentor()
    inst.instrument(tracer_provider=TracerProvider())
    yield otel_redis
    inst.uninstrument()
    otel_redis._add_search_attributes = original_hook


def _search(r):
    from redis.commands.search.query import Query

    q = Query("*=>[KNN 1 @embedding $v AS dist]").return_fields("response", "dist").dialect(2)
    return r.ft("idx:harnis_cache").search(q, query_params={"v": b"\x00" * 8})


def test_reproduces_upstream_instrumentation_crash(instrumented):
    """Without the guard, the tracing hook raises KeyError: 0 inside the Redis
    call (the error reported from Windows)."""
    with pytest.raises(KeyError):
        _search(fake_client())


def test_guard_keeps_search_working_under_instrumentation(instrumented):
    from harnis.telemetry import _guard_redis_search_attributes

    _guard_redis_search_attributes()
    assert first_hit(_search(fake_client())) == ("We open 9 to 5.", pytest.approx(0.0123))


def test_semantic_cache_reads_redis8_reply(instrumented):
    from harnis.telemetry import _guard_redis_search_attributes

    _guard_redis_search_attributes()
    cache = SemanticCache(fake_client(), threshold=0.05)
    assert cache.vector_search
    assert cache.lookup("acme", "support:v0", "When are you open?") == "We open 9 to 5."
    far = {**RESP3_REPLY, b"results": [{b"id": b"x", b"values": [],
                                        b"extra_attributes": {b"response": b"no", b"dist": b"0.9"}}]}
    assert SemanticCache(fake_client(far), threshold=0.05).lookup("acme", "s", "q") is None


def test_first_hit_accepts_native_resp3_dict():
    assert first_hit(RESP3_REPLY) == ("We open 9 to 5.", pytest.approx(0.0123))
    assert first_hit({b"results": [], b"total_results": 0}) is None


def test_cache_failure_never_fails_a_turn(store, make_orch):
    class Broken:
        def lookup(self, *a):
            raise KeyError(0)

        def store(self, *a):
            raise RuntimeError("redis down")

    orch = make_orch(store, cache=Broken())
    rec = orch.start_turn(store.new_session(), "What are your opening hours?")
    assert rec.status == "completed"
    assert "cache_error" in rec.state["flags"]


def test_cache_uses_fallback_off_db_zero_and_survives_a_dropped_index():
    """RediSearch only indexes db 0, and a FLUSHDB on any database drops every
    index (found on a real Redis Stack during the EC2 test run)."""
    import fakeredis

    from harnis.cache import SemanticCache

    assert SemanticCache(fakeredis.FakeRedis(db=15)).vector_search is False

    class Dropped:
        def search(self, *a, **k):
            raise Exception("idx:harnis_cache: no such index")

    cache = SemanticCache(fakeredis.FakeRedis(db=15))
    cache.vector_search = True
    cache.r.ft = lambda name: Dropped()
    recreated = []
    cache._init_index = lambda: recreated.append(True) or True
    assert cache.lookup("acme", "support:v0", "hours?") is None and recreated == [True]

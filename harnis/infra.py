# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Redis-backed primitives shared by every API replica:
rate limiting, per-session locks, and the event bus."""
from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

import redis as redis_lib

_TOKEN_BUCKET = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1]) or capacity
local ts = tonumber(data[2]) or now
tokens = math.min(capacity, tokens + (now - ts) * refill)
local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end
redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, math.ceil(capacity / refill) + 60)
local wait = 0
if allowed == 0 then wait = (cost - tokens) / refill end
return {allowed, tostring(wait)}
"""


class RateLimiter:
    """Token bucket per (tenant, user), atomic in Redis via Lua."""

    def __init__(self, r: redis_lib.Redis, capacity: int, refill_per_second: float):
        self.r = r
        self.capacity = capacity
        self.refill = refill_per_second
        self._script = r.register_script(_TOKEN_BUCKET)

    def allow(self, tenant_id: str, user_id: str, cost: int = 1) -> tuple[bool, float]:
        allowed, wait = self._script(keys=[f"ratelimit:{tenant_id}:{user_id}"],
                                     args=[self.capacity, self.refill, time.time(), cost])
        return bool(int(allowed)), float(wait)


class SessionLock:
    """Prevents two turns on the same session from running at once (across
    replicas). Optimistic versioning in Postgres is the second line of defence."""

    _RELEASE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"

    def __init__(self, r: redis_lib.Redis, ttl_seconds: int = 900):
        self.r = r
        self.ttl = ttl_seconds
        self._release = r.register_script(self._RELEASE)

    @contextmanager
    def hold(self, session_id: str) -> Iterator[bool]:
        token = uuid.uuid4().hex
        key = f"lock:session:{session_id}"
        acquired = bool(self.r.set(key, token, nx=True, ex=self.ttl))
        try:
            yield acquired
        finally:
            if acquired:
                self._release(keys=[key], args=[token])


class EventBus:
    """Fan-out of session events to WebSocket clients on any replica.
    Channels: events:{tenant}:user:{user_id} and events:{tenant}:reviewers."""

    def __init__(self, r: redis_lib.Redis):
        self.r = r

    def publish(self, tenant_id: str, channel: str, event: dict[str, Any]) -> None:
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)  # W3C traceparent, so the UI can link events to traces
        event = {**event, "trace": carrier, "ts": time.time()}
        self.r.publish(f"events:{tenant_id}:{channel}", json.dumps(event, default=str))

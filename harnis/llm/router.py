# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Failover router with retries, jittered backoff and a shared circuit breaker.

* Retries only errors that can succeed on retry (429/5xx/timeouts), with
  exponential backoff and full jitter, and never sleeps after the last attempt.
* Fails over to the next provider on retryable errors and on auth/config
  errors; raises immediately on a bad request (another provider won't help).
* Circuit-breaker state lives in Redis so every API replica agrees that a
  provider is down. Without Redis (unit tests, CLI) it falls back to memory.
* Each tenant has an allow-list of providers: failover never sends a tenant's
  data to a provider they haven't approved.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Callable, Iterable

from opentelemetry import trace

from .. import metrics
from .pricing import cost_usd
from .types import LLMRequest, LLMResponse, Provider, ProviderError

log = logging.getLogger(__name__)
tracer = trace.get_tracer("harnis.llm")


class CircuitBreaker:
    def __init__(self, redis=None, threshold: int = 3, open_seconds: int = 60):
        self.redis = redis
        self.threshold = threshold
        self.open_seconds = open_seconds
        self._mem_failures: dict[str, int] = {}
        self._mem_open_until: dict[str, float] = {}

    def is_open(self, key: str) -> bool:
        if self.redis is not None:
            return bool(self.redis.exists(f"circuit:open:{key}"))
        return self._mem_open_until.get(key, 0) > time.time()

    def record_failure(self, key: str) -> bool:
        """Returns True if this failure tripped the breaker."""
        if self.redis is not None:
            n = self.redis.incr(f"circuit:fail:{key}")
            self.redis.expire(f"circuit:fail:{key}", self.open_seconds)
            if n >= self.threshold:
                self.redis.set(f"circuit:open:{key}", 1, ex=self.open_seconds)
                self.redis.delete(f"circuit:fail:{key}")
                return True
            return False
        n = self._mem_failures.get(key, 0) + 1
        self._mem_failures[key] = n
        if n >= self.threshold:
            self._mem_open_until[key] = time.time() + self.open_seconds
            self._mem_failures[key] = 0
            return True
        return False

    def record_success(self, key: str) -> None:
        if self.redis is not None:
            self.redis.delete(f"circuit:fail:{key}")
        else:
            self._mem_failures[key] = 0


class AllProvidersFailed(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("all providers failed: " + " | ".join(errors))
        self.errors = errors


class LLMRouter:
    def __init__(self, providers: list[Provider], breaker: CircuitBreaker | None = None,
                 max_retries: int = 3, backoff_base: float = 0.5,
                 sleep: Callable[[float], None] = time.sleep,
                 on_trip: Callable[[str], None] | None = None):
        self.providers = providers
        self.breaker = breaker or CircuitBreaker()
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.sleep = sleep
        self.on_trip = on_trip

    def _backoff(self, attempt: int) -> float:
        # Full jitter: uniform(0, base * 2^attempt), capped.
        return random.uniform(0, min(8.0, self.backoff_base * (2 ** attempt)))

    def complete(self, req: LLMRequest, allowed: Iterable[str] | None = None) -> LLMResponse:
        allowed_set = set(allowed) if allowed is not None else None
        chain = [p for p in self.providers if allowed_set is None or p.name in allowed_set]
        if not chain:
            raise AllProvidersFailed(["no provider is allowed for this tenant"])
        errors: list[str] = []
        for provider in chain:
            model = provider.model_for(req.tier)
            key = f"{provider.name}:{model}"
            if self.breaker.is_open(key):
                errors.append(f"{key}: circuit open")
                continue
            for attempt in range(self.max_retries):
                with tracer.start_as_current_span("gen_ai.chat") as span:
                    # OpenTelemetry GenAI semantic conventions.
                    span.set_attribute("gen_ai.operation.name", "chat")
                    span.set_attribute("gen_ai.provider.name", provider.name)
                    span.set_attribute("gen_ai.request.model", model)
                    span.set_attribute("gen_ai.request.max_tokens", req.max_tokens)
                    span.set_attribute("harnis.attempt", attempt + 1)
                    started = time.perf_counter()
                    try:
                        resp = provider.complete(req)
                    except ProviderError as exc:
                        metrics.LLM_CALLS.labels(provider.name, metrics.safe(model), "error").inc()
                        metrics.LLM_LATENCY.labels(provider.name).observe(time.perf_counter() - started)
                        span.record_exception(exc)
                        span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
                        errors.append(f"{key} attempt {attempt + 1}: {exc}")
                        log.warning("provider error %s (status=%s retryable=%s)", key, exc.status, exc.retryable)
                        if not exc.failover:
                            raise  # bad request: surface it, don't burn the other providers
                        if exc.retryable and attempt < self.max_retries - 1:
                            self.sleep(self._backoff(attempt))
                            continue
                        break  # not retryable, or retries exhausted -> next provider
                    span.set_attribute("gen_ai.response.model", resp.model)
                    span.set_attribute("gen_ai.usage.input_tokens", resp.usage.input_tokens)
                    span.set_attribute("gen_ai.usage.output_tokens", resp.usage.output_tokens)
                    span.set_attribute("gen_ai.response.finish_reasons", [resp.stop_reason])
                    self.breaker.record_success(key)
                    metrics.LLM_LATENCY.labels(provider.name).observe(time.perf_counter() - started)
                    m = metrics.safe(resp.model or model)
                    metrics.LLM_CALLS.labels(provider.name, m, "ok").inc()
                    metrics.LLM_TOKENS.labels(provider.name, m, "input").inc(resp.usage.input_tokens)
                    metrics.LLM_TOKENS.labels(provider.name, m, "output").inc(resp.usage.output_tokens)
                    metrics.LLM_COST.labels(provider.name, m).inc(
                        cost_usd(resp.model or model, resp.usage.input_tokens, resp.usage.output_tokens))
                    return resp
            if self.breaker.record_failure(key):
                metrics.CIRCUIT_OPEN.labels(provider.name).inc()
                if self.on_trip:
                    self.on_trip(key)
        raise AllProvidersFailed(errors)


def aws_session(settings):
    """boto3 session from settings. Keys given in .env are passed explicitly;
    otherwise boto3's own chain applies (env vars, AWS_PROFILE/SSO, IAM role)."""
    import boto3

    keys = {}
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        keys = {"aws_access_key_id": settings.aws_access_key_id,
                "aws_secret_access_key": settings.aws_secret_access_key,
                "aws_session_token": settings.aws_session_token or None}
    return boto3.Session(profile_name=None if keys else (settings.aws_profile or None),
                         region_name=settings.aws_region, **keys)


def _aws_credentials_available(settings) -> bool:
    try:
        return aws_session(settings).get_credentials() is not None
    except Exception:  # unknown profile, botocore not installed, ...
        return False


def build_router(settings, redis=None, on_trip=None, registry=None) -> LLMRouter:
    """Providers in LLM_PROVIDERS order, built by the factories in the plugin
    registry; a provider without credentials is skipped (and logged), so the
    same chain works with whichever keys you have."""
    from ..plugins import default_registry

    registry = registry or default_registry()
    providers: list[Provider] = []
    for name in settings.provider_chain:
        factory = registry.providers.get(name)
        if factory is None:
            log.warning("unknown LLM provider %r in LLM_PROVIDERS (registered: %s)", name,
                        ", ".join(sorted(registry.providers)))
            continue
        provider = factory(settings)
        if provider is None:
            log.info("LLM provider %r skipped: not configured", name)
            continue
        providers.append(provider)
    if not providers:
        raise RuntimeError("no LLM provider configured: set ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, "
                           "OPENAI_COMPATIBLE_BASE_URL or AWS_REGION + AWS credentials, or include 'mock' "
                           "in LLM_PROVIDERS")
    log.info("LLM failover chain: %s", " -> ".join(p.name for p in providers))
    breaker = CircuitBreaker(redis, settings.circuit_failure_threshold, settings.circuit_open_seconds)
    return LLMRouter(providers, breaker, settings.llm_max_retries, settings.llm_backoff_base_seconds,
                     on_trip=on_trip)

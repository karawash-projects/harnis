# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Prometheus metrics, served at /metrics (METRICS_ENABLED, optionally behind
METRICS_TOKEN).

Labels never carry tenant or user ids, prompts or commands: cardinality stays
bounded and nothing sensitive reaches the monitoring system. Per-tenant usage
and cost are in the database (/v1/usage, /v1/analytics).

Each API process keeps its own counters, so scrape every replica (the Helm
chart annotates the Pods for Prometheus). Run one uvicorn worker per Pod and
scale with replicas, or use prometheus_client's multiprocess mode.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

HTTP_REQUESTS = Counter("harnis_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram("harnis_http_request_duration_seconds", "HTTP request duration", ["method", "route"],
                         buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120))
TURNS = Counter("harnis_turns_total", "Agent turns that ended, by final status and agent", ["status", "agent"])
TURN_LATENCY = Histogram("harnis_turn_duration_seconds", "Wall-clock time of a turn (until it ends or suspends)",
                         buckets=(0.1, 0.5, 1, 2.5, 5, 10, 20, 40, 60, 120, 300))
TOOL_CALLS = Counter("harnis_tool_calls_total", "Tool calls by tool and outcome", ["tool", "outcome"])
APPROVALS_REQUESTED = Counter("harnis_approvals_requested_total", "Actions suspended for approval", ["tool"])
APPROVAL_DECISIONS = Counter("harnis_approval_decisions_total", "Approval decisions", ["decision"])
LLM_CALLS = Counter("harnis_llm_calls_total", "Model calls by provider, model and outcome",
                    ["provider", "model", "outcome"])
LLM_LATENCY = Histogram("harnis_llm_call_duration_seconds", "Model call duration", ["provider"],
                        buckets=(0.25, 0.5, 1, 2, 4, 8, 15, 30, 60, 120))
LLM_TOKENS = Counter("harnis_llm_tokens_total", "Tokens by provider, model and direction",
                     ["provider", "model", "direction"])
LLM_COST = Counter("harnis_llm_cost_usd_total", "Estimated model cost in USD (see /v1/admin/pricing)",
                   ["provider", "model"])
CIRCUIT_OPEN = Counter("harnis_circuit_breaker_open_total", "Circuit breaker trips", ["provider"])
SANDBOX_RUNS = Counter("harnis_sandbox_runs_total", "Sandbox runs by backend, kind and outcome",
                       ["backend", "kind", "outcome"])
SANDBOX_LATENCY = Histogram("harnis_sandbox_run_duration_seconds", "Sandbox run duration", ["backend", "kind"],
                            buckets=(0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300))
RATE_LIMITED = Counter("harnis_rate_limited_total", "Turns refused by the rate limiter")
GUARD_BLOCKS = Counter("harnis_guardrail_events_total", "Guardrail events", ["kind"])
CACHE = Counter("harnis_cache_lookups_total", "Semantic cache lookups", ["result"])
BUILD = Gauge("harnis_build_info", "Harnis version", ["version"])


def safe(value: object) -> str:
    """Label values from configuration only, never from requests; still cap them."""
    return str(value)[:64] if value is not None else ""


@contextmanager
def timed(hist: Histogram, **labels: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        (hist.labels(**labels) if labels else hist).observe(time.perf_counter() - start)


def render() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST

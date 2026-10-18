# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""OpenTelemetry setup.

* OTLP/gRPC export to any collector (Jaeger locally; Tempo, Datadog, ... in
  production) — switch backends by changing OTEL_EXPORTER_OTLP_ENDPOINT only.
* Auto-instrumentation for FastAPI, psycopg and Redis, so DB and cache spans
  appear under each request without hand-written spans.
* GenAI semantic-convention attributes (gen_ai.*) are set in llm/router.py.
* `LatencyAlertProcessor` watches finished spans and raises an alert when a
  span exceeds its threshold. (A processor sees spans as they end; it can't
  mutate them, so the alert is a side effect, not a span attribute.)
* We never put prompts, file contents or command strings on spans.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Callable
from urllib.parse import urlparse

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

log = logging.getLogger(__name__)


class LatencyAlertProcessor(SpanProcessor):
    def __init__(self, thresholds_ms: dict[str, int], alert: Callable[[str, str, str | None, dict], None]):
        self.thresholds = thresholds_ms
        self.alert = alert

    def on_end(self, span: ReadableSpan) -> None:
        limit = self.thresholds.get(span.name)
        if limit is None or span.start_time is None or span.end_time is None:
            return
        ms = (span.end_time - span.start_time) / 1e6
        if ms > limit:
            attrs = span.attributes or {}
            self.alert("latency_threshold_exceeded", str(attrs.get("harnis.tenant_id", "-")),
                       None, {"span": span.name, "duration_ms": round(ms), "threshold_ms": limit})


def _guard_redis_search_attributes() -> None:
    """opentelemetry-instrumentation-redis reads FT.SEARCH replies as RESP2
    lists. redis-py 8 talks RESP3, the reply is a dict, and the hook raises
    KeyError *inside the Redis call*, failing the request. Tracing must never
    break the traced code, so wrap the hook and drop the extra attributes if it
    fails."""
    try:
        import opentelemetry.instrumentation.redis as otel_redis
    except ImportError:
        return
    original = getattr(otel_redis, "_add_search_attributes", None)
    if original is None or getattr(original, "_harnis_guarded", False):
        return

    def guarded(span, response, args):
        try:
            original(span, response, args)
        except Exception:  # attribute extraction only; the Redis reply is fine
            pass

    guarded._harnis_guarded = True  # type: ignore[attr-defined]
    otel_redis._add_search_attributes = guarded


EXPORTER_LOGGERS = ("opentelemetry.exporter.otlp.proto.grpc.exporter",
                    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
                    "opentelemetry.sdk.trace.export",
                    "opentelemetry.sdk._shared_internal")


class CollectorDownFilter(logging.Filter):
    """The OTLP exporter logs every failed retry, several lines a second while
    the collector is down. Tracing problems must not drown the application's own
    logs: let the first failure through as one clear message, then at most one
    reminder per `interval` seconds."""

    def __init__(self, endpoint: str, interval: float = 300.0, clock: Callable[[], float] = time.monotonic):
        super().__init__()
        self.endpoint, self.interval, self.clock = endpoint, interval, clock
        self._last = -interval
        self.suppressed = 0

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        if not any(k in text for k in ("export", "UNAVAILABLE", "Queue full", "dropping Span")):
            return True
        now = self.clock()
        if now - self._last < self.interval:
            self.suppressed += 1
            return False
        extra = f" ({self.suppressed} similar messages suppressed)" if self.suppressed else ""
        record.msg = (f"Can't send traces to the collector at {self.endpoint}; traces are dropped until it is "
                      f"reachable{extra}. Locally: `python tasks.py up` starts Jaeger, or set OTEL_ENABLED=false. "
                      f"Exporter said: {text.splitlines()[0][:200]}")
        record.args, record.exc_info, record.exc_text = (), None, None
        record.levelno, record.levelname = logging.WARNING, "WARNING"
        self._last, self.suppressed = now, 0
        return True


def collector_reachable(endpoint: str, timeout: float = 1.0) -> bool:
    u = urlparse(endpoint if "://" in endpoint else f"http://{endpoint}")
    port = u.port or (443 if u.scheme == "https" else 4317)
    try:
        with socket.create_connection((u.hostname or "127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _install_exporter_log_filter(endpoint: str) -> CollectorDownFilter:
    f = CollectorDownFilter(endpoint)
    for name in EXPORTER_LOGGERS:
        lg = logging.getLogger(name)
        for old in [x for x in lg.filters if isinstance(x, CollectorDownFilter)]:
            lg.removeFilter(old)
        lg.addFilter(f)
    return f


def setup_tracing(settings, alert=None, app=None) -> TracerProvider | None:
    provider = TracerProvider(resource=Resource.create({
        "service.name": settings.otel_service_name,
        "deployment.environment": settings.env,
    }))
    if alert is not None:
        provider.add_span_processor(LatencyAlertProcessor(settings.latency_thresholds_ms, alert))
    if settings.otel_enabled:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        endpoint = settings.otel_exporter_otlp_endpoint
        insecure = settings.otel_exporter_otlp_insecure
        if insecure is None:
            insecure = not endpoint.startswith("https://")
        _install_exporter_log_filter(endpoint)
        if not collector_reachable(endpoint):
            log.warning("OTEL_ENABLED=true but nothing answers at %s yet; traces are dropped until the collector "
                        "is reachable. Locally: `python tasks.py up` starts Jaeger (UI http://127.0.0.1:16686), "
                        "or set OTEL_ENABLED=false.", endpoint)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=insecure)))
    trace.set_tracer_provider(provider)

    if settings.otel_enabled:
        try:
            from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
            from opentelemetry.instrumentation.redis import RedisInstrumentor

            PsycopgInstrumentor().instrument(enable_commenter=False)
            RedisInstrumentor().instrument()
            _guard_redis_search_attributes()
            if app is not None:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

                FastAPIInstrumentor.instrument_app(app, excluded_urls="health,ready")
        except Exception as exc:  # instrumentation is best-effort
            log.warning("auto-instrumentation unavailable: %s", exc)
    return provider

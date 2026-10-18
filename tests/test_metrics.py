# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Prometheus metrics: exposure rules and what gets counted (no tenant or user
ids in labels)."""
import fakeredis
from fastapi.testclient import TestClient

from harnis.api import create_app
from harnis.config import Settings
from harnis.llm.providers import MockProvider
from harnis.llm.router import LLMRouter


def app(tmp_path, **kw):
    s = Settings(_env_file=None, workspaces_dir=str(tmp_path), **kw)
    return create_app(s, store=object(), redis=fakeredis.FakeRedis(), router=LLMRouter([MockProvider()]))


def test_metrics_open_in_development(tmp_path):
    with TestClient(app(tmp_path)) as c:
        c.get("/health")
        body = c.get("/metrics").text
        assert 'harnis_http_requests_total{method="GET",route="/health",status="200"}' in body
        assert "harnis_build_info" in body


def test_metrics_need_a_token_when_set_and_in_production(tmp_path):
    with TestClient(app(tmp_path, metrics_token="s3cret")) as c:
        assert c.get("/metrics").status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    prod = dict(env="production", jwt_secret="x" * 40, llm_providers="anthropic")
    from harnis.llm.types import LLMResponse, Usage

    class P:
        name = "anthropic"

        def model_for(self, tier):
            return "m"

        def complete(self, req):
            return LLMResponse([], "end_turn", Usage(), "anthropic", "m")

    s = Settings(_env_file=None, workspaces_dir=str(tmp_path), pricing_overrides={"m": [1, 1]}, **prod)
    a = create_app(s, store=object(), redis=fakeredis.FakeRedis(), router=LLMRouter([P()]))
    with TestClient(a) as c:
        assert c.get("/metrics").status_code == 404  # no token in production: not served at all


def test_route_templates_not_raw_paths(tmp_path):
    with TestClient(app(tmp_path)) as c:
        c.get("/v1/sessions/sess_secret123", headers={"Authorization": "Bearer x"})
        body = c.get("/metrics").text
        assert "sess_secret123" not in body and 'route="/v1/sessions/{session_id}"' in body


def test_llm_and_sandbox_metrics_recorded(tmp_path):
    from harnis import metrics
    from harnis.llm.types import LLMRequest, Message
    from harnis.sandbox import SandboxResult, _record_metrics

    before = metrics.LLM_CALLS.labels("mock", "mock-main", "ok")._value.get()
    LLMRouter([MockProvider()]).complete(LLMRequest(system="s", messages=[Message("user", [{"type": "text",
                                                                                           "text": "hi"}])]))
    assert metrics.LLM_CALLS.labels("mock", "mock-main", "ok")._value.get() == before + 1
    _record_metrics("docker", True, SandboxResult(0, "ok", duration_ms=1200))
    assert metrics.SANDBOX_RUNS.labels("docker", "install", "ok")._value.get() >= 1

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
import pytest

from harnis.llm.providers import MockProvider, OpenAIProvider
from harnis.llm.router import AllProvidersFailed, CircuitBreaker, LLMRouter
from harnis.llm.types import LLMRequest, LLMResponse, Message, ProviderError, Usage, classify_status


class Flaky:
    def __init__(self, name, errors):
        self.name = name
        self.errors = list(errors)
        self.calls = 0

    def model_for(self, tier):
        return f"{self.name}-{tier}"

    def complete(self, req):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return LLMResponse([{"type": "text", "text": f"from {self.name}"}], "end_turn", Usage(1, 1),
                           self.name, self.model_for(req.tier))


def req():
    return LLMRequest(system="s", messages=[Message("user", [{"type": "text", "text": "hi"}])])


def err(provider, status):
    r, f = classify_status(status)
    return ProviderError("boom", provider=provider, status=status, retryable=r, failover=f)


def test_classification():
    assert classify_status(429) == (True, True)
    assert classify_status(529) == (True, True)
    assert classify_status(None) == (True, True)
    assert classify_status(401) == (False, True)
    assert classify_status(400) == (False, False)


def test_retries_then_succeeds_without_sleeping_after_last_attempt():
    sleeps = []
    a = Flaky("a", [err("a", 503), err("a", 429)])
    r = LLMRouter([a], max_retries=3, sleep=sleeps.append)
    assert r.complete(req()).text == "from a"
    assert a.calls == 3 and len(sleeps) == 2


def test_fails_over_after_retries_exhausted():
    sleeps = []
    a = Flaky("a", [err("a", 500)] * 3)
    b = Flaky("b", [])
    r = LLMRouter([a, b], max_retries=3, sleep=sleeps.append)
    assert r.complete(req()).provider == "b"
    assert len(sleeps) == 2  # no sleep after the 3rd failed attempt


def test_auth_error_fails_over_without_retry():
    a = Flaky("a", [err("a", 401)])
    b = Flaky("b", [])
    r = LLMRouter([a, b], sleep=lambda s: None)
    assert r.complete(req()).provider == "b"
    assert a.calls == 1


def test_bad_request_is_not_failed_over():
    a = Flaky("a", [err("a", 400)])
    b = Flaky("b", [])
    with pytest.raises(ProviderError):
        LLMRouter([a, b], sleep=lambda s: None).complete(req())
    assert b.calls == 0


def test_circuit_breaker_opens_and_skips_provider():
    breaker = CircuitBreaker(threshold=1, open_seconds=60)
    tripped = []
    a = Flaky("a", [err("a", 500)] * 10)
    b = Flaky("b", [])
    r = LLMRouter([a, b], breaker, max_retries=1, sleep=lambda s: None, on_trip=tripped.append)
    r.complete(req())
    assert tripped == ["a:a-main"]
    calls_before = a.calls
    r.complete(req())
    assert a.calls == calls_before  # skipped while open


def test_circuit_state_shared_via_redis():
    fakeredis = pytest.importorskip("fakeredis")
    shared = fakeredis.FakeRedis()
    b1, b2 = CircuitBreaker(shared, threshold=2), CircuitBreaker(shared, threshold=2)
    b1.record_failure("x")
    b2.record_failure("x")  # second replica trips the shared breaker
    assert b1.is_open("x") and b2.is_open("x")


def test_tenant_allow_list_restricts_failover():
    a = Flaky("anthropic", [err("anthropic", 500)] * 5)
    b = Flaky("openai", [])
    r = LLMRouter([a, b], max_retries=1, sleep=lambda s: None)
    with pytest.raises(AllProvidersFailed):
        r.complete(req(), allowed=["anthropic"])
    assert b.calls == 0


def test_openai_message_translation_orders_tool_results():
    msgs = [
        Message("user", [{"type": "text", "text": "list"}]),
        Message("assistant", [{"type": "tool_use", "id": "t1", "name": "list_files", "input": {}}]),
        Message("user", [{"type": "tool_result", "tool_use_id": "t1", "content": "a.py", "is_error": False}]),
    ]
    out = OpenAIProvider._to_openai_messages("sys", msgs)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool"]
    assert out[2]["tool_calls"][0]["function"]["name"] == "list_files"
    assert out[3]["tool_call_id"] == "t1"


def test_mock_provider_routes_by_keyword():
    from harnis.tools import ROUTE_TOOL
    m = MockProvider()
    r = m.complete(LLMRequest(system="", messages=[Message("user", [{"type": "text", "text": "fix the bug"}])],
                              tools=[ROUTE_TOOL.spec()], force_tool="route"))
    assert r.tool_calls[0]["input"]["agent"] == "coder"

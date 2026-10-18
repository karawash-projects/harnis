# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Exercise the real Anthropic and OpenAI SDKs against a fake HTTP transport:
request shape, response parsing and error classification — no network, no keys."""
import json

import pytest

from harnis.llm.providers import AnthropicProvider, OpenAIProvider
from harnis.llm.types import LLMRequest, Message, ProviderError, ToolSpec

TOOLS = [ToolSpec("read_file", "Read a file", {"type": "object", "properties": {"path": {"type": "string"}},
                                                "required": ["path"]})]


def conversation():
    return [
        Message("user", [{"type": "text", "text": "read a.py"}]),
        Message("assistant", [{"type": "tool_use", "id": "tu_1", "name": "read_file", "input": {"path": "a.py"}}]),
        Message("user", [{"type": "tool_result", "tool_use_id": "tu_1", "content": "print(1)", "is_error": False}]),
    ]


def _http_module(sdk: str):
    """Newer SDK releases ship on `httpx2`, older ones on `httpx`; use whichever it imports."""
    import importlib
    base = importlib.import_module(f"{sdk}._base_client")
    return getattr(base, "httpx2", None) or base.httpx


hx = _http_module("anthropic")
ohx = _http_module("openai")


def transport(status, body, seen, mod=None):
    mod = mod or hx
    def handler(request):
        seen.append(json.loads(request.content))
        return mod.Response(status, json=body)
    return mod.Client(transport=mod.MockTransport(handler))


def test_anthropic_roundtrip():
    seen = []
    body = {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
            "content": [{"type": "text", "text": "Let me check."},
                        {"type": "tool_use", "id": "tu_2", "name": "read_file", "input": {"path": "b.py"}}],
            "stop_reason": "tool_use", "stop_sequence": None,
            "usage": {"input_tokens": 120, "output_tokens": 30}}
    p = AnthropicProvider("k", "claude-sonnet-5-5", "claude-haiku-5-5", http_client=transport(200, body, seen))
    r = p.complete(LLMRequest(system="sys", messages=conversation(), tools=TOOLS))
    sent = seen[0]
    assert sent["system"] == "sys" and sent["tools"][0]["name"] == "read_file"
    assert sent["messages"][2]["content"][0]["type"] == "tool_result"
    assert "temperature" not in sent
    assert r.stop_reason == "tool_use" and r.tool_calls[0]["input"] == {"path": "b.py"}
    assert (r.usage.input_tokens, r.usage.output_tokens) == (120, 30)


@pytest.mark.parametrize("status,retryable,failover", [(529, True, True), (429, True, True),
                                                       (401, False, True), (400, False, False)])
def test_anthropic_error_classification(status, retryable, failover):
    body = {"type": "error", "error": {"type": "x", "message": "nope"}}
    p = AnthropicProvider("k", "m", "f", http_client=transport(status, body, []))
    with pytest.raises(ProviderError) as e:
        p.complete(LLMRequest(system="s", messages=conversation()[:1]))
    assert (e.value.status, e.value.retryable, e.value.failover) == (status, retryable, failover)


def test_openai_roundtrip_and_forced_tool():
    seen = []
    body = {"id": "c1", "object": "chat.completion", "created": 0, "model": "gpt-5.5",
            "choices": [{"index": 0, "finish_reason": "tool_calls",
                         "message": {"role": "assistant", "content": None,
                                     "tool_calls": [{"id": "call_1", "type": "function",
                                                     "function": {"name": "read_file",
                                                                  "arguments": "{\"path\": \"c.py\"}"}}]}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}}
    p = OpenAIProvider("k", "gpt-5.5", "gpt-5.4-mini", http_client=transport(200, body, seen, ohx))
    r = p.complete(LLMRequest(system="sys", messages=conversation(), tools=TOOLS, force_tool="read_file"))
    sent = seen[0]
    assert [m["role"] for m in sent["messages"]] == ["system", "user", "assistant", "tool"]
    assert sent["tool_choice"]["function"]["name"] == "read_file"
    assert r.stop_reason == "tool_use" and r.tool_calls[0]["input"] == {"path": "c.py"}
    assert r.usage.input_tokens == 50


def test_openai_connection_error_is_retryable():
    def boom(request):
        raise ohx.ConnectError("down")
    p = OpenAIProvider("k", "m", "f", http_client=ohx.Client(transport=ohx.MockTransport(boom)))
    with pytest.raises(ProviderError) as e:
        p.complete(LLMRequest(system="s", messages=conversation()[:1]))
    assert e.value.retryable and e.value.failover


# ---------------------------------------------------------------------------
# Gemini (google-genai SDK) against a fake HTTP transport
# ---------------------------------------------------------------------------
def _gemini(status, body, seen):
    import httpx as real_httpx  # google-genai uses httpx (not httpx2)

    from harnis.llm.providers import GeminiProvider

    def handler(request):
        seen.append({"url": str(request.url), "body": json.loads(request.content)})
        return real_httpx.Response(status, json=body)

    client = real_httpx.Client(transport=real_httpx.MockTransport(handler))
    return GeminiProvider("test-key", "gemini-3.8-flash", "gemini-3.5-flash-lite", http_client=client)


GEMINI_TOOL_REPLY = {
    "candidates": [{
        "content": {"role": "model", "parts": [
            {"text": "Let me look."},
            {"functionCall": {"id": "fc_1", "name": "read_file", "args": {"path": "b.py"}},
             "thoughtSignature": "c2lnLWJ5dGVz"},
        ]},
        "finishReason": "STOP",
    }],
    "usageMetadata": {"promptTokenCount": 40, "candidatesTokenCount": 8, "thoughtsTokenCount": 5},
}


def test_gemini_roundtrip_tools_and_signature():
    seen = []
    p = _gemini(200, GEMINI_TOOL_REPLY, seen)
    r = p.complete(LLMRequest(system="sys", messages=conversation(), tools=TOOLS, force_tool="read_file"))
    sent = seen[0]["body"]
    assert "gemini-3.8-flash:generateContent" in seen[0]["url"]
    assert sent["systemInstruction"]["parts"][0]["text"] == "sys"
    decl = sent["tools"][0]["functionDeclarations"][0]
    schema = decl.get("parametersJsonSchema") or decl.get("parameters_json_schema")  # SDK versions differ
    assert decl["name"] == "read_file" and schema["required"] == ["path"]
    assert sent["toolConfig"]["functionCallingConfig"] == {"mode": "ANY", "allowedFunctionNames": ["read_file"]}
    roles = [c["role"] for c in sent["contents"]]
    assert roles == ["user", "model", "user"]
    # history call from another provider gets the documented placeholder signature
    assert sent["contents"][1]["parts"][0]["thoughtSignature"]
    fr = sent["contents"][2]["parts"][0]["functionResponse"]
    assert fr["name"] == "read_file" and fr["id"] == "tu_1" and fr["response"] == {"output": "print(1)"}
    # response
    assert r.stop_reason == "tool_use" and r.text == "Let me look."
    call = r.tool_calls[0]
    assert call["id"] == "fc_1" and call["input"] == {"path": "b.py"}
    assert call["provider_meta"]["gemini_signature"] == "c2lnLWJ5dGVz"
    assert (r.usage.input_tokens, r.usage.output_tokens) == (40, 13)  # thinking tokens are billed as output


def test_gemini_replays_its_own_signature_exactly():
    import base64

    seen = []
    p = _gemini(200, {"candidates": [{"content": {"role": "model", "parts": [{"text": "done"}]},
                                      "finishReason": "STOP"}], "usageMetadata": {}}, seen)
    history = [
        Message("user", [{"type": "text", "text": "read b.py"}]),
        Message("assistant", [{"type": "tool_use", "id": "fc_1", "name": "read_file", "input": {"path": "b.py"},
                               "provider_meta": {"gemini_signature": base64.b64encode(b"real-sig").decode()}}]),
        Message("user", [{"type": "tool_result", "tool_use_id": "fc_1", "content": "x", "is_error": True}]),
    ]
    r = p.complete(LLMRequest(system="s", messages=history))
    part = seen[0]["body"]["contents"][1]["parts"][0]
    assert base64.b64decode(part["thoughtSignature"]) == b"real-sig"
    assert seen[0]["body"]["contents"][2]["parts"][0]["functionResponse"]["response"] == {"error": "x"}
    assert r.stop_reason == "end_turn" and r.text == "done"


@pytest.mark.parametrize("status,retryable,failover", [(429, True, True), (503, True, True),
                                                       (403, False, True), (400, False, False)])
def test_gemini_error_classification(status, retryable, failover):
    body = {"error": {"code": status, "message": "nope", "status": "X"}}
    p = _gemini(status, body, [])
    with pytest.raises(ProviderError) as e:
        p.complete(LLMRequest(system="s", messages=conversation()[:1]))
    assert (e.value.status, e.value.retryable, e.value.failover) == (status, retryable, failover)


def test_anthropic_strips_provider_meta():
    seen = []
    body = {"id": "m", "type": "message", "role": "assistant", "model": "m", "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
    p = AnthropicProvider("k", "m", "f", http_client=transport(200, body, seen))
    msgs = conversation()
    msgs[1].content[0]["provider_meta"] = {"gemini_signature": "abc"}
    p.complete(LLMRequest(system="s", messages=msgs))
    assert "provider_meta" not in json.dumps(seen[0])


# ---------------------------------------------------------------------------
# Amazon Nova (Bedrock Converse via boto3) with botocore's Stubber, which also
# validates every request against the real Bedrock API model.
# ---------------------------------------------------------------------------
def _nova():
    import boto3
    from botocore.stub import Stubber

    from harnis.llm.providers import NovaProvider

    client = boto3.client("bedrock-runtime", region_name="us-east-1",
                          aws_access_key_id="x", aws_secret_access_key="y")
    return NovaProvider("us.amazon.nova-2-lite-v1:0", "us.amazon.nova-micro-v1:0", "us-east-1",
                        client=client), Stubber(client)


def test_nova_roundtrip_tools():
    from botocore.stub import ANY

    p, stub = _nova()
    stub.add_response("converse", {
        "output": {"message": {"role": "assistant", "content": [
            {"text": "Reading."},
            {"toolUse": {"toolUseId": "tooluse_1", "name": "read_file", "input": {"path": "c.py"}}},
        ]}},
        "stopReason": "tool_use",
        "usage": {"inputTokens": 30, "outputTokens": 9, "totalTokens": 39},
        "metrics": {"latencyMs": 100},
    }, {
        "modelId": "us.amazon.nova-2-lite-v1:0",
        "system": [{"text": "sys"}],
        "inferenceConfig": {"maxTokens": 2048, "temperature": 0.0},  # greedy decoding for tool use
        "messages": [
            {"role": "user", "content": [{"text": "read a.py"}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tu_1", "name": "read_file",
                                                            "input": {"path": "a.py"}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "tu_1", "content": [{"text": "print(1)"}],
                                                          "status": "success"}}]},
        ],
        "toolConfig": ANY,
    })
    with stub:
        r = p.complete(LLMRequest(system="sys", messages=conversation(), tools=TOOLS, force_tool="read_file"))
    stub.assert_no_pending_responses()
    assert r.stop_reason == "tool_use" and r.text == "Reading."
    assert r.tool_calls[0] == {"type": "tool_use", "id": "tooluse_1", "name": "read_file", "input": {"path": "c.py"}}
    assert (r.usage.input_tokens, r.usage.output_tokens) == (30, 9)


def test_nova_sends_tool_spec_and_forced_choice():
    p, stub = _nova()
    captured = {}
    stub.add_response("converse", {"output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
                                   "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 1,
                                                                       "totalTokens": 2},
                                   "metrics": {"latencyMs": 1}})
    p._client.meta.events.register("before-parameter-build.bedrock-runtime.Converse",
                                   lambda params, **kw: captured.update(params))
    with stub:
        p.complete(LLMRequest(system="s", messages=conversation()[:1], tools=TOOLS, force_tool="read_file",
                              tier="fast"))
    assert captured["modelId"] == "us.amazon.nova-micro-v1:0"
    spec = captured["toolConfig"]["tools"][0]["toolSpec"]
    assert spec["name"] == "read_file" and spec["inputSchema"]["json"]["required"] == ["path"]
    assert captured["toolConfig"]["toolChoice"] == {"tool": {"name": "read_file"}}


@pytest.mark.parametrize("code,status,retryable,failover", [
    ("ThrottlingException", 429, True, True),
    ("ServiceUnavailableException", 503, True, True),
    ("AccessDeniedException", 403, False, True),
    ("ValidationException", 400, False, False),
])
def test_nova_error_classification(code, status, retryable, failover):
    p, stub = _nova()
    stub.add_client_error("converse", service_error_code=code, http_status_code=status)
    with stub, pytest.raises(ProviderError) as e:
        p.complete(LLMRequest(system="s", messages=conversation()[:1]))
    assert (e.value.retryable, e.value.failover) == (retryable, failover)


def test_nova_missing_credentials_fails_over():
    from botocore.exceptions import NoCredentialsError

    from harnis.llm.providers import NovaProvider

    class NoCreds:
        def converse(self, **kw):
            raise NoCredentialsError()

    p = NovaProvider("m", "f", "us-east-1", client=NoCreds())
    with pytest.raises(ProviderError) as e:
        p.complete(LLMRequest(system="s", messages=conversation()[:1]))
    assert e.value.failover and not e.value.retryable


# ---------------------------------------------------------------------------
# Wiring: which providers the router builds from settings
# ---------------------------------------------------------------------------
def test_build_router_picks_up_gemini_and_nova(monkeypatch):
    from harnis.config import Settings
    from harnis.llm import router as router_mod

    monkeypatch.setattr(router_mod, "_aws_credentials_available", lambda s: True)
    s = Settings(llm_providers="gemini,nova,mock", gemini_api_key="g", aws_region="us-east-1")
    names = [p.name for p in router_mod.build_router(s).providers]
    assert names == ["gemini", "nova", "mock"]

    monkeypatch.setattr(router_mod, "_aws_credentials_available", lambda s: False)
    s = Settings(llm_providers="gemini,nova,mock", gemini_api_key="", aws_region="us-east-1")
    assert [p.name for p in router_mod.build_router(s).providers] == ["mock"]


def test_settings_read_gemini_and_aws_env_names(monkeypatch):
    from harnis.config import Settings

    monkeypatch.setenv("GOOGLE_API_KEY", "from-google-env")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    s = Settings(_env_file=None)
    assert s.gemini_api_key == "from-google-env" and s.aws_region == "eu-west-1"


def test_bedrock_region_prefix_ignored_for_pricing():
    from harnis.llm.pricing import cost_usd

    assert cost_usd("eu.amazon.nova-2-lite-v1:0", 1_000_000, 0) == cost_usd("amazon.nova-2-lite-v1:0", 1_000_000, 0)
    assert cost_usd("global.amazon.nova-2-lite-v1:0", 1_000_000, 0) < 1


def test_aws_keys_from_env_file_reach_boto3(tmp_path, monkeypatch):
    """Keys written in .env are not real environment variables; they must still
    be used for Bedrock."""
    from harnis.config import Settings
    from harnis.llm.router import aws_session

    for v in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    env = tmp_path / ".env"
    env.write_text("AWS_REGION=eu-west-1\nAWS_ACCESS_KEY_ID=AKIAFROMENVFILE0000\n"
                   "AWS_SECRET_ACCESS_KEY=secret-from-env-file\n", encoding="utf-8")
    s = Settings(_env_file=str(env))
    creds = aws_session(s).get_credentials()
    assert creds.access_key == "AKIAFROMENVFILE0000" and creds.secret_key == "secret-from-env-file"
    assert aws_session(s).region_name == "eu-west-1"


def test_full_turn_through_gemini_keeps_signature_across_approval(store, make_orch, tmp_path):
    """route -> write_file (needs approval) -> resume -> final answer, all via the
    real google-genai SDK against a scripted fake server. The thought signature
    from the tool call must survive the checkpoint and be sent back."""
    import base64

    import httpx as real_httpx

    from harnis.llm.providers import GeminiProvider

    requests = []
    replies = [
        {"candidates": [{"content": {"role": "model", "parts": [
            {"functionCall": {"name": "route", "args": {"agent": "coder"}}}]}}]},
        {"candidates": [{"content": {"role": "model", "parts": [
            {"functionCall": {"id": "w1", "name": "write_file", "args": {"path": "hi.py", "content": "x = 1\n"}},
             "thoughtSignature": base64.b64encode(b"sig-w1").decode()}]}}]},
        {"candidates": [{"content": {"role": "model", "parts": [{"text": "Wrote hi.py."}]},
                         "finishReason": "STOP"}]},
    ]

    def handler(request):
        requests.append(json.loads(request.content))
        return real_httpx.Response(200, json=replies[len(requests) - 1])

    gem = GeminiProvider("k", "gemini-3.8-flash", "gemini-3.5-flash-lite",
                         http_client=real_httpx.Client(transport=real_httpx.MockTransport(handler)))
    orch = make_orch(store, providers=[gem])
    rec = orch.start_turn(store.new_session(), "create hi.py")
    assert rec.status == "awaiting_approval"
    json.loads(json.dumps(rec.state))  # checkpointable as JSON
    rec = orch.resume_after_decision(rec, rec.state["awaiting"]["approval_id"], True, "bob")
    assert rec.status == "completed" and rec.state["reply"] == "Wrote hi.py."
    assert (tmp_path / "ws" / "acme" / rec.session_id / "hi.py").read_text() == "x = 1\n"
    model_turn = requests[2]["contents"][1]
    assert model_turn["role"] == "model"
    assert base64.b64decode(model_turn["parts"][0]["thoughtSignature"]) == b"sig-w1"
    assert requests[2]["contents"][2]["parts"][0]["functionResponse"]["name"] == "write_file"

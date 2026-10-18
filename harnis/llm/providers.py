# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Provider adapters: Anthropic, OpenAI, and a deterministic Mock.

Each adapter translates the neutral `LLMRequest` into its SDK's shape and the
SDK's response back into `LLMResponse`, and maps SDK errors to
`ProviderError` with retry/failover semantics.

Sampling parameters (temperature/top_p) are deliberately not part of the
neutral request: models differ in which they accept, and raising temperature
on retry is not a reliable way to escape a failure loop. The harness changes
the *context* instead (it feeds back the error and the loop-breaker warning).
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any

from .types import (
    LLMRequest, LLMResponse, Message, ProviderError, Usage, classify_status,
)


def _sdk_error(provider: str, exc: Exception) -> ProviderError:
    status = getattr(exc, "status_code", None)
    name = type(exc).__name__
    if status is None and not any(k in name for k in ("Connection", "Timeout")):
        # Unknown non-HTTP error: don't retry blindly, but let failover try another provider.
        return ProviderError(f"{name}: {exc}", provider=provider, failover=True)
    retryable, failover = classify_status(status)
    return ProviderError(f"{name}: {exc}", provider=provider, status=status,
                         retryable=retryable, failover=failover)


_NEUTRAL_KEYS = {
    "text": ("type", "text"),
    "tool_use": ("type", "id", "name", "input"),
    "tool_result": ("type", "tool_use_id", "content", "is_error"),
}


def _anthropic_block(b: dict[str, Any]) -> dict[str, Any]:
    """Neutral blocks may carry provider-only data (e.g. Gemini's
    `provider_meta`); the Anthropic API rejects unknown keys, so drop them."""
    return {k: b[k] for k in _NEUTRAL_KEYS.get(b["type"], b.keys()) if k in b}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, fast_model: str, timeout: float = 60.0,
                 http_client: Any = None, base_url: str | None = None):
        import anthropic

        # max_retries=0: the router owns retries, so they aren't multiplied.
        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0,
                                           http_client=http_client, base_url=base_url)
        self._models = {"main": model, "fast": fast_model}

    def model_for(self, tier: str) -> str:
        return self._models[tier]

    def complete(self, req: LLMRequest) -> LLMResponse:
        model = self.model_for(req.tier)
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_tokens,
            "system": req.system,
            "messages": [{"role": m.role, "content": [_anthropic_block(b) for b in m.content]}
                         for m in req.messages],
        }
        if req.tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in req.tools
            ]
            if req.force_tool:
                kwargs["tool_choice"] = {"type": "tool", "name": req.force_tool}
        try:
            resp = self._client.messages.create(**kwargs)
        except Exception as exc:  # SDK raises typed errors; normalize them
            raise _sdk_error(self.name, exc) from exc
        content: list[dict[str, Any]] = []
        for b in resp.content:
            if b.type == "text":
                content.append({"type": "text", "text": b.text})
            elif b.type == "tool_use":
                content.append({"type": "tool_use", "id": b.id, "name": b.name, "input": dict(b.input)})
        return LLMResponse(
            content=content,
            stop_reason=resp.stop_reason or "end_turn",
            usage=Usage(resp.usage.input_tokens, resp.usage.output_tokens),
            provider=self.name,
            model=model,
        )


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, fast_model: str, timeout: float = 60.0,
                 http_client: Any = None, base_url: str | None = None):
        import openai

        self._client = openai.OpenAI(api_key=api_key, timeout=timeout, max_retries=0,
                                     http_client=http_client, base_url=base_url)
        self._models = {"main": model, "fast": fast_model}

    def model_for(self, tier: str) -> str:
        return self._models[tier]

    @staticmethod
    def _to_openai_messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "assistant":
                text = "".join(b["text"] for b in m.content if b["type"] == "text")
                calls = [
                    {"id": b["id"], "type": "function",
                     "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                    for b in m.content if b["type"] == "tool_use"
                ]
                msg: dict[str, Any] = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
            else:
                # Tool results must directly follow the assistant tool_calls message.
                for b in m.content:
                    if b["type"] == "tool_result":
                        out.append({"role": "tool", "tool_call_id": b["tool_use_id"],
                                    "content": b["content"]})
                text = "".join(b["text"] for b in m.content if b["type"] == "text")
                if text:
                    out.append({"role": "user", "content": text})
        return out

    def complete(self, req: LLMRequest) -> LLMResponse:
        model = self.model_for(req.tier)
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": self._to_openai_messages(req.system, req.messages),
            "max_completion_tokens": req.max_tokens,
        }
        if req.tools:
            kwargs["tools"] = [
                {"type": "function",
                 "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}}
                for t in req.tools
            ]
            if req.force_tool:
                kwargs["tool_choice"] = {"type": "function", "function": {"name": req.force_tool}}
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise _sdk_error(self.name, exc) from exc
        choice = resp.choices[0]
        content: list[dict[str, Any]] = []
        if choice.message.content:
            content.append({"type": "text", "text": choice.message.content})
        for tc in choice.message.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"__invalid_json__": tc.function.arguments}
            content.append({"type": "tool_use", "id": tc.id, "name": tc.function.name, "input": args})
        stop = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens"}.get(
            choice.finish_reason or "stop", choice.finish_reason or "end_turn")
        usage = resp.usage
        return LLMResponse(
            content=content,
            stop_reason=stop,
            usage=Usage(getattr(usage, "prompt_tokens", 0) or 0, getattr(usage, "completion_tokens", 0) or 0),
            provider=self.name,
            model=model,
        )


class GeminiProvider:
    """Google Gemini through the `google-genai` SDK (Gemini Developer API with an
    API key, or Vertex AI when `vertexai=True` and Google Cloud credentials).

    Gemini 3 models attach a *thought signature* to function calls and require
    it to be sent back with the conversation. It is kept on the neutral block
    as `provider_meta.gemini_signature` (base64) and replayed. Calls that came
    from another provider (after a failover) get Google's documented
    placeholder signature instead."""

    name = "gemini"
    FOREIGN_SIGNATURE = b"skip_thought_signature_validator"

    def __init__(self, api_key: str, model: str, fast_model: str, timeout: float = 60.0,
                 http_client: Any = None, vertexai: bool = False, project: str | None = None,
                 location: str | None = None):
        from google import genai
        from google.genai import types

        self._types = types
        opts = types.HttpOptions(timeout=int(timeout * 1000), httpx_client=http_client)
        if vertexai:
            self._client = genai.Client(vertexai=True, project=project, location=location, http_options=opts)
        else:
            self._client = genai.Client(api_key=api_key, http_options=opts)
        self._models = {"main": model, "fast": fast_model}

    def model_for(self, tier: str) -> str:
        return self._models[tier]

    @staticmethod
    def _sig(b: dict[str, Any]) -> bytes | None:
        raw = (b.get("provider_meta") or {}).get("gemini_signature")
        return base64.b64decode(raw) if raw else None

    def _contents(self, messages: list[Message]) -> list[Any]:
        t = self._types
        names: dict[str, str] = {}  # tool_use_id -> function name (responses need the name)
        out = []
        for m in messages:
            parts = []
            if m.role == "assistant":
                has_sig = any(self._sig(b) for b in m.content)
                first_call = True
                for b in m.content:
                    if b["type"] == "text" and b.get("text"):
                        parts.append(t.Part(text=b["text"], thought_signature=self._sig(b)))
                    elif b["type"] == "tool_use":
                        names[b["id"]] = b["name"]
                        sig = self._sig(b)
                        if sig is None and not has_sig and first_call:
                            sig = self.FOREIGN_SIGNATURE
                        first_call = False
                        parts.append(t.Part(function_call=t.FunctionCall(id=b["id"], name=b["name"],
                                                                         args=b.get("input") or {}),
                                            thought_signature=sig))
                if parts:
                    out.append(t.Content(role="model", parts=parts))
            else:
                for b in m.content:
                    if b["type"] == "tool_result":
                        key = "error" if b.get("is_error") else "output"
                        parts.append(t.Part(function_response=t.FunctionResponse(
                            id=b["tool_use_id"], name=names.get(b["tool_use_id"], "tool"),
                            response={key: b["content"]})))
                    elif b["type"] == "text" and b.get("text"):
                        parts.append(t.Part(text=b["text"]))
                if parts:
                    out.append(t.Content(role="user", parts=parts))
        return out

    def complete(self, req: LLMRequest) -> LLMResponse:
        t = self._types
        model = self.model_for(req.tier)
        cfg: dict[str, Any] = {
            "system_instruction": req.system,
            "max_output_tokens": req.max_tokens,
            "automatic_function_calling": t.AutomaticFunctionCallingConfig(disable=True),
        }
        if req.tools:
            cfg["tools"] = [t.Tool(function_declarations=[
                t.FunctionDeclaration(name=s.name, description=s.description, parameters_json_schema=s.input_schema)
                for s in req.tools])]
            if req.force_tool:
                cfg["tool_config"] = t.ToolConfig(function_calling_config=t.FunctionCallingConfig(
                    mode="ANY", allowed_function_names=[req.force_tool]))
        try:
            resp = self._client.models.generate_content(
                model=model, contents=self._contents(req.messages), config=t.GenerateContentConfig(**cfg))
        except Exception as exc:
            raise _gemini_error(exc) from exc

        content: list[dict[str, Any]] = []
        cand = (resp.candidates or [None])[0]
        parts = (cand.content.parts if cand is not None and cand.content else None) or []
        for i, part in enumerate(parts):
            meta = ({"provider_meta": {"gemini_signature": base64.b64encode(part.thought_signature).decode()}}
                    if part.thought_signature else {})
            if part.function_call is not None:
                fc = part.function_call
                content.append({"type": "tool_use", "id": fc.id or f"gemini_{uuid.uuid4().hex[:12]}",
                                "name": fc.name, "input": dict(fc.args or {}), **meta})
            elif part.text and not part.thought:
                content.append({"type": "text", "text": part.text, **meta})
        finish = str(getattr(cand, "finish_reason", "") or "")
        if any(b["type"] == "tool_use" for b in content):
            stop = "tool_use"
        elif finish.endswith("MAX_TOKENS"):
            stop = "max_tokens"
        else:
            stop = "end_turn"
        u = resp.usage_metadata
        usage = Usage(getattr(u, "prompt_token_count", 0) or 0,
                      (getattr(u, "candidates_token_count", 0) or 0) + (getattr(u, "thoughts_token_count", 0) or 0))
        return LLMResponse(content, stop, usage, self.name, model)


def _gemini_error(exc: Exception) -> ProviderError:
    status = getattr(exc, "code", None)
    if not isinstance(status, int):
        status = None
    name = type(exc).__name__
    if status is None and not any(k in name for k in ("Connect", "Timeout", "Network", "Read")):
        return ProviderError(f"{name}: {exc}", provider="gemini", failover=True)
    retryable, failover = classify_status(status)
    return ProviderError(f"{name}: {exc}", provider="gemini", status=status, retryable=retryable, failover=failover)


class NovaProvider:
    """Amazon Nova through the Amazon Bedrock Converse API (`boto3`).

    Credentials come from the standard AWS chain (environment variables,
    AWS_PROFILE / SSO, or an instance/task role); no key is stored here.
    Model ids are usually cross-region inference profiles such as
    `us.amazon.nova-2-lite-v1:0`; use `eu.`/`jp.`/`global.` to match your region."""

    name = "nova"
    _RETRYABLE = {"ThrottlingException", "ServiceUnavailableException", "InternalServerException",
                  "ModelNotReadyException", "ModelTimeoutException", "ServiceQuotaExceededException"}
    _FAILOVER = {"AccessDeniedException", "UnrecognizedClientException", "ExpiredTokenException",
                 "ResourceNotFoundException", "ModelErrorException"}

    def __init__(self, model: str, fast_model: str, region: str, timeout: float = 60.0,
                 session: Any = None, client: Any = None, temperature: float | None = 0.0):
        if client is None:
            import boto3
            from botocore.config import Config

            session = session or boto3.Session(region_name=region)
            # Retries are the router's job; don't multiply them inside botocore.
            client = session.client("bedrock-runtime", config=Config(
                retries={"max_attempts": 1, "mode": "standard"}, read_timeout=timeout, connect_timeout=10))
        self._client = client
        self._models = {"main": model, "fast": fast_model}
        self.temperature = temperature

    def model_for(self, tier: str) -> str:
        return self._models[tier]

    @staticmethod
    def _messages(messages: list[Message]) -> list[dict[str, Any]]:
        out = []
        for m in messages:
            blocks: list[dict[str, Any]] = []
            for b in m.content:
                if b["type"] == "text" and b.get("text"):
                    blocks.append({"text": b["text"]})
                elif b["type"] == "tool_use":
                    blocks.append({"toolUse": {"toolUseId": b["id"], "name": b["name"], "input": b.get("input") or {}}})
                elif b["type"] == "tool_result":
                    blocks.append({"toolResult": {"toolUseId": b["tool_use_id"],
                                                  "content": [{"text": b["content"] or "(empty)"}],
                                                  "status": "error" if b.get("is_error") else "success"}})
            if blocks:
                out.append({"role": m.role, "content": blocks})
        return out

    def complete(self, req: LLMRequest) -> LLMResponse:
        model = self.model_for(req.tier)
        kwargs: dict[str, Any] = {
            "modelId": model,
            "messages": self._messages(req.messages),
            "system": [{"text": req.system}],
            "inferenceConfig": {"maxTokens": req.max_tokens},
        }
        if self.temperature is not None:
            # AWS: "use greedy decoding parameters when building function calling systems".
            kwargs["inferenceConfig"]["temperature"] = self.temperature
        if req.tools:
            kwargs["toolConfig"] = {"tools": [
                {"toolSpec": {"name": t.name, "description": t.description, "inputSchema": {"json": t.input_schema}}}
                for t in req.tools]}
            if req.force_tool:
                kwargs["toolConfig"]["toolChoice"] = {"tool": {"name": req.force_tool}}
        try:
            resp = self._client.converse(**kwargs)
        except Exception as exc:
            raise self._error(exc) from exc
        content: list[dict[str, Any]] = []
        for b in resp["output"]["message"]["content"]:
            if "text" in b:
                content.append({"type": "text", "text": b["text"]})
            elif "toolUse" in b:
                tu = b["toolUse"]
                content.append({"type": "tool_use", "id": tu["toolUseId"], "name": tu["name"],
                                "input": dict(tu.get("input") or {})})
        stop = {"tool_use": "tool_use", "end_turn": "end_turn", "stop_sequence": "end_turn",
                "max_tokens": "max_tokens"}.get(resp.get("stopReason", "end_turn"), resp.get("stopReason", "end_turn"))
        u = resp.get("usage") or {}
        return LLMResponse(content, stop, Usage(u.get("inputTokens", 0), u.get("outputTokens", 0)), self.name, model)

    def _error(self, exc: Exception) -> ProviderError:
        name = type(exc).__name__
        response = getattr(exc, "response", None)
        if isinstance(response, dict) and "Error" in response:
            code = response["Error"].get("Code", "")
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in self._RETRYABLE:
                return ProviderError(f"{code}: {exc}", provider=self.name, status=status, retryable=True)
            if code in self._FAILOVER:
                return ProviderError(f"{code}: {exc}", provider=self.name, status=status, failover=True)
            retryable, failover = classify_status(status)
            return ProviderError(f"{code}: {exc}", provider=self.name, status=status,
                                 retryable=retryable, failover=failover)
        if any(k in name for k in ("Connect", "Timeout", "EndpointConnection")):
            return ProviderError(f"{name}: {exc}", provider=self.name, retryable=True)
        # NoCredentialsError, NoRegionError, ...: this provider can't serve us; try the next.
        return ProviderError(f"{name}: {exc}", provider=self.name, failover=True)


class MockProvider:
    """Deterministic, offline stand-in so the whole platform runs and tests pass
    without API keys. It follows a small script driven by keywords in the last
    user message; see README "Trying it without API keys"."""

    name = "mock"

    def model_for(self, tier: str) -> str:
        return f"mock-{tier}"

    @staticmethod
    def _last_user_text(messages: list[Message]) -> tuple[str, int]:
        """Last plain-text user message and how many tool rounds followed it."""
        rounds = 0
        for m in reversed(messages):
            if m.role == "user":
                texts = [b["text"] for b in m.content if b["type"] == "text"]
                if texts:
                    return " ".join(texts), rounds
                rounds += 1
        return "", rounds

    @staticmethod
    def _last_results(messages: list[Message]) -> list[dict[str, Any]]:
        if messages and messages[-1].role == "user":
            return [b for b in messages[-1].content if b["type"] == "tool_result"]
        return []

    def _tool(self, name: str, args: dict[str, Any], n: int) -> list[dict[str, Any]]:
        return [{"type": "tool_use", "id": f"mock_{name}_{n}", "name": name, "input": args}]

    def complete(self, req: LLMRequest) -> LLMResponse:
        text, rounds = self._last_user_text(req.messages)
        low = text.lower()
        tool_names = {t.name for t in req.tools}
        content: list[dict[str, Any]]

        if req.force_tool == "route":
            codey = re.search(r"\b(code|file|function|bug|fix|test|write|create|refactor|run|list|read|repeat|install)\b", low)
            agent = "coder" if codey else "support"
            content = self._tool("route", {"agent": agent, "reason": "keyword routing (mock)"}, 0)
        elif "install" in low and "install_dependencies" in tool_names and rounds == 0:
            content = self._tool("install_dependencies", {"manager": "npm" if "npm" in low else "pip"}, rounds)
        elif "repeat" in low and "list_files" in tool_names:
            # Deliberately loops on the same call so the loop breaker can be demonstrated.
            content = self._tool("list_files", {}, rounds)
        elif "write_file" in tool_names and re.search(r"\b(write|create|add|fix|implement)\b", low):
            m = re.search(r"([\w\-/]+\.py)", text)
            path = m.group(1) if m else "hello.py"
            if rounds == 0:
                # Two tool calls in one response: the module and its test.
                module = path[:-3].replace("/", ".")
                test_path = "/".join(path.split("/")[:-1] + ["test_" + path.split("/")[-1]])
                body = 'def greet(name: str) -> str:\n    return f"Hello, {name}!"\n'
                test = (f"from {module} import greet\n\n\n"
                        'def test_greet():\n    assert greet("Ada") == "Hello, Ada!"\n')
                content = (self._tool("write_file", {"path": path, "content": body}, 0)
                           + [{"type": "tool_use", "id": "mock_write_file_0b", "name": "write_file",
                               "input": {"path": test_path, "content": test}}])
            elif rounds == 1 and "run_tests" in tool_names:
                content = self._tool("run_tests", {}, rounds)
            else:
                content = [{"type": "text", "text": f"I wrote {path} and ran the tests. Summary of the last result:\n"
                            + self._summarize(req.messages)}]
        elif "run_command" in tool_names and re.search(r"\brun\b(?!\s+(the\s+)?tests)", low) and rounds == 0:
            m = re.search(r"`([^`]+)`", text)
            content = self._tool("run_command", {"command": m.group(1) if m else "ls -la"}, rounds)
        elif "run_tests" in tool_names and "test" in low and rounds == 0:
            content = self._tool("run_tests", {}, rounds)
        elif "list_files" in tool_names and re.search(r"\b(list|show)\b.*\bfiles?\b", low) and rounds == 0:
            content = self._tool("list_files", {}, rounds)
        elif "read_file" in tool_names and "read" in low and rounds == 0:
            m = re.search(r"([\w\-/]+\.\w+)", text)
            content = self._tool("read_file", {"path": m.group(1) if m else "README.md"}, rounds)
        elif "handoff" in tool_names and rounds == 0 and re.search(r"\b(code|bug|repo)\b", low):
            content = self._tool("handoff", {"agent": "coder", "reason": "code question"}, rounds)
        elif rounds > 0:
            content = [{"type": "text", "text": "Done. " + self._summarize(req.messages)}]
        else:
            content = [{"type": "text", "text": f"(mock) You said: {text[:200]}"}]

        stop = "tool_use" if any(b["type"] == "tool_use" for b in content) else "end_turn"
        prompt_chars = len(req.system) + sum(len(json.dumps(m.content)) for m in req.messages)
        out_chars = len(json.dumps(content))
        return LLMResponse(content, stop, Usage(prompt_chars // 4, out_chars // 4), self.name,
                           self.model_for(req.tier))

    def _summarize(self, messages: list[Message]) -> str:
        results = self._last_results(messages)
        if not results:
            return ""
        body = results[-1]["content"]
        body = re.sub(r"</?untrusted_data[^>]*>", "", body).strip()
        return body[:400]

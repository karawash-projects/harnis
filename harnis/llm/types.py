# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Provider-neutral message format.

Every provider adapter converts to and from these types, so the orchestrator
never sees an Anthropic- or OpenAI-specific shape and failover between
providers does not change the conversation.

Content blocks (plain dicts, JSON-serializable so they can be checkpointed):
  {"type": "text", "text": "..."}
  {"type": "tool_use", "id": "...", "name": "...", "input": {...}}
  {"type": "tool_result", "tool_use_id": "...", "content": "...", "is_error": bool}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Block = dict[str, Any]


@dataclass
class Message:
    role: Literal["user", "assistant"]
    content: list[Block]

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "content": self.content}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Message":
        return Message(role=d["role"], content=list(d["content"]))


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class LLMResponse:
    content: list[Block]
    stop_reason: str  # "end_turn" | "tool_use" | "max_tokens" | ...
    usage: Usage
    provider: str
    model: str

    @property
    def text(self) -> str:
        return "".join(b["text"] for b in self.content if b["type"] == "text")

    @property
    def tool_calls(self) -> list[Block]:
        return [b for b in self.content if b["type"] == "tool_use"]


@dataclass
class LLMRequest:
    system: str
    messages: list[Message]
    tools: list[ToolSpec] = field(default_factory=list)
    max_tokens: int = 2048
    tier: Literal["main", "fast"] = "main"
    # Force a specific tool (used by the router node for structured output).
    force_tool: str | None = None


class ProviderError(Exception):
    """Normalized provider failure.

    retryable:  transient (429, 5xx, overloaded, timeout, connection) -> retry with backoff
    failover:   this provider can't serve us right now (incl. auth/config) -> try the next one
    Neither:    the request itself is bad (400/404/422) -> raise; another provider won't help
    """

    def __init__(self, message: str, *, provider: str, status: int | None = None,
                 retryable: bool = False, failover: bool = False):
        super().__init__(message)
        self.provider = provider
        self.status = status
        self.retryable = retryable
        self.failover = failover or retryable


def classify_status(status: int | None) -> tuple[bool, bool]:
    """Returns (retryable, failover) for an HTTP status."""
    if status is None:  # connection error / timeout
        return True, True
    if status in (408, 409, 429) or status >= 500:  # 529 = Anthropic overloaded
        return True, True
    if status in (401, 403):
        return False, True
    return False, False


class Provider(Protocol):
    name: str

    def model_for(self, tier: str) -> str: ...

    def complete(self, req: LLMRequest) -> LLMResponse: ...

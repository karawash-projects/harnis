# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Model prices: operator-confirmed vs reference, the production start-up check,
the admin pricing endpoint, and the `tasks.py pricing` helpers."""
import importlib.util
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

from harnis.api import create_app
from harnis.auth import mint_token
from harnis.config import Settings
from harnis.llm import pricing
from harnis.llm.providers import MockProvider
from harnis.llm.router import LLMRouter
from harnis.llm.types import LLMResponse, Usage

ROOT = Path(__file__).resolve().parent.parent


class Priced:
    name = "anthropic"

    def model_for(self, tier):
        return {"main": "claude-sonnet-5-5", "fast": "claude-haiku-5-5"}[tier]

    def complete(self, req):
        return LLMResponse([{"type": "text", "text": "hi"}], "end_turn", Usage(), self.name, "claude-sonnet-5-5")


@pytest.fixture(autouse=True)
def reset():
    yield
    pricing.configure({})


def test_confirmed_overrides_reference_and_bedrock_prefix():
    pricing.configure({"claude-sonnet-5-5": [4, 20], "amazon.nova-micro-v1:0": [0.04, 0.15]})
    assert pricing.price_for("claude-sonnet-5-5") == (4.0, 20.0)
    assert pricing.confirmed_price("us.amazon.nova-micro-v1:0") == (0.04, 0.15)
    assert pricing.confirmed_price("gpt-5.5") is None and pricing.price_for("gpt-5.5") is not None  # reference
    assert pricing.unconfirmed(["claude-sonnet-5-5", "gpt-5.5", "mock-main"]) == ["gpt-5.5"]
    assert pricing.cost_usd("never-heard-of-it", 1_000_000, 0) == pricing.UNKNOWN_MODEL_PRICE[0]


def test_pricing_file_and_validation(tmp_path):
    f = tmp_path / "pricing.json"
    f.write_text('{"my-model": [1, 2]}')
    pricing.configure({}, str(f))
    assert pricing.confirmed_price("my-model") == (1.0, 2.0)
    with pytest.raises(ValueError):
        pricing.configure({"bad": [1]})
    with pytest.raises(ValueError):
        pricing.configure({"bad": [-1, 2]})


def app(tmp_path, providers, **kw):
    s = Settings(_env_file=None, workspaces_dir=str(tmp_path), **kw)
    return create_app(s, store=object(), redis=fakeredis.FakeRedis(), router=LLMRouter(providers))


def test_production_refuses_unpriced_models(tmp_path):
    prod = dict(env="production", jwt_secret="x" * 40, llm_providers="anthropic")
    with pytest.raises(RuntimeError, match="claude-haiku-5-5, claude-sonnet-5-5"):
        app(tmp_path, [Priced()], **prod)
    app(tmp_path, [Priced()], pricing_overrides={"claude-sonnet-5-5": [3, 15], "claude-haiku-5-5": [1, 5]}, **prod)


def test_development_warns_and_admin_sees_status(tmp_path, caplog):
    a = app(tmp_path, [Priced(), MockProvider()], pricing_overrides={"claude-sonnet-5-5": [3, 15]})
    assert "No confirmed price for claude-haiku-5-5" in caplog.text
    with TestClient(a) as c:
        r = c.get("/v1/admin/pricing", headers={"Authorization": f"Bearer {mint_token('boss', 'acme', ['admin'])}"})
        body = r.json()
        rows = {m["model"]: m for m in body["models"]}
        assert not body["all_confirmed"]
        assert rows["claude-sonnet-5-5"]["confirmed"] and rows["claude-sonnet-5-5"]["input_usd_per_mtok"] == 3
        assert rows["claude-haiku-5-5"]["source"] == "reference" and rows["mock-main"]["confirmed"]
        user = {"Authorization": f"Bearer {mint_token('u', 'acme', ['user'])}"}
        assert c.get("/v1/admin/pricing", headers=user).status_code == 403


def test_pricing_overrides_read_from_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text('PRICING_OVERRIDES={"claude-sonnet-5-5": [3, 15]}\n')
    assert Settings(_env_file=str(env)).pricing_overrides == {"claude-sonnet-5-5": [3.0, 15.0]}


def load_tasks():
    spec = importlib.util.spec_from_file_location("harnis_tasks", ROOT / "tasks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tasks_finds_configured_models_without_prices():
    t = load_tasks()
    env = {"LLM_PROVIDERS": "anthropic,openai,nova,mock", "ANTHROPIC_API_KEY": "sk-x", "OPENAI_API_KEY": "",
           "AWS_REGION": "us-east-1", "NOVA_MODEL": "us.amazon.nova-2-lite-v1:0",
           "PRICING_OVERRIDES": '{"amazon.nova-2-lite-v1:0": [0.3, 2.5]}'}
    models = t.configured_models(env)
    assert ("anthropic", "claude-sonnet-5-5") in models and not any(p == "openai" for p, _ in models)
    missing = [m for _, m in t.unpriced(env)]
    assert "us.amazon.nova-2-lite-v1:0" not in missing and "claude-haiku-5-5" in missing


def test_tasks_env_strips_inline_comments_and_sees_shell_overrides(tmp_path, monkeypatch):
    t = load_tasks()
    env_file = tmp_path / ".env"
    env_file.write_text("KEYCLOAK_PORT=8080          # local Keycloak\nOPENAI_COMPATIBLE_BASE_URL=   # e.g. x\n"
                        "LLM_PROVIDERS=anthropic,mock\n")
    monkeypatch.setattr(t, "ENV_FILE", env_file)
    env = t.read_env()
    assert env["KEYCLOAK_PORT"] == "8080" and env["OPENAI_COMPATIBLE_BASE_URL"] == ""
    monkeypatch.setenv("LLM_PROVIDERS", "anthropic,mock")  # the shell wins over .env, as in the API
    monkeypatch.delenv("PRICING_OVERRIDES", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-shell")
    assert [m for _, m in t.unpriced(t.effective_env())] == ["claude-sonnet-5-5", "claude-haiku-5-5"]

# Plugins: your own tools, agents and model providers

Harnis keeps everything an agent can do in one registry: **tools**, **agents** and **model providers**. The built-ins (`coder`, `support`, `read_file`, `write_file`, the Anthropic/OpenAI/Gemini/Nova providers, ...) are registered exactly the way a plugin registers its own, so you can add to them, or replace them, without forking.

A plugin is an ordinary Python package with a `register(registry)` function. [`examples/plugins/harnis-plugin-tickets`](../examples/plugins/harnis-plugin-tickets) is a complete one: a `triage` agent that searches for existing tickets and files new ones, with every new ticket approved by a reviewer first.

## Loading plugins

Plugins are loaded only when named in the `PLUGINS` setting. Installing a package isn't enough on its own, so nothing runs in your API process unless your configuration says so.

```bash
pip install harnis-plugin-tickets        # or: pip install -e path/to/your/plugin
# .env (or the Helm chart's config)
PLUGINS=tickets                          # comma-separated
```

Each item in `PLUGINS` can be:

| Form | Example | Loads |
|---|---|---|
| entry-point name | `tickets` | `[project.entry-points."harnis.plugins"] tickets = "harnis_tickets:register"` |
| module | `mycompany.harnis_plugin` | that module's `register` function |
| module:function | `mycompany.harnis_plugin:setup` | that function |

At startup Harnis checks the registry: an agent that names a tool nobody registered stops the API from starting, rather than failing mid-conversation. `GET /v1/agents` shows what's loaded.

## Tools

```python
from pydantic import BaseModel, Field
from harnis.tools import Tool, ToolContext, safe_path, read_text

class LookupArgs(BaseModel):
    order_id: str = Field(..., pattern=r"^[A-Z0-9-]{4,20}$")

def lookup(ctx: ToolContext, args: LookupArgs) -> tuple[str, bool]:
    order = my_erp_client(ctx.tenant_id).get(args.order_id)   # your code
    return f"{order.id}: {order.status}", False                  # (output, is_error)

registry.add_tool(Tool("lookup_order", "Look up an order by id.", LookupArgs, "low", lookup))
```

| Field | Meaning |
|---|---|
| `model` | Pydantic model for the arguments. The model sees its JSON schema; invalid arguments are returned to the model as an error so it can fix the call, and your function is never called with them. |
| `risk` | `"low"` runs immediately. `"high"` suspends the session until a reviewer approves **this exact call** (the approval is bound to a hash of the arguments). Use `"high"` for anything with side effects: writing, sending, paying, deleting, filing. |
| `run(ctx, args)` | Returns `(output, is_error)`. Exceptions are not caught for you; return an error string instead. |
| `untrusted_output` | Default `True`: output is fenced as untrusted data and scanned for injected instructions before the model sees it. Leave it on for anything that returns third-party or user-controlled text. |
| `describe(workspace, args)` | Optional extra detail shown to reviewers for high-risk calls (a diff, a preview of the ticket, the email that will be sent). It is part of the approval hash. |

`ToolContext` gives you `workspace` (the session's files; always pass paths through `safe_path`), `sandbox` (to run untrusted code: `ctx.sandbox.run("cmd", ctx.workspace)`), `tenant_id`, `user_id` and `session_id`.

**Plugin code runs inside the API process with its permissions.** Never execute model-written code or shell commands there; use `ctx.sandbox`. Keep credentials for external systems in your own settings or secret store, keyed by `ctx.tenant_id`, and never accept them as tool arguments.

## Agents

```python
from harnis.plugins import AgentSpec

registry.add_agent(AgentSpec(
    name="orders",
    description="questions about existing orders, shipping and returns",   # the router reads this
    prompt="You answer questions about orders. Use lookup_order. ...",
    tools=["lookup_order", "handoff", "escalate_to_human"],
    sticky=False,        # route each new message again (like support); True keeps the conversation (like coder)
    cacheable=False,     # allow semantic-cache answers for first messages; only if answers don't depend on data
    auto_continue=False, # nudge models that announce a step without taking it (useful for multi-step work)
))
```

The router chooses between all registered agents using their `description`s, and the `route` and `handoff` tools list them automatically. Tenants can override any agent's prompt (and the router's) with `POST /v1/prompts`; the version number is part of the cache scope.

To change a built-in, register under the same name with `replace=True`. For example, to give `support` a lookup tool:

```python
from harnis.plugins import SUPPORT_PROMPT, AgentSpec

registry.add_agent(AgentSpec(name="support", description="general questions, orders, billing",
                             prompt=SUPPORT_PROMPT + " Use lookup_order for order questions.",
                             tools=["lookup_order", "handoff", "escalate_to_human"],
                             sticky=False, default=True), replace=True)
```

## Model providers

A provider turns Harnis's neutral request into a model call and back: see `harnis/llm/types.py` (`LLMRequest`, `LLMResponse`, `ProviderError`) and the built-in adapters in `harnis/llm/providers.py`.

```python
from harnis.llm.types import ProviderError, classify_status

class MyGatewayProvider:
    name = "mygateway"
    def model_for(self, tier): return {"main": "big-model", "fast": "small-model"}[tier]
    def complete(self, req): ...   # raise ProviderError(..., retryable=..., failover=...) on errors

registry.add_provider("mygateway", lambda settings: MyGatewayProvider() if gateway_configured() else None)
```

Then add it to `LLM_PROVIDERS` (failover order). Returning `None` from the factory means "not configured", and the provider is skipped with a log line. Raise `ProviderError` with the right flags (`classify_status(http_status)` helps), so the router retries transient errors, fails over on outages and auth errors, and stops on bad requests.

Self-hosted models that speak the OpenAI Chat Completions API (vLLM, Ollama, LM Studio, LiteLLM) don't need a plugin: use the built-in `openai_compatible` provider (`OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_MODEL`).

**Tenants and providers:** `tenants.allowed_providers` limits where each tenant's data may go. `*` (the default) means every configured provider; a list like `["anthropic"]` pins a tenant to specific providers for data residency or contractual reasons, and failover never leaves that list.

## Testing a plugin

Use the in-memory test fixtures from Harnis's own suite as a model: build a registry with `build_registry(["your_plugin"])`, drive the orchestrator with a scripted provider, and assert on tool results and approvals. `tests/test_plugins.py` does exactly that for the example plugin. Add eval cases (`evals/cases/*.yaml`) for your agent so `python tasks.py eval` covers it against real models.

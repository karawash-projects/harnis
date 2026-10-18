# harnis-plugin-tickets

An example [Harnis](../../../README.md) plugin: a `triage` agent with a `search_tickets` tool (runs immediately) and a `create_ticket` tool (a reviewer approves each ticket before it is filed).

```bash
pip install -e examples/plugins/harnis-plugin-tickets
# .env
PLUGINS=tickets
```

Restart the API; `GET /v1/agents` now lists `triage`, and the router can send incident reports to it. See [docs/plugins.md](../../../docs/plugins.md) for the SDK.

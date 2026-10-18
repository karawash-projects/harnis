# SPDX-License-Identifier: Apache-2.0
"""Example Harnis plugin: ticket triage.

Adds two tools and one agent:

  search_tickets  (low risk)   find existing tickets
  create_ticket   (high risk)  open a ticket; a reviewer approves each one,
                               seeing exactly the ticket that will be filed
  triage agent                 bug reports and incidents: searches before filing

To keep the example self-contained, tickets are JSON files in the session
workspace under tickets/. In a real plugin, `_file_ticket` and
`_search` would call your tracker's API (Jira, Linear, ServiceNow, ...); keep
credentials in your own settings or secret store, never in tool arguments.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from harnis.plugins import AgentSpec, Registry
from harnis.tools import Tool, ToolContext, list_workspace, read_text, safe_path, write_text


class SearchArgs(BaseModel):
    query: str = Field(..., min_length=1, max_length=200)


class CreateArgs(BaseModel):
    title: str = Field(..., min_length=5, max_length=120)
    description: str = Field(..., min_length=10, max_length=5000)
    priority: Literal["low", "normal", "high", "urgent"] = "normal"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "ticket"


def _search(ctx: ToolContext, args: SearchArgs) -> tuple[str, bool]:
    q = args.query.lower()
    hits = []
    for rel in list_workspace(ctx.workspace):
        if rel.startswith("tickets/") and rel.endswith(".json"):
            t = json.loads(read_text(safe_path(ctx.workspace, rel)))
            if q in t["title"].lower() or q in t["description"].lower():
                hits.append(f"{t['id']} [{t['priority']}] {t['title']}")
    return ("\n".join(hits) if hits else "no matching tickets"), False


def _ticket(args: dict, ctx_user: str = "") -> dict:
    return {"id": f"TCK-{_slug(args.get('title', ''))[:24]}", "title": args.get("title", ""),
            "description": args.get("description", ""), "priority": args.get("priority", "normal")}


def _file_ticket(ctx: ToolContext, args: CreateArgs) -> tuple[str, bool]:
    ticket = {**_ticket(args.model_dump()), "reporter": ctx.user_id, "tenant": ctx.tenant_id,
              "session": ctx.session_id}
    path = safe_path(ctx.workspace, f"tickets/{_slug(args.title)}.json")
    if path.exists():
        return f"a ticket with this title already exists: {ticket['id']}", True
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, json.dumps(ticket, indent=2))
    return f"created {ticket['id']}", False


def _describe(workspace: Path, args: dict) -> dict:
    # What the reviewer sees (and what the approval hash covers).
    return {"ticket_preview": _ticket(args)}


def register(registry: Registry) -> None:
    registry.add_tool(Tool("search_tickets", "Search existing tickets by keyword. Always search before filing.",
                           SearchArgs, "low", _search, untrusted_output=True))
    registry.add_tool(Tool("create_ticket", "File a new ticket. Requires human approval.",
                           CreateArgs, "high", _file_ticket, untrusted_output=False, describe=_describe))
    registry.add_agent(AgentSpec(
        name="triage",
        description="bug reports, incidents and outages: search for and file tickets",
        prompt=("You triage bug reports and incidents. First call search_tickets to look for duplicates. "
                "If none matches, call create_ticket with a clear title, steps to reproduce and impact, "
                "and a priority. Then tell the user the ticket id. Hand code changes to the coder."),
        tools=["search_tickets", "create_ticket", "list_files", "read_file", "handoff", "escalate_to_human"],
        sticky=True))

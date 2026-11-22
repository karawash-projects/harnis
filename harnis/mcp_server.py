# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""MCP server: lets tools such as Claude Code, VS Code (agent mode) and Cursor hand a task to Harnis.

    pip install "harnis[mcp]"
    HARNIS_API=https://harnis.example.com HARNIS_TOKEN=hrn_... python -m harnis.mcp_server

It runs on your machine over stdio, uploads the project folder (the same way the `harnis` command does),
and exposes five tools: start a task, check on it, send a follow-up, see the proposed changes, and apply
them. That is a governed route to the agents, not enforcement: an agent that has its own model key or shell
is not controlled by Harnis (see docs/operations.md).

There is deliberately NO tool to approve or deny. Approvals belong to people, in the Harnis console or
the `harnis` command. Give this server a token with only the `user` role, so that even a misbehaving client
could not approve anything.

Nothing touches your files until `harnis_apply_changes` is called, and that refuses any file you changed
after you looked at the proposed changes.
"""
from __future__ import annotations

import difflib
import functools
import hashlib
import os
import time
from pathlib import Path
from typing import Any

import httpx

from .cli import collect
from .tools import WorkspaceError, safe_path, write_text

WAIT_SECONDS = 60  # how long a call waits for the agent before returning the current state


class HarnisError(Exception):
    """A problem to show the user (bad token, unknown session, ...), never a stack trace."""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class HarnisClient:
    def __init__(self, api: str, token: str, workspace: Path, http: httpx.Client | None = None,
                 wait_seconds: float = WAIT_SECONDS, poll: float = 0.5):
        self.workspace = workspace.resolve()
        self.api = api.rstrip("/")
        self.wait_seconds, self.poll = wait_seconds, poll
        self.http = http or httpx.Client(base_url=self.api, headers={"Authorization": f"Bearer {token}"}, timeout=120)
        self._seen: dict[str, dict[str, str]] = {}  # session -> {path: hash of your local file when you looked}

    def call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise HarnisError(f"cannot reach Harnis at {self.api}: {exc}") from exc
        if r.status_code == 401:
            raise HarnisError("Harnis rejected the token (expired or revoked). Create a new one.")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise HarnisError(f"Harnis returned {r.status_code}: {detail}")
        return r.json()

    # -- views ----------------------------------------------------------------------------------
    def _summary(self, s: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"session_id": s["session_id"], "status": s["status"], "agent": s.get("agent"),
                               "reply": s.get("reply")}
        if s["status"] == "awaiting_approval":
            ap = s.get("approval") or {}
            action = ap.get("action") or {}
            out["waiting_for"] = (f"a human reviewer to approve {action.get('tool', 'an action')}. "
                                  f"Approve it in the Harnis console ({self.api}); this tool cannot approve.")
        if s.get("escalation"):
            e = s["escalation"]
            out["handover"] = {k: e.get(k) for k in ("what_happened", "files_written", "tests", "next_steps")}
        return out

    def _wait(self, s: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.wait_seconds
        while s["status"] == "running" and time.monotonic() < deadline:
            time.sleep(self.poll)
            s = self.call("GET", f"/v1/sessions/{s['session_id']}")
        return s

    # -- tools ----------------------------------------------------------------------------------
    def start_task(self, task: str) -> dict[str, Any]:
        files = collect(self.workspace)
        sid = self.call("POST", "/v1/sessions", json={"files": files})["session_id"]
        s = self.call("POST", f"/v1/sessions/{sid}/turns", json={"message": task})
        out = self._summary(self._wait(s))
        out["files_uploaded"] = len(files)
        return out

    def status(self, session_id: str) -> dict[str, Any]:
        return self._summary(self._wait(self.call("GET", f"/v1/sessions/{session_id}")))

    def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        s = self.call("POST", f"/v1/sessions/{session_id}/turns", json={"message": message})
        return self._summary(self._wait(s))

    def _changed(self, session_id: str) -> dict[str, tuple[str, str]]:
        remote = self.call("GET", f"/v1/sessions/{session_id}/files")
        changed: dict[str, tuple[str, str]] = {}
        for path, text in remote.items():
            try:
                local_path = safe_path(self.workspace, path)
            except WorkspaceError:
                continue
            local = local_path.read_bytes().decode("utf-8", errors="replace") if local_path.is_file() else ""
            if local != text:
                changed[path] = (local, text)
        return changed

    def get_changes(self, session_id: str) -> dict[str, Any]:
        changed = self._changed(session_id)
        self._seen[session_id] = {p: _sha(old) for p, (old, _new) in changed.items()}
        diffs = {p: "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                 fromfile=f"a/{p}", tofile=f"b/{p}"))
                 for p, (old, new) in changed.items()}
        return {"session_id": session_id, "files_changed": sorted(diffs), "diffs": diffs}

    def apply_changes(self, session_id: str, paths: list[str] | None = None) -> dict[str, Any]:
        seen = self._seen.get(session_id)
        if seen is None:
            raise HarnisError("call harnis_get_changes first, so you have seen what will be written")
        changed = self._changed(session_id)
        applied, skipped = [], {}
        for path in (paths if paths is not None else sorted(seen)):
            if path not in seen:
                skipped[path] = "not among the changes you were shown"
                continue
            if path not in changed:
                skipped[path] = "already matches the session's version"
                continue
            old, new = changed[path]
            if _sha(old) != seen[path]:
                skipped[path] = "you changed this file after looking at the proposed changes; review again"
                continue
            try:
                target = safe_path(self.workspace, path)
            except WorkspaceError as exc:
                skipped[path] = str(exc)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            write_text(target, new)
            applied.append(path)
        return {"applied": applied, "skipped": skipped}


INSTRUCTIONS = (
    "Hands tasks to Harnis, a controlled agent platform. Work happens in an isolated copy of the project. "
    "Anything that changes files or runs commands waits for a human reviewer in Harnis; you cannot approve it. "
    "Use harnis_start_task, then harnis_task_status until it is done, then harnis_get_changes and, if the user agrees, "
    "harnis_apply_changes.")


def build_server(client: HarnisClient):
    from mcp.server.mcpserver import MCPServer

    mcp = MCPServer("harnis", instructions=INSTRUCTIONS)

    def guarded(fn):
        @functools.wraps(fn)  # keeps the signature, so the tool's schema lists its real arguments
        def run(*a: Any, **k: Any) -> Any:
            try:
                return fn(*a, **k)
            except HarnisError as exc:
                return {"error": str(exc)}
        return run

    @mcp.tool(name="harnis_start_task")
    @guarded
    def harnis_start_task(task: str) -> dict:
        """Upload the project to a new Harnis session and give the agents this task. Returns the session id and where it stands (it may be waiting for a human to approve a change)."""
        return client.start_task(task)

    @mcp.tool(name="harnis_task_status")
    @guarded
    def harnis_task_status(session_id: str) -> dict:
        """Where a Harnis session stands: running, waiting for a human approval, done, or stopped (with a handover summary)."""
        return client.status(session_id)

    @mcp.tool(name="harnis_send_message")
    @guarded
    def harnis_send_message(session_id: str, message: str) -> dict:
        """Send a follow-up message in an existing Harnis session."""
        return client.send_message(session_id, message)

    @mcp.tool(name="harnis_get_changes")
    @guarded
    def harnis_get_changes(session_id: str) -> dict:
        """Show the files the agents changed in the session, as diffs against the local project. Nothing is written locally."""
        return client.get_changes(session_id)

    @mcp.tool(name="harnis_apply_changes")
    @guarded
    def harnis_apply_changes(session_id: str, paths: list[str] | None = None) -> dict:
        """Write the session's changes into the local project (all of them, or only `paths`). Only after the user has seen them via harnis_get_changes; refuses files edited since."""
        return client.apply_changes(session_id, paths)

    return mcp


def main() -> None:
    api = os.getenv("HARNIS_API", "http://127.0.0.1:8000")
    token = os.getenv("HARNIS_TOKEN")
    if not token:
        raise SystemExit("set HARNIS_TOKEN (a Harnis token or API key with the `user` role)")
    client = HarnisClient(api, token, Path(os.getenv("HARNIS_WORKSPACE", ".")))
    try:
        server = build_server(client)
    except ImportError:
        raise SystemExit('the MCP server needs the "mcp" package: pip install "harnis[mcp]"') from None
    server.run(transport="stdio")

if __name__ == "__main__":
    main()

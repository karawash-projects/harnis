# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""CLI coding agent (draft -> review -> commit).

    # macOS / Linux
    export HARNIS_TOKEN=$(python -m harnis.auth mint --user dev --tenant acme --roles user,reviewer)
    # Windows PowerShell
    $env:HARNIS_TOKEN = python -m harnis.auth mint --user dev --tenant acme --roles user,reviewer

    harnis --workspace ./myproject "add a slugify() helper with tests"

1. Your workspace is uploaded into a fresh, isolated session workspace
   (.git, virtualenvs, node_modules and big files are skipped).
2. The agent works there. Any write or command stops for your approval, with
   the diff or command shown; you answer y/N.
3. When the turn ends you see the full diff against your local files and
   decide whether to apply it. Nothing touches your real files before that.
"""
from __future__ import annotations

import argparse
import difflib
import os
import sys
import time
from pathlib import Path

import httpx

from .tools import WorkspaceError, safe_path, write_text

SKIP_DIRS = {".git", ".hg", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
             "dist", "build", ".workspaces"}
MAX_BYTES = 200_000
MAX_FILES = 200


def collect(workspace: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath, name)
            if p.is_symlink() or p.stat().st_size > MAX_BYTES or name.startswith(".env"):
                continue
            try:
                # Bytes -> UTF-8 explicitly: no locale codepage, no CRLF translation.
                text = p.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue  # binary file
            files[p.relative_to(workspace).as_posix()] = text
            if len(files) >= MAX_FILES:
                print(f"note: only the first {MAX_FILES} files were uploaded", file=sys.stderr)
                return files
    return files


def ask(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


class Client:
    def __init__(self, api: str, token: str):
        self.http = httpx.Client(base_url=api, headers={"Authorization": f"Bearer {token}"}, timeout=300)

    def call(self, method: str, path: str, **kw):
        r = self.http.request(method, path, **kw)
        if r.status_code >= 400:
            raise SystemExit(f"error {r.status_code} on {path}: {r.text}")
        return r.json()


def wait_for_resume(c: Client, session_id: str, approval_id: str) -> dict:
    for _ in range(600):
        s = c.call("GET", f"/v1/sessions/{session_id}")
        aw = s.get("awaiting") or {}
        if s["status"] != "running" and aw.get("approval_id") != approval_id:
            return s
        time.sleep(0.5)
    raise SystemExit("timed out waiting for the session to resume")


def review_loop(c: Client, s: dict) -> dict:
    while s["status"] == "awaiting_approval":
        aw = s["awaiting"]
        pending = {a["approval_id"]: a for a in c.call("GET", "/v1/approvals")}
        appr = pending.get(aw["approval_id"])
        if appr is None:
            raise SystemExit("approval not visible; does your token have the 'reviewer' role?")
        action = appr["action"]
        print(f"\n--- approval needed: {action['tool']} ---")
        if action["tool"] == "write_file":
            print(action.get("diff") or "(no changes)")
        else:
            print(f"$ {action['args'].get('command')}")
        ok = ask("Allow this?")
        c.call("POST", f"/v1/approvals/{aw['approval_id']}/decision",
               json={"approved": ok, "action_hash": aw["action_hash"]})
        s = wait_for_resume(c, s["session_id"], aw["approval_id"])
    return s


def apply_changes(c: Client, session_id: str, workspace: Path, original: dict[str, str]) -> None:
    remote = c.call("GET", f"/v1/sessions/{session_id}/files")
    changed = {p: t for p, t in remote.items() if original.get(p) != t}
    if not changed:
        print("\nNo file changes.")
        return
    print("\n=== proposed changes to your workspace ===")
    for path, text in changed.items():
        print("".join(difflib.unified_diff(original.get(path, "").splitlines(True), text.splitlines(True),
                                           fromfile=f"a/{path}", tofile=f"b/{path}")))
    if ask(f"Apply {len(changed)} file(s) to {workspace}?"):
        for path, text in changed.items():
            try:
                target = safe_path(workspace, path)
            except WorkspaceError as exc:
                print(f"skipping {path}: {exc}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            write_text(target, text)
        print("Applied.")
    else:
        print("Discarded. (The session workspace still has them.)")


def _console_safe() -> None:
    """Windows consoles may not be UTF-8; never crash printing a diff."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> None:
    _console_safe()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("message")
    ap.add_argument("--workspace", type=Path, default=Path("."))
    ap.add_argument("--session", help="continue an existing session")
    ap.add_argument("--api", default=os.getenv("HARNIS_API", "http://127.0.0.1:8000"))
    ap.add_argument("--token", default=os.getenv("HARNIS_TOKEN"))
    a = ap.parse_args(argv)
    if not a.token:
        raise SystemExit("set HARNIS_TOKEN or pass --token (python -m harnis.auth mint ...)")
    c = Client(a.api, a.token)
    original = collect(a.workspace)
    if a.session:
        session_id = a.session
    else:
        session_id = c.call("POST", "/v1/sessions", json={"files": original})["session_id"]
        print(f"session {session_id} ({len(original)} files uploaded)")
    s = c.call("POST", f"/v1/sessions/{session_id}/turns", json={"message": a.message})
    s = review_loop(c, s)
    print(f"\n[{s['status']}] {s.get('reply') or ''}")
    apply_changes(c, session_id, a.workspace, original)


if __name__ == "__main__":
    main()

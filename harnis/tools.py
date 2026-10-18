# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Built-in tools, and the `Tool` type plugins use to define their own.

Every tool has:
  * a Pydantic input model — arguments are validated before anything runs,
    and a validation error goes back to the model as a tool error (so it can
    fix its call) instead of crashing the harness;
  * a risk tier — "low" runs immediately, "high" suspends the session until a
    human approves the exact action;
  * a workspace-confined implementation.

`handoff` and `escalate_to_human` are control tools handled by the
orchestrator itself. Tools, agents and providers are looked up through
`harnis.plugins.Registry`; see docs/plugins.md to add your own.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field, ValidationError

from .llm.types import ToolSpec
from .sandbox import DEPS_DIR, RESERVED_DIR, Sandbox

MAX_FILE_BYTES = 200_000


class ListFiles(BaseModel):
    pass


class ReadFile(BaseModel):
    path: str = Field(..., min_length=1, max_length=300)


class WriteFile(BaseModel):
    path: str = Field(..., min_length=1, max_length=300)
    content: str = Field(..., max_length=MAX_FILE_BYTES)


class RunTests(BaseModel):
    pass


class RunCommand(BaseModel):
    command: str = Field(..., min_length=1, max_length=2000)


class InstallDependencies(BaseModel):
    manager: Literal["pip", "npm"] = Field(..., description="pip (Python) or npm (Node.js)")
    file: str | None = Field(None, max_length=300, description=(
        "manifest to install from: a requirements file or pyproject.toml for pip (default requirements.txt), "
        "package.json for npm (default package.json; package-lock.json next to it is used when present)"))


class Handoff(BaseModel):
    agent: str = Field(..., min_length=1, max_length=64)  # checked against the registry
    reason: str = Field("", max_length=500)


class Escalate(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class Route(BaseModel):
    agent: str = Field(..., min_length=1, max_length=64)  # checked against the registry
    reason: str = Field("", max_length=500)


class WorkspaceError(Exception):
    pass


# Device names Windows refuses to create as files, whatever the extension.
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                     *(f"lpt{i}" for i in range(1, 10))}


def normalize_rel(rel: str) -> str:
    """Workspace paths are POSIX-style everywhere ("src/app.py"), whatever OS
    the API runs on. Backslashes are treated as separators so a model that
    writes "src\\app.py" means the same file on Windows and Linux."""
    if "\x00" in rel:
        raise WorkspaceError("path contains a NUL byte")
    rel = rel.replace("\\", "/")
    if (PurePosixPath(rel).is_absolute() or PureWindowsPath(rel).drive or rel.startswith("~")):
        raise WorkspaceError("path must be relative to the workspace")
    parts = [p for p in PurePosixPath(rel).parts if p not in ("", ".")]
    if not parts:
        raise WorkspaceError("empty path")
    if ".." in parts:
        raise WorkspaceError("path escapes the workspace")
    for part in parts:
        if part.split(".")[0].lower() in _WINDOWS_RESERVED or part.endswith((" ", ".")) or \
                any(c in part for c in '<>:"|?*'):
            raise WorkspaceError(f"{part!r} is not a portable file name")
    return "/".join(parts)


def safe_path(workspace: Path, rel: str) -> Path:
    """Resolve `rel` inside the workspace, refusing absolute paths (POSIX,
    drive letters, UNC), `..`, non-portable names and symlinks that point
    outside it."""
    root = workspace.resolve()
    target = root.joinpath(*normalize_rel(rel).split("/")).resolve()
    if target != root and root not in target.parents:
        raise WorkspaceError("path escapes the workspace")
    return target


def read_text(p: Path) -> str:
    """UTF-8 regardless of the OS locale (Windows defaults to cp1252), and no
    newline translation, so hashes and diffs are identical on every OS."""
    return p.read_bytes().decode("utf-8", errors="replace")


def write_text(p: Path, content: str) -> None:
    p.write_bytes(content.encode("utf-8"))


def is_reserved(rel: str) -> bool:
    """`.harnis/` holds installed dependencies: never written by tools or seeds.
    Case-insensitive, because Windows and macOS filesystems are."""
    rel = normalize_rel(rel).lower()
    return rel == RESERVED_DIR or rel.startswith(RESERVED_DIR + "/")


def read_regular(p: Path, max_bytes: int) -> str | None:
    """Read a regular file without following a symlink at the last component
    (bind-mode sandboxes write straight into the host folder). None if it is
    not a regular file or is larger than max_bytes."""
    import stat
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        if p.is_symlink():
            return None
        fd = os.open(p, flags)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        return f.read(max_bytes + 1)[:max_bytes].decode("utf-8", errors="replace")


def list_workspace(workspace: Path, limit: int = 500) -> list[str]:
    """The project's files (installed dependencies under .harnis are not listed)."""
    root = workspace.resolve()
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        top = Path(dirpath) == root
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".pytest_cache", "node_modules"}
                       and not (top and d.lower() == RESERVED_DIR)
                       and not os.path.islink(os.path.join(dirpath, d))]
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue  # only the project's regular files
            out.append(Path(dirpath, f).relative_to(root).as_posix())
            if len(out) >= limit:
                return sorted(out)
    return sorted(out)


def action_hash(action: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def unified_diff(workspace: Path, path: str, new_content: str) -> str:
    try:
        target = safe_path(workspace, path)
        old = read_text(target) if target.is_file() else ""
    except WorkspaceError:
        old = ""
    return "".join(difflib.unified_diff(old.splitlines(True), new_content.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


@dataclass
class ToolContext:
    """What a tool implementation gets besides its validated arguments."""
    workspace: Path            # this session's workspace (use safe_path for any path you accept)
    sandbox: Sandbox           # run untrusted code here, never in the API process
    tenant_id: str = ""
    user_id: str = ""
    session_id: str = ""


@dataclass
class Tool:
    """A tool the model can call.

    risk:
      "low"      runs immediately
      "high"     suspends the session until a reviewer approves this exact call
      "control"  handled by the orchestrator (handoff, escalate)
    untrusted_output:
      True fences the result as untrusted data and scans it for injected
      instructions before the model sees it. Leave it on for anything that
      returns file contents, web pages, command output or third-party data.
    describe:
      Optional; returns extra reviewer-facing detail for high-risk calls
      (e.g. a diff). It is part of the approval hash.
    """
    name: str
    description: str
    model: type[BaseModel]
    risk: Literal["low", "high", "control"]
    run: Callable[[ToolContext, Any], tuple[str, bool]] | None  # -> (output, is_error)
    untrusted_output: bool = True
    describe: Callable[[Path, dict[str, Any]], dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        import re

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$", self.name):
            raise ValueError(f"invalid tool name {self.name!r}")
        if self.risk not in ("low", "high", "control"):
            raise ValueError(f"tool {self.name}: risk must be low, high or control")
        if self.risk != "control" and self.run is None:
            raise ValueError(f"tool {self.name}: a run function is required")

    def spec(self) -> ToolSpec:
        schema = self.model.model_json_schema()
        schema.pop("title", None)
        schema.setdefault("properties", {})
        return ToolSpec(self.name, self.description, schema)

    def validate(self, args: Any) -> BaseModel:
        return self.model.model_validate(args if isinstance(args, dict) else {})


def _list(ctx: ToolContext, _: BaseModel) -> tuple[str, bool]:
    files = list_workspace(ctx.workspace)
    return ("\n".join(files) if files else "(workspace is empty)"), False


def _read(ctx: ToolContext, a: ReadFile) -> tuple[str, bool]:  # type: ignore[override]
    try:
        p = safe_path(ctx.workspace, a.path)
        if not p.is_file():
            return f"no such file: {a.path}", True
        if p.stat().st_size > MAX_FILE_BYTES:
            return f"file too large (> {MAX_FILE_BYTES} bytes)", True
        return read_text(p), False
    except WorkspaceError as exc:
        return str(exc), True


def _write(ctx: ToolContext, a: WriteFile) -> tuple[str, bool]:  # type: ignore[override]
    try:
        if is_reserved(a.path):
            return f"{RESERVED_DIR}/ is reserved for installed dependencies; use install_dependencies", True
        p = safe_path(ctx.workspace, a.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        write_text(p, a.content)
        return f"wrote {len(a.content)} bytes to {a.path}", False
    except WorkspaceError as exc:
        return str(exc), True


def _run_tests(ctx: ToolContext, _: BaseModel) -> tuple[str, bool]:
    r = ctx.sandbox.run("python -m pytest -q -p no:cacheprovider 2>&1", ctx.workspace)
    if r.error:
        return r.error, True
    return f"exit_code={r.exit_code}\n{r.output}", r.exit_code != 0


def _run_command(ctx: ToolContext, a: RunCommand) -> tuple[str, bool]:  # type: ignore[override]
    r = ctx.sandbox.run(a.command, ctx.workspace)
    if r.error:
        return r.error, True
    return f"exit_code={r.exit_code}\n{r.output}", r.exit_code != 0


def _manifest(ctx_ws: Path, manager: str, file: str | None) -> tuple[str, Path]:
    rel = normalize_rel(file or ("requirements.txt" if manager == "pip" else "package.json"))
    if is_reserved(rel):
        raise WorkspaceError("pick a manifest in the project, not under .harnis/")
    name = PurePosixPath(rel).name
    if manager == "pip" and not (name == "pyproject.toml" or name.endswith(".txt")):
        raise WorkspaceError("pip installs from a requirements .txt file or pyproject.toml")
    if manager == "npm" and name != "package.json":
        raise WorkspaceError("npm installs from package.json")
    p = safe_path(ctx_ws, rel)
    if not p.is_file():
        raise WorkspaceError(f"no such file: {rel}")
    return rel, p


def install_command(manager: str, rel: str) -> str:
    """The exact command, part of what the reviewer approves."""
    import shlex

    target = f"{DEPS_DIR}/python" if manager == "pip" else f"{DEPS_DIR}/node"
    if manager == "pip":
        source = "." if PurePosixPath(rel).name == "pyproject.toml" else "-r " + shlex.quote(rel)
        if PurePosixPath(rel).name == "pyproject.toml" and str(PurePosixPath(rel).parent) != ".":
            source = shlex.quote(str(PurePosixPath(rel).parent))
        return (f"mkdir -p {target} && python -m pip install --no-input --no-cache-dir --target {target} "
                f"--upgrade {source} 2>&1")
    folder = str(PurePosixPath(rel).parent)
    lock = "package-lock.json" if folder == "." else f"{folder}/package-lock.json"
    # Lifecycle scripts are disabled: packages can't run code at install time.
    return (f"command -v npm >/dev/null || {{ echo 'npm is not installed in the sandbox image "
            f"(build it with --build-arg WITH_NODE=true)'; exit 127; }}; mkdir -p {target} && "
            f"cp {shlex.quote(rel)} {target}/package.json && "
            f"{{ [ -f {shlex.quote(lock)} ] && cp {shlex.quote(lock)} {target}/ || true; }} && cd {target} && "
            f"{{ [ -f package-lock.json ] && npm ci --ignore-scripts --no-audit --no-fund || "
            f"npm install --ignore-scripts --no-audit --no-fund; }} 2>&1")


def _describe_install(ws: Path, args: dict[str, Any]) -> dict[str, Any]:
    try:
        rel, p = _manifest(ws, args.get("manager", ""), args.get("file"))
    except (WorkspaceError, ValueError) as exc:
        return {"error": str(exc)}
    text = read_text(p)
    # The approval hash covers the whole manifest and every file it pulls in
    # (-r / -c includes), not just what fits on the reviewer's screen.
    digests = {rel: hashlib.sha256(p.read_bytes()).hexdigest()}
    included = []
    if args["manager"] == "pip":
        base = PurePosixPath(rel).parent
        for line in text.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0] in ("-r", "-c", "--requirement", "--constraint"):
                inc = str(base / parts[1].strip()) if str(base) != "." else parts[1].strip()
                try:
                    ip = safe_path(ws, inc)
                    digests[normalize_rel(inc)] = hashlib.sha256(ip.read_bytes()).hexdigest() if ip.is_file() \
                        else "missing"
                except WorkspaceError:
                    digests[inc] = "outside the workspace"
                included.append(inc)
    return {"manifest": rel, "manifest_content": text[:20_000],
            "manifest_truncated": len(text) > 20_000, "included_files": included, "sha256": digests,
            "command": install_command(args["manager"], rel),
            "network": "HTTPS to the allowlisted package registries only (through the egress proxy)"}


def _install(ctx: ToolContext, a: InstallDependencies) -> tuple[str, bool]:  # type: ignore[override]
    try:
        rel, _ = _manifest(ctx.workspace, a.manager, a.file)
    except WorkspaceError as exc:
        return str(exc), True
    r = ctx.sandbox.run(install_command(a.manager, rel), ctx.workspace, egress=True)
    if r.error:
        return r.error, True
    tail = r.output[-6000:]
    return f"exit_code={r.exit_code}\n{tail}", r.exit_code != 0


BUILTIN_TOOLS: list[Tool] = [
    Tool("list_files", "List files in the session workspace.", ListFiles, "low", _list),
    Tool("read_file", "Read a UTF-8 text file from the workspace.", ReadFile, "low", _read),
    Tool("write_file", "Create or overwrite a file in the workspace. Requires human approval; "
         "the reviewer sees a diff.", WriteFile, "high", _write, untrusted_output=False,
         describe=lambda ws, args: {"diff": unified_diff(ws, args.get("path", ""), args.get("content", ""))}),
    Tool("run_tests", "Run the project's test suite (pytest) in an isolated sandbox with no network.",
         RunTests, "low", _run_tests),
    Tool("run_command", "Run a shell command in an isolated sandbox (no network, read-only root, "
         "the workspace is the current directory). Requires human approval.", RunCommand, "high", _run_command),
    Tool("install_dependencies", "Install the project's dependencies (pip from a requirements file or "
         "pyproject.toml, npm from package.json) so tests and commands can import them. This is the only "
         "step with network access, limited to the package registries. Requires human approval; the reviewer "
         "sees the manifest.", InstallDependencies, "high", _install, describe=_describe_install),
    Tool("handoff", "Hand the conversation to another specialist agent.", Handoff, "control", None),
    Tool("escalate_to_human", "Stop and hand the conversation to a human operator.", Escalate, "control", None),
]

ROUTE_TOOL = Tool("route", "Choose which specialist agent should handle the user's message.",
                  Route, "control", None)


def describe_action(ctx_workspace: Path, name: str, args: dict[str, Any], tool: Tool | None = None) -> dict[str, Any]:
    """What a reviewer is shown, and what the approval hash covers."""
    action: dict[str, Any] = {"tool": name, "args": args}
    if tool is None:
        tool = next((t for t in BUILTIN_TOOLS if t.name == name), None)
    if tool is not None and tool.describe is not None:
        action.update(tool.describe(ctx_workspace, args))
    return action


__all__ = ["BUILTIN_TOOLS", "ROUTE_TOOL", "Tool", "ToolContext", "ValidationError", "install_command",
           "is_reserved", "read_regular",
           "action_hash", "describe_action", "safe_path", "normalize_rel", "list_workspace",
           "WorkspaceError", "read_text", "write_text"]

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Path policy: which workspace files agents may read or write.

A TOML file the operator points `PATH_POLICY_FILE` at:

    deny_read   = ["**/.env", "secrets/**"]       # agents cannot read these, and they are hidden from listings
    deny_write  = [".github/**", "**/*.pem"]      # agents cannot write these
    allow_write = ["src/**", "tests/**"]          # optional: if present, writes are limited to these

Patterns are matched against the workspace-relative path, case-insensitively (Windows and macOS
filesystems are). `*` matches within one folder, `**` across folders, `?` one character. A deny always
wins over an allow.

This governs the file tools (`read_file`, `write_file`, `list_files`). It does not govern what a command
run with `run_command` or an install does inside the sandbox; those are covered by the reviewer's approval
of the exact command and by the sandbox itself.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_KEYS = ("deny_read", "deny_write", "allow_write")


def _glob(pattern: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")          # zero or more folders
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _clean(pattern: object, where: str) -> str:
    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError(f"{where}: patterns must be non-empty strings")
    p = pattern.strip().replace("\\", "/")
    if p.startswith("/") or ".." in p.split("/"):
        raise ValueError(f"{where}: {pattern!r} must be relative to the workspace and contain no '..'")
    if p.endswith("/"):
        p += "**"                              # "docs/" means everything under docs
    return p


@dataclass(frozen=True)
class PathPolicy:
    deny_read: tuple[str, ...] = ()
    deny_write: tuple[str, ...] = ()
    allow_write: tuple[str, ...] = ()
    _re: dict[str, re.Pattern[str]] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        for p in (*self.deny_read, *self.deny_write, *self.allow_write):
            self._re[p] = _glob(p)

    @staticmethod
    def from_dict(data: dict) -> "PathPolicy":
        unknown = set(data) - set(_KEYS)
        if unknown:
            raise ValueError(f"unknown path policy key(s): {', '.join(sorted(unknown))}; expected {', '.join(_KEYS)}")
        vals = {}
        for k in _KEYS:
            v = data.get(k, [])
            if not isinstance(v, list):
                raise ValueError(f"{k} must be a list of patterns")
            vals[k] = tuple(_clean(p, k) for p in v)
        return PathPolicy(**vals)

    @staticmethod
    def load(path: str | Path) -> "PathPolicy":
        try:
            data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"cannot read path policy {path}: {exc}") from exc
        return PathPolicy.from_dict(data)

    def _hit(self, patterns: tuple[str, ...], rel: str) -> str | None:
        return next((p for p in patterns if self._re[p].match(rel)), None)

    def read_denied(self, rel: str) -> str | None:
        """None if reading `rel` is allowed, otherwise a reason to tell the agent."""
        hit = self._hit(self.deny_read, rel)
        return f"policy: reading {rel} is not allowed (matches {hit})" if hit else None

    def write_denied(self, rel: str) -> str | None:
        hit = self._hit(self.deny_write, rel)
        if hit:
            return f"policy: writing {rel} is not allowed (matches {hit})"
        if self.allow_write and not self._hit(self.allow_write, rel):
            return f"policy: writes are limited to {', '.join(self.allow_write)}; {rel} is outside them"
        return None

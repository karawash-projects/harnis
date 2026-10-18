# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""pytest plugin used by scripts/gvisor_check.py: run the sandbox tests under
the container runtime named in SANDBOX_RUNTIME (e.g. runsc for gVisor).

tests/test_sandbox.py builds DockerSandbox(...) without a `runtime=` argument,
so on its own it always tests the daemon's default runtime (runc). This plugin
makes every DockerSandbox created during the test session default to
$SANDBOX_RUNTIME, and fails the session if any sandbox was created with a
different runtime, so a green run really means "passed under gVisor".

Known gVisor gaps are marked as expected failures (non-strict xfail) unless
GVISOR_CHECK_STRICT=1, so they are reported but do not hide other failures.
See docs/gvisor.md ("What gVisor treats differently").

Loaded with: python -m pytest -p gvisor_pytest_plugin ...  (scripts/ on PYTHONPATH)
"""
from __future__ import annotations

import os

import pytest

RUNTIME = os.environ.get("SANDBOX_RUNTIME", "").strip()
STRICT = os.environ.get("GVISOR_CHECK_STRICT", "").strip().lower() in ("1", "true", "yes")

# test name -> why it is expected to fail under gVisor
KNOWN_GVISOR_GAPS = {
    "test_pid_limit_stops_fork_bomb": (
        "gVisor applies --pids-limit to the sandbox's host cgroup (Sentry and Gofer threads plus one "
        "systrap stub process per sandboxed process), not to the sandboxed processes themselves, so "
        "fork() may fail earlier than the limit, or the Sentry may abort instead. See docs/gvisor.md."
    ),
}

_created: list[str] = []


def pytest_configure(config: pytest.Config) -> None:
    if not RUNTIME:
        raise pytest.UsageError("gvisor_pytest_plugin: set SANDBOX_RUNTIME (e.g. runsc)")
    from harnis import sandbox as sandbox_mod

    cls = sandbox_mod.DockerSandbox
    if getattr(cls, "_gvisor_check_patched", False):
        return
    original = cls.__init__

    def __init__(self, image, *args, **kwargs):  # runtime is keyword-only in DockerSandbox
        if not kwargs.get("runtime"):
            kwargs["runtime"] = RUNTIME
        original(self, image, *args, **kwargs)
        _created.append(self.runtime or "")

    cls.__init__ = __init__
    cls._gvisor_check_patched = True


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if STRICT or RUNTIME != "runsc":
        return
    for item in items:
        reason = KNOWN_GVISOR_GAPS.get(getattr(item, "originalname", item.name))
        if reason:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=False))


def pytest_report_header(config: pytest.Config) -> str:
    return f"sandbox runtime forced to: {RUNTIME} (gvisor_pytest_plugin, strict={STRICT})"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    wrong = sorted({r or "<default>" for r in _created if r != RUNTIME})
    if wrong:
        print(f"\ngvisor_pytest_plugin: sandboxes were created with runtime(s) {wrong}, expected {RUNTIME!r}")
        session.exitstatus = 1
    elif not _created:
        print("\ngvisor_pytest_plugin: no DockerSandbox was created (were the sandbox tests skipped?)")
        session.exitstatus = 1
    else:
        print(f"\ngvisor_pytest_plugin: {len(_created)} sandbox(es) created, all with runtime {RUNTIME!r}")

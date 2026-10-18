# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Sandbox hardening, verified against a real Docker daemon.
Build the image first: `make sandbox-image`."""
import os
import sys

import pytest

from harnis.sandbox import DockerSandbox

pytestmark = pytest.mark.sandbox
IMAGE = os.getenv("SANDBOX_TEST_IMAGE", "harnis-sandbox:latest")
RUNTIME = os.getenv("SANDBOX_RUNTIME", "")  # e.g. runsc: run the suite under gVisor (docs/gvisor.md)
MODES = ["copy"] + (["bind"] if sys.platform == "linux" else [])


@pytest.fixture(scope="module", params=MODES)
def sb(request):
    try:
        import docker
        client = docker.from_env()
        client.images.get(IMAGE)
    except Exception as exc:
        pytest.skip(f"docker or image {IMAGE} unavailable: {exc}")
    return DockerSandbox(IMAGE, runtime=RUNTIME, timeout=10, memory="128m", pids_limit=64,
                         workspace_mode=request.param)


def test_runs_and_captures_output(sb, tmp_path):
    r = sb.run("echo hello", tmp_path)
    assert r.ok and "hello" in r.output


def test_no_network(sb, tmp_path):
    # Uses Python's socket module, so it doesn't depend on curl being installed.
    r = sb.run("python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)\"", tmp_path)
    assert r.exit_code != 0
    assert "unreachable" in r.output.lower() or "error" in r.output.lower()


def test_not_root(sb, tmp_path):
    r = sb.run("id -u", tmp_path)
    assert r.output.strip() != "0"


def test_root_filesystem_is_read_only(sb, tmp_path):
    r = sb.run("echo x > /etc/pwned", tmp_path)
    assert r.exit_code != 0


def test_workspace_is_writable(sb, tmp_path):
    r = sb.run("echo data > /sandbox/workspace/out.txt && cat /sandbox/workspace/out.txt", tmp_path)
    assert r.ok and (tmp_path / "out.txt").read_text().strip() == "data"


def test_timeout_kills_container(sb, tmp_path):
    r = sb.run("python3 -c 'while True: pass'", tmp_path, timeout=2)
    assert r.timed_out and r.exit_code == 124


@pytest.mark.xfail(RUNTIME == "runsc", strict=False,
                   reason="gVisor applies --pids-limit to its host cgroup, not to sandboxed processes (docs/gvisor.md)")
def test_pid_limit_stops_fork_bomb(sb, tmp_path):
    script = ("import os, sys\n"
              "n = 0\n"
              "try:\n"
              "    while True:\n"
              "        if os.fork() == 0:\n"
              "            import time; time.sleep(5); os._exit(0)\n"
              "        n += 1\n"
              "except OSError:\n"
              "    print('fork failed after', n); sys.exit(0)\n")
    (tmp_path / "bomb.py").write_text(script)
    r = sb.run("python3 /sandbox/workspace/bomb.py", tmp_path, timeout=8)
    assert "fork failed" in r.output
    assert int(r.output.split()[-1]) < 64


def test_output_is_capped(tmp_path, sb):
    small = DockerSandbox(sb.image, runtime=sb.runtime or "", timeout=10, output_limit=1000, workspace_mode=sb.mode)
    r = small.run("python3 -c \"print('x' * 50000)\"", tmp_path)
    assert "truncated" in r.output and len(r.output) < 1200


def test_no_new_privileges_and_no_caps(sb, tmp_path):
    r = sb.run("grep -E 'NoNewPrivs|CapEff' /proc/self/status", tmp_path)
    assert "NoNewPrivs:\t1" in r.output
    assert "CapEff:\t0000000000000000" in r.output


def test_tmp_is_writable_but_noexec(sb, tmp_path):
    # tmpfs mounts root-owned 0755 by default on some Docker versions, which
    # breaks HOME=/tmp for the non-root user; the harness sets mode=1777.
    r = sb.run("python3 -c \"open('/tmp/x.sh','w').write('#!/bin/sh\\necho hi\\n'); import os; os.chmod('/tmp/x.sh', 0o755)\""
               " && /tmp/x.sh", tmp_path)
    assert "Permission denied" in r.output and r.exit_code != 0
    r = sb.run("python3 -c \"open('/tmp/ok','w').write('1'); print(open('/tmp/ok').read())\"", tmp_path)
    assert r.ok and r.output.strip() == "1"


def test_existing_files_visible_and_deletions_synced(sb, tmp_path):
    (tmp_path / "keep.txt").write_text("k", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "gone.txt").write_text("g", encoding="utf-8")
    r = sb.run("cat keep.txt && rm sub/gone.txt && echo new > sub/new.txt", tmp_path)
    assert r.ok and r.output.strip() == "k"
    assert not (tmp_path / "sub" / "gone.txt").exists()
    assert (tmp_path / "sub" / "new.txt").read_text(encoding="utf-8").strip() == "new"


def test_symlink_created_in_sandbox_never_escapes_to_host(tmp_path):
    """copy mode: a link to /etc made by untrusted code is dropped on the way back."""
    try:
        import docker
        docker.from_env().images.get(IMAGE)
    except Exception as exc:
        pytest.skip(f"docker or image {IMAGE} unavailable: {exc}")
    sb = DockerSandbox(IMAGE, runtime=RUNTIME, timeout=10, workspace_mode="copy")
    r = sb.run("python3 -c \"import os; os.symlink('/etc', 'etc_link'); os.symlink('/etc/passwd', 'pw')\"",
               tmp_path)
    assert r.ok
    assert not (tmp_path / "etc_link").exists() and not (tmp_path / "pw").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="bind mode is Linux only")
def test_bind_mode_symlinks_cannot_reach_host_files(tmp_path):
    """Security review finding: in bind mode, sandboxed code writes straight into
    the host folder. A symlink it plants must not make the API read or chmod
    files outside the workspace."""
    from harnis.tools import list_workspace

    try:
        import docker
        docker.from_env().images.get(IMAGE)
    except Exception as exc:
        pytest.skip(f"docker or image {IMAGE} unavailable: {exc}")
    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP SECRET")
    secret.chmod(0o600)
    ws = tmp_path / "ws"
    ws.mkdir()
    sb = DockerSandbox(IMAGE, runtime=RUNTIME, timeout=10, workspace_mode="bind")
    # The host folder is mounted at the workspace; the link target is the host path.
    r = sb.run(f"python -c \"import os; os.symlink('{secret}', 'leak.txt')\"", ws)
    assert r.exit_code == 0, r.output
    assert not (ws / "leak.txt").is_symlink()  # removed after the run
    sb.run("echo harmless", ws)  # the permission fix-up must not follow links either
    assert secret.stat().st_mode & 0o777 == 0o600
    assert list_workspace(ws) == []

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Dependency installs: the allowlisting egress proxy, the install tool, the
reserved .harnis/deps directory, and (with Docker) the network isolation of
install runs."""
import asyncio
import io
import os
import socket
import tarfile
from pathlib import Path

import pytest

from harnis.egress_proxy import Policy, Proxy, parse_connect
from harnis.sandbox import DEPS_DIR, WorkspaceTooLarge, pack_workspace, unpack_workspace
from harnis.tools import BUILTIN_TOOLS, ToolContext, describe_action, install_command, is_reserved, list_workspace

from .conftest import FakeSandbox


# -- policy -------------------------------------------------------------------------
def test_policy_allows_only_listed_names():
    p = Policy(["pypi.org", "*.pythonhosted.org"])
    assert p.host_allowed("pypi.org") and p.host_allowed("PyPI.org.") and p.host_allowed("files.pythonhosted.org")
    for bad in ("evilpypi.org", "pypi.org.evil.com", "pythonhosted.org", "1.1.1.1", "169.254.169.254", "::1",
                "", "pypi..org", "pypi.org/x", "pypi.org@evil.com"):
        assert not p.host_allowed(bad), bad
    assert p.address_allowed("151.101.0.223")
    for private in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fd00::1"):
        assert not p.address_allowed(private), private
    assert Policy(["x"], allow_private=True).address_allowed("10.0.0.1")


def test_parse_connect():
    assert parse_connect(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: x\r\n\r\n") == ("pypi.org", 443)
    for bad in (b"GET http://pypi.org/ HTTP/1.1\r\n\r\n", b"CONNECT pypi.org HTTP/1.1\r\n\r\n",
                b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", b"\xff\xfe\r\n\r\n"):
        assert parse_connect(bad) is None


# -- proxy behaviour against local servers ---------------------------------------------
async def _echo_server():
    async def echo(r, w):
        while data := await r.read(1024):
            w.write(data)
            await w.drain()
        w.close()
    srv = await asyncio.start_server(echo, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def _through(proxy_port: int, target: str, payload: bytes = b"ping") -> tuple[str, bytes]:
    r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
    w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode()
    data = b""
    if " 200 " in status:
        w.write(payload)
        await w.drain()
        data = await asyncio.wait_for(r.read(len(payload)), 5)
    w.close()
    return status, data


def run(coro):
    return asyncio.run(coro)


def test_proxy_tunnels_allowed_names_and_refuses_private_resolution():
    async def scenario():
        echo, port = await _echo_server()
        strict = Proxy(Policy(["localhost"], ports=(port,)))
        relaxed = Proxy(Policy(["localhost"], ports=(port,), allow_private=True))
        s1 = await asyncio.start_server(strict.handle, "127.0.0.1", 0)
        s2 = await asyncio.start_server(relaxed.handle, "127.0.0.1", 0)
        p1, p2 = s1.sockets[0].getsockname()[1], s2.sockets[0].getsockname()[1]
        # "localhost" is allowlisted but resolves to loopback: refused (DNS can't point inside).
        refused = await _through(p1, f"localhost:{port}")
        allowed = await _through(p2, f"localhost:{port}", b"hello")
        wrong_port = await _through(p2, "localhost:22")
        other = await _through(p2, f"example.org:{port}")
        for s in (s1, s2, echo):
            s.close()
        return refused, allowed, wrong_port, other

    refused, allowed, wrong_port, other = run(scenario())
    assert refused[0].startswith("HTTP/1.1 403")
    assert allowed == ("HTTP/1.1 200 Connection established", b"hello")
    assert wrong_port[0].startswith("HTTP/1.1 403") and other[0].startswith("HTTP/1.1 403")


def test_proxy_chains_through_an_upstream_proxy():
    async def scenario():
        echo, port = await _echo_server()
        upstream_seen = []

        async def upstream(r, w):  # a minimal corporate proxy
            head = await r.readuntil(b"\r\n\r\n")
            upstream_seen.append(head.split(b"\r\n")[0].decode())
            ur, uw = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()

            async def pipe(a, b):
                while d := await a.read(1024):
                    b.write(d)
                    await b.drain()
                b.close()
            await asyncio.gather(pipe(r, uw), pipe(ur, w))

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        proxy = Proxy(Policy(["registry.example"], ports=(443,)),
                      upstream=f"http://127.0.0.1:{up.sockets[0].getsockname()[1]}")
        srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        result = await _through(srv.sockets[0].getsockname()[1], "registry.example:443", b"data")
        for s in (srv, up, echo):
            s.close()
        return result, upstream_seen

    (status, data), seen = run(scenario())
    assert status.endswith("200 Connection established") and data == b"data"
    assert seen == ["CONNECT registry.example:443 HTTP/1.1"]


def test_plain_http_is_refused():
    async def scenario():
        proxy = Proxy(Policy(["pypi.org"]))
        srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        r, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
        w.write(b"GET http://pypi.org/simple/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
        await w.drain()
        line = (await r.readline()).decode()
        srv.close()
        return line

    assert run(scenario()).startswith("HTTP/1.1 405")


# -- the tool ----------------------------------------------------------------------------
def install_tool():
    return next(t for t in BUILTIN_TOOLS if t.name == "install_dependencies")


def test_install_needs_approval_and_shows_the_manifest(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    t = install_tool()
    assert t.risk == "high"
    action = describe_action(tmp_path, t.name, {"manager": "pip"}, t)
    assert action["manifest"] == "requirements.txt" and "requests==2.32.3" in action["manifest_content"]
    assert action["command"] == install_command("pip", "requirements.txt")
    (tmp_path / "requirements.txt").write_text("evil-package\n")
    assert describe_action(tmp_path, t.name, {"manager": "pip"}, t) != action  # approval bound to the content


def test_install_runs_with_egress_and_validates_manifest(tmp_path):
    t = install_tool()
    sb = FakeSandbox(output="Successfully installed six")
    ctx = ToolContext(workspace=tmp_path, sandbox=sb)
    out, err = t.run(ctx, t.validate({"manager": "pip"}))
    assert err and "no such file" in out and not sb.calls
    (tmp_path / "requirements.txt").write_text("six\n")
    out, err = t.run(ctx, t.validate({"manager": "pip"}))
    assert not err and sb.egress == [True] and "--target .harnis/deps/python" in sb.calls[0]
    for bad in ({"manager": "pip", "file": "setup.cfg"}, {"manager": "npm", "file": "requirements.txt"},
                {"manager": "pip", "file": ".harnis/deps/x.txt"}, {"manager": "pip", "file": "../x.txt"}):
        out, err = t.run(ctx, t.validate(bad))
        assert err, bad
    with pytest.raises(Exception):
        t.validate({"manager": "apt"})


def test_npm_install_disables_lifecycle_scripts():
    cmd = install_command("npm", "web/package.json")
    assert "--ignore-scripts" in cmd and "web/package-lock.json" in cmd and ".harnis/deps/node" in cmd


def test_reserved_directory_is_hidden_and_not_writable(tmp_path):
    (tmp_path / "app.py").write_text("x")
    (tmp_path / DEPS_DIR / "python").mkdir(parents=True)
    (tmp_path / DEPS_DIR / "python" / "six.py").write_text("y")
    assert list_workspace(tmp_path) == ["app.py"]
    assert is_reserved(".harnis/deps/x") and is_reserved(".harnis") and not is_reserved("src/.harnis.py")
    write = next(t for t in BUILTIN_TOOLS if t.name == "write_file")
    out, err = write.run(ToolContext(workspace=tmp_path, sandbox=FakeSandbox()),
                         write.validate({"path": ".harnis/deps/python/six.py", "content": "evil"}))
    assert err and (tmp_path / DEPS_DIR / "python" / "six.py").read_text() == "y"


# -- workspace transfer with dependencies ---------------------------------------------------
def _tar(files: dict[str, tuple[bytes, int]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, (data, mode) in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_deps_have_their_own_limits_and_keep_node_modules_and_exec_bits(tmp_path):
    archive = _tar({"workspace/app.py": (b"x", 0o644),
                    f"workspace/{DEPS_DIR}/node/node_modules/left-pad/index.js": (b"y" * 100, 0o644),
                    f"workspace/{DEPS_DIR}/python/bin/tool": (b"#!/bin/sh\n", 0o755),
                    "workspace/node_modules/ignored.js": (b"z", 0o644)})
    with pytest.raises(WorkspaceTooLarge, match="installed dependencies"):
        unpack_workspace(archive, tmp_path, 1000, 10, deps_max_bytes=50, deps_max_files=10)
    unpack_workspace(archive, tmp_path, 1000, 10, deps_max_bytes=10_000, deps_max_files=10)
    assert (tmp_path / DEPS_DIR / "node/node_modules/left-pad/index.js").exists()
    assert not (tmp_path / "node_modules").exists()  # project node_modules still skipped
    if os.name != "nt":
        assert os.access(tmp_path / DEPS_DIR / "python/bin/tool", os.X_OK)
    packed = tarfile.open(fileobj=io.BytesIO(pack_workspace(tmp_path, 1000, 10, 10_000, 10)))
    names = {m.name: m for m in packed}
    assert f"workspace/{DEPS_DIR}/node/node_modules/left-pad/index.js" in names
    assert names[f"workspace/{DEPS_DIR}/python/bin/tool"].mode & 0o111
    with pytest.raises(WorkspaceTooLarge, match="the workspace"):
        pack_workspace(tmp_path, 0, 10, 10_000, 10)  # project budget is separate from deps


# -- real Docker: install runs can only reach the proxy --------------------------------------
def _docker_with_proxy_image():
    try:
        import docker
        client = docker.from_env()
        client.ping()
        out = client.containers.run("harnis-sandbox:latest", ["python", "-c",
                                    "import os; print(os.path.exists('/opt/harnis/egress_proxy.py'))"],
                                    remove=True, network_mode="none")
        return out.strip() == b"True"
    except Exception:
        return False


ATTACK = r'''
import os, socket
ph, pp = os.environ["HTTPS_PROXY"].split("//")[1].split(":")
def connect(t):
    s = socket.create_connection((ph, int(pp)), 5)
    s.sendall(f"CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n\r\n".encode())
    line = s.recv(200).split(b"\r\n")[0].decode(); s.close(); return line.split(" ")[1]
def direct(h, p):
    try:
        socket.create_connection((h, p), 3).close(); return "open"
    except OSError:
        return "blocked"
import sys
host_port = int(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect((ph, 9)); me = u.getsockname()[0]; u.close()
gateway = ".".join(me.split(".")[:3] + ["1"])  # where the Docker host would be on this network
print(connect("github.com:443"), connect("pypi.org:80"), connect("1.1.1.1:443"), connect("169.254.169.254:443"),
      direct("1.1.1.1", 443), direct("169.254.169.254", 80), direct("8.8.8.8", 53),
      direct(gateway, host_port), direct("172.17.0.1", host_port))
'''


@pytest.mark.sandbox
def test_install_runs_reach_only_the_proxy(tmp_path):
    if not _docker_with_proxy_image():
        pytest.skip("needs Docker and a sandbox image with the egress proxy (python tasks.py sandbox-image)")
    from harnis.sandbox import DockerSandbox

    (tmp_path / "attack.py").write_text(ATTACK)
    # A service on every host interface, as a developer machine or node might have.
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen()
    port = listener.getsockname()[1]
    sb = DockerSandbox("harnis-sandbox:latest",
                       egress_upstream_proxy=os.environ.get("SANDBOX_EGRESS_UPSTREAM_PROXY", ""))
    try:
        r = sb.run(f"python attack.py {port} 2>&1", tmp_path, egress=True)
    finally:
        listener.close()
    assert r.output.split() == ["403", "403", "403", "403"] + ["blocked"] * 5, r.output
    import docker
    leftover = [n.name for n in docker.from_env().networks.list() if n.name.startswith("harnis-sandbox-egress-")
                and n.name != "harnis-sandbox-egress-out"]
    assert not leftover, leftover  # per-run networks are removed
    # And normal runs have no network at all, not even the proxy.
    r = sb.run("python -c \"import socket; socket.create_connection(('harnis-egress-proxy', 3128), 3)\" 2>&1",
               tmp_path)
    assert r.exit_code != 0


@pytest.mark.sandbox
def test_install_runs_change_only_installed_packages(tmp_path):
    if not _docker_with_proxy_image():
        pytest.skip("needs Docker and a sandbox image with the egress proxy")
    from harnis.sandbox import DockerSandbox

    (tmp_path / "app.py").write_text("ORIGINAL = True\n")
    sb = DockerSandbox("harnis-sandbox:latest")
    script = ("import os; open('app.py','w').write('HIJACKED'); open('new.py','w').write('x'); "
              "os.makedirs('.harnis/deps/python', exist_ok=True); "
              "open('.harnis/deps/python/pkg.py','w').write('ok')")
    r = sb.run(f'python -c "{script}"', tmp_path, egress=True)
    assert r.exit_code == 0, r.output
    assert (tmp_path / "app.py").read_text() == "ORIGINAL = True\n" and not (tmp_path / "new.py").exists()
    assert (tmp_path / DEPS_DIR / "python" / "pkg.py").read_text() == "ok"


@pytest.mark.sandbox
def test_pip_install_then_tests_use_the_package(tmp_path):
    if not os.environ.get("HARNIS_TEST_INSTALL"):
        pytest.skip("downloads from PyPI; set HARNIS_TEST_INSTALL=1 (and SANDBOX_EGRESS_UPSTREAM_PROXY if needed)")
    if not _docker_with_proxy_image():
        pytest.skip("needs Docker and a sandbox image with the egress proxy")
    from harnis.sandbox import DockerSandbox

    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    (tmp_path / "test_app.py").write_text("import six\n\ndef test_six():\n    assert six.PY3\n")
    sb = DockerSandbox("harnis-sandbox:latest",
                       egress_upstream_proxy=os.environ.get("SANDBOX_EGRESS_UPSTREAM_PROXY", ""))
    assert sb.run("python -m pytest -q -p no:cacheprovider", tmp_path).exit_code != 0
    r = sb.run(install_command("pip", "requirements.txt"), tmp_path, egress=True)
    assert r.exit_code == 0, r.output
    assert sb.run("python -m pytest -q -p no:cacheprovider", tmp_path).exit_code == 0
    assert list_workspace(tmp_path) == ["requirements.txt", "test_app.py"]


@pytest.mark.integration
def test_install_through_the_api_needs_approval(app_pool, redis_client, tmp_path):
    import time

    from fastapi.testclient import TestClient

    from harnis.api import create_app
    from harnis.auth import mint_token
    from harnis.config import Settings
    from harnis.llm.providers import MockProvider
    from harnis.llm.router import LLMRouter
    from harnis.store import PgStore

    sb = FakeSandbox(output="Successfully installed six-1.16.0")
    app = create_app(Settings(_env_file=None, workspaces_dir=str(tmp_path / "ws"), rate_limit_capacity=100,
                              redis_url="redis://127.0.0.1:6379/15"),
                     store=PgStore(app_pool), redis=redis_client,
                     router=LLMRouter([MockProvider()], sleep=lambda s: None), sandbox=sb)
    user = {"Authorization": f"Bearer {mint_token('dev-u', 'acme', ['user'])}"}
    rev = {"Authorization": f"Bearer {mint_token('dev-r', 'acme', ['reviewer'])}"}
    with TestClient(app) as c:
        assert c.post("/v1/sessions", json={"files": {".harnis/deps/x.py": "evil"}}, headers=user).status_code == 400
        sid = c.post("/v1/sessions", json={"files": {"requirements.txt": "six==1.16.0\n"}}, headers=user).json()["session_id"]
        v = c.post(f"/v1/sessions/{sid}/turns", json={"message": "install the dependencies"}, headers=user).json()
        assert v["status"] == "awaiting_approval" and not sb.calls
        a = v["approval"]
        assert a["action"]["tool"] == "install_dependencies" and "six==1.16.0" in a["action"]["manifest_content"]
        assert c.post(f"/v1/approvals/{a['approval_id']}/decision",
                      json={"approved": True, "action_hash": a["action_hash"]}, headers=rev).status_code == 202
        for _ in range(50):
            v = c.get(f"/v1/sessions/{sid}", headers=user).json()
            if v["status"] != "awaiting_approval":
                break
            time.sleep(0.1)
        assert v["status"] == "completed" and sb.egress == [True] and "pip install" in sb.calls[0]


def test_install_approval_covers_included_requirement_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r base.txt\nsix\n")
    (tmp_path / "base.txt").write_text("requests==2.32.3\n")
    t = install_tool()
    first = describe_action(tmp_path, t.name, {"manager": "pip"}, t)
    assert first["included_files"] == ["base.txt"] and "base.txt" in first["sha256"]
    (tmp_path / "base.txt").write_text("evil==1.0\n")
    assert describe_action(tmp_path, t.name, {"manager": "pip"}, t)["sha256"] != first["sha256"]


def test_reserved_dir_is_case_insensitive_and_symlinks_are_not_listed(tmp_path):
    assert is_reserved(".Harnis/deps/x.py") and is_reserved(".HARNIS")
    (tmp_path / "real.txt").write_text("ok")
    if os.name != "nt":
        os.symlink("/etc/hostname", tmp_path / "link.txt")
        assert list_workspace(tmp_path) == ["real.txt"]
        from harnis.tools import read_regular
        assert read_regular(tmp_path / "link.txt", 1000) is None and read_regular(tmp_path / "real.txt", 10) == "ok"

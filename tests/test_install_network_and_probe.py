# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Fail-closed behaviour added in 1.1.1.

* Docker older than 28 cannot isolate an install network from the Docker host:
  installs are refused unless the operator opts in.
* The Kubernetes network probe must see both the API server and an address
  outside the cluster blocked.
"""
import os
import socket
import subprocess
import sys

import pytest

from harnis.k8s_sandbox import _PROBE_SCRIPT


# -- Docker ---------------------------------------------------------------------------
def _sandbox(allow: bool):
    docker = pytest.importorskip("docker")
    from harnis.sandbox import DockerSandbox

    created = []

    class Networks:
        def create(self, name, **kw):
            if kw.get("options"):  # Docker < 28 rejects the gateway_mode option
                raise docker.errors.APIError("invalid option: gateway_mode_ipv4")
            created.append(name)
            return object()

    class Client:
        networks = Networks()

        class containers:
            @staticmethod
            def get(name):
                raise AssertionError("must not get this far")

    sb = DockerSandbox("img", allow_host_reachable_installs=allow)
    sb._client = Client()
    return sb, created


def test_old_docker_refuses_installs_by_default():
    from harnis.sandbox import InstallNetworkUnsafe

    sb, created = _sandbox(False)
    with pytest.raises(InstallNetworkUnsafe, match="Docker 28"):
        sb._open_run_network()
    assert created == []  # nothing was created on an addressed bridge


def test_old_docker_installs_only_with_the_explicit_opt_in():
    sb, created = _sandbox(True)
    with pytest.raises(AssertionError):  # got past network creation, as intended, then hit the stub
        sb._open_run_network()
    assert len(created) == 1


# -- Kubernetes probe ---------------------------------------------------------------------
def _run_probe(env_host: str, env_port: int, external=None):
    script = _PROBE_SCRIPT
    if external:  # point the "outside the cluster" target at a local listener
        script = script.replace('("1.1.1.1", 443)', f'("127.0.0.1", {external})')
    env = {**os.environ, "KUBERNETES_SERVICE_HOST": env_host, "KUBERNETES_SERVICE_PORT": str(env_port)}
    return subprocess.run([sys.executable, "-I", "-c", script, "3", "auto"], env=env,
                          capture_output=True, text=True, timeout=30)


class _Listener:
    """A local server that accepts and drops connections (a never-accepting socket fills its backlog)."""

    def __enter__(self):
        import threading

        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self):
        while True:
            try:
                self.sock.accept()[0].close()
            except OSError:
                return

    def __exit__(self, *exc):
        self.sock.close()


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_probe_fails_when_the_api_server_is_reachable():
    with _Listener() as srv:
        r = _run_probe("127.0.0.1", srv.port, external=_closed_port())
    assert r.returncode == 3 and "still reachable" in r.stdout


def test_probe_fails_when_only_the_external_address_is_reachable():
    # The API server is blocked (closed port) but the outside address answers: not isolated.
    with _Listener() as srv:
        r = _run_probe("127.0.0.1", _closed_port(), external=srv.port)
    assert r.returncode == 3 and "still reachable" in r.stdout


def test_probe_passes_when_both_are_blocked():
    r = _run_probe("127.0.0.1", _closed_port(), external=_closed_port())
    assert r.returncode == 0, r.stdout

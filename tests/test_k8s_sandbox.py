# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""KubernetesSandbox against a fake Kubernetes API. No cluster needed.

The fake emulates the sandbox container's /sandbox directory in a temp dir:
the upload exec extracts the uploaded tar there, the command exec runs a
scripted handler that may change those files, and the download exec tars
them back, so the full copy-in / run / copy-out path is exercised.
"""
from __future__ import annotations

import io
import json
import os
import tarfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest

pytest.importorskip("kubernetes")

from kubernetes.client.exceptions import ApiException  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from harnis import k8s_sandbox  # noqa: E402
from harnis.k8s_sandbox import (SANDBOX_LABEL_KEY, KubernetesSandbox, _RUN_SCRIPT,  # noqa: E402
                                _PROBE_SCRIPT, _UPLOAD_SCRIPT, k8s_cpu, k8s_memory)
from harnis.sandbox import SANDBOX_ROOT, WORKDIR  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


@dataclass
class Outcome:
    output: bytes = b""
    exit_code: int = 0
    hang: bool = False        # stream never closes (e.g. background process holds stdout)
    takes: float = 0.0        # simulated wall time of the command
    status: dict | None = None  # raw status channel payload, overrides exit_code


def status_for(code: int) -> dict:
    if code == 0:
        return {"metadata": {}, "status": "Success"}
    return {"metadata": {}, "status": "Failure", "message": f"command terminated with non-zero exit code: {code}",
            "reason": "NonZeroExitCode", "details": {"causes": [{"reason": "ExitCode", "message": str(code)}]}}


class FakeExec:
    """WSClient look-alike (binary mode)."""

    def __init__(self, cluster: "FakeCluster", argv: list[str], stdin: bool):
        self.cluster, self.argv, self.stdin = cluster, argv, stdin
        self.channels = {1: bytearray(), 2: bytearray(), 3: bytearray()}
        self.open = True
        self.closed_by_client = False
        self.hang = False
        self.received = bytearray()
        if argv[:3] == ["sh", "-c", _UPLOAD_SCRIPT]:
            self.kind = "upload"
            self.expected = int(argv[4])
        elif argv[:2] == ["python3", "-c"]:
            self.kind = "probe"
            cluster.probe_targets.append(argv[4:])
            code, said = cluster.probe_result
            cluster.clock.advance(cluster.probe_takes)
            self._finish(said, code)
        elif argv[:2] == ["tar", "cf"]:
            self.kind = "download"
            self._finish(cluster.download_bytes(), 0)
        else:
            self.kind = "run"
            assert argv[:3] == ["sh", "-c", _RUN_SCRIPT]
            command, timeout, workdir = argv[4], int(argv[5]), argv[6]
            out = cluster.handler(command, cluster.fs / "workspace", timeout)
            cluster.clock.advance(out.takes)
            if out.hang:
                self.hang = True
                self.channels[1].extend(out.output)
            else:
                self._finish(out.output, out.exit_code, out.status)

    def _finish(self, stdout: bytes, code: int, status: dict | None = None) -> None:
        self.channels[1].extend(stdout)
        self.channels[3].extend(json.dumps(status or status_for(code)).encode())
        self.open = False

    def is_open(self) -> bool:
        return self.open

    def update(self, timeout: float = 0) -> None:
        if self.hang:
            self.cluster.clock.advance(timeout or 0.1)

    def read_channel(self, ch: int, timeout: float = 0) -> bytes:
        data = bytes(self.channels.get(ch, b""))
        if ch in self.channels:
            self.channels[ch].clear()
        return data

    def write_stdin(self, data: bytes) -> None:
        assert self.kind == "upload" and isinstance(data, bytes)
        self.received.extend(data)
        if len(self.received) >= self.expected:
            # `head -c N | tar xf - -C /sandbox`
            with tarfile.open(fileobj=io.BytesIO(bytes(self.received[: self.expected]))) as tar:
                # Trusted archive (made by pack_workspace); `filter` only exists on 3.11.4+.
                kw = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
                tar.extractall(self.cluster.fs, **kw)
            self._finish(b"", 0)

    def close_channel(self, ch: int) -> None:
        pass

    def close(self) -> None:
        self.closed_by_client = True


class FakeCore:
    """The CoreV1Api methods KubernetesSandbox uses."""

    def __init__(self, cluster: "FakeCluster"):
        self.cluster = cluster

    def create_namespaced_pod(self, namespace, body):
        self.cluster.log.append(("create", namespace, body["metadata"]["name"]))
        if self.cluster.create_error:
            raise self.cluster.create_error
        self.cluster.pods[body["metadata"]["name"]] = body

    def read_namespaced_pod(self, name, namespace):
        self.cluster.log.append(("read", namespace, name))
        statuses = self.cluster.pod_statuses
        return statuses.pop(0) if len(statuses) > 1 else statuses[0]

    def delete_namespaced_pod(self, name, namespace, grace_period_seconds=None, propagation_policy=None):
        self.cluster.log.append(("delete", namespace, name, grace_period_seconds))
        self.cluster.pods.pop(name, None)

    def list_namespaced_pod(self, namespace, label_selector=None):
        self.cluster.log.append(("list", namespace, label_selector))
        return {"items": self.cluster.listed}

    def connect_get_namespaced_pod_exec(self, *a, **kw):  # only passed to stream_fn
        raise AssertionError("must go through stream_fn")


RUNNING = {"status": {"phase": "Running", "container_statuses": [{"state": {"running": {"startedAt": "now"}}}]}}
PENDING = {"status": {"phase": "Pending", "container_statuses": [
    {"state": {"waiting": {"reason": "ContainerCreating"}}}]}}


class FakeCluster:
    def __init__(self, root: Path):
        self.fs = root / "container-sandbox"   # what /sandbox holds inside the pod
        self.fs.mkdir()
        self.clock = Clock()
        self.log: list[tuple] = []
        self.pods: dict[str, dict] = {}
        self.pod_statuses: list[dict] = [PENDING, RUNNING]
        self.create_error: Exception | None = None
        self.exec_error: Callable[[list[str]], Exception | None] = lambda argv: None
        self.handler: Callable[[str, Path, int], Outcome] = lambda cmd, ws, t: Outcome(b"ok\n")
        self.execs: list[FakeExec] = []
        self.exec_kwargs: list[dict] = []
        self.listed: list = []
        self.probe_result: tuple[int, bytes] = (0, b"")  # network blocked
        self.probe_takes = 0.5
        self.probe_targets: list[list[str]] = []
        self.core = FakeCore(self)

    def stream(self, method, name, namespace, **kw):
        self.exec_kwargs.append(kw)
        err = self.exec_error(kw["command"])
        if err is not None:
            self.log.append(("exec-error", namespace, name))
            raise err
        ex = FakeExec(self, kw["command"], kw["stdin"])
        self.log.append(("exec", namespace, name, ex.kind))
        self.execs.append(ex)
        return ex

    def download_bytes(self) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(self.fs / "workspace", arcname="workspace")
        return buf.getvalue()


@pytest.fixture
def cluster(tmp_path):
    return FakeCluster(tmp_path)


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.txt").write_text("alpha", encoding="utf-8")
    (ws / "src").mkdir()
    (ws / "src" / "b.py").write_text("print('b')\n", encoding="utf-8")
    return ws


def make_sandbox(cluster: FakeCluster, **kw) -> KubernetesSandbox:
    kw.setdefault("namespace", "sbx")
    sb = KubernetesSandbox("harnis-sandbox:1.0.0", core_api=cluster.core, stream_fn=cluster.stream,
                           sleep=cluster.clock.advance, clock=cluster.clock, **kw)
    return sb


def actions(cluster: FakeCluster) -> list:
    return [(e[0], e[3]) if e[0] == "exec" else e[0] for e in cluster.log if e[0] != "read"]


# ---------------------------------------------------------------------------
# Pod spec
# ---------------------------------------------------------------------------
def test_pod_spec_has_every_hardening_field():
    sb = KubernetesSandbox("img:1", core_api=object())
    pod = sb.build_pod_manifest("harnis-sbx-x", timeout=30)
    spec = pod["spec"]
    (c,) = spec["containers"]

    assert spec["restartPolicy"] == "Never"
    assert spec["automountServiceAccountToken"] is False
    assert spec["enableServiceLinks"] is False
    assert spec["hostNetwork"] is False and spec["hostPID"] is False and spec["hostIPC"] is False
    assert spec["activeDeadlineSeconds"] == sb.deadline_seconds(30) > 30
    assert spec["terminationGracePeriodSeconds"] == 0
    psc = spec["securityContext"]
    assert psc["runAsNonRoot"] is True and psc["runAsUser"] == 65534 and psc["runAsGroup"] == 65534
    assert psc["seccompProfile"] == {"type": "RuntimeDefault"}

    sc = c["securityContext"]
    assert sc["runAsNonRoot"] is True and sc["runAsUser"] == 65534 and sc["runAsGroup"] == 65534
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["privileged"] is False
    assert sc["capabilities"] == {"drop": ["ALL"]}
    assert sc["seccompProfile"] == {"type": "RuntimeDefault"}

    # The container only sleeps until the hard deadline; work happens over exec.
    assert c["command"] == ["sleep", str(spec["activeDeadlineSeconds"])]
    assert c["stdin"] is False and c["tty"] is False
    for kind in ("requests", "limits"):
        assert set(c["resources"][kind]) == {"cpu", "memory", "ephemeral-storage"}

    vols = {v["name"]: v for v in spec["volumes"]}
    assert vols["sandbox"]["emptyDir"]["sizeLimit"] == "256Mi"
    assert vols["tmp"]["emptyDir"] == {"medium": "Memory", "sizeLimit": "64Mi"}
    mounts = {m["mountPath"]: m["name"] for m in c["volumeMounts"]}
    assert mounts == {SANDBOX_ROOT: "sandbox", "/tmp": "tmp"}
    # No hostPath or projected service-account volumes, ever.
    assert all(set(v) == {"name", "emptyDir"} for v in spec["volumes"])
    # Optional fields stay unset by default.
    for key in ("runtimeClassName", "nodeSelector", "tolerations", "imagePullSecrets", "serviceAccountName"):
        assert key not in spec


def test_labels_namespace_runtime_class_resources_and_scheduling():
    tol = [{"key": "harnis/sandbox", "operator": "Exists", "effect": "NoSchedule"}]
    sb = KubernetesSandbox(
        "registry.example.com/harnis-sandbox:1.0.0", core_api=object(), namespace="tenant-sbx",
        runtime_class="gvisor", cpu=0.5, memory="1g", ephemeral_storage="2Gi", workspace_size_limit="1Gi",
        tmp_size_limit="32m", node_selector={"pool": "sandbox"}, tolerations=tol,
        image_pull_secrets=["regcred", ""], image_pull_policy="Always",
        labels={"team": "ml", SANDBOX_LABEL_KEY: "false"}, priority_class="sandbox-low")
    pod = sb.build_pod_manifest("p", timeout=10)
    meta, spec = pod["metadata"], pod["spec"]
    (c,) = spec["containers"]

    assert meta["namespace"] == "tenant-sbx"
    assert meta["labels"]["team"] == "ml"
    # User labels can't switch off the label the deny-all NetworkPolicy selects on.
    assert meta["labels"][SANDBOX_LABEL_KEY] == "true"
    assert meta["labels"]["app.kubernetes.io/component"] == "sandbox"
    assert spec["runtimeClassName"] == "gvisor"
    assert spec["nodeSelector"] == {"pool": "sandbox"}
    assert spec["tolerations"] == tol
    assert spec["imagePullSecrets"] == [{"name": "regcred"}]
    assert spec["priorityClassName"] == "sandbox-low"
    assert c["image"] == "registry.example.com/harnis-sandbox:1.0.0"
    assert c["imagePullPolicy"] == "Always"
    assert c["resources"]["limits"] == {"cpu": "500m", "memory": "1Gi", "ephemeral-storage": "2Gi"}
    assert c["resources"]["requests"] == {"cpu": "500m", "memory": "1Gi", "ephemeral-storage": "2Gi"}
    assert {v["name"]: v["emptyDir"].get("sizeLimit") for v in spec["volumes"]} == {"sandbox": "1Gi",
                                                                                    "tmp": "32Mi"}


def test_quantity_conversion():
    # Docker-style sizes from SANDBOX_MEMORY must not become Kubernetes millibytes.
    assert k8s_memory("512m") == "512Mi"
    assert k8s_memory("2g") == "2Gi"
    assert k8s_memory("64mb") == "64Mi"
    assert k8s_memory("512Mi") == "512Mi"
    assert k8s_memory("1G") == "1G"
    assert k8s_memory(1048576) == "1048576"
    assert k8s_cpu(1.0) == "1000m" and k8s_cpu(0.25) == "250m" and k8s_cpu("2") == "2"


def test_invalid_pull_policy_rejected():
    with pytest.raises(ValueError):
        KubernetesSandbox("img", image_pull_policy="Sometimes")


# ---------------------------------------------------------------------------
# run(): upload / exec / download
# ---------------------------------------------------------------------------
def test_run_uploads_execs_downloads_and_deletes(cluster, workspace):
    def handler(command, ws: Path, timeout):
        # The uploaded workspace is visible at /sandbox/workspace...
        assert (ws / "a.txt").read_text() == "alpha"
        assert (ws / "src" / "b.py").exists()
        # ...and the command's changes come back.
        (ws / "a.txt").unlink()
        (ws / "new.txt").write_text("created", encoding="utf-8")
        return Outcome(b"line1\nline2\n", 0)

    cluster.handler = handler
    sb = make_sandbox(cluster)
    res = sb.run("pytest -q && echo 'it worked'", workspace, timeout=20)

    assert res.ok, res
    assert res.exit_code == 0 and not res.timed_out and res.error is None
    assert res.output == "line1\nline2\n"
    assert not (workspace / "a.txt").exists()
    assert (workspace / "new.txt").read_text() == "created"
    assert (workspace / "src" / "b.py").exists()

    assert actions(cluster) == ["create", ("exec", "probe"), ("exec", "upload"), ("exec", "run"),
                                ("exec", "download"), "delete"]
    name = cluster.log[0][2]
    assert name.startswith("harnis-sbx-")
    assert all(e[1] == "sbx" for e in cluster.log)
    assert cluster.log[-1] == ("delete", "sbx", name, 0)
    assert all(ex.closed_by_client for ex in cluster.execs)

    probe, up, run, down = (kw["command"] for kw in cluster.exec_kwargs)
    assert probe[:3] == ["python3", "-c", _PROBE_SCRIPT] and probe[4:] == ["auto"]
    assert up[:4] == ["sh", "-c", _UPLOAD_SCRIPT, "sh"] and up[5] == SANDBOX_ROOT
    # The command is its own argv element, never spliced into a script.
    assert run == ["sh", "-c", _RUN_SCRIPT, "sh", "pytest -q && echo 'it worked'", "20", WORKDIR]
    assert down == ["tar", "cf", "-", "-C", SANDBOX_ROOT, "workspace"]
    for kw in cluster.exec_kwargs:
        assert kw["container"] == "sandbox" and kw["tty"] is False
        assert kw["binary"] is True and kw["_preload_content"] is False
    assert [kw["stdin"] for kw in cluster.exec_kwargs] == [False, True, False, False]
    # The pod was created with the per-run timeout baked into its deadline.
    assert name not in cluster.pods


def test_nonzero_exit_code_is_reported(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(b"1 failed\n", 3)
    res = make_sandbox(cluster).run("pytest", workspace)
    assert res.exit_code == 3 and not res.timed_out and res.error is None and not res.ok
    assert res.output == "1 failed\n"


def test_command_exiting_124_quickly_is_not_a_timeout(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(b"", 124, takes=0.1)
    res = make_sandbox(cluster).run("exit 124", workspace, timeout=10)
    assert res.exit_code == 124 and res.timed_out is False


def test_pod_deleted_even_when_exec_raises(cluster, workspace):
    def fail_run(argv):
        return ApiException(status=500, reason="Internal Server Error") if argv[2] == _RUN_SCRIPT else None

    cluster.exec_error = fail_run
    res = make_sandbox(cluster).run("ls", workspace)
    assert res.error is not None and "ApiException" in res.error and "HTTP 500" in res.error
    assert res.exit_code == -1 and not res.ok
    assert cluster.log[-1][0] == "delete" and cluster.log[-1][3] == 0
    assert not cluster.pods
    # Host workspace untouched.
    assert (workspace / "a.txt").read_text() == "alpha"


def test_pod_deleted_when_upload_fails(cluster, workspace):
    cluster.exec_error = lambda argv: RuntimeError("websocket handshake failed") if argv[2] == _UPLOAD_SCRIPT else None
    res = make_sandbox(cluster).run("ls", workspace)
    assert res.error and "websocket handshake failed" in res.error
    assert cluster.log[-1][0] == "delete"


def test_timeout_inside_container_gives_124(cluster, workspace):
    # coreutils `timeout` fired: exit 124 after `timeout` seconds.
    cluster.handler = lambda cmd, ws, t: Outcome(b"partial\n", 124, takes=t + 0.01)
    res = make_sandbox(cluster).run("sleep 999", workspace, timeout=5)
    assert res.exit_code == 124 and res.timed_out is True and res.error is None
    assert res.output.startswith("partial\n")
    assert res.output.endswith("[killed after 5s timeout]")
    assert actions(cluster)[-2:] == [("exec", "download"), "delete"]  # changes still applied


def test_timeout_after_kill_signal_gives_124(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(b"", 137, takes=t + 2)  # TERM ignored, KILL at +2s
    res = make_sandbox(cluster).run("trap '' TERM; sleep 999", workspace, timeout=5)
    assert res.exit_code == 124 and res.timed_out is True


def test_client_side_deadline_when_stream_never_closes(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(b"started\n", hang=True)
    start = cluster.clock()
    res = make_sandbox(cluster).run("sleep 999 &", workspace, timeout=3)
    assert res.exit_code == 124 and res.timed_out is True and res.error is None
    assert "started" in res.output and "[killed after 3s timeout]" in res.output
    assert cluster.clock() - start >= 3
    assert cluster.log[-1][0] == "delete"


def test_output_is_capped(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(b"x" * 1000, 0)
    res = make_sandbox(cluster, output_limit=100).run("yes", workspace)
    assert res.output.startswith("x" * 100)
    assert res.output[100:] == "\n... [truncated 900 bytes]"


def test_output_decoding_is_lossless_for_text_and_tolerant_for_binary(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome("héllo\n".encode() + b"\xff", 0)
    res = make_sandbox(cluster).run("cat", workspace)
    assert res.output.startswith("héllo\n") and res.output.endswith("\ufffd")


# ---------------------------------------------------------------------------
# Errors become SandboxResult.error, never exceptions
# ---------------------------------------------------------------------------
def test_create_error_becomes_result_error(cluster, workspace):
    cluster.create_error = ApiException(status=403, reason="Forbidden")
    res = make_sandbox(cluster).run("ls", workspace)
    assert res.error == "sandbox error: ApiException: HTTP 403 Forbidden"
    assert res.exit_code == -1
    assert not any(e[0] == "exec" for e in cluster.log)


def test_image_pull_failure_fails_fast(cluster, workspace):
    cluster.pod_statuses = [{"status": {"phase": "Pending", "container_statuses": [
        {"state": {"waiting": {"reason": "ImagePullBackOff"}}}]}}]
    res = make_sandbox(cluster).run("ls", workspace)
    assert res.error and "ImagePullBackOff" in res.error
    assert cluster.log[-1][0] == "delete"


def test_pod_that_never_starts_times_out(cluster, workspace):
    cluster.pod_statuses = [PENDING]
    res = make_sandbox(cluster, pod_start_timeout=5).run("ls", workspace)
    assert res.error and "TimeoutError" in res.error and "did not start within 5s" in res.error
    assert cluster.log[-1][0] == "delete"


def test_exec_that_cannot_start_is_an_error(cluster, workspace):
    cluster.handler = lambda cmd, ws, t: Outcome(status={"status": "Failure", "reason": "InternalError",
                                                          "message": "executable file not found"})
    res = make_sandbox(cluster).run("ls", workspace)
    assert res.error and "executable file not found" in res.error


def test_oversized_workspace_never_creates_a_pod(cluster, workspace):
    (workspace / "big.bin").write_bytes(b"x" * 5000)
    res = make_sandbox(cluster, max_workspace_bytes=1000).run("ls", workspace)
    assert res.error and "WorkspaceTooLarge" in res.error
    assert cluster.log == []


def test_too_many_output_files_is_an_error(cluster, workspace):
    def handler(cmd, ws, t):
        for i in range(10):
            (ws / f"f{i}.txt").write_text("x")
        return Outcome(b"", 0)

    cluster.handler = handler
    res = make_sandbox(cluster, max_workspace_files=5).run("touch", workspace)
    assert res.error and "WorkspaceTooLarge" in res.error
    assert cluster.log[-1][0] == "delete"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need Developer Mode on Windows")
def test_downloaded_archive_is_validated(cluster, workspace, tmp_path):
    outside = tmp_path / "outside.txt"

    def handler(cmd, ws, t):
        (ws / "link").symlink_to("/etc/passwd")
        return Outcome(b"", 0)

    cluster.handler = handler
    res = make_sandbox(cluster).run("ln -s /etc/passwd link", workspace)
    assert res.ok, res
    assert not (workspace / "link").exists() and not (workspace / "link").is_symlink()
    assert not outside.exists()
    assert (workspace / "a.txt").read_text() == "alpha"


# ---------------------------------------------------------------------------
# Tracing: same span name as DockerSandbox, no command contents
# ---------------------------------------------------------------------------
def test_span_records_argv0_only(cluster, workspace, monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(k8s_sandbox, "tracer", provider.get_tracer("test"))

    make_sandbox(cluster, runtime_class="gvisor").run("curl -H 'Authorization: Bearer s3cr3t' x", workspace)
    (span,) = exporter.get_finished_spans()
    assert span.name == "harnis.sandbox.run"
    attrs = dict(span.attributes)
    assert attrs["harnis.sandbox.argv0"] == "curl"
    assert attrs["harnis.sandbox.backend"] == "kubernetes"
    assert attrs["harnis.sandbox.k8s.namespace"] == "sbx"
    assert attrs["harnis.sandbox.k8s.runtime_class"] == "gvisor"
    assert attrs["harnis.sandbox.exit_code"] == 0
    assert all("s3cr3t" not in str(v) for v in attrs.values())


# ---------------------------------------------------------------------------
# Kube config loading and housekeeping
# ---------------------------------------------------------------------------
def test_in_cluster_config_falls_back_to_kubeconfig(monkeypatch):
    from kubernetes import config
    from kubernetes.config.config_exception import ConfigException

    calls = []

    def incluster(**kw):
        calls.append("incluster")
        raise ConfigException("not in a cluster")

    def kubeconfig(config_file=None, context=None, client_configuration=None):
        calls.append(("kubeconfig", config_file, context))
        client_configuration.host = "https://example.invalid:6443"

    monkeypatch.setattr(config, "load_incluster_config", incluster)
    monkeypatch.setattr(config, "load_kube_config", kubeconfig)
    sb = KubernetesSandbox("img", kubeconfig="/tmp/kc", context="dev")
    core = sb.core
    assert calls == ["incluster", ("kubeconfig", "/tmp/kc", "dev")]
    assert core.api_client.configuration.host == "https://example.invalid:6443"


def test_in_cluster_config_is_preferred(monkeypatch):
    from kubernetes import config

    calls = []
    monkeypatch.setattr(config, "load_incluster_config",
                        lambda client_configuration=None: calls.append("incluster"))
    monkeypatch.setattr(config, "load_kube_config", lambda **kw: calls.append("kubeconfig"))
    _ = KubernetesSandbox("img").core
    assert calls == ["incluster"]


def test_reap_deletes_only_old_pods(cluster):
    now = datetime.now(timezone.utc)
    cluster.listed = [
        {"metadata": {"name": "harnis-sbx-old", "creation_timestamp": now - timedelta(hours=2)}},
        {"metadata": {"name": "harnis-sbx-new", "creation_timestamp": now - timedelta(seconds=30)}},
    ]
    removed = make_sandbox(cluster).reap(older_than_seconds=900)
    assert removed == ["harnis-sbx-old"]
    assert ("list", "sbx", "harnis/sandbox=true") in cluster.log
    assert ("delete", "sbx", "harnis-sbx-old", 0) in cluster.log
    assert not any(e[0] == "delete" and e[2] == "harnis-sbx-new" for e in cluster.log)


def test_real_time_defaults_are_used_without_injection():
    sb = KubernetesSandbox("img", core_api=object())
    assert sb._clock is time.monotonic and sb._sleep is time.sleep


def test_api_uses_kubernetes_backend_when_configured(tmp_path):
    import fakeredis

    from harnis.api import create_app
    from harnis.config import Settings
    from harnis.k8s_sandbox import KubernetesSandbox
    from harnis.llm.providers import MockProvider
    from harnis.llm.router import LLMRouter

    s = Settings(_env_file=None, sandbox_backend="kubernetes", sandbox_k8s_namespace="sbx",
                 sandbox_k8s_image_pull_secrets="a, b", workspaces_dir=str(tmp_path))
    app = create_app(s, store=object(), redis=fakeredis.FakeRedis(), router=LLMRouter([MockProvider()]))
    sb = app.state.orch.d.sandbox
    assert isinstance(sb, KubernetesSandbox) and sb.namespace == "sbx"


def test_install_pods_get_the_egress_label_and_proxy_only_when_asked():
    from harnis.k8s_sandbox import EGRESS_LABEL_KEY, KubernetesSandbox

    sb = KubernetesSandbox("img", core_api=object(), egress_proxy_url="http://proxy.ns.svc:3128",
                           labels={EGRESS_LABEL_KEY: "registry", "team": "a"}, install_timeout=300)
    normal = sb.build_pod_manifest("p1")
    assert EGRESS_LABEL_KEY not in normal["metadata"]["labels"]  # can't be smuggled in via config labels
    env = {e["name"]: e["value"] for e in normal["spec"]["containers"][0]["env"]}
    assert "HTTPS_PROXY" not in env and env["PYTHONPATH"].endswith(".harnis/deps/python")
    install = sb.build_pod_manifest("p2", egress=True)
    assert install["metadata"]["labels"][EGRESS_LABEL_KEY] == "registry"
    env = {e["name"]: e["value"] for e in install["spec"]["containers"][0]["env"]}
    assert env["HTTPS_PROXY"] == "http://proxy.ns.svc:3128"
    assert install["spec"]["activeDeadlineSeconds"] > normal["spec"]["activeDeadlineSeconds"]


def test_install_refused_without_proxy(tmp_path):
    from harnis.k8s_sandbox import KubernetesSandbox

    r = KubernetesSandbox("img", core_api=object()).run("pip install x", tmp_path, egress=True)
    assert r.error and "not configured" in r.error


def test_install_pods_get_the_proxy_as_an_ip_address():
    from harnis.k8s_sandbox import KubernetesSandbox

    sb = KubernetesSandbox("img", core_api=object(), egress_proxy_url="http://localhost:3128")
    assert sb._resolved_proxy_url() == "http://127.0.0.1:3128"
    m = sb.build_pod_manifest("p", egress=True, proxy_url="http://10.0.0.5:3128")
    env = {e["name"]: e["value"] for e in m["spec"]["containers"][0]["env"]}
    assert env["HTTPS_PROXY"] == "http://10.0.0.5:3128"


# ---------------------------------------------------------------------------
# Network isolation probe (fail closed)
# ---------------------------------------------------------------------------
def test_command_is_not_run_while_the_pod_can_reach_the_network(cluster, workspace):
    ran = []
    cluster.handler = lambda cmd, ws, t: ran.append(cmd) or Outcome(b"ok\n")
    cluster.probe_result = (3, b"still reachable: 10.96.0.1:443")
    res = make_sandbox(cluster).run("curl evil.example", workspace)

    assert not res.ok and res.exit_code == -1
    assert "NetworkNotIsolated" in res.error and "10.96.0.1:443" in res.error
    assert ran == []                                   # the command never ran
    assert ("exec", "upload") not in actions(cluster)  # nor did the workspace go in
    assert actions(cluster)[-1] == "delete"


def test_probe_that_never_answers_fails_closed(cluster, workspace):
    sb = make_sandbox(cluster, network_probe_timeout=2)
    orig = FakeExec._finish

    def never_finish(self, stdout, code, status=None):
        if self.kind == "probe":
            self.hang = True
            return
        orig(self, stdout, code, status)

    FakeExec._finish = never_finish
    try:
        res = sb.run("echo hi", workspace)
    finally:
        FakeExec._finish = orig
    assert res.error and "NetworkNotIsolated" in res.error


def test_probe_targets_are_configurable_and_can_be_turned_off(cluster, workspace):
    make_sandbox(cluster, network_probe="10.0.0.1:443, [fd00::1]:6443").run("true", workspace)
    assert cluster.probe_targets == [["10.0.0.1:443", "[fd00::1]:6443"]]

    cluster.log.clear()
    make_sandbox(cluster, network_probe="off").run("true", workspace)
    assert ("exec", "probe") not in actions(cluster)

    with pytest.raises(ValueError):
        make_sandbox(cluster, network_probe="10.0.0.1; rm -rf /")
    with pytest.raises(ValueError):
        make_sandbox(cluster, network_probe="auto,off")


def test_install_pods_are_probed_too(cluster, workspace):
    sb = make_sandbox(cluster, egress_proxy_url="http://10.0.0.9:3128")
    cluster.probe_result = (3, b"still reachable: 10.96.0.1:443")
    res = sb.run("pip install x", workspace, egress=True)
    assert res.error and "NetworkNotIsolated" in res.error

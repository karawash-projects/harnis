# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Run untrusted commands in a short-lived, locked-down Kubernetes Pod.

Drop-in replacement for `DockerSandbox` (same `run()` signature, same
`SandboxResult`, same workspace semantics as Docker *copy* mode) for clusters
where the API must not hold a Docker socket.

Flow of one `run()`:

  1. pack the host workspace into a tar (`workspace/...`), enforcing size limits;
  2. create a Pod whose only container just sleeps until a hard deadline;
  3. wait until the Pod is Running;
  4. upload the tar through an exec stream (`tar xf - -C /sandbox`, like
     `kubectl cp`), so the workspace lands in /sandbox/workspace;
  5. exec the command in /sandbox/workspace under `timeout`, with a second,
     client-side deadline, capturing combined stdout+stderr up to a cap and the
     exit code from the exec status channel;
  6. download /sandbox/workspace (`tar cf - -C /sandbox workspace`) and apply it
     to the host through `unpack_workspace`, which validates every member;
  7. always delete the Pod (grace period 0).

Hardening applied to every Pod:
  runAsNonRoot as 65534:65534, read-only root filesystem, no privilege
  escalation, all capabilities dropped, RuntimeDefault seccomp, no service
  account token, no service links, no host namespaces, CPU / memory /
  ephemeral-storage requests and limits, size-limited emptyDir volumes for
  /sandbox and /tmp (memory-backed), activeDeadlineSeconds as a backstop,
  restartPolicy Never, optional RuntimeClass (gVisor / Kata), node selector
  and tolerations to pin sandboxes to dedicated nodes.

What the Pod spec cannot do (see docs/kubernetes.md):
  * There is no per-container PID limit in the Pod API. Set the kubelet's
    `podPidsLimit` on the nodes that run sandboxes.
  * Network isolation comes from the NetworkPolicy the Helm chart installs for
    the `harnis/sandbox: "true"` label. It only works with a CNI that enforces
    NetworkPolicy (Calico, Cilium, ...).
  * emptyDir volumes cannot be mounted noexec, unlike the Docker tmpfs.
  * runc shares the node kernel; use a gVisor or Kata RuntimeClass for
    untrusted code.

The `kubernetes` package is an optional dependency (`pip install harnis[k8s]`)
and is imported lazily.

The image needs `sh`, `sleep`, `tar`, `head` and `timeout` (coreutils). The
default sandbox image (python:3.12-slim based) has them.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from opentelemetry import trace

from .sandbox import (SANDBOX_ROOT, SANDBOX_UID, WORKDIR, SandboxResult, WorkspaceTooLarge,
                      pack_workspace, unpack_workspace, DEPS_ENV,
                      _record_metrics)

log = logging.getLogger(__name__)
tracer = trace.get_tracer("harnis.sandbox")

# Every sandbox Pod carries this label. The Helm chart's deny-all
# NetworkPolicy and the RBAC-scoped reaper select on it, so it is not
# configurable and user-supplied labels cannot override it.
SANDBOX_LABEL_KEY = "harnis/sandbox"
SANDBOX_LABEL_VALUE = "true"
EGRESS_LABEL_KEY, EGRESS_LABEL_VALUE = "harnis/egress", "registry"
BASE_LABELS = {
    "app.kubernetes.io/name": "harnis-sandbox",
    "app.kubernetes.io/component": "sandbox",
    "app.kubernetes.io/managed-by": "harnis",
    SANDBOX_LABEL_KEY: SANDBOX_LABEL_VALUE,
}
CONTAINER_NAME = "sandbox"
POD_NAME_PREFIX = "harnis-sbx-"

# Exec stream channels (kubernetes.stream.ws_client).
STDOUT, STDERR, ERROR = 1, 2, 3
STDIN_CHUNK = 64 * 1024

# Container waiting reasons that will never resolve by themselves: fail fast
# instead of waiting for pod_start_timeout.
FATAL_WAITING_REASONS = {
    "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull",
    "CreateContainerConfigError", "CreateContainerError", "RunContainerError",
}

# The command runs as `sh -c "$1"` inside /sandbox/workspace (the same as
# DockerSandbox's `sh -c command` with working_dir), under `timeout` which
# sends TERM to the whole process group at the deadline and KILL two seconds
# later. stderr is folded into stdout so the output keeps its interleaving,
# like `docker logs`. The command string is passed as a separate argv element,
# never spliced into a script, so no quoting is involved.
_RUN_SCRIPT = 'cd "$3" || exit 125; exec timeout -k 2 "$2" sh -c "$1" 2>&1'
# Upload: read exactly N bytes of stdin and extract them. Counting bytes with
# `head -c` gives tar a clean EOF on every exec protocol version (v4 has no
# way to half-close stdin).
_UPLOAD_SCRIPT = 'head -c "$1" | tar xf - -C "$2"'

# Network-isolation probe, run in the Pod before the workspace is copied in
# or the command runs. Some CNIs (kind's kindnetd, for one) apply a new Pod's
# NetworkPolicies a moment after the Pod is Running, so its first connections
# can get out. The probe connects to targets that the sandbox policies block
# (by default the API server's ClusterIP, which every Pod can resolve from its
# environment) and returns only once two attempts in a row are refused or time
# out. Exit 0: isolated; 3: still reachable at the deadline; 4: misconfigured.
_PROBE_SCRIPT = r"""
import os, socket, sys, time
def targets():
    out = []
    for t in sys.argv[2:]:
        if t == "auto":
            host = os.environ.get("KUBERNETES_SERVICE_HOST")
            if not host:
                print("KUBERNETES_SERVICE_HOST is not set; set SANDBOX_K8S_NETWORK_PROBE to host:port")
                sys.exit(4)
            out.append((host, int(os.environ.get("KUBERNETES_SERVICE_PORT", "443"))))
        else:
            host, _, port = t.rpartition(":")
            out.append((host.strip("[]"), int(port)))
    return out
ts = targets()
end = time.monotonic() + float(sys.argv[1])
blocked, reachable = 0, None
while time.monotonic() < end:
    reachable = None
    for host, port in ts:
        try:
            socket.create_connection((host, port), 0.5).close()
            reachable = "%s:%d" % (host, port)
            break
        except OSError:
            pass
    if reachable is None:
        blocked += 1
        if blocked >= 2:
            sys.exit(0)
    else:
        blocked = 0
        time.sleep(0.2)
print("still reachable: %s" % reachable)
sys.exit(3)
"""


class NetworkNotIsolated(RuntimeError):
    """The sandbox Pod could still reach the network: the command is not run."""


_DOCKER_MEMORY = re.compile(r"^(\d+(?:\.\d+)?)\s*([kmgt])b?$")


def k8s_memory(value: str | int) -> str:
    """Return a Kubernetes memory quantity.

    Docker-style sizes ("512m", "1g", "64mb") are converted to binary units
    ("512Mi", "1Gi"): in Kubernetes a lowercase "m" means *milli*, so "512m"
    would request half a byte. Kubernetes quantities ("512Mi", "1G", "1e9")
    and plain byte counts pass through unchanged."""
    s = str(value).strip()
    m = _DOCKER_MEMORY.match(s)
    if m:
        return f"{m.group(1)}{m.group(2).upper()}i"
    return s


def k8s_cpu(value: str | float | int) -> str:
    """Return a Kubernetes CPU quantity: 1.5 -> "1500m"; strings pass through."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{max(1, int(round(float(value) * 1000)))}m"
    return str(value).strip()


class _ExecError(Exception):
    """An exec stream finished without an exit status we can use."""


class KubernetesSandbox:
    """One short-lived, hardened Pod per `run()`. Thread-safe: no per-run
    state is kept on the instance, and every exec stream gets its own API
    client (the kubernetes client's `stream()` temporarily patches the client
    it is given, so sharing one across threads is unsafe)."""

    def __init__(self, image: str, *, namespace: str = "harnis-sandbox", runtime_class: str = "",
                 cpu: str | float = "1", memory: str = "512Mi", ephemeral_storage: str = "512Mi",
                 cpu_request: str | float | None = None, memory_request: str | None = None,
                 workspace_size_limit: str = "256Mi", tmp_size_limit: str = "64Mi",
                 timeout: int = 30, output_limit: int = 64_000,
                 max_workspace_bytes: int = 50_000_000, max_workspace_files: int = 2_000,
                 deps_max_bytes: int = 300_000_000, deps_max_files: int = 60_000,
                 install_timeout: int = 300, egress_proxy_url: str = "",
                 network_probe: str | list[str] = "auto", network_probe_timeout: float = 20,
                 node_selector: dict[str, str] | None = None,
                 tolerations: list[dict[str, Any]] | None = None,
                 image_pull_secrets: list[str] | None = None, image_pull_policy: str = "IfNotPresent",
                 labels: dict[str, str] | None = None, annotations: dict[str, str] | None = None,
                 priority_class: str = "", pod_start_timeout: int = 60, transfer_timeout: int = 60,
                 kubeconfig: str | None = None, context: str | None = None,
                 core_api: Any = None, stream_fn: Callable[..., Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        if image_pull_policy not in ("Always", "IfNotPresent", "Never"):
            raise ValueError("image_pull_policy must be Always, IfNotPresent or Never")
        self.image = image
        self.namespace = namespace
        self.runtime_class = runtime_class or None
        self.cpu = k8s_cpu(cpu)
        self.memory = k8s_memory(memory)
        self.cpu_request = k8s_cpu(cpu_request) if cpu_request is not None else self.cpu
        self.memory_request = k8s_memory(memory_request) if memory_request is not None else self.memory
        self.ephemeral_storage = k8s_memory(ephemeral_storage)
        self.workspace_size_limit = k8s_memory(workspace_size_limit)
        self.tmp_size_limit = k8s_memory(tmp_size_limit)
        self.timeout = timeout
        self.output_limit = output_limit
        self.max_bytes = max_workspace_bytes
        self.max_files = max_workspace_files
        self.deps_max_bytes = deps_max_bytes
        self.deps_max_files = deps_max_files
        self.install_timeout = install_timeout
        self.egress_proxy_url = egress_proxy_url
        targets = network_probe.split(",") if isinstance(network_probe, str) else list(network_probe)
        targets = [t.strip() for t in targets if t and t.strip()]
        if any(t.lower() == "off" for t in targets):
            if len(targets) > 1:  # "auto,off" is a typo, not a decision to turn the check off
                raise ValueError("network probe 'off' cannot be combined with targets")
            targets = []  # the operator's CNI enforces policy before Pods start
        for t in targets:
            if t != "auto" and not re.fullmatch(r"\[?[\w.:-]+\]?:\d{1,5}", t):
                raise ValueError(f"network probe target must be 'auto', 'off' or host:port, got {t!r}")
        self.network_probe = targets
        self.network_probe_timeout = float(network_probe_timeout)
        self.node_selector = dict(node_selector or {})
        self.tolerations = list(tolerations or [])
        self.image_pull_secrets = [s for s in (image_pull_secrets or []) if s]
        self.image_pull_policy = image_pull_policy
        # User labels first, so they can never override the base labels the
        # NetworkPolicy depends on.
        # The egress label opens the install NetworkPolicy, so only run(egress=True) sets it.
        self.labels = {**{k: v for k, v in (labels or {}).items() if k != EGRESS_LABEL_KEY}, **BASE_LABELS}
        self.annotations = dict(annotations or {})
        self.priority_class = priority_class or None
        self.pod_start_timeout = pod_start_timeout
        self.transfer_timeout = transfer_timeout
        self.kubeconfig = kubeconfig
        self.context = context
        self._core = core_api
        self._stream_fn = stream_fn
        self._configuration = None
        self._sleep = sleep
        self._clock = clock
        # Extra seconds the client waits past `timeout` for the exec stream
        # to close (the in-container `timeout` sends KILL at +2s).
        self.client_grace = 5.0

    # ------------------------------------------------------------------
    # Kubernetes client (lazy, optional dependency)
    # ------------------------------------------------------------------
    def _load_configuration(self):
        if self._configuration is None:
            from kubernetes import client, config
            from kubernetes.config.config_exception import ConfigException

            cfg = client.Configuration()
            try:
                # In a Pod: the projected service account token + cluster CA.
                config.load_incluster_config(client_configuration=cfg)
            except ConfigException:
                # Outside the cluster: $KUBECONFIG or ~/.kube/config.
                config.load_kube_config(config_file=self.kubeconfig, context=self.context,
                                        client_configuration=cfg)
            self._configuration = cfg
        return self._configuration

    @property
    def core(self):
        if self._core is None:
            from kubernetes import client

            self._core = client.CoreV1Api(client.ApiClient(self._load_configuration()))
        return self._core

    def _open_exec(self, pod: str, argv: list[str], *, stdin: bool) -> Any:
        """Open an exec stream into the sandbox container (binary channels).
        Returns a WSClient-like object: is_open/update/read_channel/write_stdin/close."""
        if self._stream_fn is not None:
            stream_fn, api = self._stream_fn, self.core
        else:
            from kubernetes import client
            from kubernetes.stream import stream as stream_fn

            api = client.CoreV1Api(client.ApiClient(self._load_configuration()))
        return stream_fn(api.connect_get_namespaced_pod_exec, pod, self.namespace,
                         container=CONTAINER_NAME, command=argv, stdin=stdin, stdout=True,
                         stderr=True, tty=False, _preload_content=False, binary=True)

    # ------------------------------------------------------------------
    # Pod spec
    # ------------------------------------------------------------------
    def deadline_seconds(self, timeout: int) -> int:
        """Hard lifetime of a Pod: start + upload + command + download, plus
        slack. Enforced twice: by `sleep` in the container and by the
        kubelet through activeDeadlineSeconds."""
        return int(self.pod_start_timeout + 2 * self.transfer_timeout + timeout + 30)

    def _resolved_proxy_url(self) -> str:
        """The proxy URL with its host resolved here, by the API: install Pods
        get no DNS access (it could be used to tunnel data out)."""
        import socket
        from urllib.parse import urlsplit, urlunsplit
        u = urlsplit(self.egress_proxy_url)
        try:
            ip = socket.gethostbyname(u.hostname or "")
        except OSError:
            return self.egress_proxy_url
        return urlunsplit((u.scheme, f"{ip}:{u.port or 3128}", u.path, "", ""))

    def build_pod_manifest(self, name: str, timeout: int | None = None, *, egress: bool = False,
                           proxy_url: str = "") -> dict[str, Any]:
        timeout = timeout or (self.install_timeout if egress else self.timeout)
        deadline = self.deadline_seconds(timeout)
        container_sc = {
            "runAsNonRoot": True,
            "runAsUser": SANDBOX_UID,
            "runAsGroup": SANDBOX_UID,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False,
            "privileged": False,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        container = {
            "name": CONTAINER_NAME,
            "image": self.image,
            "imagePullPolicy": self.image_pull_policy,
            # The container only keeps the Pod alive; work happens via exec.
            "command": ["sleep", str(deadline)],
            # The emptyDir root is world-writable; /sandbox/workspace is
            # created by the upload so it is owned by the sandbox user.
            "workingDir": SANDBOX_ROOT,
            "env": [{"name": "HOME", "value": "/tmp"},
                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                    *({"name": k, "value": v} for k, v in DEPS_ENV.items()),
                    *({"name": k, "value": proxy_url or self.egress_proxy_url}
                      for k in (("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                                 "npm_config_https_proxy", "npm_config_proxy") if egress else ()))],
            "securityContext": container_sc,
            "resources": {
                "requests": {"cpu": self.cpu_request, "memory": self.memory_request,
                             "ephemeral-storage": self.ephemeral_storage},
                "limits": {"cpu": self.cpu, "memory": self.memory,
                           "ephemeral-storage": self.ephemeral_storage},
            },
            "volumeMounts": [{"name": "sandbox", "mountPath": SANDBOX_ROOT},
                             {"name": "tmp", "mountPath": "/tmp"}],
            "stdin": False,
            "tty": False,
            "terminationMessagePolicy": "File",
        }
        spec: dict[str, Any] = {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": deadline,
            "terminationGracePeriodSeconds": 0,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "hostNetwork": False,
            "hostPID": False,
            "hostIPC": False,
            "shareProcessNamespace": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": SANDBOX_UID,
                "runAsGroup": SANDBOX_UID,
                "fsGroup": SANDBOX_UID,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [container],
            "volumes": [
                {"name": "sandbox", "emptyDir": {"sizeLimit": self.workspace_size_limit}},
                # Memory-backed: counts against the container's memory limit.
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": self.tmp_size_limit}},
            ],
        }
        if self.runtime_class:
            spec["runtimeClassName"] = self.runtime_class
        if self.node_selector:
            spec["nodeSelector"] = dict(self.node_selector)
        if self.tolerations:
            spec["tolerations"] = [dict(t) for t in self.tolerations]
        if self.image_pull_secrets:
            spec["imagePullSecrets"] = [{"name": s} for s in self.image_pull_secrets]
        if self.priority_class:
            spec["priorityClassName"] = self.priority_class
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "namespace": self.namespace,
                         "labels": {**self.labels, **({EGRESS_LABEL_KEY: EGRESS_LABEL_VALUE} if egress else {})},
                         "annotations": dict(self.annotations)},
            "spec": spec,
        }

    # ------------------------------------------------------------------
    # Pod lifecycle
    # ------------------------------------------------------------------
    @staticmethod
    def _get(obj: Any, *path: str) -> Any:
        """Read a field from either a kubernetes model object or a dict."""
        for key in path:
            if obj is None:
                return None
            if isinstance(obj, dict):
                obj = obj.get(key)
            else:
                obj = getattr(obj, key, None)
        return obj

    def _wait_running(self, name: str) -> None:
        deadline = self._clock() + self.pod_start_timeout
        reason = "Pending"
        while True:
            pod = self.core.read_namespaced_pod(name, self.namespace)
            phase = self._get(pod, "status", "phase")
            for cs in self._get(pod, "status", "container_statuses") or []:
                waiting = self._get(cs, "state", "waiting")
                if waiting is not None:
                    reason = self._get(waiting, "reason") or reason
                    if reason in FATAL_WAITING_REASONS:
                        raise RuntimeError(f"sandbox pod cannot start: {reason}")
                if phase == "Running" and self._get(cs, "state", "running") is not None:
                    return
            if phase in ("Succeeded", "Failed"):
                raise RuntimeError(f"sandbox pod ended before the command ran (phase {phase})")
            if self._clock() >= deadline:
                raise TimeoutError(f"sandbox pod did not start within {self.pod_start_timeout}s ({reason})")
            self._sleep(0.25)

    def _delete_pod(self, name: str) -> None:
        try:
            self.core.delete_namespaced_pod(name, self.namespace, grace_period_seconds=0,
                                            propagation_policy="Background")
        except Exception as exc:  # already gone, or the API is down: activeDeadline backstops it
            if getattr(exc, "status", None) != 404:
                log.warning("could not delete sandbox pod %s/%s: %s", self.namespace, name, exc)

    # ------------------------------------------------------------------
    # Exec helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _exit_code(resp: Any) -> int:
        """Exit code from the exec status (error) channel."""
        raw = resp.read_channel(ERROR)
        if not raw:
            raise _ExecError("exec stream closed without a status")
        try:
            status = json.loads(raw)
        except ValueError as exc:
            raise _ExecError("unreadable exec status") from exc
        if status.get("status") == "Success":
            return 0
        for cause in (status.get("details") or {}).get("causes") or []:
            if cause.get("reason") == "ExitCode":
                return int(cause.get("message", "-1"))
        # e.g. the executable is missing: the process never ran.
        raise _ExecError(str(status.get("message") or status.get("reason") or "exec failed")[:300])

    def _pump(self, resp: Any, deadline: float, sink: Callable[[bytes], None]) -> bool:
        """Read stdout+stderr into `sink` until the stream closes or the
        deadline passes. Returns True if the deadline was hit."""
        while resp.is_open():
            remaining = deadline - self._clock()
            if remaining <= 0:
                return True
            resp.update(timeout=min(1.0, remaining))
            for ch in (STDOUT, STDERR):
                data = resp.read_channel(ch)
                if data:
                    sink(data if isinstance(data, bytes) else data.encode())
        # Frames that arrived together with the close.
        for ch in (STDOUT, STDERR):
            data = resp.read_channel(ch)
            if data:
                sink(data if isinstance(data, bytes) else data.encode())
        return False

    @staticmethod
    def _close(resp: Any) -> None:
        try:
            resp.close()
        except Exception:
            pass

    def _check_isolated(self, pod: str) -> None:
        """Fail closed unless the Pod's network is blocked (see _PROBE_SCRIPT)."""
        if not self.network_probe:
            return
        resp = self._open_exec(pod, ["python3", "-c", _PROBE_SCRIPT, str(self.network_probe_timeout),
                                     *self.network_probe], stdin=False)
        said = bytearray()

        def keep(data: bytes) -> None:
            if len(said) < 1024:
                said.extend(data[: 1024 - len(said)])

        try:
            if self._pump(resp, self._clock() + self.network_probe_timeout + self.client_grace, keep):
                code = 3
            else:
                code = self._exit_code(resp)
        finally:
            self._close(resp)
        if code != 0:
            detail = said.decode("utf-8", errors="replace").strip()[:300]
            raise NetworkNotIsolated(
                f"the sandbox pod still had network access after {self.network_probe_timeout:g}s, so the "
                f"command was not run ({detail or f'probe exit {code}'}). Check that the cluster's CNI enforces "
                f"NetworkPolicy and that the harnis-sandbox policies are installed (docs/kubernetes.md)")

    def _upload(self, pod: str, archive: bytes) -> None:
        resp = self._open_exec(pod, ["sh", "-c", _UPLOAD_SCRIPT, "sh", str(len(archive)), SANDBOX_ROOT],
                               stdin=True)
        errors = bytearray()

        def keep(data: bytes) -> None:
            if len(errors) < 4096:
                errors.extend(data[: 4096 - len(errors)])

        try:
            for i in range(0, len(archive), STDIN_CHUNK):
                resp.write_stdin(archive[i:i + STDIN_CHUNK])
                resp.update(timeout=0)  # drain anything tar says while we write
            close_channel = getattr(resp, "close_channel", None)
            if close_channel is not None:
                close_channel(0)  # v5 protocol: half-close stdin (no-op on v4)
            if self._pump(resp, self._clock() + self.transfer_timeout, keep):
                raise TimeoutError(f"workspace upload did not finish within {self.transfer_timeout}s")
            code = self._exit_code(resp)
        finally:
            self._close(resp)
        if code != 0:
            detail = errors.decode("utf-8", errors="replace").strip()[:300]
            raise RuntimeError(f"could not copy the workspace into the sandbox (tar exit {code}: {detail})")

    def _download(self, pod: str) -> bytes:
        # Directory and header overhead on top of the content limit.
        cap = (self.max_bytes + self.deps_max_bytes
               + 1024 * (self.max_files + self.deps_max_files + 64) + 1_048_576)
        buf = bytearray()

        def collect(data: bytes) -> None:
            buf.extend(data)
            if len(buf) > cap:
                raise WorkspaceTooLarge("sandbox produced more output files than allowed")

        resp = self._open_exec(pod, ["tar", "cf", "-", "-C", SANDBOX_ROOT, "workspace"], stdin=False)
        try:
            # tar writes the archive to stdout and warnings to stderr; keep
            # the channels apart here so warnings can't corrupt the archive.
            deadline = self._clock() + self.transfer_timeout
            while resp.is_open():
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise TimeoutError(f"workspace download did not finish within {self.transfer_timeout}s")
                resp.update(timeout=min(1.0, remaining))
                data = resp.read_channel(STDOUT)
                if data:
                    collect(data)
                resp.read_channel(STDERR)
            data = resp.read_channel(STDOUT)
            if data:
                collect(data)
            code = self._exit_code(resp)
        finally:
            self._close(resp)
        # GNU tar: 1 = "some files changed while being archived" (archive is
        # still valid), 2 = fatal.
        if code not in (0, 1):
            raise RuntimeError(f"could not copy the workspace out of the sandbox (tar exit {code})")
        return bytes(buf)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @staticmethod
    def _argv0(command: str) -> str:
        try:
            return (shlex.split(command) or ["?"])[0][:64]
        except ValueError:
            return "?"

    def run(self, command: str, workspace: Path, timeout: int | None = None, *,
            egress: bool = False) -> SandboxResult:
        if egress and not self.egress_proxy_url:
            return SandboxResult(-1, "", error="dependency installs are not configured for the Kubernetes "
                                               "sandbox (SANDBOX_EGRESS_PROXY_URL; the Helm chart sets it)")
        timeout = timeout or (self.install_timeout if egress else self.timeout)
        proxy_url = self._resolved_proxy_url() if egress else ""
        workspace = workspace.resolve()
        start = self._clock()
        name = POD_NAME_PREFIX + uuid.uuid4().hex[:16]
        created = False
        with tracer.start_as_current_span("harnis.sandbox.run") as span:
            # Record the shape of the command, not its contents (may hold secrets).
            span.set_attribute("harnis.sandbox.argv0", self._argv0(command))
            span.set_attribute("harnis.sandbox.image", self.image)
            span.set_attribute("harnis.sandbox.workspace_mode", "copy")
            span.set_attribute("harnis.sandbox.backend", "kubernetes")
            span.set_attribute("harnis.sandbox.k8s.namespace", self.namespace)
            span.set_attribute("harnis.sandbox.k8s.pod", name)
            if self.runtime_class:
                span.set_attribute("harnis.sandbox.k8s.runtime_class", self.runtime_class)
            try:
                archive = pack_workspace(workspace, self.max_bytes, self.max_files,
                                         self.deps_max_bytes, self.deps_max_files)
                created = True  # set before the call: a timed-out create may still have succeeded
                self.core.create_namespaced_pod(self.namespace, self.build_pod_manifest(name, timeout, egress=egress,
                                                                                       proxy_url=proxy_url))
                self._wait_running(name)
                self._check_isolated(name)  # before anything of the session is inside the Pod
                self._upload(name, archive)

                out = bytearray()
                total = 0

                def capture(data: bytes) -> None:
                    nonlocal total
                    total += len(data)
                    room = self.output_limit - len(out)
                    if room > 0:
                        out.extend(data[:room])

                exec_start = self._clock()
                resp = self._open_exec(name, ["sh", "-c", _RUN_SCRIPT, "sh", command, str(timeout), WORKDIR],
                                       stdin=False)
                try:
                    # `timeout` in the container fires at `timeout` (KILL at
                    # +2s); the client-side deadline covers a stream that never
                    # closes (e.g. a background process holding stdout).
                    client_timed_out = self._pump(resp, exec_start + timeout + self.client_grace, capture)
                    exit_code = 124 if client_timed_out else self._exit_code(resp)
                finally:
                    self._close(resp)
                elapsed = self._clock() - exec_start
                # coreutils `timeout` exits 124 (TERM) or 137 (KILL after -k).
                timed_out = client_timed_out or (exit_code in (124, 137) and elapsed >= timeout)
                if timed_out:
                    exit_code = 124

                output = bytes(out).decode("utf-8", errors="replace")
                if total > self.output_limit:
                    output += f"\n... [truncated {total - self.output_limit} bytes]"
                if timed_out:
                    output += f"\n[killed after {timeout}s timeout]"
                # Like Docker copy mode, changes are applied even after a
                # timeout; they are validated either way.
                unpack_workspace(self._download(name), workspace, self.max_bytes, self.max_files,
                                 self.deps_max_bytes, self.deps_max_files, only_deps=egress)
                result = SandboxResult(exit_code, output, timed_out, int((self._clock() - start) * 1000))
            except Exception as exc:
                span.record_exception(exc)
                result = SandboxResult(-1, "", False, int((self._clock() - start) * 1000),
                                       error=f"sandbox error: {type(exc).__name__}: {self._safe_message(exc)}")
            finally:
                if created:
                    self._delete_pod(name)
            span.set_attribute("harnis.sandbox.exit_code", result.exit_code)
            span.set_attribute("harnis.sandbox.timed_out", result.timed_out)
            _record_metrics("kubernetes", egress, result)
            return result

    @staticmethod
    def _safe_message(exc: Exception) -> str:
        """ApiException's str() includes response headers and the full body;
        keep the error short and readable."""
        status, reason = getattr(exc, "status", None), getattr(exc, "reason", None)
        if status is not None and reason is not None:
            return f"HTTP {status} {reason}"
        return str(exc)[:500]

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def reap(self, older_than_seconds: int = 900) -> list[str]:
        """Delete sandbox Pods older than `older_than_seconds`. A run always
        deletes its Pod, but an API replica that is killed mid-run leaves a
        (deadline-expired, resource-free) Pod object behind."""
        selector = f"{SANDBOX_LABEL_KEY}={SANDBOX_LABEL_VALUE}"
        pods = self.core.list_namespaced_pod(self.namespace, label_selector=selector)
        now = time.time()
        removed = []
        for pod in self._get(pods, "items") or []:
            name = self._get(pod, "metadata", "name")
            created = self._get(pod, "metadata", "creation_timestamp")
            ts = created.timestamp() if hasattr(created, "timestamp") else None
            if name and ts is not None and now - ts > older_than_seconds:
                self._delete_pod(name)
                removed.append(name)
        return removed


def _main(argv: list[str] | None = None) -> None:
    """`python -m harnis.k8s_sandbox reap [--older-than SECONDS]`

    Reads only SANDBOX_K8S_NAMESPACE from the environment, so it can run in a
    CronJob with the API's service account and no database credentials."""
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="python -m harnis.k8s_sandbox")
    sub = parser.add_subparsers(dest="cmd", required=True)
    reap = sub.add_parser("reap", help="delete leftover sandbox pods")
    reap.add_argument("--older-than", type=int, default=900, help="minimum age in seconds (default 900)")
    reap.add_argument("--namespace", default=os.environ.get("SANDBOX_K8S_NAMESPACE", "harnis-sandbox"))
    args = parser.parse_args(argv)
    removed = KubernetesSandbox("unused", namespace=args.namespace).reap(args.older_than)
    print(f"reaped {len(removed)} sandbox pod(s) in {args.namespace}")


if __name__ == "__main__":
    _main()

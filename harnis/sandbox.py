# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Run untrusted commands in a locked-down, throwaway container.

Hardening applied to every container:
  network none, read-only root FS, all capabilities dropped,
  no-new-privileges, non-root user, memory + CPU + PID limits,
  a small noexec tmpfs for /tmp, a wall-clock timeout, capped output.

How the workspace gets into the container (SANDBOX_WORKSPACE_MODE):

  copy (default, works on Windows, macOS and Linux)
      The workspace is streamed into a fresh anonymous volume through the
      Docker archive API, the command runs, and the result is streamed back
      and validated before anything touches the host. No host paths are
      shared with the daemon, so it works the same with Docker Desktop, with
      a remote daemon, and when the API itself runs in a container. Files are
      owned by the sandbox user, so host uids don't matter.

  bind (Linux only, faster for big workspaces)
      The host directory is bind-mounted. Paths are resolved by the daemon,
      so the API and the daemon must see the same filesystem.

Docker (runc) shares the host kernel, so a kernel exploit escapes it. For
untrusted code from the internet set SANDBOX_RUNTIME=runsc (gVisor) or run
on Kata/Firecracker. The interface below doesn't change.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shlex
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

from opentelemetry import trace

tracer = trace.get_tracer("harnis.sandbox")
log = logging.getLogger(__name__)

SANDBOX_UID = 65534  # "nobody" in the image
# Commands run here in both modes. In copy mode an anonymous volume is mounted
# at /sandbox and the workspace is uploaded as a directory the sandbox user
# owns (a volume's root directory can't be re-owned through the archive API).
SANDBOX_ROOT = "/sandbox"
WORKDIR = SANDBOX_ROOT + "/workspace"
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}
# Packages installed by the approved `install_dependencies` tool. They travel
# with the workspace (so every backend sees them) under their own size limits,
# and are hidden from file listings, diffs and the CLI.
RESERVED_DIR = ".harnis"
DEPS_DIR = RESERVED_DIR + "/deps"
DEPS_ENV = {
    "PYTHONPATH": f"{WORKDIR}/{DEPS_DIR}/python",
    "NODE_PATH": f"{WORKDIR}/{DEPS_DIR}/node/node_modules",
    "PATH": f"{WORKDIR}/{DEPS_DIR}/python/bin:{WORKDIR}/{DEPS_DIR}/node/node_modules/.bin:"
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
}
EGRESS_PROXY_NAME = "harnis-egress-proxy"
_WARNED_GATEWAY = False
EGRESS_PROXY_PORT = 3128


def in_deps(rel: str) -> bool:
    return rel == DEPS_DIR or rel.startswith(DEPS_DIR + "/")


def _skip_dir(rel_dir: str, name: str) -> bool:
    """SKIP_DIRS apply to the project, not to installed dependencies
    (an npm install lives in .harnis/deps/node/node_modules)."""
    return name in SKIP_DIRS and not in_deps(rel_dir)


class _Budget:
    """Byte and file limits, with a separate allowance for installed packages."""

    def __init__(self, max_bytes: int, max_files: int, deps_bytes: int, deps_files: int):
        self.limits = {False: [max_bytes, max_files], True: [deps_bytes, deps_files]}
        self.used = {False: [0, 0], True: [0, 0]}

    def add(self, rel: str, size: int) -> None:
        deps = in_deps(rel)
        used, limit = self.used[deps], self.limits[deps]
        used[0] += size
        used[1] += 1
        if used[0] > limit[0] or used[1] > limit[1]:
            what = "installed dependencies" if deps else "the workspace"
            raise WorkspaceTooLarge(f"{what} exceed the limit of {limit[0]} bytes / {limit[1]} files")


def _record_metrics(backend: str, egress: bool, result: "SandboxResult") -> None:
    from . import metrics

    kind = "install" if egress else "command"
    outcome = ("error" if result.error else "timeout" if result.timed_out
               else "ok" if result.exit_code == 0 else "nonzero_exit")
    metrics.SANDBOX_RUNS.labels(backend, kind, outcome).inc()
    metrics.SANDBOX_LATENCY.labels(backend, kind).observe(result.duration_ms / 1000)


@dataclass
class SandboxResult:
    exit_code: int
    output: str
    timed_out: bool = False
    duration_ms: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and self.error is None


class Sandbox(Protocol):
    def run(self, command: str, workspace: Path, timeout: int | None = None, *,
            egress: bool = False) -> SandboxResult: ...


class WorkspaceTooLarge(Exception):
    pass


# ---------------------------------------------------------------------------
# Workspace <-> tar (copy mode)
# ---------------------------------------------------------------------------
def pack_workspace(workspace: Path, max_bytes: int, max_files: int = 1_000_000,
                   deps_max_bytes: int = 0, deps_max_files: int = 0) -> bytes:
    """Tar the workspace as `workspace/...` (uploaded into /sandbox), owned by
    the sandbox user. Symlinks and special files on the host are skipped,
    never followed."""
    buf = io.BytesIO()
    budget = _Budget(max_bytes, max_files, deps_max_bytes, deps_max_files)
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add_dir(name: str) -> None:
            info = tarfile.TarInfo(name)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            info.uid = info.gid = SANDBOX_UID
            info.mtime = int(time.time())
            tar.addfile(info)

        add_dir("workspace")
        for dirpath, dirnames, filenames in os.walk(workspace):
            rel_dir = Path(dirpath).relative_to(workspace).as_posix()
            dirnames[:] = sorted(d for d in dirnames if not _skip_dir(rel_dir if rel_dir != "." else "", d)
                                 and not os.path.islink(os.path.join(dirpath, d)))
            if rel_dir != ".":
                add_dir(f"workspace/{rel_dir}")
            for name in sorted(filenames):
                p = Path(dirpath, name)
                if p.is_symlink() or not p.is_file():
                    continue
                rel = p.relative_to(workspace).as_posix()
                budget.add(rel, p.stat().st_size)
                data = p.read_bytes()
                info = tarfile.TarInfo(f"workspace/{rel}")
                # Keep scripts executable. Windows hosts don't record the bit, so
                # anything in an installed package's bin/ directory counts as executable.
                executable = bool(p.stat().st_mode & 0o111) or (in_deps(rel) and "/bin/" in rel)
                info.size, info.mode = len(data), 0o755 if executable else 0o644
                info.uid = info.gid = SANDBOX_UID
                info.mtime = int(p.stat().st_mtime)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def unpack_workspace(stream: bytes | BinaryIO, workspace: Path, max_bytes: int, max_files: int,
                     deps_max_bytes: int = 0, deps_max_files: int = 0, only_deps: bool = False) -> None:
    """Apply the container's workspace directory back onto the host workspace.

    The archive was produced by untrusted code, so we never call extractall:
    only regular files and directories are accepted, every name is checked to
    stay inside the workspace, and size/count limits are enforced. Files the
    command deleted are deleted on the host too (the command was approved).

    only_deps (dependency installs): only changes under .harnis/deps are
    applied. Package code runs during an install (setup.py, build backends),
    and it must not be able to change the project the reviewer is looking at."""
    root = workspace.resolve()
    seen: set[str] = set()
    budget = _Budget(max_bytes, max_files, deps_max_bytes, deps_max_files)
    fileobj = io.BytesIO(stream) if isinstance(stream, (bytes, bytearray)) else stream
    with tarfile.open(fileobj=fileobj, mode="r:") as tar:
        for m in tar:
            parts = PurePosixPath(m.name).parts
            if not parts or parts[0] != "workspace" or ".." in parts or m.name.startswith("/"):
                continue
            rel_parts = parts[1:]
            rel = "/".join(rel_parts)
            if only_deps and not in_deps(rel):
                continue
            if not rel_parts or any(_skip_dir("/".join(rel_parts[:i]), d) for i, d in enumerate(rel_parts[:-1])) \
                    or (rel_parts[0] in SKIP_DIRS):
                continue
            target = root.joinpath(*rel_parts)
            if root not in target.resolve().parents:
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isreg():
                continue  # symlinks, hard links, devices, fifos: dropped
            try:
                budget.add(rel, m.size)
            except WorkspaceTooLarge as exc:
                raise WorkspaceTooLarge(f"sandbox output too large: {exc}") from exc
            f = tar.extractfile(m)
            if f is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            target.write_bytes(f.read())
            if m.mode & 0o111 and in_deps(rel):
                try:
                    target.chmod(0o755)
                except OSError:
                    pass
            seen.add(rel)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [d for d in dirnames if not _skip_dir(rel_dir if rel_dir != "." else "", d)]
        for name in filenames:
            p = Path(dirpath, name)
            rel = p.relative_to(root).as_posix()
            if only_deps and not in_deps(rel):
                continue
            if rel not in seen and not p.is_symlink():
                p.unlink()


def remove_symlinks(workspace: Path) -> int:
    """bind mode: sandboxed code writes straight into the host folder, so it
    can create symlinks there. Remove them after every run so nothing on the
    API side (file listings, exports, permission fixes) can be pointed outside."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(workspace):  # os.walk doesn't descend into dir symlinks
        for name in list(dirnames) + filenames:
            p = Path(dirpath, name)
            if p.is_symlink():
                p.unlink()
                n += 1
    return n


class _CappedSpool:
    """Receives the container's tar stream into a temporary file and stops as
    soon as it exceeds the limit, so a huge (or sparse) file can't exhaust the
    API's memory or disk."""

    def __init__(self, cap: int):
        import tempfile
        self.cap, self.size = cap, 0
        self.file = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)

    def write_all(self, chunks) -> "BinaryIO":
        for chunk in chunks:
            self.size += len(chunk)
            if self.size > self.cap:
                self.file.close()
                raise WorkspaceTooLarge(f"sandbox output exceeds {self.cap} bytes")
            self.file.write(chunk)
        self.file.seek(0)
        return self.file  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
class DockerSandbox:
    def __init__(self, image: str, *, runtime: str = "", memory: str = "512m", cpus: float = 1.0,
                 pids_limit: int = 128, timeout: int = 30, output_limit: int = 64_000,
                 workspace_mode: str = "copy", max_workspace_bytes: int = 50_000_000,
                 max_workspace_files: int = 2_000, deps_max_bytes: int = 300_000_000,
                 deps_max_files: int = 60_000, install_timeout: int = 300,
                 egress_allow: str = "pypi.org,files.pythonhosted.org,registry.npmjs.org",
                 egress_upstream_proxy: str = "", egress_allow_private: bool = False,
                 egress_network: str = "harnis-sandbox-egress", egress_proxy_image: str = ""):
        if workspace_mode not in ("copy", "bind"):
            raise ValueError("workspace_mode must be 'copy' or 'bind'")
        if workspace_mode == "bind" and sys.platform != "linux":
            raise ValueError("bind mode needs Linux; use copy mode on Windows and macOS")
        self.image = image
        self.runtime = runtime or None
        self.memory = memory
        self.nano_cpus = int(cpus * 1e9)
        self.pids_limit = pids_limit
        self.timeout = timeout
        self.output_limit = output_limit
        self.mode = workspace_mode
        self.max_bytes = max_workspace_bytes
        self.max_files = max_workspace_files
        self.deps_max_bytes = deps_max_bytes
        self.deps_max_files = deps_max_files
        self.install_timeout = install_timeout
        self.egress_allow = egress_allow
        self.egress_upstream_proxy = egress_upstream_proxy
        self.egress_allow_private = egress_allow_private
        self.egress_network = egress_network
        self.egress_proxy_image = egress_proxy_image or image
        self._client = None

    # -- egress for dependency installs --------------------------------------------
    def _egress_config(self) -> dict[str, str]:
        return {"EGRESS_ALLOW": self.egress_allow, "EGRESS_UPSTREAM_PROXY": self.egress_upstream_proxy,
                "EGRESS_ALLOW_PRIVATE": "true" if self.egress_allow_private else "",
                "EGRESS_LISTEN": f"0.0.0.0:{EGRESS_PROXY_PORT}"}

    def ensure_egress(self) -> str:
        """Create (once) the allowlisting proxy and return its URL.

        The proxy sits on its own outbound network (not Docker's default bridge,
        so unrelated containers can't use it). Each install run gets a private
        network of its own (see `_open_run_network`), and the proxy is attached
        to it for the duration of the run."""
        import hashlib

        import docker

        c = self.client
        out_net = self.egress_network + "-out"
        try:
            c.networks.get(out_net)
        except docker.errors.NotFound:
            try:
                c.networks.create(out_net, driver="bridge", check_duplicate=True,
                                  labels={"harnis.dev/role": "egress-proxy-outbound"})
            except docker.errors.APIError:  # another API replica created it first
                c.networks.get(out_net)
        config = self._egress_config()
        digest = hashlib.sha256(json.dumps([self.egress_proxy_image, config, out_net],
                                           sort_keys=True).encode()).hexdigest()[:16]
        try:
            proxy = c.containers.get(EGRESS_PROXY_NAME)
            if proxy.labels.get("harnis.dev/config") != digest or proxy.status != "running":
                proxy.remove(force=True)
                proxy = None
        except docker.errors.NotFound:
            proxy = None
        if proxy is None:
            try:
                proxy = self._create_proxy(c, config, digest, out_net)
            except docker.errors.APIError as exc:
                if getattr(exc, "status_code", None) != 409:
                    raise
                proxy = c.containers.get(EGRESS_PROXY_NAME)  # another replica won the race
        return f"http://{EGRESS_PROXY_NAME}:{EGRESS_PROXY_PORT}"

    def _open_run_network(self) -> tuple[str, str]:
        """A private network for one install run: `internal` (no route out) and,
        on Docker 28+, with an isolated gateway, so the Docker host has no
        address on it either. Only the proxy is attached. Concurrent installs
        can't see each other."""
        import uuid

        import docker

        c = self.client
        name = f"{self.egress_network}-{uuid.uuid4().hex[:12]}"
        labels = {"harnis.dev/role": "sandbox-egress"}
        try:
            net = c.networks.create(name, driver="bridge", internal=True, labels=labels,
                                    options={"com.docker.network.bridge.gateway_mode_ipv4": "isolated"})
        except docker.errors.APIError:
            global _WARNED_GATEWAY
            if not _WARNED_GATEWAY:
                log.warning("Docker doesn't support isolated gateways (needs Docker 28+): install runs can reach "
                            "services listening on the Docker host. Upgrade Docker or use the Kubernetes backend.")
                _WARNED_GATEWAY = True
            net = c.networks.create(name, driver="bridge", internal=True, labels=labels)
        proxy = c.containers.get(EGRESS_PROXY_NAME)
        net.connect(proxy, aliases=[EGRESS_PROXY_NAME])
        # Pass the proxy by IP address: gVisor (runsc) has its own network stack
        # and can't use Docker's embedded DNS, so container names don't resolve there.
        proxy.reload()
        ip = proxy.attrs["NetworkSettings"]["Networks"][name]["IPAddress"]
        if not ip:
            raise RuntimeError(f"the egress proxy got no address on {name}")
        return name, f"http://{ip}:{EGRESS_PROXY_PORT}"

    def _close_run_network(self, name: str) -> None:
        try:
            net = self.client.networks.get(name)
            try:
                net.disconnect(EGRESS_PROXY_NAME, force=True)
            except Exception:
                pass
            net.remove()
        except Exception as exc:  # leaked networks are labeled and harmless; log for the operator
            log.warning("could not remove install network %s: %s", name, exc)

    def _create_proxy(self, c, config: dict[str, str], digest: str, out_net: str):
        """The proxy container: hardened like a sandbox, on the bridge (to reach the registries)
        and on the internal network (to be reachable by install runs)."""
        proxy = c.containers.create(
            image=self.egress_proxy_image,
            command=["python", "/opt/harnis/egress_proxy.py"],
            name=EGRESS_PROXY_NAME, user=f"{SANDBOX_UID}:{SANDBOX_UID}", environment=config,
            read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit="256m", pids_limit=256, network=out_net,
            restart_policy={"Name": "unless-stopped"},
            labels={"harnis.dev/role": "egress-proxy", "harnis.dev/config": digest}, detach=True)
        proxy.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            proxy.reload()
            logs = proxy.logs().decode("utf-8", "replace")
            if '"listening"' in logs:
                break
            if proxy.status == "exited":
                raise RuntimeError(f"the egress proxy exited: {logs[-500:]}")
            time.sleep(0.2)
        return proxy

    @property
    def client(self):
        if self._client is None:
            import docker  # uses DOCKER_HOST, the npipe on Windows, or the unix socket

            self._client = docker.from_env()
        return self._client

    @staticmethod
    def _bind_user(workspace: Path) -> str:
        """bind mode: run as the uid owning the workspace so the agent can write
        its files, but never as root (fall back to nobody + open permissions)."""
        st = workspace.stat()
        if st.st_uid != 0:
            return f"{st.st_uid}:{st.st_gid}"
        remove_symlinks(workspace)
        for root, _dirs, files in os.walk(workspace):
            if not os.path.islink(root):
                os.chmod(root, 0o777)
            for f in files:
                p = os.path.join(root, f)
                if not os.path.islink(p):  # never follow a link: chmod would change its target
                    os.chmod(p, 0o666)
        return f"{SANDBOX_UID}:{SANDBOX_UID}"

    @staticmethod
    def _argv0(command: str) -> str:
        try:
            return (shlex.split(command) or ["?"])[0][:64]
        except ValueError:
            return "?"

    def run(self, command: str, workspace: Path, timeout: int | None = None, *,
            egress: bool = False) -> SandboxResult:
        from docker.types import Mount

        timeout = timeout or (self.install_timeout if egress else self.timeout)
        # Installs always use copy mode, so only .harnis/deps can change on the host.
        mode = "copy" if egress else self.mode
        run_network = None
        workspace = workspace.resolve()
        start = time.monotonic()
        container = None
        with tracer.start_as_current_span("harnis.sandbox.run") as span:
            # Record the shape of the command, not its contents (may hold secrets).
            span.set_attribute("harnis.sandbox.argv0", self._argv0(command))
            span.set_attribute("harnis.sandbox.image", self.image)
            span.set_attribute("harnis.sandbox.workspace_mode", mode)
            span.set_attribute("harnis.sandbox.egress", egress)
            try:
                env = {"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1", **DEPS_ENV}
                network = "none"
                if egress:
                    self.ensure_egress()
                    run_network, proxy = self._open_run_network()
                    network = run_network
                    env.update({"HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy,
                                "http_proxy": proxy, "npm_config_https_proxy": proxy, "npm_config_proxy": proxy,
                                "NO_PROXY": "", "PIP_DEFAULT_TIMEOUT": "60"})
                if mode == "copy":
                    user = f"{SANDBOX_UID}:{SANDBOX_UID}"
                    mounts = [Mount(target=SANDBOX_ROOT, source=None, type="volume")]  # anonymous volume
                    archive = pack_workspace(workspace, self.max_bytes, self.max_files,
                                             self.deps_max_bytes, self.deps_max_files)
                else:
                    user = self._bind_user(workspace)
                    mounts = [Mount(target=WORKDIR, source=str(workspace), type="bind")]
                    archive = None
                container = self.client.containers.create(
                    image=self.image,
                    command=["sh", "-c", command],
                    working_dir=WORKDIR,
                    user=user,
                    network_mode=network,
                    read_only=True,
                    tmpfs={"/tmp": "rw,noexec,nosuid,size=64m,mode=1777"},
                    mounts=mounts,
                    mem_limit=self.memory,
                    memswap_limit=self.memory,  # no swap beyond the memory limit
                    nano_cpus=self.nano_cpus,
                    pids_limit=self.pids_limit,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    runtime=self.runtime,
                    environment=env,
                    detach=True,
                )
                # Upload into the volume: the root filesystem is read-only.
                if archive is not None and not container.put_archive(SANDBOX_ROOT, archive):
                    raise RuntimeError("could not copy the workspace into the sandbox")
                container.start()
                timed_out = False
                try:
                    status = container.wait(timeout=timeout)
                    exit_code = int(status.get("StatusCode", -1))
                except Exception:  # requests ReadTimeout / ConnectionError
                    timed_out = True
                    exit_code = 124
                    try:
                        container.kill()
                    except Exception:
                        pass
                raw = container.logs(stdout=True, stderr=True) or b""
                output = raw[: self.output_limit].decode("utf-8", errors="replace")
                if len(raw) > self.output_limit:
                    output += f"\n... [truncated {len(raw) - self.output_limit} bytes]"
                if timed_out:
                    output += f"\n[killed after {timeout}s timeout]"
                if mode == "copy":
                    chunks, _stat = container.get_archive(WORKDIR)
                    cap = (self.max_bytes + self.deps_max_bytes
                           + 1024 * (self.max_files + self.deps_max_files + 64) + 1_048_576)
                    spool = _CappedSpool(cap).write_all(chunks)
                    try:
                        unpack_workspace(spool, workspace, self.max_bytes, self.max_files,
                                         self.deps_max_bytes, self.deps_max_files, only_deps=egress)
                    finally:
                        spool.close()
                else:
                    remove_symlinks(workspace)
                result = SandboxResult(exit_code, output, timed_out, int((time.monotonic() - start) * 1000))
            except Exception as exc:
                span.record_exception(exc)
                result = SandboxResult(-1, "", False, int((time.monotonic() - start) * 1000),
                                       error=f"sandbox error: {type(exc).__name__}: {exc}")
            finally:
                if container is not None:
                    try:
                        container.remove(force=True, v=True)  # v=True drops the anonymous volume
                    except Exception:
                        pass
                if run_network:
                    self._close_run_network(run_network)
            span.set_attribute("harnis.sandbox.exit_code", result.exit_code)
            span.set_attribute("harnis.sandbox.timed_out", result.timed_out)
            _record_metrics("docker", egress, result)
            return result

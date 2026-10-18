#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""k8s_local: run Harnis on a local kind cluster and check it end to end.

Works the same in PowerShell, cmd, macOS and Linux shells. Standard library only.

    python scripts/k8s_local.py up       # cluster "harnis", images, Postgres + Redis, Helm release
    python scripts/k8s_local.py check    # port-forward + scripts/harnis_check.py (JSON report)
    python scripts/k8s_local.py debug    # pods, events, describe and logs (for bug reports / CI)
    python scripts/k8s_local.py down     # delete the cluster

Needs docker (Docker Desktop is fine), kind, kubectl and helm on PATH. Every
kubectl / helm call targets the kind context explicitly (kind-harnis), so other
clusters in your kubeconfig are never touched.

Files: deploy/local-k8s/{kind-config.yaml,postgres.yaml,redis.yaml,values-kind.yaml}.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "deploy" / "local-k8s"
CHART = ROOT / "deploy" / "helm" / "harnis"
KIND_CONFIG = LOCAL / "kind-config.yaml"
VALUES = LOCAL / "values-kind.yaml"
DEPS = [LOCAL / "postgres.yaml", LOCAL / "redis.yaml"]
DEFAULT_REPORT = ROOT / ".k8s-local" / "harnis-check.json"
IS_WINDOWS = os.name == "nt"

CLUSTER = os.environ.get("HARNIS_KIND_CLUSTER", "harnis")
CONTEXT = f"kind-{CLUSTER}"
NAMESPACE = "harnis"
DEPS_NAMESPACE = "harnis-deps"
SANDBOX_NAMESPACE = "harnis-sandbox"
RELEASE = "harnis"
API_IMAGE = "harnis:local"
SANDBOX_IMAGE = "harnis-sandbox:local"

INSTALL_HINTS = {
    "docker": {"win": "install Docker Desktop: winget install Docker.DockerDesktop",
               "mac": "install Docker Desktop (or Colima / OrbStack)",
               "linux": "install Docker Engine: https://docs.docker.com/engine/install/"},
    "kind": {"win": "winget install Kubernetes.kind", "mac": "brew install kind",
             "linux": "download from https://kind.sigs.k8s.io/docs/user/quick-start/#installation"},
    "kubectl": {"win": "winget install Kubernetes.kubectl", "mac": "brew install kubectl",
                "linux": "sudo snap install kubectl --classic  (or https://kubernetes.io/docs/tasks/tools/)"},
    "helm": {"win": "winget install Helm.Helm", "mac": "brew install helm",
             "linux": "sudo snap install helm --classic  (or https://helm.sh/docs/intro/install/)"},
}


class Failed(Exception):
    pass


def say(msg: str) -> None:
    print(msg, flush=True)


def os_key() -> str:
    return "win" if IS_WINDOWS else ("mac" if sys.platform == "darwin" else "linux")


def tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise Failed(f"{name} is not installed or not on PATH. To install: {INSTALL_HINTS[name][os_key()]}")
    return path


def run(*cmd: str, check: bool = True, capture: bool = False, timeout: float | None = None,
        input_text: str | None = None) -> subprocess.CompletedProcess:
    say("> " + " ".join(cmd))
    exe = shutil.which(cmd[0]) or cmd[0]
    try:
        r = subprocess.run([exe, *cmd[1:]], cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                           capture_output=capture, timeout=timeout, input=input_text)
    except FileNotFoundError as exc:
        raise Failed(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise Failed(f"timed out after {timeout:.0f}s: {' '.join(cmd)}") from exc
    if check and r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip() if capture else ""
        raise Failed(f"command failed (exit {r.returncode}): {' '.join(cmd)}" + (f"\n{detail}" if detail else ""))
    return r


def quiet(*cmd: str, timeout: float = 60) -> subprocess.CompletedProcess:
    exe = shutil.which(cmd[0]) or cmd[0]
    try:
        return subprocess.run([exe, *cmd[1:]], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def kubectl(*args: str, **kw) -> subprocess.CompletedProcess:
    return run("kubectl", "--context", CONTEXT, *args, **kw)


def jwt_secret_from_values() -> str:
    """secrets.jwtSecret from values-kind.yaml (no YAML library needed for one key)."""
    text = VALUES.read_text(encoding="utf-8")
    m = re.search(r"^secrets:\s*\n(?:[ \t]+.*\n|\s*\n)*?[ \t]+jwtSecret:\s*[\"']?([^\"'\n#]+)[\"']?", text, re.M)
    if not m or len(m.group(1).strip()) < 32:
        raise Failed(f"could not read secrets.jwtSecret (>= 32 chars) from {VALUES}")
    return m.group(1).strip()


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------
def check_tools() -> None:
    missing = [n for n in ("docker", "kind", "kubectl", "helm") if shutil.which(n) is None]
    if missing:
        hints = "\n".join(f"  {n:8} {INSTALL_HINTS[n][os_key()]}" for n in missing)
        extra = ("\nAll at once on Windows: winget install Kubernetes.kind Kubernetes.kubectl Helm.Helm"
                 if IS_WINDOWS else "")
        raise Failed(f"missing tools: {', '.join(missing)}\n{hints}{extra}\n"
                     "Open a new terminal after installing so PATH is refreshed.")
    r = quiet("docker", "info", "--format", "{{.OSType}}", timeout=30)
    if r.returncode != 0:
        raise Failed("the Docker engine is not reachable. Start Docker Desktop (or `sudo systemctl start docker`) "
                     "and wait until it is running.\n" + (r.stderr.strip()[:500]))
    if r.stdout.strip() != "linux":
        raise Failed("Docker is in Windows-containers mode; switch Docker Desktop to Linux containers.")
    v = quiet("kind", "version", timeout=30)
    m = re.search(r"v(\d+)\.(\d+)", v.stdout or "")
    if m and (int(m.group(1)), int(m.group(2))) < (0, 24):
        raise Failed(f"kind {m.group(0)} is too old: its network plugin enforces NetworkPolicy only from v0.24, "
                     "and Harnis refuses to run sandbox commands without it. Install kind v0.24 or newer.")


def cluster_exists() -> bool:
    r = quiet("kind", "get", "clusters")
    return r.returncode == 0 and CLUSTER in r.stdout.split()


def ensure_cluster(node_image: str | None) -> None:
    if cluster_exists():
        say(f"kind cluster {CLUSTER!r} already exists")
        quiet("kind", "export", "kubeconfig", "--name", CLUSTER)
        return
    cmd = ["kind", "create", "cluster", "--name", CLUSTER, "--config", str(KIND_CONFIG), "--wait", "180s"]
    if node_image:
        cmd += ["--image", node_image]
    run(*cmd)


def build_images() -> None:
    run("docker", "build", "-t", API_IMAGE, ".")
    run("docker", "build", "-f", "Dockerfile.sandbox", "-t", SANDBOX_IMAGE, ".")


def image_id(ref: str) -> str:
    r = quiet("docker", "image", "inspect", "--format", "{{.Id}}", ref)
    if r.returncode != 0:
        raise Failed(f"image {ref} not found; run without --skip-build")
    return r.stdout.strip()


def load_images(preload_deps: bool) -> None:
    run("kind", "load", "docker-image", API_IMAGE, SANDBOX_IMAGE, "--name", CLUSTER)
    if preload_deps:  # optional: saves the node from pulling (Docker Hub rate limits, slow links)
        for ref in ("postgres:16-alpine", "redis/redis-stack-server:7.4.0-v1"):
            if quiet("docker", "image", "inspect", ref).returncode != 0:
                run("docker", "pull", ref, check=False)
            r = run("kind", "load", "docker-image", ref, "--name", CLUSTER, check=False)
            if r.returncode != 0:
                say(f"  note: could not preload {ref}; the node will pull it itself")


def deploy_deps() -> None:
    for f in DEPS:
        kubectl("apply", "-f", str(f))
    for name in ("postgres", "redis"):
        kubectl("-n", DEPS_NAMESPACE, "rollout", "status", f"deploy/{name}", "--timeout=300s")


def helm_install(api_id: str, sandbox_id: str, timeout: str) -> None:
    # Annotate the Pod template with the image ids: rebuilding :local images
    # then rolls the API on the next `up` even though the tag is unchanged.
    run("helm", "upgrade", "--install", RELEASE, str(CHART), "--kube-context", CONTEXT,
        "--namespace", NAMESPACE, "--create-namespace", "-f", str(VALUES),
        "--set-string", f"api.podAnnotations.harnis\\.dev/api-image={api_id.replace(':', '-')[:63]}",
        "--set-string", f"api.podAnnotations.harnis\\.dev/sandbox-image={sandbox_id.replace(':', '-')[:63]}",
        "--wait", "--timeout", timeout)
    kubectl("-n", NAMESPACE, "rollout", "status", f"deploy/{RELEASE}", "--timeout=300s")


def cmd_up(a: argparse.Namespace) -> None:
    check_tools()
    ensure_cluster(a.node_image)
    if not a.skip_build:
        build_images()
    api_id, sandbox_id = image_id(API_IMAGE), image_id(SANDBOX_IMAGE)
    load_images(a.preload_deps)
    deploy_deps()
    helm_install(api_id, sandbox_id, a.helm_timeout)
    say(f"\nHarnis is running on kind cluster {CLUSTER!r} (context {CONTEXT}).\n"
        f"  Check it:     python scripts/k8s_local.py check\n"
        f"  Reach it:     kubectl --context {CONTEXT} -n {NAMESPACE} port-forward svc/{RELEASE} 8000:80\n"
        f"  Sandbox Pods: kubectl --context {CONTEXT} -n {SANDBOX_NAMESPACE} get pods -w\n"
        f"  Remove it:    python scripts/k8s_local.py down")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
def free_port(preferred: int) -> int:
    for port in [preferred, *range(preferred + 1, preferred + 50)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise Failed(f"no free local port near {preferred}")


def wait_ready(url: str, proc: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise Failed(f"kubectl port-forward exited (code {proc.returncode}); is the release deployed? "
                         "Run: python scripts/k8s_local.py up")
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except OSError as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise Failed(f"{url} did not answer 200 within {timeout:.0f}s (last: {last})")


def cmd_check(a: argparse.Namespace) -> int:
    tool("kubectl")
    if quiet("kubectl", "--context", CONTEXT, "-n", NAMESPACE, "get", "svc", RELEASE).returncode != 0:
        raise Failed(f"service {RELEASE} not found in {NAMESPACE} on {CONTEXT}. Run: python scripts/k8s_local.py up")
    port = free_port(a.port)
    secret = jwt_secret_from_values()
    report = Path(a.report).resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    pf_cmd = [shutil.which("kubectl") or "kubectl", "--context", CONTEXT, "-n", NAMESPACE, "port-forward",
              f"svc/{RELEASE}", f"{port}:80", "--address", "127.0.0.1"]
    say("> " + " ".join(pf_cmd[1:]) + "   (background)")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
    pf = subprocess.Popen(pf_cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=flags)
    try:
        api = f"http://127.0.0.1:{port}"
        wait_ready(api + "/ready", pf, a.ready_timeout)
        say(f"API ready at {api} (port-forward pid {pf.pid})")
        cmd = [sys.executable, str(ROOT / "scripts" / "harnis_check.py"), "--api", api,
               "--jwt-secret", secret, "--report", str(report), *a.extra]
        say("> " + " ".join(c if c != secret else "<jwtSecret from values-kind.yaml>" for c in cmd))
        code = subprocess.run(cmd, cwd=ROOT).returncode
    finally:
        # Stop only the port-forward this run started (its recorded PID).
        if pf.poll() is None:
            pf.terminate()
            try:
                pf.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pf.kill()
                pf.wait(timeout=10)
        err = pf.stderr.read().decode("utf-8", "replace").strip() if pf.stderr else ""
        if err and a.verbose:
            say("port-forward stderr:\n" + err[-2000:])
    say(f"report: {report}")
    return code


# ---------------------------------------------------------------------------
# debug / down
# ---------------------------------------------------------------------------
def cmd_debug(_: argparse.Namespace) -> None:
    k = ["kubectl", "--context", CONTEXT]
    steps = [
        [*k, "get", "nodes", "-o", "wide"],
        [*k, "get", "pods", "-A", "-o", "wide"],
        [*k, "get", "events", "-A", "--sort-by=.lastTimestamp"],
        ["helm", "--kube-context", CONTEXT, "-n", NAMESPACE, "status", RELEASE],
        ["helm", "--kube-context", CONTEXT, "-n", NAMESPACE, "history", RELEASE],
        [*k, "-n", NAMESPACE, "get", "all,jobs,cronjobs,secrets,configmaps,networkpolicies"],
        [*k, "-n", SANDBOX_NAMESPACE, "get", "pods,networkpolicies,roles,rolebindings"],
    ]
    for ns in (NAMESPACE, DEPS_NAMESPACE, SANDBOX_NAMESPACE):
        steps.append([*k, "-n", ns, "describe", "pods"])
    steps += [
        [*k, "-n", NAMESPACE, "logs", f"deploy/{RELEASE}", "--all-containers", "--tail=300"],
        [*k, "-n", NAMESPACE, "logs", f"deploy/{RELEASE}", "--all-containers", "--previous", "--tail=100"],
        [*k, "-n", NAMESPACE, "logs", "-l", "app.kubernetes.io/component=migrate", "--tail=200"],
        [*k, "-n", DEPS_NAMESPACE, "logs", "deploy/postgres", "--tail=100"],
        [*k, "-n", DEPS_NAMESPACE, "logs", "deploy/redis", "--tail=50"],
    ]
    for cmd in steps:
        say("\n===== " + " ".join(cmd))
        r = quiet(*cmd, timeout=60)
        say((r.stdout + r.stderr).rstrip() or "(no output)")


def cmd_down(_: argparse.Namespace) -> None:
    tool("kind")
    if not cluster_exists():
        say(f"kind cluster {CLUSTER!r} does not exist")
        return
    run("kind", "delete", "cluster", "--name", CLUSTER)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("up", help="create the cluster, build + load images, deploy deps and the chart")
    up.add_argument("--skip-build", action="store_true", help="reuse existing harnis:local / harnis-sandbox:local")
    up.add_argument("--node-image", default=os.environ.get("KIND_NODE_IMAGE"),
                    help="kindest/node image for a new cluster (default: kind's own default)")
    up.add_argument("--preload-deps", action="store_true",
                    help="docker pull Postgres/Redis on the host and kind-load them (else the node pulls them)")
    up.add_argument("--helm-timeout", default="10m")
    chk = sub.add_parser("check", help="run scripts/harnis_check.py through a port-forward "
                                       "(extra harnis_check args after --)")
    chk.add_argument("--port", type=int, default=18080, help="local port for the port-forward (default 18080)")
    chk.add_argument("--report", default=str(DEFAULT_REPORT), help=f"JSON report (default {DEFAULT_REPORT})")
    chk.add_argument("--ready-timeout", type=float, default=120)
    chk.add_argument("--verbose", action="store_true")
    sub.add_parser("debug", help="print pods, events, descriptions and logs")
    sub.add_parser("down", help="delete the kind cluster")
    a = ap.parse_args(argv)
    a.extra = extra
    try:
        if a.cmd == "up":
            cmd_up(a)
        elif a.cmd == "check":
            return cmd_check(a)
        elif a.cmd == "debug":
            cmd_debug(a)
        elif a.cmd == "down":
            cmd_down(a)
    except Failed as exc:
        say(f"\nk8s_local {a.cmd}: FAILED\n{exc}")
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

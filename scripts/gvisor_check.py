#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""gvisor_check: verify that Harnis sandboxes really run under gVisor (runsc).

Steps:
  1. the Docker engine answers and has a `runsc` runtime registered
     (docker info --format '{{json .Runtimes}}');
  2. a container started with --runtime=runsc is really gVisor: its kernel
     log contains gVisor's boot banner ("Starting gVisor...") and its
     /proc/version differs from a runc container's;
  3. the same container also starts with the exact hardening flags DockerSandbox
     uses (read-only root, noexec tmpfs mode=1777, cap-drop ALL,
     no-new-privileges, pids/memory/CPU limits, no network);
  4. the Harnis sandbox test suite runs with every sandbox forced to runsc:
     SANDBOX_RUNTIME=runsc <python> -m pytest -m sandbox -p gvisor_pytest_plugin

Standard library only; works on Linux and inside WSL2. On Windows with Docker
Desktop it explains why runsc is unavailable there. See docs/gvisor.md.

    python scripts/gvisor_check.py                 # all steps
    python scripts/gvisor_check.py --skip-tests    # steps 1-3 only
    python scripts/gvisor_check.py --build         # build the sandbox image first
    python scripts/gvisor_check.py -- -k network   # extra pytest arguments after --

Exit status: 0 when everything passed, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
DOC = "docs/gvisor.md"
IS_WINDOWS = os.name == "nt"
VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
BANNER = "Starting gVisor"


class CheckFailed(Exception):
    pass


def say(msg: str) -> None:
    print(msg, flush=True)


def docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        raise CheckFailed(f"`docker {' '.join(args[:3])} ...` did not finish within {timeout:.0f}s") from exc


# ---------------------------------------------------------------------------
# 1. engine and runtime
# ---------------------------------------------------------------------------
def check_engine() -> str:
    if shutil.which("docker") is None:
        raise CheckFailed("docker is not on PATH. Install Docker Engine (Linux / WSL2), see " + DOC)
    r = docker("info", "--format", "{{.OperatingSystem}}", timeout=30)
    if r.returncode != 0:
        raise CheckFailed("the Docker engine is not reachable:\n  " + (r.stderr.strip() or r.stdout.strip())
                          + "\nStart it (`sudo systemctl start docker`; in WSL2 make sure systemd is on), "
                          "see " + DOC)
    return r.stdout.strip()


def check_runtime(runtime: str, engine_os: str) -> None:
    r = docker("info", "--format", "{{json .Runtimes}}", timeout=30)
    try:
        runtimes = sorted(json.loads(r.stdout or "{}"))
    except ValueError:
        runtimes = []
    if runtime in runtimes:
        say(f"  PASS  Docker runtime {runtime!r} is registered (runtimes: {', '.join(runtimes)})")
        return
    lines = [f"Docker has no {runtime!r} runtime (it has: {', '.join(runtimes) or 'none'})."]
    if "docker desktop" in engine_os.lower():
        lines += [
            "This engine is Docker Desktop, which cannot add the runsc runtime.",
            "Use Docker Engine inside a WSL2 Ubuntu distro instead, with Docker Desktop's WSL",
            "integration turned off for that distro (or a separate distro). Steps: " + DOC,
        ]
    elif IS_WINDOWS:
        lines += ["On Windows, run this check inside WSL2 with Docker Engine installed there. Steps: " + DOC]
    else:
        lines += [
            "Install gVisor from the official apt repository and register it with Docker:",
            "  sudo apt-get install -y runsc        # after adding the gVisor apt repo, see " + DOC,
            "  sudo runsc install                   # writes the runtime into /etc/docker/daemon.json",
            "  sudo systemctl restart docker",
        ]
    raise CheckFailed("\n".join(lines))


# ---------------------------------------------------------------------------
# 2. is it really gVisor?
# ---------------------------------------------------------------------------
# The sandbox image has no dmesg (util-linux), so read the kernel log with
# syslog(2) through glibc's klogctl (action 3 = READ_ALL). gVisor's syslog
# returns its own boot messages, starting with "Starting gVisor..."
# (pkg/sentry/kernel/syslog.go); on runc the call usually fails for a
# non-root user (dmesg_restrict), which is fine: then the banner is absent.
KLOG = ("import ctypes; b = ctypes.create_string_buffer(65536); "
        "n = ctypes.CDLL(None).klogctl(3, b, 65536); "
        "print(b.raw[:max(n, 0)].decode('utf-8', 'replace')[:2000])")
PROBE = (f"(python3 -c \"{KLOG}\" 2>/dev/null || dmesg 2>/dev/null) | head -n 8; "
         "echo '--proc-version--'; cat /proc/version")


def run_probe(image: str, runtime: str | None, extra: list[str] | None = None) -> subprocess.CompletedProcess:
    args = ["run", "--rm", "--network=none"]
    if runtime:
        args.append(f"--runtime={runtime}")
    args += extra or []
    return docker(*args, image, "sh", "-c", PROBE, timeout=180)


def check_image(image: str, build: bool) -> None:
    if build:
        say(f"  building {image} from Dockerfile.sandbox ...")
        r = subprocess.run(["docker", "build", "-f", "Dockerfile.sandbox", "-t", image, "."], cwd=ROOT)
        if r.returncode != 0:
            raise CheckFailed("building the sandbox image failed")
    if docker("image", "inspect", image, timeout=30).returncode != 0:
        raise CheckFailed(f"image {image} not found. Build it: python tasks.py sandbox-image "
                          f"(or pass --build / --image)")


def check_is_gvisor(image: str, runtime: str) -> None:
    g = run_probe(image, runtime)
    if g.returncode != 0:
        raise CheckFailed(f"`docker run --runtime={runtime} {image}` failed (exit {g.returncode}):\n"
                          f"  {(g.stderr or g.stdout).strip()[:1500]}\n"
                          f"Check `sudo journalctl -u docker` and the runsc debug log (see {DOC}, Troubleshooting).")
    out = g.stdout
    banner = BANNER in out
    g_version = out.split("--proc-version--", 1)[-1].strip()
    runc = run_probe(image, None)
    r_version = runc.stdout.split("--proc-version--", 1)[-1].strip() if runc.returncode == 0 else ""
    differs = bool(r_version) and g_version != r_version
    detail = f"/proc/version under {runtime}: {g_version[:90]!r}"
    if r_version:
        detail += f"; under the default runtime: {r_version[:90]!r}"
    if banner:
        say(f"  PASS  container under {runtime} is gVisor (kernel log shows {BANNER!r})")
        say(f"        {detail}")
        return
    if differs and "gvisor" in out.lower():
        say(f"  PASS  container under {runtime} reports gVisor; {detail}")
        return
    raise CheckFailed(f"--runtime={runtime} started a container, but it does not look like gVisor "
                      f"(no {BANNER!r} in its kernel log).\n  {detail}\n  output: {out.strip()[:600]!r}\n"
                      f"Is {runtime!r} in /etc/docker/daemon.json really pointing at runsc?")


def check_hardened_start(image: str, runtime: str, pids_limit: int) -> None:
    """The flags DockerSandbox passes (harnis/sandbox.py), as docker CLI options."""
    flags = ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
             "--pids-limit", str(pids_limit), "--memory", "128m", "--memory-swap", "128m", "--cpus", "1",
             "--user", "65534:65534", "--mount", "type=volume,target=/sandbox"]
    r = run_probe(image, runtime, flags)
    if r.returncode != 0:
        hint = ""
        if "thread" in (r.stderr + r.stdout).lower():
            hint = ("\nThe pids limit applies to the gVisor Sentry's own host threads; try a larger "
                    "SANDBOX_PIDS_LIMIT (see " + DOC + ").")
        raise CheckFailed(f"runsc could not start a container with the sandbox hardening flags "
                          f"(exit {r.returncode}):\n  {(r.stderr or r.stdout).strip()[:1500]}{hint}")
    say(f"  PASS  runsc starts a container with the DockerSandbox hardening flags (pids-limit {pids_limit})")


# ---------------------------------------------------------------------------
# 3. the sandbox test suite under runsc
# ---------------------------------------------------------------------------
def pick_python(explicit: str | None) -> str:
    if explicit:
        return explicit
    return str(VENV_PY) if VENV_PY.exists() else sys.executable


def run_tests(python: str, runtime: str, image: str, strict: bool, extra: list[str]) -> int:
    probe = subprocess.run([python, "-c", "import docker, pytest, harnis.sandbox"], cwd=ROOT,
                           capture_output=True, text=True)
    if probe.returncode != 0:
        raise CheckFailed(f"{python} cannot import docker / pytest / harnis:\n  "
                          f"{probe.stderr.strip().splitlines()[-1] if probe.stderr.strip() else ''}\n"
                          "Install the package first: python tasks.py install  (or pip install -e \".[dev]\"), "
                          "or pass --python")
    env = {**os.environ, "SANDBOX_RUNTIME": runtime, "SANDBOX_TEST_IMAGE": image,
           "PYTHONPATH": os.pathsep.join(p for p in (str(SCRIPTS), os.environ.get("PYTHONPATH", "")) if p)}
    if strict:
        env["GVISOR_CHECK_STRICT"] = "1"
    cmd = [python, "-m", "pytest", "-m", "sandbox", "-p", "gvisor_pytest_plugin", "-rsxX", "-v", *extra]
    say("> SANDBOX_RUNTIME=" + runtime + " " + " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, env=env).returncode


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runtime", default=os.environ.get("SANDBOX_RUNTIME") or "runsc",
                    help="Docker runtime name to check (default: $SANDBOX_RUNTIME or runsc)")
    ap.add_argument("--image", default=os.environ.get("SANDBOX_TEST_IMAGE", "harnis-sandbox:latest"))
    ap.add_argument("--build", action="store_true", help="build the sandbox image from Dockerfile.sandbox first")
    ap.add_argument("--python", help="interpreter with Harnis + dev extras (default: .venv, else this one)")
    ap.add_argument("--pids-limit", type=int, default=int(os.environ.get("SANDBOX_PIDS_LIMIT", "128")),
                    help="pids limit for the hardened start check (default: SANDBOX_PIDS_LIMIT or 128)")
    ap.add_argument("--skip-tests", action="store_true", help="only check the runtime, not the test suite")
    ap.add_argument("--strict", action="store_true",
                    help="do not mark known gVisor gaps (PID limit) as expected failures")
    a = ap.parse_args(argv)

    say(f"gvisor_check: runtime {a.runtime!r}, image {a.image}")
    try:
        engine_os = check_engine()
        say(f"  PASS  Docker engine reachable ({engine_os})")
        check_runtime(a.runtime, engine_os)
        check_image(a.image, a.build)
        check_is_gvisor(a.image, a.runtime)
        check_hardened_start(a.image, a.runtime, a.pids_limit)
        if a.skip_tests:
            say("\ngvisor_check: runtime checks passed (tests skipped)")
            return 0
        code = run_tests(pick_python(a.python), a.runtime, a.image, a.strict, extra)
    except CheckFailed as exc:
        say(f"  FAIL  {exc}")
        say(f"\ngvisor_check: FAILED. Setup guide: {DOC}")
        return 1
    if code != 0:
        say(f"\ngvisor_check: sandbox tests FAILED under {a.runtime} (pytest exit {code}). See {DOC}.")
        return 1
    say(f"\ngvisor_check: all checks passed under {a.runtime}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

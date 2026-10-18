#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Cross-platform task runner: the same commands on Windows, macOS and Linux.
Standard library only, so it works before anything is installed.

    python tasks.py install          # .venv + dependencies
    python tasks.py up               # Postgres, Redis, Jaeger + migrations + demo tenants
    python tasks.py sandbox-image    # image agent commands run in
    python tasks.py dev              # API on http://127.0.0.1:8000
    python tasks.py token            # print a dev JWT
    python tasks.py cli -- --workspace ./proj "create greet.py"
    python tasks.py test [unit|integration|sandbox]
    python tasks.py eval -- --providers mock,anthropic --repeat 3
    python tasks.py check            # end-to-end feature check of the running API
    python tasks.py pricing          # confirm the prices of your configured models
    python tasks.py backup | restore # database + workspaces
    python tasks.py sso-up           # local Keycloak SSO (testing only)
    python tasks.py gvisor-check     # sandbox tests under gVisor (Linux / WSL2)
    python tasks.py k8s-up | k8s-check | k8s-down   # Helm chart on a local kind cluster
    python tasks.py --help

On Windows use `py tasks.py ...` if `python` isn't on PATH.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
IS_WINDOWS = os.name == "nt"
BIN = VENV / ("Scripts" if IS_WINDOWS else "bin")
PY = BIN / ("python.exe" if IS_WINDOWS else "python")


def run(*cmd: str | os.PathLike, env: dict[str, str] | None = None, check: bool = True) -> int:
    printable = " ".join(str(c) for c in cmd)
    print(f"> {printable}", flush=True)
    merged = {**os.environ, **(env or {})}
    try:
        return subprocess.run([str(c) for c in cmd], cwd=ROOT, env=merged, check=check).returncode
    except FileNotFoundError:
        sys.exit(f"command not found: {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)


def need_venv() -> None:
    if not PY.exists():
        sys.exit("No virtualenv yet. Run: python tasks.py install")


def _engine_os() -> str | None:
    """'linux' / 'windows' if the Docker engine answers, None if it doesn't."""
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.OSType}}"],
                           capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = r.stdout.strip().lower()
    return out if r.returncode == 0 and out else None


def _start_docker_desktop() -> bool:
    """Try to launch Docker Desktop on Windows/macOS. Returns True if launched."""
    if IS_WINDOWS:
        candidates = [Path(os.environ.get(v, "")) / "Docker" / "Docker" / "Docker Desktop.exe"
                      for v in ("ProgramFiles", "ProgramW6432", "LOCALAPPDATA")]
        for exe in candidates:
            if exe.is_file():
                subprocess.Popen([str(exe)], close_fds=True)
                return True
    elif sys.platform == "darwin":
        return subprocess.run(["open", "-a", "Docker"], capture_output=True).returncode == 0
    return False


def ensure_docker() -> None:
    """Fail early with a useful message instead of Docker's raw pipe/socket error,
    and start Docker Desktop if it's installed but not running."""
    if shutil.which("docker") is None:
        sys.exit("Docker is not installed or not on PATH. Install Docker Desktop (Windows/macOS) "
                 "or Docker Engine (Linux), then try again.")
    engine = _engine_os()
    if engine is None and _start_docker_desktop():
        print("Docker Desktop isn't running; starting it (this can take a minute)...", flush=True)
        deadline = time.monotonic() + 180
        while engine is None and time.monotonic() < deadline:
            time.sleep(3)
            engine = _engine_os()
    if engine is None:
        if IS_WINDOWS:
            hint = ("Start Docker Desktop from the Start menu and wait until it says "
                    "'Engine running', then run this again.")
        elif sys.platform == "darwin":
            hint = "Start Docker Desktop (or Colima/OrbStack) and wait until it's running, then run this again."
        else:
            hint = ("Start the daemon (`sudo systemctl start docker`) and make sure your user can use it "
                    "(`sudo usermod -aG docker $USER`, then log out and back in).")
        sys.exit(f"Docker is installed but the Docker engine isn't reachable.\n{hint}")
    if engine != "linux":
        sys.exit("Docker is in Windows-containers mode. Right-click the Docker Desktop tray icon and "
                 "choose 'Switch to Linux containers...', then run this again.")


def docker_compose() -> list[str]:
    ensure_docker()
    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    sys.exit("Docker Compose v2 is required (`docker compose`).")


def compose_env() -> dict[str, str]:
    """Group id of the Docker socket, so the containerized API (`up-full`) can
    start sandboxes. Docker Desktop (Windows/macOS) exposes it as group 0."""
    gid = "0"
    sock = Path("/var/run/docker.sock")
    if sys.platform.startswith("linux") and sock.exists():
        gid = str(sock.stat().st_gid)
    return {"DOCKER_GID": os.environ.get("DOCKER_GID", gid)}


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
def t_install(_: list[str]) -> None:
    if sys.version_info < (3, 11):
        sys.exit(f"Python 3.11+ required, found {sys.version.split()[0]}")
    if not PY.exists():
        run(sys.executable, "-m", "venv", VENV)
    run(PY, "-m", "pip", "install", "-U", "pip")
    run(PY, "-m", "pip", "install", "-e", ".[dev]")
    t_env([])
    print("\nInstalled. Next: python tasks.py up")


def t_env(_: list[str]) -> None:
    env, example = ROOT / ".env", ROOT / ".env.example"
    if not env.exists():
        shutil.copyfile(example, env)
        print("created .env from .env.example")


# ---------------------------------------------------------------------------
# .env helpers and host-port conflicts
# ---------------------------------------------------------------------------
ENV_FILE = ROOT / ".env"
# (port variable, default, service, URL variables in .env whose port must follow)
PORTS = [
    ("POSTGRES_PORT", 5432, "postgres", ["DATABASE_URL", "MIGRATION_DATABASE_URL"]),
    ("REDIS_PORT", 6379, "redis", ["REDIS_URL"]),
    ("JAEGER_UI_PORT", 16686, "jaeger", []),
    ("OTLP_GRPC_PORT", 4317, "jaeger", ["OTEL_EXPORTER_OTLP_ENDPOINT"]),
    ("OTLP_HTTP_PORT", 4318, "jaeger", []),
]


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                # Inline comments ("KEY=value   # note"), as in .env.example; Compose and dotenv strip them too.
                values[k.strip()] = v.split(" #", 1)[0].split("\t#", 1)[0].strip()
    return values


def set_env(updates: dict[str, str]) -> None:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    done = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in updates:
            lines[i] = f"{key}={updates[key]}"
            done.add(key)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in done]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def port_busy(port: int) -> bool:
    """True if something already listens on localhost:port. Tries a connect as
    well as a bind: on Windows a program listening on 0.0.0.0 doesn't stop
    another one binding 127.0.0.1, so a bind test alone says "free" while
    connections to localhost would still reach the other program."""
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((addr, port)) == 0:
                    return True
        except OSError:
            pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
    except OSError:
        return True
    return False


def free_port(start: int) -> int:
    for port in range(start + 1, start + 200):
        if not port_busy(port):
            return port
    sys.exit(f"no free port found near {start}")


def running_services(dc: list[str]) -> set[str]:
    r = subprocess.run([*dc, "ps", "--status", "running", "--services"], cwd=ROOT,
                       capture_output=True, text=True, env={**os.environ, **compose_env()})
    return set(r.stdout.split()) if r.returncode == 0 else set()


def resolve_port_conflicts(dc: list[str]) -> None:
    """If another program (a locally installed PostgreSQL or Redis, another
    project's containers...) already owns a port, move ours to a free one and
    point the URLs in .env at it, instead of failing or, worse, silently
    talking to the wrong database."""
    env = read_env()
    ours = running_services(dc)
    updates: dict[str, str] = {}
    for var, default, service, url_vars in PORTS:
        port = int(env.get(var, default))
        if service in ours or not port_busy(port):
            continue
        new = free_port(port)
        print(f"Port {port} is already used by another program on this machine; "
              f"using {new} for {service} instead (saved in .env as {var}).", flush=True)
        updates[var] = str(new)
        for uv in url_vars:
            if uv in env:  # replace the port right after the host: ...@host:PORT/ or ://host:PORT/
                updates[uv] = re.sub(r"((?:@|://)[^/:@]+):\d+", rf"\g<1>:{new}", env[uv], count=1)
    if updates:
        set_env(updates)


def verify_host_postgres() -> None:
    """Check that, from this machine, the configured URL reaches the container's
    Postgres and not some other server on the same port."""
    if not PY.exists():
        return
    url = read_env().get("MIGRATION_DATABASE_URL")
    if not url:
        return
    probe = ("import sys, psycopg\n"
             "with psycopg.connect(sys.argv[1], connect_timeout=5) as c:\n"
             "    print(c.execute(\"select current_setting('data_directory')\").fetchone()[0])\n")
    r = subprocess.run([str(PY), "-c", probe, url], capture_output=True, text=True)
    if r.returncode != 0 or r.stdout.strip() != "/var/lib/postgresql/data":
        detail = (r.stderr.strip().splitlines() or [r.stdout.strip()])[-1]
        sys.exit("The containers are up, but MIGRATION_DATABASE_URL in .env doesn't reach the container's "
                 f"Postgres from this machine ({detail}).\nAnother PostgreSQL may be listening on the same "
                 "port: stop it, or set POSTGRES_PORT in .env to a free port and fix the two database URLs, "
                 "then run `python tasks.py down` and `python tasks.py up`.")


def t_up(_: list[str]) -> None:
    t_env([])
    (ROOT / ".workspaces").mkdir(exist_ok=True)
    dc = docker_compose()
    resolve_port_conflicts(dc)
    run(*dc, "up", "-d", "--wait", "postgres", "redis", "jaeger", env=compose_env())
    # --no-deps: the services were just started and are healthy. Without it,
    # `compose run` tries to start postgres a second time, which fails on some
    # Docker Desktop versions with "port is already allocated".
    run(*dc, "run", "--rm", "--no-deps", "migrate", env=compose_env())
    verify_host_postgres()
    env = read_env()
    print("\nServices are up:\n"
          f"  Postgres   127.0.0.1:{env.get('POSTGRES_PORT', 5432)}\n"
          f"  Redis      127.0.0.1:{env.get('REDIS_PORT', 6379)}\n"
          f"  Jaeger UI  http://127.0.0.1:{env.get('JAEGER_UI_PORT', 16686)}  "
          f"(traces arrive on {env.get('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://127.0.0.1:4317')})\n"
          "Next: python tasks.py sandbox-image, then python tasks.py dev")


def t_check(args: list[str]) -> None:
    """End-to-end feature check of a running API (python tasks.py dev in another terminal)."""
    env = read_env()
    if env.get("AUTH_MODE") == "oidc" and env.get("OIDC_ISSUER", "").rstrip("/").endswith("/realms/harnis") \
            and not any(a.split("=")[0] in ("--admin-token", "--env-file", "--jwt-secret") for a in args):
        return t_sso_check(args)  # local Keycloak: use its tokens
    cmd = [sys.executable, str(ROOT / "scripts" / "harnis_check.py")]
    if not any(a.startswith("--api") for a in args):
        cmd += ["--api", "http://127.0.0.1:8000"]
    creds = ("--env-file", "--jwt-secret", "--admin-token", "--dev-token")
    if not any(a.split("=")[0] in creds for a in args) and env.get("AUTH_MODE", "local") == "local" and ENV_FILE.exists():
        cmd += ["--env-file", str(ENV_FILE)]
    sys.exit(subprocess.run([*cmd, *args], cwd=ROOT).returncode)


def t_status(_: list[str]) -> None:
    """What is running, and whether each endpoint in .env answers."""
    env = read_env()
    rows = [
        ("Postgres", *_host_port(env.get("DATABASE_URL", "postgresql://127.0.0.1:5432/harnis"), 5432), ""),
        ("Redis", *_host_port(env.get("REDIS_URL", "redis://127.0.0.1:6379/0"), 6379), ""),
        ("Trace collector (OTLP)", *_host_port(env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317"),
                                               4317),
         "" if env.get("OTEL_ENABLED", "false").lower() in ("1", "true", "yes") else "(OTEL_ENABLED is off)"),
        ("Jaeger UI", "127.0.0.1", int(env.get("JAEGER_UI_PORT", 16686)), ""),
        ("API", "127.0.0.1", 8000, ""),
    ]
    for name, host, port, note in rows:
        try:
            with socket.create_connection((host, port), timeout=1):
                state = "up"
        except OSError:
            state = "DOWN"
        print(f"  {state:5} {name:24} {host}:{port} {note}")
    if shutil.which("docker"):
        print()
        subprocess.run([*docker_compose(), "ps"], cwd=ROOT, env={**os.environ, **compose_env()})


def t_up_full(_: list[str]) -> None:
    t_up([])
    t_sandbox_image([])
    run(*docker_compose(), "--profile", "full", "up", "-d", "--build", "api", env=compose_env())
    print("API container on http://127.0.0.1:8000")


def t_down(_: list[str]) -> None:
    run(*docker_compose(), "--profile", "full", "down", env=compose_env())


def t_sandbox_image(_: list[str]) -> None:
    ensure_docker()
    run("docker", "build", "-f", "Dockerfile.sandbox", "-t", "harnis-sandbox:latest", ".")


def _host_port(url: str, default_port: int) -> tuple[str, int]:
    from urllib.parse import urlsplit
    u = urlsplit(url)
    return u.hostname or "127.0.0.1", u.port or default_port


def check_services() -> None:
    """Before starting the API, make sure Postgres and Redis answer where .env
    says they are, and explain what to do if they don't."""
    env = read_env()
    targets = [
        ("Postgres", "DATABASE_URL", "postgresql://127.0.0.1:5432/harnis", 5432, "POSTGRES_PORT"),
        ("Redis", "REDIS_URL", "redis://127.0.0.1:6379/0", 6379, "REDIS_PORT"),
    ]
    problems = []
    for name, var, default_url, default_port, port_var in targets:
        host, port = _host_port(env.get(var, default_url), default_port)
        try:
            with socket.create_connection((host, port), timeout=2):
                pass
        except OSError:
            problems.append(f"  - {name} is not reachable at {host}:{port} ({var} in .env; "
                            f"the container publishes {port_var}={env.get(port_var, default_port)})")
    if env.get("OTEL_ENABLED", "false").lower() in ("1", "true", "yes"):
        host, port = _host_port(env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317"), 4317)
        try:
            with socket.create_connection((host, port), timeout=2):
                pass
        except OSError:
            print(f"Note: tracing is on (OTEL_ENABLED=true) but no collector answers at {host}:{port}, so the "
                  "Jaeger UI will stay empty.\n      `python tasks.py up` starts Jaeger; `python tasks.py status` "
                  "shows what is running. Starting the API with tracing off for this run.\n", flush=True)
            os.environ["OTEL_ENABLED"] = "false"
    if problems:
        sys.exit("Can't start the API:\n" + "\n".join(problems) + "\n\n"
                 "Start the services with `python tasks.py up` (check them with `docker compose ps`).\n"
                 "If they are running, the port in the URL and the *_PORT value in .env must match; "
                 "after changing a *_PORT value run `python tasks.py down` then `python tasks.py up`.")


# ---------------------------------------------------------------------------
# Model prices
# ---------------------------------------------------------------------------
# provider -> (setting that enables it, main-model setting, fast-model setting)
PROVIDER_MODELS = {
    "anthropic": (("ANTHROPIC_API_KEY",), "ANTHROPIC_MODEL", "ANTHROPIC_FAST_MODEL"),
    "openai": (("OPENAI_API_KEY",), "OPENAI_MODEL", "OPENAI_FAST_MODEL"),
    "openai_compatible": (("OPENAI_COMPATIBLE_BASE_URL",), "OPENAI_COMPATIBLE_MODEL", "OPENAI_COMPATIBLE_FAST_MODEL"),
    "gemini": (("GEMINI_API_KEY", "GOOGLE_API_KEY", "GEMINI_USE_VERTEXAI"), "GEMINI_MODEL", "GEMINI_FAST_MODEL"),
    "nova": (("AWS_REGION",), "NOVA_MODEL", "NOVA_FAST_MODEL"),
}
PRICING_PAGES = {
    "anthropic": "https://www.anthropic.com/pricing",
    "openai": "https://openai.com/api/pricing/",
    "gemini": "https://ai.google.dev/pricing",
    "nova": "https://aws.amazon.com/bedrock/pricing/",
    "openai_compatible": "your provider or your own hosting cost (0 for self-hosted)",
}


def _example_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip()] = v.split(" #", 1)[0].strip()
    return values


def configured_models(env: dict[str, str]) -> list[tuple[str, str]]:
    """(provider, model) for every provider in LLM_PROVIDERS that has credentials."""
    defaults = _example_env()
    chain = [p.strip() for p in env.get("LLM_PROVIDERS", defaults.get("LLM_PROVIDERS", "")).split(",") if p.strip()]
    out: list[tuple[str, str]] = []
    for provider in chain:
        if provider not in PROVIDER_MODELS:
            continue
        enablers, main, fast = PROVIDER_MODELS[provider]
        if not any(env.get(e, "").strip() and env.get(e, "").strip().lower() != "false" for e in enablers):
            continue
        for var in (main, fast):
            model = env.get(var) or defaults.get(var) or env.get(main) or defaults.get(main)
            if model and (provider, model) not in out:
                out.append((provider, model))
    return out


def _confirmed_prices(env: dict[str, str]) -> dict[str, list[float]]:
    raw = env.get("PRICING_OVERRIDES", "").strip()
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        print("PRICING_OVERRIDES in .env is not valid JSON; it will be replaced.")
        return {}


def effective_env() -> dict[str, str]:
    """What the API will see: .env, overridden by the process environment
    (pydantic settings give environment variables precedence over .env)."""
    env = read_env()
    keys = set(env) | {k for _, (enablers, main, fast) in PROVIDER_MODELS.items() for k in (*enablers, main, fast)}
    keys |= {"LLM_PROVIDERS", "PRICING_OVERRIDES", "PRICING_FILE"}
    return {**env, **{k: os.environ[k] for k in keys if os.environ.get(k)}}


def warn_shell_credentials() -> None:
    """Provider keys exported in the shell override .env without anyone noticing
    (for example an ANTHROPIC_API_KEY set for another tool)."""
    env = read_env()
    for _, (enablers, _m, _f) in PROVIDER_MODELS.items():
        for k in enablers:
            if os.environ.get(k) and os.environ.get(k) != env.get(k):
                print(f"Note: {k} is set in your shell environment and overrides .env, so the API will use it.\n"
                      f"      Unset it (or run with `env -u {k}`) if you didn't mean to.", flush=True)


def unpriced(env: dict[str, str]) -> list[tuple[str, str]]:
    confirmed = _confirmed_prices(env)
    if env.get("PRICING_FILE"):
        try:
            confirmed.update(json.loads((ROOT / env["PRICING_FILE"]).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    def known(m: str) -> bool:
        return m in confirmed or any(m.startswith(p) and m[len(p):] in confirmed
                                     for p in ("us.", "eu.", "jp.", "apac.", "au.", "ca.", "us-gov.", "global."))
    return [(p, m) for p, m in configured_models(env) if not known(m)]


def _reference_prices() -> dict[str, list[float]]:
    if not PY.exists():
        return {}
    r = subprocess.run([str(PY), "-c", "import json; from harnis.llm.pricing import REFERENCE_PRICES as R; "
                        "print(json.dumps(R))"], capture_output=True, text=True, cwd=ROOT)
    try:
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except ValueError:
        return {}


def t_pricing(args: list[str]) -> None:
    """Ask for the price of every model Harnis is configured to call; save them as PRICING_OVERRIDES."""
    t_env([])
    env = effective_env()
    models = configured_models(env) if "--all" in args else unpriced(env)
    if not models:
        if not configured_models(env):
            print("No model provider is configured with credentials in .env (only the offline mock, which is free).")
        else:
            print("Every configured model has a confirmed price. Use `python tasks.py pricing --all` to change them.")
        return
    if not sys.stdin.isatty():
        print("These models need prices; run `python tasks.py pricing` in a terminal, or set PRICING_OVERRIDES:")
        for p, m in models:
            print(f"  {m} ({p})")
        return
    ref = _reference_prices()
    confirmed = _confirmed_prices(env)
    print("Prices are in US dollars per million tokens (input, output). Cost figures, per-turn cost budgets\n"
          "and tenant cost caps depend on them. Check each provider's current pricing page.\n")
    for provider, model in models:
        bare = next((model[len(p):] for p in ("us.", "eu.", "jp.", "apac.", "au.", "ca.", "us-gov.", "global.")
                     if model.startswith(p)), model)
        hint = confirmed.get(model) or ref.get(model) or ref.get(bare)
        print(f"{model}  ({provider}; see {PRICING_PAGES.get(provider, 'the provider pricing page')})")
        while True:
            shown = f" [{hint[0]}, {hint[1]}: Enter accepts after you've checked them]" if hint else ""
            try:
                answer = input(f"  input, output USD per million tokens{shown}: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled; nothing was saved.")
                return
            if not answer and hint:
                value = [float(hint[0]), float(hint[1])]
            else:
                parts = [x for x in re.split(r"[,\s]+", answer) if x]
                try:
                    value = [float(parts[0]), float(parts[1])]
                    if min(value) < 0:
                        raise ValueError
                except (ValueError, IndexError):
                    print("  Enter two non-negative numbers, for example: 3, 15")
                    continue
            confirmed[model] = value
            break
    set_env({"PRICING_OVERRIDES": json.dumps(confirmed, separators=(", ", ": "))})
    print("\nSaved to PRICING_OVERRIDES in .env. Restart the API to apply them.")


def ask_for_prices_if_missing() -> None:
    env = effective_env()
    missing = unpriced(env)
    if not missing:
        return
    names = ", ".join(m for _, m in missing)
    print(f"Model prices are not confirmed for: {names}.\nCost figures and budgets use reference prices that may "
          "be out of date (production refuses to start without confirmed prices).")
    try:
        enter = sys.stdin.isatty() and input("Enter them now? [Y/n] ").strip().lower() in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        enter = False
    if enter:
        t_pricing([])
    else:
        print("Run `python tasks.py pricing` when you're ready.\n")


def t_dev(args: list[str]) -> None:
    need_venv()
    t_env([])
    warn_shell_credentials()
    ask_for_prices_if_missing()
    check_services()
    # Watch only the package: agents write .py files into WORKSPACES_DIR (.workspaces by default),
    # and reloading on those restarts the API in the middle of turns.
    run(PY, "-m", "uvicorn", "harnis.api:create_app", "--factory", "--reload", "--reload-dir", "harnis",
        "--host", "127.0.0.1", "--port", "8000", *args)


def t_migrate(_: list[str]) -> None:
    need_venv()
    run(PY, "-m", "harnis.migrate", "--seed", "demo")


def t_token(args: list[str]) -> None:
    need_venv()
    ap = argparse.ArgumentParser(prog="tasks.py token")
    default_user = re.sub(r"[^A-Za-z0-9_.-]", "-", getpass.getuser()) or "dev"
    ap.add_argument("--user", default=default_user)
    ap.add_argument("--tenant", default="acme")
    ap.add_argument("--roles", default="user,reviewer")
    a = ap.parse_args(args)
    run(PY, "-m", "harnis.auth", "mint", "--user", a.user, "--tenant", a.tenant, "--roles", a.roles)


def t_cli(args: list[str]) -> None:
    """Runs harnis; mints a dev token automatically if HARNIS_TOKEN is unset."""
    need_venv()
    env = {}
    if not os.environ.get("HARNIS_TOKEN"):
        out = subprocess.run([str(PY), "-m", "harnis.auth", "mint", "--user", "dev", "--tenant", "acme",
                              "--roles", "user,reviewer"], cwd=ROOT, capture_output=True, text=True, check=True)
        env["HARNIS_TOKEN"] = out.stdout.strip()
    run(PY, "-m", "harnis.cli", *args, env=env, check=False)


def t_test(args: list[str]) -> None:
    need_venv()
    suites = {"unit": ["-m", "not integration and not sandbox"], "integration": ["-m", "integration"],
              "keycloak": ["-m", "keycloak"],
              "sandbox": ["-m", "sandbox"], "browser": ["-m", "browser"], "all": []}
    which = args[0] if args and args[0] in suites else "all"
    rest = args[1:] if args and args[0] in suites else args
    run(PY, "-m", "pytest", *suites[which], *rest)


def t_redteam(args: list[str]) -> None:
    need_venv()
    run(PY, "redteam/run.py", *args)


def t_eval(args: list[str]) -> None:
    """Run the eval suite against the running API (start it with `tasks.py dev`)."""
    need_venv()
    code = run(PY, "-m", "harnis.evals", *args, check=False)
    sys.exit(code)


def t_maintenance(_: list[str]) -> None:
    need_venv()
    run(PY, "-m", "harnis.maintenance")


def t_clean(_: list[str]) -> None:
    for pattern in ("**/__pycache__", "**/.pytest_cache", "*.egg-info"):
        for p in ROOT.glob(pattern):
            if ".venv" not in p.parts:
                shutil.rmtree(p, ignore_errors=True)
    shutil.rmtree(ROOT / ".workspaces", ignore_errors=True)
    print("cleaned")


# ---------------------------------------------------------------------------
# Backup and restore (database + workspaces)
# ---------------------------------------------------------------------------
def _pg_bin_prefix() -> str:
    """Run pg_dump/pg_restore in the local stack's Postgres container when it is
    running (matching server version), else use the ones on PATH."""
    if shutil.which("docker"):
        try:
            if "postgres" in running_services(docker_compose()):
                return " ".join(docker_compose()) + " exec -T postgres"
        except SystemExit:
            pass
    if shutil.which("pg_dump"):
        return ""
    sys.exit("pg_dump not found: start the local stack (python tasks.py up) or install the PostgreSQL client tools.")


def t_backup(args: list[str]) -> None:
    """Back up the database and the workspaces into backups/harnis-<timestamp>/."""
    need_venv()
    run(PY, "-m", "harnis.backup", "create", "--pg-bin", _pg_bin_prefix(), *args)


def t_restore(args: list[str]) -> None:
    """Restore a backup (replaces the database and workspaces): tasks.py restore backups/harnis-... --yes"""
    need_venv()
    if not args:
        sys.exit("usage: python tasks.py restore backups/harnis-<timestamp> --yes")
    run(PY, "-m", "harnis.backup", "restore", *args, "--pg-bin", _pg_bin_prefix())


# ---------------------------------------------------------------------------
# Local single sign-on with Keycloak (LOCAL TESTING ONLY, see docs/keycloak.md)
# ---------------------------------------------------------------------------
KEYCLOAK_HELPER = ROOT / "scripts" / "keycloak_local.py"
# What sso-up changes in .env; the previous values are kept in SSO_PREVIOUS_SETTINGS
# (JSON, null = the key wasn't there) so sso-down can put them back.
SSO_KEYS = ["AUTH_MODE", "OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_USER_CLAIM", "OIDC_TENANT_CLAIM",
            "OIDC_ROLES_CLAIM", "OIDC_ROLE_MAP", "OIDC_CONSOLE_CLIENT_ID"]
SSO_BACKUP = "SSO_PREVIOUS_SETTINGS"


def _keycloak_url(env: dict[str, str]) -> str:
    return f"http://127.0.0.1:{env.get('KEYCLOAK_PORT', '8080')}"


def _unset_env(keys: list[str]) -> None:
    if not ENV_FILE.exists():
        return
    lines = [ln for ln in ENV_FILE.read_text(encoding="utf-8").splitlines()
             if ln.lstrip().startswith("#") or "=" not in ln or ln.split("=", 1)[0].strip() not in keys]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def t_sso_up(_: list[str]) -> None:
    """Keycloak with the "harnis" realm, and .env switched to AUTH_MODE=oidc against it."""
    t_env([])
    dc = docker_compose()
    env = read_env()
    port = int(env.get("KEYCLOAK_PORT", 8080))
    if "keycloak" not in running_services(dc) and port_busy(port):
        new = free_port(port)
        print(f"Port {port} is already used by another program; using {new} for Keycloak "
              "(saved in .env as KEYCLOAK_PORT).", flush=True)
        set_env({"KEYCLOAK_PORT": str(new)})
        env = read_env()
    url = _keycloak_url(env)
    run(*dc, "--profile", "sso", "up", "-d", "keycloak",
        env={**compose_env(), "KEYCLOAK_PORT": env.get("KEYCLOAK_PORT", "8080")})
    run(sys.executable, KEYCLOAK_HELPER, "wait", "--url", url, "--timeout", "240")
    out = subprocess.run([sys.executable, str(KEYCLOAK_HELPER), "env", "--url", url, "--json"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    settings = json.loads(out)
    if SSO_BACKUP not in env:  # keep the original settings, not the ones from an earlier sso-up
        set_env({SSO_BACKUP: json.dumps({k: env.get(k) for k in SSO_KEYS}, separators=(",", ":"))})
    set_env(settings)
    print("\nKeycloak is up (LOCAL TESTING ONLY):\n"
          f"  Admin console  {url}/admin  (admin / admin)\n"
          f"  Realm          {settings['OIDC_ISSUER']}\n"
          "  Test users     alice (user), rita (reviewer), adam (admin) in acme; gina (admin) in globex;\n"
          "                 ops (platform-admin). Password for all: harnis-local-only\n"
          ".env now has AUTH_MODE=oidc. Restart `python tasks.py dev`, open http://127.0.0.1:8000 and\n"
          "click 'Sign in with SSO'. Feature check: python tasks.py sso-check. Undo: python tasks.py sso-down")


def t_sso_down(_: list[str]) -> None:
    """Stop Keycloak and restore the auth settings .env had before sso-up."""
    run(*docker_compose(), "--profile", "sso", "rm", "--stop", "--force", "keycloak", env=compose_env())
    env = read_env()
    if SSO_BACKUP not in env:
        print("No saved settings from sso-up; .env left as it is.")
        return
    previous = json.loads(env[SSO_BACKUP])
    set_env({k: v for k, v in previous.items() if v is not None})
    _unset_env([k for k, v in previous.items() if v is None] + [SSO_BACKUP])
    print(f"Restored AUTH_MODE={previous.get('AUTH_MODE') or 'local'} in .env. Restart `python tasks.py dev`.")


def t_sso_check(args: list[str]) -> None:
    """harnis_check against the running API with Keycloak-issued tokens (adam, gina, ops)."""
    cmd = [sys.executable, str(KEYCLOAK_HELPER), "check", "--url", _keycloak_url(read_env())]
    if not any(a.startswith("--api") for a in args):
        cmd += ["--api", "http://127.0.0.1:8000"]
    sys.exit(subprocess.run([*cmd, *args], cwd=ROOT).returncode)


# ---------------------------------------------------------------------------
# gVisor and local Kubernetes (kind)
# ---------------------------------------------------------------------------
def t_gvisor_check(args: list[str]) -> None:
    """Sandbox tests under gVisor (runsc). Linux or WSL2 with Docker Engine; see docs/gvisor.md."""
    ensure_docker()
    cmd = [sys.executable, str(ROOT / "scripts" / "gvisor_check.py")]
    if PY.exists() and not any(a.startswith("--python") for a in args):
        cmd += ["--python", str(PY)]
    sys.exit(subprocess.run([*cmd, *args], cwd=ROOT).returncode)


def _k8s_local(sub: str, args: list[str]) -> None:
    sys.exit(subprocess.run([sys.executable, str(ROOT / "scripts" / "k8s_local.py"), sub, *args],
                            cwd=ROOT).returncode)


def t_k8s_up(args: list[str]) -> None:
    _k8s_local("up", args)


def t_k8s_check(args: list[str]) -> None:
    _k8s_local("check", args)


def t_k8s_down(args: list[str]) -> None:
    _k8s_local("down", args)


def t_load(args: list[str]) -> None:
    """Concurrent users against the running API (mock model); see scripts/load_test.py --help."""
    cmd = [sys.executable, str(ROOT / "scripts" / "load_test.py")]
    if not any(a.startswith("--env-file") or a.startswith("--jwt-secret") for a in args) and ENV_FILE.exists():
        cmd += ["--env-file", str(ENV_FILE)]
    sys.exit(subprocess.run([*cmd, *args], cwd=ROOT).returncode)


TASKS = {
    "install": (t_install, "create .venv and install the package with dev extras"),
    "env": (t_env, "create .env from .env.example if missing"),
    "up": (t_up, "start Postgres, Redis, Jaeger; run migrations + demo seed"),
    "up-full": (t_up_full, "also run the API in a container (dev only: uses the Docker socket)"),
    "down": (t_down, "stop the containers (keeps the database volume)"),
    "sandbox-image": (t_sandbox_image, "build the image agent commands run in"),
    "dev": (t_dev, "run the API locally with auto-reload"),
    "migrate": (t_migrate, "apply migrations from this machine (Postgres must be reachable)"),
    "token": (t_token, "print a dev JWT  [--user U --tenant T --roles user,reviewer]"),
    "cli": (t_cli, "run the coding agent CLI  (args after --)"),
    "test": (t_test, "run tests  [unit|integration|sandbox|all] [pytest args]"),
    "redteam": (t_redteam, "attack a running API"),
    "eval": (t_eval, "run the eval cases against the running API  [--providers mock,gemini --repeat 3]"),
    "status": (t_status, "which services are running and reachable"),
    "pricing": (t_pricing, "enter the prices of your configured models (--all to change confirmed ones)"),
    "check": (t_check, "end-to-end feature check against the running API (scripts/harnis_check.py)"),
    "maintenance": (t_maintenance, "ledger partitions + analytics refresh (run hourly)"),
    "backup": (t_backup, "back up the database and workspaces into backups/"),
    "restore": (t_restore, "restore a backup: tasks.py restore backups/harnis-... --yes"),
    "load": (t_load, "load test the running API with concurrent users (scripts/load_test.py)"),
    "sso-up": (t_sso_up, "local Keycloak SSO (realm harnis) and AUTH_MODE=oidc in .env (testing only)"),
    "sso-down": (t_sso_down, "stop Keycloak and restore the previous auth settings in .env"),
    "sso-check": (t_sso_check, "feature check with Keycloak-issued tokens (python tasks.py dev running)"),
    "gvisor-check": (t_gvisor_check, "check runsc and run the sandbox tests under gVisor (Linux/WSL2)"),
    "k8s-up": (t_k8s_up, "local kind cluster: build + load images, Postgres/Redis, Helm release"),
    "k8s-check": (t_k8s_check, "feature check against the kind cluster through a port-forward"),
    "k8s-down": (t_k8s_down, "delete the local kind cluster"),
    "clean": (t_clean, "remove caches and session workspaces"),
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        for name, (_, desc) in TASKS.items():
            print(f"  {name:<15} {desc}")
        return
    name, args = sys.argv[1], sys.argv[2:]
    if args and args[0] == "--":
        args = args[1:]
    if name not in TASKS:
        sys.exit(f"unknown task {name!r}; run: python tasks.py --help")
    TASKS[name][0](args)


if __name__ == "__main__":
    main()

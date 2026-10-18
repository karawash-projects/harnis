# Running Harnis sandboxes under gVisor

Harnis runs every agent command in a throwaway, locked-down container (see
`harnis/sandbox.py`). With the default Docker runtime (`runc`) that container
still shares the host's Linux kernel: a single kernel bug reachable through a
system call is enough for hostile code to escape. [gVisor](https://gvisor.dev)
puts an application kernel (the *Sentry*, written in Go) between the
container and the host kernel. The sandboxed program's system calls are
handled by the Sentry, which itself uses a small, filtered set of host system
calls, so the host kernel's attack surface shrinks dramatically.

Use gVisor whenever agents run code you did not write: anything that came from
the internet, a pull request, a customer upload or a model.

| Where Harnis runs | How to turn gVisor on |
|---|---|
| Docker (`SANDBOX_BACKEND=docker`, the default) | install `runsc` on the Docker host and set `SANDBOX_RUNTIME=runsc` |
| Kubernetes (Helm chart) | a `RuntimeClass` with handler `runsc` on the sandbox nodes and `sandbox.runtimeClassName` (see [kubernetes.md](kubernetes.md#gvisor-runtimeclass-recommended)) |

This guide covers the Docker path and how to test it on your machine before
production. Two tests are provided:

* `python scripts/gvisor_check.py` (also `python tasks.py gvisor-check`): checks that
  the Docker engine has a `runsc` runtime, that a container started with it is
  really gVisor, and runs the Harnis sandbox test suite with every sandbox
  forced onto `runsc`.
* `.github/workflows/gvisor.yml`: the same check on GitHub Actions on every push
  and pull request.

## Windows: use WSL2 with Docker Engine

gVisor is Linux-only. **Docker Desktop cannot run it**: its engine lives in a
VM that Docker Desktop manages, and you cannot add an OCI runtime such as
`runsc` to it. On Windows you therefore run a real Docker Engine inside a WSL2
Linux distro and install gVisor there.

### 1. Enable WSL2 and install Ubuntu

In PowerShell **as Administrator**:

```powershell
wsl --install -d Ubuntu-24.04
```

Reboot if asked, open "Ubuntu 24.04" from the Start menu and create your Linux
user. Check it is WSL **2** (`wsl -l -v` in PowerShell shows `VERSION 2`; if
not: `wsl --set-version Ubuntu-24.04 2`).

### 2. Keep Docker Desktop out of this distro

If Docker Desktop is installed, its "WSL integration" puts its own `docker`
CLI into your distros, pointed at Docker Desktop's engine. That engine has no
`runsc`, and two engines fighting over one distro is confusing. Pick one:

* **Turn the integration off for this distro**: Docker Desktop > Settings >
  Resources > WSL integration > switch off `Ubuntu-24.04` > Apply & restart.
* **Or use a separate distro** just for gVisor (for example install
  `Ubuntu-24.04` for this while Docker Desktop keeps its integration with your
  usual `Ubuntu` distro).

You can keep using Docker Desktop on Windows for everything else (including
the kind cluster from [kubernetes.md](kubernetes.md#try-it-locally-with-kind)).
Both engines can run at the same time, but they are separate: images, volumes
and containers are not shared, and published ports on `localhost` can clash
(stop the Docker Desktop stack with `python tasks.py down` first, or let
`tasks.py up` move ports).

### 3. Make sure systemd is on

Docker Engine is managed by systemd. Ubuntu 24.04 on current WSL has it on by
default; check inside Ubuntu:

```bash
ps -p 1 -o comm=        # must print: systemd
```

If it prints `init`, enable it and restart WSL:

```bash
printf '[boot]\nsystemd=true\n' | sudo tee /etc/wsl.conf
```

```powershell
wsl --shutdown          # in PowerShell, then open Ubuntu again
```

### 4. Install Docker Engine inside Ubuntu

From the official instructions (<https://docs.docker.com/engine/install/ubuntu/>):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"     # then close and reopen the Ubuntu terminal
```

Check that `docker` now talks to the engine **inside** WSL, not Docker Desktop:

```bash
docker info --format '{{.OperatingSystem}}'   # "Ubuntu 24.04.x LTS", NOT "Docker Desktop"
which docker                                  # /usr/bin/docker
```

### 5. Install gVisor (runsc) from the official apt repository

From <https://gvisor.dev/docs/user_guide/install/>:

```bash
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc
```

### 6. Register runsc with Docker

The package configures Docker automatically when Docker is already installed.
To do it explicitly (safe to repeat):

```bash
sudo runsc install                 # adds "runsc" to /etc/docker/daemon.json
sudo systemctl restart docker
```

`runsc install` writes the equivalent of this `/etc/docker/daemon.json`
(merge by hand if you prefer, then restart Docker):

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
```

### 7. Verify

```bash
docker info --format '{{json .Runtimes}}'    # keys include "runsc"
docker run --rm --runtime=runsc hello-world
```

Get the code into the Linux filesystem (not `/mnt/c/...`, which is slow and
has Windows file semantics), build the sandbox image and look at the kernel
log a gVisor container sees (the sandbox image has no `dmesg`, so read it
with `klogctl`):

```bash
cd ~ && git clone <your Harnis repository URL> harnis && cd harnis
docker build -f Dockerfile.sandbox -t harnis-sandbox:latest .
docker run --rm --runtime=runsc harnis-sandbox:latest python3 -c \
  "import ctypes; b = ctypes.create_string_buffer(8192); n = ctypes.CDLL(None).klogctl(3, b, 8192); print(b.raw[:n].decode())"
# [    0.000000] Starting gVisor...
```

Under `runc` the same command prints nothing (non-root users cannot read the
host kernel log); under gVisor you see the Sentry's own boot messages.

### 8. Run Harnis inside WSL2 with gVisor

```bash
sudo apt-get install -y python3-venv python3-pip
python3 tasks.py install
python3 tasks.py gvisor-check        # runtime checks + sandbox tests under runsc
```

Then the whole stack, with every agent command in gVisor:

```bash
python3 tasks.py up                  # Postgres, Redis, Jaeger in the WSL Docker Engine
echo "SANDBOX_RUNTIME=runsc" >> .env
python3 tasks.py sandbox-image
python3 tasks.py dev                 # API on http://127.0.0.1:8000
```

WSL2 forwards `localhost`, so the console at <http://127.0.0.1:8000> opens in
your Windows browser. In a second Ubuntu terminal run the feature check, which
exercises approvals and sandbox commands end to end:

```bash
python3 tasks.py check
```

`SANDBOX_WORKSPACE_MODE=bind` also works under gVisor on Linux; the default
`copy` mode is what the checks exercise.

## Linux machines and servers

The same steps without WSL: install Docker Engine (step 4), gVisor (step 5),
register it (step 6), verify (step 7), then set `SANDBOX_RUNTIME=runsc` for the
API and run `python3 tasks.py gvisor-check` on that host. Do this on every host
that runs sandboxes, and re-run the check after Docker or gVisor upgrades.

## Continuous integration

`.github/workflows/gvisor.yml` runs on `ubuntu-latest` on every push and pull
request: it installs `runsc` from the official apt repository, runs
`sudo runsc install` and restarts Docker, builds `Dockerfile.sandbox`, installs
the package (`pip install -e ".[dev]"`) and runs `scripts/gvisor_check.py`.

## What gVisor treats differently

Harnis's Docker sandbox (`harnis/sandbox.py`) asks for these settings. How
`runsc` handles each one, checked against the gVisor source
(<https://github.com/google/gvisor>, master at commit `9e94959`, October 2026):

| Setting in `DockerSandbox` | Under runsc | Source |
|---|---|---|
| `network_mode="none"` | Supported. The sandbox gets gVisor's own network stack with loopback only. | gVisor docs, [Networking](https://gvisor.dev/docs/user_guide/networking/) |
| `read_only=True` (read-only root) | Supported. The Sentry mounts the root read-only, the Gofer remounts it read-only on the host side, and the default root overlay is turned off for a read-only root. | `runsc/boot/vfs.go` (`ReadOnly: c.root.Readonly`), `runsc/cmd/sandboxsetup/gofer_mount.go`, `runsc/container/container.go` (`overlayMedium = config.NoOverlay`) |
| `tmpfs /tmp: rw,noexec,nosuid,size=64m,mode=1777` | Supported. Allowed tmpfs data options are `mode`, `size`, `uid`, `gid`; `noexec` and `nosuid` are honoured as mount flags. | `runsc/boot/vfs.go` (`tmpfsAllowedData`, mount option parsing) |
| `cap_drop=["ALL"]` | Supported. Capabilities from the OCI spec are applied to the sandboxed process by the Sentry; `/proc/self/status` reports `CapEff`. | `runsc/specutils/specutils.go` (`Capabilities`), `pkg/sentry/fsimpl/proc/task_files.go` |
| `no-new-privileges:true` | Supported. `process.noNewPrivileges` is passed to the Sentry; `/proc/self/status` reports `NoNewPrivs`. | `runsc/boot/loader.go` (`NoNewPrivs: spec.Process.NoNewPrivileges`), `pkg/sentry/fsimpl/proc/task_files.go` |
| `mem_limit` / `memswap_limit`, `nano_cpus` | Supported, applied to the host cgroup of the whole sandbox (Sentry + Gofer + your program) and mirrored into the sandbox's own cgroupfs. The Sentry's own memory counts against the limit, so very small limits leave less for the program than under runc. | `runsc/cgroup/`, `runsc/boot/vfs.go` (`cgroupfsMemoryDefaults`, `cgroupfsCPUDefaults`) |
| `pids_limit` | **Different semantics.** runsc writes the limit to the sandbox's *host* cgroup (`pids.max`). That cgroup holds gVisor's own host tasks: the Sentry's threads, the Gofer, and, with the default `systrap` platform, one host *stub* process (plus its message threads) per sandboxed address space. Sandboxed processes themselves are Sentry tasks, and the Sentry's internal pids controller starts unlimited (runsc seeds only CPU and memory from the spec). So the limit bounds a fork bomb only indirectly: far fewer than `SANDBOX_PIDS_LIMIT` sandboxed processes fit, the number depends on the CPU count, and when the host limit is hit gVisor may fail `fork()` or abort the whole sandbox (the systrap code panics if it cannot create a stub thread). With the KVM platform there are no per-process stubs. The Sentry's absolute task cap is 65536. | `runsc/cgroup/cgroup.go`, `runsc/cgroup/cgroup_v2.go` (`pids.max`), `pkg/sentry/fsimpl/cgroupfs/pids.go`, `runsc/boot/vfs.go`, `pkg/sentry/platform/systrap/systrap.go` (`NewAddressSpace`), `pkg/sentry/platform/systrap/subprocess.go`, `pkg/sentry/kernel/threads.go` (`TasksLimit`) |
| anonymous volume at `/sandbox` + `put_archive` / `get_archive` | Works. The volume is a host directory mounted into the sandbox through the Gofer; volumes are not overlaid by default (`--overlay2=root:self` covers only the root mount) and use `--file-access-mounts=shared`, so files Docker writes before start are visible inside, and files written inside are on the host volume when `get_archive` reads it after the container exits. | `runsc/config/config.go` (`defaultOverlay2`), `runsc/config/flags.go` |
| `user="65534:65534"`, `working_dir`, `environment` | Supported (standard OCI process fields). | |

Consequences for Harnis:

* **Fork bombs.** `tests/test_sandbox.py::test_pid_limit_stops_fork_bomb`
  expects `fork()` to fail cleanly before 64 processes. Under gVisor the
  outcome depends on the platform and CPU count (see the table), so
  `gvisor_check` marks this one test as a non-strict expected failure: the
  output shows `XFAIL` (it failed) or `XPASS` (it passed) with the reason,
  and other failures still fail the run. `--strict` makes it a normal test.
  Either way the memory limit, CPU limit and wall-clock timeout still stop a
  fork bomb from hurting the host; under gVisor the worst case is that the
  one sandbox aborts.
* **Sentry threads and `pids_limit`.** Because the host `pids.max` also
  covers gVisor's own threads, a very low `SANDBOX_PIDS_LIMIT` can keep the
  sandbox from starting or make it abort under load. `gvisor_check` starts a
  container with the exact DockerSandbox flags to catch the first case; if
  sandboxes fail with errors about threads or stub processes, raise
  `SANDBOX_PIDS_LIMIT` (for example to 512).
* **Performance.** System calls and file I/O go through the Sentry and Gofer,
  so syscall-heavy work (package installs, `git`, test suites with many small
  files) is noticeably slower than under runc, and each container starts a
  little slower. CPU-bound code runs at close to native speed. Raise
  `SANDBOX_TIMEOUT_SECONDS` if commands that passed under runc time out.
* **Kernel version.** Programs see gVisor's synthetic kernel (`uname -r`
  differs from the host); a few rarely used system calls and `/proc` files are
  missing. Plain Python, pytest, shell and coreutils work.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `gvisor_check` says the engine is Docker Desktop | Your `docker` CLI in WSL talks to Docker Desktop. Turn off WSL integration for that distro (step 2), reopen the terminal, check `docker info --format '{{.OperatingSystem}}'`. |
| `unknown or invalid runtime name: runsc` | `runsc` is not registered: `sudo runsc install && sudo systemctl restart docker`. |
| `Cannot connect to the Docker daemon` in WSL | systemd is off (step 3) or Docker is stopped: `sudo systemctl start docker`. |
| `docker run --runtime=runsc` fails with a cryptic error | Turn on runsc debug logs: in `/etc/docker/daemon.json` set `"runtimeArgs": ["--debug-log=/tmp/runsc/", "--debug", "--strace"]` under `runtimes.runsc`, restart Docker, retry, read `/tmp/runsc/`. Remove the flags afterwards (they are slow and log syscalls). |
| Sandbox tests time out only under runsc | gVisor overhead on a slow disk or a busy laptop; run again, or keep the repository in the WSL filesystem rather than `/mnt/c`. |
| `test_pid_limit_stops_fork_bomb` shows `XFAIL` | Expected under gVisor, see above. |

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""netpol_window: measure the gap between a sandbox Pod starting and its NetworkPolicy taking effect.

Runs N trials in each of two modes against the current kubectl context (a
cluster where `helm install harnis` or `python scripts/k8s_local.py up` has
created the sandbox namespace, its NetworkPolicies and the sandbox image):

  check-off   the run-time isolation check is disabled; the first command in a
              fresh Pod tries to connect to an address outside the cluster.
              Successful connections show the window.
  check-on    the default check (API server + external address must both be
              blocked); the same command runs only if the check passes.
              A successful connection here would be a leak.

It also times a no-op command in both modes, which is the cost of the check.

    python scripts/netpol_window.py --trials 15 --report netpol.json
    python scripts/netpol_window.py --image harnis-sandbox:local --namespace harnis-sandbox

Needs `pip install "harnis[k8s]"` (the kubernetes client) and a kubeconfig that
points at the cluster. Pass --target to test another address.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

PROBE = ("import socket,sys\n"
         "try:\n"
         "    socket.create_connection(({host!r}, {port}), 3).close(); print('OPEN')\n"
         "except OSError:\n"
         "    print('BLOCKED')\n")


def classify(res) -> str:
    out = (res.output or "").strip()
    if res.error and "network access" in res.error:
        return "refused"  # the check refused to run the command
    if res.error:
        return "error"
    if "OPEN" in out:
        return "open"
    if "BLOCKED" in out:
        return "blocked"
    return "error"


def trial(sandbox, command: str) -> tuple[str, float, str]:
    with tempfile.TemporaryDirectory() as d:
        t0 = time.monotonic()
        res = sandbox.run(command, Path(d), timeout=30)
        return classify(res), time.monotonic() - t0, (res.error or res.output or "")[:200]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trials", type=int, default=15)
    ap.add_argument("--image", default="harnis-sandbox:local")
    ap.add_argument("--namespace", default="harnis-sandbox")
    ap.add_argument("--target", default="1.1.1.1:443", help="host:port outside the cluster")
    ap.add_argument("--report", default="netpol.json")
    a = ap.parse_args(argv)
    host, _, port = a.target.rpartition(":")
    command = f"python3 -c \"{PROBE.format(host=host, port=int(port))}\""

    try:
        import harnis
        from harnis.k8s_sandbox import KubernetesSandbox
    except ImportError as exc:
        sys.exit(f"{exc}. Install with: pip install 'harnis[k8s]'")

    def make(probe: str) -> KubernetesSandbox:
        return KubernetesSandbox(a.image, namespace=a.namespace, network_probe=probe)

    report: dict = {"harnis": harnis.__version__, "target": a.target, "trials": a.trials, "modes": {}}
    for mode, probe in (("check-off", "off"), ("check-on", "auto")):
        sb = make(probe)
        outcomes, details = [], []
        for _ in range(a.trials):
            o, secs, detail = trial(sb, command)
            outcomes.append(o)
            details.append(detail)
        noop = [trial(sb, "true")[1] for _ in range(a.trials)]
        report["modes"][mode] = {
            "outcomes": {k: outcomes.count(k) for k in ("open", "blocked", "refused", "error")},
            "noop_seconds": {"median": round(statistics.median(noop), 2), "max": round(max(noop), 2),
                             "all": [round(x, 2) for x in noop]},
            "first_errors": [d for o, d in zip(outcomes, details) if o == "error"][:3],
        }
        print(f"{mode}: {report['modes'][mode]['outcomes']}  no-op median "
              f"{report['modes'][mode]['noop_seconds']['median']} s")
    Path(a.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {a.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""load_test: concurrent users against one or more Harnis API replicas.

Each virtual user runs realistic sessions against a throwaway tenant (deleted
with all its data at the end):

  * support: a question answered by the support agent;
  * coding:  a coding task that writes files (two approvals, decided by a
             reviewer through a *different* replica than the one that ran the
             turn), then runs the tests in the sandbox.

Requests are spread round-robin over the --api URLs, so with two or more
replicas every approval is resumed on another replica: this checks that
sessions really move between replicas (shared Postgres, Redis and workspaces).

Standard library only. Uses the deterministic `mock` model, so it measures
Harnis itself (routing, checkpoints, approvals, sandbox), not a model provider.

    python scripts/load_test.py --api http://127.0.0.1:8000,http://127.0.0.1:8001 \\
        --env-file .env --users 20 --sessions 5 --report load.json

Exit status 1 when the error rate or p95 latency exceeds --max-error-rate /
--max-p95, so it can gate a pipeline.
"""
from __future__ import annotations

import argparse
import itertools
import json
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harnis_check import Check, Client, mint  # noqa: E402  (same folder, standard library only)


class Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.samples: dict[str, list[float]] = {}
        self.errors: dict[str, int] = {}
        self.error_examples: list[str] = []

    def add(self, name: str, seconds: float, ok: bool, detail: str = "") -> None:
        with self.lock:
            self.samples.setdefault(name, []).append(seconds)
            if not ok:
                self.errors[name] = self.errors.get(name, 0) + 1
                if len(self.error_examples) < 10:
                    self.error_examples.append(f"{name}: {detail[:200]}")

    def summary(self) -> dict[str, dict[str, float]]:
        out = {}
        for name, xs in sorted(self.samples.items()):
            xs = sorted(xs)
            q = lambda p: xs[min(len(xs) - 1, int(p * len(xs)))]  # noqa: E731
            out[name] = {"count": len(xs), "errors": self.errors.get(name, 0),
                         "p50_ms": round(q(0.50) * 1000), "p95_ms": round(q(0.95) * 1000),
                         "p99_ms": round(q(0.99) * 1000), "mean_ms": round(statistics.fmean(xs) * 1000)}
        return out


class LoadTest:
    def __init__(self, a: argparse.Namespace):
        self.a = a
        self.urls = [u.strip().rstrip("/") for u in a.api.split(",") if u.strip()]
        self.clients = [Client(u, None, a.timeout) for u in self.urls]
        self.rr = itertools.cycle(range(len(self.clients)))
        self.rr_lock = threading.Lock()
        self.stats = Stats()
        env = Check._read_env(a.env_file) if a.env_file else {}
        self.secret = a.jwt_secret or env.get("JWT_SECRET")
        if not self.secret:
            sys.exit("needs --env-file or --jwt-secret (AUTH_MODE=local) to create test users")
        self.iss = env.get("JWT_ISSUER", "harnis")
        self.aud = env.get("JWT_AUDIENCE", "harnis-api")
        self.tenant = f"load-{uuid.uuid4().hex[:8]}"

    def client(self) -> tuple[int, Client]:
        with self.rr_lock:
            i = next(self.rr)
        return i, self.clients[i]

    def other(self, i: int) -> Client:
        return self.clients[(i + 1) % len(self.clients)]

    def tok(self, user: str, roles: list[str], tenant: str | None = None) -> str:
        return mint(self.secret, user, tenant or self.tenant, roles, self.iss, self.aud, ttl=6 * 3600)

    def timed(self, name: str, c: Client, method: str, path: str, token: str, body=None, ok=(200,)):
        start = time.perf_counter()
        try:
            r = c.call(method, path, token, body, timeout=self.a.turn_timeout)
            good = r.status in ok
            self.stats.add(name, time.perf_counter() - start, good, "" if good else repr(r))
            return r if good else None
        except Exception as exc:  # timeouts, resets
            self.stats.add(name, time.perf_counter() - start, False, f"{type(exc).__name__}: {exc}")
            return None

    def wait_status(self, c: Client, token: str, sid: str, statuses: set[str], after: int) -> dict | None:
        deadline = time.monotonic() + self.a.turn_timeout
        while time.monotonic() < deadline:
            r = c.call("GET", f"/v1/sessions/{sid}", token)
            if r.status == 200:
                v = r.json()
                if v["status"] in statuses and v["version"] > after:
                    return v
            time.sleep(0.2)
        return None

    def support(self, user: str) -> None:
        i, c = self.client()
        tok = self.tok(user, ["user"])
        r = self.timed("create_session", c, "POST", "/v1/sessions", tok, {}, ok=(201,))
        if r:
            self.timed("turn_support", c, "POST", f"/v1/sessions/{r.json()['session_id']}/turns", tok,
                       {"message": f"what are your opening hours? ({uuid.uuid4().hex[:6]})"})

    def coding(self, user: str) -> None:
        i, c = self.client()
        tok, rev = self.tok(user, ["user"]), self.tok(f"{user}-reviewer", ["reviewer"])
        start = time.perf_counter()
        r = self.timed("create_session", c, "POST", "/v1/sessions", tok, {}, ok=(201,))
        if not r:
            return
        sid = r.json()["session_id"]
        r = self.timed("turn_coding", c, "POST", f"/v1/sessions/{sid}/turns", tok, {"message": "create calc.py"})
        if not r:
            return
        v = r.json()
        for _ in range(4):
            if v["status"] != "awaiting_approval":
                break
            a = v.get("approval")
            if not a:
                self.stats.add("approval_flow", 0, False, "no approval in session view")
                return
            # Decide on the other replica: the resume must work wherever it lands.
            d = self.timed("decide", self.other(i), "POST", f"/v1/approvals/{a['approval_id']}/decision", rev,
                           {"approved": True, "action_hash": a["action_hash"]}, ok=(202,))
            if not d:
                return
            nv = self.wait_status(c, tok, sid, {"awaiting_approval", "completed", "failed", "escalated", "rejected"},
                                  v["version"])
            if nv is None:
                self.stats.add("resume", 0, False, f"session {sid} did not resume")
                return
            v = nv
        ok = v["status"] == "completed"
        self.stats.add("coding_session_end_to_end", time.perf_counter() - start, ok, f"ended {v['status']}")

    def user(self, n: int) -> None:
        name = f"u{n}-{uuid.uuid4().hex[:4]}"
        for k in range(self.a.sessions):
            (self.coding if k % 2 == 0 else self.support)(name)

    def cleanup(self, platform: str) -> bool:
        """Disable, then delete the throwaway tenant. Reports a failure (and
        fails the run) instead of leaving the tenant behind silently."""
        steps = [("disable", "PUT", f"/v1/admin/tenants/{self.tenant}", {"active": False}, (200,)),
                 ("delete", "DELETE", f"/v1/admin/tenants/{self.tenant}?confirm={self.tenant}", None, (200, 204))]
        for what, method, path, body, ok in steps:
            try:
                r = self.clients[0].call(method, path, platform, body)
            except Exception as exc:
                print(f"cleanup: could not {what} tenant {self.tenant}: {type(exc).__name__}: {exc}")
                return False
            if r.status not in ok:
                print(f"cleanup: could not {what} tenant {self.tenant}: {r!r}")
                return False
        return True

    def run(self) -> int:
        platform = self.tok("load-ops", ["platform-admin"], tenant="platform")
        r = self.clients[0].call("PUT", f"/v1/admin/tenants/{self.tenant}", platform,
                                 {"name": "load test", "allowed_providers": ["mock"]})
        if r.status != 200:
            sys.exit(f"could not create the test tenant: {r!r}")
        print(f"load test: {self.a.users} users x {self.a.sessions} sessions over {len(self.urls)} replica(s), "
              f"tenant {self.tenant}")
        start = time.perf_counter()
        with ThreadPoolExecutor(self.a.users) as pool:
            list(pool.map(self.user, range(self.a.users)))
        elapsed = time.perf_counter() - start
        # Remove the throwaway tenant and everything the run created (disable, then delete).
        cleanup_ok = self.cleanup(platform)

        summary = self.stats.summary()
        total = sum(s["count"] for s in summary.values())
        errors = sum(s["errors"] for s in summary.values())
        print(f"\n{'operation':28} {'count':>6} {'errors':>6} {'p50':>7} {'p95':>7} {'p99':>7}")
        for name, s in summary.items():
            print(f"{name:28} {s['count']:6} {s['errors']:6} {s['p50_ms']:6}ms {s['p95_ms']:6}ms {s['p99_ms']:6}ms")
        rate = errors / total if total else 1.0
        rps = total / elapsed if elapsed else 0
        print(f"\n{total} operations in {elapsed:.1f}s ({rps:.1f}/s), error rate {rate:.2%}")
        for e in self.stats.error_examples:
            print("  error:", e)
        worst_p95 = max((s["p95_ms"] for n, s in summary.items() if n.startswith("turn_")), default=0)
        failed = rate > self.a.max_error_rate or worst_p95 > self.a.max_p95 * 1000 or not cleanup_ok
        if self.a.report:
            Path(self.a.report).write_text(json.dumps({
                "replicas": self.urls, "users": self.a.users, "sessions_per_user": self.a.sessions,
                "elapsed_s": round(elapsed, 2), "ops_per_s": round(rps, 2), "error_rate": rate,
                "operations": summary, "errors": self.stats.error_examples, "cleanup_ok": cleanup_ok,
                "passed": not failed}, indent=2))
        if not cleanup_ok:
            print(f"FAIL (the test tenant {self.tenant} was not removed; delete it with the admin API)")
        else:
            print("PASS" if not failed else
                  f"FAIL (max error rate {self.a.max_error_rate:.0%}, max p95 {self.a.max_p95}s)")
        return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="comma-separated replica URLs")
    ap.add_argument("--env-file")
    ap.add_argument("--jwt-secret")
    ap.add_argument("--users", type=int, default=10)
    ap.add_argument("--sessions", type=int, default=4, help="sessions per user (alternating coding/support)")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--turn-timeout", type=float, default=120)
    ap.add_argument("--max-error-rate", type=float, default=0.01)
    ap.add_argument("--max-p95", type=float, default=30.0, help="seconds, for turn requests")
    ap.add_argument("--report")
    return LoadTest(ap.parse_args(argv)).run()


if __name__ == "__main__":
    sys.exit(main())

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Turn worker (TURN_EXECUTION=queue):

    python -m harnis.worker

The API records a turn (or a decided approval) in the `turn_jobs` table and
returns; workers claim the jobs and run them with the same orchestrator the API
uses in inline mode. Several workers, on any number of machines, share the queue.

* A job is a pointer: the session holds the (redacted) message, the approvals
  table holds the decision. Nothing else is stored in the queue.
* A claim is a lease, renewed while the turn runs. A worker that dies lets the
  lease run out (WORKER_LEASE_SECONDS) and another worker continues the session
  from its last checkpoint. After WORKER_MAX_ATTEMPTS the session is failed.
* The per-session Redis lock still guarantees one turn at a time per session.

Needs the same environment as the API (database, Redis, model providers,
sandbox) and, for the Kubernetes sandbox, the same service account. Session
files must be on storage shared between the API and the workers.
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import metrics
from .config import Settings, get_settings

log = logging.getLogger("harnis.worker")
ALIVE_FILE = Path("/tmp/harnis-worker-alive")  # the Helm liveness probe checks its age


@contextmanager
def _renewing(store: Any, tenant_id: str, job_id: str, lease_seconds: int) -> Iterator[None]:
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(lease_seconds / 3):
            try:
                store.touch_turn_job(tenant_id, job_id)
            except Exception:
                log.warning("could not renew the lease of job %s", job_id)

    t = threading.Thread(target=beat, name=f"lease-{job_id[:8]}", daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join(timeout=2)


def process_job(app_state: Any, job: dict[str, Any], settings: Settings) -> str:
    """Run one claimed job. Returns done | skipped | failed | retried."""
    store, orch, locks = app_state.store, app_state.orch, app_state.locks
    tenant, sid, job_id = job["tenant_id"], job["session_id"], job["job_id"]

    def finish(result: str) -> str:
        store.finish_turn_job(tenant, job_id)
        metrics.JOBS.labels(result).inc()
        return result

    rec = store.load_session(tenant, sid)
    if rec is None:
        return finish("skipped")
    if not store.tenant_active(tenant):
        # Don't leave the session `running` until the reaper finds it.
        if rec.status in ("running", "awaiting_approval"):
            rec.status = "failed"
            rec.state["awaiting"], rec.state["approval_decision"] = None, None
            rec.state["reply"] = "This account is disabled, so the turn was not run."
            rec.state.setdefault("flags", []).append("tenant_disabled")
            store.save_checkpoint(rec)
        return finish("skipped")
    if job["attempts"] > settings.worker_max_attempts:
        log.error("job %s for session %s gave up after %s attempts", job_id, sid, job["attempts"] - 1)
        if rec.status in ("running", "awaiting_approval"):
            rec.status = "failed"
            rec.state["awaiting"], rec.state["approval_decision"] = None, None
            rec.state["reply"] = "The turn could not be completed. Please send your message again."
            rec.state.setdefault("flags", []).append("worker_gave_up")
            store.save_checkpoint(rec)
            store.audit(tenant, sid, "harnis", "worker_gave_up", {"attempts": job["attempts"] - 1})
        return finish("failed")
    try:
        with locks.hold(sid) as acquired:
            if not acquired:  # another worker (or an inline turn) has the session: offer the job again shortly
                store.defer_turn_job(tenant, job_id, settings.worker_lease_seconds)
                metrics.JOBS.labels("retried").inc()
                return "retried"
            rec = store.load_session(tenant, sid)  # re-read under the lock
            if rec is None:
                return finish("skipped")
            with _renewing(store, tenant, job_id, settings.worker_lease_seconds):
                if job["approval_id"]:
                    appr = store.get_approval(tenant, job["approval_id"])
                    awaiting = rec.state.get("awaiting") or {}
                    if (appr and rec.status == "awaiting_approval"
                            and awaiting.get("approval_id") == job["approval_id"]):
                        orch.resume_after_decision(rec, job["approval_id"], appr["status"] == "approved",
                                                   appr["decided_by"])
                    elif rec.status == "running":  # continuing after a worker died mid-resume
                        orch.run_prepared(rec)
                    else:
                        return finish("skipped")
                elif rec.status == "running":
                    orch.run_prepared(rec)
                else:
                    return finish("skipped")
        return finish("done")
    except Exception:
        # Leave the job: its lease runs out and it is offered again (up to WORKER_MAX_ATTEMPTS).
        log.exception("job %s for session %s failed", job_id, sid)
        metrics.JOBS.labels("retried").inc()
        return "retried"


def _loop(app_state: Any, settings: Settings, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            job = app_state.store.claim_turn_job(settings.worker_lease_seconds)
        except Exception:
            log.exception("could not claim a job")
            stop.wait(2)
            continue
        if job is None:
            stop.wait(settings.worker_poll_seconds)
            continue
        process_job(app_state, job, settings)


def run(settings: Settings | None = None, stop: threading.Event | None = None, app: Any = None) -> None:
    from .api import create_app

    settings = settings or get_settings()
    stop = stop or threading.Event()
    app = app or create_app(settings)
    if settings.turn_execution != "queue":
        log.warning("TURN_EXECUTION is %r: the API runs turns itself; this worker only serves a "
                    "queue that is empty until TURN_EXECUTION=queue", settings.turn_execution)
    if settings.worker_metrics_port:
        from prometheus_client import start_http_server
        start_http_server(settings.worker_metrics_port)
    threads = [threading.Thread(target=_loop, args=(app.state, settings, stop), name=f"worker-{i}", daemon=True)
               for i in range(settings.worker_concurrency)]
    for t in threads:
        t.start()
    log.info("worker started: %s threads, lease %ss", len(threads), settings.worker_lease_seconds)
    try:
        while not stop.is_set():
            try:
                ALIVE_FILE.touch()
            except OSError:
                pass
            stop.wait(10)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=30)  # let running turns finish; leases cover a forced stop
        from .db import close_pool
        close_pool()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run(stop=stop)


if __name__ == "__main__":
    main()

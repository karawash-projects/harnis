# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Scheduled tasks: send a message to an agent on a schedule, as the person who set it up.

Every run is an ordinary session and turn, so nothing is bypassed: the same budgets and path policy
apply, and every file change or command still waits in Approvals. Nobody is watching a scheduled run,
so a run that reaches an approval simply stops there; the request expires after the usual time and
the next run is skipped while the previous one is still waiting.

Rules that keep unattended work safe:
* a minimum interval (SCHEDULE_MIN_INTERVAL_MINUTES) and a cap per person (SCHEDULE_MAX_PER_USER);
* a run is skipped, and audited, while the previous run is still working or waiting for an approval,
  and while the organization is disabled;
* after downtime a task runs once, not once for every missed time;
* a scheduler that dies mid-run only holds the task for a short lease.

Run by the API (SCHEDULER_ENABLED=true) and by workers; several of them can run at once.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, model_validator

log = logging.getLogger("harnis.scheduler")
LEASE_SECONDS = 600


class Every(BaseModel):
    kind: Literal["every"]
    minutes: int = Field(..., ge=1, le=60 * 24 * 31)


class Daily(BaseModel):
    kind: Literal["daily"]
    at: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class Weekly(BaseModel):
    kind: Literal["weekly"]
    days: list[int] = Field(..., min_length=1, max_length=7)  # Monday = 0 ... Sunday = 6
    at: str = Field(..., pattern=r"^([01]\d|2[0-3]):[0-5]\d$")

    @model_validator(mode="after")
    def _days(self) -> "Weekly":
        if any(d < 0 or d > 6 for d in self.days):
            raise ValueError("days are 0 (Monday) to 6 (Sunday)")
        self.days = sorted(set(self.days))
        return self


Spec = Every | Daily | Weekly


def parse_spec(raw: dict[str, Any], min_interval_minutes: int = 15) -> Spec:
    models = {"every": Every, "daily": Daily, "weekly": Weekly}
    if not isinstance(raw, dict) or raw.get("kind") not in models:
        raise ValueError("schedule kind must be 'every', 'daily' or 'weekly'")
    spec = models[raw["kind"]].model_validate(raw)
    if isinstance(spec, Every) and spec.minutes < min_interval_minutes:
        raise ValueError(f"the shortest interval is {min_interval_minutes} minutes")
    return spec


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise ValueError(f"unknown time zone {name!r}") from exc


def next_run(spec: Spec, tz: str, after: datetime) -> datetime:
    """The first run strictly after `after` (UTC-aware), in the task's own time zone."""
    after = after.astimezone(dt_timezone.utc)
    if isinstance(spec, Every):
        return after + timedelta(minutes=spec.minutes)
    z = zone(tz)
    hh, mm = (int(x) for x in spec.at.split(":"))
    days = set(range(7)) if isinstance(spec, Daily) else set(spec.days)
    local = after.astimezone(z)
    for i in range(0, 9):
        day = (local + timedelta(days=i)).date()
        if day.weekday() not in days:
            continue
        cand = datetime(day.year, day.month, day.day, hh, mm, tzinfo=z).astimezone(dt_timezone.utc)
        if cand > after:
            return cand
    raise ValueError("no run time found")  # unreachable: some day in the next 8 matches


class Scheduler:
    def __init__(self, store: Any, orch: Any, locks: Any, settings: Any, registry: Any):
        self.store, self.orch, self.locks, self.settings, self.registry = store, orch, locks, settings, registry

    # -- one task --------------------------------------------------------------------------
    def run_task(self, task: dict[str, Any]) -> tuple[str, str | None]:
        """Run one task now. Returns (status, session_id); status is started | skipped_waiting |
        skipped_tenant | failed. Never raises."""
        tenant, tid = task["tenant_id"], str(task["task_id"])
        try:
            if not self.store.tenant_active(tenant):
                return "skipped_tenant", None
            prev = task.get("last_session_id") or (self.store.get_schedule(tenant, tid) or {}).get("last_session_id")
            if prev and self._still_busy(tenant, prev):
                self.store.audit(tenant, prev, "harnis", "schedule_run_skipped",
                                 {"task_id": tid, "name": task["name"], "reason": "previous run still in progress"})
                return "skipped_waiting", None
            agent = task.get("agent")
            if agent and agent not in self.registry.agents:
                agent = None  # the agent was removed since: let the router choose
            rec = self.store.create_session(tenant, task["user_id"], agent)
            self.store.audit(tenant, rec.session_id, task["user_id"], "schedule_run_started",
                             {"task_id": tid, "name": task["name"]})
            self.store.update_schedule(tenant, tid, last_session_id=rec.session_id)  # an overlapping tick sees it
            with self.locks.hold(rec.session_id) as acquired:
                if not acquired:
                    return "failed", rec.session_id
                if self.settings.turn_execution == "queue":
                    guard = self.orch.d.input_guard.check(task["message"])
                    if guard.allowed:
                        rec = self.orch.prepare_turn(rec, guard.text, guard.redactions)
                        rec.version = self.store.save_checkpoint(rec)
                        self.store.enqueue_turn_job(tenant, rec.session_id)
                    else:
                        self.orch.start_turn(rec, task["message"])
                else:
                    self.orch.start_turn(rec, task["message"])
            return "started", rec.session_id
        except Exception:
            log.exception("scheduled task %s failed to start", tid)
            return "failed", None

    def _still_busy(self, tenant: str, session_id: str) -> bool:
        rec = self.store.load_session(tenant, session_id)
        if rec is None:
            return False
        if rec.status == "awaiting_approval":
            aw = rec.state.get("awaiting") or {}
            if aw.get("approval_id") and self.store.expire_approval(tenant, aw["approval_id"]):
                with self.locks.hold(session_id) as ok:
                    if ok:
                        rec = self.store.load_session(tenant, session_id) or rec
                        if rec.status == "awaiting_approval":
                            self.orch.abandon_awaiting(rec, "no reviewer decided in time")
                            rec.version = self.store.save_checkpoint(rec)
                return False
            return True
        return rec.status == "running"

    # -- the tick ----------------------------------------------------------------------------
    def tick(self, now: datetime | None = None, limit: int = 20) -> int:
        """Run every due task once. Returns how many were claimed."""
        now = now or datetime.now(dt_timezone.utc)
        tasks = self.store.claim_due_schedules(limit, LEASE_SECONDS)
        for t in tasks:
            status, sid = self.run_task(t)
            try:
                spec = parse_spec(t["schedule"], 1)
                nxt = next_run(spec, t["timezone"], now)  # from now: one run after downtime, no backlog
            except ValueError:
                log.exception("task %s has an unusable schedule; disabling it", t["task_id"])
                self.store.update_schedule(t["tenant_id"], t["task_id"], enabled=False, next_run_at=None)
                nxt = None
            self.store.finish_schedule(t["tenant_id"], t["task_id"], nxt, status, sid)
        return len(tasks)

    def loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("scheduler tick failed")
            stop.wait(self.settings.scheduler_poll_seconds)

    def start(self) -> tuple[threading.Thread, threading.Event]:
        stop = threading.Event()
        t = threading.Thread(target=self.loop, args=(stop,), name="scheduler", daemon=True)
        t.start()
        return t, stop

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Postgres implementation of the orchestrator's Store, plus the queries the
API needs. Every method opens a tenant-scoped transaction, so RLS applies."""
from __future__ import annotations

import time
import uuid
from decimal import Decimal
from typing import Any

from . import pg

from .db import tenant_tx
from .orchestrator import ConflictError, SessionRecord, new_state


class ApprovalError(Exception):
    def __init__(self, message: str, code: int = 409):
        super().__init__(message)
        self.code = code


class PgStore:
    def __init__(self, pool=None, approval_ttl_seconds: int = 3600, platform_pool=None):
        self.pool = pool
        self._platform_admin_pool = platform_pool
        self.approval_ttl = approval_ttl_seconds
        self._policy_cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def _tx(self, tenant_id: str):
        return tenant_tx(tenant_id, self.pool)

    # -- sessions ----------------------------------------------------------------
    def create_session(self, tenant_id: str, user_id: str, agent: str | None = None) -> SessionRecord:
        sid = "sess_" + uuid.uuid4().hex
        state = new_state()
        if agent:  # the user picked it on the Start page: the router must not override that
            state["agent"], state["pinned_agent"] = agent, True
        with self._tx(tenant_id) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, tenant_id, user_id, state) VALUES (%s, %s, %s, %s)",
                (sid, tenant_id, user_id, pg.Jsonb(state)))
        return SessionRecord(sid, tenant_id, user_id, "idle", "ingest", state, 0)

    def load_session(self, tenant_id: str, session_id: str) -> SessionRecord | None:
        with self._tx(tenant_id) as conn:
            row = conn.execute(
                "SELECT session_id, tenant_id, user_id, status, current_node, state, version"
                " FROM sessions WHERE session_id = %s", (session_id,)).fetchone()
        if not row:
            return None
        return SessionRecord(row["session_id"], row["tenant_id"], row["user_id"], row["status"],
                             row["current_node"], row["state"], row["version"])

    def save_checkpoint(self, rec: SessionRecord) -> int:
        with self._tx(rec.tenant_id) as conn:
            row = conn.execute(
                "UPDATE sessions SET status = %s, current_node = %s, state = %s,"
                " version = version + 1, updated_at = now()"
                " WHERE session_id = %s AND version = %s RETURNING version",
                (rec.status, rec.current_node, pg.Jsonb(rec.state), rec.session_id, rec.version)).fetchone()
        if row is None:
            raise ConflictError(f"session {rec.session_id} changed concurrently (expected v{rec.version})")
        return row["version"]

    def list_sessions(self, tenant_id: str, user_id: str | None, limit: int = 50) -> list[dict[str, Any]]:
        q = "SELECT session_id, user_id, status, updated_at FROM sessions"
        args: tuple = ()
        if user_id:
            q += " WHERE user_id = %s"
            args = (user_id,)
        q += " ORDER BY updated_at DESC LIMIT %s"
        with self._tx(tenant_id) as conn:
            return conn.execute(q, args + (limit,)).fetchall()

    # -- approvals ---------------------------------------------------------------
    def create_approval(self, tenant_id: str, session_id: str, requested_by: str,
                        action: dict[str, Any], action_hash: str) -> str:
        with self._tx(tenant_id) as conn:
            row = conn.execute(
                "INSERT INTO approvals (tenant_id, session_id, requested_by, action, action_hash, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, now() + make_interval(secs => %s)) RETURNING approval_id",
                (tenant_id, session_id, requested_by, pg.Jsonb(action), action_hash, self.approval_ttl)).fetchone()
            conn.execute(
                "INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)"
                " VALUES (%s, %s, %s, 'approval_requested', %s)",
                (tenant_id, session_id, requested_by, pg.Jsonb({"tool": action.get("tool"), "action_hash": action_hash})))
        return str(row["approval_id"])

    def list_approvals(self, tenant_id: str, status: str = "pending") -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            rows = conn.execute(
                "SELECT a.approval_id, a.session_id, a.requested_by, a.action, a.action_hash, a.status,"
                " a.requested_at, a.expires_at, a.decided_by, a.decided_at,"
                " s.state->>'agent' AS agent, s.state->'messages'->-1 AS last_message"
                " FROM approvals a LEFT JOIN sessions s ON s.session_id = a.session_id"
                " WHERE a.status = %s AND (a.status <> 'pending' OR a.expires_at > now())"
                " ORDER BY a.requested_at LIMIT 500", (status,)).fetchall()
        for r in rows:
            r["approval_id"] = str(r["approval_id"])
            # What the agent said just before asking: the nearest thing to a stated reason.
            msg = r.pop("last_message", None)
            text = ""
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                text = " ".join(b.get("text", "") for b in msg.get("content", [])
                                if isinstance(b, dict) and b.get("type") == "text").strip()
            r["context"] = text[:400] or None
        return rows

    def get_approval(self, tenant_id: str, approval_id: str) -> dict[str, Any] | None:
        with self._tx(tenant_id) as conn:
            return conn.execute("SELECT * FROM approvals WHERE approval_id = %s", (approval_id,)).fetchone()

    def expire_approval(self, tenant_id: str, approval_id: str) -> bool:
        """True when the approval has run out (marking a still-pending one as expired)."""
        with self._tx(tenant_id) as conn:
            row = conn.execute("SELECT status, expires_at <= now() AS late FROM approvals"
                               " WHERE approval_id = %s FOR UPDATE", (approval_id,)).fetchone()
            if row is None:
                return False
            if row["status"] == "pending" and row["late"]:
                conn.execute("UPDATE approvals SET status = 'expired', decided_by = 'harnis', decided_at = now()"
                             " WHERE approval_id = %s", (approval_id,))
                return True
            return row["status"] == "expired"

    def decide_approval(self, tenant_id: str, approval_id: str, approved: bool, decided_by: str,
                        action_hash: str, enqueue: bool = False) -> tuple[dict[str, Any], bool]:
        """Atomically record a decision. Returns (approval, effective_approved).
        An expired approval is recorded as expired and treated as denied.
        enqueue: in the same transaction, queue the job that resumes the session, so a decision
        can never be recorded without the resume being durably scheduled."""
        with self._tx(tenant_id) as conn:
            row = conn.execute("SELECT *, now() > expires_at AS expired FROM approvals"
                               " WHERE approval_id = %s FOR UPDATE", (approval_id,)).fetchone()
            if row is None:
                raise ApprovalError("approval not found", 404)
            if row["status"] != "pending":
                raise ApprovalError(f"approval already {row['status']}")
            if row["action_hash"] != action_hash:
                raise ApprovalError("action_hash does not match the pending action", 409)
            if row["expired"]:
                status, effective = "expired", False
            else:
                status, effective = ("approved" if approved else "denied"), approved
            conn.execute("UPDATE approvals SET status = %s, decided_by = %s, decided_at = now()"
                         " WHERE approval_id = %s", (status, decided_by, approval_id))
            conn.execute(
                "INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)"
                " VALUES (%s, %s, %s, %s, %s)",
                (tenant_id, row["session_id"], decided_by, f"approval_{status}",
                 pg.Jsonb({"approval_id": approval_id, "action_hash": action_hash})))
            if enqueue:
                conn.execute("INSERT INTO turn_jobs (tenant_id, session_id, approval_id) VALUES (%s, %s, %s)",
                             (tenant_id, row["session_id"], approval_id))
        return row, effective

    # -- turn queue (TURN_EXECUTION=queue) -------------------------------------------
    def enqueue_turn_job(self, tenant_id: str, session_id: str) -> str:
        with self._tx(tenant_id) as conn:
            row = conn.execute("INSERT INTO turn_jobs (tenant_id, session_id) VALUES (%s, %s) RETURNING job_id",
                               (tenant_id, session_id)).fetchone()
        return str(row["job_id"])

    def claim_turn_job(self, lease_seconds: int) -> dict[str, Any] | None:
        """Lease the oldest waiting (or lease-expired) job, across tenants. Ids only."""
        with self._platform() as conn:
            row = conn.execute("SELECT * FROM harnis_claim_turn_job(%s)", (lease_seconds,)).fetchone()
        if not row:
            return None
        return {"job_id": str(row["out_job_id"]), "tenant_id": row["out_tenant_id"],
                "session_id": row["out_session_id"],
                "approval_id": str(row["out_approval_id"]) if row["out_approval_id"] else None,
                "attempts": row["out_attempts"]}

    def touch_turn_job(self, tenant_id: str, job_id: str) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute("UPDATE turn_jobs SET claimed_at = now() WHERE job_id = %s", (job_id,))

    def finish_turn_job(self, tenant_id: str, job_id: str) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute("DELETE FROM turn_jobs WHERE job_id = %s", (job_id,))

    def turn_queue_stats(self) -> dict[str, float]:
        with self._platform() as conn:
            row = conn.execute("SELECT * FROM harnis_turn_queue_stats()").fetchone()
        return {"queued": int(row["out_queued"]), "oldest_seconds": float(row["out_oldest_seconds"])}

    # -- scheduled tasks ----------------------------------------------------------------
    def create_schedule(self, tenant_id: str, user_id: str, name: str, agent: str | None, message: str,
                        schedule: dict[str, Any], timezone: str, enabled: bool, next_run_at: Any,
                        max_per_user: int) -> dict[str, Any]:
        with self._tx(tenant_id) as conn:
            n = conn.execute("SELECT count(*) AS n FROM scheduled_tasks WHERE user_id = %s", (user_id,)).fetchone()["n"]
            if n >= max_per_user:
                raise ValueError(f"at most {max_per_user} scheduled tasks per person")
            return conn.execute(
                "INSERT INTO scheduled_tasks (tenant_id, user_id, name, agent, message, schedule, timezone,"
                " enabled, next_run_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
                (tenant_id, user_id, name, agent, message, pg.Jsonb(schedule), timezone, enabled,
                 next_run_at if enabled else None)).fetchone()

    def list_schedules(self, tenant_id: str, user_id: str | None) -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            if user_id is None:
                return conn.execute("SELECT * FROM scheduled_tasks ORDER BY created_at").fetchall()
            return conn.execute("SELECT * FROM scheduled_tasks WHERE user_id = %s ORDER BY created_at",
                                (user_id,)).fetchall()

    def get_schedule(self, tenant_id: str, task_id: str) -> dict[str, Any] | None:
        with self._tx(tenant_id) as conn:
            return conn.execute("SELECT * FROM scheduled_tasks WHERE task_id = %s", (task_id,)).fetchone()

    def update_schedule(self, tenant_id: str, task_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {"name", "agent", "message", "schedule", "timezone", "enabled", "next_run_at", "last_session_id"}
        sets, args = [], []
        for k, v in fields.items():
            if k not in allowed:
                raise ValueError(k)
            sets.append(f"{k} = %s")
            args.append(pg.Jsonb(v) if k == "schedule" else v)
        if not sets:
            return self.get_schedule(tenant_id, task_id)
        with self._tx(tenant_id) as conn:
            return conn.execute(f"UPDATE scheduled_tasks SET {', '.join(sets)} WHERE task_id = %s RETURNING *",
                                (*args, task_id)).fetchone()

    def delete_schedule(self, tenant_id: str, task_id: str) -> bool:
        with self._tx(tenant_id) as conn:
            return conn.execute("DELETE FROM scheduled_tasks WHERE task_id = %s RETURNING 1", (task_id,)).fetchone() is not None

    def claim_due_schedules(self, limit: int, lease_seconds: int) -> list[dict[str, Any]]:
        """Lease due tasks, across tenants (a short lease: a scheduler that dies lets another take over)."""
        with self._platform() as conn:
            rows = conn.execute("SELECT * FROM harnis_claim_due_schedules(%s, %s)", (limit, lease_seconds)).fetchall()
        return [{"task_id": str(r["out_task_id"]), "tenant_id": r["out_tenant_id"], "user_id": r["out_user_id"],
                 "name": r["out_name"], "agent": r["out_agent"], "message": r["out_message"],
                 "schedule": r["out_schedule"], "timezone": r["out_timezone"]} for r in rows]

    def finish_schedule(self, tenant_id: str, task_id: str, next_run_at: Any, status: str,
                        session_id: str | None) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute("UPDATE scheduled_tasks SET claimed_until = NULL, next_run_at = %s, last_run_at = now(),"
                         " last_status = %s, last_session_id = coalesce(%s, last_session_id)"
                         " WHERE task_id = %s", (next_run_at, status, session_id, task_id))

    # -- ledger, metrics, audit ---------------------------------------------------
    def record_usage(self, tenant_id: str, session_id: str, provider: str, model: str,
                     input_tokens: int, output_tokens: int, cost: float) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute(
                "INSERT INTO token_ledger (tenant_id, session_id, provider, model, input_tokens,"
                " output_tokens, cost_usd) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (tenant_id, session_id, provider, model, input_tokens, output_tokens, cost))

    def record_metric(self, tenant_id: str, session_id: str, latency_ms: int, cache_hit: bool,
                      outcome: str, steps: int) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute(
                "INSERT INTO run_metrics (tenant_id, session_id, latency_ms, cache_hit, outcome, steps)"
                " VALUES (%s, %s, %s, %s, %s, %s)", (tenant_id, session_id, latency_ms, cache_hit, outcome, steps))

    def audit(self, tenant_id: str, session_id: str | None, actor: str, event_type: str,
              detail: dict[str, Any]) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute(
                "INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)"
                " VALUES (%s, %s, %s, %s, %s)", (tenant_id, session_id, actor, event_type, pg.Jsonb(detail)))

    def usage_by_model(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            rows = conn.execute("SELECT provider, model, input_tokens, output_tokens, cost_usd, calls"
                                " FROM tenant_usage_by_model ORDER BY cost_usd DESC").fetchall()
        return [{**r, "cost_usd": float(r["cost_usd"])} for r in rows]

    def spend_breakdown(self, tenant_id: str, days: int = 30) -> dict[str, Any]:
        """Ledger spend by user and by agent. Both come from the conversation the call belonged to
        (its owner and the agent it ended on), so calls of deleted conversations are grouped apart."""
        gone = "(erased or expired)"
        out: dict[str, Any] = {"window_days": days}
        with self._tx(tenant_id) as conn:
            for key, expr in (("by_user", f"coalesce(s.user_id, '{gone}')"),
                              ("by_agent", f"CASE WHEN s.session_id IS NULL THEN '{gone}' ELSE coalesce(s.state->>'agent', '(not routed)') END")):
                rows = conn.execute(
                    f"SELECT {expr} AS name, count(DISTINCT l.session_id) AS sessions, count(*) AS calls,"
                    " coalesce(sum(l.input_tokens), 0) AS input_tokens, coalesce(sum(l.output_tokens), 0) AS output_tokens,"
                    " coalesce(sum(l.cost_usd), 0) AS cost_usd"
                    " FROM token_ledger l LEFT JOIN sessions s ON s.session_id = l.session_id"
                    " WHERE l.logged_at >= now() - make_interval(days => %s)"
                    " GROUP BY 1 ORDER BY sum(l.cost_usd) DESC, 1 LIMIT 200", (days,)).fetchall()
                out[key] = [{**r, "cost_usd": float(r["cost_usd"])} for r in rows]
        out["total_usd"] = round(sum(r["cost_usd"] for r in out["by_user"]), 6)
        return out

    def approval_stats(self, tenant_id: str, days: int = 30) -> dict[str, Any]:
        """How approvals went: rates, and how long reviewers took (in aggregate, not per person)."""
        eff = "CASE WHEN status = 'pending' AND expires_at <= now() THEN 'expired' ELSE status END"
        with self._tx(tenant_id) as conn:
            by_status = {r["st"]: int(r["n"]) for r in conn.execute(
                f"SELECT {eff} AS st, count(*) AS n FROM approvals"
                " WHERE requested_at >= now() - make_interval(days => %s) GROUP BY 1", (days,)).fetchall()}
            t = conn.execute(
                "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM decided_at - requested_at)) AS median_s,"
                " percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM decided_at - requested_at)) AS p90_s"
                " FROM approvals WHERE status IN ('approved', 'denied') AND decided_at IS NOT NULL"
                " AND requested_at >= now() - make_interval(days => %s)", (days,)).fetchone()
            tools: dict[str, dict[str, int]] = {}
            for r in conn.execute(
                    f"SELECT action->>'tool' AS tool, {eff} AS st, count(*) AS n FROM approvals"
                    " WHERE requested_at >= now() - make_interval(days => %s) GROUP BY 1, 2", (days,)).fetchall():
                tools.setdefault(r["tool"], {})[r["st"]] = int(r["n"])
        approved, denied = by_status.get("approved", 0), by_status.get("denied", 0)
        total = sum(by_status.values())
        return {
            "window_days": days, "total": total, "approved": approved, "denied": denied,
            "expired": by_status.get("expired", 0), "pending": by_status.get("pending", 0),
            "approval_rate_pct": round(100 * approved / (approved + denied), 1) if approved + denied else None,
            "expired_pct": round(100 * by_status.get("expired", 0) / total, 1) if total else None,
            "median_decision_s": round(float(t["median_s"]), 1) if t and t["median_s"] is not None else None,
            "p90_decision_s": round(float(t["p90_s"]), 1) if t and t["p90_s"] is not None else None,
            "by_tool": [{"tool": k, "approved": v.get("approved", 0), "denied": v.get("denied", 0),
                         "expired": v.get("expired", 0), "pending": v.get("pending", 0)}
                        for k, v in sorted(tools.items())],
        }

    def analytics_hourly(self, tenant_id: str, hours: int = 24) -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            rows = conn.execute("SELECT hour, runs, avg_latency_ms, cache_hit_pct, success_pct, halted"
                                " FROM tenant_analytics_hourly ORDER BY hour DESC LIMIT %s", (hours,)).fetchall()
        return [{k: (float(v) if isinstance(v, Decimal) else v) for k, v in r.items()} for r in rows]

    # -- prompts & tenant policy ---------------------------------------------------
    def get_prompt(self, tenant_id: str, key: str) -> tuple[str, int] | None:
        with self._tx(tenant_id) as conn:
            row = conn.execute("SELECT prompt_text, version FROM prompt_registry WHERE prompt_key = %s"
                               " ORDER BY version DESC LIMIT 1", (key,)).fetchone()
        return (row["prompt_text"], row["version"]) if row else None

    def put_prompt(self, tenant_id: str, key: str, text: str, created_by: str) -> int:
        with self._tx(tenant_id) as conn:
            # Serialize concurrent writers for this key; version numbers stay dense.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{tenant_id}:{key}",))
            row = conn.execute("SELECT coalesce(max(version), 0) + 1 AS v FROM prompt_registry"
                               " WHERE prompt_key = %s", (key,)).fetchone()
            conn.execute("INSERT INTO prompt_registry (tenant_id, prompt_key, version, prompt_text, created_by)"
                         " VALUES (%s, %s, %s, %s, %s)", (tenant_id, key, row["v"], text, created_by))
        return row["v"]

    def tenant_policy(self, tenant_id: str) -> dict[str, Any]:
        cached = self._policy_cache.get(tenant_id)
        if cached and cached[0] > time.time():
            return cached[1]
        with self._tx(tenant_id) as conn:
            row = conn.execute(
                "SELECT allowed_providers, max_cost_usd_per_turn, active, max_cost_usd_per_day,"
                " max_cost_usd_per_month, max_turn_seconds, require_tests, writes_frozen FROM tenants").fetchone()
        policy = dict(row) if row else {"allowed_providers": [], "max_cost_usd_per_turn": None, "active": False}
        for k in ("max_cost_usd_per_turn", "max_cost_usd_per_day", "max_cost_usd_per_month"):
            if policy.get(k) is not None:
                policy[k] = float(policy[k])
        self._policy_cache[tenant_id] = (time.time() + 30, policy)
        return policy

    def spend_since(self, tenant_id: str, days: int | None = None, month: bool = False) -> float:
        """USD in the token ledger for the tenant: the last `days` days, or this calendar month."""
        with self._tx(tenant_id) as conn:
            if month:
                row = conn.execute("SELECT coalesce(sum(cost_usd), 0) AS c FROM token_ledger"
                                   " WHERE logged_at >= date_trunc('month', now())").fetchone()
            else:
                row = conn.execute("SELECT coalesce(sum(cost_usd), 0) AS c FROM token_ledger"
                                   " WHERE logged_at >= now() - make_interval(days => %s)",
                                   (days or 1,)).fetchone()
        return float(row["c"])

    def trip_tenant(self, tenant_id: str, reason: str, pause: bool = False) -> None:
        with self._tx(tenant_id) as conn:
            conn.execute("SELECT harnis_trip_tenant(%s::text, %s::text, %s::boolean)", (tenant_id, reason, pause))
        self._policy_cache.pop(tenant_id, None)

    def recent_outcomes(self, tenant_id: str, minutes: int = 60) -> dict[str, int]:
        with self._tx(tenant_id) as conn:
            rows = conn.execute("SELECT outcome, count(*) AS n FROM run_metrics"
                                " WHERE recorded_at >= now() - make_interval(mins => %s) GROUP BY outcome",
                                (minutes,)).fetchall()
        return {r["outcome"]: int(r["n"]) for r in rows}

    def scorecard(self, tenant_id: str, hours: int = 24) -> dict[str, Any]:
        """Health of the harness for one tenant: outcomes, safety events, spend against caps."""
        pol = self.tenant_policy(tenant_id)
        with self._tx(tenant_id) as conn:
            outcomes = {r["outcome"]: int(r["n"]) for r in conn.execute(
                "SELECT outcome, count(*) AS n FROM run_metrics WHERE recorded_at >= now() - make_interval(hours => %s)"
                " GROUP BY outcome", (hours,)).fetchall()}
            events = {r["event_type"]: int(r["n"]) for r in conn.execute(
                "SELECT event_type, count(*) AS n FROM audit_log WHERE created_at >= now() - make_interval(hours => %s)"
                " AND event_type = ANY(%s) GROUP BY event_type",
                (hours, ["loop_detected", "input_blocked", "tool_output_injection_suspected", "approval_stale",
                         "trip_wire", "tests_failing", "history_compacted", "spend_cap_reached",
                         "internal_error", "escalated_by_agent", "injection_before_write",
                         "time_budget_exceeded", "cost_budget_exceeded"]) ).fetchall()}
            pending = conn.execute("SELECT count(*) AS n FROM approvals WHERE status = 'pending'"
                                 " AND expires_at > now()").fetchone()["n"]
            tripped = conn.execute("SELECT writes_frozen, tripped_reason, tripped_at, active FROM tenants").fetchone()
        total = sum(outcomes.values())
        bad = outcomes.get("failed", 0) + outcomes.get("escalated", 0)
        return {
            "window_hours": hours, "turns": total, "outcomes": outcomes,
            "success_pct": round(100 * outcomes.get("completed", 0) / total, 1) if total else None,
            "failure_pct": round(100 * bad / total, 1) if total else None,
            "safety_events": events, "pending_approvals": int(pending),
            "spend": {"today_usd": self.spend_since(tenant_id, days=1), "month_usd": self.spend_since(tenant_id, month=True),
                      "max_per_day": pol.get("max_cost_usd_per_day"), "max_per_month": pol.get("max_cost_usd_per_month")},
            "controls": {"max_turn_seconds": pol.get("max_turn_seconds"), "require_tests": bool(pol.get("require_tests"))},
            "trip": {"writes_frozen": bool(tripped and tripped["writes_frozen"]) if tripped else False,
                     "reason": tripped["tripped_reason"] if tripped else None,
                     "at": tripped["tripped_at"] if tripped else None,
                     "paused": bool(tripped and not tripped["active"]) if tripped else False},
        }

    def tenant_exists(self, tenant_id: str) -> bool:
        with self._tx(tenant_id) as conn:
            return conn.execute("SELECT 1 FROM tenants").fetchone() is not None

    def tenant_active(self, tenant_id: str) -> bool:
        return bool(self.tenant_policy(tenant_id).get("active"))

    # -- API keys --------------------------------------------------------------------
    def _platform(self):
        """A connection outside any tenant context, for the SECURITY DEFINER
        platform functions (they enforce their own scope)."""
        from .db import get_pool
        return (self.pool or get_pool()).connection()

    def _platform_admin(self):
        """Connection for platform administration (tenants, controls, trip wires, deletion). It uses the
        separate platform login when PLATFORM_DATABASE_URL is set, otherwise the application login."""
        from .db import get_platform_pool
        pool = self._platform_admin_pool or get_platform_pool()
        return pool.connection() if pool is not None else self._platform()

    def resolve_api_key(self, key_id: str) -> dict[str, Any] | None:
        with self._platform() as conn:
            return conn.execute("SELECT * FROM harnis_resolve_api_key(%s)", (key_id,)).fetchone()

    def create_api_key(self, tenant_id: str, key_id: str, name: str, secret_hash: str, roles: list[str],
                       created_by: str, expires_in_days: int | None) -> dict[str, Any]:
        with self._tx(tenant_id) as conn:
            row = conn.execute(
                "INSERT INTO api_keys (key_id, tenant_id, name, secret_hash, roles, created_by, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, %s,"
                " CASE WHEN %s::int IS NULL THEN NULL ELSE now() + make_interval(days => %s::int) END)"
                " RETURNING key_id, name, roles, created_by, created_at, expires_at",
                (key_id, tenant_id, name, secret_hash, roles, created_by, expires_in_days, expires_in_days)
            ).fetchone()
            conn.execute("INSERT INTO audit_log (tenant_id, actor, event_type, detail) VALUES (%s, %s, %s, %s)",
                         (tenant_id, created_by, "api_key_created", pg.Jsonb({"key_id": key_id, "roles": roles})))
        return row

    def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            return conn.execute(
                "SELECT key_id, name, roles, created_by, created_at, expires_at, last_used_at, revoked_at"
                " FROM api_keys ORDER BY created_at DESC").fetchall()

    def revoke_api_key(self, tenant_id: str, key_id: str, actor: str) -> bool:
        with self._tx(tenant_id) as conn:
            cur = conn.execute("UPDATE api_keys SET revoked_at = now() WHERE key_id = %s AND revoked_at IS NULL",
                               (key_id,))
            if cur.rowcount:
                conn.execute("INSERT INTO audit_log (tenant_id, actor, event_type, detail) VALUES (%s, %s, %s, %s)",
                             (tenant_id, actor, "api_key_revoked", pg.Jsonb({"key_id": key_id})))
            return cur.rowcount == 1

    # -- platform administration ---------------------------------------------------
    def admin_list_tenants(self) -> list[dict[str, Any]]:
        with self._platform_admin() as conn:
            rows = conn.execute("SELECT * FROM harnis_admin_list_tenants()").fetchall()
        keys = ("max_cost_usd_per_turn", "max_cost_usd_per_day", "max_cost_usd_per_month")
        return [{**r, **{k: float(r[k]) if r[k] is not None else None for k in keys}} for r in rows]

    def admin_set_tenant_controls(self, tenant_id: str, max_day: float | None, max_month: float | None,
                                  max_seconds: int | None, require_tests: bool | None, actor: str) -> None:
        with self._platform_admin() as conn:
            conn.execute("SELECT harnis_admin_set_tenant_controls(%s::text, %s::numeric, %s::numeric,"
                         " %s::integer, %s::boolean, %s::text)",
                         (tenant_id, max_day, max_month, max_seconds, require_tests, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    def admin_clear_trip(self, tenant_id: str, actor: str) -> None:
        with self._platform_admin() as conn:
            conn.execute("SELECT harnis_admin_clear_trip(%s::text, %s::text)", (tenant_id, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    def admin_upsert_tenant(self, tenant_id: str, name: str | None, allowed_providers: list[str] | None,
                            max_cost: float | None, active: bool | None, actor: str) -> None:
        with self._platform_admin() as conn:
            conn.execute("SELECT harnis_admin_upsert_tenant(%s::text, %s::text, %s::text[], %s::numeric, %s::boolean, %s::text)",
                         (tenant_id, name, allowed_providers, max_cost, active, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    # -- audit export --------------------------------------------------------------
    def audit_events(self, tenant_id: str, after_id: int = 0, limit: int = 500,
                     event_type: str | None = None, actor: str | None = None,
                     since: Any = None, until: Any = None) -> list[dict[str, Any]]:
        q = ("SELECT event_id, session_id, actor, event_type, detail, created_at FROM audit_log"
             " WHERE event_id > %s")
        args: list[Any] = [after_id]
        if event_type:
            q += " AND event_type = %s"
            args.append(event_type)
        if actor:
            q += " AND actor = %s"
            args.append(actor)
        if since is not None:
            q += " AND created_at >= %s"
            args.append(since)
        if until is not None:
            q += " AND created_at < %s"
            args.append(until)
        q += " ORDER BY event_id LIMIT %s"
        args.append(limit)
        with self._tx(tenant_id) as conn:
            return conn.execute(q, args).fetchall()


    # -- data lifecycle ------------------------------------------------------------
    def export_user(self, tenant_id: str, user_id: str) -> dict[str, Any]:
        """Everything stored about one user in a tenant (right of access)."""
        with self._tx(tenant_id) as conn:
            sessions = conn.execute(
                "SELECT session_id, status, created_at, updated_at, state -> 'messages' AS messages,"
                " state -> 'flags' AS flags FROM sessions WHERE user_id = %s ORDER BY created_at",
                (user_id,)).fetchall()
            approvals = conn.execute(
                "SELECT approval_id, session_id, requested_by, decided_by, action, status, requested_at,"
                " decided_at FROM approvals WHERE requested_by = %s OR decided_by = %s ORDER BY requested_at",
                (user_id, user_id)).fetchall()
            audit = conn.execute(
                "SELECT event_id, session_id, actor, event_type, detail, created_at FROM audit_log"
                " WHERE actor = %s ORDER BY event_id", (user_id,)).fetchall()
            keys = conn.execute("SELECT key_id, name, roles, created_at, revoked_at FROM api_keys"
                                " WHERE created_by = %s", (user_id,)).fetchall()
            prompts = conn.execute("SELECT prompt_key, version, created_at FROM prompt_registry"
                                   " WHERE created_by = %s", (user_id,)).fetchall()
            tasks = conn.execute("SELECT task_id, name, agent, message, schedule, timezone, enabled, created_at"
                                 " FROM scheduled_tasks WHERE user_id = %s", (user_id,)).fetchall()
        return {"tenant_id": tenant_id, "user_id": user_id, "sessions": sessions, "approvals": approvals,
                "scheduled_tasks": tasks,
                "audit_events": audit, "api_keys_created": keys, "prompt_versions_created": prompts}

    def erase_user(self, tenant_id: str, user_id: str, actor: str) -> dict[str, Any]:
        with self._tx(tenant_id) as conn:
            conn.execute("DELETE FROM scheduled_tasks WHERE user_id = %s", (user_id,))
            return conn.execute("SELECT harnis_erase_user(%s, %s) AS r", (user_id, actor)).fetchone()["r"]

    def delete_tenant(self, tenant_id: str, actor: str) -> dict[str, Any] | None:
        """Deletes a disabled tenant and all its data. Raises ValueError if it is active."""

        with self._platform_admin() as conn:
            try:
                with conn.transaction():
                    r = conn.execute("SELECT harnis_delete_tenant(%s) AS r", (tenant_id,)).fetchone()["r"]
                    if r is not None:
                        conn.execute("INSERT INTO platform_audit (actor, event_type, detail) VALUES (%s, %s, %s)",
                                     (actor, "tenant_deleted", pg.Jsonb(r)))
            except pg.errors.ObjectInUse as exc:
                raise ValueError(str(exc).split("\n")[0]) from exc
        self._policy_cache.pop(tenant_id, None)
        return r

    def api_key_creator(self, tenant_id: str, key_id: str) -> str | None:
        with self._tx(tenant_id) as conn:
            row = conn.execute("SELECT created_by FROM api_keys WHERE key_id = %s", (key_id,)).fetchone()
        return row["created_by"] if row else None

    def platform_events(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._platform_admin() as conn:
            return conn.execute("SELECT * FROM platform_audit ORDER BY event_id DESC LIMIT %s", (limit,)).fetchall()


__all__ = ["PgStore", "ApprovalError"]

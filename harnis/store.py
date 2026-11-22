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
    def __init__(self, pool=None, approval_ttl_seconds: int = 3600):
        self.pool = pool
        self.approval_ttl = approval_ttl_seconds
        self._policy_cache: dict[str, tuple[float, dict[str, Any]]] = {}

    def _tx(self, tenant_id: str):
        return tenant_tx(tenant_id, self.pool)

    # -- sessions ----------------------------------------------------------------
    def create_session(self, tenant_id: str, user_id: str) -> SessionRecord:
        sid = "sess_" + uuid.uuid4().hex
        with self._tx(tenant_id) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, tenant_id, user_id, state) VALUES (%s, %s, %s, %s)",
                (sid, tenant_id, user_id, pg.Jsonb(new_state())))
        return SessionRecord(sid, tenant_id, user_id, "idle", "ingest", new_state(), 0)

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
        with self._platform() as conn:
            rows = conn.execute("SELECT * FROM harnis_admin_list_tenants()").fetchall()
        keys = ("max_cost_usd_per_turn", "max_cost_usd_per_day", "max_cost_usd_per_month")
        return [{**r, **{k: float(r[k]) if r[k] is not None else None for k in keys}} for r in rows]

    def admin_set_tenant_controls(self, tenant_id: str, max_day: float | None, max_month: float | None,
                                  max_seconds: int | None, require_tests: bool | None, actor: str) -> None:
        with self._platform() as conn:
            conn.execute("SELECT harnis_admin_set_tenant_controls(%s::text, %s::numeric, %s::numeric,"
                         " %s::integer, %s::boolean, %s::text)",
                         (tenant_id, max_day, max_month, max_seconds, require_tests, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    def admin_clear_trip(self, tenant_id: str, actor: str) -> None:
        with self._platform() as conn:
            conn.execute("SELECT harnis_admin_clear_trip(%s::text, %s::text)", (tenant_id, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    def admin_upsert_tenant(self, tenant_id: str, name: str | None, allowed_providers: list[str] | None,
                            max_cost: float | None, active: bool | None, actor: str) -> None:
        with self._platform() as conn:
            conn.execute("SELECT harnis_admin_upsert_tenant(%s::text, %s::text, %s::text[], %s::numeric, %s::boolean, %s::text)",
                         (tenant_id, name, allowed_providers, max_cost, active, actor))
            conn.commit()
        self._policy_cache.pop(tenant_id, None)

    # -- audit export --------------------------------------------------------------
    def audit_events(self, tenant_id: str, after_id: int = 0, limit: int = 500,
                     event_type: str | None = None) -> list[dict[str, Any]]:
        q = ("SELECT event_id, session_id, actor, event_type, detail, created_at FROM audit_log"
             " WHERE event_id > %s")
        args: list[Any] = [after_id]
        if event_type:
            q += " AND event_type = %s"
            args.append(event_type)
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
        return {"tenant_id": tenant_id, "user_id": user_id, "sessions": sessions, "approvals": approvals,
                "audit_events": audit, "api_keys_created": keys, "prompt_versions_created": prompts}

    def erase_user(self, tenant_id: str, user_id: str, actor: str) -> dict[str, Any]:
        with self._tx(tenant_id) as conn:
            return conn.execute("SELECT harnis_erase_user(%s, %s) AS r", (user_id, actor)).fetchone()["r"]

    def delete_tenant(self, tenant_id: str, actor: str) -> dict[str, Any] | None:
        """Deletes a disabled tenant and all its data. Raises ValueError if it is active."""

        with self._platform() as conn:
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
        with self._platform() as conn:
            return conn.execute("SELECT * FROM platform_audit ORDER BY event_id DESC LIMIT %s", (limit,)).fetchall()


__all__ = ["PgStore", "ApprovalError"]

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Postgres implementation of the orchestrator's Store, plus the queries the
API needs. Every method opens a tenant-scoped transaction, so RLS applies."""
from __future__ import annotations

import time
import uuid
from decimal import Decimal
from typing import Any

from psycopg.types.json import Jsonb

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
                (sid, tenant_id, user_id, Jsonb(new_state())))
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
                (rec.status, rec.current_node, Jsonb(rec.state), rec.session_id, rec.version)).fetchone()
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
                (tenant_id, session_id, requested_by, Jsonb(action), action_hash, self.approval_ttl)).fetchone()
            conn.execute(
                "INSERT INTO audit_log (tenant_id, session_id, actor, event_type, detail)"
                " VALUES (%s, %s, %s, 'approval_requested', %s)",
                (tenant_id, session_id, requested_by, Jsonb({"tool": action.get("tool"), "action_hash": action_hash})))
        return str(row["approval_id"])

    def list_approvals(self, tenant_id: str, status: str = "pending") -> list[dict[str, Any]]:
        with self._tx(tenant_id) as conn:
            rows = conn.execute(
                "SELECT approval_id, session_id, requested_by, action, action_hash, status, requested_at, expires_at"
                " FROM approvals WHERE status = %s"
                " AND (status <> 'pending' OR expires_at > now())"
                " ORDER BY requested_at", (status,)).fetchall()
        for r in rows:
            r["approval_id"] = str(r["approval_id"])
        return rows

    def get_approval(self, tenant_id: str, approval_id: str) -> dict[str, Any] | None:
        with self._tx(tenant_id) as conn:
            return conn.execute("SELECT * FROM approvals WHERE approval_id = %s", (approval_id,)).fetchone()

    def decide_approval(self, tenant_id: str, approval_id: str, approved: bool, decided_by: str,
                        action_hash: str) -> tuple[dict[str, Any], bool]:
        """Atomically record a decision. Returns (approval, effective_approved).
        An expired approval is recorded as expired and treated as denied."""
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
                 Jsonb({"approval_id": approval_id, "action_hash": action_hash})))
        return row, effective

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
                " VALUES (%s, %s, %s, %s, %s)", (tenant_id, session_id, actor, event_type, Jsonb(detail)))

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
            row = conn.execute("SELECT allowed_providers, max_cost_usd_per_turn, active FROM tenants").fetchone()
        policy = dict(row) if row else {"allowed_providers": [], "max_cost_usd_per_turn": None, "active": False}
        self._policy_cache[tenant_id] = (time.time() + 30, policy)
        return policy

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
                         (tenant_id, created_by, "api_key_created", Jsonb({"key_id": key_id, "roles": roles})))
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
                             (tenant_id, actor, "api_key_revoked", Jsonb({"key_id": key_id})))
            return cur.rowcount == 1

    # -- platform administration ---------------------------------------------------
    def admin_list_tenants(self) -> list[dict[str, Any]]:
        with self._platform() as conn:
            rows = conn.execute("SELECT * FROM harnis_admin_list_tenants()").fetchall()
        return [{**r, "max_cost_usd_per_turn": float(r["max_cost_usd_per_turn"])
                 if r["max_cost_usd_per_turn"] is not None else None} for r in rows]

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
        import psycopg

        with self._platform() as conn:
            try:
                with conn.transaction():
                    r = conn.execute("SELECT harnis_delete_tenant(%s) AS r", (tenant_id,)).fetchone()["r"]
                    if r is not None:
                        conn.execute("INSERT INTO platform_audit (actor, event_type, detail) VALUES (%s, %s, %s)",
                                     (actor, "tenant_deleted", Jsonb(r)))
            except psycopg.errors.ObjectInUse as exc:
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

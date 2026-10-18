# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""HTTP + WebSocket API.

Run:  uvicorn harnis.api:create_app --factory --reload   (or: python -m harnis.api)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import redis as redis_lib
import redis.asyncio as aioredis
from fastapi import (BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, WebSocket,
                     WebSocketDisconnect, status)
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import __version__, metrics
from .alerts import AlertDispatcher
from .auth import TENANT_ROLES, Authenticator, Principal, current_principal, new_api_key, require_role
from .cache import SemanticCache
from .config import Settings, get_settings
from .guardrails import InputGuard, OutputGuard
from .infra import EventBus, RateLimiter, SessionLock
from .llm.router import build_router
from .plugins import Registry, build_registry
from .orchestrator import ConflictError, Deps, Limits, Orchestrator, SessionRecord, workspace_for
from .sandbox import DockerSandbox
from .store import ApprovalError, PgStore
from .telemetry import setup_tracing
from .tools import WorkspaceError, is_reserved, list_workspace, read_regular, read_text, safe_path, write_text

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class CreateSession(BaseModel):
    files: dict[str, str] = Field(default_factory=dict, description="optional seed files: path -> content")


class TurnIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=50_000)


class DecisionIn(BaseModel):
    approved: bool
    action_hash: str = Field(..., min_length=64, max_length=64)


class ApiKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    roles: list[str] = Field(default_factory=lambda: ["user"], min_length=1)
    expires_in_days: int | None = Field(None, ge=1, le=3650)

    @field_validator("roles")
    @classmethod
    def _tenant_roles_only(cls, v: list[str]) -> list[str]:
        bad = set(v) - TENANT_ROLES
        if bad:
            raise ValueError(f"API keys can only hold tenant roles {sorted(TENANT_ROLES)}; got {sorted(bad)}")
        return v


class TenantIn(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    allowed_providers: list[str] | None = None
    # Omitted fields keep their current value. max_cost_usd_per_turn = 0 removes
    # the tenant's own cap so the platform default (MAX_COST_USD_PER_TURN) applies.
    max_cost_usd_per_turn: float | None = Field(None, ge=0, le=1000)
    active: bool | None = None


class PromptIn(BaseModel):
    key: str = Field(..., pattern=r"^[a-z][a-z0-9_-]{0,31}$")  # "router" or a registered agent
    text: str = Field(..., min_length=10, max_length=20_000)


def session_view(rec: SessionRecord) -> dict[str, Any]:
    msgs = []
    for m in rec.state.get("messages", []):
        for b in m["content"]:
            if b["type"] == "text" and b["text"]:
                msgs.append({"role": m["role"], "text": b["text"]})
            elif b["type"] == "tool_use":
                msgs.append({"role": "tool_call", "text": b["name"]})
    return {"session_id": rec.session_id, "status": rec.status, "agent": rec.state.get("agent"),
            "reply": rec.state.get("reply"), "awaiting": rec.state.get("awaiting"),
            "flags": rec.state.get("flags", []), "messages": msgs[-50:], "version": rec.version,
            "turn": {k: rec.state.get("turn", {}).get(k) for k in
                     ("steps", "cost_usd", "tool_calls", "handoffs", "cache_hit", "loop_trips")}}


# ---------------------------------------------------------------------------
# App factory (dependencies injectable for tests)
# ---------------------------------------------------------------------------
def create_app(settings: Settings | None = None, *, store=None, redis=None, router=None,
               sandbox=None, cache: Any = "auto", auth: Authenticator | None = None,
               registry: Registry | None = None) -> FastAPI:
    settings = settings or get_settings()
    registry = registry or build_registry(settings.plugin_list)
    r = redis if redis is not None else redis_lib.Redis.from_url(settings.redis_url)
    alerts = AlertDispatcher(settings.alert_webhook_url, settings.alert_webhook_kind, r,
                             settings.alert_dedupe_seconds)
    store = store or PgStore(approval_ttl_seconds=settings.approval_ttl_seconds)
    bus = EventBus(r)
    limiter = RateLimiter(r, settings.rate_limit_capacity, settings.rate_limit_refill_per_second)
    locks = SessionLock(r)
    if cache == "auto":
        cache = SemanticCache(r, threshold=settings.cache_distance_threshold, ttl_seconds=settings.cache_ttl_seconds,
                              vector_type=settings.cache_vector_type) if settings.cache_enabled else None
    router = router or build_router(settings, r, on_trip=lambda key: alerts(
        "provider_circuit_open", "platform", None, {"provider": key}), registry=registry)
    from .llm import pricing
    pricing.configure(settings.pricing_overrides, settings.pricing_file)
    chain_models = {p.model_for(t) for p in router.providers for t in ("main", "fast")}
    missing = pricing.unconfirmed(chain_models)
    if missing:
        msg = (f"No confirmed price for {', '.join(missing)}. Cost figures, per-turn cost budgets and tenant cost "
               "caps use reference prices that may be out of date. Set PRICING_OVERRIDES (run "
               "`python tasks.py pricing`) or PRICING_FILE.")
        if settings.env == "production":
            raise RuntimeError(msg + " Refusing to start in production.")
        log.warning(msg)
    if sandbox is None and settings.sandbox_backend == "kubernetes":
        from .k8s_sandbox import KubernetesSandbox

        sandbox = KubernetesSandbox(
            settings.sandbox_image, namespace=settings.sandbox_k8s_namespace,
            runtime_class=settings.sandbox_k8s_runtime_class, cpu=settings.sandbox_k8s_cpu,
            memory=settings.sandbox_k8s_memory, ephemeral_storage=settings.sandbox_k8s_ephemeral_storage,
            workspace_size_limit=settings.sandbox_k8s_workspace_size, tmp_size_limit=settings.sandbox_k8s_tmp_size,
            timeout=settings.sandbox_timeout_seconds, output_limit=settings.sandbox_output_limit_bytes,
            max_workspace_bytes=settings.sandbox_max_workspace_bytes,
            node_selector=settings.sandbox_k8s_node_selector, tolerations=settings.sandbox_k8s_tolerations,
            image_pull_secrets=[s.strip() for s in settings.sandbox_k8s_image_pull_secrets.split(",") if s.strip()],
            image_pull_policy=settings.sandbox_k8s_image_pull_policy, labels=settings.sandbox_k8s_labels,
            pod_start_timeout=settings.sandbox_k8s_pod_start_timeout,
            deps_max_bytes=settings.sandbox_deps_max_bytes, deps_max_files=settings.sandbox_deps_max_files,
            install_timeout=settings.sandbox_install_timeout_seconds,
            egress_proxy_url=settings.sandbox_egress_proxy_url,
            network_probe=settings.sandbox_k8s_network_probe,
            network_probe_timeout=settings.sandbox_k8s_network_probe_timeout)
    sandbox = sandbox or DockerSandbox(
        settings.sandbox_image, runtime=settings.sandbox_runtime, memory=settings.sandbox_memory,
        cpus=settings.sandbox_cpus, pids_limit=settings.sandbox_pids_limit,
        timeout=settings.sandbox_timeout_seconds, output_limit=settings.sandbox_output_limit_bytes,
        workspace_mode=settings.sandbox_workspace_mode, max_workspace_bytes=settings.sandbox_max_workspace_bytes,
        deps_max_bytes=settings.sandbox_deps_max_bytes, deps_max_files=settings.sandbox_deps_max_files,
        install_timeout=settings.sandbox_install_timeout_seconds, egress_allow=settings.sandbox_egress_allow,
        egress_upstream_proxy=settings.sandbox_egress_upstream_proxy,
        egress_allow_private=settings.sandbox_egress_allow_private,
        egress_network=settings.sandbox_egress_network, egress_proxy_image=settings.sandbox_egress_proxy_image)
    if not settings.sandbox_install_enabled:  # operator turned network installs off
        for agent in registry.agents.values():
            agent.tools = [t for t in agent.tools if t != "install_dependencies"]
    workspaces = Path(settings.workspaces_dir).resolve()
    workspaces.mkdir(parents=True, exist_ok=True)

    orch = Orchestrator(Deps(
        store=store, router=router, sandbox=sandbox, workspaces_dir=workspaces,
        input_guard=InputGuard(redact_pii=settings.redact_pii_in_input), output_guard=OutputGuard(),
        cache=cache, publish=bus.publish, alert=alerts,
        limits=Limits(settings.max_steps_per_turn, settings.max_cost_usd_per_turn, settings.max_handoffs_per_turn,
                      settings.max_tool_calls_per_turn, settings.loop_window, settings.loop_repeat_threshold,
                      settings.auto_continue_max, settings.reroute_from_support),
        registry=registry))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        from .db import close_pool
        close_pool()

    app = FastAPI(title="Harnis", version=__version__, lifespan=lifespan)
    setup_tracing(settings, alert=alerts, app=app)
    app.state.orch, app.state.store, app.state.alerts, app.state.registry = orch, store, alerts, registry
    app.state.auth = auth if auth is not None else Authenticator(settings, store)

    def view(rec: SessionRecord) -> dict[str, Any]:
        """Session view plus, while suspended, what is waiting for approval (so
        the requester sees the exact action even without the reviewer role)."""
        out = session_view(rec)
        awaiting = rec.state.get("awaiting") or {}
        if rec.status == "awaiting_approval" and awaiting.get("approval_id"):
            a = store.get_approval(rec.tenant_id, awaiting["approval_id"])
            if a:
                out["approval"] = {k: a.get(k) for k in ("approval_id", "session_id", "requested_by", "action",
                                                          "action_hash", "status", "requested_at", "expires_at")}
        return out

    def load_owned(p: Principal, session_id: str) -> SessionRecord:
        rec = store.load_session(p.tenant_id, session_id)  # RLS: other tenants' sessions don't exist
        if rec is None or (rec.user_id != p.user_id and not p.has("reviewer")):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
        return rec

    # -- health ---------------------------------------------------------------
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        try:
            r.ping()
            from .db import get_pool
            with get_pool().connection() as conn:
                conn.execute("SELECT 1")
        except Exception as exc:
            raise HTTPException(503, f"not ready: {type(exc).__name__}") from exc
        return {"status": "ready"}

    # -- web console ------------------------------------------------------------
    def _console_csp(request: Request) -> str:
        connect = ["'self'"]
        host = request.headers.get("host")
        if host:
            connect += [f"ws://{host}", f"wss://{host}"]
        oidc = _oidc_console_config()
        if oidc and not oidc.get("error"):
            from urllib.parse import urlsplit
            for url in (oidc["token_endpoint"],):
                u = urlsplit(url)
                connect.append(f"{u.scheme}://{u.netloc}")
        return ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                f"connect-src {' '.join(connect)}; frame-ancestors 'none'; base-uri 'none'; "
                "form-action 'self'; object-src 'none'")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        template = getattr(route, "path", None) or "unmatched"  # templates, never raw paths (ids)
        if template != "/metrics":
            metrics.HTTP_REQUESTS.labels(request.method, template, str(response.status_code)).inc()
            metrics.HTTP_LATENCY.labels(request.method, template).observe(time.perf_counter() - started)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        path = request.url.path
        if path == "/" or path.startswith("/static/"):
            h["Content-Security-Policy"] = _console_csp(request)
            h.setdefault("Cache-Control", "no-cache")
        if settings.env == "production":
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    def _oidc_console_config() -> dict[str, Any] | None:
        if settings.auth_mode != "oidc" or not settings.oidc_console_client_id:
            return None
        try:
            disco = app.state.auth.oidc.discovery()
            return {"issuer": settings.oidc_issuer, "client_id": settings.oidc_console_client_id,
                    "authorization_endpoint": disco["authorization_endpoint"],
                    "token_endpoint": disco["token_endpoint"],
                    "end_session_endpoint": disco.get("end_session_endpoint"),
                    "scopes": settings.oidc_console_scopes, "token": settings.oidc_console_token,
                    "extra_params": settings.oidc_console_extra_params}
        except Exception as exc:  # IdP unreachable: say so instead of failing the page
            log.warning("OIDC discovery for the console failed: %s", exc)
            return {"error": "The identity provider could not be reached. Try again later."}

    metrics.BUILD.labels(__version__).set(1)

    if settings.metrics_enabled and settings.env == "production" and not settings.metrics_token:
        log.warning("/metrics is disabled: set METRICS_TOKEN to serve metrics in production "
                    "(the ingress usually routes every path to the API)")
    if settings.metrics_enabled and (settings.metrics_token or settings.env != "production"):
        @app.get("/metrics", include_in_schema=False)
        def prometheus(request: Request) -> Response:
            """Prometheus scrape endpoint. With METRICS_TOKEN set, scrapers must send
            `Authorization: Bearer <token>`; otherwise keep it off the public ingress."""
            if settings.metrics_token:
                import hmac
                given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                if not hmac.compare_digest(given, settings.metrics_token):
                    raise HTTPException(401, "metrics token required")
            body, content_type = metrics.render()
            return Response(body, media_type=content_type)

    @app.get("/v1/auth/config")
    def auth_config() -> dict[str, Any]:
        """Public: how the console should sign users in. Contains no secrets."""
        return {"auth_mode": settings.auth_mode, "version": __version__,
                "dev_token": settings.env == "development" and settings.auth_mode == "local",
                "oidc": _oidc_console_config()}

    if settings.console_enabled:
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        def index_disabled() -> JSONResponse:
            return JSONResponse({"name": "Harnis", "version": __version__, "docs": "/docs"})

    @app.post("/dev/token", include_in_schema=False)
    def dev_token(request: Request) -> dict[str, str]:
        """Convenience for the local console: an admin token for the demo
        tenant. Only in ENV=development and only for requests from this machine;
        production settings refuse the dev JWT secret anyway."""
        client = request.client.host if request.client else ""
        if (settings.env != "development" or settings.auth_mode != "local"
                or client not in ("127.0.0.1", "::1", "localhost", "testclient")):
            raise HTTPException(404, "not found")
        from .auth import mint_token
        return {"token": mint_token("dev", "acme", ["admin"])}

    @app.get("/me")
    def me(p: Principal = Depends(current_principal)) -> dict[str, Any]:
        return {"user_id": p.user_id, "tenant_id": p.tenant_id, "roles": sorted(p.roles), "via": p.via}

    # -- sessions & turns -------------------------------------------------------
    @app.post("/v1/sessions", status_code=201)
    def create_session(body: CreateSession, p: Principal = Depends(require_role("user"))) -> dict[str, Any]:
        if not store.tenant_exists(p.tenant_id):
            raise HTTPException(403, "unknown tenant")
        if not store.tenant_active(p.tenant_id):
            raise HTTPException(403, "tenant is disabled")
        if len(body.files) > settings.max_seed_files:
            raise HTTPException(413, f"at most {settings.max_seed_files} seed files")
        rec = store.create_session(p.tenant_id, p.user_id)
        ws = workspace_for(workspaces, p.tenant_id, rec.session_id)
        for path, content in body.files.items():
            if len(content.encode()) > settings.max_seed_file_bytes:
                raise HTTPException(413, f"{path} is larger than {settings.max_seed_file_bytes} bytes")
            try:
                if is_reserved(path):
                    raise WorkspaceError(".harnis/ is reserved for installed dependencies")
                target = safe_path(ws, path)
            except WorkspaceError as exc:
                raise HTTPException(400, f"{path}: {exc}") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            write_text(target, content)
        store.audit(p.tenant_id, rec.session_id, p.user_id, "session_created", {"seed_files": len(body.files)})
        return {"session_id": rec.session_id}

    @app.get("/v1/sessions")
    def list_sessions(p: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        return store.list_sessions(p.tenant_id, None if p.has("reviewer") else p.user_id)

    @app.get("/v1/sessions/{session_id}")
    def get_session(session_id: str, p: Principal = Depends(current_principal)) -> dict[str, Any]:
        return view(load_owned(p, session_id))

    @app.get("/v1/sessions/{session_id}/files")
    def get_files(session_id: str, p: Principal = Depends(current_principal)) -> dict[str, str]:
        rec = load_owned(p, session_id)
        ws = workspace_for(workspaces, p.tenant_id, rec.session_id)
        out: dict[str, str] = {}
        for rel in list_workspace(ws):
            text = read_regular(ws / rel, settings.max_seed_file_bytes)
            if text is not None:
                out[rel] = text
        return out

    @app.post("/v1/sessions/{session_id}/turns")
    def post_turn(session_id: str, body: TurnIn, p: Principal = Depends(require_role("user"))) -> dict[str, Any]:
        if not store.tenant_active(p.tenant_id):
            raise HTTPException(403, "tenant is disabled")
        rec = load_owned(p, session_id)
        if rec.user_id != p.user_id:
            raise HTTPException(403, "only the session owner can send messages")
        allowed, wait = limiter.allow(p.tenant_id, p.user_id)
        if not allowed:
            metrics.RATE_LIMITED.inc()
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(max(1, int(wait) + 1))})
        with locks.hold(session_id) as acquired:
            if not acquired:
                raise HTTPException(409, "another turn is already running for this session")
            rec = load_owned(p, session_id)  # re-read under the lock
            try:
                rec = orch.start_turn(rec, body.message)
            except ConflictError as exc:
                raise HTTPException(409, str(exc)) from exc
        return view(rec)

    # -- approvals --------------------------------------------------------------
    @app.get("/v1/approvals")
    def list_approvals(status_: str = Query("pending", alias="status"),
                       p: Principal = Depends(require_role("reviewer"))) -> list[dict[str, Any]]:
        return store.list_approvals(p.tenant_id, status_)

    def _resume(tenant_id: str, session_id: str, approval_id: str, approved: bool, decided_by: str) -> None:
        for _ in range(50):  # wait for any in-flight checkpoint to release the lock
            with locks.hold(session_id) as acquired:
                if acquired:
                    rec = store.load_session(tenant_id, session_id)
                    if rec is None:
                        return
                    try:
                        orch.resume_after_decision(rec, approval_id, approved, decided_by)
                    except ConflictError as exc:
                        log.warning("resume skipped: %s", exc)
                    except Exception:
                        log.exception("resume failed for %s", session_id)
                    return
            time.sleep(0.2)
        log.error("could not acquire lock to resume %s", session_id)

    @app.post("/v1/approvals/{approval_id}/decision", status_code=202)
    def decide(approval_id: str, body: DecisionIn, background: BackgroundTasks,
               p: Principal = Depends(current_principal)) -> dict[str, Any]:
        appr = store.get_approval(p.tenant_id, approval_id)
        if appr is None:
            raise HTTPException(404, "approval not found")
        # Same person: a user and the API keys they created count as one.
        requester = {appr["requested_by"]}
        if appr["requested_by"].startswith("key-") and hasattr(store, "api_key_creator"):
            creator = store.api_key_creator(p.tenant_id, appr["requested_by"][4:])
            if creator:
                requester.add(creator)
        own = bool(requester & p.identities())
        if body.approved:
            # Approving needs the reviewer role, and (by default) a second person.
            if not p.has("reviewer"):
                raise HTTPException(403, "requires role 'reviewer'")
            if own and not settings.allow_self_approval:
                raise HTTPException(403, "separation of duties: you cannot approve your own request")
        elif not (own or p.has("reviewer")):
            raise HTTPException(403, "only the requester or a reviewer can deny")
        try:
            row, effective = store.decide_approval(p.tenant_id, approval_id, body.approved, p.user_id,
                                                   body.action_hash)
        except ApprovalError as exc:
            raise HTTPException(exc.code, str(exc)) from exc
        metrics.APPROVAL_DECISIONS.labels("approved" if effective else ("denied" if not body.approved else "expired")).inc()
        background.add_task(_resume, p.tenant_id, row["session_id"], approval_id, effective, p.user_id)
        return {"approval_id": approval_id, "applied": "approved" if effective else "denied",
                "session_id": row["session_id"]}

    # -- usage, analytics, prompts ----------------------------------------------
    @app.get("/v1/usage")
    def usage(p: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        return store.usage_by_model(p.tenant_id)

    @app.get("/v1/analytics")
    def analytics(p: Principal = Depends(require_role("reviewer"))) -> list[dict[str, Any]]:
        return store.analytics_hourly(p.tenant_id)

    @app.post("/v1/prompts", status_code=201)
    def put_prompt(body: PromptIn, p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        if body.key != "router" and body.key not in registry.agents:
            raise HTTPException(400, f"unknown prompt key; use 'router' or one of {sorted(registry.agents)}")
        version = store.put_prompt(p.tenant_id, body.key, body.text, p.user_id)
        store.audit(p.tenant_id, None, p.user_id, "prompt_updated", {"key": body.key, "version": version})
        return {"key": body.key, "version": version}

    @app.get("/v1/prompts/{key}")
    def get_prompt(key: str, p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        found = store.get_prompt(p.tenant_id, key)
        if found:
            return {"key": key, "version": found[1], "text": found[0]}
        if key == "router":
            return {"key": key, "version": 0, "text": registry.router_prompt()}
        if key in registry.agents:
            return {"key": key, "version": 0, "text": registry.agents[key].prompt}
        raise HTTPException(404, "unknown prompt key")

    @app.get("/v1/agents")
    def list_agents(p: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        """Agents and the tools each may use (with their risk tier)."""
        return [{"name": a.name, "description": a.description, "default": a.name == registry.default_agent,
                 "tools": [{"name": t, "risk": registry.tools[t].risk} for t in a.tools]}
                for a in registry.agents.values()]

    # -- tenant administration (tenant admin) --------------------------------------
    @app.post("/v1/admin/api-keys", status_code=201)
    def create_api_key(body: ApiKeyIn, p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        key_id, full_key, secret_hash = new_api_key()
        row = store.create_api_key(p.tenant_id, key_id, body.name, secret_hash, sorted(set(body.roles)),
                                   p.user_id, body.expires_in_days)
        return {**row, "key": full_key, "note": "Store this key now; it cannot be shown again."}

    @app.get("/v1/admin/api-keys")
    def list_api_keys(p: Principal = Depends(require_role("admin"))) -> list[dict[str, Any]]:
        return store.list_api_keys(p.tenant_id)

    @app.delete("/v1/admin/api-keys/{key_id}", status_code=204)
    def revoke_api_key(key_id: str, p: Principal = Depends(require_role("admin"))) -> None:
        if not store.revoke_api_key(p.tenant_id, key_id, p.user_id):
            raise HTTPException(404, "API key not found or already revoked")

    @app.get("/v1/admin/audit")
    def audit(after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=5000),
              event_type: str | None = None, format: str = Query("json", pattern="^(json|ndjson)$"),
              p: Principal = Depends(require_role("admin"))):
        """Append-only audit log for your tenant, oldest first. Page with
        `after=<last event_id>`; `format=ndjson` for SIEM ingestion."""
        rows = store.audit_events(p.tenant_id, after, limit, event_type)
        if format == "ndjson":
            body = "".join(json.dumps(r, default=str) + "\n" for r in rows)
            return Response(body, media_type="application/x-ndjson")
        return {"events": rows, "next_after": rows[-1]["event_id"] if rows else after}

    @app.get("/v1/admin/pricing")
    def pricing_status(p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        """Prices used for cost figures and budgets, and whether the operator confirmed them."""
        rows = pricing.describe(chain_models)
        return {"models": rows, "all_confirmed": all(r["confirmed"] for r in rows)}

    # -- data lifecycle (tenant admin) ------------------------------------------------
    def _valid_user(user_id: str) -> str:
        from .auth import _ID
        if not _ID.match(user_id):
            raise HTTPException(400, "invalid user id")
        return user_id

    def _remove_workspace(tenant_id: str, session_id: str) -> None:
        import shutil
        shutil.rmtree(workspaces / tenant_id / session_id, ignore_errors=True)  # ids are validated

    @app.get("/v1/admin/users/{user_id}/export")
    def export_user(user_id: str, p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        """Everything Harnis stores about one user of your tenant, including their
        sessions' workspace files (right of access / data portability)."""
        data = store.export_user(p.tenant_id, _valid_user(user_id))
        for sess in data["sessions"]:
            ws = workspaces / p.tenant_id / sess["session_id"]
            files = {rel: read_regular(ws / rel, settings.max_seed_file_bytes)
                     for rel in list_workspace(ws)} if ws.exists() else {}
            sess["files"] = {k: v for k, v in files.items() if v is not None}
        store.audit(p.tenant_id, None, p.user_id, "user_exported", {"user_id": user_id})
        return data

    @app.delete("/v1/admin/users/{user_id}/data")
    def erase_user(user_id: str, confirm: str = Query(..., description="repeat the user id to confirm"),
                   p: Principal = Depends(require_role("admin"))) -> dict[str, Any]:
        """Erase a user's data in your tenant (right to erasure): their sessions,
        workspaces and approvals are deleted; their id in the audit log and other
        retained history is replaced by a random pseudonym. Irreversible."""
        _valid_user(user_id)
        if confirm != user_id:
            raise HTTPException(400, "confirm must repeat the user id")
        result = store.erase_user(p.tenant_id, user_id, p.user_id)
        for sid in result.get("sessions") or []:
            _remove_workspace(p.tenant_id, sid)
        if cache is not None:
            cache.clear_tenant(p.tenant_id)  # cached answers can't be traced to a user
        return {k: v for k, v in result.items() if k != "sessions"}

    # -- platform administration (platform-admin) -----------------------------------
    @app.get("/v1/admin/tenants")
    def list_tenants(p: Principal = Depends(require_role("platform-admin"))) -> list[dict[str, Any]]:
        return store.admin_list_tenants()

    @app.put("/v1/admin/tenants/{tenant_id}")
    def upsert_tenant(tenant_id: str, body: TenantIn,
                      p: Principal = Depends(require_role("platform-admin"))) -> dict[str, Any]:
        from .auth import _ID
        if not _ID.match(tenant_id):
            raise HTTPException(400, "tenant id: letters, digits, '_', '.', '-' (max 64)")
        unknown = set(body.allowed_providers or []) - set(registry.providers) - {"*"}
        if unknown:
            raise HTTPException(400, f"unknown providers: {sorted(unknown)}")
        store.admin_upsert_tenant(tenant_id, body.name, body.allowed_providers, body.max_cost_usd_per_turn,
                                  body.active, p.user_id)
        return next(t for t in store.admin_list_tenants() if t["tenant_id"] == tenant_id)

    @app.delete("/v1/admin/tenants/{tenant_id}")
    def delete_tenant(tenant_id: str, confirm: str = Query(..., description="repeat the tenant id to confirm"),
                      p: Principal = Depends(require_role("platform-admin"))) -> dict[str, Any]:
        """Delete a disabled tenant with all its data: sessions, workspaces,
        approvals, prompts, API keys, usage and its audit log. Irreversible;
        the deletion is recorded in the platform audit log."""
        from .auth import _ID
        if not _ID.match(tenant_id) or confirm != tenant_id:
            raise HTTPException(400, "confirm must repeat a valid tenant id")
        try:
            result = store.delete_tenant(tenant_id, p.user_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        if result is None:
            raise HTTPException(404, "tenant not found")
        import shutil
        shutil.rmtree(workspaces / tenant_id, ignore_errors=True)
        if cache is not None:
            cache.clear_tenant(tenant_id)
        return result

    @app.get("/v1/admin/platform-events")
    def platform_events(limit: int = Query(200, ge=1, le=1000),
                        p: Principal = Depends(require_role("platform-admin"))) -> list[dict[str, Any]]:
        return store.platform_events(limit)

    # -- WebSocket event stream -------------------------------------------------
    @app.websocket("/v1/ws")
    async def ws(websocket: WebSocket, token: str = Query(...)):
        # Browsers can't set headers on WebSocket upgrades, so the token comes in
        # the query string. Keep tokens short-lived and don't log query strings.
        try:
            p = app.state.auth.authenticate(token)
        except HTTPException:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        ar = aioredis.Redis.from_url(settings.redis_url)
        pubsub = ar.pubsub()
        channels = [f"events:{p.tenant_id}:user:{p.user_id}"]
        if p.has("reviewer"):
            channels.append(f"events:{p.tenant_id}:reviewers")
        await pubsub.subscribe(*channels)

        async def pump() -> None:
            async for msg in pubsub.listen():
                if msg.get("type") == "message":
                    data = msg["data"]
                    await websocket.send_text(data.decode() if isinstance(data, bytes) else data)

        task = asyncio.create_task(pump())
        try:
            await websocket.send_text(json.dumps({"type": "hello", "channels": len(channels)}))
            while True:
                await websocket.receive_text()  # keepalive / client pings
        except WebSocketDisconnect:
            pass
        finally:
            task.cancel()
            await pubsub.unsubscribe()
            await pubsub.aclose()
            await ar.aclose()

    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run("harnis.api:create_app", factory=True, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()

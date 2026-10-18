# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

import pytest

# Tests must not depend on a developer's .env: environment variables take
# precedence over it, so pin everything that changes behaviour.
os.environ.update({
    "ENV": "test",
    "JWT_SECRET": "test-secret-test-secret-test-secret-xx",
    "ALLOW_SELF_APPROVAL": "false",
    "OTEL_ENABLED": "false",
    "LLM_PROVIDERS": "mock",
    "ALERT_WEBHOOK_URL": "",
})

from harnis.orchestrator import Deps, Limits, Orchestrator, SessionRecord, new_state  # noqa: E402
from harnis.llm.providers import MockProvider  # noqa: E402
from harnis.llm.router import LLMRouter  # noqa: E402
from harnis.sandbox import SandboxResult  # noqa: E402


class MemoryStore:
    """In-memory Store for unit tests (same contract as PgStore)."""

    def __init__(self, policy: dict[str, Any] | None = None):
        self.sessions: dict[str, SessionRecord] = {}
        self.approvals: dict[str, dict[str, Any]] = {}
        self.usage: list[tuple] = []
        self.metrics: list[tuple] = []
        self.audits: list[tuple] = []
        self.prompts: dict[tuple[str, str], tuple[str, int]] = {}
        self.policy = policy or {"allowed_providers": None, "max_cost_usd_per_turn": None}

    def new_session(self, tenant="acme", user="alice") -> SessionRecord:
        rec = SessionRecord("s_" + uuid.uuid4().hex[:8], tenant, user, "idle", "ingest", new_state(), 0)
        self.sessions[rec.session_id] = rec
        return rec

    def load_session(self, tenant_id, session_id):
        rec = self.sessions.get(session_id)
        return rec if rec and rec.tenant_id == tenant_id else None

    def save_checkpoint(self, rec):
        rec.version += 1
        return rec.version

    def create_approval(self, tenant_id, session_id, requested_by, action, action_hash):
        aid = uuid.uuid4().hex
        self.approvals[aid] = {"session_id": session_id, "action": action, "action_hash": action_hash}
        return aid

    def record_usage(self, *a):
        self.usage.append(a)

    def record_metric(self, *a):
        self.metrics.append(a)

    def audit(self, *a):
        self.audits.append(a)

    def get_prompt(self, tenant_id, key):
        return self.prompts.get((tenant_id, key))

    def tenant_policy(self, tenant_id):
        return self.policy


class FakeSandbox:
    def __init__(self, exit_code: int = 0, output: str = "1 passed"):
        self.calls: list[str] = []
        self.exit_code, self.output = exit_code, output

    def run(self, command, workspace, timeout=None, *, egress=False):
        self.calls.append(command)
        self.egress = getattr(self, "egress", []) + [egress]
        return SandboxResult(self.exit_code, self.output)


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def sandbox():
    return FakeSandbox()


@pytest.fixture
def make_orch(tmp_path):
    def factory(store, sandbox=None, providers=None, limits=None, cache=None, alerts=None):
        deps = Deps(store=store, router=LLMRouter(providers or [MockProvider()], sleep=lambda s: None),
                    sandbox=sandbox or FakeSandbox(), workspaces_dir=tmp_path / "ws",
                    limits=limits or Limits(), cache=cache,
                    alert=(lambda *a: alerts.append(a)) if alerts is not None else (lambda *a: None))
        return Orchestrator(deps)
    return factory


# ---------------------------------------------------------------------------
# Integration fixtures: a throwaway database per test session
# ---------------------------------------------------------------------------
OWNER_DSN_BASE = os.getenv("TEST_PG_OWNER_DSN", "postgresql://postgres:postgres@127.0.0.1:5432")
REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://127.0.0.1:6379/15")


def _pg_available() -> bool:
    try:
        import psycopg
        with psycopg.connect(f"{OWNER_DSN_BASE}/postgres", connect_timeout=2):
            return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def pg():
    if not _pg_available():
        pytest.skip("Postgres not reachable (run `python tasks.py up`)")
    import psycopg
    from harnis.migrate import apply_migrations, create_tenant

    name = "harnis_test_" + uuid.uuid4().hex[:8]
    with psycopg.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    owner_dsn = f"{OWNER_DSN_BASE}/{name}"
    apply_migrations(owner_dsn, app_password="harnis_app")
    for t in ("acme", "globex"):
        create_tenant(t, t.title(), ["mock"], dsn=owner_dsn)
    host = OWNER_DSN_BASE.split("@", 1)[1]
    app_dsn = f"postgresql://harnis_app:harnis_app@{host}/{name}"
    yield {"owner": owner_dsn, "app": app_dsn, "name": name}
    with psycopg.connect(f"{OWNER_DSN_BASE}/postgres", autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture(scope="session")
def app_pool(pg):
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(pg["app"], min_size=1, max_size=4, kwargs={"row_factory": dict_row}, open=True)
    yield pool
    pool.close()


@pytest.fixture
def redis_client():
    import redis
    r = redis.Redis.from_url(REDIS_URL)
    try:
        r.ping()
    except Exception:
        pytest.skip("Redis not reachable (run `python tasks.py up`)")
    r.flushdb()
    yield r
    r.flushdb()


def workspace_root(tmp_path: Path) -> Path:
    return tmp_path / "ws"

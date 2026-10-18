# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Run the external feature-check script (scripts/harnis_check.py) against a
live API server, so the script and the API can't drift apart."""
import json
import sys
from pathlib import Path

import pytest

from .test_console import harnis_app, serve

pytestmark = pytest.mark.integration
SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture
def check(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    sys.modules.pop("harnis_check", None)
    import harnis_check
    return harnis_check


def test_script_tokens_are_accepted_by_harnis(check):
    from harnis.auth import decode_token

    from harnis.config import get_settings

    s = get_settings()
    t = check.mint(s.jwt_secret, "u1", "acme", ["reviewer"], s.jwt_issuer, s.jwt_audience)
    p = decode_token(t)
    assert (p.user_id, p.tenant_id, set(p.roles)) == ("u1", "acme", {"reviewer"})


def test_feature_check_passes_against_the_api(check, tmp_path, app_pool, redis_client):
    # FakeSandbox can't echo commands or attempt connections, so the
    # sandbox checks run against the real sandbox in tests/test_sandbox.py.
    app = harnis_app(tmp_path, app_pool, redis_client, allow_self_approval=False, cache_enabled=True,
                     rate_limit_capacity=20)
    report = tmp_path / "report.json"
    with serve(app) as url:
        from harnis.config import get_settings

        code = check.main(["--api", url, "--jwt-secret", get_settings().jwt_secret,
                           "--report", str(report), "--turn-timeout", "30",
                           "--only", "authentication", "conversations", "guardrails", "tenancy",
                           "administration", "events", "rate_limit"])
    results = json.loads(report.read_text())
    failed = [r for r in results["results"] if r["status"] == "FAIL"]
    assert code == 0 and not failed, failed
    assert results["mock_model"] and results["summary"]["PASS"] >= 40

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Scheduled tasks: schedule maths (unit) and the API and scheduler against Postgres (integration)."""
from datetime import datetime, timedelta, timezone

import pytest

from harnis.scheduler import Scheduler, next_run, parse_spec
from tests.test_lifecycle import client, h, tenant, ws  # noqa: F401

UTC = timezone.utc


def spec(**kw):
    return parse_spec(kw, 15)


def test_every_adds_the_interval():
    a = datetime(2026, 3, 1, 10, 0, tzinfo=UTC)
    assert next_run(spec(kind="every", minutes=90), "UTC", a) == a + timedelta(minutes=90)


def test_daily_picks_today_or_tomorrow_in_the_task_zone():
    s = spec(kind="daily", at="09:00")
    assert next_run(s, "UTC", datetime(2026, 3, 1, 8, 0, tzinfo=UTC)) == datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
    assert next_run(s, "UTC", datetime(2026, 3, 1, 9, 0, tzinfo=UTC)) == datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
    # 09:00 in Beirut (UTC+2 in winter) is 07:00 UTC
    assert next_run(s, "Asia/Beirut", datetime(2026, 1, 10, 5, 0, tzinfo=UTC)) == datetime(2026, 1, 10, 7, 0, tzinfo=UTC)


def test_weekly_uses_only_the_chosen_days_and_follows_daylight_saving():
    s = spec(kind="weekly", days=[0, 3], at="08:30")  # Monday and Thursday
    after = datetime(2026, 3, 3, 12, 0, tzinfo=UTC)   # a Tuesday
    assert next_run(s, "UTC", after) == datetime(2026, 3, 5, 8, 30, tzinfo=UTC)
    # New York: 08:30 is UTC-5 in winter and UTC-4 after the March 8 change
    assert next_run(s, "America/New_York", datetime(2026, 3, 2, 14, 0, tzinfo=UTC)) == datetime(2026, 3, 5, 13, 30, tzinfo=UTC)
    assert next_run(s, "America/New_York", datetime(2026, 3, 9, 11, 0, tzinfo=UTC)) == datetime(2026, 3, 9, 12, 30, tzinfo=UTC)


@pytest.mark.parametrize("raw", [
    {"kind": "every", "minutes": 5}, {"kind": "every", "minutes": 0}, {"kind": "daily", "at": "25:00"},
    {"kind": "daily", "at": "9:00"}, {"kind": "weekly", "days": [], "at": "09:00"},
    {"kind": "weekly", "days": [7], "at": "09:00"}, {"kind": "cron", "expr": "* * * * *"}, {}])
def test_bad_schedules_are_rejected(raw):
    with pytest.raises(ValueError):
        parse_spec(raw, 15)


def test_unknown_zone_is_rejected():
    from harnis.scheduler import zone
    with pytest.raises(ValueError):
        zone("Mars/Olympus")


# -- API and scheduler ---------------------------------------------------------------------
BODY = {"name": "Nightly check", "message": "create calc.py", "schedule": {"kind": "daily", "at": "03:00"},
        "timezone": "UTC"}


def make(client, tenant, user="alice", **over):
    r = client.post("/v1/schedules", json={**BODY, **over}, headers=h(user, tenant))
    assert r.status_code == 201, r.text
    return r.json()


def sched_for(client):
    return Scheduler(client.app.state.store, client.app.state.orch, client.app.state.locks,
                     client.app.state.settings, client.app.state.registry)


def due_now(client, tenant, task_id):
    client.app.state.store.update_schedule(tenant, task_id, next_run_at=datetime.now(UTC) - timedelta(minutes=1))


@pytest.mark.integration
def test_crud_validation_and_privacy(client, tenant):
    t = make(client, tenant)
    assert t["enabled"] and t["next_run_at"] and t["last_status"] is None
    mine = client.get("/v1/schedules", headers=h("alice", tenant)).json()
    assert [x["task_id"] for x in mine["tasks"]] == [t["task_id"]] and mine["scheduler_enabled"] is False
    assert client.get("/v1/schedules", headers=h("bob", tenant)).json()["tasks"] == []
    assert client.delete(f"/v1/schedules/{t['task_id']}", headers=h("bob", tenant)).status_code == 404
    assert client.patch(f"/v1/schedules/{t['task_id']}", json={"enabled": False}, headers=h("bob", tenant)).status_code == 404
    for bad in ({"schedule": {"kind": "every", "minutes": 1}}, {"timezone": "Nope/Zone"}, {"agent": "ghost"}):
        assert client.post("/v1/schedules", json={**BODY, **bad}, headers=h("alice", tenant)).status_code == 400
    p = client.patch(f"/v1/schedules/{t['task_id']}", json={"enabled": False}, headers=h("alice", tenant)).json()
    assert p["enabled"] is False and p["next_run_at"] is None
    p = client.patch(f"/v1/schedules/{t['task_id']}", json={"enabled": True, "schedule": {"kind": "every", "minutes": 60}},
                     headers=h("alice", tenant)).json()
    assert p["next_run_at"] and p["schedule"]["minutes"] == 60
    admin_all = client.get("/v1/schedules?all=1", headers=h("boss", tenant, ("admin",))).json()["tasks"]
    assert t["task_id"] in [x["task_id"] for x in admin_all]
    assert client.delete(f"/v1/schedules/{t['task_id']}", headers=h("boss", tenant, ("admin",))).status_code == 204
    kinds = {e["event_type"] for e in client.get("/v1/admin/audit", headers=h("boss", tenant, ("admin",))).json()["events"]}
    assert {"schedule_created", "schedule_updated", "schedule_deleted"} <= kinds


@pytest.mark.integration
def test_per_person_cap(client, tenant):
    client.app.state.settings.schedule_max_per_user = 2
    make(client, tenant, "carol"), make(client, tenant, "carol")
    r = client.post("/v1/schedules", json=BODY, headers=h("carol", tenant))
    assert r.status_code == 409 and "at most 2" in r.text
    assert client.post("/v1/schedules", json=BODY, headers=h("dave", tenant)).status_code == 201


@pytest.mark.integration
def test_a_due_task_runs_as_its_owner_and_still_waits_for_approval(client, tenant):
    t = make(client, tenant)
    due_now(client, tenant, t["task_id"])
    assert sched_for(client).tick() >= 1
    row = client.get("/v1/schedules", headers=h("alice", tenant)).json()["tasks"][0]
    assert row["last_status"] == "started" and row["last_session_id"]
    assert datetime.fromisoformat(row["next_run_at"].replace("Z", "+00:00")) > datetime.now(UTC)
    s = client.get(f"/v1/sessions/{row['last_session_id']}", headers=h("alice", tenant)).json()
    assert s["status"] == "awaiting_approval"            # no approval was skipped
    assert s["approval"]["requested_by"] == "alice"
    assert client.get(f"/v1/sessions/{row['last_session_id']}", headers=h("bob", tenant)).status_code == 404


@pytest.mark.integration
def test_next_run_is_skipped_while_the_previous_run_waits_then_resumes_after_expiry(client, tenant):
    store = client.app.state.store
    t = make(client, tenant)
    sch = sched_for(client)
    due_now(client, tenant, t["task_id"]); sch.tick()
    first = store.get_schedule(tenant, t["task_id"])["last_session_id"]
    due_now(client, tenant, t["task_id"]); sch.tick()
    row = store.get_schedule(tenant, t["task_id"])
    assert row["last_status"] == "skipped_waiting" and row["last_session_id"] == first
    events = client.get("/v1/admin/audit?event_type=schedule_run_skipped", headers=h("boss", tenant, ("admin",))).json()["events"]
    assert any(e["detail"]["task_id"] == t["task_id"] for e in events)
    # nobody decided in time: the approval expires, the session is released, the next run proceeds
    aw = store.load_session(tenant, first).state["awaiting"]["approval_id"]
    from harnis import pg
    with store._tx(tenant) as conn:
        conn.execute("UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE approval_id = %s", (aw,))
    due_now(client, tenant, t["task_id"]); sch.tick()
    row = store.get_schedule(tenant, t["task_id"])
    assert row["last_status"] == "started" and row["last_session_id"] != first
    assert store.load_session(tenant, first).status == "failed"


@pytest.mark.integration
def test_disabled_tenant_skips_and_downtime_gives_one_run(client, tenant):
    store = client.app.state.store
    t = make(client, tenant, schedule={"kind": "every", "minutes": 60})
    store.update_schedule(tenant, t["task_id"], next_run_at=datetime.now(UTC) - timedelta(days=3))
    sch = sched_for(client)
    assert sch.tick() >= 1
    row = store.get_schedule(tenant, t["task_id"])
    assert row["last_status"] == "started"
    assert row["next_run_at"] > datetime.now(UTC)          # not a backlog of 72 runs
    assert sch.tick() == 0 or store.get_schedule(tenant, t["task_id"])["last_session_id"] == row["last_session_id"]


@pytest.mark.integration
def test_run_now_and_erasure(client, tenant):
    t = make(client, tenant, "erin")
    r = client.post(f"/v1/schedules/{t['task_id']}/run", headers=h("erin", tenant))
    assert r.status_code == 202 and r.json()["session_id"]
    again = client.post(f"/v1/schedules/{t['task_id']}/run", headers=h("erin", tenant))
    assert again.status_code == 409                          # still waiting for its approval
    assert client.post(f"/v1/schedules/{t['task_id']}/run", headers=h("bob", tenant)).status_code == 404
    export = client.get("/v1/admin/users/erin/export", headers=h("boss", tenant, ("admin",))).json()
    assert [x["name"] for x in export["scheduled_tasks"]] == ["Nightly check"]
    assert client.delete("/v1/admin/users/erin/data?confirm=erin", headers=h("boss", tenant, ("admin",))).status_code in (200, 204)
    assert client.app.state.store.get_schedule(tenant, t["task_id"]) is None

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Incident alerts to Slack or Discord.

* Non-blocking: sends on a background thread with a short timeout.
* De-duplicated: the same (type, tenant) alerts at most once per window
  (shared via Redis when available), so a loop doesn't spam the channel.
* Minimal data: IDs and the incident type only — never user content.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

log = logging.getLogger(__name__)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="alerts")


def slack_payload(kind: str, tenant: str, session: str | None, detail: dict[str, Any]) -> dict[str, Any]:
    fields = [{"type": "mrkdwn", "text": f"*Type*\n`{kind}`"},
              {"type": "mrkdwn", "text": f"*Tenant*\n`{tenant}`"},
              {"type": "mrkdwn", "text": f"*Session*\n`{session or '-'}`"}]
    fields += [{"type": "mrkdwn", "text": f"*{k}*\n`{v}`"} for k, v in list(detail.items())[:4]]
    return {"text": f"Harnis alert: {kind} ({tenant})",
            "blocks": [{"type": "header", "text": {"type": "plain_text", "text": f"Harnis alert: {kind}"}},
                       {"type": "section", "fields": fields}]}


def discord_payload(kind: str, tenant: str, session: str | None, detail: dict[str, Any]) -> dict[str, Any]:
    fields = [{"name": "Tenant", "value": tenant, "inline": True},
              {"name": "Session", "value": session or "-", "inline": True}]
    fields += [{"name": str(k), "value": str(v), "inline": True} for k, v in list(detail.items())[:4]]
    return {"username": "Harnis",
            "embeds": [{"title": f"Harnis alert: {kind}", "color": 0xE5484D, "fields": fields}]}


class AlertDispatcher:
    def __init__(self, webhook_url: str = "", kind: str = "slack", redis=None, dedupe_seconds: int = 300):
        self.url = webhook_url
        self.kind = kind
        self.redis = redis
        self.dedupe = dedupe_seconds
        self.sent: list[dict[str, Any]] = []  # recent payloads, handy in tests

    def _should_send(self, key: str) -> bool:
        if self.redis is None:
            return True
        return bool(self.redis.set(f"alert:dedupe:{key}", 1, nx=True, ex=self.dedupe))

    def __call__(self, kind: str, tenant: str, session: str | None, detail: dict[str, Any]) -> None:
        if not self._should_send(f"{kind}:{tenant}"):
            return
        build = discord_payload if self.kind == "discord" else slack_payload
        payload = build(kind, tenant, session, detail)
        self.sent = (self.sent + [payload])[-50:]
        log.warning("ALERT %s tenant=%s session=%s %s", kind, tenant, session, detail)
        if self.url:
            _executor.submit(self._post, payload)

    def _post(self, payload: dict[str, Any]) -> None:
        try:
            r = httpx.post(self.url, json=payload, timeout=5.0)
            if r.status_code >= 300:
                log.error("alert webhook returned %s", r.status_code)
        except httpx.HTTPError as exc:
            log.error("alert webhook failed: %s", exc)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""The MCP server speaks the protocol over stdio, as an IDE or coding tool would start it."""
import asyncio
import os
import sys

import pytest

pytest.importorskip("mcp")


def test_a_real_client_can_connect_over_stdio_and_gets_errors_as_messages():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def go():
        params = StdioServerParameters(command=sys.executable, args=["-m", "harnis.mcp_server"],
                                       env={**os.environ, "HARNIS_TOKEN": "t", "HARNIS_API": "http://127.0.0.1:1"})
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                out = await s.call_tool("harnis_task_status", {"session_id": "x"})
                return names, out.content[0].text

    names, text = asyncio.run(asyncio.wait_for(go(), 60))
    assert "harnis_start_task" in names and not any("approve" in n for n in names)
    assert "cannot reach Harnis" in text


def test_it_refuses_to_start_without_a_token(monkeypatch):
    from harnis.mcp_server import main

    monkeypatch.delenv("HARNIS_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="HARNIS_TOKEN"):
        main()

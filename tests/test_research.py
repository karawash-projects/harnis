# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Governed research tools: allowlist, SSRF protection, caps, opt-in registration."""
import socket

import pytest

from harnis.config import Settings
from harnis.egress_proxy import Policy
from harnis.plugins import Registry, register_builtins
from harnis.research import FetchError, Fetcher, html_to_text, make_search_tool, register, resolve_public
from harnis.tools import ToolContext

HTML = (b"<html><head><title> Example  page </title><style>p{}</style></head><body><script>evil()</script>"
        b"<h1>Hello</h1><p>First <b>para</b></p><p>Second</p></body></html>")


def fetcher(responses, allow=("example.com", "*.docs.org"), ip="93.184.216.34"):
    calls = []

    def send(addr, host, target, headers):
        calls.append((addr, host, target))
        return responses[host + target] if (host + target) in responses else responses[host]

    return Fetcher(list(allow), resolver=lambda h, p: ip, send=send), calls


def test_html_becomes_readable_text_without_scripts():
    title, text = html_to_text(HTML.decode())
    assert title == "Example page"
    assert "evil" not in text and "p{}" not in text
    assert text.splitlines()[:3] == ["Hello", "First para", "Second"]


def test_fetch_reads_an_allowed_page_at_the_checked_address():
    f, calls = fetcher({"example.com": (200, {"content-type": "text/html; charset=utf-8"}, HTML)})
    url, title, text = f.fetch("https://example.com/a?x=1")
    assert title == "Example page" and "Second" in text
    assert calls == [("93.184.216.34", "example.com", "/a?x=1")]


@pytest.mark.parametrize("url", [
    "http://example.com/", "https://evil.com/", "https://user:pw@example.com/", "https://example.com:8443/",
    "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest/meta-data/", "ftp://example.com/",
    "https://example.com.evil.com/"])
def test_fetch_refuses_what_is_not_allowed(url):
    f, calls = fetcher({"example.com": (200, {}, b"x")})
    with pytest.raises(FetchError):
        f.fetch(url)
    assert calls == []


def test_wildcard_allows_subdomains_only():
    f, _ = fetcher({"api.docs.org": (200, {"content-type": "text/plain"}, b"ok")})
    assert f.fetch("https://api.docs.org/")[2] == "ok"
    with pytest.raises(FetchError):
        f.fetch("https://docs.org.evil.com/")


def test_redirect_to_a_site_that_is_not_allowed_is_refused():
    f, calls = fetcher({"example.com": (302, {"location": "https://evil.com/x"}, b"")})
    with pytest.raises(FetchError, match="not on the allowed"):
        f.fetch("https://example.com/")
    assert len(calls) == 1


def test_redirect_to_an_allowed_site_is_followed_and_loops_stop():
    f, _ = fetcher({"example.com": (302, {"location": "https://api.docs.org/y"}, b""),
                    "api.docs.org": (200, {"content-type": "text/plain"}, b"landed")})
    assert f.fetch("https://example.com/")[0] == "https://api.docs.org/y"
    loop, _ = fetcher({"example.com": (302, {"location": "https://example.com/"}, b"")})
    with pytest.raises(FetchError, match="redirects"):
        loop.fetch("https://example.com/")


def test_binary_error_and_huge_pages_are_handled():
    f, _ = fetcher({"example.com/bin": (200, {"content-type": "application/pdf"}, b"%PDF"),
                    "example.com/gone": (404, {}, b""),
                    "example.com/big": (200, {"content-type": "text/plain"}, b"a" * 100_000)})
    with pytest.raises(FetchError, match="not supported"):
        f.fetch("https://example.com/bin")
    with pytest.raises(FetchError, match="404"):
        f.fetch("https://example.com/gone")
    assert len(f.fetch("https://example.com/big")[2]) == 20_000


def test_names_that_resolve_to_internal_addresses_are_refused(monkeypatch):
    def fake(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in fake.ips]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    p = Policy(["example.com"])
    for ips in (["10.0.0.5"], ["127.0.0.1"], ["169.254.169.254"], ["93.184.216.34", "192.168.1.1"]):
        fake.ips = ips
        with pytest.raises(FetchError, match="non-public"):
            resolve_public("example.com", p)
    fake.ips = ["93.184.216.34"]
    assert resolve_public("example.com", p) == "93.184.216.34"


def test_search_formats_results_and_hides_service_errors():
    class R:
        def __init__(self, data=None, fail=False):
            self.data, self.fail = data, fail
        def raise_for_status(self):
            if self.fail:
                raise RuntimeError("boom with secret-token")
        def json(self):
            return self.data
    seen = {}

    def get(url, params, timeout):
        seen.update(url=url, params=params)
        return R({"results": [{"title": "T", "url": "https://example.com/a", "content": "snippet"}] * 9})
    ctx = ToolContext(None, None, "t", "u", "s", None)
    tool = make_search_tool("http://search.internal/search", get=get)
    out, err = tool.run(ctx, tool.validate({"query": "harnis", "max_results": 2}))
    assert not err and out.count("https://example.com/a") == 2 and seen["params"]["q"] == "harnis"
    bad = make_search_tool("http://x", get=lambda *a, **k: R(fail=True))
    out, err = bad.run(ctx, bad.validate({"query": "harnis"}))
    assert err and "secret-token" not in out


def test_nothing_is_registered_unless_configured():
    r = Registry()
    register_builtins(r)
    register(r, Settings(_env_file=None))
    assert "web_fetch" not in r.tools and "researcher" not in r.agents
    register(r, Settings(_env_file=None, research_allow_domains="example.com"))
    assert "web_fetch" in r.tools and "web_search" not in r.tools
    assert r.agents["researcher"].tools[:1] == ["web_fetch"]
    r.validate()
    r2 = Registry()
    register_builtins(r2)
    register(r2, Settings(_env_file=None, search_url="http://s/search"))
    assert "web_search" in r2.tools and "web_fetch" not in r2.tools


def test_plugin_loads_by_module_name():
    r = Registry()
    register_builtins(r)
    r.load(["harnis.research"])  # default settings: loads, registers nothing
    assert "harnis.research" in r.loaded_plugins

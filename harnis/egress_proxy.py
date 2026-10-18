# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""Allowlisting egress proxy for dependency installs.

Sandboxes never have network access, except an approved `install_dependencies`
run, which is attached to an isolated network whose only reachable endpoint is
this proxy. The proxy:

* only accepts HTTPS tunnels (`CONNECT host:443`); plain HTTP and other ports
  are refused, so it can't be used to reach internal services over HTTP;
* only to hostnames on the allowlist (exact names, or `*.example.com` for
  subdomains); IP literals are refused, and every resolved address must be
  public (no private, loopback, link-local or metadata addresses), so DNS
  tricks can't point an allowed name at the internal network;
* can chain to a corporate proxy (`--upstream http://proxy:3128`);
* logs every request (allowed or refused) as one JSON line, and enforces
  connection, idle-time and size limits.

Standard library only, so it runs in the sandbox image:

    python egress_proxy.py --listen 0.0.0.0:3128 --allow pypi.org,files.pythonhosted.org
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

DEFAULT_ALLOW = "pypi.org,files.pythonhosted.org,registry.npmjs.org"
MAX_HEADER = 16 * 1024
_HOST_RE_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


def log(event: str, **fields) -> None:
    print(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}), flush=True)


class Policy:
    def __init__(self, allow: list[str], ports: tuple[int, ...] = (443,), allow_private: bool = False):
        self.exact = {a.lower().rstrip(".") for a in allow if a and not a.startswith("*.")}
        self.suffixes = {a[1:].lower().rstrip(".") for a in allow if a.startswith("*.")}  # ".example.com"
        self.ports = ports
        self.allow_private = allow_private

    def host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if not host or set(host) - _HOST_RE_OK or ".." in host:
            return False
        try:
            ipaddress.ip_address(host)
            return False  # IP literals are never allowed: names only
        except ValueError:
            pass
        return host in self.exact or any(host.endswith(s) for s in self.suffixes)

    def address_allowed(self, ip: str) -> bool:
        if self.allow_private:
            return True
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_multicast


def parse_connect(head: bytes) -> tuple[str, int] | None:
    """`CONNECT host:port HTTP/1.1` -> (host, port), or None if not a CONNECT."""
    try:
        line = head.split(b"\r\n", 1)[0].decode("ascii")
        method, target, version = line.split(" ")
    except (UnicodeDecodeError, ValueError):
        return None
    if method != "CONNECT" or not version.startswith("HTTP/1."):
        return None
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit() or host.startswith("["):
        return None
    return host, int(port)


class Proxy:
    def __init__(self, policy: Policy, upstream: str = "", idle_timeout: float = 120.0,
                 max_bytes: int = 2 * 1024 ** 3, max_connections: int = 256, connect_timeout: float = 15.0):
        self.policy = policy
        self.upstream = urlsplit(upstream) if upstream else None
        self.idle_timeout = idle_timeout
        self.max_bytes = max_bytes
        self.connect_timeout = connect_timeout
        self.slots = asyncio.Semaphore(max_connections)

    async def _resolve_checked(self, host: str, port: int) -> str:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = {i[4][0] for i in infos}
        bad = [ip for ip in ips if not self.policy.address_allowed(ip)]
        if not ips or bad:
            raise PermissionError(f"{host} resolves to a non-public address")
        return sorted(ips)[0]

    async def _open_upstream(self, host: str, port: int):
        if self.upstream is None:
            ip = await self._resolve_checked(host, port)
            return await asyncio.wait_for(asyncio.open_connection(ip, port), self.connect_timeout)
        # Chain through the corporate proxy; it resolves the name.
        u = self.upstream
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(u.hostname, u.port or 3128), self.connect_timeout)
        auth = ""
        if u.username:
            token = base64.b64encode(f"{u.username}:{u.password or ''}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {token}\r\n"
        writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.connect_timeout)
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            writer.close()
            raise ConnectionError("upstream proxy refused: " + head.split(b"\r\n", 1)[0].decode(errors="replace"))
        return reader, writer

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: list[int]) -> None:
        try:
            while True:
                data = await asyncio.wait_for(src.read(65536), self.idle_timeout)
                if not data:
                    break
                counter[0] += len(data)
                if counter[0] > self.max_bytes:
                    break
                dst.write(data)
                await dst.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        async with self.slots:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                writer.close()
                return
            target = parse_connect(head)
            if target is None:
                log("refused", client=peer, reason="only HTTPS CONNECT tunnels are allowed")
                await self._reply(writer, 405, "Only HTTPS (CONNECT) is allowed")
                return
            host, port = target
            if port not in self.policy.ports or not self.policy.host_allowed(host):
                log("refused", client=peer, host=host, port=port, reason="not on the allowlist")
                await self._reply(writer, 403, f"{host}:{port} is not on the egress allowlist")
                return
            try:
                up_reader, up_writer = await self._open_upstream(host, port)
            except PermissionError as exc:
                log("refused", client=peer, host=host, port=port, reason=str(exc))
                await self._reply(writer, 403, str(exc))
                return
            except Exception as exc:
                log("error", client=peer, host=host, port=port, reason=f"{type(exc).__name__}: {exc}")
                await self._reply(writer, 502, "could not reach the registry")
                return
            log("allowed", client=peer, host=host, port=port)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            sent, received = [0], [0]
            await asyncio.gather(self._pipe(reader, up_writer, sent), self._pipe(up_reader, writer, received))
            log("closed", client=peer, host=host, bytes_out=sent[0], bytes_in=received[0])

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int, text: str) -> None:
        body = (text + "\n").encode()
        reason = {403: "Forbidden", 405: "Method Not Allowed", 502: "Bad Gateway"}.get(code, "Error")
        try:
            writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()


async def serve(listen: str, proxy: Proxy) -> None:
    host, _, port = listen.rpartition(":")
    server = await asyncio.start_server(proxy.handle, host or "0.0.0.0", int(port), limit=MAX_HEADER)
    log("listening", address=listen, allow=sorted(proxy.policy.exact | {"*" + s for s in proxy.policy.suffixes}),
        upstream=bool(proxy.upstream))
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Allowlisting HTTPS egress proxy for Harnis dependency installs")
    ap.add_argument("--listen", default=os.environ.get("EGRESS_LISTEN", "0.0.0.0:3128"))
    ap.add_argument("--allow", default=os.environ.get("EGRESS_ALLOW", DEFAULT_ALLOW),
                    help="comma-separated hostnames; *.example.com allows subdomains")
    ap.add_argument("--upstream", default=os.environ.get("EGRESS_UPSTREAM_PROXY", ""),
                    help="chain through this HTTP proxy (http://user:pass@host:port)")
    ap.add_argument("--allow-private", action="store_true",
                    default=os.environ.get("EGRESS_ALLOW_PRIVATE", "") == "true",
                    help="allow names resolving to private addresses (internal package mirrors)")
    ap.add_argument("--max-connections", type=int, default=256)
    a = ap.parse_args(argv)
    policy = Policy([x.strip() for x in a.allow.split(",") if x.strip()], allow_private=a.allow_private)
    try:
        asyncio.run(serve(a.listen, Proxy(policy, a.upstream, max_connections=a.max_connections)))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

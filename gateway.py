#!/usr/bin/env python3
"""Async HTTP reverse-proxy gateway.

Features: TLS termination, Host-header routing, weighted round-robin and
least-connections balancing, periodic TCP health checks, and a Redis-backed
token-bucket rate limiter (atomic Lua script).

Requirements: Python 3.10+, pip install pyyaml "redis>=5.0.1"
Environment:  CONFIG_PATH (default: config.yaml)
              TLS_CERT_FILE, TLS_KEY_FILE (required when tls.enabled is true)
"""

import asyncio
import logging
import os
import ssl
from dataclasses import dataclass

import redis.asyncio as aioredis
import yaml

log = logging.getLogger("gateway")

MAX_HEAD_BYTES = 64 * 1024
MAX_BODY_CHUNK = 64 * 1024
IO_TIMEOUT = 30.0
CONNECT_TIMEOUT = 3.0
HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "te",
    "trailer", "upgrade", "transfer-encoding",
}

TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + tonumber(t[2]) / 1000
local bucket = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(bucket[1])
local ts = tonumber(bucket[2])
if tokens == nil then
  tokens = capacity
  ts = now
end
tokens = math.min(capacity, tokens + math.max(0, now - ts) / 1000 * rate)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', key, math.ceil(capacity / rate * 1000) + 1000)
return allowed
"""


@dataclass(eq=False)
class Backend:
    host: str
    port: int
    weight: int = 1
    healthy: bool = True
    active: int = 0
    current_weight: int = 0


class Balancer:
    ALGORITHMS = ("weighted_round_robin", "least_connections")

    def __init__(self, backends, algorithm):
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"unknown balancing algorithm: {algorithm!r}")
        self.backends = backends
        self.algorithm = algorithm

    def pick(self):
        live = [b for b in self.backends if b.healthy]
        if not live:
            return None
        if self.algorithm == "least_connections":
            return min(live, key=lambda b: b.active)
        # Smooth weighted round-robin, the same scheme nginx uses.
        total = sum(b.weight for b in live)
        for b in live:
            b.current_weight += b.weight
        chosen = max(live, key=lambda b: b.current_weight)
        chosen.current_weight -= total
        return chosen


class RateLimiter:
    def __init__(self, redis_url, capacity, refill_per_second):
        self.client = aioredis.from_url(redis_url)
        self.script = self.client.register_script(TOKEN_BUCKET_LUA)
        self.capacity = capacity
        self.rate = refill_per_second

    async def allow(self, client_ip):
        try:
            result = await self.script(
                keys=[f"rl:{client_ip}"],
                args=[self.capacity, self.rate],
            )
            return int(result) == 1
        except aioredis.RedisError as exc:
            # Fail open so a Redis outage does not take the whole proxy down.
            log.warning("rate limiter unavailable, allowing request: %s", exc)
            return True


async def check_backend(backend, timeout):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(backend.host, backend.port), timeout
        )
        writer.close()
        await writer.wait_closed()
        alive = True
    except (OSError, asyncio.TimeoutError):
        alive = False
    if alive != backend.healthy:
        log.info("backend %s:%d is now %s",
                 backend.host, backend.port, "up" if alive else "down")
    backend.healthy = alive


async def health_loop(backends, interval, timeout):
    while True:
        await asyncio.sleep(interval)
        await asyncio.gather(*(check_backend(b, timeout) for b in backends))


def parse_head(head):
    lines = head[:-4].split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) != 3:
        raise ValueError("malformed request line")
    method, target, version = parts
    headers = {}
    for raw in lines[1:]:
        name, sep, value = raw.partition(b":")
        name = name.strip()
        if not sep or not name:
            raise ValueError("malformed header")
        headers[name.decode("latin-1").lower()] = value.strip().decode("latin-1")
    return method, target, version, headers


async def send_error(writer, status, reason):
    body = f"{status} {reason}\n".encode("latin-1")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    try:
        writer.write(head + body)
        await writer.drain()
    except OSError:
        pass


async def copy_body(src, dst, remaining):
    try:
        while remaining > 0:
            chunk = await asyncio.wait_for(
                src.read(min(MAX_BODY_CHUNK, remaining)), IO_TIMEOUT
            )
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
            remaining -= len(chunk)
    except (OSError, asyncio.TimeoutError) as exc:
        log.debug("request body copy stopped: %s", exc)


async def pipe(src, dst):
    while True:
        data = await asyncio.wait_for(src.read(MAX_BODY_CHUNK), IO_TIMEOUT)
        if not data:
            break
        dst.write(data)
        await dst.drain()


class Gateway:
    def __init__(self, routes, default, limiter):
        self.routes = routes  # {hostname: Balancer}
        self.default = default
        self.limiter = limiter

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        peer_ip = str(peer[0])
        backend = None
        upstream_writer = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IO_TIMEOUT)
            try:
                method, target, version, headers = parse_head(head)
            except ValueError:
                await send_error(writer, 400, "Bad Request")
                return

            if self.limiter and not await self.limiter.allow(peer_ip):
                await send_error(writer, 429, "Too Many Requests")
                return

            if "transfer-encoding" in headers:
                await send_error(writer, 501, "Chunked request bodies not supported")
                return
            length = headers.get("content-length", "0")
            if not length.isdigit():
                await send_error(writer, 400, "Bad Content-Length")
                return
            body_len = int(length)

            host = headers.get("host", "").split(":")[0].lower()
            balancer = self.routes.get(host, self.default)
            backend = balancer.pick()
            if backend is None:
                await send_error(writer, 503, "No healthy backends")
                return
            backend.active += 1  # no await between pick() and this increment

            try:
                up_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(backend.host, backend.port),
                    CONNECT_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError):
                log.warning("connect to %s:%d failed", backend.host, backend.port)
                backend.healthy = False  # health loop restores it when reachable
                await send_error(writer, 502, "Bad Gateway")
                return

            headers["x-forwarded-for"] = (
                f"{headers['x-forwarded-for']}, {peer_ip}"
                if "x-forwarded-for" in headers else peer_ip
            )
            lines = [f"{method} {target} {version}"]
            lines += [f"{k}: {v}" for k, v in headers.items() if k not in HOP_BY_HOP]
            lines.append("Connection: close")
            upstream_writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

            body_task = asyncio.create_task(copy_body(reader, upstream_writer, body_len))
            try:
                await pipe(up_reader, writer)
            finally:
                body_task.cancel()

        except asyncio.IncompleteReadError:
            pass  # client closed before finishing the request head
        except asyncio.LimitOverrunError:
            await send_error(writer, 431, "Request Header Fields Too Large")
        except asyncio.TimeoutError:
            pass
        except OSError as exc:
            log.debug("connection from %s ended: %s", peer_ip, exc)
        finally:
            if backend is not None:
                backend.active -= 1
            if upstream_writer is not None:
                upstream_writer.close()
            writer.close()


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"{path} is empty or not a mapping")
    for key in ("listen", "pools", "default_pool"):
        if key not in cfg:
            raise ValueError(f"missing '{key}' in {path}")
    return cfg


def build_gateway(cfg):
    pools, backends = {}, []
    for name, spec in cfg["pools"].items():
        items = []
        for b in spec["backends"]:
            weight = int(b.get("weight", 1))
            if weight < 1:
                raise ValueError(f"pool {name!r}: weight must be >= 1")
            items.append(Backend(str(b["host"]), int(b["port"]), weight))
        pools[name] = Balancer(items, spec.get("algorithm", "weighted_round_robin"))
        backends.extend(items)

    if cfg["default_pool"] not in pools:
        raise ValueError(f"default_pool {cfg['default_pool']!r} is not defined")
    routes = {}
    for host, pool in (cfg.get("routes") or {}).items():
        if pool not in pools:
            raise ValueError(f"route {host!r} points to unknown pool {pool!r}")
        routes[str(host).lower()] = pools[pool]

    limiter = None
    rl = cfg.get("rate_limit") or {}
    if rl.get("enabled"):
        rate = float(rl["refill_per_second"])
        if rate <= 0:
            raise ValueError("rate_limit.refill_per_second must be > 0")
        limiter = RateLimiter(rl["redis_url"], int(rl["capacity"]), rate)

    return Gateway(routes, pools[cfg["default_pool"]], limiter), backends


def build_ssl_context(tls_cfg):
    if not (tls_cfg or {}).get("enabled"):
        return None
    cert = os.environ.get("TLS_CERT_FILE")
    key = os.environ.get("TLS_KEY_FILE")
    if not cert or not key:
        raise RuntimeError("TLS_CERT_FILE and TLS_KEY_FILE must be set when TLS is enabled")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 is negotiated when the client supports it
    ctx.load_cert_chain(cert, key)
    return ctx


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(os.environ.get("CONFIG_PATH", "config.yaml"))
    gateway, backends = build_gateway(cfg)
    ssl_ctx = build_ssl_context(cfg.get("tls"))

    hc = cfg.get("health_check") or {}
    interval = float(hc.get("interval", 5))
    timeout = float(hc.get("timeout", 2))
    await asyncio.gather(*(check_backend(b, timeout) for b in backends))
    health = asyncio.create_task(health_loop(backends, interval, timeout))

    listen = cfg["listen"]
    host = listen.get("host", "0.0.0.0")
    port = int(listen["port"])
    server = await asyncio.start_server(
        gateway.handle, host, port, ssl=ssl_ctx, limit=MAX_HEAD_BYTES
    )
    log.info("gateway listening on %s:%d (tls=%s)", host, port, bool(ssl_ctx))
    try:
        async with server:
            await server.serve_forever()
    finally:
        health.cancel()
        if gateway.limiter is not None:
            await gateway.limiter.client.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
# Proxy Gateway

A high-throughput asynchronous HTTP reverse proxy written in Python (asyncio). It terminates TLS, routes requests by Host header, balances load across backends, runs TCP health checks, and enforces a per-client token-bucket rate limit stored in Redis.

<!-- Replace the line below with your Grafana dashboard screenshot once it exists in docs/. -->

## Features

- Streaming request and response bodies in 64 KiB chunks. Bodies are never buffered whole in memory.
- TLS termination (TLS 1.2 minimum, TLS 1.3 when the client supports it).
- Routing by Host header with a default pool.
- Balancing algorithms: `weighted_round_robin` and `least_connections`.
- Periodic TCP health checks. Failed backends are removed from rotation until they respond again.
- Distributed rate limiting with an atomic Redis Lua script. The limiter fails open if Redis is unavailable.
- Runs as a non-root user with a read-only root filesystem.

## Architecture

```text
       clients
          |
          v
+-----------------------+
|   Gateway (asyncio)   |
|  - TLS termination    |
|  - rate limit --------+--------> Redis (token buckets)
|  - route by Host      |
|  - balance per pool   |
+-----------------------+
          |
          v
     backend1  backend2   <-- TCP health checks run every few seconds       
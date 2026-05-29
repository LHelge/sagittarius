---
id: ynh
title: E6.5 · Listeners (UDP SO_REUSEPORT pool + TCP accept loop, dual-stack)
status: open
priority: P1
created: 2026-05-29T07:42:15.076991051Z
updated: 2026-05-29T08:20:01.225344897Z
tags:
- pipeline
- dns
depends_on:
- unc
- zc5
- bfx
parent: 4k2
---

Bind the DNS sockets and pump datagrams/streams through the `tower` service stack (E6.4). See SPEC §3.1, §10.

## Deliverables
- `cargo add socket2`.
- **UDP:** per configured `--dns-addr`, a `UdpListenerPool` of **N `SO_REUSEPORT` sockets** built via `socket2` (set `SO_REUSEPORT` + `SO_REUSEADDR`, bind, → `std::net::UdpSocket` → `tokio::net::UdpSocket::from_std`), one `recv` task per socket so the kernel fans datagrams across cores. **N defaults to the available core count** (degrades to 1; single-socket fallback where `SO_REUSEPORT` is unavailable). A response longer than `min(requestor's EDNS UDP payload size from E2.5's `EdnsInfo`, 1232 B)` → set the `TC` bit (truncated) and expect a TCP retry (1232 B = DNS Flag Day 2020 safe EDNS buffer size).
- **TCP:** per `--dns-addr`, a single `TcpListener` accept loop spawning bounded per-connection handler tasks; 2-byte length framing (E2.1); RFC 7766 query pipelining + idle timeout. **No `SO_REUSEPORT` for TCP** (low-volume fallback — not worth it).
- **Dual-stack:** use `socket2` `IPV6_V6ONLY(true)` so `0.0.0.0:53` and `[::]:53` bind as separate clean v4/v6 listeners (no v4-mapped overlap).
- Per datagram/stream: build a `DnsRequest` (E6.1), oneshot it through the service stack, write the reply.
- **Service-error → response mapping:** the oneshot returns `Result`. Map the E6.4 typed errors to minimal responses (E2.5), all preserving the request ID: rate-limit **and** concurrency/load-shed → **REFUSED** (Outcome=`Refused`); per-request timeout and upstream all-fail → **SERVFAIL**. These are still logged via E6.6.
- Malformed query handling at the listener boundary: if E2.4 can recover the transaction ID, send E2.5's minimal FORMERR; if the header is too short/corrupt to recover an ID, drop the datagram/TCP message without a response.
- Integrate the E1 shutdown signal: stop accepting new work and drain in-flight via the runtime TaskTracker.

## Design notes
- A single shared `tokio` `UdpSocket` does **not** scale (readiness/queue contention); throughput comes from *separate* `SO_REUSEPORT` sockets — hence the pool.
- The E6.4 tower limiters (rate / concurrency / load-shed / timeout) are built once and **shared** (cloned) across every UDP socket task and the TCP handler — limits are global, not per-socket.
- Behaviour on a `UdpListenerPool` / listener type (CLAUDE.md).

## Validation
- UDP and TCP queries to ephemeral bound sockets resolve correctly.
- With N>1, multiple `SO_REUSEPORT` sockets each receive traffic (load spread observed).
- A response exceeding the UDP threshold sets `TC`; the TCP retry returns the full data.
- Malformed query with recoverable ID receives FORMERR; too-short header receives no response.
- A rate-limited / load-shed query receives REFUSED; a timed-out / upstream-all-fail query receives SERVFAIL.
- Dual-stack: both an IPv4 and an IPv6 listener serve.
- On shutdown, listeners stop accepting and in-flight queries drain within the timeout.

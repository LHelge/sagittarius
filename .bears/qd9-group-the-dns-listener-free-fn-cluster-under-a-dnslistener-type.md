---
id: qd9
title: Group the DNS listener free-fn cluster under a DnsListener type
status: open
priority: P2
created: 2026-05-30T11:32:40.817354208Z
updated: 2026-05-30T11:32:54.697480438Z
tags:
- refactor
- risky
depends_on:
- qs8
parent: 46z
---

**Where:** `src/resolver/pipeline/listener.rs` — the cluster of generic-over-service free functions: `run_service`, `udp_loop`, `handle_udp_datagram`, `tcp_loop`, `handle_tcp_connection`, `is_reuseport_unsupported`.

**Why:** They form one cohesive component (the DNS listener machinery); grouping them as methods on a `DnsListener` (owning the socket/service + cancellation token) makes the component explicit and removes the largest remaining free-fn cluster.

**Do:**
- Introduce a `DnsListener<S>` (or similar) type holding the shared deps (service, token, socket) and turn the loops/handlers into methods.
- `is_reuseport_unsupported` is a pure `&io::Error` predicate — fine as a private assoc fn or a small inherent method.
- **Highest-risk item in this round** (async loops + generics + the live UDP/TCP serving path). Do it **last**, on its own commit, and lean on the existing listener tests + a manual smoke test (real `dig` against UDP and TCP) before declaring done.
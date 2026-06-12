---
id: "5hj"
title: Remove dead UDP framing identity helpers
status: open
priority: P3
created: "2026-06-12T23:03:04.162211955Z"
updated: "2026-06-12T23:03:04.162211955Z"
tags:
  - refactor
  - codec
parent: cde
---

`codec/framing.rs` — `udp::unwrap_datagram` and `udp::wrap_datagram` are identity functions with **no production call sites** (only their own unit tests). Delete the functions and their tests; keep the module-level doc note that a UDP datagram boundary *is* the message boundary (that's the documentation value the functions were carrying).

Commit: `refactor(codec): drop unused UDP framing identity helpers`
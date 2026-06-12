---
id: "65z"
title: "Small idiomatic nits: redundant map_err, duplicate accessor, select! indent"
status: done
priority: P3
created: "2026-06-12T23:03:24.930533675Z"
updated: "2026-06-12T23:21:10.828509873Z"
tags:
  - refactor
parent: cde
---

One pass over three trivia items:

1. `resolver/state.rs:266,281,289,301` — `ResolverState::hydrate` calls `.map_err(resolver::Error::Storage)` four times; `resolver::Error` already derives `#[from] crate::storage::Error`, so plain `?` converts. Drop the map_errs.
2. `codec/message.rs:270` — `ParseError::id()` is a convenience accessor that is *identical* to reading the public `id` field ("Convenience accessor — identical to reading `self.id`"). Either remove the method (callers in `listener.rs` switch to `.id`) or make the field private; don't keep both.
3. `resolver/pipeline/listener.rs:413-420` — the body of the `recv_from` select! arm is mis-indented (rustfmt does not format inside `tokio::select!`). Re-indent by hand.

Commit: `refactor: drop redundant error mapping and accessor, fix select! indent`
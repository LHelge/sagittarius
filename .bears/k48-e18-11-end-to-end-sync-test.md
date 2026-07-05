---
id: k48
title: E18.11 — End-to-end sync test
status: done
priority: P1
created: "2026-07-05T12:34:09.115682228Z"
updated: "2026-07-05T13:26:46.067557640Z"
tags:
  - secondary
  - test
depends_on:
  - axq
  - g93
  - q3j
parent: b6b
---

New tests/secondary_sync.rs (or #[tokio::test] in src/sync/mod.rs). Reuse app.rs full_stack test + web/mod.rs TestServer idioms: primary AdminServer with seeded admin + minted key; secondary ConfigSyncer pointed at it; change config on primary (blacklist add + settings); one tick → assert secondary ResolverState reflects it + blocklist source appeared; second tick returns 304 applies nothing; secondary mutating routes 403 + api 401s without key.
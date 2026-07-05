---
id: g93
title: E18.8 — Config-sync subsystem (poll + apply)
status: done
priority: P1
created: "2026-07-05T12:33:52.402397595Z"
updated: "2026-07-05T13:15:27.024843390Z"
tags:
  - secondary
  - sync
depends_on:
  - pry
  - fvu
  - d7p
  - cdj
  - axq
parent: b6b
---

New src/sync/mod.rs: ConfigSyncer + ConfigApplier. reqwest client via Fetcher pattern. Loop like blocklist/scheduler.rs::run: immediate sync then select! over fixed poll interval const (~30-60s) + token.cancelled(). GET with Bearer + If-None-Match. 304 no-op; unreachable/5xx/timeout warn + keep last-good; 200 deserialize+apply+advance last_version from ETag. Apply order settings→upstreams→blacklist→allowlist→local_records→forward_zones→admin_users→blocklists (last, refresh.trigger() only). Each write-through-then-swap via web-handler seams (see plan table). Per-section txn; abort tick + don't advance last_version on hard failure. Wire in src/app.rs: when Secondary, construct syncer + spawn_subsystem("config-sync",..).
Needs E18.4 wired (endpoint) — but code-depends on E18.6/E18.7/E18.3. Also depends on E18.4 for the live endpoint used by the e2e; keep dep on cdj(repo indirectly via E18.4). 
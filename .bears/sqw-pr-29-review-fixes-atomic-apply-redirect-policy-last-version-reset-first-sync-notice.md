---
id: sqw
title: "PR #29 review fixes: atomic apply, redirect policy, last_version reset, first-sync notice"
status: done
priority: P1
created: "2026-07-08T10:19:41.603236098Z"
updated: "2026-07-08T10:27:34.339564868Z"
tags:
  - secondary
---

Fix the top 4 code-review findings on feat/secondary-fallback-instance:
1. apply_upstreams/apply_local_records: parse all DTOs first + transactional replace_all repo methods (no torn DB).
2. ConfigSyncer: redirect Policy::none() + clear Redirected error (reqwest strips Authorization on http→https).
3. sync_once: clear last_version when an apply fails after mutating state (no 304-frozen mixed state).
4. Secondary login page: "waiting for first config sync" notice when admin_users is empty, incl. last sync error.
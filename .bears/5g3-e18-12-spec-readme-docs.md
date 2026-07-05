---
id: "5g3"
title: E18.12 — SPEC/README docs
status: done
priority: P2
created: "2026-07-05T12:34:15.303668045Z"
updated: "2026-07-05T13:28:55.414316109Z"
tags:
  - secondary
  - docs
depends_on:
  - axq
  - g93
  - q3j
parent: b6b
---

SPEC.md: soften §1 non-goal (read-only secondary/fallback mirror supported, §13) + add §13 Secondary/fallback instance (roles, CLI/env pairing, api-key trust, mirror-worthy vs local-only split, content-hash + conditional-GET poll, read-only UI, independent blocklist refetch, TLS requirement on primary↔secondary hop). README.md: short High availability / fallback section. Consider deploy/ compose env vars.
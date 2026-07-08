---
id: myv
title: "Review fast-follows: skip no-op applies, sort_order reconcile, URL/ETag edge cases, theme + cleanup"
status: open
priority: P2
created: "2026-07-08T10:28:24.544164483Z"
updated: "2026-07-08T10:28:24.544164483Z"
tags:
  - secondary
---

Deferred findings from the PR #29 pre-merge review (5–10):
- apply_config_snapshot runs every section unconditionally: any primary edit flushes the secondary's DNS cache (rebuild_forward_zones → cache().clear()), rebuilds the upstream pool (DoT/DoH reconnects), and refetches all blocklists (refresh.trigger()). Skip sections whose diff is empty (DTOs derive PartialEq).
- apply_forward_zones never reconciles sort_order on existing zones → permanent silent divergence from the snapshot.
- normalize_primary_url should clear/reject query+fragment (Url::set_query(None)/set_fragment(None)); prefer Url::join in ConfigSyncer.
- etag_matches should handle RFC 9110 `*` and comma-separated If-None-Match lists.
- ui_theme: classify as per-instance (exclude from SettingsDto/apply) + exempt /theme/toggle in readonly::guard so a secondary's operator can pick their own theme.
- Version-plumbing cleanup: drop strip_etag_quotes + ETag-header read (set last_version = snapshot.version()), make SyncOutcome::Applied a unit variant; share the ago() helper; tests/common/mod.rs for duplicated e2e helpers.
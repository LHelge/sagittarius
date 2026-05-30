---
id: g8q
title: Convert upstream_config_from_row into TryFrom<&Upstream> for UpstreamConfig
status: open
priority: P1
created: 2026-05-30T11:32:21.020880005Z
updated: 2026-05-30T11:32:21.020880005Z
tags:
- refactor
parent: 46z
---

**Where:** `src/resolver/pipeline/engine.rs:181` — `pub fn upstream_config_from_row(row: &Upstream) -> Option<UpstreamConfig>`.

**Why:** It's a pure conversion `&Upstream → UpstreamConfig` and should use the standard-trait convention already used across storage (`SettingsRow → Settings`, `LocalRecordRow → LocalRecord`, `AdminUserRow → AdminUser`).

**Do:**
- Replace with `impl TryFrom<&Upstream> for UpstreamConfig` (the "unparseable address → skip" case becomes the `Err`/`None` handling at the call site). If callers genuinely want "skip silently", a `From<&Upstream> for Option<UpstreamConfig>` or an inherent `Upstream::to_config(&self) -> Option<UpstreamConfig>` is acceptable — pick whichever keeps call sites cleanest.
- Update call sites (the E8.9 upstream-pool rebuild + engine build).
- Keep behavior identical (default-port logic per transport, bare-IP vs explicit-port, skip DoH URL/hostname).
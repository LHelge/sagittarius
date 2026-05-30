---
id: gkd
title: E13.3 · forward_zones storage + config UI
status: open
priority: P2
created: 2026-05-30T20:23:41.505116502Z
updated: 2026-05-30T20:23:41.505116502Z
tags:
- storage
- web
parent: s2e
---

Persist conditional-forward zones and let the admin point them at the router/DHCP.

## Migration (reversible; `sqlx migrate add -r forward_zones`)
- `forward_zones` table: `id`, `zone_suffix TEXT NOT NULL` (e.g. `168.192.in-addr.arpa`), `target TEXT` (IP or IP:port of the router/DHCP resolver; nullable until set), `enabled INTEGER NOT NULL DEFAULT 0 CHECK (0,1)`, `sort_order INTEGER NOT NULL DEFAULT 0`. Index on `enabled`.
- **Seed** the RFC1918 + ULA reverse zones (`10.in-addr.arpa`, `16.172.in-addr.arpa`…`31.172.in-addr.arpa`, `168.192.in-addr.arpa`, `c.f.ip6.arpa`, `d.f.ip6.arpa`) **disabled with NULL target** — the admin enables them and sets the router target.
- `cargo sqlx prepare`, commit `.sqlx/`.

## Repo (`src/storage/forward_zones.rs`)
- Trait + `SqliteForwardZoneRepo`: `list`, `list_enabled`, `set_target`, `set_enabled`, (add/remove for custom zones — future-friendly).

## Web (`src/web/`)
- A forwarding settings section: list zones, set the router/DHCP target, toggle enabled. CSRF-protected.

## Tests
- Schema + seed rows present (disabled, NULL target).
- Repo round-trips target/enabled; `list_enabled` filters.
- UI renders zones + target field.
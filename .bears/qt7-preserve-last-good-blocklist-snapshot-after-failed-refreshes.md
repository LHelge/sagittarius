---
id: qt7
title: Preserve last-good blocklist snapshot after failed refreshes
status: open
priority: P1
created: 2026-05-30T17:43:47.021538Z
updated: 2026-05-30T17:43:47.021538Z
tags:
- review
- blocklist
parent: d7d
---

Adjust refresh install semantics so failed sources without cache do not replace the live blocklist with a partial/empty set contrary to SPEC.
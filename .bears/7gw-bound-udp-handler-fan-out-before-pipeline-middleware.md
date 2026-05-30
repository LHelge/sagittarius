---
id: 7gw
title: Bound UDP handler fan-out before pipeline middleware
status: open
priority: P2
created: 2026-05-30T17:43:47.028730Z
updated: 2026-05-30T17:43:47.028730Z
tags:
- review
- dns
- performance
parent: d7d
---

Prevent unbounded per-datagram task fan-out and allocations from bypassing the intended protective limits.
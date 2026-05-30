---
id: rwj
title: Bound EDNS COOKIE reflection and TCP framing
status: open
priority: P1
created: 2026-05-30T17:43:47.014098Z
updated: 2026-05-30T17:43:47.014098Z
tags:
- review
- dns
- codec
parent: d7d
---

Validate EDNS COOKIE option length before reflecting it, avoid u16 truncation, and return framing errors instead of panicking on oversized TCP responses.
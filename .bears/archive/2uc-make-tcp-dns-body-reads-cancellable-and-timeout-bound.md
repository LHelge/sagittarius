---
id: 2uc
title: Make TCP DNS body reads cancellable and timeout-bound
status: done
priority: P1
created: 2026-05-30T17:43:47.002523Z
updated: 2026-05-30T17:47:00.006801Z
tags:
- review
- dns
- tcp
parent: d7d
---

Fix the TCP DNS listener so body reads observe shutdown and idle timeout, matching the length-prefix behavior and the handler comment.
---
id: zpf
title: Make first-run setup admin creation atomic
status: done
priority: P2
created: 2026-05-30T17:43:54.631115Z
updated: 2026-05-30T17:59:40.946290Z
tags:
- review
- web
- auth
parent: d7d
---

Remove the count-then-insert race in initial admin setup.
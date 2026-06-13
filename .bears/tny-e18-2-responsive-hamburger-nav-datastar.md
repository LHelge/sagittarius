---
id: tny
title: E18.2 — Responsive hamburger nav (Datastar)
status: done
priority: P2
created: "2026-06-13T14:58:52.885774954Z"
updated: "2026-06-13T16:48:19.318506714Z"
tags:
  - web
  - ui
depends_on:
  - vj4
parent: ag8
---

Replace the flex-wrap menu with a proper mobile hamburger drawer.

- `templates/base.html`: add `data-signals="{navOpen:false}"`, a hamburger
  `<button data-on-click="$navOpen=!$navOpen">` (menu/close icon via the macro),
  and toggle `.sgt-nav` with `data-class`/`data-show`. Close drawer on link click.
- `assets/app.css`: add the **first media queries** in the file. Below ~768px:
  hide the link row by default, show the hamburger, render the open nav as a
  vertical drawer; above the breakpoint show links inline and hide the hamburger.
  Reflow the pause/logout controls sensibly.

Verify in a browser at ~375px and wide: hamburger opens/closes, links work and
close the drawer; no layout breakage at the breakpoint.
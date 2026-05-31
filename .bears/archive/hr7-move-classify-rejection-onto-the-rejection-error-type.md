---
id: hr7
title: Move classify_rejection onto the rejection error type
status: done
priority: P2
created: 2026-05-30T11:32:29.997458577Z
updated: 2026-05-30T12:34:36.703905175Z
tags:
- refactor
parent: 46z
---

**Where:** `src/resolver/pipeline/middleware.rs:210` — `pub fn classify_rejection(err: &BoxError) -> (Outcome, Rcode)`.

**Why:** It's behavior keyed on the protective-middleware rejection; reads better as a method or a `From` conversion than a free function.

**Do:**
- Express as a method on the rejection/error (or `impl From<&…> for (Outcome, Rcode)` if the error type is local) so the classification lives with the type it inspects.
- If `BoxError` (foreign) makes a trait impl awkward, prefer an inherent method on whatever local error/wrapper is available, or document why it must stay free.
- Keep the mapping identical.
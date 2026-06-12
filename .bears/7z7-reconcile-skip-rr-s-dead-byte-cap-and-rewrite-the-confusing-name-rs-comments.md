---
id: "7z7"
title: Reconcile skip_rr's dead byte-cap and rewrite the confusing name.rs comments
status: done
priority: P3
created: "2026-06-12T23:02:56.779837204Z"
updated: "2026-06-12T23:12:16.488859733Z"
tags:
  - refactor
  - codec
parent: cde
---

In `Name::skip_rr` (`codec/name.rs`):

- The `total_label_bytes > MAX_SKIP_BYTES` (512) check at ~line 372 is **unreachable**: the `total_label_bytes > MAX_NAME_WIRE_LEN` (255) check right after it always fires first, because the counter grows by ≤63 per label. The docs ("two independent caps, either of which alone is sufficient") contradict the code. Keep one cap (255 is the meaningful one), delete the dead branch, and fix the doc comment + `MAX_SKIP_BYTES` constant accordingly.
- Rewrite the wire_len accounting comment in `read_question` (~line 176): it currently says the length byte is "already counted above as part of the constant wire_len increment below", which describes nothing.
- Rewrite the pointer-validation comment in `skip_rr` (~line 316): it reasons out loud about an approach it then rejects ("… is too strict … so we allow …"). State the final rule only.

Behaviour unchanged — all existing tests (incl. pointer-loop/forward-pointer cases) must pass untouched; the fuzz targets cover this code, so consider a short local fuzz run.

Commit: `refactor(codec): remove unreachable skip_rr byte-cap, clarify name comments`
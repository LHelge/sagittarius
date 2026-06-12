---
id: xe2
title: "Docs drift sweep: AttributedSet rename, doc placement, Safety headings, qtype tracing"
status: done
priority: P3
created: "2026-06-12T23:05:26.249881667Z"
updated: "2026-06-12T23:28:57.456670557Z"
tags:
  - docs
  - refactor
parent: cde
---

Four small consistency fixes, no behaviour change (the qtype item changes log output format only):

1. **`blocklist/scheduler.rs`** — module docs and the `refresh_once` doc still say the live blocklist is a `MatchSet`; it has been an `AttributedSet` since E11 (`f1c033e`). Update the references (incl. the ASCII pipeline diagram caption if applicable).
2. **`resolver/pipeline/engine.rs:171-188`** — the doc block describing the `TryFrom<&Upstream>` port-mapping rules is attached to the `UnmappableUpstream` struct. Move the mapping description onto the `TryFrom` impl; leave the struct a one-liner.
3. **`# Safety` headings on safe code** — `Name::from_normalized` (`codec/name.rs:117`) uses a `# Safety` rustdoc section, and `Query::question_wire` (`codec/message.rs:443`) has a `// Safety:` comment; neither involves `unsafe`. Rename to "Invariants" / "Contract" so the Safety convention keeps meaning unsafe-related.
4. **qtype rendered via Debug in tracing fields** — `QueryEvent::emit` (`telemetry/event.rs:112`, `qtype = ?self.qtype`) and the upstream-failure warn in `pipeline/forward.rs:166` predate the canonical `Qtype` Display (`ac50f3c`); switch `?` → `%` so logs say `AAAA`/`HTTPS`/`TYPE15` like the UI and the persisted log.

Commit: `docs: fix blocklist/engine doc drift, Safety headings, qtype log rendering`
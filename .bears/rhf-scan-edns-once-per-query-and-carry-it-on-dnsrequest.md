---
id: rhf
title: Scan EDNS once per query and carry it on DnsRequest
status: done
priority: P3
created: "2026-06-12T23:02:44.740882508Z"
updated: "2026-06-12T23:16:29.293009752Z"
tags:
  - refactor
  - resolver
  - hot-path
parent: cde
---

`EdnsInfo::scan` walks the full RR sections of the query and currently runs up to **4× per forwarded UDP query**:

- `listener.rs:450` — `handle_datagram` (for the UDP size limit / TC decision)
- `listener.rs:376` — `ServeLoop::run_service` (for the error-response path)
- `layers.rs:100` — `DecisionStack::call` (for block/local synthesis)
- `forward.rs:112` — `ForwardService::call` (for the SERVFAIL path)

**Change:** scan once when the request is built (listener / `DnsRequest::new`) and store the `Option<EdnsInfo>` on `DnsRequest` with an accessor; downstream layers read it instead of rescanning. TCP path likewise.

Pure refactor — responses must be byte-identical. Existing listener/layer/forward tests must stay green; consider one assertion that the carried info matches a fresh scan.

Commit: `refactor(resolver): scan EDNS info once per query, carry it on DnsRequest`
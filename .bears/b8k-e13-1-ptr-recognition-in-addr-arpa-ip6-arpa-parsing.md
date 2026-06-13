---
id: b8k
title: E13.1 · PTR recognition + in-addr.arpa/ip6.arpa parsing
status: done
priority: P2
created: "2026-05-30T20:23:33.967846232Z"
updated: "2026-06-13T14:27:12.281629332Z"
tags:
  - dns
  - codec
parent: s2e
---

Recognize a reverse-DNS question and parse the address out of the arpa name. Pure, heavily-tested helper — the foundation for E13.2 and E13.4.

## Work
- Recognize a PTR question: qtype 12. Recommended: add `Qtype::Ptr` (= 12) to the enum (`src/codec/message.rs`) with its `From<u16>`/`Into<u16>` arms, and update the `Qtype::Other(_)` match in `src/resolver/local.rs`. (Alternatively keep matching `Other(12)` — but a named variant reads better now that we handle it.)
- Parser on a `Name` → `Option<IpAddr>`:
  - `<d>.<c>.<b>.<a>.in-addr.arpa` → `Ipv4Addr(a,b,c,d)` (reversed octets).
  - `<32 nibbles>.ip6.arpa` → `Ipv6Addr` (reversed nibbles).
  - Validate label count/format; malformed or non-arpa → `None`.

## Tests
- Round-trip a v4 address through its arpa form and back.
- Parse a full v6 `ip6.arpa` name.
- Reject malformed (wrong label count, non-hex nibble, octet > 255) → `None`.
- A normal forward name → `None`.
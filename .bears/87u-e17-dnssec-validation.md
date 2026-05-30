---
id: 87u
title: E17 · DNSSEC validation
type: epic
status: open
priority: P3
created: 2026-05-30T20:47:27.689044822Z
updated: 2026-05-30T20:47:41.115586308Z
tags:
- dns
- security
- roadmap
depends_on:
- ugd
---

**STUB — not in 0.2.0.** Roadmap epic; subtasks to be defined after E16's architecture fork is decided.

## Goal
Cryptographically validate DNSSEC: RRSIG/DNSKEY/DS chain verification up to the root trust anchor, plus NSEC/NSEC3 negative-existence proofs; return SERVFAIL on bogus. Targets the **privacy/security user**; the **speed user** leaves it off.

## Design notes (from planning)
- The validator is **mode-agnostic machinery** — the same logic validates records whether they came from recursion (E16) or from a forwarder. Sagittarius sits on a trusted LAN, so client-side validation isn't the driver; validating what *we* resolve is.
- **Wire it into the recursive track first** (depends on E16). Write the validator reusably so a **"validating forwarder"** posture (forward with DO=1 + validate the response) is a cheap later toggle — value even on a trusted network, since the threat is the upstream/path, not the LAN.
- Architecture: **strongly prefer `hickory-proto` DNSSEC validation** over hand-rolling crypto + NSEC3 (security-critical, huge).

## Relationship
Depends on **E16** (recursive track). Out of 0.2.0 scope (which is E10–E15).
# Sagittarius — Technical Specification

> Status: **Draft / pre-1.0.** 0.1.0 is released; 0.2.0 is in progress (see the
> §12 roadmap). This document describes the intended design and evolves as the
> implementation matures. Items under *Later (future)* in §12 are not yet
> scheduled.

Sagittarius is a self-hosted DNS sinkhole — a recursive/forwarding DNS server
that blocks unwanted domains (ads, trackers, malware) at the network level,
comparable to Pi-hole and AdGuard Home. It is written in Rust and ships as a
**single self-contained binary** with the DNS engine, storage, and web admin
interface all included.

---

## 1. Goals and non-goals

### Goals

- **Single binary.** No external runtime dependencies, no separate web server,
  no bundled interpreter. One executable plus a single SQLite database file.
- **Performance first.** The DNS hot path must be fast and allocation-conscious.
  Wire-format parsing is hand-written rather than delegated to a general-purpose
  library so the layout and copying behaviour can be controlled directly.
- **Low memory footprint.** Suitable for small home servers, routers, and SBCs
  (e.g. Raspberry Pi class hardware).
- **Operable.** A clean web UI for configuration, live query inspection, and
  statistics, protected by authentication.
- **Safe defaults.** Sensible out-of-the-box blocking and resolver behaviour.

### Non-goals (at least for now)

- Acting as an authoritative DNS server for public zones.
- A full-featured DHCP server *(may be revisited later)*.
- Clustering / multi-node coordination.
- Replacing a general-purpose recursive resolver's full feature set (DNSSEC
  validation is *(future)*, not part of v0.1).

---

## 2. Technology stack

| Concern | Choice | Notes |
|---|---|---|
| Language | Rust (edition 2024) | |
| Async runtime | [`tokio`](https://tokio.rs) | UDP/TCP listeners, task scheduling |
| Runtime lifecycle | [`tokio-util`](https://docs.rs/tokio-util) | `CancellationToken` + `TaskTracker` for graceful shutdown / in-flight drain (§10) |
| Error handling | [`thiserror`](https://docs.rs/thiserror) / [`anyhow`](https://docs.rs/anyhow) | Typed per-module library errors; `anyhow` only at the `main` boundary |
| Service middleware | [`tower`](https://docs.rs/tower) | Backpressure, load shedding, timeouts; hosts the per-client rate-limit layer |
| Per-client rate limiting | [`governor`](https://docs.rs/governor) | Keyed (per client IP) rate limiter behind a small `tower` layer — `tower`'s own limiter isn't keyed (§5, §11) |
| DNS socket setup | [`socket2`](https://docs.rs/socket2) | `SO_REUSEPORT` UDP listener pool + `IPV6_V6ONLY` clean dual-stack binds (§3.1) |
| DNS wire format | **Custom parser/serializer** over [`bytes`](https://docs.rs/bytes) | Shallow parse on the hot path; raw-bytes passthrough; no general name decompression on the fast path (see §5) |
| Upstream transport client | [`hickory`](https://github.com/hickory-dns/hickory-dns) | Scoped to upstream UDP/TCP/**DoT/DoH** transport, not receive-side parsing |
| Upstream selection | [`rand`](https://docs.rs/rand) | Random upstream choice per query, with failover (§7) |
| Blocklist fetching | [`reqwest`](https://docs.rs/reqwest) (rustls) | HTTP(S) client for blocklist sources with conditional `ETag`/`Last-Modified` requests (§6) |
| Persistent storage | SQLite via [`sqlx`](https://docs.rs/sqlx) | System of record for config, credentials, lists, local records, and the durable query-log history. Compile-time-checked queries (`query!`/`query_as!`); migrations embedded in the binary via the `sqlx::migrate!` macro |
| Logging / telemetry | [`tracing`](https://docs.rs/tracing) + [`tracing-subscriber`](https://docs.rs/tracing-subscriber) | Structured app + query logging to stdout; operator handles retention externally |
| CLI arguments | [`clap`](https://docs.rs/clap) | Operational flags (bind addresses, database path) with env fallbacks and sane defaults |
| In-memory blocking sets | `HashSet` / `HashMap` | Admin blacklist and allowlist (`HashSet`); the aggregated blocklist is a `HashMap<Name, blocklist_id>` recording each domain's primary source (§3.1, §6) |
| Lock-free state swap | [`arc-swap`](https://docs.rs/arc-swap) | Atomically swap immutable list snapshots so hot-path reads never block (§3.2) |
| Local DNS records | `HashMap` (exact) + suffix-probe wildcards | Handful of entries; wildcards like `*.home.lan` via most-specific suffix match |
| DNS cache | [`moka`](https://docs.rs/moka) | Per-entry expiration driven by record TTL |
| HTTP server | [`axum`](https://docs.rs/axum) | Admin API + UI, on tokio/tower |
| Password hashing | [`argon2`](https://docs.rs/argon2) | Argon2id admin password hashing (§9, §11) |
| HTML templating | [`askama`](https://docs.rs/askama) + [`askama_web`](https://docs.rs/askama_web) | Compile-time checked templates; `askama_web` for the axum response integration |
| Frontend interactivity | [Datastar](https://data-star.dev) (over SSE) | Fragments + reactive signals + SSE in one ~14 KB lib; no Alpine, no Node build step |
| Styling | [Pico CSS](https://picocss.com) + thin custom layer | Classless/semantic-first; one CSS file, dark mode, no build step |
| Asset delivery | `include_str!` / `include_bytes!` | All JS, CSS, images, favicon, and Lucide icon sprite (`icondata_lu`) vendored and compiled into the binary |

The web UI and DNS engine share the same tokio runtime and process.

### 2.1 Codec philosophy: shallow parse, raw passthrough

The receive-side codec is hand-written and deliberately *lazy*. It maps onto the
layered `tower` pipeline (§5): outer layers make their routing decision from a
**shallow parse** (header + question only) and can early-return without ever
touching the answer/authority/additional sections.

A key property makes this both fast and safe: the **question name is always the
first name in the message and is therefore never compressed** in a well-formed
packet (compression pointers can only reference a *prior* occurrence). The
routing-critical parser thus needs **no general name-decompression logic at
all** — the compression-pointer handling that is the classic source of DNS
parser vulnerabilities lives only in the RR sections, which the hot path never
walks. The codec still defensively rejects a pointer appearing in the question
and rejects `QDCOUNT != 1`.

What is hand-written is therefore a small, bounded surface — not a
general-purpose DNS library:

1. **Shallow reader** — header (12 bytes) + the single question.
2. **Response synthesis** — block answers (NXDOMAIN / null-IP / custom) and
   local-record answers built directly into the output buffer, EDNS-aware (see
   below).
3. **Bounded TTL scan** — on the forward path only, walk the RR sections once to
   find the minimum TTL and record the byte offsets of each real RR TTL field
   (§8). OPT pseudo-RRs are recognized and skipped because their TTL-shaped field
   is EDNS metadata, not a cache TTL. Name skipping here is hard-capped to defeat
   pointer loops.

**EDNS(0).** Routing needs only the header and question, so the shallow parse is
unaffected by EDNS — the claims above hold. Response *synthesis* is the one place
that peeks further: if the query carries an OPT record (additional section), a
synthesized block/local answer echoes a matching OPT, honouring the requestor's
advertised UDP payload size and reflecting an EDNS COOKIE when present. That is a
cheap scan of the additional section, which on a query is otherwise near-empty.
Forwarded and cached responses already carry the upstream's OPT through the
raw-bytes path, so no special handling is needed there beyond preserving it and
patching the response transaction ID.

hickory remains a dependency for upstream **transport** (it already implements
DoT/DoH); it is not used to deserialize received messages on the hot path.

---

## 3. High-level architecture

```
   DNS clients               ┌──────────────────────────────────────────────┐
  (UDP/TCP :53) ────────────►│  sagittarius — single process                 │
                             │                                               │
                             │  ┌───────────┐   ┌─────────────────────────┐  │
                             │  │ Listeners │──►│ Query pipeline (tower)  │  │
                             │  │  UDP/TCP  │   │  parse → local? →       │  │
                             │  └───────────┘   │  blacklist? → allow →   │  │
                             │                  │  blocklist? → cache →   │  │
                             │                  │  forward → reply → log  │  │
                             │                  └────────────┬────────────┘  │
                             │                               │               │
                             │  ┌────────────────┐  ┌────────▼─────────┐     │
   Admin browser             │  │ In-memory state│  │ Upstream client  │───────► Upstream
  (HTTP 127.0.0.1:8080)      │  │ blacklist /    │  │ UDP/TCP/DoT/DoH   │     │  resolvers
        ▲                    │  │ allowlist /    │  └──────────────────┘     │
        │                    │  │ blocklist set  │                           │
        ▼                    │  │ local records  │  ┌──────────────────┐     │
   ┌──────────────┐          │  │ moka cache     │◄─┤ SQLite (one file)│     │
   │ axum+askama  │◄────────►│  │ live-log buf   │  │ config, creds,   │     │
   │ +Datastar/SSE│          │  │ runtime stats  │  │ lists, records,  │     │
   └──────────────┘          │  └────────────────┘  │ blocklist cache  │     │
                             │                       └──────────────────┘     │
                             └──────────────────────────────────────────────┘
```

### 3.1 Components

1. **Listeners** — bind UDP and TCP on the configured DNS port(s), read raw
   datagrams/streams, and hand framed messages to the pipeline. TCP handles
   message length framing and large responses; UDP handles the common case and
   truncation (`TC` bit) fallback.

2. **Query pipeline** — a `tower` service stack wrapping the core resolver.
   Middleware layers provide rate limiting (per client), concurrency limiting /
   backpressure, timeouts, and load shedding. The inner service runs the
   resolution logic (§5).

3. **DNS codec** — custom, *lazy* parser/serializer over `bytes::Bytes`
   (see §2.1). A shallow parse (header + question) drives routing; the original
   datagram is carried through as refcounted `Bytes` so blocked/forwarded
   responses avoid re-serialization. Designed to validate untrusted input
   defensively and to minimize allocations on the hot path.

4. **In-memory state** — the hot data set. The first three are kept as distinct
   sets because they are consulted at different stages with different precedence
   (§5):
   - **Admin blacklist** (`HashSet`) — domains the admin explicitly blocked.
     Persisted in SQLite, mirrored in memory. Highest precedence.
   - **Allowlist** (`HashSet`) — domains the admin explicitly allowed; an
     *exception* that suppresses blocklist matching (but not the admin
     blacklist). Persisted in SQLite, mirrored in memory.
   - **Blocklist set** (`HashMap<Name, blocklist_id>`) — the aggregated,
     deduplicated domains expanded from all enabled blocklist *sources*, each
     mapped to its **primary source** so a block can be attributed to a list
     (§6). The decision layer still treats it as a presence check (`Name → bool`);
     attribution is read only off the hot path. **Memory-only at runtime**; only
     source definitions and cached fetched copies are persisted (§6).
   - **Local records** — a small set (typically a handful) served
     authoritatively. Records are keyed by normalized name and type (A/AAAA in
     v0.1), so the same local name may have both IPv4 and IPv6 answers. Exact
     names live in a `HashMap`; wildcard patterns (e.g. `*.home.lan`) are
     matched by stripping leftmost labels and probing for `*.<suffix>`, with
     the most-specific match winning. A local name match for a different qtype
     returns authoritative NODATA rather than leaking the private name upstream.
     Deliberately *not* optimized for large volumes — a reversed-label trie is
     a future option if domain-suffix blocking is ever added (§12). A derived
     **reverse index** (`IpAddr → name`) is built alongside this snapshot from
     the exact A/AAAA records so reverse (PTR) queries for IPs we own are
     answered authoritatively (§5); when several names share an address the
     canonical one is chosen deterministically (shortest name, lexical
     tie-break). Wildcards are excluded from the reverse index — they map a
     pattern, not a concrete host.
   - **Conditional-forward zones** — the enabled `forward_zones` (§4) compiled
     into a most-specific-wins suffix → target map plus a small set of upstream
     forwarders (one per distinct target, deduplicated). Held in an atomically
     swappable snapshot like the upstream pool; rebuilt and swapped when the
     admin edits a zone. Consulted between local records and the blocking stages
     (§5).
   - **Cache** (`moka`) — positive and negative answers keyed by
     `(qname, qtype, qclass)`, each entry expiring per the record TTL.
   - **Runtime settings snapshot** — cache TTL bounds, negative-TTL cap,
     blocking mode/custom sinkhole IP, and refresh interval are loaded from
     SQLite into an atomically swappable snapshot. Admin setting changes write
     through to SQLite, then update the live snapshot so new queries observe the
     change immediately where the underlying subsystem supports it.

   The following are **runtime-only** (not loaded from or written to SQLite) and
   reset on restart:
   - **Live-log tail** — a `tokio::sync::broadcast` channel that the admin SSE
     endpoint subscribes to for the real-time tail. Durable history lives in the
     `query_log` table (§4); the admin log page seeds from the DB and then
     streams the broadcast for "now" forward (the in-memory ring buffer is gone).
   - **Runtime stats** — lightweight in-memory counters/aggregates (total
     queries, blocked count/ratio, top domains, top clients) maintained as
     queries flow. These are the *since-startup* live figures; the dashboard also
     shows a restart-surviving window computed from `query_log` (§9).

5. **Upstream client** — forwards cache-miss, non-blocked, non-local queries to
   configured upstream resolvers over plain UDP/TCP and encrypted DoT/DoH.

6. **Storage (SQLite)** — durable system of record (§4). At startup the relevant
   configuration tables are read into the in-memory structures; updates via the
   admin UI write through to SQLite and refresh memory. It also holds the durable
   **`query_log`** table — per-query history written off the hot path (§4, §9).

7. **Telemetry** — every resolved query is (a) emitted as a structured event via
   `tracing` to stdout, where the operator can route it (journald, file, log
   shipper) for any retention they want, (b) pushed to the in-memory live-log
   broadcast for the admin UI tail, and (c) — when query logging is enabled —
   enqueued onto a bounded channel that a dedicated writer task batches into the
   `query_log` table. The enqueue never blocks the response path: a full channel
   drops (and counts) the event rather than awaiting (§3.2, §9).

8. **Web admin (axum + askama)** — configuration, list management, live query
   log, and dashboards. Always authenticated; serves plain HTTP behind a reverse
   proxy that terminates TLS (§9, §10).

9. **Background tasks** — long-lived tokio tasks decoupled from the hot path.
   Chief among them is the **blocklist refresh scheduler** (periodic and
   on-demand: fetch → parse → dedupe → atomically swap the blocklist set, §6).
   A failed refresh never blocks query serving — the last good snapshot stays in
   use until the next successful fetch.

### 3.2 Concurrency & shared state

All shared runtime state is built for many concurrent readers (the per-query hot
path) and occasional writers (admin edits, blocklist refresh):

- **List snapshots behind `arc-swap`.** The admin blacklist, allowlist,
  aggregated blocklist set, and local records are each held as an immutable
  `Arc<…>` snapshot inside an `ArcSwap`. A query reads the current snapshot with
  a cheap atomic load and never blocks; a writer builds a fresh structure *off*
  the hot path and atomically swaps it in, so no reader ever sees a torn or
  partially-updated set. The blocklist snapshot is a `Name → primary
  blocklist_id` map, but the decision layer reads it as a presence check; the
  attribution value is consulted only off the hot path (§6).
- **Cache.** `moka` is already a concurrent cache; shared via `Arc`, no extra
  locking.
- **Stats.** Runtime counters are atomics (top-N may use a sharded/relaxed
  structure); the dashboard reads a consistent-enough snapshot.
- **Live-log.** Query events are published to a `tokio::sync::broadcast` channel
  (one receiver per SSE subscriber) for the real-time tail. History is no longer
  kept in memory: a freshly opened log view seeds from the `query_log` table
  (keyset-paginated, newest-first) and then streams the broadcast. Persistence is
  decoupled via a bounded `mpsc` channel drained by a batching writer task, so
  the hot path never waits on a DB write.
- **Runtime settings / upstream pool.** Runtime settings and the active upstream
  pool are replaced as whole immutable snapshots when the admin changes them.
  Cache capacity is the exception: `moka` capacity is fixed when the cache is
  built, so changing it rebuilds the cache or requires restart depending on the
  implementation path chosen by the UI.
- **Blocking pause.** A single atomic Unix-second deadline (`0` = active) records
  when a temporary pause (§5, §9) expires. The hot path reads it with one relaxed
  atomic load and auto-resumes by comparison — no timer. It is **runtime-only,
  never persisted**, so a restart resumes blocking (fail-safe), and pausing
  touches no list snapshot (nothing to rebuild or refresh on resume).
- **Per-upstream health.** A small per-upstream tracker (EWMA latency,
  success/failure counts, last error) updated on every forward attempt (§7). It
  is **runtime-only** (resets on restart, like `Stats`) and lives on the
  hot-swappable upstream pool handle so it survives a pool rebuild on an
  upstream-config or strategy change. The answering upstream now populates each
  `QueryEvent` (previously always absent), so the persisted query log records it.

The DNS engine and web admin share these structures by `Arc` within the single
process. Every admin mutation **writes through to SQLite first, then swaps the
in-memory snapshot**, keeping the durable store and memory in agreement.

---

## 4. Data model (SQLite)

The exact schema will be defined in migrations; this is the conceptual model.

The database holds global configuration **and** the durable per-query history
(`query_log`, below).

- **settings** — a typed single-row table for global configuration: cache
  sizing and TTL bounds (including the negative-TTL cap), blocking
  mode/response, blocklist refresh interval, UI preferences, and the query-log
  controls (`query_log_enabled`, default on; `query_log_retention_days`, default
  30). (Network bind addresses, the database file path, and cookie-security
  policy are CLI/env operational settings, not stored here — see §10.)
- **upstreams** — resolver definitions: address, transport (`udp`, `tcp`,
  `dot`, `doh`), optional TLS server name, enabled flag, and sort order.
- **admin_users** — admin credentials for the web UI: username, password hash
  (Argon2id), role, timestamps.
- **sessions** — active admin sessions. Session tokens are opaque random values;
  only a token hash is stored in SQLite, alongside user, created, and expiry
  timestamps.
- **blocklists** — subscribed blocklist sources: URL, format, enabled flag,
  last-updated, entry count, ETag/last-modified for conditional refresh.
- **blacklist** — domains/patterns the admin explicitly blocked. Highest
  precedence; wins over the allowlist and blocklists.
- **allowlist** — domains/patterns the admin explicitly allowed. An exception
  that suppresses **blocklist** matches (not the admin blacklist), letting a
  single domain be permitted without editing a multi-thousand-entry blocklist.
- **local_records** — local DNS entries: name (incl. wildcard), type, value,
  TTL; resolved authoritatively without contacting upstreams.
- **forward_zones** — conditional-forward zones: a `zone_suffix` → `target`
  (resolver `IP` or `IP:port`, nullable until set) routing table with an
  `enabled` flag and sort order. A query whose name falls under an enabled zone
  is forwarded to that zone's target instead of the default upstream pool (§5,
  §7). Seeded with the RFC1918 / ULA reverse zones (`10.in-addr.arpa`,
  `16.172.in-addr.arpa`…`31.172.in-addr.arpa`, `168.192.in-addr.arpa`,
  `c.f.ip6.arpa`, `d.f.ip6.arpa`) **disabled with a NULL target** so the admin
  can point LAN reverse-DNS (PTR) at the router/DHCP resolver. The mechanism is
  general, not PTR-specific — it later serves split-horizon forward zones
  (e.g. `corp.internal`) too.
- **query_log** — durable per-query history, one row per resolved query: `id`
  (autoincrement; chronological order + pagination cursor), `ts` (receipt time,
  epoch **milliseconds**), `client` (IP), `qname`, `qtype`, `outcome` (a stable
  token), nullable `rcode` and `upstream`, `latency_ms`, and a nullable
  `blocklist_id` attributing a `blocked-blocklist` row to its primary source
  (§6). `blocklist_id` is a **plain integer, not a foreign key** — keeping the
  bare id preserves historical attribution after a list is deleted (the read
  path LEFT JOINs `blocklists` and shows unknown ids as "removed list") and keeps
  the write-heavy inserts cheap. Indexed on `ts` for the retention purge;
  pagination uses the primary key. Writes are batched off the hot path by a
  dedicated writer task; an hourly purge deletes rows older than the retention
  window and runs `PRAGMA incremental_vacuum` to return freed pages (the pool
  sets `auto_vacuum = INCREMENTAL` for fresh databases).

**Deferred to post-MVP** *(future)*:

- **stats** — materialized aggregates for historical dashboards/charts. The
  dashboard's persisted window is currently computed from `query_log` aggregates
  on demand (no charts yet); a materialized table would back time-series charts.

Blocklist *contents* are expanded into the in-memory blocklist set during the
blocklist scheduler's offline-start phase; SQLite stores the source definitions
and cached fetched copies so the service can start while offline.

**Seed defaults.** Sensible default configuration is inserted directly by the
migration scripts, so a freshly created database is usable out of the box with
no special first-run logic. Examples: default upstream resolvers
**`1.1.1.1`** and **`1.0.0.1`** (Cloudflare), default cache bounds, and the
default sinkhole response. The admin can change any of these later via the UI;
the seed values are only the starting point.

---

## 5. DNS query lifecycle

The resolution path is expressed as a `tower` service stack. The request that
flows through it carries the original datagram plus the shallow parse:

```rust
struct DnsRequest {
    raw: Bytes,         // original datagram, refcounted
    header: Header,     // 12 bytes, trivially parsed
    question: Question, // normalized qname + qtype + qclass
    client: SocketAddr,
}
```

Each layer routes on `question` alone. Some layers **short-circuit** with a
response (local records, blocks, cache hits); the allowlist layer does **not** —
it only sets a flag and lets the request continue. Only the innermost forward
service ever parses past the question.

```
RateLimit ─► ShallowParse ─► LocalRecords ─► ForwardZones ─► Blacklist ─► Allowlist ─► Blocklists ─► Cache ─► Forward
 (tower)      (codec)        (answer/PTR)    (cond. fwd)      (block)       (set flag)   (block*)      (hit)    (inner)
                                             routes          continues    *unless flag set
```

**Precedence:** local records win over everything (including local PTR synthesis
for IPs we own); then **conditional-forward zones** route matching names ahead of
all blocking — you don't block your own reverse zones; then the admin
**blacklist** (explicit deny) wins over the **allowlist** (explicit allow); the
allowlist in turn only suppresses the bulk **blocklists**.

**Pause gate.** When blocking is temporarily paused (§9), the three blocking
stages — blacklist, allowlist, blocklist — are skipped immediately after local
records, and the query proceeds to cache/upstream for a real answer. Local
records are unaffected (they sit above the gate and stay authoritative). The
pause is a runtime-only deadline (§3.1) that auto-resumes by comparison, so a
would-be-blocked query during a pause resolves and logs as **forwarded** /
**cached**.

1. **Rate limit / load shed / timeout.** `tower` layers protect the engine
   before any work is done (per-client limits, concurrency cap, deadlines).
2. **Shallow parse.** Reject malformed messages and `QDCOUNT != 1`. Read the
   header and the single question; normalize the name (lowercase, trailing dot).
   No name decompression is needed here (§2.1). If enough of the header was
   parsed to recover the transaction ID, return `FORMERR`; otherwise drop the
   packet/stream message because no valid response can be addressed.
3. **Local records.** If the name matches a local record (exact or wildcard)
   for the requested qtype, synthesize an authoritative answer into the output
   buffer and return. If the name is local but has no record for the requested
   qtype, return authoritative NODATA. **Reverse (PTR) queries** are handled
   here too: a PTR question's `in-addr.arpa` / `ip6.arpa` name is parsed back to
   an `IpAddr`, and if it belongs to a local A/AAAA record the reverse index
   (§3.1) yields the canonical name, which is synthesized as an authoritative
   PTR answer (RDATA = the name encoded as DNS labels). A reverse query for an
   address we do **not** own falls through — it is **not** answered NODATA here,
   so it can reach conditional forwarding / the upstream pool. Local records are
   absolute — checked first, ahead of all blocking — and skip the cache and
   upstream entirely.
4. **Conditional-forward zones.** If the name falls under an enabled forward
   zone (most-specific suffix wins, §3.1), route the query to that zone's target
   resolver instead of the default upstream pool, then continue through the
   normal **cache → forward** path (zone answers are cached like any upstream
   answer). This sits below local records (a local PTR answer wins) and **above**
   the blocking stages, so a host never blocks its own reverse zones. On no match
   the query continues unchanged.
5. **Admin blacklist.** If the name is in the admin blacklist (**exact match**),
   synthesize the configured sinkhole response from the question — `NXDOMAIN`,
   `0.0.0.0` / `::`, or a configured custom IP — and log as **blocked**. Highest
   blocking precedence; not overridable by the allowlist.
6. **Allowlist.** If the name is in the allowlist, set an `allow-bypass` flag and
   **continue** (this is an exception, not an answer). The flag tells the
   blocklist layer to stand down so the query proceeds to cache/upstream for a
   real answer.
7. **Blocklists.** If the name is in the aggregated blocklist set (**exact
   match**) and the `allow-bypass` flag is not set, synthesize the sinkhole
   response and log as **blocked**. No full parse required.
8. **Cache lookup.** Check the `moka` cache keyed by `(qname, qtype, qclass)`.
   On hit, re-emit the cached raw bytes, patching the transaction ID and TTL
   fields in place (§8), and log as **cached**.
9. **Upstream resolution (inner service).** On miss, forward to an upstream
   chosen by the configured selection strategy (§7) over its transport
   (UDP/TCP/DoT/DoH) via the hickory client, recording the answering upstream
   and its latency. Apply a per-query timeout and fail over (or race, in
   parallel mode) on error/timeout (§7).
10. **Cache store.** Scan the response once for the minimum positive-answer TTL,
   recording each real RR TTL field's byte offset (excluding EDNS OPT
   pseudo-RRs). Positive responses use that minimum TTL; negative responses
   (`NXDOMAIN` / `NODATA`) use the SOA-derived negative TTL where available and
   are not cached if no SOA-derived TTL is available. Expiry is capped by the
   configured negative-TTL cap for negative answers and then clamped to the
   configured min/max bounds.
11. **Reply.** Send the response to the client, patching the transaction ID to
    the client's query ID for both forwarded and cached raw-byte responses. Set
    the `TC` bit and expect TCP retry if a UDP response would exceed size
    limits.
12. **Log.** Emit the outcome as a structured `tracing` event to stdout, update
    the in-memory runtime stats, and push the event onto the live-log broadcast
    for the admin SSE stream. No database write in v0.1.

**Blocking granularity (v0.1): exact match only.** Both the admin blacklist and
the blocklist set are matched as exact domains (a single `HashSet` lookup).
Subdomain / parent-label blocking is future scope — it is the feature that would
motivate the reversed-label trie noted in §3.1 (§12).

**Response codes.** Beyond the synthesized block answers above (`NXDOMAIN` /
null-IP / custom, per the configured block mode) and authoritative local
`NODATA`, the pipeline maps failure conditions to standard RCODEs:

- **`FORMERR`** — a malformed but recoverable query (e.g. `QDCOUNT != 1` or a
  compression pointer in the question) whose transaction ID could still be read.
- **`REFUSED`** — load-shed by the protective `tower` layers: per-client rate
  limiting (§11) or backpressure rejection.
- **`SERVFAIL`** — the inner resolver could not produce an answer: the per-query
  timeout elapsed or every upstream in the failover budget failed (§7).
  `SERVFAIL` responses are not cached.

---

## 6. Blocklists

- **Sources.** Users subscribe to blocklist URLs. Supported input formats:
  - **hosts** format (`0.0.0.0 example.com`),
  - **domain lists** (one domain per line).

  AdBlock-style rule parsing is future scope; v0.1 deliberately keeps parsers
  to the two simple domain-oriented formats above.
- **Refresh.** Lists are fetched on a schedule and on demand, using
  `ETag`/`Last-Modified` for conditional requests. A cached copy is retained
  **in the SQLite database** (not as separate files) so startup works offline.
- **Aggregation.** All enabled blocklist sources are fetched, parsed,
  deduplicated, and expanded into a single in-memory **blocklist set** at startup
  and on refresh. This set is memory-only — only the source URLs (and optional
  cached copies) are persisted. The admin **blacklist** and **allowlist** are
  kept as separate sets (§3.1) and applied with their own precedence at query
  time (§5); they are never merged into the blocklist set.
- **Per-domain attribution.** The aggregated set is a `Name → primary
  blocklist_id` map: each domain records the **primary source** that contributed
  it. On overlap, the first writer wins; sources are aggregated in ascending
  `blocklist_id` order, so the **lowest-id (oldest-subscribed) list** is the
  primary. Only this single primary is stored — a deliberate trade-off that keeps
  the map value a bare `i64` (no bitmask, no per-domain source list) at the cost
  of overlap / "uniquely blocked by X" analysis (a junction table could add that
  later). Attribution is resolved **off the hot path** by the query-log writer,
  which reads the live snapshot and stamps `query_log.blocklist_id` for
  `blocked-blocklist` rows; the decision layer itself stays a pure presence
  check. This is eventually consistent — a refresh in the ~1s write delay can
  shift or drop an attribution (→ `NULL`), which is acceptable for effectiveness
  telemetry.
- **Counts.** Per-list entry counts and last-update times are surfaced in the UI.

---

## 7. Upstream resolution

- Multiple upstreams may be configured. The **selection strategy** (set in the
  admin UI, §9) decides how an upstream is picked per query:
  - **random** (default) — uniform shuffle, spreading load evenly;
  - **latency-weighted** — weighted-random bias toward faster, healthier
    upstreams (weight ∝ success ÷ EWMA latency), while still exploring;
  - **parallel** — race the first *N* upstreams concurrently and take the first
    success, cancelling the rest, so a slow upstream never gates the answer.
- Transports: **UDP**, **TCP**, **DNS-over-TLS (DoT)**, **DNS-over-HTTPS (DoH)**.
- The sequential strategies (random / latency-weighted) apply a per-query
  timeout and **fail over** to the next upstream on error/timeout; the default
  budget tries at most two upstreams total so the outer resolver timeout stays
  bounded and predictable.
- **Per-upstream health** is tracked in memory: every forward attempt records
  which upstream answered, its latency (an EWMA), and success/failure counts —
  feeding the latency-weighted selector and the admin dashboard (§9). The
  answering upstream is also recorded on each query event (and so in the
  persisted query log, §4).
- `hickory` is used as the upstream client to avoid reimplementing DoT/DoH
  transport details; the receive-side codec remains custom (§2.1).
- Default seeded upstreams are Cloudflare `1.1.1.1` / `1.0.0.1` (§4), changeable
  via the admin UI.
- **No DNSSEC in v0.1.** Forwarded queries set the EDNS `DO` bit to `0`
  (`edns_set_dnssec_ok = false`); Sagittarius does not request or validate
  DNSSEC records. Validation is future scope (§12).

---

## 8. Caching

- Backed by `moka` with **per-entry expiration** so each cached answer lives
  exactly as long as its DNS TTL (clamped to configured min/max).
- **Raw-bytes cache.** Entries store the upstream response *as received*
  (`Bytes`) together with the byte offsets of each TTL field, recorded during
  the min-TTL scan (§5 step 10). EDNS OPT pseudo-RRs are not TTL-bearing records
  and are excluded from offset recording. Nothing is re-serialized on a hit.
- **Cheap, correct serving.** On a hit the cached bytes are re-emitted with two
  in-place patches: the **transaction ID** (set to the client's query ID) and
  the **TTL fields** at the recorded offsets (decremented by elapsed time). No
  parse, no allocation, no re-serialization.
- Caches both **positive** answers and **negative** responses (`NXDOMAIN` /
  `NODATA`) using the SOA-derived negative TTL ([RFC 2308](https://www.rfc-editor.org/rfc/rfc2308))
  where available; SOA-less negative responses are served but not cached.
- Keyed by `(qname, qtype, qclass)`.
- Bounded by a configurable maximum size; eviction handled by `moka`.

---

## 9. Web administration

- **Server.** `axum` on the shared tokio runtime, fronted by `tower` middleware.
- **Rendering.** `askama` compile-time templates render the HTML and fragments;
  **Datastar** drives interactivity (fragment merges + reactive signals) with no
  JS build toolchain. The live query log streams over **SSE**, and a single SSE
  stream can update the log *and* the dashboard counters together (merge-signals)
  — which is why Datastar suits this UI. Styling is **Pico CSS** (classless, so
  the semantic HTML rendered by Askama is styled automatically) plus a thin
  custom stylesheet for bespoke widgets.
- **Asset delivery.** All frontend assets — the Datastar JS, Pico CSS, the custom
  stylesheet, images, and favicon — are **vendored into the repository and
  compiled into the binary** via `include_str!` / `include_bytes!`. No external
  CDN fetches at runtime and no Node build step. **Icons** are a curated handful
  of [Lucide](https://lucide.dev) glyphs pulled from the `icondata_lu` crate and
  rendered once into a single `<symbol>` sprite served at `/assets/icons.svg`
  (`src/web/icons.rs`); templates reference them via the `icon` askama macro, and
  because Lucide strokes with `currentColor` they inherit text colour and theme
  automatically. The admin UI is responsive: a hamburger drawer below ~768 px.
- **Capabilities:**
  - Dashboard: sections of figures (no charts). The **live (since-startup)**
    cards — total queries, blocked count/ratio, top blocked domains, top clients
    — come from the in-memory runtime counters and update over SSE. A **last-24h
    (persisted)** section is computed from `query_log` aggregates and so survives
    restart. A **System** panel shows version, uptime, queries/sec, cache fill
    (entries / capacity), and the process's own resident memory; uptime and qps
    tick client-side. A **per-upstream health** table shows each upstream's
    address, query count, success rate, EWMA latency, and last error (§7).
    *(Historical/time-series charts remain deferred to post-MVP.)*
  - Live query log: the page seeds the newest page of history from the
    `query_log` table and then streams the real-time tail over SSE, with
    **scroll-back** (`Load older` paginates further back by row id) and
    client-side filtering. **One-click list management**: rows blocked by the
    blocklist expose a *Whitelist* action (add to the allowlist), and
    forwarded/cached resolved rows expose a *Blacklist* action (add to the admin
    blacklist). Rows whose outcome would make the action ineffective (for
    example local-record answers, or admin-blacklist blocks that the allowlist
    cannot override) do not offer that one-click action. The list change writes
    through to SQLite and refreshes the in-memory sets immediately.
  - Blocklist subscription management (add/remove/enable, manual refresh). The
    page also shows **per-list effectiveness**: each source's windowed block
    count (last 24h) and its share of all blocklist blocks, so the admin can see
    which lists are pulling their weight. Blocks credited to a source that has
    since been removed are summarized as a "removed list" row (§6).
  - Manual blacklist / whitelist editing.
  - **Pause blocking** for a chosen duration (5 m / 30 m / 1 h, or a custom value)
    with a *Resume now* control — a navbar menu plus a countdown banner shown on
    every page while paused (the remaining time counts down client-side). All
    blocking stands down for the duration (§5); local records keep answering. The
    deadline is runtime-only, so a restart resumes blocking (§3.2).
  - Local DNS record management (including wildcards).
  - Upstream resolver configuration, including the **selection strategy**
    (random / latency-weighted / parallel) and the parallel fan-out (§7).
  - **Conditional forwarding** (§4, §5): list the forward zones, set each zone's
    router/DHCP target resolver, and toggle it on/off, plus a one-click
    "forward all reverse zones here" action that points every private reverse
    zone at a single resolver — the common LAN reverse-DNS setup. Edits write
    through to SQLite and rebuild the live zone forwarders immediately.
  - Settings — including the **query-log controls**: an enable/disable toggle
    (logging on by default), a retention window in days (default 30), and a
    *Clear query log now* action that purges all stored history.
- **Auth.** Admin login backed by `admin_users`; passwords hashed with
  **Argon2id**. Session cookies hold opaque random tokens; SQLite stores only a
  hash of each token. The admin interface is never exposed unauthenticated. On
  first run (empty `admin_users`) a one-step wizard collects the initial admin
  username/password before the UI unlocks (§10).
- **Session-cookie security.** Because Sagittarius does not terminate TLS in
  v0.1, cookie `Secure` handling is an operational policy: `auto` (default),
  `always`, or `never`. `auto` sets `Secure` when the browser-facing request is
  HTTPS (directly or via trusted `X-Forwarded-Proto: https`) and omits it for
  direct plain-HTTP use such as loopback/local testing. Secure cookies use the
  `__Host-sgt_session` name; insecure/plain-HTTP cookies use a non-prefixed
  name so browser prefix rules are respected. `HttpOnly`, `SameSite=Strict`,
  and `Path=/` are always set. Operators should use `always` behind a correctly
  configured TLS reverse proxy and avoid `never` on untrusted networks.
- **CSRF.** All state-changing requests (the one-click list buttons, settings,
  list edits) are CSRF-protected — `SameSite` cookies plus an anti-CSRF token
  and origin checks — so a malicious page cannot drive the admin API.
- **TLS.** Not built in for v0.1. Front the admin interface with a reverse proxy
  (Caddy, Traefik, nginx) to terminate TLS and manage certificates (e.g. Let's
  Encrypt). The app serves plain HTTP and is expected to bind a local/loopback
  or trusted-network address in that setup. Native TLS/ACME may come later (§12).

---

## 10. Configuration & deployment

- **Single binary** containing the DNS engine, web server, embedded UI assets,
  and SQLite access.
- **CLI arguments.** Operational settings are `clap`-parsed flags with
  environment-variable fallbacks and sane defaults:
  - `--admin-addr` — admin interface bind address, default **`127.0.0.1:8080`**
    (loopback, since TLS/exposure is the reverse proxy's job — §9).
  - `--dns-addr` — DNS listener bind address, default **`0.0.0.0:53`**. May be
    repeated to bind several addresses, e.g. add `[::]:53` for IPv6 (dual-stack);
    AAAA queries are resolved/forwarded normally and blocked with `::`.
  - `--db-path` — path to the SQLite database file, default
    **`sagittarius.db`** (in the working directory). Packaged/systemd installs
    typically point this at something like `/var/lib/sagittarius/sagittarius.db`.
  - `--session-cookie-secure` — `auto` / `always` / `never`, default
    **`auto`**; controls whether admin session cookies carry the `Secure`
    attribute when Sagittarius is behind a TLS-terminating reverse proxy or is
    accessed directly over plain HTTP (§9).

  Application configuration (upstreams, lists, local records, etc.) lives in
  SQLite and is managed through the admin UI, not via flags.
- **Persistence is a single file.** The SQLite database is the only on-disk
  artifact — it holds config, credentials, lists, local records, *and* the
  cached blocklist contents (§6). There is no separate data directory.
- **Bootstrapping.** On startup the embedded migrations (`sqlx::migrate!`) run
  against the SQLite file, creating or upgrading the schema as needed. The
  migrations also **seed default configuration** (e.g. Cloudflare `1.1.1.1` /
  `1.0.0.1` upstreams — §4), so a fresh database works immediately.
- **First-run wizard.** If the `admin_users` table is empty, the web UI presents
  a one-step wizard that collects **only a username and password** for the
  initial admin account. Everything else is already bootstrapped to working
  defaults by the migrations, so the DNS resolver is functional immediately on
  startup even before the admin account is created; settings can be adjusted in
  the UI afterwards.
- **Privileges.** Binding port 53 typically requires elevated privileges or a
  granted capability (`CAP_NET_BIND_SERVICE` on Linux); the listen port is
  configurable for unprivileged setups.
- **Process management.** Intended to run under systemd (or a container) as a
  long-lived service. Example deployment files ship in `deploy/` (a hardened
  systemd unit, a Caddy reverse-proxy snippet, and a Docker Compose file).
- **Distribution.** Tagged releases publish prebuilt Linux `x86_64`/`aarch64`
  binaries (GitHub Releases), the `sagittarius` crate (crates.io, for
  `cargo install`), and a multi-arch container image
  (`ghcr.io/lhelge/sagittarius`). See `RELEASING.md`.
- **Graceful shutdown.** On `SIGTERM`/`SIGINT` the process stops accepting new
  queries, lets in-flight ones drain within a bounded timeout, and closes the
  SQLite connection cleanly before exiting.
- **TLS / remote access.** The admin interface serves plain HTTP in v0.1; put a
  reverse proxy (Caddy, Traefik, nginx) in front of it for TLS and certificate
  management. Bind the admin interface to loopback or a trusted network so it is
  not directly exposed.

---

## 11. Security considerations

- Treat all inbound DNS as untrusted; the custom parser must be hardened against
  malformed/oversized messages, compression-pointer loops, and amplification
  vectors.
- Rate limiting / load shedding via `tower` to resist floods and reduce
  amplification abuse.
- Admin credentials hashed with Argon2id; admin surface always authenticated,
  with CSRF protection on all state-changing requests (§9). TLS is provided by a
  fronting reverse proxy in v0.1 (§9), so the app should bind a
  loopback/trusted-network address rather than a public interface.
- When deployed behind a reverse proxy, forwarded scheme/host headers used for
  secure-cookie `auto` mode and CSRF origin checks must come only from a trusted
  proxy. Direct public plain-HTTP admin exposure is not a safe deployment.
- Query events may contain sensitive browsing data. They are emitted to stdout
  via `tracing` and, **when query logging is enabled (the default), persisted to
  the `query_log` table** with their client IP, queried name, and outcome. This
  is a deliberate privacy trade-off for a useful, restart-surviving log and
  dashboard — and it is operator-controllable: logging can be **disabled**
  entirely (settings toggle), the **retention window** is configurable (default
  30 days, enforced by an hourly purge), and a **Clear query log now** action
  wipes stored history on demand. Operators handling others' traffic should set
  retention deliberately, or disable logging, to match their privacy obligations;
  the database file itself should be protected like any store of personal data.
  Log verbosity (the stdout stream) remains independently configurable.

---

## 12. Roadmap

### v0.1 — first milestone *(released as 0.1.0)*

- [x] Custom lazy DNS codec: shallow reader (header + question), EDNS/OPT-aware
      response synthesis, bounded TTL scan (UDP + TCP).
- [x] `cargo-fuzz` target for the codec against malformed/adversarial input.
- [x] tokio listeners (IPv4/IPv6) + tower pipeline (rate limit, timeout,
      backpressure, early-return layers).
- [x] In-memory blacklist/allowlist/blocklist sets + local-record map with
      wildcards behind `arc-swap`; moka raw-bytes cache with TTL-offset patching.
- [x] Upstream forwarding incl. **DoH/DoT** (hickory transport client).
- [x] Blocklist subscription, fetch, aggregation, and background refresh
      scheduler (atomic snapshot swap).
- [x] SQLite storage (config only) + migrations (schema + seed defaults) +
      startup load into memory.
- [x] `tracing`/`tracing-subscriber` query + app logging to stdout.
- [x] In-memory live-log buffer + broadcast and runtime stats counters.
- [x] axum + askama + Datastar (SSE) admin UI (live log + dashboard), Pico CSS,
      authentication + CSRF protection.
- [x] Graceful shutdown (drain in-flight queries, close DB cleanly).
- [x] Vendor all frontend assets and embed via `include_str!`/`include_bytes!`.

### v0.2 — next milestone *(planned)*

Scoped as epics **E10–E15** in the project task tracker. The §-level design for
each feature is filled in as it lands; this list is the milestone scope.

- **Persistent query log & historical telemetry** (E10) — per-query rows
  persisted to SQLite, written off the DNS hot path (bounded queue + batched
  writes); configurable retention (default 30 days) with a periodic purge and
  incremental vacuum; a DB-backed, paginated live log (replacing the in-memory
  ring buffer); windowed, restart-surviving dashboard figures; a logging
  enable/disable toggle and a clear-log action.
- **Per-list blocklist effectiveness** (E11) — record which blocklist source
  blocked each request (primary source per domain, resolved off the hot path)
  and surface per-list block counts.
- **Temporarily pause blocking** (E12) — disable all blocking for a chosen
  duration (5 min / 30 min / 1 h / custom) with resume-now; auto-resumes.
- **Reverse DNS for the LAN** (E13) — *shipped*: synthesizes PTR from local
  records (an `IpAddr → name` reverse index, §3.1) and conditional-forwards the
  private `in-addr.arpa` / `ip6.arpa` zones to the router/DHCP via a general
  `forward_zones` mechanism (§4, §5) that also serves split-horizon forward
  zones later.
- **Client hostname decoration** (E14) — show device hostnames (IP fallback) in
  the live log and top-clients via internal, cached reverse lookups.
- **Upstream selection & health** (E15) — per-upstream response-time tracking
  and telemetry, plus selection strategies beyond random (latency-weighted and
  parallel).

### Later *(future)*

- Historical dashboard **time-series charts** built on the durable query log
  (server-rendered SVG or a tiny lib such as uPlot; vendored and embedded like
  all other assets).
- **Recursive resolution** mode (E16) — iterate from the root instead of
  forwarding; likely built on `hickory-recursor`, kept as an opt-in mode so the
  raw-passthrough forward path is unaffected.
- **DNSSEC validation** (E17) — validate the RRSIG chain to the root trust
  anchor; wired into the recursive track first and reusable for a
  validating-forwarder mode. Depends on the recursive track.
- Subdomain / parent-domain blocking (reversed-label trie, shared with local
  records — §3.1).
- Native TLS / built-in ACME (Let's Encrypt) for the admin interface.
- Per-client / per-group policies.
- Integrated DHCP server and DHCP-driven local records.
- Full AdBlock filter syntax.
- Prometheus metrics / external observability.
- Import/export and backup tooling.

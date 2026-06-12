# Sagittarius

> A fast, self-hosted DNS sinkhole in a single Rust binary.

Sagittarius is an open-source, network-wide DNS sinkhole — it blocks ads,
trackers, and malicious domains for every device on your network, in the spirit
of [Pi-hole](https://pi-hole.net/) and
[AdGuard Home](https://adguard.com/en/adguard-home/overview.html). Everything —
the DNS engine, storage, and web admin interface — ships in **one
self-contained binary**.

It is named after **Sagittarius A\***, the supermassive black hole at the centre
of the Milky Way: a fitting namesake for something whose job is to make unwanted
traffic disappear.

> ⚠️ **Early development.** Sagittarius is pre-1.0 and not yet ready for general
> use. The design is described in [`SPEC.md`](SPEC.md); interfaces and features
> are still changing.

---

## Goals

- **Single binary** — no external services, interpreters, or web server to set up.
- **Fast** — a hand-written DNS codec and a `tokio`/`tower` request pipeline keep
  the hot path lean.
- **Light** — runs comfortably on small home servers, routers, and SBCs.
- **Operable** — a clean, authenticated web UI for configuration, live query
  inspection, and statistics.

## Planned features (v0.1)

- 🛡️ **DNS blocking** via subscribable blocklists (hosts / domain-list formats)
  plus manual allow/deny lists. Exact-domain matching in v0.1. **Per-list
  effectiveness** shows how many blocks each source contributed (last 24h) and
  its share of the total, so you can see which lists are pulling their weight.
- 📊 **Live query log and dashboard** — block ratio, top domains, top clients,
  and a live query log streamed over SSE, with one-click allow/deny straight
  from the log. The log and dashboard are backed by a **persistent query log**
  (configurable retention, default 30 days; an enable/disable toggle and a
  clear-now action), so history and windowed figures survive a restart.
- 🔒 **Encrypted upstreams** — forward to resolvers over DNS-over-HTTPS (DoH) and
  DNS-over-TLS (DoT).
- 🏠 **Local DNS records** — define names for your own network, including
  wildcards (e.g. `*.home.lan`).

See the [roadmap](SPEC.md#12-roadmap) for what's planned beyond the first
milestone.

## Architecture at a glance

| Layer | Technology |
|---|---|
| Async runtime | [`tokio`](https://tokio.rs) |
| Service middleware (rate limiting, backpressure) | [`tower`](https://docs.rs/tower) |
| DNS wire format | Custom lazy parser/serializer over [`bytes`](https://docs.rs/bytes) — shallow parse + raw passthrough |
| Upstream transport | [`hickory`](https://github.com/hickory-dns/hickory-dns) — UDP/TCP/DoT/DoH |
| Persistent storage | SQLite via [`sqlx`](https://docs.rs/sqlx) — compile-time-checked queries, embedded migrations; stores config and the durable query-log history |
| Logging | [`tracing`](https://docs.rs/tracing) to stdout; live log streamed to the UI over SSE |
| CLI / config | [`clap`](https://docs.rs/clap) flags (bind addresses, db path) with sane defaults |
| Hot-path state | `HashSet` blacklist/allowlist + a `HashMap` blocklist (domain → primary source) and `HashMap` local records, hot-swapped via [`arc-swap`](https://docs.rs/arc-swap); [`moka`](https://docs.rs/moka) cache with per-entry TTL |
| Web server | [`axum`](https://docs.rs/axum) |
| Templating / UI | [`askama`](https://docs.rs/askama) + [Datastar](https://data-star.dev) (SSE) + [Pico CSS](https://picocss.com) |
| Frontend assets | Vendored and embedded via `include_str!` / `include_bytes!` — no CDN, no Node build |

The full design is documented in [`SPEC.md`](SPEC.md).

## Install

Pick whichever fits; all of them give the same single binary.

**Quick install (Linux + systemd).** Downloads the latest release binary
(checksum-verified), creates an unprivileged `sagittarius` user, and installs
and starts the hardened systemd service from
[`deploy/sagittarius.service`](deploy/sagittarius.service):

```sh
curl -fsSL https://raw.githubusercontent.com/LHelge/sagittarius/main/deploy/install.sh | sudo sh
```

Re-running the script upgrades an existing install in place. The admin UI is
then reachable on port 8080 of the host. (As with any `curl | sh`, feel free
to download [`deploy/install.sh`](deploy/install.sh) and read it first.)

**Prebuilt binary.** Download a Linux `x86_64` or `aarch64` tarball from the
[latest release](https://github.com/LHelge/sagittarius/releases/latest), verify
its `.sha256`, unpack, and run `./sagittarius`.

**From crates.io.**

```sh
cargo install sagittarius
```

**Docker** (multi-arch `amd64` / `arm64`, published to GHCR):

```sh
docker run -d --name sagittarius \
  -p 53:53/udp -p 53:53/tcp \
  -p 127.0.0.1:8080:8080 \
  -v sagittarius-data:/data \
  ghcr.io/lhelge/sagittarius:latest
```

The admin UI is published on loopback above; front it with a reverse proxy for
remote access. A ready-made Compose file is at
[`deploy/docker-compose.yml`](deploy/docker-compose.yml).

## Building

Requires a recent Rust toolchain (edition 2024).

```sh
git clone https://github.com/LHelge/sagittarius.git
cd sagittarius
cargo build --release
```

The resulting binary is at `target/release/sagittarius`.

## Running

```sh
# all flags shown with their defaults — `sagittarius` alone works too
sagittarius --dns-addr 0.0.0.0:53 --admin-addr 127.0.0.1:8080 --db-path sagittarius.db --session-cookie-secure auto
```

On first run, open the admin interface and complete the one-step wizard to
create the initial admin user. Everything else is pre-seeded to working defaults
(e.g. Cloudflare `1.1.1.1` / `1.0.0.1` upstreams), so the resolver is functional
immediately. All state lives in the single SQLite file at `--db-path`.

Notes:

- Binding port 53 usually needs elevated privileges or the
  `CAP_NET_BIND_SERVICE` capability.
- The admin interface serves plain HTTP and defaults to loopback. Put it behind
  a reverse proxy (Caddy, Traefik, nginx) for TLS / remote access.
- `--session-cookie-secure auto` uses secure admin cookies when the
  browser-facing request is HTTPS, and allows direct local HTTP while testing.

## Deployment

The [`deploy/`](deploy/) directory has ready-to-adapt examples:

- [`deploy/install.sh`](deploy/install.sh) — the **quick-install script** (see
  [Install](#install)) that downloads the latest release and sets up the
  systemd service below.
- [`deploy/sagittarius.service`](deploy/sagittarius.service) — a hardened
  **systemd** unit that runs Sagittarius as a dedicated unprivileged user with
  `CAP_NET_BIND_SERVICE` for port 53, the database under
  `/var/lib/sagittarius`, graceful `SIGTERM` shutdown, and the admin UI on
  `0.0.0.0:8080` so it is reachable from the LAN out of the box.
- [`deploy/Caddyfile`](deploy/Caddyfile) — a **reverse-proxy** snippet that
  terminates TLS (automatic certificates) in front of a loopback admin UI.

For TLS or exposure beyond a trusted network, bind the admin interface to
loopback and reach it only through the proxy; the forwarded scheme/host
headers it sets are trusted for secure-cookie and CSRF origin decisions.

> Detailed installation and configuration docs will be added as the project
> stabilizes.

## Contributing

Sagittarius is in early development and contributions, ideas, and feedback are
welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the quality gate,
branch/PR workflow, and how to set up the local git hooks.

Enable the hooks with a single command after cloning:

```sh
git config core.hooksPath .githooks
```

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

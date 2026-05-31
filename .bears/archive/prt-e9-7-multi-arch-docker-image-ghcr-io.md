---
id: prt
title: E9.7 · Multi-arch Docker image → ghcr.io
status: done
priority: P2
created: 2026-05-30T13:09:44.258449197Z
updated: 2026-05-30T13:59:29.360745294Z
tags:
- release
- ci
- docker
depends_on:
- wjp
parent: 8wg
---

Build and push a multi-arch container image to GitHub Container Registry. See SPEC §10, §12.

## Deliverables
- A **`Dockerfile`**:
  - Runtime stage on **`debian:bookworm-slim`** or **`gcr.io/distroless/cc`** — glibc is required because the binaries are gnu, not musl (no `scratch`).
  - `EXPOSE 53/udp 53/tcp 8080`; `VOLUME` for the SQLite db path; sensible default `--db-path` (e.g. `/data/sagittarius.db`) and `--admin-addr 0.0.0.0:8080` so the admin UI is reachable from outside the container.
  - CA roots are **compiled in** (`hickory-net` `webpki-roots` + reqwest rustls), so no system `ca-certificates` package is needed for DoT/DoH upstreams.
- A `docker` job (`needs: verify`) using `docker/setup-buildx-action` + `docker/build-push-action`:
  - platforms `linux/amd64,linux/arm64`,
  - reuse the gnu binaries from E9.5 (copy per-arch artifact into the runtime stage) to avoid recompiling,
  - `docker/metadata-action` tags: the semver (`X.Y.Z`, `X.Y`, `X`) + `latest` (skip `latest` for prereleases),
  - login to `ghcr.io` with the built-in `GITHUB_TOKEN` (`packages: write`), push to `ghcr.io/lhelge/sagittarius`.

## Design notes
- Port 53 inside the container is unprivileged; on the host, document `--cap-add NET_BIND_SERVICE` or host-network/port-map in E9.8.
- Keep the image minimal — single binary + db volume, nothing else.

## Validation
- A tag pushes a multi-arch manifest to `ghcr.io/lhelge/sagittarius:X.Y.Z` + `:latest`; `docker run` resolves a query and serves the admin UI on both amd64 and arm64.

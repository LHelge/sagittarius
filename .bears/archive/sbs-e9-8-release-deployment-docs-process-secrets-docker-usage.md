---
id: sbs
title: E9.8 · Release & deployment docs (process, secrets, Docker usage)
status: done
priority: P2
created: 2026-05-30T13:09:48.698678287Z
updated: 2026-05-30T14:01:13.035927887Z
tags:
- release
- docs
depends_on:
- wjp
- jfy
- prt
parent: 8wg
---

Document how to cut and consume a release now that the pipeline exists. Closes the loop with E9.3. See SPEC §10, §12.

## Deliverables
- **Release ritual** (README/SPEC §10 or a short `RELEASING.md`): use conventional commits → bump `Cargo.toml` version → tag `vX.Y.Z` → push tag → pipeline runs verify/changelog/release/crates.io/docker.
- **Required repo secrets / settings**: `CARGO_REGISTRY_TOKEN` (crates.io); note ghcr uses the built-in `GITHUB_TOKEN` with `packages: write` (no extra secret).
- **Install/run docs in README**:
  - download a prebuilt binary from the GitHub Release,
  - `cargo install sagittarius`,
  - `docker run` + a small **docker-compose** example pulling `ghcr.io/lhelge/sagittarius:latest` (db volume, port mappings for 53/udp+tcp and 8080, `--cap-add NET_BIND_SERVICE` note for host port 53).
- **CHANGELOG reconciliation**: confirm the committed `CHANGELOG.md` (E9.3 seed) and the git-cliff release notes use the same `cliff.toml`, so the file and the GH Release body stay consistent.
- Update SPEC §10 deployment to mention the published container image alongside the existing systemd guidance.

## Design notes
- Pure docs/coordination task — no new workflow logic; depends on all shipping mechanisms (E9.5–E9.7) existing so the docs describe real behaviour.

## Validation
- A reader can follow the docs to cut a release and to deploy via binary, `cargo install`, or the ghcr image. SPEC/README/CLAUDE reflect the shipped release pipeline (no stale claims).

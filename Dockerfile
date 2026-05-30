# syntax=docker/dockerfile:1
#
# Runtime image for Sagittarius.
#
# The binary is built ahead of time by the release workflow (gnu target, one per
# architecture) and copied in here, so this image only needs to supply a glibc
# base and CA roots. `distroless/cc-debian12` provides both and is multi-arch,
# and because there is no `RUN` step nothing executes at build time — the
# multi-arch (amd64/arm64) build needs no QEMU emulation. `TARGETARCH` selects
# the matching prebuilt binary that the workflow stages under `binaries/`.
FROM gcr.io/distroless/cc-debian12

ARG TARGETARCH
COPY binaries/${TARGETARCH}/sagittarius /usr/local/bin/sagittarius

# The SQLite database is the only on-disk state; mount a volume here to persist
# config across restarts.
VOLUME ["/data"]

# DNS (UDP + TCP) and the admin UI.
EXPOSE 53/udp 53/tcp 8080

ENTRYPOINT ["/usr/local/bin/sagittarius"]
CMD ["--dns-addr", "0.0.0.0:53", "--admin-addr", "0.0.0.0:8080", "--db-path", "/data/sagittarius.db"]

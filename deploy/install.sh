#!/bin/sh
# Sagittarius installer — downloads the latest release binary from GitHub and
# installs it as a hardened systemd service (deploy/sagittarius.service).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/LHelge/sagittarius/main/deploy/install.sh | sudo sh
#
# What it does:
#   1. Detects the CPU architecture (x86_64 / aarch64 Linux).
#   2. Resolves the latest GitHub release, downloads its tarball, and verifies
#      the published SHA-256 checksum.
#   3. Creates the unprivileged `sagittarius` system user and
#      /var/lib/sagittarius state directory.
#   4. Installs the binary to /usr/local/bin and the systemd unit (pinned to
#      the same release tag) to /etc/systemd/system.
#   5. Enables and starts the service.
#
# Safe to re-run: an existing install is upgraded in place and the service
# restarted.

set -eu

REPO="LHelge/sagittarius"
BIN_DIR="/usr/local/bin"
UNIT_PATH="/etc/systemd/system/sagittarius.service"
STATE_DIR="/var/lib/sagittarius"
SERVICE_USER="sagittarius"

say() { printf '%s\n' "==> $*"; }
fail() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "this script must run as root — pipe it to 'sudo sh'"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd (systemctl) is required"

# ── 1. Architecture ───────────────────────────────────────────────────────────
case "$(uname -s)" in
Linux) ;;
*) fail "only Linux is supported (got: $(uname -s))" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
*) fail "unsupported architecture: $(uname -m) (x86_64 and aarch64 builds are published)" ;;
esac

# ── 2. Latest release → download + verify ─────────────────────────────────────
say "resolving the latest release of ${REPO}…"
tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
    sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
[ -n "${tag}" ] || fail "could not determine the latest release tag"
version="${tag#v}"

pkg="sagittarius-${version}-${target}"
base_url="https://github.com/${REPO}/releases/download/${tag}"

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT INT TERM

say "downloading ${pkg}.tar.gz (${tag})…"
curl -fsSL -o "${tmp}/${pkg}.tar.gz" "${base_url}/${pkg}.tar.gz"
curl -fsSL -o "${tmp}/${pkg}.tar.gz.sha256" "${base_url}/${pkg}.tar.gz.sha256"

say "verifying checksum…"
(cd "${tmp}" && sha256sum -c "${pkg}.tar.gz.sha256" >/dev/null) ||
    fail "checksum verification failed for ${pkg}.tar.gz"

tar -C "${tmp}" -xzf "${tmp}/${pkg}.tar.gz"
[ -x "${tmp}/${pkg}/sagittarius" ] || fail "binary missing from the release tarball"

say "downloading the systemd unit (${tag})…"
curl -fsSL -o "${tmp}/sagittarius.service" \
    "https://raw.githubusercontent.com/${REPO}/${tag}/deploy/sagittarius.service"

# ── 3. User + state directory ─────────────────────────────────────────────────
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    say "creating the ${SERVICE_USER} system user…"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"

# ── 4. Binary + unit ──────────────────────────────────────────────────────────
say "installing sagittarius ${version} to ${BIN_DIR}…"
install -Dm755 "${tmp}/${pkg}/sagittarius" "${BIN_DIR}/sagittarius"
install -Dm644 "${tmp}/sagittarius.service" "${UNIT_PATH}"

# ── 5. Enable + start ─────────────────────────────────────────────────────────
say "starting the service…"
systemctl daemon-reload
systemctl enable sagittarius >/dev/null 2>&1 || true
systemctl restart sagittarius

say "done — sagittarius ${version} is running."
say "open http://<this-host>:8080 to finish setup (first-run wizard);"
say "check status with: systemctl status sagittarius"

#!/bin/sh
# PDMCGuard Installer
# Usage: curl -sSL https://pdmcguard.com/install.sh | sh
#
# Downloads the latest pdmcguard binary for your OS/arch,
# verifies the checksum, and installs to /usr/local/bin.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

REPO="AnerGcorp/pdmcguard"
BINARY="pdmcguard"
INSTALL_DIR="/usr/local/bin"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { printf "${CYAN}>${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$1"; }
fail()  { printf "${RED}✗ %s${RESET}\n" "$1"; exit 1; }

# ── Detect OS + Arch ─────────────────────────────────────────
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)

  case "$OS" in
    darwin) OS="darwin" ;;
    linux)  OS="linux" ;;
    *)      fail "Unsupported OS: $OS (only macOS and Linux are supported)" ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    arm64|aarch64)   ARCH="arm64" ;;
    *)               fail "Unsupported architecture: $ARCH" ;;
  esac

  PLATFORM="${OS}_${ARCH}"
}

# ── Fetch latest version ─────────────────────────────────────
get_latest_version() {
  VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | \
    grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [ -z "$VERSION" ]; then
    fail "Could not determine latest version. Check https://github.com/${REPO}/releases"
  fi

  # Strip leading 'v' for archive name
  VERSION_NUM=$(echo "$VERSION" | sed 's/^v//')
}

# ── Download + verify + install ──────────────────────────────
install() {
  ARCHIVE="${BINARY}_${VERSION_NUM}_${PLATFORM}.tar.gz"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
  CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT

  info "Downloading ${BINARY} ${VERSION} for ${PLATFORM}..."
  curl -sSL -o "${TMPDIR}/${ARCHIVE}" "$URL" || fail "Download failed: $URL"

  info "Verifying checksum..."
  curl -sSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL" || fail "Checksum download failed"

  EXPECTED=$(grep "${ARCHIVE}" "${TMPDIR}/checksums.txt" | awk '{print $1}')
  if [ -z "$EXPECTED" ]; then
    fail "No checksum found for ${ARCHIVE}"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')
  else
    fail "No sha256sum or shasum available for verification"
  fi

  if [ "$EXPECTED" != "$ACTUAL" ]; then
    fail "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Actual:   ${ACTUAL}"
  fi
  ok "Checksum verified"

  info "Extracting..."
  tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"

  # Install binary
  if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  else
    info "Requesting sudo to install to ${INSTALL_DIR}..."
    sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  fi

  chmod +x "${INSTALL_DIR}/${BINARY}"
  ok "Installed to ${INSTALL_DIR}/${BINARY}"
}

# ── Success message ──────────────────────────────────────────
print_success() {
  printf "\n"
  printf "${BOLD}${GREEN}"
  printf "  ██████╗ ██████╗ ███╗   ███╗ ██████╗\n"
  printf "  ██╔══██╗██╔══██╗████╗ ████║██╔════╝\n"
  printf "  ██████╔╝██║  ██║██╔████╔██║██║\n"
  printf "  ██╔═══╝ ██║  ██║██║╚██╔╝██║██║\n"
  printf "  ██║     ██████╔╝██║ ╚═╝ ██║╚██████╗\n"
  printf "  ╚═╝     ╚═════╝ ╚═╝     ╚═╝ ╚═════╝\n"
  printf "${RESET}"
  printf "  ${BOLD}G  U  A  R  D${RESET}  ·  ${GREEN}%s${RESET}  ·  daemon\n" "$VERSION"
  printf "  supply chain security for developers\n"
  printf "\n"
  printf "  ${CYAN}Next steps:${RESET}\n"
  printf "\n"
  printf "  1. Authenticate with your dashboard:\n"
  printf "     ${BOLD}pdmcguard login${RESET}\n"
  printf "\n"
  printf "  2. Install the daemon service + shell hooks:\n"
  printf "     ${BOLD}pdmcguard install${RESET}\n"
  printf "\n"
  printf "  3. Check status:\n"
  printf "     ${BOLD}pdmcguard status${RESET}\n"
  printf "\n"
  printf "  Dashboard: ${CYAN}https://pdmcguard.com${RESET}\n"
  printf "  Docs:      ${CYAN}https://docs.pdmcguard.com${RESET}\n"
  printf "\n"
}

# ── Main ─────────────────────────────────────────────────────
main() {
  printf "\n${BOLD}PDMCGuard Installer${RESET}\n"
  printf "Passive Dependency Monitor & Compromise Guard\n\n"

  detect_platform
  get_latest_version
  install
  print_success
}

main

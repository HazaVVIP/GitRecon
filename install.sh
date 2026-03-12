#!/usr/bin/env bash
set -e

REPO="HazaVVIP/GitRecon"
BIN_NAME="gitrecon"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_TAG="linux" ;;
  Darwin) OS_TAG="macos" ;;
  *)
    echo "[!] Unsupported OS: $OS"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)  ARCH_TAG="x86_64" ;;
  aarch64|arm64) ARCH_TAG="aarch64" ;;
  *)
    echo "[!] Unsupported architecture: $ARCH"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

# Try to install a pre-built release binary first
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}-${OS_TAG}-${ARCH_TAG}"

echo "[*] GitRecon Installer"
echo "    OS   : $OS ($OS_TAG)"
echo "    Arch : $ARCH ($ARCH_TAG)"
echo ""

if curl -fsSL --head "$RELEASE_URL" >/dev/null 2>&1; then
  echo "[*] Downloading pre-built binary from GitHub Releases..."
  TMP="$(mktemp)"
  curl -fsSL "$RELEASE_URL" -o "$TMP"
  chmod +x "$TMP"

  if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
  else
    sudo mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
  fi

  echo "[✓] Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
  echo ""
  echo "  Run: gitrecon --help"
else
  # Fall back to building from source
  echo "[*] No pre-built binary found. Building from source..."
  echo ""

  # Ensure Rust is available
  if ! command -v cargo &>/dev/null; then
    echo "[*] Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    export PATH="$HOME/.cargo/bin:$PATH"
  fi

  BUILD_DIR="$(mktemp -d)"
  echo "[*] Cloning repository..."
  git clone --depth 1 "https://github.com/${REPO}.git" "$BUILD_DIR"

  echo "[*] Building release binary (this may take a minute)..."
  cargo build --manifest-path "${BUILD_DIR}/Cargo.toml" --release

  BIN="${BUILD_DIR}/target/release/${BIN_NAME}"

  if [ -w "$INSTALL_DIR" ]; then
    cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}"
  else
    sudo cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}"
  fi

  rm -rf "$BUILD_DIR"

  echo "[✓] Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
  echo ""
  echo "  Run: gitrecon --help"
fi

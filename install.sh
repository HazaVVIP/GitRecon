#!/usr/bin/env bash
set -e

REPO="HazaVVIP/GitRecon"
BIN_NAME="gitrecon"
INSTALL_DIR="/usr/local/bin"

# ════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ════════════════════════════════════════════════

info()    { echo "[*] $1"; }
success() { echo "[✓] $1"; }
error()   { echo "[!] $1"; }
warn()    { echo "[~] $1"; }

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Detect package manager
detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists yum; then
        echo "yum"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists brew; then
        echo "brew"
    elif command_exists apk; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Install system dependencies for building
install_build_dependencies() {
    local pkg_manager="$1"

    case "$pkg_manager" in
        apt)
            info "Installing build dependencies via apt..."
            sudo apt-get update -qq
            sudo apt-get install -y build-essential gcc make pkg-config libssl-dev curl git
            ;;
        yum|dnf)
            info "Installing build dependencies via $pkg_manager..."
            sudo $pkg_manager install -y gcc make pkg-config openssl-devel curl git
            ;;
        pacman)
            info "Installing build dependencies via pacman..."
            sudo pacman -S --noconfirm base-devel pkg-config openssl curl git
            ;;
        brew)
            info "Installing build dependencies via brew..."
            brew install pkg-config openssl curl git
            ;;
        apk)
            info "Installing build dependencies via apk..."
            apk add --no-cache build-base gcc openssl-dev curl git
            ;;
        *)
            warn "Unknown package manager. Skipping system dependency installation."
            warn "You may need to install: gcc, make, pkg-config, libssl-dev, curl, git"
            ;;
    esac
}

# ════════════════════════════════════════════════
# DETECTION
# ════════════════════════════════════════════════

info "GitRecon Installer"
echo "    Detecting environment..."

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  OS_TAG="linux" ;;
  Darwin) OS_TAG="macos" ;;
  *)
    error "Unsupported OS: $OS"
    echo "    Supported: Linux, macOS"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="x86_64" ;;
  aarch64|arm64) ARCH_TAG="aarch64" ;;
  *)
    error "Unsupported architecture: $ARCH"
    echo "    Supported: x86_64, aarch64/arm64"
    echo "    Please build from source: cargo build --release"
    exit 1
    ;;
esac

echo "    OS   : $OS ($OS_TAG)"
echo "    Arch : $ARCH ($ARCH_TAG)"
echo ""

# ════════════════════════════════════════════════
# PREREQUISITE CHECKS
# ════════════════════════════════════════════════

# Check for curl (needed for both binary download and rustup)
if ! command_exists curl; then
    error "curl is required but not installed."
    if [ "$OS" = "Linux" ]; then
        echo "    Install with: sudo apt-get install curl  # Debian/Ubuntu"
        echo "              : sudo yum install curl        # RHEL/CentOS"
    else
        echo "    Install with: brew install curl"
    fi
    exit 1
fi

# ════════════════════════════════════════════════
# BINARY INSTALLATION (PREFERRED)
# ════════════════════════════════════════════════

RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}-${OS_TAG}-${ARCH_TAG}"

info "Checking for pre-built binary..."
if curl -fsSL --head "$RELEASE_URL" >/dev/null 2>&1; then
    info "Downloading pre-built binary from GitHub Releases..."
    TMP="$(mktemp)"

    if ! curl -fsSL "$RELEASE_URL" -o "$TMP"; then
        error "Failed to download binary. Please check your internet connection."
        exit 1
    fi

    chmod +x "$TMP"

    # Verify binary is not empty
    if [ ! -s "$TMP" ]; then
        error "Downloaded binary is empty. Please try again or report this issue."
        rm -f "$TMP"
        exit 1
    fi

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
    else
        if ! sudo mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null; then
            error "Failed to install to $INSTALL_DIR. Try running with sudo."
            rm -f "$TMP"
            exit 1
        fi
    fi

    success "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
    echo ""
    echo "  Run: gitrecon --help"
    echo ""
    echo "  Quick start:"
    echo "    gitrecon https://example.com"
    echo "    gitrecon --token ghp_xxxxxxxxxxxxxxxxxxxx"
    exit 0
fi

# ════════════════════════════════════════════════
# SOURCE BUILD FALLBACK
# ════════════════════════════════════════════════

warn "No pre-built binary found for your platform."
info "Building from source..."

# Check for git
if ! command_exists git; then
    error "git is required for source build but not installed."
    PKG_MANAGER="$(detect_package_manager)"
    case "$PKG_MANAGER" in
        apt)
            echo "    Install with: sudo apt-get install git"
            ;;
        yum|dnf)
            echo "    Install with: sudo $PKG_MANAGER install git"
            ;;
        brew)
            echo "    Install with: brew install git"
            ;;
        *)
            echo "    Please install git using your package manager"
            ;;
    esac
    exit 1
fi

# Ensure Rust is available
if ! command_exists cargo; then
    info "Rust not found. Installing via rustup..."

    # Install build dependencies first on Linux
    if [ "$OS" = "Linux" ]; then
        PKG_MANAGER="$(detect_package_manager)"
        install_build_dependencies "$PKG_MANAGER"
    fi

    # Install Rust
    if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path; then
        error "Failed to install Rust. Please visit https://rustup.rs/"
        exit 1
    fi

    # Source cargo environment in current shell
    export PATH="$HOME/.cargo/bin:$PATH"

    # Verify cargo is now available
    if ! command_exists cargo; then
        error "Cargo installation failed. Please restart your terminal and try again."
        exit 1
    fi

    success "Rust installed successfully"
fi

# Show Rust version
RUST_VERSION="$(cargo --version 2>/dev/null || echo "unknown")"
info "Using $RUST_VERSION"

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
trap "rm -rf $BUILD_DIR" EXIT INT TERM

info "Cloning repository..."
if ! git clone --depth 1 "https://github.com/${REPO}.git" "$BUILD_DIR" 2>/dev/null; then
    error "Failed to clone repository. Please check your internet connection."
    exit 1
fi

info "Building release binary (this may take 1-3 minutes)..."
echo "    This requires significant CPU and memory. Please be patient."

if ! cargo build --manifest-path "${BUILD_DIR}/Cargo.toml" --release 2>&1; then
    error "Build failed. Please check:"
    echo "    1. You have sufficient disk space (>2GB)"
    echo "    2. You have adequate memory (>1GB)"
    echo "    3. All build dependencies are installed"
    echo ""
    echo "    For detailed error, run:"
    echo "      cd $BUILD_DIR && cargo build --release"
    exit 1
fi

BIN="${BUILD_DIR}/target/release/${BIN_NAME}"

# Verify binary exists
if [ ! -f "$BIN" ]; then
    error "Build completed but binary not found at: $BIN"
    exit 1
fi

# Install binary
info "Installing binary..."
if [ -w "$INSTALL_DIR" ]; then
    cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}"
else
    if ! sudo cp "$BIN" "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null; then
        error "Failed to install to $INSTALL_DIR. Try running with sudo."
        exit 1
    fi
fi

success "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
echo ""

# Show PATH reminder if using local cargo
if [ -f "$HOME/.cargo/bin/cargo" ]; then
    CARGO_BIN="$HOME/.cargo/bin"
    if ! echo "$PATH" | grep -q "$CARGO_BIN"; then
        warn "Note: ~/.cargo/bin is not in your PATH"
        echo "      Add the following to your ~/.bashrc or ~/.zshrc:"
        echo "      export PATH=\"\$HOME/.cargo/bin:\$PATH\""
    fi
fi

echo "  Run: gitrecon --help"
echo ""
echo "  Quick start:"
echo "    gitrecon https://example.com"
echo "    gitrecon --token ghp_xxxxxxxxxxxxxxxxxxxx"
echo ""
echo "  Documentation: https://github.com/${REPO}"
